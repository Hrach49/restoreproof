// The Timestamper (W4.4, docs/decisions.md 2026-10-06 W4.4, points 4, 6 and 7):
// which answer of a TSA becomes timestamp.tst, and what every other answer is
// called. The TSA is the test-only one of tsa_lab.hpp behind a FakeHttpClient;
// nothing here reaches the network.

#include "fake_http_client.hpp"
#include "tsa_lab.hpp"

#include <rp/retry_policy.hpp>
#include <rp/rfc3161.hpp>
#include <rp/timestamper.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <openssl/ts.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace std::chrono_literals;
using Catch::Matchers::ContainsSubstring;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::TimestampOutcome;
using rp::test::FakeHttpClient;
using rp::test::FakeRfc3161;
using rp::test::kDigestAbc;
using rp::test::kDigestEmpty;
using rp::test::make_response;
using rp::test::Rfc3161Fault;
using rp::test::TestTsa;

const std::string kUrl = "http://tsa.test/stamp";
constexpr std::uint64_t kNonce = 0x00c0ffee12345678ULL;
const std::string kReplyType = "application/timestamp-reply";

const TestTsa& tsa()
{
    static const TestTsa one;
    return one;
}

const TestTsa& other_tsa()
{
    static const TestTsa one("another test root (not a secret)");
    return one;
}

struct Lab {
    FakeHttpClient http;
    FakeRfc3161 primitive;
    std::vector<std::chrono::milliseconds> sleeps;
    std::uint64_t next_nonce = kNonce;
    std::shared_ptr<spdlog::logger> logger;

    rp::Timestamper timestamper()
    {
        rp::TimestamperOptions options;
        options.url = kUrl;
        options.ca_pem = tsa().root_pem();
        options.http = &http;
        options.primitive = &primitive;
        options.nonce = [this]() -> std::optional<std::uint64_t> { return next_nonce++; };
        options.sleep = [this](std::chrono::milliseconds wait) { sleeps.push_back(wait); };
        options.logger = logger;
        return rp::Timestamper(std::move(options));
    }

    // The TSA answers every request as it should.
    void answer_well()
    {
        http.on(HttpMethod::post, kUrl, [](const HttpRequest& request) {
            return make_response(200, tsa().respond(request.body), kReplyType);
        });
    }
};

// The nonce and the digest a request carries.
struct Sent {
    std::uint64_t nonce = 0;
    std::vector<unsigned char> digest;
};

// No Catch2 assertion: handlers call this.
Sent sent_in(const std::string& request)
{
    Sent sent;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(request.data());
    const std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)> parsed(
        d2i_TS_REQ(nullptr, &p, static_cast<long>(request.size())), &TS_REQ_free);
    if (!parsed) {
        throw std::runtime_error("the request isn't a TimeStampReq");
    }
    ASN1_INTEGER_get_uint64(&sent.nonce, TS_REQ_get_nonce(parsed.get()));
    const ASN1_OCTET_STRING* message =
        TS_MSG_IMPRINT_get_msg(TS_REQ_get_msg_imprint(parsed.get()));
    sent.digest.assign(ASN1_STRING_get0_data(message),
                       ASN1_STRING_get0_data(message) + ASN1_STRING_length(message));
    return sent;
}

std::array<unsigned char, 32> as_digest(const std::vector<unsigned char>& bytes)
{
    std::array<unsigned char, 32> digest{};
    std::copy_n(bytes.begin(), 32, digest.begin());
    return digest;
}

struct Row {
    const char* name;
    std::string_view code;
    FakeHttpClient::Handler handler;
};

} // namespace

// --- Failure paths: one row per code ------------------------------------------

TEST_CASE("an answer that can't be taken is its code after three attempts, never a throw",
          "[timestamper]")
{
    namespace code = rp::timestamp_code;
    const Row row = GENERATE_COPY(
        Row{"the TSA can't be reached", code::kUnreachable,
            [](const HttpRequest&) -> HttpResponse {
                throw rp::HttpError("POST http://tsa.test/stamp: could not connect",
                                    rp::TransportError::connect, 0, 1);
            }},
        Row{"the request times out", code::kUnreachable,
            [](const HttpRequest&) -> HttpResponse {
                throw rp::HttpError("POST http://tsa.test/stamp: timed out",
                                    rp::TransportError::timeout, 0, 1);
            }},
        Row{"503", code::kHttpStatus,
            [](const HttpRequest&) { return make_response(503, "busy", "text/plain"); }},
        Row{"a redirect", code::kHttpStatus,
            [](const HttpRequest&) { return make_response(302, "", "text/plain"); }},
        Row{"HTML with 200", code::kMalformed,
            [](const HttpRequest&) {
                return make_response(200, "<html><body>maintenance</body></html>", "text/html");
            }},
        Row{"an empty body", code::kMalformed,
            [](const HttpRequest&) { return make_response(200); }},
        Row{"granted, and no token", code::kMalformed,
            [](const HttpRequest&) {
                return make_response(200, std::string("\x30\x05\x30\x03\x02\x01\x00", 7),
                                     kReplyType);
            }},
        Row{"a rejection", code::kRejected,
            [](const HttpRequest&) { return make_response(200, TestTsa::rejection(), kReplyType); }},
        Row{"grantedWithMods", code::kRejected,
            [](const HttpRequest& request) {
                return make_response(200, TestTsa::with_status(tsa().respond(request.body), 1),
                                     kReplyType);
            }},
        Row{"another request's nonce", code::kNonce,
            [](const HttpRequest& request) {
                const Sent sent = sent_in(request.body);
                return make_response(
                    200,
                    tsa().respond(rp::openssl_rfc3161().request(as_digest(sent.digest),
                                                                sent.nonce + 1)),
                    kReplyType);
            }},
        Row{"a token over another hash", code::kImprint,
            [](const HttpRequest& request) {
                return make_response(
                    200,
                    tsa().respond(rp::openssl_rfc3161().request(kDigestEmpty,
                                                                sent_in(request.body).nonce)),
                    kReplyType);
            }},
        Row{"a TSA under another root", code::kUntrusted,
            [](const HttpRequest& request) {
                return make_response(200, other_tsa().respond(request.body), kReplyType);
            }},
        Row{"a body over the limit", code::kTooLarge,
            [](const HttpRequest&) {
                return make_response(200, std::string(rp::kMaxTimestampFileBytes + 1, '\x30'),
                                     kReplyType);
            }},
        Row{"an HTTP client that fails in its own way", code::kInternal,
            [](const HttpRequest&) -> HttpResponse { throw std::logic_error("no route"); }},
        Row{"an HTTP client that throws no exception type", code::kInternal,
            [](const HttpRequest&) -> HttpResponse { throw 42; }});
    CAPTURE(row.name);
    Lab lab;
    lab.http.on(HttpMethod::post, kUrl, row.handler);

    const TimestampOutcome outcome = lab.timestamper().stamp(kDigestAbc);

    CHECK_FALSE(outcome.stamped());
    CHECK(outcome.token.empty());
    CHECK(outcome.error == row.code);
    CHECK(outcome.attempts == 3);
    CHECK(lab.http.requests().size() == 3);
    CHECK(lab.sleeps == std::vector<std::chrono::milliseconds>{30s, 60s});
}

TEST_CASE("a primitive that fails is a code too, and nothing is taken", "[timestamper]")
{
    namespace code = rp::timestamp_code;
    struct FaultRow {
        Rfc3161Fault fault;
        std::string_view code;
        std::size_t requests; // sent to the TSA
    };
    const FaultRow row = GENERATE(
        FaultRow{Rfc3161Fault::request_empty, code::kInternal, 0},
        FaultRow{Rfc3161Fault::request_throws, code::kInternal, 0},
        FaultRow{Rfc3161Fault::response_throws, code::kInternal, 3},
        FaultRow{Rfc3161Fault::token_none, code::kMalformed, 3},
        FaultRow{Rfc3161Fault::token_throws, code::kInternal, 3},
        FaultRow{Rfc3161Fault::verify_false, code::kUntrusted, 3},
        FaultRow{Rfc3161Fault::verify_throws, code::kInternal, 3});
    CAPTURE(static_cast<int>(row.fault));
    Lab lab;
    lab.answer_well();
    lab.primitive.fault = row.fault;

    const TimestampOutcome outcome = lab.timestamper().stamp(kDigestAbc);

    CHECK_FALSE(outcome.stamped());
    CHECK(outcome.error == row.code);
    CHECK(outcome.attempts == 3);
    CHECK(lab.http.requests().size() == row.requests);
    CHECK(lab.sleeps == std::vector<std::chrono::milliseconds>{30s, 60s});
}

TEST_CASE("without a nonce no request is sent", "[timestamper]")
{
    Lab lab;
    lab.answer_well();
    rp::TimestamperOptions options;
    options.url = kUrl;
    options.ca_pem = tsa().root_pem();
    options.http = &lab.http;
    options.primitive = &lab.primitive;
    options.sleep = [&lab](std::chrono::milliseconds wait) { lab.sleeps.push_back(wait); };
    lab.primitive.fault = Rfc3161Fault::nonce_none;

    const TimestampOutcome outcome = rp::Timestamper(std::move(options)).stamp(kDigestAbc);

    CHECK(outcome.error == rp::timestamp_code::kInternal);
    CHECK(outcome.attempts == 3);
    CHECK(lab.http.requests().empty());
}

TEST_CASE("a Timestamper without an HTTP client asks nobody", "[timestamper]")
{
    Lab lab;
    rp::TimestamperOptions options;
    options.url = kUrl;
    options.ca_pem = tsa().root_pem();
    options.sleep = [&lab](std::chrono::milliseconds wait) { lab.sleeps.push_back(wait); };

    const TimestampOutcome outcome = rp::Timestamper(std::move(options)).stamp(kDigestAbc);

    CHECK(outcome.error == rp::timestamp_code::kInternal);
    CHECK(outcome.attempts == 3);
}

// --- The happy path ------------------------------------------------------------

TEST_CASE("a good answer is taken at the first attempt, the token as the TSA sent it",
          "[timestamper]")
{
    Lab lab;
    std::string sent_token;
    lab.http.on(HttpMethod::post, kUrl, [&sent_token](const HttpRequest& request) {
        std::string response = tsa().respond(request.body);
        sent_token = rp::openssl_rfc3161().parse_response(response)->token;
        return make_response(200, std::move(response), kReplyType);
    });

    const TimestampOutcome outcome = lab.timestamper().stamp(kDigestAbc);

    REQUIRE(outcome.stamped());
    CHECK(outcome.error.empty());
    CHECK(outcome.attempts == 1);
    CHECK(outcome.token == sent_token);
    CHECK(outcome.gen_time == rp::test::kTestTsaTime);
    CHECK(lab.sleeps.empty());
    CHECK(rp::openssl_rfc3161().verify_token(outcome.token, tsa().root_pem()));

    const std::vector<HttpRequest> requests = lab.http.requests();
    REQUIRE(requests.size() == 1);
    const HttpRequest& request = requests.front();
    CHECK(request.method == HttpMethod::post);
    CHECK(request.url == kUrl);
    CHECK(request.content_type == "application/timestamp-query");
    CHECK(request.headers.empty());
    CHECK(request.parts.empty());
    CHECK(request.timeout == 10s);
    // The attempts are counted by the Timestamper alone.
    CHECK(request.max_attempts == 1);
    CHECK_FALSE(request.retry_on_status);
    CHECK(request.max_body_bytes == rp::kMaxTimestampFileBytes);
    const Sent sent = sent_in(request.body);
    CHECK(sent.nonce == kNonce);
    CHECK(sent.digest == std::vector<unsigned char>(kDigestAbc.begin(), kDigestAbc.end()));
}

TEST_CASE("a failure and then a good answer: the token, two attempts, one wait", "[timestamper]")
{
    Lab lab;
    int calls = 0;
    lab.http.on(HttpMethod::post, kUrl, [&calls](const HttpRequest& request) {
        if (++calls == 1) {
            return make_response(503, "busy", "text/plain");
        }
        return make_response(200, tsa().respond(request.body), kReplyType);
    });

    const TimestampOutcome outcome = lab.timestamper().stamp(kDigestAbc);

    REQUIRE(outcome.stamped());
    CHECK(outcome.attempts == 2);
    CHECK(lab.sleeps == std::vector<std::chrono::milliseconds>{30s});
    // Each attempt has a nonce of its own.
    const std::vector<HttpRequest> requests = lab.http.requests();
    REQUIRE(requests.size() == 2);
    CHECK(sent_in(requests[0].body).nonce == kNonce);
    CHECK(sent_in(requests[1].body).nonce == kNonce + 1);
}

TEST_CASE("the third attempt still counts, and the last failure's code is the answer",
          "[timestamper]")
{
    Lab lab;
    int calls = 0;
    bool succeed = GENERATE(true, false);
    lab.http.on(HttpMethod::post, kUrl, [&calls, succeed](const HttpRequest& request) {
        ++calls;
        if (calls == 1) {
            return make_response(503, "busy", "text/plain");
        }
        if (calls == 2 || !succeed) {
            return make_response(200, TestTsa::rejection(), kReplyType);
        }
        return make_response(200, tsa().respond(request.body), kReplyType);
    });

    const TimestampOutcome outcome = lab.timestamper().stamp(kDigestAbc);

    CHECK(outcome.stamped() == succeed);
    CHECK(outcome.attempts == 3);
    CHECK(outcome.error == (succeed ? std::string_view{} : rp::timestamp_code::kRejected));
    CHECK(lab.sleeps == std::vector<std::chrono::milliseconds>{30s, 60s});
}

TEST_CASE("the default nonce is the primitive's, new for each attempt", "[timestamper]")
{
    Lab lab;
    lab.http.on(HttpMethod::post, kUrl,
                [](const HttpRequest&) { return make_response(503, "busy", "text/plain"); });
    rp::TimestamperOptions options;
    options.url = kUrl;
    options.ca_pem = tsa().root_pem();
    options.http = &lab.http;
    options.sleep = [](std::chrono::milliseconds) {};

    CHECK(rp::Timestamper(std::move(options)).stamp(kDigestAbc).attempts == 3);

    const std::vector<HttpRequest> requests = lab.http.requests();
    REQUIRE(requests.size() == 3);
    CHECK(sent_in(requests[0].body).nonce != sent_in(requests[1].body).nonce);
    CHECK(sent_in(requests[1].body).nonce != sent_in(requests[2].body).nonce);
}

TEST_CASE("one debug line per attempt, with the code or granted and never a body",
          "[timestamper]")
{
    Lab lab;
    std::ostringstream log;
    lab.logger = std::make_shared<spdlog::logger>(
        "timestamper_test", std::make_shared<spdlog::sinks::ostream_sink_mt>(log));
    lab.logger->set_level(spdlog::level::debug);
    lab.logger->set_pattern("%v");
    int calls = 0;
    lab.http.on(HttpMethod::post, kUrl, [&calls](const HttpRequest& request) {
        if (++calls == 1) {
            return make_response(200, "BODY-SENTINEL", "text/html");
        }
        return make_response(200, tsa().respond(request.body), kReplyType);
    });

    REQUIRE(lab.timestamper().stamp(kDigestAbc).stamped());

    std::string lines = log.str();
    std::erase(lines, '');
    CHECK(lines == "timestamp: attempt 1 of 3: tsa_response_malformed\n"
                       "timestamp: attempt 2 of 3: granted\n");
}

TEST_CASE("the codes are the documented ones, in their order", "[timestamper]")
{
    CHECK(rp::timestamp_codes() ==
          std::vector<std::string>{"tsa_unreachable", "tsa_http_status", "tsa_token_too_large",
                                   "tsa_response_malformed", "tsa_rejected", "tsa_nonce_mismatch",
                                   "tsa_imprint_mismatch", "tsa_untrusted", "timestamp_internal",
                                   "timestamp_not_written"});
    CHECK(rp::kDefaultTsaUrl == "http://timestamp.digicert.com");
    CHECK(rp::kTimestampAttempts == 3);
}

TEST_CASE("without a sleep the attempts follow at once", "[timestamper]")
{
    Lab lab;
    lab.http.on(HttpMethod::post, kUrl,
                [](const HttpRequest&) { return make_response(503, "busy", "text/plain"); });
    rp::TimestamperOptions options;
    options.url = kUrl;
    options.ca_pem = tsa().root_pem();
    options.http = &lab.http;

    const TimestampOutcome outcome = rp::Timestamper(std::move(options)).stamp(kDigestAbc);

    CHECK(outcome.error == rp::timestamp_code::kHttpStatus);
    CHECK(outcome.attempts == 3);
}

TEST_CASE("a sleep that throws ends nothing", "[timestamper]")
{
    Lab lab;
    lab.answer_well();
    rp::TimestamperOptions options;
    options.url = kUrl;
    options.ca_pem = tsa().root_pem();
    options.http = &lab.http;
    int calls = 0;
    lab.http.on(HttpMethod::post, kUrl, [&calls](const HttpRequest& request) {
        if (++calls == 1) {
            return make_response(503, "busy", "text/plain");
        }
        return make_response(200, tsa().respond(request.body), kReplyType);
    });
    options.sleep = [](std::chrono::milliseconds) { throw std::runtime_error("interrupted"); };

    // The wait that threw is that attempt's failure; the next one is still made.
    const TimestampOutcome outcome = rp::Timestamper(std::move(options)).stamp(kDigestAbc);

    CHECK(outcome.error == rp::timestamp_code::kInternal);
    CHECK(outcome.attempts == 3);
    CHECK(calls == 1);
}
