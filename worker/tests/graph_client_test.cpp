// W2.1: GraphClient's token handling against the recorded Entra replies in
// tests/fixtures/graph/ (README.md there), served by FakeHttpClient: the
// AADSTS error table, redirects, retries and their waits, the reply checks,
// the cache and its renewal, single-flight renewals, and no secret in any
// message or log line. Nothing here touches the network.

#include "fake_http_client.hpp"
#include "test_certs.hpp"

#include <rp/base64.hpp>
#include <rp/client_assertion.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using Catch::Matchers::ContainsSubstring;

namespace {

using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::graph::GraphClient;
using rp::graph::GraphClientOptions;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using rp::test::to_response;
using Clock = std::chrono::system_clock;

const std::string kTenant = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";
const std::string kClient = "737da5ef-baf2-4198-b009-e160d8ca77c9";
const std::string kTokenUrl =
    "https://login.microsoftonline.com/" + kTenant + "/oauth2/v2.0/token";
const std::string kMessagesPath =
    "/users/restoretest@RestoreProofLab.onmicrosoft.com/mailFolders/inbox/messages?$top=1&$select=id";
const std::string kMessagesUrl = "https://graph.microsoft.com/v1.0" + kMessagesPath;

// Every test runs at this wall-clock time.
const Clock::time_point kNow = std::chrono::sys_days{std::chrono::year{2026} / 9 / 28} + 12h;
// Sentinels no message or log line may contain.
constexpr const char* kPfxPassword = "Sentinel-Graph-PFX-Password-4b2a";

// The test certificate's PFX as the environment would hold it, made once.
const std::string& pfx_base64()
{
    static const std::string pfx = rp::test::to_base64(rp::test::make_pfx(
        rp::test::make_client_cert("RestoreProof Worker",
                                   rp::test::ClientCertOptions{.now = Clock::to_time_t(kNow)}),
        kPfxPassword));
    return pfx;
}

rp::graph::ClientCertificate certificate()
{
    return rp::graph::load_client_certificate(pfx_base64(), kPfxPassword, kNow);
}

// The recorded 200 token reply with this token and lifetime.
HttpResponse token_response(const std::string& access, std::int64_t expires_in = 3599)
{
    json fixture = load_fixture_json("graph", "token-200");
    fixture["body"]["access_token"] = access;
    fixture["body"]["expires_in"] = expires_in;
    return to_response(fixture);
}

// An Entra error reply in the recorded shape.
HttpResponse entra_error(int status, const std::string& error, std::optional<std::int64_t> code,
                         const std::string& text = "Something is wrong.")
{
    json body = {{"error", error},
                 {"error_description",
                  (code ? "AADSTS" + std::to_string(*code) + ": " : std::string{}) + text +
                      " Trace ID: 11111111-2222-3333-4444-555555555555"},
                 {"error_codes", code ? json::array({*code}) : json::array()},
                 {"trace_id", "11111111-2222-3333-4444-555555555555"}};
    HttpResponse response = make_response(status, body.dump());
    response.headers["x-ms-request-id"] = "11111111-2222-3333-4444-555555555555";
    return response;
}

// The value of `key` in a form body, as sent (still percent-encoded).
std::string form_value(const std::string& body, const std::string& key)
{
    const std::string prefix = key + "=";
    std::size_t start = 0;
    while (start <= body.size()) {
        const std::size_t end = std::min(body.find('&', start), body.size());
        const std::string_view pair = std::string_view{body}.substr(start, end - start);
        if (pair.starts_with(prefix)) {
            return std::string{pair.substr(prefix.size())};
        }
        start = end + 1;
    }
    return "(absent)";
}

std::string header(const HttpRequest& request, const std::string& name)
{
    const auto it = request.headers.find(name);
    return it == request.headers.end() ? "(none)" : it->second;
}

// What a call threw, flattened for CHECKs.
struct Caught {
    std::string kind = "none";
    std::string what;
    int status = 0;
    std::string code;
    std::string request_id;
    std::optional<std::chrono::seconds> retry_after;
};

Caught catch_graph(const std::function<void()>& call)
{
    const auto fill = [](std::string kind, const rp::graph::GraphError& e) {
        return Caught{std::move(kind), e.what(), e.status(), e.code(), e.request_id(), {}};
    };
    try {
        call();
    } catch (const rp::graph::TransientError& e) {
        Caught caught = fill("TransientError", e);
        caught.retry_after = e.retry_after();
        return caught;
    } catch (const rp::graph::AuthError& e) {
        return fill("AuthError", e);
    } catch (const rp::graph::PermissionError& e) {
        return fill("PermissionError", e);
    } catch (const rp::graph::NotFoundError& e) {
        return fill("NotFoundError", e);
    } catch (const rp::graph::CertificateError& e) {
        return fill("CertificateError", e);
    } catch (const rp::graph::GraphError& e) {
        return fill("GraphError", e);
    } catch (const std::exception& e) {
        return Caught{"other", e.what()};
    }
    return {};
}

// Entra and Graph as a test sees them. The token endpoint answers with
// on_token (by default "token-<n>" for the n-th request, 3599 s); the one
// Graph route answers the recorded inbox. Time only moves when the test says
// so; waits are recorded, never slept; every log line, trace level up, goes
// to a string.
struct Lab {
    Lab()
    {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("graph_test", sink);
        logger->set_level(spdlog::level::trace);
        logger->set_formatter(std::make_unique<spdlog::pattern_formatter>(
            "%l %v", spdlog::pattern_time_type::utc, "\n"));
        http.on(HttpMethod::post, kTokenUrl, [this](const HttpRequest& request) {
            const int n = ++token_requests;
            std::function<HttpResponse(int, const HttpRequest&)> handler;
            {
                const std::lock_guard lock(mutex);
                handler = on_token;
            }
            return handler(n, request);
        });
        http.on(HttpMethod::get, kMessagesUrl, {load_fixture("graph", "messages-200")});
    }

    GraphClientOptions options()
    {
        GraphClientOptions out;
        out.logger = logger;
        out.now = [this] { return std::chrono::steady_clock::time_point{} + now.load(); };
        out.wall_now = [] { return kNow; };
        out.sleep = [this](std::chrono::milliseconds wait) {
            const std::lock_guard lock(mutex);
            sleeps.push_back(wait);
        };
        out.jitter = [] { return 0.0; };
        out.timeout = 45s;
        return out;
    }

    std::unique_ptr<GraphClient> make_client()
    {
        return std::make_unique<GraphClient>(http, kTenant, kClient, certificate(), options());
    }

    void set_on_token(std::function<HttpResponse(int, const HttpRequest&)> handler)
    {
        const std::lock_guard lock(mutex);
        on_token = std::move(handler);
    }

    // Answers every token request with `response`.
    void token_always(const HttpResponse& response)
    {
        set_on_token([response](int, const HttpRequest&) { return response; });
    }

    void advance(std::chrono::milliseconds by) { now = now.load() + by; }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    std::vector<std::chrono::milliseconds> waits()
    {
        const std::lock_guard lock(mutex);
        return sleeps;
    }

    // The client assertions sent, in order.
    std::vector<std::string> assertions() const
    {
        std::vector<std::string> out;
        for (const HttpRequest& request : http.requests()) {
            if (request.url == kTokenUrl) {
                out.push_back(form_value(request.body, "client_assertion"));
            }
        }
        return out;
    }

    // The Authorization header of each Graph GET, in order.
    std::vector<std::string> bearers() const
    {
        std::vector<std::string> out;
        for (const HttpRequest& request : http.requests()) {
            if (request.method == HttpMethod::get) {
                out.push_back(header(request, "Authorization"));
            }
        }
        return out;
    }

    rp::test::FakeHttpClient http;
    std::atomic<std::chrono::milliseconds> now{0ms};
    std::mutex mutex;
    std::vector<std::chrono::milliseconds> sleeps;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    std::atomic<int> token_requests = 0;
    std::function<HttpResponse(int, const HttpRequest&)> on_token = [](int n,
                                                                       const HttpRequest&) {
        return token_response("token-" + std::to_string(n));
    };
};

// One GET through a fresh client of `lab`, as the tests' trigger for a
// token request.
Caught get_once(Lab& lab)
{
    auto client = lab.make_client();
    return catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); });
}

std::string thumbprint()
{
    return certificate().sha1_thumbprint();
}

} // namespace

// --- Failure paths ----------------------------------------------------------

TEST_CASE("the constructor refuses IDs that aren't GUIDs and a timeout of 0", "[graph][client]")
{
    rp::test::FakeHttpClient http;
    const std::string bad = GENERATE(as<std::string>{}, "", "contoso.onmicrosoft.com", "common",
                                     "{bcd6bd1a-ea42-489d-aa28-2c19a44ad146}",
                                     "bcd6bd1a-ea42-489d-aa28-2c19a44ad146/x");
    CAPTURE(bad);
    CHECK(catch_graph([&] { GraphClient{http, bad, kClient, certificate()}; }).kind ==
          "GraphError");
    CHECK(catch_graph([&] { GraphClient{http, kTenant, bad, certificate()}; }).kind ==
          "GraphError");

    GraphClientOptions options;
    options.timeout = GENERATE(0ms, -1ms);
    CHECK_THROWS_AS((GraphClient{http, kTenant, kClient, certificate(), options}),
                    std::invalid_argument);
    CHECK(http.requests().empty());
}

TEST_CASE("each recorded Entra refusal is an AuthError that says what to check, sent once",
          "[graph][client]")
{
    struct Row {
        std::string fixture;
        int status;
        std::string code;
        std::string hint;
    };
    const Row row = GENERATE_COPY(values<Row>({
        {"token-bad-signature-401", 401, "700027",
         "is the certificate with SHA-1 thumbprint " + thumbprint() + " uploaded to app " +
             kClient + "?"},
        {"token-unknown-thumbprint-401", 401, "700027",
         "is the certificate with SHA-1 thumbprint " + thumbprint() + " uploaded to app " +
             kClient + "?"},
        {"token-unknown-app-400", 400, "700016", "check graph_client_id and graph_tenant_id"},
        {"token-unknown-tenant-400", 400, "90002", "check graph_tenant_id"},
        {"token-expired-assertion-401", 401, "700024",
         "this machine's clock reads 2026-09-28T12:00:00Z (UTC)"},
        {"token-future-assertion-401", 401, "700024",
         "this machine's clock reads 2026-09-28T12:00:00Z (UTC)"},
    }));
    CAPTURE(row.fixture);
    const HttpResponse response = load_fixture("graph", row.fixture);
    Lab lab;
    lab.token_always(response);

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "AuthError");
    CHECK(caught.status == row.status);
    CHECK(caught.code == row.code);
    CHECK(caught.request_id == response.headers.at("x-ms-request-id"));
    CHECK_THAT(caught.what, ContainsSubstring(row.hint));
    CHECK_THAT(caught.what, ContainsSubstring("AADSTS" + row.code));
    CHECK_THAT(caught.what, ContainsSubstring("HTTP " + std::to_string(row.status)));
    // Never retried, and no Graph call without a token.
    CHECK(lab.token_requests == 1);
    CHECK(lab.waits().empty());
    CHECK(lab.bearers().empty());
}

TEST_CASE("Entra's codes map to errors by the table, not by the status", "[graph][client]")
{
    struct Row {
        int status;
        std::string error;
        std::int64_t code;
        std::string hint; // empty: none
    };
    const std::string cert_hint = "is the certificate with SHA-1 thumbprint " + thumbprint() +
                                  " uploaded to app " + kClient + "?";
    const std::string clock_hint = "this machine's clock reads 2026-09-28T12:00:00Z (UTC)";
    const std::string disabled_hint =
        "the app " + kClient + " is disabled, deleted or not found in tenant " + kTenant;
    const Row row = GENERATE_COPY(values<Row>({
        {400, "unauthorized_client", 700016, "check graph_client_id and graph_tenant_id"},
        {400, "invalid_request", 90002, "check graph_tenant_id"},
        {400, "invalid_request", 900023, "check graph_tenant_id"},
        {400, "invalid_request", 50059, "check graph_tenant_id"},
        {401, "invalid_client", 700027, cert_hint},
        {401, "invalid_client", 7000274, cert_hint},
        {400, "invalid_client", 50012, cert_hint},
        {400, "invalid_client", 700030, cert_hint},
        {401, "invalid_client", 700024, clock_hint},
        {400, "invalid_grant", 50027, clock_hint},
        {400, "invalid_grant", 53003, "a Conditional Access policy blocks the sign-in"},
        {400, "unauthorized_client", 70001, disabled_hint},
        {400, "unauthorized_client", 7000112, disabled_hint},
        {400, "unauthorized_client", 500014, disabled_hint},
        {400, "unauthorized_client", 1000031, disabled_hint},
        // The code wins over a status that would be retried.
        {500, "unauthorized_client", 700016, "check graph_client_id and graph_tenant_id"},
        {503, "invalid_client", 700027, cert_hint},
        // Any other code on a 4xx: an AuthError that names it, without a hint.
        {401, "invalid_client", 7000215, ""},
        {400, "invalid_scope", 1002012, ""},
    }));
    CAPTURE(row.status, row.code);
    Lab lab;
    lab.token_always(entra_error(row.status, row.error, row.code));

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "AuthError");
    CHECK(caught.status == row.status);
    CHECK(caught.code == std::to_string(row.code));
    CHECK_THAT(caught.what, ContainsSubstring("AADSTS" + std::to_string(row.code)));
    CHECK_THAT(caught.what, ContainsSubstring(row.error));
    if (!row.hint.empty()) {
        CHECK_THAT(caught.what, ContainsSubstring(row.hint));
    }
    CHECK(lab.token_requests == 1);
}

TEST_CASE("the AADSTS code comes from error_codes, else from error_description",
          "[graph][client]")
{
    struct Row {
        json error_codes; // null: absent
        std::string description;
        std::string code;
    };
    const Row row = GENERATE(values<Row>({
        {json::array({90002, 700016}), "AADSTS700016: x", "90002"},
        {nullptr, "AADSTS700016: Application not found.", "700016"},
        {json::array(), "AADSTS90002: Tenant not found.", "90002"},
        {json::array({"x"}), "AADSTS700016: x", "700016"},
        {json::array({-5}), "AADSTS700016: x", "700016"},
        // No number anywhere: the "error" is the code.
        {nullptr, "No code here.", "invalid_client"},
        {nullptr, "AADSTS: no digits", "invalid_client"},
    }));
    CAPTURE(row.error_codes.dump(), row.description);
    json body = {{"error", "invalid_client"}, {"error_description", row.description}};
    if (!row.error_codes.is_null()) {
        body["error_codes"] = row.error_codes;
    }
    Lab lab;
    lab.token_always(make_response(401, body.dump()));

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "AuthError");
    CHECK(caught.code == row.code);
    CHECK(lab.token_requests == 1);
}

TEST_CASE("transient Entra answers are retried five times, then a TransientError",
          "[graph][client]")
{
    const HttpResponse response = GENERATE(
        load_fixture("graph", "token-503-temporarily-unavailable"),
        load_fixture("graph", "token-500-html"), entra_error(400, "invalid_request", 90006),
        entra_error(400, "invalid_request", 90033), entra_error(400, "invalid_request", 90090),
        entra_error(400, "invalid_request", 50033), entra_error(400, "invalid_request", 90055),
        entra_error(400, "temporarily_unavailable", std::nullopt),
        entra_error(500, "server_error", std::nullopt), entra_error(502, "whatever", 12345),
        make_response(504, ""), make_response(429, ""),
        make_response(429, R"({"error":"too_many_requests"})"),
        make_response(503, "Service Unavailable", "text/plain"));
    CAPTURE(response.status, response.body);
    Lab lab;
    lab.token_always(response);

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.status == response.status);
    CHECK_THAT(caught.what, ContainsSubstring("after 5 attempts"));
    CHECK(lab.token_requests == rp::kMaxHttpAttempts);
    // The first wait is at least 5 s, as Microsoft asks for Entra's errors;
    // later ones follow rp::retry_delay() (jitter 0: 1, 2, 4, 8 s).
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{5s, 5s, 5s, 8s});
    CHECK(lab.bearers().empty());
}

TEST_CASE("a reply that isn't Entra's JSON is a GraphError that doesn't quote it",
          "[graph][client]")
{
    const HttpResponse response = GENERATE(
        make_response(400, "<html><body>Bad Request ECHOED-BODY</body></html>", "text/html"),
        make_response(404, "ECHOED-BODY not found", "text/plain"),
        make_response(401, ""), make_response(400, R"({"message":"ECHOED-BODY"})"),
        make_response(403, R"(["ECHOED-BODY"])"), make_response(400, R"({"error":42})"));
    CAPTURE(response.status, response.body);
    Lab lab;
    lab.token_always(response);

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == response.status);
    CHECK(caught.what.find("ECHOED-BODY") == std::string::npos);
    CHECK(caught.what.find("<html") == std::string::npos);
    CHECK(lab.token_requests == 1);
}

TEST_CASE("a 500 page from a proxy is never quoted either", "[graph][client]")
{
    Lab lab;
    lab.token_always(load_fixture("graph", "token-500-html"));

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.what.find("<html") == std::string::npos);
    CHECK(caught.what.find("Echoed request") == std::string::npos);
}

TEST_CASE("a redirect from the token endpoint is a GraphError and isn't followed",
          "[graph][client]")
{
    const int status = GENERATE(301, 302, 303, 307, 308);
    CAPTURE(status);
    HttpResponse response = load_fixture("graph", "token-302-redirect");
    response.status = status;
    Lab lab;
    lab.token_always(response);

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == status);
    CHECK_THAT(caught.what, ContainsSubstring("HTTP " + std::to_string(status)));
    CHECK_THAT(caught.what, ContainsSubstring("redirect"));
    // One request in all: nothing went to the Location (the fake has no
    // route there and would have thrown std::logic_error).
    CHECK(lab.http.requests().size() == 1);
    CHECK(lab.waits().empty());
}

TEST_CASE("a transport failure is resent with a new assertion", "[graph][client]")
{
    // Unlike Veeam's token request, every kind is resent, dropped connections
    // and timeouts included: each attempt is a new assertion, and a token
    // request changes nothing on Entra's side.
    const rp::TransportError error =
        GENERATE(rp::TransportError::connect, rp::TransportError::dropped,
                 rp::TransportError::timeout, rp::TransportError::handshake);
    CAPTURE(static_cast<int>(error));
    Lab lab;
    lab.set_on_token([error](int n, const HttpRequest&) -> HttpResponse {
        if (n <= 2) {
            throw rp::HttpError("POST " + kTokenUrl + ": no response", error, 0, 1);
        }
        return token_response("token-" + std::to_string(n));
    });

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "none");
    CHECK(lab.token_requests == 3);
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{5s, 5s});
    const std::vector<std::string> assertions = lab.assertions();
    CHECK(std::set<std::string>(assertions.begin(), assertions.end()).size() == 3);
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer token-3"});
}

TEST_CASE("five transport failures in a row are a TransientError", "[graph][client]")
{
    Lab lab;
    lab.set_on_token([](int, const HttpRequest&) -> HttpResponse {
        throw rp::HttpError("POST " + kTokenUrl + ": timed out", rp::TransportError::timeout, 0,
                            1);
    });

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.status == 0);
    CHECK_THAT(caught.what, ContainsSubstring("timed out"));
    CHECK_THAT(caught.what, ContainsSubstring("after 5 attempts"));
    CHECK(lab.token_requests == 5);
}

TEST_CASE("a TLS or local failure is a GraphError, sent once", "[graph][client]")
{
    const rp::TransportError error = GENERATE(rp::TransportError::tls, rp::TransportError::other);
    CAPTURE(static_cast<int>(error));
    Lab lab;
    lab.set_on_token([error](int, const HttpRequest&) -> HttpResponse {
        throw rp::HttpError("POST " + kTokenUrl + ": certificate verify failed", error, 0, 1);
    });

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK_THAT(caught.what, ContainsSubstring("certificate verify failed"));
    CHECK(lab.token_requests == 1);
}

TEST_CASE("Retry-After on a 429 or 503 sets the wait, never below the backoff",
          "[graph][client]")
{
    struct Row {
        int status;
        std::string retry_after;
        std::chrono::milliseconds wait;
    };
    const Row row = GENERATE(values<Row>({
        {429, "30", 30s},
        {503, "30", 30s},
        {429, " 45\t", 45s},
        {429, "Mon, 28 Sep 2026 12:00:45 GMT", 45s},
        {503, "Mon, 28 Sep 2026 12:02:00 GMT", 120s},
        // Below the backoff, past, junk, or on another status: the backoff.
        {429, "2", 5s},
        {429, "0", 5s},
        {429, "Mon, 28 Sep 2026 11:00:00 GMT", 5s},
        {429, "soon", 5s},
        {429, "-30", 5s},
        {429, "1.5", 5s},
        {500, "30", 5s},
        {502, "30", 5s},
    }));
    CAPTURE(row.status, row.retry_after);
    Lab lab;
    lab.set_on_token([row](int n, const HttpRequest&) {
        if (n == 1) {
            HttpResponse response = entra_error(row.status, "temporarily_unavailable", std::nullopt);
            response.headers["Retry-After"] = row.retry_after;
            return response;
        }
        return token_response("token-" + std::to_string(n));
    });

    CHECK(get_once(lab).kind == "none");
    CHECK(lab.token_requests == 2);
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{row.wait});
}

TEST_CASE("the recorded 429's Retry-After is honoured", "[graph][client]")
{
    Lab lab;
    lab.set_on_token([](int n, const HttpRequest&) {
        return n == 1 ? load_fixture("graph", "token-429-retry-after")
                      : token_response("token-" + std::to_string(n));
    });

    CHECK(get_once(lab).kind == "none");
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{60s});
}

TEST_CASE("a Retry-After over 120 s ends the call at once, carrying it", "[graph][client]")
{
    struct Row {
        std::string retry_after;
        std::chrono::seconds expected;
    };
    const Row row = GENERATE(values<Row>({
        {"121", 121s},
        {"3600", 3600s},
        {"Mon, 28 Sep 2026 13:00:00 GMT", 3600s},
    }));
    CAPTURE(row.retry_after);
    HttpResponse response = make_response(429, "");
    response.headers["Retry-After"] = row.retry_after;
    Lab lab;
    lab.token_always(response);

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.status == 429);
    CHECK(caught.retry_after == row.expected);
    CHECK_THAT(caught.what, ContainsSubstring(std::to_string(row.expected.count()) + " s"));
    CHECK(lab.token_requests == 1);
    CHECK(lab.waits().empty());
}

TEST_CASE("a Retry-After too large for any number is over the cap, not wrapped",
          "[graph][client]")
{
    HttpResponse response = make_response(503, "");
    response.headers["Retry-After"] = "99999999999999999999999999";
    Lab lab;
    lab.token_always(response);

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    REQUIRE(caught.retry_after.has_value());
    CHECK(*caught.retry_after > rp::graph::kMaxRetryWait);
    CHECK(lab.token_requests == 1);
}

TEST_CASE("the waits of one call stay within 300 s in all", "[graph][client]")
{
    HttpResponse response = make_response(429, "");
    response.headers["Retry-After"] = "100";
    Lab lab;
    lab.token_always(response);

    const Caught caught = get_once(lab);

    // 100 + 100 + 100 = 300 s is allowed; a fourth wait would pass it.
    CHECK(caught.kind == "TransientError");
    CHECK(caught.retry_after == 100s);
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{100s, 100s, 100s});
    CHECK(lab.token_requests == 4);
    CHECK_THAT(caught.what, ContainsSubstring("300 s"));
}

TEST_CASE("Retry-After values parse as delta-seconds or an IMF-fixdate", "[graph][client]")
{
    struct Row {
        std::string value;
        std::optional<std::int64_t> seconds;
    };
    const Row row = GENERATE(values<Row>({
        {"0", 0},
        {"120", 120},
        {"007", 7},
        {" \t30 ", 30},
        {"Mon, 28 Sep 2026 12:00:01 GMT", 1},
        {"Tue, 29 Sep 2026 12:00:00 GMT", 86400},
        {"Mon, 28 Sep 2026 12:00:00 GMT", 0},
        {"Sun, 06 Nov 1994 08:49:37 GMT", 0}, // past: no wait
        {"Thu, 01 Jan 2099 00:00:00 GMT", 2280312000},
        // The day name isn't checked against the date.
        {"Fri, 28 Sep 2026 12:00:10 GMT", 10},
        // Junk and the obsolete forms: ignored.
        {"", std::nullopt},
        {" ", std::nullopt},
        {"-1", std::nullopt},
        {"+5", std::nullopt},
        {"1.5", std::nullopt},
        {"1e3", std::nullopt},
        {"30s", std::nullopt},
        {"3 0", std::nullopt},
        {"Monday, 28-Sep-26 12:00:01 GMT", std::nullopt},
        {"Mon Sep 28 12:00:01 2026", std::nullopt},
        {"Mon, 28 Sep 2026 12:00:01 UTC", std::nullopt},
        {"Mon, 28 Sep 2026 12:00:01 GMT ", 1},
        {"Mon, 28 Sep 2026 12:00:01GMT", std::nullopt},
        {"Mon, 31 Sep 2026 12:00:00 GMT", std::nullopt},
        {"Mon, 29 Feb 2026 12:00:00 GMT", std::nullopt},
        {"Mon, 28 Sep 2026 24:00:00 GMT", std::nullopt},
        {"Mon, 28 Sep 2026 12:60:00 GMT", std::nullopt},
        {"Mon, 28 Sep 2026 12:00:61 GMT", std::nullopt},
        {"Mon, 28 Sept 2026 12:00:00 GMT", std::nullopt},
        {"Mon, 28 sep 2026 12:00:00 GMT", std::nullopt},
        {"Xyz, 28 Sep 2026 12:00:00 GMT", std::nullopt},
        {"Mon, 8 Sep 2026 12:00:00 GMT", std::nullopt},
        {"Mon, 28 Sep 26 12:00:00 GMT", std::nullopt},
        {"Mon, 2a Sep 2026 12:00:00 GMT", std::nullopt},
    }));
    CAPTURE(row.value);
    const std::optional<std::chrono::seconds> parsed = rp::graph::parse_retry_after(row.value, kNow);
    if (row.seconds) {
        REQUIRE(parsed.has_value());
        CHECK(parsed->count() == *row.seconds);
    } else {
        CHECK_FALSE(parsed.has_value());
    }
}

TEST_CASE("huge delta-seconds saturate instead of wrapping", "[graph][client]")
{
    const std::string value = GENERATE(as<std::string>{}, "9223372036854775807",
                                       "9223372036854775808", std::string(400, '9'));
    const auto parsed = rp::graph::parse_retry_after(value, kNow);
    REQUIRE(parsed.has_value());
    CHECK(*parsed > std::chrono::seconds{1'000'000'000});
}

TEST_CASE("a token reply without a usable token is a GraphError that doesn't quote it",
          "[graph][client]")
{
    const std::string tok = "SentinelTok-9f3e";
    const std::string body = GENERATE_COPY(
        std::string{"SentinelTok-9f3e is not JSON"}, std::string{R"(["SentinelTok-9f3e"])"},
        R"({"token_type":"Bearer","expires_in":3599})",
        R"({"token_type":"Bearer","expires_in":3599,"access_token":""})",
        R"({"token_type":"Bearer","expires_in":3599,"access_token":5})",
        R"({"token_type":"Bearer","expires_in":3599,"access_token":null})",
        R"({"expires_in":3599,"access_token":")" + tok + R"("})",
        R"({"token_type":"mac","expires_in":3599,"access_token":")" + tok + R"("})",
        R"({"token_type":"pop","expires_in":3599,"access_token":")" + tok + R"("})",
        R"({"token_type":1,"expires_in":3599,"access_token":")" + tok + R"("})",
        R"({"token_type":"Bearer","access_token":")" + tok + R"("})",
        R"({"token_type":"Bearer","expires_in":0,"access_token":")" + tok + R"("})",
        R"({"token_type":"Bearer","expires_in":-1,"access_token":")" + tok + R"("})",
        R"({"token_type":"Bearer","expires_in":"3599","access_token":")" + tok + R"("})",
        R"({"token_type":"Bearer","expires_in":3599.5,"access_token":")" + tok + R"("})",
        R"({"token_type":"Bearer","expires_in":null,"access_token":")" + tok + R"("})",
        // A token that would break or forge a header line.
        R"({"token_type":"Bearer","expires_in":3599,"access_token":")" + tok + R"( x"})",
        R"({"token_type":"Bearer","expires_in":3599,"access_token":")" + tok +
            R"(\r\nX-Evil: 1"})",
        R"({"token_type":"Bearer","expires_in":3599,"access_token":")" + tok + R"(é"})",
        R"({"token_type":"Bearer","expires_in":3599,"access_token":")" + tok + R"(\u0000"})");
    CAPTURE(body);
    Lab lab;
    lab.token_always(make_response(200, body));

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == 200);
    CHECK(caught.what.find(tok) == std::string::npos);
    CHECK(lab.log().find(tok) == std::string::npos);
    CHECK(lab.token_requests == 1);
    CHECK(lab.bearers().empty());
}

TEST_CASE("callers waiting behind a failed token request share its failure", "[graph][client]")
{
    constexpr int kThreads = 8;
    Lab lab;
    std::atomic<int> ready = 0;
    lab.set_on_token([&ready](int, const HttpRequest&) {
        // Every caller has started; give them time to queue on the lock.
        while (ready.load() < kThreads) {
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(100ms);
        return load_fixture("graph", "token-bad-signature-401");
    });
    auto client = lab.make_client();

    std::atomic<int> auth = 0;
    std::atomic<int> other = 0;
    {
        std::vector<std::jthread> threads;
        for (int i = 0; i < kThreads; ++i) {
            threads.emplace_back([&] {
                ++ready;
                try {
                    client->get(kMessagesPath, rp::graph::kMailReadGrant);
                } catch (const rp::graph::AuthError&) {
                    ++auth;
                } catch (...) {
                    ++other; // checked after the join: nothing escapes a thread
                }
            });
        }
    }

    CHECK(other == 0);
    CHECK(auth == kThreads);
    CHECK(lab.token_requests == 1);

    // A later call is a new attempt, not the old failure.
    lab.set_on_token([](int n, const HttpRequest&) {
        return token_response("token-" + std::to_string(n));
    });
    CHECK(catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); }).kind ==
          "none");
    CHECK(lab.token_requests == 2);
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer token-2"});
}

TEST_CASE("the constructor's certificate error comes before any request", "[graph][client]")
{
    // certificate_from_secrets throws before a GraphClient exists: nothing
    // can be sent with a PFX the Worker can't use.
    rp::test::FakeHttpClient http;
    rp::Secrets secrets;
    secrets.graph_cert_pfx_base64 = pfx_base64();
    secrets.graph_cert_password = "wrong";
    CHECK(catch_graph([&] {
              GraphClient{http, kTenant, kClient,
                          rp::graph::certificate_from_secrets(secrets, kNow)};
          }).kind == "CertificateError");
    CHECK(http.requests().empty());
}

TEST_CASE("get() refuses anything but a path before any request", "[graph][client]")
{
    const std::string target = GENERATE(as<std::string>{}, "", "users/x",
                                        "https://graph.microsoft.com/v1.0/users/x",
                                        "https://evil.example/v1.0/users/x");
    CAPTURE(target);
    Lab lab;
    auto client = lab.make_client();

    CHECK(catch_graph([&] { client->get(target, rp::graph::kMailReadGrant); }).kind ==
          "GraphError");
    CHECK(lab.http.requests().empty());
}

TEST_CASE("a Graph error status is a GraphError for now", "[graph][client]")
{
    // W2.1's next step maps 401, 403, 404, 429 and 5xx; until then any non-2xx
    // is at least an error, never a response taken for data.
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {load_fixture("graph", "messages-403-exchange")});

    const Caught caught = get_once(lab);

    CHECK_FALSE(caught.kind == "none");
    CHECK(caught.status == 403);
    CHECK(caught.code == "ErrorAccessDenied");
    CHECK(caught.request_id == "a6273daa-7ac8-44a8-bda9-b9d8e07d0a45");
    CHECK(caught.what.find("$top") == std::string::npos);
}

TEST_CASE("a Graph error keeps innerError's code and request ID", "[graph][client]")
{
    struct Row {
        HttpResponse response;
        std::string code;
        std::string inner_code;
        std::string request_id;
    };
    HttpResponse lower_case = make_response(
        404, R"({"error":{"code":"itemNotFound","message":"Item not found",)"
             R"("innererror":{"code":"resourceNotFound","request-id":"from-body"}}})");
    lower_case.headers["request-id"] = "from-header";
    const Row row = GENERATE_COPY(values<Row>({
        {load_fixture("graph", "site-403-accessdenied"), "accessDenied", "",
         "fc57d2c2-4ef3-48fe-ac0b-bd0c465230fa"},
        {lower_case, "itemNotFound", "resourceNotFound", "from-body"},
        {make_response(500, R"({"error":{"code":"x","innerError":"not an object"}})"), "x", "", ""},
    }));
    CAPTURE(row.response.body);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {row.response});
    auto client = lab.make_client();

    try {
        client->get(kMessagesPath, rp::graph::kMailReadGrant);
        FAIL("get() returned after an error status");
    } catch (const rp::graph::GraphError& e) {
        CHECK(e.status() == row.response.status);
        CHECK(e.code() == row.code);
        CHECK(e.inner_code() == row.inner_code);
        CHECK(e.request_id() == row.request_id);
        if (!row.request_id.empty()) {
            CHECK_THAT(std::string{e.what()}, ContainsSubstring("(request ID " + row.request_id + ")"));
        }
    }
}

TEST_CASE("a Graph GET that gets no response is a TransientError, a TLS failure a GraphError",
          "[graph][client]")
{
    struct Row {
        rp::TransportError error;
        std::string kind;
    };
    const Row row = GENERATE(values<Row>({
        {rp::TransportError::timeout, "TransientError"},
        {rp::TransportError::connect, "TransientError"},
        {rp::TransportError::tls, "GraphError"},
        {rp::TransportError::other, "GraphError"},
    }));
    CAPTURE(row.kind);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, [row](const HttpRequest&) -> HttpResponse {
        throw rp::HttpError("GET " + kMessagesUrl + ": no response", row.error, 0, 1);
    });

    const Caught caught = get_once(lab);

    CHECK(caught.kind == row.kind);
    CHECK_THAT(caught.what, ContainsSubstring("Graph GET /v1.0/users/"));
}

TEST_CASE("a client with default clocks and jitter signs in and waits at least 5 s",
          "[graph][client]")
{
    Lab lab;
    lab.set_on_token([](int n, const HttpRequest&) -> HttpResponse {
        if (n == 1) {
            throw rp::HttpError("POST " + kTokenUrl + ": timed out", rp::TransportError::timeout,
                                0, 1);
        }
        return token_response("token-" + std::to_string(n));
    });
    GraphClientOptions options;
    options.sleep = [&lab](std::chrono::milliseconds wait) {
        const std::lock_guard lock(lab.mutex);
        lab.sleeps.push_back(wait);
    };
    GraphClient client(lab.http, kTenant, kClient, certificate(), options);

    CHECK(client.get(kMessagesPath, rp::graph::kMailReadGrant).status == 200);
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{5s});
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer token-2"});
}

TEST_CASE("nothing secret reaches an error message or the log", "[graph][client]")
{
    // A whole session at trace level: a timeout, a refusal, a garbled reply,
    // a token, a renewal. The assertion, the tokens, the PFX and its password
    // go out in bodies and headers, which are never logged.
    const std::string token_1 = "eyJ0eXAiOiJKV1QifQ.eyJzZW50aW5lbCI6MX0.U2VudGluZWxUb2tlbk9uZQ";
    const std::string token_2 = "SentinelAccessTokenTwo";
    Lab lab;
    lab.set_on_token([&](int n, const HttpRequest&) -> HttpResponse {
        switch (n) {
        case 1:
            throw rp::HttpError("POST " + kTokenUrl + ": timed out", rp::TransportError::timeout,
                                0, 1);
        case 2:
            return load_fixture("graph", "token-bad-signature-401");
        case 3:
            return make_response(200, R"({"token_type":"mac","expires_in":3599,"access_token":")" +
                                          token_1 + R"("})");
        case 4:
            return token_response(token_1);
        default:
            return token_response(token_2);
        }
    });
    auto client = lab.make_client();

    std::vector<std::string> messages;
    for (int i = 0; i < 4; ++i) {
        const Caught caught =
            catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); });
        messages.push_back(caught.what);
        lab.advance(3600s);
    }

    CHECK(lab.token_requests == 5);
    CHECK(lab.bearers() ==
          std::vector<std::string>{"Bearer " + token_1, "Bearer " + token_2});
    std::vector<std::string> secrets = lab.assertions();
    secrets.insert(secrets.end(), {token_1, token_2, kPfxPassword, pfx_base64().substr(0, 16),
                                   pfx_base64().substr(pfx_base64().size() / 2, 16)});
    const std::string log = lab.log();
    CAPTURE(log);
    CHECK_THAT(log, ContainsSubstring("retrying"));
    CHECK_THAT(log, ContainsSubstring("token expires in 3599 s"));
    for (const std::string& secret : secrets) {
        CHECK(log.find(secret) == std::string::npos);
        for (const std::string& message : messages) {
            CHECK(message.find(secret) == std::string::npos);
        }
    }
}

// --- Happy paths --------------------------------------------------------------

TEST_CASE("the token request is a client-credentials grant with a fresh assertion",
          "[graph][client]")
{
    Lab lab;
    auto client = lab.make_client();

    client->get(kMessagesPath, rp::graph::kMailReadGrant);

    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 2);
    const HttpRequest& token = sent[0];
    CHECK(token.method == HttpMethod::post);
    CHECK(token.url == kTokenUrl);
    CHECK(token.content_type == "application/x-www-form-urlencoded");
    const std::string assertion = form_value(token.body, "client_assertion");
    CHECK(token.body ==
          "client_id=" + kClient + "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"
          "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
          "&client_assertion=" + assertion + "&grant_type=client_credentials");
    CHECK(header(token, "Authorization") == "(none)");
    CHECK(header(token, "Accept") == "application/json");
    CHECK(header(token, "User-Agent") == "ISV|RestoreProof|RestoreProofWorker/" RP_VERSION);
    CHECK_FALSE(token.retry_on_status);
    CHECK(token.max_attempts == 1);
    CHECK(token.timeout == 45s);

    // The assertion is this client's, signed now.
    const std::size_t dot = assertion.find('.');
    REQUIRE(dot != std::string::npos);
    const std::size_t dot2 = assertion.find('.', dot + 1);
    REQUIRE(dot2 != std::string::npos);
    std::string payload = assertion.substr(dot + 1, dot2 - dot - 1);
    for (char& c : payload) {
        c = c == '-' ? '+' : c == '_' ? '/' : c;
    }
    while (payload.size() % 4 != 0) {
        payload += '=';
    }
    const auto decoded = rp::base64_decode(payload);
    REQUIRE(decoded.has_value());
    const json claims = json::parse(std::string(decoded->begin(), decoded->end()));
    CHECK(claims.at("aud") == kTokenUrl);
    CHECK(claims.at("iss") == kClient);
    CHECK(claims.at("sub") == kClient);
    CHECK(claims.at("nbf") == Clock::to_time_t(kNow));

    const HttpRequest& call = sent[1];
    CHECK(call.method == HttpMethod::get);
    CHECK(call.url == kMessagesUrl);
    CHECK(header(call, "Authorization") == "Bearer token-1");
    CHECK(header(call, "Accept") == "application/json");
    CHECK(header(call, "User-Agent") == "ISV|RestoreProof|RestoreProofWorker/" RP_VERSION);
    CHECK_FALSE(call.retry_on_status);
    CHECK(call.max_attempts == 1);
    CHECK(call.timeout == 45s);
}

TEST_CASE("user_agent names the ISV, the product and the version", "[graph][client]")
{
    CHECK(rp::graph::user_agent() == "ISV|RestoreProof|RestoreProofWorker/" RP_VERSION);
}

TEST_CASE("get() returns the recorded inbox", "[graph][client]")
{
    Lab lab;
    auto client = lab.make_client();

    const HttpResponse response = client->get(kMessagesPath, rp::graph::kMailReadGrant);

    CHECK(response.status == 200);
    CHECK(json::parse(response.body).at("value") == json::array());
}

TEST_CASE("the token is kept and used for later calls", "[graph][client]")
{
    Lab lab;
    auto client = lab.make_client();

    for (int i = 0; i < 3; ++i) {
        client->get(kMessagesPath, rp::graph::kMailReadGrant);
        lab.advance(1000s);
    }

    CHECK(lab.token_requests == 1);
    CHECK(lab.bearers() ==
          std::vector<std::string>{"Bearer token-1", "Bearer token-1", "Bearer token-1"});
}

TEST_CASE("the token is renewed 60 s before it expires, or at half a short lifetime",
          "[graph][client]")
{
    struct Row {
        std::int64_t expires_in;
        std::chrono::milliseconds renew_after;
    };
    const Row row = GENERATE(values<Row>({
        {3599, 3539s},
        {121, 61s},
        {120, 60s},
        {100, 50s},
        {1, 500ms},
        // Capped at a day.
        {86401, 86340s},
        {1'000'000'000'000, 86340s},
    }));
    CAPTURE(row.expires_in);
    Lab lab;
    lab.set_on_token([row](int n, const HttpRequest&) {
        return token_response("token-" + std::to_string(n), row.expires_in);
    });
    auto client = lab.make_client();

    client->get(kMessagesPath, rp::graph::kMailReadGrant);
    lab.advance(row.renew_after - 1ms);
    client->get(kMessagesPath, rp::graph::kMailReadGrant);
    CHECK(lab.token_requests == 1);
    lab.advance(1ms);
    client->get(kMessagesPath, rp::graph::kMailReadGrant);
    CHECK(lab.token_requests == 2);
    CHECK(lab.bearers() ==
          std::vector<std::string>{"Bearer token-1", "Bearer token-1", "Bearer token-2"});
}

TEST_CASE("token_type Bearer is accepted in any case", "[graph][client]")
{
    const std::string type = GENERATE("Bearer", "bearer", "BEARER", "bEaReR");
    Lab lab;
    lab.token_always(make_response(
        200, R"({"token_type":")" + type + R"(","expires_in":3599,"access_token":"t"})"));

    CHECK(get_once(lab).kind == "none");
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer t"});
}

TEST_CASE("concurrent calls share one token request", "[graph][client]")
{
    constexpr int kThreads = 8;
    Lab lab;
    lab.set_on_token([](int n, const HttpRequest&) {
        // Long enough for every other thread to be waiting on the lock.
        std::this_thread::sleep_for(50ms);
        return token_response("token-" + std::to_string(n));
    });
    auto client = lab.make_client();

    std::atomic<int> succeeded = 0;
    std::atomic<int> failed = 0;
    {
        std::vector<std::jthread> threads;
        for (int i = 0; i < kThreads; ++i) {
            threads.emplace_back([&] {
                try {
                    if (client->get(kMessagesPath, rp::graph::kMailReadGrant).status == 200) {
                        ++succeeded;
                    }
                } catch (...) {
                    ++failed; // an exception escaping a thread would end the run
                }
            });
        }
    }

    CHECK(failed == 0);
    CHECK(succeeded == kThreads);
    CHECK(lab.token_requests == 1);
    for (const std::string& bearer : lab.bearers()) {
        CHECK(bearer == "Bearer token-1");
    }
}
