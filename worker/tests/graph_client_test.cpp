// W2.1: GraphClient against the recorded Entra and Graph replies in
// tests/fixtures/graph/ (README.md there), served by FakeHttpClient. The
// token: the AADSTS error table, redirects, retries and their waits, the
// reply checks, the cache and its renewal, single-flight renewals. GET: the
// URLs the token may go to, 401 and a fresh token, 403 naming the grant, 404,
// 429/5xx/transport retries within their caps, redirects, get_json and
// paging. No secret in any message or log line. Nothing here touches the
// network.

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
#include <iterator>
#include <cctype>
#include <fstream>
#include <filesystem>
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
        return Caught{"CertificateError", e.what()};
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

// The request ID a recorded Graph reply carries, as GraphError reads it:
// innerError's request-id, else the request-id header. A re-recording
// (record-graph-fixtures) changes it, so tests read it rather than spell it out.
std::string recorded_request_id(const std::string& fixture)
{
    const json doc = load_fixture_json("graph", fixture);
    const json& body = doc.at("body");
    if (body.is_object() && body.contains("error") && body.at("error").is_object()) {
        for (const auto& [key, inner] : body.at("error").items()) {
            std::string lower = key;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lower == "innererror" && inner.is_object() && inner.contains("request-id")) {
                return inner.at("request-id").get<std::string>();
            }
        }
    }
    return doc.at("headers").at("request-id").get<std::string>();
}

// The user of messages-404-unknown-user: a random name the recorder draws on
// every run, which Graph quotes in its message ('nobody-...@domain').
std::string recorded_unknown_user()
{
    const std::string message = load_fixture_json("graph", "messages-404-unknown-user")
                                    .at("body")
                                    .at("error")
                                    .at("message")
                                    .get<std::string>();
    const std::size_t open = message.find('\'');
    const std::size_t close = message.find('\'', open + 1);
    REQUIRE(open != std::string::npos);
    REQUIRE(close != std::string::npos);
    return message.substr(open + 1, close - open - 1);
}

} // namespace

// Review of W2.1: lab/README.md tells people to re-run record-graph-fixtures,
// which rewrites every live fixture with new request IDs, trace IDs and a new
// random user. A test that spells one of those out turns red on the next
// recording: this scan finds any in the Worker's test sources.
TEST_CASE("no test spells out a value a live re-recording changes", "[graph][client]")
{
    const std::filesystem::path tests_dir = std::filesystem::path{RP_SOURCE_DIR} / "tests";
    // GUIDs a re-recording keeps: the lab's tenant and app, Graph's own app.
    const std::set<std::string> stable{
        kTenant, kClient, "00000003-0000-0000-c000-000000000000",
        // the lab's RestoreTest site and web and its RestoreTarget list (sharePointIds in restoretarget-drive-200.json): fixed since L1.4
        "fe08085d-eb70-42e8-95a6-470189bd98eb", "4ecaf399-cc0e-4d95-b3fe-cd091a09e689",
        "ffec069d-65e4-4c3a-9da2-ac086cf9dafa",
        // alice's OneDrive as a site: its site, web and Documents list (sharepointIds in onedrive-folder-200.json), fixed while her OneDrive exists; graph_ids_test.cpp derives its drive ID from them
        "6d600fc0-65f8-4811-ad18-096ec5b7e834", "98cfff1a-b404-4438-ae6e-6927a6ccc325",
        "1a9f64df-d9fd-4302-af7a-457d2beff537"};
    const auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    // Every GUID (8-4-4-4-12 hex digits) and "nobody-<8 hex>" in `text`.
    const auto volatile_values = [&](const std::string& text) {
        std::set<std::string> out;
        constexpr std::string_view shape = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        for (std::size_t at = 0; at + shape.size() <= text.size(); ++at) {
            bool guid = at == 0 || !is_hex(text[at - 1]);
            for (std::size_t i = 0; guid && i < shape.size(); ++i) {
                guid = shape[i] == '-' ? text[at + i] == '-' : is_hex(text[at + i]);
            }
            if (guid && (at + shape.size() == text.size() || !is_hex(text[at + shape.size()]))) {
                out.insert(text.substr(at, shape.size()));
            }
        }
        for (std::size_t at = text.find("nobody-"); at != std::string::npos;
             at = text.find("nobody-", at + 1)) {
            const std::string name = text.substr(at, 15);
            if (name.size() == 15 && std::all_of(name.begin() + 7, name.end(), is_hex)) {
                out.insert(name);
            }
        }
        return out;
    };
    const auto read = [](const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), {});
    };

    std::set<std::string> recorded;
    for (const auto& entry : std::filesystem::directory_iterator(tests_dir / "fixtures" / "graph")) {
        if (entry.path().extension() != ".json") {
            continue;
        }
        const std::string text = read(entry.path());
        if (json::parse(text).value("source", "").starts_with("live")) {
            for (const std::string& value : volatile_values(text)) {
                if (!stable.contains(value)) {
                    recorded.insert(value);
                }
            }
        }
    }
    REQUIRE_FALSE(recorded.empty());

    for (const auto& entry : std::filesystem::directory_iterator(tests_dir)) {
        const std::string ext = entry.path().extension().string();
        if (ext != ".cpp" && ext != ".hpp") {
            continue;
        }
        const std::string source = read(entry.path());
        for (const std::string& value : recorded) {
            CAPTURE(entry.path().filename().string(), value);
            CHECK(source.find(value) == std::string::npos);
        }
    }
}

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
        {"Tue, 01 Jan 2030 00:00:00 GMT", 102859200},
        // More than 1e9 s away is kept as 1e9 s (about 31 years): a date past
        // the year MSVC's int minutes wrap at (about 6053) included.
        {"Thu, 01 Jan 2099 00:00:00 GMT", 1'000'000'000},
        {"Mon, 01 Jan 6053 00:00:00 GMT", 1'000'000'000},
        {"Tue, 01 Jan 6054 00:00:00 GMT", 1'000'000'000},
        {"Fri, 31 Dec 9999 23:59:59 GMT", 1'000'000'000},
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
    // 1e9 s: over any cap, and small enough to add to either clock's now().
    const std::string value =
        GENERATE(as<std::string>{}, "1000000001", "9223372036854775807", "9223372036854775808",
                 std::string(400, '9'));
    const auto parsed = rp::graph::parse_retry_after(value, kNow);
    REQUIRE(parsed.has_value());
    CHECK(*parsed == std::chrono::seconds{1'000'000'000});
    CHECK_NOTHROW(std::chrono::steady_clock::now() + *parsed);
    CHECK(Clock::now() + *parsed > Clock::now());
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

// --- GET: where the token may go ---------------------------------------------

TEST_CASE("get() sends the token nowhere but https://graph.microsoft.com/v1.0/",
          "[graph][client][get]")
{
    // Refused before anything is sent, the token request included: an
    // @odata.nextLink (or a path) that points elsewhere, or that curl might
    // read differently from a text compare, never gets the token.
    const std::string target = GENERATE(
        as<std::string>{}, "", "users/x", "v1.0/users/x", "graph.microsoft.com/v1.0/users/x",
        // Another host that starts or ends like Graph's.
        "https://graph.microsoft.com.evil.example/v1.0/users/x",
        "https://evilgraph.microsoft.com/v1.0/users/x", "https://evil.example/v1.0/users/x",
        "https://login.microsoftonline.com/common/v1.0/users/x",
        "https://graph.microsoft.us/v1.0/users/x",
        "https://microsoftgraph.chinacloudapi.cn/v1.0/users/x",
        // Not https, or not spelled exactly so.
        "http://graph.microsoft.com/v1.0/users/x", "HTTPS://GRAPH.MICROSOFT.COM/v1.0/users/x",
        "https:/graph.microsoft.com/v1.0/users/x", "https:///graph.microsoft.com/v1.0/users/x",
        "//graph.microsoft.com/v1.0/users/x",
        // Userinfo, a port, a trailing dot, an encoded dot or slash, a
        // backslash: all before the path.
        "https://user@graph.microsoft.com/v1.0/users/x",
        "https://graph.microsoft.com@evil.example/v1.0/users/x",
        "https://graph.microsoft.com:443/v1.0/users/x",
        "https://graph.microsoft.com:444/v1.0/users/x",
        "https://graph.microsoft.com./v1.0/users/x",
        "https://graph.microsoft.com.:443/v1.0/users/x",
        "https://graph.microsoft.com%2eevil.example/v1.0/users/x",
        "https://graph.microsoft.com%2Fv1.0/users/x",
        "https://graph.microsoft.com\\@evil.example/v1.0/users/x",
        // Another API version, or v1.0 without its slash.
        "https://graph.microsoft.com/beta/users/x", "https://graph.microsoft.com/v1.0",
        "https://graph.microsoft.com/v1.0?$top=1", "https://graph.microsoft.com/v1.0.evil/users",
        "https://graph.microsoft.com/V1.0/users/x",
        // Whitespace, control characters, a backslash or a fragment anywhere.
        " https://graph.microsoft.com/v1.0/users/x", "https://graph.microsoft.com/v1.0/users/x\t",
        "https://graph.microsoft.com/v1.0/users/x y", "/users/x\ty", "/users/x y",
        "/users/x\r\nHost: evil.example", "/users/x\ny", std::string("/users/x\0y", 10),
        "/users/x\x7f", "/users/x\x1b[0m", "/users\\x", "https://graph.microsoft.com/v1.0/users\\x",
        "/users/x#y", "/users/x?$top=1#y",
        // The UTF-8 control characters of control_chars.hpp as well (review
        // of W2.1): NEL, a line separator, a right-to-left override.
        "/users/x\xC2\x85y", "/users/x\xE2\x80\xA8y", "/users/\xE2\x80\xAEx",
        "https://graph.microsoft.com/v1.0/users/x\xE2\x81\xA6y",
        // An encoded slash or backslash, or a double-encoded dot or separator,
        // which a server decoding first would read as a dot segment.
        "/users/x/..%2f..%2fbeta/me", "/users/x/..%2F..%2Fbeta/me", "/users/..%5c..%5cbeta",
        "/users/%252e%252e/beta", "/users/%252E%252e/beta", "/users/x%252fy", "/users/x%255cy",
        // Dot segments, plain or encoded, which curl would resolve out of v1.0.
        "/../beta/users", "/users/../../beta/users", "/users/./x", "/users/..", "/users/.",
        "https://graph.microsoft.com/v1.0/../beta/users", "/users/%2e%2e/x", "/users/%2E%2e/x",
        "/users/%2e/x", "/%2e%2e/beta/users",
        // An empty segment: a protocol-relative URL passed as a path.
        "//evil.example/v1.0/users/x", "/users//x");
    CAPTURE(target);
    Lab lab;
    auto client = lab.make_client();

    const Caught by_get = catch_graph([&] { client->get(target, rp::graph::kMailReadGrant); });
    const Caught by_json =
        catch_graph([&] { client->get_json(target, rp::graph::kMailReadGrant); });

    CHECK(by_get.kind == "GraphError");
    CHECK(by_json.kind == "GraphError");
    CHECK(by_get.status == 0);
    CHECK_THAT(by_get.what, ContainsSubstring("https://graph.microsoft.com/v1.0/"));
    // Quoted on one line at most: no control character reaches a log.
    CHECK(std::none_of(by_get.what.begin(), by_get.what.end(),
                       [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7F; }));
    CHECK_THAT(by_get.what, !ContainsSubstring("\xC2\x85") && !ContainsSubstring("\xE2\x80\xA8") &&
                                !ContainsSubstring("\xE2\x80\xAE"));
    CHECK(lab.http.requests().empty());
}

// --- GET: 401 ------------------------------------------------------------------

TEST_CASE("a 401 after a fresh token is an AuthError that names the grant", "[graph][client][get]")
{
    struct Row {
        std::string fixture;
        std::string request_id;
    };
    const std::string fixture = GENERATE(as<std::string>{}, "api-invalid-token-401",
                                         "api-no-token-401");
    const Row row{fixture, recorded_request_id(fixture)};
    CAPTURE(row.fixture);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {load_fixture("graph", row.fixture)});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "AuthError");
    CHECK(caught.status == 401);
    CHECK(caught.code == "InvalidAuthenticationToken");
    CHECK(caught.request_id == row.request_id);
    CHECK(caught.what ==
          "Graph GET /v1.0/users/restoretest@RestoreProofLab.onmicrosoft.com/mailFolders/inbox/"
          "messages: HTTP 401 (InvalidAuthenticationToken) again after a fresh token: the Worker "
          "app relies on Exchange RBAC \"Application Mail.Read\" in a management scope covering "
          "the test mailbox; see docs/security/graph-permissions.md (request ID " +
              row.request_id + ")");
    // One fresh token, one resend, no wait.
    CHECK(lab.token_requests == 2);
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer token-1", "Bearer token-2"});
    CHECK(lab.waits().empty());
}

TEST_CASE("a 401 asking for more claims is an AuthError at once", "[graph][client][get]")
{
    HttpResponse upper = load_fixture("graph", "api-no-token-401");
    upper.headers["WWW-Authenticate"] =
        R"(Bearer realm="", ERROR="INSUFFICIENT_CLAIMS", claims="e30=")";
    const HttpResponse response =
        GENERATE_COPY(load_fixture("graph", "api-insufficient-claims-401"), upper);
    CAPTURE(response.headers.at("WWW-Authenticate"));
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {response});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "AuthError");
    CHECK(caught.status == 401);
    CHECK_THAT(caught.what, ContainsSubstring("insufficient_claims"));
    CHECK_THAT(caught.what, ContainsSubstring("Conditional Access"));
    CHECK(lab.token_requests == 1);
    CHECK(lab.bearers().size() == 1);
}

TEST_CASE("a 401 for a token another call has replaced is resent with the current one",
          "[graph][client][get]")
{
    // The first answer comes back after another call has renewed the token
    // (here: while the request was out, the clock passed the renewal and a
    // second call on the same client fetched token-2). The 401 is for the old
    // token, so the call is resent with the current one: no third token.
    const std::string other_url = std::string{rp::graph::kGraphBaseUrl} + "/sites/root";
    Lab lab;
    std::unique_ptr<GraphClient> client;
    std::atomic<int> calls = 0;
    lab.http.on(HttpMethod::get, other_url, {load_fixture("graph", "messages-200")});
    lab.http.on(HttpMethod::get, kMessagesUrl, [&](const HttpRequest&) {
        if (++calls == 1) {
            lab.advance(3600s);
            client->get("/sites/root", rp::graph::kSitesReadGrant);
            return load_fixture("graph", "api-invalid-token-401");
        }
        return load_fixture("graph", "messages-200");
    });
    client = lab.make_client();

    CHECK(client->get(kMessagesPath, rp::graph::kMailReadGrant).status == 200);
    CHECK(lab.token_requests == 2);
    CHECK(lab.bearers() ==
          std::vector<std::string>{"Bearer token-1", "Bearer token-2", "Bearer token-2"});
}

TEST_CASE("a 401 that keeps coming for replaced tokens ends after three resends",
          "[graph][client][get]")
{
    const std::string other_url = std::string{rp::graph::kGraphBaseUrl} + "/sites/root";
    Lab lab;
    std::unique_ptr<GraphClient> client;
    lab.http.on(HttpMethod::get, other_url, {load_fixture("graph", "messages-200")});
    lab.http.on(HttpMethod::get, kMessagesUrl, [&](const HttpRequest&) {
        // Every answer comes back after another call has renewed the token.
        lab.advance(3600s);
        client->get("/sites/root", rp::graph::kSitesReadGrant);
        return load_fixture("graph", "api-invalid-token-401");
    });
    client = lab.make_client();

    const Caught caught =
        catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); });

    CHECK(caught.kind == "AuthError");
    CHECK_THAT(caught.what, ContainsSubstring("again with a newer token"));
    CHECK_THAT(caught.what, ContainsSubstring("Application Mail.Read"));
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 4);
}

TEST_CASE("a replaced token that is due as well counts as the one fresh token",
          "[graph][client][get]")
{
    // The first answer comes back after another call has renewed the token,
    // and the clock has passed that token's renewal too: the call fetches a
    // fresh one, and that is its one fresh token. Another 401 is an AuthError.
    const std::string other_url = std::string{rp::graph::kGraphBaseUrl} + "/sites/root";
    Lab lab;
    std::unique_ptr<GraphClient> client;
    std::atomic<int> calls = 0;
    lab.http.on(HttpMethod::get, other_url, {load_fixture("graph", "messages-200")});
    lab.http.on(HttpMethod::get, kMessagesUrl, [&](const HttpRequest&) {
        if (++calls == 1) {
            lab.advance(3600s);
            client->get("/sites/root", rp::graph::kSitesReadGrant);
            lab.advance(3600s);
        }
        return load_fixture("graph", "api-invalid-token-401");
    });
    client = lab.make_client();

    const Caught caught =
        catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); });

    CHECK(caught.kind == "AuthError");
    CHECK_THAT(caught.what, ContainsSubstring("again after a fresh token"));
    CHECK(lab.token_requests == 3);
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 2);
}

TEST_CASE("a failed token renewal after a 401 is that failure", "[graph][client][get]")
{
    Lab lab;
    lab.set_on_token([](int n, const HttpRequest&) {
        return n == 1 ? token_response("token-1") : load_fixture("graph", "token-bad-signature-401");
    });
    lab.http.on(HttpMethod::get, kMessagesUrl, {load_fixture("graph", "api-invalid-token-401")});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "AuthError");
    CHECK(caught.code == "700027");
    CHECK(lab.bearers().size() == 1);
}

// --- GET: 403, 404 and other refusals --------------------------------------------

TEST_CASE("a 403 is a PermissionError naming the grant the call relies on",
          "[graph][client][get]")
{
    struct Row {
        std::string fixture;
        std::string path;
        rp::graph::Grant grant;
        std::string code;
        std::string request_id;
    };
    Row row = GENERATE(values<Row>({
        {"messages-403-exchange",
         "/users/alice@RestoreProofLab.onmicrosoft.com/mailFolders/inbox/messages?$top=1&$select=id",
         rp::graph::kMailReadGrant, "ErrorAccessDenied", ""},
        {"site-403-accessdenied", "/sites/restoreprooflab.sharepoint.com",
         rp::graph::kSitesReadGrant, "accessDenied", ""},
        {"users-403-requestdenied", "/users?$top=1&$select=id", rp::graph::kMailReadGrant,
         "Authorization_RequestDenied", ""},
    }));
    row.request_id = recorded_request_id(row.fixture);
    CAPTURE(row.fixture);
    const std::string url = std::string{rp::graph::kGraphBaseUrl} + row.path;
    Lab lab;
    lab.http.on(HttpMethod::get, url, {load_fixture("graph", row.fixture)});
    auto client = lab.make_client();

    try {
        client->get(row.path, row.grant);
        FAIL("get() returned after a 403");
    } catch (const rp::graph::PermissionError& e) {
        CHECK(std::string{e.what()} ==
              "Graph denied GET /v1.0" + row.path.substr(0, row.path.find('?')) + " (403 " +
                  row.code + "): the Worker app relies on " +
                  std::string{row.grant.description} +
                  "; see docs/security/graph-permissions.md (request ID " + row.request_id + ")");
        CHECK(e.grant() == row.grant.description);
        CHECK(e.status() == 403);
        CHECK(e.code() == row.code);
        CHECK(e.request_id() == row.request_id);
    }
    // Neither resent nor re-tokened: another token has the same roles.
    CHECK(lab.http.count(HttpMethod::get, url) == 1);
    CHECK(lab.token_requests == 1);
    CHECK(lab.waits().empty());
}

// Review of W2.1: a TLS-inspecting proxy answers a blocked request with its
// own 403 page inside the tunnel. Like a 404 without Graph's JSON, that is no
// verdict of Graph's on the app's permissions.
TEST_CASE("a 403 without Graph's JSON is a GraphError that points at the network, not a "
          "PermissionError",
          "[graph][client][get]")
{
    const HttpResponse response = GENERATE(
        make_response(403, "<html>Forbidden ECHOED-BODY</html>", "text/html"),
        make_response(403, "ECHOED-BODY", "text/plain"),
        make_response(403, R"({"error":"ECHOED-BODY"})"));
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {response});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == 403);
    CHECK(caught.code.empty());
    CHECK(caught.what ==
          "Graph GET /v1.0/users/restoretest@RestoreProofLab.onmicrosoft.com/mailFolders/inbox/"
          "messages: HTTP 403 without Graph's error in the reply: something between this machine "
          "and graph.microsoft.com (a proxy, a firewall) may have refused it");
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 1);
    CHECK(lab.waits().empty());
}

TEST_CASE("a 404 is a NotFoundError with Graph's explanation", "[graph][client][get]")
{
    const std::string user = recorded_unknown_user();
    const std::string path = "/users/" + user + "/mailFolders/inbox/messages?$top=1";
    const std::string url = std::string{rp::graph::kGraphBaseUrl} + path;
    Lab lab;
    lab.http.on(HttpMethod::get, url, {load_fixture("graph", "messages-404-unknown-user")});
    auto client = lab.make_client();

    const Caught caught = catch_graph([&] { client->get(path, rp::graph::kMailReadGrant); });

    CHECK(caught.kind == "NotFoundError");
    CHECK(caught.status == 404);
    CHECK(caught.code == "ErrorInvalidUser");
    CHECK(caught.what == "Graph GET /v1.0/users/" + user +
                             "/mailFolders/inbox/messages: HTTP 404 (ErrorInvalidUser): The "
                             "requested user '" +
                             user + "' is invalid. (request ID " +
                             recorded_request_id("messages-404-unknown-user") + ")");
    CHECK(lab.http.count(HttpMethod::get, url) == 1);
}

// Review of W2.1: get() can't tell a missing mailbox, site or drive (the
// setup is wrong: status `error`) from an item missing from a restore (the
// restore failed: `fail`). An item lookup says so by calling find(), which
// answers a missing item with nullopt; a missing mailbox or user still throws.
TEST_CASE("find() answers an item Graph says is missing with nullopt", "[graph][client][get]")
{
    const HttpResponse response = GENERATE(
        make_response(404, R"({"error":{"code":"ErrorItemNotFound",)"
                           R"("message":"The specified object was not found in the store."}})"),
        make_response(404, R"({"error":{"code":"itemNotFound","message":"Item not found"}})"));
    CAPTURE(response.body);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {response});
    auto client = lab.make_client();

    CHECK_FALSE(client->find(kMessagesPath, rp::graph::kMailReadGrant).has_value());
    CHECK_FALSE(client->find_json(kMessagesPath, rp::graph::kMailReadGrant).has_value());
    // get() is for what must be there: the same 404 is an error.
    CHECK(catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); }).kind ==
          "NotFoundError");
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 3);
}

TEST_CASE("find() still throws for a missing mailbox or user and anything but Graph's 404",
          "[graph][client][get]")
{
    struct Row {
        HttpResponse response;
        std::string kind;
    };
    const Row row = GENERATE(values<Row>({
        {load_fixture("graph", "messages-404-unknown-user"), "NotFoundError"},
        {make_response(404, R"({"error":{"code":"ErrorNonExistentMailbox","message":"x"}})"),
         "NotFoundError"},
        {make_response(404, R"({"error":{"code":"Request_ResourceNotFound","message":"x"}})"),
         "NotFoundError"},
        {load_fixture("graph", "messages-404-mailbox-not-enabled"), "GraphError"},
        {make_response(404, "<html>Not Found</html>", "text/html"), "GraphError"},
        {load_fixture("graph", "messages-403-exchange"), "PermissionError"},
    }));
    CAPTURE(row.response.body);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {row.response});
    auto client = lab.make_client();

    CHECK(catch_graph([&] { client->find(kMessagesPath, rp::graph::kMailReadGrant); }).kind ==
          row.kind);
    CHECK(catch_graph([&] { client->find_json(kMessagesPath, rp::graph::kMailReadGrant); }).kind ==
          row.kind);
}

TEST_CASE("find() returns what is there, as get() does", "[graph][client][get]")
{
    Lab lab;
    auto client = lab.make_client();

    const std::optional<HttpResponse> response =
        client->find(kMessagesPath, rp::graph::kMailReadGrant);
    const std::optional<json> doc = client->find_json(kMessagesPath, rp::graph::kMailReadGrant);

    REQUIRE(response.has_value());
    CHECK(response->status == 200);
    REQUIRE(doc.has_value());
    CHECK(doc->at("value") == json::array());
}

TEST_CASE("a 404 that isn't Graph's JSON is a GraphError, not a NotFoundError",
          "[graph][client][get]")
{
    // A proxy, a gateway or a wrong path: not an item Graph says is missing.
    const HttpResponse response =
        GENERATE(make_response(404, "<html><body>Not Found ECHOED-BODY</body></html>",
                               "text/html"),
                 make_response(404, "ECHOED-BODY", "text/plain"));
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {response});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == 404);
    CHECK_THAT(caught.what, !ContainsSubstring("ECHOED-BODY"));
    CHECK_THAT(caught.what, !ContainsSubstring("<html"));
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 1);
    CHECK(lab.waits().empty());
}

TEST_CASE("a mailbox Graph can't read is a GraphError, not a NotFoundError",
          "[graph][client][get]")
{
    HttpResponse not_supported = load_fixture("graph", "messages-404-mailbox-not-enabled");
    not_supported.body = R"({"error":{"code":"MailboxNotSupportedForRESTAPI",)"
                         R"("message":"REST API is not yet supported for this mailbox."}})";
    HttpResponse as_400 = load_fixture("graph", "messages-404-mailbox-not-enabled");
    as_400.status = 400;
    const HttpResponse response =
        GENERATE_COPY(load_fixture("graph", "messages-404-mailbox-not-enabled"), not_supported,
                      as_400);
    CAPTURE(response.body);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {response});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == response.status);
    CHECK_THAT(caught.code, ContainsSubstring("ForRESTAPI"));
    CHECK_THAT(caught.what, ContainsSubstring("Exchange Online licence"));
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 1);
}

TEST_CASE("other refusals are a GraphError with Graph's code and message, sent once",
          "[graph][client][get]")
{
    const int status = GENERATE(400, 405, 409, 410, 412, 413, 422);
    CAPTURE(status);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl,
                {make_response(status, R"({"error":{"code":"BadRequest",)"
                                       R"("message":"Invalid filter clause"}})")});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == status);
    CHECK(caught.code == "BadRequest");
    CHECK_THAT(caught.what, ContainsSubstring("HTTP " + std::to_string(status) +
                                              " (BadRequest): Invalid filter clause"));
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 1);
    CHECK(lab.waits().empty());
}

TEST_CASE("a Graph error keeps innerError's code and request ID", "[graph][client][get]")
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
         recorded_request_id("site-403-accessdenied")},
        {lower_case, "itemNotFound", "resourceNotFound", "from-body"},
        {make_response(400, R"({"error":{"code":"x","innerError":"not an object"}})"), "x", "", ""},
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

// --- GET: 429, 5xx and transport failures -------------------------------------------

TEST_CASE("a GET's 429 or 503 waits as Retry-After says, never below the backoff",
          "[graph][client][get]")
{
    struct Row {
        int status;
        std::optional<std::string> retry_after;
        std::chrono::milliseconds wait;
    };
    const Row row = GENERATE(values<Row>({
        {429, "3", 3s},
        {503, "10", 10s},
        {429, " 45\t", 45s},
        {429, "Mon, 28 Sep 2026 12:00:45 GMT", 45s},
        {503, "Mon, 28 Sep 2026 12:02:00 GMT", 120s},
        {429, "120", 120s},
        // Below the backoff, past, junk, absent, or on another status: the
        // backoff (1 s before the second attempt).
        {429, "0", 1s},
        {429, "Mon, 28 Sep 2026 11:00:00 GMT", 1s},
        {429, "soon", 1s},
        {429, "-30", 1s},
        {503, std::nullopt, 1s},
        {500, "30", 1s},
        {502, "30", 1s},
        {504, "30", 1s},
    }));
    CAPTURE(row.status, row.retry_after);
    HttpResponse first = make_response(row.status, R"({"error":{"code":"x","message":"busy"}})");
    if (row.retry_after) {
        first.headers["Retry-After"] = *row.retry_after;
    }
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {first, load_fixture("graph", "messages-200")});

    CHECK(get_once(lab).kind == "none");
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{row.wait});
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 2);
    CHECK(lab.token_requests == 1);
}

TEST_CASE("the recorded throttling replies are waited out", "[graph][client][get]")
{
    struct Row {
        std::string fixture;
        std::chrono::milliseconds wait;
    };
    const Row row = GENERATE(values<Row>({
        {"messages-429-throttled", 3s},
        {"messages-503-unavailable", 10s},
    }));
    CAPTURE(row.fixture);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl,
                {load_fixture("graph", row.fixture), load_fixture("graph", "messages-200")});

    CHECK(get_once(lab).kind == "none");
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{row.wait});
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring("retrying in"));
    CHECK(log.find("$select") == std::string::npos);
}

TEST_CASE("429 and 5xx are tried five times, then a TransientError", "[graph][client][get]")
{
    struct Row {
        HttpResponse response;
        std::string code;
    };
    const Row row = GENERATE_COPY(values<Row>({
        {load_fixture("graph", "messages-429-throttled"), "ApplicationThrottled"},
        {load_fixture("graph", "messages-503-unavailable"), "serviceNotAvailable"},
        {make_response(500, R"({"error":{"code":"generalException","message":"x"}})"),
         "generalException"},
        {make_response(502, "<html><body>Bad gateway: SecretProxyPage</body></html>", "text/html"),
         ""},
        {make_response(504, ""), ""},
        {make_response(599, "not json"), ""},
    }));
    CAPTURE(row.response.status);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {row.response});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.status == row.response.status);
    CHECK(caught.code == row.code);
    CHECK_THAT(caught.what, ContainsSubstring("after 5 attempts"));
    CHECK(caught.what.find("SecretProxyPage") == std::string::npos);
    CHECK(caught.what.find("not json") == std::string::npos);
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 5);
    std::vector<std::chrono::milliseconds> expected{1s, 2s, 4s, 8s};
    if (row.response.status == 429) {
        expected = {3s, 3s, 4s, 8s};
    } else if (row.response.status == 503) {
        expected = {10s, 10s, 10s, 10s};
    }
    CHECK(lab.waits() == expected);
}

TEST_CASE("a GET's Retry-After over 120 s ends the call at once, carrying it",
          "[graph][client][get]")
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
    HttpResponse response = load_fixture("graph", "messages-429-throttled");
    response.headers["Retry-After"] = row.retry_after;
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {response});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.status == 429);
    CHECK(caught.code == "ApplicationThrottled");
    CHECK(caught.retry_after == row.expected);
    CHECK_THAT(caught.what, ContainsSubstring(std::to_string(row.expected.count()) + " s"));
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 1);
    CHECK(lab.waits().empty());
}

TEST_CASE("a GET's waits stay within 300 s in all", "[graph][client][get]")
{
    HttpResponse response = load_fixture("graph", "messages-503-unavailable");
    response.headers["Retry-After"] = "100";
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {response});

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.retry_after == 100s);
    CHECK_THAT(caught.what, ContainsSubstring("300 s"));
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{100s, 100s, 100s});
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 4);
}

TEST_CASE("a token renewal inside a GET waits within the same 300 s", "[graph][client][get]")
{
    // Graph asks to wait; the wait outlasts the token; Entra asks to wait as
    // well. Both come out of the one call's budget.
    HttpResponse graph_busy = load_fixture("graph", "messages-503-unavailable");
    graph_busy.headers["Retry-After"] = "100";
    HttpResponse entra_busy = entra_error(503, "temporarily_unavailable", 90006);
    entra_busy.headers["Retry-After"] = "100";
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {graph_busy});
    lab.set_on_token([entra_busy](int n, const HttpRequest&) {
        return n == 1 ? token_response("token-1") : entra_busy;
    });
    GraphClientOptions options = lab.options();
    const auto record = options.sleep;
    options.sleep = [&lab, record](std::chrono::milliseconds wait) {
        record(wait);
        lab.advance(3600s);
    };
    GraphClient client(lab.http, kTenant, kClient, certificate(), options);

    const Caught caught =
        catch_graph([&] { client.get(kMessagesPath, rp::graph::kMailReadGrant); });

    CHECK(caught.kind == "TransientError");
    CHECK_THAT(caught.what, ContainsSubstring("300 s"));
    std::chrono::milliseconds total{0};
    for (const std::chrono::milliseconds wait : lab.waits()) {
        total += wait;
    }
    CHECK(total <= 300s);
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{100s, 100s, 100s});
}

// Review of W2.1: a renewal held the one lock across Entra's sends and retry
// waits, so every call blocked behind it, even one whose token was still good,
// and the time it blocked counted against no budget.
TEST_CASE("a call with a good token doesn't wait behind another call's token renewal",
          "[graph][client][get]")
{
    const std::string other_url = std::string{rp::graph::kGraphBaseUrl} + "/sites/root";
    Lab lab;
    std::atomic<bool> release = false;
    lab.set_on_token([&release](int n, const HttpRequest&) {
        if (n == 2) {
            // Held until the test lets go, 5 s at most, so a regression fails
            // rather than hangs.
            const auto until = std::chrono::steady_clock::now() + 5s;
            while (!release && std::chrono::steady_clock::now() < until) {
                std::this_thread::sleep_for(1ms);
            }
        }
        return token_response("token-" + std::to_string(n));
    });
    // /sites/root answers 401 once: its caller renews while token-1 is good.
    std::atomic<int> site_calls = 0;
    lab.http.on(HttpMethod::get, other_url, [&site_calls](const HttpRequest&) {
        return ++site_calls == 1 ? load_fixture("graph", "api-invalid-token-401")
                                 : load_fixture("graph", "messages-200");
    });
    auto client = lab.make_client();
    REQUIRE(client->get(kMessagesPath, rp::graph::kMailReadGrant).status == 200);

    std::jthread renewer([&client] {
        try {
            client->get("/sites/root", rp::graph::kSitesReadGrant);
        } catch (...) {
            // Checked through the requests after the join.
        }
    });
    while (lab.token_requests < 2) {
        std::this_thread::yield();
    }
    const auto start = std::chrono::steady_clock::now();
    const int status = client->get(kMessagesPath, rp::graph::kMailReadGrant).status;
    const auto elapsed = std::chrono::steady_clock::now() - start;
    release = true;
    renewer.join();

    CHECK(status == 200);
    CHECK(elapsed < 3s);
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer token-1", "Bearer token-1",
                                                    "Bearer token-1", "Bearer token-2"});
}

TEST_CASE("time spent waiting for another call's token renewal counts toward a call's 300 s",
          "[graph][client][get]")
{
    const std::string other_url = std::string{rp::graph::kGraphBaseUrl} + "/sites/root";
    HttpResponse graph_busy = load_fixture("graph", "messages-503-unavailable");
    graph_busy.headers["Retry-After"] = "20";
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {graph_busy});
    lab.http.on(HttpMethod::get, other_url, {load_fixture("graph", "messages-200")});
    std::atomic<bool> waiter_started = false;
    lab.set_on_token([&lab, &waiter_started](int n, const HttpRequest&) {
        if (n == 2) {
            // The other call has started and is waiting for this renewal,
            // which takes 290 s by the client's clock.
            const auto until = std::chrono::steady_clock::now() + 5s;
            while (!waiter_started && std::chrono::steady_clock::now() < until) {
                std::this_thread::yield();
            }
            std::this_thread::sleep_for(200ms);
            lab.advance(290s);
        }
        return token_response("token-" + std::to_string(n));
    });
    auto client = lab.make_client();
    REQUIRE(client->get("/sites/root", rp::graph::kSitesReadGrant).status == 200);
    lab.advance(3600s); // token-1 is due

    std::jthread renewer([&client] {
        try {
            client->get("/sites/root", rp::graph::kSitesReadGrant);
        } catch (...) {
            // Checked through the token count after the join.
        }
    });
    while (lab.token_requests < 2) {
        std::this_thread::yield();
    }
    Caught caught;
    {
        std::jthread waiter([&] {
            waiter_started = true;
            caught = catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); });
        });
    }
    renewer.join();

    // 290 s waited for the renewal, and Graph asks for 20 more: over 300 s.
    CHECK(caught.kind == "TransientError");
    CHECK_THAT(caught.what, ContainsSubstring("300 s"));
    CHECK(lab.waits().empty());
    CHECK(lab.token_requests == 2);
}

TEST_CASE("the token is checked again before every attempt", "[graph][client][get]")
{
    // A long wait can outlast the token: the retry goes out with a new one.
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl,
                {load_fixture("graph", "messages-503-unavailable"),
                 load_fixture("graph", "messages-200")});
    GraphClientOptions options = lab.options();
    options.sleep = [&lab](std::chrono::milliseconds) { lab.advance(3600s); };
    GraphClient client(lab.http, kTenant, kClient, certificate(), options);

    CHECK(client.get(kMessagesPath, rp::graph::kMailReadGrant).status == 200);
    CHECK(lab.token_requests == 2);
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer token-1", "Bearer token-2"});
}

TEST_CASE("5xx, 429 and transport failures share the five attempts", "[graph][client][get]")
{
    Lab lab;
    std::atomic<int> calls = 0;
    lab.http.on(HttpMethod::get, kMessagesUrl, [&calls](const HttpRequest&) -> HttpResponse {
        switch (++calls) {
        case 1:
            return make_response(503, "");
        case 2:
            throw rp::HttpError("GET: timed out", rp::TransportError::timeout, 0, 1);
        case 3:
            return make_response(429, "");
        case 4:
            throw rp::HttpError("GET: dropped", rp::TransportError::dropped, 0, 1);
        default:
            return make_response(500, "");
        }
    });

    const Caught caught = get_once(lab);

    CHECK(caught.kind == "TransientError");
    CHECK(caught.status == 500);
    CHECK(calls == 5);
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{1s, 2s, 4s, 8s});
}

TEST_CASE("a GET that gets no response is tried five times, a TLS failure once",
          "[graph][client][get]")
{
    struct Row {
        rp::TransportError error;
        std::string kind;
        std::size_t sent;
    };
    const Row row = GENERATE(values<Row>({
        {rp::TransportError::connect, "TransientError", 5},
        {rp::TransportError::handshake, "TransientError", 5},
        {rp::TransportError::dropped, "TransientError", 5},
        {rp::TransportError::timeout, "TransientError", 5},
        {rp::TransportError::tls, "GraphError", 1},
        {rp::TransportError::other, "GraphError", 1},
    }));
    CAPTURE(row.kind, row.sent);
    Lab lab;
    // HttpClient's message starts with the method and the whole URL.
    lab.http.on(HttpMethod::get, kMessagesUrl, [row](const HttpRequest&) -> HttpResponse {
        throw rp::HttpError("GET " + kMessagesUrl + ": no response: curl says why", row.error, 0,
                            1);
    });

    const Caught caught = get_once(lab);

    CHECK(caught.kind == row.kind);
    CHECK_THAT(caught.what, ContainsSubstring("Graph GET /v1.0/users/"));
    CHECK_THAT(caught.what, ContainsSubstring(": no response: curl says why"));
    // Review of W2.1: the query (a $filter may name what is looked for) stays
    // out of the message and the log, as display_path() keeps it out, and the
    // URL isn't repeated.
    CHECK_THAT(caught.what, !ContainsSubstring("$select") && !ContainsSubstring("https://"));
    CHECK_THAT(lab.log(), !ContainsSubstring("$select"));
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == row.sent);
    CHECK(lab.waits().size() == row.sent - 1);
}

TEST_CASE("a transport failure without HttpClient's prefix is described by its kind",
          "[graph][client][get]")
{
    struct Row {
        rp::TransportError error;
        std::string text;
    };
    const Row row = GENERATE(values<Row>({
        {rp::TransportError::connect, "could not connect"},
        {rp::TransportError::handshake, "the TLS handshake broke off"},
        {rp::TransportError::dropped, "the connection dropped"},
        {rp::TransportError::timeout, "timed out"},
        {rp::TransportError::tls, "TLS failed"},
        {rp::TransportError::other, "the request failed"},
    }));
    CAPTURE(row.text);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, [row](const HttpRequest&) -> HttpResponse {
        throw rp::HttpError("something else " + kMessagesUrl, row.error, 0, 1);
    });

    const Caught caught = get_once(lab);

    CHECK_THAT(caught.what, ContainsSubstring("/messages: " + row.text));
    CHECK_THAT(caught.what, !ContainsSubstring("$select"));
}

TEST_CASE("a GET that gets no response once is sent again", "[graph][client][get]")
{
    const rp::TransportError error =
        GENERATE(rp::TransportError::connect, rp::TransportError::handshake,
                 rp::TransportError::dropped, rp::TransportError::timeout);
    Lab lab;
    std::atomic<int> calls = 0;
    lab.http.on(HttpMethod::get, kMessagesUrl, [&calls, error](const HttpRequest&) {
        if (++calls == 1) {
            throw rp::HttpError("GET: no response", error, 0, 1);
        }
        return load_fixture("graph", "messages-200");
    });

    CHECK(get_once(lab).kind == "none");
    CHECK(calls == 2);
    CHECK(lab.waits() == std::vector<std::chrono::milliseconds>{1s});
}

// --- GET: redirects ------------------------------------------------------------

TEST_CASE("a GET's redirect is returned, not followed, and get_json refuses it",
          "[graph][client][get]")
{
    const int status = GENERATE(301, 302, 303, 307, 308);
    CAPTURE(status);
    HttpResponse redirect = make_response(status);
    redirect.headers["Location"] = "https://evil.example/steal";
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {redirect});
    auto client = lab.make_client();

    const HttpResponse response = client->get(kMessagesPath, rp::graph::kMailReadGrant);
    const Caught by_json =
        catch_graph([&] { client->get_json(kMessagesPath, rp::graph::kMailReadGrant); });

    CHECK(response.status == status);
    CHECK(response.headers.at("Location") == "https://evil.example/steal");
    CHECK(by_json.kind == "GraphError");
    CHECK(by_json.status == status);
    CHECK(lab.http.count(HttpMethod::get, "https://evil.example/steal") == 0);
    CHECK(lab.http.count(HttpMethod::get, kMessagesUrl) == 2);
    CHECK(lab.token_requests == 1);
}

TEST_CASE("get_json refuses a reply that isn't a JSON object without quoting it",
          "[graph][client][get]")
{
    const std::string body = GENERATE(as<std::string>{}, "", "SecretBody", "[1,2]", "\"text\"",
                                      "{\"value\":[]", "null");
    CAPTURE(body);
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl, {make_response(200, body)});
    auto client = lab.make_client();

    const Caught caught =
        catch_graph([&] { client->get_json(kMessagesPath, rp::graph::kMailReadGrant); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.status == 200);
    CHECK(caught.what.find("SecretBody") == std::string::npos);
    CHECK_THAT(caught.what, ContainsSubstring("Graph GET /v1.0/users/"));
}

TEST_CASE("no token reaches a GET's error message or the log", "[graph][client][get]")
{
    const std::string token_1 = "SentinelGraphAccessTokenOne";
    const std::string token_2 = "SentinelGraphAccessTokenTwo";
    Lab lab;
    lab.set_on_token([&](int n, const HttpRequest&) {
        return token_response(n == 1 ? token_1 : token_2);
    });
    auto client = lab.make_client();
    std::vector<std::string> messages;
    for (const char* fixture : {"api-invalid-token-401", "messages-403-exchange",
                                "messages-404-unknown-user", "messages-503-unavailable",
                                "api-insufficient-claims-401"}) {
        lab.http.on(HttpMethod::get, kMessagesUrl, {load_fixture("graph", fixture)});
        messages.push_back(
            catch_graph([&] { client->get(kMessagesPath, rp::graph::kMailReadGrant); }).what);
    }

    const std::string log = lab.log();
    CAPTURE(log);
    CHECK_THAT(log, ContainsSubstring("fresh token"));
    for (const std::string& secret : {token_1, token_2, std::string{"Bearer Sentinel"}}) {
        CHECK(log.find(secret) == std::string::npos);
        for (const std::string& message : messages) {
            CHECK(message.find(secret) == std::string::npos);
        }
    }
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

TEST_CASE("get() sends a path under v1.0 and an exact v1.0 URL as they are, with the token",
          "[graph][client][get]")
{
    struct Row {
        std::string target;
        std::string url;
    };
    const std::string base{rp::graph::kGraphBaseUrl};
    const Row row = GENERATE_COPY(values<Row>({
        {kMessagesPath, kMessagesUrl},
        {kMessagesUrl, kMessagesUrl},
        {"/sites/restoreprooflab.sharepoint.com:/sites/RestoreTest",
         base + "/sites/restoreprooflab.sharepoint.com:/sites/RestoreTest"},
        // An @odata.nextLink: encoded characters in the query are Graph's
        // business, and a dot inside a segment is no dot segment.
        {base + "/users/x/messages?%24top=1&%24skiptoken=a%2eb%3D%3D",
         base + "/users/x/messages?%24top=1&%24skiptoken=a%2eb%3D%3D"},
        {"/users/x/messages?$filter=subject eq 'a'", base + "/users/x/messages?$filter=subject eq 'a'"},
        {"/drives/b!x..y/items/root:/a.b..c", base + "/drives/b!x..y/items/root:/a.b..c"},
    }));
    CAPTURE(row.target);
    Lab lab;
    lab.http.on(HttpMethod::get, row.url, {load_fixture("graph", "messages-200")});
    auto client = lab.make_client();

    // Whitespace in the query is refused like anywhere else.
    if (row.target.find(' ') != std::string::npos) {
        CHECK(catch_graph([&] { client->get(row.target, rp::graph::kMailReadGrant); }).kind ==
              "GraphError");
        CHECK(lab.http.requests().empty());
        return;
    }
    CHECK(client->get(row.target, rp::graph::kMailReadGrant).status == 200);
    CHECK(lab.http.count(HttpMethod::get, row.url) == 1);
    CHECK(lab.bearers() == std::vector<std::string>{"Bearer token-1"});
}

TEST_CASE("get_json returns the recorded inbox", "[graph][client][get]")
{
    Lab lab;
    auto client = lab.make_client();

    const json doc = client->get_json(kMessagesPath, rp::graph::kMailReadGrant);

    CHECK(doc.at("value") == json::array());
    CHECK(doc.at("@odata.context").get<std::string>().starts_with(
        "https://graph.microsoft.com/v1.0/$metadata#users("));
}

TEST_CASE("pages follow @odata.nextLink with the same token", "[graph][client][get]")
{
    const std::string next =
        kMessagesUrl + "&$skiptoken=MSZZVlhKbFkwMWhhV3c9";
    const std::string last = kMessagesUrl + "&$skiptoken=MiZZVlhKbFkwMWhhV3c9";
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl,
                {make_response(200, json{{"value", {{{"id", "a"}}}}, {"@odata.nextLink", next}}.dump())});
    lab.http.on(HttpMethod::get, next,
                {make_response(200, json{{"value", {{{"id", "b"}}}}, {"@odata.nextLink", last}}.dump())});
    lab.http.on(HttpMethod::get, last, {make_response(200, json{{"value", {{{"id", "c"}}}}}.dump())});
    auto client = lab.make_client();

    std::vector<std::string> ids;
    std::string target = kMessagesPath;
    for (int page = 0; page < 10 && !target.empty(); ++page) {
        const json doc = client->get_json(target, rp::graph::kMailReadGrant);
        for (const json& item : doc.at("value")) {
            ids.push_back(item.at("id").get<std::string>());
        }
        target = doc.value("@odata.nextLink", std::string{});
    }

    CHECK(ids == std::vector<std::string>{"a", "b", "c"});
    CHECK(lab.token_requests == 1);
    CHECK(lab.bearers() ==
          std::vector<std::string>{"Bearer token-1", "Bearer token-1", "Bearer token-1"});
    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 4);
    CHECK(sent[2].url == next);
    CHECK(sent[3].url == last);
}

TEST_CASE("the Graph HTTP client trusts the Windows store alone: no CA file, no pin",
          "[graph][client]")
{
    auto logger = std::make_shared<spdlog::logger>("graph_http_test");
    const rp::HttpClientOptions options = rp::graph::graph_http_client_options(logger);

    CHECK_FALSE(options.ca_file.has_value());
    CHECK_FALSE(options.pinned_cert_sha256.has_value());
    CHECK(options.logger == logger);
    CHECK_FALSE(rp::graph::graph_http_client_options().logger);

    const std::unique_ptr<rp::IHttpClient> http = rp::graph::make_graph_http_client(logger);
    CHECK(dynamic_cast<rp::HttpClient*>(http.get()) != nullptr);
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

// W2.2: the Prefer header the mail listing needs, and nothing else.

TEST_CASE("get refuses a caller header other than Prefer before sending anything",
          "[graph][client][headers]")
{
    const std::string name = GENERATE(as<std::string>{}, "Authorization", "authorization",
                                       "Proxy-Authorization", "Host", "Cookie", "X-Anything");
    CAPTURE(name);
    Lab lab;
    auto client = lab.make_client();

    const Caught caught = catch_graph(
        [&] { client->get(kMessagesPath, rp::graph::kMailReadGrant, {{name, "x"}}); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == "Graph GET: refused the header \"" + name +
                             "\" since a caller may add only Prefer; the token and the other headers "
                             "are the client's");
    CHECK(lab.token_requests == 0);
    CHECK(lab.http.requests().empty());
}

TEST_CASE("get refuses a Prefer value with a control character or an empty one",
          "[graph][client][headers]")
{
    const std::string value =
        GENERATE(as<std::string>{}, "a\r\nX-Evil: 1", "a\nb", "a\x01", "", "a\xC2\x85");
    CAPTURE(value);
    Lab lab;
    auto client = lab.make_client();

    const Caught caught = catch_graph(
        [&] { client->get(kMessagesPath, rp::graph::kMailReadGrant, {{"Prefer", value}}); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == "Graph GET: refused the value of the header \"Prefer\": it is empty or "
                         "holds a control character");
    CHECK(lab.token_requests == 0);
    CHECK(lab.http.requests().empty());
}

TEST_CASE("a Prefer header goes with every attempt, after a 401 resend and a 503 retry, and "
          "never replaces the token",
          "[graph][client][headers]")
{
    const std::string prefer = R"(outlook.body-content-type="text", IdType="ImmutableId")";
    Lab lab;
    lab.http.on(HttpMethod::get, kMessagesUrl,
                {load_fixture("graph", "api-invalid-token-401"), make_response(503, ""),
                 load_fixture("graph", "messages-200")});
    auto client = lab.make_client();

    // Any case of the name is the one allowed header.
    const HttpResponse response =
        client->get(kMessagesPath, rp::graph::kMailReadGrant, {{"prefer", prefer}});

    CHECK(response.status == 200);
    CHECK(lab.bearers() ==
          std::vector<std::string>{"Bearer token-1", "Bearer token-2", "Bearer token-2"});
    std::size_t gets = 0;
    for (const HttpRequest& request : lab.http.requests()) {
        if (request.method == HttpMethod::get) {
            ++gets;
            CHECK(header(request, "Prefer") == prefer);
            CHECK(header(request, "Accept") == "application/json");
        }
    }
    CHECK(gets == 3);
}

TEST_CASE("get_json, find and find_json pass the headers through", "[graph][client][headers]")
{
    const std::string call = GENERATE(as<std::string>{}, "get_json", "find", "find_json");
    CAPTURE(call);
    Lab lab;
    auto client = lab.make_client();
    const rp::HttpHeaders headers{{"Prefer", "x=1"}};

    if (call == "get_json") {
        client->get_json(kMessagesPath, rp::graph::kMailReadGrant, headers);
    } else if (call == "find") {
        CHECK(client->find(kMessagesPath, rp::graph::kMailReadGrant, headers).has_value());
    } else {
        CHECK(client->find_json(kMessagesPath, rp::graph::kMailReadGrant, headers).has_value());
    }

    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 2);
    CHECK(header(sent[1], "Prefer") == "x=1");
    CHECK(header(sent[1], "Authorization") == "Bearer token-1");
}

TEST_CASE("the refusals of a caller header come before the URL is sent, for every call",
          "[graph][client][headers]")
{
    const std::string call = GENERATE(as<std::string>{}, "get_json", "find", "find_json");
    CAPTURE(call);
    Lab lab;
    auto client = lab.make_client();
    const rp::HttpHeaders headers{{"Authorization", "Bearer mine"}};

    const Caught caught = catch_graph([&] {
        if (call == "get_json") {
            client->get_json(kMessagesPath, rp::graph::kMailReadGrant, headers);
        } else if (call == "find") {
            client->find(kMessagesPath, rp::graph::kMailReadGrant, headers);
        } else {
            client->find_json(kMessagesPath, rp::graph::kMailReadGrant, headers);
        }
    });

    CHECK(caught.kind == "GraphError");
    CHECK_THAT(caught.what, ContainsSubstring("refused the header \"Authorization\""));
    CHECK(lab.http.requests().empty());
}

TEST_CASE("every grant's text is generic: it names no lab value", "[graph][client]")
{
    struct Row {
        rp::graph::Grant grant;
        std::string text;
    };
    const Row row = GENERATE(values<Row>({
        {rp::graph::kMailReadGrant,
         "Exchange RBAC \"Application Mail.Read\" in a management scope covering the test "
         "mailbox"},
        {rp::graph::kSitesReadGrant, "Sites.Selected read on the test site"},
        {rp::graph::kOneDriveReadGrant,
         "Files.SelectedOperations.Selected read on the test OneDrive folder"},
    }));
    CAPTURE(row.text);

    CHECK(row.grant.description == row.text);
    std::string lower{row.grant.description};
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const std::string lab_value : {"restoreproof", "restoretest", "restoretarget", "alice",
                                        "onmicrosoft", "sharepoint.com", "b!"}) {
        CAPTURE(lab_value);
        CHECK(lower.find(lab_value) == std::string::npos);
    }
}
