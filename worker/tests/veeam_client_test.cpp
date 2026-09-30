// W1.5: VeeamClient against the recorded Veeam responses in
// tests/fixtures/veeam/ (docs/api/veeam-notes.md §9), served by
// FakeHttpClient. Nothing here touches the network; the live check against the
// lab is veeam_client_live_test.cpp (RP_LIVE=1). The token rules are
// veeam-notes §1.7, the error table §8 with the 2026-09-26 decisions
// (docs/decisions.md).

#include "fake_http_client.hpp"

#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>
#include <rp/veeam_client.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <functional>
#include <latch>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using rp::test::to_response;

const std::string kBase = "https://veeam.test:4443";
const std::string kTokenUrl = kBase + "/v8/token";
const std::string kLogoutUrl = kBase + "/v8/token/logout";
const std::string kOrgId = "ff96d072-29e2-4cb4-a155-2590f5473176";
const std::string kUnknownOrgId = "00000000-0000-0000-0000-000000000001";
const std::string kUsername = "DESKTOP-P55CDUM\\rp-veeam";
// A password with every character form encoding must escape, and a non-ASCII
// one ("ö" in UTF-8). It must never show up in a log line or an error.
const std::string kPassword = "Sentinel&Pa55=w\xc3\xb6rd+%";
const std::string kPasswordForm = "Sentinel%26Pa55%3Dw%C3%B6rd%2B%25";

const std::string kNewestPoint =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e371ac3d9c-eb29-42b6-a391-ae81fcc4681c";
const std::string kOldestPoint =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e32fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7";

std::string orgs_url(int limit = 1000, int offset = 0)
{
    return kBase + "/v8/Organizations?limit=" + std::to_string(limit) +
           "&offset=" + std::to_string(offset);
}

std::string points_url(const std::string& org = kOrgId, int limit = 1000, int offset = 0)
{
    return kBase + "/v8/RestorePoints?organizationId=" + org + "&limit=" + std::to_string(limit) +
           "&offset=" + std::to_string(offset);
}

// The recorded 200 token response with these tokens in place of [REDACTED].
HttpResponse token_response(const std::string& access, const std::string& refresh,
                            int expires_in = 3600)
{
    json fixture = load_fixture_json("veeam", "token-200");
    fixture["body"]["access_token"] = access;
    fixture["body"]["refresh_token"] = refresh;
    fixture["body"]["expires_in"] = expires_in;
    return to_response(fixture);
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

std::string bearer(const HttpRequest& request)
{
    const auto it = request.headers.find("Authorization");
    return it == request.headers.end() ? "(none)" : it->second;
}

std::size_t count_of(std::string_view text, std::string_view needle)
{
    std::size_t n = 0;
    for (std::size_t at = text.find(needle); at != std::string_view::npos;
         at = text.find(needle, at + needle.size())) {
        ++n;
    }
    return n;
}

// The Veeam server as a test sees it. The token endpoint grants numbered
// tokens: the n-th password sign-in "access-login-<n>" / "refresh-login-<n>",
// the n-th refresh "access-refresh-<n>" / "refresh-refresh-<n>", unless a test
// replaces on_login or on_refresh. Time only moves when the test says so;
// waits are recorded, never slept; debug lines go to a string.
struct Lab {
    Lab()
    {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("veeam_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::debug);
        http.on(HttpMethod::post, kTokenUrl, [this](const HttpRequest& request) {
            const std::string grant = form_value(request.body, "grant_type");
            if (grant == "password") {
                return on_login(++logins);
            }
            if (grant == "refresh_token") {
                return on_refresh(++refreshes, form_value(request.body, "refresh_token"));
            }
            throw std::logic_error("unexpected grant_type " + grant);
        });
    }

    std::unique_ptr<rp::VeeamClient> make_client(int page_size = 1000)
    {
        rp::VeeamClientOptions options;
        options.logger = logger;
        options.now = [this] { return std::chrono::steady_clock::time_point{} + now.load(); };
        options.sleep = [this](std::chrono::milliseconds wait) {
            const std::lock_guard lock(mutex);
            sleeps.push_back(wait);
        };
        options.jitter = [] { return 0.0; };
        options.page_size = page_size;
        options.timeout = 45s;
        return std::make_unique<rp::VeeamClient>(http, kBase, kUsername, kPassword,
                                                 std::move(options));
    }

    void advance(std::chrono::milliseconds by) { now = now.load() + by; }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    // The token requests, in order: "password" or "refresh_token".
    std::vector<std::string> grants() const
    {
        std::vector<std::string> out;
        for (const HttpRequest& request : http.requests()) {
            if (request.url == kTokenUrl) {
                out.push_back(form_value(request.body, "grant_type"));
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
    std::atomic<int> logins = 0;
    std::atomic<int> refreshes = 0;
    std::function<HttpResponse(int)> on_login = [](int n) {
        return token_response("access-login-" + std::to_string(n),
                              "refresh-login-" + std::to_string(n));
    };
    std::function<HttpResponse(int, const std::string&)> on_refresh = [](int n,
                                                                          const std::string&) {
        return token_response("access-refresh-" + std::to_string(n),
                              "refresh-refresh-" + std::to_string(n));
    };
};

// Which of the four exception types `call` threw ("none" if it returned).
std::string thrown_kind(const std::function<void()>& call)
{
    try {
        call();
    } catch (const rp::AuthError&) {
        return "AuthError";
    } catch (const rp::NotFoundError&) {
        return "NotFoundError";
    } catch (const rp::TransientError&) {
        return "TransientError";
    } catch (const rp::VeeamError&) {
        return "VeeamError";
    }
    return "none";
}

// A page of restore points with these backupTimes (IDs "p<i>").
HttpResponse points_page(const std::vector<json>& backup_times)
{
    json results = json::array();
    for (std::size_t i = 0; i < backup_times.size(); ++i) {
        json point = {{"id", "p" + std::to_string(i)}, {"organizationId", kOrgId}};
        if (!backup_times[i].is_null()) {
            point["backupTime"] = backup_times[i];
        }
        results.push_back(point);
    }
    return make_response(200, json{{"offset", 0}, {"limit", 1000}, {"results", results}}.dump());
}

} // namespace

// --- Failure paths ----------------------------------------------------------

TEST_CASE("a refused sign-in is an AuthError, sent once and never retried", "[veeam]")
{
    // Veeam refuses a wrong password, an unknown user and a missing role the
    // same way: 401 with a message, or, before its REST service restarts, an
    // empty 500 (veeam-notes §1.2).
    const auto [fixture, expected] = GENERATE(table<std::string, std::string>({
        {"token-rejected-401",
         "Veeam POST /v8/token: HTTP 401: The server has rejected the client credentials."},
        {"token-rejected-500-empty", "Veeam POST /v8/token: HTTP 500"},
    }));
    CAPTURE(fixture);
    Lab lab;
    lab.on_login = [fixture = fixture](int) { return load_fixture("veeam", fixture); };
    auto client = lab.make_client();

    try {
        client->list_organizations();
        FAIL("list_organizations() returned after a refused sign-in");
    } catch (const rp::AuthError& e) {
        CHECK(std::string{e.what()} == expected);
        CHECK(e.status() == load_fixture("veeam", fixture).status);
    }
    CHECK_THROWS_AS(client->login(), rp::AuthError);

    CHECK(lab.logins == 2);
    CHECK(lab.http.requests().size() == 2); // no API call went out
    CHECK(lab.sleeps.empty());
    for (const HttpRequest& request : lab.http.requests()) {
        CHECK_FALSE(request.retry_on_status);
    }
    const std::string log = lab.log();
    CHECK(log.find(kPassword) == std::string::npos);
    CHECK(log.find(kPasswordForm) == std::string::npos);
}

TEST_CASE("any failed refresh falls back to a password sign-in", "[veeam]")
{
    using Refresh = std::function<HttpResponse(int, const std::string&)>;
    const Refresh failure = GENERATE(
        // The recorded one: a used, logged-out or restart-killed refresh token.
        Refresh{[](int, const std::string&) { return load_fixture("veeam", "token-refresh-invalid-401"); }},
        Refresh{[](int, const std::string&) { return make_response(500); }},
        Refresh{[](int, const std::string&) {
            return make_response(500, R"({"message":"An antiforgery token is not specified."})");
        }},
        Refresh{[](int, const std::string&) { return make_response(200, "not json"); }},
        // Not a VeeamError: its message isn't ours, so it isn't logged either.
        Refresh{[](int, const std::string&) -> HttpResponse {
            throw std::runtime_error("SENTINEL_NOT_OURS");
        }});
    Lab lab;
    lab.on_refresh = failure;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    auto client = lab.make_client();

    client->list_organizations();
    lab.advance(3540s);
    const std::vector<rp::Organization> orgs = client->list_organizations();

    CHECK(orgs.size() == 1);
    CHECK(lab.grants() == std::vector<std::string>{"password", "refresh_token", "password"});
    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 5);
    CHECK(form_value(sent[2].body, "refresh_token") == "refresh-login-1");
    CHECK(form_value(sent[2].body, "disable_antiforgery_token") == "true");
    CHECK(bearer(sent[4]) == "Bearer access-login-2");
    CHECK(lab.log().find("SENTINEL") == std::string::npos);
}

TEST_CASE("a refresh that can't reach Veeam is a TransientError, without a password sign-in",
          "[veeam]")
{
    // A password sign-in would spend the same retries on the same unreachable
    // server, while every other caller waits on the lock (W1.5 review).
    using Refresh = std::function<HttpResponse(int, const std::string&)>;
    const Refresh failure = GENERATE(
        Refresh{[](int, const std::string&) -> HttpResponse {
            throw rp::HttpError("POST https://veeam.test:4443/v8/token: timed out",
                                rp::TransportError::timeout, 0, 1);
        }},
        Refresh{[](int, const std::string&) { return make_response(503); }},
        Refresh{[](int, const std::string&) {
            return make_response(502, "<html>Bad Gateway</html>", "text/html");
        }});
    Lab lab;
    lab.on_refresh = failure;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    auto client = lab.make_client();

    client->list_organizations();
    lab.advance(3540s);
    CHECK(thrown_kind([&] { client->list_organizations(); }) == "TransientError");

    CHECK(lab.grants() == std::vector<std::string>{"password", "refresh_token"});
    CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 1);
}

TEST_CASE("an expired or revoked token gets one fresh sign-in, then the call is resent",
          "[veeam]")
{
    // Past its expiry, revoked by a refresh or a logout, or killed by a REST
    // service restart: all are a 401 with an empty body (veeam-notes §1.3).
    const std::string fixture = GENERATE("api-expired-token-401", "api-invalid-token-401");
    CAPTURE(fixture);
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), [&fixture](const HttpRequest& request) {
        return bearer(request) == "Bearer access-login-1"
                   ? load_fixture("veeam", fixture)
                   : load_fixture("veeam", "organizations-200");
    });
    auto client = lab.make_client();

    CHECK(client->list_organizations().size() == 1);

    CHECK(lab.grants() == std::vector<std::string>{"password", "password"});
    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 4);
    CHECK(bearer(sent[1]) == "Bearer access-login-1");
    CHECK(bearer(sent[3]) == "Bearer access-login-2");
    // Only an expired token says why, and that isn't secret: it is logged.
    if (fixture == "api-expired-token-401") {
        CHECK(lab.log().find("The token expired at '09/26/2026 17:01:43'") != std::string::npos);
    }
}

TEST_CASE("a second 401 after a fresh sign-in is an AuthError", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "api-invalid-token-401")});
    auto client = lab.make_client();

    try {
        client->list_organizations();
        FAIL("list_organizations() returned after two 401s");
    } catch (const rp::AuthError& e) {
        CHECK(e.status() == 401);
        CHECK(std::string{e.what()} ==
              "Veeam GET /v8/Organizations?limit=1000&offset=0: HTTP 401 again after signing in "
              "afresh");
    }
    CHECK(lab.logins == 2);
    CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 2);
}

TEST_CASE("a 401 with a message on an API call is an AuthError without a new sign-in", "[veeam]")
{
    // The credentials are valid but the account's role doesn't allow the call
    // (veeam-notes §8): signing in again would only loop.
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {make_response(401, R"({"message":"The server has rejected the client credentials."})")});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->list_organizations(); }) == "AuthError");
    CHECK(lab.logins == 1);
    CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 1);
}

TEST_CASE("a 401 for a token older than the current one is resent without a new sign-in",
          "[veeam]")
{
    // Another caller refreshed or signed in while this request was in
    // flight, which revoked the token it carried (veeam-notes §1.4).
    Lab lab;
    std::unique_ptr<rp::VeeamClient> client = lab.make_client();
    std::atomic<int> gets = 0;
    lab.http.on(HttpMethod::get, orgs_url(), [&](const HttpRequest&) {
        // No Catch2 assertion in here: it runs on the client's thread.
        if (++gets == 1) {
            client->login(); // the other caller
            return load_fixture("veeam", "api-invalid-token-401");
        }
        return load_fixture("veeam", "organizations-200");
    });

    CHECK(client->list_organizations().size() == 1);

    CHECK(lab.logins == 2); // the first sign-in and the other caller's; none by this call
    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 4);
    CHECK(bearer(sent[1]) == "Bearer access-login-1");
    CHECK(bearer(sent.back()) == "Bearer access-login-2");
}

TEST_CASE("a 500 with a Veeam message is a VeeamError, sent once", "[veeam]")
{
    Lab lab;
    const HttpResponse recorded = load_fixture("veeam", "explore-500-before-first");
    lab.http.on(HttpMethod::get, orgs_url(), {recorded});
    auto client = lab.make_client();

    try {
        client->list_organizations();
        FAIL("list_organizations() returned after a 500");
    } catch (const rp::TransientError&) {
        FAIL("a 500 with Veeam's message was treated as transient");
    } catch (const rp::VeeamError& e) {
        CHECK(e.status() == 500);
        CHECK(e.body() == recorded.body);
        CHECK(std::string{e.what()} ==
              "Veeam GET /v8/Organizations?limit=1000&offset=0: HTTP 500: The chosen restore "
              "point date precedes the date of the first available restore point (9/25/2026 "
              "7:24:31 PM).");
    }
    CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 1);
    CHECK(lab.sleeps.empty());
}

TEST_CASE("an empty 503 on a GET is retried, then a TransientError", "[veeam]")
{
    Lab lab;
    auto client = lab.make_client();

    SECTION("it clears: the call succeeds")
    {
        lab.http.on(HttpMethod::get, orgs_url(),
                    {make_response(503), make_response(503),
                     load_fixture("veeam", "organizations-200")});
        CHECK(client->list_organizations().size() == 1);
        CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 3);
        CHECK(lab.sleeps == std::vector<std::chrono::milliseconds>{1000ms, 2000ms});
    }

    SECTION("it doesn't: TransientError after five attempts")
    {
        lab.http.on(HttpMethod::get, orgs_url(), {make_response(503)});
        try {
            client->list_organizations();
            FAIL("list_organizations() returned after five 503s");
        } catch (const rp::TransientError& e) {
            CHECK(e.status() == 503);
            CHECK(std::string{e.what()} ==
                  "Veeam GET /v8/Organizations?limit=1000&offset=0: HTTP 503 after 5 attempts");
        }
        CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 5);
        CHECK(lab.sleeps ==
              std::vector<std::chrono::milliseconds>{1000ms, 2000ms, 4000ms, 8000ms});
    }
}

TEST_CASE("an unknown organisation is a NotFoundError", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, points_url(kUnknownOrgId),
                {load_fixture("veeam", "restore-points-unknown-org-404")});
    auto client = lab.make_client();

    try {
        client->list_restore_points(kUnknownOrgId);
        FAIL("list_restore_points() returned for an unknown organisation");
    } catch (const rp::NotFoundError& e) {
        CHECK(e.status() == 404);
        CHECK(e.error_code() == "ResourceNotFound");
        CHECK(std::string{e.what()} ==
              "Veeam GET /v8/RestorePoints?organizationId=" + kUnknownOrgId +
                  "&limit=1000&offset=0: HTTP 404 (ResourceNotFound): Organization does not "
                  "exist: ID " +
                  kUnknownOrgId + ".");
    }
}

TEST_CASE("an organisation with no restore points gives an empty list", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, points_url(), {load_fixture("veeam", "restore-points-empty-200")});
    auto client = lab.make_client();

    CHECK(client->list_restore_points(kOrgId).empty());
    CHECK(lab.http.count(HttpMethod::get, points_url()) == 1);
}

TEST_CASE("each HTTP status maps to one kind of error", "[veeam]")
{
    // veeam-notes §8 with the 2026-09-26 decisions. `sends`: how many times
    // the GET went out (a transient 5xx is retried, nothing else is).
    const std::string rejected = R"({"message":"The server has rejected the client credentials."})";
    const std::string denied = R"({"message":"Access denied.","errorCode":"ResourceAccessDenied"})";
    const auto [status, body, kind, sends] =
        GENERATE_COPY(table<int, std::string, std::string, int>({
            {400, load_fixture("veeam", "restore-point-400-format").body, "VeeamError", 1},
            {400, load_fixture("veeam", "restore-points-bad-query-400").body, "VeeamError", 1},
            {400, denied, "AuthError", 1},
            {401, rejected, "AuthError", 1},
            {403, "", "AuthError", 1},
            {404, load_fixture("veeam", "organization-404").body, "NotFoundError", 1},
            {404, "", "VeeamError", 1}, // a route that doesn't exist
            {409, R"({"message":"Unable to provide statistics until the restore session completes."})",
             "VeeamError", 1},
            {500, R"({"message":"Restore session is stopped."})", "VeeamError", 1},
            {500, denied, "AuthError", 1},
            {500, "", "TransientError", 5},
            {500, "<html><body>Internal Server Error</body></html>", "TransientError", 5},
            {500, "[1, 2]", "TransientError", 5},
            {500, R"({"errorCode":"Timeout"})", "TransientError", 5},
            {500, R"({"message": 42})", "TransientError", 5},
            {501, "", "TransientError", 5},
            {502, R"({"message":"Bad gateway"})", "TransientError", 5},
            {503, "", "TransientError", 5},
            {504, R"({"message":"Gateway timeout"})", "TransientError", 5},
            {302, "", "VeeamError", 1},
            {418, "", "VeeamError", 1},
        }));
    CAPTURE(status, body);
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {make_response(status, body)});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->list_organizations(); }) == kind);
    CHECK(lab.http.count(HttpMethod::get, orgs_url()) == static_cast<std::size_t>(sends));
    CHECK(lab.logins == 1);
}

TEST_CASE("each HTTP status from the token endpoint maps to one kind of error", "[veeam]")
{
    // A 500 on /v8/token is a refused sign-in: Veeam has answered a wrong
    // password with an empty one. Any other 5xx means what it means on any
    // call: a gateway, or a service starting up (W1.5 review). None is
    // retried: the next call signs in again.
    const auto [status, body, kind] = GENERATE(table<int, std::string, std::string>({
        {400, R"({"message":"Missing mandatory parameters: grant_type.","errorCode":"ParameterValidationFailure"})",
         "VeeamError"},
        {401, R"({"message":"The server has rejected the client credentials."})", "AuthError"},
        {403, "", "AuthError"},
        {500, "", "AuthError"},
        {500, R"({"message":"An antiforgery token is not specified."})", "AuthError"},
        {502, "", "TransientError"},
        {503, R"({"message":"Service unavailable"})", "TransientError"},
        {504, "", "TransientError"},
        {501, "", "TransientError"},
        {501, R"({"message":"Not implemented."})", "VeeamError"},
        {302, "", "VeeamError"},
    }));
    CAPTURE(status, body);
    Lab lab;
    lab.on_login = [status = status, body = body](int) { return make_response(status, body); };
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->login(); }) == kind);
    CHECK(lab.logins == 1);
    CHECK(lab.sleeps.empty());
}

TEST_CASE("a transport failure is a TransientError, a TLS failure a plain VeeamError", "[veeam]")
{
    // VeeamClient makes every attempt itself (HttpClient one per send), five
    // in all. A GET changes nothing, so any failure worth it is retried; a
    // token request only when it can't have reached Veeam (no connection, no
    // handshake): a resent password grant is another logon, a resent refresh
    // a used token (W1.5 review).
    using T = rp::TransportError;
    const auto [error, on_sign_in, kind, sends] = GENERATE(table<T, bool, std::string, int>({
        {T::connect, false, "TransientError", 5},
        {T::dropped, false, "TransientError", 5},
        {T::timeout, false, "TransientError", 5},
        {T::handshake, false, "TransientError", 5},
        // A certificate that doesn't verify won't fix itself.
        {T::tls, false, "VeeamError", 1},
        {T::other, false, "VeeamError", 1},
        {T::connect, true, "TransientError", 5},
        {T::handshake, true, "TransientError", 5},
        {T::dropped, true, "TransientError", 1},
        {T::timeout, true, "TransientError", 1},
        {T::tls, true, "VeeamError", 1},
        {T::other, true, "VeeamError", 1},
    }));
    CAPTURE(error, on_sign_in);
    Lab lab;
    const auto fail = [error = error](const HttpRequest& request) -> HttpResponse {
        throw rp::HttpError(std::string{rp::to_string(request.method)} + " " + request.url +
                                ": failed",
                            error, 0, 1);
    };
    const std::string url = on_sign_in ? kTokenUrl : orgs_url();
    const HttpMethod method = on_sign_in ? HttpMethod::post : HttpMethod::get;
    lab.http.on(method, url, fail);
    auto client = lab.make_client();

    try {
        client->list_organizations();
        FAIL("list_organizations() returned after a transport failure");
    } catch (const rp::VeeamError& e) {
        CHECK(e.status() == 0);
        CHECK(thrown_kind([&e] { throw; }) == kind);
        const std::string expected =
            "Veeam " + std::string{on_sign_in ? "POST " : "GET "} + url + ": failed" +
            (sends > 1 ? " (" + std::to_string(sends) + " attempts)" : std::string{});
        CHECK(std::string{e.what()} == expected);
    }
    CHECK(lab.http.count(method, url) == static_cast<std::size_t>(sends));
    CHECK(lab.sleeps.size() == static_cast<std::size_t>(sends - 1));
    // HttpClient makes one attempt per send; the client counts them all.
    for (const HttpRequest& request : lab.http.requests()) {
        CHECK(request.max_attempts == 1);
    }
}

TEST_CASE("a GET makes five attempts in all, whatever mix of failures", "[veeam]")
{
    // One budget for transport failures and transient 5xx together: HttpClient
    // retrying under the client's own retries made 25 requests of one GET.
    Lab lab;
    std::atomic<int> gets = 0;
    lab.http.on(HttpMethod::get, orgs_url(), [&](const HttpRequest& request) -> HttpResponse {
        const int n = ++gets;
        if (n == 1 || n == 4) {
            throw rp::HttpError("GET " + request.url + ": timed out", rp::TransportError::timeout,
                                0, 1);
        }
        return make_response(503);
    });
    auto client = lab.make_client();

    try {
        client->list_organizations();
        FAIL("list_organizations() returned after five failures");
    } catch (const rp::TransientError& e) {
        CHECK(std::string{e.what()} ==
              "Veeam GET /v8/Organizations?limit=1000&offset=0: HTTP 503 after 5 attempts");
    }
    CHECK(gets == 5);
    CHECK(lab.sleeps == std::vector<std::chrono::milliseconds>{1000ms, 2000ms, 4000ms, 8000ms});
}

TEST_CASE("a sign-in is resent only when it can't have reached Veeam", "[veeam]")
{
    Lab lab;
    lab.on_login = [](int n) -> HttpResponse {
        if (n <= 2) {
            throw rp::HttpError("POST https://veeam.test:4443/v8/token: could not connect",
                                rp::TransportError::connect, 0, 1);
        }
        return token_response("access-login-" + std::to_string(n), "r");
    };
    auto client = lab.make_client();

    client->login();

    CHECK(lab.logins == 3);
    CHECK(lab.sleeps == std::vector<std::chrono::milliseconds>{1000ms, 2000ms});
}

TEST_CASE("a token response without a usable token is a VeeamError that doesn't quote it",
          "[veeam]")
{
    const std::string body = GENERATE(
        R"({"refresh_token":"SENTINEL_RT_9c1d","expires_in":3600})",
        R"({"access_token":"","refresh_token":"SENTINEL_RT_9c1d","expires_in":3600})",
        R"({"access_token":"SENTINEL_AT_77aa","refresh_token":"SENTINEL_RT_9c1d"})",
        R"({"access_token":"SENTINEL_AT_77aa","refresh_token":"SENTINEL_RT_9c1d","expires_in":0})",
        R"({"access_token":"SENTINEL_AT_77aa","refresh_token":"SENTINEL_RT_9c1d","expires_in":"3600"})",
        R"({"access_token":["SENTINEL_AT_77aa"],"expires_in":3600})",
        R"(["SENTINEL_AT_77aa"])", "SENTINEL_AT_77aa not json");
    CAPTURE(body);
    Lab lab;
    lab.on_login = [body](int) { return make_response(200, body); };
    auto client = lab.make_client();

    try {
        client->login();
        FAIL("login() accepted a token response without a usable token");
    } catch (const rp::AuthError&) {
        FAIL("a malformed token response isn't a refusal");
    } catch (const rp::VeeamError& e) {
        const std::string what = e.what();
        CAPTURE(what);
        CHECK(e.body().empty());
        CHECK(what.find("SENTINEL") == std::string::npos);
        CHECK(what.starts_with("Veeam POST /v8/token: "));
    }
    CHECK(lab.log().find("SENTINEL") == std::string::npos);
}

TEST_CASE("a list response of the wrong shape is a VeeamError", "[veeam]")
{
    const std::string body = GENERATE(
        "not json", "[]", "{}", R"({"results":{}})", R"({"results":[1]})",
        R"({"results":[{"name":"no id"}]})", R"({"results":[{"id":7,"name":"x"}]})",
        R"({"results":[{"id":"ff96d072-29e2-4cb4-a155-2590f5473176"}]})",
        R"({"results":[{"id":"x","name":"y","msid":5}]})");
    CAPTURE(body);
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {make_response(200, body)});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->list_organizations(); }) == "VeeamError");
}

TEST_CASE("a backupTime that isn't a UTC time in Veeam's form is a VeeamError", "[veeam]")
{
    // Explore sessions are opened by this exact string: a point whose time
    // Veeam itself would refuse (veeam-notes §4.2) can't be tested.
    const json backup_time = GENERATE(
        json("2026-09-25T19:37:15.2145203+00:00"), json("2026-09-25T19:37:15"),
        json("2026-09-25T19:37:15.12345678Z"), json("2026-09-25T19:37:15.Z"),
        json("2026-09-25 19:37:15Z"), json("2026-9-25T19:37:15Z"), json("2026-13-25T19:37:15Z"),
        json("2026-09-25T24:00:00Z"), json("2026-09-25T19:37:15.21x5203Z"), json("yesterday"),
        // A fraction too long for an int: refused before it is read.
        json("2026-09-25T19:37:15.123456789012Z"),
        json(""), json(20260925), json(nullptr));
    CAPTURE(backup_time.dump());
    Lab lab;
    lab.http.on(HttpMethod::get, points_url(), {points_page({backup_time})});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->list_restore_points(kOrgId); }) == "VeeamError");
}

TEST_CASE("an organisation ID that isn't a UUID is refused before any request", "[veeam]")
{
    const std::string id = GENERATE(
        "", "not-a-guid", "ff96d072-29e2-4cb4-a155-2590f547317",
        "ff96d072-29e2-4cb4-a155-2590f54731766", "ff96d072x29e2-4cb4-a155-2590f5473176",
        "ff96d072-29e2-4cb4-a155-2590f547317g", "ff96d072-29e2-4cb4-a155-2590f5473176&limit=1",
        "{ff96d072-29e2-4cb4-a155-2590f5473176}");
    CAPTURE(id);
    Lab lab;
    auto client = lab.make_client();

    CHECK_THROWS_AS(client->list_restore_points(id), std::invalid_argument);
    CHECK(lab.http.requests().empty());
}

TEST_CASE("paging that makes no progress is a VeeamError, not an endless loop", "[veeam]")
{
    // A server that ignores offset returns the same full page for ever.
    Lab lab;
    for (int offset : {0, 1, 2, 3}) {
        lab.http.on(HttpMethod::get, points_url(kOrgId, 1, offset),
                    {load_fixture("veeam", "restore-points-page1")});
    }
    auto client = lab.make_client(1);

    try {
        client->list_restore_points(kOrgId);
        FAIL("list_restore_points() returned for a server that repeats one page");
    } catch (const rp::VeeamError& e) {
        CHECK(std::string{e.what()} ==
              "Veeam GET /v8/RestorePoints?organizationId=" + kOrgId +
                  "&limit=1&offset=3: 3 full pages in a row brought nothing new; paging stopped");
    }
    CHECK(lab.http.requests().size() == 5); // sign-in and four pages
}

TEST_CASE("a full page of points already seen isn't the end while later pages move on",
          "[veeam]")
{
    // A backup finishing between two reads puts a point in front, so with
    // limit=1 the next page repeats the last one; the page after moves on
    // (W1.5 review).
    Lab lab;
    const auto page = [](const std::string& id) {
        json results = json::array();
        if (!id.empty()) {
            results.push_back(
                {{"id", id}, {"backupTime", "2026-09-25T19:00:0" + id.substr(1) + "Z"}});
        }
        return make_response(200, json{{"results", results}}.dump());
    };
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1, 0), {page("p1")});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1, 1), {page("p1")});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1, 2), {page("p2")});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1, 3), {page("")});
    auto client = lab.make_client(1);

    const std::vector<rp::RestorePoint> points = client->list_restore_points(kOrgId);

    REQUIRE(points.size() == 2);
    CHECK(points[0].id == "p2");
    CHECK(points[1].id == "p1");
}

TEST_CASE("the constructor refuses what can't work", "[veeam]")
{
    rp::test::FakeHttpClient http;
    CHECK_THROWS_AS(rp::VeeamClient(http, "", kUsername, kPassword), std::invalid_argument);
    CHECK_THROWS_AS(rp::VeeamClient(http, kBase, "", kPassword), std::invalid_argument);
    CHECK_THROWS_AS(rp::VeeamClient(http, kBase, kUsername, ""), std::invalid_argument);
    // The password grant must never go out in clear.
    CHECK_THROWS_AS(rp::VeeamClient(http, "http://veeam.test:4443", kUsername, kPassword),
                    std::invalid_argument);
    CHECK_NOTHROW(rp::VeeamClient(http, "HTTPS://veeam.test:4443", kUsername, kPassword));
    rp::VeeamClientOptions no_timeout;
    no_timeout.timeout = 0ms;
    CHECK_THROWS_AS(rp::VeeamClient(http, kBase, kUsername, kPassword, no_timeout),
                    std::invalid_argument);
    const int page_size = GENERATE(-1, 0, 10001);
    CAPTURE(page_size);
    rp::VeeamClientOptions options;
    options.page_size = page_size;
    CHECK_THROWS_AS(rp::VeeamClient(http, kBase, kUsername, kPassword, options),
                    std::invalid_argument);
    CHECK(http.requests().empty());
}

TEST_CASE("a failed refresh and a refused sign-in end in an AuthError", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    lab.on_refresh = [](int, const std::string&) {
        return load_fixture("veeam", "token-refresh-invalid-401");
    };
    auto client = lab.make_client();
    client->login();
    lab.on_login = [](int) { return load_fixture("veeam", "token-rejected-401"); };
    lab.advance(3540s);

    CHECK(thrown_kind([&] { client->list_organizations(); }) == "AuthError");
    CHECK(lab.grants() == std::vector<std::string>{"password", "refresh_token", "password"});
    CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 0);
}

TEST_CASE("callers waiting behind a failed sign-in share its failure", "[veeam]")
{
    // Veeam down: every token request takes HttpClient's five attempts. Eight
    // callers must not try one after another, each taking that long.
    constexpr int kThreads = 8;
    Lab lab;
    std::atomic<int> ready = 0;
    lab.on_login = [&ready](int) -> HttpResponse {
        // Every caller has started; give them time to queue on the lock.
        while (ready.load() < kThreads) {
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(100ms);
        throw rp::HttpError("POST https://veeam.test:4443/v8/token: timed out",
                            rp::TransportError::timeout, 0, 1);
    };
    auto client = lab.make_client();

    std::atomic<int> transient = 0;
    std::atomic<int> other = 0;
    {
        std::vector<std::jthread> threads;
        for (int i = 0; i < kThreads; ++i) {
            threads.emplace_back([&] {
                ++ready;
                try {
                    client->list_organizations();
                } catch (const rp::TransientError&) {
                    ++transient;
                } catch (...) {
                    ++other; // checked after the join: nothing escapes a thread
                }
            });
        }
    }

    CHECK(other == 0);
    CHECK(transient == kThreads);
    CHECK(lab.logins == 1);

    // A later call is a new attempt, not the old failure.
    lab.on_login = [](int n) { return token_response("access-login-" + std::to_string(n), "r"); };
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    CHECK(client->list_organizations().size() == 1);
    CHECK(lab.logins == 2);
}

TEST_CASE("a refresh that brings no refresh token leaves the next renewal to the password",
          "[veeam]")
{
    Lab lab;
    lab.on_refresh = [](int n, const std::string&) {
        json fixture = load_fixture_json("veeam", "token-refresh-200");
        fixture["body"]["access_token"] = "access-refresh-" + std::to_string(n);
        fixture["body"].erase("refresh_token");
        return to_response(fixture);
    };
    auto client = lab.make_client();

    client->login();
    lab.advance(3540s);
    client->ensure_token(); // refresh 1: no refresh token comes back
    lab.advance(3540s);
    client->ensure_token(); // so this renewal signs in with the password

    CHECK(lab.grants() == std::vector<std::string>{"password", "refresh_token", "password"});
}

TEST_CASE("a token lifetime is kept within bounds", "[veeam]")
{
    // expires_in at or below twice the margin: refresh at half the lifetime,
    // so a short-lived token isn't refreshed on every call. Above a day: a
    // day, so no arithmetic can overflow and a token isn't trusted for ever.
    const auto [expires_in, refresh_after] =
        GENERATE(table<std::int64_t, std::chrono::milliseconds>({
            {3600, 3540s},
            {120, 60s},
            {30, 15s},
            {1, 500ms},
            {86400, 86340s},
            {9'000'000'000'000LL, 86340s},
        }));
    CAPTURE(expires_in);
    Lab lab;
    lab.on_login = [expires_in = expires_in](int n) {
        json fixture = load_fixture_json("veeam", "token-200");
        fixture["body"]["access_token"] = "access-login-" + std::to_string(n);
        fixture["body"]["refresh_token"] = "r";
        fixture["body"]["expires_in"] = expires_in;
        return to_response(fixture);
    };
    auto client = lab.make_client();

    client->login();
    lab.advance(refresh_after - 1ms);
    client->ensure_token();
    CHECK(lab.refreshes == 0);
    lab.advance(1ms);
    client->ensure_token();
    CHECK(lab.refreshes == 1);
}

TEST_CASE("a 401 on the resend with a newer token gets one fresh sign-in", "[veeam]")
{
    // Another caller replaced the token, then a REST service restart killed
    // the newer one too (veeam-notes §1.3): the recovery a restart needs.
    const bool recovers = GENERATE(true, false);
    CAPTURE(recovers);
    Lab lab;
    std::unique_ptr<rp::VeeamClient> client = lab.make_client();
    std::atomic<int> gets = 0;
    lab.http.on(HttpMethod::get, orgs_url(), [&](const HttpRequest& request) {
        if (++gets == 1) {
            client->login(); // another caller replaces the token meanwhile
        }
        if (recovers && bearer(request) == "Bearer access-login-3") {
            return load_fixture("veeam", "organizations-200");
        }
        return load_fixture("veeam", "api-invalid-token-401");
    });

    if (recovers) {
        CHECK(client->list_organizations().size() == 1);
    } else {
        try {
            client->list_organizations();
            FAIL("list_organizations() returned after three 401s");
        } catch (const rp::AuthError& e) {
            CHECK(std::string{e.what()} ==
                  "Veeam GET /v8/Organizations?limit=1000&offset=0: HTTP 401 again after "
                  "signing in afresh");
        }
    }
    // The first sign-in, the other caller's, and this call's one fresh one.
    CHECK(lab.logins == 3);
    CHECK(gets == 3);
    std::vector<std::string> bearers;
    for (const HttpRequest& request : lab.http.requests()) {
        if (request.method == HttpMethod::get) {
            bearers.push_back(bearer(request));
        }
    }
    CHECK(bearers == std::vector<std::string>{"Bearer access-login-1", "Bearer access-login-2",
                                              "Bearer access-login-3"});
}

TEST_CASE("a newer token that is itself about to expire is refreshed before the resend",
          "[veeam]")
{
    Lab lab;
    std::unique_ptr<rp::VeeamClient> client = lab.make_client();
    std::atomic<int> gets = 0;
    lab.http.on(HttpMethod::get, orgs_url(), [&](const HttpRequest&) {
        if (++gets == 1) {
            client->login();     // another caller's token...
            lab.advance(3540s);  // ...and this request took most of an hour
            return load_fixture("veeam", "api-invalid-token-401");
        }
        return load_fixture("veeam", "organizations-200");
    });

    CHECK(client->list_organizations().size() == 1);
    CHECK(lab.refreshes == 1);
    CHECK(bearer(lab.http.requests().back()) == "Bearer access-refresh-1");
}

TEST_CASE("a page shorter than asked but as long as Veeam's own limit isn't the end", "[veeam]")
{
    // Veeam echoes the limit it applied. If it caps the one asked for, a full
    // page of that size isn't the last one.
    Lab lab;
    const auto page = [](int offset, int count, int limit) {
        json results = json::array();
        for (int i = 0; i < count; ++i) {
            results.push_back({{"id", "p" + std::to_string(offset + i)},
                               {"backupTime",
                                "2026-09-25T19:00:00." + std::to_string(offset + i) + "Z"}});
        }
        return make_response(
            200, json{{"offset", offset}, {"limit", limit}, {"results", results}}.dump());
    };
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1000, 0), {page(0, 3, 3)});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1000, 3), {page(3, 2, 3)});
    auto client = lab.make_client();

    CHECK(client->list_restore_points(kOrgId).size() == 5);
}

TEST_CASE("a list GET answered with no content is a VeeamError", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {make_response(204)});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->list_organizations(); }) == "VeeamError");
}

TEST_CASE("a token-endpoint error keeps no body: a proxy may echo the password back", "[veeam]")
{
    Lab lab;
    lab.on_login = [](int) {
        return make_response(400, "grant_type=password&username=x&password=" + kPasswordForm,
                             "text/plain");
    };
    auto client = lab.make_client();

    try {
        client->login();
        FAIL("login() returned after a 400");
    } catch (const rp::VeeamError& e) {
        CHECK(e.body().empty());
        CHECK(std::string{e.what()}.find(kPasswordForm) == std::string::npos);
    }
}

TEST_CASE("a Veeam message is cut at 500 bytes without splitting a character", "[veeam]")
{
    // 499 ASCII bytes, then "ö" (2 bytes in UTF-8) across the cut.
    const std::string message = std::string(499, 'x') + "\xc3\xb6" + std::string(100, 'y');
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {make_response(400, json{{"message", message}}.dump())});
    auto client = lab.make_client();

    try {
        client->list_organizations();
        FAIL("list_organizations() returned after a 400");
    } catch (const rp::VeeamError& e) {
        CHECK(std::string{e.what()}.ends_with(": " + std::string(499, 'x') + "..."));
    }
}

TEST_CASE("a renewal failure is shared only while no renewal has succeeded since", "[veeam]")
{
    // W1.5 review: a caller that waited while B's sign-in failed was handed
    // B's error even after C's later sign-in had succeeded. Here the caller's
    // request is in flight (its GET handler plays B and C, on the caller's
    // thread, so the order is fixed) and comes back with an empty 401.
    const bool c_signs_in = GENERATE(true, false);
    CAPTURE(c_signs_in);
    Lab lab;
    std::unique_ptr<rp::VeeamClient> client = lab.make_client();
    client->login();
    std::atomic<int> gets = 0;
    std::atomic<int> b_failed = 0;
    lab.http.on(HttpMethod::get, orgs_url(), [&](const HttpRequest&) {
        if (++gets == 1) {
            lab.on_login = [](int) -> HttpResponse {
                throw rp::HttpError("POST https://veeam.test:4443/v8/token: timed out",
                                    rp::TransportError::timeout, 0, 1);
            };
            try {
                client->login(); // B
            } catch (const rp::TransientError&) {
                ++b_failed;
            }
            lab.on_login = [](int n) {
                return token_response("access-login-" + std::to_string(n), "r");
            };
            if (c_signs_in) {
                client->login(); // C
            }
            return load_fixture("veeam", "api-invalid-token-401");
        }
        return load_fixture("veeam", "organizations-200");
    });

    if (c_signs_in) {
        // C's token works: the caller resends with it, B's error is history.
        CHECK(client->list_organizations().size() == 1);
        CHECK(lab.logins == 3);
        CHECK(bearer(lab.http.requests().back()) == "Bearer access-login-3");
    } else {
        // Nothing has worked since B failed: the caller gets B's failure
        // rather than trying again itself.
        CHECK(thrown_kind([&] { client->list_organizations(); }) == "TransientError");
        CHECK(lab.logins == 2);
        CHECK(gets == 1);
    }
    CHECK(b_failed == 1);
}

TEST_CASE("a deeply nested value in a list entry doesn't overflow the stack", "[veeam]")
{
    // Parsing and destroying JSON are iterative, copying it is recursive: an
    // entry is moved out of its page, never copied (W1.5 review).
    constexpr std::size_t kDepth = 100000;
    const std::string deep = std::string(kDepth, '[') + std::string(kDepth, ']');
    const std::string body =
        R"({"results":[{"id":"p0","backupTime":"2026-09-25T19:37:15Z","z":)" + deep + "}]}";
    Lab lab;
    lab.http.on(HttpMethod::get, points_url(), {make_response(200, body)});
    auto client = lab.make_client();

    const std::vector<rp::RestorePoint> points = client->list_restore_points(kOrgId);

    REQUIRE(points.size() == 1);
    CHECK(points[0].id == "p0");
}

TEST_CASE("control characters in Veeam's text never reach an error message", "[veeam]")
{
    // Multi-byte ones too, the set config.cpp refuses in values: C1 controls
    // (NEL), the line and paragraph separators, bidi marks, embeddings,
    // overrides and isolates, and the Arabic letter mark. Each can forge or
    // reorder a log line.
    const std::string message = R"(a\nb\u0085c\u2028d\u2029e\u202Ef\u2066g\u2069h\u061Ci\u200Fj\u200Ek\u202Al)";
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {make_response(400, R"({"message":")" + message + R"(","errorCode":"X\u2028Y"})")});
    auto client = lab.make_client();

    try {
        client->list_organizations();
        FAIL("list_organizations() returned after a 400");
    } catch (const rp::VeeamError& e) {
        CHECK(std::string{e.what()} ==
              "Veeam GET /v8/Organizations?limit=1000&offset=0: HTTP 400 (X Y): a b c d e f g h i "
              "j k l");
        CHECK(e.error_code() == "X Y");
    }
}

TEST_CASE("an expires_in too large for a signed 64-bit number is capped, not refused",
          "[veeam]")
{
    Lab lab;
    lab.on_login = [](int n) {
        json fixture = load_fixture_json("veeam", "token-200");
        fixture["body"]["access_token"] = "access-login-" + std::to_string(n);
        fixture["body"]["refresh_token"] = "r";
        fixture["body"]["expires_in"] = std::uint64_t{18446744073709551615ULL};
        return to_response(fixture);
    };
    auto client = lab.make_client();

    client->login();
    lab.advance(86340s - 1ms);
    client->ensure_token();
    CHECK(lab.refreshes == 0);
    lab.advance(1ms);
    client->ensure_token();
    CHECK(lab.refreshes == 1);
}

// --- Happy paths --------------------------------------------------------------

TEST_CASE("the sign-in is a form-encoded password grant with the antiforgery flag", "[veeam]")
{
    Lab lab;
    rp::VeeamClientOptions options;
    options.timeout = 45s;
    // A trailing '/' on the configured URL is ignored.
    rp::VeeamClient client(lab.http, kBase + "/", kUsername, kPassword, options);

    client.login();

    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].method == HttpMethod::post);
    CHECK(sent[0].url == kTokenUrl);
    CHECK(sent[0].content_type == "application/x-www-form-urlencoded");
    CHECK(sent[0].body == "grant_type=password&username=DESKTOP-P55CDUM%5Crp-veeam&password=" +
                              kPasswordForm + "&disable_antiforgery_token=true");
    CHECK(sent[0].headers.find("Authorization") == sent[0].headers.end());
    CHECK(sent[0].headers.at("Accept") == "application/json");
    CHECK_FALSE(sent[0].retry_on_status);
    CHECK(sent[0].max_attempts == 1);
    CHECK(sent[0].timeout == 45s);
}

TEST_CASE("list_organizations reads every organisation with the bearer token", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    auto client = lab.make_client();

    const std::vector<rp::Organization> orgs = client->list_organizations();

    REQUIRE(orgs.size() == 1);
    CHECK(orgs[0].id == kOrgId);
    CHECK(orgs[0].name == "RestoreProofLab.onmicrosoft.com");
    CHECK(orgs[0].msid == "bcd6bd1a-ea42-489d-aa28-2c19a44ad146");
    CHECK(orgs[0].region == "Worldwide");
    CHECK(orgs[0].office_name == "RestoreProofLab.onmicrosoft.com");
    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 2);
    CHECK(sent[1].method == HttpMethod::get);
    CHECK(bearer(sent[1]) == "Bearer access-login-1");
    CHECK(sent[1].headers.at("Accept") == "application/json");
    CHECK_FALSE(sent[1].retry_on_status);
    CHECK(sent[1].max_attempts == 1);
    CHECK(sent[1].timeout == 45s);
}

TEST_CASE("restore points come back newest first whatever order Veeam sends", "[veeam]")
{
    const std::string fixture = GENERATE("restore-points-200", "restore-points-asc-200");
    CAPTURE(fixture);
    Lab lab;
    lab.http.on(HttpMethod::get, points_url(), {load_fixture("veeam", fixture)});
    auto client = lab.make_client();

    const std::vector<rp::RestorePoint> points = client->list_restore_points(kOrgId);

    REQUIRE(points.size() == 2);
    CHECK(points[0].id == kNewestPoint);
    CHECK(points[0].backup_time == "2026-09-25T19:37:15.2145203Z");
    CHECK(points[1].id == kOldestPoint);
    CHECK(points[1].backup_time == "2026-09-25T19:24:31.0936821Z");
    for (const rp::RestorePoint& point : points) {
        CHECK(point.id.size() == 72);
        CHECK(point.organization_id == kOrgId);
        CHECK(point.repository_id == "c2f0f2e7-177f-48ac-992b-93a50cf702e3");
        CHECK(point.job_id == "4cf03510-457c-401b-a1c6-e7e69be296e1");
        CHECK(point.is_exchange);
        CHECK(point.is_sharepoint);
        CHECK(point.is_onedrive);
        CHECK_FALSE(point.is_teams);
        CHECK_FALSE(point.is_deleted);
        CHECK_FALSE(point.is_long_term_copy);
        CHECK_FALSE(point.is_copy);
    }
}

TEST_CASE("restore points are paged until a page is short", "[veeam]")
{
    // The recorded pages of limit=1 hold one point each, so the second is
    // still full and a third, empty page ends the list.
    Lab lab;
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1, 0), {load_fixture("veeam", "restore-points-page1")});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1, 1), {load_fixture("veeam", "restore-points-page2")});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 1, 2),
                {load_fixture("veeam", "restore-points-empty-200")});
    auto client = lab.make_client(1);

    const std::vector<rp::RestorePoint> points = client->list_restore_points(kOrgId);

    REQUIRE(points.size() == 2);
    CHECK(points[0].id == kNewestPoint);
    CHECK(points[1].id == kOldestPoint);
    for (int offset : {0, 1, 2}) {
        CHECK(lab.http.count(HttpMethod::get, points_url(kOrgId, 1, offset)) == 1);
    }
}

TEST_CASE("organisations are paged too", "[veeam]")
{
    Lab lab;
    // The recorded page echoes limit 30; these are pages of limit=1.
    json first = load_fixture_json("veeam", "organizations-200");
    first["body"]["limit"] = 1;
    json second = first;
    second["body"]["offset"] = 1;
    second["body"]["results"][0]["id"] = "11111111-2222-3333-4444-555555555555";
    second["body"]["results"][0]["name"] = "second.onmicrosoft.com";
    lab.http.on(HttpMethod::get, orgs_url(1, 0), {to_response(first)});
    lab.http.on(HttpMethod::get, orgs_url(1, 1), {to_response(second)});
    lab.http.on(HttpMethod::get, orgs_url(1, 2), {make_response(200, R"({"results":[]})")});
    auto client = lab.make_client(1);

    const std::vector<rp::Organization> orgs = client->list_organizations();

    REQUIRE(orgs.size() == 2);
    CHECK(orgs[0].id == kOrgId);
    CHECK(orgs[1].name == "second.onmicrosoft.com");
}

TEST_CASE("a point seen on an earlier page is kept once", "[veeam]")
{
    // A backup finishing while the list is read pushes every point one place
    // down, so the next page starts with one already seen.
    Lab lab;
    const auto page = [](std::vector<std::string> ids) {
        json results = json::array();
        for (const std::string& id : ids) {
            results.push_back({{"id", id}, {"backupTime", "2026-09-25T19:00:0" + id.substr(1) + "Z"}});
        }
        return make_response(200, json{{"results", results}}.dump());
    };
    lab.http.on(HttpMethod::get, points_url(kOrgId, 2, 0), {page({"p1", "p2"})});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 2, 2), {page({"p2", "p3"})});
    lab.http.on(HttpMethod::get, points_url(kOrgId, 2, 4), {page({})});
    auto client = lab.make_client(2);

    const std::vector<rp::RestorePoint> points = client->list_restore_points(kOrgId);

    REQUIRE(points.size() == 3);
    CHECK(points[0].id == "p3");
    CHECK(points[1].id == "p2");
    CHECK(points[2].id == "p1");
}

TEST_CASE("backupTime is kept as sent and sorted by its value, not its text", "[veeam]")
{
    // Veeam's serializer drops trailing zeros from the fraction, so "…15Z"
    // (15.0 s) must sort before "…15.2Z" although 'Z' > '.' as text.
    Lab lab;
    lab.http.on(HttpMethod::get, points_url(),
                {points_page({json("2026-09-25T19:37:15Z"), json("2026-09-24T23:59:59.9999999Z"),
                              json("2026-09-25T19:37:15.2Z"), json("2027-01-01T00:00:00Z"),
                              json("2026-09-25T19:37:15.0000001Z")})});
    auto client = lab.make_client();

    const std::vector<rp::RestorePoint> points = client->list_restore_points(kOrgId);

    std::vector<std::string> times;
    for (const rp::RestorePoint& point : points) {
        times.push_back(point.backup_time);
    }
    CHECK(times == std::vector<std::string>{"2027-01-01T00:00:00Z", "2026-09-25T19:37:15.2Z",
                                            "2026-09-25T19:37:15.0000001Z", "2026-09-25T19:37:15Z",
                                            "2026-09-24T23:59:59.9999999Z"});
}

TEST_CASE("the token is refreshed 60 s before it expires, not earlier", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    auto client = lab.make_client();

    client->ensure_token(); // none yet: signs in
    CHECK(lab.grants() == std::vector<std::string>{"password"});

    lab.advance(3539s);
    client->list_organizations();
    CHECK(lab.refreshes == 0);

    lab.advance(1s); // 3540 s: 60 s left
    client->list_organizations();
    CHECK(lab.refreshes == 1);

    // The next refresh counts from the refreshed token's arrival and uses the
    // newest refresh token: the one it came with.
    lab.advance(3539s);
    client->list_organizations();
    CHECK(lab.refreshes == 1);
    lab.advance(1s);
    client->list_organizations();
    CHECK(lab.refreshes == 2);

    const std::vector<HttpRequest> sent = lab.http.requests();
    std::vector<std::string> refresh_tokens;
    std::vector<std::string> bearers;
    for (const HttpRequest& request : sent) {
        if (request.url == kTokenUrl && form_value(request.body, "grant_type") == "refresh_token") {
            refresh_tokens.push_back(form_value(request.body, "refresh_token"));
            CHECK(form_value(request.body, "disable_antiforgery_token") == "true");
        } else if (request.method == HttpMethod::get) {
            bearers.push_back(bearer(request));
        }
    }
    CHECK(refresh_tokens == std::vector<std::string>{"refresh-login-1", "refresh-refresh-1"});
    CHECK(bearers == std::vector<std::string>{"Bearer access-login-1", "Bearer access-refresh-1",
                                              "Bearer access-refresh-1", "Bearer access-refresh-2"});
    CHECK(lab.logins == 1);
}

TEST_CASE("the refresh point follows expires_in", "[veeam]")
{
    Lab lab;
    lab.on_login = [](int n) {
        return token_response("access-login-" + std::to_string(n), "r", 120);
    };
    auto client = lab.make_client();

    client->login();
    lab.advance(59s);
    client->ensure_token();
    CHECK(lab.refreshes == 0);
    lab.advance(1s); // 60 of 120 s: 60 s left
    client->ensure_token();
    CHECK(lab.refreshes == 1);
}

TEST_CASE("concurrent calls share one refresh", "[veeam]")
{
    constexpr int kThreads = 8;
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    lab.on_refresh = [](int n, const std::string&) {
        // Long enough for every other thread to be waiting on the lock.
        std::this_thread::sleep_for(50ms);
        return token_response("access-refresh-" + std::to_string(n), "refresh-refresh-1");
    };
    auto client = lab.make_client();
    client->login();
    lab.advance(3590s);

    std::atomic<int> succeeded = 0;
    std::atomic<int> failed = 0;
    {
        std::vector<std::jthread> threads;
        for (int i = 0; i < kThreads; ++i) {
            threads.emplace_back([&] {
                try {
                    if (client->list_organizations().size() == 1) {
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
    CHECK(lab.refreshes == 1);
    CHECK(lab.logins == 1);
    for (const HttpRequest& request : lab.http.requests()) {
        if (request.method == HttpMethod::get) {
            CHECK(bearer(request) == "Bearer access-refresh-1");
        }
    }
}

TEST_CASE("concurrent 401s share one fresh sign-in", "[veeam]")
{
    // A REST service restart kills the token every request in flight carries.
    constexpr int kThreads = 8;
    Lab lab;
    std::latch all_sent(kThreads);
    // Counted before the latch: a regression that resends the old token would
    // arrive a ninth time, and a latch counted below zero aborts the run.
    std::atomic<int> old_token_sends = 0;
    lab.http.on(HttpMethod::get, orgs_url(), [&](const HttpRequest& request) {
        if (bearer(request) == "Bearer access-login-1") {
            if (++old_token_sends <= kThreads) {
                all_sent.arrive_and_wait(); // every thread got its 401 with the same token
            }
            return load_fixture("veeam", "api-invalid-token-401");
        }
        return load_fixture("veeam", "organizations-200");
    });
    auto client = lab.make_client();
    client->login();

    std::atomic<int> succeeded = 0;
    std::atomic<int> failed = 0;
    {
        std::vector<std::jthread> threads;
        for (int i = 0; i < kThreads; ++i) {
            threads.emplace_back([&] {
                try {
                    if (client->list_organizations().size() == 1) {
                        ++succeeded;
                    }
                } catch (...) {
                    ++failed;
                }
            });
        }
    }

    CHECK(failed == 0);
    CHECK(old_token_sends == kThreads);
    CHECK(succeeded == kThreads);
    CHECK(lab.logins == 2);
    CHECK(lab.http.count(HttpMethod::get, orgs_url()) == 2 * kThreads);
}

TEST_CASE("logout ends the chain; a later call signs in again", "[veeam]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});

    SECTION("not signed in: nothing is sent")
    {
        auto client = lab.make_client();
        client->logout();
        CHECK(lab.http.requests().empty());
    }

    SECTION("signed in: POST /v8/token/logout with the bearer token")
    {
        lab.http.on(HttpMethod::post, kLogoutUrl, {load_fixture("veeam", "logout-204")});
        auto client = lab.make_client();
        client->login();
        client->logout();
        client->logout(); // the second has nothing to end

        CHECK(lab.http.count(HttpMethod::post, kLogoutUrl) == 1);
        const HttpRequest logout = lab.http.requests().back();
        CHECK(bearer(logout) == "Bearer access-login-1");
        CHECK(logout.body.empty());
        CHECK_FALSE(logout.retry_on_status);
        CHECK(logout.max_attempts == 1); // best effort: never resent

        client->list_organizations();
        CHECK(lab.logins == 2);
    }

    SECTION("an access token due for refresh is refreshed first: Veeam refuses an expired one")
    {
        // A refused logout would leave the refresh-token chain alive on Veeam
        // after the job (veeam-notes §1.5, §1.6).
        lab.http.on(HttpMethod::post, kLogoutUrl, {load_fixture("veeam", "logout-204")});
        auto client = lab.make_client();
        client->login();
        lab.advance(3540s);

        client->logout();

        CHECK(lab.grants() == std::vector<std::string>{"password", "refresh_token"});
        CHECK(bearer(lab.http.requests().back()) == "Bearer access-refresh-1");
    }

    SECTION("a refresh that fails before the logout doesn't stop it")
    {
        lab.http.on(HttpMethod::post, kLogoutUrl, {load_fixture("veeam", "logout-204")});
        lab.on_refresh = [](int, const std::string&) -> HttpResponse {
            throw rp::HttpError("POST https://veeam.test:4443/v8/token: could not connect",
                                rp::TransportError::connect, 0, 1);
        };
        auto client = lab.make_client();
        client->login();
        lab.advance(3540s);

        client->logout();

        // One try and no password sign-in: a logout is best effort.
        CHECK(lab.grants() == std::vector<std::string>{"password", "refresh_token"});
        CHECK(lab.sleeps.empty());
        CHECK(lab.http.count(HttpMethod::post, kLogoutUrl) == 1);
        CHECK(bearer(lab.http.requests().back()) == "Bearer access-login-1");
    }

    SECTION("a failed logout is swallowed and the tokens are forgotten anyway")
    {
        const auto failure = GENERATE(
            std::function<HttpResponse(const HttpRequest&)>{
                [](const HttpRequest&) { return make_response(500); }},
            std::function<HttpResponse(const HttpRequest&)>{
                [](const HttpRequest&) { return load_fixture("veeam", "api-invalid-token-401"); }},
            std::function<HttpResponse(const HttpRequest&)>{[](const HttpRequest&) -> HttpResponse {
                throw rp::HttpError("POST: could not connect", rp::TransportError::connect, 0, 5);
            }});
        lab.http.on(HttpMethod::post, kLogoutUrl, failure);
        auto client = lab.make_client();
        client->login();

        client->logout(); // noexcept: a throw here would terminate
        client->list_organizations();

        CHECK(lab.logins == 2);
    }
}

TEST_CASE("nothing secret reaches the log or an error message", "[veeam]")
{
    // A whole session: sign-in, a revoked token and a fresh sign-in, a
    // refresh, a refused refresh, and a logout. The tokens and the password
    // go out in headers and bodies, which are never logged.
    Lab lab;
    lab.on_refresh = [](int n, const std::string&) {
        return n == 1 ? token_response("access-refresh-1", "refresh-refresh-1")
                      : load_fixture("veeam", "token-refresh-invalid-401");
    };
    std::atomic<int> gets = 0;
    lab.http.on(HttpMethod::get, orgs_url(), [&](const HttpRequest&) {
        return ++gets == 1 ? load_fixture("veeam", "api-expired-token-401")
                           : load_fixture("veeam", "organizations-200");
    });
    lab.http.on(HttpMethod::post, kLogoutUrl, {load_fixture("veeam", "logout-204")});
    auto client = lab.make_client();

    client->list_organizations();
    lab.advance(3540s);
    client->list_organizations();
    lab.advance(3540s);
    client->list_organizations();
    client->logout();
    lab.on_login = [](int) { return load_fixture("veeam", "token-rejected-401"); };
    std::string what;
    try {
        client->list_organizations();
    } catch (const rp::AuthError& e) {
        what = e.what();
    }

    CHECK(lab.grants() == std::vector<std::string>{"password", "password", "refresh_token",
                                                   "refresh_token", "password", "password"});
    const std::string log = lab.log();
    CAPTURE(log);
    CHECK_FALSE(what.empty());
    for (const std::string& secret :
         {kPassword, kPasswordForm, std::string{"access-login"}, std::string{"refresh-login"},
          std::string{"access-refresh"}, std::string{"refresh-refresh"}}) {
        CHECK(log.find(secret) == std::string::npos);
        CHECK(what.find(secret) == std::string::npos);
    }
    // And the log says what happened.
    CHECK(count_of(log, "signed in") == 3);
    CHECK(count_of(log, "token refreshed") == 1);
    CHECK(count_of(log, "refresh failed") == 1);
    CHECK(count_of(log, "signing in again") >= 1);
    CHECK(count_of(log, "logged out") == 1);
}

// --- W2.5: the organisation app, browsing, explore, restore POST, Stop -------

namespace {

const std::string kSessionId = "6ee50a66-c46f-4200-b793-c03f8bcbbb8b";
const std::string kBackupTime = "2026-09-25T19:37:15.2145203Z";
const std::string kExploreUrl = kBase + "/v8/Organizations/" + kOrgId + "/explore";
const std::string kRestorePath =
    "/v8/RestoreSessions/171ea3e1-1f41-420c-94f7-140b57470d4a/organization/mailboxes/"
    "12af7578-24c6-48e4-a3a5-3174bda4f4d4/items/restoreTo";
// A restore body as W2.5 sends it, but for its secrets: they must never show
// up in an outcome, an error or the log.
const std::string kRestoreBody =
    R"({"mailbox":"restoretest@RestoreProofLab.onmicrosoft.com","folder":"Inbox",)"
    R"("applicationId":"1fd2609d-1242-43fe-94b5-d58688a90bd6",)"
    R"("applicationCertificate":"SENTINEL-PFX-MIIK","applicationCertificatePassword":"SENTINEL-PW"})";

// One organisation entry with `settings` under `key` ("absent": no key).
HttpResponse org_with_settings(const std::string& key, const std::string& settings)
{
    json org = {{"id", kOrgId}, {"name", "RestoreProofLab.onmicrosoft.com"}};
    if (settings != "absent") {
        org[key] = json::parse(settings);
    }
    return make_response(200,
                         json{{"offset", 0}, {"limit", 1000}, {"results", json::array({org})}}
                             .dump());
}

std::optional<rp::OrganizationApp> app_of(const rp::Organization& org, const std::string& key)
{
    return key == "exchangeOnlineSettings" ? org.exchange_app : org.sharepoint_app;
}

// Throws the transport failure `error`, as HttpClient does.
[[noreturn]] void throw_transport(const HttpRequest& request, rp::TransportError error)
{
    throw rp::HttpError("POST " + request.url + ": no response", error, 0, 1);
}

using Answer = std::function<HttpResponse(const HttpRequest&)>;

Answer transport(rp::TransportError error)
{
    return [error](const HttpRequest& request) -> HttpResponse { throw_transport(request, error); };
}

Answer respond(HttpResponse response)
{
    return [response](const HttpRequest&) { return response; };
}

} // namespace

TEST_CASE("an organisation app field of the wrong JSON kind is a VeeamError", "[veeam][w2.5]")
{
    const std::string key = GENERATE("exchangeOnlineSettings", "sharePointOnlineSettings");
    const std::string settings = GENERATE(
        R"("x")", "[]", "5", "true",
        R"({"applicationId":5,"applicationCertificateThumbprint":"T"})",
        R"({"applicationId":"A","applicationCertificateThumbprint":true})",
        R"({"applicationId":{},"applicationCertificateThumbprint":"T"})");
    CAPTURE(key, settings);
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {org_with_settings(key, settings)});
    auto client = lab.make_client();

    std::string what;
    CHECK(thrown_kind([&] {
              try {
                  client->list_organizations();
              } catch (const rp::VeeamError& e) {
                  what = e.what();
                  throw;
              }
          }) == "VeeamError");
    CHECK(what.starts_with("Veeam GET /v8/Organizations: unexpected response: "));
}

TEST_CASE("an organisation app is set only with both strings there and not empty",
          "[veeam][w2.5]")
{
    struct Row {
        std::string settings;
        bool set;
    };
    const std::string key = GENERATE("exchangeOnlineSettings", "sharePointOnlineSettings");
    const Row row = GENERATE(values<Row>({
        {"absent", false},
        {"null", false},
        {"{}", false},
        {R"({"applicationId":"A"})", false},
        {R"({"applicationCertificateThumbprint":"T"})", false},
        {R"({"applicationId":"A","applicationCertificateThumbprint":""})", false},
        {R"({"applicationId":"","applicationCertificateThumbprint":"T"})", false},
        {R"({"applicationId":null,"applicationCertificateThumbprint":"T"})", false},
        {R"({"applicationId":"A","applicationCertificateThumbprint":null})", false},
        {R"({"applicationId":"A","applicationCertificateThumbprint":"T","account":7})", true},
    }));
    CAPTURE(key, row.settings);
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {org_with_settings(key, row.settings)});
    auto client = lab.make_client();

    const std::vector<rp::Organization> orgs = client->list_organizations();

    REQUIRE(orgs.size() == 1);
    const auto app = app_of(orgs[0], key);
    CHECK(app.has_value() == row.set);
    if (app) {
        CHECK(app->application_id == "A");
        CHECK(app->certificate_thumbprint == "T");
    }
    // The other one was never sent.
    CHECK_FALSE(app_of(orgs[0], key == "exchangeOnlineSettings" ? "sharePointOnlineSettings"
                                                                 : "exchangeOnlineSettings"));
}

TEST_CASE("list_organizations reads the Exchange and SharePoint apps as Veeam sent them",
          "[veeam][w2.5]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
    auto client = lab.make_client();

    const std::vector<rp::Organization> orgs = client->list_organizations();

    REQUIRE(orgs.size() == 1);
    for (const auto& app : {orgs[0].exchange_app, orgs[0].sharepoint_app}) {
        REQUIRE(app.has_value());
        CHECK(app->application_id == "1fd2609d-1242-43fe-94b5-d58688a90bd6");
        CHECK(app->certificate_thumbprint == "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7");
    }
}

TEST_CASE("a path outside /v8/ is refused before any request", "[veeam][w2.5]")
{
    const std::string path = GENERATE("", "v8/RestoreSessions", "/v9/RestoreSessions",
                                      "/V8/RestoreSessions", "https://elsewhere.test/v8/x",
                                      "//elsewhere.test/v8/x", "/v8");
    CAPTURE(path);
    Lab lab;
    auto client = lab.make_client();

    CHECK_THROWS_AS(client->get_json(path), std::invalid_argument);
    CHECK_THROWS_AS(client->get_ordered_json(path), std::invalid_argument);
    CHECK_THROWS_AS(client->get_all(path), std::invalid_argument);
    CHECK_THROWS_AS(client->post_restore_once(path, kRestoreBody, 60s), std::invalid_argument);
    CHECK(lab.http.requests().empty());
}

TEST_CASE("get_json maps Veeam's answers as the list calls do", "[veeam][w2.5]")
{
    struct Row {
        HttpResponse response;
        std::string kind;
        std::size_t sends;
    };
    const Row row = GENERATE(values<Row>({
        {load_fixture("veeam", "organization-404"), "NotFoundError", 1},
        {load_fixture("veeam", "statistics-409"), "VeeamError", 1},
        {load_fixture("veeam", "explore-500-not-utc"), "VeeamError", 1},
        {make_response(503), "TransientError", 5},
        {make_response(403, R"({"message":"no role"})"), "AuthError", 1},
        {make_response(200, "not json"), "VeeamError", 1},
        {make_response(200, ""), "VeeamError", 1},
    }));
    CAPTURE(row.response.status, row.kind);
    Lab lab;
    const std::string path = "/v8/RestoreSessions/" + kSessionId + "/Statistics";
    lab.http.on(HttpMethod::get, kBase + path, {row.response});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->get_json(path); }) == row.kind);
    CHECK(lab.http.count(HttpMethod::get, kBase + path) == row.sends);
}

TEST_CASE("get_json signs in afresh after an empty 401 and returns the JSON", "[veeam][w2.5]")
{
    Lab lab;
    const std::string url = kBase + "/v8/RestoreSessions/" + kSessionId;
    lab.http.on(HttpMethod::get, url,
                {load_fixture("veeam", "api-expired-token-401"),
                 load_fixture("veeam", "session-working")});
    auto client = lab.make_client();

    const json doc = client->get_json("/v8/RestoreSessions/" + kSessionId);

    CHECK(doc.at("state") == "Working");
    CHECK(lab.logins == 2);
    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 4);
    CHECK(bearer(sent[3]) == "Bearer access-login-2");
    CHECK(sent[3].method == HttpMethod::get);
    CHECK(sent[3].timeout == 45s);
}

TEST_CASE("get_ordered_json keeps the keys in Veeam's order", "[veeam][w2.5]")
{
    Lab lab;
    const std::string body =
        R"({"name":"a.docx","id":"x","_links":{"self":{"href":"/v8"}},"sizeBytes":5})";
    lab.http.on(HttpMethod::get, kBase + "/v8/RestoreSessions/" + kSessionId,
                {make_response(200, body)});
    auto client = lab.make_client();

    CHECK(client->get_ordered_json("/v8/RestoreSessions/" + kSessionId).dump() == body);
    CHECK(thrown_kind([&] {
              lab.http.on(HttpMethod::get, kBase + "/v8/RestoreSessions/" + kSessionId,
                          {make_response(200, "{")});
              client->get_ordered_json("/v8/RestoreSessions/" + kSessionId);
          }) == "VeeamError");
}

TEST_CASE("get_all pages a browse list after its own query", "[veeam][w2.5]")
{
    Lab lab;
    const std::string path = "/v8/RestoreSessions/" + kSessionId + "/organization/mailboxes";
    lab.http.on(HttpMethod::get, kBase + path + "?limit=2&offset=0",
                {make_response(200, R"({"results":[{"id":"m1"},{"id":"m2"}]})")});
    lab.http.on(HttpMethod::get, kBase + path + "?limit=2&offset=2",
                {make_response(200, R"({"results":[{"id":"m3","email":"x@y"}]})")});
    const std::string with_query = path + "/m1/folders?name=Inbox";
    lab.http.on(HttpMethod::get, kBase + with_query + "&limit=2&offset=0",
                {make_response(200, R"({"results":[{"id":"f1"}]})")});
    auto client = lab.make_client(2);

    const std::vector<json> mailboxes = client->get_all(path);
    REQUIRE(mailboxes.size() == 3);
    CHECK(mailboxes[2].at("email") == "x@y");
    CHECK(client->get_all(with_query).size() == 1);
}

TEST_CASE("an explore session needs a UUID, a UTC time and a type before any request",
          "[veeam][w2.5]")
{
    struct Row {
        std::string org;
        std::string time;
        std::string type;
    };
    const Row row = GENERATE(values<Row>({
        {"not-a-uuid", kBackupTime, "Vex"},
        {kOrgId + "/x", kBackupTime, "Vex"},
        {kOrgId, "2026-09-25T19:37:15.2145203+00:00", "Vex"},
        {kOrgId, "2026-09-25T19:37:15", "Vesp"},
        {kOrgId, "", "Veod"},
        {kOrgId, R"(2026-09-25T19:37:15Z","type":"Vesp)", "Vex"},
        {kOrgId, kBackupTime, "vex"},
        {kOrgId, kBackupTime, "Mail"},
        {kOrgId, kBackupTime, ""},
        {kOrgId, kBackupTime, R"(Vex","showDeleted":true,"x":")"},
    }));
    CAPTURE(row.org, row.time, row.type);
    Lab lab;
    auto client = lab.make_client();

    CHECK_THROWS_AS(client->open_explore_session(row.org, row.time, row.type),
                    std::invalid_argument);
    CHECK(lab.http.requests().empty());
}

TEST_CASE("an explore session is opened with exactly the recorded body", "[veeam][w2.5]")
{
    const std::string type = GENERATE("Vex", "Vesp", "Veod");
    const std::string time = GENERATE(as<std::string>{}, "2026-09-25T19:37:15.2145203Z",
                                      "2026-09-27T22:00:48Z");
    CAPTURE(type, time);
    Lab lab;
    lab.http.on(HttpMethod::post, kExploreUrl, {load_fixture("veeam", "explore-201")});
    auto client = lab.make_client();

    CHECK(client->open_explore_session(kOrgId, time, type) == kSessionId);

    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 2);
    CHECK(sent[1].method == HttpMethod::post);
    CHECK(sent[1].url == kExploreUrl);
    CHECK(sent[1].body == R"({"dateTime":")" + time + R"(","type":")" + type +
                              R"(","showDeleted":false,"showAllVersions":false})");
    CHECK(sent[1].content_type == "application/json; charset=utf-8");
    CHECK(bearer(sent[1]) == "Bearer access-login-1");
    CHECK(sent[1].max_attempts == 1);
    CHECK_FALSE(sent[1].retry_on_status);
    CHECK(sent[1].timeout == 45s);
}

TEST_CASE("an explore answer without a session UUID is a VeeamError", "[veeam][w2.5]")
{
    const std::string body =
        GENERATE("", "not json", "[]", "{}", R"({"id":5})", R"({"id":"6ee50a66"})",
                 R"({"sessionId":"6ee50a66-c46f-4200-b793-c03f8bcbbb8b"})");
    CAPTURE(body);
    Lab lab;
    lab.http.on(HttpMethod::post, kExploreUrl, {make_response(201, body)});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->open_explore_session(kOrgId, kBackupTime, "Vex"); }) ==
          "VeeamError");
    CHECK(lab.http.count(HttpMethod::post, kExploreUrl) == 1);
}

TEST_CASE("an explore POST is resent only when it never went out, or after an empty 401",
          "[veeam][w2.5]")
{
    struct Row {
        std::string name;
        Answer first;        // then explore-201
        std::string outcome; // "none" or the exception kind
        std::size_t sends;
        int logins;
    };
    const Row row = GENERATE(values<Row>({
        {"connect", transport(rp::TransportError::connect), "none", 2, 1},
        {"handshake", transport(rp::TransportError::handshake), "none", 2, 1},
        {"dropped", transport(rp::TransportError::dropped), "TransientError", 1, 1},
        {"timeout", transport(rp::TransportError::timeout), "TransientError", 1, 1},
        {"503", respond(make_response(503)), "TransientError", 1, 1},
        {"500 with a message", respond(load_fixture("veeam", "explore-500-not-utc")),
         "VeeamError", 1, 1},
        {"empty 401", respond(load_fixture("veeam", "api-invalid-token-401")), "none", 2, 2},
        {"401 with a message", respond(make_response(401, R"({"message":"no"})")), "AuthError",
         1, 1},
    }));
    CAPTURE(row.name);
    Lab lab;
    auto calls = std::make_shared<std::atomic<int>>(0);
    lab.http.on(HttpMethod::post, kExploreUrl, [calls, first = row.first](const HttpRequest& r) {
        return ++*calls == 1 ? first(r) : load_fixture("veeam", "explore-201");
    });
    auto client = lab.make_client();

    std::string id;
    CHECK(thrown_kind([&] { id = client->open_explore_session(kOrgId, kBackupTime, "Vex"); }) ==
          row.outcome);
    CHECK(id == (row.outcome == "none" ? kSessionId : ""));
    CHECK(lab.http.count(HttpMethod::post, kExploreUrl) == row.sends);
    CHECK(lab.logins == row.logins);
}

TEST_CASE("a restore POST goes out exactly once, whatever comes back", "[veeam][w2.5]")
{
    using Kind = rp::VeeamClient::RestorePostOutcome::Kind;
    struct Row {
        std::string name;
        Answer answer;
        Kind kind;
        int status;
        std::string error_code;
        std::string session_id;
        std::string message; // a part of the outcome's message
    };
    const Row row = GENERATE(values<Row>({
        {"dropped", transport(rp::TransportError::dropped), Kind::no_answer, 0, "", "",
         ": no answer ("},
        {"timeout", transport(rp::TransportError::timeout), Kind::no_answer, 0, "", "",
         ": no answer ("},
        // No connection or no handshake: the request never went out.
        {"connect", transport(rp::TransportError::connect), Kind::not_sent, 0, "", "",
         ": not sent ("},
        {"handshake", transport(rp::TransportError::handshake), Kind::not_sent, 0, "", "",
         ": not sent ("},
        {"not an HttpError",
         [](const HttpRequest&) -> HttpResponse { throw std::runtime_error("SENTINEL-PW"); },
         Kind::no_answer, 0, "", "", ": no answer (the send failed)"},
        {"500",
         respond(make_response(500,
                               R"({"message":"Restore failed.","errorCode":"InternalError"})")),
         Kind::no_answer, 500, "InternalError", "", ": HTTP 500 (InternalError): Restore failed."},
        {"502", respond(make_response(502)), Kind::no_answer, 502, "", "", ": HTTP 502"},
        {"302", respond(make_response(302)), Kind::no_answer, 302, "", "", ": HTTP 302"},
        {"101", respond(make_response(101)), Kind::no_answer, 101, "", "", ": HTTP 101"},
        {"400",
         respond(make_response(
             400,
             R"({"message":"Folder not found.","errorCode":"ParameterValidationFailure"})")),
         Kind::refused, 400, "ParameterValidationFailure", "",
         ": HTTP 400 (ParameterValidationFailure): Folder not found."},
        {"400 quoting the body",
         respond(make_response(400, json{{"message", "Bad body: " + kRestoreBody}}.dump())),
         Kind::refused, 400, "", "", "\"applicationCertificatePassword\":\"[REDACTED]\""},
        {"401", respond(load_fixture("veeam", "api-expired-token-401")), Kind::refused, 401, "",
         "", ": HTTP 401"},
        {"403",
         respond(make_response(
             403, R"({"message":"Access denied.","errorCode":"ResourceAccessDenied"})")),
         Kind::refused, 403, "ResourceAccessDenied", "", ": HTTP 403"},
        {"200 without a sessionId", respond(make_response(200, "{}")), Kind::no_answer, 200, "",
         "", ": HTTP 200 without a restore session ID"},
        {"200 not JSON", respond(make_response(200, "ok")), Kind::no_answer, 200, "", "",
         ": HTTP 200 without a restore session ID"},
        {"200 with a sessionId that isn't a UUID",
         respond(make_response(200, R"({"sessionId":"b6fe35ef"})")), Kind::no_answer, 200, "",
         "", ": HTTP 200 without a restore session ID"},
        {"200 with a sessionId that isn't a string",
         respond(make_response(200, R"({"sessionId":7})")), Kind::no_answer, 200, "", "",
         ": HTTP 200 without a restore session ID"},
        {"200 as recorded", respond(load_fixture("veeam", "restore-mail-200")), Kind::accepted,
         200, "", "b6fe35ef-9633-481d-9756-3496a717d8a9",
         ": HTTP 200, restore session b6fe35ef-9633-481d-9756-3496a717d8a9"},
        {"201 with a sessionId",
         respond(make_response(201, R"({"sessionId":"15c3f986-0000-4000-8000-000000000001"})")),
         Kind::accepted, 201, "", "15c3f986-0000-4000-8000-000000000001",
         ": HTTP 201, restore session"},
        // Lower case, as GET /v8/RestoreSessions lists it for the duplicate check.
        {"200 with a sessionId in upper case",
         respond(make_response(200, R"({"sessionId":"15C3F986-0000-4000-8000-00000000000A"})")),
         Kind::accepted, 200, "", "15c3f986-0000-4000-8000-00000000000a",
         ": HTTP 200, restore session 15c3f986-0000-4000-8000-00000000000a"},
    }));
    CAPTURE(row.name);
    Lab lab;
    const std::string url = kBase + kRestorePath;
    lab.http.on(HttpMethod::post, url, row.answer);
    auto client = lab.make_client();

    const rp::VeeamClient::RestorePostOutcome out =
        client->post_restore_once(kRestorePath, kRestoreBody, 60s);

    CHECK(out.kind == row.kind);
    CHECK(out.status == row.status);
    CHECK(out.error_code == row.error_code);
    CHECK(out.session_id == row.session_id);
    CHECK(out.message.starts_with("Veeam POST " + kRestorePath));
    CHECK(out.message.find(row.message) != std::string::npos);
    CHECK(out.message.find('\n') == std::string::npos);
    // One send, and nothing but the sign-in before it: no resend, and no
    // fresh sign-in after a 401.
    const std::vector<HttpRequest> sent = lab.http.requests();
    REQUIRE(sent.size() == 2);
    CHECK(sent[0].url == kTokenUrl);
    const HttpRequest& post = sent[1];
    CHECK(post.method == HttpMethod::post);
    CHECK(post.url == url);
    CHECK(post.body == kRestoreBody);
    CHECK(post.content_type == "application/json; charset=utf-8");
    CHECK(post.max_attempts == 1);
    CHECK_FALSE(post.retry_on_status);
    CHECK(post.timeout == 60s);
    CHECK(bearer(post) == "Bearer access-login-1");
    CHECK(post.headers.at("Accept") == "application/json");
    CHECK(lab.logins == 1);
    // The certificate and its password never leave the request.
    const std::string log = lab.log();
    for (const std::string secret : {"SENTINEL-PFX", "SENTINEL-PW"}) {
        CHECK(out.message.find(secret) == std::string::npos);
        CHECK(log.find(secret) == std::string::npos);
    }
}

TEST_CASE("a restore POST takes its own timeout and refuses one of 0 or less", "[veeam][w2.5]")
{
    Lab lab;
    lab.http.on(HttpMethod::post, kBase + kRestorePath,
                {load_fixture("veeam", "restore-mail-200")});
    auto client = lab.make_client();

    CHECK_THROWS_AS(client->post_restore_once(kRestorePath, kRestoreBody, 0ms),
                    std::invalid_argument);
    CHECK_THROWS_AS(client->post_restore_once(kRestorePath, kRestoreBody, -1ms),
                    std::invalid_argument);
    CHECK(lab.http.requests().empty());

    client->post_restore_once(kRestorePath, kRestoreBody, 1234ms);
    CHECK(lab.http.requests().back().timeout == 1234ms);
}

TEST_CASE("a restore POST whose token can't be had throws and sends nothing", "[veeam][w2.5]")
{
    Lab lab;
    lab.on_login = [](int) { return load_fixture("veeam", "token-rejected-401"); };
    lab.http.on(HttpMethod::post, kBase + kRestorePath,
                {load_fixture("veeam", "restore-mail-200")});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->post_restore_once(kRestorePath, kRestoreBody, 60s); }) ==
          "AuthError");
    CHECK(lab.http.count(HttpMethod::post, kBase + kRestorePath) == 0);
}

TEST_CASE("a restore POST with a token due for renewal renews it first", "[veeam][w2.5]")
{
    Lab lab;
    lab.http.on(HttpMethod::post, kBase + kRestorePath,
                {load_fixture("veeam", "restore-mail-200")});
    auto client = lab.make_client();
    client->ensure_token();
    lab.advance(3541s);

    client->post_restore_once(kRestorePath, kRestoreBody, 60s);

    CHECK(lab.grants() == std::vector<std::string>{"password", "refresh_token"});
    CHECK(bearer(lab.http.requests().back()) == "Bearer access-refresh-1");
}

TEST_CASE("stop_session refuses an ID that isn't a UUID before any request", "[veeam][w2.5]")
{
    const std::string id = GENERATE(as<std::string>{}, "", "x", kSessionId + "/Stop",
                                    "6ee50a66-c46f-4200-b793-c03f8bcbbb8");
    CAPTURE(id);
    Lab lab;
    auto client = lab.make_client();

    CHECK_THROWS_AS(client->stop_session(id), std::invalid_argument);
    CHECK(lab.http.requests().empty());
}

TEST_CASE("stop_session posts Stop once and maps a failure as get_json does", "[veeam][w2.5]")
{
    struct Row {
        HttpResponse response;
        std::string kind;
    };
    const Row row = GENERATE(values<Row>({
        {load_fixture("veeam", "stop-204"), "none"},
        {make_response(200, "{}"), "none"},
        {make_response(404,
                       R"({"message":"Session not found.","errorCode":"ResourceNotFound"})"),
         "NotFoundError"},
        {make_response(500, R"({"message":"Cannot stop."})"), "VeeamError"},
        {make_response(503), "TransientError"},
        {make_response(403, R"({"message":"no"})"), "AuthError"},
    }));
    CAPTURE(row.response.status);
    Lab lab;
    const std::string url = kBase + "/v8/RestoreSessions/" + kSessionId + "/Stop";
    lab.http.on(HttpMethod::post, url, {row.response});
    auto client = lab.make_client();

    CHECK(thrown_kind([&] { client->stop_session(kSessionId); }) == row.kind);
    // Not resent after a 5xx: a Stop that went out may have been acted on.
    REQUIRE(lab.http.count(HttpMethod::post, url) == 1);
    const HttpRequest post = lab.http.requests().back();
    CHECK(post.body.empty());
    CHECK(post.content_type.empty());
    CHECK(bearer(post) == "Bearer access-login-1");
}
