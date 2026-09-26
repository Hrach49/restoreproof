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

TEST_CASE("a sign-in failure isn't handed to a waiter once a later sign-in succeeded",
          "[veeam]")
{
    // W1.5 review: A waits for the lock while B's sign-in fails and C's then
    // succeeds; A must use C's token, not fail with B's error. Which of A and
    // C takes the lock first after B is the scheduler's choice (C is made
    // likely to win: it is running when B lets go), so the scenario runs
    // several times. A may fail only when it came first; before the fix it
    // failed every time. C starts once B has let go of the lock (its call has
    // returned), while A is still being woken: running, C usually wins.
    constexpr int kRounds = 20;
    int a_succeeded = 0;
    int a_failed_otherwise = 0;
    for (int round = 0; round < kRounds; ++round) {
        Lab lab;
        lab.http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
        std::atomic<bool> a_started = false;
        std::atomic<bool> b_done = false;
        lab.on_login = [&](int n) -> HttpResponse {
            if (n == 1) {
                // B, holding the lock: wait until A queues behind it.
                while (!a_started.load()) {
                    std::this_thread::yield();
                }
                std::this_thread::sleep_for(20ms);
                throw rp::HttpError("POST https://veeam.test:4443/v8/token: timed out",
                                    rp::TransportError::timeout, 0, 1);
            }
            return token_response("access-login-" + std::to_string(n), "r");
        };
        auto client = lab.make_client();

        std::atomic<int> a_result = 0; // 1 succeeded, 2 TransientError, 3 anything else
        {
            std::jthread b([&] {
                try {
                    client->login();
                } catch (...) {
                    b_done = true;
                }
            });
            while (lab.logins.load() == 0) {
                std::this_thread::yield();
            }
            std::jthread a([&] {
                a_started = true;
                try {
                    a_result = client->list_organizations().size() == 1 ? 1 : 3;
                } catch (const rp::TransientError&) {
                    a_result = 2;
                } catch (...) {
                    a_result = 3;
                }
            });
            std::jthread c([&] {
                while (!b_done.load()) {
                    std::this_thread::yield();
                }
                try {
                    client->login();
                } catch (...) {
                }
            });
        }
        a_succeeded += a_result == 1 ? 1 : 0;
        a_failed_otherwise += a_result == 3 ? 1 : 0;
    }
    CHECK(a_failed_otherwise == 0);
    CHECK(a_succeeded > 0);
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
