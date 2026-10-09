// The service's heartbeat (src/heartbeat.hpp; W4.8, docs/decisions.md
// 2026-10-08 point 11): one POST to <cloud_url>/v1/heartbeat, the body's exact
// bytes, and which word each failure is. On FakeHttpClient, and over a real
// local server. Failure paths first.

#include "fake_http_client.hpp"
#include "local_http_server.hpp"

#include "../src/heartbeat.hpp"

#include <rp/canonical_json.hpp>
#include <rp/http_client.hpp>
#include <rp/service_errors.hpp>
#include <rp/uploader.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;

const std::string kCloud = "https://cloud.example.invalid";
const std::string kHeartbeat = kCloud + "/v1/heartbeat";

// 2026-10-08T10:11:12.345Z.
std::chrono::system_clock::time_point a_time()
{
    return std::chrono::sys_days{std::chrono::year{2026} / 10 / 8} + 10h + 11min + 12s + 345ms;
}

rp::Heartbeat troubled()
{
    rp::Heartbeat heartbeat;
    heartbeat.version = "0.4.8";
    heartbeat.last_error = "veeam_sessions_working";
    heartbeat.last_error_at = a_time();
    heartbeat.outbox_depth = 3;
    heartbeat.uptime_s = 86400;
    return heartbeat;
}

} // namespace

TEST_CASE("heartbeat: anything but a 2xx is a failure with its word", "[heartbeat]")
{
    struct Row {
        const char* name;
        std::function<rp::HttpResponse(const rp::HttpRequest&)> answer;
        std::string word;
    };
    const auto status = [](int code) {
        return [code](const rp::HttpRequest&) { return rp::test::make_response(code, "x"); };
    };
    const auto transport = [](rp::TransportError error, int http_status = 0) {
        return [error, http_status](const rp::HttpRequest&) -> rp::HttpResponse {
            throw rp::HttpError("POST https://cloud.example.invalid/v1/heartbeat: failed", error,
                                http_status, 1);
        };
    };
    const Row row = GENERATE_COPY(
        Row{"500", status(500), "http_500"},
        Row{"503", status(503), "http_503"},
        Row{"404", status(404), "http_404"},
        Row{"401", status(401), "http_401"},
        Row{"301", status(301), "http_301"},
        Row{"199", status(199), "http_199"},
        Row{"300", status(300), "http_300"},
        Row{"a status of two digits", status(99), "internal"},
        Row{"a status of four digits", status(1000), "internal"},
        Row{"no connection", transport(rp::TransportError::connect), "unreachable"},
        Row{"a dropped connection", transport(rp::TransportError::dropped), "unreachable"},
        Row{"a broken-off handshake", transport(rp::TransportError::handshake), "unreachable"},
        Row{"a certificate refused", transport(rp::TransportError::tls), "unreachable"},
        Row{"a timeout", transport(rp::TransportError::timeout), "timeout"},
        Row{"a malformed URL", transport(rp::TransportError::other), "internal"},
        Row{"a 5xx thrown", transport(rp::TransportError::none, 502), "http_502"},
        Row{"an error with no cause", transport(rp::TransportError::none, 0), "internal"},
        Row{"another exception", [](const rp::HttpRequest&) -> rp::HttpResponse {
                throw std::runtime_error("boom");
            }, "internal"},
        Row{"not an exception", [](const rp::HttpRequest&) -> rp::HttpResponse { throw 42; },
            "internal"});
    CAPTURE(row.name);
    rp::test::FakeHttpClient http;
    http.on(rp::HttpMethod::post, kHeartbeat, row.answer);

    const rp::HeartbeatAnswer answer = rp::send_heartbeat(http, kCloud, troubled());

    CHECK_FALSE(answer.ok);
    CHECK(answer.error == row.word);
    // Sent once: the next interval is the retry.
    CHECK(http.requests().size() == 1);
    // A failed heartbeat is never the last error a heartbeat reports.
    CHECK_FALSE(rp::is_service_error(answer.error));
}

TEST_CASE("heartbeat: a body that has no canonical form is internal, and nothing is sent",
          "[heartbeat]")
{
    rp::Heartbeat heartbeat = troubled();
    SECTION("a count past 2^53 - 1")
    {
        heartbeat.uptime_s = std::numeric_limits<std::uint64_t>::max();
    }
    SECTION("a text that isn't UTF-8")
    {
        heartbeat.last_error = "upload_\xff";
    }
    rp::test::FakeHttpClient http;
    http.on(rp::HttpMethod::post, kHeartbeat, {rp::test::make_response(204)});

    CHECK_THROWS_AS(rp::heartbeat_body(heartbeat), rp::CanonicalJsonError);
    const rp::HeartbeatAnswer answer = rp::send_heartbeat(http, kCloud, heartbeat);

    CHECK_FALSE(answer.ok);
    CHECK(answer.error == "internal");
    CHECK(http.requests().empty());
}

TEST_CASE("heartbeat: the body is canonical JSON with exactly the five keys", "[heartbeat]")
{
    SECTION("with a last error")
    {
        CHECK(rp::heartbeat_body(troubled()) ==
              R"({"last_error":"veeam_sessions_working","last_error_at":"2026-10-08T10:11:12.345Z",)"
              R"("outbox_depth":3,"uptime_s":86400,"version":"0.4.8"})");
    }
    SECTION("without one: null, never left out")
    {
        rp::Heartbeat heartbeat;
        heartbeat.version = "0.4.8";
        CHECK(rp::heartbeat_body(heartbeat) ==
              R"({"last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":0,)"
              R"("version":"0.4.8"})");
    }
    SECTION("its own canonical form, whatever the fields")
    {
        rp::Heartbeat heartbeat = troubled();
        heartbeat.last_error = "upload_http_503";
        heartbeat.outbox_depth = 9007199254740991u;
        const std::string body = rp::heartbeat_body(heartbeat);
        const nlohmann::json parsed = nlohmann::json::parse(body);
        CHECK(rp::canonical_json(parsed) == body);
        CHECK(parsed.size() == 5);
        CHECK(parsed.at("outbox_depth") == 9007199254740991u);
    }
    SECTION("the time is UTC to the millisecond, cut and never rounded")
    {
        CHECK(rp::heartbeat_time_text(a_time()) == "2026-10-08T10:11:12.345Z");
        CHECK(rp::heartbeat_time_text(a_time() + 999us) == "2026-10-08T10:11:12.345Z");
        CHECK(rp::heartbeat_time_text(std::chrono::sys_days{std::chrono::year{2027} / 1 / 1}) ==
              "2027-01-01T00:00:00.000Z");
    }
}

TEST_CASE("heartbeat: one POST to <cloud_url>/v1/heartbeat, sent once, 10 s, with no credential; "
          "any 2xx is taken",
          "[heartbeat][acceptance]")
{
    const std::string base = GENERATE("https://cloud.example.invalid",
                                      "https://cloud.example.invalid/",
                                      "https://cloud.example.invalid///");
    const int status = GENERATE(204, 200, 202, 299);
    CAPTURE(base, status);
    rp::test::FakeHttpClient http;
    http.on(rp::HttpMethod::post, kHeartbeat, {rp::test::make_response(status)});
    const rp::Heartbeat heartbeat = troubled();

    const rp::HeartbeatAnswer answer = rp::send_heartbeat(http, base, heartbeat);

    CHECK(answer.ok);
    CHECK(answer.error.empty());
    const std::vector<rp::HttpRequest> requests = http.requests();
    REQUIRE(requests.size() == 1);
    const rp::HttpRequest& request = requests.front();
    CHECK(request.method == rp::HttpMethod::post);
    CHECK(request.url == kHeartbeat);
    CHECK(request.body == rp::heartbeat_body(heartbeat));
    CHECK(request.content_type == "application/json");
    // W5.1 adds the token; until then nothing that could be one is sent.
    CHECK(request.headers.empty());
    CHECK(request.parts.empty());
    CHECK(request.max_attempts == 1);
    CHECK_FALSE(request.retry_on_status);
    CHECK(request.timeout == std::chrono::milliseconds{10000});
    CHECK(request.max_body_bytes == 64u * 1024u);
}

TEST_CASE("heartbeat: over a real connection the body arrives byte for byte, and a server that "
          "isn't there is unreachable",
          "[heartbeat][http]")
{
    std::string body = "unset";
    std::string content_type = "unset";
    std::string authorization = "unset";
    int hits = 0;
    int status = 204;
    rp::test::LocalHttpServer server;
    server.server().Post("/v1/heartbeat", [&](const httplib::Request& req, httplib::Response& res) {
        ++hits;
        body = req.body;
        content_type = req.get_header_value("Content-Type");
        authorization = req.get_header_value("Authorization");
        res.status = status;
    });
    rp::HttpClientOptions options;
    options.sleep = [](std::chrono::milliseconds) {};
    rp::HttpClient http(options);
    const rp::Heartbeat heartbeat = troubled();

    const rp::HeartbeatAnswer answer = rp::send_heartbeat(http, server.url() + "/", heartbeat);

    CHECK(answer.ok);
    CHECK(hits == 1);
    CHECK(body ==
          R"({"last_error":"veeam_sessions_working","last_error_at":"2026-10-08T10:11:12.345Z",)"
          R"("outbox_depth":3,"uptime_s":86400,"version":"0.4.8"})");
    CHECK(content_type == "application/json");
    CHECK(authorization.empty());

    // A 5xx is answered once, not retried.
    status = 503;
    const rp::HeartbeatAnswer busy = rp::send_heartbeat(http, server.url(), heartbeat);
    CHECK_FALSE(busy.ok);
    CHECK(busy.error == "http_503");
    CHECK(hits == 2);

    const std::string closed =
        "http://127.0.0.1:" + std::to_string(rp::test::closed_local_port());
    const rp::HeartbeatAnswer refused = rp::send_heartbeat(http, closed, heartbeat);
    CHECK_FALSE(refused.ok);
    CHECK(refused.error == "unreachable");
}

TEST_CASE("the cloud's routes are joined to cloud_url one way", "[heartbeat][uploader]")
{
    CHECK(rp::cloud_endpoint("https://c.example.invalid", "/v1/heartbeat") ==
          "https://c.example.invalid/v1/heartbeat");
    CHECK(rp::cloud_endpoint("https://c.example.invalid//", "/v1/results") ==
          "https://c.example.invalid/v1/results");
    CHECK(rp::cloud_endpoint("https://c.example.invalid/base/", "/v1/results") ==
          "https://c.example.invalid/base/v1/results");
}
