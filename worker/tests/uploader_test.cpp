// The outbox's real uploader (rp/uploader.hpp; W4.6): one multipart POST to
// <cloud_url>/v1/results, and which code each answer is. On FakeHttpClient, and
// once over a real local server. Failure paths first.

#include "fake_http_client.hpp"
#include "local_http_server.hpp"

#include <rp/http_client.hpp>
#include <rp/outbox.hpp>
#include <rp/uploader.hpp>

#include <httplib.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

const std::string kCloud = "https://cloud.example.invalid";
const std::string kResults = kCloud + "/v1/results";
// A token of the Cloud's shape (W5.1), never a real one.
const std::string kToken = "UploadTok-w51-0123456789abcdefABCDEF_-01234";

std::vector<rp::UploadPart> three_parts()
{
    return {{"result", "result.json", "application/json", R"({"run_id":"run-0001"})"},
            {"signature", "signature.json", "application/json", R"({"bundle_sha256":"00"})"},
            {"items.csv", "items.csv", "application/octet-stream",
             std::string("a\x00\xff\r\n--b", 9)}};
}

} // namespace

TEST_CASE("uploader: anything but the Cloud's 202 is a failed attempt with its code", "[uploader]")
{
    struct Row {
        const char* name;
        std::function<rp::HttpResponse(const rp::HttpRequest&)> answer;
        std::string code;
    };
    const auto status = [](int code) {
        return [code](const rp::HttpRequest&) { return rp::test::cloud_answer(code, "x"); };
    };
    // W5.1 (docs/decisions.md 2026-10-15, point 5): a 2xx without the
    // contract header, or with another value, is not the Cloud's.
    const auto bare = [](int code) {
        return [code](const rp::HttpRequest&) { return rp::test::make_response(code, "x"); };
    };
    const auto other_contract = [](int code) {
        return [code](const rp::HttpRequest&) {
            rp::HttpResponse response = rp::test::make_response(code, "x");
            response.headers["X-RestoreProof-API"] = "2";
            return response;
        };
    };
    const auto transport = [](rp::TransportError error, int http_status = 0) {
        return [error, http_status](const rp::HttpRequest&) -> rp::HttpResponse {
            throw rp::HttpError("POST https://cloud.example.invalid/v1/results: failed", error,
                                http_status, 1);
        };
    };
    const Row row = GENERATE_COPY(
        Row{"500", status(500), "upload_http_500"},
        Row{"503", status(503), "upload_http_503"},
        Row{"200", status(200), "upload_http_200"},
        Row{"201", status(201), "upload_http_201"},
        Row{"301", status(301), "upload_http_301"},
        Row{"401", status(401), "upload_http_401"},
        Row{"413", status(413), "upload_http_413"},
        Row{"409", status(409), "upload_http_409"},
        Row{"202 without the contract header", bare(202), "upload_not_cloud"},
        Row{"200 without the contract header", bare(200), "upload_not_cloud"},
        Row{"202 of another contract", other_contract(202), "upload_not_cloud"},
        Row{"a proxy's 502, which has no header", bare(502), "upload_http_502"},
        Row{"a server's 400, which has no header", bare(400), "upload_http_400"},
        Row{"a status of two digits", status(99), "upload_internal"},
        Row{"a status of four digits", status(1000), "upload_internal"},
        Row{"no connection", transport(rp::TransportError::connect), "upload_unreachable"},
        Row{"a dropped connection", transport(rp::TransportError::dropped), "upload_unreachable"},
        Row{"a broken-off handshake", transport(rp::TransportError::handshake),
            "upload_unreachable"},
        Row{"a certificate refused", transport(rp::TransportError::tls), "upload_unreachable"},
        Row{"a timeout", transport(rp::TransportError::timeout), "upload_timeout"},
        Row{"a malformed URL", transport(rp::TransportError::other), "upload_internal"},
        Row{"a 5xx thrown", transport(rp::TransportError::none, 502), "upload_http_502"},
        Row{"an error with no cause", transport(rp::TransportError::none, 0), "upload_internal"},
        Row{"another exception", [](const rp::HttpRequest&) -> rp::HttpResponse {
                throw std::runtime_error("boom");
            }, "upload_internal"},
        Row{"not an exception", [](const rp::HttpRequest&) -> rp::HttpResponse { throw 42; },
            "upload_internal"});
    CAPTURE(row.name);
    rp::test::FakeHttpClient http;
    http.on(rp::HttpMethod::post, kResults, row.answer);
    rp::CloudUploader uploader(http, kCloud, kToken);

    const rp::UploadAnswer answer = uploader.upload("run-0001", three_parts());

    CHECK_FALSE(answer.accepted);
    CHECK(answer.error == row.code);
    CHECK(rp::is_upload_error(answer.error));
    // Sent once: the outbox owns the schedule.
    CHECK(http.requests().size() == 1);
}

TEST_CASE("uploader: 500 then 202: the second upload is accepted", "[uploader]")
{
    rp::test::FakeHttpClient http;
    http.on(rp::HttpMethod::post, kResults,
            {rp::test::make_response(500, "busy", "text/plain"), rp::test::cloud_answer(202)});
    rp::CloudUploader uploader(http, kCloud, kToken);

    const rp::UploadAnswer first = uploader.upload("run-0001", three_parts());
    const rp::UploadAnswer second = uploader.upload("run-0001", three_parts());

    CHECK_FALSE(first.accepted);
    CHECK(first.error == "upload_http_500");
    CHECK(second.accepted);
    CHECK(second.error.empty());
    CHECK(http.requests().size() == 2);
}

TEST_CASE("uploader: one POST to <cloud_url>/v1/results, the parts in their order, sent once and "
          "with the API token alone",
          "[uploader][acceptance]")
{
    const std::string base = GENERATE("https://cloud.example.invalid",
                                      "https://cloud.example.invalid/",
                                      "https://cloud.example.invalid///");
    rp::test::FakeHttpClient http;
    http.on(rp::HttpMethod::post, kResults, {rp::test::cloud_answer(202)});
    rp::CloudUploader uploader(http, base, kToken);
    CHECK(uploader.url() == kResults);
    const std::vector<rp::UploadPart> parts = three_parts();

    const rp::UploadAnswer answer = uploader.upload("run-0001", parts);

    CHECK(answer.accepted);
    const std::vector<rp::HttpRequest> requests = http.requests();
    REQUIRE(requests.size() == 1);
    const rp::HttpRequest& request = requests.front();
    CHECK(request.method == rp::HttpMethod::post);
    CHECK(request.url == kResults);
    // W5.1: the API token as a bearer token, and no other header.
    CHECK(request.headers == rp::HttpHeaders{{"Authorization", "Bearer " + kToken}});
    CHECK(request.body.empty());
    CHECK(request.max_attempts == 1);
    CHECK_FALSE(request.retry_on_status);
    CHECK(request.timeout == std::chrono::milliseconds{120000});
    CHECK(request.max_body_bytes == 64u * 1024u);
    REQUIRE(request.parts.size() == parts.size());
    for (std::size_t i = 0; i < parts.size(); ++i) {
        CAPTURE(i);
        CHECK(request.parts[i].name == parts[i].name);
        CHECK(request.parts[i].filename == parts[i].filename);
        CHECK(request.parts[i].content_type == parts[i].content_type);
        CHECK(request.parts[i].content == parts[i].bytes);
    }
}

TEST_CASE("uploader: over a real connection every part arrives byte for byte, and a server that "
          "isn't there is unreachable",
          "[uploader][http]")
{
    httplib::MultipartFormData received;
    std::string authorization = "unset";
    rp::test::LocalHttpServer server;
    server.server().Post("/v1/results", [&](const httplib::Request& req, httplib::Response& res) {
        received = req.form;
        authorization = req.get_header_value("Authorization");
        res.status = 202;
        res.set_header("X-RestoreProof-API", "1");
    });
    rp::HttpClientOptions options;
    options.sleep = [](std::chrono::milliseconds) {};
    rp::HttpClient http(options);
    const std::vector<rp::UploadPart> parts = three_parts();

    const rp::UploadAnswer answer =
        rp::CloudUploader(http, server.url(), kToken).upload("run-0001", parts);

    CHECK(answer.accepted);
    CHECK(authorization == "Bearer " + kToken);
    for (const rp::UploadPart& part : parts) {
        CAPTURE(part.name);
        REQUIRE(received.has_file(part.name));
        CHECK(received.get_file(part.name).content == part.bytes);
        CHECK(received.get_file(part.name).filename == part.filename);
        CHECK(received.get_file(part.name).content_type == part.content_type);
    }

    const std::string closed =
        "http://127.0.0.1:" + std::to_string(rp::test::closed_local_port());
    const rp::UploadAnswer refused = rp::CloudUploader(http, closed, kToken).upload("run-0001", parts);
    CHECK_FALSE(refused.accepted);
    CHECK(refused.error == "upload_unreachable");
}

// W4.8 (docs/decisions.md 2026-10-08 point 12): the service has no stderr, so
// the cloud client logs where its caller says.
TEST_CASE("the cloud client logs to the logger it is given; without one it still answers",
          "[uploader][http]")
{
    rp::test::LocalHttpServer server;
    server.server().Get("/v1/ping", [](const httplib::Request&, httplib::Response& res) {
        res.status = 204;
    });
    std::ostringstream log;
    const auto logger = std::make_shared<spdlog::logger>(
        "cloud-test", std::make_shared<spdlog::sinks::ostream_sink_mt>(log));
    logger->set_level(spdlog::level::debug);
    const rp::Config config;

    const std::unique_ptr<rp::IHttpClient> given = rp::make_cloud_http_client(config, logger);
    REQUIRE(given);
    CHECK(given->get(server.url("/v1/ping")).status == 204);
    logger->flush();
    // HttpClient's one debug line per request, and on this logger.
    CHECK(log.str().find("/v1/ping") != std::string::npos);

    // Null: the commands' stderr logger, which keeps warnings and worse.
    const std::size_t logged = log.str().size();
    const std::unique_ptr<rp::IHttpClient> plain = rp::make_cloud_http_client(config);
    REQUIRE(plain);
    CHECK(plain->get(server.url("/v1/ping")).status == 204);
    CHECK(rp::make_cloud_http_client(config, nullptr)->get(server.url("/v1/ping")).status == 204);
    logger->flush();
    CHECK(log.str().size() == logged);
}
