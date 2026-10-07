// The outbox's real uploader (rp/uploader.hpp; W4.6): one multipart POST to
// <cloud_url>/v1/results, and which code each answer is. On FakeHttpClient, and
// once over a real local server. Failure paths first.

#include "fake_http_client.hpp"
#include "local_http_server.hpp"

#include <rp/http_client.hpp>
#include <rp/outbox.hpp>
#include <rp/uploader.hpp>

#include <httplib.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

const std::string kCloud = "https://cloud.example.invalid";
const std::string kResults = kCloud + "/v1/results";

std::vector<rp::UploadPart> three_parts()
{
    return {{"result", "result.json", "application/json", R"({"run_id":"run-0001"})"},
            {"signature", "signature.json", "application/json", R"({"bundle_sha256":"00"})"},
            {"items.csv", "items.csv", "application/octet-stream",
             std::string("a\x00\xff\r\n--b", 9)}};
}

} // namespace

TEST_CASE("uploader: anything but a 202 is a failed attempt with its code", "[uploader]")
{
    struct Row {
        const char* name;
        std::function<rp::HttpResponse(const rp::HttpRequest&)> answer;
        std::string code;
    };
    const auto status = [](int code) {
        return [code](const rp::HttpRequest&) { return rp::test::make_response(code, "x"); };
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
    rp::CloudUploader uploader(http, kCloud);

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
            {rp::test::make_response(500, "busy", "text/plain"), rp::test::make_response(202)});
    rp::CloudUploader uploader(http, kCloud);

    const rp::UploadAnswer first = uploader.upload("run-0001", three_parts());
    const rp::UploadAnswer second = uploader.upload("run-0001", three_parts());

    CHECK_FALSE(first.accepted);
    CHECK(first.error == "upload_http_500");
    CHECK(second.accepted);
    CHECK(second.error.empty());
    CHECK(http.requests().size() == 2);
}

TEST_CASE("uploader: one POST to <cloud_url>/v1/results, the parts in their order, sent once and "
          "with no credential",
          "[uploader][acceptance]")
{
    const std::string base = GENERATE("https://cloud.example.invalid",
                                      "https://cloud.example.invalid/",
                                      "https://cloud.example.invalid///");
    rp::test::FakeHttpClient http;
    http.on(rp::HttpMethod::post, kResults, {rp::test::make_response(202)});
    rp::CloudUploader uploader(http, base);
    CHECK(uploader.url() == kResults);
    const std::vector<rp::UploadPart> parts = three_parts();

    const rp::UploadAnswer answer = uploader.upload("run-0001", parts);

    CHECK(answer.accepted);
    const std::vector<rp::HttpRequest> requests = http.requests();
    REQUIRE(requests.size() == 1);
    const rp::HttpRequest& request = requests.front();
    CHECK(request.method == rp::HttpMethod::post);
    CHECK(request.url == kResults);
    // W5.1 adds the token; until then nothing that could be one is sent.
    CHECK(request.headers.empty());
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
    });
    rp::HttpClientOptions options;
    options.sleep = [](std::chrono::milliseconds) {};
    rp::HttpClient http(options);
    const std::vector<rp::UploadPart> parts = three_parts();

    const rp::UploadAnswer answer =
        rp::CloudUploader(http, server.url()).upload("run-0001", parts);

    CHECK(answer.accepted);
    CHECK(authorization.empty());
    for (const rp::UploadPart& part : parts) {
        CAPTURE(part.name);
        REQUIRE(received.has_file(part.name));
        CHECK(received.get_file(part.name).content == part.bytes);
        CHECK(received.get_file(part.name).filename == part.filename);
        CHECK(received.get_file(part.name).content_type == part.content_type);
    }

    const std::string closed =
        "http://127.0.0.1:" + std::to_string(rp::test::closed_local_port());
    const rp::UploadAnswer refused = rp::CloudUploader(http, closed).upload("run-0001", parts);
    CHECK_FALSE(refused.accepted);
    CHECK(refused.error == "upload_unreachable");
}
