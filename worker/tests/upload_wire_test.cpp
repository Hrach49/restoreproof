// W5.1 (docs/decisions.md 2026-10-15, point 10; C5.11's code review, finding 3):
// the bytes the Worker's uploader puts on the wire for the shared vector's
// bundle, kept as shared/testdata/signing-v1/dispatched-run.wire beside the
// vector, so the Cloud's contract test posts what cpr and curl really send,
// not a request httpx built from the part list. The hidden writer makes the
// file; the test below holds it equal to what the uploader sends now, the
// boundary aside (curl picks a new one per request), so a cpr or curl
// upgrade that changes the framing fails here or in the Cloud's test.

#include "local_http_server.hpp"

#include <rp/base64.hpp>
#include <rp/http_client.hpp>
#include <rp/outbox.hpp>
#include <rp/sha256.hpp>
#include <rp/uploader.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace {

using nlohmann::json;

const std::filesystem::path kVector = std::filesystem::path{RP_SHARED_DIR} / "testdata" / "signing-v1" / "dispatched-run.json";
const std::filesystem::path kWire = std::filesystem::path{RP_SHARED_DIR} / "testdata" / "signing-v1" / "dispatched-run.wire";
const std::filesystem::path kWireNote =
    std::filesystem::path{RP_SHARED_DIR} / "testdata" / "signing-v1" / "dispatched-run.wire.json";
// The token the capture carries; the Cloud's test puts its own Worker's in
// the header it sends, which is no part of these bytes.
const std::string kToken = "WireToken-w51-0123456789abcdefABCDEF_-01234";

std::string read_bytes(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

// The vector's parts in the outbox's order, each file's bytes.
std::vector<rp::UploadPart> vector_parts()
{
    const json vector = json::parse(read_bytes(kVector));
    std::vector<rp::UploadPart> parts;
    for (const json& part : vector.at("upload")) {
        const std::string name = part.at("filename").get<std::string>();
        const json& file = vector.at("files").at(name);
        std::string bytes;
        if (file.is_string()) {
            bytes = file.get<std::string>();
        } else {
            const std::optional<std::vector<unsigned char>> decoded =
                rp::base64_decode(file.at("base64").get<std::string>());
            REQUIRE(decoded);
            bytes.assign(decoded->begin(), decoded->end());
        }
        parts.push_back({part.at("name").get<std::string>(), name,
                         part.at("content_type").get<std::string>(), std::move(bytes)});
    }
    return parts;
}

struct Captured {
    std::string content_type;
    std::string body;
    std::string boundary;
};

// One upload of the vector's parts through the real uploader and the real
// client, to a local server that keeps the body as it arrived.
Captured capture()
{
    rp::test::RecordingServer server("HTTP/1.1 202 Accepted\r\nX-RestoreProof-API: 1\r\n"
                                     "Content-Length: 0\r\nConnection: close\r\n\r\n");
    rp::HttpClientOptions options;
    options.sleep = [](std::chrono::milliseconds) {};
    rp::HttpClient http(options);

    const rp::UploadAnswer answer =
        rp::CloudUploader(http, server.url(), kToken).upload("run", vector_parts());
    server.wait();

    CAPTURE(answer.error);
    REQUIRE(answer.accepted);
    Captured got;
    got.body = server.body();
    // The request's Content-Type header, as the Cloud reads it.
    const std::string& head = server.head();
    const std::size_t named = head.find("\r\nContent-Type: ");
    REQUIRE(named != std::string::npos);
    const std::size_t value = named + 16;
    got.content_type = head.substr(value, head.find("\r\n", value) - value);
    const std::size_t at = got.content_type.find("boundary=");
    REQUIRE(at != std::string::npos);
    got.boundary = got.content_type.substr(at + 9);
    REQUIRE(got.boundary.size() >= 16);
    return got;
}

std::string replaced(std::string text, const std::string& from, const std::string& to)
{
    for (std::size_t at = text.find(from); at != std::string::npos; at = text.find(from, at + to.size())) {
        text.replace(at, from.size(), to);
    }
    return text;
}

} // namespace

TEST_CASE("the upload's wire bytes are the shared vector's, the boundary aside", "[uploader][wire]")
{
    const json note = json::parse(read_bytes(kWireNote));
    const std::string committed = read_bytes(kWire);
    const std::string boundary = note.at("boundary").get<std::string>();
    REQUIRE(note.at("length") == committed.size());
    REQUIRE(note.at("sha256") == rp::sha256_hex(committed));
    REQUIRE(note.at("content_type") == "multipart/form-data; boundary=" + boundary);

    const Captured now = capture();

    CHECK(now.content_type == "multipart/form-data; boundary=" + now.boundary);
    CHECK(replaced(now.body, now.boundary, boundary) == committed);
}

TEST_CASE("write shared/testdata/signing-v1/dispatched-run.wire", "[.write_shared_upload_wire]")
{
    const Captured got = capture();
    {
        std::ofstream file(kWire, std::ios::binary | std::ios::trunc);
        REQUIRE(file);
        file << got.body;
    }
    const json note{
        {"description",
         "The body the C++ Worker's uploader (rp::CloudUploader over cpr and curl) sent for "
         "dispatched-run.json's bundle, byte for byte, as a local server received it; the content "
         "type with curl's boundary for this capture. Written by `rptests "
         "\"[.write_shared_upload_wire]\"` (W5.1); posted unchanged by the Cloud's contract test."},
        {"boundary", got.boundary},
        {"content_type", got.content_type},
        {"length", got.body.size()},
        {"sha256", rp::sha256_hex(got.body)},
    };
    std::ofstream file(kWireNote, std::ios::binary | std::ios::trunc);
    REQUIRE(file);
    file << note.dump(2) << '\n';
}
