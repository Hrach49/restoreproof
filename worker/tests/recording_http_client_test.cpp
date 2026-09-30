// Q2.1: `--record <dir>`'s recorder (rp/recording_http_client.hpp). What a
// fixture keeps of an exchange, what it never keeps, and the refusals when
// something secret survives scrubbing. The commands' --record runs are in
// veeam_command_test.cpp, graph_command_test.cpp and restore_command_test.cpp.

#include "fake_http_client.hpp"
#include "test_support.hpp"

#include <rp/config.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

using Catch::Matchers::ContainsSubstring;

namespace {

using nlohmann::ordered_json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::RecordedBody;
using rp::test::make_response;

const std::string kSource = "rpworker test --record";
const std::string kVeeam = "https://veeam.test:4443";
// Secrets no rule of redact() would find by their place: only the recorder's
// known-secret check can.
const std::string kPassword = "Sentinel&Pa55=w\xc3\xb6rd+%";
const std::string kAccessToken = "SENTINEL-ACCESS-TOKEN-7d2a";
const std::string kRefreshToken = "SENTINEL-REFRESH-TOKEN-7d2a";
// {"alg":"PS256"}.{"x":1}.signature: JWT-shaped.
const std::string kJwt =
    "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJyZXN0b3JlcHJvb2YtdGVzdCJ9.c2lnbmF0dXJlLXNlbnRpbmVs";
const std::string kPfx = "MIIKYAIBAzCCChwGCSqGSIb3DQEHAaCCCg0EggoJ-SENTINEL-PFX";
const std::string kPfxPassword = "SENTINEL-PFX-PASSWORD-19";

HttpRequest request(HttpMethod method, std::string url, std::string body = {},
                    std::string content_type = {})
{
    HttpRequest r;
    r.method = method;
    r.url = std::move(url);
    r.body = std::move(body);
    r.content_type = std::move(content_type);
    return r;
}

HttpRequest token_request()
{
    return request(HttpMethod::post, kVeeam + "/v8/token",
                   "grant_type=password&username=rp-veeam&password=Sentinel%26Pa55%3Dw%C3%B6rd%2B%25"
                   "&disable_antiforgery_token=true",
                   "application/x-www-form-urlencoded");
}

HttpResponse token_response()
{
    return make_response(200, R"({"access_token":")" + kAccessToken + R"(","refresh_token":")" +
                                  kRefreshToken +
                                  R"(","token_type":"bearer","expires_in":3600,"userName":"rp-veeam"})");
}

ordered_json parsed(const rp::ScrubbedExchange& file)
{
    return ordered_json::parse(file.text);
}

rp::ScrubbedExchange scrub(const HttpRequest& req, const HttpResponse& resp,
                           RecordedBody body = RecordedBody::content,
                           const std::set<std::string>& secrets = {})
{
    return rp::scrub_exchange(1, kSource, req, resp, body, secrets);
}

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), {}};
}

std::vector<std::string> names_in(const std::filesystem::path& dir)
{
    std::vector<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        names.push_back(entry.path().filename().string());
    }
    std::ranges::sort(names);
    return names;
}

} // namespace

// --- The folder ----------------------------------------------------------------

TEST_CASE("the recorder refuses a --record folder that isn't new or empty", "[record]")
{
    rp::test::TempDir dir;
    dir.write("old.json", "{}");
    try {
        rp::FixtureRecorder recorder(dir.path(), kSource, {});
        FAIL("a folder with a file in it was taken");
    } catch (const rp::ConfigError& e) {
        CHECK(e.key() == "--record");
        CHECK_THAT(e.what(), ContainsSubstring("the --record folder is not empty"));
    }
    // A file is no folder.
    try {
        rp::FixtureRecorder recorder(dir.path() / "old.json", kSource, {});
        FAIL("a file was taken for a folder");
    } catch (const rp::ConfigError& e) {
        CHECK_THAT(e.what(), ContainsSubstring("the --record path is not a folder"));
    }
    // Nothing was touched.
    CHECK(names_in(dir.path()) == std::vector<std::string>{"old.json"});
}

TEST_CASE("the recorder makes a missing --record folder and takes an empty one", "[record]")
{
    rp::test::TempDir dir;
    const std::filesystem::path nested = dir.path() / "a" / "b";
    rp::FixtureRecorder made(nested, kSource, {});
    CHECK(std::filesystem::is_directory(nested));
    CHECK(made.dir() == nested);
    rp::FixtureRecorder empty(nested, kSource, {});
    CHECK(empty.written() == 0);
    CHECK(empty.problems().empty());
}

// --- File names ----------------------------------------------------------------

TEST_CASE("a fixture's name is its number, method and path", "[record]")
{
    const auto [index, method, url, name] =
        GENERATE(table<std::size_t, HttpMethod, std::string, std::string>({
            {1, HttpMethod::get, "https://veeam.test:4443/v8/Organizations?limit=1000&offset=0",
             "001-get-v8-organizations.json"},
            {12, HttpMethod::post, "https://veeam.test:4443/v8/token", "012-post-v8-token.json"},
            {3, HttpMethod::del, "https://veeam.test:4443/", "003-delete-root.json"},
            {4, HttpMethod::get, "https://veeam.test:4443", "004-get-root.json"},
            {5, HttpMethod::get, "https://h/v1.0/users/restoretest@x.onmicrosoft.com/mailFolders/Inbox#f",
             "005-get-v1-0-users-restoretest-x-onmicrosoft-com-mailfolders-inbox.json"},
            {1000, HttpMethod::get, "/a//B_c/", "1000-get-a-b-c.json"},
            // Cut at 60 characters, never ending in '-'.
            {7, HttpMethod::get,
             "https://h/v8/RestoreSessions/171ea3e1-1f41-420c-94f7-140b57470d4a/organization/x",
             "007-get-v8-restoresessions-171ea3e1-1f41-420c-94f7-140b57470d4a-orga.json"},
            {8, HttpMethod::get,
             "https://h/v8/RestoreSessions/171ea3e1-1f41-420c-94f7-140b57470d4a/abc/xyz",
             "008-get-v8-restoresessions-171ea3e1-1f41-420c-94f7-140b57470d4a-abc.json"},
        }));
    CAPTURE(url);
    CHECK(rp::fixture_file_name(index, method, url) == name);
}

// --- What a fixture keeps --------------------------------------------------------

TEST_CASE("a token reply is recorded with placeholders and no request body", "[record]")
{
    const rp::ScrubbedExchange file = scrub(token_request(), token_response());
    CHECK(file.file_name == "001-post-v8-token.json");
    const ordered_json doc = parsed(file);
    CHECK(doc["source"] == kSource);
    CHECK(doc["request"] == "POST /v8/token");
    CHECK(doc["status"] == 200);
    CHECK(doc["headers"] == ordered_json{{"Content-Type", "application/json; charset=utf-8"}});
    CHECK(doc["body"]["access_token"] == "[REDACTED]");
    CHECK(doc["body"]["refresh_token"] == "[REDACTED]");
    CHECK(doc["body"]["expires_in"] == 3600);
    // The form body, with the password, is never written.
    CHECK_FALSE(doc.contains("request_body"));
    CHECK(file.text.find("Sentinel") == std::string::npos);
    CHECK(file.text.ends_with("}\n"));
    // Keys stay in the order they came.
    std::vector<std::string> keys;
    for (const auto& [key, value] : doc.items()) {
        keys.push_back(key);
    }
    CHECK(keys == std::vector<std::string>{"source", "request", "status", "headers", "body"});
    std::vector<std::string> body_keys;
    for (const auto& [key, value] : doc["body"].items()) {
        body_keys.push_back(key);
    }
    CHECK(body_keys == std::vector<std::string>{"access_token", "refresh_token", "token_type",
                                                "expires_in", "userName"});
}

TEST_CASE("a recorded token reply replays: its placeholder is a token the clients accept",
          "[record]")
{
    // The Veeam and Graph clients only need a non-empty token they can put in
    // a header; the fake serves the placeholder back as recorded.
    rp::test::TempDir dir;
    auto recorder = std::make_shared<rp::FixtureRecorder>(dir.path() / "rec", kSource,
                                                          std::vector<std::string>{});
    rp::test::FakeHttpClient live;
    live.on(HttpMethod::post, kVeeam + "/v8/token", {token_response()});
    rp::RecordingHttpClient client(std::make_unique<rp::test::ForwardingHttpClient>(live),
                                   recorder, "veeam");
    client.send(token_request());
    REQUIRE(recorder->written() == 1);

    rp::test::FakeHttpClient replay;
    CHECK(replay.serve_recording(dir.path() / "rec" / "veeam") == 1);
    const HttpResponse again = replay.send(token_request());
    CHECK(again.status == 200);
    CHECK(nlohmann::json::parse(again.body)["access_token"] == "[REDACTED]");
}

TEST_CASE("a fixture keeps only the response headers a replay needs", "[record]")
{
    HttpResponse resp = make_response(302, "", "");
    resp.headers["Content-Type"] = "text/html";
    resp.headers["Retry-After"] = "3";
    resp.headers["WWW-Authenticate"] = R"(Bearer realm="", error="invalid_token")";
    resp.headers["Location"] =
        "https://x.sharepoint.com/sites/t/_layouts/15/download.aspx?UniqueId=abc&tempauth=v1.secret&Translate=false";
    resp.headers["Set-Cookie"] = "FedAuth=cookie-secret";
    resp.headers["request-id"] = "0f6a";
    resp.headers["Authorization"] = "Bearer should-never-be-here";
    const rp::ScrubbedExchange file =
        scrub(request(HttpMethod::get, "https://graph.microsoft.com/v1.0/drives/b!x/items/1/content"),
              resp);
    const ordered_json doc = parsed(file);
    CHECK(doc["headers"] ==
          ordered_json{{"Content-Type", "text/html"},
                       {"Retry-After", "3"},
                       {"WWW-Authenticate", R"(Bearer realm="", error="invalid_token")"},
                       {"Location", "https://x.sharepoint.com/sites/t/_layouts/15/download.aspx?"
                                    "UniqueId=SCRUBBED&tempauth=SCRUBBED&Translate=SCRUBBED"}});
    CHECK(file.text.find("secret") == std::string::npos);
    CHECK(doc["body"].is_null());
}

TEST_CASE("no request header is ever recorded", "[record]")
{
    HttpRequest req = request(HttpMethod::get, kVeeam + "/v8/Organizations");
    req.headers["Authorization"] = "Bearer " + kAccessToken;
    req.headers["X-Custom"] = "custom-header-value";
    const rp::ScrubbedExchange file = scrub(req, make_response(200, "[]"));
    CHECK(file.text.find("custom-header-value") == std::string::npos);
    CHECK(file.text.find(kAccessToken) == std::string::npos);
    CHECK(parsed(file)["body"] == ordered_json::array());
}

TEST_CASE("a download is recorded as its size and SHA-256, never its bytes", "[record]")
{
    const std::string bytes = "PK\x03\x04 the file's own bytes";
    HttpResponse resp = make_response(200, bytes, "application/octet-stream");
    const rp::ScrubbedExchange file =
        scrub(request(HttpMethod::get, "https://x.sharepoint.com/sites/t/_layouts/15/download.aspx?"
                                       "UniqueId=abc&tempauth=v1.secret&ApiVersion=2.0"),
              resp, RecordedBody::digest);
    const ordered_json doc = parsed(file);
    CHECK(doc["request"] == "GET /sites/t/_layouts/15/download.aspx?UniqueId=SCRUBBED&"
                            "tempauth=SCRUBBED&ApiVersion=SCRUBBED");
    CHECK(doc["body"].is_null());
    CHECK(doc["body_size"] == bytes.size());
    CHECK(doc["body_sha256"] == rp::sha256_hex(bytes));
    CHECK(file.text.find("the file's own bytes") == std::string::npos);
    // A replay has no bytes to send, and says so.
    CHECK_THROWS_AS(rp::test::to_response(doc), std::runtime_error);
}

TEST_CASE("a body that isn't UTF-8 is recorded as its digest", "[record]")
{
    const std::string bytes = "\xff\xfe\x00 binary";
    const ordered_json doc =
        parsed(scrub(request(HttpMethod::get, kVeeam + "/v8/x"), make_response(200, bytes)));
    CHECK(doc["body"].is_null());
    CHECK(doc["body_sha256"] == rp::sha256_hex(bytes));
}

TEST_CASE("a text body is recorded as a string, redacted", "[record]")
{
    const ordered_json doc =
        parsed(scrub(request(HttpMethod::get, kVeeam + "/v8/x"),
                     make_response(500, "<html>Bearer abc123def and password=hunter22 end</html>",
                                   "text/html")));
    CHECK(doc["body"] == "<html>Bearer [REDACTED] and password=[REDACTED] end</html>");
}

TEST_CASE("an empty body is null, and the fragment never goes into the request line",
          "[record]")
{
    const ordered_json doc = parsed(scrub(request(HttpMethod::del, kVeeam + "/v8/x?y=1#frag"),
                                          make_response(204)));
    CHECK(doc["request"] == "DELETE /v8/x?y=1");
    CHECK(doc["body"].is_null());
    CHECK_FALSE(doc.contains("body_size"));
}

TEST_CASE("a query value that is a secret is redacted in the request line", "[record]")
{
    const ordered_json doc = parsed(
        scrub(request(HttpMethod::get, kVeeam + "/v8/x?limit=5&access_token=abcdef123"),
              make_response(200, "{}")));
    CHECK(doc["request"] == "GET /v8/x?limit=5&access_token=[REDACTED]");
}

TEST_CASE("Graph's download links are dropped from bodies", "[record]")
{
    const std::string body = R"({"value":[{"id":"1","name":"a.docx",)"
                             R"("@microsoft.graph.downloadUrl":"https://x/download.aspx?tempauth=v1.s"},)"
                             R"({"id":"2","nested":{"@content.downloadUrl":"https://x/y"}}]})";
    const ordered_json doc = parsed(
        scrub(request(HttpMethod::get, "https://graph.microsoft.com/v1.0/drives/b!x/root/children"),
              make_response(200, body)));
    CHECK(doc["body"] == ordered_json::parse(R"({"value":[{"id":"1","name":"a.docx"},)"
                                             R"({"id":"2","nested":{}}]})"));
}

TEST_CASE("a JSON request body is recorded with the restore credential redacted", "[record]")
{
    const std::string body = R"({"mailbox":"restoretest@x.onmicrosoft.com","folder":"Inbox",)"
                             R"("applicationCertificate":")" + kPfx +
                             R"(","applicationCertificatePassword":")" + kPfxPassword + R"("})";
    const HttpRequest req = request(HttpMethod::post, kVeeam + "/v8/RestoreSessions/s/x/restoreTo",
                                    body, "application/json");
    const std::vector<std::string> learned = rp::secrets_in(req, make_response(200, "{}"));
    CHECK(std::ranges::find(learned, kPfx) != learned.end());
    CHECK(std::ranges::find(learned, kPfxPassword) != learned.end());

    const rp::ScrubbedExchange file = scrub(req, make_response(200, R"({"sessionId":"s"})"),
                                            RecordedBody::content,
                                            {learned.begin(), learned.end()});
    const ordered_json doc = parsed(file);
    CHECK(doc["request_body"] ==
          ordered_json::parse(R"({"mailbox":"restoretest@x.onmicrosoft.com","folder":"Inbox",)"
                              R"("applicationCertificate":"[REDACTED]",)"
                              R"("applicationCertificatePassword":"[REDACTED]"})"));
    CHECK(file.text.find("SENTINEL") == std::string::npos);
}

TEST_CASE("a multipart request body is never recorded", "[record]")
{
    HttpRequest req = request(HttpMethod::post, "https://cloud.test/v1/bundles");
    req.body = R"({"not":"sent"})";
    req.parts.push_back({"bundle", R"({"a":1})", "bundle.json", "application/json"});
    CHECK_FALSE(parsed(scrub(req, make_response(202, "{}"))).contains("request_body"));
}

// --- What the recorder learns ------------------------------------------------------

TEST_CASE("the recorder learns the secrets an exchange carries", "[record]")
{
    HttpRequest req = token_request();
    req.headers["Authorization"] = "Bearer " + kAccessToken;
    HttpResponse resp = token_response();
    resp.headers["Location"] = "https://x/download.aspx?tempauth=v1.location-secret&UniqueId=u1";
    const std::vector<std::string> learned = rp::secrets_in(req, resp);
    const auto has = [&](const std::string& value) {
        return std::ranges::find(learned, value) != learned.end();
    };
    // The password raw (form-encoded) and decoded, both tokens, the header.
    CHECK(has("Sentinel%26Pa55%3Dw%C3%B6rd%2B%25"));
    CHECK(has(kPassword));
    CHECK(has(kAccessToken));
    CHECK(has("Bearer " + kAccessToken));
    CHECK(has(kRefreshToken));
    CHECK(has("v1.location-secret"));
    // Not secrets: the user name, the grant type, the Location's other values.
    CHECK_FALSE(has("rp-veeam"));
    CHECK_FALSE(has("password"));
    CHECK_FALSE(has("u1"));
}

TEST_CASE("the recorder learns a client assertion and a secret in a URL", "[record]")
{
    const HttpRequest form =
        request(HttpMethod::post, "https://login.microsoftonline.com/t/oauth2/v2.0/token",
                "client_id=c&client_assertion_type=urn%3Aietf&client_assertion=" + kJwt +
                    "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
                "application/x-www-form-urlencoded");
    const std::vector<std::string> learned = rp::secrets_in(form, make_response(400, "{}"));
    CHECK(std::ranges::find(learned, kJwt) != learned.end());
    CHECK(std::ranges::find(learned, std::string{"urn:ietf"}) == learned.end());

    const std::vector<std::string> in_url = rp::secrets_in(
        request(HttpMethod::get, "https://x/download.aspx?UniqueId=u&tempauth=v1.url-secret#f"),
        make_response(200));
    CHECK(in_url == std::vector<std::string>{"v1.url-secret"});
}

TEST_CASE("a placeholder is never learned as a secret", "[record]")
{
    // A replayed fixture's token is "[REDACTED]" already; learning it would
    // refuse every later file that holds a scrubbed value.
    HttpRequest req = request(HttpMethod::get, kVeeam + "/v8/x?tempauth=SCRUBBED");
    req.headers["Authorization"] = "Bearer [REDACTED]";
    CHECK(rp::secrets_in(req, make_response(200, R"({"access_token":"[REDACTED]"})")).empty());
}

TEST_CASE("a secret shorter than the minimum isn't learned", "[record]")
{
    const std::vector<std::string> learned = rp::secrets_in(
        request(HttpMethod::post, kVeeam + "/v8/token", "password=abc12", "application/x-www-form-urlencoded"),
        make_response(200, R"({"access_token":"abcdef"})"));
    CHECK(learned == std::vector<std::string>{"abcdef"});
}

// --- Refusals ------------------------------------------------------------------------

TEST_CASE("a fixture that still holds a secret is refused, saying which rule", "[record]")
{
    const auto [body, secrets, rule] =
        GENERATE(table<std::string, std::set<std::string>, std::string>({
            // A known secret where no key names it.
            {R"({"note":"SENTINEL-KNOWN-SECRET"})", {"SENTINEL-KNOWN-SECRET"},
             "it holds a known secret"},
            // JSON-escaped: a quote and a backslash in it.
            {R"({"note":"a\"b\\c-long"})", {"a\"b\\c-long"}, "it holds a known secret"},
            // JWT-shaped without its dots: redact() leaves it.
            {R"({"blob":"eyJ)" + std::string(37, '0') + R"("})", {},
             "it holds what looks like a JWT"},
            // A tempauth value redact() doesn't know, URL-encoded.
            {R"({"link":"https://x/download.aspx?tempauth%3Dv1.abc"})", {},
             "it holds a tempauth download credential"},
            {R"({"error":"AADSTS700027: client_assertion contains an invalid signature"})", {},
             "it mentions client_assertion"},
        }));
    CAPTURE(body);
    try {
        scrub(request(HttpMethod::get, kVeeam + "/v8/x"), make_response(200, body),
              RecordedBody::content, secrets);
        FAIL("the fixture was not refused");
    } catch (const rp::RecordRefused& e) {
        CHECK(std::string{e.what()} == "refused: " + rule);
    }
}

TEST_CASE("scrubbed values pass the refusal rules", "[record]")
{
    // "eyJ" and 36 base64url characters: one short of the JWT rule.
    const std::string body =
        R"({"a":"tempauth=SCRUBBED","b":"tempauth=[REDACTED]","c":"\"tempauth\": \"SCRUBBED\"",)"
        R"("d":"eyJ)" + std::string(36, '0') + R"(","e":"tempauthority=x"})";
    CHECK_NOTHROW(scrub(request(HttpMethod::get, kVeeam + "/v8/x"), make_response(200, body),
                        RecordedBody::content, {"short", ""}));
}

TEST_CASE("the recorder ignores known secrets shorter than the minimum", "[record]")
{
    rp::test::TempDir dir;
    rp::FixtureRecorder recorder(dir.path() / "rec", kSource, {"", "abc", "bearer"});
    // "bearer" (6) is known and would refuse the token reply; "abc" is ignored.
    recorder.record("veeam", request(HttpMethod::get, kVeeam + "/v8/abc"),
                    make_response(200, R"({"x":"abc"})"), RecordedBody::content);
    recorder.record("veeam", token_request(), token_response(), RecordedBody::content);
    CHECK(recorder.written() == 1);
    CHECK(recorder.problems() ==
          std::vector<std::string>{"veeam/002-post-v8-token.json: refused: it holds a known secret"});
}

// --- The recording client --------------------------------------------------------

TEST_CASE("the recording client passes every request through and numbers each service",
          "[record]")
{
    rp::test::TempDir dir;
    auto recorder = std::make_shared<rp::FixtureRecorder>(
        dir.path() / "rec", kSource, std::vector<std::string>{kPassword});
    rp::test::FakeHttpClient veeam_live;
    veeam_live.on(HttpMethod::post, kVeeam + "/v8/token", {token_response()});
    veeam_live.on(HttpMethod::get, kVeeam + "/v8/Organizations?limit=1000&offset=0",
                  {make_response(200, R"({"results":[]})")});
    rp::test::FakeHttpClient graph_live;
    graph_live.on(HttpMethod::get, "https://graph.microsoft.com/v1.0/me",
                  {make_response(200, R"({"id":"me"})")});
    rp::RecordingHttpClient veeam(std::make_unique<rp::test::ForwardingHttpClient>(veeam_live),
                                  recorder, "veeam");
    rp::RecordingHttpClient graph(std::make_unique<rp::test::ForwardingHttpClient>(graph_live),
                                  recorder, "graph");

    const HttpRequest token = token_request();
    const HttpResponse got = veeam.send(token);
    // Sent unchanged, answered unchanged.
    REQUIRE(veeam_live.requests().size() == 1);
    CHECK(veeam_live.requests()[0].body == token.body);
    CHECK(got.body == token_response().body);
    veeam.get(kVeeam + "/v8/Organizations?limit=1000&offset=0");
    graph.get("https://graph.microsoft.com/v1.0/me");

    CHECK(recorder->written() == 3);
    CHECK(recorder->problems().empty());
    CHECK(names_in(dir.path() / "rec") == std::vector<std::string>{"graph", "veeam"});
    CHECK(names_in(dir.path() / "rec" / "veeam") ==
          std::vector<std::string>{"001-post-v8-token.json", "002-get-v8-organizations.json"});
    CHECK(names_in(dir.path() / "rec" / "graph") ==
          std::vector<std::string>{"001-get-v1-0-me.json"});
    const std::string token_file = read_file(dir.path() / "rec" / "veeam" / "001-post-v8-token.json");
    CHECK(token_file.find(kAccessToken) == std::string::npos);
    CHECK(token_file.find(kRefreshToken) == std::string::npos);
}

TEST_CASE("the recording client records nothing for a request that failed", "[record]")
{
    rp::test::TempDir dir;
    auto recorder = std::make_shared<rp::FixtureRecorder>(dir.path() / "rec", kSource,
                                                          std::vector<std::string>{});
    rp::test::FakeHttpClient live;
    live.on(HttpMethod::get, kVeeam + "/v8/x", [](const HttpRequest&) -> HttpResponse {
        throw rp::HttpError("GET /v8/x: could not connect", rp::TransportError::connect, 0, 5);
    });
    rp::RecordingHttpClient client(std::make_unique<rp::test::ForwardingHttpClient>(live),
                                   recorder, "veeam");
    CHECK_THROWS_AS(client.get(kVeeam + "/v8/x"), rp::HttpError);
    CHECK(recorder->written() == 0);
    CHECK(recorder->problems().empty());
}

TEST_CASE("a refused exchange is named, and the next one keeps its own number", "[record]")
{
    rp::test::TempDir dir;
    auto recorder = std::make_shared<rp::FixtureRecorder>(
        dir.path() / "rec", kSource, std::vector<std::string>{"SENTINEL-KNOWN-SECRET"});
    rp::test::FakeHttpClient live;
    live.on(HttpMethod::get, kVeeam + "/v8/a", {make_response(200, R"({"n":"SENTINEL-KNOWN-SECRET"})")});
    live.on(HttpMethod::get, kVeeam + "/v8/b", {make_response(200, R"({"n":1})")});
    rp::RecordingHttpClient client(std::make_unique<rp::test::ForwardingHttpClient>(live),
                                   recorder, "veeam");
    // The response still reaches the caller: recording never changes what it sees.
    CHECK(client.get(kVeeam + "/v8/a").body == R"({"n":"SENTINEL-KNOWN-SECRET"})");
    client.get(kVeeam + "/v8/b");
    CHECK(recorder->written() == 1);
    CHECK(recorder->problems() == std::vector<std::string>{
                                      "veeam/001-get-v8-a.json: refused: it holds a known secret"});
    CHECK(names_in(dir.path() / "rec" / "veeam") ==
          std::vector<std::string>{"002-get-v8-b.json"});
}

TEST_CASE("a recording that can't be written is a problem, not an exception", "[record]")
{
    rp::test::TempDir dir;
    rp::FixtureRecorder recorder(dir.path() / "rec", kSource, {});
    // A file where the service's folder should be.
    dir.write(std::filesystem::path("rec") / "veeam", "not a folder");
    recorder.record("veeam", request(HttpMethod::get, kVeeam + "/v8/a"), make_response(200, "{}"),
                    RecordedBody::content);
    CHECK(recorder.written() == 0);
    CHECK(recorder.problems() ==
          std::vector<std::string>{"veeam/001-get-v8-a.json: could not be written"});
}

TEST_CASE("the recording client needs a client and a recorder", "[record]")
{
    rp::test::TempDir dir;
    auto recorder = std::make_shared<rp::FixtureRecorder>(dir.path() / "rec", kSource,
                                                          std::vector<std::string>{});
    CHECK_THROWS_AS(rp::RecordingHttpClient(nullptr, recorder, "veeam"), std::invalid_argument);
    rp::test::FakeHttpClient live;
    CHECK_THROWS_AS(rp::RecordingHttpClient(std::make_unique<rp::test::ForwardingHttpClient>(live),
                                            nullptr, "veeam"),
                    std::invalid_argument);
}

// --- Replay ----------------------------------------------------------------------------

TEST_CASE("FakeHttpClient replays a recording by method and path, in number order",
          "[record][fake]")
{
    rp::test::TempDir dir;
    auto recorder = std::make_shared<rp::FixtureRecorder>(dir.path() / "rec", kSource,
                                                          std::vector<std::string>{});
    rp::test::FakeHttpClient live;
    live.on(HttpMethod::get, kVeeam + "/v8/RestoreSessions/s1",
            {make_response(200, R"({"state":"Working"})"), make_response(200, R"({"state":"Stopped"})")});
    live.on(HttpMethod::post, kVeeam + "/v8/token/logout", {make_response(204)});
    rp::RecordingHttpClient client(std::make_unique<rp::test::ForwardingHttpClient>(live),
                                   recorder, "veeam");
    client.get(kVeeam + "/v8/RestoreSessions/s1");
    client.get(kVeeam + "/v8/RestoreSessions/s1");
    client.post(kVeeam + "/v8/token/logout", "", "");

    rp::test::FakeHttpClient replay;
    CHECK(replay.serve_recording(dir.path() / "rec" / "veeam") == 3);
    // Any host: a recording names none.
    CHECK(replay.get("https://elsewhere.test/v8/RestoreSessions/s1").body == R"({"state":"Working"})");
    CHECK(replay.get("https://elsewhere.test/v8/RestoreSessions/s1").body == R"({"state":"Stopped"})");
    // The last one repeats.
    CHECK(replay.get("https://elsewhere.test/v8/RestoreSessions/s1").body == R"({"state":"Stopped"})");
    CHECK(replay.post("https://elsewhere.test/v8/token/logout", "", "").status == 204);
    // Another method or path has no route.
    CHECK_THROWS_AS(replay.del("https://elsewhere.test/v8/RestoreSessions/s1"), std::logic_error);
    CHECK_THROWS_AS(replay.get("https://elsewhere.test/v8/RestoreSessions/s1?x=1"), std::logic_error);
}

TEST_CASE("FakeHttpClient refuses a recording file it can't route", "[record][fake]")
{
    const std::string line = GENERATE(std::string{"PATCH /v8/x"}, std::string{"GET"});
    rp::test::TempDir dir;
    dir.write("001-x.json", ordered_json{{"request", line}, {"status", 200}, {"headers", {}},
                                         {"body", nullptr}}
                                .dump());
    rp::test::FakeHttpClient replay;
    CHECK_THROWS_AS(replay.serve_recording(dir.path()), std::runtime_error);
}

TEST_CASE("FakeHttpClient routes by URL, then recorded path, then pattern", "[fake]")
{
    rp::test::FakeHttpClient fake;
    fake.on_path(HttpMethod::get, "/v8/RestoreSessions?startTimeFrom=*&limit=50",
                 {make_response(200, "pattern")});
    fake.on_path(HttpMethod::get, "/v8/RestoreSessions/*", {make_response(200, "any session")});
    fake.on(HttpMethod::get, kVeeam + "/v8/RestoreSessions/s1", {make_response(200, "exact")});
    CHECK(fake.get(kVeeam + "/v8/RestoreSessions/s1").body == "exact");
    CHECK(fake.get("https://other.test/v8/RestoreSessions/s1").body == "any session");
    CHECK(fake.get(kVeeam + "/v8/RestoreSessions?startTimeFrom=2026-10-01T10:00:00Z&limit=50").body ==
          "pattern");
    // '*' never crosses a '/'.
    CHECK_THROWS_AS(fake.get(kVeeam + "/v8/RestoreSessions/s1/Events"), std::logic_error);
    CHECK_THROWS_AS(fake.post(kVeeam + "/v8/RestoreSessions/s1", "", ""), std::logic_error);
}

TEST_CASE("path patterns match '*' within one segment only", "[fake]")
{
    const auto [pattern, path, match] = GENERATE(table<std::string, std::string, bool>({
        {"/a/*", "/a/b", true},
        {"/a/*", "/a/", true},
        {"/a/*", "/a/b/c", false},
        {"/a/*/c", "/a/b/c", true},
        {"/a/*/c", "/a/c", false},
        {"*", "", true},
        {"", "", true},
        {"", "/a", false},
        {"/a?x=*", "/a?x=1&y=2", true},
        {"/a", "/b", false},
        {"/a", "/a/", false},
    }));
    CAPTURE(pattern, path);
    CHECK(rp::test::path_matches(pattern, path) == match);
    CHECK(rp::test::url_path("https://h:1/a/b?c=d#e") == "/a/b?c=d");
    CHECK(rp::test::url_path("https://h") == "/");
    CHECK(rp::test::url_path("/x") == "/x");
}
