// W1.3: the HTTP client. Everything here talks to 127.0.0.1 only, and no test
// really sleeps for backoff: the waits are recorded instead.

#include "local_http_server.hpp" // first: httplib needs winsock2.h before windows.h

#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "../src/http_client_detail.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iterator>
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

std::size_t count_of(std::string_view text, std::string_view needle)
{
    std::size_t count = 0;
    for (std::size_t at = text.find(needle); at != std::string_view::npos;
         at = text.find(needle, at + needle.size())) {
        ++count;
    }
    return count;
}

// An HttpClient whose log, waits and jitter the test controls: the log goes
// to a string at debug level, the waits are recorded, jitter is 0.
struct TestClient {
    TestClient()
    {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("http_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::debug);
        rp::HttpClientOptions options;
        options.logger = logger;
        options.sleep = [this](std::chrono::milliseconds wait) {
            const std::lock_guard lock(mutex);
            sleeps.push_back(wait);
        };
        options.jitter = [] { return 0.0; };
        client = std::make_unique<rp::HttpClient>(std::move(options));
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    std::mutex mutex;
    std::vector<std::chrono::milliseconds> sleeps;
    std::unique_ptr<rp::HttpClient> client;
};

} // namespace

TEST_CASE("a call to an unreachable host is tried five times and logs no secrets", "[http]")
{
    // W1.3 "Done when". Secrets sit in all three places a request carries them:
    // a header, a form body and the query string.
    constexpr std::string_view auth_sentinel = "SENTINEL_AUTH_7f3a9c";
    constexpr std::string_view password_sentinel = "SENTINEL_PW_52b1e8";
    constexpr std::string_view secret_sentinel = "SENTINEL_CS_d04c6e";

    TestClient t;
    rp::HttpRequest request;
    request.method = rp::HttpMethod::post;
    request.url = "http://127.0.0.1:" + std::to_string(rp::test::closed_local_port()) +
                  "/token?client_secret=" + std::string{secret_sentinel};
    request.headers["Authorization"] = "Bearer " + std::string{auth_sentinel};
    request.body = "grant_type=password&username=u&password=" + std::string{password_sentinel};
    request.content_type = "application/x-www-form-urlencoded";

    std::string what;
    try {
        t.client->send(request);
        FAIL("send() returned for an unreachable host");
    } catch (const rp::HttpError& e) {
        what = e.what();
        CHECK(e.attempts() == 5);
        CHECK(e.error() == rp::TransportError::connect);
        CHECK(e.status() == 0);
    }

    const std::string log = t.log();
    CAPTURE(log, what);
    CHECK(count_of(log, "attempt ") == 5);
    for (int n = 1; n <= 5; ++n) {
        CHECK(count_of(log, "attempt " + std::to_string(n) + "/5") == 1);
    }
    CHECK(t.sleeps == std::vector<std::chrono::milliseconds>{1000ms, 2000ms, 4000ms, 8000ms});
    for (std::string_view sentinel : {auth_sentinel, password_sentinel, secret_sentinel}) {
        CHECK(log.find(sentinel) == std::string::npos);
        CHECK(what.find(sentinel) == std::string::npos);
    }
    // The URL was logged, redacted.
    CHECK(log.find("client_secret=[REDACTED]") != std::string::npos);
    CHECK(what.find("client_secret=[REDACTED]") != std::string::npos);
}

TEST_CASE("a status the client doesn't retry is returned after one attempt", "[http]")
{
    const int status = GENERATE(400, 401, 403, 404, 409, 429);
    CAPTURE(status);
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    server.server().Get("/item", [&](const httplib::Request&, httplib::Response& res) {
        ++hits;
        res.status = status;
        res.set_content("nope", "text/plain");
    });
    TestClient t;

    const rp::HttpResponse response = t.client->get(server.url("/item"));

    CHECK(response.status == status);
    CHECK(response.body == "nope");
    CHECK(hits == 1);
    CHECK(t.sleeps.empty());
    CHECK(count_of(t.log(), "attempt 1/5: HTTP " + std::to_string(status) + " in ") == 1);
}

TEST_CASE("a 5xx on every attempt ends in an HttpError after five attempts", "[http]")
{
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    server.server().Get("/busy", [&](const httplib::Request&, httplib::Response& res) {
        ++hits;
        res.status = 503;
    });
    TestClient t;

    try {
        t.client->get(server.url("/busy"));
        FAIL("send() returned for a server that only answers 503");
    } catch (const rp::HttpError& e) {
        CHECK(e.status() == 503);
        CHECK(e.error() == rp::TransportError::none);
        CHECK(e.attempts() == 5);
        CHECK(std::string{e.what()} == "GET " + server.url("/busy") + ": HTTP 503 after 5 attempts");
    }
    CHECK(hits == 5);
    CHECK(t.sleeps == std::vector<std::chrono::milliseconds>{1000ms, 2000ms, 4000ms, 8000ms});
    const std::string log = t.log();
    CHECK(count_of(log, ": HTTP 503 in ") == 5);
    CHECK(count_of(log, "; retrying in ") == 4);
    CHECK(count_of(log, "attempt 1/5: HTTP 503 in ") == 1);
    CHECK(log.find("attempt 5/5: HTTP 503 in ") != std::string::npos);
}

TEST_CASE("a 5xx followed by a success returns the success", "[http]")
{
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    server.server().Get("/flaky", [&](const httplib::Request&, httplib::Response& res) {
        res.status = ++hits < 3 ? 500 : 200;
        res.set_content("ok", "text/plain");
    });
    TestClient t;

    const rp::HttpResponse response = t.client->get(server.url("/flaky"));

    CHECK(response.status == 200);
    CHECK(response.body == "ok");
    CHECK(hits == 3);
    CHECK(t.sleeps == std::vector<std::chrono::milliseconds>{1000ms, 2000ms});
}

TEST_CASE("a request that outlives its timeout is retried as a timeout", "[http]")
{
    // The handler holds each request until the gate opens or 1.5 s pass; the
    // client gives up after 200 ms. The gate opens before the server stops, so
    // shutdown doesn't wait on sleeping handlers.
    struct Gate {
        std::mutex mutex;
        std::condition_variable cv;
        bool open = false;
    };
    std::atomic<int> hits = 0;
    Gate gate;
    rp::test::LocalHttpServer server;
    server.server().Get("/slow", [&](const httplib::Request&, httplib::Response& res) {
        ++hits;
        std::unique_lock lock(gate.mutex);
        gate.cv.wait_for(lock, 1500ms, [&] { return gate.open; });
        res.set_content("late", "text/plain");
    });
    struct OpenOnExit {
        Gate& gate;
        ~OpenOnExit()
        {
            {
                const std::lock_guard lock(gate.mutex);
                gate.open = true;
            }
            gate.cv.notify_all();
        }
    } open_on_exit{gate};
    TestClient t;
    rp::HttpRequest request;
    request.url = server.url("/slow");
    request.timeout = 200ms;

    const auto start = std::chrono::steady_clock::now();
    try {
        t.client->send(request);
        FAIL("send() returned for a server that never answers in time");
    } catch (const rp::HttpError& e) {
        CHECK(e.error() == rp::TransportError::timeout);
        CHECK(e.status() == 0);
        CHECK(e.attempts() == 5);
        CHECK(std::string{e.what()}.starts_with("GET " + server.url("/slow") +
                                                ": timed out after 5 attempts: "));
    }
    CHECK(std::chrono::steady_clock::now() - start < 5s);
    CHECK(hits == 5);
    CHECK(t.sleeps.size() == 4);
    CHECK(count_of(t.log(), ": timed out (") == 5);
}

TEST_CASE("a TLS failure is not retried", "[http]")
{
    // https:// to a plain-HTTP server: the TLS handshake can't succeed.
    rp::test::LocalHttpServer server;
    server.server().Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("plain", "text/plain");
    });
    TestClient t;
    const std::string url = "https://127.0.0.1:" + std::to_string(server.port()) + "/";

    try {
        t.client->get(url);
        FAIL("send() returned over a failed TLS handshake");
    } catch (const rp::HttpError& e) {
        CHECK(e.error() == rp::TransportError::tls);
        CHECK(e.attempts() == 1);
        CHECK(std::string{e.what()}.starts_with("GET " + url +
                                                ": TLS failure on attempt 1 (not retried): "));
    }
    CHECK(t.sleeps.empty());
}

TEST_CASE("a malformed URL fails once as other, without a retry", "[http]")
{
    const std::string url = GENERATE("nosuchscheme://127.0.0.1/", "http://[::1/");
    CAPTURE(url);
    TestClient t;

    try {
        t.client->get(url);
        FAIL("send() returned for a malformed URL");
    } catch (const rp::HttpError& e) {
        CHECK(e.error() == rp::TransportError::other);
        CHECK(e.attempts() == 1);
        CHECK(std::string{e.what()}.starts_with("GET " + url +
                                                ": request failed on attempt 1 (not retried): "));
    }
    CHECK(t.sleeps.empty());
    CHECK(count_of(t.log(), ": request failed (") == 1);
}

TEST_CASE("a plain multipart field with a NUL byte is refused before sending", "[http]")
{
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    server.server().Post("/upload", [&](const httplib::Request&, httplib::Response&) { ++hits; });
    TestClient t;

    REQUIRE_THROWS_AS(t.client->post_multipart(server.url("/upload"),
                                               {{"field", std::string("a\0b", 3), "", ""}}),
                      std::invalid_argument);
    CHECK(hits == 0);
}

TEST_CASE("HttpError redacts its message", "[http]")
{
    // A fake (Q2.1) may throw HttpError with any text; it still can't carry a
    // secret out.
    const rp::HttpError e("GET https://h/p?client_secret=SENTINEL_CS_x: HTTP 500 after 5 attempts",
                          rp::TransportError::none, 500, 5);
    CHECK(std::string{e.what()}.find("SENTINEL_CS_x") == std::string::npos);
    CHECK(e.status() == 500);
    CHECK(e.error() == rp::TransportError::none);
    CHECK(e.attempts() == 5);
}

TEST_CASE("a POST sends its body, content type and headers", "[http]")
{
    std::string method;
    std::string body;
    std::string content_type;
    std::string custom;
    rp::test::LocalHttpServer server;
    server.server().Post("/echo", [&](const httplib::Request& req, httplib::Response& res) {
        method = req.method;
        body = req.body;
        content_type = req.get_header_value("Content-Type");
        custom = req.get_header_value("X-Rp-Test");
        res.status = 201;
    });
    TestClient t;
    rp::RequestOptions options;
    options.headers["x-rp-test"] = "yes";
    const std::string sent = std::string("{\"a\":1}\0\xff", 9);

    const rp::HttpResponse response =
        t.client->post(server.url("/echo"), sent, "application/json", options);

    CHECK(response.status == 201);
    CHECK(method == "POST");
    CHECK(body == sent);
    CHECK(content_type == "application/json");
    CHECK(custom == "yes");
}

TEST_CASE("a DELETE reaches the server as DELETE", "[http]")
{
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    server.server().Delete("/item/7", [&](const httplib::Request&, httplib::Response& res) {
        ++hits;
        res.status = 204;
    });
    TestClient t;

    CHECK(t.client->del(server.url("/item/7")).status == 204);
    CHECK(hits == 1);
}

TEST_CASE("a multipart upload arrives intact", "[http]")
{
    httplib::MultipartFormData received;
    rp::test::LocalHttpServer server;
    server.server().Post("/upload", [&](const httplib::Request& req, httplib::Response&) {
        received = req.form;
    });
    TestClient t;
    const std::string binary("\x00\x01\xff\xfe-\r\n--end\x00", 12);
    // "файл" is Cyrillic: outside the ANSI code page, so it proves the name
    // goes out as UTF-8.
    const std::string filename = "\xd1\x84\xd0\xb0\xd0\xb9\xd0\xbb.bin";

    const rp::HttpResponse response = t.client->post_multipart(
        server.url("/upload"), {{"bundle", binary, filename, "application/octet-stream"},
                                {"job_id", "42", "", ""},
                                {"empty", "", "empty.txt", "text/plain"}});

    CHECK(response.status == 200);
    REQUIRE(received.has_file("bundle"));
    const httplib::FormData file = received.get_file("bundle");
    CHECK(file.content == binary);
    CHECK(file.filename == filename);
    CHECK(file.content_type == "application/octet-stream");
    CHECK(received.get_field("job_id") == "42");
    REQUIRE(received.has_file("empty"));
    CHECK(received.get_file("empty").content.empty());
    CHECK(received.get_file("empty").filename == "empty.txt");
}

TEST_CASE("response headers are read case-insensitively", "[http]")
{
    rp::test::LocalHttpServer server;
    server.server().Get("/h", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("X-Request-Id", "abc123");
        res.set_content("{}", "application/json");
    });
    TestClient t;

    const rp::HttpResponse response = t.client->get(server.url("/h"));

    CHECK(response.headers.at("x-request-id") == "abc123");
    CHECK(response.headers.at("X-REQUEST-ID") == "abc123");
    CHECK(response.headers.at("content-type") == "application/json");
}

TEST_CASE("a redirect is returned to the caller, not followed", "[http]")
{
    std::atomic<int> followed = 0;
    rp::test::LocalHttpServer server;
    server.server().Get("/from", [](const httplib::Request&, httplib::Response& res) {
        res.set_redirect("/to", 302);
    });
    server.server().Get("/to", [&](const httplib::Request&, httplib::Response&) { ++followed; });
    TestClient t;

    const rp::HttpResponse response = t.client->get(server.url("/from"));

    CHECK(response.status == 302);
    CHECK(response.headers.at("location") == "/to");
    CHECK(followed == 0);
}

TEST_CASE("the per-request timeout reaches the transport", "[http]")
{
    // The same slow handler as above, but a timeout long enough for it: the
    // request succeeds, so the timeout isn't a fixed value.
    rp::test::LocalHttpServer server;
    server.server().Get("/slowish", [](const httplib::Request&, httplib::Response& res) {
        std::this_thread::sleep_for(300ms);
        res.set_content("done", "text/plain");
    });
    TestClient t;
    rp::RequestOptions options;
    options.timeout = 5s;

    CHECK(t.client->get(server.url("/slowish"), options).body == "done");
}

TEST_CASE("an HttpClient with default options sends a request", "[http]")
{
    rp::test::LocalHttpServer server;
    server.server().Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("hi", "text/plain");
    });
    rp::HttpClient client;

    CHECK(client.get(server.url("/")).body == "hi");
}

namespace {

// Records what it's asked to send: proves a fake needs only send(), the seam
// Q2.1's FakeHttpClient uses.
class RecordingClient final : public rp::IHttpClient {
public:
    rp::HttpResponse send(const rp::HttpRequest& request) override
    {
        sent.push_back(request);
        return {200, {}, "recorded"};
    }

    std::vector<rp::HttpRequest> sent;
};

} // namespace

TEST_CASE("the IHttpClient helpers build the request and call send", "[http]")
{
    RecordingClient fake;
    rp::RequestOptions options;
    options.headers["Authorization"] = "Bearer t";
    options.timeout = 120s;

    CHECK(fake.get("https://h/a", options).body == "recorded");
    fake.post("https://h/b", "x=1", "application/x-www-form-urlencoded");
    fake.post_multipart("https://h/c", {{"f", "data", "f.bin", "application/octet-stream"}});
    fake.del("https://h/d", options);

    REQUIRE(fake.sent.size() == 4);
    CHECK(fake.sent[0].method == rp::HttpMethod::get);
    CHECK(fake.sent[0].url == "https://h/a");
    CHECK(fake.sent[0].headers.at("authorization") == "Bearer t");
    CHECK(fake.sent[0].timeout == 120s);
    CHECK(fake.sent[1].method == rp::HttpMethod::post);
    CHECK(fake.sent[1].body == "x=1");
    CHECK(fake.sent[1].content_type == "application/x-www-form-urlencoded");
    CHECK(fake.sent[1].timeout == rp::kDefaultHttpTimeout);
    CHECK(fake.sent[1].headers.empty());
    CHECK(fake.sent[2].method == rp::HttpMethod::post);
    REQUIRE(fake.sent[2].parts.size() == 1);
    CHECK(fake.sent[2].parts[0].filename == "f.bin");
    CHECK(fake.sent[2].body.empty());
    CHECK(fake.sent[3].method == rp::HttpMethod::del);
    CHECK(fake.sent[3].url == "https://h/d");
    CHECK(fake.sent[3].timeout == 120s);
}

TEST_CASE("to_string names each HTTP method", "[http]")
{
    const auto [method, name] = GENERATE(table<rp::HttpMethod, std::string_view>({
        {rp::HttpMethod::get, "GET"},
        {rp::HttpMethod::post, "POST"},
        {rp::HttpMethod::del, "DELETE"},
    }));
    CHECK(rp::to_string(method) == name);
}

TEST_CASE("header names compare case-insensitively", "[http]")
{
    const rp::CaseInsensitiveLess less;
    CHECK_FALSE(less("Content-Type", "content-type"));
    CHECK_FALSE(less("content-type", "Content-Type"));
    CHECK(less("Accept", "authorization"));
    CHECK(less("a", "AB"));
    CHECK_FALSE(less("AB", "a"));
}

// --- TLS configuration ------------------------------------------------------

TEST_CASE("TLS verification is on with or without a custom CA file", "[http]")
{
    // "тест-ca.pem": Cyrillic, outside the ANSI code page.
    const std::string cyrillic = "C:\\certs\\\xd1\x82\xd0\xb5\xd1\x81\xd1\x82-ca.pem";
    const std::optional<std::string> ca_file =
        GENERATE_COPY(std::optional<std::string>{}, std::optional<std::string>{cyrillic});
    CAPTURE(ca_file.value_or("(none)"));

    const cpr::SslOptions options = rp::detail::make_ssl_options(ca_file);

    CHECK(options.verify_peer);
    CHECK(options.verify_host);
    CHECK_FALSE(options.ssl_no_revoke);
    // The exact UTF-8 bytes: no conversion through the ANSI code page.
    CHECK(options.ca_info == ca_file.value_or(""));
}

namespace {

// Constructs that turn TLS verification (or revocation checking) off, with
// all whitespace removed. None may appear in the Worker's own code.
constexpr std::array<std::string_view, 14> kTlsDisablers{
    "VerifySsl{false}",       "VerifySsl(false)",       "verify_peer=false",
    "verify_host=false",      "CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST",
    "NO_REVOKE",              "ssl_no_revoke=true",     "NoRevoke",
    "VerifyPeer{false}",      "VerifyHost{false}",      "VerifyPeer(false)",
    "VerifyHost(false)",      "verify_peer=0",
};

// The disablers found in `source`, ignoring whitespace.
std::vector<std::string_view> find_tls_disablers(std::string_view source)
{
    std::string compact;
    std::copy_if(source.begin(), source.end(), std::back_inserter(compact),
                 [](char c) { return !std::isspace(static_cast<unsigned char>(c)); });
    std::vector<std::string_view> found;
    for (std::string_view pattern : kTlsDisablers) {
        if (compact.find(pattern) != std::string::npos) {
            found.push_back(pattern);
        }
    }
    return found;
}

} // namespace

TEST_CASE("the TLS scan finds each way to turn verification off", "[http]")
{
    const std::string_view planted = GENERATE(
        "session.SetVerifySsl(cpr::VerifySsl{ false });", "cpr::VerifySsl(false)",
        "options.verify_peer = false;", "opts.verify_host =\n false;",
        "curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);",
        "curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);", "flags |= CURLSSLOPT_NO_REVOKE;",
        "o.ssl_no_revoke = true;", "cpr::ssl::NoRevoke{true}", "cpr::ssl::VerifyPeer{false}",
        "cpr::ssl::VerifyHost{false}", "ssl::VerifyPeer( false )", "ssl::VerifyHost(false)",
        "o.verify_peer = 0;");
    CAPTURE(planted);
    CHECK(find_tls_disablers(planted).size() == 1);
    CHECK(find_tls_disablers("options.verify_peer = true; options.verify_host = true;").empty());
}

TEST_CASE("no Worker source turns TLS verification off", "[http]")
{
    const std::filesystem::path root{RP_SOURCE_DIR};
    std::size_t scanned = 0;
    for (const char* dir : {"src", "include", "app"}) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root / dir)) {
            const std::filesystem::path& path = entry.path();
            if (!entry.is_regular_file() ||
                (path.extension() != ".cpp" && path.extension() != ".hpp" &&
                 path.extension() != ".h")) {
                continue;
            }
            std::ifstream file(path, std::ios::binary);
            const std::string text{std::istreambuf_iterator<char>(file), {}};
            CAPTURE(path.generic_string());
            CHECK(find_tls_disablers(text).empty());
            ++scanned;
        }
    }
    // The scan saw the HTTP client itself, so it isn't looking in the wrong place.
    CHECK(scanned >= 10);
    CHECK(std::filesystem::exists(root / "src" / "http_client.cpp"));
}

TEST_CASE("curl errors map to the retry policy's transport errors", "[http]")
{
    using E = cpr::ErrorCode;
    using T = rp::TransportError;
    const auto [code, expected] = GENERATE(table<E, T>({
        {E::OK, T::none},
        {E::COULDNT_RESOLVE_PROXY, T::connect},
        {E::COULDNT_RESOLVE_HOST, T::connect},
        {E::COULDNT_CONNECT, T::connect},
        {E::SEND_ERROR, T::connect},
        {E::RECV_ERROR, T::connect},
        {E::GOT_NOTHING, T::connect},
        {E::PARTIAL_FILE, T::connect},
        {E::NO_CONNECTION_AVAILABLE, T::connect},
        {E::OPERATION_TIMEDOUT, T::timeout},
        {E::SSL_CONNECT_ERROR, T::tls},
        {E::SSL_ENGINE_NOTFOUND, T::tls},
        {E::SSL_ENGINE_SETFAILED, T::tls},
        {E::SSL_CERTPROBLEM, T::tls},
        {E::SSL_CIPHER, T::tls},
        {E::PEER_FAILED_VERIFICATION, T::tls},
        {E::USE_SSL_FAILED, T::tls},
        {E::SSL_ENGINE_INITFAILED, T::tls},
        {E::SSL_CACERT_BADFILE, T::tls},
        {E::SSL_SHUTDOWN_FAILED, T::tls},
        {E::SSL_CRL_BADFILE, T::tls},
        {E::SSL_ISSUER_ERROR, T::tls},
        {E::SSL_PINNEDPUBKEYNOTMATCH, T::tls},
        {E::SSL_INVALIDCERTSTATUS, T::tls},
        {E::SSL_CLIENTCERT, T::tls},
        {E::UNSUPPORTED_PROTOCOL, T::other},
        {E::URL_MALFORMAT, T::other},
        {E::WEIRD_SERVER_REPLY, T::other},
        {E::TOO_MANY_REDIRECTS, T::other},
        {E::OUT_OF_MEMORY, T::other},
        {E::UNKNOWN_ERROR, T::other},
    }));
    CAPTURE(static_cast<int>(code));
    CHECK(rp::detail::classify(code) == expected);
}
