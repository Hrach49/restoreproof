// W1.3: the HTTP client. Everything here talks to 127.0.0.1 only, and no test
// really sleeps for backoff: the waits are recorded instead.

#include "local_http_server.hpp" // first: httplib needs winsock2.h before windows.h
#include "test_support.hpp"

#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "../src/http_client_detail.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <clocale>
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

TEST_CASE("a connection dropped during the TLS handshake is retried", "[http]")
{
    // Schannel reports any failure to send or receive handshake data as
    // SSL_CONNECT_ERROR, not as the RECV_ERROR a plain-HTTP drop gives. The
    // server reads the ClientHello and closes, as a restarting Veeam REST
    // service or a load balancer would.
    rp::test::DroppingServer server;
    TestClient t;
    const std::string url = "https://127.0.0.1:" + std::to_string(server.port()) + "/";

    try {
        t.client->get(url);
        FAIL("send() returned over a dropped TLS handshake");
    } catch (const rp::HttpError& e) {
        CHECK(e.error() == rp::TransportError::handshake);
        CHECK(e.status() == 0);
        CHECK(e.attempts() == 5);
        CHECK(std::string{e.what()}.starts_with("GET " + url +
                                                ": TLS handshake failed after 5 attempts: "));
    }
    CHECK(server.accepted() == 5);
    CHECK(t.sleeps == std::vector<std::chrono::milliseconds>{1000ms, 2000ms, 4000ms, 8000ms});
    CHECK(count_of(t.log(), ": TLS handshake failed (") == 5);
}

TEST_CASE("a malformed URL fails once as other, without a retry", "[http]")
{
    const std::string url = "http://[::1/";
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

TEST_CASE("a URL that isn't http:// or https:// is refused before sending", "[http]")
{
    // curl here is built with FILE, FTP, SMB, LDAP and more. A URL taken from a
    // server response (a nextLink, a Location, a _links href) must not read a
    // local file or open a cleartext connection elsewhere. curl would also
    // guess a scheme for a URL without one ("ftp.host/x" as FTP).
    const rp::test::TempDir dir;
    const std::filesystem::path secret = dir.write("vault.bin", "SENTINEL_FILE_91d2");
    const std::u8string secret_u8 = secret.generic_u8string();
    const std::string file_url = "file:///" + std::string{secret_u8.begin(), secret_u8.end()};
    const std::string url = GENERATE_COPY(
        file_url, std::string{"FILE:///C:/Windows/win.ini"}, std::string{"ftp://127.0.0.1/x"},
        std::string{"smb://127.0.0.1/share"}, std::string{"ldap://127.0.0.1/"},
        std::string{"nosuchscheme://127.0.0.1/"}, std::string{"127.0.0.1/x"},
        std::string{"ftp.example.com/x"}, std::string{"//127.0.0.1/x"},
        std::string{" http://127.0.0.1/"}, std::string{"http:/127.0.0.1/"},
        std::string{"https:127.0.0.1/"}, std::string{""});
    CAPTURE(url);
    TestClient t;

    try {
        const rp::HttpResponse response = t.client->get(url);
        FAIL("send() returned for a URL that isn't http:// or https://; body: " << response.body);
    } catch (const rp::HttpError& e) {
        const std::string what = e.what();
        CAPTURE(what);
        CHECK(e.error() == rp::TransportError::other);
        CHECK(e.status() == 0);
        CHECK(e.attempts() == 0);
        CHECK(what == "GET " + url +
                          ": refused before sending: only http:// and https:// URLs are sent");
    }
    CHECK(t.sleeps.empty());
    CHECK(t.log().empty());
}

TEST_CASE("the URL scheme is matched in any case", "[http]")
{
    rp::test::LocalHttpServer server;
    server.server().Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("ok", "text/plain");
    });
    const std::string scheme = GENERATE("http", "HTTP", "Http");
    TestClient t;

    const rp::HttpResponse response =
        t.client->get(scheme + "://127.0.0.1:" + std::to_string(server.port()) + "/");

    CHECK(response.status == 200);
}

TEST_CASE("a refused URL's message is redacted", "[http]")
{
    TestClient t;
    try {
        t.client->get("ftp://user:SENTINEL_PW_1b7e@127.0.0.1/?client_secret=SENTINEL_CS_4c0a");
        FAIL("send() returned for an ftp:// URL");
    } catch (const rp::HttpError& e) {
        const std::string what = e.what();
        CAPTURE(what);
        CHECK(what.find("SENTINEL") == std::string::npos);
    }
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

TEST_CASE("a request with an unknown method is refused, never sent as DELETE", "[http]")
{
    // perform() and to_string() used to send every method but GET and POST as
    // DELETE. A method added later without a case, or a value out of range,
    // would have deleted whatever the URL named.
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    const auto count = [&](const httplib::Request&, httplib::Response&) { ++hits; };
    server.server().Get("/item", count);
    server.server().Post("/item", count);
    server.server().Delete("/item", count);
    TestClient t;
    rp::HttpRequest request;
    request.method = static_cast<rp::HttpMethod>(99);
    request.url = server.url("/item");

    try {
        t.client->send(request);
        FAIL("send() returned for an unknown method");
    } catch (const std::invalid_argument& e) {
        CHECK(std::string{e.what()} == "unknown HTTP method 99");
    }
    CHECK(hits == 0);
    CHECK(rp::to_string(request.method) == "UNKNOWN");
}

TEST_CASE("a request timeout of zero or less is refused before sending", "[http]")
{
    // curl reads a timeout of 0 as "none": the request could hang for ever.
    const std::chrono::milliseconds timeout = GENERATE(0ms, -1ms, -30000ms);
    CAPTURE(timeout.count());
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    server.server().Get("/", [&](const httplib::Request&, httplib::Response&) { ++hits; });
    TestClient t;
    rp::RequestOptions options;
    options.timeout = timeout;

    REQUIRE_THROWS_AS(t.client->get(server.url("/"), options), std::invalid_argument);
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

TEST_CASE("an HttpClient still sends when spdlog has no default logger", "[http]")
{
    // spdlog::drop_all() and shutdown() leave the default logger null.
    struct RestoreDefaultLogger {
        std::shared_ptr<spdlog::logger> saved = spdlog::default_logger();
        ~RestoreDefaultLogger() { spdlog::set_default_logger(saved); }
    } restore;
    spdlog::drop_all();
    REQUIRE(spdlog::default_logger() == nullptr);
    rp::test::LocalHttpServer server;
    server.server().Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("hi", "text/plain");
    });
    rp::HttpClient client;

    CHECK(client.get(server.url("/")).body == "hi");
}

TEST_CASE("the default jitter shortens a wait by at most a quarter", "[http]")
{
    std::atomic<int> hits = 0;
    rp::test::LocalHttpServer server;
    server.server().Get("/flaky", [&](const httplib::Request&, httplib::Response& res) {
        res.status = ++hits < 5 ? 500 : 200;
    });
    std::vector<std::chrono::milliseconds> sleeps;
    rp::HttpClientOptions options;
    options.sleep = [&](std::chrono::milliseconds wait) { sleeps.push_back(wait); };
    rp::HttpClient client(std::move(options));

    CHECK(client.get(server.url("/flaky")).status == 200);

    REQUIRE(sleeps.size() == 4);
    for (std::size_t i = 0; i < sleeps.size(); ++i) {
        const std::chrono::milliseconds nominal = rp::retry_delay(static_cast<int>(i) + 1, 0.0);
        CAPTURE(i, sleeps[i].count());
        CHECK(sleeps[i] <= nominal);
        CHECK(sleeps[i] >= nominal * 3 / 4);
    }
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
    // Bytes from 0x80 sort after ASCII (unsigned), whatever char's sign.
    CHECK(less("z", "\x80"));
    CHECK_FALSE(less("\x80", "z"));
}

TEST_CASE("header names fold only ASCII letters, whatever the C locale", "[http]")
{
    // Under a Western code page, std::tolower would fold 0xC4 (Ä in
    // Windows-1252) to 0xE4 (ä) and make them one header name. HTTP header
    // names are ASCII tokens; only A-Z fold.
    struct RestoreLocale {
        std::string saved = std::setlocale(LC_ALL, nullptr);
        ~RestoreLocale() { std::setlocale(LC_ALL, saved.c_str()); }
    } restore;
    REQUIRE(std::setlocale(LC_ALL, ".1252") != nullptr);
    const rp::CaseInsensitiveLess less;

    CHECK(less("\xC4", "\xE4"));
    CHECK_FALSE(less("\xE4", "\xC4"));
    CHECK_FALSE(less("X-A", "x-a"));
    CHECK_FALSE(less("x-a", "X-A"));
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

// A tripwire, not a proof: it catches the usual ways to weaken TLS through
// cpr or curl; review catches the rest.
//
// Names with no business anywhere in Worker code, comments included: cpr's
// per-option TLS switches, raw curl options and flags (CURLOPT_SSL_*,
// CURLOPT_PROXY_SSL_*, CURLSSLOPT_*, and curl_easy_setopt itself: cpr sets
// every option), revocation opt-outs, SSL_CTX callbacks that could replace
// verification, in-memory CA bundles (only ca_file is a way to add trust),
// and verify_status: OCSP stapling stays at cpr's default, off, on purpose
// (many servers, a self-signed Veeam one included, don't staple), so nothing
// should touch it.
constexpr std::array<std::string_view, 16> kTlsBannedNames{
    "VerifySsl",        "VerifyPeer",       "VerifyHost",          "NoRevoke",
    "ssl_no_revoke",    "CURLOPT_SSL_",     "CURLOPT_PROXY_SSL_",  "CURLSSLOPT_",
    "curl_easy_setopt", "ssl_ctx_callback", "SslCtxCallback",      "CURLOPT_CAINFO_BLOB",
    "ca_info_blob",     "CaInfoBlob",       "ca_buffer",           "verify_status",
};

// SslOptions members that may only ever be set to exactly `true`.
constexpr std::array<std::string_view, 2> kMustBeTrue{"verify_peer", "verify_host"};

// The one raw curl call allowed, whitespace removed: revocation checked on a
// best-effort basis with a CA file (a revoked certificate is still rejected),
// which cpr has no setting for. Only src/http_client.cpp may hold it, once.
constexpr std::string_view kAllowedRevokeBestEffort =
    "curl_easy_setopt(session.GetCurlHolder()->handle,CURLOPT_SSL_OPTIONS,CURLSSLOPT_NATIVE_CA|"
    "CURLSSLOPT_REVOKE_BEST_EFFORT);";

// `source` with whitespace removed.
std::string compact(std::string_view source)
{
    std::string out;
    std::copy_if(source.begin(), source.end(), std::back_inserter(out),
                 [](char c) { return !std::isspace(static_cast<unsigned char>(c)); });
    return out;
}

// What in `source` could weaken TLS: each banned name present outside the
// allowed statement, and each verify_peer / verify_host not followed by
// exactly "=true;" once whitespace is removed, so `= allow`, `= !strict`,
// `{false}`, a reference to it, or a read all count.
std::vector<std::string> find_tls_disablers(std::string_view source)
{
    std::string compact = ::compact(source);
    for (std::size_t at = compact.find(kAllowedRevokeBestEffort); at != std::string::npos;
         at = compact.find(kAllowedRevokeBestEffort, at)) {
        compact.erase(at, kAllowedRevokeBestEffort.size());
    }
    std::vector<std::string> found;
    for (std::string_view name : kTlsBannedNames) {
        if (compact.find(name) != std::string::npos) {
            found.emplace_back(name);
        }
    }
    for (std::string_view member : kMustBeTrue) {
        for (std::size_t at = compact.find(member); at != std::string::npos;
             at = compact.find(member, at + 1)) {
            if (!std::string_view{compact}.substr(at + member.size()).starts_with("=true;")) {
                found.push_back(std::string{member} + " not set to exactly true");
            }
        }
    }
    return found;
}

} // namespace

TEST_CASE("the TLS scan flags each way to weaken verification", "[http]")
{
    const std::string_view planted = GENERATE(
        // Literal false or 0.
        "session.SetVerifySsl(cpr::VerifySsl{ false });", "cpr::VerifySsl(false)",
        "options.verify_peer = false;", "opts.verify_host =\n false;", "o.verify_peer = 0;",
        "cpr::ssl::VerifyPeer{false}", "cpr::ssl::VerifyHost{false}", "ssl::VerifyPeer( false )",
        // Anything but a literal true.
        "cpr::VerifySsl{insecure}", "verify_peer = allow;", "verify_host = !strict;",
        "o.verify_peer = true && strict;", "cpr::SslOptions o{.verify_peer{false}};",
        "bool& v = o.verify_host;", "o.verify_status = true;",
        // Raw curl options and flags.
        "curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);",
        "curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);", "curl_easy_setopt(h, 64, 0L);",
        "CURLOPT_SSL_OPTIONS", "CURLOPT_SSL_CTX_FUNCTION", "CURLOPT_PROXY_SSL_VERIFYPEER",
        "flags |= CURLSSLOPT_NO_REVOKE;", "CURLSSLOPT_REVOKE_BEST_EFFORT",
        // The allowed statement, changed or with more after it.
        "curl_easy_setopt(session.GetCurlHolder()->handle, CURLOPT_SSL_OPTIONS,\n"
        "    CURLSSLOPT_NATIVE_CA | CURLSSLOPT_NO_REVOKE);",
        "curl_easy_setopt(session.GetCurlHolder()->handle, CURLOPT_SSL_OPTIONS,\n"
        "    CURLSSLOPT_NATIVE_CA | CURLSSLOPT_REVOKE_BEST_EFFORT | CURLSSLOPT_NO_REVOKE);",
        "curl_easy_setopt(session.GetCurlHolder()->handle, CURLOPT_SSL_OPTIONS,\n"
        "    CURLSSLOPT_NATIVE_CA | CURLSSLOPT_REVOKE_BEST_EFFORT);\n"
        "curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);",
        "curl_easy_setopt(other->handle, CURLOPT_SSL_OPTIONS,\n"
        "    CURLSSLOPT_NATIVE_CA | CURLSSLOPT_REVOKE_BEST_EFFORT);",
        // Revocation opt-outs, context callbacks, in-memory CAs.
        "o.ssl_no_revoke = true;", "cpr::ssl::NoRevoke{true}", "o.ssl_ctx_callback = f;",
        "cpr::ssl::SslCtxCallback{f}", "CURLOPT_CAINFO_BLOB", "o.ca_info_blob = pem;",
        "cpr::ssl::CaInfoBlob{pem}", "o.ca_buffer = pem;");
    CAPTURE(planted);
    CHECK_FALSE(find_tls_disablers(planted).empty());
}

TEST_CASE("the TLS scan passes what make_ssl_options needs", "[http]")
{
    const std::string_view legitimate = GENERATE(
        "options.verify_peer = true;", "options.verify_host   =\n true ;",
        "cpr::SslOptions options;", "options.ca_info = *ca_file;", "session.SetSslOptions(ssl);",
        "curl_easy_setopt(session.GetCurlHolder()->handle, CURLOPT_SSL_OPTIONS,\n"
        "                 CURLSSLOPT_NATIVE_CA | CURLSSLOPT_REVOKE_BEST_EFFORT);",
        "// CURLOPT_CAINFO, which curl's Schannel backend reads as UTF-8");
    CAPTURE(legitimate);
    CHECK(find_tls_disablers(legitimate).empty());
}

TEST_CASE("no Worker source turns TLS verification off", "[http]")
{
    const std::filesystem::path root{RP_SOURCE_DIR};
    std::size_t scanned = 0;
    std::vector<std::string> allowed_in;
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
            CHECK(find_tls_disablers(text) == std::vector<std::string>{});
            const std::string compact_text = compact(text);
            for (std::size_t at = compact_text.find(kAllowedRevokeBestEffort);
                 at != std::string::npos;
                 at = compact_text.find(kAllowedRevokeBestEffort, at + 1)) {
                allowed_in.push_back(path.lexically_relative(root).generic_string());
            }
            ++scanned;
        }
    }
    // The scan saw the HTTP client itself, so it isn't looking in the wrong place.
    CHECK(scanned >= 10);
    CHECK(std::filesystem::exists(root / "src" / "http_client.cpp"));
    // The one raw curl call is where it belongs, and only there.
    CHECK(allowed_in == std::vector<std::string>{"src/http_client.cpp"});
}

TEST_CASE("a failed attempt is described by what went wrong", "[http]")
{
    using E = cpr::ErrorCode;
    const auto [code, text] = GENERATE(table<E, std::string_view>({
        {E::COULDNT_RESOLVE_PROXY, "could not connect"},
        {E::COULDNT_RESOLVE_HOST, "could not connect"},
        {E::COULDNT_CONNECT, "could not connect"},
        {E::NO_CONNECTION_AVAILABLE, "could not connect"},
        // After the request went out: the server may have acted on it.
        {E::SEND_ERROR, "connection dropped"},
        {E::RECV_ERROR, "connection dropped"},
        {E::GOT_NOTHING, "connection dropped"},
        {E::PARTIAL_FILE, "connection dropped"},
        {E::OPERATION_TIMEDOUT, "timed out"},
        {E::SSL_CONNECT_ERROR, "TLS handshake failed"},
        {E::PEER_FAILED_VERIFICATION, "TLS failure"},
        {E::URL_MALFORMAT, "request failed"},
        {E::UNKNOWN_ERROR, "request failed"},
    }));
    CAPTURE(static_cast<int>(code));
    CHECK(rp::detail::describe(code) == text);
}

TEST_CASE("curl's error text falls back to the error code's name when empty", "[http]")
{
    // Schannel often leaves curl's message empty (a TLS or hostname failure),
    // and "...(not retried): " with nothing after it helps no one.
    CHECK(rp::detail::error_text(cpr::Error{}) == "curl error OK");
    cpr::Error tls;
    tls.code = cpr::ErrorCode::PEER_FAILED_VERIFICATION;
    CHECK(rp::detail::error_text(tls) == "curl error PEER_FAILED_VERIFICATION");
    cpr::Error unnamed;
    unnamed.code = static_cast<cpr::ErrorCode>(999);
    CHECK(rp::detail::error_text(unnamed) == "curl error 999");
    cpr::Error with_message;
    with_message.code = cpr::ErrorCode::COULDNT_CONNECT;
    with_message.message = "Failed to connect to 127.0.0.1 port 1";
    CHECK(rp::detail::error_text(with_message) == "Failed to connect to 127.0.0.1 port 1");
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
        // Schannel's code for a connection dropped mid-handshake, as well as
        // for a protocol or cipher the two sides can't agree on. A certificate
        // verdict has codes of its own, below.
        {E::SSL_CONNECT_ERROR, T::handshake},
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
