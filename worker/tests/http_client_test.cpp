// W1.3: the HTTP client. Everything here talks to 127.0.0.1 only, and no test
// really sleeps for backoff: the waits are recorded instead.

#include "local_http_server.hpp" // first: httplib needs winsock2.h before windows.h

#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
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
