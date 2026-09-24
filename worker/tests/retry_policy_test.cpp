#include <rp/retry_policy.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace {

using rp::AttemptOutcome;
using rp::TransportError;

AttemptOutcome transport_error(TransportError error)
{
    return AttemptOutcome{error, 0};
}

AttemptOutcome http_status(int status)
{
    return AttemptOutcome{TransportError::none, status};
}

} // namespace

// Five attempts in total, not 1 + 5: the owner's reading of "retries five
// times" in W1.3's "Done when" (docs/decisions.md).
static_assert(rp::kMaxHttpAttempts == 5);

TEST_CASE("a request is made at most five times in total", "[retry]")
{
    REQUIRE(rp::kMaxHttpAttempts == 5);
}

TEST_CASE("is_retryable retries connection errors, timeouts and failed handshakes but never tls "
          "or other errors",
          "[retry]")
{
    const auto [error, expected] = GENERATE(table<TransportError, bool>({
        {TransportError::connect, true},
        {TransportError::timeout, true},
        {TransportError::handshake, true},
        {TransportError::tls, false},
        {TransportError::other, false},
    }));
    CAPTURE(static_cast<int>(error));

    REQUIRE(rp::is_retryable(transport_error(error)) == expected);
}

TEST_CASE("is_retryable retries HTTP 5xx and no other status", "[retry]")
{
    const auto [status, expected] = GENERATE(table<int, bool>({
        {0, false},   {100, false}, {200, false}, {204, false}, {301, false},
        {304, false}, {400, false}, {401, false}, {403, false}, {404, false},
        {408, false}, {409, false}, {429, false}, {499, false}, {500, true},
        {502, true},  {503, true},  {504, true},  {599, true},  {600, false},
    }));
    CAPTURE(status);

    REQUIRE(rp::is_retryable(http_status(status)) == expected);
}

TEST_CASE("should_retry never retries a non-retryable outcome", "[retry]")
{
    const AttemptOutcome outcome = GENERATE(http_status(404), http_status(200),
                                            transport_error(TransportError::tls));
    const int attempt = GENERATE(1, 2, 4);
    CAPTURE(outcome.status, static_cast<int>(outcome.error), attempt);

    REQUIRE_FALSE(rp::should_retry(outcome, attempt));
}

TEST_CASE("should_retry stops a retryable outcome after the fifth attempt", "[retry]")
{
    const AttemptOutcome outcome = GENERATE(transport_error(TransportError::connect),
                                            transport_error(TransportError::timeout),
                                            transport_error(TransportError::handshake),
                                            http_status(503));
    const auto [attempt, expected] = GENERATE(table<int, bool>({
        {1, true},
        {2, true},
        {3, true},
        {4, true},
        {5, false},
        {6, false},
        {100, false},
    }));
    CAPTURE(outcome.status, static_cast<int>(outcome.error), attempt);

    REQUIRE(rp::should_retry(outcome, attempt) == expected);
}

namespace {

struct Run {
    int attempts = 0;
    std::vector<std::int64_t> delays_ms;
};

// What HttpClient's loop does with a request whose every attempt ends with
// `outcome`, minus the sleeping: the attempts made and the waits between them.
Run run_always(const AttemptOutcome& outcome)
{
    Run run;
    int attempt = 1;
    while (rp::should_retry(outcome, attempt)) {
        run.delays_ms.push_back(rp::retry_delay(attempt, 0.0).count());
        ++attempt;
    }
    run.attempts = attempt;
    return run;
}

} // namespace

TEST_CASE("a request that always fails to connect is tried five times, 1, 2, 4 and 8 s apart",
          "[retry]")
{
    const Run run = run_always(transport_error(TransportError::connect));

    REQUIRE(run.attempts == 5);
    REQUIRE(run.delays_ms == std::vector<std::int64_t>{1000, 2000, 4000, 8000});
}

TEST_CASE("a request that always gets 503 is tried five times, 1, 2, 4 and 8 s apart", "[retry]")
{
    const Run run = run_always(http_status(503));

    REQUIRE(run.attempts == 5);
    REQUIRE(run.delays_ms == std::vector<std::int64_t>{1000, 2000, 4000, 8000});
}

TEST_CASE("a request that gets 404 is tried once, with no wait", "[retry]")
{
    const Run run = run_always(http_status(404));

    REQUIRE(run.attempts == 1);
    REQUIRE(run.delays_ms.empty());
}

TEST_CASE("retry_delay doubles from 1 s and stays at the 16 s cap", "[retry]")
{
    const auto [retry, expected_ms] = GENERATE(table<int, std::int64_t>({
        {1, 1000},
        {2, 2000},
        {3, 4000},
        {4, 8000},
        {5, 16000},
        {6, 16000},
        {7, 16000},
        {8, 16000},
    }));
    CAPTURE(retry);

    REQUIRE(rp::retry_delay(retry, 0.0).count() == expected_ms);
}

TEST_CASE("retry_delay treats a retry number below 1 as the first retry", "[retry]")
{
    const int retry = GENERATE(0, -5, std::numeric_limits<int>::min());
    CAPTURE(retry);

    REQUIRE(rp::retry_delay(retry, 0.0) == rp::kFirstRetryDelay);
}

TEST_CASE("retry_delay never goes above 16 s, however high the retry number", "[retry]")
{
    // A shift by retry - 1 would overflow long before INT_MAX.
    const int retry = GENERATE(31, 32, 33, 63, 64, 65, 1000, std::numeric_limits<int>::max());
    CAPTURE(retry);

    REQUIRE(rp::retry_delay(retry, 0.0) == rp::kMaxRetryDelay);
}

TEST_CASE("retry_delay takes up to a quarter off the nominal delay for jitter", "[retry]")
{
    // Out-of-range jitter is clamped, and NaN counts as none: a bad random
    // source must never stretch the wait past the cap or shrink it to nothing.
    const auto [jitter, expected_ms] = GENERATE(table<double, std::int64_t>({
        {0.0, 1000},
        {0.5, 875},
        {1.0, 750},
        {0.25, 937},   // 62.5 ms off, rounded away from zero to 63
        {0.001, 1000}, // 0.25 ms off rounds to nothing
        {-1.0, 1000},
        {-std::numeric_limits<double>::infinity(), 1000},
        {2.0, 750},
        {std::numeric_limits<double>::infinity(), 750},
        {std::numeric_limits<double>::quiet_NaN(), 1000},
    }));
    CAPTURE(jitter);

    REQUIRE(rp::retry_delay(1, jitter).count() == expected_ms);
}

TEST_CASE("retry_delay applies jitter to the 16 s cap and never exceeds it", "[retry]")
{
    const auto [jitter, expected_ms] = GENERATE(table<double, std::int64_t>({
        {0.0, 16000},
        {0.5, 14000},
        {1.0, 12000},
        {-1.0, 16000},
        {2.0, 12000},
        {std::numeric_limits<double>::quiet_NaN(), 16000},
    }));
    const int retry = GENERATE(5, std::numeric_limits<int>::max());
    CAPTURE(jitter, retry);

    const std::chrono::milliseconds delay = rp::retry_delay(retry, jitter);
    REQUIRE(delay.count() == expected_ms);
    REQUIRE(delay <= rp::kMaxRetryDelay);
}
