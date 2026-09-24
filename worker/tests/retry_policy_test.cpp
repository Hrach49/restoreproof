#include <rp/retry_policy.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <utility>

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

TEST_CASE("is_retryable retries connection errors and timeouts but never tls or other errors",
          "[retry]")
{
    const auto [error, expected] = GENERATE(table<TransportError, bool>({
        {TransportError::connect, true},
        {TransportError::timeout, true},
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
