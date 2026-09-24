#include <rp/retry_policy.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>

namespace rp {

bool is_retryable(const AttemptOutcome& outcome) noexcept
{
    if (outcome.error == TransportError::none) {
        // Only a server-side failure may go away on its own. 4xx means the
        // request itself is wrong or not allowed, so sending it again changes
        // nothing; that includes 408 and 429 (W1.3: never retry 4xx). Anything
        // outside 500-599 isn't a server failure either.
        return outcome.status >= 500 && outcome.status <= 599;
    }
    // A dropped connection, a timeout or a broken-off handshake can be
    // transient. A bad certificate or a malformed URL won't fix itself between
    // tries.
    return outcome.error == TransportError::connect || outcome.error == TransportError::timeout ||
           outcome.error == TransportError::handshake;
}

bool should_retry(const AttemptOutcome& outcome, int attempt) noexcept
{
    return is_retryable(outcome) && attempt < kMaxHttpAttempts;
}

std::chrono::milliseconds retry_delay(int retry, double jitter) noexcept
{
    // Retry 5 already reaches the cap (1 s * 2^4 = 16 s). Capping the exponent
    // before shifting keeps a huge `retry` from overflowing; flooring it at 0
    // makes retry < 1 the first retry.
    constexpr int kMaxExponent = 4;
    static_assert((kFirstRetryDelay * (1 << kMaxExponent)) == kMaxRetryDelay);
    const int exponent = std::clamp(retry, 1, kMaxExponent + 1) - 1;
    const std::int64_t nominal_ms = kFirstRetryDelay.count() << exponent;

    // NaN fails every comparison, so std::clamp would pass it through: count
    // it as no jitter. Infinities clamp like any other out-of-range value.
    const double clamped = std::isnan(jitter) ? 0.0 : std::clamp(jitter, 0.0, 1.0);
    // At most nominal_ms / 4, so the result stays within [75%, 100%] of nominal.
    const std::int64_t reduction_ms =
        std::llround(static_cast<double>(nominal_ms) * 0.25 * clamped);
    return std::chrono::milliseconds{nominal_ms - reduction_ms};
}

} // namespace rp
