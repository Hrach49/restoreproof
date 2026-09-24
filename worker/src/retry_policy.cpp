#include <rp/retry_policy.hpp>

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
    // A dropped connection or a timeout can be transient. A bad certificate or
    // a malformed URL won't fix itself between tries.
    return outcome.error == TransportError::connect || outcome.error == TransportError::timeout;
}

bool should_retry(const AttemptOutcome& outcome, int attempt) noexcept
{
    return is_retryable(outcome) && attempt < kMaxHttpAttempts;
}

std::chrono::milliseconds retry_delay(int, double) noexcept
{
    return std::chrono::milliseconds{0};
}

} // namespace rp
