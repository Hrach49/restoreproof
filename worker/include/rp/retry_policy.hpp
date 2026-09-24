#pragma once

#include <chrono>

namespace rp {

// How one HTTP attempt ended when no response came back.
enum class TransportError {
    none,    // a response arrived: see the status
    connect, // couldn't resolve or connect, or the connection dropped before a response
    timeout, // the per-request timeout expired
    tls,     // TLS handshake or certificate verification failed
    other,   // anything else (malformed URL, local failure)
};

struct AttemptOutcome {
    TransportError error = TransportError::none;
    int status = 0; // the HTTP status when error == none
};

// Attempts per request, the first included: 1 + 4 retries. W1.3's "Done when"
// says "retries five times"; it is read as five attempts in total
// (docs/decisions.md).
inline constexpr int kMaxHttpAttempts = 5;
inline constexpr std::chrono::milliseconds kFirstRetryDelay{1000};
inline constexpr std::chrono::milliseconds kMaxRetryDelay{16000};

// Worth another attempt: connect and timeout errors, and HTTP 500-599. Never
// 4xx (or any non-5xx status), tls or other.
bool is_retryable(const AttemptOutcome& outcome) noexcept;

// Whether to make another attempt after attempt number `attempt` (1-based)
// ended with `outcome`: is_retryable() and attempt < kMaxHttpAttempts.
bool should_retry(const AttemptOutcome& outcome, int attempt) noexcept;

// The wait before retry number `retry` (1-based: retry 1 is the wait between
// attempts 1 and 2). Nominal delay min(1 s * 2^(retry - 1), 16 s), reduced by
// jitter: nominal * (1 - 0.25 * jitter), with jitter clamped to [0, 1]. So with
// jitter 0: 1, 2, 4, 8 s, then 16 s for every later retry; never above 16 s,
// never below 75% of nominal. `retry` below 1 is treated as 1.
// Computed in whole milliseconds: nominal_ms - round(nominal_ms * 0.25 * jitter),
// halves rounded away from zero, so jitter 0.5 on retry 1 is exactly 875 ms. A
// NaN jitter counts as 0. The caller draws the jitter (uniform in [0, 1]) and
// does the waiting, so this stays a pure function tests call without sleeping.
std::chrono::milliseconds retry_delay(int retry, double jitter) noexcept;

} // namespace rp
