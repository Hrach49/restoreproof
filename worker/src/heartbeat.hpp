#pragma once

// The service's heartbeat (W4.8, docs/decisions.md 2026-10-08 point 11): one
// POST <cloud_url>/v1/heartbeat, Content-Type application/json, the body
// canonical-json-v1 with exactly five keys:
//
//   {"last_error": <word> | null, "last_error_at": <time> | null,
//    "outbox_depth": <n>, "uptime_s": <n>, "version": "<rpworker's>"}
//
// C5.8's body plus the time. The endpoint is a stub until W5.1: no
// Authorization header and no other credential is sent. Nothing is decided
// here but which word an answer is; when a heartbeat is due, what its fields
// are and what is logged for a failed one is the loop's (rp/service_loop.hpp).
// Not strict: the one HTTP call, as src/uploader.cpp is.

#include <rp/http_client.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace rp {

inline constexpr std::string_view kHeartbeatPath = "/v1/heartbeat";
// The whole request: connect, send and the answer.
inline constexpr std::chrono::milliseconds kHeartbeatTimeout{10000};
// The most that is read of the answer's body.
inline constexpr std::uint64_t kMaxHeartbeatAnswerBytes = 64u * 1024u;

// What a failed heartbeat is, beside http_<status>.
namespace heartbeat_code {
inline constexpr std::string_view kHttpPrefix = "http_"; // then the status, three digits
inline constexpr std::string_view kUnreachable = "unreachable";
inline constexpr std::string_view kTimeout = "timeout";
inline constexpr std::string_view kInternal = "internal";
} // namespace heartbeat_code

struct Heartbeat {
    // rp::version().
    std::string version;
    // One of rp::service_error_codes()' words (rp/service_errors.hpp), or
    // nullopt for none since the service started. Sent as it is given.
    std::optional<std::string> last_error;
    // When that was; nullopt beside no error.
    std::optional<std::chrono::system_clock::time_point> last_error_at;
    // The runs under outbox\, the ones that can't be sent included.
    std::uint64_t outbox_depth = 0;
    // Whole seconds since the service started.
    std::uint64_t uptime_s = 0;
};

// A heartbeat's time, as the result writes its own: UTC to the millisecond,
// "YYYY-MM-DDTHH:MM:SS.mmmZ".
std::string heartbeat_time_text(std::chrono::system_clock::time_point time);

// The body: `heartbeat` as canonical-json-v1, an absent last_error or
// last_error_at as null. Throws rp::CanonicalJsonError for what the form
// refuses (a count past 2^53 - 1, a text that isn't UTF-8).
std::string heartbeat_body(const Heartbeat& heartbeat);

struct HeartbeatAnswer {
    bool ok = false;
    // Empty when ok; else http_<status>, unreachable, timeout or internal.
    std::string error;
};

// POST <cloud_url>/v1/heartbeat (a '/' at the URL's end dropped) with
// heartbeat_body, sent once (max_attempts 1, no retry on a status: the next
// interval is the retry), kHeartbeatTimeout. Any 2xx is ok. Else:
// http_<status> for any other answer (three digits; a status outside 100 to
// 999 is internal), timeout for a timeout, unreachable for no connection, a
// broken-off or failed TLS handshake, a certificate the client refuses or a
// connection dropped mid-request, internal for anything else, a body that
// has no canonical form included (nothing is sent then). Never throws but
// for no memory.
HeartbeatAnswer send_heartbeat(IHttpClient& http, std::string_view cloud_url,
                               const Heartbeat& heartbeat);

} // namespace rp
