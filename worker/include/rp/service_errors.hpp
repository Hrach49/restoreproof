#pragma once

// The words a heartbeat's `last_error` may be (W4.8, docs/decisions.md
// 2026-10-08 point 11): the latest of the service loop's own troubles since
// the service started. Never a run's own error code (the result carries
// that), never what(), never a path or a name.
//
// Strict (100% line), by its name.

#include <span>
#include <string_view>

namespace rp {

namespace service_error {
inline constexpr std::string_view kJobsUnreadable = "jobs_unreadable";
inline constexpr std::string_view kJobInvalid = "job_invalid";
inline constexpr std::string_view kJobNotStarted = "job_not_started";
inline constexpr std::string_view kRecordNotWritten = "record_not_written";
inline constexpr std::string_view kRecordNotRemoved = "record_not_removed";
inline constexpr std::string_view kRecordUnreadable = "record_unreadable";
inline constexpr std::string_view kRunNotClosed = "run_not_closed";
inline constexpr std::string_view kRunNotQueued = "run_not_queued";
// The outbox's two: a run that is never sent, and one that couldn't be read
// at this pass (upload_code::kFolderChanged, kFlushNotRead).
inline constexpr std::string_view kFolderChanged = "folder_changed";
inline constexpr std::string_view kNotRead = "not_read";
inline constexpr std::string_view kVeeamLookFailed = "veeam_look_failed";
inline constexpr std::string_view kVeeamSessionsWorking = "veeam_sessions_working";
inline constexpr std::string_view kRecoveryCleanIncomplete = "recovery_clean_incomplete";
} // namespace service_error

// The fixed words, in the entry's order: the thirteen above, then the
// outbox's upload words that are fixed (upload_unreachable, upload_timeout,
// upload_internal). upload_http_<status> is one too, by its pattern, and so
// not in the list.
std::span<const std::string_view> service_error_codes() noexcept;

// Whether `word` may be a heartbeat's last_error: one of
// service_error_codes(), or upload_http_ and three digits.
bool is_service_error(std::string_view word) noexcept;

} // namespace rp
