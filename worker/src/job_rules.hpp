#pragma once

// What makes a run's request well-formed, as pure functions: the rules
// `rpworker restore` and `rpworker test` hold a command line to
// (parse_pipeline_args, run_pipeline) and the service's jobs reader holds a
// job to (docs/decisions.md 2026-10-08, W4.8 point 3), so that both call one
// rule and neither keeps a copy.

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace rp::job_rules {

// The most items of one type a run samples.
inline constexpr int kMaxSampleSize = 100;
// A canary cursor's largest value: six decimal digits.
inline constexpr std::int64_t kMaxCursor = 999999;
inline constexpr std::size_t kMaxPointIdLength = 128;
// The newest restore point, in any ASCII case.
inline constexpr std::string_view kLatest = "latest";

// A sample size: 0 to kMaxSampleSize.
bool is_sample_size(std::int64_t n) noexcept;

// Whether the three sizes ask for nothing: a run that would restore nothing
// is no run.
bool is_empty_sample(std::int64_t mail, std::int64_t sharepoint, std::int64_t onedrive) noexcept;

// --point's rule: 1 to kMaxPointIdLength ASCII letters, digits and hyphens,
// so safe to echo in a message. `latest`, in any case, is one too.
bool is_point(std::string_view text) noexcept;

// One number of a canary cursor: 0 to kMaxCursor.
bool is_cursor_value(std::int64_t n) noexcept;

// --run-id's rule (sampling::check_run_id): 1 to 128 bytes of A-Z a-z 0-9
// . _ : -.
bool is_run_id(std::string_view text);

// A run ID that also names the run's folder (W4.2 point 8, W4.8 point 3):
// is_run_id and a plain file name (rp::is_plain_file_name: no ':', no
// trailing '.', not "." or "..", not a DOS device's name). What --evidence
// holds a --run-id to, and the jobs reader a job's run_id.
bool is_folder_run_id(std::string_view text);

} // namespace rp::job_rules
