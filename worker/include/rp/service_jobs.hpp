#pragma once

// The service's job source, read (W4.8, docs/decisions.md 2026-10-08 points 3
// and 4): the jobs document `restoreproof.jobs.v1`, a stub file whose shape is
// the Cloud's coming answer to GET /v1/jobs (W5.1).
//
//   {"format":"restoreproof.jobs.v1","jobs":[<job>, ...]}
//
// Strict JSON (a key twice in any object is refused), a closed top level, at
// most kMaxJobsFileBytes and kMaxJobs jobs. A job is a closed object:
//   run_id               required; a run ID that names a folder
//                        (job_rules::is_folder_run_id)
//   client_id            required; 1 to 128 printable ASCII characters, or null
//   sample_mail, sample_sp, sample_od
//                        required integers 0 to 100, not all 0
//   restore_point        required; `latest` or a restore point ID (--point's rule)
//   screenshots_enabled  required boolean
//   canary_cursor        optional; three integers 0 to 999999, default 0,0,0
// The rules are the ones a command line is held to (src/job_rules.hpp), not a
// copy.
//
// Whoever can write the file commands the Worker, so read_jobs reads it only
// when its owner passes the vault's rule (rp::read_trusted_file).
//
// Nothing here is logged or run: the loop (rp/service_loop.hpp) decides what
// becomes of each entry. Every word this reader hands on (a JobsFault's text,
// a JobEntry's `fault`) is one of its own; no text of the file reaches a
// message but a run_id that passed its rule.
//
// Strict (100% line): this decides which jobs run.

#include <rp/sample_selector.hpp>
#include <rp/vault.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

inline constexpr std::string_view kJobsFormat = "restoreproof.jobs.v1";
// The most the jobs file may hold: bytes, and jobs (C5.6's "max 5").
inline constexpr std::uintmax_t kMaxJobsFileBytes = 1024u * 1024u;
inline constexpr std::size_t kMaxJobs = 5;
// The longest client_id.
inline constexpr std::size_t kMaxClientIdLength = 128;
// A JobEntry's `fault` for a key the job format doesn't have.
inline constexpr std::string_view kJobUnknownKey = "unknown key";

// A job that passed every rule.
struct Job {
    std::string run_id;
    // nullopt for the document's null. Not checked against the config's
    // tenant and not written into the result until W4.11.
    std::optional<std::string> client_id;
    int sample_mail = 0;
    int sample_sp = 0;
    int sample_od = 0;
    // `latest`, in the case the document wrote it, or a restore point ID.
    std::string restore_point;
    bool screenshots_enabled = false;
    sampling::CanaryCursor canary_cursor;
};

enum class JobState {
    // J1: no run_id, one that is no string, or one failing its rule. Nothing
    // can be signed under a name the Cloud knows.
    no_run_id,
    // J3: a usable run_id and another rule broken; reported as job_invalid.
    invalid,
    // J4 (or J2, which the loop decides): every rule passed.
    valid
};

// One entry of the document's `jobs`, in its order.
struct JobEntry {
    JobState state = JobState::no_run_id;
    // Its place in the document, from 1.
    std::size_t position = 0;
    // invalid: the first key at fault, in the order client_id, sample_mail,
    // sample_sp, sample_od, restore_point, screenshots_enabled, canary_cursor
    // (three sizes that are each valid and all 0 are sample_mail's fault),
    // or kJobUnknownKey when those all pass and the job has another key.
    // Empty otherwise.
    std::string fault;
    // valid: the job. invalid: its run_id, and its client_id when that
    // passed its rule (nullopt when client_id is the key at fault); the rest
    // as a new Job has it. no_run_id: a new Job.
    Job job;
};

// Why a jobs file runs nothing.
enum class JobsFault {
    unreadable,   // there, but it can't be opened or read
    too_large,    // over kMaxJobsFileBytes
    not_json,     // not JSON, or an object with a key twice
    not_document, // not the document's shape
    too_many,     // more than kMaxJobs jobs
    not_trusted   // owned by neither SYSTEM, Administrators nor this account
};

// The fixed words of the log line for each: "can't be read", "over 1 MiB",
// "not JSON", "not a restoreproof.jobs.v1 document", "more than 5 jobs",
// "owned by neither SYSTEM, Administrators nor this account".
std::string_view to_text(JobsFault fault) noexcept;

// "jobs error: <file>: <to_text(fault)>", the file as UTF-8.
std::string jobs_error_line(const std::filesystem::path& file, JobsFault fault);

enum class JobsState {
    no_file, // nothing is at the path: no jobs and no error
    error,   // `fault` says why nothing runs
    read     // `jobs` holds the document's entries, none to five
};

struct JobsDocument {
    JobsState state = JobsState::no_file;
    // Set exactly when `state` is error.
    std::optional<JobsFault> fault;
    // Empty unless `state` is read.
    std::vector<JobEntry> jobs;
    // The SHA-256 (lower-case hex) of the bytes that were read, so the loop
    // can tell a file whose content changed; empty when no bytes were (no
    // file, unreadable, too large, not trusted).
    std::string sha256;
};

// `text` as a jobs document: `state` is read or error (not_json,
// not_document, too_many, in that order), `sha256` always set. A UTF-8 byte
// order mark before the document is taken. Pure; never throws but for no
// memory.
JobsDocument parse_jobs(std::string_view text);

// How the file is read: rp::read_trusted_file's signature.
using JobsFileReader =
    std::function<TrustedFile(const std::filesystem::path& file, std::uintmax_t max_bytes)>;

// Reads `file` whole through `read` (null: rp::read_trusted_file, so only a
// file whose owner passes the vault's rule), at most kMaxJobsFileBytes, and
// parses it. absent is no_file; unreadable, not_trusted and too_large are
// their faults, nothing parsed.
JobsDocument read_jobs(const std::filesystem::path& file, const JobsFileReader& read = {});

} // namespace rp
