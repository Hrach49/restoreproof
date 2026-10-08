#pragma once

// What the service knows of the one run it has taken (W4.8, docs/decisions.md
// 2026-10-08 points 6 to 9): running.json, written ahead of everything a run
// does; the plan for a run whose folder was left without a result; the rule
// for the backup product's sessions after one; and when the record goes.
// Decided logic only: every file, every call of the backup product and every
// signature is reached through a function this is handed (RecordFiles,
// CloseRunCalls), so each branch is a row a fake drives.
//
// Strict (100% line), by its name.

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/outbox.hpp>
#include <rp/restore_command.hpp>
#include <rp/result_builder.hpp>
#include <rp/run_status.hpp>
#include <rp/vault.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace rp {

struct PipelineReport; // src/run_pipeline.hpp

inline constexpr std::string_view kRunningFormat = "restoreproof.running.v1";
inline constexpr std::string_view kRunningFileName = "running.json";
// What a record the service can't trust or read is moved aside as.
inline constexpr std::string_view kRunningUnreadName = "running.json.unread";
// A record is never larger: one that would be isn't written, and a file that
// is isn't a record.
inline constexpr std::uintmax_t kMaxRecordBytes = 64u * 1024u;
// How long after the last restore request, or after this process began the
// hold when that is later, the run's own sessions are left running (point 9:
// twice the request's timeout, for a restore the product hadn't listed yet).
inline constexpr std::chrono::seconds kHoldWait{120};

// A record's time, as the result writes its own: UTC to the millisecond,
// "YYYY-MM-DDTHH:MM:SS.mmmZ", cut and not rounded.
std::string record_time_text(std::chrono::system_clock::time_point time);

// That text read back, or nothing for any other shape and for a date or a
// time of day that doesn't exist.
std::optional<std::chrono::system_clock::time_point> record_time(std::string_view text) noexcept;

enum class RecordKind {
    run,        // a job being run
    job_invalid // a job that is no job (point 4, J3): only reported
};

// What the run's folder is to be closed as when it has no result.json; a
// record without one is of a run the process ended during: interrupted.
enum class CloseAs { result_invalid, internal, job_invalid };

// "run" or "job_invalid"; "result_invalid", "internal" or "job_invalid".
std::string_view to_string(RecordKind kind) noexcept;
std::string_view to_string(CloseAs close_as) noexcept;

struct RecordRestorePoint {
    std::string id;
    std::string backup_time_raw; // the backup product's own text

    bool operator==(const RecordRestorePoint&) const = default;
};

// running.json (point 6): IDs, times and fixed words, never a secret or an
// item's name. Exactly these keys and `format`, fourteen, in the file under these names.
struct RunningRecord {
    // The result's client object as the config gives it (its client_id null).
    ResultClient client;
    // The job's client_id: the record's and the log's alone until W4.11.
    std::optional<std::string> client_id;
    std::optional<CloseAs> close_as;
    // With close_as: `internal`, the run folder's word (not_written, changed,
    // holds_secret, not_signed, invalid); `job_invalid`, the jobs reader's
    // word for the key at fault; `result_invalid`, how the run itself had
    // ended (ended_detail), or nothing when that isn't known. Without
    // close_as: nothing. And one more word, written by
    // with_changed_text_files after a close that itself found a text file
    // changed: `changed` without close_as and for `internal`, and
    // "<ending>; changed" for `result_invalid`.
    std::optional<std::string> close_detail;
    // {type, api}, once the run line is out.
    std::optional<connector::ConnectorInfo> connector;
    RecordKind kind = RecordKind::run;
    std::optional<RecordRestorePoint> restore_point; // once the run line is out
    // False is a promise that no restore request went out; true means one may
    // have, whether or not the backup product took it.
    bool restore_requested = false;
    std::optional<std::string> restore_requested_at; // the last request's time
    std::string run_id;
    // The sessions the run opened in the backup product and is to close
    // itself, in the order they were opened.
    std::vector<std::string> sessions;
    std::optional<std::string> started_at; // the result's started_at
    std::string taken_at;

    bool operator==(const RunningRecord&) const;
};

// Write (a) of point 6, before the pipeline is called: the run, the job's
// client_id, the config's client and the time; everything else null, empty
// or false.
RunningRecord new_run_record(std::string_view run_id, std::optional<std::string> client_id,
                             const Config& config,
                             std::chrono::system_clock::time_point taken_at);

// The same for a job that is no job, before its folder is made: kind
// job_invalid, and from the first write close_as job_invalid with `key`, the
// jobs reader's word for the key at fault, so that a close cut short by a
// kill still knows why.
RunningRecord new_job_invalid_record(std::string_view run_id,
                                     std::optional<std::string> client_id, const Config& config,
                                     std::chrono::system_clock::time_point taken_at,
                                     std::string_view key);

// Write (b), right after the run line: started_at, the restore point and the
// connector.
RunningRecord with_run_started(RunningRecord record, const RunStarted& started);

// Write (c), at every session the run opens and is to close itself: `id`
// added to sessions, once.
RunningRecord with_session(RunningRecord record, std::string_view id);

// Write (d), before every restore request: restore_requested true and the
// time of this one.
RunningRecord with_restore_request(RunningRecord record,
                                   std::chrono::system_clock::time_point time);

// Write (e), after a run that left its folder without a result.
RunningRecord with_close(RunningRecord record, CloseAs close_as,
                         std::optional<std::string> detail);

// After a close that itself answered `changed` (a text file altered between
// its hash and the read back): the record says so, so that the next try
// replaces both text files by their empty forms, and the code the run is
// closed with stays what it was. Without close_as, and for `internal`,
// close_detail becomes `changed`; for `result_invalid` the ending gets
// "; changed" after it ("error" standing for an ending that isn't known);
// a job_invalid record is unchanged (its text files are always replaced).
// Applied twice it gives the same record.
RunningRecord with_changed_text_files(RunningRecord record);

// close_detail for close_as result_invalid: how the run itself had ended,
// "pass", "fail", "error <code>" for a code of verification::error_codes(),
// else "error" (PipelineReport's replaced_status and replaced_code).
std::string ended_detail(verification::RunStatus status, std::string_view code);

// The record in canonical-json-v1. Throws CanonicalJsonError for a string
// that isn't UTF-8.
std::string record_text(const RunningRecord& record);

// Strict: `text` must be its own canonical form, nested no deeper than
// kMaxJsonNesting (a record has three levels; a deeper text is never parsed),
// and hold exactly the fourteen keys with their kinds and words, or it is not
// a restoreproof.running.v1 record (nullopt). The words: `format`; `kind`;
// `run_id` a run ID that can name a folder; `client` the result's client
// object within the schema's lengths, its client_id null; `client_id` null
// or 1 to 128 printable ASCII characters; `close_as` null or its three
// words, job_invalid exactly when `kind` is; `close_detail` as RunningRecord
// says (so null or `changed` without close_as); `connector` null or {type "veeam_m365", api at most 64 bytes};
// `restore_point` null or two strings of at most 1024 bytes;
// `restore_requested_at` a time exactly when restore_requested is true;
// `sessions` strings of 1 to 128 printable ASCII characters; `started_at`
// null or a time; `taken_at` a time. So a record that reads gives a result
// the schema takes. Never throws but for no memory.
std::optional<RunningRecord> parse_record(std::string_view text);

// The file calls of the record; each must be set.
struct RecordFiles {
    // rp::read_trusted_file: whole, and only when its owner passes the
    // vault's rule.
    std::function<TrustedFile(const std::filesystem::path&, std::uintmax_t max_bytes)> read;
    // The atomic writer, replacing; makes the record's folder when it isn't
    // there. Whether the file now holds the text.
    std::function<bool(const std::filesystem::path&, std::string_view text)> write;
    // Whether nothing is at the path afterwards.
    std::function<bool(const std::filesystem::path&)> erase;
    // Moves `from` to `to`, replacing what is there; whether it did.
    std::function<bool(const std::filesystem::path& from, const std::filesystem::path& to)>
        move_aside;
};

enum class RecordState {
    none,        // no file: no run is taken
    record,      // read, and a record
    not_trusted, // owned by neither SYSTEM, Administrators nor this account
    not_record,  // read (or over kMaxRecordBytes) and not a record
    unreadable   // there, and it can't be read
};

struct RecordRead {
    RecordState state = RecordState::none;
    std::optional<RunningRecord> record; // with `record` only
};

class RecordStore {
public:
    // `file` is <state folder>\running.json.
    RecordStore(std::filesystem::path file, RecordFiles files);

    RecordRead read() const;

    // False, and nothing written, for a record that has no canonical form,
    // is over kMaxRecordBytes or wouldn't read back as a record; else the
    // writer's answer.
    bool write(const RunningRecord& record) const;

    bool erase() const;

    // The file moved to running.json.unread beside it, replacing an older
    // one.
    bool move_aside() const;

    const std::filesystem::path& file() const noexcept { return file_; }
    std::filesystem::path unread_file() const;

private:
    std::filesystem::path file_;
    RecordFiles files_;
};

// What the run's folder under the runs root holds.
struct FolderContents {
    bool exists = false;
    bool result = false;      // result.json: the folder is complete
    bool items_csv = false;
    bool session_log = false;
    bool signature = false;   // signature.json
    bool timestamp = false;   // timestamp.tst
    bool screenshot = false;  // screenshot.png
    bool temp_files = false;  // any "<name>.<16 hex>.tmp"
    // Of a file that is there: its owner is neither SYSTEM, Administrators
    // nor this account (rp::check_trusted_owner answering not_trusted). The
    // runs root has the inherited ACL until W7.1, so a local user can put a
    // file there; the service acts on no such file's word.
    bool result_untrusted = false;
    bool signature_untrusted = false;
    bool items_csv_untrusted = false;
    bool session_log_untrusted = false;
};

enum class CloseAction {
    queue_only, // the folder has its result.json: nothing is signed twice
    close,      // the result is written afterwards
    refuse      // the folder has a result.json, and that or its signature.json
                // is of an owner the service doesn't trust: not queued
};

// What closing the record's run means (point 7). Everything after `action`
// is for `close` alone.
struct ClosePlan {
    CloseAction action = CloseAction::close;
    std::string run_id;
    // The folder isn't there: a kill before the pipeline made it, or a job
    // that is no job.
    bool make_folder = false;
    // What is taken away first, of signature.json, timestamp.tst and
    // screenshot.png, the ones that are there; and whether the atomic
    // writer's temp files are.
    std::vector<std::string> remove;
    bool remove_temp_files = false;
    // items.csv and veeam-session.log: kept as they are (one that isn't
    // there written in its empty form), or both replaced by their empty
    // forms: when the run, or an earlier close, had found one changed after
    // it hashed it, and always for a job that is no job.
    bool replace_text_files = false;
    // One of the two text files is there and of an owner the service doesn't
    // trust: both are replaced, and the log says so.
    bool untrusted_text_files = false;
    // interrupted without close_as, else close_as.
    std::string code;
    // Status error with `code`, restore_sent the record's restore_requested
    // (never for job_invalid), every count 0.
    verification::RunVerdict verdict;
    // The result's facts: what the record knows, else the connector
    // "veeam_m365" with an empty api and the empty restore point.
    std::optional<std::string> started_at;
    connector::ConnectorInfo connector;
    std::string restore_point_id;
    std::string restore_point_time;
    ResultClient client;

    // Whether anything is to be taken away.
    bool removes() const noexcept { return !remove.empty() || remove_temp_files; }
};

ClosePlan plan_close(const RunningRecord& record, const FolderContents& folder);

// W4.2's rule for a run without a restore session to show: `disabled`, or
// `no_page` with screenshots on (EvidenceBuilder::adopt_attachments gives the
// same).
Screenshot close_screenshot(bool screenshots_enabled) noexcept;

// The result of a `close` plan through rp::ResultBuilder: this Worker's
// version, the plan's facts and verdict, `evidence`'s attachments and
// screenshot; ended_at, sample, expected, restore, check and cleanup null,
// every span null.
std::variant<BuiltResult, ResultError> build_close_result(const ClosePlan& plan,
                                                          const Evidence& evidence);

// What became of a folder (the shared tail's RunFolderOutcome, less `none`).
enum class FolderEnd {
    incomplete, // no result.json; `word` why
    complete,   // result.json written, not in the outbox; `word` the outbox's
    queued      // under <outbox root>\outbox
};

struct FolderOutcome {
    FolderEnd state = FolderEnd::incomplete;
    std::string word;
};

// The real calls of a close, each on the folder the record names and no
// other; each must be set.
struct CloseRunCalls {
    std::function<FolderContents()> look;
    // Makes the folder; whether it is there.
    std::function<bool()> make_folder;
    // EvidenceBuilder::remove_unfinished.
    std::function<bool()> remove_unfinished;
    // The signing key read from the vault, then the shared tail
    // (rp::finish_run_folder) with EvidenceBuilder::adopt_attachments(
    // replace_text_files) and `result` as its result. No vault, or no key in
    // it: incomplete, "vault".
    std::function<FolderOutcome(
        bool replace_text_files,
        const std::function<std::optional<std::string>(const Evidence&)>& result)>
        finish;
    // rp::Outbox::queue for a folder that has its result.json.
    std::function<FolderOutcome()> queue;
};

enum class CloseRunState {
    queued,     // in the outbox
    not_closed, // no result.json: `word` is vault, not_signed, not_written,
                // holds_secret, changed or invalid; or one the service
                // doesn't trust: `untrusted`
    not_queued  // complete and not in the outbox: `word` is the outbox's
};

struct CloseRunOutcome {
    CloseRunState state = CloseRunState::not_closed;
    std::string word;
    // The close met a text file of an owner the service doesn't trust and
    // replaced both by their empty forms (the plan's untrusted_text_files),
    // whatever became of the folder afterwards.
    bool untrusted_text_files = false;
};

// Point 7's order: a folder with a result.json is only queued, or, when the
// result.json or its signature.json is of an owner the service doesn't
// trust, left as it is (not_closed, "untrusted"); one that
// isn't there is made; what a signing that didn't finish left is taken
// away; then the tail. A folder that can't be made, and one whose leftovers
// can't be taken away, is not_closed "not_written".
CloseRunOutcome close_run(const RunningRecord& record, const CloseRunCalls& calls);

// Whether a record needs the hold at all when nothing more is known of its
// run than the record: a restore may have been requested, or sessions were
// opened that nobody may have closed (point 8, b).
bool needs_hold(const RunningRecord& record) noexcept;

enum class HoldStep {
    over, // nothing of the run is running any more
    end,  // end these sessions, then look again
    wait  // not yet
};

struct HoldDecision {
    HoldStep step = HoldStep::wait;
    // `end`: the recorded sessions still running, in the look's order.
    std::vector<std::string> end;
    // The sessions still running that the record doesn't list, and the
    // oldest one's creation time: with `wait`, what the warning names.
    std::size_t others = 0;
    std::optional<std::chrono::system_clock::time_point> others_since;
    // `over` after a restore request: the restore targets are to be cleaned
    // once, the clean after the run never made.
    bool clean_due = false;
};

// Point 9's rule for one look. `running` is the connector's own_sessions
// since the record's taken_at; `hold_began` is when this process began the
// hold. Without a restore request each recorded session still running is
// ended at once and the others are not counted against the run. After one:
// while any other session runs, wait; when none does, the recorded ones are
// ended once kHoldWait has passed since the later of restore_requested_at
// and `hold_began`. Over when no recorded session runs and, after a restore
// request, no other does.
HoldDecision decide_hold(const RunningRecord& record,
                         const std::vector<connector::OwnSession>& running,
                         std::chrono::system_clock::time_point now,
                         std::chrono::system_clock::time_point hold_began);

// Whether the config's client is the record's: only then are the restore
// targets cleaned for the record's run.
bool is_records_client(const Config& config, const RunningRecord& record);

// Whether the record goes (point 6): the run's folder is in the outbox or
// under sent\, or the run ended before its run line and has none; and no
// restore of it may still be running. `report` is the pipeline's, of the run
// when it ended in this process, else null (a record found at start); with
// one, the run closed its own sessions, and a restore may still run only
// when the report says so and the record says one was requested; without
// one, whenever needs_hold. `hold_done` is the hold of point 9 over.
bool record_may_go(const RunningRecord& record, OutboxHolds holds, const PipelineReport* report,
                   bool hold_done) noexcept;

} // namespace rp
