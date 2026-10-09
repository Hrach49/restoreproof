#pragma once

// The status decision table (W3.3; docs/decisions.md 2026-10-01, W3.3;
// docs/verification.md, "The status decision table"): what a run produced,
// turned into one status, pass, fail or error. Pure: it never calls the backup
// product or Graph. The check is the evidence; the backup product's own
// account is only a warning or an infrastructure excuse, so neither an
// unclean target nor an unreachable service becomes `fail`, and a "restored
// successfully" that wrote nothing can't become `pass`.

#include <rp/checker.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/sample_selector.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::verification {

// pass: the restore ran and every sampled item verified; fail: the backup
// didn't deliver an item (missing or mismatched, its target read fine, not
// blamed on infrastructure); error: the test couldn't tell.
enum class RunStatus { pass, fail, error };

// "pass", "fail" or "error"; "unknown" for a value outside the enum.
std::string_view to_string(RunStatus status) noexcept;

// Where a run stopped:
//  - before_restore: the sample, the expected set, the before snapshot;
//  - restore: restore_sample threw;
//  - check: the read-back or the check threw something that isn't Graph's
//    (Graph's per-type failures are already item errors in the CheckResult).
enum class RunPhase { before_restore, restore, check };

// "before_restore", "restore" or "check"; "unknown" for a value outside the enum.
std::string_view to_string(RunPhase phase) noexcept;

// What stopped a run. Never the exception's what(), which may name a tenant
// value: the command prints that on stderr itself.
struct RunStop {
    RunPhase phase = RunPhase::before_restore;
    std::string error_code; // a code of decision point 2, e.g. "backup_transient"
    // In the restore phase only: the error promised that no restore was sent
    // (its message ends with connector::kNothingRestored), so the restore
    // targets are as they were. Ignored in the other phases.
    bool nothing_restored = false;
};

// The stop an exception makes, by its type (decision point 2), the same in
// every phase:
//  - rp::ConfigError (graph::CertificateError too), sampling::ManifestError:
//    config;
//  - a graph::GraphError: the check's code for it (read_error_code,
//    rp/checker.hpp): target_guard, graph_auth, graph_permission,
//    graph_transient or graph, wherever it was thrown (the connector's guard
//    lets Graph's errors out as Graph's);
//  - connector::SafetyViolation: target_guard; connector::AuthError:
//    backup_auth; connector::TransientError: backup_transient;
//    connector::NotFoundError: not_in_backup; any other connector::Error:
//    backup;
//  - connector::Interrupted (a stop asked of the Worker, W4.8): interrupted;
//  - rp::ClientMismatchError (the client check, W4.11): client_mismatch;
//    connector::UnknownConnectorError: connector_unknown (W4.11; before, config);
//  - anything else: internal.
// In the restore phase, nothing_restored is whether a known exception's
// what() ends with connector::kNothingRestored (never for internal).
// Throws std::invalid_argument for a null `error`.
RunStop stop_reason(std::exception_ptr error, RunPhase phase);

// A type's canaries or random items the sample took fewer of than it wanted.
struct Shortfall {
    connector::ItemKind kind = connector::ItemKind::mail;
    ItemSource source = ItemSource::canary;
    int wanted = 0;
    int taken = 0;
};

// The sample's shortfalls, mail, SharePoint, OneDrive, each its canaries then
// its random items: canaries wanted ceil(requested / 2), taken
// canary_ids.size(); random wanted random_wanted, taken random_taken; a half
// listed only when it took fewer than it wanted. The one shortfall rule:
// `rpworker restore`'s NOTE column reads it too.
std::vector<Shortfall> shortfalls_of(const sampling::SampleRecord& record);

// What a run produced. The pointers are borrowed: null means "not there",
// and each must outlive the decide_status call.
struct RunFacts {
    const ExpectedSet* expected = nullptr; // once the sample is chosen
    std::vector<Shortfall> shortfalls;     // shortfalls_of the sample's record
    std::optional<RunStop> stop;           // whatever stopped the run, at most one
    const connector::RestoreResult* restore = nullptr; // restore_sample returned
    const CheckResult* check = nullptr;                // the check ran
    // The restore point's backup time as the backup product wrote it (Veeam's
    // UTC form, rp::parse_veeam_time); empty or unreadable: not known. Read
    // only for an item the backup said the restore point doesn't hold.
    std::string restore_point_time;
};

// One note beside the status, never a status of its own. `message` is one
// line, never a tenant value (no subject, name, address or Graph ID; the
// backup product's session IDs, results and details only, control characters
// as spaces). `indexes` are the expected items it concerns, ascending.
//  - backup_session: one per restore session whose result isn't exactly
//    "Success": "<kind> session <id>: <result>[ (<details>)]", its items (an
//    empty session ID matches none); the details only when they read as the
//    backup's counts, "<n> item(s) processed[ (<n> <word>, ...)]" with words
//    of Veeam's own (success(es), warning(s), failure(s), error(s), skipped),
//    since other text may name an item or an address;
//  - backup_item: the verified items the backup didn't report restored;
//  - duplicate: the items more than one restored copy matched;
//  - shortfall: one per Shortfall, "<kind> <canary|random>: <taken> of <wanted>";
//  - stale_copies: earlier runs' copies the check ignored, "<n> copies from
//    earlier runs in the restore targets were ignored (mail <x>, sharepoint
//    <y>, onedrive <z>)".
struct StatusWarning {
    std::string code;
    std::string message;
    std::vector<std::size_t> indexes;
};

// An item that couldn't be checked, with why: the check's code
// (graph_auth, graph_permission, graph_transient, target_guard, graph,
// stale_target), backup_infrastructure or not_in_backup.
struct UncheckedItem {
    std::size_t index = 0;
    std::string error_code;
};

struct RunVerdict {
    RunStatus status = RunStatus::error;
    std::string error_code; // error only
    std::string message;    // one line, never a tenant value
    // Whether a restore may have been sent, so items may be in the restore
    // targets (W3.4's cleanup): a restore result that isn't not_run, or a stop
    // in the restore without nothing_restored. Set by every row.
    bool restore_sent = false;
    // Rows 5 to 8 only (the item verdicts); empty for rows 1 to 4.
    std::vector<std::size_t> failed;      // fail only
    std::vector<UncheckedItem> unchecked; // ascending by index
    std::vector<StatusWarning> warnings;  // in the order of StatusWarning's codes
    std::size_t items = 0;                // the expected set's items (0 without one)
    // The verified items by expected kind; their sum is the verified count.
    std::size_t verified_manifest = 0;
    std::size_t verified_fields = 0;
    std::size_t verified_metadata = 0;

    std::size_t verified() const noexcept
    {
        return verified_manifest + verified_fields + verified_metadata;
    }
};

// Pure; never throws for facts that don't add up (row 1 is an error). Each
// item's verdict, first fit wins: its check `error` -> unchecked, the check's
// code; `match` -> verified, whatever the backup said; `missing` or
// `mismatch` while the backup said the item wasn't restored, for an
// infrastructure reason -> unchecked, backup_infrastructure; `missing` or
// `mismatch` while the backup said the restore point doesn't hold the item
// (ItemOutcome::not_in_backup), unless it is a canary whose container the
// point holds (not container_missing) and the restore point was taken after
// the expected set's canaries_seeded_at (both read, the point strictly
// later) -> unchecked, not_in_backup; `missing` or `mismatch`
// -> failed. The run, first fit wins:
//  1. facts that don't add up -> error internal: no expected set and no stop;
//     a restore without an expected set, or a check without a restore; an
//     expected item not at its index; a restore of an empty sample, or a
//     sample of items without a restore result and no stop; a restore
//     (not not_run) whose items aren't the expected items in number and kind;
//     a check whose items aren't (in number, index and kind), or an item
//     error with a code the checker doesn't give; a restore without a check
//     and no stop; a stop whose code isn't one of decision point 2's, or
//     whose phase contradicts what is there (before_restore or restore beside
//     a restore or a check, restore without an expected set, check without a
//     restore or beside a check); a value outside its enum (RunPhase,
//     ExpectedKind, RestoreStatus, ItemOutcome, CheckOutcome); a check item
//     whose `found` contradicts its outcome (match or mismatch not found,
//     missing or error found). No warnings.
//  2. a stop -> error, the stop's code; in the restore phase its message says
//     whether nothing was restored or items may be in the restore targets;
//  3. the expected set is empty -> error empty_sample;
//  4. the restore returned not_run -> error not_run;
//  5. any item failed -> fail, the failed items (and the unchecked beside them);
//  6. the restore is `failed` and every item verified -> error
//     restore_contradiction;
//  7. any item unchecked -> error, the first item code present of
//     target_guard, graph_auth, graph_permission, backup_infrastructure,
//     not_in_backup, graph, graph_transient, stale_target;
//  8. every item verified -> pass.
// Rows 2 to 8 carry the warnings their facts give (StatusWarning).
RunVerdict decide_status(const RunFacts& facts);

// The verdict of a run whose result isn't valid restoreproof.result.v1, or
// couldn't be built (docs/decisions.md 2026-10-04, W4.1 point 5): error
// result_invalid, the Worker's own fault, with the message "the result isn't
// valid restoreproof.result.v1; the run itself ended <pass|fail|error
// <code>>", the words of `verdict` (its code only when it is one of
// error_codes(); never its message). Keeps restore_sent (the clean after
// still runs), the item count and the warnings; clears the failed and
// unchecked items and the verified counts, as rows 1 to 4 leave them.
RunVerdict result_invalid(const RunVerdict& verdict);

// A stop asked of the Worker during a run (docs/decisions.md 2026-10-08, W4.8
// point 13). Whether a verdict decided after the stop came is replaced by
// interrupted(): an error with a code other than interrupted, target_guard,
// result_invalid, client_mismatch and connector_unknown (facts about the run's
// input, not a wait), since a wait the stop cut short reads as the failure
// of whichever service was being waited for. A pass or a fail reached in
// spite of the stop stays what it is.
bool interrupt_replaces(const RunVerdict& verdict) noexcept;

// The verdict that replaces `verdict` then: error interrupted, "the Worker
// was stopped during the run; the run itself ended <pass|fail|error <code>>",
// the words as result_invalid() writes them. Keeps and clears what
// result_invalid() does.
RunVerdict interrupted(const RunVerdict& verdict);

// The verdicts of a result written afterwards, for a run whose folder was
// left without one (W4.8 point 7): every count 0, no failed or unchecked
// item, no warning. `restore_requested` is the run record's word that a
// restore request may have gone out, and becomes restore_sent.
//  - error interrupted, the process ended during the run: "the run was
//    interrupted before its result was written; no restore request had been
//    sent", or "...; a restore request may have been sent, so items may be in
//    the restore targets";
RunVerdict interrupted_before_result(bool restore_requested);
//  - error internal, the run returned and its folder couldn't be completed:
//    "the run ended without a result the Worker could write; this result was
//    written afterwards";
RunVerdict ended_without_result(bool restore_requested);
//  - error result_invalid, the run's own result wasn't valid:
//    result_invalid()'s message, naming how the run had ended (`ended_code`
//    read for an error only, and only when it is one of error_codes()).
RunVerdict result_invalid_afterwards(RunStatus ended_status, std::string_view ended_code,
                                     bool restore_requested);

// The verdict of a job whose connector type this Worker has no connector
// for (W4.11 point 4; the loop's J3b): error connector_unknown, "the job's
// connector type isn't one this Worker has; nothing was done", restore_sent
// false, every count 0.
RunVerdict connector_unknown();

// The verdict of a job the Worker was handed and can't run (W4.8 point 4,
// J3): error job_invalid, "the job isn't a valid job (<key>); nothing was
// done", restore_sent false, every count 0. `key` is the jobs reader's word
// for the first key at fault (a key of the job's format, or "unknown key"),
// never text taken from the job.
RunVerdict job_invalid(std::string_view key);

// The vocabularies, which the result's schema is held to (W4.1 point 3).
// Every code a verdict's error_code can carry, in the table's order:
// config, internal, backup_auth, backup_transient, not_in_backup,
// no_restore_point, target_guard, backup, graph_auth, graph_permission,
// backup_infrastructure, graph, graph_transient, stale_target, empty_sample,
// not_run, restore_contradiction, result_invalid, interrupted, job_invalid,
// client_mismatch, connector_unknown.
std::vector<std::string_view> error_codes();

// The codes an UncheckedItem can carry, most severe first (row 7's order).
std::vector<std::string_view> unchecked_item_codes();

// StatusWarning's codes, in the order a verdict lists its warnings:
// backup_session, backup_item, duplicate, shortfall, stale_copies.
std::vector<std::string_view> warning_codes();

// The result's "status" object: {"status", "error_code" (error only),
// "message", "restore_sent", "counts": {"items", "verified", "failed", "unchecked"},
// "verified": {"manifest", "fields", "metadata"}, "failed_items": [index...],
// "unchecked_items": [{"index", "error_code"}], "warnings": [{"code",
// "message", "indexes"}]}. Every key but error_code always there.
nlohmann::json to_json(const RunVerdict& verdict);

// Whether a restore session's details read as the backup's counts: "<n>
// item(s) processed", then optionally a parenthesis of "<n> <word>" pairs of
// Veeam's own words (success(es), warning(s), failure(s), error(s), skipped),
// e.g. "5 items processed (4 successes, 1 warning)". The one filter of
// Veeam's details: backup_session's warning and the result's `restore`
// object keep them only then; any other text may name an item or an address.
bool is_backup_counts(std::string_view details);

// The result's "restore" object (W3.6 point 5): {"status", "items_sent",
// "items_restored", "sessions": [{"id", "kind", "result", "details" (when
// is_backup_counts, else null), "items_sent", "items_restored",
// "started_at_raw", "ended_at_raw" (the product's text, unparsed)}], "items":
// [{"index" (its place in result.items), "kind", "outcome", "infrastructure",
// "container_missing", "session_id"}]}. No item name and no Veeam message: those may name a tenant
// value.
nlohmann::json to_json(const connector::RestoreResult& result);

// rpworker's exit code for an error code (rp::exit_code), from the one table
// of codes the status line's texts and row 7's severity come from too:
// config, internal, result_invalid, job_invalid and connector_unknown 1;
// backup_auth, graph_auth and graph_permission 2; backup_transient and
// graph_transient 3; any other (interrupted, client_mismatch, and a code the
// table doesn't hold too) 4.
int exit_code_of(std::string_view error_code) noexcept;

// rpworker's exit code for a verdict: pass 0; fail 5 (exit_code::restore);
// error its code's.
int exit_code_of(const RunVerdict& verdict) noexcept;

} // namespace rp::verification
