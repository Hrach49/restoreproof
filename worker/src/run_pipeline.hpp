#pragma once

// The run `rpworker restore` (W2.8, W3.1 to W3.5) and `rpworker test` (W3.6)
// share: one pipeline, so one guard, one mutex, one status table and one
// cleanup (docs/decisions.md 2026-10-03, W3.6 point 4). Each command keeps
// its own parser and says through a Presentation where its output differs:
// restore's per-item restore rows and check table, test's table after the
// check and its --json file. What the run does and prints is documented on
// run_restore_command (rp/restore_command.hpp).

#include "command_config.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/checker.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_selector.hpp>
#include <rp/step_timer.hpp>

#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace rp {

// The command line both commands take, as given (UTF-8).
struct PipelineArgs {
    std::optional<int> mail;
    std::optional<int> sharepoint;
    std::optional<int> onedrive;
    std::optional<std::string_view> point; // an ID; nullopt = latest
    std::optional<std::string_view> run_id;
    std::optional<sampling::CanaryCursor> cursor;
    std::optional<std::string_view> manifest;
    std::optional<std::string_view> config;
    std::optional<std::string_view> vault; // W4.5: the vault file; nullopt = the default
    std::optional<std::string_view> record;
    // `test --evidence <dir>` (W4.2): the runs root, in which the run makes
    // its folder <dir>\<run_id>. Not one of parse_pipeline_args' options: the
    // command that takes it sets it.
    std::optional<std::string_view> evidence;
    // `test --evidence <dir> --outbox <root>` (W4.6): the outbox's root; the
    // finished run folder is queued as <root>\outbox\<run_id>. Only with
    // `evidence`; set by the command, as it is.
    std::optional<std::string_view> outbox;
};

// Whether each of those options in `options` (--mail --sp --od --point
// --run-id --canary-cursor --manifest --config --vault --record, each with its
// value) is well-formed by the rules on run_restore_command, each copied
// into `parsed`.
bool parse_pipeline_args(const CommandOptions& options, PipelineArgs& parsed);

// What one run produced, handed on once at its end (W3.6 point 4, W4.1
// points 1 and 5): the finished restoreproof.result.v1, built and validated
// by the pipeline (rp::ResultBuilder) once the clean after and the timings
// are done.
struct RunSummary {
    std::string run_id;
    // The result's canonical text (rp::canonical_json), exactly what a file
    // holds; borrowed for the call only. Null when there is no valid result:
    // no verdict (an unexpected failure), a run that ended `error
    // result_invalid`, or a finished result that couldn't be built or isn't
    // valid by the schema. Never a cut-down one.
    const std::string* result = nullptr;
};

// Where a command's output differs from the other's.
struct Presentation {
    // The recording's label, "rpworker <version> <command> --record".
    std::string_view command;
    // Restore's per-item rows after the restore (KIND SOURCE NAME OUTCOME
    // SESSION ELAPSED MESSAGE), before the session rows.
    bool restore_rows = true;
    // The check's table, a paragraph with its blank line before it, or "" for
    // no rows; printed after the check and before its count line. `verdict`
    // is the run's, decided from that check.
    std::function<std::string(const verification::ExpectedSet&, const verification::CheckResult&,
                              const verification::RunVerdict&, const connector::RestoreResult*)>
        check_table;
    // Called once the config is read and before the secrets; what it throws
    // is handled as the config's errors are (a ConfigError: "config error:
    // <what()>", exit 1). Null = nothing.
    std::function<void()> after_config;
    // Called once, last, by every run that printed its run line, after the
    // timings and env.on_timings, with `code` the exit code so far and
    // whether stdout was lost; returns the exit code. When it throws,
    // "error: unexpected failure" goes on `err`, a `code` of 0 becomes 1 and
    // any other is kept; `test --json`'s hook catches what its own writes
    // throw, so only a bug gets here. Null = nothing, and the
    // finished result isn't built: only the one validation before the
    // status line runs.
    std::function<int(const RunSummary&, int code, bool output_lost)> on_run;
};

// With args.evidence (W4.2 and W4.3, docs/decisions.md 2026-10-05;
// rp::EvidenceBuilder, rp::Signer):
//  - once the config is read and before the secrets, "config error:
//    --evidence <dir>: not a UTF-8 path" or, for a --run-id that isn't a plain
//    file name, "config error: --evidence: the run ID can't name a folder",
//    exit 1;
//  - right after the Graph certificate is checked, before the schema, the
//    manifest, the run mutex and any Veeam call, the signing key is parsed
//    (rp::SigningKey::from_base64): "config error: signing_key_base64 is
//    not in the vault; --evidence signs the result" or "config error:
//    signing_key_base64 is not an Ed25519 private key (Base64 of PKCS#8
//    DER)", exit 1, no run line. A run without args.evidence never parses
//    the key nor needs it;
//  - once the run ID is known and before the run line, the run folder is
//    made; if it can't be, "evidence error: <folder>: the run folder already
//    exists; nothing was done" (or "... couldn't be made; ..."; for a made-up
//    run ID that can't name one, "evidence error: the run ID can't name a
//    folder; nothing was done"), exit 1, no run line;
//  - last, where on_run would be called (which then isn't): items.csv and
//    veeam-session.log are written, the screenshot asked for
//    (env.capture_screenshot, config's screenshots_enabled), the finished
//    result built with `attachments` and `screenshot` and validated, each
//    attachment read back against its hash, the canonical text signed
//    (env.sign_result, the run's key) and signature.json written, and
//    result.json written, exactly the canonical text; then, both only once
//    result.json is written, "signed <bundle_sha256> key <key_id>" and
//    "evidence <folder>: result.json, signature.json, items.csv,
//    veeam-session.log[, screenshot.png]" on `out`. On `err`, each with an
//    exit code of 0 becoming 1 and the status unchanged: "evidence error:
//    <file>: could not be written" (signature.json too; a signature.json
//    written before a result.json that couldn't be is removed again),
//    "evidence error: <file>: changed after it was hashed", "evidence error:
//    <folder>: the result holds a secret value; no result.json was written",
//    "evidence error: <folder>: the result couldn't be signed; no result.json
//    was written", or, for a run with no valid result (after the text files
//    are written; such a run is not signed), "evidence error: <folder>: the
//    result isn't valid restoreproof.result.v1; no result.json was written".
//
// With args.outbox too (W4.6, docs/decisions.md 2026-10-07; rp::Outbox):
//  - with the --evidence root, "config error: --outbox <root>: not a UTF-8
//    path", exit 1, before the secrets; then, still before the secrets, the
//    mutex and any Veeam call (the W4.6 review, finding 1), rp::Outbox::prepare:
//    with a --run-id, "outbox error: <root>\outbox\<run_id>: already queued;
//    nothing was done" or "outbox error: <root>\sent\<run_id>: already sent;
//    nothing was done"; <root>\outbox made, else "outbox error: <root>\outbox:
//    the folder couldn't be made; nothing was done"; the two roots on one
//    volume, else "outbox error: <dir>: not on the same volume as
//    <root>\outbox; nothing was done"; each exit 1;
//  - last, only once result.json is written and the signed, timestamped and
//    evidence lines are out, the run folder is renamed to
//    <root>\outbox\<run_id> and its manifest.json written there (the W4.4
//    code as its timestamp.code when the run got no token): "queued <outbox
//    folder>" on `out`. A folder that can't be queued stays in <dir> as it
//    is: one "outbox error: ..." line on `err` (rp::Outbox::queue_error), the
//    status unchanged and an exit code of 0 becoming 1; so for a queued
//    folder whose manifest couldn't be written, after its "queued" line. A
//    run with no result.json queues nothing and says nothing of the outbox.
//
// Whatever the command, the signing key's text is taken out of the run's
// Secrets (wiped there) before the connector is made, and wiped with the
// parsed key on every way out of the run.
//
// The run but for what --record wrote, which the command prints last:
// `recorder` is set once the recording is open. Returns an rp::exit_code.
// No exception escapes.
int run_pipeline(const PipelineArgs& args, std::ostream& out, std::ostream& err,
                 const RestoreCommandEnv& env, std::shared_ptr<FixtureRecorder>& recorder,
                 const Presentation& presentation);

// "<blank line>\ncheck: <a> match, <b> mismatch, <c> missing, <d> error\n":
// the check's count line, the same in both commands.
std::string format_check_counts(const verification::CheckResult& check);

// The text table helpers' cell for connector or tenant text: "-" when empty,
// else table_cell(text) (a control character becomes a space).
std::string cell_or_dash(std::string_view text);

// The kind's name, "mail", "sharepoint" or "onedrive".
std::string kind_name(connector::ItemKind kind);

} // namespace rp
