#pragma once

// `rpworker restore` (W2.8): picks a restore point of veeam_org_name, chooses a
// sample with the sampler (rp/sample_selector.hpp), restores it through the
// veeam_m365 connector's restore_sample into the three restore targets, and
// prints what became of each item. It WRITES to the tenant: into the restore
// targets only, through restore_sample, whose first step is the target guard's
// layer 1; this command builds no restore request of its own. Since W3.2 it
// reads the restored items back through Graph and checks them against the
// expected set (rp/checker.hpp): the targets are listed before the restore and
// again, hashed, after it. Since W3.3 the run ends with its status, pass, fail
// or error (rp/run_status.hpp), which decides the exit code. Since W3.4 it
// holds the run mutex (rp/run_lock.hpp) and empties the three restore targets
// (rp/cleaner.hpp) before the sample is chosen and, when a restore was sent,
// after the status line; the cleanup never changes the status but through the
// guard. Since W3.5 it times its steps and ends with their table, which
// changes nothing else. Since W3.6 its run is the pipeline `rpworker test`
// shares (src/run_pipeline.hpp, rp/test_command.hpp), so both run, print and
// exit alike but for each one's tables. The choices are the 2026-09-30 W2.8,
// 2026-10-01 W3.2 and W3.3, 2026-10-02 W3.4 and 2026-10-03 W3.5 and W3.6
// entries in docs/decisions.md; usage and an example are in
// docs/worker-config.md ("rpworker restore").

#include <rp/cleaner.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/http_client.hpp>
#include <rp/run_lock.hpp>
#include <rp/secrets.hpp>
#include <rp/step_timer.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace rp {

// What a run's cleanup did and the state it leaves the restore targets in
// (W3.4 point 7): the result's `cleanup` object beside `status`, which W4.1
// adopts into result.v1.json. Counts and codes only.
struct RunCleanup {
    // The clean before the sample was chosen; nullopt when none ran (the run
    // stopped before its Graph client was made).
    std::optional<graph::CleanupResult> before;
    // The clean after the status line; nullopt when none ran: nothing was
    // restored, or there was no Graph client.
    std::optional<graph::CleanupResult> after;
    // The status's restore_sent: items may be in the targets.
    bool restore_sent = false;
    // The run stopped in its restore phase without the connector's promise
    // that nothing was sent (a POST with no answer, a poll that gave up):
    // Veeam may still be writing into the targets after the clean-after.
    bool restore_may_still_run = false;

    // The state the run leaves behind: false when the restore may still run,
    // else after's ok() when the clean-after ran, else false when a restore
    // was sent, else before's ok() (false when that didn't run either).
    bool cleanup_ok() const noexcept;
};

// {"cleanup_ok", "restore_may_still_run", "before": {...} | null, "after":
// {...} | null}, each clean as graph::to_json(CleanupResult).
nlohmann::json to_json(const RunCleanup& cleanup);

// What the command reaches outside itself. run_cli passes
// default_restore_command_env(); tests pass a temp config, their own secrets, a
// connector (a fake, or the real one on a FakeHttpClient), Graph and the
// downloads on FakeHttpClients, a fixed run ID and a clock they move.
struct RestoreCommandEnv {
    // The config file without --config (rp::default_config_path). Called only
    // then, and only after the arguments parsed.
    std::function<std::filesystem::path()> default_config_path;
    // rp::load_secrets_from_env.
    std::function<Secrets()> load_secrets;
    // Makes the connector; null = the default registry's connector::kVeeamM365
    // (connector::default_connector_registry().create). Called once, after the
    // config, the secrets and the manifest are read.
    std::function<std::unique_ptr<connector::IConnector>(
        const Config&, const Secrets&, const connector::ConnectorOptions&)>
        make_connector;
    // Passed to make_connector as they are, but a null `logger` is replaced by
    // make_command_logger()'s (warnings and worse, to stderr), never spdlog's
    // default logger, which writes to stdout. The check's own Graph client
    // (W3.2) is made with the same: its HTTP client from make_graph_http
    // (null: graph::make_graph_http_client), and its logger, now, wall_now,
    // sleep and jitter.
    connector::ConnectorOptions connector_options;
    // Makes the HTTP client the check downloads restored files through
    // (W3.2); null = graph::make_download_http_client. Called once, right
    // after the run line, with the Graph client the cleanup and the check
    // share (W3.4).
    std::function<std::unique_ptr<IHttpClient>()> make_download_http;
    // A new run ID when --run-id isn't given; null = make_run_id(). What it
    // returns must pass sampling::check_run_id, or the command fails with
    // "error: unexpected failure".
    std::function<std::string()> make_run_id;
    // The steady clock the restore's own time, each checked item's ms (each
    // file's read, each comparison) and the step timings (W3.5) are measured
    // by; null = connector_options.now, the clock the connector measures each
    // session's submit and wait on, else steady_clock::now. Set both, if at
    // all, to one clock: `restore` holds submit and wait only on one clock.
    // Never a wall clock. A reading for the timings alone that throws
    // changes nothing but its span; one the run needs (the restore's line,
    // the check) stops it as an unexpected failure.
    std::function<std::chrono::steady_clock::time_point()> now;
    // Takes the run mutex without waiting (W3.4): the lock, held until the
    // command returns, or null when another run holds it. Null =
    // rp::try_take_restore_targets_lock. Called once, after the manifest's
    // checks and before the --record folder and the connector are made. What
    // it throws is an unexpected failure (exit 1).
    std::function<std::unique_ptr<RunLock>()> take_run_lock;
    // Whether the result's validator is there (W4.1); null =
    // rp::result_schema_ready. Asked once, after the config, the secrets and
    // the sample sizes and before the manifest, the run mutex and any Veeam
    // call: false is "error: the result schema couldn't be loaded; nothing
    // was done", exit 1, no run line.
    std::function<bool()> result_schema_ready;
    // Given the run's cleanup once its line is out, before the step timings'
    // table (on_timings is the last hook), for every run that printed its
    // run line; null = nothing. W4.1 writes it into the result.
    std::function<void(const RunCleanup&)> on_cleanup;
    // Given the run's step timings (W3.5) once, after the table (or where it
    // would have been when stdout is lost), for every run that printed its
    // run line; null = nothing. W4.1 writes timing::to_json of it into the
    // result as `timings`. What it throws is ignored: timings decide nothing.
    std::function<void(const timing::RunTimings&)> on_timings;
    // `rpworker test --json <file>` only (W3.6, rp/test_command.hpp): writes
    // the result's canonical text (W4.1) to the file, whether it did. Null = the atomic
    // writer (src/atomic_file.hpp: a temp file beside it, flushed, moved
    // onto it, never over a file already there). What it throws is a
    // failure. `restore` never calls it.
    std::function<bool(const std::filesystem::path&, std::string_view)> write_summary;
    // `rpworker test --evidence <dir>` only (W4.2, rp/evidence_builder.hpp):
    // writes one new file of the run folder, whether it did; null = the atomic
    // writer, as write_summary's. What it throws is a failure.
    std::function<bool(const std::filesystem::path&, std::string_view)> write_evidence_file;
    // The screenshot's capturer, asked only when the config's
    // screenshots_enabled is true; null = rp::no_screenshot_page, which starts
    // no browser. Whatever it answers or throws, the status is unchanged.
    ScreenshotCapturer capture_screenshot;
    // `rpworker test --evidence <dir>` only (W4.3, rp/signer.hpp): signs the
    // result's canonical text, the bytes result.json is about to be written
    // with, with the run's key (the one RP_SIGNING_KEY_BASE64 carries, parsed
    // before anything is done); null = rp::Signer::sign. nullopt, or anything
    // thrown, is a result that couldn't be signed: no result.json, the status
    // unchanged.
    std::function<std::optional<SignedResult>(std::string_view canonical, const SigningKey& key)>
        sign_result;
    // `rpworker test --evidence <dir>` only (W4.4, rp/timestamper.hpp): makes
    // the HTTP client the TSA is asked through, once, when the result is
    // signed; null = an rp::HttpClient with connector_options' logger. With
    // --record its exchanges go under "tsa", both bodies as Base64. The
    // Timestamper waits between its attempts with connector_options.sleep
    // (null = std::this_thread::sleep_for).
    std::function<std::unique_ptr<IHttpClient>()> make_tsa_http;
    // The nonce of each timestamp request; null = a random one.
    std::function<std::optional<std::uint64_t>()> timestamp_nonce;
};

// The real environment: rp::default_config_path, rp::load_secrets_from_env, the
// default registry's veeam_m365 connector with a logger that writes warnings
// and worse to stderr, make_run_id, the steady clock and the real run mutex.
RestoreCommandEnv default_restore_command_env();

// "rp-<YYYYMMDDTHHMMSSZ>-<8 lower-case hex digits>": the current UTC time and
// 32 bits from std::random_device. Passes sampling::check_run_id.
std::string make_run_id();

// "H:MM:SS" (hours not padded, as many digits as needed), the duration cut to
// whole seconds; a negative duration is "-".
std::string format_elapsed(std::chrono::nanoseconds elapsed);

// `rpworker restore ...`. `args` is what follows "restore" on the command line,
// in UTF-8:
//   [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>]
//   [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>]
//   [--record <dir>]
// in any order, each at most once, each with its value. <n> is 1 to 3 ASCII
// digits, 0 to 100; an absent size is config's sample_mail, sample_sp or
// sample_od. --point is `latest` in any ASCII case (the default: the newest
// restore point) or a restore point ID: 1 to 128 ASCII letters, digits and
// hyphens (Veeam's are two GUIDs run together), matched ASCII
// case-insensitively. --run-id must pass
// sampling::check_run_id; without it a new one is made (make_run_id).
// --canary-cursor is three decimal numbers of 1 to 6 digits each, split by
// commas, nothing else (default 0,0,0). --manifest defaults to
// seed-manifest.json in the config file's folder.
//
// In this order: the arguments; the config, the Veeam secrets
// (rp::require_veeam_secrets) and the Graph certificate, opened and checked
// as restore_sample will (graph::certificate_from_secrets at
// connector_options.wall_now, or now: an unset RP_GRAPH_CERT_PASSWORD is no
// password, as for `graph list`); the manifest, sampling::check_manifest
// (its tenant, no canary in a restore target) and sampling::cursor_problem;
// the run mutex (env.take_run_lock, W3.4); the connector; its restore points
// for veeam_org_name and the one chosen; the run ID; the first two lines,
// flushed; the Graph client and the clean before (graph::Cleaner, all three
// targets) and its line, flushed; sampling::choose_sample (it browses
// Veeam); the rest of the header, flushed; the expected set
// (verification::build_expected_set); the before snapshot: the targets the
// sample has items of, listed through Graph (graph::TargetReader, its guards
// included) without hashing; restore_sample; the tables and the restore's
// line, flushed; the after read: the same targets listed again, each item
// hashed and each docx and xlsx by office-v1 (verification::office_hook);
// verification::check; the check's table and line; the run's status
// (verification::decide_status) and its warnings; the clean after, when the
// status says a restore was sent, and its line; the step timings' table
// (W3.5). Prints to `out`, as UTF-8:
//
//   restore point <backup_time>  <id>  (veeam_org_name <org>)
//   run <run ID>  seed <8 hex digits>
//   cleanup before <ok|incomplete>: deleted <a> mail, <b> sharepoint, <c> onedrive[...]
//   canary cursor <m>,<s>,<o> -> <m>,<s>,<o>
//     KIND        REQUESTED  CANARIES  RANDOM  NOTE
//     mail        <n>        <t> of <w>  <t> of <w>  [canary shortfall | random
//                                                     shortfall | canary and random shortfall]
//     sharepoint  ...
//     onedrive    ...
//   restoring <k> item(s) ...                  (not printed when k is 0)
//   <blank line>
//     KIND  SOURCE  NAME  OUTCOME  SESSION  ELAPSED  MESSAGE        one row per item
//   <blank line>
//     SESSION  KIND  RESULT  RESTORED  STARTED  ENDED  ELAPSED        one row per session
//   <blank line>
//   restore <status>: <restored> of <sent> item(s) restored in <H:MM:SS>
//   <blank line>
//     KIND  SOURCE  NAME  OUTCOME  FIELDS  DUP  MS              one row per expected item
//   <blank line>
//   check: <a> match, <b> mismatch, <c> missing, <d> error
//   <blank line>
//   status <pass|fail|error>[ <error_code>]: <message>
//   cleanup after <ok|incomplete|skipped>: ...
//   <blank line>
//   STEP                  TIME         NOTE
//   restore_point_lookup  <H:MM:SS.mmm | ->  [<note>]   all eleven spans, in
//   ...                                                  timing::Span order
//   total                 ...
//
// The step timings (W3.5, rp/step_timer.hpp; docs/decisions.md 2026-10-03
// W3.5): named spans on env.now, read at fixed boundaries, spans that share a
// boundary sharing one reading. `total` starts just before the restore points
// are listed (what comes before is local and untimed) and ends after the
// clean after; restore_point_lookup, cleanup_before, sample_select,
// target_snapshot (the before snapshot), restore (restore_sample, the same
// readings as the restore's line), verify (the restore's tables, the read
// back and the check), recovery (restore + verify) and cleanup_after are the
// command's own; restore_submit and restore_wait are the sessions' reported
// durations, summed (timing::sum_session_durations), "not reported" when
// restore_sample threw. The spans overlap and don't add up to total. A span a
// stop left open ends "stopped" at one reading taken as the stop is handled,
// before the status line and the clean after; total ends after the clean
// after. NOTE is empty for a measured span, else "stopped", "not run", "not
// reported", "clock went back" or "not closed" (a bug, or a clock that threw
// at the span's end: such a reading changes nothing else), and a span
// without a duration reads "-". The
// table ends every run that printed its run line, after the cleanup after
// line; none before it. It isn't printed when stdout is lost, a failing table
// write changes nothing, and timings never change a status, a warning or an
// exit code. env.on_timings gets them once, after the table.
//
// The cleanup lines (W3.4) hold counts and codes, never a name or an ID:
//   cleanup <before|after> ok: deleted <a> mail, <b> sharepoint, <c> onedrive
//   cleanup <before|after> incomplete: deleted ...[; left <x> mail, <y>
//     sharepoint, <z> onedrive][; skipped <n>][; <target> <error_code>]...[;
//     the restore may still be running; the next run cleans before]
//   cleanup after skipped: nothing was restored
//   cleanup after skipped: no Graph client
// "deleted" counts Graph's 204s; "left" the items the last listing still
// showed; "skipped" the entries never deleted (folders, packages, ...). Each
// target that stopped on an error is a line on `err`, "cleanup error:
// <mail|sharepoint|onedrive>: <what> (<error_code>)", <what> a fixed text
// (the Cleaner's own log line has Graph's message), and each target not left
// empty "warning: cleanup: <target> not emptied <before|after> the run (left
// <x>, skipped <n>[, <error_code>])". A clean-before whose guard refused a
// target (target_guard) stops the run there, before any Veeam explore
// session: status error target_guard, exit 4. Any other cleanup failure only
// shows in these lines and in RunCleanup (env.on_cleanup): it never changes
// the status or the exit code; a pass with leftovers still exits 0. The
// clean after runs after the status line and its warnings, so the decided
// verdict never waits on it, and after the check, so no evidence is deleted
// before it is read; after a check that threw, and after a restore_sample
// that threw having sent a restore (the cleanup line then says the restore
// may still be running), it runs too.
//
// The status line (W3.3) ends every run once its first two lines are out,
// whatever stopped it: a failure choosing the sample, an empty sample (status
// error empty_sample, nothing restored), a failure in the before snapshot,
// restore_sample throwing, the check failing unexpectedly, or the normal end;
// it is its own paragraph after whatever was printed by then. Its message is
// one line, counts and fixed words, never a tenant value nor an exception's
// what() (that stays on `err`, as below). Then each of the status's warnings
// is one line on `err`, "warning: <code>: <message>", in this order:
// backup_session (a restore session whose result isn't Success), backup_item
// (verified items the backup didn't report restored), duplicate, shortfall
// (one per type and half that took fewer than it wanted, e.g. "warning:
// shortfall: sharepoint random: 0 of 2") and stale_copies ("warning:
// stale_copies: <n> copies from earlier runs in the restore targets were
// ignored (mail <x>, sharepoint <y>, onedrive <z>)"). The after read
// downloads only this run's copies of expected files
// (verification::hash_filter): an earlier run's leftover is never read.
//
// The check's rows: SOURCE canary or random; NAME the expected subject or file
// name; OUTCOME match, mismatch, missing or error; FIELDS the fields that
// didn't match, joined by commas, or an error's code (graph_auth,
// graph_permission, graph_transient, target_guard, graph, stale_target), "-"
// otherwise; DUP "<n> copies" when more than one copy of this run's matched,
// "-" otherwise; MS the item's ms when a copy was found, "-" otherwise.
//
// The first two lines are written and flushed as soon as the run ID exists,
// before choose_sample, so a run that fails from then on still shows its run
// ID and seed; the rest of the header (up to "restoring ...") is flushed
// before restore_sample. CANARIES: taken of ceil(n/2); RANDOM: taken of
// floor(n/2); a shortfall is named, never filled. SOURCE is canary or random
// (by the item's place in its type: canaries first), OUTCOME restored, failed
// or unknown, with " (infrastructure)" when the connector reads the message as
// Veeam failing to reach Microsoft 365 or lacking permissions (or being
// throttled); ELAPSED is the item's session's end - start as the connector
// reports them, cut to whole seconds ("-" when either doesn't read or it's
// negative);
// MESSAGE "-" when empty. RESTORED is "<restored> of <sent>". A table with no
// rows isn't printed. The restore's line's time is restore_sample's own, by
// env.now: the step timings' `restore` span, not their `total`.
// Text from the connector goes through table_cell(): a control character
// becomes a space. Warnings go to stderr only.
//
// With --record <dir> (Q2.1, rp/recording_http_client.hpp), every exchange
// with Veeam (under "veeam"), with Entra and Graph for the target guard, the
// cleanup and the check (under "graph"; the cleanup's deletes too) and each
// download of the check (under "download", its size and SHA-256 only) is also
// written, scrubbed, under <dir>/<service>/ (a folder that must be new or
// empty, opened after the secrets and before any
// request), and "recorded <n> exchange(s) in <dir>" ends `out`, whatever the
// result; each exchange not written is a "record error: <service>/<file>:
// <why>" line on `err`, and turns an exit code of 0 into 1. The restore
// still writes to the tenant: recording changes nothing sent.
//
// Returns an rp::exit_code. Once the run line is out, it is the status's
// (verification::exit_code_of): pass 0; fail 5 (exit_code::restore); error 1
// for config, internal and result_invalid, 2 for backup_auth, graph_auth and
// graph_permission, 3 for backup_transient and graph_transient, 4 for any
// other code (target_guard, not_in_backup, backup, backup_infrastructure,
// graph, stale_target, empty_sample, not_run, restore_contradiction). Each
// failure has one line on `err` too:
//  - 64: a command line it doesn't understand (rp::kCliUsage), before the
//    config is read; after it, "usage error: every sample size is 0 (--mail,
//    --sp, --od, or config's sample_mail, sample_sp, sample_od): nothing to
//    restore"; after the manifest, "usage error: --canary-cursor: the <kind>
//    cursor must be below <n>, the manifest's <kind> canaries" (or "must be 0:
//    the manifest has no <kind> canaries"), <kind> mail, sharepoint or onedrive;
//  - 1: "config error: <message>" for a ConfigError (a config that doesn't
//    load, a --config or --manifest path that isn't UTF-8, a secret that can't
//    be read, "RP_VEEAM_USERNAME is not set", then RP_VEEAM_PASSWORD, and a
//    Graph certificate that certificate_from_secrets refuses (unset, not
//    Base64, a password that doesn't open it, expired, ...), and a --record
//    folder that isn't new or empty, all before any Veeam call), a
//    sampling::ManifestError ("canary manifest: ...", a manifest that
//    doesn't load, whose tenant_id isn't graph_tenant_id or
//    that names a restore target, all before the connector is made) and an
//    UnknownConnectorError; "config error: unexpected failure" for any other
//    exception while loading the config and secrets, and "error: unexpected
//    failure" for any other exception after (a failed write or flush of `out`
//    before the restore included: it stops the command before choose_sample
//    or restore_sample); neither ever shows the exception's message. A failed
//    write or flush of `out` once restore_sample returned (the tables, the
//    check's table or the status line) doesn't stop the check: "error:
//    writing the output failed after the restore ran (run <run ID>, restore
//    <restore status>: <restored> of <sent> item(s) restored); run status
//    <pass|fail|error>[ <code>]", then the warnings, and the status's exit
//    code (1 when that is 0: its output was lost); a status line lost with
//    no restore result (once the run line is out) is "error: writing the
//    output failed (run <run ID>); run status ...";
//  - 4, before any Veeam call, with no run line and no status line:
//    "restore error: another RestoreProof run is using the restore targets;
//    nothing was done" when the run mutex is taken (W3.4), or "restore
//    error: the last RestoreProof run ended without releasing the restore
//    targets; nothing was done; the next run cleans them before it restores"
//    when its last holder ended without releasing it (rp::AbandonedRunLock);
//  - before the run line, with no status line: "restore error: <what()>" for
//    a connector::Error listing the restore points (2 for an AuthError, 3 for
//    a TransientError, 4 for any other), and 4 with "restore error: no
//    restore points for veeam_org_name" or "restore error: restore point
//    <id> not found for veeam_org_name";
//  - the before snapshot: a failure reading the targets stops the run,
//    nothing restored: "check error: <what()>; nothing was restored" for a
//    graph::GraphError or a ConfigError; the status's code is graph_auth,
//    graph_permission, graph_transient, target_guard (a WrongTargetError of
//    the targets' guards) or graph, or config;
//  - "restore error: <what()>" for a connector::Error while choosing the
//    sample or restoring (backup_auth for an AuthError, backup_transient for
//    a TransientError, target_guard for a SafetyViolation ("restore error:
//    target guard: ..."), not_in_backup for a NotFoundError, backup for any
//    other, a NotImplementedError included), or a graph::GraphError
//    restore_sample's guard let out (graph_auth, graph_permission,
//    graph_transient or graph, never a backup code); every exception's exit
//    code, before the run line too, is its stop's (verification::stop_reason
//    and exit_code_of), the one mapping;
//  - after an error restore_sample threw (not a ConfigError), unless its
//    message ends with connector::kNothingRestored, a second line: "restore
//    error: the restore had started: items may be in the restore targets
//    (run <run ID>)";
//  - a target whose after read failed is "check error: <what()>" on `err`
//    and makes its items unchecked with its code (the status error), never a
//    stop;
//  - any other exception while reading back or checking (std::bad_alloc, a
//    logic error): "check error: unexpected failure" ("check error:
//    <what()>" for a ConfigError, status error config), then "restore error:
//    the restore had started: items may be in the restore targets (run <run
//    ID>)", no check table: status error internal, 1.
// W4.1: once the status is decided and before the check's table and the
// status line, the run's restoreproof.result.v1 is built as it stands and
// validated by the embedded schema (rp/result_builder.hpp), for `restore` and
// `test` alike, with or without --json. A result that isn't valid makes the
// run "status error result_invalid: the result isn't valid
// restoreproof.result.v1; the run itself ended <pass|fail|error <code>>", 1,
// after one line on `err`: "result error: <n> schema violation(s), first at
// <JSON pointer>" (the pointer only when each of its parts is a key of the
// schema or an index), "result error: the result has no canonical form" or
// "result error: the result couldn't be built". The warnings and the clean
// after are as for the status it replaced.
// The backup's own status never decides: a partial restore whose items all
// verify is a pass (0), a failed one whose items all match is error
// restore_contradiction (4), an item it failed for an infrastructure reason
// that the check doesn't find is unchecked (error backup_infrastructure, 4)
// unless another item is missing or a mismatch (fail, 5).
// connector::Error's what() is safe to print (rp/connector.hpp). No exception
// escapes.
int run_restore_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const RestoreCommandEnv& env);

} // namespace rp
