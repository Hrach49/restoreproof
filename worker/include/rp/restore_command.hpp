#pragma once

// `rpworker restore` (W2.8): picks a restore point of veeam_org_name, chooses a
// sample with the sampler (rp/sample_selector.hpp), restores it through the
// veeam_m365 connector's restore_sample into the three restore targets, and
// prints what became of each item. It WRITES to the tenant: into the restore
// targets only, through restore_sample, whose first step is the target guard's
// layer 1; this command builds no restore request of its own. Since W3.2 it
// reads the restored items back through Graph and checks them against the
// expected set (rp/checker.hpp): the targets are listed before the restore and
// again, hashed, after it. Nothing is cleaned up (W3.4). The choices are the
// 2026-09-30 W2.8 and 2026-10-01 W3.2 entries in docs/decisions.md; usage and
// an example are in docs/worker-config.md ("rpworker restore").

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace rp {

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
    // (W3.2); null = graph::make_download_http_client. Called once, after the
    // sample is chosen and before the targets are first read.
    std::function<std::unique_ptr<IHttpClient>()> make_download_http;
    // A new run ID when --run-id isn't given; null = make_run_id(). What it
    // returns must pass sampling::check_run_id, or the command fails with
    // "error: unexpected failure".
    std::function<std::string()> make_run_id;
    // The steady clock the restore's total time and each checked item's ms
    // (each file's read, each comparison) are measured by; null =
    // steady_clock::now.
    std::function<std::chrono::steady_clock::time_point()> now;
};

// The real environment: rp::default_config_path, rp::load_secrets_from_env, the
// default registry's veeam_m365 connector with a logger that writes warnings
// and worse to stderr, make_run_id and the steady clock.
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
// the connector; its restore points for veeam_org_name and the one chosen; the
// run ID; the first two lines, flushed; sampling::choose_sample (it browses
// Veeam); the rest of the header, flushed; the expected set
// (verification::build_expected_set); the before snapshot: the targets the
// sample has items of, listed through Graph (graph::TargetReader, its guards
// included) without hashing; restore_sample; the tables and the status line,
// flushed; the after read: the same targets listed again, each item hashed
// and each docx and xlsx by office-v1 (verification::office_hook);
// verification::check; the check's table and lines. Prints to `out`, as UTF-8:
//
//   restore point <backup_time>  <id>  (veeam_org_name <org>)
//   run <run ID>  seed <8 hex digits>
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
//   status <status>: <restored> of <sent> item(s) restored in <H:MM:SS>
//   <blank line>
//     KIND  SOURCE  NAME  OUTCOME  FIELDS  DUP  MS              one row per expected item
//   <blank line>
//   check: <a> match, <b> mismatch, <c> missing, <d> error
//   check: <n> copies from earlier runs were ignored (mail <x>, sharepoint <y>, onedrive <z>)
//                                                   (only when n isn't 0)
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
// rows isn't printed. The total is restore_sample's own time, by env.now.
// Text from the connector goes through table_cell(): a control character
// becomes a space. Warnings go to stderr only.
//
// With --record <dir> (Q2.1, rp/recording_http_client.hpp), every exchange
// with Veeam (under "veeam"), with Entra and Graph for the target guard and
// the check (under "graph") and each download of the check (under
// "download", its size and SHA-256 only) is also written, scrubbed, under <dir>/<service>/ (a folder
// that must be new or empty, opened after the secrets and before any
// request), and "recorded <n> exchange(s) in <dir>" ends `out`, whatever the
// result; each exchange not written is a "record error: <service>/<file>:
// <why>" line on `err`, and turns an exit code of 0 into 1. The restore
// still writes to the tenant: recording changes nothing sent.
//
// Returns an rp::exit_code, with one line on `err` for each failure:
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
//    write or flush of `out` after restore_sample returned is "error: writing
//    the output failed after the restore ran (run <run ID>, status <status>:
//    <restored> of <sent> item(s) restored)", then the restore's own exit
//    code and line as below (1 when that is 0: its output was lost);
//  - before restore_sample, a failure reading the targets for the before
//    snapshot stops the run, nothing restored: "check error: <what()>;
//    nothing was restored", 2 for a graph::AuthError or PermissionError, 3
//    for a graph::TransientError, 4 for any other graph::GraphError (a
//    WrongTargetError of the targets' guards included), 1 for a ConfigError;
//  - 2: "restore error: <what()>" for a connector::AuthError;
//  - 3: the same for a connector::TransientError (Veeam unreachable);
//  - 4: the same for any other connector::Error: a SafetyViolation ("restore
//    error: target guard: ..."), a NotFoundError, a NotImplementedError; also
//    "restore error: no restore points for veeam_org_name", "restore error:
//    restore point <id> not found for veeam_org_name", "restore error: the
//    sample is empty: nothing to restore (<kind>: <shortfall>[; ...])" after
//    the header, without calling restore_sample (<kind> each type asked for,
//    <shortfall> as in NOTE), and, after the tables and the status line:
//    "restore error: <n> item(s) failed for an infrastructure reason (Veeam
//    couldn't reach Microsoft 365, lacked permissions or was throttled); this
//    is an error, not a restore failure" when any item not restored is marked
//    infrastructure (whatever the status), and "restore error: the restore did
//    not run: nothing was sent (status not_run)";
//  - after an error restore_sample threw (2, 3, 4, or 1 for an unexpected
//    one; not a ConfigError), unless its message ends with
//    connector::kNothingRestored, a second line: "restore error: the restore
//    had started: items may be in the restore targets (run <run ID>)";
//  - 5 (exit_code::restore): the restore ran and its status is partial or
//    failed, no item for an infrastructure reason; the tables and the status
//    line are printed, nothing on `err`;
//  - once the restore's code above is 0 (W3.2, until W3.3's status table): 5
//    with "check: <n> item(s) didn't verify" when an item is missing or a
//    mismatch, else 4 with "check: <n> item(s) couldn't be checked" when one
//    is an error. A target whose after read failed is "check error:
//    <what()>" on `err` and makes its items `error`, never a failed command;
//    a failed write of the check's table is the output failure above, with
//    the check's code in place of the restore's;
//  - 0: status succeeded and every item matched (a random shortfall
//    included: the header names it).
// connector::Error's what() is safe to print (rp/connector.hpp). No exception
// escapes.
int run_restore_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const RestoreCommandEnv& env);

} // namespace rp
