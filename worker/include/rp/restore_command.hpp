#pragma once

// `rpworker restore` (W2.8): picks a restore point of veeam_org_name, chooses a
// sample with the sampler (rp/sample_selector.hpp), restores it through the
// veeam_m365 connector's restore_sample into the three restore targets, and
// prints what became of each item. It WRITES to the tenant: into the restore
// targets only, through restore_sample, whose first step is the target guard's
// layer 1; this command builds no restore request of its own. Nothing is read
// back or cleaned up (W3.x). The choices are the 2026-09-30 W2.8 entry in
// docs/decisions.md; usage and an example are in docs/worker-config.md
// ("rpworker restore").

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
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
// connector (a fake, or the real one on a FakeHttpClient), a fixed run ID and
// a clock they move.
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
    // default logger, which writes to stdout.
    connector::ConnectorOptions connector_options;
    // A new run ID when --run-id isn't given; null = make_run_id(). What it
    // returns must pass sampling::check_run_id, or the command fails with
    // "error: unexpected failure".
    std::function<std::string()> make_run_id;
    // The steady clock the restore's total time is measured by; null =
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
// in any order, each at most once, each with its value. <n> is 1 to 3 ASCII
// digits, 0 to 100; an absent size is config's sample_mail, sample_sp or
// sample_od. --point is `latest` (the default: the newest restore point) or a
// restore point ID: 1 to 128 ASCII letters, digits and hyphens (Veeam's are
// two GUIDs run together), matched ASCII case-insensitively. --run-id must pass
// sampling::check_run_id; without it a new one is made (make_run_id).
// --canary-cursor is three decimal numbers of 1 to 6 digits each, split by
// commas, nothing else (default 0,0,0). --manifest defaults to
// seed-manifest.json in the config file's folder.
//
// In this order: the arguments; the config and the Veeam secrets; the
// manifest (and its tenant against graph_tenant_id, and the cursor against its
// canaries); the connector; its restore points for veeam_org_name and the one
// chosen; sampling::choose_sample; the header, flushed; restore_sample; the
// tables and the status line. Prints to `out`, as UTF-8:
//
//   restore point <backup_time>  <id>  (veeam_org_name <org>)
//   run <run ID>  seed <8 hex digits>  canary cursor <m>,<s>,<o> -> <m>,<s>,<o>
//     KIND        REQUESTED  CANARIES  RANDOM  NOTE
//     mail        <n>        <t> of <w>  <t> of <w>  [canary shortfall | random
//                                                     shortfall | canary and random shortfall]
//     sharepoint  ...
//     onedrive    ...
//   restoring <k> item(s) ...
//   <blank line>
//     KIND  SOURCE  NAME  OUTCOME  SESSION  ELAPSED  MESSAGE        one row per item
//   <blank line>
//     SESSION  KIND  RESULT  RESTORED  STARTED  ENDED  ELAPSED        one row per session
//   <blank line>
//   status <status>: <restored> of <sent> item(s) restored in <H:MM:SS>
//
// The header (the lines up to "restoring ...") is written and flushed before
// restore_sample, so a run that then fails still shows its run ID and seed.
// CANARIES: taken of ceil(n/2); RANDOM: taken of floor(n/2); a shortfall is
// named, never filled. SOURCE is canary or random (by the item's place in its
// type: canaries first), OUTCOME restored, failed or unknown, with
// " (infrastructure)" when the connector reads the message as Veeam failing
// to reach Microsoft 365; ELAPSED is the item's session's end - start as the
// connector reports them ("-" when either doesn't read or it's negative);
// MESSAGE "-" when empty. RESTORED is "<restored> of <sent>". A table with no
// rows isn't printed. The total is restore_sample's own time, by env.now.
// Text from the connector goes through table_cell(): a control character
// becomes a space. Warnings go to stderr only.
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
//    be read, "RP_VEEAM_USERNAME is not set" then RP_VEEAM_PASSWORD, and the
//    Graph certificate, which restore_sample reads first), a
//    sampling::ManifestError ("canary manifest: ...", a manifest that doesn't
//    load or whose tenant_id isn't graph_tenant_id) and an
//    UnknownConnectorError; "config error: unexpected failure" for any other
//    exception while loading the config and secrets, and "error: unexpected
//    failure" for any other exception after (a failed write or flush of `out`
//    included; a failed header stops the command before restore_sample);
//    neither ever shows the exception's message;
//  - 2: "restore error: <what()>" for a connector::AuthError;
//  - 3: the same for a connector::TransientError (Veeam unreachable);
//  - 4: the same for any other connector::Error: a SafetyViolation ("restore
//    error: target guard: ..."), a NotFoundError, a NotImplementedError; also
//    "restore error: no restore points for veeam_org_name" and "restore error:
//    restore point <id> not found for veeam_org_name";
//  - 5 (exit_code::restore): the restore ran and its status is partial,
//    failed or not_run; the tables and the status line are printed;
//  - 0: status succeeded (a random shortfall included: the header names it).
// connector::Error's what() is safe to print (rp/connector.hpp). No exception
// escapes.
int run_restore_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const RestoreCommandEnv& env);

} // namespace rp
