#pragma once

// `rpworker client check --profile-file <file> [--vault <file>] [--record
// <dir>]` (W4.10, docs/decisions.md 2026-10-09 point 6): reads a client
// profile (rp/client_profile.hpp) from a file and lists its three restore
// targets through the Worker's app, as `rpworker graph list` lists the
// config's, so a profile the Cloud will dispatch can be checked at a prompt
// before any job carries it. Reads only. No --config: nothing of the config
// reaches a Graph call (Graph is trusted through the Windows store, the
// certificate is the vault's), so the command reads none. The output and
// exit codes are in docs/worker-config.md ("rpworker client check").

#include <rp/graph_command.hpp>

#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// `rpworker client ...`. `args` is what follows "client" on the command line,
// in UTF-8; the only subcommand is `check`, followed by `--profile-file
// <file>` (required; an empty value is a missing one), `--vault <file>` and
// `--record <dir>` in any order, each at most once.
//
// In this order: the profile file (rp::read_client_profile_file); the vault
// (--vault, or env.default_vault_path) and the Worker app's certificate, as
// `graph list` opens them; --record; then the three restore targets of the
// profile listed as `graph list` lists them without --hash (each file
// target's guard first, the mailbox's check first too, nothing downloaded).
// Prints to `out`, as UTF-8, only once everything is read:
//
//   client profile: veeam_org_name <org>, tenant <guid>, app <guid>
//   <blank line>
//   <graph list's three tables and its summary line>
//
// With --record <dir>, as `graph list --record`: the exchanges under
// <dir>/graph, "recorded <n> exchange(s) in <dir>" last.
//
// Returns an rp::exit_code, with one line on `err` for each failure, `graph
// list`'s:
//  - 64: arguments it doesn't understand (rp::kCliUsage), --profile-file
//    missing or empty included;
//  - 1: "config error: --profile-file <file>: <problem>" for a profile file
//    that can't be used (can't be read, over 64 KiB, not JSON, not a
//    restoreproof.client-profile.v1 document, key "<key>" <its problem>, has
//    a key that isn't the profile's), before the vault is read; "config
//    error: <message>" for a vault that can't be used, a secret that isn't
//    in it or a certificate that doesn't open, and a --record folder that
//    isn't new or empty; "error: unexpected failure" for any other exception
//    afterwards;
//  - 2: "graph error: <what()>" for a graph::AuthError or PermissionError,
//    whose message names the grant the call relies on: a target the app
//    can't reach names the missing grant;
//  - 3: the same for a graph::TransientError;
//  - 4: the same for any other graph::GraphError: a NotFoundError (a missing
//    mailbox, drive or folder), a WrongTargetError (the guard refused: the
//    profile names something that isn't a RestoreTarget), an unexpected
//    answer.
// env.default_config_path is never called. No exception escapes.
int run_client_command(std::span<const std::string_view> args, std::ostream& out,
                       std::ostream& err, const GraphCommandEnv& env);

} // namespace rp
