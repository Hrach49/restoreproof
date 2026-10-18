#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// rpworker's exit codes, for every command (docs/worker-config.md). 64 is
// sysexits' EX_USAGE, so the codes below it can say why a command failed.
namespace exit_code {
inline constexpr int ok = 0;
// config.json missing or invalid, a --config or --vault path that isn't
// UTF-8, a vault that can't be used or a secret it doesn't hold (W4.5,
// rp::VaultError; the Graph certificate's included: a
// graph::CertificateError is a ConfigError), for `rpworker restore` and `test` also a
// canary manifest that doesn't load or isn't graph_tenant_id's and an unknown
// connector, a --record folder that isn't new or empty (or can't be made),
// a command that ran but whose --record recording isn't complete (an exchange
// refused or not written; a command that failed keeps its own code), or any
// unexpected failure (whose message is never shown), an exception no command
// handled included. For `rpworker restore` and `test` also a run whose status is
// error config, internal or result_invalid (a result that isn't valid
// restoreproof.result.v1; job_invalid, which only the service's loop gives a
// job, W4.8, is this code's too), and a pass whose output was lost; for `test` also
// a --json path refused (not UTF-8, a file already there, no such folder), a
// pass whose --json file couldn't be written, and with --evidence a run ID
// that can't name a folder, a run folder that is already there or can't be
// made, and a pass whose run folder isn't complete. For `rpworker signer` (W4.3):
// signing_key_base64 not in the vault or not a key (`public-key`), a folder
// that can't be opened or a --public-key file that can't be read or isn't an
// Ed25519 public key in PEM (`verify`), and an answer that didn't reach
// stdout. For `rpworker vault` (W4.5): a vault that can't be used, and a
// value `set` refuses. For `rpworker service` (W4.7): every "service error"
// not named under 3 (access denied, a service that isn't installed or is
// already, a step of `install` that failed, a service that stopped while
// starting, `run` in a process the Service Control Manager didn't start), an
// answer that didn't reach stdout, and, under the Service Control Manager, a
// `run` that didn't end in a clean stop (nobody reads that one: the SCM reads
// the status the service reported).
inline constexpr int config = 1;
// The service refused the credentials, the account's role, the token or a
// permission: Veeam's AuthError, Graph's AuthError and PermissionError (whose
// message names the grant the call relies on). For `restore` and `test`: status
// error backup_auth, graph_auth or graph_permission.
inline constexpr int auth = 2;
// The service couldn't be reached or asked to try later: no connection, a
// timeout, a TLS handshake failure, 502/503/504 (and Graph's 429 and other
// 5xx) after the retries (Veeam's and Graph's TransientError). For `restore`
// and `test`: status error backup_transient or graph_transient. For `rpworker
// outbox flush` (W4.6): a run is left queued, or another flush is running.
// For `rpworker service` (W4.7): not yet, and trying again may do it: the
// service still starting or still stopping when the wait is up, stopping
// when asked to start, or marked for deletion.
inline constexpr int transient = 3;
// Any other error from the service (Veeam's or Graph's NotFoundError
// included, a certificate that fails verification: TLS failures that aren't a
// broken-off handshake, a failed download, and a restore target the guard
// refuses: Graph's WrongTargetError, and the restore-target guard's
// connector::SafetyViolation, rp/target_guard.hpp), or veeam_org_name not
// among Veeam's organisations. For `restore` and `test` also: no restore
// points, a --point ID not found, and a run whose status is error with any
// code not named under 1, 2 or 3 (rp/run_status.hpp's error_codes():
// not_in_backup, no_restore_point, target_guard, backup,
// backup_infrastructure, graph, stale_target, empty_sample, not_run,
// restore_contradiction, and interrupted: the Worker was asked to stop
// during the run, W4.8). The service here is Veeam or Graph, never the
// Windows service: `rpworker service` doesn't use this code.
inline constexpr int service = 4;
// The thing tested failed. For `rpworker restore` and `rpworker test`: the
// run's status is `fail` (W3.3, rp/run_status.hpp): an item is missing or a
// mismatch, its target read fine and the backup didn't blame infrastructure
// for it. A result about the backup, not an error: a run whose status is error
// ends as 1 to 4, whatever the restore itself reported (docs/decisions.md
// 2026-10-01, W3.3). For `rpworker signer verify` (W4.3): the folder is not
// verified, "not verified: <word>" on stdout: anything wrong inside the
// folder, a missing file included (docs/decisions.md 2026-10-05, W4.3 point 4).
inline constexpr int restore = 5;
// A command line rpworker doesn't understand; for `restore` and `test` also,
// once the config or the manifest is read, every sample size 0 or a
// --canary-cursor out of the manifest's range ("usage error: ..." on stderr
// instead of the usage line).
inline constexpr int usage = 64;
} // namespace exit_code

// What rpworker prints on stderr, with exit_code::usage, for a command line it
// doesn't understand. Every command shares it.
inline constexpr std::string_view kCliUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] [--vault <file>] | "
    "rpworker vault set|remove <name> [--vault <file>] | rpworker vault list|test [--vault <file>] | "
    "rpworker vault grant <account> [--vault <file>] | "
    "rpworker veeam list [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker graph list [--hash] [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker graph certificate [--vault <file>] | "
    "rpworker client check --profile-file <file> [--vault <file>] [--record <dir>] | "
    "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] | "
    "rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] [--json <file> | --evidence <dir> [--outbox <root>]] | "
    "rpworker outbox flush [--config <path>] [--vault <file>] [--outbox <root>] "
    "[--record <dir>] | "
    "rpworker outbox list [--outbox <root>] | "
    "rpworker cloud register [--config <path>] [--vault <file>] [--name <worker name>] "
    "[--record <dir>] | "
    "rpworker signer public-key [--vault <file>] | rpworker signer new-key [--vault <file>] [--replace] | "
    "rpworker signer verify <folder> --public-key <pem file> [--tsa-ca <pem file>] | "
    "rpworker service install [--config <path>] | rpworker service uninstall|start|stop | "
    "rpworker service run [--config <path>] | "
    "rpworker doctor [--config <path>] [--vault <file>] [--client <profile file>]... "
    "[--json <file>] [--record <dir>]\n";

// rpworker's command line: `--version`, `config ...` (rp/config_check.hpp),
// `vault ...` (rp/vault_command.hpp, W4.5), `veeam ...`
// (rp/veeam_command.hpp), `graph ...` (rp/graph_command.hpp), `client ...`
// (rp/client_command.hpp, W4.10), `restore ...`
// (rp/restore_command.hpp), `test ...` (rp/test_command.hpp), `outbox ...`
// (rp/outbox_command.hpp, W4.6), `cloud ...` (rp/cloud_command.hpp, W5.1),
// `signer ...` (rp/signer_command.hpp),
// `service ...` (rp/service_command.hpp, W4.7) or `doctor ...`
// (rp/doctor_command.hpp, W7.2).
// `args` is argv without the program name, in UTF-8. Normal output goes to
// `out`, usage and errors to `err`.
// Returns the process exit code (rp::exit_code): 0 on success, 64 with
// kCliUsage on `err` for a command line it doesn't understand (or, from
// `restore` and `test`, 64 with a "usage error: ..." line for all-zero sample sizes or a
// canary cursor out of range), and the command's own code when it fails. No exception escapes: one a command lets
// out is "error: unexpected failure" on `err` and exit code 1, never a crash,
// which the runtime would end with exit code 3 (exit_code::transient).
int run_cli(std::span<const std::string_view> args, std::ostream& out,
            std::ostream& err) noexcept;

// rpworker's wmain(): `argv` is the command line as Windows passes it, in
// UTF-16 with the program name first. Converts the arguments after the
// program name to UTF-8 and runs run_cli. The narrow argv of main() is in the
// ANSI code page, which turns characters outside it into '?'. An argument
// that isn't valid UTF-16 (an unpaired surrogate) is a command line it
// doesn't understand: usage on `err`, exit code 64. No exception escapes, as
// with run_cli.
int run_main(std::span<const wchar_t* const> argv, std::ostream& out,
             std::ostream& err) noexcept;

} // namespace rp
