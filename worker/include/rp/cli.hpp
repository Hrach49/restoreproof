#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// rpworker's exit codes, for every command (docs/worker-config.md). 64 is
// sysexits' EX_USAGE, so the codes below it can say why a command failed.
namespace exit_code {
inline constexpr int ok = 0;
// config.json missing or invalid, a --config path that isn't UTF-8, a secret
// variable unset or unreadable (the Graph certificate's included: a
// graph::CertificateError is a ConfigError), or any unexpected failure (whose
// message is never shown), an exception no command handled included.
inline constexpr int config = 1;
// The service refused the credentials, the account's role, the token or a
// permission: Veeam's AuthError, Graph's AuthError and PermissionError (whose
// message names the grant the call relies on).
inline constexpr int auth = 2;
// The service couldn't be reached or asked to try later: no connection, a
// timeout, a TLS handshake failure, 502/503/504 (and Graph's 429 and other
// 5xx) after the retries (Veeam's and Graph's TransientError).
inline constexpr int transient = 3;
// Any other error from the service (Veeam's or Graph's NotFoundError
// included, a certificate that fails verification: TLS failures that aren't a
// broken-off handshake, a failed download, and a restore target the guard
// refuses: Graph's WrongTargetError, and the restore-target guard's
// connector::SafetyViolation, rp/target_guard.hpp, for the command that will
// restore), or veeam_org_name not among Veeam's organisations.
inline constexpr int service = 4;
// A command line rpworker doesn't understand.
inline constexpr int usage = 64;
} // namespace exit_code

// What rpworker prints on stderr, with exit_code::usage, for a command line it
// doesn't understand. Every command shares it.
inline constexpr std::string_view kCliUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] | "
    "rpworker veeam list [--config <path>] | rpworker graph list [--hash] [--config <path>]\n";

// rpworker's command line: `--version`, `config ...` (rp/config_check.hpp),
// `veeam ...` (rp/veeam_command.hpp) or `graph ...` (rp/graph_command.hpp).
// `args` is argv without the program name, in UTF-8. Normal output goes to
// `out`, usage and errors to `err`.
// Returns the process exit code (rp::exit_code): 0 on success, 64 with
// kCliUsage on `err` for a command line it doesn't understand, and the
// command's own code when it fails. No exception escapes: one a command lets
// out is "error: unexpected failure" on `err` and exit code 1, never a crash,
// whose abort() would exit with 3 (exit_code::transient).
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
