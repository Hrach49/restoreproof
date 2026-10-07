#pragma once

// `rpworker veeam list [--config <path>] [--record <dir>]` (W1.6, Q2.1): signs
// in to Veeam, lists every organisation and its restore points as a table,
// and logs out. The output and exit codes are in docs/worker-config.md
// ("rpworker veeam list") and docs/decisions.md (2026-09-27).

#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/veeam_client.hpp>

#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <span>
#include <string_view>

namespace rp {

// What the command reaches outside itself. run_cli passes
// default_veeam_command_env(); tests pass a temp config, their own secrets, a
// FakeHttpClient and a logger they read.
struct VeeamCommandEnv {
    // The config file without --config (rp::default_config_path). Called only
    // then, and only after the arguments parsed.
    std::function<std::filesystem::path()> default_config_path;
    // The vault without --vault (rp::default_vault_path, W4.5). Called only
    // then, after the config is read.
    std::function<std::filesystem::path()> default_vault_path;
    // rp::read_vault, on the vault --vault names or the default one.
    std::function<Secrets(const std::filesystem::path& vault)> load_secrets;
    // The HTTP client for Veeam. The command fills ca_file and
    // pinned_cert_sha256 from Config::veeam_ca_file and veeam_cert_sha256 (TLS
    // is never off) and logger, sleep and jitter from `client_options`.
    std::function<std::unique_ptr<IHttpClient>(const HttpClientOptions&)> make_http;
    // Passed to VeeamClient as they are; `logger` also goes to the HTTP
    // client. Every line either logs is at debug level and redacted.
    VeeamClientOptions client_options;
};

// The real environment: rp::default_config_path, rp::default_vault_path,
// rp::read_vault, an rp::HttpClient, and a logger that writes warnings and
// worse to stderr, so no log line can land in the table on stdout.
VeeamCommandEnv default_veeam_command_env();

// `rpworker veeam ...`. `args` is what follows "veeam" on the command line,
// in UTF-8; the only subcommand is `list`, followed by `--config <path>`,
// `--vault <file>` and `--record <dir>` in any order, each at most once.
//
// Prints to `out`, as UTF-8, a table of every organisation Veeam returns
// (sorted by name, ASCII case-insensitively, then ID) with its restore points
// (newest first), the organisation named by Config::veeam_org_name marked
// with "*", then a blank line and a summary line. The table is built in full
// before anything is printed, so a Veeam failure prints nothing on `out`. Logs
// out of Veeam at the end, after the table, whatever happened after the
// sign-in.
//
// With --record <dir> (Q2.1, rp/recording_http_client.hpp), every exchange
// with Veeam is also written, scrubbed, under <dir>/veeam/ (a folder that must
// be new or empty, opened after the secrets and before any request), and
// "recorded <n> exchange(s) in <dir>" ends `out`, whatever the result; each
// exchange not written is a "record error: veeam/<file>: <why>" line on `err`,
// and turns an exit code of 0 into 1.
//
// Returns an rp::exit_code, with one line on `err` for each failure:
//  - 64: arguments it doesn't understand (rp::kCliUsage);
//  - 1: "config error: <message>" for a ConfigError (a config that doesn't
//    load, a --config or --vault path that isn't UTF-8, a vault that can't be
//    used: rp::VaultError's messages), "config error: veeam_username is not
//    in the vault" (then veeam_password)
//    for a missing secret, a --record folder that isn't new or empty or a
//    --record path that isn't UTF-8, "config error: unexpected failure" for
//    any other
//    exception while loading the config and secrets, and "error: unexpected
//    failure" for one that isn't a VeeamError afterwards (one while writing
//    the table included, after which `out` may hold part of it); neither
//    ever shows the exception's message;
//  - 2: "veeam error: <what()>" for an AuthError, 3 for a TransientError, 4
//    for any other VeeamError (a restore-point list that fails for any
//    organisation fails the command; a certificate that fails verification
//    is one too);
//  - 4 also when no organisation is named veeam_org_name: the table is
//    printed, then "veeam error: organisation <name> (veeam_org_name) not
//    found in Veeam".
// No exception escapes.
int run_veeam_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const VeeamCommandEnv& env);

} // namespace rp
