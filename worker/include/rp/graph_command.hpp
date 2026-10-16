#pragma once

// `rpworker graph list [--hash] [--config <path>] [--record <dir>]` (W2.3,
// Q2.1): what is in the three restore targets right now, read through Graph
// with W2.2's rp::graph::TargetReader and printed as three tables. The
// operator's check before and after a restore. Reads only. The output and
// exit codes are in docs/worker-config.md ("rpworker graph list") and
// docs/decisions.md (2026-09-28, W2.3).

#include <rp/graph_client.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>

#include <spdlog/logger.h>

#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <span>
#include <string_view>

namespace rp {

// What the command reaches outside itself. run_cli passes
// default_graph_command_env(); tests pass a temp config, their own secrets,
// FakeHttpClients and a logger they read.
struct GraphCommandEnv {
    // The config file without --config (rp::default_config_path). Called only
    // then, and only after the arguments parsed.
    std::function<std::filesystem::path()> default_config_path;
    // The vault without --vault (rp::default_vault_path, W4.5). Called only
    // then, after the config is read.
    std::function<std::filesystem::path()> default_vault_path;
    // rp::read_vault, on the vault --vault names or the default one.
    std::function<Secrets(const std::filesystem::path& vault)> load_secrets;
    // The HTTP client for Graph and Entra, the token's only road:
    // rp::graph::make_graph_http_client, called with client_options.logger.
    std::function<std::unique_ptr<IHttpClient>(std::shared_ptr<spdlog::logger>)> make_graph_http;
    // The HTTP client for downloads, which never carries the token:
    // rp::graph::make_download_http_client. Called only with --hash.
    std::function<std::unique_ptr<IHttpClient>()> make_download_http;
    // Passed to GraphClient as they are, but a null `logger` is replaced by
    // make_command_logger()'s (warnings and worse, to stderr), never spdlog's
    // default logger, which writes to stdout. The logger also goes to the Graph
    // HTTP client, the certificate's loading, the reader and its downloads;
    // `wall_now` (null: system_clock::now) is also the time the certificate
    // must be valid at.
    graph::GraphClientOptions client_options;
};

// The real environment: rp::default_config_path, rp::default_vault_path,
// rp::read_vault, the two Graph HTTP clients, and a logger that writes
// warnings and worse to stderr, so no log line can land in the tables on
// stdout.
GraphCommandEnv default_graph_command_env();

// `rpworker graph ...`. `args` is what follows "graph" on the command line, in
// UTF-8: `list`, followed by `--hash`, `--config <path>`, `--vault <file>` and
// `--record <dir>` in any order, each at most once; or `certificate [--vault
// <file>]`.
//
// `certificate` (W7.0, docs/decisions.md 2026-10-16 point 4): opens the vault's
// Graph certificate as the sign-in does (graph::certificate_from_secrets, the
// same refusals as `list`'s "config error: ..." lines, exit 1) and prints its
// public half alone on `out`, one PEM "CERTIFICATE" block, then
// "thumbprint <SHA-1> (SHA-1), expires <YYYY-MM-DDTHH:MM:SSZ>" on `err`; exit 0.
// No config is read and nothing is sent. The PFX, its password and the key
// never reach either stream. What a client tenant's app registration gets
// (tools/tenant-setup).
//
// Signs in to Graph as the Worker app (graph_tenant_id, graph_client_id, and
// the certificate from the vault's graph_cert_pfx_base64 and
// graph_cert_password),
// lists the test mailbox's Inbox, the RestoreTarget library and the test
// OneDrive's RestoreTarget folder (each file target's guard first), and prints
// to `out`, as UTF-8, three tables in that order: each a heading line with the
// location and its count ("Mail (<test_mailbox>, Inbox): 2 item(s)"), then, if
// it holds anything, a column header and one row per item in Graph's order.
// Mail: RECEIVED, SENDER, SUBJECT, ID; files: NAME, SIZE, ID ("-" for a
// missing or empty value, "(no subject)" for a missing or empty subject). Under
// a file target's rows (under its heading when it lists none), "  (<n>
// folder(s) or other entries not listed)" when its listing left any out
// (W3.4), so a location showing zero items really holds nothing. With --hash each
// file is downloaded (without the token) and both kinds get SHA256 and RULE
// ("text-v1" for mail, "bytes" for files); without it nothing is downloaded
// and SIZE is Graph's. A blank line after each table, then a summary line.
// Graph's text goes through table_cell(): a control character becomes a
// space. The tables are built in full before anything is printed, so a
// failure prints nothing on `out`.
//
// With --record <dir> (Q2.1, rp/recording_http_client.hpp), every exchange
// with Entra and Graph (under "graph") and each download (under "download",
// as its size and SHA-256 only) is also written, scrubbed, under
// <dir>/<service>/ (a folder that must be new or empty, opened after the
// secrets and before any request), and "recorded <n> exchange(s) in <dir>"
// ends `out`, whatever the result; each exchange not written is a "record
// error: <service>/<file>: <why>" line on `err`, and turns an exit code of 0
// into 1.
//
// Returns an rp::exit_code, with one line on `err` for each failure:
//  - 64: arguments it doesn't understand (rp::kCliUsage);
//  - 1: "config error: <message>" for a ConfigError (a config that doesn't
//    load, a --config or --vault path that isn't UTF-8, a vault that can't be
//    used (rp::VaultError's messages), and a graph::CertificateError:
//    "graph_cert_pfx_base64 is not in the vault", a PFX
//    that doesn't open, a certificate that isn't valid, and a --record folder
//    that isn't new or empty), "config error:
//    unexpected failure" for any other exception while loading the config,
//    secrets and certificate, and "error: unexpected failure" for one that
//    isn't a graph::GraphError afterwards (a failed write or flush of `out`
//    included, exceptions on or off); neither ever shows the exception's message;
//  - 2: "graph error: <what()>" for a graph::AuthError or PermissionError
//    (whose message names the grant the call relies on);
//  - 3: the same for a graph::TransientError;
//  - 4: the same for any other graph::GraphError: a NotFoundError (a missing
//    mailbox, drive or folder), a WrongTargetError (the guard refused a drive
//    or folder), a failed download, an unexpected answer.
// No exception escapes.
int run_graph_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const GraphCommandEnv& env);

} // namespace rp
