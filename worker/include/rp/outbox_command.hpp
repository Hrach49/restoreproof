#pragma once

// `rpworker outbox flush` and `rpworker outbox list` (W4.6, docs/decisions.md
// 2026-10-07 point 5): what an operator, and until W4.8 a scheduled task, runs
// to send the queued runs and to see the queue. Neither reads the vault: the
// upload carries no credential until W5.1.

#include <rp/config.hpp>
#include <rp/http_client.hpp>
#include <rp/outbox.hpp>
#include <rp/run_lock.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <span>
#include <string_view>

namespace rp {

// What the commands reach outside themselves. run_cli passes
// default_outbox_command_env(); tests pass temp folders, a fake HTTP client, a
// clock and a fake mutex.
struct OutboxCommandEnv {
    // The config file without --config (rp::default_config_path): `flush`
    // only, called only then.
    std::function<std::filesystem::path()> default_config_path;
    // The outbox's root without --outbox (rp::default_outbox_root). Called
    // only then.
    std::function<std::filesystem::path()> default_outbox_root;
    // Makes the HTTP client the Cloud is reached through; null = an
    // rp::HttpClient that trusts the Windows store, or config's cloud_ca_file
    // in its place, with the commands' logger. With --record its exchanges go
    // under "cloud".
    std::function<std::unique_ptr<IHttpClient>(const Config&)> make_cloud_http;
    // The wall clock a flush goes by; null = system_clock::now.
    std::function<std::chrono::system_clock::time_point()> wall_now;
    // Takes the flush mutex without waiting: the lock, or null when another
    // flush holds it; null = rp::try_take_named_lock(rp::kOutboxMutex). One
    // whose last holder ended without releasing it (rp::AbandonedRunLock) is
    // taken again at once: a flush that died left nothing half done.
    std::function<std::unique_ptr<RunLock>()> take_flush_lock;
    // The outbox's file calls; each null = the real one.
    OutboxFiles files;
};

// %ProgramData%\RestoreProof: outbox\ and sent\ are under it. Throws
// ConfigError if Windows can't resolve ProgramData.
std::filesystem::path default_outbox_root();

// The real environment.
OutboxCommandEnv default_outbox_command_env();

// `rpworker outbox ...`. `args` is what follows "outbox", in UTF-8.
//
// `flush [--config <path>] [--outbox <root>] [--record <dir>]`: one pass of
// rp::Outbox::flush with rp::CloudUploader on config's cloud_url. On `out`:
// each of the flush's lines ("pruned <run>", "sent <run>", "kept <run>:
// <code>; attempt <n>, next at <time>", "kept <run>: folder_changed",
// "waiting <run>: next at <time>", "moved <run>"), then "<n> queued, <m>
// sent"; on `err` its "outbox error: ..." and "outbox warning: ..." lines.
// Exit 0 when no run is left under outbox\; 3 (exit_code::transient) when one
// is, or when another flush holds the mutex ("outbox error: another flush is
// running; nothing was done"); 1 for "config error: <what()>" (the config, a
// --config, --outbox or --record path that isn't UTF-8, a --record folder
// that isn't new or empty), for a root that can't be read ("outbox error:
// <root>: the outbox can't be read", no count line), for an incomplete
// recording, and, when nothing stays queued, for any other "outbox error"
// line.
//
// `list [--outbox <root>]`: reads only. A table, one row per queued run, RUN
// QUEUED ATTEMPTS NEXT LAST_ERROR TIMESTAMP ("-" for a null; TIMESTAMP
// "timestamped", "not_timestamped" or "not_timestamped <code>"; a run without
// a readable manifest is "-" in every cell but RUN and LAST_ERROR
// "no_manifest"), no table when nothing is queued, then "<n> queued, <m>
// sent". On `err` one "outbox error: <folder>: no result.json; not a queued
// run" per folder under outbox\ that isn't a run. Exit 0; 1 for a root that
// can't be read or a --outbox path that isn't UTF-8.
//
// 64 with rp::kCliUsage on `err` for anything else: no subcommand, an unknown
// one, an option of the other subcommand, an option twice or without its
// value, an empty value. A ConfigError is the only exception caught: what
// else is thrown is run_cli's "error: unexpected failure".
int run_outbox_command(std::span<const std::string_view> args, std::ostream& out,
                       std::ostream& err, const OutboxCommandEnv& env);

} // namespace rp
