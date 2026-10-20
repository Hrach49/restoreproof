#include <rp/outbox_command.hpp>

#include <rp/cert_export.hpp>
#include <rp/vault.hpp>

#include <rp/cli.hpp>
#include <rp/secrets.hpp>
#include <rp/uploader.hpp>

#include "command_config.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"

#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace rp {

namespace {

// --outbox as a path, or the default root. Throws ConfigError.
std::filesystem::path root_of(std::optional<std::string_view> arg, const OutboxCommandEnv& env)
{
    if (!arg) {
        return env.default_outbox_root();
    }
    std::optional<std::filesystem::path> root = path_from_utf8(*arg);
    if (!root) {
        throw ConfigError("--outbox", "the --outbox path is not valid UTF-8");
    }
    return std::move(*root);
}

std::string or_dash(const std::optional<std::string>& text)
{
    return text ? table_cell(*text) : std::string{"-"};
}

int run_flush(const CommandOptions& options, std::ostream& out, std::ostream& err,
              const OutboxCommandEnv& env)
{
    Config config;
    std::filesystem::path root;
    std::unique_ptr<RunLock> lock;
    std::shared_ptr<FixtureRecorder> recorder;
    // Every value wiped when the command ends (the W5.1 code review's
    // finding 11).
    WipedSecrets held;
    Secrets& secrets = held.secrets;
    // One return after the handler (see signer.cpp).
    std::optional<std::string> problem;
    try {
        config = load_config(command_config_path(options.value("--config"), env.default_config_path));
        root = root_of(options.value("--outbox"), env);
        const std::filesystem::path vault = command_vault_path(
            options.value("--vault"), env.default_vault_path ? env.default_vault_path : default_vault_path);
        secrets = env.load_secrets ? env.load_secrets(vault) : read_vault(vault);
        // The one name read; the others are wiped now.
        wipe_secrets(secrets, "cloud_api_token");
        if (secrets.cloud_api_token && !secrets.cloud_api_token->empty()) {
            lock = take_outbox_flush_lock(env.take_flush_lock);
        }
        // A flush that is refused makes no recording folder.
        if (lock) {
            recorder = open_recording(options.value("--record"), "outbox flush", secrets);
        }
    } catch (const ConfigError& e) {
        problem = e.what();
    }
    if (problem) {
        err << "config error: " << *problem << '\n';
        return exit_code::config;
    }
    if (!secrets.cloud_api_token || secrets.cloud_api_token->empty()) {
        err << "outbox error: cloud_api_token is not in the vault; nothing was sent (rpworker "
               "cloud register)\n";
        return exit_code::config;
    }
    if (!lock) {
        err << "outbox error: another flush is running; nothing was done\n";
        return exit_code::transient;
    }
    const std::unique_ptr<IHttpClient> http =
        recorded(env.make_cloud_http ? env.make_cloud_http(config) : make_cloud_http_client(config),
                 recorder, "cloud");
    if (!http) {
        throw std::logic_error("no HTTP client for the Cloud");
    }
    CloudUploader uploader(*http, config.cloud_url, *secrets.cloud_api_token);
    Outbox outbox({root, env.files, nullptr});
    // An operator's flush: a run a 401 kept is tried at once.
    // --now: every queued run is due (the uninstall's last flush, W7.3's review).
    const FlushReport report =
        outbox.flush(uploader, env.wall_now ? env.wall_now() : std::chrono::system_clock::now(), {},
                     true, options.has_flag("--now"));
    for (const std::string& line : report.out) {
        out << line << '\n';
    }
    for (const std::string& line : report.err) {
        err << line << '\n';
    }
    int code = exit_code::config;
    if (report.readable) {
        out << report.queued << " queued, " << report.sent << " sent, " << report.failed
            << " failed\n";
        code = report.queued > 0 ? exit_code::transient
                                 : report.errors ? exit_code::config : exit_code::ok;
    }
    out.flush();
    return finish_recording(recorder.get(), out, err, code);
}

int run_list(const CommandOptions& options, std::ostream& out, std::ostream& err,
             const OutboxCommandEnv& env)
{
    std::filesystem::path root;
    std::optional<std::string> problem;
    try {
        root = root_of(options.value("--outbox"), env);
    } catch (const ConfigError& e) {
        problem = e.what();
    }
    if (problem) {
        err << "config error: " << *problem << '\n';
        return exit_code::config;
    }
    const OutboxListing listing = Outbox({root, env.files, nullptr}).list();
    if (!listing.readable) {
        err << "outbox error: " << table_cell(path_to_utf8(root)) << ": the outbox can't be read\n";
        return exit_code::config;
    }
    std::vector<TableRow> rows{
        {"", {"RUN", "QUEUED", "ATTEMPTS", "NEXT", "LAST_ERROR", "TIMESTAMP"}}};
    for (const QueuedRun& run : listing.queued) {
        if (!run.manifest) {
            rows.push_back({"", {table_cell(run.run_id), "-", "-", "-", "no_manifest", "-"}});
            continue;
        }
        const OutboxManifest& manifest = *run.manifest;
        const std::string stamp =
            manifest.timestamped ? std::string{"timestamped"}
                                 : manifest.timestamp_code
                                       ? "not_timestamped " + table_cell(*manifest.timestamp_code)
                                       : std::string{"not_timestamped"};
        rows.push_back({"",
                        {table_cell(run.run_id), manifest.queued_at,
                         std::to_string(manifest.attempts), or_dash(manifest.next_attempt_at),
                         or_dash(manifest.last_error), stamp}});
    }
    if (rows.size() > 1) {
        out << format_table(rows);
    }
    for (const std::string& line : listing.errors) {
        err << line << '\n';
    }
    out << listing.queued.size() << " queued, " << listing.sent << " sent, " << listing.failed
        << " failed\n";
    out.flush();
    return exit_code::ok;
}

// The options' values, none of them empty.
bool none_empty(const CommandOptions& options)
{
    for (const auto& [name, value] : options.values) {
        if (value.empty()) {
            return false;
        }
    }
    return true;
}

} // namespace

std::filesystem::path default_outbox_root()
{
    return program_data_dir() / "RestoreProof";
}

OutboxCommandEnv default_outbox_command_env()
{
    OutboxCommandEnv env;
    env.default_config_path = default_config_path;
    env.default_outbox_root = default_outbox_root;
    return env;
}

int run_outbox_command(std::span<const std::string_view> args, std::ostream& out,
                       std::ostream& err, const OutboxCommandEnv& env)
{
    if (!args.empty() && args[0] == "flush") {
        const std::optional<CommandOptions> options =
            parse_options(args.subspan(1), {"--config", "--vault", "--outbox", "--record"}, {"--now"});
        if (options && none_empty(*options)) {
            return run_flush(*options, out, err, env);
        }
    }
    if (!args.empty() && args[0] == "list") {
        const std::optional<CommandOptions> options = parse_options(args.subspan(1), {"--outbox"});
        if (options && none_empty(*options)) {
            return run_list(*options, out, err, env);
        }
    }
    err << kCliUsage;
    return exit_code::usage;
}

} // namespace rp
