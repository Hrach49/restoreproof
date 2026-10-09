#include <rp/client_command.hpp>

#include <rp/cli.hpp>
#include <rp/client_assertion.hpp>
#include <rp/client_profile.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>

#include "command_config.hpp"
#include "path_utf8.hpp"
#include "target_listing.hpp"
#include "text_table.hpp"

#include <chrono>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

namespace rp {

namespace {

// `check --profile-file <file> [--vault <file>] [--record <dir>]`'s options;
// nullopt for any other command line, a missing or empty --profile-file
// included (no file has an empty name).
std::optional<CommandOptions> parse_check_args(std::span<const std::string_view> args)
{
    if (args.empty() || args[0] != "check") {
        return std::nullopt;
    }
    std::optional<CommandOptions> options =
        parse_options(args.subspan(1), {"--profile-file", "--vault", "--record"});
    if (!options) {
        return std::nullopt;
    }
    const std::optional<std::string_view> file = options->value("--profile-file");
    if (!file || file->empty()) {
        return std::nullopt;
    }
    return options;
}

// The first line: what the profile names, so the tables below are read as
// that client's. IDs and the organisation's name, never a secret.
std::string heading_of(const ClientProfile& profile)
{
    return std::format("client profile: veeam_org_name {}, tenant {}, app {}\n\n",
                       table_cell(profile.veeam_org_name), profile.graph_tenant_id,
                       profile.graph_client_id);
}

// The command but for what --record wrote, which run_client_command prints
// last: `recorder` is set once the recording is open.
int run_check(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
              const GraphCommandEnv& env, std::shared_ptr<FixtureRecorder>& recorder)
{
    const std::optional<CommandOptions> options = parse_check_args(args);
    if (!options) {
        err << kCliUsage;
        return exit_code::usage;
    }
    const std::string_view file_arg = *options->value("--profile-file");
    const std::optional<std::string_view> vault_arg = options->value("--vault");
    const std::optional<std::string_view> record_arg = options->value("--record");

    // Never spdlog's default logger, which writes to stdout, where the tables are.
    graph::GraphClientOptions client_options = env.client_options;
    if (!client_options.logger) {
        client_options.logger = make_command_logger();
    }
    ClientProfile profile;
    std::optional<graph::ClientCertificate> certificate;
    try {
        // The profile first: a file that can't be used costs no vault read.
        const std::optional<std::filesystem::path> file = path_from_utf8(file_arg);
        if (!file) {
            throw ConfigError("--profile-file", "--profile-file " + table_cell(file_arg) +
                                                    ": not a UTF-8 path");
        }
        profile = read_client_profile_file(*file);
        const auto wall_now = client_options.wall_now ? client_options.wall_now()
                                                      : std::chrono::system_clock::now();
        // As `graph list` opens them: a CertificateError is a ConfigError.
        const Secrets secrets =
            env.load_secrets(command_vault_path(vault_arg, env.default_vault_path));
        certificate = graph::certificate_from_secrets(secrets, wall_now, client_options.logger);
        recorder = open_recording(record_arg, "client check", secrets);
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return exit_code::config;
    } catch (...) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
    }
    return list_restore_targets(profile, false, heading_of(profile), std::move(*certificate),
                                client_options, env, recorder, out, err);
}

} // namespace

int run_client_command(std::span<const std::string_view> args, std::ostream& out,
                       std::ostream& err, const GraphCommandEnv& env)
{
    std::shared_ptr<FixtureRecorder> recorder;
    const int code = run_check(args, out, err, env, recorder);
    return finish_recording(recorder.get(), out, err, code);
}

} // namespace rp
