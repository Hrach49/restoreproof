#include <rp/veeam_command.hpp>

#include <rp/cli.hpp>
#include <rp/config.hpp>

#include "command_config.hpp"

#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <exception>
#include <optional>
#include <ostream>
#include <string>
#include <utility>

namespace rp {

namespace {

// Whether `args` are `list` or `list --config <path>`; for the latter, sets
// `config_arg` to the path as given, in UTF-8.
bool parse_list_args(std::span<const std::string_view> args,
                     std::optional<std::string_view>& config_arg)
{
    return !args.empty() && args[0] == "list" && parse_config_option(args.subspan(1), config_arg);
}

bool is_set(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty();
}

} // namespace

VeeamCommandEnv default_veeam_command_env()
{
    VeeamCommandEnv env;
    env.default_config_path = default_config_path;
    env.load_secrets = load_secrets_from_env;
    env.make_http = [](const HttpClientOptions& options) -> std::unique_ptr<IHttpClient> {
        return std::make_unique<HttpClient>(options);
    };
    // Not registered with spdlog, and not the default logger, which writes to
    // stdout.
    auto logger = std::make_shared<spdlog::logger>(
        "rpworker", std::make_shared<spdlog::sinks::stderr_sink_mt>());
    logger->set_level(spdlog::level::warn);
    env.client_options.logger = std::move(logger);
    return env;
}

int run_veeam_command(std::span<const std::string_view> args, std::ostream& out,
                      std::ostream& err, const VeeamCommandEnv& env)
{
    std::optional<std::string_view> config_arg;
    if (!parse_list_args(args, config_arg)) {
        err << kCliUsage;
        return exit_code::usage;
    }

    Config config;
    Secrets secrets;
    try {
        config = load_config(command_config_path(config_arg, env.default_config_path));
        secrets = env.load_secrets();
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return exit_code::config;
    } catch (const std::exception&) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
    }
    if (!is_set(secrets.veeam_username)) {
        err << "config error: " << kEnvVeeamUsername << " is not set\n";
        return exit_code::config;
    }
    if (!is_set(secrets.veeam_password)) {
        err << "config error: " << kEnvVeeamPassword << " is not set\n";
        return exit_code::config;
    }
    (void)out;
    return exit_code::ok;
}

} // namespace rp
