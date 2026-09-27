#include <rp/veeam_command.hpp>

#include <rp/cli.hpp>
#include <rp/config.hpp>

#include "command_config.hpp"

#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <exception>
#include <memory>
#include <optional>
#include <ostream>
#include <stdexcept>
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

// what() is safe to print: VeeamError's message went through rp::redact().
int report_veeam_error(std::ostream& err, const VeeamError& e, int code)
{
    err << "veeam error: " << e.what() << '\n';
    return code;
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
    HttpClientOptions http_options;
    // TLS is never off: the CA file and the pin only choose what to trust.
    http_options.ca_file = config.veeam_ca_file;
    http_options.pinned_cert_sha256 = config.veeam_cert_sha256;
    http_options.logger = env.client_options.logger;
    http_options.sleep = env.client_options.sleep;
    http_options.jitter = env.client_options.jitter;

    // Declared in this order so the client, which holds a reference to the
    // HTTP client, goes first.
    std::unique_ptr<IHttpClient> http;
    std::unique_ptr<VeeamClient> client;
    int code = exit_code::ok;
    try {
        http = env.make_http(http_options);
        if (!http) {
            throw std::logic_error("no HTTP client");
        }
        client = std::make_unique<VeeamClient>(*http, config.veeam_url, *secrets.veeam_username,
                                               *secrets.veeam_password, env.client_options);
        for (const Organization& org : client->list_organizations()) {
            client->list_restore_points(org.id);
        }
    } catch (const AuthError& e) {
        code = report_veeam_error(err, e, exit_code::auth);
    } catch (const TransientError& e) {
        code = report_veeam_error(err, e, exit_code::transient);
    } catch (const VeeamError& e) {
        code = report_veeam_error(err, e, exit_code::veeam);
    } catch (const std::exception&) {
        // Its message may not be safe to show.
        err << "error: unexpected failure\n";
        code = exit_code::config;
    }
    if (client) {
        client->logout();
    }
    (void)out;
    return code;
}

} // namespace rp
