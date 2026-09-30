#include "command_config.hpp"

#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/version.hpp>

#include "path_utf8.hpp"

#include <spdlog/sinks/stdout_sinks.h>

#include <ostream>
#include <utility>
#include <vector>

namespace rp {

bool parse_config_option(std::span<const std::string_view> args,
                         std::optional<std::string_view>& config_arg)
{
    if (args.empty()) {
        return true;
    }
    if (args.size() == 2 && args[0] == "--config") {
        config_arg = args[1];
        return true;
    }
    return false;
}

std::filesystem::path command_config_path(std::optional<std::string_view> config_arg,
                                          const std::function<std::filesystem::path()>& default_path)
{
    if (!config_arg) {
        return default_path();
    }
    std::optional<std::filesystem::path> path = path_from_utf8(*config_arg);
    if (!path) {
        throw ConfigError("", "the --config path is not valid UTF-8");
    }
    return std::move(*path);
}

std::shared_ptr<spdlog::logger> make_command_logger()
{
    auto logger = std::make_shared<spdlog::logger>(
        "rpworker", std::make_shared<spdlog::sinks::stderr_sink_mt>());
    logger->set_level(spdlog::level::warn);
    return logger;
}

std::shared_ptr<FixtureRecorder> open_recording(std::optional<std::string_view> record_arg,
                                                std::string_view command,
                                                const Secrets& secrets)
{
    if (!record_arg) {
        return nullptr;
    }
    std::optional<std::filesystem::path> dir = path_from_utf8(*record_arg);
    if (!dir) {
        throw ConfigError("--record", "the --record path is not valid UTF-8");
    }
    std::vector<std::string> known;
    for (const std::optional<std::string>* secret :
         {&secrets.veeam_password, &secrets.graph_cert_pfx_base64, &secrets.graph_cert_password}) {
        if (*secret) {
            known.push_back(**secret);
        }
    }
    return std::make_shared<FixtureRecorder>(
        std::move(*dir), "rpworker " + std::string{version()} + " " + std::string{command} +
                             " --record",
        known);
}

std::unique_ptr<IHttpClient> recorded(std::unique_ptr<IHttpClient> client,
                                      const std::shared_ptr<FixtureRecorder>& recorder,
                                      std::string service, RecordedBody body)
{
    if (!recorder || !client) {
        return client;
    }
    return std::make_unique<RecordingHttpClient>(std::move(client), recorder, std::move(service),
                                                 body);
}

int finish_recording(const FixtureRecorder* recorder, std::ostream& out, std::ostream& err,
                     int code) noexcept
{
    if (recorder == nullptr) {
        return code;
    }
    try {
        const std::vector<std::string> problems = recorder->problems();
        out << "recorded " << recorder->written() << " exchange(s) in "
            << path_to_utf8(recorder->dir()) << '\n';
        out.flush();
        for (const std::string& problem : problems) {
            err << "record error: " << problem << '\n';
        }
        return problems.empty() || code != exit_code::ok ? code : exit_code::config;
    } catch (...) {
        return code == exit_code::ok ? exit_code::config : code;
    }
}

} // namespace rp
