#include "command_config.hpp"

#include <rp/config.hpp>

#include "path_utf8.hpp"

#include <spdlog/sinks/stdout_sinks.h>

#include <utility>

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

} // namespace rp
