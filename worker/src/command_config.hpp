#pragma once

// What the commands share: the `[--config <path>]` tail of their command
// lines and the path it chooses (docs/worker-config.md), and the logger of
// the commands that call a service.

#include <spdlog/logger.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace rp {

// Whether `args` is nothing or `--config <path>`; for the latter, sets
// `config_arg` to the path as given, in UTF-8.
bool parse_config_option(std::span<const std::string_view> args,
                         std::optional<std::string_view>& config_arg);

// The config file to read: `config_arg` as a path, or, without one,
// `default_path()`, which is called only then (so --config never looks up
// ProgramData). Throws ConfigError ("the --config path is not valid UTF-8")
// for a --config path that isn't UTF-8, and whatever `default_path` throws.
std::filesystem::path command_config_path(std::optional<std::string_view> config_arg,
                                          const std::function<std::filesystem::path()>& default_path);

// The logger `veeam list` and `graph list` give their clients: warnings and
// worse, to stderr only, so no log line can land in a table on stdout. Not
// registered with spdlog, and not the default logger, which writes to stdout.
std::shared_ptr<spdlog::logger> make_command_logger();

} // namespace rp
