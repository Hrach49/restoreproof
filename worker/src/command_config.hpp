#pragma once

// What the commands share: parsing their options, the path `--config`
// chooses (docs/worker-config.md), the logger of the commands that call a
// service, and their `--record <dir>` (Q2.1).

#include <rp/http_client.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/secrets.hpp>

#include <spdlog/logger.h>

#include <filesystem>
#include <functional>
#include <initializer_list>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>

namespace rp {

// A command's options as parse_options found them, each as given (UTF-8).
struct CommandOptions {
    std::map<std::string_view, std::string_view, std::less<>> values;
    std::set<std::string_view, std::less<>> flags;

    // The value given for `name`, or nullopt.
    std::optional<std::string_view> value(std::string_view name) const;
    bool has_flag(std::string_view name) const;
};

// `args` (the words after the command's name) as options in any order, each
// at most once: a name in `value_names` takes the word after it as its value,
// whatever that word is; a name in `flag_names` stands alone. nullopt for
// anything else: another word, an option twice, a value missing.
std::optional<CommandOptions> parse_options(std::span<const std::string_view> args,
                                            std::initializer_list<std::string_view> value_names,
                                            std::initializer_list<std::string_view> flag_names = {});

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

// `--record <dir>` (Q2.1): nullptr without it; otherwise the recorder for
// `command` ("veeam list", ...), its files' source "rpworker <version>
// <command> --record", with the Veeam password and the Graph certificate and
// its password as secrets it must never write. Throws ConfigError for a path
// that isn't UTF-8 ("the --record path is not valid UTF-8") and whatever
// FixtureRecorder throws (a folder that isn't new or empty).
std::shared_ptr<FixtureRecorder> open_recording(std::optional<std::string_view> record_arg,
                                                std::string_view command,
                                                const Secrets& secrets);

// `client`, recording under `service` when `recorder` isn't null (and
// `client` isn't: a null client stays null, for the caller's own check).
std::unique_ptr<IHttpClient> recorded(std::unique_ptr<IHttpClient> client,
                                      const std::shared_ptr<FixtureRecorder>& recorder,
                                      std::string service,
                                      RecordedBody body = RecordedBody::content);

// `code`, but exit_code::config for a command that succeeded with an
// exchange not written (so far), or whose recording can't say. Without a
// recorder, `code`. finish_recording's rule, for an exit code known before it
// runs (W3.6's --json summary). Never throws.
int recorded_exit_code(const FixtureRecorder* recorder, int code) noexcept;

// After a command with --record: "recorded <n> exchange(s) in <dir>" on `out`
// and one "record error: <problem>" line per exchange not written on `err`.
// Returns recorded_exit_code(recorder, code). Without a recorder, prints
// nothing. Never throws.
int finish_recording(const FixtureRecorder* recorder, std::ostream& out, std::ostream& err,
                     int code) noexcept;

} // namespace rp
