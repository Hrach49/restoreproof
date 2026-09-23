#pragma once

#include <filesystem>
#include <functional>
#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// `rpworker config ...`. `args` is what follows "config" on the command line,
// in UTF-8; the only subcommand is `check [--config <path>]`. A --config path
// that isn't valid UTF-8 fails the check ("config error: the --config path is
// not valid UTF-8"). Without --config it reads
// the path `default_path` returns (rp::run_cli passes rp::default_config_path;
// tests pass a temp file, so they never touch ProgramData). It is called only
// then, so usage errors and --config never look up ProgramData.
//
// `check` loads the config and the secrets and prints every config field and
// every secret variable, masked, to `out`. Returns 0 on success, 2 with the
// usage line on `err` for arguments it doesn't understand, and 1 when the
// check fails: "config error: <message>" on `err` for a ConfigError (including
// one from `default_path`), "config error: unexpected failure" for any other
// exception, whose message is never shown. No exception escapes.
int run_config_command(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                       const std::function<std::filesystem::path()>& default_path);

} // namespace rp
