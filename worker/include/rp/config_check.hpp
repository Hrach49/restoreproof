#pragma once

#include <filesystem>
#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// `rpworker config ...`. `args` is what follows "config" on the command line;
// the only subcommand is `check [--config <path>]`. Without --config it reads
// `default_path` (rp::run_cli passes rp::default_config_path(); tests pass a
// temp file, so they never touch ProgramData).
//
// `check` loads the config and the secrets and prints every config field and
// every secret variable, masked, to `out`. Returns 0 on success, 1 with
// "config error: <message>" on `err` when the config fails to load, and 2 with
// the usage line on `err` for arguments it doesn't understand.
int run_config_command(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                       const std::filesystem::path& default_path);

} // namespace rp
