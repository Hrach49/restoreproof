#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// rpworker's command line: `--version` or `config ...` (rp/config_check.hpp).
// `args` is argv without the program name. Normal output goes to `out`, usage
// and errors to `err`. Returns the process exit code: 0 on success, 1 when the
// command fails (e.g. the config doesn't load), 2 for a command line it
// doesn't understand.
int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

} // namespace rp
