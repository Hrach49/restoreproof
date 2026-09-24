#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// rpworker's command line: `--version` or `config ...` (rp/config_check.hpp).
// `args` is argv without the program name, in UTF-8. Normal output goes to
// `out`, usage and errors to `err`. Returns the process exit code: 0 on
// success, 1 when the command fails (e.g. the config doesn't load), 2 for a
// command line it doesn't understand.
int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

// rpworker's wmain(): `argv` is the command line as Windows passes it, in
// UTF-16 with the program name first. Converts the arguments after the
// program name to UTF-8 and runs run_cli. The narrow argv of main() is in the
// ANSI code page, which turns characters outside it into '?'. An argument
// that isn't valid UTF-16 (an unpaired surrogate) is a command line it
// doesn't understand: usage on `err`, exit code 2.
int run_main(std::span<const wchar_t* const> argv, std::ostream& out, std::ostream& err);

} // namespace rp
