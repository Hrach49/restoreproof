#include <rp/cli.hpp>

#include <rp/config.hpp>
#include <rp/config_check.hpp>
#include <rp/version.hpp>

#include "utf16.hpp"

#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace rp {

namespace {

constexpr std::string_view kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>]\n";

} // namespace

int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err)
{
    if (args.size() == 1 && args[0] == "--version") {
        out << version() << '\n';
        return 0;
    }
    if (!args.empty() && args[0] == "config") {
        return run_config_command(args.subspan(1), out, err, default_config_path);
    }
    err << kCliUsage;
    return exit_code::usage;
}

int run_main(std::span<const wchar_t* const> argv, std::ostream& out, std::ostream& err)
{
    std::vector<std::string> utf8_args;
    for (const wchar_t* arg : argv.subspan(argv.empty() ? 0 : 1)) {
        std::optional<std::string> utf8 = utf16_to_utf8(arg);
        if (!utf8) {
            err << kCliUsage;
            return exit_code::usage;
        }
        utf8_args.push_back(std::move(*utf8));
    }
    const std::vector<std::string_view> args(utf8_args.begin(), utf8_args.end());
    return run_cli(args, out, err);
}

} // namespace rp
