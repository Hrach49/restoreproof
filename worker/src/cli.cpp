#include <rp/cli.hpp>

#include <rp/config.hpp>
#include <rp/config_check.hpp>
#include <rp/graph_command.hpp>
#include <rp/veeam_command.hpp>
#include <rp/version.hpp>

#include "utf16.hpp"

#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace rp {

namespace {

// Runs `command` and returns its exit code. An exception it lets out is
// reported without its message, which may not be safe to show, as exit code 1:
// escaping wmain it would end in abort(), whose exit code on Windows, 3, is
// exit_code::transient.
template <typename Command>
int guarded(std::ostream& err, Command&& command) noexcept
{
    try {
        return command();
    } catch (...) {
        try {
            err << "error: unexpected failure\n";
        } catch (...) {
            // Nowhere left to say it; the exit code still does.
        }
        return exit_code::config;
    }
}

int dispatch(std::span<const std::string_view> args, std::ostream& out, std::ostream& err)
{
    if (args.size() == 1 && args[0] == "--version") {
        out << version() << '\n';
        return exit_code::ok;
    }
    if (!args.empty() && args[0] == "config") {
        return run_config_command(args.subspan(1), out, err, default_config_path);
    }
    if (!args.empty() && args[0] == "veeam") {
        return run_veeam_command(args.subspan(1), out, err, default_veeam_command_env());
    }
    if (!args.empty() && args[0] == "graph") {
        return run_graph_command(args.subspan(1), out, err, default_graph_command_env());
    }
    err << kCliUsage;
    return exit_code::usage;
}

} // namespace

int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) noexcept
{
    return guarded(err, [&] { return dispatch(args, out, err); });
}

int run_main(std::span<const wchar_t* const> argv, std::ostream& out, std::ostream& err) noexcept
{
    return guarded(err, [&] {
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
    });
}

} // namespace rp
