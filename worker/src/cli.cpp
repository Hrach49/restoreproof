#include <rp/cli.hpp>

#include <rp/config.hpp>
#include <rp/config_check.hpp>
#include <rp/version.hpp>

#include <ostream>

namespace rp {

int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err)
{
    if (args.size() == 1 && args[0] == "--version") {
        out << version() << '\n';
        return 0;
    }
    if (!args.empty() && args[0] == "config") {
        return run_config_command(args.subspan(1), out, err, default_config_path());
    }
    err << "usage: rpworker --version | rpworker config check [--config <path>]\n";
    return 2;
}

} // namespace rp
