#include <rp/cli.hpp>

#include <rp/version.hpp>

#include <ostream>

namespace rp {

int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err)
{
    if (args.size() == 1 && args[0] == "--version") {
        out << version() << '\n';
        return 0;
    }
    err << "usage: rpworker --version\n";
    return 2;
}

} // namespace rp
