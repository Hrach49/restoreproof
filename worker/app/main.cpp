// rpworker entry point: hands argv to rpcore and nothing else. Parsing and
// exit codes live in rp::run_cli, where rptests can reach them
// (docs/decisions.md).

#include <rp/cli.hpp>

#include <iostream>
#include <string_view>
#include <vector>

int main(int argc, char* argv[])
{
    const std::vector<std::string_view> args(argv + (argc > 0 ? 1 : 0), argv + argc);
    return rp::run_cli(args, std::cout, std::cerr);
}
