// rpworker entry point: hands the command line to rpcore and nothing else.
// Parsing and exit codes live in rp::run_main and rp::run_cli, where rptests
// can reach them (docs/decisions.md). wmain, not main: main's argv is in the
// ANSI code page and loses any character outside it.

#include <rp/cli.hpp>

#include <cstddef>
#include <iostream>
#include <span>

int wmain(int argc, wchar_t* argv[])
{
    return rp::run_main(std::span<const wchar_t* const>(argv, static_cast<std::size_t>(argc)),
                        std::cout, std::cerr);
}
