// rpworker entry point. Lives outside src/ so it isn't counted against rpcore
// coverage (docs/decisions.md); keep it a thin call into rpcore.

#include <rp/version.hpp>

#include <iostream>
#include <string_view>

int main(int argc, char* argv[])
{
    if (argc == 2 && std::string_view{argv[1]} == "--version") {
        std::cout << rp::version() << '\n';
        return 0;
    }
    std::cerr << "usage: rpworker --version\n";
    return 2;
}
