#include <rp/cli.hpp>
#include <rp/version.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using Args = std::vector<std::string_view>;

TEST_CASE("rpworker prints usage to stderr and exits 2 for anything but a lone --version", "[cli]")
{
    const Args args = GENERATE(
        Args{},
        Args{"--no-such-option"},
        Args{""},
        Args{"-v"},
        Args{"version"},
        Args{"--VERSION"},
        Args{"--version", "extra"},
        Args{"extra", "--version"},
        Args{"--version", "--version"});
    CAPTURE(args);

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 2);
    REQUIRE(out.str().empty());
    REQUIRE(err.str() == "usage: rpworker --version\n");
}

TEST_CASE("rpworker --version prints the project version to stdout and exits 0", "[cli]")
{
    const Args args{"--version"};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 0);
    REQUIRE(out.str() == std::string{rp::version()} + "\n");
    REQUIRE(err.str().empty());
}
