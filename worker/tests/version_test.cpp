#include <rp/version.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string_view>

TEST_CASE("rpcore reports the project version", "[version]")
{
    // RP_VERSION comes from project(VERSION ...) in worker/CMakeLists.txt.
    REQUIRE(rp::version() == std::string_view{RP_VERSION});
}

TEST_CASE("rpcore version is a dotted major.minor.patch triple", "[version]")
{
    const std::string_view v = rp::version();
    REQUIRE_FALSE(v.empty());
    REQUIRE(std::count(v.begin(), v.end(), '.') == 2);
}
