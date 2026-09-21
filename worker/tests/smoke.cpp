#include <catch2/catch_test_macros.hpp>

#include <string_view>

TEST_CASE("toolchain builds C++20 and runs Catch2 tests", "[smoke]")
{
    // starts_with is C++20: this fails to compile if the standard flag is lost.
    REQUIRE(std::string_view{"restoreproof"}.starts_with("restore"));
}
