#include <rp/sha256.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>
#include <utility>

// FIPS 180-2 examples and a binary row (NUL and 0xFF), so the input is taken by
// length, never as a C string.
TEST_CASE("sha256_hex gives the lower-case hex SHA-256 of the bytes", "[sha256]")
{
    const auto [bytes, hex] = GENERATE(table<std::string, std::string>({
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {std::string("\0\x01\xff", 3), "26a66b061e8f48f39927c312f25293959729eee95978e2892d49d3512a5cc092"},
    }));
    CAPTURE(hex);
    CHECK(rp::sha256_hex(bytes) == hex);
}
