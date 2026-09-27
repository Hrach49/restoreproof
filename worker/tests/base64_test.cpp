#include <rp/base64.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::optional<std::string> decode(std::string_view text)
{
    const auto bytes = rp::base64_decode(text);
    if (!bytes) {
        return std::nullopt;
    }
    return std::string(bytes->begin(), bytes->end());
}

struct Row {
    std::string_view plain;
    std::string_view encoded;
};

} // namespace

// Failure paths first. Strict: the standard alphabet only, padding to a
// multiple of four, nothing else. A PFX pasted with a line break or run
// through a base64url encoder is refused rather than half-read.
TEST_CASE("base64_decode refuses anything but strict padded standard Base64", "[base64]")
{
    const std::string_view text = GENERATE(values<std::string_view>({
        // Length not a multiple of four (padding missing or short).
        "Zg",
        "Zg=",
        "Zm9vYg",
        "Zm9vYmE",
        "A",
        // Too much padding, or padding in the middle.
        "Z===",
        "====",
        "Zg==Zg==",
        "Zm=v",
        "=Zm9",
        "Zg==\n",
        // Whitespace anywhere.
        " Zm9v",
        "Zm9v ",
        "Zm9v\nYmFy",
        "Zm9v\r\n",
        "Zm\t9v",
        // Characters outside the standard alphabet: base64url, and others.
        "Zm-v",
        "Zm_v",
        "Zm9v!A==",
        "Zm9v.A==",
        "\xC3\xA9Zm9",
        std::string_view("Zm\0v", 4),
        // Non-canonical: unused bits after the last character not zero.
        "Zh==",
        "Zm9=",
        "Zm9vYh==",
        "Zm9vYmF=",
    }));
    CAPTURE(text);
    CHECK_FALSE(rp::base64_decode(text).has_value());
}

// RFC 4648 section 10.
TEST_CASE("base64_decode decodes the RFC 4648 test vectors", "[base64]")
{
    const Row row = GENERATE(values<Row>({
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    }));
    CAPTURE(row.encoded);
    CHECK(decode(row.encoded) == std::string(row.plain));
}

TEST_CASE("base64_decode reads every byte value and both alphabet ends", "[base64]")
{
    // "+/" and "AZaz09": every class of the alphabet.
    CHECK(decode("+/+/") == std::string("\xFB\xFF\xBF"));
    CHECK(decode("AAAA") == std::string(3, '\0'));
    CHECK(decode("////") == std::string(3, '\xFF'));
    const auto az = rp::base64_decode("QVphejA5");
    REQUIRE(az.has_value());
    CHECK(std::string(az->begin(), az->end()) == "AZaz09");

    std::vector<unsigned char> all;
    for (int i = 0; i < 256; ++i) {
        all.push_back(static_cast<unsigned char>(i));
    }
    // base64url of every byte, turned into standard Base64 with padding.
    std::string encoded = rp::base64url_encode(all);
    for (char& c : encoded) {
        c = c == '-' ? '+' : c == '_' ? '/' : c;
    }
    while (encoded.size() % 4 != 0) {
        encoded += '=';
    }
    CHECK(rp::base64_decode(encoded) == all);
}

TEST_CASE("base64url_encode uses - and _ and no padding", "[base64]")
{
    const Row row = GENERATE(values<Row>({
        {"", ""},
        {"f", "Zg"},
        {"fo", "Zm8"},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg"},
        {"fooba", "Zm9vYmE"},
        {"foobar", "Zm9vYmFy"},
        // {"alg":"PS256"}: the start of every JWT header.
        {R"({"alg":"PS256"})", "eyJhbGciOiJQUzI1NiJ9"},
        {"\xFB\xFF\xBF", "-_-_"},
        {"\xFB\xFF", "-_8"},
        {"\xFF", "_w"},
    }));
    CAPTURE(row.plain);
    CHECK(rp::base64url_encode(row.plain) == row.encoded);
}

TEST_CASE("base64url_encode takes bytes as well as text", "[base64]")
{
    const std::vector<unsigned char> bytes{0x00, 0xFB, 0xFF};
    CHECK(rp::base64url_encode(bytes) == "APv_");
    CHECK(rp::base64url_encode(std::vector<unsigned char>{}).empty());
}
