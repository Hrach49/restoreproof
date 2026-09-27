// The text helpers VeeamClient and GraphClient share (src/text_util.hpp).

#include "../src/text_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>
#include <string_view>

namespace {

struct Row {
    std::string_view input;
    std::string_view expected;
};

} // namespace

TEST_CASE("form_encode percent-encodes every byte but letters, digits and -._~", "[text_util]")
{
    const Row row = GENERATE(values<Row>({
        {"", ""},
        {"AZaz09-._~", "AZaz09-._~"},
        {" ", "%20"},
        {"+&=%", "%2B%26%3D%25"},
        {"a b/c?d#e", "a%20b%2Fc%3Fd%23e"},
        {"urn:ietf:params", "urn%3Aietf%3Aparams"},
        {"\xC3\xA9", "%C3%A9"},
        {std::string_view("\0\x7F\xFF", 3), "%00%7F%FF"},
    }));
    CAPTURE(row.input);
    CHECK(rp::form_encode(row.input) == row.expected);
}

TEST_CASE("one_line replaces control characters with a space", "[text_util]")
{
    const Row row = GENERATE(values<Row>({
        {"plain text", "plain text"},
        {"a\r\nb\tc", "a  b c"},
        {"x\x7Fy", "x y"},
        // NEL (U+0085), the line separator (U+2028) and a bidi override (U+202E).
        {"a\xC2\x85" "b\xE2\x80\xA8" "c\xE2\x80\xAE" "d", "a b c d"},
        // Other non-ASCII text is kept.
        {"\xC3\xA9t\xC3\xA9", "\xC3\xA9t\xC3\xA9"},
    }));
    CAPTURE(row.input);
    CHECK(rp::one_line(row.input) == row.expected);
}

TEST_CASE("one_line cuts at 500 bytes by default, never inside a UTF-8 character", "[text_util]")
{
    static_assert(rp::kOneLineMaxBytes == 500);
    CHECK(rp::one_line(std::string(500, 'a')) == std::string(500, 'a'));
    CHECK(rp::one_line(std::string(501, 'a')) == std::string(500, 'a') + "...");
    // A two-byte character straddling the cut is dropped whole.
    const std::string straddling = std::string(499, 'a') + "\xC3\xA9" + "b";
    CHECK(rp::one_line(straddling) == std::string(499, 'a') + "...");
}

TEST_CASE("one_line takes a smaller limit", "[text_util]")
{
    CHECK(rp::one_line("abcdef", 3) == "abc...");
    CHECK(rp::one_line("abc", 3) == "abc");
    CHECK(rp::one_line("a\nbcdef", 4) == "a bc...");
    CHECK(rp::one_line("\xE2\x82\xAC\xE2\x82\xAC", 4) == "\xE2\x82\xAC...");
    CHECK(rp::one_line("abc", 0) == "...");
    CHECK(rp::one_line("", 0).empty());
}
