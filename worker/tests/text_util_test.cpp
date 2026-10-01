// The text helpers VeeamClient and GraphClient share (src/text_util.hpp).

#include "../src/text_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <clocale>
#include <string>
#include <string_view>

namespace {

struct Row {
    std::string_view input;
    std::string_view expected;
};

} // namespace

TEST_CASE("joined puts the separator between names only", "[text_util]")
{
    CHECK(rp::joined({}, ", ").empty());
    CHECK(rp::joined({"subject"}, ", ") == "subject");
    CHECK(rp::joined({"subject", "sent_at", "sha256"}, ", ") == "subject, sent_at, sha256");
    CHECK(rp::joined({"subject", "sent_at"}, ",") == "subject,sent_at");
}

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

TEST_CASE("percent_decode turns each %XX into its byte and keeps a stray '%'", "[text_util]")
{
    const Row row = GENERATE(values<Row>({
        {"", ""},
        {"Restore%54arget", "RestoreTarget"},
        {"%2f%2F%c3%A9", "/\x2F\xC3\xA9"},
        {"100%", "100%"},
        {"%4", "%4"},
        {"%zz%4g", "%zz%4g"},
        {"a%20b", "a b"},
    }));
    CAPTURE(row.input);
    CHECK(rp::percent_decode(row.input) == row.expected);
}

TEST_CASE("without_controls replaces each control character with a space and never cuts", "[text_util]")
{
    CHECK(rp::without_controls("") == "");
    CHECK(rp::without_controls("Hrachya Harutyunyan") == "Hrachya Harutyunyan");
    CHECK(rp::without_controls("a\tb\x7F" "c\xC2\x9F" "d\xD8\x9C" "e\xE2\x80\x8F" "f\xE2\x80\xA8" "g\xE2\x81\xA6" "h") ==
          "a b c d e f g h");
    // Other multi-byte characters are kept.
    CHECK(rp::without_controls("\xC5\xB9r\xC3\xB3" "d\xC5\x82o") == "\xC5\xB9r\xC3\xB3" "d\xC5\x82o");
    CHECK(rp::without_controls(std::string(600, 'a')) == std::string(600, 'a'));
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

// Review of W2.2: std::tolower follows the C locale, which under a Western code
// page folds bytes above 0x7F, the parts of UTF-8 characters included.
TEST_CASE("ascii_lower and ascii_iequals fold A-Z only, whatever the locale", "[text_util]")
{
    const std::string saved = std::setlocale(LC_ALL, nullptr);
    std::setlocale(LC_ALL, ".1252");
    CHECK(rp::ascii_lower("RestoreTarget.DOCX") == "restoretarget.docx");
    CHECK(rp::ascii_lower("\xC9\xC3\x89@[`{") == "\xC9\xC3\x89@[`{");
    CHECK(rp::ascii_lower("").empty());
    CHECK(rp::ascii_iequals("RestoreTarget", "restoretarget"));
    CHECK_FALSE(rp::ascii_iequals("\xC9", "\xE9"));
    CHECK_FALSE(rp::ascii_iequals("abc", "abcd"));
    CHECK(rp::ascii_ends_with_i("report.DocX", ".docx"));
    CHECK_FALSE(rp::ascii_ends_with_i("docx", ".docx"));
    std::setlocale(LC_ALL, saved.c_str());
}
