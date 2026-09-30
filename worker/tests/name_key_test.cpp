// The name key (src/name_key.hpp, W2.6 review): SharePoint and OneDrive
// compare file names case-insensitively across Unicode, so the sampler's
// same-name skip and restore_sample's same-name refusal fold every letter's
// case, not only A-Z. Non-ASCII text is spelled in UTF-8 escapes: the source
// is compiled without /utf-8.

#include "../src/name_key.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>

namespace {

// "Zrodla.docx" with Polish letters: Z-acute, o-acute, l-stroke.
const std::string kUpperZrodla = "\xC5\xB9r\xC3\xB3" "d\xC5\x82" "a.docx"; // Źródła.docx
const std::string kLowerZrodla = "\xC5\xBAr\xC3\xB3" "d\xC5\x82" "a.docx"; // źródła.docx
const std::string kShoutZrodla = "\xC5\xB9R\xC3\x93" "D\xC5\x81" "A.DOCX"; // ŹRÓDŁA.DOCX

} // namespace

TEST_CASE("name_key: names equal but for the case of any letter share a key", "[name-key]")
{
    const auto [a, b] = GENERATE_COPY(table<std::string, std::string>({
        {"Report.docx", "REPORT.DOCX"},
        {"report.docx", "Report.Docx"},
        {kUpperZrodla, kLowerZrodla},
        {kLowerZrodla, kShoutZrodla},
        // Cyrillic: "Отчёт.pdf" and "ОТЧЁТ.pdf".
        {"\xD0\x9E\xD1\x82\xD1\x87\xD1\x91\xD1\x82.pdf", "\xD0\x9E\xD0\xA2\xD0\xA7\xD0\x81\xD0\xA2.pdf"},
        // Greek: "σ" and "Σ".
        {"\xCF\x83.txt", "\xCE\xA3.txt"},
        {"", ""},
    }));
    CAPTURE(a, b);
    CHECK(rp::name_key(a) == rp::name_key(b));
    CHECK(rp::same_name(a, b));
}

TEST_CASE("name_key: different names keep different keys", "[name-key]")
{
    const auto [a, b] = GENERATE_COPY(table<std::string, std::string>({
        {"Report.docx", "Report.pdf"},
        {"report.docx", "report .docx"},
        // "Źródła" and "Zrodla": an accent is not a case.
        {kUpperZrodla, "Zrodla.docx"},
        {kLowerZrodla, "zrodla.docx"},
        // Invalid UTF-8 is folded A-Z only, byte for byte, and never matches valid text.
        {"a\xFF.txt", "A\xFE.txt"},
        {"\xC5", "\xC5\xB9"},
    }));
    CAPTURE(a, b);
    CHECK(rp::name_key(a) != rp::name_key(b));
    CHECK_FALSE(rp::same_name(a, b));
}

TEST_CASE("name_key: invalid UTF-8 is upper-cased A-Z only, every other byte kept", "[name-key]")
{
    CHECK(rp::name_key("a\xFF" "b.txt") == "A\xFF" "B.TXT");
    CHECK(rp::same_name("a\xFF" "b.txt", "A\xFF" "b.TXT"));
}

TEST_CASE("name_key: the key is the invariant upper case, in UTF-8", "[name-key]")
{
    CHECK(rp::name_key("Budget.xlsx") == "BUDGET.XLSX");
    CHECK(rp::name_key(kLowerZrodla) == kShoutZrodla);
}
