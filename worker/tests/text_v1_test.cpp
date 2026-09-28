#include <rp/text_v1.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>

namespace {

// shared/testdata/body-normalization-text-v1.json: the vectors the seeder
// (lab/seeder/normalize.py) passes too.
nlohmann::json load_vectors()
{
    const std::string path = std::string{RP_SHARED_DIR} + "/testdata/body-normalization-text-v1.json";
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read " + path);
    }
    return nlohmann::json::parse(std::string{std::istreambuf_iterator<char>(file), {}});
}

constexpr const char* kEmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
constexpr const char* kAbcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

} // namespace

TEST_CASE("every shared text-v1 vector normalises and hashes as the seeder's", "[text-v1]")
{
    const nlohmann::json vectors = load_vectors();
    REQUIRE(vectors.at("normalization").get<std::string>() == rp::kTextV1);
    const nlohmann::json& cases = vectors.at("cases");
    REQUIRE(cases.size() >= 19);
    for (const nlohmann::json& c : cases) {
        const std::string name = c.at("name").get<std::string>();
        const std::string input = c.at("input").get<std::string>();
        CAPTURE(name);
        CHECK(rp::normalize_text_v1(input) == c.at("normalized").get<std::string>());
        CHECK(rp::text_v1_sha256(input) == c.at("sha256").get<std::string>());
    }
}

// The same list as lab/tests/test_normalize.py::test_vectors_file_covers_every_required_case,
// so a case dropped from the file can't pass unnoticed here.
TEST_CASE("the vector file names every case the seeder's tests require", "[text-v1]")
{
    const nlohmann::json cases = load_vectors().at("cases");
    std::set<std::string> names;
    for (const nlohmann::json& c : cases) {
        names.insert(c.at("name").get<std::string>());
    }
    CHECK(names.size() == cases.size());
    const std::string required = GENERATE(values<std::string>({
        "plain", "crlf", "lone-cr", "mixed-endings", "trailing-spaces", "trailing-tabs",
        "trailing-spaces-last-line", "trailing-newlines", "trailing-crlf-blank-lines",
        "leading-bom", "bom-not-at-start", "leading-whitespace", "nbsp-at-line-end", "non-ascii",
        "combining-sequence", "empty", "only-newlines", "catalog-rp-canary-0001-crlf",
        "catalog-rp-canary-0001-lf",
    }));
    CAPTURE(required);
    CHECK(names.count(required) == 1);
}

// Hand-derived, independent of the file. A \x escape followed by a hex digit is
// split into two literals (\x escapes are greedy).
TEST_CASE("normalize_text_v1 changes only what text-v1 names", "[text-v1]")
{
    const auto [input, normalized] = GENERATE(table<std::string, std::string>({
        {"\xEF\xBB\xBF\xEF\xBB\xBF" "a", "\xEF\xBB\xBF" "a"},  // one BOM dropped, not two
        {"a\r\r\nb", "a\n\nb"},                                 // lone CR, then CRLF
        {"nbsp\xC2\xA0 \n", "nbsp\xC2\xA0"},                    // NBSP is not whitespace here
        {" lead", " lead"},                                     // no leading trim
        {"e\xCC\x81", "e\xCC\x81"},                             // no Unicode normalisation
        {"a \t\n \nb\t", "a\n\nb"},                             // every line, the last included
    }));
    CAPTURE(input);
    CHECK(rp::normalize_text_v1(input) == normalized);
}

TEST_CASE("text_v1_sha256 hashes the normalised text", "[text-v1]")
{
    const auto [input, hash] = GENERATE(table<std::string, std::string>({
        {"\n\n", kEmptyHash},
        {"", kEmptyHash},
        {"abc", kAbcHash},
        {"abc  \r\n", kAbcHash},
        {"\xEF\xBB\xBF" "abc\t\r\n\r\n", kAbcHash},
    }));
    CAPTURE(input);
    CHECK(rp::text_v1_sha256(input) == hash);
}
