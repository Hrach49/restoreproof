#include <rp/canonical_json.hpp>

#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>

namespace {

// shared/testdata/canonical-json-v1.json: the vectors the Cloud's
// cloud/tests/test_canonical_json.py runs too (its accepted cases).
nlohmann::json load_vectors()
{
    const std::string path = std::string{RP_SHARED_DIR} + "/testdata/canonical-json-v1.json";
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read " + path);
    }
    return nlohmann::json::parse(std::string{std::istreambuf_iterator<char>(file), {}});
}

constexpr const char* kFloat = "canonical-json-v1: a floating-point number";
constexpr const char* kInteger = "canonical-json-v1: an integer outside +-(2^53 - 1)";
constexpr const char* kKey = "canonical-json-v1: an object key that isn't ASCII";
constexpr const char* kNotJson = "canonical-json-v1: a value that isn't JSON";
constexpr const char* kUtf8 = "canonical-json-v1: a string that isn't valid UTF-8";

// The vector file's `reason` words and the message each stands for.
std::string message_of(const std::string& reason)
{
    if (reason == "float") {
        return kFloat;
    }
    if (reason == "integer_out_of_range") {
        return kInteger;
    }
    if (reason == "non_ascii_key") {
        return kKey;
    }
    throw std::runtime_error("unknown reason in the vector file: " + reason);
}

// What canonical_json threw for `value`; empty when it didn't throw.
std::string refusal(const nlohmann::json& value)
{
    try {
        (void)rp::canonical_json(value);
    } catch (const rp::CanonicalJsonError& e) {
        return e.what();
    }
    return {};
}

constexpr std::int64_t kMax = 9007199254740991; // 2^53 - 1

} // namespace

// ---- refusals ----------------------------------------------------------------

TEST_CASE("every shared canonical-json-v1 reject is refused for its rule", "[canonical_json]")
{
    const nlohmann::json vectors = load_vectors();
    REQUIRE(vectors.at("form").get<std::string>() == rp::kCanonicalJsonV1);
    const nlohmann::json& rejects = vectors.at("rejects");
    REQUIRE(rejects.size() >= 5);
    for (const nlohmann::json& r : rejects) {
        const std::string name = r.at("name").get<std::string>();
        CAPTURE(name);
        const nlohmann::json input = nlohmann::json::parse(r.at("input_text").get<std::string>());
        CHECK(refusal(input) == message_of(r.at("reason").get<std::string>()));
        CHECK_THROWS_AS(rp::canonical_sha256(input), rp::CanonicalJsonError);
    }
}

TEST_CASE("canonical_json refuses a floating-point number wherever it is", "[canonical_json]")
{
    const nlohmann::json value = GENERATE(values<nlohmann::json>({
        nlohmann::json(1.0),
        nlohmann::json(0.0),
        nlohmann::json(-0.0),
        nlohmann::json(1e300),
        nlohmann::json(std::numeric_limits<double>::quiet_NaN()),
        nlohmann::json(std::numeric_limits<double>::infinity()),
        nlohmann::json(-std::numeric_limits<double>::infinity()),
        nlohmann::json::array({1, nlohmann::json::array({2, 3.5})}),
        nlohmann::json{{"a", {{"b", nlohmann::json::array({nlohmann::json{{"c", 2.0}}})}}}},
    }));
    CHECK(refusal(value) == kFloat);
}

TEST_CASE("canonical_json refuses an integer outside +-(2^53 - 1), signed or unsigned", "[canonical_json]")
{
    const nlohmann::json value = GENERATE(values<nlohmann::json>({
        nlohmann::json(kMax + 1),
        nlohmann::json(-kMax - 1),
        nlohmann::json(std::numeric_limits<std::int64_t>::max()),
        nlohmann::json(std::numeric_limits<std::int64_t>::min()),
        nlohmann::json(static_cast<std::uint64_t>(kMax) + 1),
        nlohmann::json(std::numeric_limits<std::uint64_t>::max()),
        nlohmann::json{{"ms", std::numeric_limits<std::uint64_t>::max()}},
        nlohmann::json::array({0, nlohmann::json{{"n", kMax + 1}}}),
    }));
    CHECK(refusal(value) == kInteger);
}

TEST_CASE("canonical_json takes the integers at the two ends of the range", "[canonical_json]")
{
    CHECK(rp::canonical_json(nlohmann::json(kMax)) == "9007199254740991");
    CHECK(rp::canonical_json(nlohmann::json(-kMax)) == "-9007199254740991");
    CHECK(rp::canonical_json(nlohmann::json(static_cast<std::uint64_t>(kMax))) == "9007199254740991");
}

TEST_CASE("canonical_json refuses an object key with a non-ASCII byte", "[canonical_json]")
{
    const std::string key = GENERATE(values<std::string>({
        "\xC3\xA9",          // é
        "caf\xC3\xA9",       // the last character
        "a\x80",             // not UTF-8 either
        "\xFF",
        "\xF0\x9F\x98\x80",  // astral
    }));
    CAPTURE(key);
    CHECK(refusal(nlohmann::json{{key, 1}}) == kKey);
    CHECK(refusal(nlohmann::json::array({nlohmann::json{{"a", nlohmann::json{{key, nullptr}}}}})) == kKey);
}

// Invalid UTF-8 can't be written in a JSON file, so these bytes are built here.
// Never replaced by U+FFFD, as rp.run-summary.v0's dump did.
TEST_CASE("canonical_json refuses invalid UTF-8 in a string", "[canonical_json]")
{
    const std::string bytes = GENERATE(values<std::string>({
        "\xFF",
        "abc\x80",
        "\xC3",                  // cut short
        "\xC0\xAF",              // overlong
        "\xED\xA0\x80",          // a lone surrogate
        "\xF4\x90\x80\x80",      // past U+10FFFF
        "ok \xE2\x82 cut",
    }));
    CAPTURE(bytes);
    CHECK(refusal(nlohmann::json(bytes)) == kUtf8);
    CHECK(refusal(nlohmann::json{{"reason", bytes}}) == kUtf8);
    CHECK(refusal(nlohmann::json::array({"fine", nlohmann::json::array({bytes})})) == kUtf8);
}

TEST_CASE("canonical_json refuses a value that isn't JSON", "[canonical_json]")
{
    const nlohmann::json discarded = nlohmann::json::parse("not json", nullptr, false);
    REQUIRE(discarded.is_discarded());
    const nlohmann::json binary = nlohmann::json::binary({0x01, 0x02});
    CHECK(refusal(discarded) == kNotJson);
    CHECK(refusal(binary) == kNotJson);
    CHECK(refusal(nlohmann::json{{"a", nlohmann::json::array({binary})}}) == kNotJson);
}

// The result is what gets signed and uploaded: a refusal names its rule and
// nothing of the document.
TEST_CASE("a refusal never carries the value or the key", "[canonical_json]")
{
    const std::string secret = "SENTINEL-\xC3\xA9";
    const std::string message = GENERATE_COPY(
        refusal(nlohmann::json{{secret, 1}}),
        refusal(nlohmann::json{{"SENTINEL", 1.5}}),
        refusal(nlohmann::json{{"SENTINEL", "SENTINEL\xFF"}}),
        refusal(nlohmann::json{{"SENTINEL", std::numeric_limits<std::uint64_t>::max()}}));
    CAPTURE(message);
    CHECK(message.starts_with("canonical-json-v1: "));
    CHECK(message.find("SENTINEL") == std::string::npos);
    CHECK(message.find("18446744073709551615") == std::string::npos);
    CHECK(message.find("1.5") == std::string::npos);
}

TEST_CASE("CanonicalJsonError is a runtime_error", "[canonical_json]")
{
    CHECK_THROWS_AS(rp::canonical_json(nlohmann::json(1.5)), std::runtime_error);
}

// ---- the shared vectors --------------------------------------------------------

TEST_CASE("every shared canonical-json-v1 case reproduces its canonical text and hash", "[canonical_json]")
{
    const nlohmann::json vectors = load_vectors();
    const nlohmann::json& cases = vectors.at("cases");
    REQUIRE(cases.size() >= 33);
    for (const nlohmann::json& c : cases) {
        const std::string name = c.at("name").get<std::string>();
        const std::string expected = c.at("canonical").get<std::string>();
        CAPTURE(name);
        const std::string canonical = rp::canonical_json(c.at("input"));
        CHECK(canonical == expected);
        CHECK(rp::sha256_hex(canonical) == c.at("sha256").get<std::string>());
        CHECK(rp::canonical_sha256(c.at("input")) == c.at("sha256").get<std::string>());
        // The canonical text is a fixed point: parsed back, it gives itself.
        CHECK(rp::canonical_json(nlohmann::json::parse(canonical)) == canonical);
    }
}

// A case dropped from the file can't pass unnoticed.
TEST_CASE("the canonical-json-v1 vector file names every required case and reject", "[canonical_json]")
{
    const nlohmann::json vectors = load_vectors();
    std::set<std::string> names;
    for (const char* list : {"cases", "rejects"}) {
        for (const nlohmann::json& entry : vectors.at(list)) {
            names.insert(entry.at("name").get<std::string>());
        }
    }
    CHECK(names.size() == vectors.at("cases").size() + vectors.at("rejects").size());
    const std::string required = GENERATE(values<std::string>({
        "empty-object", "empty-array", "empty-string", "true", "false", "null",
        "literals-in-containers", "empty-containers-nested", "whitespace-removed", "key-order",
        "key-order-nested", "key-prefixes", "keys-escaped", "array-order-kept", "control-characters",
        "control-characters-each", "del", "slash", "quote", "backslash", "latin-e-acute",
        "combining-not-composed", "line-separator-u2028", "paragraph-separator-u2029",
        "bom-in-string", "astral", "nested-arrays-of-strings", "integer-zero", "integer-minus-one",
        "integer-max", "integer-min", "integers", "result-shaped",
        "float", "float-fraction", "float-exponent", "float-nested", "integer-two-to-the-53",
        "integer-minus-two-to-the-53", "integer-out-of-range-nested", "non-ascii-key",
        "non-ascii-key-nested",
    }));
    CAPTURE(required);
    CHECK(names.count(required) == 1);
}

// ---- the form itself, independent of the file ----------------------------------

TEST_CASE("canonical_json writes compact text with keys in byte order", "[canonical_json]")
{
    const auto [text, canonical] = GENERATE(table<std::string, std::string>({
        {R"(  { "b" : 1 , "a" : [ 1 , 2 ] }  )", R"({"a":[1,2],"b":1})"},
        {R"({"a":1,"B":2,"_":3,"aa":4,"1":5,"10":6,"2":7,"":8})",
         R"({"":8,"1":5,"10":6,"2":7,"B":2,"_":3,"a":1,"aa":4})"},
        {R"({"z":{"y":null,"x":true},"a":false})", R"({"a":false,"z":{"x":true,"y":null}})"},
        {"[]", "[]"},
        {"{}", "{}"},
        {R"("")", R"("")"},
        {"-0", "0"},
        {R"(["\u00e9","\u2028","\u2029","\ud83d\ude00","\u007f","\/"])",
         "[\"\xC3\xA9\",\"\xE2\x80\xA8\",\"\xE2\x80\xA9\",\"\xF0\x9F\x98\x80\",\"\x7F\",\"/\"]"},
        {R"(["\u0000","\u001f","\b","\f","\n","\r","\t","\"","\\","\u000B"])",
         R"(["\u0000","\u001f","\b","\f","\n","\r","\t","\"","\\","\u000b"])"},
    }));
    CAPTURE(text);
    CHECK(rp::canonical_json(nlohmann::json::parse(text)) == canonical);
}

TEST_CASE("canonical_json ends without a newline and holds no whitespace outside strings", "[canonical_json]")
{
    const nlohmann::json value = {{"list", {1, 2, 3}}, {"object", {{"k", "v"}}}, {"n", nullptr}};
    const std::string canonical = rp::canonical_json(value);
    CHECK(canonical == R"({"list":[1,2,3],"n":null,"object":{"k":"v"}})");
    CHECK(canonical.find_first_of(" \t\r\n") == std::string::npos);
}

TEST_CASE("canonical_json output parsed back and canonicalised again is identical", "[canonical_json]")
{
    const nlohmann::json value = {
        {"text", "line\n\"quoted\" \\ \x01 \xC3\xA9 \xF0\x9F\x98\x80 \x7F"},
        {"nul", std::string("a\0b", 3)},
        {"numbers", {0, -1, kMax, -kMax}},
        {"nested", {{"b", {{"d", nullptr}, {"c", {true, false}}}}, {"a", nlohmann::json::array()}}},
    };
    const std::string once = rp::canonical_json(value);
    const std::string twice = rp::canonical_json(nlohmann::json::parse(once));
    CHECK(once == twice);
    CHECK(nlohmann::json::parse(once) == value);
}

TEST_CASE("canonical_sha256 is the SHA-256 of the canonical bytes", "[canonical_json]")
{
    const nlohmann::json value = {{"b", 1}, {"a", "\xC3\xA9"}};
    CHECK(rp::canonical_sha256(value) == rp::sha256_hex("{\"a\":\"\xC3\xA9\",\"b\":1}"));
    // "{}", hashed by Python's hashlib.
    CHECK(rp::canonical_sha256(nlohmann::json::object())
          == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
}
