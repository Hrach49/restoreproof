// restoreproof.result.v1's schema (W4.1, docs/decisions.md 2026-10-04, points
// 2, 3 and 5): the embedded bytes are the file's, the schema keeps to the
// keywords JSON Schema draft 7 and 2020-12 read alike, its enums are the
// code's words, and the documents of shared/testdata/result-v1/ validate as
// they say (the Cloud's Python validator runs the same file).

#include <rp/result_schema.hpp>

#include "../src/result_schema_detail.hpp"
#include "result_lab.hpp"

#include <rp/canonical_json.hpp>
#include <rp/connector_registry.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/sample_rng.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using nlohmann::json;
using rp::ResultValidation;
using rp::validate_result;

constexpr const char* kSchemaFile = "schemas/result.v1.json";

json schema()
{
    return json::parse(rp::result_schema_text());
}

// The node at a JSON pointer of the schema.
json at(const std::string& pointer)
{
    return schema().at(json::json_pointer(pointer));
}

// --- the keyword walk -------------------------------------------------------

// Point 3's list: what draft 7 (the C++ validator) and 2020-12 (Python's)
// read alike.
const std::set<std::string> kKeywords = {
    "$schema", "$id",       "title",     "description", "type",       "enum",
    "const",   "properties", "required", "additionalProperties",      "items",
    "minItems", "maxItems", "minLength", "maxLength",   "pattern",    "minimum",
    "maximum", "allOf",     "anyOf",     "oneOf",       "not",        "if",
    "then",    "else",      "$defs",     "$ref"};

// Every problem of the schema at `where`: a keyword outside the list, a $ref
// with a sibling, `items` that isn't one schema, an object type left open, a
// pattern with a backslash class. Descends through schema positions only, so
// a property of the result named `format`, `items`, `type` or `status` is
// never read as a keyword.
void walk(const json& node, const std::string& where, std::vector<std::string>& problems)
{
    if (!node.is_object()) {
        problems.push_back(where + ": not an object schema");
        return;
    }
    if (node.contains("$ref") && node.size() != 1) {
        problems.push_back(where + ": a $ref with a sibling");
    }
    if (node.contains("type") && node.at("type") == "object" &&
        (!node.contains("additionalProperties") || node.at("additionalProperties") != false)) {
        problems.push_back(where + ": an object left open");
    }
    for (const auto& [key, value] : node.items()) {
        const std::string here = where + "/" + key;
        if (!kKeywords.contains(key)) {
            problems.push_back(here + ": not an allowed keyword");
            continue;
        }
        if (key == "properties" || key == "$defs") {
            if (!value.is_object()) {
                problems.push_back(here + ": not an object");
                continue;
            }
            for (const auto& [name, member] : value.items()) {
                walk(member, here + "/" + name, problems);
            }
        } else if (key == "items" || key == "not" || key == "if" || key == "then" ||
                   key == "else") {
            walk(value, here, problems);
        } else if (key == "allOf" || key == "anyOf" || key == "oneOf") {
            if (!value.is_array() || value.empty()) {
                problems.push_back(here + ": not a list of schemas");
                continue;
            }
            for (std::size_t i = 0; i < value.size(); ++i) {
                walk(value[i], here + "/" + std::to_string(i), problems);
            }
        } else if (key == "additionalProperties") {
            if (value.is_object()) {
                walk(value, here, problems);
            } else if (!value.is_boolean()) {
                problems.push_back(here + ": neither a schema nor a boolean");
            }
        } else if (key == "pattern") {
            if (!value.is_string()) {
                problems.push_back(here + ": not a string");
                continue;
            }
            const std::string& pattern = value.get_ref<const std::string&>();
            for (std::size_t i = 0; i + 1 < pattern.size(); ++i) {
                if (pattern[i] == '\\') {
                    if (std::string_view{"dDwWsSbB"}.find(pattern[i + 1]) !=
                        std::string_view::npos) {
                        problems.push_back(here + ": a backslash class");
                    }
                    ++i; // an escaped backslash escapes nothing after it
                }
            }
        }
    }
}

std::vector<std::string> problems_of(const json& root)
{
    std::vector<std::string> problems;
    walk(root, "", problems);
    return problems;
}

std::vector<std::string> strings(std::vector<std::string_view> views)
{
    return {views.begin(), views.end()};
}

// --- the shared documents ---------------------------------------------------

const json& cases_file()
{
    static const json file = json::parse(rp::test::read_shared("testdata/result-v1/cases.json"));
    return file;
}

const json& base_document()
{
    static const json base = json::parse(
        rp::test::read_shared("testdata/result-v1/" + cases_file().at("base").get<std::string>()));
    return base;
}

bool holds_float(const json& value)
{
    if (value.is_structured()) {
        for (const json& member : value) {
            if (holds_float(member)) {
                return true;
            }
        }
        return false;
    }
    return value.is_number_float();
}

// The base with one value replaced (or added).
json with(const std::string& pointer, json value)
{
    json document = base_document();
    document[json::json_pointer(pointer)] = std::move(value);
    return document;
}

} // namespace

TEST_CASE("the embedded result schema is the file's bytes", "[result_schema]")
{
    const std::string file = rp::test::read_shared(kSchemaFile);
    REQUIRE_FALSE(file.empty());
    REQUIRE(rp::result_schema_text().size() == file.size());
    REQUIRE(rp::result_schema_text() == file);
    // LF only (.gitattributes): the bytes the Cloud reads on Linux.
    REQUIRE(file.find('\r') == std::string::npos);
    REQUIRE(json::parse(file).at("$schema") == "https://json-schema.org/draft/2020-12/schema");
}

TEST_CASE("the keyword walk refuses what the two drafts read differently", "[result_schema]")
{
    struct Row {
        const char* name;
        const char* schema;
        const char* problem;
    };
    const Row row = GENERATE(
        Row{"format", R"({"type":"string","format":"date-time"})", "/format: not an allowed keyword"},
        Row{"prefixItems", R"({"type":"array","prefixItems":[{"type":"string"}]})",
            "/prefixItems: not an allowed keyword"},
        Row{"unevaluatedProperties",
            R"({"properties":{"a":{"unevaluatedProperties":false}}})",
            "/properties/a/unevaluatedProperties: not an allowed keyword"},
        Row{"dependentRequired", R"({"items":{"dependentRequired":{"a":["b"]}}})",
            "/items/dependentRequired: not an allowed keyword"},
        Row{"patternProperties", R"({"not":{"patternProperties":{"^a":{}}}})",
            "/not/patternProperties: not an allowed keyword"},
        Row{"definitions", R"({"definitions":{}})", "/definitions: not an allowed keyword"},
        Row{"$ref with a sibling",
            R"({"oneOf":[{"$ref":"#/$defs/a","description":"x"}],"$defs":{"a":{"type":"null"}}})",
            "/oneOf/0: a $ref with a sibling"},
        Row{"items as a list", R"({"items":[{"type":"string"}]})",
            "/items: not an object schema"},
        Row{"a boolean schema", R"({"properties":{"a":true}})",
            "/properties/a: not an object schema"},
        Row{"an open object", R"({"if":{"type":"object","properties":{}}})",
            "/if: an object left open"},
        Row{"additionalProperties true on an object",
            R"({"then":{"type":"object","additionalProperties":true}})",
            "/then: an object left open"},
        Row{"\\d", R"({"else":{"pattern":"^\\d+$"}})", "/else/pattern: a backslash class"},
        Row{"\\w", R"({"allOf":[{"pattern":"\\w"}]})", "/allOf/0/pattern: a backslash class"},
        Row{"\\s", R"({"anyOf":[{"pattern":"a\\sb"}]})", "/anyOf/0/pattern: a backslash class"},
        Row{"\\b", R"({"$defs":{"a":{"pattern":"\\bx"}}})",
            "/$defs/a/pattern: a backslash class"},
        Row{"a keyword under additionalProperties",
            R"({"additionalProperties":{"format":"uuid"}})",
            "/additionalProperties/format: not an allowed keyword"});
    INFO(row.name);
    REQUIRE(problems_of(json::parse(row.schema)) == std::vector<std::string>{row.problem});
}

TEST_CASE("the keyword walk reads a property's name as a name", "[result_schema]")
{
    // The result has keys called format, items, type and status.
    const json schema = json::parse(
        R"({"type":"object","additionalProperties":false,
            "properties":{"format":{"const":"x"},"items":{"type":"array","items":{"type":"integer"}},
                          "type":{"enum":["a"]},"status":{"$ref":"#/$defs/s"},
                          "prefixItems":{"type":"null"},"text":{"pattern":"^a\\.b\\\\d[0-9]$"}},
            "$defs":{"s":{"type":"null"}}})");
    REQUIRE(problems_of(schema).empty());
}

TEST_CASE("the result schema keeps to the allowed keywords", "[result_schema]")
{
    const json root = schema();
    REQUIRE(problems_of(root) == std::vector<std::string>{});
    REQUIRE(root.at("$id").is_string());
    REQUIRE(root.at("title").is_string());
    REQUIRE(root.at("additionalProperties") == false);
}

TEST_CASE("the result schema's top level is the seventeen keys, all required", "[result_schema]")
{
    const std::vector<std::string> keys = {
        "format",        "worker_version", "run_id",   "started_at", "ended_at",
        "connector",     "client",         "restore_point", "sample", "expected",
        "restore",       "check",          "status",   "cleanup",    "timings",
        "attachments",   "screenshot"};
    const std::set<std::string> wanted(keys.begin(), keys.end());
    REQUIRE(wanted.size() == 17);

    std::set<std::string> properties;
    const json top = at("/properties");
    for (const auto& [name, unused] : top.items()) {
        properties.insert(name);
    }
    REQUIRE(properties == wanted);
    const std::vector<std::string> required = at("/required");
    REQUIRE(std::set<std::string>(required.begin(), required.end()) == wanted);
    REQUIRE(required.size() == 17);

    // status and timings are objects, never null; no scope until W4.11.
    REQUIRE(at("/properties/status") == json{{"$ref", "#/$defs/status"}});
    REQUIRE(at("/properties/timings") == json{{"$ref", "#/$defs/timings"}});
    REQUIRE_FALSE(at("/properties/client/properties").contains("scope"));
    for (const char* later : {"signature", "tsa_token", "tsa_error", "worker_id",
                              "bundle_sha256", "command", "exit_code", "veeam_org_name"}) {
        INFO(later);
        REQUIRE_FALSE(properties.contains(later));
    }
}

TEST_CASE("the result schema's enums are the code's words", "[result_schema]")
{
    namespace v = rp::verification;
    using rp::connector::ItemKind;
    using rp::connector::ItemOutcome;
    using rp::connector::RestoreStatus;
    using rp::connector::to_string;
    const auto list = [](const std::string& pointer) {
        return at(pointer).get<std::vector<std::string>>();
    };
    const auto text = [](std::string_view view) { return std::string{view}; };

    SECTION("the format, the sampler's algorithm and the connectors")
    {
        REQUIRE(at("/properties/format/const") == text(rp::kResultFormat));
        REQUIRE(at("/$defs/sample/properties/algorithm/const") ==
                text(rp::sampling::kAlgorithm));
        REQUIRE(list("/properties/connector/properties/type/enum") ==
                rp::connector::default_connector_registry().names());
        REQUIRE(list("/properties/connector/properties/type/enum") ==
                std::vector<std::string>{text(rp::connector::kVeeamM365)});
    }

    SECTION("the status's codes are run_status's lists")
    {
        REQUIRE(list("/$defs/status/properties/status/enum") ==
                std::vector<std::string>{text(v::to_string(v::RunStatus::pass)),
                                         text(v::to_string(v::RunStatus::fail)),
                                         text(v::to_string(v::RunStatus::error))});
        REQUIRE(list("/$defs/status/properties/error_code/enum") == strings(v::error_codes()));
        REQUIRE(list("/$defs/status/properties/warnings/items/properties/code/enum") ==
                strings(v::warning_codes()));
        REQUIRE(list("/$defs/status/properties/unchecked_items/items/properties/error_code/enum") ==
                strings(v::unchecked_item_codes()));
    }

    SECTION("the kinds, sources, expected kinds and hash rules")
    {
        REQUIRE(list("/$defs/kind/enum") ==
                std::vector<std::string>{text(to_string(ItemKind::mail)),
                                         text(to_string(ItemKind::sharepoint)),
                                         text(to_string(ItemKind::onedrive))});
        REQUIRE(list("/$defs/expected_item/properties/source/enum") ==
                std::vector<std::string>{text(v::to_string(v::ItemSource::canary)),
                                         text(v::to_string(v::ItemSource::random))});
        REQUIRE(list("/$defs/expected_item/properties/expected_kind/enum") ==
                std::vector<std::string>{text(v::to_string(v::ExpectedKind::manifest)),
                                         text(v::to_string(v::ExpectedKind::fields)),
                                         text(v::to_string(v::ExpectedKind::metadata))});
        // No table in the code: text-v1 is the manifest loader's one mail
        // rule, bytes and office-v1 are expected_set.cpp's file rules.
        REQUIRE(list("/$defs/expected_item/properties/sha256_rule/enum") ==
                std::vector<std::string>{"text-v1", "bytes", "office-v1"});
    }

    SECTION("the restore's statuses and item outcomes")
    {
        REQUIRE(list("/$defs/restore/properties/status/enum") ==
                std::vector<std::string>{text(to_string(RestoreStatus::not_run)),
                                         text(to_string(RestoreStatus::succeeded)),
                                         text(to_string(RestoreStatus::partial)),
                                         text(to_string(RestoreStatus::failed))});
        REQUIRE(list("/$defs/restore/properties/items/items/properties/outcome/enum") ==
                std::vector<std::string>{text(to_string(ItemOutcome::unknown)),
                                         text(to_string(ItemOutcome::restored)),
                                         text(to_string(ItemOutcome::failed)),
                                         text(to_string(ItemOutcome::not_in_backup))});
    }

    SECTION("the check's outcomes, fields and codes")
    {
        REQUIRE(list("/$defs/check_item/properties/outcome/enum") ==
                std::vector<std::string>{text(v::to_string(v::CheckOutcome::match)),
                                         text(v::to_string(v::CheckOutcome::mismatch)),
                                         text(v::to_string(v::CheckOutcome::missing)),
                                         text(v::to_string(v::CheckOutcome::error))});
        // ItemCheck::mismatches' order (rp/checker.hpp).
        REQUIRE(list("/$defs/check_item/properties/mismatches/items/enum") ==
                std::vector<std::string>{"subject", "sender_address", "sender_name", "sent_at",
                                         "received_at", "internet_message_id", "size_bytes",
                                         "sha256"});
        // read_error_code's codes and the checker's own stale_target: the
        // unchecked items' codes but the two the backup gives.
        const std::vector<std::string> codes = list("/$defs/check_item/properties/error_code/enum");
        REQUIRE(codes == std::vector<std::string>{"graph_auth", "graph_permission",
                                                  "graph_transient", "target_guard", "graph",
                                                  "stale_target"});
        std::set<std::string> unchecked;
        for (const std::string_view code : v::unchecked_item_codes()) {
            unchecked.insert(text(code));
        }
        unchecked.erase("backup_infrastructure");
        unchecked.erase("not_in_backup");
        REQUIRE(std::set<std::string>(codes.begin(), codes.end()) == unchecked);
    }

    SECTION("the cleanup's codes")
    {
        // TargetCleanup::error_code (rp/cleaner.hpp).
        REQUIRE(list("/$defs/cleanup_target/properties/error_code/enum") ==
                std::vector<std::string>{"target_guard", "graph_auth", "graph_permission",
                                         "graph_transient", "graph", "config", "internal"});
    }

    SECTION("the attachments' names and the screenshot's states and reasons (W4.2)")
    {
        REQUIRE(list("/$defs/attachment/properties/name/enum") == rp::attachment_names());
        REQUIRE(at("/$defs/screenshot/oneOf/0/properties/state/const") ==
                rp::to_json(rp::Screenshot{true, rp::ScreenshotReason::failed}).at("state"));
        REQUIRE(at("/$defs/screenshot/oneOf/1/properties/state/const") ==
                rp::to_json(rp::Screenshot{false, rp::ScreenshotReason::failed}).at("state"));
        REQUIRE(list("/$defs/screenshot/oneOf/1/properties/reason/enum") ==
                rp::screenshot_reasons());
        // items.csv and veeam-session.log always, screenshot.png when captured.
        REQUIRE(at("/$defs/attachments/minItems") == 2);
        REQUIRE(at("/$defs/attachments/maxItems") == rp::attachment_names().size());
    }

    SECTION("the spans and their notes")
    {
        std::vector<std::string> names;
        for (std::size_t i = 0; i < rp::timing::kSpanCount; ++i) {
            names.push_back(text(rp::timing::to_string(static_cast<rp::timing::Span>(i))));
        }
        REQUIRE(names.size() == 11);
        REQUIRE(list("/$defs/timings/properties/spans/required") == names);
        const json spans = at("/$defs/timings/properties/spans/properties");
        REQUIRE(spans.size() == names.size());
        for (const std::string& name : names) {
            INFO(name);
            REQUIRE(spans.at(name) == json{{"$ref", "#/$defs/span"}});
        }
        using rp::timing::SpanState;
        REQUIRE(at("/$defs/span/oneOf/2/properties/note/const") ==
                text(rp::timing::to_string(SpanState::stopped)));
        REQUIRE(list("/$defs/span/oneOf/3/properties/note/enum") ==
                std::vector<std::string>{text(rp::timing::to_string(SpanState::open)),
                                         text(rp::timing::to_string(SpanState::not_reported)),
                                         text(rp::timing::to_string(SpanState::clock_backwards))});
    }
}

// The `reason` pattern repeats three of the code's word lists: the item kinds,
// read_error_code's codes and the mismatch fields. The enums beside it are
// held to the code above; this holds the pattern to them, with the words the
// checker joins them by (src/checker.cpp). A reason the pattern doesn't know
// would end a real run `error result_invalid`.
TEST_CASE("the result schema's reason pattern takes every reason the checker can write",
          "[result_schema]")
{
    using rp::connector::ItemKind;
    const auto list = [](const std::string& pointer) {
        return at(pointer).get<std::vector<std::string>>();
    };
    const auto valid = [](const json& item) {
        return validate_result(with("/check/items/0", item)).valid;
    };

    SECTION("a target that couldn't be read: every kind with every code but stale_target")
    {
        std::size_t reasons = 0;
        for (const ItemKind kind : {ItemKind::mail, ItemKind::sharepoint, ItemKind::onedrive}) {
            for (const std::string& code : list("/$defs/check_item/properties/error_code/enum")) {
                if (code == "stale_target") {
                    continue;
                }
                const std::string reason = "the " + std::string{rp::connector::to_string(kind)} +
                                           " restore target couldn't be read (" + code + ")";
                INFO(reason);
                REQUIRE(valid({{"index", 0},
                               {"outcome", "error"},
                               {"found", false},
                               {"reason", reason},
                               {"error_code", code}}));
                ++reasons;
            }
        }
        REQUIRE(reasons == 15);
    }

    SECTION("fields that did not match: every field, alone and all together, with and without "
            "the office-v1 note")
    {
        const std::vector<std::string> fields =
            list("/$defs/check_item/properties/mismatches/items/enum");
        REQUIRE(fields.size() == 8);
        const std::string note = "; the restored package isn't valid office-v1 input";
        const auto mismatch = [](const std::vector<std::string>& which, const std::string& reason) {
            return json{{"index", 0},
                        {"outcome", "mismatch"},
                        {"found", true},
                        {"mismatches", which},
                        {"reason", reason},
                        {"ms", 40}};
        };
        std::string all;
        for (const std::string& field : fields) {
            INFO(field);
            const std::string reason = "fields did not match: " + field;
            REQUIRE(valid(mismatch({field}, reason)));
            REQUIRE(valid(mismatch({field}, reason + note)));
            all += (all.empty() ? "" : ", ") + field;
        }
        INFO(all);
        REQUIRE(valid(mismatch(fields, "fields did not match: " + all)));
        REQUIRE(valid(mismatch(fields, "fields did not match: " + all + note)));
    }

    SECTION("the two reasons without a list")
    {
        REQUIRE(valid({{"index", 0},
                       {"outcome", "missing"},
                       {"found", false},
                       {"reason", "no restored copy found"}}));
        REQUIRE(valid({{"index", 0},
                       {"outcome", "error"},
                       {"found", false},
                       {"reason", "only an earlier run's copy is in the target"},
                       {"error_code", "stale_target"}}));
    }

    SECTION("a word of no list is refused")
    {
        const char* reason = GENERATE(
            "the calendar restore target couldn't be read (graph)",
            "the mail restore target couldn't be read (stale_target)",
            "the mail restore target couldn't be read (backup)",
            "fields did not match: body",
            "fields did not match: subject,sent_at",
            "fields did not match: subject; the restored package isn't valid office-v2 input");
        INFO(reason);
        // Each in the item its reason belongs to, valid but for the reason.
        const bool fields = std::string_view{reason}.starts_with("fields");
        const json item = fields ? json{{"index", 0},
                                        {"outcome", "mismatch"},
                                        {"found", true},
                                        {"mismatches", {"subject"}},
                                        {"reason", reason},
                                        {"ms", 40}}
                                 : json{{"index", 0},
                                        {"outcome", "error"},
                                        {"found", false},
                                        {"reason", reason},
                                        {"error_code", "graph"}};
        json good = item;
        good["reason"] = fields ? "fields did not match: subject"
                                : "the mail restore target couldn't be read (graph)";
        REQUIRE(valid(good));
        REQUIRE_FALSE(valid(item));
    }
}

TEST_CASE("the shared result documents validate as they say", "[result_schema]")
{
    const json& cases = cases_file().at("cases");
    REQUIRE(cases_file().at("format") == std::string{rp::kResultFormat});
    // The file can't shrink unnoticed.
    REQUIRE(cases.size() == 176);

    const std::size_t i = GENERATE(range(std::size_t{0}, std::size_t{176}));
    const json& entry = cases.at(i);
    const std::string name = entry.at("name");
    INFO(name);
    const json document = base_document().patch(entry.at("patch"));
    // No float in the shared cases: Python reads 1.0 as an integer.
    REQUIRE_FALSE(holds_float(document));

    const ResultValidation result = validate_result(document);
    INFO("first violation at \"" << result.first_pointer << "\"");
    REQUIRE(result.valid == entry.at("valid").get<bool>());
    REQUIRE((result.violations == 0) == result.valid);
    if (result.valid) {
        REQUIRE(result.first_pointer.empty());
    }
}

TEST_CASE("the shared result documents' names are unique and both kinds are there",
          "[result_schema]")
{
    std::set<std::string> names;
    std::size_t valid = 0;
    for (const json& entry : cases_file().at("cases")) {
        REQUIRE(names.insert(entry.at("name").get<std::string>()).second);
        valid += entry.at("valid").get<bool>() ? 1 : 0;
        REQUIRE(entry.size() == 3);
        REQUIRE(entry.at("patch").is_array());
    }
    REQUIRE(valid == 43);
    REQUIRE(names.contains("base"));
    // valid.json is canonical-json-v1: one line, no trailing newline.
    const std::string text = rp::test::read_shared("testdata/result-v1/valid.json");
    REQUIRE(text == rp::canonical_json(json::parse(text)));
}

// Python accepts 1.0 where the schema says integer, so these aren't in the
// shared file; the Worker's canonical form refuses a float before the schema
// is asked, and the schema refuses it too.
TEST_CASE("a float where the result schema wants an integer is invalid", "[result_schema]")
{
    const char* pointer = GENERATE("/status/counts/items", "/expected/items/0/index",
                                   "/timings/spans/total/ms", "/check/items/0/ms",
                                   "/sample/mail/requested", "/cleanup/after/mail/found");
    INFO(pointer);
    REQUIRE(validate_result(base_document()).valid);
    const ResultValidation result = validate_result(with(pointer, 5.0));
    REQUIRE_FALSE(result.valid);
    REQUIRE(result.violations >= 1);
}

// The validator library (2.4.0) reads an unsigned instance into a signed 64-bit
// value before it compares it with minimum and maximum: 2^64 - 1 would be -1
// there, inside $defs/integer's range. validate_result refuses such a number
// itself, as the schema and Python's validator do.
TEST_CASE("an integer past the signed 64-bit range is invalid wherever the schema wants an integer",
          "[result_schema]")
{
    const char* pointer = GENERATE("/check/items/0/ms", "/timings/spans/total/ms",
                                   "/status/counts/items", "/expected/items/0/index");
    const std::uint64_t value =
        GENERATE(std::uint64_t{18446744073709551615ULL},  // -1 as a signed value
                 std::uint64_t{18446744073709551615ULL} - 9007199254740990ULL, // -(2^53 - 1)
                 std::uint64_t{9223372036854775808ULL});  // 2^63
    INFO(pointer << " = " << value);
    const ResultValidation result = validate_result(with(pointer, value));
    REQUIRE_FALSE(result.valid);
    REQUIRE(result.violations >= 1);
    REQUIRE(result.first_pointer == pointer);
}

TEST_CASE("an integer past the signed 64-bit range is refused where the schema knows no key",
          "[result_schema]")
{
    // No place the schema doesn't know is ever repeated.
    const ResultValidation result =
        validate_result(with("/unknown-b41e", std::uint64_t{18446744073709551615ULL}));
    REQUIRE_FALSE(result.valid);
    REQUIRE(result.violations >= 1);
    REQUIRE(result.first_pointer.empty());
}

TEST_CASE("the embedded result schema loads into a validator", "[result_schema]")
{
    CHECK(rp::result_schema_ready());
    CHECK(rp::result_schema_ready());
    CHECK(validate_result(base_document()).valid);
}

TEST_CASE("a document that isn't an object is not a result", "[result_schema]")
{
    const json document = GENERATE(json(), json::array(), json("restoreproof.result.v1"),
                                   json(1), json::object());
    const ResultValidation result = validate_result(document);
    REQUIRE_FALSE(result.valid);
    REQUIRE(result.violations >= 1);
    REQUIRE(result.first_pointer.empty());
}

TEST_CASE("validate_result names where, never what", "[result_schema]")
{
    SECTION("a wrong value comes back as its pointer alone")
    {
        const ResultValidation result =
            validate_result(with("/started_at", "alice@contoso.example's secret"));
        REQUIRE_FALSE(result.valid);
        REQUIRE(result.violations == 1);
        REQUIRE(result.first_pointer == "/started_at");
    }

    SECTION("an array index is kept")
    {
        const ResultValidation result =
            validate_result(with("/expected/items/1/received_at", "carol@contoso.example"));
        REQUIRE_FALSE(result.valid);
        REQUIRE(result.first_pointer == "/expected/items/1/received_at");
    }

    SECTION("below a nullable section, the place is the value's own")
    {
        struct Row {
            const char* pointer;
            json value;
        };
        const Row row = GENERATE(Row{"/cleanup/after/mail/left", -1},
                                 Row{"/check/items/3/copies", 1},
                                 Row{"/sample/onedrive/random/pool_sha256", "x"},
                                 Row{"/restore/sessions/2/kind", "teams"},
                                 Row{"/timings/spans/total", json::object()},
                                 Row{"/restore_point/backup_time", "2026-10-03 22:00"},
                                 Row{"/expected", json::array()});
        INFO(row.pointer);
        const ResultValidation result = validate_result(with(row.pointer, row.value));
        REQUIRE_FALSE(result.valid);
        REQUIRE(result.violations == 1);
        REQUIRE(result.first_pointer == row.pointer);
    }

    SECTION("the first of several is the one named, and all are counted")
    {
        json document = with("/format", "x");
        document["connector"]["type"] = "y";
        document["status"]["restore_sent"] = "z";
        const ResultValidation result = validate_result(document);
        REQUIRE_FALSE(result.valid);
        REQUIRE(result.violations == 3);
        const std::set<std::string> places = {"/format", "/connector/type",
                                              "/status/restore_sent"};
        REQUIRE(places.contains(result.first_pointer));
    }

    SECTION("a key the schema doesn't know is counted at its object, never named")
    {
        const std::string key = GENERATE("Alice@contoso.example", "contoso", "a/b", "a~b", "",
                                         "Subject", "7x");
        INFO(key);
        json document = base_document();
        document["client"]["targets"][key] = "x";
        const ResultValidation result = validate_result(document);
        REQUIRE_FALSE(result.valid);
        REQUIRE(result.violations == 1);
        REQUIRE(result.first_pointer == "/client/targets");
    }
}

TEST_CASE("a pointer is kept only when the schema knows each of its parts", "[result_schema]")
{
    using rp::detail::known_result_pointer;

    SECTION("kept")
    {
        const std::string pointer =
            GENERATE("", "/status", "/expected/items/12/received_at", "/timings/spans/total/ms",
                     "/sample/mail/random/keys/0/3", "/client/targets/onedrive_folder_id",
                     "/restore/sessions/0/started_at_raw", "/check/items/0");
        INFO(pointer);
        REQUIRE(known_result_pointer(pointer) == pointer);
    }

    SECTION("dropped")
    {
        // A key of the document the schema doesn't name, however harmless it
        // looks, and anything that isn't a pointer.
        const std::string pointer =
            GENERATE("/client/targets/Alice@contoso.example", "/client/contoso", "/contoso",
                     "/status/Status", "/expected/items/1/received_at/", "/a~1b", "/a~0b",
                     "//status", "status", "/expected/items/-1", "/expected/items/1x",
                     "/expected/items/+1", "/client/targets/ mailbox", "/$defs", "/properties",
                     "/expected/items/\xC3\xBC");
        INFO(pointer);
        REQUIRE(known_result_pointer(pointer).empty());
    }
}

TEST_CASE("validate_result can be called from several threads", "[result_schema]")
{
    const json good = base_document();
    const json bad = with("/format", "x");
    std::vector<int> wrong(4, 0);
    {
        std::vector<std::jthread> threads;
        for (std::size_t t = 0; t < wrong.size(); ++t) {
            threads.emplace_back([&, t] {
                for (int i = 0; i < 20; ++i) {
                    if (!validate_result(good).valid || validate_result(bad).valid) {
                        ++wrong[t];
                    }
                }
            });
        }
    }
    REQUIRE(wrong == std::vector<int>(4, 0));
}
