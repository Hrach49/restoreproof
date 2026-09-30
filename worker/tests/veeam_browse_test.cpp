// Reading Veeam's listings (src/veeam_browse.hpp), shared by restore_sample
// (W2.5) and list_candidates (W2.6).

#include "../src/veeam_browse.hpp"
#include "../src/veeam_restore.hpp"

#include <rp/connector.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <vector>

namespace {

using nlohmann::json;
namespace vb = rp::veeam_browse;
using rp::veeam_restore::ShapeError;

struct BoolRow {
    std::string entry;
    bool expected;
};

struct RefusedRow {
    std::string entry;
    std::string message;
};

} // namespace

TEST_CASE("bool_at refuses an entry or a value of another kind", "[veeam_browse]")
{
    const RefusedRow row = GENERATE(values<RefusedRow>({
        {R"(["isArchive"])", "an entry that isn't an object"},
        {R"("text")", "an entry that isn't an object"},
        {R"({"isArchive":"true"})", "\"isArchive\" isn't a boolean"},
        {R"({"isArchive":1})", "\"isArchive\" isn't a boolean"},
        {R"({"isArchive":{}})", "\"isArchive\" isn't a boolean"},
    }));
    CAPTURE(row.entry);
    CHECK_THROWS_WITH(vb::bool_at(json::parse(row.entry), "isArchive"), row.message);
    CHECK_THROWS_AS(vb::bool_at(json::parse(row.entry), "isArchive"), ShapeError);
}

TEST_CASE("bool_at reads a bool, and a missing or null one as false", "[veeam_browse]")
{
    const BoolRow row = GENERATE(values<BoolRow>({
        {R"({})", false},
        {R"({"isArchive":null})", false},
        {R"({"isArchive":false})", false},
        {R"({"isArchive":true})", true},
        {R"({"isPublic":true})", false},
    }));
    CAPTURE(row.entry);
    CHECK(vb::bool_at(json::parse(row.entry), "isArchive") == row.expected);
}

TEST_CASE("text_at reads a string, and a missing or null one as none", "[veeam_browse]")
{
    CHECK_THROWS_WITH(vb::text_at(json::array(), "name"), "an entry that isn't an object");
    CHECK_THROWS_WITH(vb::text_at(json{{"name", 3}}, "name"), "\"name\" isn't a string");
    CHECK(vb::text_at(json::object(), "name") == nullptr);
    CHECK(vb::text_at(json{{"name", nullptr}}, "name") == nullptr);
    const json entry{{"name", "Inbox"}};
    REQUIRE(vb::text_at(entry, "name") != nullptr);
    CHECK(*vb::text_at(entry, "name") == "Inbox");
}

TEST_CASE("is_file_named takes a document whose isFolder is false", "[veeam_browse]")
{
    CHECK_THROWS_WITH(vb::is_file_named(json{{"name", "a.pdf"}, {"isFolder", "no"}}, "a.pdf"),
                      "\"isFolder\" isn't a boolean");
    CHECK_FALSE(vb::is_file_named(json{{"name", "a.pdf"}}, "a.pdf"));
    CHECK_FALSE(vb::is_file_named(json{{"name", "a.pdf"}, {"isFolder", nullptr}}, "a.pdf"));
    CHECK_FALSE(vb::is_file_named(json{{"name", "a.pdf"}, {"isFolder", true}}, "a.pdf"));
    CHECK_FALSE(vb::is_file_named(json{{"name", "A.pdf"}, {"isFolder", false}}, "a.pdf"));
    CHECK(vb::is_file_named(json{{"name", "a.pdf"}, {"isFolder", false}}, "a.pdf"));
}

TEST_CASE("exactly_one names the item and what it looked for", "[veeam_browse]")
{
    const std::vector<json> list{json{{"id", "1"}, {"name", "a"}}, json{{"id", "2"}, {"name", "a"}},
                                 json{{"id", "3"}, {"name", "b"}}};
    const auto named = [](const std::string& name) {
        return [name](const json& e) { return e.at("name") == name; };
    };
    CHECK_THROWS_AS(vb::exactly_one(list, "mail item 0 \"x\"", "the message", named("c")),
                    rp::connector::NotFoundError);
    CHECK_THROWS_WITH(vb::exactly_one(list, "mail item 0 \"x\"", "the message", named("c")),
                      "veeam_m365: mail item 0 \"x\": the message not found in the restore point");
    CHECK_THROWS_WITH(vb::exactly_one(list, "mail item 0 \"x\"", "the message", named("a")),
                      "veeam_m365: mail item 0 \"x\": the message matches 2 entries in the "
                      "restore point");
    CHECK(vb::id_of(vb::exactly_one(list, "item", "it", named("b"))) == "3");
    CHECK(vb::shown_text("line\nbreak") == "\"line break\"");
}
