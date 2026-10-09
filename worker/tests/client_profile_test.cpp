// The client profile (rp/client_profile.hpp; W4.10, docs/decisions.md
// 2026-10-09 points 1 and 8): the shared vectors judged by the reader in code
// and by the schema validator alike, the fault each bad profile is reported
// with (the key and config.json's text, never a value), the closed object, the
// config's local profile and the profile file's reader. Failure paths first.

#include "result_lab.hpp"
#include "schema_walk.hpp"
#include "test_support.hpp"

#include <rp/client_profile.hpp>
#include <rp/config.hpp>

#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using nlohmann::json;
using rp::ClientProfile;
using rp::ProfileFault;

namespace {

constexpr const char* kSchemaFile = "schemas/client-profile.v1.json";
constexpr std::size_t kCases = 104;
constexpr std::size_t kValid = 18;
constexpr std::size_t kCodeRefuses = 2;

const json& schema()
{
    static const json file = json::parse(rp::test::read_shared(kSchemaFile));
    return file;
}

const json& cases_file()
{
    static const json file =
        json::parse(rp::test::read_shared("testdata/client-profile-v1/cases.json"));
    return file;
}

const json& base_profile()
{
    static const json base = json::parse(rp::test::read_shared(
        "testdata/client-profile-v1/" + cases_file().at("base").get<std::string>()));
    return base;
}

json with(const std::string& key, json value)
{
    json document = base_profile();
    document[key] = std::move(value);
    return document;
}

// `count` Cyrillic letters: two UTF-8 bytes each, one character each.
std::string two_byte_letters(std::size_t count)
{
    std::string text;
    for (std::size_t i = 0; i < count; ++i) {
        text += "\xd0\xb6";
    }
    return text;
}

json without(const std::string& key)
{
    json document = base_profile();
    document.erase(key);
    return document;
}

std::optional<ProfileFault> fault_of(const json& value)
{
    const std::variant<ClientProfile, ProfileFault> parsed = rp::parse_client_profile(value);
    if (const ProfileFault* fault = std::get_if<ProfileFault>(&parsed)) {
        return *fault;
    }
    return std::nullopt;
}

ClientProfile profile_of(const json& value)
{
    const std::variant<ClientProfile, ProfileFault> parsed = rp::parse_client_profile(value);
    if (const ProfileFault* fault = std::get_if<ProfileFault>(&parsed)) {
        FAIL("refused: " << fault->text());
    }
    return std::get<ClientProfile>(parsed);
}

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// read_client_profile_file's ConfigError for `file`.
rp::ConfigError read_error(const std::filesystem::path& file)
{
    try {
        rp::read_client_profile_file(file);
    } catch (const rp::ConfigError& e) {
        return e;
    }
    FAIL("the file was read as a profile");
    return rp::ConfigError("", "unreachable");
}

} // namespace

// --- the shared vectors ------------------------------------------------------

TEST_CASE("the profile schema is in the shared subset and says what the entry says",
          "[client_profile][schema]")
{
    CHECK(rp::test::problems_of(schema()) == std::vector<std::string>{});
    CHECK(rp::test::read_shared(kSchemaFile).find('\r') == std::string::npos);
    CHECK(schema().at("additionalProperties") == false);
    CHECK(schema().at("properties").size() == 9);
    CHECK(schema().at("required").size() == 9);
    CHECK(schema().at("properties").at("format").at("const") ==
          std::string{rp::kClientProfileFormat});
    for (const std::string_view key : rp::kClientProfileKeys) {
        CHECK(schema().at("properties").contains(key));
    }
}

TEST_CASE("every shared profile case is judged alike by the reader and by the schema",
          "[client_profile][schema]")
{
    const json& cases = cases_file().at("cases");
    REQUIRE(cases_file().at("format") == std::string{rp::kClientProfileFormat});
    // The file can't shrink unnoticed: the Cloud pins the same counts.
    REQUIRE(cases.size() == kCases);
    std::size_t valid = 0;
    std::size_t code_refuses = 0;
    for (const json& entry : cases) {
        valid += entry.at("valid").get<bool>() ? 1 : 0;
        code_refuses += entry.value("code_refuses", false) ? 1 : 0;
    }
    REQUIRE(valid == kValid);
    REQUIRE(code_refuses == kCodeRefuses);

    nlohmann::json_schema::json_validator validator;
    validator.set_root_schema(schema());

    const std::size_t i = GENERATE(range(std::size_t{0}, kCases));
    const json& entry = cases.at(i);
    const std::string name = entry.at("name");
    INFO(name);
    const json document = base_profile().patch(entry.at("patch"));
    const bool schema_valid = entry.at("valid").get<bool>();
    const bool code_refuses_this = entry.value("code_refuses", false);
    // A case the code refuses is one the schema accepts: the file says so.
    REQUIRE((!code_refuses_this || schema_valid));

    bool accepted = true;
    try {
        validator.validate(document);
    } catch (const std::exception&) {
        accepted = false;
    }
    CHECK(accepted == schema_valid);

    const std::optional<ProfileFault> fault = fault_of(document);
    const std::string said = fault ? fault->text() : std::string{"a profile"};
    INFO(said);
    CHECK(fault.has_value() == (!schema_valid || code_refuses_this));
    if (!fault) {
        // What was read is what the document holds.
        CHECK(rp::to_json(std::get<ClientProfile>(rp::parse_client_profile(document))) ==
              document);
    }
}

// --- the faults --------------------------------------------------------------

TEST_CASE("a bad profile is reported with its first key at fault and config.json's text",
          "[client_profile]")
{
    struct Row {
        const char* name;
        json document;
        ProfileFault fault;
    };
    const Row row = GENERATE(
        Row{"an array", json::array(), {"", "not a restoreproof.client-profile.v1 document"}},
        Row{"null", json(), {"", "not a restoreproof.client-profile.v1 document"}},
        Row{"no format", without("format"), {"", "not a restoreproof.client-profile.v1 document"}},
        Row{"another format", with("format", "restoreproof.jobs.v1"),
            {"", "not a restoreproof.client-profile.v1 document"}},
        Row{"a format that is a number", with("format", 1),
            {"", "not a restoreproof.client-profile.v1 document"}},
        Row{"an unknown key, named", with("client_id", "client-7"),
            {"", "has a key that isn't the profile's: \"client_id\""}},
        Row{"an unknown key that can't be printed", with("bad key\x07", 1),
            {"", "has a key that isn't the profile's"}},
        Row{"an unknown key before a missing one", with("zzz", 1).patch(json::parse(
                                                            R"([{"op":"remove","path":"/test_mailbox"}])")),
            {"", "has a key that isn't the profile's: \"zzz\""}},
        Row{"a missing key", without("veeam_org_name"), {"veeam_org_name", "is missing (required)"}},
        Row{"the first missing key in the config's order",
            without("test_site_id").patch(json::parse(R"([{"op":"remove","path":"/graph_client_id"}])")),
            {"graph_client_id", "is missing (required)"}},
        Row{"a number", with("graph_tenant_id", 7), {"graph_tenant_id", "must be a string"}},
        Row{"null", with("test_library_id", nullptr), {"test_library_id", "must be a string"}},
        Row{"empty", with("veeam_org_name", ""), {"veeam_org_name", "must not be empty"}},
        Row{"a newline in the organisation's name", with("veeam_org_name", "a\nb"),
            {"veeam_org_name", "must not contain control characters"}},
        Row{"a bidi control in the organisation's name", with("veeam_org_name", "a\xe2\x80\xae" "b"),
            {"veeam_org_name", "must not contain control characters"}},
        Row{"an organisation name of 1025 characters", with("veeam_org_name", std::string(1025, 'o')),
            {"veeam_org_name", "must be at most 1024 characters"}},
        // The limit counts characters as the schema does, not UTF-8 bytes.
        Row{"an organisation name of 1025 two-byte characters",
            with("veeam_org_name", two_byte_letters(1025)),
            {"veeam_org_name", "must be at most 1024 characters"}},
        Row{"a mailbox of 1025 characters",
            with("test_mailbox", "restoretest@" + std::string(1009, 'a') + ".com"),
            {"test_mailbox", "must be at most 1024 characters"}},
        Row{"a tenant in braces", with("graph_tenant_id", "{11111111-2222-3333-4444-555555555555}"),
            {"graph_tenant_id", std::string{rp::kGuidRule}}},
        Row{"an app ID that is a name", with("graph_client_id", "RestoreProof Worker"),
            {"graph_client_id", std::string{rp::kGuidRule}}},
        Row{"another mailbox", with("test_mailbox", "alice@contoso.onmicrosoft.com"),
            {"test_mailbox", std::string{rp::kRestoreMailboxRule}}},
        Row{"a site URL", with("test_site_id", "https://contoso.sharepoint.com/sites/RestoreTest"),
            {"test_site_id", std::string{rp::kGraphSiteIdRule}}},
        Row{"a list GUID for the library", with("test_library_id", "ffec069d-65e4-4c3a-9da2-ac086cf9dafa"),
            {"test_library_id", std::string{rp::kGraphDriveIdRule}}},
        Row{"a OneDrive drive ID without b!", with("test_onedrive_drive_id", "onedrive"),
            {"test_onedrive_drive_id", std::string{rp::kGraphDriveIdRule}}},
        Row{"a folder ID with a slash", with("test_onedrive_folder_id", "01/ABC"),
            {"test_onedrive_folder_id", std::string{rp::kGraphItemIdRule}}});
    CAPTURE(row.name);

    const std::optional<ProfileFault> fault = fault_of(row.document);
    REQUIRE(fault);
    CHECK(fault->key == row.fault.key);
    CHECK(fault->problem == row.fault.problem);
    CHECK(fault->text() == (row.fault.key.empty()
                                ? row.fault.problem
                                : "key \"" + row.fault.key + "\" " + row.fault.problem));
    // Never a value of the document.
    CHECK_THAT(fault->text(), !ContainsSubstring("contoso"));
    CHECK_THAT(fault->text(), !ContainsSubstring("client-7"));
}

TEST_CASE("the profile's rule texts are config.json's own", "[client_profile]")
{
    // One text per rule (point 1): the config's switch and the profile's
    // reader say the same words.
    CHECK(std::string{rp::kGuidRule} ==
          "must be a GUID (8-4-4-4-12 hexadecimal digits, as the Entra admin center shows it), "
          "not a name");
    CHECK(std::string{rp::kRestoreMailboxRule} ==
          "must be restoretest@<domain>: restores only ever go to the restoretest mailbox");
    const rp::ConfigError error = [] {
        try {
            rp::parse_config(R"({"cloud_url":"https://c","veeam_url":"https://v",)"
                             R"("veeam_org_name":"o","graph_tenant_id":"x","graph_client_id":"x",)"
                             R"("test_mailbox":"restoretest@a.b","test_site_id":"s",)"
                             R"("test_library_id":"l","test_onedrive_drive_id":"d",)"
                             R"("test_onedrive_folder_id":"f"})");
        } catch (const rp::ConfigError& e) {
            return e;
        }
        return rp::ConfigError("", "accepted");
    }();
    CHECK(error.key() == "graph_tenant_id");
    CHECK_THAT(error.what(), ContainsSubstring(std::string{rp::kGuidRule}));
}

// --- the profile, the object and the config's local profile -------------------

TEST_CASE("a profile is read with every key, and written back as the closed object",
          "[client_profile]")
{
    const ClientProfile profile = profile_of(base_profile());
    CHECK(profile.veeam_org_name == "contoso.onmicrosoft.com");
    CHECK(profile.graph_tenant_id == "11111111-2222-3333-4444-555555555555");
    CHECK(profile.graph_client_id == "22222222-3333-4444-5555-666666666666");
    CHECK(profile.test_mailbox == "restoretest@contoso.onmicrosoft.com");
    CHECK(profile.test_site_id ==
          "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
          "aaaaaaaa-0000-0000-0000-000000000002");
    CHECK(profile.test_library_id == "b!library");
    CHECK(profile.test_onedrive_drive_id == "b!onedrive");
    CHECK(profile.test_onedrive_folder_id == "01FOLDER");
    // Values are kept as given: the case of a GUID or the mailbox isn't changed.
    const ClientProfile upper = profile_of(with("test_mailbox", "RESTORETEST@Contoso.OnMicrosoft.com"));
    CHECK(upper.test_mailbox == "RESTORETEST@Contoso.OnMicrosoft.com");

    const json object = rp::to_json(profile);
    CHECK(object == base_profile());
    CHECK(object.at("format") == std::string{rp::kClientProfileFormat});
    CHECK(object.size() == 9);
    CHECK(profile_of(object) == profile);
}

TEST_CASE("the config's eight client keys are its local profile, or there is none",
          "[client_profile]")
{
    rp::Config config;
    CHECK_FALSE(rp::local_profile(config));

    config.veeam_org_name = "contoso.onmicrosoft.com";
    config.graph_tenant_id = "11111111-2222-3333-4444-555555555555";
    config.graph_client_id = "22222222-3333-4444-5555-666666666666";
    config.test_mailbox = "restoretest@contoso.onmicrosoft.com";
    config.test_site_id = "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
                          "aaaaaaaa-0000-0000-0000-000000000002";
    config.test_library_id = "b!library";
    config.test_onedrive_drive_id = "b!onedrive";
    config.test_onedrive_folder_id = "01FOLDER";
    const std::optional<ClientProfile> local = rp::local_profile(config);
    REQUIRE(local);
    CHECK(*local == profile_of(base_profile()));

    // parse_config takes the eight together or not at all, so a Config built
    // in code with some of them is no local profile either.
    config.test_onedrive_folder_id.clear();
    CHECK_FALSE(rp::local_profile(config));
}

// --- the file ----------------------------------------------------------------

TEST_CASE("a profile file that can't be used is refused by one line naming no value",
          "[client_profile][file]")
{
    rp::test::TempDir dir;
    struct Row {
        const char* name;
        std::filesystem::path file;
        std::string problem;
    };
    const std::vector<Row> rows{
        {"missing", dir.path() / "missing.json", "can't be read"},
        {"a folder", dir.path(), "can't be read"},
        {"over 64 KiB", dir.write("big.json", std::string(64u * 1024u + 1, ' ')), "over 64 KiB"},
        {"not JSON", dir.write("text.json", "not json"), "not JSON"},
        {"a key twice",
         dir.write("twice.json", R"({"format":"restoreproof.client-profile.v1","format":"x"})"),
         "not JSON"},
        {"nested past 32 levels", dir.write("deep.json", std::string(40, '[') + std::string(40, ']')),
         "not JSON"},
        {"a jobs document", dir.write("jobs.json", R"({"format":"restoreproof.jobs.v1","jobs":[]})"),
         "not a restoreproof.client-profile.v1 document"},
        {"a bad key",
         dir.write("bad.json", with("test_mailbox", "alice@contoso.onmicrosoft.com").dump()),
         "key \"test_mailbox\" " + std::string{rp::kRestoreMailboxRule}},
        {"a missing key", dir.write("short.json", without("graph_client_id").dump()),
         "key \"graph_client_id\" is missing (required)"}};
    for (const Row& row : rows) {
        CAPTURE(row.name);
        const rp::ConfigError error = read_error(row.file);
        CHECK(error.key() == "--profile-file");
        CHECK(std::string{error.what()} == "--profile-file " + utf8(row.file) + ": " + row.problem);
        CHECK_THAT(error.what(), !ContainsSubstring("alice"));
    }
}

TEST_CASE("a profile file is read whole: white space, key order and a byte order mark taken",
          "[client_profile][file]")
{
    rp::test::TempDir dir;
    const std::filesystem::path pretty = dir.write("pretty.json", "\xef\xbb\xbf" + base_profile().dump(2) + "\n");
    CHECK(rp::read_client_profile_file(pretty) == profile_of(base_profile()));
    // A name outside the ANSI code page is read too.
    const std::filesystem::path wide = dir.write(L"профиль.json", base_profile().dump());
    CHECK(rp::read_client_profile_file(wide) == profile_of(base_profile()));
    // And the limit is the limit: exactly 64 KiB is read.
    std::string padded = base_profile().dump();
    padded.append(64u * 1024u - padded.size(), ' ');
    CHECK(rp::read_client_profile_file(dir.write("padded.json", padded)) ==
          profile_of(base_profile()));
}
