// The canary manifest loader (W2.6, rp/canary_manifest.hpp): the committed
// lab/seed-manifest.json, and in-memory edits of it that break one rule each.

#include <rp/canary_manifest.hpp>

#include "../src/path_utf8.hpp"

#include <rp/config.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>
#include <string_view>

namespace {

using nlohmann::json;
using rp::sampling::CanaryFile;
using rp::sampling::ContentRule;
using rp::sampling::ManifestError;

// Entries 0-19 are the mails, 20-29 the SharePoint files, 30-39 the OneDrive
// files (the manifest's catalog order).
constexpr int kFirstSharePoint = 20;
constexpr int kFirstOneDrive = 30;

std::filesystem::path manifest_path()
{
    return std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json";
}

std::string manifest_text()
{
    std::ifstream in(manifest_path(), std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

const json& manifest_json()
{
    static const json parsed = json::parse(manifest_text());
    return parsed;
}

std::string refusal_of(std::string_view text)
{
    try {
        rp::sampling::parse_canary_manifest(text);
    } catch (const ManifestError& e) {
        return e.what();
    }
    return "(accepted)";
}

std::string refusal_of_edit(const std::function<void(json&)>& edit)
{
    json manifest = manifest_json();
    edit(manifest);
    return refusal_of(manifest.dump());
}

const CanaryFile& file_named(const std::vector<CanaryFile>& files, std::string_view name)
{
    for (const CanaryFile& file : files) {
        if (file.name == name) {
            return file;
        }
    }
    FAIL("no canary file " << name);
    throw;
}

struct Row {
    std::string what;
    std::function<void(json&)> edit;
    std::string message;
};

std::string at(int entry, std::string_view rest)
{
    return "canary manifest: /entries/" + std::to_string(entry) + std::string{rest};
}

} // namespace

// Failure paths first.
TEST_CASE("the canary manifest refuses text that isn't a JSON object", "[canary-manifest]")
{
    const auto [text, message] = GENERATE(table<std::string, std::string>({
        {"", "canary manifest: isn't valid JSON"},
        {"{\"schema\": ", "canary manifest: isn't valid JSON"},
        {"[]", "canary manifest: must be a JSON object"},
        {"\"seed-manifest.v1\"", "canary manifest: must be a JSON object"},
    }));
    CAPTURE(text);
    CHECK(refusal_of(text) == message);
}

TEST_CASE("the canary manifest refuses an entry or field that breaks its rule",
          "[canary-manifest]")
{
    const std::string schema = "canary manifest: /schema: must be \"seed-manifest.v1\"";
    const std::string tenant = "canary manifest: /tenant_id: must be a GUID";
    const std::string received = at(0, "/received_at: must be \"YYYY-MM-DDTHH:MM:SSZ\"");
    const std::string stored_size = at(kFirstSharePoint, "/stored_size: must be an integer of 0 or more");
    const std::string folder_path =
        at(kFirstSharePoint, "/location/folder_path: must start with \"/\" and have no \"..\" segment");
    const std::string od_folder_path =
        at(kFirstOneDrive, "/location/folder_path: must start with \"/\" and have no \"..\" segment");
    const Row row = GENERATE_COPY(values<Row>({
        {"no schema", [](json& m) { m.erase("schema"); }, schema},
        {"schema v2", [](json& m) { m["schema"] = "seed-manifest.v2"; }, schema},
        {"schema a number", [](json& m) { m["schema"] = 1; }, schema},
        {"no tenant_id", [](json& m) { m.erase("tenant_id"); }, tenant},
        {"tenant_id a name", [](json& m) { m["tenant_id"] = "RestoreProofLab.onmicrosoft.com"; }, tenant},
        {"no entries", [](json& m) { m.erase("entries"); }, "canary manifest: /entries: must be an array"},
        {"entries an object", [](json& m) { m["entries"] = json::object(); },
         "canary manifest: /entries: must be an array"},
        {"an entry a number", [](json& m) { m["entries"][3] = 5; }, at(3, ": must be an object")},
        {"an unknown kind", [](json& m) { m["entries"][3]["kind"] = "teams_message"; },
         at(3, "/kind: must be \"mail\", \"sharepoint_file\" or \"onedrive_file\"")},
        {"no kind", [](json& m) { m["entries"][3].erase("kind"); },
         at(3, "/kind: must be \"mail\", \"sharepoint_file\" or \"onedrive_file\"")},
        {"no id", [](json& m) { m["entries"][3].erase("id"); }, at(3, "/id: must be a non-empty string")},
        {"an empty id", [](json& m) { m["entries"][3]["id"] = ""; }, at(3, "/id: must be a non-empty string")},
        {"an id a number", [](json& m) { m["entries"][3]["id"] = 3; }, at(3, "/id: must be a non-empty string")},
        {"an id repeated", [](json& m) { m["entries"][35]["id"] = m["entries"][2]["id"]; },
         at(35, "/id: repeats /entries/2/id")},
        // Mail.
        {"no subject", [](json& m) { m["entries"][0].erase("subject"); },
         at(0, "/subject: must be a non-empty string")},
        {"an empty subject", [](json& m) { m["entries"][0]["subject"] = ""; },
         at(0, "/subject: must be a non-empty string")},
        {"no received_at", [](json& m) { m["entries"][0].erase("received_at"); }, received},
        {"received_at with a fraction", [](json& m) { m["entries"][0]["received_at"] = "2026-09-24T22:14:43.5Z"; }, received},
        {"received_at with an offset", [](json& m) { m["entries"][0]["received_at"] = "2026-09-24T22:14:43+00:00"; }, received},
        {"received_at with a space", [](json& m) { m["entries"][0]["received_at"] = "2026-09-24 22:14:43Z"; }, received},
        {"received_at a non-digit", [](json& m) { m["entries"][0]["received_at"] = "2026-09-2xT22:14:43Z"; }, received},
        {"no location", [](json& m) { m["entries"][0].erase("location"); }, at(0, "/location: must be an object")},
        {"location a string", [](json& m) { m["entries"][0]["location"] = "Inbox"; }, at(0, "/location: must be an object")},
        {"no mailbox", [](json& m) { m["entries"][0]["location"].erase("mailbox"); },
         at(0, "/location/mailbox: must be a non-empty string")},
        {"a restoretest mailbox", [](json& m) { m["entries"][0]["location"]["mailbox"] = "RestoreTest@RestoreProofLab.onmicrosoft.com"; },
         at(0, "/location/mailbox: is a restore target (a restoretest mailbox)")},
        {"no folder", [](json& m) { m["entries"][0]["location"]["folder"] = ""; },
         at(0, "/location/folder: must be a non-empty string")},
        {"a subject repeated but for case", [](json& m) { m["entries"][7]["subject"] = "rp-canary-0002"; },
         at(7, "/subject: repeats /entries/1/subject (ignoring case)")},
        // Files.
        {"no name", [](json& m) { m["entries"][kFirstSharePoint].erase("name"); },
         at(kFirstSharePoint, "/name: must be a non-empty string")},
        {"another file_type", [](json& m) { m["entries"][kFirstSharePoint]["file_type"] = "doc"; },
         at(kFirstSharePoint, "/file_type: must be \"pdf\", \"docx\", \"xlsx\", \"txt\" or \"png\"")},
        {"no content_rule", [](json& m) { m["entries"][kFirstOneDrive].erase("content_rule"); },
         at(kFirstOneDrive, "/content_rule: must be \"bytes\" or \"office-v1\"")},
        {"content_rule office-v2", [](json& m) { m["entries"][kFirstSharePoint]["content_rule"] = "office-v2"; },
         at(kFirstSharePoint, "/content_rule: must be \"bytes\" or \"office-v1\"")},
        {"stored_size below 0", [](json& m) { m["entries"][kFirstSharePoint]["stored_size"] = -1; }, stored_size},
        {"stored_size a fraction", [](json& m) { m["entries"][kFirstSharePoint]["stored_size"] = 925.5; }, stored_size},
        {"stored_size a string", [](json& m) { m["entries"][kFirstSharePoint]["stored_size"] = "925"; }, stored_size},
        {"no stored_size", [](json& m) { m["entries"][kFirstSharePoint].erase("stored_size"); }, stored_size},
        {"a relative folder_path", [](json& m) { m["entries"][kFirstSharePoint]["location"]["folder_path"] = "RestoreTest"; }, folder_path},
        {"an empty folder_path", [](json& m) { m["entries"][kFirstSharePoint]["location"]["folder_path"] = ""; }, folder_path},
        {"a folder_path with ..", [](json& m) { m["entries"][kFirstOneDrive]["location"]["folder_path"] = "/RestoreTest/../RestoreTarget"; }, od_folder_path},
        {"a folder_path ending in ..", [](json& m) { m["entries"][kFirstOneDrive]["location"]["folder_path"] = "/RestoreTest/.."; }, od_folder_path},
        {"no file location", [](json& m) { m["entries"][kFirstOneDrive].erase("location"); },
         at(kFirstOneDrive, "/location: must be an object")},
        {"a name repeated but for case", [](json& m) { m["entries"][kFirstSharePoint + 4]["name"] = "RP-CANARY-01.PDF"; },
         at(kFirstSharePoint + 4, "/name: repeats /entries/20/name (ignoring case)")},
        // SharePoint.
        {"site_id a GUID", [](json& m) { m["entries"][kFirstSharePoint]["location"]["site_id"] = "fe08085d-eb70-42e8-95a6-470189bd98eb"; },
         at(kFirstSharePoint, "/location/site_id: ") + std::string{rp::kGraphSiteIdRule}},
        {"drive_id a list ID", [](json& m) { m["entries"][kFirstSharePoint]["location"]["drive_id"] = m["entries"][kFirstSharePoint]["location"]["list_id"]; },
         at(kFirstSharePoint, "/location/drive_id: ") + std::string{rp::kGraphDriveIdRule}},
        {"list_id not a GUID", [](json& m) { m["entries"][kFirstSharePoint]["location"]["list_id"] = "RestoreTest"; },
         at(kFirstSharePoint, "/location/list_id: must be a GUID")},
        {"no list_id", [](json& m) { m["entries"][kFirstSharePoint]["location"].erase("list_id"); },
         at(kFirstSharePoint, "/location/list_id: must be a GUID")},
        // OneDrive.
        {"no user", [](json& m) { m["entries"][kFirstOneDrive]["location"].erase("user"); },
         at(kFirstOneDrive, "/location/user: must be a non-empty string")},
    }));
    CAPTURE(row.what);
    CHECK(refusal_of_edit(row.edit) == row.message);
}

TEST_CASE("load_canary_manifest reports a file it can't read", "[canary-manifest]")
{
    const std::filesystem::path missing = std::filesystem::path{RP_SOURCE_DIR} / "no-such-manifest.json";
    try {
        rp::sampling::load_canary_manifest(missing);
        FAIL("loaded");
    } catch (const ManifestError& e) {
        CHECK(std::string{e.what()} ==
              "canary manifest: " + rp::path_to_utf8(missing) + ": cannot read the file");
    }
}

TEST_CASE("the committed manifest loads: 20 mails, 10 SharePoint and 10 OneDrive files",
          "[canary-manifest]")
{
    const std::string text = manifest_text();
    const rp::sampling::CanaryManifest manifest = rp::sampling::load_canary_manifest(manifest_path());
    CHECK(manifest.tenant_id == manifest_json().at("tenant_id").get<std::string>());
    CHECK(manifest.sha256 == rp::sha256_hex(text));
    REQUIRE(manifest.mail.size() == 20);
    REQUIRE(manifest.sharepoint.size() == 10);
    REQUIRE(manifest.onedrive.size() == 10);

    // Each field read from where the manifest has it.
    const json& entries = manifest_json().at("entries");
    for (std::size_t i = 0; i < manifest.mail.size(); ++i) {
        const rp::sampling::CanaryMail& mail = manifest.mail[i];
        const json& entry = entries.at(i);
        CAPTURE(i);
        CHECK(mail.entry == i);
        CHECK(mail.id == entry.at("id").get<std::string>());
        CHECK(mail.subject == entry.at("subject").get<std::string>());
        CHECK(mail.received_at == entry.at("received_at").get<std::string>());
        CHECK(mail.mailbox == entry.at("location").at("mailbox").get<std::string>());
        CHECK(mail.folder == entry.at("location").at("folder").get<std::string>());
    }
    for (std::size_t i = 0; i < manifest.sharepoint.size(); ++i) {
        const CanaryFile& file = manifest.sharepoint[i];
        const json& entry = entries.at(kFirstSharePoint + i);
        CAPTURE(i);
        CHECK(file.entry == kFirstSharePoint + i);
        CHECK(file.id == entry.at("id").get<std::string>());
        CHECK(file.name == entry.at("name").get<std::string>());
        CHECK(file.file_type == entry.at("file_type").get<std::string>());
        CHECK(file.stored_size == entry.at("stored_size").get<std::int64_t>());
        CHECK(file.folder_path == entry.at("location").at("folder_path").get<std::string>());
        CHECK(file.site_id == entry.at("location").at("site_id").get<std::string>());
        CHECK(file.drive_id == entry.at("location").at("drive_id").get<std::string>());
        CHECK(file.list_id == entry.at("location").at("list_id").get<std::string>());
        CHECK(file.user.empty());
    }
    for (std::size_t i = 0; i < manifest.onedrive.size(); ++i) {
        const CanaryFile& file = manifest.onedrive[i];
        const json& entry = entries.at(kFirstOneDrive + i);
        CAPTURE(i);
        CHECK(file.entry == kFirstOneDrive + i);
        CHECK(file.id == entry.at("id").get<std::string>());
        CHECK(file.name == entry.at("name").get<std::string>());
        CHECK(file.folder_path == entry.at("location").at("folder_path").get<std::string>());
        CHECK(file.user == entry.at("location").at("user").get<std::string>());
        CHECK(file.site_id.empty());
        CHECK(file.drive_id.empty());
        CHECK(file.list_id.empty());
    }
    CHECK(manifest.mail.front().id == "RP-CANARY-0001");
    CHECK(manifest.sharepoint.front().name == "rp-canary-01.pdf");
    CHECK(manifest.sharepoint.front().content_rule == ContentRule::bytes);
    CHECK(file_named(manifest.sharepoint, "rp-canary-02.docx").content_rule == ContentRule::office_v1);
    CHECK(manifest.onedrive.front().name == "rp-canary-11.pdf");
}

TEST_CASE("the manifest's SHA-256 is of its bytes, not of the JSON", "[canary-manifest]")
{
    const std::string compact = manifest_json().dump();
    CHECK(rp::sampling::parse_canary_manifest(compact).sha256 == rp::sha256_hex(compact));
    CHECK(rp::sampling::parse_canary_manifest(compact).sha256 != rp::sha256_hex(manifest_text()));
}

TEST_CASE("a pilot's manifest may hold other counts, none included; other fields are ignored",
          "[canary-manifest]")
{
    json manifest = manifest_json();
    manifest["entries"] = json::array({manifest_json().at("entries").at(kFirstOneDrive)});
    manifest["entries"][0]["new_field"] = {1, 2};
    manifest["entries"][0]["name"] = "rp-canary-01.pdf"; // a SharePoint canary's name: another kind
    const rp::sampling::CanaryManifest one = rp::sampling::parse_canary_manifest(manifest.dump());
    CHECK(one.mail.empty());
    CHECK(one.sharepoint.empty());
    REQUIRE(one.onedrive.size() == 1);
    CHECK(one.onedrive.front().entry == 0);

    manifest["entries"] = json::array();
    const rp::sampling::CanaryManifest none = rp::sampling::parse_canary_manifest(manifest.dump());
    CHECK(none.mail.empty());
    CHECK(none.sharepoint.empty());
    CHECK(none.onedrive.empty());
}

TEST_CASE("a canary's selector: stored_size for bytes files, -1 for office-v1 ones",
          "[canary-manifest]")
{
    const rp::sampling::CanaryManifest manifest = rp::sampling::load_canary_manifest(manifest_path());

    const auto [name, size] = GENERATE(table<std::string, std::int64_t>({
        {"rp-canary-01.pdf", 925},
        {"rp-canary-02.docx", -1},
        {"rp-canary-03.xlsx", -1},
        {"rp-canary-04.txt", manifest_json().at("entries").at(kFirstSharePoint + 3).at("stored_size").get<std::int64_t>()},
    }));
    CAPTURE(name);
    const CanaryFile& file = file_named(manifest.sharepoint, name);
    const rp::connector::SharePointSelector sp = rp::sampling::to_sharepoint_selector(file);
    CHECK(sp.site_id == file.site_id);
    CHECK(sp.drive_id == file.drive_id);
    CHECK(sp.folder_path == file.folder_path);
    CHECK(sp.name == file.name);
    CHECK(sp.list_id == file.list_id);
    CHECK(sp.size == size);
}

TEST_CASE("a OneDrive canary's and a mail canary's selectors", "[canary-manifest]")
{
    const rp::sampling::CanaryManifest manifest = rp::sampling::load_canary_manifest(manifest_path());

    const CanaryFile& pdf = file_named(manifest.onedrive, "rp-canary-11.pdf");
    const rp::connector::OneDriveSelector od = rp::sampling::to_onedrive_selector(pdf);
    CHECK(od.user == pdf.user);
    CHECK(od.folder_path == pdf.folder_path);
    CHECK(od.name == "rp-canary-11.pdf");
    CHECK(od.size == 925);
    // OneDrive keeps Office files as uploaded, but office-v1 is the rule wherever they are.
    CHECK(rp::sampling::to_onedrive_selector(file_named(manifest.onedrive, "rp-canary-12.docx")).size == -1);

    const rp::connector::MailSelector mail = rp::sampling::to_selector(manifest.mail.front());
    CHECK(mail.mailbox == manifest.mail.front().mailbox);
    CHECK(mail.folder == "Inbox");
    CHECK(mail.subject == "RP-CANARY-0001");
    CHECK(mail.received_at == manifest.mail.front().received_at);
}
