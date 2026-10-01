// The canary manifest loader (W2.6 and W3.1, rp/canary_manifest.hpp): the
// committed lab/seed-manifest.json, and in-memory edits of it that break one
// rule each.

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

TEST_CASE("the canary manifest refuses a number too large for a double, without quoting it",
          "[canary-manifest]")
{
    // nlohmann throws out_of_range 406, not parse_error, and its message
    // quotes the number: it must still be a ManifestError that doesn't.
    const std::string number = GENERATE(as<std::string>{}, "1e400", "-1e400", "1e99999");
    CAPTURE(number);
    const std::string text = manifest_text();
    REQUIRE(text.starts_with("{"));
    const std::string edited = "{\"unused\": " + number + ", " + text.substr(1);

    const std::string message = refusal_of(edited);

    CHECK(message == "canary manifest: isn't valid JSON (a number is out of range)");
    CHECK(message.find(number) == std::string::npos);
}

TEST_CASE("the canary manifest takes a received_at at the edges of a real date and time",
          "[canary-manifest]")
{
    const std::string value = GENERATE(as<std::string>{}, "2028-02-29T00:00:00Z",
                                       "2026-12-31T23:59:59Z", "2000-02-29T12:00:00Z");
    CAPTURE(value);
    CHECK(refusal_of_edit([&](json& m) { m["entries"][0]["received_at"] = value; }) ==
          "(accepted)");
}

TEST_CASE("the canary manifest refuses an entry or field that breaks its rule",
          "[canary-manifest]")
{
    const std::string schema = "canary manifest: /schema: must be \"seed-manifest.v1\"";
    const std::string tenant = "canary manifest: /tenant_id: must be a GUID";
    const std::string received =
        at(0, "/received_at: must be \"YYYY-MM-DDTHH:MM:SSZ\", a real date and time in UTC");
    const std::string stored_size = at(kFirstSharePoint, "/stored_size: must be an integer of 0 or more");
    const std::string sent =
        at(4, "/sent_at: must be \"YYYY-MM-DDTHH:MM:SSZ\", a real date and time in UTC");
    const std::string one_at = at(4, "/sender: must hold exactly one \"@\" (an address)");
    const std::string sender_space = at(4, "/sender: holds whitespace or a control character");
    const std::string message_id_control = at(4, "/internet_message_id: holds a control character");
    const std::string normalization = at(4, "/body_normalization: must be \"text-v1\", the only one known");
    const std::string body_hash = at(4, "/body_sha256: must be 64 lower-case hex digits (a SHA-256)");
    const std::string content_hash =
        at(kFirstOneDrive + 1, "/content_sha256: must be 64 lower-case hex digits (a SHA-256)");
    const std::string folder_path =
        at(kFirstSharePoint, "/location/folder_path: must start with \"/\" and have no \"..\" segment, backslash or colon");
    const std::string od_folder_path =
        at(kFirstOneDrive, "/location/folder_path: must start with \"/\" and have no \"..\" segment, backslash or colon");
    const auto rule_by_type = [](int entry) {
        return at(entry, "/content_rule: must be \"office-v1\" for a docx or xlsx and \"bytes\" for a pdf, txt or png");
    };
    const auto name_by_type = [](int entry) {
        return at(entry, "/name: must be a name SharePoint rewrites (src/office_files.hpp) for a docx or xlsx, and only then");
    };
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
        // The shape holds, the date or time doesn't.
        {"received_at month 13, hour 99", [](json& m) { m["entries"][0]["received_at"] = "2026-13-45T99:99:99Z"; }, received},
        {"received_at month 0", [](json& m) { m["entries"][0]["received_at"] = "2026-00-10T22:14:43Z"; }, received},
        {"received_at day 0", [](json& m) { m["entries"][0]["received_at"] = "2026-09-00T22:14:43Z"; }, received},
        {"received_at 31 September", [](json& m) { m["entries"][0]["received_at"] = "2026-09-31T22:14:43Z"; }, received},
        {"received_at 29 February of a common year", [](json& m) { m["entries"][0]["received_at"] = "2026-02-29T22:14:43Z"; }, received},
        {"received_at hour 24", [](json& m) { m["entries"][0]["received_at"] = "2026-09-24T24:00:00Z"; }, received},
        {"received_at minute 60", [](json& m) { m["entries"][0]["received_at"] = "2026-09-24T22:60:43Z"; }, received},
        {"received_at second 60", [](json& m) { m["entries"][0]["received_at"] = "2026-09-24T22:14:60Z"; }, received},
        {"no location", [](json& m) { m["entries"][0].erase("location"); }, at(0, "/location: must be an object")},
        {"location a string", [](json& m) { m["entries"][0]["location"] = "Inbox"; }, at(0, "/location: must be an object")},
        {"no mailbox", [](json& m) { m["entries"][0]["location"].erase("mailbox"); },
         at(0, "/location/mailbox: must be a non-empty string")},
        {"a restoretest mailbox", [](json& m) { m["entries"][0]["location"]["mailbox"] = "RestoreTest@RestoreProofLab.onmicrosoft.com"; },
         at(0, "/location/mailbox: is a restore target (a restoretest mailbox)")},
        {"a mailbox with a space", [](json& m) { m["entries"][0]["location"]["mailbox"] = "alice @RestoreProofLab.onmicrosoft.com"; },
         at(0, "/location/mailbox: holds whitespace or a control character")},
        {"no folder", [](json& m) { m["entries"][0]["location"]["folder"] = ""; },
         at(0, "/location/folder: must be a non-empty string")},
        // What the expected set compares a mail with (W3.1).
        {"no sender", [](json& m) { m["entries"][4].erase("sender"); }, at(4, "/sender: must be a non-empty string")},
        {"an empty sender", [](json& m) { m["entries"][4]["sender"] = ""; }, at(4, "/sender: must be a non-empty string")},
        {"a sender a number", [](json& m) { m["entries"][4]["sender"] = 7; }, at(4, "/sender: must be a non-empty string")},
        {"a sender without @", [](json& m) { m["entries"][4]["sender"] = "Hrachya Harutyunyan"; }, one_at},
        {"a sender with two @", [](json& m) { m["entries"][4]["sender"] = "a@b@RestoreProofLab.onmicrosoft.com"; }, one_at},
        {"a sender with a space", [](json& m) { m["entries"][4]["sender"] = "a b@RestoreProofLab.onmicrosoft.com"; }, sender_space},
        {"a sender with a tab", [](json& m) { m["entries"][4]["sender"] = "ab@RestoreProofLab.onmicrosoft.com\t"; }, sender_space},
        {"a sender with DEL", [](json& m) { m["entries"][4]["sender"] = "ab\x7F@RestoreProofLab.onmicrosoft.com"; }, sender_space},
        {"no sent_at", [](json& m) { m["entries"][4].erase("sent_at"); }, sent},
        {"sent_at with a fraction", [](json& m) { m["entries"][4]["sent_at"] = "2026-09-24T22:14:40.5Z"; }, sent},
        {"sent_at 31 September", [](json& m) { m["entries"][4]["sent_at"] = "2026-09-31T22:14:40Z"; }, sent},
        {"sent_at second 60", [](json& m) { m["entries"][4]["sent_at"] = "2026-09-24T22:14:60Z"; }, sent},
        {"no internet_message_id", [](json& m) { m["entries"][4].erase("internet_message_id"); },
         at(4, "/internet_message_id: must be a non-empty string")},
        {"an empty internet_message_id", [](json& m) { m["entries"][4]["internet_message_id"] = ""; },
         at(4, "/internet_message_id: must be a non-empty string")},
        {"an internet_message_id with a line break", [](json& m) { m["entries"][4]["internet_message_id"] = "<a@b>\r\nX: y"; },
         message_id_control},
        {"an internet_message_id with DEL", [](json& m) { m["entries"][4]["internet_message_id"] = "<a\x7F@b>"; },
         message_id_control},
        {"no body_normalization", [](json& m) { m["entries"][4].erase("body_normalization"); }, normalization},
        {"body_normalization text-v2", [](json& m) { m["entries"][4]["body_normalization"] = "text-v2"; }, normalization},
        {"body_normalization TEXT-V1", [](json& m) { m["entries"][4]["body_normalization"] = "TEXT-V1"; }, normalization},
        {"no body_sha256", [](json& m) { m["entries"][4].erase("body_sha256"); }, body_hash},
        {"body_sha256 in upper case",
         [](json& m) { m["entries"][4]["body_sha256"] = "4E1A958631216825C0E67FAADFE1D56B787CB6470A891F0860C21CC7BAD19BBE"; },
         body_hash},
        {"body_sha256 one digit short",
         [](json& m) { m["entries"][4]["body_sha256"] = "4e1a958631216825c0e67faadfe1d56b787cb6470a891f0860c21cc7bad19bb"; },
         body_hash},
        {"body_sha256 one digit long",
         [](json& m) { m["entries"][4]["body_sha256"] = "4e1a958631216825c0e67faadfe1d56b787cb6470a891f0860c21cc7bad19bbe0"; },
         body_hash},
        {"body_sha256 not hex",
         [](json& m) { m["entries"][4]["body_sha256"] = "ge1a958631216825c0e67faadfe1d56b787cb6470a891f0860c21cc7bad19bbe"; },
         body_hash},
        {"body_sha256 a number", [](json& m) { m["entries"][4]["body_sha256"] = 1; }, body_hash},
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
        // A rule a restored copy can be checked by (W3.1 review).
        {"a docx by bytes", [](json& m) { m["entries"][kFirstSharePoint + 1]["content_rule"] = "bytes"; },
         rule_by_type(kFirstSharePoint + 1)},
        {"an xlsx by bytes", [](json& m) { m["entries"][kFirstOneDrive + 2]["content_rule"] = "bytes"; },
         rule_by_type(kFirstOneDrive + 2)},
        {"a pdf by office-v1", [](json& m) { m["entries"][kFirstSharePoint]["content_rule"] = "office-v1"; },
         rule_by_type(kFirstSharePoint)},
        {"a png by office-v1", [](json& m) { m["entries"][kFirstOneDrive + 4]["content_rule"] = "office-v1"; },
         rule_by_type(kFirstOneDrive + 4)},
        {"a pdf named .docx", [](json& m) { m["entries"][kFirstSharePoint]["name"] = "rp-canary-01.docx"; },
         name_by_type(kFirstSharePoint)},
        {"a txt named .XLSM", [](json& m) { m["entries"][kFirstOneDrive + 3]["name"] = "rp-canary-14.XLSM"; },
         name_by_type(kFirstOneDrive + 3)},
        {"a docx named .pdf", [](json& m) { m["entries"][kFirstOneDrive + 1]["name"] = "rp-canary-12.pdf"; },
         name_by_type(kFirstOneDrive + 1)},
        {"no content_sha256", [](json& m) { m["entries"][kFirstOneDrive + 1].erase("content_sha256"); }, content_hash},
        {"content_sha256 in upper case",
         [](json& m) {
             m["entries"][kFirstOneDrive + 1]["content_sha256"] =
                 "8CB6004F5024EF81530F08DA82DD9A949807D62AF1EB71095A8B80E5B5923A2E";
         },
         content_hash},
        {"content_sha256 empty", [](json& m) { m["entries"][kFirstOneDrive + 1]["content_sha256"] = ""; }, content_hash},
        {"content_sha256 with a space",
         [](json& m) {
             m["entries"][kFirstOneDrive + 1]["content_sha256"] =
                 "8cb6004f5024ef81530f08da82dd9a949807d62af1eb71095a8b80e5b5923a2 ";
         },
         content_hash},
        {"stored_size below 0", [](json& m) { m["entries"][kFirstSharePoint]["stored_size"] = -1; }, stored_size},
        {"stored_size a fraction", [](json& m) { m["entries"][kFirstSharePoint]["stored_size"] = 925.5; }, stored_size},
        {"stored_size a string", [](json& m) { m["entries"][kFirstSharePoint]["stored_size"] = "925"; }, stored_size},
        {"no stored_size", [](json& m) { m["entries"][kFirstSharePoint].erase("stored_size"); }, stored_size},
        {"a relative folder_path", [](json& m) { m["entries"][kFirstSharePoint]["location"]["folder_path"] = "RestoreTest"; }, folder_path},
        {"an empty folder_path", [](json& m) { m["entries"][kFirstSharePoint]["location"]["folder_path"] = ""; }, folder_path},
        {"a folder_path with ..", [](json& m) { m["entries"][kFirstOneDrive]["location"]["folder_path"] = "/RestoreTest/../RestoreTarget"; }, od_folder_path},
        {"a folder_path with a backslash", [](json& m) { m["entries"][kFirstOneDrive]["location"]["folder_path"] = "/Restore\\Test"; }, od_folder_path},
        {"a folder_path with a colon", [](json& m) { m["entries"][kFirstSharePoint]["location"]["folder_path"] = "/drive/root:/RestoreTest"; }, folder_path},
        {"a folder_path ending in ..", [](json& m) { m["entries"][kFirstOneDrive]["location"]["folder_path"] = "/RestoreTest/.."; }, od_folder_path},
        {"no file location", [](json& m) { m["entries"][kFirstOneDrive].erase("location"); },
         at(kFirstOneDrive, "/location: must be an object")},
        {"a name repeated but for case", [](json& m) { m["entries"][kFirstSharePoint + 4]["name"] = "RP-CANARY-01.PDF"; },
         at(kFirstSharePoint + 4, "/name: repeats /entries/20/name (ignoring case)")},
        // Names differing only in a non-ASCII letter's case ("Źródła" and
        // "źródła") are one name to SharePoint and OneDrive, and to
        // restore_sample's same-name refusal (src/name_key.hpp).
        {"a SharePoint name repeated but for a non-ASCII letter's case",
         [](json& m) {
             m["entries"][kFirstSharePoint]["name"] = "\xC5\xB9r\xC3\xB3" "d\xC5\x82" "a.pdf";
             m["entries"][kFirstSharePoint + 4]["name"] = "\xC5\xBAr\xC3\xB3" "d\xC5\x82" "a.pdf";
         },
         at(kFirstSharePoint + 4, "/name: repeats /entries/20/name (ignoring case)")},
        {"a OneDrive name repeated but for a non-ASCII letter's case",
         [](json& m) {
             m["entries"][kFirstOneDrive]["name"] = "\xC5\xB9r\xC3\xB3" "d\xC5\x82" "a.pdf";
             m["entries"][kFirstOneDrive + 3]["name"] = "\xC5\xB9R\xC3\x93" "D\xC5\x81" "A.PDF";
         },
         at(kFirstOneDrive + 3, "/name: repeats /entries/30/name (ignoring case)")},
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
        CHECK(mail.sender == entry.at("sender").get<std::string>());
        CHECK(mail.sent_at == entry.at("sent_at").get<std::string>());
        CHECK(mail.internet_message_id == entry.at("internet_message_id").get<std::string>());
        CHECK(mail.body_sha256 == entry.at("body_sha256").get<std::string>());
        CHECK(mail.body_normalization == "text-v1");
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
        CHECK(file.content_sha256 == entry.at("content_sha256").get<std::string>());
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
        CHECK(file.content_sha256 == entry.at("content_sha256").get<std::string>());
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
