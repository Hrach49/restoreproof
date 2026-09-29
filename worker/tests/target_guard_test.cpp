// W2.7: the restore-target guard, layer 1 (rp/target_guard.hpp). Graph is
// served by a FakeHttpClient with the recorded replies for the test mailbox's
// Inbox, the RestoreTarget library and the test OneDrive folder; the refusals
// are edits of those replies, other recorded replies
// or specs whose items come from a restore target. A test passes only on the
// guard's own refusal: a SafetyViolation whose message starts with
// "target guard: " and says why. The canaries' own IDs appear nowhere here.

#include "../src/text_util.hpp"
#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_errors.hpp>
#include <rp/graph_targets.hpp>
#include <rp/target_guard.hpp>
#include <rp/target_guard_graph.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

using nlohmann::json;
using rp::connector::MailSelector;
using rp::connector::OneDriveSelector;
using rp::connector::RestoreSpec;
using rp::connector::SharePointSelector;
using rp::test::load_fixture_json;
using namespace rp::test::target_guard_lab;

const std::string kRestored = "; nothing was restored";
const std::string kLibraryTail =
    ": the Worker restores only into the RestoreTarget library; nothing was restored";

// A GUID of the same shape as `guid` that differs from it (built, not spelled out).
std::string other_guid(std::string guid)
{
    guid[0] = guid[0] == '0' ? '1' : '0';
    return guid;
}

// A mail item from the test mailbox itself.
MailSelector mail_from_target()
{
    return {lab_values().mailbox, "Inbox", "s"};
}

// Puts spdlog's default logger back when a test is done with it.
struct RestoreDefaultLogger {
    std::shared_ptr<spdlog::logger> saved = spdlog::default_logger();
    ~RestoreDefaultLogger() { spdlog::set_default_logger(saved); }
};

// How many lines `text` has (each ends with '\n').
std::size_t lines_of(const std::string& text)
{
    return static_cast<std::size_t>(std::count(text.begin(), text.end(), '\n'));
}

} // namespace

// ---- the acceptance test: alice's inbox can't be a target ---------------------------------

TEST_CASE("the guard refuses a test_mailbox that reaches another mailbox than restoretest",
          "[target_guard]")
{
    // restoretest@<domain> has the right shape, but may be an alias of alice's
    // live mailbox: Exchange then refuses the Worker app, whose scope is the
    // restoretest mailbox alone (the recorded 403 is alice's Inbox).
    const std::string alias = "restoretest@client.example";
    rp::Config config = lab_config();
    config.test_mailbox = alias;
    GuardLab lab;
    lab.serve(inbox_url(alias), load_fixture_json("graph", "mailbox-inbox-403-exchange"));

    const Thrown thrown =
        thrown_by([&] { lab.guard().check_spec(make_spec({mail_source()}, {}, {}, config)); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what ==
          "target guard: Graph refused the Worker app the Inbox of the mailbox test_mailbox names "
          "(403): the app's Exchange scope covers the restoretest mailbox alone, so the address is "
          "another mailbox, or the grant \"" +
              std::string{rp::graph::kMailReadGrant.description} +
              "\" is missing: the Worker restores only into the restoretest mailbox" + kRestored);
    CHECK(lab.gets(inbox_url(alias)) == 1);
    CHECK(lab.log() == "critical SECURITY: " + thrown.what + "\n");
}

TEST_CASE("the guard refuses an Inbox reply without an id", "[target_guard]")
{
    GuardLab lab;
    lab.serve_edited(inbox_url(), "mailbox-inbox-200", [](json& b) { b.erase("id"); });

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(full_spec()); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == "target guard: Graph's reply for the Inbox of the mailbox test_mailbox "
                         "names has no id; the Worker can't tell the mailbox is there" + kRestored);
    CHECK(lab.gets(drive_url()) == 0);
}

TEST_CASE("no RestoreTargets names alice's inbox", "[target_guard]")
{
    // RestoreTargets has no default and comes only from a Config, which takes
    // restoretest@<domain> alone, so no spec can carry alice's inbox as its target.
    const std::string mailbox = GENERATE(as<std::string>{}, "alice@RestoreProofLab.onmicrosoft.com",
                                         "restoretest.alice@RestoreProofLab.onmicrosoft.com",
                                         "restore\xC2\xADtest@RestoreProofLab.onmicrosoft.com");
    CAPTURE(mailbox);
    rp::Config config = lab_config();
    config.test_mailbox = mailbox;

    const Thrown thrown = thrown_by([&] { make_spec({mail_source()}, {}, {}, config); });

    CHECK(thrown.kind == "other");
    CHECK(thrown.what == "restore target test_mailbox must be restoretest@<domain>");
}

// ---- items sampled from a restore target: refused before any call --------------------------

TEST_CASE("the guard refuses an item sampled from a restore target before any Graph call",
          "[target_guard]")
{
    struct Row {
        std::string name;
        RestoreSpec spec;
        std::string message;
    };
    const std::string library = lab_values().library_id;
    const auto mail_from = [](std::string mailbox, std::string folder = "Inbox") {
        return MailSelector{std::move(mailbox), std::move(folder), "s"};
    };
    const auto sp_from = [](std::string drive, std::string name = "f.pdf") {
        return SharePointSelector{lab_values().site_id, std::move(drive), "/", std::move(name)};
    };
    const auto od_from = [](std::string path, std::string user = "alice@x.example") {
        return OneDriveSelector{std::move(user), std::move(path), "f.pdf"};
    };
    const std::string mail_target =
        "target guard: mail item 1 is sampled from a restore target (a restoretest mailbox)" +
        kRestored;
    const std::string sp_target = "target guard: sharepoint item 1 is sampled from a restore "
                                  "target (the library test_library_id names)" + kRestored;
    const std::string od_target = "target guard: onedrive item 1 is sampled from a restore "
                                  "target (a RestoreTarget folder)" + kRestored;
    const Row row = GENERATE_COPY(
        Row{"mail from the test mailbox",
            make_spec({mail_source(), mail_from(lab_values().mailbox)}), mail_target},
        Row{"mail from the test mailbox in another case",
            make_spec({mail_source(), mail_from("RESTORETEST@restoreprooflab.onmicrosoft.com")}),
            mail_target},
        Row{"mail from another tenant's restoretest",
            make_spec({mail_source(), mail_from("restoretest@other.example")}), mail_target},
        Row{"mail with no mailbox", make_spec({mail_from("")}),
            "target guard: mail item 0 names no source mailbox or folder" + kRestored},
        Row{"mail with no folder", make_spec({mail_from("alice@x.example", "")}),
            "target guard: mail item 0 names no source mailbox or folder" + kRestored},
        Row{"a file from the RestoreTarget library",
            make_spec({}, {sharepoint_source(), sp_from(library)}), sp_target},
        Row{"a file from the RestoreTarget library, drive ID in another case",
            make_spec({}, {sharepoint_source(), sp_from(rp::ascii_lower(library))}),
            sp_target},
        Row{"a SharePoint item with no drive", make_spec({}, {sp_from("")}),
            "target guard: sharepoint item 0 names no source library or file" + kRestored},
        Row{"a SharePoint item with no name", make_spec({}, {sp_from("b!x", "")}),
            "target guard: sharepoint item 0 names no source library or file" + kRestored},
        Row{"a file from /RestoreTarget",
            make_spec({}, {}, {onedrive_source(), od_from("/RestoreTarget")}), od_target},
        Row{"a file from /restoretarget/",
            make_spec({}, {}, {onedrive_source(), od_from("/restoretarget/")}), od_target},
        Row{"a file from RestoreTarget without the leading slash",
            make_spec({}, {}, {onedrive_source(), od_from("RestoreTarget")}), od_target},
        Row{"a file from a subfolder of RestoreTarget",
            make_spec({}, {}, {onedrive_source(), od_from("/RestoreTarget/sub")}), od_target},
        Row{"a file from //./RestoreTarget",
            make_spec({}, {}, {onedrive_source(), od_from("//./RestoreTarget")}), od_target},
        Row{"a file from a path with ..",
            make_spec({}, {}, {od_from("/RestoreTest/../RestoreTarget")}),
            "target guard: onedrive item 0's folder path has a \"..\" segment" + kRestored},
        Row{"a OneDrive item with no owner", make_spec({}, {}, {od_from("/RestoreTest", "")}),
            "target guard: onedrive item 0 names no owner or file" + kRestored},
        Row{"a OneDrive item with no name",
            make_spec({}, {}, {OneDriveSelector{"alice@x.example", "/RestoreTest", ""}}),
            "target guard: onedrive item 0 names no owner or file" + kRestored});
    CAPTURE(row.name);
    GuardLab lab;

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(row.spec); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == row.message);
    CHECK(lab.graph_gets() == 0);
}

TEST_CASE("the guard checks every item before it resolves any target", "[target_guard]")
{
    GuardLab lab;
    // SharePoint items come first but are fine; the OneDrive item is refused
    // before the library is read.
    const RestoreSpec spec = make_spec({mail_source()}, {sharepoint_source()},
                                       {OneDriveSelector{"alice@x.example", "/RestoreTarget", "f"}});

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(spec); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK_THAT(thrown.what, StartsWith("target guard: onedrive item 0 is sampled"));
    CHECK(lab.graph_gets() == 0);
}

// ---- the configured targets: resolved and refused -----------------------------------------

TEST_CASE("the guard refuses a configured library that isn't the test site's RestoreTarget",
          "[target_guard]")
{
    const std::string not_site = "target guard: the drive test_library_id names is not in the "
                                 "site test_site_id names" + kRestored;
    const std::string no_ids = "target guard: Graph's reply for the drive test_library_id names "
                               "has no list ID or site URL in sharePointIds; the Worker can't "
                               "tell the library apart" + kRestored;
    const auto named = [](const std::string& shown) {
        return "target guard: the drive test_library_id names is \"" + shown +
               "\", not \"RestoreTarget\"" + kLibraryTail;
    };
    const auto rename = [](std::string name) {
        return [name](json& b) { b["name"] = name; };
    };
    struct Row {
        std::string name;
        std::function<void(json&)> edit;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        // The lab tenant's default library, and the English one: live data.
        Row{"the default library Dokumenty", rename("Dokumenty"), named("Dokumenty")},
        Row{"Documents", rename("Documents"), named("Documents")},
        Row{"Shared Documents", rename("Shared Documents"), named("Shared Documents")},
        // The canary library: its name, and a list ID other than the target's.
        Row{"the canary library RestoreTest",
            [](json& b) {
                b["name"] = "RestoreTest";
                b["sharePointIds"]["listId"] =
                    other_guid(b["sharePointIds"]["listId"].get<std::string>());
            },
            named("RestoreTest")},
        Row{"a soft hyphen look-alike", rename("Restore\xC2\xADTarget"),
            named("Restore\xC2\xADTarget")},
        Row{"a zero-width space look-alike", rename("Restore\xE2\x80\x8BTarget"),
            named("Restore\xE2\x80\x8BTarget")},
        Row{"another case", rename("restoretarget"), named("restoretarget")},
        Row{"a trailing space", rename("RestoreTarget "), named("RestoreTarget ")},
        Row{"a personal drive", [](json& b) { b["driveType"] = "personal"; },
            "target guard: the drive test_library_id names is not a document library" +
                kRestored},
        Row{"another site",
            [](json& b) {
                b["sharePointIds"]["siteId"] =
                    other_guid(b["sharePointIds"]["siteId"].get<std::string>());
            },
            not_site},
        Row{"another web",
            [](json& b) {
                b["sharePointIds"]["webId"] =
                    other_guid(b["sharePointIds"]["webId"].get<std::string>());
            },
            not_site},
        Row{"a renamed canary library (its URL)",
            [](json& b) {
                const std::string url = b["webUrl"].get<std::string>();
                b["webUrl"] = url.substr(0, url.rfind('/')) + "/RestoreTest";
            },
            "target guard: the drive test_library_id names has the address of another library "
            "(not .../RestoreTarget)" + kLibraryTail},
        Row{"sharePointIds removed", [](json& b) { b.erase("sharePointIds"); },
            "target guard: Graph's reply for the drive test_library_id names has no "
            "sharePointIds; the Worker can't check it is in the test site" + kRestored},
        Row{"listId removed", [](json& b) { b["sharePointIds"].erase("listId"); }, no_ids},
        Row{"listId not a GUID", [](json& b) { b["sharePointIds"]["listId"] = "RestoreTarget"; },
            no_ids},
        Row{"siteUrl removed", [](json& b) { b["sharePointIds"].erase("siteUrl"); }, no_ids},
        Row{"siteUrl not a string", [](json& b) { b["sharePointIds"]["siteUrl"] = 1; }, no_ids});
    CAPTURE(row.name);
    GuardLab lab;
    lab.serve_edited(drive_url(), "restoretarget-drive-200", row.edit);

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(full_spec()); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == row.message);
    CHECK(lab.gets(drive_url()) == 1);
    CHECK(lab.gets(folder_url()) == 0);
}

TEST_CASE("the guard refuses a configured OneDrive folder that isn't the RestoreTarget",
          "[target_guard]")
{
    const std::string od = lab_values().onedrive_drive_id;
    const std::string no_site = "target guard: Graph's reply for the OneDrive folder "
                                "test_onedrive_folder_id names has no parentReference.siteId; the "
                                "Worker can't tell the OneDrive apart" + kRestored;
    const std::string no_ids = "target guard: Graph's reply for the OneDrive folder "
                               "test_onedrive_folder_id names has no sharepointIds with its site, "
                               "web and site URL; the Worker can't tell the OneDrive apart" +
                               kRestored;
    struct Row {
        std::string name;
        std::function<void(json&)> edit;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"the canary folder RestoreTest", [](json& b) { b["name"] = "RestoreTest"; },
            "target guard: the OneDrive item test_onedrive_folder_id names is \"RestoreTest\", "
            "not \"RestoreTarget\": the Worker restores only into the RestoreTarget folder" +
                kRestored},
        Row{"a zero-width space look-alike",
            [](json& b) { b["name"] = "Restore\xE2\x80\x8BTarget"; },
            "target guard: the OneDrive item test_onedrive_folder_id names is "
            "\"Restore\xE2\x80\x8BTarget\", not \"RestoreTarget\": the Worker restores only into "
            "the RestoreTarget folder" + kRestored},
        Row{"a file, not a folder", [](json& b) { b.erase("folder"); },
            "target guard: the OneDrive item test_onedrive_folder_id names is not a folder" +
                kRestored},
        Row{"another drive",
            [](json& b) { b["parentReference"]["driveId"] = "b!madeUpOtherDrive"; },
            "target guard: the OneDrive folder test_onedrive_folder_id names is not in the drive "
            "test_onedrive_drive_id names" + kRestored},
        Row{"a site library's drive",
            [](json& b) { b["parentReference"]["driveType"] = "documentLibrary"; },
            "target guard: the drive test_onedrive_drive_id names is not a OneDrive (Graph's "
            "driveType is not \"business\"): a site library's folder is never read as the test "
            "OneDrive's" + kRestored},
        Row{"not at the root",
            [od](json& b) { b["parentReference"]["path"] = "/drives/" + od + "/root:/RestoreTest"; },
            "target guard: the OneDrive folder test_onedrive_folder_id names is not directly "
            "under the drive's root" + kRestored},
        Row{"no path", [](json& b) { b["parentReference"].erase("path"); },
            "target guard: Graph's reply for the OneDrive folder test_onedrive_folder_id names "
            "has no parentReference.path; the Worker can't check it is at the drive's root" +
                kRestored},
        Row{"siteId removed", [](json& b) { b["parentReference"].erase("siteId"); }, no_site},
        Row{"siteId not a GUID", [](json& b) { b["parentReference"]["siteId"] = "alice"; },
            no_site},
        Row{"sharepointIds removed", [](json& b) { b.erase("sharepointIds"); }, no_ids},
        Row{"siteUrl removed", [](json& b) { b["sharepointIds"].erase("siteUrl"); }, no_ids},
        Row{"siteUrl not a string", [](json& b) { b["sharepointIds"]["siteUrl"] = 1; }, no_ids},
        Row{"webId not a GUID", [](json& b) { b["sharepointIds"]["webId"] = "alice"; }, no_ids},
        Row{"sharepointIds of another site",
            [](json& b) {
                b["sharepointIds"]["siteId"] =
                    other_guid(b["sharepointIds"]["siteId"].get<std::string>());
            },
            no_ids});
    CAPTURE(row.name);
    GuardLab lab;
    lab.serve_edited(folder_url(), "onedrive-folder-200", row.edit);

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(full_spec()); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == row.message);
    CHECK(lab.gets(drive_url()) == 1);
    CHECK(lab.gets(folder_url()) == 1);
}

TEST_CASE("Graph's own errors pass the guard with their types", "[target_guard]")
{
    struct Row {
        std::string name;
        std::string url;
        std::string fixture;
        std::string kind;
    };
    const Row row = GENERATE(values<Row>({
        {"a 403 on the library", drive_url(), "site-403-accessdenied", "PermissionError"},
        {"a 404 on the folder", folder_url(), "onedrive-folder-404-itemnotfound", "NotFoundError"},
        {"a 503 on the library", drive_url(), "messages-503-unavailable", "TransientError"},
        {"a 404 on the Inbox: no such mailbox", inbox_url(), "messages-404-unknown-user",
         "NotFoundError"},
        {"a 503 on the Inbox", inbox_url(), "messages-503-unavailable", "TransientError"},
    }));
    CAPTURE(row.name);
    GuardLab lab;
    lab.serve(row.url, load_fixture_json("graph", row.fixture));

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(full_spec()); });

    CHECK(thrown.kind == row.kind);
    CHECK_THAT(thrown.what, !StartsWith("target guard: "));
    // Not the guard's refusal: no SECURITY line.
    CHECK_THAT(lab.log(), !ContainsSubstring("SECURITY"));
}

TEST_CASE("the folder's 404 still says the Worker app may lack its grant", "[target_guard]")
{
    GuardLab lab;
    lab.serve(folder_url(), load_fixture_json("graph", "onedrive-folder-404-itemnotfound"));

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(make_spec({}, {}, {onedrive_source()})); });

    CHECK(thrown.kind == "NotFoundError");
    CHECK_THAT(thrown.what, ContainsSubstring("the Worker app may lack the grant \"" +
                                              std::string{rp::graph::kOneDriveReadGrant.description}));
}

// ---- what passes ---------------------------------------------------------------------------

TEST_CASE("an empty spec checks nothing and calls nothing", "[target_guard]")
{
    GuardLab lab;

    const rp::CheckedTargets checked = lab.guard().check_spec(make_spec());

    CHECK(lab.graph_http.requests().empty());
    CHECK_FALSE(checked.library().has_value());
    CHECK_FALSE(checked.onedrive_folder().has_value());
    CHECK_FALSE(checked.mailbox().has_value());
    CHECK(lab.log().empty());
}

TEST_CASE("a mail-only spec reads the test mailbox's Inbox once and nothing else",
          "[target_guard]")
{
    GuardLab lab;
    const json inbox = load_fixture_json("graph", "mailbox-inbox-200").at("body");

    const rp::CheckedTargets checked =
        lab.guard().check_spec(make_spec({mail_source(1), mail_source(2)}));

    CHECK(lab.gets(inbox_url()) == 1);
    CHECK(lab.graph_gets() == 1);
    REQUIRE(checked.mailbox().has_value());
    CHECK(checked.mailbox()->address == lab_values().mailbox);
    CHECK(checked.mailbox()->inbox_id == inbox.at("id").get<std::string>());
    CHECK(checked.configured().mailbox() == lab_values().mailbox);
    CHECK_FALSE(checked.library().has_value());
    CHECK_FALSE(checked.onedrive_folder().has_value());
}

TEST_CASE("the guard resolves each file target once, whatever the number of items",
          "[target_guard]")
{
    GuardLab lab;
    const json drive = load_fixture_json("graph", "restoretarget-drive-200").at("body");
    const json folder = load_fixture_json("graph", "onedrive-folder-200").at("body");

    const rp::CheckedTargets checked = lab.guard().check_spec(
        make_spec({mail_source()}, {sharepoint_source(1), sharepoint_source(2), sharepoint_source(3)},
                  {onedrive_source(1), onedrive_source(2)}));

    CHECK(lab.gets(inbox_url()) == 1);
    CHECK(lab.gets(drive_url()) == 1);
    CHECK(lab.gets(folder_url()) == 1);
    CHECK(lab.graph_gets() == 3);
    REQUIRE(checked.mailbox().has_value());
    CHECK(checked.mailbox()->address == lab_values().mailbox);
    REQUIRE(checked.library().has_value());
    const rp::graph::ResolvedLibrary& library = *checked.library();
    CHECK(library.name == "RestoreTarget");
    CHECK(library.drive_id == lab_values().library_id);
    CHECK(library.list_id == drive.at("sharePointIds").at("listId").get<std::string>());
    CHECK(library.site_id == drive.at("sharePointIds").at("siteId").get<std::string>());
    CHECK(library.web_id == drive.at("sharePointIds").at("webId").get<std::string>());
    CHECK(library.site_url == drive.at("sharePointIds").at("siteUrl").get<std::string>());
    REQUIRE(checked.onedrive_folder().has_value());
    const rp::graph::ResolvedOneDriveFolder& od = *checked.onedrive_folder();
    CHECK(od.name == "RestoreTarget");
    CHECK(od.drive_id == lab_values().onedrive_drive_id);
    CHECK(od.folder_id == lab_values().folder_id);
    CHECK(od.site_id == folder.at("parentReference").at("siteId").get<std::string>());
    CHECK(od.web_id == folder.at("sharepointIds").at("webId").get<std::string>());
    CHECK(od.site_url == folder.at("sharepointIds").at("siteUrl").get<std::string>());
    CHECK(lab.log().find("SECURITY") == std::string::npos);
}

TEST_CASE("the guard takes OneDrive sources outside a RestoreTarget folder", "[target_guard]")
{
    const std::string path = GENERATE(as<std::string>{}, "/", "", "/RestoreTest", "/RestoreTargets",
                                      "/Documents/RestoreTarget", "/RestoreTest/./x");
    CAPTURE(path);
    GuardLab lab;

    const rp::CheckedTargets checked = lab.guard().check_spec(
        make_spec({}, {}, {OneDriveSelector{"alice@x.example", path, "f.pdf"}}));

    CHECK(checked.onedrive_folder().has_value());
}

// ---- the one log line ----------------------------------------------------------------------

TEST_CASE("a refusal is one critical SECURITY line", "[target_guard]")
{
    GuardLab lab;
    lab.serve_edited(drive_url(), "restoretarget-drive-200", [](json& b) { b["name"] = "Dokumenty"; });

    const Thrown thrown = thrown_by([&] { lab.guard().check_spec(full_spec()); });

    REQUIRE(thrown.kind == "SafetyViolation");
    const std::string log = lab.log();
    CHECK(lines_of(log) == 1);
    CHECK(log == "critical SECURITY: " + thrown.what + "\n");
}

TEST_CASE("without a logger the refusal goes to spdlog's default logger", "[target_guard]")
{
    GuardLab lab;
    const RestoreDefaultLogger restore;
    spdlog::set_default_logger(lab.logger);
    rp::TargetGuard guard(*lab.graph);

    const Thrown thrown = thrown_by([&] { guard.check_spec(make_spec({mail_from_target()})); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(lab.log() == "critical SECURITY: " + thrown.what + "\n");
}

TEST_CASE("without any logger the guard still refuses", "[target_guard]")
{
    GuardLab lab;
    const RestoreDefaultLogger restore;
    // spdlog::drop_all() and shutdown() leave the default logger null.
    spdlog::drop_all();
    REQUIRE(spdlog::default_logger() == nullptr);
    rp::TargetGuard guard(*lab.graph);

    const Thrown thrown = thrown_by([&] { guard.check_spec(make_spec({mail_from_target()})); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK_THAT(thrown.what, StartsWith("target guard: mail item 0 is sampled"));
}
