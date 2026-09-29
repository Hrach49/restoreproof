// W2.7: the restore-target guard, layer 2, on Veeam's restore requests
// (rp/target_guard_veeam.hpp). The requests are W2.4's recorded restore POSTs
// (tests/fixtures/veeam/restore-*-200.json: path and body as sent, credentials
// [REDACTED]); layer 1 runs first on W2.2's recorded Graph replies, as it must.
// The context is what W2.5 will have found by browsing, taken from the same
// recording. The 12 mutations of docs/api/veeam-restore-flow.md §6 run on each
// type, and a test passes only on the guard's own refusal: a SafetyViolation
// whose message starts with "target guard: " and says why.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"

#include <rp/connector.hpp>
#include <rp/target_guard.hpp>
#include <rp/target_guard_veeam.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;
using Catch::Matchers::StartsWith;

namespace {

using nlohmann::json;
using rp::veeam::GuardedItem;
using rp::veeam::RestoreKind;
using rp::veeam::RestoreRequestContext;
using rp::test::load_fixture_json;
using namespace rp::test::target_guard_lab;

// An explore session this run opened besides the one in the path. Made up.
const std::string kOtherExplore = "0a1b2c3d-0000-4000-8000-00000000abcd";
const std::string kNotSent = "; the restore was not sent";
const std::string kSentinel = "Sentinel-Guard-Credential-7c41";

// A recorded restore request and its context, as a test may edit them.
struct Request {
    std::string name;
    std::string path;
    json body;
    // The exact text to check; the body's dump() when unset.
    std::optional<std::string> raw;
    RestoreRequestContext ctx;

    std::string text() const { return raw ? *raw : body.dump(); }
    int kind() const { return static_cast<int>(ctx.kind); }
};

std::vector<std::string> split(const std::string& path)
{
    std::vector<std::string> out;
    std::size_t at = 0;
    for (;;) {
        const std::size_t slash = path.find('/', at);
        out.push_back(path.substr(at, slash == std::string::npos ? slash : slash - at));
        if (slash == std::string::npos) {
            return out;
        }
        at = slash + 1;
    }
}

// The fixture's request, and the context W2.5 would have built for it.
Request recorded(const std::string& fixture)
{
    const json recording = load_fixture_json("veeam", fixture);
    Request r;
    r.name = fixture;
    r.path = recording.at("request").get<std::string>().substr(5); // after "POST "
    r.body = recording.at("request_body");
    RestoreRequestContext& ctx = r.ctx;
    ctx.kind = r.path.find("/mailboxes/") != std::string::npos ? RestoreKind::mail
               : r.path.find("/Sites/") != std::string::npos ? RestoreKind::sharepoint
                                                              : RestoreKind::onedrive;
    const std::vector<std::string> segments = split(r.path);
    ctx.opened_explore_sessions = {kOtherExplore, segments.at(3)};
    ctx.container_id = segments.at(6);
    if (ctx.kind == RestoreKind::mail) {
        for (const json& item : r.body.at("items")) {
            ctx.items.push_back({item.at("id").get<std::string>(), ""});
        }
        ctx.organization_name = r.body.at("officeOrganizationName").get<std::string>();
    } else {
        for (const json& document : r.body.at("documents")) {
            ctx.items.push_back(
                {document.at("id").get<std::string>(), document.at("name").get<std::string>()});
        }
        ctx.organization_name = r.body.at("organizationName").get<std::string>();
    }
    ctx.application_id = r.body.at("applicationId").get<std::string>();
    ctx.office_region = r.body.at("officeRegion").get<std::string>();
    if (ctx.kind == RestoreKind::onedrive) {
        ctx.target_onedrive_id = r.body.at("onedrive").at("id").get<std::string>();
        ctx.target_onedrive_name = r.body.at("onedrive").at("name").get<std::string>();
        ctx.target_onedrive_url = r.body.at("onedrive").at("url").get<std::string>();
    }
    return r;
}

// Layer 1 on a spec with an item of each type, then layer 2 on `r`.
Thrown check(GuardLab& lab, const Request& r)
{
    const rp::CheckedTargets targets = lab.guard().check_spec(full_spec());
    return thrown_by([&] {
        rp::veeam::check_restore_request(targets, r.ctx, r.path, r.text(), lab.options());
    });
}

Thrown check(const Request& r)
{
    GuardLab lab;
    return check(lab, r);
}

// The body's item list: "items" for mail, "documents" for files.
json& items_of(Request& r)
{
    return r.body.at(r.ctx.kind == RestoreKind::mail ? "items" : "documents");
}

// The first key the body's dump() writes.
std::string first_key(const json& body)
{
    return body.begin().key();
}

std::string guard_message(const std::string& why)
{
    return "target guard: " + why + kNotSent;
}

const std::vector<std::string> kRecorded = {"restore-mail-200", "restore-sp-200",
                                            "restore-od-200", "restore-mail-x5-200",
                                            "restore-mail-r1-200"};

} // namespace

// ---- the recorded requests pass -------------------------------------------------------------

TEST_CASE("the guard accepts every restore request W2.4 recorded", "[target_guard][veeam]")
{
    const std::string fixture = GENERATE(from_range(kRecorded));
    CAPTURE(fixture);
    GuardLab lab;

    const Thrown thrown = check(lab, recorded(fixture));

    CHECK(thrown.kind == "none");
    CHECK(thrown.what.empty());
    CHECK(lab.log().empty());
}

TEST_CASE("the guard accepts a file restore from a site or OneDrive other than the target's",
          "[target_guard][veeam]")
{
    // The path names the source: W2.6 samples real data from any site or
    // OneDrive, while siteURL/list and onedrive/folder keep the destination the
    // RestoreTarget library or folder (docs/decisions.md 2026-09-29, W2.7,
    // deviation 1). The recorded SharePoint source is the target's own site.
    const std::string fixture = GENERATE(as<std::string>{}, "restore-sp-200", "restore-od-200");
    CAPTURE(fixture);
    const std::string other =
        "0a1b2c3d-0000-4000-8000-0000000000010a1b2c3d-0000-4000-8000-000000000002";
    GuardLab lab;
    Request r = recorded(fixture);
    const std::string old = r.ctx.container_id;
    r.path.replace(r.path.find(old), old.size(), other);
    r.ctx.container_id = other;
    json& document = r.body.at("documents").at(0);
    if (r.ctx.kind == RestoreKind::sharepoint) {
        const std::string id = other + document.at("id").get<std::string>().substr(old.size());
        document.at("id") = id;
        document.at("siteId") = other;
        r.ctx.items.at(0).id = id;
    } else {
        document.at("oneDriveId") = other;
    }

    const Thrown thrown = check(lab, r);

    CHECK(thrown.kind == "none");
    CHECK(thrown.what.empty());
    CHECK(lab.log().empty());
}

TEST_CASE("the guard accepts item and OneDrive names outside ASCII", "[target_guard][veeam]")
{
    // They identify and name no target, so they are compared byte for byte
    // (docs/decisions.md 2026-09-29, W2.7, deviation 3): a real file with an
    // accent in its name is no guard violation.
    struct Row {
        std::string fixture;
        std::string what;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-sp-200", "documents[0].name"},
        {"restore-od-200", "documents[0].name"},
        {"restore-od-200", "onedrive.name"},
    }));
    CAPTURE(row.fixture, row.what);
    const std::string name = "Caf\xC3\xA9 \xE2\x80\x94 R\xC3\xA9sum\xC3\xA9.pdf";
    GuardLab lab;
    Request r = recorded(row.fixture);
    if (row.what == "onedrive.name") {
        r.body.at("onedrive").at("name") = name;
        r.ctx.target_onedrive_name = name;
    } else {
        r.body.at("documents").at(0).at("name") = name;
        r.ctx.items.at(0).name = name;
    }

    const Thrown thrown = check(lab, r);

    CHECK(thrown.kind == "none");
    CHECK(thrown.what.empty());
    CHECK(lab.log().empty());
}

// ---- the 12 mutations of restore-flow §6, per type -----------------------------------------

TEST_CASE("the guard refuses each of restore-flow's 12 mutations, for each type",
          "[target_guard][veeam]")
{
    struct Mutation {
        std::string name;
        std::function<void(Request&)> apply;
        // The refusal's reason, per kind: mail, SharePoint, OneDrive.
        std::vector<std::string> why;
    };
    const auto per_kind = [](Request& r, std::function<void(Request&)> mail,
                             std::function<void(Request&)> sp, std::function<void(Request&)> od) {
        const std::vector<std::function<void(Request&)>> edits = {mail, sp, od};
        edits.at(static_cast<std::size_t>(r.kind()))(r);
    };
    const std::string alice = "alice@RestoreProofLab.onmicrosoft.com";
    const std::string items_twice = "the body's items are not exactly the ones resolved";
    const std::vector<Mutation> mutations = {
        {"1 wrong target container",
         [&](Request& r) {
             per_kind(
                 r, [&](Request& m) { m.body["mailbox"] = alice; },
                 [](Request& s) {
                     s.body["siteURL"] = "https://restoreprooflab.sharepoint.com/sites/Other";
                 },
                 [](Request& o) {
                     o.body["onedrive"]["url"] = "https://restoreprooflab-my.sharepoint.com/"
                                                 "personal/bob_restoreprooflab_onmicrosoft_com";
                 });
         },
         {"mailbox is not the test mailbox", "siteURL is not the RestoreTarget library's site",
          "onedrive.url is not the test OneDrive's address"}},
        {"2 canary location",
         [&](Request& r) {
             per_kind(
                 r, [](Request& m) { m.body["folder"] = "Sent Items"; },
                 [](Request& s) { s.body["list"] = "RestoreTest"; },
                 [](Request& o) { o.body["folder"] = "RestoreTest"; });
         },
         {"folder is not Inbox", "list is not the RestoreTarget library",
          "folder is not the RestoreTarget folder"}},
        {"3 impersonation / case",
         [&](Request& r) {
             per_kind(
                 r, [&](Request& m) { m.body["impersonationAccountName"] = alice; },
                 [](Request& s) { s.body["list"] = "restoretarget"; },
                 [](Request& o) { o.body["folder"] = "restoretarget"; });
         },
         {"impersonationAccountName is not the test mailbox",
          "list is not the RestoreTarget library", "folder is not the RestoreTarget folder"}},
        {"4 extra key", [](Request& r) { r.body["restoreToOriginalLocation"] = true; },
         {"the mail body's keys are not exactly the expected set (extra: "
          "restoreToOriginalLocation; missing: none)",
          "the sharepoint body's keys are not exactly the expected set (extra: "
          "restoreToOriginalLocation; missing: none)",
          "the onedrive body's keys are not exactly the expected set (extra: "
          "restoreToOriginalLocation; missing: none)"}},
        {"5 other app",
         [](Request& r) { r.body["applicationId"] = "00000000-0000-0000-0000-000000000000"; },
         {"applicationId is not the organisation's app", "applicationId is not the organisation's app",
          "applicationId is not the organisation's app"}},
        {"6 look-alike name (U+00AD)",
         [&](Request& r) {
             per_kind(
                 r, [](Request& m) { m.body["folder"] = "In\xC2\xAD" "box"; },
                 [](Request& s) { s.body["list"] = "Restore\xC2\xADTarget"; },
                 [](Request& o) { o.body["folder"] = "Restore\xC2\xADTarget"; });
         },
         {"folder has a character outside printable ASCII",
          "list has a character outside printable ASCII",
          "folder has a character outside printable ASCII"}},
        {"7 array instead of a string",
         [&](Request& r) {
             per_kind(
                 r, [](Request& m) { m.body["mailbox"] = json::array({m.body["mailbox"]}); },
                 [](Request& s) { s.body["siteURL"] = json::array({s.body["siteURL"]}); },
                 [](Request& o) { o.body["folder"] = json::array({o.body["folder"]}); });
         },
         {"mailbox is not a JSON string", "siteURL is not a JSON string",
          "folder is not a JSON string"}},
        {"8 duplicated item",
         [](Request& r) {
             json& items = items_of(r);
             const json first = items.at(0);
             if (items.size() > 1) {
                 items.erase(items.size() - 1);
             }
             items.push_back(first);
         },
         {items_twice, items_twice, items_twice}},
        {"9 extra item",
         [](Request& r) {
             json& items = items_of(r);
             items.push_back(items.at(0));
         },
         {items_twice, items_twice, items_twice}},
        {"10 duplicate key",
         [](Request& r) {
             const std::string text = r.body.dump();
             r.raw = "{\"" + first_key(r.body) + "\":\"x\"," + text.substr(1);
         },
         {"the body has a key twice in one object", "the body has a key twice in one object",
          "the body has a key twice in one object"}},
        {"11 original-location path",
         [](Request& r) {
             const std::size_t last = r.path.rfind('/');
             r.path = r.path.substr(0, last) + "/restore";
         },
         {"the path is not the mail restore-to-another-location call",
          "the path is not the sharepoint restore-to-another-location call",
          "the path is not the onedrive restore-to-another-location call"}},
        {"12 dot-segment path", [](Request& r) { r.path += "/../../restore"; },
         {"the path has a query, fragment, escape or dot segment",
          "the path has a query, fragment, escape or dot segment",
          "the path has a query, fragment, escape or dot segment"}},
    };
    const std::string fixture =
        GENERATE(as<std::string>{}, "restore-mail-200", "restore-sp-200", "restore-od-200");
    const std::size_t at = GENERATE(range<std::size_t>(0, 12));
    const Mutation& mutation = mutations.at(at);
    CAPTURE(fixture, mutation.name);
    Request r = recorded(fixture);
    mutation.apply(r);

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == guard_message(mutation.why.at(static_cast<std::size_t>(r.kind()))));
}

TEST_CASE("a duplicated item is refused although the count still matches",
          "[target_guard][veeam]")
{
    Request r = recorded("restore-mail-x5-200");
    json& items = r.body.at("items");
    REQUIRE(items.size() == 5);
    items.at(4) = items.at(0);

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == guard_message("the body's items are not exactly the ones resolved"));
}

TEST_CASE("an item missing from the body is refused", "[target_guard][veeam]")
{
    Request r = recorded("restore-mail-x5-200");
    r.body.at("items").erase(2);

    const Thrown thrown = check(r);

    CHECK(thrown.what == guard_message("the body's items are not exactly the ones resolved"));
}

TEST_CASE("a file restored under another name is refused", "[target_guard][veeam]")
{
    const std::string fixture = GENERATE(as<std::string>{}, "restore-sp-200", "restore-od-200");
    CAPTURE(fixture);
    Request r = recorded(fixture);
    r.body.at("documents").at(0).at("name") = "other.pdf";

    const Thrown thrown = check(r);

    CHECK(thrown.what == guard_message("the body's items are not exactly the ones resolved"));
}

// ---- look-alikes, case and value kinds -----------------------------------------------------

TEST_CASE("the guard refuses look-alikes and case variants of the target names",
          "[target_guard][veeam]")
{
    struct Row {
        std::string fixture;
        std::string key;
        std::string value;
        std::string why;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-mail-200", "folder", "In\xE2\x80\x8B" "box",
         "folder has a character outside printable ASCII"},
        {"restore-mail-200", "folder", "inbox", "folder is not Inbox"},
        {"restore-mail-200", "folder", "Inbox ", "folder is not Inbox"},
        {"restore-mail-200", "mailbox", "RestoreTest@RestoreProofLab.onmicrosoft.com",
         "mailbox is not the test mailbox"},
        {"restore-mail-200", "mailbox", "restoretest@restoreprooflab.onmicrosoft.com",
         "mailbox is not the test mailbox"},
        {"restore-mail-200", "mailbox", "restoretest\xE2\x80\x8B@RestoreProofLab.onmicrosoft.com",
         "mailbox has a character outside printable ASCII"},
        {"restore-mail-200", "impersonationAccountName",
         "RESTORETEST@RestoreProofLab.onmicrosoft.com",
         "impersonationAccountName is not the test mailbox"},
        {"restore-sp-200", "list", "Restore\xE2\x80\x8BTarget",
         "list has a character outside printable ASCII"},
        {"restore-sp-200", "list", "RESTORETARGET", "list is not the RestoreTarget library"},
        {"restore-sp-200", "list", "Documents", "list is not the RestoreTarget library"},
        {"restore-sp-200", "list", "Shared Documents", "list is not the RestoreTarget library"},
        {"restore-sp-200", "list", "Dokumenty", "list is not the RestoreTarget library"},
        {"restore-sp-200", "siteURL", "https://restoreprooflab.sharepoint.com/sites/restoretest",
         "siteURL is not the RestoreTarget library's site"},
        {"restore-od-200", "folder", "Restore\xE2\x80\x8BTarget",
         "folder has a character outside printable ASCII"},
        {"restore-od-200", "folder", "RestoreTarget\x7F",
         "folder has a character outside printable ASCII"},
        {"restore-od-200", "folder", "Documents", "folder is not the RestoreTarget folder"},
    }));
    CAPTURE(row.fixture, row.key, row.value);
    Request r = recorded(row.fixture);
    r.body[row.key] = row.value;

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == guard_message(row.why));
}

TEST_CASE("the guard checks each value's JSON kind, not just its value", "[target_guard][veeam]")
{
    struct Row {
        std::string fixture;
        std::string pointer; // a JSON pointer into the body
        json value;
        std::string why;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-mail-200", "/mailbox", 7, "mailbox is not a JSON string"},
        {"restore-mail-200", "/mailbox", nullptr, "mailbox is not a JSON string"},
        {"restore-mail-200", "/folder", json::object({{"name", "Inbox"}}),
         "folder is not a JSON string"},
        {"restore-mail-200", "/officeRegion", true, "officeRegion is not a JSON string"},
        {"restore-mail-200", "/applicationCertificate", 1,
         "applicationCertificate is not a JSON string"},
        {"restore-mail-200", "/applicationCertificatePassword", nullptr,
         "applicationCertificatePassword is not a JSON string"},
        {"restore-mail-200", "/changedItems", "true", "changedItems is not a JSON boolean"},
        {"restore-mail-200", "/excludeLitigationHoldItems", 1,
         "excludeLitigationHoldItems is not a JSON boolean"},
        {"restore-mail-200", "/items", json::object(), "items is not a JSON array"},
        {"restore-mail-200", "/items/0", "an id", "items[0] is not an object holding only an id"},
        {"restore-mail-200", "/items/0/name", "x", "items[0] is not an object holding only an id"},
        {"restore-mail-200", "/items/0/id", 5, "items[0].id is not a JSON string"},
        {"restore-mail-200", "/officeOrganizationName", "Other.onmicrosoft.com",
         "officeOrganizationName is not the organisation's"},
        {"restore-sp-200", "/sendSharedLinksNotification", "false",
         "sendSharedLinksNotification is not a JSON boolean"},
        {"restore-sp-200", "/sendSharedLinksNotification", true,
         "sendSharedLinksNotification is not false"},
        {"restore-sp-200", "/documents", "x", "documents is not a JSON array"},
        {"restore-sp-200", "/documents/0", json::array(), "documents[0] is not a JSON object"},
        {"restore-sp-200", "/documents/0/isFolder", true, "documents[0] is a folder"},
        {"restore-sp-200", "/documents/0/isFolder", "false",
         "documents[0].isFolder is not a JSON boolean"},
        {"restore-sp-200", "/documents/0/name", 1, "documents[0].name is not a JSON string"},
        {"restore-sp-200", "/documents/0/siteId", "0a1b2c3d-0000-4000-8000-000000000000",
         "documents[0].siteId is not the site in the path"},
        {"restore-sp-200", "/documents/0/siteId", 3, "documents[0].siteId is not a JSON string"},
        {"restore-sp-200", "/documents/0/id", "0a1b2c3d-0000-4000-8000-00000000abcd",
         "documents[0].id is not in the site in the path"},
        {"restore-sp-200", "/documentVersion", "First", "documentVersion is not Last"},
        {"restore-sp-200", "/documentLastVersionAction", "Overwrite",
         "documentLastVersionAction is not Merge"},
        {"restore-sp-200", "/organizationName", "Other.onmicrosoft.com",
         "organizationName is not the organisation's"},
        {"restore-sp-200", "/officeRegion", "China", "officeRegion is not the organisation's region"},
        {"restore-od-200", "/onedrive", "x", "onedrive is not an object of exactly id, name and url"},
        {"restore-od-200", "/onedrive/extra", "x",
         "onedrive is not an object of exactly id, name and url"},
        {"restore-od-200", "/onedrive/id", 1, "onedrive.id is not a JSON string"},
        {"restore-od-200", "/onedrive/name", 1, "onedrive.name is not a JSON string"},
        {"restore-od-200", "/onedrive/name", "Bob Test", "onedrive.name is not the test OneDrive's"},
        {"restore-od-200", "/deletedItems", "yes", "deletedItems is not a JSON boolean"},
        {"restore-od-200", "/documents/0/oneDriveId", "0a1b2c3d-0000-4000-8000-00000000abcd",
         "documents[0].oneDriveId is not the OneDrive in the path"},
        {"restore-od-200", "/documents/0/isFolder", true, "documents[0] is a folder"},
        {"restore-od-200", "/documents/0/id", 7, "documents[0].id is not a JSON string"},
    }));
    CAPTURE(row.fixture, row.pointer);
    Request r = recorded(row.fixture);
    r.body[json::json_pointer(row.pointer)] = row.value;

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == guard_message(row.why));
}

TEST_CASE("a missing key is refused, at the top and in a document", "[target_guard][veeam]")
{
    struct Row {
        std::string fixture;
        std::string pointer;
        std::string why;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-mail-200", "/folder",
         "the mail body's keys are not exactly the expected set (extra: none; missing: folder)"},
        {"restore-sp-200", "/documents/0/siteId", "documents[0].siteId is missing"},
        {"restore-sp-200", "/documents/0/isFolder", "documents[0].isFolder is missing"},
        {"restore-od-200", "/documents/0/oneDriveId", "documents[0].oneDriveId is missing"},
        {"restore-od-200", "/onedrive/url",
         "onedrive is not an object of exactly id, name and url"},
    }));
    CAPTURE(row.fixture, row.pointer);
    Request r = recorded(row.fixture);
    const json::json_pointer pointer(row.pointer);
    r.body.at(pointer.parent_pointer()).erase(pointer.back());

    const Thrown thrown = check(r);

    CHECK(thrown.what == guard_message(row.why));
}

TEST_CASE("the guard refuses a restore whose source is the RestoreTarget library",
          "[target_guard][veeam]")
{
    // The targets are in every restore point (restore-flow §4.4): a document
    // whose ID names the RestoreTarget list is a restore from a restore target.
    const json drive = load_fixture_json("graph", "restoretarget-drive-200").at("body");
    const std::string target_list = drive.at("sharePointIds").at("listId").get<std::string>();
    Request r = recorded("restore-sp-200");
    const std::string document =
        r.ctx.container_id + target_list + "5ac127fb-0646-464e-a89a-76e93e62feb8";
    r.body.at("documents").at(0).at("id") = document;
    r.ctx.items.at(0).id = document;

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == guard_message("documents[0] is sampled from the RestoreTarget library: "
                                       "a restore target is never a source"));
}

TEST_CASE("the guard refuses a OneDrive that isn't the RestoreTarget folder's",
          "[target_guard][veeam]")
{
    struct Row {
        std::string name;
        std::string id;
        std::string url;
        std::string why;
    };
    const Row row = GENERATE(values<Row>({
        // Even when W2.5's context agrees with the body.
        {"another site's OneDrive", "<other site>", "", "onedrive.id is not the test OneDrive"},
        {"another tenant's host", "",
         "https://evil-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com",
         "onedrive.url is not the test OneDrive's address"},
        {"the tenant's site host, not -my", "",
         "https://restoreprooflab.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com",
         "onedrive.url is not the test OneDrive's address"},
        {"plain http", "",
         "http://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com",
         "onedrive.url is not the test OneDrive's address"},
        {"a query", "",
         "https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com?x=1",
         "onedrive.url is not the test OneDrive's address"},
        {"a fragment", "",
         "https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com#x",
         "onedrive.url is not the test OneDrive's address"},
        // Another user's OneDrive on the tenant's own -my host: only Graph's
        // site URL for the RestoreTarget folder tells it apart.
        {"bob's OneDrive", "",
         "https://restoreprooflab-my.sharepoint.com/personal/bob_restoreprooflab_onmicrosoft_com",
         "onedrive.url is not the test OneDrive's address"},
        {"a prefix of the test OneDrive's address", "",
         "https://restoreprooflab-my.sharepoint.com/personal/alice",
         "onedrive.url is not the test OneDrive's address"},
        {"a trailing slash", "",
         "https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com/",
         "onedrive.url is not the test OneDrive's address"},
        // The right site GUID, another web.
        {"another web of the test OneDrive's site", "<other web>", "",
         "onedrive.id is not the test OneDrive"},
    }));
    CAPTURE(row.name);
    Request r = recorded("restore-od-200");
    if (!row.id.empty()) {
        // One of the recorded ID's two GUIDs replaced (built, not spelled out).
        const std::string& recorded_id = r.ctx.target_onedrive_id;
        const std::string id = row.id == "<other site>"
                                   ? kOtherExplore + recorded_id.substr(36)
                                   : recorded_id.substr(0, 36) + kOtherExplore;
        r.body.at("onedrive").at("id") = id;
        r.ctx.target_onedrive_id = id;
    }
    if (!row.url.empty()) {
        r.body.at("onedrive").at("url") = row.url;
        r.ctx.target_onedrive_url = row.url;
    }

    const Thrown thrown = check(r);

    CHECK(thrown.what == guard_message(row.why));
}

TEST_CASE("the guard refuses a OneDrive other than the one W2.5 matched", "[target_guard][veeam]")
{
    // The first GUID still names the RestoreTarget folder's site.
    Request r = recorded("restore-od-200");
    r.body.at("onedrive").at("id") =
        r.ctx.target_onedrive_id.substr(0, 36) + "0a1b2c3d-0000-4000-8000-00000000abcd";

    CHECK(check(r).what == guard_message("onedrive.id is not the test OneDrive"));
}

TEST_CASE("the OneDrive's ID and address are compared with Graph's ignoring case",
          "[target_guard][veeam]")
{
    Request r = recorded("restore-od-200");
    std::string id = r.ctx.target_onedrive_id;
    std::transform(id.begin(), id.end(), id.begin(),
                   [](char c) { return c >= 'a' && c <= 'f' ? static_cast<char>(c - 32) : c; });
    const std::string url =
        "https://RestoreProofLab-my.SharePoint.com/personal/ALICE_restoreprooflab_onmicrosoft_com";
    r.body.at("onedrive").at("id") = id;
    r.body.at("onedrive").at("url") = url;
    r.ctx.target_onedrive_id = id;
    r.ctx.target_onedrive_url = url;

    CHECK(check(r).kind == "none");
}

// ---- the text itself -----------------------------------------------------------------------

TEST_CASE("the guard refuses a duplicate key at any depth", "[target_guard][veeam]")
{
    struct Row {
        std::string fixture;
        std::string find;
        std::string replace;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-mail-200", "\"folder\":\"Inbox\"", "\"folder\":\"Inbox\",\"folder\":\"Inbox\""},
        {"restore-mail-200", "{\"id\":\"", "{\"id\":\"x\",\"id\":\""},
        {"restore-sp-200", "\"isFolder\":false", "\"isFolder\":false,\"isFolder\":false"},
        {"restore-od-200", "\"name\":\"Alice Test\"",
         "\"name\":\"Alice Test\",\"name\":\"Alice Test\""},
        {"restore-od-200", "\"isFolder\":false", "\"isFolder\":true,\"isFolder\":false"},
    }));
    CAPTURE(row.fixture, row.find);
    Request r = recorded(row.fixture);
    std::string text = r.body.dump();
    const std::size_t at = text.find(row.find);
    REQUIRE(at != std::string::npos);
    r.raw = text.replace(at, row.find.size(), row.replace);

    const Thrown thrown = check(r);

    CHECK(thrown.what == guard_message("the body has a key twice in one object"));
}

TEST_CASE("the guard refuses two keys of one object that differ only in ASCII case",
          "[target_guard][veeam]")
{
    // Veeam's REST server is .NET, whose JSON binders match names ignoring
    // case and keep the last: a stray "Id" beside the checked "id" could be the
    // item Veeam restores, "IsFolder" the folder flag it reads.
    struct Row {
        std::string fixture;
        std::string pointer; // the case variant added beside the checked key
        json value;
    };
    const std::string elsewhere = "0a1b2c3d-0000-4000-8000-00000000abcd";
    const Row row = GENERATE_COPY(values<Row>({
        {"restore-sp-200", "/documents/0/Id", elsewhere},
        {"restore-sp-200", "/documents/0/SiteId", elsewhere},
        {"restore-sp-200", "/documents/0/IsFolder", true},
        {"restore-sp-200", "/documents/0/NAME", "other.pdf"},
        {"restore-od-200", "/documents/0/OneDriveId", elsewhere},
        {"restore-od-200", "/documents/0/ID", elsewhere},
        {"restore-od-200", "/onedrive/URL", "https://restoreprooflab-my.sharepoint.com/personal/bob"},
        {"restore-mail-200", "/items/0/ID", elsewhere},
        {"restore-mail-200", "/Mailbox", "alice@RestoreProofLab.onmicrosoft.com"},
    }));
    CAPTURE(row.fixture, row.pointer);
    Request r = recorded(row.fixture);
    r.body[json::json_pointer(row.pointer)] = row.value;

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what ==
          guard_message("the body has two keys in one object that differ only in ASCII case"));
}

TEST_CASE("the guard refuses a key with a character outside printable ASCII",
          "[target_guard][veeam]")
{
    // .NET's case-insensitive match folds some non-ASCII letters to ASCII
    // (U+017F, long s, to 'S'): such a key could stand for a checked one.
    struct Row {
        std::string fixture;
        std::string pointer;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-sp-200", "/documents/0/\xC5\xBFiteId"},
        {"restore-od-200", "/documents/0/i\xE2\x80\x8B" "d"},
        {"restore-mail-200", "/folder\xC2\xAD"},
        {"restore-mail-200", "/items/0/\x7F"},
        {"restore-sp-200", "/documents/0/tab\tkey"},
    }));
    CAPTURE(row.fixture, row.pointer);
    Request r = recorded(row.fixture);
    r.body[json::json_pointer(row.pointer)] = "x";

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what ==
          guard_message("the body has a key with a character outside printable ASCII"));
}

TEST_CASE("the guard refuses a body that isn't one JSON object", "[target_guard][veeam]")
{
    Request r = recorded("restore-sp-200");
    const std::string text = r.body.dump();
    struct Row {
        std::string name;
        std::string text;
        std::string why;
    };
    const Row row = GENERATE_COPY(
        Row{"empty", "", "the body is not valid JSON"},
        Row{"cut short", text.substr(0, text.size() / 2), "the body is not valid JSON"},
        Row{"trailing text", text + "x", "the body is not valid JSON"},
        Row{"two objects", text + text, "the body is not valid JSON"},
        Row{"a comment", "/*c*/" + text, "the body is not valid JSON"},
        Row{"invalid UTF-8 in a string",
            text.substr(0, text.find("RestoreTarget")) + "Restore\xFFTarget" +
                text.substr(text.find("RestoreTarget") + 13),
            "the body is not valid JSON"},
        Row{"a lone surrogate escape",
            text.substr(0, text.find("RestoreTarget")) + "Restore\\ud800Target" +
                text.substr(text.find("RestoreTarget") + 13),
            "the body is not valid JSON"},
        Row{"an array", "[" + text + "]", "the body is not a JSON object"},
        Row{"a string", "\"just a string\"", "the body is not a JSON object"});
    CAPTURE(row.name);
    r.raw = row.text;

    const Thrown thrown = check(r);

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == guard_message(row.why));
}

TEST_CASE("an escaped name is read as the name it spells", "[target_guard][veeam]")
{
    // JSON escapes are part of the exact text: \u0052 is 'R', and passes; the
    // soft hyphen, escaped, is still refused.
    Request r = recorded("restore-sp-200");
    const std::string text = r.body.dump();
    const std::size_t at = text.find("\"RestoreTarget\"");
    r.raw = text.substr(0, at) + "\"\\u0052estoreTarget\"" + text.substr(at + 15);
    CHECK(check(r).kind == "none");

    r.raw = text.substr(0, at) + "\"Restore\\u00adTarget\"" + text.substr(at + 15);
    CHECK(check(r).what == guard_message("list has a character outside printable ASCII"));
}

// ---- the path ------------------------------------------------------------------------------

TEST_CASE("the guard refuses a path with a query, fragment, escape or dot segment",
          "[target_guard][veeam]")
{
    const std::string fixture =
        GENERATE(as<std::string>{}, "restore-mail-200", "restore-sp-200", "restore-od-200");
    const std::string suffix = GENERATE(as<std::string>{}, "?x=1", "#f", "/.", "/..", "/", "\\x");
    CAPTURE(fixture, suffix);
    Request r = recorded(fixture);
    r.path += suffix;
    if (suffix == "/") {
        r.path += "/restoreTo"; // "//"
    }

    const Thrown thrown = check(r);

    CHECK(thrown.what == guard_message("the path has a query, fragment, escape or dot segment"));
}

TEST_CASE("the guard refuses a percent-escaped or dot-segmented path", "[target_guard][veeam]")
{
    Request r = recorded("restore-mail-200");
    const std::string path = r.path;
    const std::string edited = GENERATE_COPY(
        as<std::string>{}, path.substr(0, path.size() - 9) + "%72estoreTo",
        path.substr(0, path.rfind('/')) + "/./restoreTo",
        path.substr(0, path.rfind('/')) + "/x/../restoreTo");
    CAPTURE(edited);
    r.path = edited;

    CHECK(check(r).what ==
          guard_message("the path has a query, fragment, escape or dot segment"));
}

TEST_CASE("the guard refuses an explore session this run didn't open", "[target_guard][veeam]")
{
    struct Row {
        std::string name;
        std::function<void(Request&)> edit;
    };
    const Row row = GENERATE(values<Row>({
        {"not in the list",
         [](Request& r) { r.ctx.opened_explore_sessions = {kOtherExplore}; }},
        {"none opened", [](Request& r) { r.ctx.opened_explore_sessions.clear(); }},
        {"in upper case, in the path and the list",
         [](Request& r) {
             std::string& e = r.ctx.opened_explore_sessions.at(1);
             std::transform(e.begin(), e.end(), e.begin(), [](char c) {
                 return c >= 'a' && c <= 'f' ? static_cast<char>(c - 32) : c;
             });
             r.path.replace(20, 36, e);
         }},
        {"another API version",
         [](Request& r) { r.path.replace(0, 3, "/v7"); }},
    }));
    CAPTURE(row.name);
    Request r = recorded("restore-od-200");
    row.edit(r);

    CHECK(check(r).what ==
          guard_message("the explore session in the path is not one this run opened"));
}

TEST_CASE("the guard refuses a path of another kind than the context's", "[target_guard][veeam]")
{
    struct Row {
        std::string fixture;
        RestoreKind kind;
        std::string why;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-mail-200", RestoreKind::sharepoint,
         "the path is not the sharepoint restore-to-another-location call"},
        {"restore-sp-200", RestoreKind::onedrive,
         "the path is not the onedrive restore-to-another-location call"},
        {"restore-od-200", RestoreKind::mail,
         "the path is not the mail restore-to-another-location call"},
    }));
    CAPTURE(row.fixture);
    Request r = recorded(row.fixture);
    r.ctx.kind = row.kind;
    r.ctx.target_onedrive_id = "x";
    r.ctx.target_onedrive_url = "x";

    CHECK(check(r).what == guard_message(row.why));
}

TEST_CASE("the guard refuses a container other than the context's", "[target_guard][veeam]")
{
    Request r = recorded("restore-mail-200");
    r.ctx.container_id = kOtherExplore;

    CHECK(check(r).what ==
          guard_message("the path is not the mail restore-to-another-location call"));
}

// ---- the context ---------------------------------------------------------------------------

TEST_CASE("the guard refuses a context it can't check against", "[target_guard][veeam]")
{
    struct Row {
        std::string name;
        std::string fixture;
        std::function<void(RestoreRequestContext&)> edit;
        std::string why;
    };
    const Row row = GENERATE(values<Row>({
        {"no items", "restore-mail-200",
         [](RestoreRequestContext& c) { c.items.clear(); }, "bad context: no items to restore"},
        {"an item twice", "restore-mail-x5-200",
         [](RestoreRequestContext& c) { c.items.at(3).id = c.items.at(1).id; },
         "bad context: an item ID appears twice"},
        {"container not a GUID", "restore-mail-200",
         [](RestoreRequestContext& c) { c.container_id = "alice"; },
         "bad context: the container ID is not one or more lower-case GUIDs"},
        {"container empty", "restore-mail-200",
         [](RestoreRequestContext& c) { c.container_id.clear(); },
         "bad context: the container ID is not one or more lower-case GUIDs"},
        {"container in upper case", "restore-mail-200",
         [](RestoreRequestContext& c) {
             std::transform(c.container_id.begin(), c.container_id.end(), c.container_id.begin(),
                            [](char x) { return x >= 'a' && x <= 'f' ? static_cast<char>(x - 32) : x; });
         },
         "bad context: the container ID is not one or more lower-case GUIDs"},
        {"container a GUID and a half", "restore-sp-200",
         [](RestoreRequestContext& c) { c.container_id.resize(54); },
         "bad context: the container ID is not one or more lower-case GUIDs"},
        {"no application ID", "restore-mail-200",
         [](RestoreRequestContext& c) { c.application_id.clear(); },
         "bad context: application_id is empty or not printable ASCII"},
        {"organisation not ASCII", "restore-sp-200",
         [](RestoreRequestContext& c) { c.organization_name = "Org\xC2\xAD.example"; },
         "bad context: organization_name is empty or not printable ASCII"},
        {"no region", "restore-od-200",
         [](RestoreRequestContext& c) { c.office_region.clear(); },
         "bad context: office_region is empty or not printable ASCII"},
        {"no target OneDrive", "restore-od-200",
         [](RestoreRequestContext& c) { c.target_onedrive_id.clear(); },
         "bad context: target_onedrive_id is empty or not printable ASCII"},
        {"target OneDrive URL with a control character", "restore-od-200",
         [](RestoreRequestContext& c) { c.target_onedrive_url += "\n"; },
         "bad context: target_onedrive_url is empty or not printable ASCII"},
    }));
    CAPTURE(row.name);
    Request r = recorded(row.fixture);
    row.edit(r.ctx);

    CHECK(check(r).what == guard_message(row.why));
}

TEST_CASE("layer 2 can't check a restore whose target layer 1 didn't resolve",
          "[target_guard][veeam]")
{
    struct Row {
        std::string fixture;
        bool mail_spec;
        std::string why;
    };
    const Row row = GENERATE(values<Row>({
        {"restore-sp-200", true,
         "bad context: the RestoreTarget library was not checked (the spec had no SharePoint item)"},
        {"restore-od-200", true,
         "bad context: the RestoreTarget folder was not checked (the spec had no OneDrive item)"},
        {"restore-mail-200", false,
         "bad context: the test mailbox was not checked (the spec had no mail item)"},
    }));
    CAPTURE(row.fixture);
    GuardLab lab;
    const rp::CheckedTargets other = lab.guard().check_spec(
        row.mail_spec ? make_spec({mail_source()}) : make_spec({}, {sharepoint_source()}));
    const Request r = recorded(row.fixture);

    const Thrown thrown = thrown_by([&] {
        rp::veeam::check_restore_request(other, r.ctx, r.path, r.text(), lab.options());
    });

    CHECK(thrown.what == guard_message(row.why));
}

// ---- logging and credentials ---------------------------------------------------------------

TEST_CASE("a refusal logs one critical line and never a credential", "[target_guard][veeam]")
{
    struct Row {
        std::string name;
        std::function<void(Request&)> edit;
    };
    const Row row = GENERATE(values<Row>({
        {"a wrong mailbox",
         [](Request& r) { r.body["mailbox"] = "alice@RestoreProofLab.onmicrosoft.com"; }},
        {"the password as a number", [](Request& r) { r.body["applicationCertificatePassword"] = 7; }},
        {"the certificate as an object",
         [](Request& r) {
             r.body["applicationCertificate"] = json::object({{"pfx", kSentinel}});
         }},
        {"invalid JSON after the credential",
         [](Request& r) { r.raw = r.body.dump() + kSentinel; }},
        {"invalid JSON inside the credential",
         [](Request& r) {
             std::string text = r.body.dump();
             const std::size_t at = text.find(kSentinel);
             r.raw = text.insert(at + 3, "\"");
         }},
        {"a duplicate credential key",
         [](Request& r) {
             r.raw = "{\"applicationCertificatePassword\":\"" + kSentinel + "\"," +
                     r.body.dump().substr(1);
         }},
    }));
    CAPTURE(row.name);
    GuardLab lab;
    Request r = recorded("restore-mail-200");
    r.body["applicationCertificate"] = kSentinel;
    r.body["applicationCertificatePassword"] = kSentinel;
    row.edit(r);

    const Thrown thrown = check(lab, r);

    REQUIRE(thrown.kind == "SafetyViolation");
    CHECK_THAT(thrown.what, StartsWith("target guard: "));
    CHECK_THAT(thrown.what, EndsWith(kNotSent));
    CHECK_THAT(thrown.what, !ContainsSubstring(kSentinel));
    const std::string log = lab.log();
    CHECK(log == "critical SECURITY: " + thrown.what + "\n");
    CHECK_THAT(log, !ContainsSubstring(kSentinel));
}

TEST_CASE("a request that passes logs nothing and leaves the credentials alone",
          "[target_guard][veeam]")
{
    GuardLab lab;
    Request r = recorded("restore-od-200");
    r.body["applicationCertificate"] = kSentinel;
    r.body["applicationCertificatePassword"] = "";

    CHECK(check(lab, r).kind == "none");
    CHECK(lab.log().empty());
}
