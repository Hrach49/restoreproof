// W2.5: the pure parts of restore_sample (src/veeam_restore.hpp): Veeam's
// names and times, the preflight and duplicate-check filters, how items are
// split into calls, the bodies, and the verdict on a stopped session. Tables
// from docs/api/veeam-restore-flow.md §8-§12 and W2.4's and W1.0's recorded
// sessions (tests/fixtures/veeam/w24-*, w10-*).

#include "../src/text_util.hpp"
#include "../src/veeam_restore.hpp"
#include "fake_http_client.hpp"

#include <rp/connector.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;

namespace {

namespace vr = rp::veeam_restore;
using nlohmann::json;
using nlohmann::ordered_json;
using rp::connector::ItemKind;
using rp::connector::ItemOutcome;
using rp::connector::RestoreStatus;
using rp::test::load_fixture_json;
using namespace std::chrono_literals;

json body_of(const std::string& name)
{
    return load_fixture_json("veeam", name).at("body");
}

vr::UtcTime at(const std::string& text)
{
    return vr::parse_veeam_time(text).value();
}

std::string kind_of(const std::function<void()>& call)
{
    try {
        call();
    } catch (const vr::ShapeError& e) {
        return std::string{"ShapeError: "} + e.what();
    }
    return "none";
}

} // namespace

// ---- names and times -------------------------------------------------------------------

TEST_CASE("Veeam's session type for each kind", "[veeam_restore]")
{
    const auto [kind, type] = GENERATE(table<ItemKind, std::string>({
        {ItemKind::mail, "Vex"},
        {ItemKind::sharepoint, "Vesp"},
        {ItemKind::onedrive, "Veod"},
    }));
    CHECK(vr::session_type(kind) == type);
}

TEST_CASE("the account as Veeam lists it in initiatedBy", "[veeam_restore]")
{
    const auto [username, bare] = GENERATE(table<std::string, std::string>({
        {"DESKTOP-P55CDUM\\rp-veeam", "rp-veeam"},
        {"rp-veeam", "rp-veeam"},
        {"DOMAIN\\sub\\user", "user"},
        {"trailing\\", ""},
    }));
    CHECK(vr::bare_account(username) == bare);
}

TEST_CASE("a name in a Veeam path or query keeps only the unreserved characters",
          "[veeam_restore]")
{
    // restore_sample encodes folder names and IDs with form_encode.
    const auto [text, encoded] = GENERATE(table<std::string, std::string>({
        {"Inbox", "Inbox"},
        {"AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQwAAA",
         "AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQwAAA"},
        {"Sent Items", "Sent%20Items"},
        {"a/b?c&d=e#f%", "a%2Fb%3Fc%26d%3De%23f%25"},
        {"Skrzynka odbiorcza \xC5\x9B", "Skrzynka%20odbiorcza%20%C5%9B"},
    }));
    CHECK(rp::form_encode(text) == encoded);
}

TEST_CASE("a POST time is written to the whole second, cut not rounded", "[veeam_restore]")
{
    using std::chrono::system_clock;
    const auto base = std::chrono::sys_days{std::chrono::year{2026} / 9 / 28} + 21h + 30min + 20s;
    const auto [time, text] = GENERATE_COPY(table<system_clock::time_point, std::string>({
        {base, "2026-09-28T21:30:20Z"},
        {base + 999ms, "2026-09-28T21:30:20Z"},
        {base - 60s, "2026-09-28T21:29:20Z"},
        {std::chrono::sys_days{std::chrono::year{2026} / 1 / 2} + 3h + 4min + 5s,
         "2026-01-02T03:04:05Z"},
        {std::chrono::sys_days{std::chrono::year{999} / 12 / 31} + 23h + 59min + 59s,
         "0999-12-31T23:59:59Z"},
    }));
    CHECK(vr::format_utc_seconds(time) == text);
}

TEST_CASE("Veeam's times are read with up to seven fractional digits and Z", "[veeam_restore]")
{
    const auto whole = std::chrono::sys_days{std::chrono::year{2026} / 9 / 28} + 21h + 30min + 20s;
    const auto [text, ok, nanos] = GENERATE(table<std::string, bool, std::int64_t>({
        {"2026-09-28T21:30:20Z", true, 0},
        {"2026-09-28T21:30:20.3324555Z", true, 332455500},
        {"2026-09-28T21:30:20.1Z", true, 100000000},
        {"2026-09-28T21:30:20.12345678Z", false, 0}, // eight digits
        {"2026-09-28T21:30:20.Z", false, 0},
        {"2026-09-28T21:30:20", false, 0},             // no Z
        {"9999-12-31T23:59:59.9999999", false, 0},     // a Working session's endTime
        {"2026-09-28T21:30:20+00:00", false, 0},
        {"2026-09-28 21:30:20Z", false, 0},
        {"2026-02-30T21:30:20Z", false, 0},            // no such day
        {"2026-09-28T24:30:20Z", false, 0},
        {"2026-09-28T21:60:20Z", false, 0},
        {"2026-09-28T21:30:60Z", false, 0},
        {"2026-09-2xT21:30:20Z", false, 0},
        {"2026-09-28T21:30:20,1Z", false, 0},
        // Outside what a time in nanoseconds holds (1677-09-21 to 2262-04-11):
        // refused, never overflowed.
        {"9999-12-31T23:59:59.9999999Z", false, 0},
        {"2262-04-12T00:00:00Z", false, 0},
        {"0001-01-01T00:00:00Z", false, 0},
        {"1677-09-21T00:12:44Z", false, 0},
        {"", false, 0},
    }));
    CAPTURE(text);
    const std::optional<vr::UtcTime> parsed = vr::parse_veeam_time(text);
    REQUIRE(parsed.has_value() == ok);
    if (ok) {
        CHECK(*parsed == vr::UtcTime{whole} + std::chrono::nanoseconds{nanos});
    }
}

TEST_CASE("a Veeam time cut to the second, as a sample's received_at", "[veeam_restore]")
{
    const auto [text, whole] = GENERATE(table<std::string, std::optional<std::string>>({
        // Veeam's fraction varies; the cut never rounds up.
        {"2026-09-24T22:14:43.77087Z", "2026-09-24T22:14:43Z"},
        {"2026-09-24T22:14:43.9999999Z", "2026-09-24T22:14:43Z"},
        {"2026-09-24T22:14:43Z", "2026-09-24T22:14:43Z"},
        {"2026-09-24T22:14:43", std::nullopt},
    }));
    CHECK(vr::to_whole_seconds(text) == whole);
}

TEST_CASE("Veeam's site ID from a Graph site ID", "[veeam_restore]")
{
    const auto [site, veeam] = GENERATE(table<std::string, std::optional<std::string>>({
        {"restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-"
         "b3fe-cd091a09e689",
         "fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e689"},
        {"restoreprooflab.sharepoint.com,FE08085D-EB70-42E8-95A6-470189BD98EB,4ECAF399-CC0E-4D95-"
         "B3FE-CD091A09E689",
         "fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e689"},
        {"fe08085d-eb70-42e8-95a6-470189bd98eb", std::nullopt},
        {"", std::nullopt},
    }));
    CHECK(vr::veeam_site_id(site) == veeam);
}

TEST_CASE("the personal OneDrive address of a user", "[veeam_restore]")
{
    const auto [host, user, address] =
        GENERATE(table<std::string, std::string, std::optional<std::string>>({
            {"restoreprooflab.sharepoint.com", "alice@RestoreProofLab.onmicrosoft.com",
             "https://restoreprooflab-my.sharepoint.com/personal/"
             "alice_restoreprooflab_onmicrosoft_com"},
            {"RestoreProofLab.SharePoint.com", "first.last@contoso.com",
             "https://restoreprooflab-my.sharepoint.com/personal/first_last_contoso_com"},
            {"restoreprooflab.sharepoint.com", "", std::nullopt},
            {"sharepoint.com", "alice@x", std::nullopt},
            {".sharepoint.com", "alice@x", std::nullopt},
            {"a.b.sharepoint.com", "alice@x", std::nullopt},
            {"restoreprooflab.example.com", "alice@x", std::nullopt},
        }));
    CHECK(vr::onedrive_url(host, user) == address);
}

TEST_CASE("a folder path's segments", "[veeam_restore]")
{
    const auto [path, segments] = GENERATE(table<std::string, std::vector<std::string>>({
        {"/", {}},
        {"", {}},
        {"/RestoreTest", {"RestoreTest"}},
        {"RestoreTest/sub/", {"RestoreTest", "sub"}},
        {"//./a/./b", {"a", "b"}},
    }));
    CHECK(vr::path_segments(path) == segments);
}

TEST_CASE("an ID of one or more UUIDs run together", "[veeam_restore]")
{
    const auto [id, ok] = GENERATE(table<std::string, bool>({
        {"e00393b0-a896-4487-ad04-0e1be36468fb", true},
        {"0a000000-0000-4000-8000-0000000000010b000000-0000-4000-8000-000000000002", true},
        {"0A000000-0000-4000-8000-00000000000A", true},
        {"", false},
        {"e00393b0-a896-4487-ad04-0e1be36468f", false},
        {"0a000000-0000-4000-8000-000000000001/b000000-0000-4000-8000-000000000002", false},
    }));
    CHECK(vr::is_uuid_run(id) == ok);
}

TEST_CASE("which texts read as infrastructure", "[veeam_restore]")
{
    const auto [text, infrastructure] = GENERATE(table<std::string, bool>({
        {"Cannot connect to Microsoft 365. Failed to connect to https://x", true},
        {"cannot CONNECT to microsoft 365", true},
        {"Restore operation failed with error: Failed to open mailbox: restoretest@x..", true},
        {"The application is missing the required application permissions", true},
        {"AADSTS700016: Application not found", true},
        {"Failed to restore folder: Failed to access mailbox..", true},
        // The other ways a service call fails (the W2.5 review): throttled,
        // timed out, unavailable, refused.
        {"The remote server returned an error: (429) Too Many Requests.", true},
        {"Request was throttled by Exchange Online", true},
        {"The operation has timed out.", true},
        {"Timeout expired", true},
        {"The remote server returned an error: (503) Server Unavailable.", true},
        {"Service Unavailable", true},
        {"Access denied.", true},
        {"Access is denied", true},
        {"The remote server returned an error: (401) Unauthorized.", true},
        {"The remote server returned an error: (403) Forbidden.", true},
        {"Unable to connect to the remote server", true},
        {"The underlying connection was closed", true},
        {"The remote name could not be resolved", true},
        {"The proxy server refused the connection", true},
        {"The certificate chain was issued by an authority that is not trusted", true},
        {"The token has expired", true},
        {"Item rp-canary-06.pdf was restored successfully", false},
        {"Restore failed: the item is locked", false},
        {"Item is corrupted in the backup", false},
        {"", false},
    }));
    CHECK(vr::is_infrastructure_text(text) == infrastructure);
}

TEST_CASE("only Veeam's own words are left of a message", "[veeam_restore]")
{
    const std::string cut = "\x1F";
    const auto [text, tenant, words] =
        GENERATE_COPY(table<std::string, std::vector<std::string>, std::string>({
            // A recorded success: the item, its source and target fields.
            {"Item RP-CANARY-0005 was restored successfully (type: IPM.Note; source: Alice "
             "Test\\Inbox; target: restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox)",
             {"RP-CANARY-0005"},
             "Item " + cut + " was restored successfully (type: IPM.Note; " + cut + "; " + cut + ")"},
            // W1.0's failures keep their markers.
            {"Restore operation failed with error: Failed to open mailbox: "
             "restoretest@RestoreProofLab.onmicrosoft.com..",
             {},
             "Restore operation failed with error: Failed to open mailbox: " + cut},
            {"Cannot connect to Microsoft 365. Failed to connect to https://x.sharepoint.com/..",
             {},
             "Cannot connect to Microsoft 365. Failed to connect to " + cut},
            // Quoted parts, but not an apostrophe.
            {"Can't restore folder \"AADSTS notes\" of 'Timeout Club'", {},
             "Can't restore folder " + cut + " of " + cut},
            // Paths, addresses, and the run's names, whole.
            {"Folder Projects/Access denied/2026 of bob@x.com failed for Alice Proxy", {"Alice Proxy"},
             "Folder " + cut + " " + cut + " of " + cut + " failed for " + cut},
            {"source: no end", {}, cut},
            {"an \"unclosed quote", {}, "an \"unclosed quote"},
            {"", {""}, ""},
        }));
    CAPTURE(text);
    CHECK(vr::veeam_words(text, tenant) == words);
}

// ---- the preflight and the duplicate check -----------------------------------------------

TEST_CASE("the preflight finds the account's Working sessions", "[veeam_restore]")
{
    json list = body_of("w24-mail-x5-sweep-before");
    CHECK(vr::working_sessions(list, "rp-veeam").empty());
    list["results"][3]["state"] = "Working";
    list["results"][5]["state"] = "Working";
    list["results"][5]["initiatedBy"] = "someone-else";
    list["results"][7]["state"] = "Working";
    list["results"][7]["initiatedBy"] = "RP-VEEAM";
    const std::vector<std::string> found = vr::working_sessions(list, "rp-veeam");
    CHECK(found == std::vector<std::string>{list["results"][3]["id"].get<std::string>(),
                                            list["results"][7]["id"].get<std::string>()});
}

TEST_CASE("the preflight refuses a list of the wrong shape", "[veeam_restore]")
{
    const auto [name, list, message] = GENERATE(table<std::string, json, std::string>({
        {"no results", json::object(), "ShapeError: no \"results\" list"},
        {"results not a list", json{{"results", 1}}, "ShapeError: no \"results\" list"},
        {"not an object", json::array(), "ShapeError: no \"results\" list"},
        {"an entry not an object", json{{"results", {1}}},
         "ShapeError: a session that isn't an object"},
        {"a state of another kind", json{{"results", {{{"state", 1}}}}},
         "ShapeError: \"state\" isn't a string"},
    }));
    CAPTURE(name);
    CHECK(kind_of([&] { vr::working_sessions(list, "rp-veeam"); }) == message);
}

TEST_CASE("the duplicate check keeps only the restore just posted", "[veeam_restore]")
{
    // W2.4's mail x5 run: the restore session, its own explore session (same
    // type and account) and two older OneDrive sessions.
    const json recorded = body_of("w24-mail-x5-sessions-after-post");
    const std::string restore = "a9fb8fe0-caf9-49b3-9374-0ee3bea58b0f";
    const std::string explore = "e64a4f87-6d08-4e57-a117-dd3de2d2bc02";
    const vr::UtcTime posted = at("2026-09-28T21:30:20Z");
    vr::DuplicateFilter filter{"rp-veeam", "Vex", {explore}, posted - vr::kDuplicateFloor};
    CHECK(vr::new_restore_sessions(recorded, filter) == std::vector<std::string>{restore});

    struct Row {
        std::string name;
        std::function<void(json&, vr::DuplicateFilter&)> edit;
        std::vector<std::string> kept;
    };
    const Row row = GENERATE_COPY(
        Row{"the restore already known",
            [=](json&, vr::DuplicateFilter& f) { f.known.insert(restore); }, {}},
        Row{"the explore session not known", [=](json&, vr::DuplicateFilter& f) { f.known.clear(); },
            {restore, explore}},
        Row{"another account", [](json& l, vr::DuplicateFilter&) {
                l["results"][0]["initiatedBy"] = "other";
            }, {}},
        Row{"the account in another case", [](json& l, vr::DuplicateFilter&) {
                l["results"][0]["initiatedBy"] = "RP-Veeam";
            }, {restore}},
        Row{"another type", [](json&, vr::DuplicateFilter& f) { f.type = "Veod"; }, {}},
        Row{"created before the floor", [](json& l, vr::DuplicateFilter&) {
                l["results"][0]["creationTime"] = "2026-09-28T21:30:14.9999999Z";
            }, {}},
        Row{"created at the floor", [](json& l, vr::DuplicateFilter&) {
                l["results"][0]["creationTime"] = "2026-09-28T21:30:15Z";
            }, {restore}},
        Row{"a creationTime Veeam never writes", [](json& l, vr::DuplicateFilter&) {
                l["results"][0]["creationTime"] = "2026-09-28T21:30:20";
            }, {}},
        Row{"no creationTime", [](json& l, vr::DuplicateFilter&) {
                l["results"][0].erase("creationTime");
            }, {}},
        Row{"an ID in upper case", [=](json& l, vr::DuplicateFilter&) {
                l["results"][0]["id"] = "A9FB8FE0-CAF9-49B3-9374-0EE3BEA58B0F";
            }, {}},
        Row{"an ID that isn't a UUID", [](json& l, vr::DuplicateFilter&) {
                l["results"][0]["id"] = "a9fb8fe0";
            }, {}},
        Row{"an ID of another kind", [](json& l, vr::DuplicateFilter&) {
                l["results"][0]["id"] = 7;
            }, {}},
        Row{"no type", [](json& l, vr::DuplicateFilter&) { l["results"][0].erase("type"); }, {}},
        Row{"no initiatedBy", [](json& l, vr::DuplicateFilter&) {
                l["results"][0].erase("initiatedBy");
            }, {}},
        Row{"an entry that isn't an object", [](json& l, vr::DuplicateFilter&) {
                l["results"][0] = "x";
            }, {}},
        Row{"two new sessions", [](json& l, vr::DuplicateFilter&) {
                json copy = l["results"][0];
                copy["id"] = "b0000000-0000-4000-8000-000000000001";
                l["results"].push_back(copy);
            }, {restore, "b0000000-0000-4000-8000-000000000001"}},
        Row{"the organisation's", [](json&, vr::DuplicateFilter& f) {
                f.organization = "restoreprooflab.ONMICROSOFT.com";
            }, {restore}},
        Row{"another organisation's", [](json&, vr::DuplicateFilter& f) {
                f.organization = "Other.onmicrosoft.com";
            }, {}},
        Row{"no organisation named: kept", [](json& l, vr::DuplicateFilter& f) {
                f.organization = "Other.onmicrosoft.com";
                l["results"][0].erase("organization");
            }, {restore}},
        Row{"an organisation of another kind", [](json& l, vr::DuplicateFilter& f) {
                f.organization = "RestoreProofLab.onmicrosoft.com";
                l["results"][0]["organization"] = 7;
            }, {}},
        Row{"Working only, and it is", [](json&, vr::DuplicateFilter& f) {
                f.working_only = true;
            }, {restore}},
        Row{"Working only, and it stopped", [](json& l, vr::DuplicateFilter& f) {
                f.working_only = true;
                l["results"][0]["state"] = "Stopped";
            }, {}},
        Row{"Working only, and no state", [](json& l, vr::DuplicateFilter& f) {
                f.working_only = true;
                l["results"][0].erase("state");
            }, {}});
    CAPTURE(row.name);
    json list = recorded;
    vr::DuplicateFilter edited = filter;
    row.edit(list, edited);
    CHECK(vr::new_restore_sessions(list, edited) == row.kept);
}

TEST_CASE("the duplicate check refuses a list of the wrong shape", "[veeam_restore]")
{
    CHECK(kind_of([] { vr::new_restore_sessions(json::object(), {}); }) ==
          "ShapeError: no \"results\" list");
}

// ---- splitting into calls ----------------------------------------------------------------

TEST_CASE("one call per source container, same-named items in separate calls",
          "[veeam_restore]")
{
    struct Row {
        std::string name;
        std::vector<std::string> containers;
        std::vector<std::string> names;
        std::vector<std::vector<std::size_t>> calls;
    };
    const Row row = GENERATE(values<Row>({
        {"one item", {"m"}, {"a"}, {{0}}},
        {"five of one mailbox", {"m", "m", "m", "m", "m"}, {"a", "b", "c", "d", "e"},
         {{0, 1, 2, 3, 4}}},
        {"two mailboxes, in order of first appearance", {"m2", "m1", "m2"}, {"a", "b", "c"},
         {{0, 2}, {1}}},
        {"a name twice in one container", {"m", "m", "m"}, {"a", "b", "a"}, {{0, 1}, {2}}},
        {"a name three times", {"m", "m", "m", "m"}, {"a", "a", "b", "a"}, {{0, 2}, {1}, {3}}},
        {"the same name in two containers", {"m1", "m2"}, {"a", "a"}, {{0}, {1}}},
        {"names differ only in case", {"m", "m"}, {"a", "A"}, {{0, 1}}},
        {"nothing", {}, {}, {}},
    }));
    CAPTURE(row.name);
    CHECK(vr::split_calls(row.containers, row.names) == row.calls);
}

// ---- the bodies --------------------------------------------------------------------------

TEST_CASE("the bodies are the recorded ones, key for key", "[veeam_restore]")
{
    const vr::OrganizationFacts org{"1fd2609d-1242-43fe-94b5-d58688a90bd6",
                                    "RestoreProofLab.onmicrosoft.com", "Worldwide"};
    // The recorded body, its keys in the order they were sent.
    const auto recorded = [](const std::string& name) {
        const std::string path = std::string{RP_FIXTURE_DIR} + "/veeam/" + name + ".json";
        std::ifstream file(path, std::ios::binary);
        return ordered_json::parse(std::string{std::istreambuf_iterator<char>(file), {}})
            .at("request_body");
    };
    SECTION("mail")
    {
        ordered_json expected = recorded("restore-mail-x5-200");
        std::vector<std::string> ids;
        for (const auto& item : expected["items"]) {
            ids.push_back(item["id"].get<std::string>());
        }
        ordered_json body = vr::mail_body(ids, "restoretest@RestoreProofLab.onmicrosoft.com", org);
        body["applicationCertificate"] = "[REDACTED]";
        body["applicationCertificatePassword"] = "[REDACTED]";
        CHECK(body.dump() == expected.dump());
    }
    SECTION("SharePoint")
    {
        const ordered_json expected = recorded("restore-sp-200");
        std::vector<ordered_json> documents(expected["documents"].begin(),
                                            expected["documents"].end());
        ordered_json body = vr::sharepoint_body(
            documents, "https://restoreprooflab.sharepoint.com/sites/RestoreTest", "RestoreTarget",
            org);
        body["applicationCertificate"] = "[REDACTED]";
        body["applicationCertificatePassword"] = "[REDACTED]";
        CHECK(body.dump() == expected.dump());
    }
    SECTION("OneDrive")
    {
        const ordered_json expected = recorded("restore-od-200");
        std::vector<ordered_json> documents(expected["documents"].begin(),
                                            expected["documents"].end());
        ordered_json body =
            vr::onedrive_body(documents, expected["onedrive"], "RestoreTarget", org);
        body["applicationCertificate"] = "[REDACTED]";
        body["applicationCertificatePassword"] = "[REDACTED]";
        CHECK(body.dump() == expected.dump());
    }
}

TEST_CASE("a document goes into a body without _links and _actions, in Veeam's order",
          "[veeam_restore]")
{
    const ordered_json reread = ordered_json::parse(
        R"({"siteId":"s","sizeBytes":925,"_links":{"self":{}},"id":"d","_actions":{},"name":"n","isFolder":false})");
    CHECK(vr::body_document(reread).dump() ==
          R"({"siteId":"s","sizeBytes":925,"id":"d","name":"n","isFolder":false})");
}

// ---- reading a stopped session -----------------------------------------------------------

TEST_CASE("a session is read as Veeam wrote it", "[veeam_restore]")
{
    const vr::SessionState working = vr::read_session(body_of("w24-mail-x5-session-working"));
    CHECK(working.state == "Working");
    const vr::SessionState stopped = vr::read_session(body_of("w24-mail-x5-session"));
    CHECK(stopped.state == "Stopped");
    CHECK(stopped.result == "Success");
    CHECK(stopped.details == "5 items processed (5 successes)");
    CHECK(stopped.creation_time == "2026-09-28T21:30:20.3324555Z");
    CHECK(stopped.end_time == "2026-09-28T21:31:41.596799Z");
}

TEST_CASE("a session, statistics or events of the wrong shape", "[veeam_restore]")
{
    json session = body_of("w24-mail-x5-session");
    json stats = body_of("w24-sp-x1-statistics");
    json events = body_of("w24-sp-x1-events");
    struct Row {
        std::string name;
        std::function<void()> call;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"a session not an object", [] { vr::read_session(json::array()); },
            "a session that isn't an object"},
        Row{"a session without a state", [=]() mutable {
                session.erase("state");
                vr::read_session(session);
            }, "a session without a \"state\""},
        Row{"a state of another kind", [=]() mutable {
                session["state"] = 1;
                vr::read_session(session);
            }, "\"state\" isn't a string"},
        Row{"a result of another kind", [=]() mutable {
                session["result"] = true;
                vr::read_session(session);
            }, "\"result\" isn't a string"},
        Row{"statistics not an object", [] { vr::read_statistics(json::array()); },
            "statistics that aren't an object"},
        Row{"no restoredItemsCount", [=]() mutable {
                stats.erase("restoredItemsCount");
                vr::read_statistics(stats);
            }, "no whole \"restoredItemsCount\""},
        Row{"a restoredItemsCount as text", [=]() mutable {
                stats["restoredItemsCount"] = "1";
                vr::read_statistics(stats);
            }, "no whole \"restoredItemsCount\""},
        Row{"a negative restoredItemsCount", [=]() mutable {
                stats["restoredItemsCount"] = -1;
                vr::read_statistics(stats);
            }, "no whole \"restoredItemsCount\""},
        Row{"a fractional restoredItemsCount", [=]() mutable {
                stats["restoredItemsCount"] = 1.5;
                vr::read_statistics(stats);
            }, "no whole \"restoredItemsCount\""},
        Row{"no items", [=]() mutable {
                stats.erase("items");
                vr::read_statistics(stats);
            }, "no \"items\" list"},
        Row{"an item not an object", [=]() mutable {
                stats["items"] = {1};
                vr::read_statistics(stats);
            }, "a statistics item that isn't an object"},
        Row{"an item's status of another kind", [=]() mutable {
                stats["items"][0]["status"] = 0;
                vr::read_statistics(stats);
            }, "\"status\" isn't a string"},
        Row{"errors not a list", [=]() mutable {
                stats["errors"] = "x";
                vr::read_statistics(stats);
            }, "\"errors\" isn't a list"},
        Row{"an error not a string", [=]() mutable {
                stats["errors"] = {1};
                vr::read_statistics(stats);
            }, "an error that isn't a string"},
        Row{"events without results", [] { vr::read_events(json::object()); },
            "no \"results\" list"},
        Row{"an event not an object", [] { vr::read_events(json{{"results", {"x"}}}); },
            "an event that isn't an object"},
        Row{"an event's itemName of another kind", [=]() mutable {
                events["results"][1]["itemName"] = 1;
                vr::read_events(events);
            }, "\"itemName\" isn't a string"},
        Row{"an event's message of another kind", [=]() mutable {
                events["results"][1]["message"] = json::object();
                vr::read_events(events);
            }, "\"message\" isn't a string"});
    CAPTURE(row.name);
    CHECK(kind_of(row.call) == "ShapeError: " + row.message);
}

TEST_CASE("statistics and events are read with missing and null fields empty", "[veeam_restore]")
{
    json stats = body_of("w10-sp-user-statistics");
    stats["items"] = {{{"id", nullptr}}};
    const vr::Statistics read = vr::read_statistics(stats);
    CHECK(read.restored == 0);
    REQUIRE(read.items.size() == 1);
    CHECK(read.items[0].id.empty());
    CHECK(read.items[0].status.empty());
    CHECK(read.errors.size() == 1);
    stats["errors"] = nullptr;
    CHECK(vr::read_statistics(stats).errors.empty());

    const std::vector<vr::Event> events = vr::read_events(body_of("w24-sp-x1-events"));
    REQUIRE(events.size() == 3);
    CHECK(events[0].type == "None");
    CHECK(events[0].item_name.empty());
    CHECK(events[1].type == "Restore");
    CHECK(events[1].status == "Success");
    CHECK(events[1].item_name == "rp-canary-06.pdf");
}

namespace {

// The verdict on a recorded (perhaps edited) session.
vr::SessionVerdict verdict(ItemKind kind, const std::string& run, const std::vector<vr::SentItem>& sent,
                           const std::function<void(json&, json&, json&)>& edit = {},
                           const std::vector<std::string>& tenant_texts = {})
{
    json session = body_of(run + "-session");
    json stats = body_of(run + "-statistics");
    json events = body_of(run + "-events");
    if (edit) {
        edit(session, stats, events);
    }
    return vr::judge(kind, session.at("id").get<std::string>(), vr::read_session(session),
                     vr::read_statistics(stats), vr::read_events(events), sent, tenant_texts);
}

const std::string kSpDocument =
    "fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e6897eb0f08a-f57b-418c-"
    "8ca6-f2ab812976665ac127fb-0646-464e-a89a-76e93e62feb8";
const std::string kOdDocument = "14ad2a26-a9d6-4307-a1b0-7f15d8b7debb";

std::vector<vr::SentItem> mail_x5_sent()
{
    return {{"RP-CANARY-0002", "i2"}, {"RP-CANARY-0003", "i3"}, {"RP-CANARY-0004", "i4"},
            {"RP-CANARY-0005", "i5"}, {"RP-CANARY-0006", "i6"}};
}

} // namespace

TEST_CASE("the recorded sessions are verdicts of succeeded", "[veeam_restore]")
{
    struct Row {
        ItemKind kind;
        std::string run;
        std::vector<vr::SentItem> sent;
    };
    const Row row = GENERATE_COPY(values<Row>({
        {ItemKind::mail, "w24-mail-x5", mail_x5_sent()},
        {ItemKind::mail, "w24-mail-x1", {{"RP-CANARY-0011", "i"}}},
        {ItemKind::sharepoint, "w24-sp-x1", {{"rp-canary-06.pdf", kSpDocument}}},
        {ItemKind::onedrive, "w24-od-x1", {{"rp-canary-16.pdf", kOdDocument}}},
    }));
    CAPTURE(row.run);
    const vr::SessionVerdict v = verdict(row.kind, row.run, row.sent);
    CHECK(v.succeeded);
    CHECK_FALSE(v.infrastructure);
    REQUIRE(v.items.size() == row.sent.size());
    for (std::size_t i = 0; i < row.sent.size(); ++i) {
        CHECK(v.items[i].kind == row.kind);
        CHECK(v.items[i].name == row.sent[i].name);
        CHECK(v.items[i].outcome == ItemOutcome::restored);
        CHECK_THAT(v.items[i].message, ContainsSubstring("was restored successfully"));
        CHECK_FALSE(v.items[i].infrastructure);
    }
}

TEST_CASE("the verdict table", "[veeam_restore]")
{
    using Edit = std::function<void(json&, json&, json&)>;
    struct Row {
        std::string name;
        ItemKind kind;
        std::string run;
        std::vector<vr::SentItem> sent;
        Edit edit;
        bool succeeded;
        std::vector<ItemOutcome> outcomes;
    };
    const auto restored = ItemOutcome::restored;
    const auto failed = ItemOutcome::failed;
    const auto unknown = ItemOutcome::unknown;
    const std::vector<vr::SentItem> sp{{"rp-canary-06.pdf", kSpDocument}};
    const std::vector<vr::SentItem> od{{"rp-canary-16.pdf", kOdDocument}};
    const Row row = GENERATE_COPY(values<Row>({
        {"Warning, fewer restored", ItemKind::mail, "w24-mail-x5", mail_x5_sent(),
         [](json& s, json& st, json& e) {
             s["result"] = "Warning";
             st["restoredItemsCount"] = 4;
             for (json& event : e["results"]) {
                 if (event.value("itemName", "") == "RP-CANARY-0004") {
                     event["status"] = "Warning";
                     event["message"] = "Item RP-CANARY-0004 was skipped";
                 }
             }
         },
         false, {restored, restored, failed, restored, restored}},
        {"a short restoredItemsCount", ItemKind::mail, "w24-mail-x5", mail_x5_sent(),
         [](json&, json& st, json&) { st["restoredItemsCount"] = 4; }, false,
         {restored, restored, restored, restored, restored}},
        {"an item without its event", ItemKind::mail, "w24-mail-x5", mail_x5_sent(),
         [](json&, json&, json& e) { e["results"].erase(2); }, false,
         {restored, restored, unknown, restored, restored}},
        {"an item's event names another type", ItemKind::mail, "w24-mail-x5", mail_x5_sent(),
         [](json&, json&, json& e) { e["results"][1]["type"] = "None"; }, false,
         {restored, unknown, restored, restored, restored}},
        {"a result other than Success", ItemKind::sharepoint, "w24-sp-x1", sp,
         [](json& s, json&, json&) { s["result"] = "Warning"; }, false, {restored}},
        {"a file without its statistics entry", ItemKind::sharepoint, "w24-sp-x1", sp,
         [](json&, json& st, json&) { st["items"] = json::array(); }, false, {unknown}},
        {"a file whose statistics entry failed", ItemKind::sharepoint, "w24-sp-x1", sp,
         [](json&, json& st, json&) { st["items"][0]["status"] = "Failed"; }, false, {unknown}},
        {"a SharePoint entry with the whole document ID", ItemKind::sharepoint, "w24-sp-x1", sp,
         [](json&, json& st, json&) { st["items"][0]["id"] = kSpDocument; }, false, {unknown}},
        {"a OneDrive entry with the document ID's end only", ItemKind::onedrive, "w24-od-x1",
         {{"rp-canary-16.pdf", "0a000000-0000-4000-8000-000000000001" + kOdDocument}},
         [](json&, json&, json&) {}, false, {unknown}},
        {"a statistics ID in upper case", ItemKind::onedrive, "w24-od-x1", od,
         [](json&, json& st, json&) {
             st["items"][0]["id"] = "14AD2A26-A9D6-4307-A1B0-7F15D8B7DEBB";
         },
         true, {restored}},
        {"an itemName in another case", ItemKind::onedrive, "w24-od-x1", od,
         [](json&, json&, json& e) { e["results"][1]["itemName"] = "RP-CANARY-16.PDF"; }, false,
         {unknown}},
        {"a failed Restore event", ItemKind::onedrive, "w24-od-x1", od,
         [](json& s, json& st, json& e) {
             s["result"] = "Failed";
             st["restoredItemsCount"] = 0;
             e["results"][1]["status"] = "Failed";
             e["results"][1]["message"] = "Item rp-canary-16.pdf: access denied";
         },
         false, {failed}},
    }));
    CAPTURE(row.name);
    const vr::SessionVerdict v = verdict(row.kind, row.run, row.sent, row.edit);
    CHECK(v.succeeded == row.succeeded);
    std::vector<ItemOutcome> outcomes;
    for (const auto& item : v.items) {
        outcomes.push_back(item.outcome);
    }
    CHECK(outcomes == row.outcomes);
}

TEST_CASE("W1.0's failed restores read as infrastructure", "[veeam_restore]")
{
    struct Row {
        ItemKind kind;
        std::string run;
        std::string text;
    };
    const Row row = GENERATE(values<Row>({
        {ItemKind::mail, "w10-mail-user", "Failed to access mailbox"},
        {ItemKind::sharepoint, "w10-sp-user", "Cannot connect to Microsoft 365"},
        // No errors[] in the statistics: the reason is only in the events.
        {ItemKind::onedrive, "w10-od-user", "Cannot connect to Microsoft 365"},
    }));
    CAPTURE(row.run);
    const vr::SessionVerdict v = verdict(row.kind, row.run, {{"rp-canary-16.pdf", kOdDocument}});
    CHECK(v.infrastructure);
    CHECK_THAT(v.infrastructure_text, ContainsSubstring(row.text));
    CHECK_FALSE(v.succeeded);
    REQUIRE(v.items.size() == 1);
    CHECK(v.items[0].outcome == ItemOutcome::unknown);
    CHECK(v.items[0].infrastructure);
    CHECK_THAT(v.items[0].message, ContainsSubstring(row.text));
}

TEST_CASE("an item's name never makes its session or itself infrastructure", "[veeam_restore]")
{
    // A sampled real mail's subject (or a file's name) is the tenant's text:
    // Veeam puts it into the item's event, and only what Veeam says about the
    // item may read as infrastructure.
    struct Row {
        std::string name;
        std::string subject;
        bool fails;
        std::string failure; // the item event's message after the subject
        bool infrastructure;
    };
    const Row row = GENERATE(values<Row>({
        {"restored, AADSTS in the subject", "AADSTS50076 sign-in error", false, "", false},
        {"restored, a marker in the subject", "Failed to open mailbox - ticket 4411", false, "",
         false},
        {"failed for itself, a marker in the subject", "Failed to open mailbox - ticket 4411",
         true, ": the item is corrupt", false},
        {"failed for lack of Microsoft 365", "Quarterly report", true,
         ": AADSTS700016: Application not found", true},
    }));
    CAPTURE(row.name);
    const vr::SessionVerdict v = verdict(
        ItemKind::mail, "w24-mail-x1", {{row.subject, "i"}}, [&](json& s, json& st, json& e) {
            json& item = e["results"][1];
            item["itemName"] = row.subject;
            item["title"] = row.subject;
            if (row.fails) {
                s["result"] = "Failed";
                st["restoredItemsCount"] = 0;
                item["status"] = "Failed";
                item["message"] = "Failed to restore item " + row.subject + row.failure;
            } else {
                item["message"] = "Item " + row.subject + " was restored successfully";
            }
        });
    CHECK(v.infrastructure == row.infrastructure);
    REQUIRE(v.items.size() == 1);
    CHECK(v.items[0].outcome == (row.fails ? ItemOutcome::failed : ItemOutcome::restored));
    CHECK(v.items[0].infrastructure == row.infrastructure);
    CHECK(v.succeeded == !row.fails);
    CHECK_THAT(v.items[0].message, ContainsSubstring(row.subject));
}

TEST_CASE("an item's message falls back to the statistics' error", "[veeam_restore]")
{
    const vr::SessionVerdict v = verdict(
        ItemKind::mail, "w10-mail-user", {{"RP-CANARY-0001", "i"}}, [](json&, json&, json& e) {
            e["results"] = json::array();
        });
    CHECK(v.items[0].message == "Restore operation failed with error: Failed to open mailbox: "
                                "restoretest@RestoreProofLab.onmicrosoft.com..");
    CHECK(v.infrastructure);
}

TEST_CASE("an item that failed for itself isn't infrastructure", "[veeam_restore]")
{
    // Veeam reached the item and says what is wrong with it: a `fail` to be.
    const vr::SessionVerdict v = verdict(
        ItemKind::onedrive, "w10-od-user", {{"rp-canary-16.pdf", kOdDocument}},
        [](json&, json&, json& e) {
            e["results"][1] = {{"type", "Restore"},
                               {"status", "Failed"},
                               {"itemName", "rp-canary-16.pdf"},
                               {"title", "Restore failed: the item is locked"},
                               {"message", "Restore failed: the item is locked"}};
        });
    CHECK_FALSE(v.infrastructure);
    CHECK(v.infrastructure_text.empty());
    CHECK(v.items[0].outcome == ItemOutcome::failed);
    CHECK(v.items[0].message == "Restore failed: the item is locked");
    CHECK_FALSE(v.items[0].infrastructure);
}

TEST_CASE("a session that restored nothing and named no item is infrastructure",
          "[veeam_restore]")
{
    // The W2.5 review: Veeam never reached the items, so nothing is known about
    // the backup; whatever its words, the test couldn't run (never `fail`).
    const auto [name, message, text] = GENERATE(table<std::string, std::string, std::string>({
        {"a failure no marker names", "Restore failed: the job was cancelled",
         "Veeam reported on none of the items: Restore failed: the job was cancelled"},
        {"no failing event", "", "Veeam reported on none of the items: 0 items processed"},
    }));
    CAPTURE(name);
    const vr::SessionVerdict v = verdict(
        ItemKind::onedrive, "w10-od-user", {{"rp-canary-16.pdf", kOdDocument}},
        [message = message](json&, json&, json& e) {
            json kept = json::array();
            if (!message.empty()) {
                kept.push_back({{"type", "None"},
                                {"status", "Failed"},
                                {"title", message},
                                {"message", message}});
            }
            e["results"] = kept;
        });
    CHECK(v.infrastructure);
    CHECK(v.infrastructure_text == text);
    CHECK_FALSE(v.succeeded);
    CHECK(v.items[0].outcome == ItemOutcome::unknown);
}

TEST_CASE("a restored item keeps a session that named no failure out of infrastructure",
          "[veeam_restore]")
{
    // Something was restored: the no-item rule is only for a session that
    // restored nothing.
    const vr::SessionVerdict v = verdict(ItemKind::mail, "w24-mail-x5", mail_x5_sent(),
                                         [](json&, json&, json& e) {
                                             json kept = json::array();
                                             for (json& event : e["results"]) {
                                                 if (event.value("type", "") != "Restore") {
                                                     kept.push_back(event);
                                                 }
                                             }
                                             e["results"] = kept;
                                         });
    CHECK_FALSE(v.infrastructure);
    CHECK_FALSE(v.succeeded);
}

TEST_CASE("the tenant's text in a failing item's message never makes it infrastructure",
          "[veeam_restore]")
{
    // The W2.5 review: Veeam's messages quote the mailbox's display name, its
    // folder, site paths and addresses, all the tenant's text.
    const auto [name, message, tenant, infrastructure] =
        GENERATE(table<std::string, std::string, std::vector<std::string>, bool>({
            {"a display name in the source field",
             "Item Report was not restored: item is corrupt (type: IPM.Note; source: AADSTS "
             "Team\\Inbox; target: restoretest@x.com\\<null>\\Inbox)",
             {}, false},
            {"a folder path", "Failed to restore item in Shared/Access denied/2026: item is corrupt",
             {}, false},
            {"a quoted folder", "Failed to restore item in folder \"Proxy Timeout\": item is corrupt",
             {}, false},
            {"a display name the run knows", "Failed to restore item of Token Holders: item is corrupt",
             {"Token Holders"}, false},
            {"a site URL", "Failed to restore https://x.sharepoint.com/sites/Timeout: item is corrupt",
             {}, false},
            {"Veeam's own words beside them",
             "Failed to restore item of Token Holders: The operation has timed out.",
             {"Token Holders"}, true},
        }));
    CAPTURE(name);
    const vr::SessionVerdict v = verdict(
        ItemKind::mail, "w24-mail-x1", {{"Report", "i"}},
        [message = message](json& s, json& st, json& e) {
            json& item = e["results"][1];
            s["result"] = "Failed";
            st["restoredItemsCount"] = 0;
            item["itemName"] = "Report";
            item["title"] = "Report";
            item["status"] = "Failed";
            item["message"] = message;
        },
        tenant);
    CHECK(v.infrastructure == infrastructure);
    CHECK(v.items[0].outcome == ItemOutcome::failed);
    CHECK(v.items[0].infrastructure == infrastructure);
}

TEST_CASE("the session's log lines", "[veeam_restore]")
{
    const vr::SessionVerdict v = verdict(ItemKind::sharepoint, "w24-sp-x1",
                                         {{"rp-canary-06.pdf", kSpDocument}});
    CHECK(v.log_lines ==
          std::vector<std::string>{
              "session f7e9e6a8-62f3-4abd-a62c-84554981a6da (sharepoint): Success, 1 item "
              "processed (1 success)",
              "Success rp-canary-06.pdf: Item rp-canary-06.pdf was restored successfully (type: "
              "File; source: /sites/RestoreTest/RestoreTest/rp-canary-06.pdf; target: "
              "https://restoreprooflab.sharepoint.com/sites/RestoreTest)"});

    const vr::SessionVerdict failed = verdict(ItemKind::onedrive, "w10-od-user",
                                              {{"rp-canary-16.pdf", kOdDocument}},
                                              [](json& s, json&, json& e) {
                                                  s.erase("details");
                                                  e["results"][1]["message"] = "a\nforged line";
                                              });
    CHECK(failed.log_lines ==
          std::vector<std::string>{
              "session 0a1f03fb-4448-4d8d-a4ff-b63cb1780661 (onedrive): Failed",
              "Failed Cannot connect to Microsoft 365. Failed to connect to "
              "https://restoreprooflab-my.sharepoint.com/personal/"
              "alice_restoreprooflab_onmicrosoft_com.: a forged line",
              "Failed Restore session failed: Restore session failed"});
}

TEST_CASE("the overall status", "[veeam_restore]")
{
    const auto [sessions, restored, all, status] =
        GENERATE(table<std::size_t, std::int64_t, bool, RestoreStatus>({
            {0, 0, true, RestoreStatus::not_run},
            {1, 0, true, RestoreStatus::failed},
            {2, 0, false, RestoreStatus::failed},
            {1, 5, true, RestoreStatus::succeeded},
            {3, 7, true, RestoreStatus::succeeded},
            {1, 4, false, RestoreStatus::partial},
            {2, 1, false, RestoreStatus::partial},
        }));
    CHECK(vr::overall_status(sessions, restored, all) == status);
}
