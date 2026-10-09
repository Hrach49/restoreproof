// W1.7 "Done when": code that holds only an rp::connector::IConnector& (as
// the scheduler will, W4.8) runs a connector without knowing Veeam. This file
// includes rp/connector.hpp and nothing from Veeam, and a scan below checks
// that nothing it includes reaches a Veeam header. The types and rules are the
// 2026-09-27 W1.7 entry in docs/decisions.md.

#include <rp/config.hpp>
#include <rp/connector.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>


namespace {

namespace connector = rp::connector;

// The values config.json holds for the three restore targets.
rp::Config config_with_targets()
{
    rp::Config config;
    config.test_mailbox = "restoretest@example.onmicrosoft.com";
    config.test_site_id = "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002";
    config.test_library_id = "b!library-id";
    config.test_onedrive_drive_id = "b!drive-id";
    config.test_onedrive_folder_id = "folder-id";
    return config;
}

connector::RestorePoint point(std::string id, std::string backup_time, bool mail = true)
{
    connector::RestorePoint p;
    p.id = std::move(id);
    p.backup_time = std::move(backup_time);
    p.has_mail = mail;
    p.has_sharepoint = true;
    p.has_onedrive = true;
    return p;
}

// A connector that isn't Veeam: it answers from what the test gives it and
// keeps the specs it was asked to restore.
class FakeConnector final : public connector::IConnector {
public:
    connector::ConnectorInfo describe() const override { return {"fake", "1"}; }

    std::vector<connector::RestorePoint> list_restore_points(const std::string& client_ref) override
    {
        clients.push_back(client_ref);
        if (list_error) {
            list_error();
        }
        return points;
    }

    connector::RestoreResult restore_sample(const connector::RestoreSpec& spec) override
    {
        specs.push_back(spec);
        connector::RestoreResult result;
        result.status = connector::RestoreStatus::succeeded;
        result.session_ids = {"session-1"};
        result.log = "restored";
        result.items_restored = static_cast<int>(spec.item_count());
        return result;
    }

    std::vector<connector::RestorePoint> points;
    std::function<void()> list_error;
    std::vector<std::string> clients;
    std::vector<connector::RestoreSpec> specs;
};

// What a scheduler-like caller learns from one run.
struct Outcome {
    std::string connector;
    std::optional<connector::RestoreResult> result;
    std::string error; // "auth", "transient", "not_found", "other"; empty when none
};

// Scheduler-like code: it knows only IConnector. Picks the newest restore
// point that holds mail and restores one canary mail into the configured
// targets.
Outcome run_one(connector::IConnector& source, const std::string& client_ref,
                const connector::RestoreTargets& targets)
{
    Outcome outcome;
    outcome.connector = source.describe().name;
    try {
        const std::vector<connector::RestorePoint> points = source.list_restore_points(client_ref);
        const auto newest = std::ranges::find_if(points, &connector::RestorePoint::has_mail);
        if (newest == points.end()) {
            return outcome;
        }
        connector::RestoreSpec spec{.client_ref = client_ref,
                                    .restore_point = *newest,
                                    .targets = targets,
                                    .mail = {{"alice@example.onmicrosoft.com", "Inbox",
                                              "RP-CANARY-0001"}}};
        outcome.result = source.restore_sample(spec);
    } catch (const connector::AuthError&) {
        outcome.error = "auth";
    } catch (const connector::TransientError&) {
        outcome.error = "transient";
    } catch (const connector::NotFoundError&) {
        outcome.error = "not_found";
    } catch (const connector::Error&) {
        outcome.error = "other";
    }
    return outcome;
}

// --- The include scan ----------------------------------------------------------

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

struct IncludeDirective {
    char kind; // '<' or '"'
    std::string name;
    bool operator==(const IncludeDirective&) const = default;
};

// The #include directives in `text`, one line at a time. Each line is matched
// whole, so the result doesn't hang on whether `^` matches after a newline:
// the standard makes that std::regex::multiline, and MSVC's STL changed its
// default between toolsets.
std::vector<IncludeDirective> include_directives(const std::string& text)
{
    const std::regex directive(R"re(\s*#\s*include\s*([<"])([^>"]+)[>"].*)re");
    std::vector<IncludeDirective> out;
    std::istringstream lines(text);
    for (std::string line; std::getline(lines, line);) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        std::smatch match;
        if (std::regex_match(line, match, directive)) {
            out.push_back({match[1].str()[0], match[2].str()});
        }
    }
    return out;
}

// Every Worker source file `start` reaches through #include, itself included:
// <rp/...> resolves in include/, "..." next to the including file. System and
// vcpkg headers are left out; they can't include Worker headers.
std::set<std::filesystem::path> worker_includes(const std::filesystem::path& start)
{
    const std::filesystem::path include_dir = std::filesystem::path{RP_SOURCE_DIR} / "include";
    std::set<std::filesystem::path> seen;
    std::vector<std::filesystem::path> todo{start.lexically_normal()};
    while (!todo.empty()) {
        const std::filesystem::path file = todo.back();
        todo.pop_back();
        if (!seen.insert(file).second) {
            continue;
        }
        for (const IncludeDirective& include : include_directives(read_file(file))) {
            std::filesystem::path target;
            if (include.kind == '"') {
                target = file.parent_path() / include.name;
            } else if (include.name.starts_with("rp/")) {
                target = include_dir / include.name;
            } else {
                continue;
            }
            REQUIRE(std::filesystem::exists(target));
            todo.push_back(target.lexically_normal());
        }
    }
    return seen;
}

std::string lower(std::string text)
{
    std::ranges::transform(text, text.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

} // namespace

TEST_CASE("the include scan finds directives on every line, not only the first", "[connector]")
{
    // The CI toolset's std::regex reads `^` as the start of the text only, so a
    // scan anchored with it found no #include after the first line and the
    // test below failed there (PR #127).
    const std::string text = "// comment first\n"
                             "#include <rp/a.hpp>\r\n"
                             "  #  include \"b.hpp\"\n"
                             "#include <vector>\n"
                             "int x; // #include <rp/not_a_directive.hpp>\n";
    REQUIRE(include_directives(text) == std::vector<IncludeDirective>{
                                            {'<', "rp/a.hpp"}, {'"', "b.hpp"}, {'<', "vector"}});
}

TEST_CASE("code holding an IConnector& reaches no Veeam header", "[connector]")
{
    const std::filesystem::path self =
        std::filesystem::path{RP_SOURCE_DIR} / "tests" / "connector_test.cpp";
    const std::set<std::filesystem::path> reached = worker_includes(self);

    std::set<std::string> names;
    for (const std::filesystem::path& file : reached) {
        names.insert(file.filename().string());
    }
    CAPTURE(names);
    // Not vacuous: the scan did follow the interface's own header.
    REQUIRE(names.contains("connector.hpp"));
    REQUIRE(names.contains("config.hpp"));
    for (const std::string& name : names) {
        CHECK_FALSE(lower(name).find("veeam") != std::string::npos);
    }
}

// --- Failure paths ---------------------------------------------------------------

TEST_CASE("a connector's errors reach the caller as connector errors", "[connector]")
{
    using Thrower = std::function<void()>;
    const auto [thrower, expected] = GENERATE(table<Thrower, std::string>({
        {[] { throw connector::AuthError("refused"); }, "auth"},
        {[] { throw connector::TransientError("unreachable"); }, "transient"},
        {[] { throw connector::NotFoundError("no such client"); }, "not_found"},
        {[] { throw connector::NotImplementedError("later"); }, "other"},
        {[] { throw connector::Error("anything else"); }, "other"},
    }));
    CAPTURE(expected);
    FakeConnector fake;
    fake.list_error = thrower;
    const connector::RestoreTargets targets =
        connector::RestoreTargets::from_config(config_with_targets());

    const Outcome outcome = run_one(fake, "client.onmicrosoft.com", targets);
    REQUIRE(outcome.error == expected);
    REQUIRE_FALSE(outcome.result);
    REQUIRE(fake.specs.empty());
}

TEST_CASE("every connector error is a connector::Error that keeps its message", "[connector]")
{
    using Thrower = std::function<void()>;
    const Thrower thrower = GENERATE(
        Thrower{[] { throw connector::AuthError("the message"); }},
        Thrower{[] { throw connector::TransientError("the message"); }},
        Thrower{[] { throw connector::NotFoundError("the message"); }},
        Thrower{[] { throw connector::NotImplementedError("the message"); }});
    try {
        thrower();
        FAIL("nothing thrown");
    } catch (const connector::Error& e) {
        REQUIRE(std::string{e.what()} == "the message");
    }
}

TEST_CASE("restore targets can't be built from a config missing one", "[connector]")
{
    const std::string key = GENERATE("test_mailbox", "test_site_id", "test_library_id",
                                     "test_onedrive_drive_id", "test_onedrive_folder_id");
    CAPTURE(key);
    rp::Config config = config_with_targets();
    if (key == "test_mailbox") {
        config.test_mailbox.clear();
    } else if (key == "test_site_id") {
        config.test_site_id.clear();
    } else if (key == "test_library_id") {
        config.test_library_id.clear();
    } else if (key == "test_onedrive_drive_id") {
        config.test_onedrive_drive_id.clear();
    } else {
        config.test_onedrive_folder_id.clear();
    }

    REQUIRE_THROWS_MATCHES(connector::RestoreTargets::from_config(config), std::invalid_argument,
                           Catch::Matchers::Message("restore target " + key + " is empty"));
}

TEST_CASE("restore targets refuse a mailbox that isn't restoretest@<domain>", "[connector]")
{
    // load_config refuses these already; a Config built in code must not get
    // past from_config either (CLAUDE.md, "Restore targets").
    const std::string mailbox = GENERATE("alice@example.onmicrosoft.com",
                                         "restoretest@localhost", "restoretest@",
                                         "restoretest@example..com",
                                         "xrestoretest@example.onmicrosoft.com",
                                         "restoretest@exa mple.com",
                                         "restor\xD0\xB5test@example.onmicrosoft.com");
    CAPTURE(mailbox);
    rp::Config config = config_with_targets();
    config.test_mailbox = mailbox;

    REQUIRE_THROWS_MATCHES(
        connector::RestoreTargets::from_config(config), std::invalid_argument,
        Catch::Matchers::Message("restore target test_mailbox must be restoretest@<domain>"));
}

// Review of W2.2: load_config checks the shapes; a Config built in code must
// not get past from_config either, since the IDs go into Graph URL paths.
TEST_CASE("restore targets refuse IDs that can't be Graph IDs", "[connector]")
{
    const auto [key, value, rule] = GENERATE(table<std::string, std::string, std::string>({
        {"test_site_id", "site-id",
         "must be a Graph site ID (\"<tenant>.sharepoint.com,<site GUID>,<web GUID>\")"},
        {"test_library_id", "x/children",
         "must be a Graph drive ID (\"b!\" then letters, digits, '-' and '_'), not a list ID"},
        {"test_onedrive_drive_id", "b!a b",
         "must be a Graph drive ID (\"b!\" then letters, digits, '-' and '_'), not a list ID"},
        {"test_onedrive_folder_id", "a?b",
         "must be a Graph item ID (letters, digits, '!', '-' and '_')"},
    }));
    CAPTURE(key, value);
    rp::Config config = config_with_targets();
    if (key == "test_site_id") {
        config.test_site_id = value;
    } else if (key == "test_library_id") {
        config.test_library_id = value;
    } else if (key == "test_onedrive_drive_id") {
        config.test_onedrive_drive_id = value;
    } else {
        config.test_onedrive_folder_id = value;
    }

    REQUIRE_THROWS_MATCHES(connector::RestoreTargets::from_config(config), std::invalid_argument,
                           Catch::Matchers::Message("restore target " + key + " " + rule));
}

TEST_CASE("restore targets take restoretest@<domain> in any case", "[connector]")
{
    rp::Config config = config_with_targets();
    config.test_mailbox = "RestoreTest@Example.onmicrosoft.com";

    REQUIRE(connector::RestoreTargets::from_config(config).mailbox() ==
            "RestoreTest@Example.onmicrosoft.com");
}

// --- Happy paths -------------------------------------------------------------------

// W4.10 point 4: from_profile is the factory; from_config wraps it.
TEST_CASE("restore targets come from a client profile, with the same checks", "[connector]")
{
    rp::ClientProfile profile;
    profile.veeam_org_name = "example.onmicrosoft.com";
    profile.graph_tenant_id = "00000000-0000-0000-0000-000000000001";
    profile.graph_client_id = "00000000-0000-0000-0000-000000000002";
    profile.test_mailbox = "restoretest@example.onmicrosoft.com";
    profile.test_site_id = "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002";
    profile.test_library_id = "b!library-id";
    profile.test_onedrive_drive_id = "b!drive-id";
    profile.test_onedrive_folder_id = "folder-id";

    const connector::RestoreTargets targets = connector::RestoreTargets::from_profile(profile);
    REQUIRE(targets.mailbox() == "restoretest@example.onmicrosoft.com");
    REQUIRE(targets.site_id() == profile.test_site_id);
    REQUIRE(targets.library_id() == "b!library-id");
    REQUIRE(targets.onedrive_drive_id() == "b!drive-id");
    REQUIRE(targets.onedrive_folder_id() == "folder-id");

    SECTION("an empty target")
    {
        profile.test_library_id.clear();
        REQUIRE_THROWS_MATCHES(connector::RestoreTargets::from_profile(profile),
                               std::invalid_argument,
                               Catch::Matchers::Message("restore target test_library_id is empty"));
    }
    SECTION("another mailbox")
    {
        profile.test_mailbox = "alice@example.onmicrosoft.com";
        REQUIRE_THROWS_MATCHES(
            connector::RestoreTargets::from_profile(profile), std::invalid_argument,
            Catch::Matchers::Message("restore target test_mailbox must be restoretest@<domain>"));
    }
    SECTION("an ID that can't be a Graph ID")
    {
        profile.test_onedrive_folder_id = "01/ABC";
        REQUIRE_THROWS_MATCHES(connector::RestoreTargets::from_profile(profile),
                               std::invalid_argument,
                               Catch::Matchers::Message("restore target test_onedrive_folder_id " +
                                                        std::string{rp::kGraphItemIdRule}));
    }
    SECTION("the organisation, tenant and app are no target: not checked here")
    {
        profile.veeam_org_name.clear();
        profile.graph_tenant_id = "not a guid";
        REQUIRE(connector::RestoreTargets::from_profile(profile).mailbox() ==
                "restoretest@example.onmicrosoft.com");
    }
}

TEST_CASE("restore targets are the configured test locations", "[connector]")
{
    const connector::RestoreTargets targets =
        connector::RestoreTargets::from_config(config_with_targets());
    REQUIRE(targets.mailbox() == "restoretest@example.onmicrosoft.com");
    REQUIRE(targets.site_id() == "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002");
    REQUIRE(targets.library_id() == "b!library-id");
    REQUIRE(targets.onedrive_drive_id() == "b!drive-id");
    REQUIRE(targets.onedrive_folder_id() == "folder-id");
}

TEST_CASE("a restore status has one name each", "[connector]")
{
    const auto [status, name] = GENERATE(table<connector::RestoreStatus, std::string>({
        {connector::RestoreStatus::not_run, "not_run"},
        {connector::RestoreStatus::succeeded, "succeeded"},
        {connector::RestoreStatus::partial, "partial"},
        {connector::RestoreStatus::failed, "failed"},
    }));
    REQUIRE(connector::to_string(status) == name);
}

TEST_CASE("a new restore result has not run", "[connector]")
{
    const connector::RestoreResult result;
    REQUIRE(result.status == connector::RestoreStatus::not_run);
    REQUIRE(result.session_ids.empty());
    REQUIRE(result.log.empty());
    REQUIRE(result.items_restored == 0);
    REQUIRE(result.items_sent == 0);
    REQUIRE(result.sessions.empty());
    REQUIRE(result.items.empty());
    const connector::ItemRestoreResult item;
    REQUIRE(item.outcome == connector::ItemOutcome::unknown);
    REQUIRE_FALSE(item.infrastructure);
    const connector::RestoreSessionResult session;
    REQUIRE(session.items_sent == 0);
    REQUIRE(session.items_restored == 0);
}

TEST_CASE("item kinds and outcomes have stable names", "[connector]")
{
    const auto [kind, kind_name] = GENERATE(table<connector::ItemKind, std::string>({
        {connector::ItemKind::mail, "mail"},
        {connector::ItemKind::sharepoint, "sharepoint"},
        {connector::ItemKind::onedrive, "onedrive"},
    }));
    CHECK(connector::to_string(kind) == kind_name);
    const auto [outcome, outcome_name] = GENERATE(table<connector::ItemOutcome, std::string>({
        {connector::ItemOutcome::unknown, "unknown"},
        {connector::ItemOutcome::restored, "restored"},
        {connector::ItemOutcome::failed, "failed"},
        {connector::ItemOutcome::not_in_backup, "not_in_backup"},
    }));
    CHECK(connector::to_string(outcome) == outcome_name);
}

TEST_CASE("the selectors' optional fields start unset", "[connector]")
{
    const connector::MailSelector mail{"alice@x", "Inbox", "s"};
    CHECK(mail.received_at.empty());
    const connector::SharePointSelector sp{"site", "drive", "/", "f.pdf"};
    CHECK(sp.list_id.empty());
    CHECK(sp.size == -1);
    const connector::OneDriveSelector od{"alice@x", "/RestoreTest", "f.pdf"};
    CHECK(od.size == -1);
}

TEST_CASE("a connector that can't list candidates says so by name", "[connector]")
{
    FakeConnector fake;
    const connector::CandidateQuery query{
        .client_ref = "Contoso",
        .restore_point = {},
        .targets = connector::RestoreTargets::from_config(config_with_targets()),
        .mail = true};
    REQUIRE_THROWS_MATCHES(fake.list_candidates(query), connector::NotImplementedError,
                           Catch::Matchers::Message("fake: listing candidates isn't implemented"));
}

TEST_CASE("a connector that can't list or end its account's sessions says so by name",
          "[connector][w4.8]")
{
    FakeConnector fake;
    REQUIRE_THROWS_MATCHES(
        fake.own_sessions(std::chrono::system_clock::time_point{}), connector::NotImplementedError,
        Catch::Matchers::Message("fake: listing the account's sessions isn't implemented"));
    REQUIRE_THROWS_MATCHES(fake.end_session("session-1"), connector::NotImplementedError,
                           Catch::Matchers::Message("fake: ending a session isn't implemented"));
}

TEST_CASE("candidate limits and records start at the documented values", "[connector]")
{
    const connector::CandidateLimits limits;
    CHECK(limits.containers_wanted == 2);
    CHECK(limits.containers_tried == 8);
    CHECK(limits.folders_per_container == 3);
    CHECK(limits.walk_depth == 2);
    CHECK(limits.walk_calls == 20);
    CHECK(limits.max_file_bytes == 64ll * 1024 * 1024);
    const connector::BrowseRecord record;
    CHECK(record.containers_eligible == 0);
    CHECK(record.containers_listed.empty());
    CHECK(record.containers_unresolved == 0);
    CHECK(record.folders_listed == 0);
    CHECK_FALSE(record.short_of_containers);
    CHECK(connector::SharePointCandidate{}.size_bytes == -1);
    CHECK(connector::OneDriveCandidate{}.size_bytes == -1);
}

TEST_CASE("a restore spec counts its items across the three types", "[connector]")
{
    const connector::RestoreTargets targets =
        connector::RestoreTargets::from_config(config_with_targets());
    connector::RestoreSpec spec{.client_ref = "c", .restore_point = point("p", "t"),
                                .targets = targets};
    REQUIRE(spec.item_count() == 0);
    spec.mail = {{"alice@x", "Inbox", "RP-CANARY-0001"}, {"bob@x", "Inbox", "RP-CANARY-0002"}};
    spec.sharepoint = {{"site", "drive", "/", "rp-canary-01.pdf"}};
    spec.onedrive = {{"alice@x", "/RestoreTest", "rp-canary-11.pdf"}};
    REQUIRE(spec.item_count() == 4);
}

TEST_CASE("scheduler-like code runs a connector it knows only as IConnector&", "[connector]")
{
    FakeConnector fake;
    // Newest first, as list_restore_points promises; the newest holds no mail.
    fake.points = {point("p3", "2026-09-27T02:00:00.0000000Z", false),
                   point("p2", "2026-09-26T02:00:00.0000000Z"),
                   point("p1", "2026-09-25T02:00:00.0000000Z")};
    const connector::RestoreTargets targets =
        connector::RestoreTargets::from_config(config_with_targets());

    const Outcome outcome = run_one(fake, "client.onmicrosoft.com", targets);
    REQUIRE(outcome.error.empty());
    REQUIRE(outcome.connector == "fake");
    REQUIRE(fake.clients == std::vector<std::string>{"client.onmicrosoft.com"});
    REQUIRE(fake.specs.size() == 1);
    const connector::RestoreSpec& spec = fake.specs[0];
    REQUIRE(spec.client_ref == "client.onmicrosoft.com");
    REQUIRE(spec.restore_point.id == "p2");
    REQUIRE(spec.restore_point.backup_time == "2026-09-26T02:00:00.0000000Z");
    REQUIRE(spec.targets.mailbox() == "restoretest@example.onmicrosoft.com");
    REQUIRE(spec.targets.onedrive_folder_id() == "folder-id");
    REQUIRE(spec.mail.size() == 1);
    REQUIRE(spec.mail[0].subject == "RP-CANARY-0001");
    REQUIRE(outcome.result);
    REQUIRE(outcome.result->status == connector::RestoreStatus::succeeded);
    REQUIRE(outcome.result->items_restored == 1);
    REQUIRE(outcome.result->session_ids == std::vector<std::string>{"session-1"});
}
