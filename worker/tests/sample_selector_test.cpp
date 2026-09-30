// The sampler (W2.6, rp/sample_selector.hpp): the canary rotation, the random
// half's draw from a connector's pool, what the result records, and
// choose_sample over a connector that isn't Veeam. Failure paths first. The
// choices are the 2026-09-30 W2.6 entry in docs/decisions.md.

#include "target_guard_lab.hpp"

#include "../src/text_util.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/sample_rng.hpp>
#include <rp/sample_selector.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace connector = rp::connector;
namespace lab = rp::test::target_guard_lab;
using nlohmann::json;
using rp::sampling::CanaryCursor;
using rp::sampling::CanaryManifest;
using rp::sampling::SamplePlan;
using rp::sampling::SampleSelector;
using rp::sampling::Selection;

constexpr std::string_view kRunId = "run-0001";
// A source outside the restore targets and the canary locations. Made up.
const std::string kCarol = "carol@RestoreProofLab.onmicrosoft.com";

const CanaryManifest& lab_manifest()
{
    static const CanaryManifest manifest = rp::sampling::load_canary_manifest(
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json");
    return manifest;
}

const connector::RestoreTargets& targets()
{
    static const connector::RestoreTargets t =
        connector::RestoreTargets::from_config(lab::lab_config());
    return t;
}

std::string two_digits(int n)
{
    return (n < 10 ? "0" : "") + std::to_string(n);
}

connector::MailSelector mail_candidate(int n, const std::string& folder = "Archive")
{
    return {kCarol, folder, "real mail " + two_digits(n), "2026-09-20T10:00:" + two_digits(n % 60) + "Z"};
}

connector::SharePointCandidate sp_candidate(int n, const std::string& folder = "/Projects")
{
    connector::SharePointSelector s = lab::sharepoint_source(n);
    s.folder_path = folder;
    s.name = "report-" + two_digits(n) + ".pdf";
    return {s, 1000 + n};
}

connector::OneDriveCandidate od_candidate(int n, const std::string& folder = "/Projects")
{
    return {{kCarol, folder, "notes-" + two_digits(n) + ".txt"}, 500 + n};
}

Selection select(const SamplePlan& plan, const connector::CandidatePool& pool = {},
                 const CanaryCursor& cursor = {}, std::string_view run_id = kRunId,
                 const CanaryManifest& manifest = lab_manifest())
{
    return SampleSelector::select(plan, manifest, cursor, targets(), pool, run_id);
}

// What a call threw: its kind and message.
struct Thrown {
    std::string kind = "none";
    std::string what;
};

Thrown thrown_by(const std::function<void()>& call)
{
    try {
        call();
    } catch (const rp::sampling::ManifestError& e) {
        return {"ManifestError", e.what()};
    } catch (const connector::NotImplementedError& e) {
        return {"NotImplementedError", e.what()};
    } catch (const std::invalid_argument& e) {
        return {"invalid_argument", e.what()};
    } catch (const std::logic_error& e) {
        return {"logic_error", e.what()};
    } catch (const std::exception& e) {
        return {"other", e.what()};
    }
    return {};
}

std::vector<std::string> ids_from(const std::vector<std::string>& all, std::size_t start, int count)
{
    std::vector<std::string> out;
    for (int j = 0; j < count; ++j) {
        out.push_back(all[(start + static_cast<std::size_t>(j)) % all.size()]);
    }
    return out;
}

std::vector<std::string> mail_ids(const CanaryManifest& manifest)
{
    std::vector<std::string> out;
    for (const auto& mail : manifest.mail) {
        out.push_back(mail.id);
    }
    return out;
}

// The lab manifest with only its first `m` mails.
CanaryManifest with_mails(std::size_t m)
{
    CanaryManifest manifest = lab_manifest();
    manifest.mail.resize(m);
    return manifest;
}

// Everything a selection chose, for comparing two of them.
json selectors_json(const Selection& s)
{
    json out = {{"mail", json::array()}, {"sharepoint", json::array()}, {"onedrive", json::array()}};
    for (const auto& m : s.mail) {
        out["mail"].push_back({m.mailbox, m.folder, m.subject, m.received_at});
    }
    for (const auto& p : s.sharepoint) {
        out["sharepoint"].push_back({p.site_id, p.drive_id, p.folder_path, p.name, p.list_id, p.size});
    }
    for (const auto& o : s.onedrive) {
        out["onedrive"].push_back({o.user, o.folder_path, o.name, o.size});
    }
    return out;
}

json everything(const Selection& s)
{
    return {{"selectors", selectors_json(s)}, {"record", rp::sampling::to_json(s.record)}};
}

// A connector that isn't Veeam: it keeps each query and answers with `pool`.
class SamplingConnector : public connector::IConnector {
public:
    connector::ConnectorInfo describe() const override { return {"fake", "1"}; }

    std::vector<connector::RestorePoint> list_restore_points(const std::string&) override
    {
        return {};
    }

    connector::RestoreResult restore_sample(const connector::RestoreSpec&) override
    {
        throw std::logic_error("the sampler never restores");
    }

    connector::CandidatePool list_candidates(const connector::CandidateQuery& query) override
    {
        queries.push_back(query);
        return pool;
    }

    connector::CandidatePool pool;
    std::vector<connector::CandidateQuery> queries;
};

// A connector without list_candidates: IConnector's default.
class BareConnector : public connector::IConnector {
public:
    connector::ConnectorInfo describe() const override { return {"bare", "1"}; }
    std::vector<connector::RestorePoint> list_restore_points(const std::string&) override
    {
        return {};
    }
    connector::RestoreResult restore_sample(const connector::RestoreSpec&) override { return {}; }
};

connector::RestorePoint lab_point()
{
    connector::RestorePoint point;
    point.id = "repository-and-point";
    point.backup_time = "2026-09-29T22:00:45.6603083Z";
    point.has_mail = point.has_sharepoint = point.has_onedrive = true;
    return point;
}

Selection choose(connector::IConnector& c, const SamplePlan& plan,
                 const std::string& tenant = lab_manifest().tenant_id,
                 std::string_view run_id = kRunId, const CanaryCursor& cursor = {},
                 const connector::CandidateLimits& limits = {})
{
    return rp::sampling::choose_sample(c, "RestoreProofLab.onmicrosoft.com", lab_point(), targets(),
                                       tenant, plan, lab_manifest(), cursor, run_id, limits);
}

} // namespace

// 1. Inputs out of range.
TEST_CASE("select refuses a bad run ID, a size outside 0..100 or a cursor out of range",
          "[sample-selector]")
{
    struct Row {
        SamplePlan plan;
        CanaryCursor cursor;
        std::string run_id;
        bool no_sharepoint;
        std::string message;
    };
    const Row row = GENERATE_COPY(values<Row>({
        {{-1, 5, 5}, {}, "run-0001", false, "sampler: the mail sample size must be from 0 to 100"},
        {{5, 101, 5}, {}, "run-0001", false, "sampler: the sharepoint sample size must be from 0 to 100"},
        {{5, 5, -1}, {}, "run-0001", false, "sampler: the onedrive sample size must be from 0 to 100"},
        {{5, 5, 5}, {20, 0, 0}, "run-0001", false,
         "sampler: the mail cursor must be below 20, the manifest's mail canaries"},
        {{5, 5, 5}, {0, 0, 10}, "run-0001", false,
         "sampler: the onedrive cursor must be below 10, the manifest's onedrive canaries"},
        {{5, 5, 5}, {0, 1, 0}, "run-0001", true,
         "sampler: the sharepoint cursor must be 0: the manifest has no sharepoint canaries"},
        {{5, 5, 5}, {}, "", false,
         "sampler: the run ID must be 1 to 128 characters of A-Z, a-z, 0-9, '.', '_', ':' and '-'"},
        {{5, 5, 5}, {}, "run 0001", false,
         "sampler: the run ID must be 1 to 128 characters of A-Z, a-z, 0-9, '.', '_', ':' and '-'"},
    }));
    CAPTURE(row.message);
    CanaryManifest manifest = lab_manifest();
    if (row.no_sharepoint) {
        manifest.sharepoint.clear();
    }
    const Thrown thrown =
        thrown_by([&] { select(row.plan, {}, row.cursor, row.run_id, manifest); });
    CHECK(thrown.kind == "invalid_argument");
    CHECK(thrown.what == row.message);

    // choose_sample checks the same before it asks the connector anything.
    SamplingConnector c;
    const Thrown chosen = thrown_by([&] {
        rp::sampling::choose_sample(c, "client", lab_point(), targets(), manifest.tenant_id,
                                    row.plan, manifest, row.cursor, row.run_id);
    });
    CHECK(chosen.kind == "invalid_argument");
    CHECK(chosen.what == row.message);
    CHECK(c.queries.empty());
}

// 2. A manifest (built in code, or loaded for other targets) with a canary in a restore target.
TEST_CASE("select refuses a manifest with a canary in a restore target", "[sample-selector]")
{
    struct Row {
        std::string what;
        std::function<void(CanaryManifest&)> edit;
        std::string message;
    };
    const Row row = GENERATE(values<Row>({
        {"the restoretest mailbox",
         [](CanaryManifest& m) { m.mail[2].mailbox = "RESTORETEST@RestoreProofLab.onmicrosoft.com"; },
         "canary manifest: /entries/2/location/mailbox: is a restore target (a restoretest mailbox)"},
        {"the RestoreTarget library",
         [](CanaryManifest& m) { m.sharepoint[3].drive_id = targets().library_id(); },
         "canary manifest: /entries/23/location/drive_id: is a restore target (the library "
         "test_library_id names)"},
        {"the RestoreTarget library, another case",
         [](CanaryManifest& m) { m.sharepoint[0].drive_id = rp::ascii_lower(targets().library_id()); },
         "canary manifest: /entries/20/location/drive_id: is a restore target (the library "
         "test_library_id names)"},
        {"a RestoreTarget folder",
         [](CanaryManifest& m) { m.onedrive[0].folder_path = "/RestoreTarget"; },
         "canary manifest: /entries/30/location/folder_path: is in a restore target (a "
         "RestoreTarget folder)"},
        {"a restoretarget folder's subfolder",
         [](CanaryManifest& m) { m.onedrive[9].folder_path = "//./restoretarget/2026"; },
         "canary manifest: /entries/39/location/folder_path: is in a restore target (a "
         "RestoreTarget folder)"},
        {"a path with ..",
         [](CanaryManifest& m) { m.onedrive[1].folder_path = "/RestoreTest/../RestoreTarget"; },
         "canary manifest: /entries/31/location/folder_path: must start with \"/\" and have no "
         "\"..\" segment"},
    }));
    CAPTURE(row.what);
    CanaryManifest manifest = lab_manifest();
    row.edit(manifest);
    // Whatever the plan: the manifest is wrong.
    const Thrown thrown = thrown_by([&] { select({1, 0, 0}, {}, {}, kRunId, manifest); });
    CHECK(thrown.kind == "ManifestError");
    CHECK(thrown.what == row.message);
}

// 3. A pool holding what list_candidates must never offer: all of it is refused.
TEST_CASE("select refuses a pool with a restore target, a canary or a canary location",
          "[sample-selector]")
{
    struct Row {
        std::string what;
        std::function<void(connector::CandidatePool&)> edit;
        std::string message;
        std::function<void(CanaryManifest&)> edit_manifest = [](CanaryManifest&) {};
    };
    const auto offered = [](std::string_view kind, std::string_view why) {
        return "sampler: the connector offered " + std::string{kind} + " candidate 1, which is " +
               std::string{why} + "; nothing was sampled";
    };
    const Row row = GENERATE_COPY(values<Row>({
        // Mail.
        {"a restoretest mailbox", [](auto& p) { p.mail[1].mailbox = "restoretest@RestoreProofLab.onmicrosoft.com"; },
         offered("mail", "from a restore target (a restoretest mailbox)")},
        {"a canary's Sent Items copy", [](auto& p) { p.mail[1].subject = "rp-canary-0003"; },
         offered("mail", "a canary (its subject starts with rp-canary-)")},
        {"a subject with the canary prefix", [](auto& p) { p.mail[1].subject = "RP-Canary-weekly"; },
         offered("mail", "a canary (its subject starts with rp-canary-)")},
        {"a canary's subject in another case", [](auto& p) { p.mail[1].subject = "QUARTERLY figures"; },
         offered("mail", "a canary (its subject is a canary's)"),
         [](CanaryManifest& m) { m.mail[4].subject = "Quarterly Figures"; }},
        {"no mailbox", [](auto& p) { p.mail[1].mailbox.clear(); },
         offered("mail", "incomplete (no mailbox, folder, subject or received time)")},
        {"no folder", [](auto& p) { p.mail[1].folder.clear(); },
         offered("mail", "incomplete (no mailbox, folder, subject or received time)")},
        {"no subject", [](auto& p) { p.mail[1].subject.clear(); },
         offered("mail", "incomplete (no mailbox, folder, subject or received time)")},
        {"no received time", [](auto& p) { p.mail[1].received_at.clear(); },
         offered("mail", "incomplete (no mailbox, folder, subject or received time)")},
        // SharePoint.
        {"the RestoreTarget library", [](auto& p) { p.sharepoint[1].selector.drive_id = targets().library_id(); },
         offered("sharepoint", "from a restore target (the library test_library_id names)")},
        {"no drive ID", [](auto& p) { p.sharepoint[1].selector.drive_id.clear(); },
         offered("sharepoint", "incomplete (no site, drive or file name)")},
        {"no site", [](auto& p) { p.sharepoint[1].selector.site_id.clear(); },
         offered("sharepoint", "incomplete (no site, drive or file name)")},
        {"no file name", [](auto& p) { p.sharepoint[1].selector.name.clear(); },
         offered("sharepoint", "incomplete (no site, drive or file name)")},
        {"a list ID that isn't a GUID", [](auto& p) { p.sharepoint[1].selector.list_id = "Documents"; },
         offered("sharepoint", "from a library whose list ID isn't a GUID")},
        {"the canary library",
         [](auto& p) { p.sharepoint[1].selector.list_id = rp::ascii_lower(lab_manifest().sharepoint[0].list_id); },
         offered("sharepoint", "from a canary library")},
        {"a folder path with ..", [](auto& p) { p.sharepoint[1].selector.folder_path = "/Projects/../x"; },
         offered("sharepoint", "in a folder path with a \"..\" segment")},
        {"a canary name", [](auto& p) { p.sharepoint[1].selector.name = "RP-CANARY-06.PDF"; },
         offered("sharepoint", "a canary (its name starts with rp-canary-)")},
        {"a canary's name in another case", [](auto& p) { p.sharepoint[1].selector.name = "budget.XLSX"; },
         offered("sharepoint", "a canary (its name is a canary's)"),
         [](CanaryManifest& m) { m.sharepoint[2].name = "Budget.xlsx"; }},
        // OneDrive.
        {"a RestoreTarget folder", [](auto& p) { p.onedrive[1].selector.folder_path = "/RestoreTarget"; },
         offered("onedrive", "in a restore target (a RestoreTarget folder)")},
        {"a restoretarget subfolder", [](auto& p) { p.onedrive[1].selector.folder_path = "/./restoretarget/x"; },
         offered("onedrive", "in a restore target (a RestoreTarget folder)")},
        {"a RestoreTest folder", [](auto& p) { p.onedrive[1].selector.folder_path = "/RestoreTest"; },
         offered("onedrive", "in a canary location (a RestoreTest folder)")},
        {"a restoretest subfolder", [](auto& p) { p.onedrive[1].selector.folder_path = "//restoretest/old"; },
         offered("onedrive", "in a canary location (a RestoreTest folder)")},
        {"a folder path with ..", [](auto& p) { p.onedrive[1].selector.folder_path = "/Projects/.."; },
         offered("onedrive", "in a folder path with a \"..\" segment")},
        {"no owner", [](auto& p) { p.onedrive[1].selector.user.clear(); },
         offered("onedrive", "incomplete (no owner or file name)")},
        {"no file name", [](auto& p) { p.onedrive[1].selector.name.clear(); },
         offered("onedrive", "incomplete (no owner or file name)")},
        {"a canary name", [](auto& p) { p.onedrive[1].selector.name = "rp-canary-16.pdf"; },
         offered("onedrive", "a canary (its name starts with rp-canary-)")},
        {"a canary's name in another case", [](auto& p) { p.onedrive[1].selector.name = "PLAN.docx"; },
         offered("onedrive", "a canary (its name is a canary's)"),
         [](CanaryManifest& m) { m.onedrive[5].name = "plan.DOCX"; }},
    }));
    CAPTURE(row.what);
    connector::CandidatePool pool;
    pool.mail = {mail_candidate(0), mail_candidate(1)};
    pool.sharepoint = {sp_candidate(0), sp_candidate(1)};
    pool.onedrive = {od_candidate(0), od_candidate(1)};
    REQUIRE_NOTHROW(select({5, 5, 5}, pool));
    row.edit(pool);
    CanaryManifest manifest = lab_manifest();
    row.edit_manifest(manifest);
    // Even for a type whose random half is 0: the connector has a bug.
    const Thrown thrown = thrown_by([&] { select({1, 1, 1}, pool, {}, kRunId, manifest); });
    CHECK(thrown.kind == "logic_error");
    CHECK(thrown.what == row.message);
}

// 4. The halves: c = min(ceil(N/2), M) canaries, floor(N/2) random items.
TEST_CASE("each type's sample is ceil(N/2) canaries, at most M, and floor(N/2) random items",
          "[sample-selector]")
{
    const auto [m, n, c, r] = GENERATE(table<std::size_t, int, int, int>({
        {20, 0, 0, 0},   {20, 1, 1, 0},   {20, 2, 1, 1},    {20, 5, 3, 2},
        {20, 21, 11, 10}, {20, 41, 20, 20}, {20, 100, 20, 50},
        {10, 0, 0, 0},   {10, 1, 1, 0},   {10, 2, 1, 1},    {10, 5, 3, 2},
        {10, 21, 10, 10}, {10, 41, 10, 20}, {10, 100, 10, 50},
    }));
    CAPTURE(m, n);
    connector::CandidatePool pool;
    for (int i = 0; i < 60; ++i) {
        pool.mail.push_back(mail_candidate(i));
    }
    const Selection s = select({n, 0, 0}, pool, {}, kRunId, with_mails(m));
    CHECK(s.record.mail.requested == n);
    CHECK(s.record.mail.canary_wanted == c);
    CHECK(s.record.mail.canary_ids.size() == static_cast<std::size_t>(c));
    CHECK(s.record.mail.random_wanted == r);
    CHECK(s.record.mail.random_taken == r);
    CHECK(s.record.mail.random_keys.size() == static_cast<std::size_t>(r));
    CHECK(s.record.mail.pool_size == 60);
    REQUIRE(s.mail.size() == static_cast<std::size_t>(c + r));
    // Canaries first, then the random items.
    for (int i = 0; i < c; ++i) {
        CHECK(s.mail[i].subject.starts_with("RP-CANARY-"));
    }
    for (int i = c; i < c + r; ++i) {
        CHECK(s.mail[i].mailbox == kCarol);
    }
    // The other types asked for nothing.
    CHECK(s.sharepoint.empty());
    CHECK(s.onedrive.empty());
    CHECK(s.record.sharepoint.canary_wanted == 0);
}

// 5. The rotation's window and the next cursor.
TEST_CASE("canaries are taken from the cursor on, and the next cursor follows the window",
          "[sample-selector]")
{
    const std::size_t m = GENERATE(10u, 20u);
    const int n = GENERATE(1, 2, 3, 5, 10, 19, 20, 21, 40, 100);
    const std::uint32_t cursor = GENERATE_COPY(0u, 7u, static_cast<std::uint32_t>(m - 1));
    CAPTURE(m, n, cursor);
    const CanaryManifest manifest = with_mails(m);
    const Selection s = select({n, 0, 0}, {}, {cursor, 0, 0}, kRunId, manifest);
    const int c = std::min<int>((n + 1) / 2, static_cast<int>(m));
    CHECK(s.record.mail.cursor == cursor);
    CHECK(s.record.mail.cursor_next == (cursor + c) % m);
    CHECK(s.record.mail.canary_ids == ids_from(mail_ids(manifest), cursor, c));
    REQUIRE(s.mail.size() == static_cast<std::size_t>(c));
    for (int j = 0; j < c; ++j) {
        const auto& canary = manifest.mail[(cursor + j) % m];
        CHECK(s.mail[j].mailbox == canary.mailbox);
        CHECK(s.mail[j].folder == canary.folder);
        CHECK(s.mail[j].subject == canary.subject);
        CHECK(s.mail[j].received_at == canary.received_at);
    }
}

TEST_CASE("the rotation wraps: two examples written out", "[sample-selector]")
{
    const Selection sp = select({0, 5, 0}, {}, {0, 7, 0});
    CHECK(sp.record.sharepoint.canary_ids ==
          std::vector<std::string>{"rp-canary-08.xlsx", "rp-canary-09.txt", "rp-canary-10.png"});
    CHECK(sp.record.sharepoint.cursor_next == 0);
    CHECK(sp.sharepoint[0].size == -1); // office-v1
    CHECK(sp.sharepoint[1].size == lab_manifest().sharepoint[8].stored_size);

    const Selection mail = select({40, 0, 0}, {}, {7, 0, 0});
    REQUIRE(mail.record.mail.canary_ids.size() == 20);
    CHECK(mail.record.mail.canary_ids.front() == "RP-CANARY-0008");
    CHECK(mail.record.mail.canary_ids[12] == "RP-CANARY-0020");
    CHECK(mail.record.mail.canary_ids[13] == "RP-CANARY-0001");
    CHECK(mail.record.mail.canary_ids.back() == "RP-CANARY-0007");
    CHECK(mail.record.mail.cursor_next == 7);
}

// 6. Coverage: every canary within ceil(M/c) <= ceil(20/(N/2)) runs, from any start.
TEST_CASE("every canary of a type is taken within ceil(M/c) <= ceil(20/(N/2)) runs",
          "[sample-selector]")
{
    for (const std::size_t m : {std::size_t{10}, std::size_t{20}}) {
        const CanaryManifest manifest = with_mails(m);
        for (int n = 1; n <= 100; ++n) {
            const std::size_t c = std::min<std::size_t>((n + 1) / 2, m);
            const std::size_t runs = (m + c - 1) / c;
            // ceil(20 / (N/2)) = ceil(40 / N).
            REQUIRE(runs <= static_cast<std::size_t>((40 + n - 1) / n));
            for (std::uint32_t start = 0; start < m; ++start) {
                CAPTURE(m, n, start);
                std::set<std::string> covered;
                CanaryCursor cursor{start, 0, 0};
                for (std::size_t run = 0; run < runs; ++run) {
                    const Selection s = select({n, 0, 0}, {}, cursor, kRunId, manifest);
                    covered.insert(s.record.mail.canary_ids.begin(), s.record.mail.canary_ids.end());
                    cursor.mail = s.record.mail.cursor_next;
                }
                REQUIRE(covered.size() == m);
            }
        }
    }
}

// 7. Same names: the skip uses up its draw.
TEST_CASE("a random pick whose name is already taken is skipped and its draw used up",
          "[sample-selector]")
{
    connector::CandidatePool pool;
    pool.sharepoint = {sp_candidate(1, "/b"), sp_candidate(2, "/c"), sp_candidate(3, "/a")};
    pool.sharepoint[0].selector.name = "report.DOCX";
    pool.sharepoint[1].selector.name = "Other.pdf";
    pool.sharepoint[2].selector.name = "Report.docx";
    // Sorted: /a Report.docx (0), /b report.DOCX (1), /c Other.pdf (2). A run
    // ID whose draw puts the two same-named files first, found by search.
    std::string run_id;
    std::vector<std::size_t> order;
    for (int i = 0; order.empty() || order[0] + order[1] != 1; ++i) {
        run_id = "same-name-" + std::to_string(i);
        rp::sampling::SampleRng rng(rp::sampling::stream_seed(
            rp::sampling::seed_from_run_id(run_id), connector::ItemKind::sharepoint,
            rp::sampling::Stream::items));
        rp::sampling::Shuffle shuffle(rng, 3);
        order = {*shuffle.next(), *shuffle.next(), *shuffle.next()};
    }
    CAPTURE(run_id, order);
    REQUIRE(order[2] == 2);

    const Selection s = select({0, 4, 0}, pool, {}, run_id);
    const std::string first = order[0] == 0 ? "/a" : "/b";
    REQUIRE(s.sharepoint.size() == 4);
    CHECK(s.sharepoint[2].folder_path == first);
    CHECK(s.sharepoint[3].name == "Other.pdf");
    CHECK(s.record.sharepoint.random_taken == 2);
    CHECK(s.record.sharepoint.random_keys.size() == 2);
    CHECK(s.record.sharepoint.random_keys[1].back() == "Other.pdf");
}

TEST_CASE("two mails of one subject, but for case, are never both taken", "[sample-selector]")
{
    connector::CandidatePool pool;
    pool.mail = {mail_candidate(1, "Archive"), mail_candidate(2, "Projects")};
    pool.mail[0].subject = "Hello";
    pool.mail[1].subject = "HELLO";
    for (const std::string run_id : {"run-0001", "run-0002", "run-0003", "run-0004"}) {
        CAPTURE(run_id);
        const Selection s = select({4, 0, 0}, pool, {}, run_id);
        CHECK(s.record.mail.random_wanted == 2);
        CHECK(s.record.mail.random_taken == 1);
        CHECK(s.record.mail.pool_size == 2);
        REQUIRE(s.mail.size() == 3);
        CHECK(rp::ascii_lower(s.mail[2].subject) == "hello");
    }
}

// 8. A shortfall is recorded, not filled.
TEST_CASE("a pool smaller than the random half: all of it taken, the shortfall recorded",
          "[sample-selector]")
{
    const int size = GENERATE(0, 1, 4);
    CAPTURE(size);
    connector::CandidatePool pool;
    for (int i = 0; i < size; ++i) {
        pool.onedrive.push_back(od_candidate(i));
    }
    pool.onedrive_browse.containers_eligible = 4;
    pool.onedrive_browse.containers_listed = {kCarol};
    pool.onedrive_browse.folders_listed = 3;
    pool.onedrive_browse.short_of_containers = true;

    const Selection s = select({0, 0, 10}, pool);
    const rp::sampling::KindRecord& k = s.record.onedrive;
    CHECK(k.canary_wanted == 5);
    CHECK(k.random_wanted == 5);
    CHECK(k.random_taken == size);
    CHECK(k.pool_size == static_cast<std::size_t>(size));
    CHECK(k.random_keys.size() == static_cast<std::size_t>(size));
    CHECK(k.browse.containers_eligible == 4);
    CHECK(k.browse.containers_listed == std::vector<std::string>{kCarol});
    CHECK(k.browse.folders_listed == 3);
    CHECK(k.browse.short_of_containers);
    // No canary is moved to the random half.
    CHECK(s.onedrive.size() == static_cast<std::size_t>(5 + size));
    if (size == 0) {
        CHECK(k.pool_sha256 == rp::sha256_hex("[]"));
    }
}

// 9. Determinism.
TEST_CASE("the same inputs give the same selection, whatever the pool's order and repeats",
          "[sample-selector]")
{
    connector::CandidatePool pool;
    for (int i = 0; i < 50; ++i) {
        pool.mail.push_back(mail_candidate(i));
        pool.sharepoint.push_back(sp_candidate(i));
        pool.onedrive.push_back(od_candidate(i));
    }
    const SamplePlan plan{10, 10, 10};
    const json once = everything(select(plan, pool));
    CHECK(everything(select(plan, pool)) == once);

    connector::CandidatePool reversed = pool;
    std::reverse(reversed.mail.begin(), reversed.mail.end());
    std::reverse(reversed.sharepoint.begin(), reversed.sharepoint.end());
    std::reverse(reversed.onedrive.begin(), reversed.onedrive.end());
    CHECK(everything(select(plan, reversed)) == once);

    connector::CandidatePool twice = pool;
    twice.mail.insert(twice.mail.end(), pool.mail.begin(), pool.mail.end());
    twice.sharepoint.insert(twice.sharepoint.end(), pool.sharepoint.begin(), pool.sharepoint.end());
    twice.onedrive.insert(twice.onedrive.end(), pool.onedrive.begin(), pool.onedrive.end());
    const Selection deduplicated = select(plan, twice);
    CHECK(everything(deduplicated) == once);
    CHECK(deduplicated.record.mail.pool_size == 50);

    // Another run ID, other picks; the canaries don't move.
    const Selection other = select(plan, pool, {}, "run-0002");
    CHECK(other.record.mail.canary_ids == select(plan, pool).record.mail.canary_ids);
    CHECK(other.record.mail.random_keys != select(plan, pool).record.mail.random_keys);
    CHECK(other.record.sharepoint.random_keys != select(plan, pool).record.sharepoint.random_keys);
    CHECK(other.record.onedrive.random_keys != select(plan, pool).record.onedrive.random_keys);
    CHECK(other.record.mail.pool_sha256 == select(plan, pool).record.mail.pool_sha256);
}

TEST_CASE("a type's picks don't move when another type's size changes", "[sample-selector]")
{
    connector::CandidatePool pool;
    for (int i = 0; i < 50; ++i) {
        pool.mail.push_back(mail_candidate(i));
        pool.onedrive.push_back(od_candidate(i));
    }
    CHECK(select({10, 0, 10}, pool).record.onedrive.random_keys ==
          select({2, 0, 10}, pool).record.onedrive.random_keys);
}

TEST_CASE("a random file's size is unchecked: -1, whatever the candidate held", "[sample-selector]")
{
    connector::CandidatePool pool;
    pool.sharepoint = {sp_candidate(1)};
    pool.sharepoint[0].selector.size = 1001;
    pool.onedrive = {od_candidate(1)};
    pool.onedrive[0].selector.size = 501;
    const Selection s = select({0, 2, 2}, pool);
    REQUIRE(s.sharepoint.size() == 2);
    REQUIRE(s.onedrive.size() == 2);
    CHECK(s.sharepoint[1].size == -1);
    CHECK(s.onedrive[1].size == -1);
    CHECK(s.sharepoint[1].drive_id == pool.sharepoint[0].selector.drive_id);
}

// 10. The result's "sample" object.
TEST_CASE("to_json writes the result's sample object", "[sample-selector]")
{
    connector::CandidatePool pool;
    pool.mail = {mail_candidate(7)};
    pool.mail_browse = {.containers_eligible = 4,
                        .containers_listed = {kCarol},
                        .containers_unresolved = 1,
                        .folders_listed = 3,
                        .short_of_containers = true};
    const Selection s = select({2, 1, 0}, pool, {0, 9, 0});
    const json key = {rp::ascii_lower(kCarol), "Archive", "real mail 07", "2026-09-20T10:00:07Z"};
    const std::string empty_pool = rp::sha256_hex("[]");
    const json expected = {
        {"algorithm", "sample-v1"},
        {"run_id", "run-0001"},
        {"seed", "8b26e36a"},
        {"manifest_sha256", lab_manifest().sha256},
        {"mail",
         {{"requested", 2},
          {"canary", {{"cursor", 0}, {"cursor_next", 1}, {"wanted", 1}, {"ids", {"RP-CANARY-0001"}}}},
          {"random",
           {{"wanted", 1},
            {"taken", 1},
            {"pool_size", 1},
            {"pool_sha256", rp::sha256_hex(json::array({key}).dump())},
            {"keys", json::array({key})},
            {"containers_eligible", 4},
            {"containers_listed", {kCarol}},
            {"containers_unresolved", 1},
            {"folders_listed", 3},
            {"short_of_containers", true}}}}},
        {"sharepoint",
         {{"requested", 1},
          {"canary", {{"cursor", 9}, {"cursor_next", 0}, {"wanted", 1}, {"ids", {"rp-canary-10.png"}}}},
          {"random",
           {{"wanted", 0},
            {"taken", 0},
            {"pool_size", 0},
            {"pool_sha256", empty_pool},
            {"keys", json::array()},
            {"containers_eligible", 0},
            {"containers_listed", json::array()},
            {"containers_unresolved", 0},
            {"folders_listed", 0},
            {"short_of_containers", false}}}}},
        {"onedrive",
         {{"requested", 0},
          {"canary", {{"cursor", 0}, {"cursor_next", 0}, {"wanted", 0}, {"ids", json::array()}}},
          {"random",
           {{"wanted", 0},
            {"taken", 0},
            {"pool_size", 0},
            {"pool_sha256", empty_pool},
            {"keys", json::array()},
            {"containers_eligible", 0},
            {"containers_listed", json::array()},
            {"containers_unresolved", 0},
            {"folders_listed", 0},
            {"short_of_containers", false}}}}},
    };
    CHECK(rp::sampling::to_json(s.record) == expected);
}

TEST_CASE("SamplePlan::from_config takes sample_mail, sample_sp and sample_od", "[sample-selector]")
{
    rp::Config config;
    config.sample_mail = 7;
    config.sample_sp = 0;
    config.sample_od = 100;
    const SamplePlan plan = SamplePlan::from_config(config);
    CHECK(plan.mail == 7);
    CHECK(plan.sharepoint == 0);
    CHECK(plan.onedrive == 100);
    const SamplePlan defaults = SamplePlan::from_config(rp::Config{});
    CHECK(defaults.mail == 5);
    CHECK(defaults.sharepoint == 5);
    CHECK(defaults.onedrive == 5);
}

// 11. choose_sample over a connector that isn't Veeam.
TEST_CASE("choose_sample refuses a manifest from another tenant before any listing",
          "[sample-selector]")
{
    SamplingConnector c;
    const Thrown thrown =
        thrown_by([&] { choose(c, {5, 5, 5}, "00000000-0000-4000-8000-000000000001"); });
    CHECK(thrown.kind == "ManifestError");
    CHECK(thrown.what == "canary manifest: /tenant_id: isn't the client's tenant (graph_tenant_id)");
    CHECK(c.queries.empty());
}

TEST_CASE("choose_sample passes a connector's NotImplementedError out", "[sample-selector]")
{
    BareConnector c;
    const Thrown thrown = thrown_by([&] { choose(c, {5, 5, 5}); });
    CHECK(thrown.kind == "NotImplementedError");
    CHECK(thrown.what == "bare: listing candidates isn't implemented");
}

TEST_CASE("choose_sample doesn't list candidates when every random half is 0; the tenant ID in any case",
          "[sample-selector]")
{
    BareConnector bare; // would throw if asked
    std::string tenant = lab_manifest().tenant_id;
    std::transform(tenant.begin(), tenant.end(), tenant.begin(),
                   [](char ch) { return ch >= 'a' && ch <= 'z' ? static_cast<char>(ch - 32) : ch; });
    REQUIRE(tenant != lab_manifest().tenant_id);
    const Selection s = choose(bare, {1, 1, 0}, tenant); // the tenant ID in upper case
    CHECK(s.mail.size() == 1);
    CHECK(s.sharepoint.size() == 1);
    CHECK(s.onedrive.empty());
    CHECK(s.record.mail.pool_sha256 == rp::sha256_hex("[]"));
}

TEST_CASE("choose_sample asks for the types with a random half, with the canaries excluded",
          "[sample-selector]")
{
    SamplingConnector c;
    c.pool.mail = {mail_candidate(1)};
    c.pool.onedrive = {od_candidate(1), od_candidate(2)};
    connector::CandidateLimits limits;
    limits.containers_wanted = 3;
    limits.containers_tried = 5;
    limits.folders_per_container = 1;
    limits.walk_depth = 4;
    limits.walk_calls = 9;
    limits.max_file_bytes = 1234;
    const Selection s = choose(c, {5, 1, 4}, lab_manifest().tenant_id, "run-0001", {3, 2, 1}, limits);

    REQUIRE(c.queries.size() == 1);
    const connector::CandidateQuery& q = c.queries.front();
    CHECK(q.client_ref == "RestoreProofLab.onmicrosoft.com");
    CHECK(q.restore_point.id == lab_point().id);
    CHECK(q.restore_point.backup_time == lab_point().backup_time);
    CHECK(q.targets.library_id() == targets().library_id());
    CHECK(q.targets.mailbox() == targets().mailbox());
    CHECK(q.mail);
    CHECK_FALSE(q.sharepoint);
    CHECK(q.onedrive);
    CHECK(q.seed == rp::sampling::seed_from_run_id("run-0001"));
    CHECK(q.seed == 0x8b26e36au);
    std::vector<std::string> subjects;
    for (const auto& mail : lab_manifest().mail) {
        subjects.push_back(mail.subject);
    }
    std::vector<std::string> sp_names;
    for (const auto& file : lab_manifest().sharepoint) {
        sp_names.push_back(file.name);
    }
    std::vector<std::string> od_names;
    for (const auto& file : lab_manifest().onedrive) {
        od_names.push_back(file.name);
    }
    CHECK(q.exclude.subjects == subjects);
    CHECK(q.exclude.sharepoint_names == sp_names);
    CHECK(q.exclude.onedrive_names == od_names);
    // Ten canaries, one library.
    CHECK(q.exclude.list_ids == std::vector<std::string>{lab_manifest().sharepoint[0].list_id});
    CHECK(q.limits.containers_wanted == 3);
    CHECK(q.limits.containers_tried == 5);
    CHECK(q.limits.folders_per_container == 1);
    CHECK(q.limits.walk_depth == 4);
    CHECK(q.limits.walk_calls == 9);
    CHECK(q.limits.max_file_bytes == 1234);

    // The pool it returned is what select drew from.
    REQUIRE(s.mail.size() == 4);
    CHECK(s.mail[3].mailbox == kCarol);
    CHECK(s.record.mail.cursor == 3);
    CHECK(s.record.mail.random_taken == 1);
    CHECK(s.sharepoint.size() == 1);
    CHECK(s.record.sharepoint.cursor == 2);
    CHECK(s.onedrive.size() == 4);
    CHECK(s.record.onedrive.random_taken == 2);
    CHECK(everything(s) ==
          everything(SampleSelector::select({5, 1, 4}, lab_manifest(), {3, 2, 1}, targets(), c.pool,
                                            "run-0001")));
}

// 12. What the sampler chose passes the restore-target guard (W2.7, layer 1).
TEST_CASE("a selection passes TargetGuard::check_spec", "[sample-selector]")
{
    connector::CandidatePool pool;
    for (int i = 0; i < 20; ++i) {
        pool.mail.push_back(mail_candidate(i));
        pool.sharepoint.push_back(sp_candidate(i));
        pool.onedrive.push_back(od_candidate(i));
    }
    const std::uint32_t start = GENERATE(0u, 5u, 9u);
    const int size = GENERATE(1, 5, 20, 100);
    CAPTURE(start, size);
    const Selection s = select({size, size, size}, pool, {start, start, start});
    lab::GuardLab guard_lab;
    const connector::RestoreSpec spec = lab::make_spec(s.mail, s.sharepoint, s.onedrive);
    CHECK(spec.item_count() == s.mail.size() + s.sharepoint.size() + s.onedrive.size());
    CHECK_NOTHROW(guard_lab.guard().check_spec(spec));
}
