// The expected set (W3.1, rp/expected_set.hpp): one expected record per
// sampled item, with its expected kind, built from the sampler's selection and
// the canary manifest. Failure paths first. The choices are the 2026-10-01
// W3.1 entry in docs/decisions.md.

#include "target_guard_lab.hpp"

#include "../src/office_files.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/sample_selector.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace connector = rp::connector;
namespace lab = rp::test::target_guard_lab;
namespace verification = rp::verification;
using connector::ItemKind;
using nlohmann::json;
using rp::sampling::CanaryCursor;
using rp::sampling::CanaryManifest;
using rp::sampling::SamplePlan;
using rp::sampling::Selection;
using verification::ExpectedItem;
using verification::ExpectedKind;
using verification::ExpectedSet;
using verification::ItemSource;

constexpr std::string_view kRunId = "run-0001";
// A source outside the restore targets and the canary locations. Made up.
const std::string kCarol = "carol@RestoreProofLab.onmicrosoft.com";

std::filesystem::path lab_manifest_path()
{
    return std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json";
}

const CanaryManifest& lab_manifest()
{
    static const CanaryManifest manifest = rp::sampling::load_canary_manifest(lab_manifest_path());
    return manifest;
}

// The manifest file's entries as JSON: the expected values are read from it,
// not spelled here.
const json& lab_entries()
{
    static const json entries = [] {
        std::ifstream file(lab_manifest_path(), std::ios::binary);
        return json::parse(file).at("entries");
    }();
    return entries;
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

connector::MailCandidate mail_candidate(int n, const std::string& sender = "Bob Test",
                                        const std::string& sent = "2026-09-20T09:59:00Z")
{
    return {{kCarol, "Archive", "real mail " + two_digits(n), "2026-09-20T10:00:" + two_digits(n) + "Z"},
            sender,
            sent};
}

connector::SharePointCandidate sp_candidate(int n, const std::string& name,
                                            std::int64_t size = 1000)
{
    connector::SharePointSelector s = lab::sharepoint_source(n);
    s.folder_path = "/Projects";
    s.name = name;
    return {s, size};
}

connector::OneDriveCandidate od_candidate(const std::string& name, std::int64_t size = 500)
{
    return {{kCarol, "/Projects", name}, size};
}

// Mails and files of every sort: a mail without a sender or a sent time, a
// pdf, an Office file, a file without an extension.
connector::CandidatePool mixed_pool()
{
    connector::CandidatePool pool;
    pool.mail = {mail_candidate(1), mail_candidate(2, ""), mail_candidate(3, "Dana", "")};
    pool.sharepoint = {sp_candidate(1, "report.pdf", 1234), sp_candidate(2, "Plan.DOCX", 15000),
                       sp_candidate(3, "README", 42)};
    pool.onedrive = {od_candidate("notes.txt", 77), od_candidate("deck.pptx", 9000)};
    return pool;
}

Selection select(const SamplePlan& plan, const connector::CandidatePool& pool = {},
                 const CanaryCursor& cursor = {})
{
    return rp::sampling::SampleSelector::select(plan, &lab_manifest(), cursor, targets(), pool,
                                                kRunId);
}

// A connector that isn't Veeam, answering list_candidates with `pool`.
class PoolConnector : public connector::IConnector {
public:
    explicit PoolConnector(connector::CandidatePool p) : pool(std::move(p)) {}

    connector::ConnectorInfo describe() const override { return {"fake", "1"}; }
    std::vector<connector::RestorePoint> list_restore_points(const std::string&) override
    {
        return {};
    }
    connector::RestoreResult restore_sample(const connector::RestoreSpec&) override
    {
        throw std::logic_error("the expected set never restores");
    }
    connector::CandidatePool list_candidates(const connector::CandidateQuery&) override
    {
        return pool;
    }

    connector::CandidatePool pool;
};

connector::RestorePoint lab_point()
{
    connector::RestorePoint point;
    point.id = "repository-and-point";
    point.backup_time = "2026-09-29T22:00:45.6603083Z";
    point.has_mail = point.has_sharepoint = point.has_onedrive = true;
    return point;
}

struct Thrown {
    std::string kind = "none";
    std::string what;
};

Thrown thrown_by(const std::function<void()>& call)
{
    try {
        call();
    } catch (const std::invalid_argument& e) {
        return {"invalid_argument", e.what()};
    } catch (const std::logic_error& e) {
        return {"logic_error", e.what()};
    } catch (const std::exception& e) {
        return {"other", e.what()};
    }
    return {};
}

std::size_t count_of(const ExpectedSet& set, ExpectedKind kind)
{
    std::size_t n = 0;
    for (const ExpectedItem& item : set.items) {
        n += item.expected_kind == kind ? 1 : 0;
    }
    return n;
}

// One consistent item of each sort: a SharePoint canary, a random mail, a
// random OneDrive file and a mail canary, at their indexes.
std::vector<ExpectedItem> consistent_items()
{
    ExpectedItem canary;
    canary.index = 0;
    canary.kind = ItemKind::sharepoint;
    canary.source = ItemSource::canary;
    canary.expected_kind = ExpectedKind::manifest;
    canary.canary_id = "rp-canary-01.pdf";
    canary.file = verification::ExpectedFile{"rp-canary-01.pdf", 925};
    canary.sha256 = std::string(64, 'b');
    canary.sha256_rule = "bytes";
    ExpectedItem mail;
    mail.index = 1;
    mail.kind = ItemKind::mail;
    mail.source = ItemSource::random;
    mail.expected_kind = ExpectedKind::fields;
    mail.random_key = {"carol@restoreprooflab.onmicrosoft.com", "Archive", "Lunch", "2026-09-20T10:00:00Z"};
    mail.mail = verification::ExpectedMail{"Lunch", std::nullopt, std::nullopt, std::nullopt,
                                           "2026-09-20T10:00:00Z", std::nullopt};
    ExpectedItem file;
    file.index = 2;
    file.kind = ItemKind::onedrive;
    file.source = ItemSource::random;
    file.expected_kind = ExpectedKind::metadata;
    file.random_key = {"carol@restoreprooflab.onmicrosoft.com", "/", "Plan.docx"};
    file.file = verification::ExpectedFile{"Plan.docx", std::nullopt};
    ExpectedItem mail_canary;
    mail_canary.index = 3;
    mail_canary.kind = ItemKind::mail;
    mail_canary.source = ItemSource::canary;
    mail_canary.expected_kind = ExpectedKind::manifest;
    mail_canary.canary_id = "RP-CANARY-0008";
    mail_canary.mail = verification::ExpectedMail{"RP-CANARY-0008", "admin@example.com", std::nullopt,
                                                  "2026-09-24T22:14:41Z", "2026-09-24T22:14:44Z",
                                                  "<id@example.com>"};
    mail_canary.sha256 = std::string(64, 'c');
    mail_canary.sha256_rule = "text-v1";
    return {canary, mail, file, mail_canary};
}

} // namespace

// 1. Refusals: nothing is built.
TEST_CASE("build_expected_set refuses a selection that isn't this manifest's or doesn't add up",
          "[expected-set]")
{
    struct Row {
        std::string what;
        std::function<void(Selection&, CanaryManifest&)> edit;
        std::string kind;
        std::string message;
    };
    const auto mismatch = [](std::string_view kind) {
        return "expected set: the " + std::string{kind} +
               " selectors don't match the canaries and random items recorded";
    };
    const Row row = GENERATE_COPY(values<Row>({
        {"a selection from another manifest",
         [](Selection&, CanaryManifest& m) { m.sha256 = std::string(64, '0'); }, "invalid_argument",
         "expected set: the selection wasn't made from this manifest"},
        {"a mail selector more than recorded",
         [](Selection& s, CanaryManifest&) { s.mail.push_back(s.mail.back()); }, "invalid_argument",
         mismatch("mail")},
        {"a SharePoint random item taken but no selector",
         [](Selection& s, CanaryManifest&) { s.sharepoint.pop_back(); }, "invalid_argument",
         mismatch("sharepoint")},
        {"a OneDrive random candidate missing",
         [](Selection& s, CanaryManifest&) { s.onedrive_random.pop_back(); }, "invalid_argument",
         mismatch("onedrive")},
        {"a random key fewer than the random candidates",
         [](Selection& s, CanaryManifest&) { s.record.mail.random_keys.pop_back(); }, "invalid_argument",
         mismatch("mail")},
        {"more mail random items taken than recorded",
         [](Selection& s, CanaryManifest&) { ++s.record.mail.random_taken; }, "invalid_argument",
         mismatch("mail")},
        {"fewer SharePoint random items taken than recorded",
         [](Selection& s, CanaryManifest&) { --s.record.sharepoint.random_taken; }, "invalid_argument",
         mismatch("sharepoint")},
        {"more OneDrive canaries wanted than recorded",
         [](Selection& s, CanaryManifest&) { ++s.record.onedrive.canary_wanted; }, "invalid_argument",
         mismatch("onedrive")},
        {"a canary id more than selected",
         [](Selection& s, CanaryManifest&) { s.record.onedrive.canary_ids.push_back("rp-canary-20.png"); },
         "invalid_argument", mismatch("onedrive")},
        {"a mail canary the manifest hasn't",
         [](Selection& s, CanaryManifest&) { s.record.mail.canary_ids[1] = "RP-CANARY-9999"; },
         "logic_error", "expected set: canary 1 of mail isn't in the manifest"},
        {"a SharePoint canary that is a OneDrive canary",
         [](Selection& s, CanaryManifest&) { s.record.sharepoint.canary_ids[0] = "rp-canary-11.pdf"; },
         "logic_error", "expected set: canary 0 of sharepoint isn't in the manifest"},
        {"a canary selector that isn't its entry's",
         [](Selection& s, CanaryManifest&) { s.onedrive[1].folder_path = "/Elsewhere"; },
         "logic_error", "expected set: canary 1 of onedrive isn't the manifest's entry"},
        {"a random mail selector that differs from its candidate",
         [](Selection& s, CanaryManifest&) { s.mail[3].subject = "something else"; }, "logic_error",
         "expected set: random item 0 of mail isn't the candidate the sampler took"},
        {"a random SharePoint selector that differs from its candidate",
         [](Selection& s, CanaryManifest&) { s.sharepoint_random[1].selector.name = "other.pdf"; },
         "logic_error", "expected set: random item 1 of sharepoint isn't the candidate the sampler took"},
        {"a random mail key that isn't its selector's",
         [](Selection& s, CanaryManifest&) { s.record.mail.random_keys[1][2] = "something else"; },
         "logic_error", "expected set: random item 1 of mail isn't the candidate the sampler took"},
        {"a random SharePoint key that isn't its selector's",
         [](Selection& s, CanaryManifest&) { s.record.sharepoint.random_keys[0].back() = "other.pdf"; },
         "logic_error", "expected set: random item 0 of sharepoint isn't the candidate the sampler took"},
        {"a random OneDrive key that isn't its selector's",
         [](Selection& s, CanaryManifest&) { s.record.onedrive.random_keys[0][0] = "dana@example.com"; },
         "logic_error", "expected set: random item 0 of onedrive isn't the candidate the sampler took"},
        {"a random OneDrive selector whose size isn't unchecked",
         [](Selection& s, CanaryManifest&) { s.onedrive[2].size = 77; }, "logic_error",
         "expected set: random item 0 of onedrive isn't the candidate the sampler took"},
    }));
    CAPTURE(row.what);
    Selection s = select({6, 4, 3}, mixed_pool());
    REQUIRE(s.mail.size() == 6);
    REQUIRE(s.sharepoint.size() == 4);
    REQUIRE(s.onedrive.size() == 3);
    CanaryManifest manifest = lab_manifest();
    REQUIRE_NOTHROW(verification::build_expected_set(s, &manifest));
    row.edit(s, manifest);
    const Thrown thrown = thrown_by([&] { verification::build_expected_set(s, &manifest); });
    CHECK(thrown.kind == row.kind);
    CHECK(thrown.what == row.message);
}

// 2. to_json writes no item whose expected kind its fields don't back.
// W6.2: a selection made without canaries.
TEST_CASE("without a manifest every item is a random one's and the set says it had no canaries",
          "[expected-set][w6.2]")
{
    connector::CandidatePool pool;
    pool.mail = {mail_candidate(1), mail_candidate(2)};
    pool.sharepoint = {sp_candidate(1, "plan.pdf")};
    pool.onedrive = {od_candidate("notes.txt")};
    const Selection s = rp::sampling::SampleSelector::select({2, 1, 1}, nullptr, {}, targets(),
                                                             pool, kRunId);

    const ExpectedSet set = verification::build_expected_set(s, nullptr);

    CHECK_FALSE(set.canaries);
    CHECK(set.manifest_sha256.empty());
    CHECK(set.canaries_seeded_at.empty());
    REQUIRE(set.items.size() == 4);
    for (std::size_t i = 0; i < set.items.size(); ++i) {
        CAPTURE(i);
        CHECK(set.items[i].index == i);
        CHECK(set.items[i].source == ItemSource::random);
        CHECK(set.items[i].canary_id.empty());
        CHECK_FALSE(set.items[i].random_key.empty());
        CHECK(set.items[i].sha256.empty());
    }
    CHECK(set.items[0].expected_kind == ExpectedKind::fields);
    CHECK(set.items[1].expected_kind == ExpectedKind::fields);
    CHECK(set.items[2].expected_kind == ExpectedKind::metadata);
    CHECK(set.items[3].expected_kind == ExpectedKind::metadata);
    const json out = verification::to_json(set);
    CHECK_FALSE(out.contains("manifest_sha256"));
    CHECK(out.at("counts") == json{{"manifest", 0}, {"fields", 2}, {"metadata", 2}, {"backup_content", 0}});
    CHECK(out.at("items").size() == 4);
}

TEST_CASE("build_expected_set refuses a manifest it wasn't given, and one it was",
          "[expected-set][w6.2]")
{
    connector::CandidatePool pool;
    pool.mail = {mail_candidate(1)};
    const Selection with = select({1, 0, 0}, pool);
    const Selection without =
        rp::sampling::SampleSelector::select({1, 0, 0}, nullptr, {}, targets(), pool, kRunId);

    const Thrown missing = thrown_by([&] { verification::build_expected_set(with, nullptr); });
    CHECK(missing.kind == "invalid_argument");
    CHECK(missing.what ==
          "expected set: the selection was made from a manifest this call doesn't have");

    const Thrown extra =
        thrown_by([&] { verification::build_expected_set(without, &lab_manifest()); });
    CHECK(extra.kind == "invalid_argument");
    CHECK(extra.what == "expected set: the selection was made without canaries");
}

TEST_CASE("to_json refuses an item that claims more or other than it holds", "[expected-set]")
{
    struct Row {
        std::string what;
        std::function<void(std::vector<ExpectedItem>&)> edit;
        std::string message;
    };
    const auto item = [](int n, std::string_view why) {
        return "expected set: item " + std::to_string(n) + " " + std::string{why};
    };
    const std::string not_canary = "is manifest but not a canary with a hash and its rule";
    const std::string not_random =
        "is fields or metadata but not a random item of its type without a hash";
    using Items = std::vector<ExpectedItem>;
    const Row row = GENERATE_COPY(values<Row>({
        // The review's case: a kind never set reads as a canary's.
        {"a random file whose kind was never set",
         [](Items& items) {
             ExpectedItem forgot;
             forgot.index = 4;
             forgot.kind = ItemKind::onedrive;
             forgot.random_key = {"carol@restoreprooflab.onmicrosoft.com", "/", "a.pdf"};
             forgot.file = verification::ExpectedFile{"a.pdf", 12};
             items.push_back(forgot);
         },
         item(4, not_canary)},
        {"a manifest item without a hash", [](Items& i) { i[0].sha256.clear(); }, item(0, not_canary)},
        {"a manifest item with an upper-case hash", [](Items& i) { i[0].sha256 = std::string(64, 'B'); },
         item(0, not_canary)},
        {"a manifest item whose hash isn't hex", [](Items& i) { i[0].sha256 = std::string(64, 'g'); },
         item(0, not_canary)},
        {"a manifest item whose hash is short", [](Items& i) { i[0].sha256.pop_back(); }, item(0, not_canary)},
        {"a manifest item without a rule", [](Items& i) { i[0].sha256_rule.clear(); }, item(0, not_canary)},
        {"a file by text-v1", [](Items& i) { i[0].sha256_rule = "text-v1"; }, item(0, not_canary)},
        {"a mail by bytes", [](Items& i) { i[3].sha256_rule = "bytes"; }, item(3, not_canary)},
        {"a manifest item from a random source", [](Items& i) { i[0].source = ItemSource::random; },
         item(0, not_canary)},
        {"a manifest item without a canary id", [](Items& i) { i[0].canary_id.clear(); }, item(0, not_canary)},
        {"a manifest item with a random key", [](Items& i) { i[0].random_key = {"k"}; }, item(0, not_canary)},
        {"a fields item with a hash", [](Items& i) { i[1].sha256 = std::string(64, 'b'); }, item(1, not_random)},
        {"a metadata item with a rule", [](Items& i) { i[2].sha256_rule = "bytes"; }, item(2, not_random)},
        {"a fields item from a canary", [](Items& i) { i[1].source = ItemSource::canary; }, item(1, not_random)},
        {"a metadata item with a canary id", [](Items& i) { i[2].canary_id = "x"; }, item(2, not_random)},
        {"a metadata item without a key", [](Items& i) { i[2].random_key.clear(); }, item(2, not_random)},
        {"a file said to be fields", [](Items& i) { i[2].expected_kind = ExpectedKind::fields; },
         item(2, not_random)},
        {"a mail said to be metadata", [](Items& i) { i[1].expected_kind = ExpectedKind::metadata; },
         item(1, not_random)},
        {"an expected kind outside the enum", [](Items& i) { i[1].expected_kind = static_cast<ExpectedKind>(7); },
         item(1, "has an unknown expected kind")},
        {"an item out of its index", [](Items& i) { i[2].index = 7; }, item(2, "isn't at its index")},
        {"a type outside the enum", [](Items& i) { i[1].kind = static_cast<ItemKind>(9); },
         item(1, "has an unknown type")},
        {"a mail without its fields", [](Items& i) { i[1].mail.reset(); }, item(1, "doesn't hold its type's fields")},
        {"a file holding a mail's fields too", [](Items& i) { i[2].mail = verification::ExpectedMail{}; },
         item(2, "doesn't hold its type's fields")},
    }));
    CAPTURE(row.what);
    ExpectedSet set{std::string(64, 'a'), consistent_items()};
    REQUIRE_NOTHROW(verification::to_json(set));
    row.edit(set.items);
    const Thrown thrown = thrown_by([&] { verification::to_json(set); });
    CHECK(thrown.kind == "logic_error");
    CHECK(thrown.what == row.message);
}

// 3. Acceptance (Done when, issue #36): every sampled item has an expected
// record and its kind is explicit.
TEST_CASE("every sampled item has an expected record, in RestoreSpec order, with its kind explicit",
          "[expected-set]")
{
    // Per type (mail, SharePoint, OneDrive): random items wanted and taken,
    // and selectors; then the counts of manifest, fields and metadata. The
    // pool holds 3 mails, 3 SharePoint and 2 OneDrive files.
    struct Row {
        std::string what;
        SamplePlan plan;
        CanaryCursor cursor;
        std::array<int, 3> wanted;
        std::array<int, 3> taken;
        std::array<std::size_t, 3> selectors;
        std::array<std::size_t, 3> counts;
    };
    const Row row = GENERATE_COPY(values<Row>({
        {"canaries and random items of all three types", {5, 4, 3}, {0, 0, 0},
         {2, 2, 1}, {2, 2, 1}, {5, 4, 3}, {7, 2, 3}},
        // Random halves of 3, 4 and 3 from pools of 3, 3 and 2: SharePoint
        // and OneDrive short.
        {"fewer random items than wanted", {7, 9, 7}, {3, 8, 9},
         {3, 4, 3}, {3, 3, 2}, {7, 8, 6}, {13, 3, 5}},
        {"a type of size 0", {0, 2, 3}, {0, 1, 2}, {0, 1, 1}, {0, 1, 1}, {0, 2, 3}, {3, 0, 2}},
        {"only canaries", {1, 1, 1}, {19, 9, 0}, {0, 0, 0}, {0, 0, 0}, {1, 1, 1}, {3, 0, 0}},
    }));
    CAPTURE(row.what);
    PoolConnector c(mixed_pool());
    const Selection s = rp::sampling::choose_sample(
        c, "RestoreProofLab.onmicrosoft.com", lab_point(), targets(), lab_manifest().tenant_id,
        row.plan, &lab_manifest(), row.cursor, kRunId);
    CHECK(s.record.mail.random_wanted == row.wanted[0]);
    CHECK(s.record.sharepoint.random_wanted == row.wanted[1]);
    CHECK(s.record.onedrive.random_wanted == row.wanted[2]);
    CHECK(s.record.mail.random_taken == row.taken[0]);
    CHECK(s.record.sharepoint.random_taken == row.taken[1]);
    CHECK(s.record.onedrive.random_taken == row.taken[2]);
    CHECK(s.mail_random.size() == static_cast<std::size_t>(row.taken[0]));
    CHECK(s.sharepoint_random.size() == static_cast<std::size_t>(row.taken[1]));
    CHECK(s.onedrive_random.size() == static_cast<std::size_t>(row.taken[2]));
    CHECK(s.mail.size() == row.selectors[0]);
    CHECK(s.sharepoint.size() == row.selectors[1]);
    CHECK(s.onedrive.size() == row.selectors[2]);

    const ExpectedSet set = verification::build_expected_set(s, &lab_manifest());
    CHECK(count_of(set, ExpectedKind::manifest) == row.counts[0]);
    CHECK(count_of(set, ExpectedKind::fields) == row.counts[1]);
    CHECK(count_of(set, ExpectedKind::metadata) == row.counts[2]);

    const std::size_t n = s.mail.size() + s.sharepoint.size() + s.onedrive.size();
    REQUIRE(set.items.size() == n);
    CHECK(set.manifest_sha256 == lab_manifest().sha256);
    // When the manifest's canaries were in place: a restore point taken later holds them.
    CHECK(set.canaries_seeded_at == "2026-09-24T22:38:54Z");
    // The spec's order: mail, SharePoint, OneDrive; per type the canaries,
    // then the random items, as the selection holds them.
    struct Part {
        ItemKind kind;
        std::size_t size;
        const rp::sampling::KindRecord* record;
    };
    std::size_t index = 0;
    for (const Part& part : {Part{ItemKind::mail, s.mail.size(), &s.record.mail},
                             Part{ItemKind::sharepoint, s.sharepoint.size(), &s.record.sharepoint},
                             Part{ItemKind::onedrive, s.onedrive.size(), &s.record.onedrive}}) {
        for (std::size_t j = 0; j < part.size; ++j, ++index) {
            const ExpectedItem& item = set.items[index];
            CAPTURE(index, j);
            CHECK(item.index == index);
            CHECK(item.kind == part.kind);
            const bool canary = j < part.record->canary_ids.size();
            if (canary) {
                CHECK(item.source == ItemSource::canary);
                CHECK(item.expected_kind == ExpectedKind::manifest);
                CHECK(item.canary_id == part.record->canary_ids[j]);
                CHECK(item.random_key.empty());
                CHECK(item.sha256.size() == 64);
                CHECK_FALSE(item.sha256_rule.empty());
            } else {
                CHECK(item.source == ItemSource::random);
                CHECK(item.expected_kind ==
                      (part.kind == ItemKind::mail ? ExpectedKind::fields : ExpectedKind::metadata));
                CHECK(item.canary_id.empty());
                CHECK(item.random_key ==
                      part.record->random_keys[j - part.record->canary_ids.size()]);
                CHECK(item.sha256.empty());
                CHECK(item.sha256_rule.empty());
            }
            CHECK(item.mail.has_value() == (part.kind == ItemKind::mail));
            CHECK(item.file.has_value() == (part.kind != ItemKind::mail));
        }
    }
    // The subjects and names line up with the selectors.
    for (std::size_t i = 0; i < s.mail.size(); ++i) {
        CHECK(set.items[i].mail->subject == s.mail[i].subject);
        CHECK(set.items[i].mail->received_at == s.mail[i].received_at);
    }
    for (std::size_t i = 0; i < s.sharepoint.size(); ++i) {
        CHECK(set.items[s.mail.size() + i].file->name == s.sharepoint[i].name);
    }
    for (std::size_t i = 0; i < s.onedrive.size(); ++i) {
        CHECK(set.items[s.mail.size() + s.sharepoint.size() + i].file->name == s.onedrive[i].name);
    }

    const json out = verification::to_json(set);
    const json& counts = out.at("counts");
    CHECK(counts.size() == 4);
    CHECK(counts.at("backup_content").get<std::size_t>() == 0);
    CHECK(counts.at("manifest").get<std::size_t>() == count_of(set, ExpectedKind::manifest));
    CHECK(counts.at("fields").get<std::size_t>() == count_of(set, ExpectedKind::fields));
    CHECK(counts.at("metadata").get<std::size_t>() == count_of(set, ExpectedKind::metadata));
    CHECK(counts.at("manifest").get<std::size_t>() + counts.at("fields").get<std::size_t>() +
              counts.at("metadata").get<std::size_t>() ==
          n);
    REQUIRE(out.at("items").size() == n);
    for (std::size_t i = 0; i < n; ++i) {
        CHECK(out.at("items")[i].at("index").get<std::size_t>() == i);
        CHECK(out.at("items")[i].at("expected_kind").is_string());
    }
}

// 4. Canary mail, from the real manifest.
TEST_CASE("a canary mail expects the manifest's fields and its body hash by text-v1",
          "[expected-set]")
{
    const std::uint32_t cursor = GENERATE(0u, 7u, 15u);
    CAPTURE(cursor);
    const ExpectedSet set =
        verification::build_expected_set(select({1, 0, 0}, {}, {cursor, 0, 0}), &lab_manifest());
    REQUIRE(set.items.size() == 1);
    const ExpectedItem& item = set.items[0];
    const json& entry = lab_entries().at(cursor);
    REQUIRE(entry.at("kind") == "mail");
    CHECK(item.kind == ItemKind::mail);
    CHECK(item.source == ItemSource::canary);
    CHECK(item.expected_kind == ExpectedKind::manifest);
    CHECK(item.canary_id == entry.at("id").get<std::string>());
    REQUIRE(item.mail);
    CHECK(item.mail->subject == entry.at("subject").get<std::string>());
    CHECK(item.mail->sender_address == entry.at("sender").get<std::string>());
    CHECK_FALSE(item.mail->sender_name);
    CHECK(item.mail->sent_at == entry.at("sent_at").get<std::string>());
    CHECK(item.mail->received_at == entry.at("received_at").get<std::string>());
    CHECK(item.mail->internet_message_id == entry.at("internet_message_id").get<std::string>());
    CHECK(item.sha256 == entry.at("body_sha256").get<std::string>());
    CHECK(item.sha256_rule == "text-v1");
    CHECK_FALSE(item.file);
}

// 5. Canary files.
TEST_CASE("a canary file expects its content hash by its rule, and its size only for bytes",
          "[expected-set]")
{
    struct Row {
        std::string what;
        CanaryCursor cursor;
        SamplePlan plan;
        std::size_t entry;
        std::string rule;
        bool sized;
    };
    const Row row = GENERATE_COPY(values<Row>({
        {"a SharePoint pdf", {0, 0, 0}, {0, 1, 0}, 20, "bytes", true},
        {"a SharePoint docx (rewritten by SharePoint)", {0, 1, 0}, {0, 1, 0}, 21, "office-v1", false},
        {"a OneDrive xlsx (not rewritten, still office-v1)", {0, 0, 2}, {0, 0, 1}, 32, "office-v1", false},
        {"a OneDrive pdf", {0, 0, 0}, {0, 0, 1}, 30, "bytes", true},
    }));
    CAPTURE(row.what);
    const ExpectedSet set =
        verification::build_expected_set(select(row.plan, {}, row.cursor), &lab_manifest());
    REQUIRE(set.items.size() == 1);
    const ExpectedItem& item = set.items[0];
    const json& entry = lab_entries().at(row.entry);
    CHECK(item.kind == (row.plan.sharepoint == 1 ? ItemKind::sharepoint : ItemKind::onedrive));
    CHECK(item.source == ItemSource::canary);
    CHECK(item.expected_kind == ExpectedKind::manifest);
    CHECK(item.canary_id == entry.at("id").get<std::string>());
    REQUIRE(item.file);
    CHECK(item.file->name == entry.at("name").get<std::string>());
    if (row.sized) {
        CHECK(item.file->size_bytes == entry.at("stored_size").get<std::int64_t>());
    } else {
        CHECK_FALSE(item.file->size_bytes);
    }
    CHECK(item.sha256 == entry.at("content_sha256").get<std::string>());
    CHECK(item.sha256_rule == row.rule);
    CHECK(entry.at("content_rule").get<std::string>() == row.rule);
    CHECK_FALSE(item.mail);
}

// 6. Random mail.
TEST_CASE("a random mail expects the backup's fields; what the backup didn't say is left out",
          "[expected-set]")
{
    struct Row {
        std::string what;
        std::string sender;
        std::string sent;
    };
    const Row row = GENERATE(values<Row>({
        {"neither sender nor sent time", "", ""},
        {"no sender", "", "2026-09-20T09:59:00Z"},
        {"no sent time", "Bob Test", ""},
        {"sender and sent time", "Bob Test", "2026-09-20T09:59:00Z"},
    }));
    CAPTURE(row.what);
    connector::CandidatePool pool;
    pool.mail = {mail_candidate(4, row.sender, row.sent)};
    const ExpectedSet set = verification::build_expected_set(select({2, 0, 0}, pool), &lab_manifest());
    REQUIRE(set.items.size() == 2);
    const ExpectedItem& item = set.items[1];
    CHECK(item.index == 1);
    CHECK(item.source == ItemSource::random);
    CHECK(item.expected_kind == ExpectedKind::fields);
    CHECK(item.random_key == std::vector<std::string>{"carol@restoreprooflab.onmicrosoft.com",
                                                      "Archive", "real mail 04",
                                                      "2026-09-20T10:00:04Z"});
    REQUIRE(item.mail);
    CHECK(item.mail->subject == "real mail 04");
    CHECK(item.mail->received_at == "2026-09-20T10:00:04Z");
    CHECK(item.mail->sender_name == (row.sender.empty() ? std::nullopt : std::optional{row.sender}));
    CHECK(item.mail->sent_at == (row.sent.empty() ? std::nullopt : std::optional{row.sent}));
    CHECK_FALSE(item.mail->sender_address);
    CHECK_FALSE(item.mail->internet_message_id);
    CHECK(item.sha256.empty());
    CHECK(item.sha256_rule.empty());

    const json out = verification::to_json(set).at("items")[1];
    CHECK(out.contains("sender_name") == !row.sender.empty());
    CHECK(out.contains("sent_at") == !row.sent.empty());
    CHECK_FALSE(out.contains("sender_address"));
    CHECK_FALSE(out.contains("sha256"));
}

// 7. Random files.
TEST_CASE("a random file expects its name, and the backup's size unless SharePoint rewrites it",
          "[expected-set]")
{
    struct Row {
        std::string name;
        bool sized;
    };
    const Row row = GENERATE(values<Row>({
        {"PLAN.DocX", false}, {"a.DocM", false}, {"a.Dotx", false}, {"a.dOTm", false},
        {"Budget.XLsx", false}, {"a.xLSm", false}, {"a.XltX", false}, {"a.xLTm", false},
        {"Deck.PPtx", false}, {"a.PptM", false}, {"a.pOTx", false}, {"a.POtm", false},
        {"a.ppSX", false}, {"a.PpSm", false}, {"Book.XLSB", false}, {"old.doc", false},
        {"sheet.xls", false}, {"Old.PPT", false},
        {"report.pdf", true}, {"README", true}, {"notes.docx.txt", true}, {"flow.vsdx", true},
        {"addin.xlam", true}, {"notes.odt", true},
        {"a.docxx", true},
    }));
    const bool sharepoint = GENERATE(true, false);
    CAPTURE(row.name, sharepoint);
    connector::CandidatePool pool;
    if (sharepoint) {
        pool.sharepoint = {sp_candidate(1, row.name, 4321)};
    } else {
        pool.onedrive = {od_candidate(row.name, 4321)};
    }
    const ExpectedSet set = verification::build_expected_set(
        select({0, sharepoint ? 2 : 0, sharepoint ? 0 : 2}, pool), &lab_manifest());
    REQUIRE(set.items.size() == 2);
    const ExpectedItem& item = set.items[1];
    CHECK(item.kind == (sharepoint ? ItemKind::sharepoint : ItemKind::onedrive));
    CHECK(item.source == ItemSource::random);
    CHECK(item.expected_kind == ExpectedKind::metadata);
    REQUIRE(item.file);
    CHECK(item.file->name == row.name);
    CHECK(item.file->size_bytes == (row.sized ? std::optional<std::int64_t>{4321} : std::nullopt));
    CHECK(item.sha256.empty());
    CHECK(item.sha256_rule.empty());
    CHECK(verification::to_json(set).at("items")[1].contains("size_bytes") == row.sized);
}

TEST_CASE("a random file whose size the backup didn't give expects no size", "[expected-set]")
{
    // -1 is the candidate's default: a connector that doesn't say.
    const std::int64_t size = GENERATE(std::int64_t{-1}, std::int64_t{-42});
    const bool sharepoint = GENERATE(true, false);
    CAPTURE(size, sharepoint);
    connector::CandidatePool pool;
    if (sharepoint) {
        pool.sharepoint = {sp_candidate(1, "report.pdf", size)};
    } else {
        pool.onedrive = {od_candidate("report.pdf", size)};
    }
    const ExpectedSet set = verification::build_expected_set(
        select({0, sharepoint ? 2 : 0, sharepoint ? 0 : 2}, pool), &lab_manifest());
    REQUIRE(set.items.size() == 2);
    REQUIRE(set.items[1].file);
    CHECK(set.items[1].expected_kind == ExpectedKind::metadata);
    CHECK(set.items[1].file->size_bytes == std::nullopt);
    CHECK_FALSE(verification::to_json(set).at("items")[1].contains("size_bytes"));
}

// A size of 0 is one the backup gave: an empty file.
TEST_CASE("a random empty file expects size 0", "[expected-set]")
{
    connector::CandidatePool pool;
    pool.onedrive = {od_candidate("empty.txt", 0)};
    const ExpectedSet set = verification::build_expected_set(select({0, 0, 2}, pool), &lab_manifest());
    REQUIRE(set.items.size() == 2);
    REQUIRE(set.items[1].file);
    CHECK(set.items[1].file->size_bytes == std::optional<std::int64_t>{0});
}


// 8. The one rule for the Office files SharePoint rewrites.
TEST_CASE("is_rewritten_office_file: the extensions SharePoint was seen to rewrite, ASCII case-insensitive",
          "[expected-set]")
{
    struct Row {
        std::string name;
        bool office;
    };
    const Row row = GENERATE(values<Row>({
        // Not one SharePoint rewrites (the live check of 2026-10-01).
        {"", false},
        {".docx", false}, // only an extension: no name before the dot
        {"docx", false},
        {"plan.docx.txt", false},
        {".doc", false},
        {"doc", false},
        {"plan.doc.txt", false},
        {"plan.vsdx", false},
        {"plan.vsdm", false},
        {"plan.vssx", false},
        {"plan.vstx", false},
        {"plan.xlam", false},
        {"plan.ppam", false},
        {"plan.ods", false},
        {"plan.rtf", false},
        {"plan.pdf", false},
        {"plan.docx ", false},
        {"plan.docxx", false},
        {"plan_docx", false},
        {"plan.odt", false},
        {"plan.zip", false},
        // One it rewrites.
        {"a.docx", true}, {"a.docm", true}, {"a.dotx", true}, {"a.dotm", true},
        {"a.xlsx", true}, {"a.xlsm", true}, {"a.xltx", true}, {"a.xltm", true},
        {"a.pptx", true}, {"a.pptm", true}, {"a.potx", true}, {"a.potm", true},
        {"a.ppsx", true}, {"a.ppsm", true}, {"a.xlsb", true}, {"a.doc", true},
        {"a.xls", true}, {"a.ppt", true}, {"OLD.DOC", true}, {"Budget.Xls", true},
        {"PLAN.DOCX", true}, {"Plan.XlSx", true}, {"..pptx", true}, {"a.b.docx", true},
        {"\xC5\xB9r\xC3\xB3" "d\xC5\x82" "a.docx", true},
    }));
    CAPTURE(row.name);
    CHECK(rp::is_rewritten_office_file(row.name) == row.office);
}

// 9. The result's "expected" object.
TEST_CASE("to_json writes the result's expected object; unknown values are left out",
          "[expected-set]")
{
    ExpectedSet set;
    set.manifest_sha256 = std::string(64, 'a');
    ExpectedItem canary;
    canary.index = 0;
    canary.kind = ItemKind::sharepoint;
    canary.source = ItemSource::canary;
    canary.expected_kind = ExpectedKind::manifest;
    canary.canary_id = "rp-canary-01.pdf";
    canary.file = verification::ExpectedFile{"rp-canary-01.pdf", 925};
    canary.sha256 = std::string(64, 'b');
    canary.sha256_rule = "bytes";
    ExpectedItem random;
    random.index = 1;
    random.kind = ItemKind::mail;
    random.source = ItemSource::random;
    random.expected_kind = ExpectedKind::fields;
    random.random_key = {"carol@restoreprooflab.onmicrosoft.com", "Archive", "Lunch",
                         "2026-09-20T10:00:00Z"};
    random.mail = verification::ExpectedMail{"Lunch", std::nullopt, std::nullopt,
                                             "2026-09-20T09:59:58Z", "2026-09-20T10:00:00Z",
                                             std::nullopt};
    ExpectedItem office;
    office.index = 2;
    office.kind = ItemKind::onedrive;
    office.source = ItemSource::random;
    office.expected_kind = ExpectedKind::metadata;
    office.random_key = {"carol@restoreprooflab.onmicrosoft.com", "/", "Plan.docx"};
    office.file = verification::ExpectedFile{"Plan.docx", std::nullopt};
    set.items = {canary, random, office};

    CHECK(verification::to_json(set) == json::parse(R"({
        "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "counts": {"manifest": 1, "fields": 1, "metadata": 1, "backup_content": 0},
        "items": [
            {"index": 0, "kind": "sharepoint", "source": "canary", "expected_kind": "manifest",
             "canary_id": "rp-canary-01.pdf", "name": "rp-canary-01.pdf", "size_bytes": 925,
             "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             "sha256_rule": "bytes"},
            {"index": 1, "kind": "mail", "source": "random", "expected_kind": "fields",
             "key": ["carol@restoreprooflab.onmicrosoft.com", "Archive", "Lunch", "2026-09-20T10:00:00Z"],
             "subject": "Lunch", "sent_at": "2026-09-20T09:59:58Z", "received_at": "2026-09-20T10:00:00Z"},
            {"index": 2, "kind": "onedrive", "source": "random", "expected_kind": "metadata",
             "key": ["carol@restoreprooflab.onmicrosoft.com", "/", "Plan.docx"], "name": "Plan.docx"}
        ]
    })"));

    // A canary mail: every field, and counts with zeros.
    ExpectedItem mail;
    mail.kind = ItemKind::mail;
    mail.canary_id = "RP-CANARY-0008";
    mail.mail = verification::ExpectedMail{"RP-CANARY-0008", "admin@example.com", std::nullopt,
                                           "2026-09-24T22:14:41Z", "2026-09-24T22:14:44Z",
                                           "<id@example.com>"};
    mail.sha256 = std::string(64, 'c');
    mail.sha256_rule = "text-v1";
    const json one = verification::to_json(ExpectedSet{std::string(64, 'd'), {mail}});
    CHECK(one.at("counts") == json{{"manifest", 1}, {"fields", 0}, {"metadata", 0}, {"backup_content", 0}});
    CHECK(one.at("items")[0] == json::parse(R"({
        "index": 0, "kind": "mail", "source": "canary", "expected_kind": "manifest",
        "canary_id": "RP-CANARY-0008", "subject": "RP-CANARY-0008",
        "sender_address": "admin@example.com", "sent_at": "2026-09-24T22:14:41Z",
        "received_at": "2026-09-24T22:14:44Z", "internet_message_id": "<id@example.com>",
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "sha256_rule": "text-v1"
    })"));

    const json empty = verification::to_json(ExpectedSet{});
    CHECK(empty.at("counts") == json{{"manifest", 0}, {"fields", 0}, {"metadata", 0}, {"backup_content", 0}});
    CHECK(empty.at("items") == json::array());
}

TEST_CASE("the kinds and sources as strings", "[expected-set]")
{
    CHECK(verification::to_string(ExpectedKind::manifest) == "manifest");
    CHECK(verification::to_string(ExpectedKind::fields) == "fields");
    CHECK(verification::to_string(ExpectedKind::metadata) == "metadata");
    CHECK(verification::to_string(ItemSource::canary) == "canary");
    CHECK(verification::to_string(ItemSource::random) == "random");
    // Outside the enum: never a value that claims a check.
    CHECK(verification::to_string(static_cast<ExpectedKind>(7)) == "unknown");
    CHECK(verification::to_string(static_cast<ItemSource>(7)) == "unknown");
}
