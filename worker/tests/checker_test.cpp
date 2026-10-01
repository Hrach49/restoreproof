// The checker (W3.2, rp/checker.hpp): what became of each expected item in
// the restore targets, from one read of them before the restore and one
// after. Pure: the reads are built here as TargetReader returns them. Failure
// paths first: a target that couldn't be read, nothing restored, only an
// earlier run's copy, each field that doesn't agree. The choices are the
// 2026-10-01 W3.2 entry in docs/decisions.md.

#include <rp/checker.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/graph_errors.hpp>
#include <rp/graph_targets.hpp>
#include <rp/office_v1.hpp>
#include <rp/sha256.hpp>
#include <rp/target_guard_graph.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;

namespace {

namespace connector = rp::connector;
namespace verification = rp::verification;
using connector::ItemKind;
using nlohmann::json;
using rp::graph::FoundItem;
using rp::graph::ItemType;
using verification::CheckOutcome;
using verification::CheckResult;
using verification::ExpectedItem;
using verification::ExpectedSet;
using verification::ItemCheck;
using verification::ItemSource;
using verification::TargetSnapshot;
using verification::TargetsRead;

const std::string kHashA(64, 'a');
const std::string kHashB(64, 'b');

// --- Expected items, as build_expected_set makes them ---------------------------------

ExpectedItem canary_mail(std::size_t index, const std::string& subject = "RP-CANARY-0001")
{
    ExpectedItem item;
    item.index = index;
    item.kind = ItemKind::mail;
    item.source = ItemSource::canary;
    item.expected_kind = verification::ExpectedKind::manifest;
    item.canary_id = subject;
    item.mail = verification::ExpectedMail{subject,
                                           "Sender@RestoreProofLab.onmicrosoft.com",
                                           std::nullopt,
                                           "2026-09-24T22:14:40Z",
                                           "2026-09-24T22:14:43Z",
                                           "<" + subject + "@lab.example>"};
    item.sha256 = kHashA;
    item.sha256_rule = "text-v1";
    return item;
}

ExpectedItem random_mail(std::size_t index, const std::string& subject = "Lunch")
{
    ExpectedItem item;
    item.index = index;
    item.kind = ItemKind::mail;
    item.source = ItemSource::random;
    item.expected_kind = verification::ExpectedKind::fields;
    item.random_key = {"carol@lab.example", "Inbox", subject, "2026-09-20T10:00:00Z"};
    item.mail = verification::ExpectedMail{subject, std::nullopt, "Carol Test",
                                           "2026-09-20T09:59:00Z", "2026-09-20T10:00:00Z",
                                           std::nullopt};
    return item;
}

ExpectedItem canary_file(std::size_t index, ItemKind kind, const std::string& name,
                         const std::string& rule = "bytes", const std::string& hash = kHashA)
{
    ExpectedItem item;
    item.index = index;
    item.kind = kind;
    item.source = ItemSource::canary;
    item.expected_kind = verification::ExpectedKind::manifest;
    item.canary_id = name;
    item.file = verification::ExpectedFile{
        name, rule == "bytes" ? std::optional<std::int64_t>{925} : std::nullopt};
    item.sha256 = hash;
    item.sha256_rule = rule;
    return item;
}

ExpectedItem random_file(std::size_t index, ItemKind kind, const std::string& name,
                         std::optional<std::int64_t> size = 1000)
{
    ExpectedItem item;
    item.index = index;
    item.kind = kind;
    item.source = ItemSource::random;
    item.expected_kind = verification::ExpectedKind::metadata;
    item.random_key = {"carol@lab.example", "/Projects", name};
    item.file = verification::ExpectedFile{name, size};
    return item;
}

ExpectedSet set_of(std::vector<ExpectedItem> items)
{
    return {std::string(64, 'f'), std::move(items)};
}

// --- Restored copies, as TargetReader reads them --------------------------------------

// A copy of the expected mail that agrees on every field.
FoundItem mail_copy(const ExpectedItem& want, const std::string& id,
                    const std::string& created = "2026-10-01T10:00:00Z")
{
    const verification::ExpectedMail& m = *want.mail;
    FoundItem item;
    item.type = ItemType::mail;
    item.id = id;
    item.subject = m.subject;
    item.sender = m.sender_address.value_or("someone@lab.example");
    item.sender_name = m.sender_name.value_or("Someone");
    item.sent_at = m.sent_at.value_or("2026-09-20T09:00:00Z");
    item.received_at = m.received_at;
    item.internet_message_id = m.internet_message_id.value_or("<random@lab.example>");
    item.created_at = created;
    item.sha256 = want.sha256.empty() ? kHashB : want.sha256;
    item.sha256_rule = "text-v1";
    return item;
}

ItemType type_of(ItemKind kind)
{
    return kind == ItemKind::sharepoint ? ItemType::sharepoint : ItemType::onedrive;
}

// A copy of the expected file that agrees on every field.
FoundItem file_copy(const ExpectedItem& want, const std::string& id,
                    const std::string& ctag = "\"c:{1},2\"",
                    const std::string& modified = "2026-10-01T10:00:00Z")
{
    FoundItem item;
    item.type = type_of(want.kind);
    item.id = id;
    item.name = want.file->name;
    item.ctag = ctag;
    item.created_at = "2026-09-24T22:14:43Z";
    item.modified_at = modified;
    item.size_bytes = static_cast<std::uint64_t>(want.file->size_bytes.value_or(4096));
    item.listed_size = item.size_bytes;
    if (want.sha256_rule == "bytes") {
        item.sha256 = want.sha256;
    } else {
        item.sha256 = kHashB;
    }
    item.sha256_rule = "bytes";
    return item;
}

verification::TargetRead& read_of(TargetsRead& reads, ItemKind kind)
{
    return kind == ItemKind::mail         ? reads.mail
           : kind == ItemKind::sharepoint ? reads.sharepoint
                                          : reads.onedrive;
}

// One canary and one random item of every type, the restore's copies of each
// in `after`, nothing before.
struct Scene {
    Scene()
    {
        expected = set_of({canary_mail(0), random_mail(1),
                           canary_file(2, ItemKind::sharepoint, "rp-canary-01.pdf"),
                           random_file(3, ItemKind::sharepoint, "report.pdf"),
                           canary_file(4, ItemKind::onedrive, "rp-canary-12.docx", "office-v1"),
                           random_file(5, ItemKind::onedrive, "notes.txt", 77)});
        const std::vector<ExpectedItem>& e = expected.items;
        after.mail.items = {mail_copy(e[0], "m-0"), mail_copy(e[1], "m-1")};
        after.sharepoint.items = {file_copy(e[2], "s-2"), file_copy(e[3], "s-3")};
        after.onedrive.items = {file_copy(e[4], "o-4"), file_copy(e[5], "o-5")};
        after.onedrive.office["o-4"] = {kHashA, ""};
    }

    CheckResult run() const { return verification::check(expected, before, after, clock); }

    ItemCheck run_one(std::size_t index) const { return run().items.at(index); }

    ExpectedSet expected;
    TargetSnapshot before;
    TargetsRead after;
    std::function<std::chrono::steady_clock::time_point()> clock;
};

std::vector<CheckOutcome> outcomes(const CheckResult& result)
{
    std::vector<CheckOutcome> out;
    for (const ItemCheck& item : result.items) {
        out.push_back(item.outcome);
    }
    return out;
}

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

std::filesystem::path canary_path(const std::string& name)
{
    return std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "canary" / name;
}

} // namespace

// --- Failure paths: the targets couldn't be read ----------------------------------------

TEST_CASE("check: a target that couldn't be read makes each of its items error with the read's "
          "code; the other types are still checked",
          "[checker]")
{
    const ItemKind kind = GENERATE(ItemKind::mail, ItemKind::sharepoint, ItemKind::onedrive);
    const std::string code = GENERATE("graph_auth", "graph_permission", "graph_transient",
                                      "target_guard", "graph");
    CAPTURE(connector::to_string(kind), code);
    Scene scene;
    read_of(scene.after, kind).error_code = code;
    // A read that failed part-way: whatever it held isn't looked at.
    read_of(scene.after, kind).items.clear();

    const CheckResult result = scene.run();

    REQUIRE(result.items.size() == 6);
    for (const ItemCheck& item : result.items) {
        CAPTURE(item.index);
        if (item.kind == kind) {
            CHECK(item.outcome == CheckOutcome::error);
            CHECK(item.error_code == code);
            CHECK_FALSE(item.found);
            CHECK(item.mismatches.empty());
            CHECK(item.reason == "the " + std::string{connector::to_string(kind)} +
                                     " restore target couldn't be read (" + code + ")");
        } else {
            CHECK(item.outcome == CheckOutcome::match);
        }
    }
}

TEST_CASE("check: a read error wins over copies the read still holds", "[checker]")
{
    Scene scene;
    scene.after.sharepoint.error_code = "graph_transient";

    const CheckResult result = scene.run();

    CHECK(result.items[2].outcome == CheckOutcome::error);
    CHECK(result.items[3].outcome == CheckOutcome::error);
    CHECK(result.stale_sharepoint == 0);
}

// --- Failure paths: nothing of this run's -----------------------------------------------

TEST_CASE("check: an item with no copy at all is missing", "[checker]")
{
    const std::size_t index = GENERATE(range(std::size_t{0}, std::size_t{6}));
    CAPTURE(index);
    Scene scene;
    const ExpectedItem& want = scene.expected.items[index];
    std::vector<FoundItem>& items = read_of(scene.after, want.kind).items;
    std::erase_if(items, [&](const FoundItem& item) { return item.id.ends_with(std::to_string(index)); });

    const ItemCheck item = scene.run_one(index);

    CHECK(item.outcome == CheckOutcome::missing);
    CHECK_FALSE(item.found);
    CHECK(item.reason == "no restored copy found");
    CHECK(item.error_code.empty());
    CHECK(item.ms == 0);
    CHECK(item.copies == 0);
}

TEST_CASE("check: a file that was there before is this run's only if its cTag moved; else the "
          "item is error stale_target",
          "[checker]")
{
    using Tag = std::optional<std::string>;
    const auto [before_tag, after_tag, outcome] =
        GENERATE(table<Tag, Tag, CheckOutcome>({
            {Tag{"\"c:{1},2\""}, Tag{"\"c:{1},2\""}, CheckOutcome::error}, // unchanged
            {std::nullopt, Tag{"\"c:{1},2\""}, CheckOutcome::error},       // unknown before
            {Tag{"\"c:{1},2\""}, std::nullopt, CheckOutcome::error},       // unknown after
            {std::nullopt, std::nullopt, CheckOutcome::error},
            {Tag{"\"c:{1},2\""}, Tag{"\"c:{1},3\""}, CheckOutcome::match}, // moved: this run's
        }));
    const ItemKind kind = GENERATE(ItemKind::sharepoint, ItemKind::onedrive);
    CAPTURE(before_tag, after_tag, connector::to_string(kind));
    Scene scene;
    const std::size_t index = kind == ItemKind::sharepoint ? 2 : 5;
    FoundItem& copy = read_of(scene.after, kind).items[kind == ItemKind::sharepoint ? 0 : 1];
    copy.ctag = after_tag;
    (kind == ItemKind::sharepoint ? scene.before.sharepoint : scene.before.onedrive)[copy.id] =
        before_tag;

    const CheckResult result = scene.run();

    const ItemCheck& item = result.items[index];
    CHECK(item.outcome == outcome);
    const std::size_t stale =
        kind == ItemKind::sharepoint ? result.stale_sharepoint : result.stale_onedrive;
    if (outcome == CheckOutcome::error) {
        CHECK(item.error_code == "stale_target");
        CHECK_FALSE(item.found);
        CHECK(item.reason == "only an earlier run's copy is in the target");
        CHECK(stale == 1);
    } else {
        CHECK(item.found);
        CHECK(stale == 0);
    }
}

TEST_CASE("check: an earlier run's file beside this run's copy is ignored and counted",
          "[checker]")
{
    Scene scene;
    FoundItem old = file_copy(scene.expected.items[2], "s-old", "\"c:{9},1\"", "2026-10-02T00:00:00Z");
    old.sha256 = kHashB; // it wouldn't match: never looked at
    scene.after.sharepoint.items.push_back(old);
    scene.before.sharepoint["s-old"] = "\"c:{9},1\"";

    const CheckResult result = scene.run();

    CHECK(result.items[2].outcome == CheckOutcome::match);
    CHECK(result.items[2].graph_id == "s-2");
    CHECK_FALSE(result.items[2].duplicate);
    CHECK(result.stale_sharepoint == 1);
}

TEST_CASE("check: a stale file of another name doesn't make an item stale_target", "[checker]")
{
    Scene scene;
    scene.after.sharepoint.items.erase(scene.after.sharepoint.items.begin());
    FoundItem other = file_copy(scene.expected.items[3], "s-old");
    other.name = "something else.pdf";
    scene.after.sharepoint.items.push_back(other);
    scene.before.sharepoint["s-old"] = other.ctag;

    const ItemCheck item = scene.run_one(2);

    CHECK(item.outcome == CheckOutcome::missing);
}

TEST_CASE("check: a mail that was in the target before is never this run's copy; when it is the "
          "only one that matches, the item is error stale_target, never missing",
          "[checker]")
{
    // W3.2 live run 2 (2026-10-01): Veeam said "restored successfully" for five mails already
    // in the Inbox and wrote nothing; the Inbox kept run 1's copies, same Graph IDs. A missing
    // item there would be a `fail` for what is an unclean target, so it is an error.
    const std::size_t index = GENERATE(std::size_t{0}, std::size_t{1});
    CAPTURE(index);
    Scene scene;
    scene.before.mail.insert("m-" + std::to_string(index));

    const CheckResult result = scene.run();

    const ItemCheck& item = result.items[index];
    CHECK(item.outcome == CheckOutcome::error);
    CHECK(item.error_code == "stale_target");
    CHECK_FALSE(item.found);
    CHECK(item.reason == "only an earlier run's copy is in the target");
    CHECK(item.ms == 0);
    CHECK(result.stale_mail == 1);
}

TEST_CASE("check: an earlier mail that the item wouldn't match leaves it missing", "[checker]")
{
    const std::size_t index = GENERATE(std::size_t{0}, std::size_t{1});
    CAPTURE(index);
    Scene scene;
    FoundItem& old = scene.after.mail.items[index];
    scene.before.mail.insert(old.id);
    old.subject = "another subject";
    old.internet_message_id = "<another@id>";

    const ItemCheck item = scene.run_one(index);

    CHECK(item.outcome == CheckOutcome::missing);
    CHECK(item.reason == "no restored copy found");
}

TEST_CASE("check: a canary mail whose earlier copy only shares its subject is stale_target too",
          "[checker]")
{
    Scene scene;
    FoundItem& old = scene.after.mail.items[0];
    REQUIRE(scene.expected.items[0].mail->internet_message_id);
    scene.before.mail.insert(old.id);
    old.internet_message_id = "<another@id>";

    const ItemCheck item = scene.run_one(0);

    CHECK(item.outcome == CheckOutcome::error);
    CHECK(item.error_code == "stale_target");
}

// --- Failure paths: fields that don't agree ---------------------------------------------

TEST_CASE("check: each field that doesn't agree is a mismatch, named in the reason", "[checker]")
{
    struct Row {
        std::string name;
        std::size_t index;
        std::function<void(FoundItem&)> edit;
        std::vector<std::string> mismatches;
    };
    const std::vector<Row> rows{
        // The canary mail (index 0), found by its internet message ID.
        {"canary subject", 0, [](FoundItem& f) { f.subject = "RP-CANARY-0001 "; }, {"subject"}},
        {"canary no subject", 0, [](FoundItem& f) { f.subject.reset(); }, {"subject"}},
        {"canary sender", 0, [](FoundItem& f) { f.sender = "other@RestoreProofLab.onmicrosoft.com"; },
         {"sender_address"}},
        {"canary no sender", 0, [](FoundItem& f) { f.sender.reset(); }, {"sender_address"}},
        {"canary sent", 0, [](FoundItem& f) { f.sent_at = "2026-09-24T22:16:41Z"; }, {"sent_at"}},
        {"canary no sent", 0, [](FoundItem& f) { f.sent_at.reset(); }, {"sent_at"}},
        {"canary sent not a time", 0, [](FoundItem& f) { f.sent_at = "yesterday"; }, {"sent_at"}},
        {"canary received", 0, [](FoundItem& f) { f.received_at = "2026-09-23T22:14:43Z"; },
         {"received_at"}},
        {"canary no received", 0, [](FoundItem& f) { f.received_at.reset(); }, {"received_at"}},
        {"canary received with an offset", 0,
         [](FoundItem& f) { f.received_at = "2026-09-24T22:14:43+00:00"; }, {"received_at"}},
        {"canary body", 0, [](FoundItem& f) { f.sha256 = kHashB; }, {"sha256"}},
        {"canary body rule", 0, [](FoundItem& f) { f.sha256_rule = "bytes"; }, {"sha256"}},
        {"canary body not hashed", 0,
         [](FoundItem& f) {
             f.sha256.clear();
             f.sha256_rule.clear();
         },
         {"sha256"}},
        {"canary several", 0,
         [](FoundItem& f) {
             f.subject = "x";
             f.sender.reset();
             f.sent_at.reset();
             f.received_at.reset();
             f.sha256 = kHashB;
         },
         {"subject", "sender_address", "sent_at", "received_at", "sha256"}},
        // The random mail (index 1), found by its subject.
        {"random sender name", 1, [](FoundItem& f) { f.sender_name = "Carol  Test"; },
         {"sender_name"}},
        {"random no sender name", 1, [](FoundItem& f) { f.sender_name.reset(); }, {"sender_name"}},
        {"random sent", 1, [](FoundItem& f) { f.sent_at = "2026-09-20T10:01:01Z"; }, {"sent_at"}},
        {"random received", 1, [](FoundItem& f) { f.received_at = "2026-09-20T09:57:59Z"; },
         {"received_at"}},
        // Files: the SharePoint canary (2, bytes), the SharePoint random (3),
        // the OneDrive canary (4, office-v1), the OneDrive random (5).
        {"canary file size", 2, [](FoundItem& f) { f.size_bytes = 924; }, {"size_bytes"}},
        {"canary file no size", 2, [](FoundItem& f) { f.size_bytes.reset(); }, {"size_bytes"}},
        {"canary file bytes", 2, [](FoundItem& f) { f.sha256 = kHashB; }, {"sha256"}},
        {"canary file rule", 2, [](FoundItem& f) { f.sha256_rule = "text-v1"; }, {"sha256"}},
        {"canary file size and bytes", 2,
         [](FoundItem& f) {
             f.size_bytes = 1;
             f.sha256 = kHashB;
         },
         {"size_bytes", "sha256"}},
        {"random file size", 3, [](FoundItem& f) { f.size_bytes = 1001; }, {"size_bytes"}},
        {"random OneDrive file size", 5, [](FoundItem& f) { f.size_bytes = 0; }, {"size_bytes"}},
    };
    const Row& row = rows[GENERATE(range(std::size_t{0}, std::size_t{25}))];
    REQUIRE(rows.size() == 25);
    CAPTURE(row.name);
    Scene scene;
    const ExpectedItem& want = scene.expected.items[row.index];
    std::vector<FoundItem>& items = read_of(scene.after, want.kind).items;
    for (FoundItem& item : items) {
        if (item.id.ends_with(std::to_string(row.index))) {
            row.edit(item);
        }
    }

    const CheckResult result = scene.run();

    const ItemCheck& item = result.items[row.index];
    CHECK(item.outcome == CheckOutcome::mismatch);
    CHECK(item.found);
    CHECK(item.mismatches == row.mismatches);
    std::string fields;
    for (const std::string& f : row.mismatches) {
        fields += (fields.empty() ? "" : ", ") + f;
    }
    CHECK(item.reason == "fields did not match: " + fields);
    CHECK(item.error_code.empty());
    // The others still match.
    for (const ItemCheck& other : result.items) {
        if (other.index != row.index) {
            CHECK(other.outcome == CheckOutcome::match);
        }
    }
}

TEST_CASE("check: times agree within 120 seconds either way, inclusive", "[checker]")
{
    const auto [received, agrees] = GENERATE(table<std::string, bool>({
        {"2026-09-24T22:14:43Z", true},
        {"2026-09-24T22:16:42Z", true},      // +119 s
        {"2026-09-24T22:16:43Z", true},      // +120 s
        {"2026-09-24T22:16:43.5Z", false},   // +120.5 s
        {"2026-09-24T22:16:44Z", false},     // +121 s
        {"2026-09-24T22:12:44Z", true},      // -119 s
        {"2026-09-24T22:12:43Z", true},      // -120 s
        {"2026-09-24T22:12:42.9999999Z", false},
        {"2026-09-24T22:12:42Z", false},     // -121 s
        {"2026-09-24T22:14:43.1234567Z", true},
        // Centuries apart: never subtracted, so never wrapped to a match.
        {"1700-01-01T00:00:00Z", false},
        {"1678-01-01T00:00:00Z", false},
        {"2261-12-31T00:00:00Z", false},
        {"2261-12-31T23:59:59.9999999Z", false},
    }));
    CAPTURE(received);
    Scene scene;
    scene.after.mail.items[0].received_at = received;
    scene.after.mail.items[0].sent_at = received; // sent_at is 3 s earlier: still within, or not

    const ItemCheck item = scene.run_one(0);

    if (agrees) {
        CHECK(std::ranges::find(item.mismatches, "received_at") == item.mismatches.end());
    } else {
        CHECK(std::ranges::find(item.mismatches, "received_at") != item.mismatches.end());
    }
}

TEST_CASE("check: the sender address agrees in any ASCII case, the sender name only byte for "
          "byte after control characters become spaces",
          "[checker]")
{
    SECTION("address in another ASCII case")
    {
        Scene scene;
        scene.after.mail.items[0].sender = "SENDER@restoreprooflab.ONMICROSOFT.COM";
        CHECK(scene.run_one(0).outcome == CheckOutcome::match);
    }
    SECTION("address differing beyond ASCII case")
    {
        Scene scene;
        // U+0130 (capital I with dot) is no ASCII case of 'i'.
        scene.after.mail.items[0].sender = "Sender@RestoreProofLab.onm\xc4\xb0" "crosoft.com";
        CHECK(scene.run_one(0).mismatches == std::vector<std::string>{"sender_address"});
    }
    SECTION("name in another case")
    {
        Scene scene;
        scene.after.mail.items[1].sender_name = "carol test";
        CHECK(scene.run_one(1).mismatches == std::vector<std::string>{"sender_name"});
    }
    SECTION("name with a control character where the expectation has a space")
    {
        Scene scene;
        scene.after.mail.items[1].sender_name = "Carol\tTest";
        CHECK(scene.run_one(1).outcome == CheckOutcome::match);
    }
}

TEST_CASE("check: a field the expectation doesn't carry isn't compared", "[checker]")
{
    SECTION("a random mail without a sender name or a sent time")
    {
        Scene scene;
        scene.expected.items[1].mail->sender_name.reset();
        scene.expected.items[1].mail->sent_at.reset();
        scene.after.mail.items[1].sender_name.reset();
        scene.after.mail.items[1].sent_at = "not a time";
        CHECK(scene.run_one(1).outcome == CheckOutcome::match);
    }
    SECTION("a random mail has no sender address, internet message ID or hash to compare")
    {
        Scene scene;
        scene.after.mail.items[1].sender = "anyone@else.example";
        scene.after.mail.items[1].internet_message_id.reset();
        scene.after.mail.items[1].sha256.clear();
        CHECK(scene.run_one(1).outcome == CheckOutcome::match);
    }
    SECTION("a canary mail has no sender name to compare")
    {
        Scene scene;
        scene.after.mail.items[0].sender_name = "Anybody";
        CHECK(scene.run_one(0).outcome == CheckOutcome::match);
    }
    SECTION("a random file without a size (an Office package)")
    {
        Scene scene;
        scene.expected.items[3].file->size_bytes.reset();
        scene.after.sharepoint.items[1].size_bytes = 123456;
        CHECK(scene.run_one(3).outcome == CheckOutcome::match);
    }
    SECTION("a random file has no hash to compare")
    {
        Scene scene;
        scene.after.onedrive.items[1].sha256 = kHashB;
        CHECK(scene.run_one(5).outcome == CheckOutcome::match);
    }
    SECTION("an office-v1 canary has no size to compare")
    {
        Scene scene;
        scene.after.onedrive.items[0].size_bytes = 1;
        CHECK(scene.run_one(4).outcome == CheckOutcome::match);
    }
}

// --- office-v1 --------------------------------------------------------------------------

TEST_CASE("check: an office-v1 canary is compared with the after read's office hash",
          "[checker]")
{
    Scene scene;
    SECTION("the same hash: a match, whatever the bytes' own hash")
    {
        CHECK(scene.run_one(4).outcome == CheckOutcome::match);
    }
    SECTION("another hash")
    {
        scene.after.onedrive.office["o-4"] = {kHashB, ""};
        const ItemCheck item = scene.run_one(4);
        CHECK(item.mismatches == std::vector<std::string>{"sha256"});
        CHECK(item.reason == "fields did not match: sha256");
    }
    SECTION("no office hash at all")
    {
        scene.after.onedrive.office.clear();
        CHECK(scene.run_one(4).mismatches == std::vector<std::string>{"sha256"});
    }
    SECTION("a package that isn't valid office-v1 input: the restored file is broken")
    {
        scene.after.onedrive.office["o-4"] = {"", "office-v1: not a ZIP package\nsecond line"};
        const ItemCheck item = scene.run_one(4);
        CHECK(item.outcome == CheckOutcome::mismatch);
        CHECK(item.mismatches == std::vector<std::string>{"sha256"});
        CHECK(item.reason == "fields did not match: sha256; the restored package isn't valid "
                             "office-v1 input (office-v1: not a ZIP package second line)");
        CHECK(item.error_code.empty());
    }
}

// --- Finding the copy -------------------------------------------------------------------

TEST_CASE("check: a canary mail whose internet message ID isn't found is looked up by subject, "
          "the ID then a mismatch",
          "[checker]")
{
    Scene scene;
    scene.after.mail.items[0].internet_message_id = "<rewritten@lab.example>";

    const ItemCheck item = scene.run_one(0);

    CHECK(item.found);
    CHECK(item.graph_id == "m-0");
    CHECK(item.mismatches == std::vector<std::string>{"internet_message_id"});
}

TEST_CASE("check: a canary mail found by its internet message ID ignores a copy with its "
          "subject alone",
          "[checker]")
{
    Scene scene;
    FoundItem other = scene.after.mail.items[0];
    other.id = "m-other";
    other.internet_message_id = "<another@lab.example>";
    other.created_at = "2026-10-02T00:00:00Z";
    scene.after.mail.items.push_back(other);

    const ItemCheck item = scene.run_one(0);

    CHECK(item.outcome == CheckOutcome::match);
    CHECK(item.graph_id == "m-0");
    CHECK_FALSE(item.duplicate);
}

TEST_CASE("check: a random mail never takes a copy a canary matched", "[checker]")
{
    Scene scene;
    // A random mail with the canary's subject: the canary's copy is claimed.
    scene.expected.items[1] = random_mail(1, "RP-CANARY-0001");
    scene.after.mail.items.pop_back();

    const CheckResult result = scene.run();

    CHECK(result.items[0].outcome == CheckOutcome::match);
    CHECK(result.items[1].outcome == CheckOutcome::missing);
}

TEST_CASE("check: canaries claim first, whatever their place in the set", "[checker]")
{
    // A random mail before the canary in index order, both with one subject.
    ExpectedItem random = random_mail(0, "RP-CANARY-0001");
    ExpectedItem canary = canary_mail(1);
    const ExpectedSet expected = set_of({random, canary});
    TargetsRead after;
    after.mail.items = {mail_copy(canary, "m-canary")};

    const CheckResult result = verification::check(expected, {}, after);

    CHECK(result.items[1].outcome == CheckOutcome::match);
    CHECK(result.items[0].outcome == CheckOutcome::missing);
}

TEST_CASE("check: a random mail claims the copies it matched: a second with one subject is "
          "missing",
          "[checker]")
{
    const ExpectedSet expected = set_of({random_mail(0), random_mail(1)});
    TargetsRead after;
    after.mail.items = {mail_copy(expected.items[0], "m-1", "2026-10-01T10:00:00Z"),
                        mail_copy(expected.items[0], "m-2", "2026-10-01T10:00:01Z")};

    const CheckResult result = verification::check(expected, {}, after);

    // The first in index order takes both copies; a copy counts for one item only.
    CHECK(result.items[0].outcome == CheckOutcome::match);
    CHECK(result.items[0].duplicate);
    CHECK(result.items[0].copies == 2);
    CHECK(result.items[0].graph_id == "m-2");
    CHECK(result.items[1].outcome == CheckOutcome::missing);
    CHECK_FALSE(result.items[1].found);
    CHECK(result.items[1].reason == "no restored copy found");
}

TEST_CASE("check: two expected files of one type with one name: the second finds the first's "
          "copy claimed",
          "[checker]")
{
    const ItemKind kind = GENERATE(ItemKind::sharepoint, ItemKind::onedrive);
    const bool second_random = GENERATE(false, true);
    CAPTURE(connector::to_string(kind), second_random);
    const ExpectedItem first = canary_file(0, kind, "rp-canary-01.pdf");
    const ExpectedItem second = second_random ? random_file(1, kind, "RP-CANARY-01.PDF", 925)
                                              : canary_file(1, kind, "Rp-Canary-01.pdf");
    const ExpectedSet expected = set_of({first, second});
    TargetsRead after;
    read_of(after, kind).items = {file_copy(first, "f-1")};

    const CheckResult result = verification::check(expected, {}, after);

    CHECK(result.items[0].outcome == CheckOutcome::match);
    CHECK(result.items[0].graph_id == "f-1");
    CHECK(result.items[1].outcome == CheckOutcome::missing);
    CHECK_FALSE(result.items[1].found);
}

TEST_CASE("check: a file's copy claimed by an earlier item, and an earlier run's copy of that "
          "name: stale_target",
          "[checker]")
{
    const ExpectedItem first = canary_file(0, ItemKind::sharepoint, "rp-canary-01.pdf");
    const ExpectedItem second = random_file(1, ItemKind::sharepoint, "rp-canary-01.pdf", 925);
    const ExpectedSet expected = set_of({first, second});
    TargetSnapshot before;
    before.sharepoint["f-old"] = "\"c:{old},1\"";
    TargetsRead after;
    after.sharepoint.items = {file_copy(first, "f-1"), file_copy(first, "f-old", "\"c:{old},1\"")};

    const CheckResult result = verification::check(expected, before, after);

    CHECK(result.items[0].outcome == CheckOutcome::match);
    CHECK(result.items[1].outcome == CheckOutcome::error);
    CHECK(result.items[1].error_code == "stale_target");
}

TEST_CASE("check: a file is found by its name as SharePoint compares it, in its own target only",
          "[checker]")
{
    SECTION("another case, beyond ASCII too")
    {
        Scene scene;
        scene.expected.items[3].file->name = "\xc3\xa9t\xc3\xa9.pdf"; // "ete.pdf" with e-acute
        scene.after.sharepoint.items[1].name = "\xc3\x89T\xc3\x89.PDF"; // the same in upper case, E-acute
        CHECK(scene.run_one(3).outcome == CheckOutcome::match);
    }
    SECTION("a copy in the other file target isn't this one's")
    {
        Scene scene;
        FoundItem moved = scene.after.sharepoint.items[0];
        moved.type = ItemType::onedrive;
        scene.after.onedrive.items.push_back(moved);
        scene.after.sharepoint.items.erase(scene.after.sharepoint.items.begin());
        CHECK(scene.run_one(2).outcome == CheckOutcome::missing);
    }
    SECTION("a file without a name is nobody's")
    {
        Scene scene;
        scene.after.sharepoint.items[0].name.reset();
        CHECK(scene.run_one(2).outcome == CheckOutcome::missing);
    }
}

TEST_CASE("check: of several copies the newest is compared; duplicate and copies are set, the "
          "outcome isn't changed by them",
          "[checker]")
{
    SECTION("mails, by createdDateTime")
    {
        Scene scene;
        FoundItem older = scene.after.mail.items[0];
        older.id = "m-z-older";
        older.created_at = "2026-10-01T09:59:59.9Z";
        older.sha256 = kHashB; // the older one wouldn't match
        scene.after.mail.items.push_back(older);
        const ItemCheck item = scene.run_one(0);
        CHECK(item.outcome == CheckOutcome::match);
        CHECK(item.graph_id == "m-0");
        CHECK(item.duplicate);
        CHECK(item.copies == 2);
    }
    SECTION("files, by lastModifiedDateTime; the newest may mismatch")
    {
        Scene scene;
        FoundItem newer = scene.after.sharepoint.items[0];
        newer.id = "s-a-newer";
        newer.modified_at = "2026-10-01T10:00:01Z";
        newer.sha256 = kHashB;
        scene.after.sharepoint.items.push_back(newer);
        const ItemCheck item = scene.run_one(2);
        CHECK(item.outcome == CheckOutcome::mismatch);
        CHECK(item.graph_id == "s-a-newer");
        CHECK(item.duplicate);
        CHECK(item.copies == 2);
    }
    SECTION("a time that doesn't read is the oldest")
    {
        Scene scene;
        FoundItem unreadable = scene.after.sharepoint.items[0];
        unreadable.id = "s-z";
        unreadable.modified_at = "soon";
        FoundItem none = unreadable;
        none.id = "s-zz";
        none.modified_at.reset();
        scene.after.sharepoint.items.push_back(unreadable);
        scene.after.sharepoint.items.push_back(none);
        const ItemCheck item = scene.run_one(2);
        CHECK(item.graph_id == "s-2");
        CHECK(item.copies == 3);
    }
    SECTION("a tie goes to the greater ID")
    {
        Scene scene;
        FoundItem twin = scene.after.mail.items[0];
        twin.id = "m-1-twin"; // greater than "m-0"
        scene.after.mail.items.push_back(twin);
        CHECK(scene.run_one(0).graph_id == "m-1-twin");
    }
}

// --- Timing -----------------------------------------------------------------------------

TEST_CASE("check: an item's ms is its copy's read time plus its comparison's", "[checker]")
{
    Scene scene;
    std::chrono::steady_clock::time_point t{};
    scene.clock = [&t] {
        const auto now = t;
        t += std::chrono::milliseconds{7};
        return now;
    };
    scene.after.sharepoint.items[0].read_ms = 1500;

    const CheckResult result = scene.run();

    CHECK(result.items[0].ms == 7);    // a mail: the comparison only
    CHECK(result.items[2].ms == 1507); // a file: its download and hash too
}

TEST_CASE("check: an item not found has no ms", "[checker]")
{
    Scene scene;
    scene.after.mail.items.clear();
    int calls = 0;
    scene.clock = [&calls] {
        ++calls;
        return std::chrono::steady_clock::time_point{};
    };

    const CheckResult result = scene.run();

    CHECK(result.items[0].ms == 0);
    CHECK(result.items[1].ms == 0);
    // Two per item compared: the four files.
    CHECK(calls == 8);
}

// --- What check refuses -----------------------------------------------------------------

TEST_CASE("check: expected items out of index order are refused", "[checker]")
{
    const std::vector<std::vector<std::size_t>> orders{{1, 0}, {0, 0}, {1}, {0, 2}};
    const std::vector<std::size_t> order = GENERATE_COPY(from_range(orders));
    std::vector<ExpectedItem> items;
    for (const std::size_t i : order) {
        items.push_back(random_mail(i));
    }

    CHECK_THROWS_AS(verification::check(set_of(items), {}, {}), std::invalid_argument);
}

TEST_CASE("check: an expected item build_expected_set wouldn't make is a logic error",
          "[checker]")
{
    Scene scene;
    SECTION("a mail without its fields")
    {
        scene.expected.items[0].mail.reset();
    }
    SECTION("a file without its fields")
    {
        scene.expected.items[2].file.reset();
    }
    SECTION("an expected time that isn't one")
    {
        scene.expected.items[0].mail->received_at = "2026-09-24 22:14:43";
    }
    SECTION("an expected sent time that isn't one")
    {
        scene.expected.items[1].mail->sent_at = "";
    }
    SECTION("a hash rule it doesn't know")
    {
        scene.expected.items[2].sha256_rule = "bytes-v2";
    }
    CHECK_THROWS_AS(scene.run(), std::logic_error);
}

TEST_CASE("check: an empty expected set checks nothing", "[checker]")
{
    TargetsRead after;
    after.mail.items = {mail_copy(random_mail(0), "m-0")};
    const CheckResult result = verification::check(set_of({}), {}, after);
    CHECK(result.items.empty());
    CHECK(result.stale_mail == 0);
}

// --- The JSON ---------------------------------------------------------------------------

TEST_CASE("check JSON: counts, stale copies and one object per item, never a found value",
          "[checker]")
{
    Scene scene;
    std::chrono::steady_clock::time_point t{};
    scene.clock = [&t] {
        const auto now = t;
        t += std::chrono::milliseconds{2};
        return now;
    };
    // 0 match; 1 a duplicate match; 2 mismatch; 3 missing; 4 and 5 error.
    FoundItem twin = scene.after.mail.items[1];
    twin.id = "m-1-twin";
    scene.after.mail.items.push_back(twin);
    scene.after.sharepoint.items[0].sha256 = kHashB;
    scene.after.sharepoint.items[0].read_ms = 40;
    scene.after.sharepoint.items.pop_back();
    scene.after.onedrive.error_code = "graph_permission";
    scene.after.onedrive.items.clear();
    scene.before.mail.insert("m-earlier");
    FoundItem earlier = scene.after.mail.items[0];
    earlier.id = "m-earlier";
    scene.after.mail.items.push_back(earlier);

    const json out = verification::to_json(scene.run());

    const json expected = json::parse(R"json({
        "counts": {"match": 2, "mismatch": 1, "missing": 1, "error": 2},
        "stale_copies": {"mail": 1, "sharepoint": 0, "onedrive": 0},
        "items": [
            {"index": 0, "outcome": "match", "found": true, "ms": 2},
            {"index": 1, "outcome": "match", "found": true, "duplicate": true, "copies": 2,
             "ms": 2},
            {"index": 2, "outcome": "mismatch", "found": true, "mismatches": ["sha256"],
             "reason": "fields did not match: sha256", "ms": 42},
            {"index": 3, "outcome": "missing", "found": false, "reason": "no restored copy found"},
            {"index": 4, "outcome": "error", "found": false, "error_code": "graph_permission",
             "reason": "the onedrive restore target couldn't be read (graph_permission)"},
            {"index": 5, "outcome": "error", "found": false, "error_code": "graph_permission",
             "reason": "the onedrive restore target couldn't be read (graph_permission)"}
        ]
    })json");
    CHECK(out == expected);
    const std::string text = out.dump();
    CHECK_THAT(text, !ContainsSubstring("m-0"));
    CHECK_THAT(text, !ContainsSubstring("RP-CANARY"));
    CHECK_THAT(text, !ContainsSubstring("Lunch"));
}

TEST_CASE("check JSON: an empty result has every count", "[checker]")
{
    const json expected = json::parse(R"({
        "counts": {"match": 0, "mismatch": 0, "missing": 0, "error": 0},
        "stale_copies": {"mail": 0, "sharepoint": 0, "onedrive": 0},
        "items": []
    })");
    CHECK(verification::to_json(CheckResult{}) == expected);
}

TEST_CASE("check JSON: nothing is written for an item whose fields contradict its outcome",
          "[checker]")
{
    const auto match = [] {
        ItemCheck item;
        item.outcome = CheckOutcome::match;
        item.found = true;
        item.copies = 1;
        return item;
    };
    struct Row {
        std::string name;
        std::function<void(ItemCheck&)> edit;
        std::string why;
    };
    const std::vector<Row> rows{
        {"not at its index", [](ItemCheck& i) { i.index = 1; }, "isn't at its index"},
        {"match not found", [](ItemCheck& i) { i.found = false; }, "is a match"},
        {"match with mismatches", [](ItemCheck& i) { i.mismatches = {"subject"}; }, "is a match"},
        {"match with a reason", [](ItemCheck& i) { i.reason = "x"; }, "is a match"},
        {"match with a code", [](ItemCheck& i) { i.error_code = "graph"; }, "is a match"},
        {"mismatch without mismatches",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::mismatch;
             i.reason = "x";
         },
         "is a mismatch"},
        {"mismatch without a reason",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::mismatch;
             i.mismatches = {"subject"};
         },
         "is a mismatch"},
        {"mismatch with a code",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::mismatch;
             i.mismatches = {"subject"};
             i.reason = "x";
             i.error_code = "graph";
         },
         "is a mismatch"},
        {"mismatch not found",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::mismatch;
             i.mismatches = {"subject"};
             i.reason = "x";
             i.found = false;
         },
         "is a mismatch"},
        {"missing but found",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::missing;
             i.reason = "x";
         },
         "is missing"},
        {"missing without a reason",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::missing;
             i.found = false;
         },
         "is missing"},
        {"missing with a code",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::missing;
             i.found = false;
             i.reason = "x";
             i.error_code = "graph";
         },
         "is missing"},
        {"missing with mismatches",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::missing;
             i.found = false;
             i.reason = "x";
             i.mismatches = {"subject"};
         },
         "is missing"},
        {"error without a code",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::error;
             i.found = false;
             i.reason = "x";
         },
         "is an error"},
        {"error found",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::error;
             i.reason = "x";
             i.error_code = "graph";
         },
         "is an error"},
        {"error without a reason",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::error;
             i.found = false;
             i.error_code = "graph";
         },
         "is an error"},
        {"error with mismatches",
         [](ItemCheck& i) {
             i.outcome = CheckOutcome::error;
             i.found = false;
             i.reason = "x";
             i.error_code = "graph";
             i.mismatches = {"subject"};
         },
         "is an error"},
        {"a duplicate of one copy",
         [](ItemCheck& i) { i.duplicate = true; }, "is a duplicate"},
        {"a duplicate not found",
         [](ItemCheck& i) {
             i.duplicate = true;
             i.copies = 2;
             i.found = false;
         },
         "is a duplicate"},
        {"an outcome outside the enum",
         [](ItemCheck& i) { i.outcome = static_cast<CheckOutcome>(42); },
         "has an outcome outside the enum"},
    };
    const Row& row = rows[GENERATE(range(std::size_t{0}, std::size_t{20}))];
    REQUIRE(rows.size() == 20);
    CAPTURE(row.name);
    CheckResult result;
    result.items = {match()};
    REQUIRE_NOTHROW(verification::to_json(result));
    row.edit(result.items[0]);

    try {
        verification::to_json(result);
        FAIL("no logic_error");
    } catch (const std::logic_error& e) {
        CHECK_THAT(std::string{e.what()}, Catch::Matchers::StartsWith("check: item 0 " + row.why));
    }
}

TEST_CASE("check: outcomes have their names; one outside the enum is unknown", "[checker]")
{
    CHECK(verification::to_string(CheckOutcome::match) == "match");
    CHECK(verification::to_string(CheckOutcome::mismatch) == "mismatch");
    CHECK(verification::to_string(CheckOutcome::missing) == "missing");
    CHECK(verification::to_string(CheckOutcome::error) == "error");
    CHECK(verification::to_string(static_cast<CheckOutcome>(42)) == "unknown");
}

// --- The reads --------------------------------------------------------------------------

TEST_CASE("check: read_error_code names each infrastructure failure; anything else is rethrown",
          "[checker]")
{
    const auto code_of = [](auto error) {
        return verification::read_error_code(std::make_exception_ptr(error));
    };
    CHECK(code_of(rp::graph::WrongTargetError("not the RestoreTarget library")) == "target_guard");
    CHECK(code_of(rp::graph::AuthError("refused")) == "graph_auth");
    CHECK(code_of(rp::graph::PermissionError("denied", "Sites.Selected")) == "graph_permission");
    CHECK(code_of(rp::graph::TransientError("try later", 503)) == "graph_transient");
    CHECK(code_of(rp::graph::NotFoundError("no drive", 404)) == "graph");
    CHECK(code_of(rp::graph::GraphError("odd answer")) == "graph");
    CHECK(code_of(rp::graph::CertificateError("RP_GRAPH_CERT_PFX_BASE64 is not set")) == "graph");
    CHECK(code_of(rp::ConfigError("x", "bad")) == "graph");
    CHECK_THROWS_AS(code_of(std::runtime_error("SENTINEL")), std::runtime_error);
    CHECK_THROWS_AS(code_of(std::bad_alloc()), std::bad_alloc);
    CHECK_THROWS_AS(verification::read_error_code(nullptr), std::invalid_argument);
}

TEST_CASE("check: snapshot_of keeps each mail's ID and each file's ID with its cTag",
          "[checker]")
{
    TargetsRead before;
    FoundItem mail;
    mail.id = "m-1";
    before.mail.items = {mail};
    FoundItem sp;
    sp.type = ItemType::sharepoint;
    sp.id = "s-1";
    sp.ctag = "\"c:{1},1\"";
    FoundItem od;
    od.type = ItemType::onedrive;
    od.id = "o-1";
    before.sharepoint.items = {sp};
    before.onedrive.items = {od};

    const TargetSnapshot snapshot = verification::snapshot_of(before);

    CHECK(snapshot.mail == std::set<std::string>{"m-1"});
    CHECK(snapshot.sharepoint == std::map<std::string, std::optional<std::string>>{
                                     {"s-1", "\"c:{1},1\""}});
    CHECK(snapshot.onedrive ==
          std::map<std::string, std::optional<std::string>>{{"o-1", std::nullopt}});
}

TEST_CASE("check: is_new_file: a file not there before, or whose cTag moved; one cTag unknown "
          "can't show a move",
          "[checker]")
{
    using Tag = std::optional<std::string>;
    const auto [there, before_tag, after_tag, fresh] = GENERATE(table<bool, Tag, Tag, bool>({
        {false, std::nullopt, std::nullopt, true},
        {false, std::nullopt, Tag{"\"c:{1},1\""}, true},
        {true, Tag{"\"c:{1},1\""}, Tag{"\"c:{1},2\""}, true},
        {true, Tag{"\"c:{1},1\""}, Tag{"\"c:{1},1\""}, false},
        {true, std::nullopt, Tag{"\"c:{1},1\""}, false},
        {true, Tag{"\"c:{1},1\""}, std::nullopt, false},
        {true, std::nullopt, std::nullopt, false},
    }));
    const ItemType type = GENERATE(ItemType::sharepoint, ItemType::onedrive);
    CAPTURE(there, before_tag, after_tag, rp::graph::to_string(type));
    TargetSnapshot before;
    FoundItem file;
    file.type = type;
    file.id = "f-1";
    file.ctag = after_tag;
    if (there) {
        (type == ItemType::sharepoint ? before.sharepoint : before.onedrive)["f-1"] = before_tag;
        // The same ID in the other target says nothing about this one.
        (type == ItemType::sharepoint ? before.onedrive : before.sharepoint)["f-2"] = before_tag;
    } else {
        (type == ItemType::sharepoint ? before.onedrive : before.sharepoint)["f-1"] = before_tag;
    }

    CHECK(verification::is_new_file(before, file) == fresh);
}

TEST_CASE("check: is_new_file refuses a mail", "[checker]")
{
    FoundItem mail;
    mail.id = "m-1";
    CHECK_THROWS_AS(verification::is_new_file({}, mail), std::logic_error);
}

TEST_CASE("check: hash_filter takes only this run's files with an expected name of their type",
          "[checker]")
{
    const ExpectedSet expected =
        set_of({canary_mail(0), canary_file(1, ItemKind::sharepoint, "rp-canary-01.pdf"),
                random_file(2, ItemKind::onedrive, "\xc3\xa9t\xc3\xa9.pdf")});
    TargetSnapshot before;
    before.sharepoint["s-old"] = "\"c:{old},1\"";
    before.sharepoint["s-moved"] = "\"c:{moved},1\"";
    const auto file = [](ItemType type, const std::string& id, const std::string& name,
                         const std::string& ctag) {
        FoundItem item;
        item.type = type;
        item.id = id;
        item.name = name;
        item.ctag = ctag;
        return item;
    };
    struct Row {
        std::string what;
        FoundItem item;
        bool hashed;
    };
    const std::vector<Row> rows{
        {"new, expected name", file(ItemType::sharepoint, "s-new", "rp-canary-01.pdf", "\"c:{n},1\""),
         true},
        {"new, the name in another case", file(ItemType::sharepoint, "s-new", "RP-CANARY-01.PDF", "x"),
         true},
        {"new, beyond ASCII case", file(ItemType::onedrive, "o-new", "\xc3\x89T\xc3\x89.PDF", "x"),
         true},
        {"cTag moved", file(ItemType::sharepoint, "s-moved", "rp-canary-01.pdf", "\"c:{moved},2\""),
         true},
        {"an earlier run's copy", file(ItemType::sharepoint, "s-old", "rp-canary-01.pdf", "\"c:{old},1\""),
         false},
        {"new, a name nobody expects", file(ItemType::sharepoint, "s-x", "leftover.pdf", "x"), false},
        {"new, the other type's name", file(ItemType::sharepoint, "s-x", "\xc3\xa9t\xc3\xa9.pdf", "x"),
         false},
        {"new, the mail's subject", file(ItemType::onedrive, "o-x", "RP-CANARY-0001", "x"), false},
    };
    const auto hash = verification::hash_filter(expected, before);
    for (const Row& row : rows) {
        CAPTURE(row.what);
        CHECK(hash(row.item) == row.hashed);
    }
    FoundItem unnamed = rows[0].item;
    unnamed.name.reset();
    CHECK_FALSE(hash(unnamed));
    // A mail has no bytes to hash: never one of the files.
    FoundItem mail = rows[0].item;
    mail.type = ItemType::mail;
    CHECK_FALSE(hash(mail));
}

TEST_CASE("check: hash_filter never downloads a random Office file, which carries no size or "
          "hash to compare",
          "[checker]")
{
    const ExpectedSet expected =
        set_of({random_file(0, ItemKind::sharepoint, "plan.docx", std::nullopt),
                random_file(1, ItemKind::onedrive, "notes.pdf"),
                canary_file(2, ItemKind::onedrive, "rp-canary-02.docx", "office-v1")});
    const auto hash = verification::hash_filter(expected, {});
    const auto file = [](ItemType type, const std::string& name) {
        FoundItem item;
        item.type = type;
        item.id = "new-" + name;
        item.name = name;
        return item;
    };
    CHECK_FALSE(hash(file(ItemType::sharepoint, "plan.docx")));
    CHECK(hash(file(ItemType::onedrive, "notes.pdf")));
    CHECK(hash(file(ItemType::onedrive, "rp-canary-02.docx")));
}

TEST_CASE("check: hash_filter keeps its own copy of what it was given", "[checker]")
{
    std::function<bool(const FoundItem&)> hash;
    {
        const ExpectedSet expected = set_of({canary_file(0, ItemKind::sharepoint, "a.pdf")});
        const TargetSnapshot before;
        hash = verification::hash_filter(expected, before);
    }
    FoundItem item;
    item.type = ItemType::sharepoint;
    item.id = "s-1";
    item.name = "a.pdf";
    CHECK(hash(item));
}

TEST_CASE("check: office_hook hashes each docx and xlsx by office-v1 into its type's read, and "
          "keeps a refusal instead of throwing",
          "[checker]")
{
    TargetsRead after;
    const auto hook = verification::office_hook(after);
    const std::string docx = read_file(canary_path("rp-canary-02.docx"));
    const std::string xlsx = read_file(canary_path("rp-canary-03.xlsx"));
    const auto file = [](ItemType type, const std::string& id, const std::string& name) {
        FoundItem item;
        item.type = type;
        item.id = id;
        item.name = name;
        return item;
    };

    hook(file(ItemType::sharepoint, "s-docx", "Report.DOCX"), docx);
    hook(file(ItemType::onedrive, "o-xlsx", "book.xlsx"), xlsx);
    hook(file(ItemType::onedrive, "o-broken", "broken.docx"), "not a zip");
    hook(file(ItemType::sharepoint, "s-pdf", "rp-canary-01.pdf"), "pdf bytes");
    hook(file(ItemType::sharepoint, "s-pptx", "deck.pptx"), docx);
    hook(file(ItemType::sharepoint, "s-bare", ".docx"), docx);
    FoundItem unnamed = file(ItemType::sharepoint, "s-unnamed", "");
    unnamed.name.reset();
    hook(unnamed, docx);

    CHECK(after.sharepoint.office.size() == 1);
    CHECK(after.sharepoint.office.at("s-docx").sha256 == rp::office_v1_sha256(docx, "docx"));
    CHECK(after.sharepoint.office.at("s-docx").error.empty());
    REQUIRE(after.onedrive.office.size() == 2);
    CHECK(after.onedrive.office.at("o-xlsx").sha256 == rp::office_v1_sha256(xlsx, "xlsx"));
    CHECK(after.onedrive.office.at("o-broken").sha256.empty());
    CHECK_FALSE(after.onedrive.office.at("o-broken").error.empty());
    CHECK(after.mail.office.empty());
    CHECK_THROWS_AS(hook(file(ItemType::mail, "m-1", "x.docx"), docx), std::logic_error);
}

TEST_CASE("check: an office-v1 canary checked end to end from the canary's own bytes",
          "[checker]")
{
    const std::string docx = read_file(canary_path("rp-canary-02.docx"));
    const ExpectedSet expected = set_of({canary_file(0, ItemKind::sharepoint, "rp-canary-02.docx",
                                                     "office-v1",
                                                     rp::office_v1_sha256(docx, "docx"))});
    TargetsRead after;
    FoundItem copy = file_copy(expected.items[0], "s-0");
    copy.sha256 = rp::sha256_hex(docx);
    after.sharepoint.items = {copy};
    verification::office_hook(after)(copy, docx);

    const CheckResult result = verification::check(expected, {}, after);

    CHECK(result.items[0].outcome == CheckOutcome::match);
}
