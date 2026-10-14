// W6.3 (#183): a random file's content against the backup's own copy
// (rp/backup_content.hpp; docs/decisions.md 2026-10-14, W6.3 and W6.2,
// points 3 to 5): the rule by name, the hasher the connector hands the
// exported bytes to, which files ask for their content, and how the exports
// raise an expectation from metadata to backup_content before the read back.
// The Office packages are the office-content-v1 vectors (canary content, ours),
// never a tenant file. Failure paths first.

#include "target_guard_lab.hpp"

#include <rp/backup_content.hpp>
#include <rp/canary_manifest.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/result_schema.hpp>
#include <rp/sample_selector.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace connector = rp::connector;
namespace lab = rp::test::target_guard_lab;
namespace verification = rp::verification;
using connector::ContentOutcome;
using connector::ItemKind;
using nlohmann::json;
using rp::sampling::ContentRule;
using rp::sampling::Selection;
using verification::ContentDigest;
using verification::ContentDigests;
using verification::ExpectedKind;
using verification::ExpectedSet;

constexpr std::string_view kRunId = "run-0001";
const std::string kCarol = "carol@RestoreProofLab.onmicrosoft.com";

std::string vector_file(const std::string& name)
{
    const std::filesystem::path path =
        std::filesystem::path{RP_SHARED_DIR} / "testdata" / "office-content-v1" / name;
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

const std::string& docx_bytes()
{
    static const std::string bytes = vector_file("rp-canary-02.local.docx");
    return bytes;
}
// The vectors' office-v1 of that docx (office-content-v1/cases.json).
const std::string kDocxOfficeV1 = "5540efd7b59d4573f6dacbeaace49561ac0e86b0ff29edd7c76a8f4b5342f30b";

const connector::RestoreTargets& targets()
{
    static const connector::RestoreTargets t =
        connector::RestoreTargets::from_config(lab::lab_config());
    return t;
}

connector::SharePointCandidate sp_file(int n, const std::string& name, std::int64_t size)
{
    connector::SharePointSelector s = lab::sharepoint_source(n);
    s.folder_path = "/Projects";
    s.name = name;
    return {s, size};
}

connector::OneDriveCandidate od_file(const std::string& name, std::int64_t size)
{
    return {{kCarol, "/Projects", name}, size};
}

// A sample without canaries of three SharePoint files (a pdf, a docx, a pptx)
// and one OneDrive txt, and its expected set.
struct World {
    World()
    {
        connector::CandidatePool pool;
        pool.sharepoint = {sp_file(1, "plan.pdf", 900), sp_file(2, "notes.docx", 3230),
                           sp_file(3, "deck.pptx", 5000)};
        pool.onedrive = {od_file("list.txt", 60)};
        selection = rp::sampling::SampleSelector::select({0, 3, 1}, nullptr, {}, targets(), pool,
                                                         kRunId);
        expected = verification::build_expected_set(selection, nullptr);
        REQUIRE(expected.items.size() == 4);
    }
    // The set's item index of the file named `name`.
    std::size_t item(const std::string& name) const
    {
        for (const verification::ExpectedItem& i : expected.items) {
            if (i.file && i.file->name == name) {
                return i.index;
            }
        }
        FAIL("no item " << name);
        return 0;
    }
    // Its index among its kind's selectors.
    std::pair<ItemKind, std::size_t> place(const std::string& name) const
    {
        for (std::size_t i = 0; i < selection.sharepoint.size(); ++i) {
            if (selection.sharepoint[i].name == name) {
                return {ItemKind::sharepoint, i};
            }
        }
        for (std::size_t i = 0; i < selection.onedrive.size(); ++i) {
            if (selection.onedrive[i].name == name) {
                return {ItemKind::onedrive, i};
            }
        }
        FAIL("no selector " << name);
        return {};
    }
    connector::ContentExport exported(const std::string& name, ContentOutcome outcome,
                                      std::int64_t size = -1) const
    {
        const auto [kind, index] = place(name);
        return {kind, index, outcome, outcome == ContentOutcome::exported ? size : -1, 7};
    }
    Selection selection;
    ExpectedSet expected;
};

ContentDigest digest_of(std::string_view bytes, bool office)
{
    ContentDigest d;
    d.size_bytes = static_cast<std::int64_t>(bytes.size());
    d.sha256 = rp::sha256_hex(bytes);
    if (office) {
        d.office_v1 = kDocxOfficeV1;
    }
    return d;
}

std::string thrown_by(const std::function<void()>& call)
{
    try {
        call();
    } catch (const std::logic_error& e) {
        return e.what();
    }
    return "none";
}

} // namespace

// ---- the rule by name ----------------------------------------------------------------

TEST_CASE("content_rule: office-v1 for docx and xlsx, none for the rest SharePoint rewrites, "
          "bytes for every other name",
          "[backup_content][w6.3]")
{
    const auto [name, rule] = GENERATE(table<std::string, std::optional<ContentRule>>({
        {"a.pdf", ContentRule::bytes},
        {"a.txt", ContentRule::bytes},
        {"a.png", ContentRule::bytes},
        {"no extension", ContentRule::bytes},
        {"drawing.vsdx", ContentRule::bytes},
        {"a.odt", ContentRule::bytes},
        {"a.docx", ContentRule::office_v1},
        {"A.DOCX", ContentRule::office_v1},
        {"sheet.Xlsx", ContentRule::office_v1},
        // A name that is only an extension is no package (office_files.hpp's rule).
        {".docx", ContentRule::bytes},
        {"deck.pptx", std::nullopt},
        {"macro.docm", std::nullopt},
        {"macro.xlsm", std::nullopt},
        {"template.dotx", std::nullopt},
        {"binary.xlsb", std::nullopt},
        {"old.doc", std::nullopt},
        {"old.xls", std::nullopt},
        {"old.ppt", std::nullopt},
    }));
    CAPTURE(name);
    CHECK(verification::content_rule(name) == rule);
}

// ---- the hasher ----------------------------------------------------------------------

TEST_CASE("the hasher refuses content the spec has no file for", "[backup_content][w6.3]")
{
    verification::ContentHasher hasher({"a.pdf"}, {});
    CHECK(thrown_by([&] { hasher.on_content(ItemKind::sharepoint, 1, "x"); }) ==
          "backup content: content for sharepoint item 1, which the spec doesn't have");
    CHECK(thrown_by([&] { hasher.on_content(ItemKind::onedrive, 0, "x"); }) ==
          "backup content: content for onedrive item 0, which the spec doesn't have");
    CHECK(thrown_by([&] { hasher.on_content(ItemKind::mail, 0, "x"); }) ==
          "backup content: content for mail item 0, which the spec doesn't have");
    CHECK(hasher.digests().empty());
}

TEST_CASE("the hasher keeps each file's size and SHA-256, and office-v1 for a docx or xlsx",
          "[backup_content][w6.3]")
{
    verification::ContentHasher hasher({"a.pdf", "b.docx", "broken.xlsx"}, {"c.txt"});

    hasher.on_content(ItemKind::sharepoint, 0, "%PDF-1.4 x");
    hasher.on_content(ItemKind::sharepoint, 1, docx_bytes());
    hasher.on_content(ItemKind::sharepoint, 2, "not a package");
    hasher.on_content(ItemKind::onedrive, 0, "");

    const ContentDigests d = hasher.digests();
    REQUIRE(d.size() == 4);
    const ContentDigest& pdf = d.at({ItemKind::sharepoint, 0});
    CHECK(pdf.size_bytes == 10);
    CHECK(pdf.sha256 == rp::sha256_hex("%PDF-1.4 x"));
    CHECK(pdf.office_v1.empty());
    CHECK_FALSE(pdf.office_invalid);
    const ContentDigest& docx = d.at({ItemKind::sharepoint, 1});
    CHECK(docx.sha256 == rp::sha256_hex(docx_bytes()));
    CHECK(docx.office_v1 == kDocxOfficeV1);
    CHECK_FALSE(docx.office_invalid);
    const ContentDigest& broken = d.at({ItemKind::sharepoint, 2});
    CHECK(broken.office_v1.empty());
    CHECK(broken.office_invalid);
    const ContentDigest& empty = d.at({ItemKind::onedrive, 0});
    CHECK(empty.size_bytes == 0);
    CHECK(empty.sha256 == rp::sha256_hex(""));
}

// ---- which files ask -----------------------------------------------------------------

TEST_CASE("mark_wanted asks for every random file with a content rule, never a canary or a mail",
          "[backup_content][w6.3]")
{
    connector::RestoreSpec spec{.client_ref = "c",
                                .restore_point = {},
                                .targets = targets(),
                                .mail = {{"alice@x", "Inbox", "s"}},
                                .sharepoint = {{"s", "d", "/", "rp-canary-01.pdf"},
                                               {"s", "d", "/", "plan.pdf"},
                                               {"s", "d", "/", "deck.pptx"},
                                               {"s", "d", "/", "notes.docx"}},
                                .onedrive = {{"alice@x", "/", "list.txt"}}};
    rp::sampling::SampleRecord record;
    record.sharepoint.canary_ids = {"rp-canary-01.pdf"};

    CHECK(verification::mark_wanted(spec, record) == 3);

    CHECK_FALSE(spec.sharepoint[0].want_content); // a canary: the manifest's hash
    CHECK(spec.sharepoint[1].want_content);
    CHECK_FALSE(spec.sharepoint[2].want_content); // no content rule
    CHECK(spec.sharepoint[3].want_content);
    CHECK(spec.onedrive[0].want_content);
    CHECK(spec.content_count() == 3);
}

// ---- raising the expectation ---------------------------------------------------------

TEST_CASE("add_backup_content refuses facts that don't add up, and changes nothing then",
          "[backup_content][w6.3]")
{
    struct Row {
        std::string what;
        std::function<void(const World&, connector::RestoreResult&, ContentDigests&)> edit;
        std::string message;
    };
    const auto all_exported = [](const World& w, connector::RestoreResult& r, ContentDigests& d) {
        r.content = {w.exported("plan.pdf", ContentOutcome::exported, 900),
                     w.exported("notes.docx", ContentOutcome::exported, 3230),
                     w.exported("list.txt", ContentOutcome::exported, 60)};
        d[w.place("plan.pdf")] = digest_of(std::string(900, 'p'), false);
        d[w.place("notes.docx")] = digest_of(docx_bytes(), true);
        d[w.place("list.txt")] = digest_of(std::string(60, 't'), false);
    };
    const Row row = GENERATE_COPY(values<Row>({
        {"an export for a file of no rule",
         [=](const World& w, connector::RestoreResult& r, ContentDigests& d) {
             all_exported(w, r, d);
             r.content.push_back(w.exported("deck.pptx", ContentOutcome::refused));
         },
         "backup content: export 3 is for a file without a content rule"},
        {"an export for an index the set hasn't",
         [=](const World& w, connector::RestoreResult& r, ContentDigests& d) {
             all_exported(w, r, d);
             r.content.push_back({ItemKind::onedrive, 5, ContentOutcome::refused, -1, 0});
         },
         "backup content: export 3 is for no random file of the set"},
        {"a second export of one file",
         [=](const World& w, connector::RestoreResult& r, ContentDigests& d) {
             all_exported(w, r, d);
             r.content.push_back(w.exported("plan.pdf", ContentOutcome::exported, 900));
         },
         "backup content: export 3 is a second one for its file"},
        {"an exported file without its digest",
         [=](const World& w, connector::RestoreResult& r, ContentDigests& d) {
             all_exported(w, r, d);
             d.erase(w.place("list.txt"));
         },
         "backup content: export 2 has no digest"},
        {"a digest of a file that wasn't exported",
         [=](const World& w, connector::RestoreResult& r, ContentDigests& d) {
             all_exported(w, r, d);
             r.content[0].outcome = ContentOutcome::refused;
         },
         "backup content: export 0 has a digest but wasn't exported"},
        {"a digest without an export",
         [=](const World& w, connector::RestoreResult& r, ContentDigests& d) {
             all_exported(w, r, d);
             r.content.pop_back();
             d.erase(w.place("list.txt"));
             d[w.place("deck.pptx")] = digest_of("x", false);
         },
         // Which selector the pptx is depends on the draw: the prefix is held.
         "backup content: a digest of sharepoint item *"},
        {"a file with a rule and no export",
         [=](const World& w, connector::RestoreResult& r, ContentDigests& d) {
             all_exported(w, r, d);
             r.content.pop_back();
             d.erase(w.place("list.txt"));
         },
         "backup content: item 3 has a content rule and no export"},
    }));
    CAPTURE(row.what);
    World w;
    connector::RestoreResult result;
    ContentDigests digests;
    row.edit(w, result, digests);
    const json before = verification::to_json(w.expected);

    const std::string thrown =
        thrown_by([&] { verification::add_backup_content(w.expected, result, digests); });
    if (row.message.ends_with('*')) {
        CHECK(thrown.starts_with(row.message.substr(0, row.message.size() - 1)));
        CHECK(thrown.ends_with(" has no export"));
    } else {
        CHECK(thrown == row.message);
    }
    CHECK(verification::to_json(w.expected) == before);
}

TEST_CASE("add_backup_content raises each exported file to backup_content by its rule, and "
          "words every other random file",
          "[backup_content][w6.3]")
{
    World w;
    connector::RestoreResult result;
    result.content = {w.exported("plan.pdf", ContentOutcome::exported, 900),
                      w.exported("notes.docx", ContentOutcome::exported, 3230),
                      w.exported("list.txt", ContentOutcome::no_answer)};
    ContentDigests digests;
    const std::string pdf(900, 'p');
    digests[w.place("plan.pdf")] = digest_of(pdf, false);
    digests[w.place("notes.docx")] = digest_of(docx_bytes(), true);

    verification::add_backup_content(w.expected, result, digests);

    const auto& pdf_item = w.expected.items[w.item("plan.pdf")];
    CHECK(pdf_item.expected_kind == ExpectedKind::backup_content);
    CHECK(pdf_item.sha256 == rp::sha256_hex(pdf));
    CHECK(pdf_item.sha256_rule == "bytes");
    CHECK(pdf_item.file->size_bytes == 900);
    CHECK(pdf_item.export_word == "exported");
    const auto& docx_item = w.expected.items[w.item("notes.docx")];
    CHECK(docx_item.expected_kind == ExpectedKind::backup_content);
    CHECK(docx_item.sha256 == kDocxOfficeV1);
    CHECK(docx_item.sha256_rule == "office-v1");
    CHECK_FALSE(docx_item.file->size_bytes.has_value()); // SharePoint rewrites it
    const auto& pptx_item = w.expected.items[w.item("deck.pptx")];
    CHECK(pptx_item.expected_kind == ExpectedKind::metadata);
    CHECK(pptx_item.export_word == "no_rule");
    CHECK(pptx_item.sha256.empty());
    const auto& txt_item = w.expected.items[w.item("list.txt")];
    CHECK(txt_item.expected_kind == ExpectedKind::metadata);
    CHECK(txt_item.export_word == "no_answer");
    CHECK(txt_item.sha256.empty());
    CHECK(txt_item.file->size_bytes == 60); // the backup's listed size, as before
    // What the result says: the four kinds counted, every word written.
    const json out = verification::to_json(w.expected);
    CHECK(out.at("counts") ==
          json{{"manifest", 0}, {"fields", 0}, {"metadata", 2}, {"backup_content", 2}});
    CHECK(out.at("items").at(w.item("plan.pdf")).at("export") == "exported");
    CHECK(out.at("items").at(w.item("deck.pptx")).at("export") == "no_rule");
    CHECK(out.at("items").at(w.item("list.txt")).at("export") == "no_answer");
    CHECK_FALSE(out.at("items").at(w.item("notes.docx")).contains("size_bytes"));
}

TEST_CASE("add_backup_content: every way an export gives nothing leaves the file metadata with "
          "its word",
          "[backup_content][w6.3]")
{
    const auto [outcome, word] = GENERATE(table<ContentOutcome, std::string>({
        {ContentOutcome::refused, "refused"},
        {ContentOutcome::no_answer, "no_answer"},
        {ContentOutcome::size_mismatch, "size_mismatch"},
        {ContentOutcome::over_cap, "over_cap"},
        {ContentOutcome::not_in_backup, "not_in_backup"},
        {ContentOutcome::budget, "budget"},
    }));
    CAPTURE(word);
    World w;
    connector::RestoreResult result;
    result.content = {w.exported("plan.pdf", outcome), w.exported("notes.docx", outcome),
                      w.exported("list.txt", outcome)};

    verification::add_backup_content(w.expected, result, {});

    for (const std::string name : {"plan.pdf", "notes.docx", "list.txt"}) {
        CAPTURE(name);
        const auto& item = w.expected.items[w.item(name)];
        CHECK(item.expected_kind == ExpectedKind::metadata);
        CHECK(item.export_word == word);
        CHECK(item.sha256.empty());
    }
    CHECK(verification::to_json(w.expected).at("counts").at("backup_content") == 0);
}

TEST_CASE("add_backup_content: an exported docx office-v1 refuses stays metadata, "
          "invalid_package",
          "[backup_content][w6.3]")
{
    World w;
    connector::RestoreResult result;
    result.content = {w.exported("plan.pdf", ContentOutcome::refused),
                      w.exported("notes.docx", ContentOutcome::exported, 13),
                      w.exported("list.txt", ContentOutcome::refused)};
    ContentDigests digests;
    ContentDigest bad = digest_of("not a package", false);
    bad.office_invalid = true;
    digests[w.place("notes.docx")] = bad;

    verification::add_backup_content(w.expected, result, digests);

    const auto& item = w.expected.items[w.item("notes.docx")];
    CHECK(item.expected_kind == ExpectedKind::metadata);
    CHECK(item.export_word == "invalid_package");
    CHECK(item.sha256.empty());
}

TEST_CASE("add_backup_content leaves canaries and mails alone", "[backup_content][w6.3]")
{
    static const rp::sampling::CanaryManifest manifest = rp::sampling::load_canary_manifest(
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json");
    connector::CandidatePool pool;
    pool.sharepoint = {sp_file(1, "plan.pdf", 900)};
    const Selection s =
        rp::sampling::SampleSelector::select({1, 2, 0}, &manifest, {}, targets(), pool, kRunId);
    ExpectedSet expected = verification::build_expected_set(s, &manifest);
    const json before = verification::to_json(expected);
    REQUIRE(s.sharepoint.size() == 2); // one canary, then the random pdf
    connector::RestoreResult result;
    result.content = {{ItemKind::sharepoint, 1, ContentOutcome::refused, -1, 3}};

    verification::add_backup_content(expected, result, {});

    for (const auto& item : expected.items) {
        CAPTURE(item.index);
        if (item.source == verification::ItemSource::canary) {
            CHECK(item.export_word.empty());
            CHECK(item.expected_kind == ExpectedKind::manifest);
        }
    }
    CHECK(expected.items.back().export_word == "refused");
    // A canary's export is refused as no random file's.
    result.content = {{ItemKind::sharepoint, 0, ContentOutcome::refused, -1, 3}};
    ExpectedSet again = verification::build_expected_set(s, &manifest);
    CHECK(thrown_by([&] { verification::add_backup_content(again, result, {}); }) ==
          "backup content: export 0 is for no random file of the set");
    CHECK(verification::to_json(again) == before);
}

TEST_CASE("content_exports_line counts the exports by word, and is empty when none was asked",
          "[backup_content][w6.3]")
{
    connector::RestoreResult result;
    CHECK(verification::content_exports_line(result).empty());
    result.content = {{ItemKind::sharepoint, 0, ContentOutcome::exported, 9, 1},
                      {ItemKind::sharepoint, 1, ContentOutcome::budget, -1, 0},
                      {ItemKind::onedrive, 0, ContentOutcome::refused, -1, 2},
                      {ItemKind::onedrive, 1, ContentOutcome::refused, -1, 2}};
    CHECK(verification::content_exports_line(result) ==
          "content exports: 1 of 4 file(s) exported from the backup (refused 2, budget 1)\n");
    result.content = {{ItemKind::onedrive, 0, ContentOutcome::exported, 9, 1}};
    CHECK(verification::content_exports_line(result) ==
          "content exports: 1 of 1 file(s) exported from the backup\n");
}
