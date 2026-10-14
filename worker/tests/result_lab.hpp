#pragma once

// The result tests' hand-made run (W4.1): one of every item shape, restored,
// matched and cleaned, so the document ResultBuilder makes from it holds every
// part of restoreproof.result.v1. (shared/testdata/result-v1/valid.json is
// the whole pipeline's own run, tests/test_command_test.cpp.)

#include <rp/checker.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/restore_command.hpp>
#include <rp/result_builder.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_selector.hpp>
#include <rp/step_timer.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace rp::test {

// A file under shared/, byte for byte.
inline std::string read_shared(const std::string& relative)
{
    const std::string path = std::string{RP_SHARED_DIR} + "/" + relative;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read " + path);
    }
    return std::string{std::istreambuf_iterator<char>(file), {}};
}

// What a run hands the builder. parts() borrows from this object: keep it
// alive, and where it is, for as long as the parts are used.
struct ResultFacts {
    sampling::SampleRecord sample;
    verification::ExpectedSet expected;
    connector::RestoreResult restore;
    verification::CheckResult check;
    verification::RunVerdict verdict;
    RunCleanup cleanup;
    timing::RunTimings timings;

    ResultParts parts() const
    {
        ResultParts parts;
        parts.worker_version = "0.0.0";
        parts.run_id = "rp-20261004T100000Z-0a1b2c3d";
        parts.started_at = "2026-10-04T10:00:00.125Z";
        parts.ended_at = "2026-10-04T10:04:09.500Z";
        parts.connector = {"veeam_m365", "v8"};
        parts.client = {.tenant_id = "11111111-2222-3333-4444-555555555555",
                        .veeam_org_name = "contoso.onmicrosoft.com",
                        .mailbox = "restoretest@contoso.example",
                        .site_id = "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
                                   "aaaaaaaa-0000-0000-0000-000000000002",
                        .library_id = "b!library",
                        .onedrive_drive_id = "b!onedrive",
                        .onedrive_folder_id = "01FOLDER"};
        parts.restore_point_id = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100";
        parts.restore_point_time = "2026-10-03T22:00:45.6603083Z";
        parts.sample = &sample;
        parts.expected = &expected;
        parts.restore = &restore;
        parts.check = &check;
        parts.verdict = &verdict;
        parts.cleanup = &cleanup;
        parts.timings = &timings;
        return parts;
    }
};

inline const std::string kLabManifestSha256(64, 'a');

// Two items per type, a canary and a random one: a canary mail (text-v1), a
// random mail with Veeam's sender name and sent time, an office-v1 and a
// sized random SharePoint file, a `bytes` and an unsized random OneDrive
// file. All restored and matched, the random SharePoint file twice.
inline ResultFacts full_result_facts()
{
    using connector::ItemKind;
    using verification::ExpectedFile;
    using verification::ExpectedItem;
    using verification::ExpectedKind;
    using verification::ExpectedMail;
    using verification::ItemSource;

    ResultFacts facts;

    const std::vector<std::string> mail_key = {"alice@contoso.example", "Inbox",
                                               "Quarterly figures", "2026-09-30T07:15:00Z"};
    const std::vector<std::string> sharepoint_key = {
        "contoso.sharepoint.com,cccccccc-0000-0000-0000-000000000001,"
        "cccccccc-0000-0000-0000-000000000002",
        "dddddddd-0000-0000-0000-000000000001", "/Reports", "Budget 2026.pdf"};
    // A name outside ASCII (U+00DC as UTF-8), so the canonical text holds one.
    const std::string umlaut_name = "\xC3\x9C" "bersicht.docx";
    const std::vector<std::string> onedrive_key = {"bob@contoso.example", "/Notes", umlaut_name};

    sampling::SampleRecord& sample = facts.sample;
    sample.run_id = "rp-20261004T100000Z-0a1b2c3d";
    sample.seed = 0x6138257d;
    sample.canaries = true;
    sample.manifest_sha256 = kLabManifestSha256;
    const auto kind = [](std::string canary, std::vector<std::string> key, std::string container) {
        sampling::KindRecord record;
        record.requested = 2;
        record.cursor = 3;
        record.cursor_next = 4;
        record.canary_wanted = 1;
        record.canary_ids = {std::move(canary)};
        record.random_wanted = 1;
        record.random_taken = 1;
        record.pool_size = 7;
        record.pool_sha256 = std::string(64, 'b');
        record.random_keys = {std::move(key)};
        record.browse.containers_eligible = 4;
        record.browse.containers_listed = {std::move(container)};
        record.browse.containers_unresolved = 0;
        record.browse.folders_listed = 2;
        return record;
    };
    sample.mail = kind("canary-mail-04", mail_key, "alice@contoso.example");
    sample.sharepoint = kind("canary-sp-04.docx", sharepoint_key, sharepoint_key[0]);
    sample.onedrive = kind("canary-od-04.txt", onedrive_key, "bob@contoso.example");
    sample.onedrive.browse.containers_unresolved = 1;
    sample.onedrive.browse.short_of_containers = true;

    verification::ExpectedSet& expected = facts.expected;
    expected.canaries = true;
    expected.manifest_sha256 = kLabManifestSha256;
    expected.canaries_seeded_at = "2026-09-25T09:00:00Z";
    const auto item = [&](ItemKind item_kind, ItemSource source, ExpectedKind expected_kind) {
        ExpectedItem out;
        out.index = expected.items.size();
        out.kind = item_kind;
        out.source = source;
        out.expected_kind = expected_kind;
        return out;
    };
    {
        ExpectedItem canary = item(ItemKind::mail, ItemSource::canary, ExpectedKind::manifest);
        canary.canary_id = "canary-mail-04";
        canary.mail = ExpectedMail{"canary-mail-04",         "seeder@contoso.example",
                                   std::nullopt,             "2026-09-25T08:59:58Z",
                                   "2026-09-25T09:00:01Z",   "<canary-mail-04@contoso.example>"};
        canary.sha256 = std::string(64, 'c');
        canary.sha256_rule = "text-v1";
        expected.items.push_back(canary);

        ExpectedItem random = item(ItemKind::mail, ItemSource::random, ExpectedKind::fields);
        random.random_key = mail_key;
        random.mail = ExpectedMail{"Quarterly figures",    std::nullopt, "Carol Example",
                                   "2026-09-30T07:14:58Z", "2026-09-30T07:15:00Z", std::nullopt};
        expected.items.push_back(random);
    }
    {
        ExpectedItem canary =
            item(ItemKind::sharepoint, ItemSource::canary, ExpectedKind::manifest);
        canary.canary_id = "canary-sp-04.docx";
        canary.file = ExpectedFile{"canary-sp-04.docx", std::nullopt};
        canary.sha256 = std::string(64, 'd');
        canary.sha256_rule = "office-v1";
        expected.items.push_back(canary);

        ExpectedItem random =
            item(ItemKind::sharepoint, ItemSource::random, ExpectedKind::metadata);
        random.random_key = sharepoint_key;
        random.file = ExpectedFile{"Budget 2026.pdf", 48213};
        expected.items.push_back(random);
    }
    {
        ExpectedItem canary = item(ItemKind::onedrive, ItemSource::canary, ExpectedKind::manifest);
        canary.canary_id = "canary-od-04.txt";
        canary.file = ExpectedFile{"canary-od-04.txt", 1024};
        canary.sha256 = std::string(64, 'e');
        canary.sha256_rule = "bytes";
        expected.items.push_back(canary);

        ExpectedItem random = item(ItemKind::onedrive, ItemSource::random, ExpectedKind::metadata);
        random.random_key = onedrive_key;
        random.file = ExpectedFile{umlaut_name, std::nullopt};
        expected.items.push_back(random);
    }

    connector::RestoreResult& restore = facts.restore;
    restore.status = connector::RestoreStatus::succeeded;
    restore.items_sent = 6;
    restore.items_restored = 6;
    const auto session = [&](std::string id, ItemKind session_kind, std::string details) {
        connector::RestoreSessionResult out;
        out.id = id;
        out.kind = session_kind;
        out.result = "Success";
        out.details = std::move(details);
        out.started_at = "2026-10-04T10:00:40.1234567Z";
        out.ended_at = "2026-10-04T10:01:10.25Z";
        out.items_sent = 2;
        out.items_restored = 2;
        restore.sessions.push_back(out);
        restore.session_ids.push_back(id);
        for (int i = 0; i < 2; ++i) {
            connector::ItemRestoreResult restored;
            restored.kind = session_kind;
            restored.session_id = id;
            restored.outcome = connector::ItemOutcome::restored;
            restore.items.push_back(restored);
        }
    };
    session("5a1c0000-0000-0000-0000-000000000001", ItemKind::mail,
            "2 items processed (2 successes)");
    session("5a1c0000-0000-0000-0000-000000000002", ItemKind::sharepoint,
            "2 items processed (2 successes)");
    // Details that aren't the backup's counts are written as null.
    session("5a1c0000-0000-0000-0000-000000000003", ItemKind::onedrive, "");

    verification::CheckResult& check = facts.check;
    for (const ExpectedItem& want : expected.items) {
        verification::ItemCheck found;
        found.index = want.index;
        found.kind = want.kind;
        found.outcome = verification::CheckOutcome::match;
        found.found = true;
        found.copies = 1;
        found.ms = 120 + static_cast<std::int64_t>(want.index);
        check.items.push_back(found);
    }
    check.items[3].duplicate = true;
    check.items[3].copies = 2;

    verification::RunFacts run;
    run.expected = &expected;
    run.restore = &restore;
    run.check = &check;
    run.restore_point_time = "2026-10-03T22:00:45.6603083Z";
    facts.verdict = verification::decide_status(run);

    const auto cleaned = [](graph::CleanupWhen when, std::size_t each) {
        graph::CleanupResult out;
        out.when = when;
        for (graph::TargetCleanup* target : {&out.mail, &out.sharepoint, &out.onedrive}) {
            target->found = each;
            target->deleted = each;
            target->rounds = 1;
        }
        return out;
    };
    facts.cleanup.before = cleaned(graph::CleanupWhen::before_run, 0);
    facts.cleanup.after = cleaned(graph::CleanupWhen::after_run, 2);
    facts.cleanup.after->sharepoint.found = 3;
    facts.cleanup.after->sharepoint.deleted = 3;
    facts.cleanup.restore_sent = true;

    for (std::size_t i = 0; i < timing::kSpanCount; ++i) {
        facts.timings.spans[i] = {timing::SpanState::measured,
                                  std::chrono::milliseconds{1000 * (i + 1) + 7}};
    }
    return facts;
}

} // namespace rp::test
