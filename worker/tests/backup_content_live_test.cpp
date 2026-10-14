// W6.3 (#183): the live Done-when of the content check against the backup's
// own copy (docs/decisions.md 2026-10-14, W6.3 and W6.2, point 15). On the
// lab's restore point, the 14 real files of L1.8 (7 in the RestoreTest site's
// default library, 7 in alice's OneDrive root; no canary, no mail) are
// restored three times through the connector's guarded path, each with the
// pipeline's own pieces: want_content on every file (mark_wanted), the
// exports into the ContentHasher, add_backup_content, the read back with
// TargetReader, check and decide_status, the Cleaner's clean before and after.
//   (a) as it is: 14 backup_content (12 by bytes, the xlsx and the docx by
//       office-v1), 14 match, pass;
//   (b) one byte of team-meeting-notes.txt's restored copy changed in the
//       RestoreTarget library before the read back (one PUT over the copy, by
//       the Worker app's own write grant on the RestoreTarget list, the one the
//       live cleanup test seeds with; the library resolved through the guard's
//       own check first): that item mismatch on sha256, fail with its index
//       listed, the other 13 match;
//   (c) with content_max_bytes 1: 14 over_cap, 14 metadata matched by name
//       and size, pass with the content_export warning naming all 14 and
//       verified.backup_content 0: an export that fails is not a fail.
// Skipped unless both RP_LIVE=1 and RP_LIVE_RESTORE=1. Run by hand from an
// elevated VS 2022 Developer PowerShell on the Veeam server, through
// docs/api/veeam-lab/w6.3-harness/w63-live.ps1, which empties the targets
// first and cleans them in its finally. Variables: those of the live restore
// test (docs/testing.md), and RP_LIVE_EVIDENCE_FILE (optional: the three
// runs as JSON: names, sizes, hashes, words, statuses; no credential).

#include "live_secrets.hpp"
#include "graph_live_lab.hpp"
#include "test_support.hpp"

#include <rp/backup_content.hpp>
#include <rp/cert_export.hpp>
#include <rp/checker.hpp>
#include <rp/cleaner.hpp>
#include <rp/client_assertion.hpp>
#include <rp/client_profile.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/expected_set.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_targets.hpp>
#include <rp/run_lock.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_selector.hpp>
#include <rp/secrets.hpp>
#include <rp/target_guard_graph.hpp>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace connector = rp::connector;
namespace sampling = rp::sampling;
namespace verification = rp::verification;
using connector::ItemKind;
using nlohmann::json;
using rp::test::graph_live::env_or;

const std::string kLabOrgName = "RestoreProofLab.onmicrosoft.com";
const std::string kLabCertSha256 =
    "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";
const std::string kGraphV1 = "https://graph.microsoft.com/v1.0";

// L1.8's real files (lab/tenant.md, "Real data for the random sample").
const std::vector<std::string> kSharePointNames = {
    "team-meeting-notes.txt", "supplier-contacts.txt",  "project-brief.pdf",  "budget-summary.pdf",
    "office-floor-plan.png",  "brand-colours-draft.png", "room-bookings.xlsx"};
const std::vector<std::string> kOneDriveNames = {
    "reading-list.txt",  "travel-notes.txt",      "expense-report-march.pdf", "course-certificate.pdf",
    "holiday-photo.png", "whiteboard-sketch.png", "weekly-status.docx"};
// The file whose restored copy (b) changes by one byte: a plain file, so its
// rule is bytes, in the RestoreTarget library.
const std::string kTampered = "team-meeting-notes.txt";

constexpr rp::graph::TargetCheckWording kTamperWording{"changes one byte only in",
                                                       "nothing was changed"};

// The hasher, keeping the bytes of the one file (b) changes as well: the
// changed copy is the export's bytes with one byte flipped, so the copy is
// otherwise what the restore wrote.
class KeepingSink final : public connector::IContentSink {
public:
    KeepingSink(verification::ContentHasher& hasher, std::size_t keep) : hasher_(hasher), keep_(keep) {}
    void on_content(ItemKind kind, std::size_t index, std::string_view bytes) override
    {
        hasher_.on_content(kind, index, bytes);
        if (kind == ItemKind::sharepoint && index == keep_) {
            const std::lock_guard lock(mutex_);
            kept_ = std::string{bytes};
        }
    }
    std::optional<std::string> kept() const
    {
        const std::lock_guard lock(mutex_);
        return kept_;
    }

private:
    verification::ContentHasher& hasher_;
    std::size_t keep_;
    mutable std::mutex mutex_;
    std::optional<std::string> kept_;
};

cpr::SslOptions verifying_tls()
{
    cpr::SslOptions ssl;
    ssl.verify_peer = true;
    ssl.verify_host = true;
    return ssl;
}

// An app-only Graph token of the test's own (never printed), from the Worker
// app's certificate, as the live cleanup test makes its seeds' (the change of
// (b) doesn't go through GraphClient, whose one write is the Cleaner's).
std::string write_token(const rp::Config& config, const rp::Secrets& secrets)
{
    const rp::graph::ClientCertificate certificate =
        rp::graph::certificate_from_secrets(secrets, std::chrono::system_clock::now());
    cpr::Session session;
    session.SetUrl(cpr::Url{rp::graph::entra_token_url(config.graph_tenant_id)});
    session.SetPayload(cpr::Payload{
        {"client_id", config.graph_client_id},
        {"scope", std::string{rp::graph::kGraphScope}},
        {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
        {"client_assertion",
         rp::graph::make_client_assertion(certificate, config.graph_tenant_id,
                                          config.graph_client_id,
                                          std::chrono::system_clock::now())},
        {"grant_type", "client_credentials"}});
    session.SetTimeout(cpr::Timeout{std::chrono::seconds{60}});
    session.SetRedirect(cpr::Redirect{0L, false, false, cpr::PostRedirectFlags::NONE});
    session.SetSslOptions(verifying_tls());
    const cpr::Response response = session.Post();
    if (response.status_code != 200) {
        throw std::runtime_error("write token: HTTP " + std::to_string(response.status_code) +
                                 " " + response.error.message);
    }
    return json::parse(response.text).at("access_token").get<std::string>();
}

// PUT the copy's content: its status (200 for a replaced content).
long put_content(const std::string& token, const std::string& drive_id,
                 const std::string& item_id, const std::string& bytes)
{
    cpr::Session session;
    session.SetUrl(cpr::Url{kGraphV1 + "/drives/" + drive_id + "/items/" + item_id + "/content"});
    session.SetHeader(cpr::Header{{"Authorization", "Bearer " + token},
                                  {"Content-Type", "application/octet-stream"}});
    session.SetBody(cpr::Body{bytes});
    session.SetTimeout(cpr::Timeout{std::chrono::seconds{60}});
    session.SetRedirect(cpr::Redirect{0L, false, false, cpr::PostRedirectFlags::NONE});
    session.SetSslOptions(verifying_tls());
    const cpr::Response response = session.Put();
    std::cout << "tamper PUT " << kTampered << ": HTTP " << response.status_code << "\n";
    if (response.status_code < 200 || response.status_code > 299) {
        std::cout << "  " << response.error.message << " " << response.text.substr(0, 500) << "\n";
    }
    return response.status_code;
}

enum class Scenario { as_is, one_byte_changed, export_fails };

std::string_view name_of(Scenario s)
{
    return s == Scenario::as_is              ? "a: as it is"
           : s == Scenario::one_byte_changed ? "b: one byte changed in the restored copy"
                                             : "c: every export over a cap of 1 byte";
}

struct Outcome {
    verification::RunVerdict verdict;
    json record;
};

} // namespace

TEST_CASE("live backup content: real files checked by hash against the backup's copy, a changed "
          "byte fails its item, a failed export is not a fail",
          "[live][writes]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"} ||
        rp::test::get_env("RP_LIVE_RESTORE") != std::optional<std::string>{"1"}) {
        SKIP("writes to the lab tenant: set both RP_LIVE=1 and RP_LIVE_RESTORE=1 to run");
    }
    const std::optional<std::string> ca_file = rp::test::get_env("RP_LIVE_VEEAM_CA_FILE");
    REQUIRE(ca_file);
    const std::unique_ptr<rp::RunLock> lock = rp::try_take_restore_targets_lock();
    REQUIRE(lock != nullptr); // another RestoreProof run is using the restore targets
    rp::Config config = rp::test::graph_live::live_config();
    config.veeam_url = env_or("RP_LIVE_VEEAM_URL", "https://localhost:4443");
    config.veeam_ca_file = ca_file;
    config.veeam_cert_sha256 = env_or("RP_LIVE_VEEAM_CERT_SHA256", kLabCertSha256);
    config.veeam_org_name = kLabOrgName;
    const rp::Secrets secrets = rp::test::live_secrets();
    REQUIRE(secrets.veeam_username);
    REQUIRE(secrets.veeam_password);

    auto logger = std::make_shared<spdlog::logger>(
        "live_backup_content", std::make_shared<spdlog::sinks::ostream_sink_mt>(std::cout));
    logger->set_level(spdlog::level::info);

    // The connector, the newest point, and the 14 files from the sampler's
    // own listing with no manifest (W6.2): the lister's own rules, the
    // restore targets and the rp-canary- prefix, keep canaries out.
    connector::ConnectorOptions options;
    options.logger = logger;
    options.cert_exporter = rp::make_local_machine_cert_exporter();
    options.client = rp::local_profile(config);
    REQUIRE(options.client.has_value());
    const std::unique_ptr<connector::IConnector> made = connector::default_connector_registry()
        .create(connector::kVeeamM365, config, secrets, options);
    connector::IConnector& source = *made;
    const std::vector<connector::RestorePoint> points = source.list_restore_points(kLabOrgName);
    REQUIRE_FALSE(points.empty());
    const connector::RestorePoint& newest = points.front();
    std::cout << "restore point " << newest.backup_time << " " << newest.id << "\n";
    const connector::RestoreTargets targets = connector::RestoreTargets::from_config(config);
    connector::CandidateQuery query{.client_ref = kLabOrgName,
                                    .restore_point = newest,
                                    .targets = targets,
                                    .mail = false,
                                    .sharepoint = true,
                                    .onedrive = true,
                                    .seed = 0x5763,
                                    .exclude = {},
                                    .limits = {}};
    query.limits.containers_wanted = 16;
    query.limits.containers_tried = 16;
    query.limits.folders_per_container = 8;
    const connector::CandidatePool pool = source.list_candidates(query);

    // A selection without canaries of exactly those 14, as the sampler makes
    // one: each candidate's selector with size -1 and its key recorded.
    sampling::Selection selection;
    selection.record.run_id = "w6.3-live";
    selection.record.canaries = false;
    const auto take = [](const auto& candidates, const std::vector<std::string>& names,
                         auto& selectors, auto& randoms, sampling::KindRecord& record) {
        for (const std::string& name : names) {
            std::size_t hits = 0;
            for (const auto& c : candidates) {
                if (c.selector.name == name) {
                    ++hits;
                    auto picked = c;
                    picked.selector.size = -1;
                    selectors.push_back(picked.selector);
                    randoms.push_back(picked);
                    record.random_keys.push_back(sampling::random_key(picked.selector));
                }
            }
            CAPTURE(name);
            REQUIRE(hits == 1);
        }
        record.requested = static_cast<int>(names.size());
        record.random_wanted = record.requested;
        record.random_taken = record.requested;
    };
    take(pool.sharepoint, kSharePointNames, selection.sharepoint, selection.sharepoint_random,
         selection.record.sharepoint);
    take(pool.onedrive, kOneDriveNames, selection.onedrive, selection.onedrive_random,
         selection.record.onedrive);
    std::size_t tampered_index = 0;
    for (std::size_t i = 0; i < selection.sharepoint.size(); ++i) {
        if (selection.sharepoint[i].name == kTampered) {
            tampered_index = i;
        }
    }

    // Graph as the Worker app, the downloads, the Cleaner.
    const std::unique_ptr<rp::IHttpClient> graph_http = rp::graph::make_graph_http_client(logger);
    rp::graph::GraphClientOptions graph_options;
    graph_options.logger = logger;
    rp::graph::GraphClient graph(
        *graph_http, config.graph_tenant_id, config.graph_client_id,
        rp::graph::certificate_from_secrets(secrets, std::chrono::system_clock::now(), logger),
        graph_options);
    const std::unique_ptr<rp::IHttpClient> download = rp::graph::make_download_http_client();
    rp::graph::CleanerOptions cleaner_options;
    cleaner_options.logger = logger;
    rp::graph::Cleaner cleaner(graph, targets, cleaner_options);
    const auto reader = [&](rp::graph::TargetReaderOptions o) {
        o.logger = logger;
        return rp::graph::TargetReader(graph, *download, targets, o);
    };

    const auto run = [&](Scenario scenario) -> Outcome {
        std::cout << "\n== " << name_of(scenario) << "\n";
        const rp::graph::CleanupResult before_clean =
            cleaner.clean(rp::graph::CleanupWhen::before_run);
        REQUIRE(before_clean.ok());
        verification::TargetsRead before;
        {
            rp::graph::TargetReaderOptions o;
            o.hash_items = false;
            rp::graph::TargetReader r = reader(o);
            before.sharepoint.items = r.list_sharepoint();
            before.onedrive.items = r.list_onedrive();
        }
        REQUIRE(before.sharepoint.items.empty());
        REQUIRE(before.onedrive.items.empty());

        connector::RestoreSpec spec{.client_ref = kLabOrgName,
                                    .restore_point = newest,
                                    .targets = targets,
                                    .mail = {},
                                    .sharepoint = selection.sharepoint,
                                    .onedrive = selection.onedrive};
        std::vector<std::string> sp_names;
        for (const auto& s : spec.sharepoint) {
            sp_names.push_back(s.name);
        }
        std::vector<std::string> od_names;
        for (const auto& o : spec.onedrive) {
            od_names.push_back(o.name);
        }
        verification::ContentHasher hasher(sp_names, od_names);
        KeepingSink sink(hasher, tampered_index);
        REQUIRE(verification::mark_wanted(spec, selection.record) == 14);
        spec.content_sink = &sink;
        if (scenario == Scenario::export_fails) {
            spec.content_max_bytes = 1;
        }

        const connector::RestoreResult result = source.restore_sample(spec);
        std::cout << verification::content_exports_line(result);
        verification::ExpectedSet expected = verification::build_expected_set(selection, nullptr);
        verification::add_backup_content(expected, result, hasher.digests());

        if (scenario == Scenario::one_byte_changed) {
            // The library through the guard's own check first; the copy is
            // this run's (not in the before listing), in the RestoreTarget
            // library alone.
            const rp::graph::ResolvedLibrary library =
                rp::graph::check_restore_library(graph, targets, kTamperWording);
            REQUIRE(library.drive_id == config.test_library_id);
            rp::graph::TargetReaderOptions o;
            o.hash_items = false;
            std::optional<std::string> copy_id;
            for (const rp::graph::FoundItem& f : reader(o).list_sharepoint()) {
                if (f.name == kTampered) {
                    copy_id = f.id;
                }
            }
            REQUIRE(copy_id);
            std::optional<std::string> bytes = sink.kept();
            REQUIRE(bytes);
            REQUIRE_FALSE(bytes->empty());
            (*bytes)[0] = static_cast<char>((*bytes)[0] ^ 0x01);
            const long status = put_content(write_token(config, secrets), library.drive_id,
                                            *copy_id, *bytes);
            INFO("if the grant refuses the PUT, change one byte of the copy by hand (docs/testing.md)");
            REQUIRE((status >= 200 && status <= 299));
        }

        verification::TargetsRead after;
        const verification::TargetSnapshot snapshot = verification::snapshot_of(before);
        {
            rp::graph::TargetReaderOptions o;
            o.hash_items = true;
            o.hash_file = verification::hash_filter(expected, snapshot);
            o.on_file = verification::office_hook(after);
            rp::graph::TargetReader r = reader(o);
            after.sharepoint.items = r.list_sharepoint();
            after.onedrive.items = r.list_onedrive();
        }
        const verification::CheckResult checked = verification::check(expected, snapshot, after);
        verification::RunFacts facts;
        facts.expected = &expected;
        facts.restore = &result;
        facts.check = &checked;
        facts.restore_point_time = newest.backup_time;
        const verification::RunVerdict verdict = verification::decide_status(facts);
        std::cout << "status " << verification::to_string(verdict.status) << ": " << verdict.message
                  << "\n";
        for (const verification::StatusWarning& w : verdict.warnings) {
            std::cout << "warning: " << w.code << ": " << w.message << "\n";
        }

        json items = json::array();
        for (const verification::ExpectedItem& item : expected.items) {
            const verification::ItemCheck& c = checked.items[item.index];
            std::cout << "  " << connector::to_string(item.kind) << "  " << item.file->name << "  "
                      << verification::to_string(item.expected_kind) << "  " << item.export_word
                      << "  " << (item.sha256_rule.empty() ? "-" : item.sha256_rule) << "  "
                      << (item.sha256.empty() ? "-" : item.sha256) << "  "
                      << (c.found_sha256.empty() ? "-" : c.found_sha256) << "  "
                      << verification::to_string(c.outcome) << "\n";
            items.push_back({{"index", item.index},
                             {"kind", connector::to_string(item.kind)},
                             {"name", item.file->name},
                             {"expected_kind", verification::to_string(item.expected_kind)},
                             {"export", item.export_word},
                             {"sha256_rule", item.sha256_rule},
                             {"expected_sha256", item.sha256},
                             {"found_sha256", c.found_sha256},
                             {"outcome", verification::to_string(c.outcome)}});
        }
        json exports = json::array();
        for (const connector::ContentExport& e : result.content) {
            exports.push_back({{"kind", connector::to_string(e.kind)},
                               {"index", e.index},
                               {"outcome", connector::to_string(e.outcome)},
                               {"size_bytes", e.size_bytes},
                               {"ms", e.ms}});
        }
        const json record = {{"scenario", name_of(scenario)},
                             {"restore", connector::to_string(result.status)},
                             {"exports", exports},
                             {"items", items},
                             {"status", verification::to_json(verdict)}};

        const rp::graph::CleanupResult after_clean =
            cleaner.clean(rp::graph::CleanupWhen::after_run);
        CHECK(after_clean.ok());
        return {verdict, record};
    };

    json evidence = json::array();
    const auto count_kind = [](const json& record, std::string_view kind) {
        std::size_t n = 0;
        for (const json& i : record.at("items")) {
            n += i.at("expected_kind").get<std::string>() == kind ? 1 : 0;
        }
        return n;
    };

    // (a) as it is: every file by its content, every one matches.
    const Outcome a = run(Scenario::as_is);
    evidence.push_back(a.record);
    CHECK(a.verdict.status == verification::RunStatus::pass);
    CHECK(count_kind(a.record, "backup_content") == 14);
    CHECK(a.verdict.verified_backup_content == 14);
    for (const json& i : a.record.at("items")) {
        CAPTURE(i.at("name"));
        CHECK(i.at("export") == "exported");
        CHECK(i.at("outcome") == "match");
        const std::string name = i.at("name").get<std::string>();
        const bool office = name.ends_with(".xlsx") || name.ends_with(".docx");
        CHECK(i.at("sha256_rule") == (office ? "office-v1" : "bytes"));
    }

    // (b) one byte changed in one restored copy: that item fails.
    const Outcome b = run(Scenario::one_byte_changed);
    evidence.push_back(b.record);
    CHECK(b.verdict.status == verification::RunStatus::fail);
    REQUIRE(b.verdict.failed.size() == 1);
    const json& failed = b.record.at("items").at(b.verdict.failed.front());
    CHECK(failed.at("name") == kTampered);
    CHECK(failed.at("outcome") == "mismatch");
    CHECK(failed.at("expected_sha256") != failed.at("found_sha256"));
    std::size_t matched = 0;
    for (const json& i : b.record.at("items")) {
        matched += i.at("outcome") == "match" ? 1 : 0;
    }
    CHECK(matched == 13);

    // (c) every export over the cap: nothing of the content checked, the
    // names and sizes still are, and the run passes with the warning.
    const Outcome c = run(Scenario::export_fails);
    evidence.push_back(c.record);
    CHECK(c.verdict.status == verification::RunStatus::pass);
    CHECK(count_kind(c.record, "metadata") == 14);
    CHECK(c.verdict.verified_backup_content == 0);
    bool warned = false;
    for (const verification::StatusWarning& w : c.verdict.warnings) {
        if (w.code == "content_export") {
            warned = true;
            CHECK(w.indexes.size() == 14);
        }
    }
    CHECK(warned);
    for (const json& i : c.record.at("items")) {
        CHECK(i.at("export") == "over_cap");
        CHECK(i.at("outcome") == "match");
    }

    if (const std::optional<std::string> file = rp::test::get_env("RP_LIVE_EVIDENCE_FILE");
        file && !file->empty()) {
        std::ofstream out(*file, std::ios::binary | std::ios::trunc);
        out << json{{"restore_point", {{"id", newest.id}, {"backup_time", newest.backup_time}}},
                    {"runs", evidence}}
                   .dump(2)
            << "\n";
        CHECK(out.good());
    }
}
