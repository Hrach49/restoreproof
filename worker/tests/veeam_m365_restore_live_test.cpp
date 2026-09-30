// W2.5 (#30) "Done when": the default registry's "veeam_m365" connector
// restores 10 canaries (5 mails from one mailbox's Inbox, 3 SharePoint files,
// 2 OneDrive files, all from lab/seed-manifest.json) from the lab
// organisation's newest restore point into the three restore targets, in one
// restore_sample call.
//
// It WRITES to the lab tenant: skipped unless both RP_LIVE=1 and
// RP_LIVE_RESTORE=1, so a normal RP_LIVE=1 run stays read-only. Run it by
// hand, from an elevated shell (the certificate export reads
// LocalMachine\My's private key), with the restore targets empty first
// (`rpworker graph list`); clean them up by hand afterwards until W3.4.
// docs/testing.md, "Live restore (writes to the lab tenant)".
//
// Environment: the Veeam and Graph variables of the other live tests
// (docs/testing.md, "Live tests"), plus
//   RP_LIVE_RESTORE=1
//   RP_LIVE_EVIDENCE_FILE   optional: where to write the RestoreResult as JSON
// The canaries are chosen from the manifest, never named here: the first by
// ID, pdf and txt files before any other, never docx or xlsx (SharePoint
// rewrites Office files, so their size differs from the manifest's).

#include "graph_live_lab.hpp"
#include "test_support.hpp"

#include <rp/cert_export.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/secrets.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace connector = rp::connector;
using nlohmann::json;
using rp::test::graph_live::env_or;

const std::string kLabOrgName = "RestoreProofLab.onmicrosoft.com";
const std::string kLabCertSha256 =
    "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";

constexpr std::size_t kMails = 5;
constexpr std::size_t kSharePointFiles = 3;
constexpr std::size_t kOneDriveFiles = 2;

std::filesystem::path manifest_path()
{
    return std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json";
}

// The manifest's entries of `kind`, ordered by ID.
std::vector<json> entries_of(const json& manifest, const std::string& kind)
{
    std::vector<json> out;
    for (const json& entry : manifest.at("entries")) {
        if (entry.at("kind") == kind) {
            out.push_back(entry);
        }
    }
    std::ranges::sort(out, [](const json& a, const json& b) {
        return a.at("id").get<std::string>() < b.at("id").get<std::string>();
    });
    return out;
}

// `count` files of `kind`: pdf and txt first, then any other type but docx
// and xlsx, each group by ID.
std::vector<json> files_of(const json& manifest, const std::string& kind, std::size_t count)
{
    std::vector<json> preferred;
    std::vector<json> others;
    for (json& entry : entries_of(manifest, kind)) {
        const std::string type = entry.at("file_type").get<std::string>();
        if (type == "pdf" || type == "txt") {
            preferred.push_back(std::move(entry));
        } else if (type != "docx" && type != "xlsx") {
            others.push_back(std::move(entry));
        }
    }
    preferred.insert(preferred.end(), others.begin(), others.end());
    if (preferred.size() < count) {
        throw std::runtime_error("the manifest has too few " + kind + " entries");
    }
    preferred.resize(count);
    return preferred;
}

std::vector<connector::MailSelector> mail_items(const json& manifest)
{
    std::vector<connector::MailSelector> out;
    std::string mailbox;
    for (const json& entry : entries_of(manifest, "mail")) {
        const json& location = entry.at("location");
        if (location.at("folder") != "Inbox") {
            continue;
        }
        if (mailbox.empty()) {
            mailbox = location.at("mailbox").get<std::string>();
        }
        if (location.at("mailbox") != mailbox || out.size() == kMails) {
            continue;
        }
        out.push_back({.mailbox = mailbox,
                       .folder = "Inbox",
                       .subject = entry.at("subject").get<std::string>(),
                       .received_at = entry.at("received_at").get<std::string>()});
    }
    if (out.size() < kMails) {
        throw std::runtime_error("the manifest has too few mails in one Inbox");
    }
    return out;
}

std::vector<connector::SharePointSelector> sharepoint_items(const json& manifest)
{
    std::vector<connector::SharePointSelector> out;
    for (const json& entry : files_of(manifest, "sharepoint_file", kSharePointFiles)) {
        const json& location = entry.at("location");
        out.push_back({.site_id = location.at("site_id").get<std::string>(),
                       .drive_id = location.at("drive_id").get<std::string>(),
                       .folder_path = location.at("folder_path").get<std::string>(),
                       .name = entry.at("name").get<std::string>(),
                       .list_id = location.at("list_id").get<std::string>(),
                       .size = entry.at("stored_size").get<std::int64_t>()});
    }
    return out;
}

std::vector<connector::OneDriveSelector> onedrive_items(const json& manifest)
{
    std::vector<connector::OneDriveSelector> out;
    for (const json& entry : files_of(manifest, "onedrive_file", kOneDriveFiles)) {
        const json& location = entry.at("location");
        out.push_back({.user = location.at("user").get<std::string>(),
                       .folder_path = location.at("folder_path").get<std::string>(),
                       .name = entry.at("name").get<std::string>(),
                       .size = entry.at("stored_size").get<std::int64_t>()});
    }
    return out;
}

// The result as evidence: what restore_sample returned, nothing else (it
// holds no credential).
json to_json(const connector::RestoreResult& result, const connector::RestoreSpec& spec)
{
    json sessions = json::array();
    for (const connector::RestoreSessionResult& s : result.sessions) {
        sessions.push_back({{"id", s.id},
                            {"kind", connector::to_string(s.kind)},
                            {"result", s.result},
                            {"details", s.details},
                            {"started_at", s.started_at},
                            {"ended_at", s.ended_at},
                            {"items_sent", s.items_sent},
                            {"items_restored", s.items_restored}});
    }
    json items = json::array();
    for (const connector::ItemRestoreResult& item : result.items) {
        items.push_back({{"kind", connector::to_string(item.kind)},
                         {"name", item.name},
                         {"session_id", item.session_id},
                         {"outcome", connector::to_string(item.outcome)},
                         {"message", item.message},
                         {"infrastructure", item.infrastructure}});
    }
    return {{"restore_point",
             {{"id", spec.restore_point.id}, {"backup_time", spec.restore_point.backup_time}}},
            {"status", connector::to_string(result.status)},
            {"items_sent", result.items_sent},
            {"items_restored", result.items_restored},
            {"session_ids", result.session_ids},
            {"sessions", sessions},
            {"items", items},
            {"log", result.log}};
}

void print_summary(const connector::RestoreResult& result)
{
    std::cout << "status " << connector::to_string(result.status) << ": " << result.items_restored
              << " of " << result.items_sent << " item(s) restored\n";
    for (const connector::RestoreSessionResult& s : result.sessions) {
        std::cout << "session " << s.id << " (" << connector::to_string(s.kind) << ") "
                  << s.started_at << " .. " << s.ended_at << ": " << s.result << ", "
                  << s.details << " (" << s.items_restored << " of " << s.items_sent << ")\n";
    }
    for (const connector::ItemRestoreResult& item : result.items) {
        std::cout << "item " << connector::to_string(item.kind) << " " << item.name << ": "
                  << connector::to_string(item.outcome)
                  << (item.message.empty() ? "" : " (" + item.message + ")") << "\n";
    }
    std::cout << "log:\n" << result.log << (result.log.ends_with('\n') ? "" : "\n");
}

} // namespace

TEST_CASE("live restore: restore_sample restores 10 canaries into the lab's restore targets",
          "[live][writes]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"} ||
        rp::test::get_env("RP_LIVE_RESTORE") != std::optional<std::string>{"1"}) {
        SKIP("writes to the lab tenant: set both RP_LIVE=1 and RP_LIVE_RESTORE=1 to run");
    }
    const std::optional<std::string> ca_file = rp::test::get_env("RP_LIVE_VEEAM_CA_FILE");
    REQUIRE(ca_file);
    rp::Config config = rp::test::graph_live::live_config();
    config.veeam_url = env_or("RP_LIVE_VEEAM_URL", "https://localhost:4443");
    config.veeam_ca_file = ca_file;
    config.veeam_cert_sha256 = env_or("RP_LIVE_VEEAM_CERT_SHA256", kLabCertSha256);
    config.veeam_org_name = kLabOrgName;

    // Info and worse to stdout, redacted like every line.
    auto logger = std::make_shared<spdlog::logger>(
        "live_restore", std::make_shared<spdlog::sinks::ostream_sink_mt>(std::cout));
    logger->set_level(spdlog::level::info);
    connector::ConnectorOptions options;
    options.logger = logger;
    options.cert_exporter = rp::make_local_machine_cert_exporter();
    const std::unique_ptr<connector::IConnector> made = connector::default_connector_registry()
        .create(connector::kVeeamM365, config, rp::load_secrets_from_env(), options);
    connector::IConnector& source = *made;

    const std::vector<connector::RestorePoint> points = source.list_restore_points(kLabOrgName);
    REQUIRE_FALSE(points.empty());
    const connector::RestorePoint& newest = points.front();
    std::cout << "restore point " << newest.backup_time << " " << newest.id << "\n";

    json manifest;
    {
        std::ifstream in(manifest_path());
        REQUIRE(in);
        manifest = json::parse(in);
    }
    const connector::RestoreSpec spec{.client_ref = kLabOrgName,
                                      .restore_point = newest,
                                      .targets = connector::RestoreTargets::from_config(config),
                                      .mail = mail_items(manifest),
                                      .sharepoint = sharepoint_items(manifest),
                                      .onedrive = onedrive_items(manifest)};
    REQUIRE(spec.item_count() == kMails + kSharePointFiles + kOneDriveFiles);
    for (const connector::MailSelector& m : spec.mail) {
        std::cout << "sample mail " << m.mailbox << " " << m.folder << " " << m.subject << " "
                  << m.received_at << "\n";
    }
    for (const connector::SharePointSelector& f : spec.sharepoint) {
        std::cout << "sample sharepoint " << f.folder_path << " " << f.name << " " << f.size << "\n";
    }
    for (const connector::OneDriveSelector& f : spec.onedrive) {
        std::cout << "sample onedrive " << f.user << " " << f.folder_path << " " << f.name << " "
                  << f.size << "\n";
    }

    const connector::RestoreResult result = source.restore_sample(spec);
    print_summary(result);
    if (const std::optional<std::string> evidence = rp::test::get_env("RP_LIVE_EVIDENCE_FILE");
        evidence && !evidence->empty()) {
        // The variable is UTF-8; a path from a std::string would be read as ANSI.
        std::ofstream out(std::filesystem::path{std::u8string(evidence->begin(), evidence->end())},
                          std::ios::binary);
        REQUIRE(out);
        out << to_json(result, spec).dump(2) << "\n";
        std::cout << "evidence written to " << *evidence << "\n";
    }

    REQUIRE(result.status == connector::RestoreStatus::succeeded);
    REQUIRE(result.items_restored == 10);
}
