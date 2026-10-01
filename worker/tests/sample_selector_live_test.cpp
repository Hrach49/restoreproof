// W2.6 (#31) live dry run: choose_sample against the lab's Veeam and
// lab/seed-manifest.json, twice with one run ID and cursor, on the lab
// organisation's newest restore point. Read-only for Microsoft 365: it
// restores nothing. It opens explore sessions and stops them again (the same
// precedent as docs/api/veeam-m365/10-restore.ps1 -WhatIf), and reads the
// restore targets through Graph for the target guard's layer 1. Skipped
// unless RP_LIVE=1. docs/testing.md, "Live sample (dry run)".
//
// It checks that both runs chose the same sample, that TargetGuard::check_spec
// accepts it, that the only POSTs were sign-ins, explore sessions and their
// Stop, and that no session of the account is left Working; it prints the
// selection, the result's "sample" object and its "expected" object (W3.1:
// one expected record per item, its kind explicit; the lab has no real files
// yet, so expect a file shortfall).
//
// Environment: the Veeam and Graph variables of the other live tests
// (docs/testing.md, "Live tests"), plus, both optional:
//   RP_LIVE_RUN_ID          the run ID; default "live-dry-run"
//   RP_LIVE_SAMPLE_CURSOR   "m,s,o", the canary cursor per type; default "0,0,0"

#include "graph_live_lab.hpp"
#include "test_support.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/expected_set.hpp>
#include <rp/graph_client.hpp>
#include <rp/http_client.hpp>
#include <rp/sample_selector.hpp>
#include <rp/secrets.hpp>
#include <rp/target_guard.hpp>
#include <rp/veeam_client.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace connector = rp::connector;
namespace sampling = rp::sampling;
using nlohmann::json;
using rp::test::graph_live::env_or;

const std::string kLabOrgName = "RestoreProofLab.onmicrosoft.com";
const std::string kLabCertSha256 =
    "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";

// What went out: each request's method and URL (never a header or body), and
// how many entries each OneDrive root listing held.
struct Sent {
    std::mutex mutex;
    std::vector<std::string> posts;
    std::size_t gets = 0;
    std::vector<std::size_t> onedrive_root_entries;
};

// Sends through the real client; records what went out.
class CountingHttpClient final : public rp::IHttpClient {
public:
    CountingHttpClient(std::unique_ptr<rp::IHttpClient> inner, Sent& sent)
        : inner_(std::move(inner)), sent_(sent)
    {
    }

    rp::HttpResponse send(const rp::HttpRequest& request) override
    {
        rp::HttpResponse response = inner_->send(request);
        const std::lock_guard lock(sent_.mutex);
        if (request.method == rp::HttpMethod::post) {
            sent_.posts.push_back(request.url);
        } else if (request.method == rp::HttpMethod::get) {
            ++sent_.gets;
            if (request.url.find("/Organization/OneDrives/") != std::string::npos &&
                request.url.find("/Documents?parentId=root") != std::string::npos) {
                const json body = json::parse(response.body, nullptr, false);
                sent_.onedrive_root_entries.push_back(
                    body.is_object() && body.contains("results") && body["results"].is_array()
                        ? body["results"].size()
                        : 0);
            }
        }
        return response;
    }

private:
    std::unique_ptr<rp::IHttpClient> inner_;
    Sent& sent_;
};

// "m,s,o" as three numbers, else std::invalid_argument.
sampling::CanaryCursor parse_cursor(const std::string& text)
{
    std::istringstream in(text);
    sampling::CanaryCursor cursor;
    char comma1 = 0;
    char comma2 = 0;
    if (!(in >> cursor.mail >> comma1 >> cursor.sharepoint >> comma2 >> cursor.onedrive) ||
        comma1 != ',' || comma2 != ',' || !(in >> std::ws).eof()) {
        throw std::invalid_argument("RP_LIVE_SAMPLE_CURSOR must be \"m,s,o\", e.g. 0,0,0");
    }
    return cursor;
}

json selectors_json(const sampling::Selection& s)
{
    json out = {{"mail", json::array()}, {"sharepoint", json::array()}, {"onedrive", json::array()}};
    for (const connector::MailSelector& m : s.mail) {
        out["mail"].push_back({m.mailbox, m.folder, m.subject, m.received_at});
    }
    for (const connector::SharePointSelector& p : s.sharepoint) {
        out["sharepoint"].push_back({p.site_id, p.drive_id, p.folder_path, p.name, p.list_id, p.size});
    }
    for (const connector::OneDriveSelector& o : s.onedrive) {
        out["onedrive"].push_back({o.user, o.folder_path, o.name, o.size});
    }
    return out;
}

// The account as Veeam lists it in initiatedBy: the username without its
// MACHINE\ or DOMAIN\ part.
std::string bare_account(const std::string& username)
{
    const std::size_t slash = username.rfind('\\');
    return slash == std::string::npos ? username : username.substr(slash + 1);
}

std::string lower(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

} // namespace

TEST_CASE("live sample: choose_sample picks the same sample twice, the guard accepts it, and "
          "nothing is restored",
          "[live][sample]")
{
    if (!rp::test::graph_live::live_enabled()) {
        SKIP("set RP_LIVE=1 to run against the lab's Veeam and Graph");
    }
    const std::optional<std::string> ca_file = rp::test::get_env("RP_LIVE_VEEAM_CA_FILE");
    REQUIRE(ca_file);
    rp::Config config = rp::test::graph_live::live_config();
    config.veeam_url = env_or("RP_LIVE_VEEAM_URL", "https://localhost:4443");
    config.veeam_ca_file = ca_file;
    config.veeam_cert_sha256 = env_or("RP_LIVE_VEEAM_CERT_SHA256", kLabCertSha256);
    config.veeam_org_name = kLabOrgName;
    const rp::Secrets secrets = rp::load_secrets_from_env();
    REQUIRE(secrets.veeam_username);
    REQUIRE(secrets.veeam_password);
    const std::string run_id = env_or("RP_LIVE_RUN_ID", "live-dry-run");
    const sampling::CanaryCursor cursor = parse_cursor(env_or("RP_LIVE_SAMPLE_CURSOR", "0,0,0"));

    // Warnings and worse to stdout, redacted like every line.
    auto logger = std::make_shared<spdlog::logger>(
        "live_sample", std::make_shared<spdlog::sinks::ostream_sink_mt>(std::cout));
    logger->set_level(spdlog::level::warn);
    Sent sent;
    std::optional<rp::HttpClientOptions> veeam_http_options;
    connector::ConnectorOptions options;
    options.logger = logger;
    options.make_http = [&](const rp::HttpClientOptions& http_options) {
        veeam_http_options = http_options;
        return std::make_unique<CountingHttpClient>(std::make_unique<rp::HttpClient>(http_options),
                                                    sent);
    };
    const std::unique_ptr<connector::IConnector> made =
        connector::default_connector_registry().create(connector::kVeeamM365, config, secrets,
                                                       options);
    connector::IConnector& source = *made;

    const std::vector<connector::RestorePoint> points = source.list_restore_points(kLabOrgName);
    REQUIRE_FALSE(points.empty());
    const connector::RestorePoint& newest = points.front();
    const sampling::CanaryManifest manifest = sampling::load_canary_manifest(
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json");
    const connector::RestoreTargets targets = connector::RestoreTargets::from_config(config);
    const sampling::SamplePlan plan = sampling::SamplePlan::from_config(config);
    std::cout << "restore point " << newest.backup_time << " " << newest.id << "\n"
              << "run " << run_id << ", cursor " << cursor.mail << "," << cursor.sharepoint << ","
              << cursor.onedrive << ", plan " << plan.mail << "/" << plan.sharepoint << "/"
              << plan.onedrive << "\n";

    const sampling::Selection first =
        sampling::choose_sample(source, kLabOrgName, newest, targets, config.graph_tenant_id, plan,
                                manifest, cursor, run_id);
    const sampling::Selection second =
        sampling::choose_sample(source, kLabOrgName, newest, targets, config.graph_tenant_id, plan,
                                manifest, cursor, run_id);

    std::cout << "selection:\n" << selectors_json(first).dump(2) << "\n";
    std::cout << "sample:\n" << sampling::to_json(first.record).dump(2) << "\n";
    const rp::verification::ExpectedSet expected =
        rp::verification::build_expected_set(first, manifest);
    std::cout << "expected:\n" << rp::verification::to_json(expected).dump(2) << "\n";
    for (const std::size_t n : sent.onedrive_root_entries) {
        std::cout << "a OneDrive's Documents?parentId=root listed " << n << " entries\n";
    }
    std::cout << sent.gets << " GET(s), " << sent.posts.size() << " POST(s)\n";

    // 1. Twice the same: the draw is the run ID's and the restore point's.
    CHECK(selectors_json(second) == selectors_json(first));
    CHECK(sampling::to_json(second.record) == sampling::to_json(first.record));
    // Every item has its expected record; the second run's is the same.
    CHECK(expected.items.size() ==
          first.mail.size() + first.sharepoint.size() + first.onedrive.size());
    CHECK(rp::verification::to_json(rp::verification::build_expected_set(second, manifest)) ==
          rp::verification::to_json(expected));

    // 2. The target guard's layer 1 accepts it (Graph, read-only).
    auto graph_http = rp::graph::make_graph_http_client(logger);
    rp::graph::GraphClient graph(*graph_http, config.graph_tenant_id, config.graph_client_id,
                                 rp::graph::certificate_from_secrets(
                                     secrets, std::chrono::system_clock::now(), logger));
    const connector::RestoreSpec spec{.client_ref = kLabOrgName,
                                      .restore_point = newest,
                                      .targets = targets,
                                      .mail = first.mail,
                                      .sharepoint = first.sharepoint,
                                      .onedrive = first.onedrive};
    rp::TargetGuardOptions guard_options;
    guard_options.logger = logger;
    CHECK_NOTHROW(rp::TargetGuard(graph, guard_options).check_spec(spec));

    // 3. Nothing but sign-ins, explore sessions and their Stop was POSTed.
    {
        const std::lock_guard lock(sent.mutex);
        for (const std::string& url : sent.posts) {
            CAPTURE(url);
            CHECK((url.ends_with("/v8/token") || url.ends_with("/v8/token/logout") ||
                   url.ends_with("/explore") || url.ends_with("/Stop")));
        }
    }

    // 4. No session of the account is left Working.
    REQUIRE(veeam_http_options);
    rp::HttpClient check_http(*veeam_http_options);
    rp::VeeamClient check(check_http, config.veeam_url, *secrets.veeam_username,
                          *secrets.veeam_password);
    const json sessions = check.get_json("/v8/RestoreSessions?limit=200");
    check.logout();
    const std::string account = lower(bare_account(*secrets.veeam_username));
    for (const json& session : sessions.at("results")) {
        const bool ours = session.contains("initiatedBy") && session["initiatedBy"].is_string() &&
                          lower(session["initiatedBy"].get<std::string>()) == account;
        const bool working = session.contains("state") && session["state"] == "Working";
        CAPTURE(session.value("id", std::string{}));
        CHECK_FALSE((ours && working));
    }
}
