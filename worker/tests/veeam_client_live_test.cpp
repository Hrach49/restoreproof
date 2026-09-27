// W1.5 and W1.6 "Done when": the lab's Veeam returns the real organisation
// and its restore points, through VeeamClient and through `rpworker veeam
// list`; and W1.7's "veeam_m365" connector, held as an IConnector&, does too. Skipped unless RP_LIVE=1. Read-only: each signs in, lists
// organisations and restore points, and logs out; no explore session, no
// restore.
//
// Environment (docs/testing.md):
//   RP_LIVE=1
//   RP_VEEAM_USERNAME, RP_VEEAM_PASSWORD   the Veeam account (rp/secrets.hpp)
//   RP_LIVE_VEEAM_CA_FILE                  PEM of Veeam's REST certificate
//   RP_LIVE_VEEAM_CERT_SHA256              its SHA-256; default: the lab's
//   RP_LIVE_VEEAM_URL                      default: https://localhost:4443

#include "test_support.hpp"

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/veeam_client.hpp>
#include <rp/veeam_command.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

// The lab (docs/api/veeam-notes.md, lab/tenant.md).
const std::string kLabOrgId = "ff96d072-29e2-4cb4-a155-2590f5473176";
const std::string kLabOrgName = "RestoreProofLab.onmicrosoft.com";
const std::string kLabFull = "2026-09-25T19:24:31.0936821Z";
const std::string kLabIncremental = "2026-09-25T19:37:15.2145203Z";
const std::string kLabCertSha256 =
    "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";

std::string env_or(const char* name, const std::string& fallback)
{
    const std::optional<std::string> value = rp::test::get_env(name);
    return value && !value->empty() ? *value : fallback;
}

} // namespace

TEST_CASE("live: the lab's Veeam returns the real organisation and its restore points",
          "[veeam][live]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"}) {
        SKIP("set RP_LIVE=1 to run against the lab's Veeam");
    }
    const rp::Secrets secrets = rp::load_secrets_from_env();
    REQUIRE(secrets.veeam_username);
    REQUIRE(secrets.veeam_password);
    const std::optional<std::string> ca_file = rp::test::get_env("RP_LIVE_VEEAM_CA_FILE");
    REQUIRE(ca_file);

    rp::HttpClientOptions http_options;
    http_options.ca_file = ca_file;
    http_options.pinned_cert_sha256 = env_or("RP_LIVE_VEEAM_CERT_SHA256", kLabCertSha256);
    rp::HttpClient http(std::move(http_options));
    rp::VeeamClient client(http, env_or("RP_LIVE_VEEAM_URL", "https://localhost:4443"),
                           *secrets.veeam_username, *secrets.veeam_password);

    const std::vector<rp::Organization> orgs = client.list_organizations();
    const auto org = std::find_if(orgs.begin(), orgs.end(),
                                  [](const rp::Organization& o) { return o.id == kLabOrgId; });
    REQUIRE(org != orgs.end());
    CHECK(org->name == kLabOrgName);
    std::cout << "organisation " << org->id << " " << org->name << " (msid " << org->msid
              << ", " << org->region << ")\n";

    const std::vector<rp::RestorePoint> points = client.list_restore_points(org->id);
    for (const rp::RestorePoint& point : points) {
        std::cout << "restore point " << point.backup_time << " " << point.id << "\n";
    }
    client.logout();

    // The lab's two points; a later backup would add newer ones in front.
    std::vector<std::string> times;
    for (const rp::RestorePoint& point : points) {
        times.push_back(point.backup_time);
    }
    const auto incremental = std::find(times.begin(), times.end(), kLabIncremental);
    const auto full = std::find(times.begin(), times.end(), kLabFull);
    REQUIRE(incremental != times.end());
    REQUIRE(full != times.end());
    CHECK(incremental < full);
    for (const rp::RestorePoint& point : points) {
        CHECK(point.organization_id == kLabOrgId);
        CHECK(point.id.size() == 72);
    }
}

// W1.6 "Done when": `rpworker veeam list` prints the two restore points of the
// lab's organisation. The same environment as above; the config is written to
// a temp file from it. Read-only, like the test above.
TEST_CASE("live: rpworker veeam list prints the lab organisation's two restore points",
          "[veeam][live]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"}) {
        SKIP("set RP_LIVE=1 to run against the lab's Veeam");
    }
    const std::optional<std::string> ca_file = rp::test::get_env("RP_LIVE_VEEAM_CA_FILE");
    REQUIRE(ca_file);
    const nlohmann::json config = {
        {"cloud_url", "https://cloud.example.invalid"},
        {"veeam_url", env_or("RP_LIVE_VEEAM_URL", "https://localhost:4443")},
        {"veeam_org_name", kLabOrgName},
        {"graph_tenant_id", "unused"},
        {"graph_client_id", "unused"},
        {"test_mailbox", "restoretest@RestoreProofLab.onmicrosoft.com"},
        {"test_site_id", "unused"},
        {"test_library_id", "unused"},
        {"test_onedrive_drive_id", "unused"},
        {"test_onedrive_folder_id", "unused"},
        {"veeam_ca_file", *ca_file},
        {"veeam_cert_sha256", env_or("RP_LIVE_VEEAM_CERT_SHA256", kLabCertSha256)}};
    const rp::test::TempDir dir;
    const std::filesystem::path path = dir.write("config.json", config.dump());
    const std::u8string path_utf8 = path.u8string();
    const std::string path_arg(path_utf8.begin(), path_utf8.end());
    const std::vector<std::string_view> args{"list", "--config", path_arg};

    std::ostringstream out;
    std::ostringstream err;
    const int exit_code = rp::run_veeam_command(args, out, err, rp::default_veeam_command_env());
    std::cout << out.str();
    INFO(err.str());
    REQUIRE(exit_code == 0);
    REQUIRE(err.str().empty());

    // The rows of the organisation, marked as veeam_org_name. The lab's two
    // points, newest first; a later backup adds newer rows in front of them.
    std::vector<std::string> rows;
    std::istringstream lines(out.str());
    for (std::string line; std::getline(lines, line);) {
        if (line.starts_with("* " + kLabOrgName + "  ")) {
            rows.push_back(line);
        }
    }
    const auto row_with = [&rows](const std::string& backup_time) {
        return std::find_if(rows.begin(), rows.end(), [&backup_time](const std::string& row) {
            return row.find("  " + backup_time + "  ") != std::string::npos;
        });
    };
    const auto incremental = row_with(kLabIncremental);
    const auto full = row_with(kLabFull);
    REQUIRE(incremental != rows.end());
    REQUIRE(full != rows.end());
    CHECK(incremental < full);
}

// W1.7: the default registry's "veeam_m365" connector, through IConnector&
// only, lists the lab organisation's restore points by its name. The same
// environment as above; the real rp::HttpClient. Read-only, like the tests
// above: the connector signs in, lists, and logs out when it goes.
TEST_CASE("live: the veeam_m365 connector lists the lab's restore points as an IConnector&",
          "[veeam][live]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"}) {
        SKIP("set RP_LIVE=1 to run against the lab's Veeam");
    }
    const std::optional<std::string> ca_file = rp::test::get_env("RP_LIVE_VEEAM_CA_FILE");
    REQUIRE(ca_file);
    rp::Config config;
    config.veeam_url = env_or("RP_LIVE_VEEAM_URL", "https://localhost:4443");
    config.veeam_ca_file = ca_file;
    config.veeam_cert_sha256 = env_or("RP_LIVE_VEEAM_CERT_SHA256", kLabCertSha256);

    const std::unique_ptr<rp::connector::IConnector> made =
        rp::connector::default_connector_registry().create(rp::connector::kVeeamM365, config,
                                                           rp::load_secrets_from_env());
    rp::connector::IConnector& source = *made;
    CHECK(source.describe().name == "veeam_m365");
    const std::vector<rp::connector::RestorePoint> points =
        source.list_restore_points(kLabOrgName);
    std::vector<std::string> times;
    for (const rp::connector::RestorePoint& point : points) {
        std::cout << "connector restore point " << point.backup_time << " " << point.id << "\n";
        times.push_back(point.backup_time);
    }
    const auto incremental = std::find(times.begin(), times.end(), kLabIncremental);
    const auto full = std::find(times.begin(), times.end(), kLabFull);
    REQUIRE(incremental != times.end());
    REQUIRE(full != times.end());
    CHECK(incremental < full);
}
