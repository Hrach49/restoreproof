// W1.5 "Done when": a live call against the lab's Veeam returns the real
// organisation and its restore points. Skipped unless RP_LIVE=1. Read-only:
// it signs in, lists organisations and restore points, and logs out; no
// explore session, no restore.
//
// Environment (docs/testing.md):
//   RP_LIVE=1
//   RP_VEEAM_USERNAME, RP_VEEAM_PASSWORD   the Veeam account (rp/secrets.hpp)
//   RP_LIVE_VEEAM_CA_FILE                  PEM of Veeam's REST certificate
//   RP_LIVE_VEEAM_CERT_SHA256              its SHA-256; default: the lab's
//   RP_LIVE_VEEAM_URL                      default: https://localhost:4443

#include "test_support.hpp"

#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/veeam_client.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <iostream>
#include <optional>
#include <string>
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
