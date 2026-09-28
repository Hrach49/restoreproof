// W2.2 "Done when": the three restore-target listings match what the tenant
// shows, once with the locations empty and again after one item was put in
// each by hand. This test lists all three through TargetReader on the real
// Graph and prints what it found; the person running it compares that with
// the tenant. Skipped unless RP_LIVE=1. Read-only: GETs and downloads only,
// and only of the restore targets (never the RestoreTest library or folder).
//
// Run it with its output shown (ctest hides it without -V):
//   .\worker\build\dev\rptests.exe "[targets][live]"
//
// Environment (docs/testing.md):
//   RP_LIVE=1
//   RP_GRAPH_CERT_PFX_BASE64, RP_GRAPH_CERT_PASSWORD   the Worker app's
//       certificate (rp/secrets.hpp; lab/entra/set-worker-env.ps1 sets them)
//   RP_LIVE_GRAPH_TENANT_ID, RP_LIVE_GRAPH_CLIENT_ID   as graph_client_live_test
//   RP_LIVE_TARGET_MAILBOX              default: restoretest@
//   RP_LIVE_TARGET_SITE_ID              default: the RestoreTest site
//   RP_LIVE_TARGET_LIBRARY_ID           default: the RestoreTarget library's drive
//   RP_LIVE_TARGET_ONEDRIVE_DRIVE_ID    default: alice's OneDrive
//   RP_LIVE_TARGET_ONEDRIVE_FOLDER_ID   default: its /RestoreTarget folder

#include "found_item_line.hpp"
#include "test_support.hpp"

#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_targets.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

// The lab's restore targets (lab/tenant.md, "Restore targets"). No canary
// location is named here or anywhere under worker/.
const std::string kLabTenantId = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";
const std::string kLabWorkerClientId = "737da5ef-baf2-4198-b009-e160d8ca77c9";
const std::string kLabMailbox = "restoretest@RestoreProofLab.onmicrosoft.com";
const std::string kLabSiteId = "restoreprooflab.sharepoint.com,"
                               "fe08085d-eb70-42e8-95a6-470189bd98eb,"
                               "4ecaf399-cc0e-4d95-b3fe-cd091a09e689";
const std::string kLabLibraryDriveId =
    "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6";
const std::string kLabOneDriveDriveId =
    "b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3";
const std::string kLabOneDriveFolderId = "01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH";

std::string env_or(const char* name, const std::string& fallback)
{
    const std::optional<std::string> value = rp::test::get_env(name);
    return value && !value->empty() ? *value : fallback;
}

rp::connector::RestoreTargets live_targets()
{
    rp::Config config;
    config.test_mailbox = env_or("RP_LIVE_TARGET_MAILBOX", kLabMailbox);
    config.test_site_id = env_or("RP_LIVE_TARGET_SITE_ID", kLabSiteId);
    config.test_library_id = env_or("RP_LIVE_TARGET_LIBRARY_ID", kLabLibraryDriveId);
    config.test_onedrive_drive_id =
        env_or("RP_LIVE_TARGET_ONEDRIVE_DRIVE_ID", kLabOneDriveDriveId);
    config.test_onedrive_folder_id =
        env_or("RP_LIVE_TARGET_ONEDRIVE_FOLDER_ID", kLabOneDriveFolderId);
    return rp::connector::RestoreTargets::from_config(config);
}

// A GraphClient on the real Graph HttpClient (Windows store) and the
// certificate from the Worker's secrets, plus the token-free download client.
struct LiveGraph {
    std::unique_ptr<rp::IHttpClient> http = rp::graph::make_graph_http_client();
    std::unique_ptr<rp::IHttpClient> download = rp::graph::make_download_http_client();
    rp::graph::GraphClient client{
        *http, env_or("RP_LIVE_GRAPH_TENANT_ID", kLabTenantId),
        env_or("RP_LIVE_GRAPH_CLIENT_ID", kLabWorkerClientId),
        rp::graph::certificate_from_secrets(rp::load_secrets_from_env(),
                                            std::chrono::system_clock::now())};
};

} // namespace

TEST_CASE("live: the three restore targets list as the tenant shows them",
          "[graph][targets][live]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"}) {
        SKIP("set RP_LIVE=1 to run against the lab tenant's Graph");
    }
    LiveGraph graph;
    rp::graph::TargetReader reader(graph.client, *graph.download, live_targets());

    std::vector<rp::graph::FoundItem> items;
    REQUIRE_NOTHROW(items = reader.list_all());

    // One line per item (found_item_line.hpp), Graph's text made fit for one line.
    std::map<std::string, int> totals{{"mail", 0}, {"sharepoint", 0}, {"onedrive", 0}};
    for (const rp::graph::FoundItem& item : items) {
        ++totals[std::string{rp::graph::to_string(item.type)}];
        std::cout << rp::test::found_item_line(item) << "\n";
    }
    for (const auto& [type, total] : totals) {
        std::cout << type << " total: " << total << "\n";
    }
}
