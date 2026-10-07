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
//   RP_LIVE_VAULT                  the vault with the Worker app's certificate; default
//       %ProgramData%\RestoreProof\vault.bin (live_secrets.hpp)
//   RP_LIVE_GRAPH_TENANT_ID, RP_LIVE_GRAPH_CLIENT_ID   as graph_client_live_test
//   RP_LIVE_TARGET_MAILBOX              default: restoretest@
//   RP_LIVE_TARGET_SITE_ID              default: the RestoreTest site
//   RP_LIVE_TARGET_LIBRARY_ID           default: the RestoreTarget library's drive
//   RP_LIVE_TARGET_ONEDRIVE_DRIVE_ID    default: alice's OneDrive
//   RP_LIVE_TARGET_ONEDRIVE_FOLDER_ID   default: its /RestoreTarget folder

#include "live_secrets.hpp"
#include "found_item_line.hpp"
#include "graph_live_lab.hpp"

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

using namespace rp::test::graph_live;

// A GraphClient on the real Graph HttpClient (Windows store) and the
// certificate from the Worker's secrets, plus the token-free download client.
struct LiveGraph {
    std::unique_ptr<rp::IHttpClient> http = rp::graph::make_graph_http_client();
    std::unique_ptr<rp::IHttpClient> download = rp::graph::make_download_http_client();
    rp::graph::GraphClient client{
        *http, live_tenant_id(), live_client_id(),
        rp::graph::certificate_from_secrets(rp::test::live_secrets(),
                                            std::chrono::system_clock::now())};
};

} // namespace

TEST_CASE("live: the three restore targets list as the tenant shows them",
          "[graph][targets][live]")
{
    if (!live_enabled()) {
        SKIP("set RP_LIVE=1 to run against the lab tenant's Graph");
    }
    LiveGraph graph;
    rp::graph::TargetReader reader(graph.client, *graph.download,
                                   rp::connector::RestoreTargets::from_config(live_config()));

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
