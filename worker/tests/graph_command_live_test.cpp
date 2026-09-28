// W2.3 "Done when": `rpworker graph list` runs end-to-end against the tenant.
// This test runs rp::run_graph_command with the real environment
// (default_graph_command_env(): the Windows store, the real clocks, the
// Worker's secrets from the process environment) on a config holding the lab's
// values, without and with --hash, and prints the tables for the person
// running it to compare with the tenant. Skipped unless RP_LIVE=1. Read-only:
// GETs and downloads of the restore targets only.
//
// Run it with its output shown (ctest hides it without -V):
//   .\worker\build\dev\rptests.exe "[graph_command][live]"
//
// Environment (docs/testing.md): as graph_targets_live_test.cpp, whose
// RP_LIVE_GRAPH_* and RP_LIVE_TARGET_* variables it reads too.

#include "graph_live_lab.hpp"
#include "test_support.hpp"

#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/graph_command.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using Catch::Matchers::ContainsSubstring;

namespace {

using namespace rp::test::graph_live;

// A config file with the live values; the Veeam and Cloud keys are required
// but never used by `graph list`.
std::filesystem::path write_live_config(const rp::test::TempDir& dir)
{
    const rp::Config config = live_config();
    const nlohmann::json body{
        {"cloud_url", "https://cloud.example.invalid"},
        {"veeam_url", "https://localhost:4443"},
        {"veeam_org_name", "RestoreProofLab.onmicrosoft.com"},
        {"graph_tenant_id", config.graph_tenant_id},
        {"graph_client_id", config.graph_client_id},
        {"test_mailbox", config.test_mailbox},
        {"test_site_id", config.test_site_id},
        {"test_library_id", config.test_library_id},
        {"test_onedrive_drive_id", config.test_onedrive_drive_id},
        {"test_onedrive_folder_id", config.test_onedrive_folder_id},
    };
    return dir.write("config.json", body.dump(2));
}

} // namespace

TEST_CASE("live: rpworker graph list prints the three restore targets", "[graph_command][live]")
{
    if (!live_enabled()) {
        SKIP("set RP_LIVE=1 to run against the lab tenant's Graph");
    }
    const bool hash = GENERATE(false, true);
    CAPTURE(hash);
    const rp::test::TempDir dir;
    const std::u8string path = write_live_config(dir).u8string();
    const std::string path_arg{path.begin(), path.end()};
    std::vector<std::string_view> args{"list", "--config", path_arg};
    if (hash) {
        args.push_back("--hash");
    }
    std::ostringstream out;
    std::ostringstream err;

    const int code = rp::run_graph_command(args, out, err, rp::default_graph_command_env());

    std::cout << "--- rpworker graph list" << (hash ? " --hash" : "") << " (exit " << code
              << ")\n"
              << out.str() << err.str();
    CHECK(code == rp::exit_code::ok);
    CHECK(err.str().empty());
    CHECK_THAT(out.str(), ContainsSubstring("Mail (" + live_config().test_mailbox + ", Inbox): "));
    CHECK_THAT(out.str(), ContainsSubstring("\nSharePoint (RestoreTarget library): "));
    CHECK_THAT(out.str(), ContainsSubstring("\nOneDrive (RestoreTarget folder): "));
    CHECK_THAT(out.str(), ContainsSubstring(" item(s) in the three restore targets\n"));
}
