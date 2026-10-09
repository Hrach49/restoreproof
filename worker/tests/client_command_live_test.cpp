// W4.10 "Done when": `rpworker client check --profile-file <file>` prints the
// lab's three restore targets with no client keys in any config (the command
// reads none), and a profile that breaks the schema exits 1 naming the bad
// key. This test runs rp::run_client_command with the real environment
// (default_graph_command_env(): the Windows store, the real clocks, the
// vault) on a profile file written from the lab's values, and prints the
// tables for the person running it to compare with `graph list`. Skipped
// unless RP_LIVE=1. Read-only: GETs of the restore targets only.
//
// Run it with its output shown (ctest hides it without -V):
//   .\worker\build\dev\rptests.exe "[client_command][live]"
//
// Environment (docs/testing.md): as graph_command_live_test.cpp.

#include "graph_live_lab.hpp"
#include "test_support.hpp"

#include <rp/cli.hpp>
#include <rp/client_command.hpp>
#include <rp/client_profile.hpp>
#include <rp/config.hpp>
#include <rp/graph_command.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

using namespace rp::test::graph_live;

// The lab's profile, as a job will carry it.
nlohmann::json live_profile()
{
    const rp::Config config = live_config();
    return nlohmann::json{
        {"format", std::string{rp::kClientProfileFormat}},
        {"veeam_org_name", "RestoreProofLab.onmicrosoft.com"},
        {"graph_tenant_id", config.graph_tenant_id},
        {"graph_client_id", config.graph_client_id},
        {"test_mailbox", config.test_mailbox},
        {"test_site_id", config.test_site_id},
        {"test_library_id", config.test_library_id},
        {"test_onedrive_drive_id", config.test_onedrive_drive_id},
        {"test_onedrive_folder_id", config.test_onedrive_folder_id},
    };
}

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

} // namespace

TEST_CASE("live: rpworker client check prints a profile's three restore targets, and names the "
          "key of a profile that breaks the schema",
          "[graph][client_command][live]")
{
    if (!live_enabled()) {
        SKIP("set RP_LIVE=1 to run against the lab tenant's Graph");
    }
    const rp::test::TempDir dir;
    const std::string profile = utf8(dir.write("lab-profile.json", live_profile().dump(2)));
    std::ostringstream out;
    std::ostringstream err;

    const int code = rp::run_client_command(std::vector<std::string_view>{"check", "--profile-file", profile},
                                            out, err, rp::default_graph_command_env());

    std::cout << "--- rpworker client check --profile-file (exit " << code << ")\n"
              << out.str() << err.str();
    CHECK(code == rp::exit_code::ok);
    CHECK(err.str().empty());
    CHECK_THAT(out.str(), StartsWith("client profile: veeam_org_name RestoreProofLab.onmicrosoft.com, "
                                     "tenant " + live_config().graph_tenant_id + ", app " +
                                     live_config().graph_client_id + "\n\n"));
    CHECK_THAT(out.str(), ContainsSubstring("Mail (" + live_config().test_mailbox + ", Inbox): "));
    CHECK_THAT(out.str(), ContainsSubstring("\nSharePoint (RestoreTarget library): "));
    CHECK_THAT(out.str(), ContainsSubstring("\nOneDrive (RestoreTarget folder): "));
    CHECK_THAT(out.str(), ContainsSubstring(" item(s) in the three restore targets\n"));

    // A profile that breaks the schema: exit 1, the key named, no value, no request.
    nlohmann::json bad = live_profile();
    bad["test_mailbox"] = "alice@RestoreProofLab.onmicrosoft.com";
    const std::string bad_file = utf8(dir.write("bad-profile.json", bad.dump(2)));
    std::ostringstream bad_out;
    std::ostringstream bad_err;
    const int bad_code = rp::run_client_command(
        std::vector<std::string_view>{"check", "--profile-file", bad_file}, bad_out, bad_err,
        rp::default_graph_command_env());
    std::cout << "--- rpworker client check --profile-file (a bad mailbox; exit " << bad_code
              << ")\n"
              << bad_out.str() << bad_err.str();
    CHECK(bad_code == rp::exit_code::config);
    CHECK(bad_out.str().empty());
    CHECK(bad_err.str() == "config error: --profile-file " + bad_file + ": key \"test_mailbox\" " +
                               std::string{rp::kRestoreMailboxRule} + "\n");
}
