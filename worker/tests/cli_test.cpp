#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/version.hpp>

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using Args = std::vector<std::string_view>;

namespace {

const std::string kUsage = "usage: rpworker --version | rpworker config check [--config <path>]\n";

} // namespace

TEST_CASE("rpworker prints usage to stderr and exits 2 for a command line it doesn't know", "[cli]")
{
    const Args args = GENERATE(
        Args{},
        Args{"--no-such-option"},
        Args{""},
        Args{"-v"},
        Args{"version"},
        Args{"--VERSION"},
        Args{"--version", "extra"},
        Args{"extra", "--version"},
        Args{"--version", "--version"},
        Args{"config"},
        Args{"Config", "check"},
        Args{"--version", "config", "check"},
        Args{"config", "check", "--config"});
    CAPTURE(args);

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 2);
    REQUIRE(out.str().empty());
    REQUIRE(err.str() == kUsage);
}

TEST_CASE("rpworker --version prints the project version to stdout and exits 0", "[cli]")
{
    const Args args{"--version"};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 0);
    REQUIRE(out.str() == std::string{rp::version()} + "\n");
    REQUIRE(err.str().empty());
}

TEST_CASE("rpworker config check --config <file> checks that file", "[cli]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", R"({
        "cloud_url": "https://cloud.example.invalid",
        "veeam_url": "https://veeam.example.invalid",
        "veeam_org_name": "example.onmicrosoft.com",
        "graph_tenant_id": "tenant",
        "graph_client_id": "client",
        "test_mailbox": "restoretest@example.onmicrosoft.com",
        "test_site_id": "site",
        "test_library_id": "library",
        "test_onedrive_drive_id": "drive",
        "test_onedrive_folder_id": "folder"
    })");
    const std::string path_arg = path.string();
    const Args args{"config", "check", "--config", path_arg};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 0);
    REQUIRE(err.str().empty());
    REQUIRE(out.str().starts_with("config file: " + path_arg + "\n"));
}

TEST_CASE("rpworker config check without --config reads the ProgramData config", "[cli]")
{
    // Only reads: whether this machine has a config there or not, the output
    // names the default path.
    const Args args{"config", "check"};
    const std::string path = rp::default_config_path().string();

    std::ostringstream out;
    std::ostringstream err;
    const int exit_code = rp::run_cli(args, out, err);
    CAPTURE(exit_code, err.str());
    if (exit_code == 1) {
        REQUIRE(err.str().starts_with("config error: " + path + ": "));
    } else {
        REQUIRE(exit_code == 0);
        REQUIRE(out.str().starts_with("config file: " + path + "\n"));
    }
}
