#include <rp/config_check.hpp>
#include <rp/secrets.hpp>

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Args = std::vector<std::string_view>;

namespace {

const std::string kUsage = "usage: rpworker --version | rpworker config check [--config <path>]\n";

// Every key set; sample_od left out to show its default.
const std::string kConfigJson = R"({
    "cloud_url": "https://cloud.example.invalid",
    "veeam_url": "https://veeam.example.invalid:4443",
    "veeam_org_name": "example.onmicrosoft.com",
    "graph_tenant_id": "00000000-0000-0000-0000-000000000001",
    "graph_client_id": "00000000-0000-0000-0000-000000000002",
    "test_mailbox": "restoretest@example.onmicrosoft.com",
    "test_site_id": "site-id",
    "test_library_id": "library-id",
    "test_onedrive_drive_id": "drive-id",
    "test_onedrive_folder_id": "folder-id",
    "poll_interval_s": 60,
    "heartbeat_interval_s": 120,
    "sample_mail": 0,
    "sample_sp": 7,
    "log_level": "warn"
})";

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// The output of a successful check of kConfigJson at `path`, with the three
// secret lines given.
std::string expected_output(const std::filesystem::path& path, std::string_view user,
                            std::string_view password, std::string_view graph)
{
    return "config file: " + utf8(path) + "\n" +
           "cloud_url                 https://cloud.example.invalid\n"
           "veeam_url                 https://veeam.example.invalid:4443\n"
           "veeam_org_name            example.onmicrosoft.com\n"
           "graph_tenant_id           00000000-0000-0000-0000-000000000001\n"
           "graph_client_id           00000000-0000-0000-0000-000000000002\n"
           "test_mailbox              restoretest@example.onmicrosoft.com\n"
           "test_site_id              site-id\n"
           "test_library_id           library-id\n"
           "test_onedrive_drive_id    drive-id\n"
           "test_onedrive_folder_id   folder-id\n"
           "poll_interval_s           60\n"
           "heartbeat_interval_s      120\n"
           "sample_mail               0\n"
           "sample_sp                 7\n"
           "sample_od                 5\n"
           "log_level                 warn\n"
           "secrets (environment variables; values are never shown):\n"
           "RP_VEEAM_USERNAME         " +
           std::string{user} + "\n" + "RP_VEEAM_PASSWORD         " + std::string{password} +
           "\n" + "RP_GRAPH_CLIENT_SECRET    " + std::string{graph} + "\n";
}

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

Run run(const Args& args, const std::filesystem::path& default_path)
{
    std::ostringstream out;
    std::ostringstream err;
    const int exit_code = rp::run_config_command(args, out, err, default_path);
    return {exit_code, out.str(), err.str()};
}

} // namespace

TEST_CASE("rpworker config prints usage and exits 2 for arguments it doesn't understand",
          "[config_check]")
{
    const Args args = GENERATE(
        Args{},
        Args{""},
        Args{"Check"},
        Args{"show"},
        Args{"--config", "x.json", "check"},
        Args{"check", "--config"},
        Args{"check", "x.json"},
        Args{"check", "--config", "x.json", "extra"},
        Args{"check", "--config", "x.json", "--config", "y.json"},
        Args{"check", "--CONFIG", "x.json"},
        Args{"check", "check"});
    CAPTURE(args);
    const rp::test::TempDir dir;

    const Run result = run(args, dir.write("config.json", kConfigJson));
    REQUIRE(result.exit_code == 2);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == kUsage);
}

TEST_CASE("rpworker config check exits 1 with the error when the config doesn't load",
          "[config_check]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path missing = dir.path() / "missing.json";
    const std::string missing_arg = utf8(missing);

    const Run result = run(Args{"check", "--config", missing_arg}, dir.path() / "unused.json");
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + missing_arg + ": cannot read config file\n");
}

TEST_CASE("rpworker config check reports an invalid config without its values", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", R"({"cloud_url": "http://SENTINEL-2a9f"})");
    const std::string path_arg = utf8(path);

    const Run result = run(Args{"check", "--config", path_arg}, dir.path() / "unused.json");
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err ==
            "config error: " + path_arg +
                ": config key \"cloud_url\" must be an https:// URL with no user name, password, "
                "query or fragment\n");
}

TEST_CASE("rpworker config check prints every setting and masks the secrets", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const std::string path_arg = utf8(path);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, "user-0c41");
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, "password-0c41");
    const rp::test::ScopedEnv graph(rp::kEnvGraphClientSecret, std::nullopt);

    const Run result = run(Args{"check", "--config", path_arg}, dir.path() / "unused.json");
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_output(path, "**** (set)", "**** (set)", "(not set)"));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reads the default path without --config", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::test::ScopedEnv graph(rp::kEnvGraphClientSecret, "graph-0c41");

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_output(path, "(not set)", "(not set)", "**** (set)"));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check never prints a secret's value", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, "SENTINEL-USER-91e7");
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, "SENTINEL-PASSWORD-91e7");
    const rp::test::ScopedEnv graph(rp::kEnvGraphClientSecret, "SENTINEL-GRAPH-91e7");

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.exit_code == 0);
    const std::string all = result.out + result.err;
    REQUIRE_THAT(all, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(all, !ContainsSubstring("91e7"));
    REQUIRE_THAT(all, ContainsSubstring("RP_VEEAM_USERNAME         **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("RP_VEEAM_PASSWORD         **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("RP_GRAPH_CLIENT_SECRET    **** (set)\n"));
}

TEST_CASE("rpworker config check never prints a password in a URL", "[config_check]")
{
    const rp::test::TempDir dir;
    std::string text = kConfigJson;
    const std::string url = "https://cloud.example.invalid";
    text.replace(text.find(url), url.size(), "https://user:SENTINEL-3b8d@cloud.example.invalid");
    const auto path = dir.write("config.json", text);

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.exit_code == 1);
    REQUIRE_THAT(result.out + result.err, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(result.err, ContainsSubstring("\"cloud_url\""));
}
