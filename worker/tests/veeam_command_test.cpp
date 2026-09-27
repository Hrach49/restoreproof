// W1.6: `rpworker veeam list` (rp::run_veeam_command) against the recorded
// Veeam responses in tests/fixtures/veeam/, served by FakeHttpClient. Nothing
// here touches the network; the live run against the lab is in
// veeam_client_live_test.cpp (RP_LIVE=1). Exit codes and output are the
// 2026-09-27 decision in docs/decisions.md.

#include "fake_http_client.hpp"
#include "test_support.hpp"

#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/veeam_client.hpp>
#include <rp/veeam_command.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
using Catch::Matchers::ContainsSubstring;
using Args = std::vector<std::string_view>;

namespace {

using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using rp::test::to_response;

const std::string kUsage = "usage: rpworker --version | rpworker config check [--config <path>] | "
                           "rpworker veeam list [--config <path>]\n";

const std::string kBase = "https://veeam.test:4443";
const std::string kTokenUrl = kBase + "/v8/token";
const std::string kLogoutUrl = kBase + "/v8/token/logout";
const std::string kOrgId = "ff96d072-29e2-4cb4-a155-2590f5473176";
const std::string kOrgName = "RestoreProofLab.onmicrosoft.com";
const std::string kUsername = "DESKTOP-P55CDUM\\rp-veeam";
// As in veeam_client_test.cpp: every character form encoding must escape, and
// a non-ASCII one. It must never show up in output, an error or a log line.
const std::string kPassword = "Sentinel&Pa55=w\xc3\xb6rd+%";
const std::string kPasswordForm = "Sentinel%26Pa55%3Dw%C3%B6rd%2B%25";
const std::string kAccessToken = "SENTINEL-ACCESS-TOKEN-4c1e";
const std::string kRefreshToken = "SENTINEL-REFRESH-TOKEN-4c1e";

const std::string kNewestPoint =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e371ac3d9c-eb29-42b6-a391-ae81fcc4681c";
const std::string kOldestPoint =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e32fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7";

// The lab's REST certificate (tests/fixtures/veeam/README.md) and its SHA-256.
const std::string kLabCertSha256 =
    "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";

// A valid config for kBase; veeam_org_name is the lab's organisation.
std::string config_json(const std::string& org_name = kOrgName, const std::string& extra = {})
{
    return "{" + extra + R"(
    "cloud_url": "https://cloud.example.invalid",
    "veeam_url": ")" + kBase + R"(",
    "veeam_org_name": )" + json(org_name).dump() + R"(,
    "graph_tenant_id": "tenant",
    "graph_client_id": "client",
    "test_mailbox": "restoretest@example.onmicrosoft.com",
    "test_site_id": "site",
    "test_library_id": "library",
    "test_onedrive_drive_id": "drive",
    "test_onedrive_folder_id": "folder"
})";
}

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

std::string orgs_url()
{
    return kBase + "/v8/Organizations?limit=1000&offset=0";
}

std::string points_url(const std::string& org = kOrgId)
{
    return kBase + "/v8/RestorePoints?organizationId=" + org + "&limit=1000&offset=0";
}

// The recorded 200 token response with the sentinel tokens in place of
// [REDACTED].
HttpResponse token_response()
{
    json fixture = load_fixture_json("veeam", "token-200");
    fixture["body"]["access_token"] = kAccessToken;
    fixture["body"]["refresh_token"] = kRefreshToken;
    return to_response(fixture);
}

// An IHttpClient the command owns that sends through the test's fake, so the
// test can still read the fake's log after the command has returned.
class ForwardingHttpClient final : public rp::IHttpClient {
public:
    explicit ForwardingHttpClient(rp::IHttpClient& target) : target_(target) {}

    HttpResponse send(const HttpRequest& request) override { return target_.send(request); }

private:
    rp::IHttpClient& target_;
};

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

// Everything run_veeam_command reaches outside itself: a config file in a temp
// directory, the secrets, the HTTP client (a FakeHttpClient serving the lab's
// recorded answers) and a logger that writes every level to a string. Counts
// how often the command asks for each; waits are recorded, never slept.
struct Harness {
    explicit Harness(const std::string& config = config_json())
    {
        config_path = dir.write("config.json", config);
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("veeam_command_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::trace);
        http.on(HttpMethod::post, kTokenUrl, {token_response()});
        http.on(HttpMethod::get, orgs_url(), {load_fixture("veeam", "organizations-200")});
        http.on(HttpMethod::get, points_url(), {load_fixture("veeam", "restore-points-200")});
        http.on(HttpMethod::post, kLogoutUrl, {load_fixture("veeam", "logout-204")});
    }

    rp::VeeamCommandEnv env()
    {
        rp::VeeamCommandEnv env;
        env.default_config_path = [this] {
            ++default_path_calls;
            return default_path();
        };
        env.load_secrets = [this] {
            ++load_secrets_calls;
            return load_secrets();
        };
        env.make_http = [this](const rp::HttpClientOptions& options)
            -> std::unique_ptr<rp::IHttpClient> {
            ++make_http_calls;
            http_options = options;
            return make_http();
        };
        env.client_options.logger = logger;
        env.client_options.sleep = [this](std::chrono::milliseconds wait) {
            sleeps.push_back(wait);
        };
        env.client_options.jitter = [] { return 0.0; };
        return env;
    }

    Run run(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        const int exit_code = rp::run_veeam_command(args, out, err, env());
        return {exit_code, out.str(), err.str()};
    }

    // `veeam list --config <the temp config>`.
    Run run_list()
    {
        const std::string path_arg = utf8(config_path);
        return run(Args{"list", "--config", path_arg});
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    rp::test::TempDir dir;
    std::filesystem::path config_path;
    rp::test::FakeHttpClient http;
    std::function<std::filesystem::path()> default_path = [this] { return config_path; };
    std::function<rp::Secrets()> load_secrets = [] {
        return rp::Secrets{kUsername, kPassword, std::nullopt};
    };
    std::function<std::unique_ptr<rp::IHttpClient>()> make_http = [this] {
        return std::make_unique<ForwardingHttpClient>(http);
    };
    int default_path_calls = 0;
    int load_secrets_calls = 0;
    int make_http_calls = 0;
    std::optional<rp::HttpClientOptions> http_options;
    std::vector<std::chrono::milliseconds> sleeps;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
};

} // namespace

// --- The command line --------------------------------------------------------

TEST_CASE("rpworker veeam prints usage and exits 64 for arguments it doesn't understand",
          "[veeam_command]")
{
    const Args args = GENERATE(
        Args{},
        Args{""},
        Args{"lst"},
        Args{"List"},
        Args{"list", "extra"},
        Args{"list", "x.json"},
        Args{"list", "--config"},
        Args{"list", "--CONFIG", "x.json"},
        Args{"list", "--config", "x.json", "extra"},
        Args{"list", "--config", "x.json", "--config", "y.json"},
        Args{"--config", "x.json", "list"},
        Args{"list", "list"});
    CAPTURE(args);
    Harness lab;

    const Run result = lab.run(args);
    REQUIRE(result.exit_code == 64);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == kUsage);
    // A usage error looks up nothing: no ProgramData, no secrets, no Veeam.
    REQUIRE(lab.default_path_calls == 0);
    REQUIRE(lab.load_secrets_calls == 0);
    REQUIRE(lab.make_http_calls == 0);
}

TEST_CASE("rpworker veeam list exits 1 with the error when the config doesn't load",
          "[veeam_command]")
{
    Harness lab;
    const std::string missing = utf8(lab.dir.path() / "missing.json");

    const Run result = lab.run(Args{"list", "--config", missing});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + missing + ": cannot read config file\n");
    REQUIRE(lab.default_path_calls == 0);
    REQUIRE(lab.make_http_calls == 0);
    REQUIRE(lab.http.requests().empty());
}

TEST_CASE("rpworker veeam list reports an invalid config without its values", "[veeam_command]")
{
    Harness lab(R"({"veeam_url": "http://SENTINEL-2a9f"})");

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE_THAT(result.err, ContainsSubstring("config error: "));
    REQUIRE_THAT(result.err, !ContainsSubstring("SENTINEL"));
    REQUIRE(lab.make_http_calls == 0);
}

TEST_CASE("rpworker veeam list reports a --config path that isn't UTF-8", "[veeam_command]")
{
    const std::string path_arg = GENERATE(std::string("\xFF.json"), std::string("a\xC3.json"));
    CAPTURE(path_arg);
    Harness lab;

    const Run result = lab.run(Args{"list", "--config", path_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: the --config path is not valid UTF-8\n");
    REQUIRE(lab.default_path_calls == 0);
}

TEST_CASE("rpworker veeam list reads the default path without --config", "[veeam_command]")
{
    Harness lab;
    lab.load_secrets = [] { return rp::Secrets{}; };

    const Run result = lab.run(Args{"list"});
    REQUIRE(lab.default_path_calls == 1);
    // The config loaded, so the command got as far as the secrets.
    REQUIRE(result.err == "config error: RP_VEEAM_USERNAME is not set\n");
    REQUIRE(result.exit_code == 1);
}

TEST_CASE("rpworker veeam list reports a default path it can't find", "[veeam_command]")
{
    Harness lab;
    lab.default_path = []() -> std::filesystem::path {
        throw rp::ConfigError("", "cannot find the ProgramData folder");
    };

    const Run result = lab.run(Args{"list"});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: cannot find the ProgramData folder\n");
}

TEST_CASE("rpworker veeam list reports any other config failure without its message",
          "[veeam_command]")
{
    Harness lab;
    const bool in_secrets = GENERATE(false, true);
    CAPTURE(in_secrets);
    if (in_secrets) {
        lab.load_secrets = []() -> rp::Secrets { throw std::runtime_error("SENTINEL-d51f"); };
    } else {
        lab.default_path = []() -> std::filesystem::path {
            throw std::runtime_error("SENTINEL-d51f");
        };
    }

    const Run result = lab.run(Args{"list"});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: unexpected failure\n");
    REQUIRE(lab.make_http_calls == 0);
}

TEST_CASE("rpworker veeam list reports a secret variable that can't be read", "[veeam_command]")
{
    Harness lab;
    lab.load_secrets = []() -> rp::Secrets {
        throw rp::ConfigError("RP_VEEAM_PASSWORD",
                              "environment variable RP_VEEAM_PASSWORD is not valid Unicode");
    };

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err ==
            "config error: environment variable RP_VEEAM_PASSWORD is not valid Unicode\n");
    REQUIRE(lab.make_http_calls == 0);
}

TEST_CASE("rpworker veeam list needs RP_VEEAM_USERNAME and RP_VEEAM_PASSWORD, username first",
          "[veeam_command]")
{
    using Maybe = std::optional<std::string>;
    struct Case {
        Maybe username;
        Maybe password;
        std::string expected;
    };
    const Case c = GENERATE(
        Case{std::nullopt, std::nullopt, "config error: RP_VEEAM_USERNAME is not set\n"},
        Case{std::nullopt, kPassword, "config error: RP_VEEAM_USERNAME is not set\n"},
        Case{"", kPassword, "config error: RP_VEEAM_USERNAME is not set\n"},
        Case{kUsername, std::nullopt, "config error: RP_VEEAM_PASSWORD is not set\n"},
        Case{kUsername, "", "config error: RP_VEEAM_PASSWORD is not set\n"});
    CAPTURE(c.expected);
    Harness lab;
    lab.load_secrets = [c] { return rp::Secrets{c.username, c.password, std::nullopt}; };

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == c.expected);
    REQUIRE(lab.make_http_calls == 0);
    REQUIRE(lab.http.requests().empty());
}

TEST_CASE("rpworker veeam's real environment reads ProgramData and the process environment",
          "[veeam_command]")
{
    const rp::VeeamCommandEnv env = rp::default_veeam_command_env();

    REQUIRE(env.default_config_path() == rp::default_config_path());
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, "user-5d2e");
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::Secrets secrets = env.load_secrets();
    REQUIRE(secrets.veeam_username == std::optional<std::string>{"user-5d2e"});
    REQUIRE_FALSE(secrets.veeam_password);
    // A real HttpClient; making one sends nothing.
    REQUIRE(env.make_http(rp::HttpClientOptions{}) != nullptr);
    // Log lines never go to stdout, where the table is, and only warnings and
    // worse are written at all.
    REQUIRE(env.client_options.logger != nullptr);
    REQUIRE(env.client_options.logger != spdlog::default_logger());
    REQUIRE(env.client_options.logger->level() == spdlog::level::warn);
}
