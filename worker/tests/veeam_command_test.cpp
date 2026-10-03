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

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <ostream>
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
                           "rpworker veeam list [--config <path>] [--record <dir>] | "
                           "rpworker graph list [--hash] [--config <path>] [--record <dir>] | "
                           "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
                           "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] "
                           "[--config <path>] [--record <dir>] | "
                           "rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
                           "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] "
                           "[--config <path>] [--record <dir>] [--json <file>]\n";

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
    "graph_tenant_id": "00000000-0000-0000-0000-000000000001",
    "graph_client_id": "00000000-0000-0000-0000-000000000002",
    "test_mailbox": "restoretest@example.onmicrosoft.com",
    "test_site_id": "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002",
    "test_library_id": "b!library",
    "test_onedrive_drive_id": "b!drive",
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

    // The same, onto the streams given.
    int run_list(std::ostream& out, std::ostream& err)
    {
        const std::string path_arg = utf8(config_path);
        return rp::run_veeam_command(Args{"list", "--config", path_arg}, out, err, env());
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
        return std::make_unique<rp::test::ForwardingHttpClient>(http);
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
        Args{"list", "list"},
        Args{"list", "--record"},
        Args{"list", "--RECORD", "rec"},
        Args{"list", "--record", "a", "--record", "b"},
        Args{"list", "--record", "a", "--config"});
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

// --- Veeam ---------------------------------------------------------------------

namespace {

// The recorded organisation list with one entry per (id, name), each a copy of
// the recorded organisation.
HttpResponse orgs_response(const std::vector<std::pair<std::string, std::string>>& orgs)
{
    json fixture = load_fixture_json("veeam", "organizations-200");
    const json recorded = fixture["body"]["results"].at(0);
    json results = json::array();
    for (const auto& [id, name] : orgs) {
        json org = recorded;
        org["id"] = id;
        org["name"] = name;
        results.push_back(std::move(org));
    }
    fixture["body"]["results"] = std::move(results);
    return to_response(fixture);
}

const std::string kOtherOrgId = "0b5e0a52-6d3c-4f55-9a53-6f6f2c7c1d11";

std::size_t logouts(const Harness& lab)
{
    return lab.http.count(HttpMethod::post, kLogoutUrl);
}

} // namespace

TEST_CASE("rpworker veeam list gives the HTTP client the config's CA file and pin",
          "[veeam_command]")
{
    const std::string ca_file = std::string{RP_FIXTURE_DIR} + "/veeam/rest-certificate.pem";
    Harness lab(config_json(kOrgName, "\"veeam_ca_file\": " + json(ca_file).dump() +
                                          ", \"veeam_cert_sha256\": \"" + kLabCertSha256 +
                                          "\","));

    const Run result = lab.run_list();
    REQUIRE(result.err.empty());
    REQUIRE(result.exit_code == 0);
    REQUIRE(lab.make_http_calls == 1);
    REQUIRE(lab.http_options);
    CHECK(lab.http_options->ca_file == std::optional<std::string>{ca_file});
    CHECK(lab.http_options->pinned_cert_sha256 == std::optional<std::string>{kLabCertSha256});
    // The injected logger and waits reach the HTTP layer too.
    CHECK(lab.http_options->logger == lab.logger);
    CHECK(lab.http_options->sleep);
    CHECK(lab.http_options->jitter);
}

TEST_CASE("rpworker veeam list without a CA file leaves the HTTP client's trust as it is",
          "[veeam_command]")
{
    Harness lab;

    REQUIRE(lab.run_list().exit_code == 0);
    REQUIRE(lab.http_options);
    CHECK_FALSE(lab.http_options->ca_file);
    CHECK_FALSE(lab.http_options->pinned_cert_sha256);
}

TEST_CASE("rpworker veeam list signs in with the secrets, then logs out", "[veeam_command]")
{
    Harness lab;

    REQUIRE(lab.run_list().exit_code == 0);
    const std::vector<HttpRequest> requests = lab.http.requests();
    REQUIRE(requests.size() == 4);
    CHECK(requests[0].url == kTokenUrl);
    CHECK(requests[0].body.find("&password=" + kPasswordForm + "&") != std::string::npos);
    CHECK(requests[1].url == orgs_url());
    CHECK(requests[2].url == points_url());
    CHECK(requests[3].url == kLogoutUrl);
}

TEST_CASE("rpworker veeam list exits 2 when Veeam refuses the sign-in", "[veeam_command]")
{
    Harness lab;
    lab.http.on(HttpMethod::post, kTokenUrl, {load_fixture("veeam", "token-rejected-401")});

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 2);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "veeam error: Veeam POST /v8/token: HTTP 401: The server has rejected "
                          "the client credentials.\n");
    // Never signed in, so there is nothing to log out of.
    REQUIRE(logouts(lab) == 0);
}

TEST_CASE("rpworker veeam list exits 2 when Veeam refuses a call after the sign-in, and logs out",
          "[veeam_command]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {make_response(403, R"({"message":"Access denied."})")});

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 2);
    REQUIRE(result.out.empty());
    REQUIRE(result.err ==
            "veeam error: Veeam GET /v8/Organizations?limit=1000&offset=0: HTTP 403: Access "
            "denied.\n");
    REQUIRE(logouts(lab) == 1);
}

TEST_CASE("rpworker veeam list exits 3 when Veeam can't be reached", "[veeam_command]")
{
    SECTION("no connection at the sign-in")
    {
        Harness lab;
        lab.http.on(HttpMethod::post, kTokenUrl, [](const HttpRequest&) -> HttpResponse {
            throw rp::HttpError("connection refused", rp::TransportError::connect, 0, 1);
        });

        const Run result = lab.run_list();
        REQUIRE(result.exit_code == 3);
        REQUIRE(result.out.empty());
        REQUIRE_THAT(result.err, Catch::Matchers::StartsWith("veeam error: Veeam "));
        REQUIRE_THAT(result.err, ContainsSubstring("connection refused"));
        REQUIRE(logouts(lab) == 0);
        // Retried without waiting: the test's sleep only records.
        REQUIRE(lab.http.count(HttpMethod::post, kTokenUrl) == 5);
        REQUIRE(lab.sleeps.size() == 4);
    }
    SECTION("a gateway answering 503 to every attempt after the sign-in")
    {
        Harness lab;
        lab.http.on(HttpMethod::get, orgs_url(), {make_response(503)});

        const Run result = lab.run_list();
        REQUIRE(result.exit_code == 3);
        REQUIRE(result.out.empty());
        REQUIRE(result.err == "veeam error: Veeam GET /v8/Organizations?limit=1000&offset=0: "
                              "HTTP 503 after 5 attempts\n");
        REQUIRE(logouts(lab) == 1);
    }
}

TEST_CASE("rpworker veeam list exits 4 for any other Veeam error, and logs out", "[veeam_command]")
{
    struct Case {
        std::string fixture;
        std::string expected;
    };
    const Case c = GENERATE(
        Case{"restore-points-unknown-org-404",
             "veeam error: Veeam GET /v8/RestorePoints?organizationId=" + kOrgId +
                 "&limit=1000&offset=0: HTTP 404 (ResourceNotFound): Organization does not "
                 "exist: ID 00000000-0000-0000-0000-000000000001.\n"},
        Case{"route-404-empty", "veeam error: Veeam GET /v8/RestorePoints?organizationId=" +
                                    kOrgId + "&limit=1000&offset=0: HTTP 404\n"});
    CAPTURE(c.fixture);
    Harness lab;
    lab.http.on(HttpMethod::get, points_url(), {load_fixture("veeam", c.fixture)});

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 4);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == c.expected);
    REQUIRE(logouts(lab) == 1);
}

TEST_CASE("rpworker veeam list fails as a whole when any organisation's restore points fail",
          "[veeam_command]")
{
    // Both organisations list; the second one's points vanish in between.
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {orgs_response({{kOrgId, kOrgName}, {kOtherOrgId, "Zeta.onmicrosoft.com"}})});
    lab.http.on(HttpMethod::get, points_url(kOtherOrgId),
                {load_fixture("veeam", "restore-points-unknown-org-404")});

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 4);
    // No partial table.
    REQUIRE(result.out.empty());
    REQUIRE_THAT(result.err,
                 Catch::Matchers::StartsWith("veeam error: Veeam GET "
                                             "/v8/RestorePoints?organizationId=" +
                                             kOtherOrgId));
    REQUIRE(lab.http.count(HttpMethod::get, points_url()) == 1);
    REQUIRE(logouts(lab) == 1);
}

TEST_CASE("rpworker veeam list reports an unexpected failure without its message, and logs out",
          "[veeam_command]")
{
    SECTION("after the sign-in")
    {
        // Not a VeeamError: a failure the command doesn't expect.
        Harness lab;
        lab.http.on(HttpMethod::get, points_url(), [](const HttpRequest&) -> HttpResponse {
            throw std::logic_error("SENTINEL-6b0f");
        });

        const Run result = lab.run_list();
        REQUIRE(result.exit_code == 1);
        REQUIRE(result.out.empty());
        REQUIRE(result.err == "error: unexpected failure\n");
        REQUIRE(logouts(lab) == 1);
    }
    SECTION("one that isn't a std::exception")
    {
        Harness lab;
        lab.http.on(HttpMethod::get, points_url(),
                    [](const HttpRequest&) -> HttpResponse { throw 42; });

        const Run result = lab.run_list();
        REQUIRE(result.exit_code == 1);
        REQUIRE(result.out.empty());
        REQUIRE(result.err == "error: unexpected failure\n");
        REQUIRE(logouts(lab) == 1);
    }
    SECTION("writing the table")
    {
        // Every list read, then stdout fails: no exception escapes, and the
        // command still logs out.
        Harness lab;
        rp::test::FailingStreamBuf failing;
        std::ostream out(&failing);
        out.exceptions(std::ios::badbit);
        std::ostringstream err;

        REQUIRE(lab.run_list(out, err) == 1);
        REQUIRE(err.str() == "error: unexpected failure\n");
        REQUIRE(lab.http.count(HttpMethod::get, points_url()) == 1);
        REQUIRE(logouts(lab) == 1);
    }
    SECTION("making the HTTP client")
    {
        Harness lab;
        const bool throws = GENERATE(true, false);
        CAPTURE(throws);
        lab.make_http = [throws]() -> std::unique_ptr<rp::IHttpClient> {
            if (throws) {
                throw std::runtime_error("SENTINEL-6b0f");
            }
            return nullptr;
        };

        const Run result = lab.run_list();
        REQUIRE(result.exit_code == 1);
        REQUIRE(result.out.empty());
        REQUIRE(result.err == "error: unexpected failure\n");
        REQUIRE(lab.http.requests().empty());
    }
}

// --- The table -----------------------------------------------------------------

namespace {

const std::string kHeader = "  ORGANIZATION                     BACKUP TIME                   EX  SP  "
                            "OD  TM  LONG-TERM  RESTORE POINT ID\n";
const std::string kNewestRow = "* RestoreProofLab.onmicrosoft.com  2026-09-25T19:37:15.2145203Z  "
                               "x   x   x   -   no         " +
                               kNewestPoint + "\n";
const std::string kOldestRow = "* RestoreProofLab.onmicrosoft.com  2026-09-25T19:24:31.0936821Z  "
                               "x   x   x   -   no         " +
                               kOldestPoint + "\n";

const std::string kMissingOrg = "veeam error: organisation RestoreProofLab.onmicrosoft.com "
                                "(veeam_org_name) not found in Veeam\n";

} // namespace

TEST_CASE("rpworker veeam list prints the lab's organisation and its two restore points",
          "[veeam_command]")
{
    Harness lab;

    const Run result = lab.run_list();
    REQUIRE(result.err.empty());
    REQUIRE(result.out == kHeader + kNewestRow + kOldestRow + "\n" +
                              "1 organisation(s), 2 restore point(s); * = veeam_org_name\n");
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker veeam list marks veeam_org_name in any case", "[veeam_command]")
{
    Harness lab(config_json("RESTOREPROOFLAB.onmicrosoft.COM"));

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 0);
    REQUIRE(result.out.starts_with(kHeader + kNewestRow + kOldestRow));
}

TEST_CASE("rpworker veeam list shows each workload flag and long-term copies", "[veeam_command]")
{
    json fixture = load_fixture_json("veeam", "restore-points-200");
    json& oldest = fixture["body"]["results"].at(1);
    oldest["isExchange"] = false;
    oldest["isSharePoint"] = false;
    oldest["isOneDrive"] = false;
    oldest["isTeams"] = true;
    oldest["isLongTermCopy"] = true;
    Harness lab;
    lab.http.on(HttpMethod::get, points_url(), {to_response(fixture)});

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == 0);
    REQUIRE(result.out == kHeader + kNewestRow +
                              "* RestoreProofLab.onmicrosoft.com  2026-09-25T19:24:31.0936821Z  "
                              "-   -   -   x   yes        " +
                              kOldestPoint + "\n\n" +
                              "1 organisation(s), 2 restore point(s); * = veeam_org_name\n");
}

TEST_CASE("rpworker veeam list prints an organisation with no restore points on one row",
          "[veeam_command]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, points_url(), {load_fixture("veeam", "restore-points-empty-200")});

    const Run result = lab.run_list();
    REQUIRE(result.err.empty());
    REQUIRE(result.out ==
            "  ORGANIZATION                     BACKUP TIME          EX  SP  OD  TM  LONG-TERM  "
            "RESTORE POINT ID\n"
            "* RestoreProofLab.onmicrosoft.com  (no restore points)\n"
            "\n"
            "1 organisation(s), 0 restore point(s); * = veeam_org_name\n");
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker veeam list sorts organisations by name in any case, then ID, and pads by "
          "character",
          "[veeam_command]")
{
    const std::string alpha_id = "a1a1a1a1-0000-4000-8000-000000000001";
    const std::string same_lower_id = "11111111-0000-4000-8000-000000000001";
    const std::string same_upper_id = "22222222-0000-4000-8000-000000000002";
    // "ü" is two bytes in UTF-8 but one character: the column is padded by
    // characters.
    const std::string zurich = "Z\xc3\xbcrich-Versicherung-Test.onmicrosoft.com";
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {orgs_response({{kOtherOrgId, zurich},
                                {same_upper_id, "Same.onmicrosoft.com"},
                                {kOrgId, kOrgName},
                                {same_lower_id, "same.onmicrosoft.com"},
                                {alpha_id, "alpha.onmicrosoft.com"}})});
    for (const std::string& id : {kOtherOrgId, alpha_id, same_lower_id, same_upper_id}) {
        lab.http.on(HttpMethod::get, points_url(id),
                    {load_fixture("veeam", "restore-points-empty-200")});
    }

    const Run result = lab.run_list();
    REQUIRE(result.err.empty());
    REQUIRE(result.out ==
            "  ORGANIZATION                              BACKUP TIME                   EX  SP  OD  "
            "TM  LONG-TERM  RESTORE POINT ID\n"
            "  alpha.onmicrosoft.com                     (no restore points)\n"
            "* RestoreProofLab.onmicrosoft.com           2026-09-25T19:37:15.2145203Z  x   x   x   "
            "-   no         " +
                kNewestPoint +
                "\n"
                "* RestoreProofLab.onmicrosoft.com           2026-09-25T19:24:31.0936821Z  x   x   "
                "x   -   no         " +
                kOldestPoint +
                "\n"
                "  same.onmicrosoft.com                      (no restore points)\n"
                "  Same.onmicrosoft.com                      (no restore points)\n"
                "  " +
                zurich +
                "  (no restore points)\n"
                "\n"
                "5 organisation(s), 2 restore point(s); * = veeam_org_name\n");
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker veeam list prints the table, then exits 4, when veeam_org_name isn't there",
          "[veeam_command]")
{
    // The one organisation's name also carries a newline and a right-to-left
    // override from the server, which must not forge or reorder a line.
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {orgs_response({{kOtherOrgId, "Evil\nOrg\xe2\x80\xae"}})});
    lab.http.on(HttpMethod::get, points_url(kOtherOrgId),
                {load_fixture("veeam", "restore-points-empty-200")});

    const Run result = lab.run_list();
    REQUIRE(result.out == "  ORGANIZATION  BACKUP TIME          EX  SP  OD  TM  LONG-TERM  "
                          "RESTORE POINT ID\n"
                          "  Evil Org      (no restore points)\n"
                          "\n"
                          "1 organisation(s), 0 restore point(s); * = veeam_org_name\n");
    REQUIRE(result.err == kMissingOrg);
    REQUIRE(result.exit_code == 4);
    REQUIRE(logouts(lab) == 1);
}

TEST_CASE("rpworker veeam list says so when Veeam has no organisations, and exits 4",
          "[veeam_command]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(), {orgs_response({})});

    const Run result = lab.run_list();
    REQUIRE(result.out == "no organisations in Veeam\n"
                          "\n"
                          "0 organisation(s), 0 restore point(s); * = veeam_org_name\n");
    REQUIRE(result.err == kMissingOrg);
    REQUIRE(result.exit_code == 4);
    REQUIRE(lab.http.count(HttpMethod::get, points_url()) == 0);
    REQUIRE(logouts(lab) == 1);
}

// --- Secrets -------------------------------------------------------------------

TEST_CASE("rpworker veeam list never prints or logs the password or a token", "[veeam_command]")
{
    // What a proxy or a broken server might echo back: the posted form, and
    // the password and tokens in the other forms rp::redact() knows.
    const std::string echoed = "grant_type=password&username=x&password=" + kPasswordForm +
                               "&refresh_token=" + kRefreshToken + " access_token=" +
                               kAccessToken + "\npassword: " + kPassword;
    struct Case {
        std::string name;
        int exit_code;
        bool signs_in;
        std::function<void(Harness&)> arrange;
    };
    const Case c = GENERATE_COPY(
        Case{"success", 0, true, [](Harness&) {}},
        Case{"sign-in refused", 2, false,
             [](Harness& lab) {
                 lab.http.on(HttpMethod::post, kTokenUrl,
                             {load_fixture("veeam", "token-rejected-401")});
             }},
        Case{"sign-in answered with the form echoed", 4, false,
             [echoed](Harness& lab) {
                 lab.http.on(HttpMethod::post, kTokenUrl,
                             {make_response(400, json{{"message", echoed}}.dump())});
             }},
        Case{"Veeam unreachable after the sign-in", 3, true,
             [](Harness& lab) { lab.http.on(HttpMethod::get, orgs_url(), {make_response(503)}); }},
        Case{"a 4xx whose body echoes the secrets", 4, true,
             [echoed](Harness& lab) {
                 lab.http.on(HttpMethod::get, points_url(),
                             {make_response(400, json{{"message", echoed},
                                                      {"errorCode", "ParameterValidationFailure"}}
                                                     .dump())});
             }});
    CAPTURE(c.name);
    Harness lab;
    c.arrange(lab);

    const Run result = lab.run_list();
    REQUIRE(result.exit_code == c.exit_code);
    const std::string log = lab.log();
    CAPTURE(result.out, result.err, log);
    for (const std::string& text : {result.out, result.err, log}) {
        CHECK_THAT(text, !ContainsSubstring(kPassword));
        CHECK_THAT(text, !ContainsSubstring(kPasswordForm));
        CHECK_THAT(text, !ContainsSubstring("Sentinel"));
        CHECK_THAT(text, !ContainsSubstring(kAccessToken));
        CHECK_THAT(text, !ContainsSubstring(kRefreshToken));
        CHECK_THAT(text, !ContainsSubstring("4c1e"));
    }
    // After a sign-in the client has logged, so there was a log to leak into.
    CHECK(log.empty() == !c.signs_in);
}

// --- --record (Q2.1) -----------------------------------------------------------

namespace {

std::vector<std::string> files_in(const std::filesystem::path& dir)
{
    std::vector<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        names.push_back(utf8(entry.path().filename()));
    }
    std::ranges::sort(names);
    return names;
}

std::string read_text(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), {}};
}

// `veeam list --config <the temp config> --record <dir>`.
Run run_recorded(Harness& lab, const std::filesystem::path& dir)
{
    const std::string config_arg = utf8(lab.config_path);
    const std::string record_arg = utf8(dir);
    return lab.run(Args{"list", "--config", config_arg, "--record", record_arg});
}

const std::string kLabTable = kHeader + kNewestRow + kOldestRow + "\n" +
                              "1 organisation(s), 2 restore point(s); * = veeam_org_name\n";

} // namespace

TEST_CASE("rpworker veeam list --record writes each exchange, and a replay prints the same "
          "table",
          "[veeam_command][record]")
{
    Harness lab;
    const std::filesystem::path rec = lab.dir.path() / "rec";

    const Run result = run_recorded(lab, rec);
    REQUIRE(result.err.empty());
    REQUIRE(result.exit_code == 0);
    REQUIRE(result.out == kLabTable + "recorded 4 exchange(s) in " + utf8(rec) + "\n");
    REQUIRE(files_in(rec) == std::vector<std::string>{"veeam"});
    REQUIRE(files_in(rec / "veeam") ==
            std::vector<std::string>{"001-post-v8-token.json", "002-get-v8-organizations.json",
                                     "003-get-v8-restorepoints.json",
                                     "004-post-v8-token-logout.json"});
    for (const std::string& name : files_in(rec / "veeam")) {
        const std::string text = read_text(rec / "veeam" / name);
        CAPTURE(name);
        CHECK_THAT(text, !ContainsSubstring("Sentinel"));
        CHECK_THAT(text, !ContainsSubstring(kPasswordForm));
        CHECK_THAT(text, !ContainsSubstring(kAccessToken));
        CHECK_THAT(text, !ContainsSubstring(kRefreshToken));
    }
    const json token = json::parse(read_text(rec / "veeam" / "001-post-v8-token.json"));
    CHECK(token["request"] == "POST /v8/token");
    CHECK(token["body"]["access_token"] == "[REDACTED]");
    CHECK(json::parse(read_text(rec / "veeam" / "002-get-v8-organizations.json"))["request"] ==
          "GET /v8/Organizations?limit=1000&offset=0");

    // The recording alone answers a second run: nothing else is routed.
    Harness replay;
    rp::test::FakeHttpClient recorded;
    REQUIRE(recorded.serve_recording(rec / "veeam") == 4);
    replay.make_http = [&recorded] {
        return std::make_unique<rp::test::ForwardingHttpClient>(recorded);
    };
    const Run again = replay.run_list();
    CHECK(again.err.empty());
    CHECK(again.exit_code == 0);
    CHECK(again.out == kLabTable);
    CHECK(recorded.requests().size() == 4);
}

TEST_CASE("rpworker veeam list --record records a failed run too, which keeps its exit code",
          "[veeam_command][record]")
{
    Harness lab;
    lab.http.on(HttpMethod::post, kTokenUrl, {load_fixture("veeam", "token-rejected-401")});
    const std::filesystem::path rec = lab.dir.path() / "rec";

    const Run result = run_recorded(lab, rec);
    REQUIRE(result.exit_code == 2);
    REQUIRE(result.out == "recorded 1 exchange(s) in " + utf8(rec) + "\n");
    REQUIRE(files_in(rec / "veeam") == std::vector<std::string>{"001-post-v8-token.json"});
    CHECK(json::parse(read_text(rec / "veeam" / "001-post-v8-token.json"))["status"] == 401);
}

TEST_CASE("rpworker veeam list --record exits 1 when an exchange is refused for a secret",
          "[veeam_command][record]")
{
    // Veeam echoing the password where no rule of redact() looks for one.
    Harness lab;
    json orgs = load_fixture_json("veeam", "organizations-200");
    orgs["body"]["results"][0]["description"] = kPassword;
    lab.http.on(HttpMethod::get, orgs_url(), {to_response(orgs)});
    const std::filesystem::path rec = lab.dir.path() / "rec";

    const Run result = run_recorded(lab, rec);
    // The listing itself is untouched: recording never changes what the command sees.
    REQUIRE(result.out == kLabTable + "recorded 3 exchange(s) in " + utf8(rec) + "\n");
    REQUIRE(result.err ==
            "record error: veeam/002-get-v8-organizations.json: refused: it holds a known secret\n");
    REQUIRE(result.exit_code == 1);
    REQUIRE(files_in(rec / "veeam") ==
            std::vector<std::string>{"001-post-v8-token.json", "003-get-v8-restorepoints.json",
                                     "004-post-v8-token-logout.json"});
}

TEST_CASE("rpworker veeam list --record refuses a folder that isn't empty, before any request",
          "[veeam_command][record]")
{
    Harness lab;
    const std::filesystem::path old = lab.dir.write("config-copy.json", "{}");
    const std::string config_arg = utf8(lab.config_path);
    const std::string record_arg = utf8(lab.dir.path());

    const Run result = lab.run(Args{"list", "--record", record_arg, "--config", config_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err ==
            "config error: " + record_arg + ": the --record folder is not empty\n");
    REQUIRE(lab.make_http_calls == 0);
    CHECK(std::filesystem::exists(old));
}

TEST_CASE("rpworker veeam list reports a --record path that isn't UTF-8", "[veeam_command][record]")
{
    Harness lab;
    const std::string config_arg = utf8(lab.config_path);

    const Run result = lab.run(Args{"list", "--config", config_arg, "--record", "rec\xff"});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.err == "config error: the --record path is not valid UTF-8\n");
    REQUIRE(lab.make_http_calls == 0);
}

TEST_CASE("rpworker veeam list replays the lab's live recording (Q2.1's Done when)",
          "[veeam_command][record]")
{
    // `rpworker veeam list --record` against the lab's Veeam on 2026-10-01:
    // tests/fixtures/veeam/q21-veeam-list/. The recording alone answers the
    // command; the expected rows are read from it, never spelled here.
    const std::filesystem::path dir =
        std::filesystem::path{RP_FIXTURE_DIR} / "veeam" / "q21-veeam-list";
    rp::test::FakeHttpClient recorded;
    REQUIRE(recorded.serve_recording(dir) == 4);
    Harness lab;
    lab.make_http = [&recorded] {
        return std::make_unique<rp::test::ForwardingHttpClient>(recorded);
    };

    const Run result = lab.run_list();
    REQUIRE(result.err.empty());
    REQUIRE(result.exit_code == 0);
    // The token, the organisations, the restore points and the logout, each once.
    CHECK(recorded.requests().size() == 4);

    const json points =
        json::parse(read_text(dir / "003-get-v8-restorepoints.json"))["body"]["results"];
    REQUIRE(points.size() >= 2);
    // Newest first, as Veeam's backupTime strings sort; each ID on its row.
    std::vector<std::pair<std::string, std::string>> expected;
    for (const json& point : points) {
        expected.emplace_back(point.at("backupTime").get<std::string>(),
                              point.at("id").get<std::string>());
    }
    std::ranges::sort(expected, std::greater<>{});
    std::size_t at = 0;
    for (const auto& [time, id] : expected) {
        CAPTURE(time, id);
        const std::size_t row = result.out.find("* RestoreProofLab.onmicrosoft.com  " + time, at);
        REQUIRE(row != std::string::npos);
        const std::size_t end = result.out.find('\n', row);
        CHECK(result.out.substr(row, end - row).ends_with(id));
        at = end;
    }
    CHECK_THAT(result.out, ContainsSubstring("1 organisation(s), " +
                                             std::to_string(points.size()) +
                                             " restore point(s); * = veeam_org_name\n"));
    // Nothing secret was recorded: the tokens are the placeholder.
    const json token = json::parse(read_text(dir / "001-post-v8-token.json"));
    CHECK(token["body"]["access_token"] == "[REDACTED]");
    CHECK(token["body"]["refresh_token"] == "[REDACTED]");
}
