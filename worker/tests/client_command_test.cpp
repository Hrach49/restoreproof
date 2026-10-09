// W4.10: `rpworker client check --profile-file <file>` (rp::run_client_command)
// against W2.2's recorded Graph replies in tests/fixtures/graph/, served by a
// FakeHttpClient. The profile is a file the test writes; the command reads no
// config. Nothing here touches the network. Failure paths first: the
// arguments, the file, the vault, then each Graph failure's exit code, then
// the three tables under the profile's heading. The usage line is
// rp::kCliUsage; cli_test.cpp holds its text.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "test_support.hpp"

#include <rp/cli.hpp>
#include <rp/client_command.hpp>
#include <rp/client_profile.hpp>
#include <rp/config.hpp>
#include <rp/graph_client.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

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
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
using Args = std::vector<std::string_view>;

namespace {

using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::test::load_fixture;
using rp::test::make_response;
using namespace rp::test::graph_lab;

const std::string kUsage{rp::kCliUsage};
constexpr const char* kOrgName = "RestoreProofLab.onmicrosoft.com";

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// The lab's profile: the tenant, app and restore targets the recorded
// replies show, as a restoreproof.client-profile.v1 object.
json lab_profile()
{
    const Lab_values& v = lab_values();
    return json{{"format", std::string{rp::kClientProfileFormat}},
                {"veeam_org_name", kOrgName},
                {"graph_tenant_id", kTenant},
                {"graph_client_id", kClient},
                {"test_mailbox", v.mailbox},
                {"test_site_id", v.site_id},
                {"test_library_id", v.library_id},
                {"test_onedrive_drive_id", v.onedrive_drive_id},
                {"test_onedrive_folder_id", v.folder_id}};
}

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

// Everything run_client_command reaches outside itself: a profile file in a
// temp directory, the secrets (the test certificate), the Graph HTTP client
// and a logger that writes every level to a string. The config's path is
// never asked for.
struct Harness {
    Harness()
    {
        profile_path = dir.write("profile.json", lab_profile().dump(2));
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("client_command_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::trace);
        graph_http.on(HttpMethod::post, kTokenUrl, {token_response()});
    }

    rp::GraphCommandEnv env()
    {
        rp::GraphCommandEnv env;
        env.default_config_path = [this] {
            ++default_config_calls;
            return dir.path() / "never-read.json";
        };
        env.default_vault_path = [this] {
            ++default_vault_calls;
            return dir.path() / "default-vault.bin";
        };
        env.load_secrets = [this](const std::filesystem::path& vault) {
            ++load_secrets_calls;
            vault_read = vault;
            return load_secrets();
        };
        env.make_graph_http = [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            ++make_graph_http_calls;
            return std::make_unique<rp::test::ForwardingHttpClient>(graph_http);
        };
        env.make_download_http = [this]() -> std::unique_ptr<rp::IHttpClient> {
            ++make_download_http_calls;
            return nullptr;
        };
        env.client_options.logger = logger;
        env.client_options.now = [] { return std::chrono::steady_clock::time_point{}; };
        env.client_options.wall_now = [] { return kNow; };
        env.client_options.sleep = [](std::chrono::milliseconds) {};
        env.client_options.jitter = [] { return 0.0; };
        return env;
    }

    Run run(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        const int exit_code = rp::run_client_command(args, out, err, env());
        return {exit_code, out.str(), err.str()};
    }

    // `check --profile-file <the temp profile>`.
    Run run_check()
    {
        return run(Args{"check", "--profile-file", utf8(profile_path)});
    }

    // All three targets empty, their guards passing.
    void serve_empty()
    {
        graph_http.on(HttpMethod::get, inbox_url(), {load_fixture("graph", "mailbox-inbox-200")});
        graph_http.on(HttpMethod::get, mail_list_url(false),
                      {load_fixture("graph", "mail-list-200-empty")});
        graph_http.on(HttpMethod::get, drive_url(), {load_fixture("graph", "restoretarget-drive-200")});
        serve_library_root(graph_http);
        graph_http.on(HttpMethod::get, library_children_url(),
                      {load_fixture("graph", "restoretarget-children-200-empty")});
        graph_http.on(HttpMethod::get, folder_url(), {load_fixture("graph", "onedrive-folder-200")});
        graph_http.on(HttpMethod::get, folder_children_url(),
                      {load_fixture("graph", "onedrive-children-200-empty")});
    }

    // One item in each target, as recorded; nothing is downloaded.
    void serve_one_each()
    {
        serve_empty();
        graph_http.on(HttpMethod::get, mail_list_url(false),
                      {load_fixture("graph", "mail-list-200-one-item")});
        graph_http.on(HttpMethod::get, library_children_url(),
                      {load_fixture("graph", "restoretarget-children-200-one-item")});
        graph_http.on(HttpMethod::get, folder_children_url(),
                      {load_fixture("graph", "onedrive-children-200-one-item")});
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    rp::test::TempDir dir;
    std::filesystem::path profile_path;
    rp::test::FakeHttpClient graph_http;
    std::function<rp::Secrets()> load_secrets = [] {
        return rp::Secrets{std::nullopt, std::nullopt, pfx_base64(), kPfxPassword};
    };
    std::filesystem::path vault_read;
    int default_config_calls = 0;
    int default_vault_calls = 0;
    int load_secrets_calls = 0;
    int make_graph_http_calls = 0;
    int make_download_http_calls = 0;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
};

const std::string kHeading = "client profile: veeam_org_name " + std::string{kOrgName} +
                             ", tenant " + kTenant + ", app " + kClient + "\n\n";

std::string mail_heading(std::size_t count)
{
    return "Mail (" + lab_values().mailbox + ", Inbox): " + std::to_string(count) + " item(s)\n";
}

const std::string kEmptyTables = mail_heading(0) +
                                 "\n"
                                 "SharePoint (RestoreTarget library): 0 item(s)\n"
                                 "\n"
                                 "OneDrive (RestoreTarget folder): 0 item(s)\n"
                                 "\n"
                                 "0 item(s) in the three restore targets\n";

} // namespace

// --- The command line --------------------------------------------------------

TEST_CASE("rpworker client prints usage and exits 64 for arguments it doesn't understand",
          "[client_command]")
{
    const Args args = GENERATE(
        Args{}, Args{""}, Args{"Check"}, Args{"list"},
        Args{"check"},                                        // --profile-file is required
        Args{"check", "--profile-file"},                      // without its value
        Args{"check", "--profile-file", ""},                  // an empty value is a missing one
        Args{"check", "--profile-file", "a.json", "--profile-file", "b.json"},
        Args{"check", "--profile-file", "a.json", "--config", "c.json"}, // no config is read
        Args{"check", "--profile-file", "a.json", "--hash"},            // nothing is downloaded
        Args{"check", "--profile-file", "a.json", "--vault"},
        Args{"check", "--profile-file", "a.json", "extra"},
        Args{"--profile-file", "a.json", "check"});
    CAPTURE(args);
    Harness lab;

    const Run result = lab.run(args);

    CHECK(result.exit_code == rp::exit_code::usage);
    CHECK(result.out.empty());
    CHECK(result.err == kUsage);
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_graph_http_calls == 0);
}

// --- The profile file ---------------------------------------------------------

TEST_CASE("rpworker client check refuses a profile file it can't use, naming the key and no "
          "value, before the vault",
          "[client_command][client_profile]")
{
    Harness lab;
    json bad_mailbox = lab_profile();
    bad_mailbox["test_mailbox"] = "alice@RestoreProofLab.onmicrosoft.com";
    json no_library = lab_profile();
    no_library.erase("test_library_id");
    json braces = lab_profile();
    braces["graph_tenant_id"] = "{" + kTenant + "}";
    json extra = lab_profile();
    extra["client_id"] = "client-7";
    struct Row {
        const char* name;
        std::filesystem::path file;
        std::string problem;
    };
    const std::vector<Row> rows{
        {"missing", lab.dir.path() / "none.json", "can't be read"},
        {"not JSON", lab.dir.write("text.json", "{"), "not JSON"},
        {"a jobs document",
         lab.dir.write("jobs.json", R"({"format":"restoreproof.jobs.v1","jobs":[]})"),
         "not a restoreproof.client-profile.v1 document"},
        {"another mailbox", lab.dir.write("alice.json", bad_mailbox.dump()),
         "key \"test_mailbox\" " + std::string{rp::kRestoreMailboxRule}},
        {"a missing key", lab.dir.write("short.json", no_library.dump()),
         "key \"test_library_id\" is missing (required)"},
        {"a tenant in braces", lab.dir.write("braces.json", braces.dump()),
         "key \"graph_tenant_id\" " + std::string{rp::kGuidRule}},
        {"a key that isn't the profile's", lab.dir.write("extra.json", extra.dump()),
         "has a key that isn't the profile's: \"client_id\""},
    };
    for (const Row& row : rows) {
        CAPTURE(row.name);
        const Run result = lab.run(Args{"check", "--profile-file", utf8(row.file)});
        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.out.empty());
        CHECK(result.err == "config error: --profile-file " + utf8(row.file) + ": " + row.problem + "\n");
        CHECK_THAT(result.err, !ContainsSubstring("alice@"));
    }
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_graph_http_calls == 0);
    CHECK(lab.default_config_calls == 0);
}

// --- The vault and the certificate -------------------------------------------

TEST_CASE("rpworker client check needs the certificate's secrets, before any request",
          "[client_command]")
{
    Harness lab;
    SECTION("no PFX")
    {
        lab.load_secrets = [] { return rp::Secrets{}; };
        const Run result = lab.run_check();
        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.out.empty());
        CHECK(result.err == "config error: graph_cert_pfx_base64 is not in the vault\n");
    }
    SECTION("a vault that can't be read")
    {
        lab.load_secrets = []() -> rp::Secrets { throw rp::ConfigError("", "the vault file can't be read"); };
        const Run result = lab.run_check();
        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.err == "config error: the vault file can't be read\n");
    }
    SECTION("a failure that isn't a ConfigError hides its message")
    {
        lab.load_secrets = []() -> rp::Secrets { throw std::runtime_error("SENTINEL-message"); };
        const Run result = lab.run_check();
        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.err == "config error: unexpected failure\n");
    }
    CHECK(lab.make_graph_http_calls == 0);
    CHECK(lab.default_vault_calls == 1);
}

TEST_CASE("rpworker client check reads the vault --vault names, else the default", "[client_command]")
{
    Harness lab;
    lab.serve_empty();
    SECTION("--vault")
    {
        const std::filesystem::path vault = lab.dir.path() / "lab-vault.bin";
        const Run result =
            lab.run(Args{"check", "--profile-file", utf8(lab.profile_path), "--vault", utf8(vault)});
        CHECK(result.exit_code == rp::exit_code::ok);
        CHECK(lab.vault_read == vault);
        CHECK(lab.default_vault_calls == 0);
    }
    SECTION("the default")
    {
        const Run result = lab.run_check();
        CHECK(result.exit_code == rp::exit_code::ok);
        CHECK(lab.vault_read == lab.dir.path() / "default-vault.bin");
        CHECK(lab.default_vault_calls == 1);
    }
    CHECK(lab.load_secrets_calls == 1);
    CHECK(lab.default_config_calls == 0);
}

// --- Graph's failures ---------------------------------------------------------

TEST_CASE("rpworker client check maps each Graph failure to its exit code and prints no table",
          "[client_command]")
{
    struct Row {
        const char* name;
        const char* fixture;
        int exit_code;
        const char* line;
    };
    const Row row = GENERATE(
        Row{"a target the app can't reach names the grant", "site-403-accessdenied",
            rp::exit_code::auth, "Sites.Selected read on the test site"},
        Row{"a drive that isn't there", "drive-404-itemnotfound", rp::exit_code::service,
            "404"},
        Row{"a throttled call that never clears", "messages-503-unavailable",
            rp::exit_code::transient, "503"});
    CAPTURE(row.name);
    Harness lab;
    lab.serve_empty();
    const std::string url = std::string{row.fixture}.starts_with("messages") ? mail_list_url(false)
                                                                              : drive_url();
    lab.graph_http.on(HttpMethod::get, url, {load_fixture("graph", row.fixture)});

    const Run result = lab.run_check();

    CHECK(result.exit_code == row.exit_code);
    CHECK(result.out.empty());
    CHECK_THAT(result.err, StartsWith("graph error: "));
    CHECK_THAT(result.err, ContainsSubstring(row.line));
}

TEST_CASE("rpworker client check refuses a profile whose library isn't a RestoreTarget, exit 4",
          "[client_command]")
{
    Harness lab;
    lab.serve_empty();
    // The guard's own check: the drive the profile names is called otherwise.
    json drive = rp::test::load_fixture_json("graph", "restoretarget-drive-200");
    drive["body"]["name"] = "RestoreTest";
    lab.graph_http.on(HttpMethod::get, drive_url(), {rp::test::to_response(drive)});

    const Run result = lab.run_check();

    CHECK(result.exit_code == rp::exit_code::service);
    CHECK(result.out.empty());
    CHECK_THAT(result.err, StartsWith("graph error: the drive test_library_id names is "));
    CHECK_THAT(result.err, ContainsSubstring("not \"RestoreTarget\""));
}

// --- The tables ---------------------------------------------------------------

TEST_CASE("rpworker client check prints the profile's heading and three empty tables, reading "
          "no config and downloading nothing",
          "[client_command][client_profile]")
{
    Harness lab;
    lab.serve_empty();

    const Run result = lab.run_check();

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK(result.err.empty());
    CHECK(result.out == kHeading + kEmptyTables);
    CHECK(lab.default_config_calls == 0);
    CHECK(lab.make_download_http_calls == 0);
    CHECK(lab.make_graph_http_calls == 1);
    // Nothing of the profile but its heading, and no secret, reaches the log.
    CHECK_THAT(lab.log(), !ContainsSubstring(kPfxPassword));
}

TEST_CASE("rpworker client check lists one item each as graph list does, with Graph's sizes",
          "[client_command]")
{
    Harness lab;
    lab.serve_one_each();

    const Run result = lab.run_check();

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK_THAT(result.out, StartsWith(kHeading + mail_heading(1)));
    CHECK_THAT(result.out, ContainsSubstring("SharePoint (RestoreTarget library): 1 item(s)\n"));
    CHECK_THAT(result.out, ContainsSubstring("OneDrive (RestoreTarget folder): 1 item(s)\n"));
    CHECK_THAT(result.out, ContainsSubstring("\n3 item(s) in the three restore targets\n"));
    // Without --hash: no SHA256 column, no download.
    CHECK_THAT(result.out, !ContainsSubstring("SHA256"));
    CHECK(lab.make_download_http_calls == 0);
}

TEST_CASE("rpworker client check --record keeps the Graph exchanges and says so last",
          "[client_command]")
{
    Harness lab;
    lab.serve_empty();
    const std::filesystem::path folder = lab.dir.path() / "rec";

    const Run result = lab.run(
        Args{"check", "--profile-file", utf8(lab.profile_path), "--record", utf8(folder)});

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK_THAT(result.out, StartsWith(kHeading + kEmptyTables + "recorded "));
    CHECK(std::filesystem::is_directory(folder / "graph"));
    CHECK_FALSE(std::filesystem::exists(folder / "download"));
}

TEST_CASE("rpworker client check reports a write of the tables that fails, exit 1",
          "[client_command]")
{
    Harness lab;
    lab.serve_empty();
    struct FailingBuffer : std::streambuf {
        int_type overflow(int_type) override { return traits_type::eof(); }
        std::streamsize xsputn(const char*, std::streamsize) override { return 0; }
    } buffer;
    std::ostream out(&buffer);
    std::ostringstream err;

    const int code = rp::run_client_command(Args{"check", "--profile-file", utf8(lab.profile_path)},
                                            out, err, lab.env());

    CHECK(code == rp::exit_code::config);
    CHECK(err.str() == "error: unexpected failure\n");
}
