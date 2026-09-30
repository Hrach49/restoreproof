// W2.3: `rpworker graph list` (rp::run_graph_command) against W2.2's recorded
// Graph replies in tests/fixtures/graph/, served by two FakeHttpClients: Graph
// (with its token route) and SharePoint's download host. Nothing here touches
// the network; the live run is graph_command_live_test.cpp (RP_LIVE=1). The
// lab's values and the fixture helpers are graph_lab.hpp's. Exit codes and
// output are the W2.3 entry in docs/decisions.md.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "test_support.hpp"

#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_command.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>
#include <rp/sha256.hpp>
#include <rp/text_v1.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <ios>
#include <memory>
#include <optional>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;
using Catch::Matchers::StartsWith;
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
using namespace rp::test::graph_lab;

const std::string kUsage = "usage: rpworker --version | rpworker config check [--config <path>] | "
                           "rpworker veeam list [--config <path>] | "
                           "rpworker graph list [--hash] [--config <path>] | "
                           "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
                           "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] "
                           "[--config <path>]\n";

// The download link's credential: in no output, error or log line.
const std::string kTempauth = "v1.SENTINEL-command-tempauth";

// A valid config with the lab's tenant, app and restore targets.
std::string config_json()
{
    const Lab_values& v = lab_values();
    return json{
        {"cloud_url", "https://cloud.example.invalid"},
        {"veeam_url", "https://veeam.test:4443"},
        {"veeam_org_name", "RestoreProofLab.onmicrosoft.com"},
        {"graph_tenant_id", kTenant},
        {"graph_client_id", kClient},
        {"test_mailbox", v.mailbox},
        {"test_site_id", v.site_id},
        {"test_library_id", v.library_id},
        {"test_onedrive_drive_id", v.onedrive_drive_id},
        {"test_onedrive_folder_id", v.folder_id},
    }
        .dump(2);
}

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

// Everything run_graph_command reaches outside itself: a config file in a temp
// directory, the secrets (the test certificate), the two HTTP clients and a
// logger that writes every level to a string. Counts how often the command
// asks for each; waits are recorded, never slept.
struct Harness {
    Harness()
    {
        config_path = dir.write("config.json", config_json());
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("graph_command_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::trace);
        graph_http.on(HttpMethod::post, kTokenUrl, {token_response()});
    }

    rp::GraphCommandEnv env()
    {
        rp::GraphCommandEnv env;
        env.default_config_path = [this] {
            ++default_path_calls;
            return config_path;
        };
        env.load_secrets = [this] {
            ++load_secrets_calls;
            return load_secrets();
        };
        env.make_graph_http = [this](std::shared_ptr<spdlog::logger> given)
            -> std::unique_ptr<rp::IHttpClient> {
            ++make_graph_http_calls;
            graph_http_logger = std::move(given);
            return make_graph_http();
        };
        env.make_download_http = [this]() -> std::unique_ptr<rp::IHttpClient> {
            ++make_download_http_calls;
            return make_download_http();
        };
        env.client_options.logger = logger;
        env.client_options.now = [] { return std::chrono::steady_clock::time_point{}; };
        env.client_options.wall_now = [] { return kNow; };
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
        const int exit_code = rp::run_graph_command(args, out, err, env());
        return {exit_code, out.str(), err.str()};
    }

    // `graph list [--hash] --config <the temp config>`.
    Run run_list(bool hash = false)
    {
        const std::string path_arg = utf8(config_path);
        return hash ? run(Args{"list", "--hash", "--config", path_arg})
                    : run(Args{"list", "--config", path_arg});
    }

    // All three targets empty.
    void serve_empty()
    {
        serve_mail(load_fixture("graph", "mail-list-200-empty"));
        graph_http.on(HttpMethod::get, drive_url(), {load_fixture("graph", "restoretarget-drive-200")});
        graph_http.on(HttpMethod::get, library_children_url(),
                      {load_fixture("graph", "restoretarget-children-200-empty")});
        graph_http.on(HttpMethod::get, folder_url(), {load_fixture("graph", "onedrive-folder-200")});
        graph_http.on(HttpMethod::get, folder_children_url(),
                      {load_fixture("graph", "onedrive-children-200-empty")});
    }

    // One item in each target, as recorded.
    void serve_one_each()
    {
        serve_mail(load_fixture("graph", "mail-list-200-one-item"));
        serve_location(graph_http, dl_http, sharepoint_location());
        serve_location(graph_http, dl_http, onedrive_location());
    }

    // The mail listing with the bodies (--hash) and without.
    void serve_mail(const HttpResponse& response)
    {
        graph_http.on(HttpMethod::get, mail_list_url(true), {response});
        graph_http.on(HttpMethod::get, mail_list_url(false), {response});
    }

    void serve(const std::string& url, HttpResponse response)
    {
        graph_http.on(HttpMethod::get, url, {std::move(response)});
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    // Every request Graph got other than token requests.
    std::vector<std::string> graph_gets() const
    {
        std::vector<std::string> out;
        for (const HttpRequest& request : graph_http.requests()) {
            if (request.url != kTokenUrl) {
                out.push_back(request.url);
            }
        }
        return out;
    }

    rp::test::TempDir dir;
    std::filesystem::path config_path;
    rp::test::FakeHttpClient graph_http;
    rp::test::FakeHttpClient dl_http;
    std::function<rp::Secrets()> load_secrets = [] {
        return rp::Secrets{std::nullopt, std::nullopt, pfx_base64(), kPfxPassword};
    };
    std::function<std::unique_ptr<rp::IHttpClient>()> make_graph_http = [this] {
        return std::make_unique<rp::test::ForwardingHttpClient>(graph_http);
    };
    std::function<std::unique_ptr<rp::IHttpClient>()> make_download_http = [this] {
        return std::make_unique<rp::test::ForwardingHttpClient>(dl_http);
    };
    int default_path_calls = 0;
    int load_secrets_calls = 0;
    int make_graph_http_calls = 0;
    int make_download_http_calls = 0;
    std::shared_ptr<spdlog::logger> graph_http_logger;
    std::vector<std::chrono::milliseconds> sleeps;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
};

// A table as the command should print it, written out independently of
// src/text_table.cpp: each row indented by two spaces, columns padded to the
// widest cell (the values here are ASCII) and two spaces apart.
std::string table(const std::vector<std::vector<std::string>>& rows)
{
    std::vector<std::size_t> widths(rows.at(0).size(), 0);
    for (const auto& row : rows) {
        for (std::size_t i = 0; i < row.size(); ++i) {
            widths[i] = std::max(widths[i], row[i].size());
        }
    }
    std::string text;
    for (const auto& row : rows) {
        std::string line = "  ";
        for (std::size_t i = 0; i < row.size(); ++i) {
            line += row[i];
            if (i + 1 < row.size()) {
                line += std::string(widths[i] - row[i].size() + 2, ' ');
            }
        }
        text += line + "\n";
    }
    return text;
}

std::string mail_heading(std::size_t count)
{
    return "Mail (" + lab_values().mailbox + ", Inbox): " + std::to_string(count) + " item(s)\n";
}

const std::string kEmptyOutput = mail_heading(0) +
                                 "\n"
                                 "SharePoint (RestoreTarget library): 0 item(s)\n"
                                 "\n"
                                 "OneDrive (RestoreTarget folder): 0 item(s)\n"
                                 "\n"
                                 "0 item(s) in the three restore targets\n";

// The recorded one-item mail as a row: received, sender, subject, id.
std::vector<std::string> mail_row()
{
    const json message = messages_of("mail-list-200-one-item").at(0);
    return {message.at("receivedDateTime").get<std::string>(),
            message.at("from").at("emailAddress").at("address").get<std::string>(),
            message.at("subject").get<std::string>(), message.at("id").get<std::string>()};
}

// A file location's one recorded file as a row: name, size, id.
std::vector<std::string> file_row(const FileLocation& at)
{
    const json file = file_of(at);
    return {file.at("name").get<std::string>(), std::to_string(file.at("size").get<std::size_t>()),
            file.at("id").get<std::string>()};
}

std::size_t line_count(const std::string& text)
{
    return static_cast<std::size_t>(std::ranges::count(text, '\n'));
}

// A stream every write to fails: writing the tables sets badbit, or throws
// with exceptions on.
struct FailingBuffer : std::streambuf {
    int_type overflow(int_type) override { return traits_type::eof(); }
    std::streamsize xsputn(const char*, std::streamsize) override { return 0; }
};

// A stream that takes every write but fails to flush them, as a buffered
// write to a full disk does.
struct FailingFlushBuffer : std::streambuf {
    int_type overflow(int_type c) override { return traits_type::not_eof(c); }
    std::streamsize xsputn(const char*, std::streamsize n) override { return n; }
    int sync() override { return -1; }
};

} // namespace

// --- The command line --------------------------------------------------------

TEST_CASE("rpworker graph prints usage and exits 64 for arguments it doesn't understand",
          "[graph_command]")
{
    const Args args = GENERATE(Args{}, Args{"foo"}, Args{"lst"}, Args{"list", "--bogus"},
                               Args{"list", "extra"}, Args{"list", "--config"},
                               Args{"list", "--hash", "--config"}, Args{"list", "--hash", "--hash"},
                               Args{"list", "--config", "a.json", "--config", "b.json"},
                               Args{"list", "--HASH"}, Args{"--hash", "list"});
    CAPTURE(args);
    Harness lab;

    const Run result = lab.run(args);

    CHECK(result.exit_code == rp::exit_code::usage);
    CHECK(result.out.empty());
    CHECK(result.err == kUsage);
    // Nothing is looked up for a command line that isn't understood.
    CHECK(lab.default_path_calls == 0);
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_graph_http_calls == 0);
    CHECK(lab.graph_http.requests().empty());
}

TEST_CASE("rpworker graph list takes --hash and --config in either order", "[graph_command]")
{
    Harness lab;
    lab.serve_empty();
    const std::string path = utf8(lab.config_path);
    const bool hash_first = GENERATE(true, false);
    const Args args = hash_first ? Args{"list", "--hash", "--config", path}
                                 : Args{"list", "--config", path, "--hash"};
    CAPTURE(args);

    const Run result = lab.run(args);

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK(result.out == kEmptyOutput);
    CHECK(result.err.empty());
    CHECK(lab.default_path_calls == 0);
}

TEST_CASE("rpworker graph list reads the default path without --config", "[graph_command]")
{
    Harness lab;
    lab.serve_empty();
    const bool hash = GENERATE(false, true);
    CAPTURE(hash);

    const Run result = hash ? lab.run(Args{"list", "--hash"}) : lab.run(Args{"list"});

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK(result.out == kEmptyOutput);
    CHECK(lab.default_path_calls == 1);
}

// --- Config and secrets ----------------------------------------------------------

TEST_CASE("rpworker graph list exits 1 with the error when the config doesn't load",
          "[graph_command]")
{
    Harness lab;
    const std::filesystem::path missing = lab.dir.path() / "no-such-config.json";
    const std::string path_arg = utf8(missing);

    const Run result = lab.run(Args{"list", "--config", path_arg});

    CHECK(result.exit_code == rp::exit_code::config);
    CHECK(result.out.empty());
    CHECK(result.err == "config error: " + path_arg + ": cannot read config file\n");
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_graph_http_calls == 0);
}

TEST_CASE("rpworker graph list needs the certificate's secrets, before any request",
          "[graph_command]")
{
    struct Row {
        std::string name;
        rp::Secrets secrets;
        std::string err;
    };
    const Row row = GENERATE_COPY(
        Row{"no PFX", rp::Secrets{std::nullopt, std::nullopt, std::nullopt, kPfxPassword},
            "config error: RP_GRAPH_CERT_PFX_BASE64 is not set\n"},
        Row{"an empty PFX", rp::Secrets{std::nullopt, std::nullopt, "", kPfxPassword},
            "config error: RP_GRAPH_CERT_PFX_BASE64 is not set\n"},
        Row{"no password for a PFX that needs one",
            rp::Secrets{std::nullopt, std::nullopt, pfx_base64(), std::nullopt},
            "config error: RP_GRAPH_CERT_PASSWORD is not set"});
    CAPTURE(row.name);
    Harness lab;
    lab.load_secrets = [&row] { return row.secrets; };

    const Run result = lab.run_list();

    CHECK(result.exit_code == rp::exit_code::config);
    CHECK(result.out.empty());
    CHECK_THAT(result.err, StartsWith(row.err));
    CHECK(line_count(result.err) == 1);
    CHECK(result.err.find(kPfxPassword) == std::string::npos);
    CHECK(lab.make_graph_http_calls == 0);
    CHECK(lab.graph_http.requests().empty());
}

TEST_CASE("rpworker graph list reports a secret it can't read, and hides other failures' messages",
          "[graph_command]")
{
    SECTION("a ConfigError")
    {
        Harness lab;
        const rp::ConfigError error(std::string{rp::kEnvGraphCertPassword},
                                    "environment variable RP_GRAPH_CERT_PASSWORD is not valid "
                                    "Unicode");
        lab.load_secrets = [error]() -> rp::Secrets { throw error; };

        const Run result = lab.run_list();

        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.out.empty());
        CHECK(result.err == "config error: " + std::string{error.what()} + "\n");
        CHECK_THAT(result.err, ContainsSubstring("RP_GRAPH_CERT_PASSWORD"));
    }
    SECTION("anything else")
    {
        Harness lab;
        lab.load_secrets = []() -> rp::Secrets { throw std::runtime_error("SENTINEL-2c4d"); };

        const Run result = lab.run_list();

        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.out.empty());
        CHECK(result.err == "config error: unexpected failure\n");
    }
}

// --- Graph's refusals --------------------------------------------------------------

TEST_CASE("rpworker graph list maps each Graph failure to its exit code and prints no table",
          "[graph_command]")
{
    using Setup = std::function<void(Harness&)>;
    struct Row {
        std::string name;
        bool hash;
        Setup setup;
        int exit_code;
        std::string contains; // in the one line on stderr
        std::size_t sleeps = 0; // waits between attempts: only what may work later is retried
    };
    const auto busy = [] {
        HttpResponse response =
            make_response(503, R"({"error":{"code":"serviceNotAvailable","message":"x"}})");
        response.headers["Retry-After"] = "1";
        return response;
    };
    const auto wrong_library = [] {
        json fixture = load_fixture_json("graph", "restoretarget-drive-200");
        fixture["body"]["name"] = "RestoreTest";
        return to_response(fixture);
    };
    const auto wrong_folder = [] {
        json fixture = load_fixture_json("graph", "onedrive-folder-200");
        fixture["body"]["name"] = "RestoreTest";
        return to_response(fixture);
    };
    const Row row = GENERATE_COPY(
        Row{"the token refused (401)", false,
            [](Harness& lab) {
                lab.graph_http.on(HttpMethod::post, kTokenUrl,
                                  {load_fixture("graph", "token-bad-signature-401")});
            },
            rp::exit_code::auth, "AADSTS700027"},
        Row{"403 on the mailbox", false,
            [](Harness& lab) {
                lab.serve_mail(load_fixture("graph", "messages-403-exchange"));
            },
            rp::exit_code::auth, std::string{rp::graph::kMailReadGrant.description}},
        Row{"403 on the RestoreTarget library", false,
            [](Harness& lab) { lab.serve(drive_url(), load_fixture("graph", "site-403-accessdenied")); },
            rp::exit_code::auth, std::string{rp::graph::kSitesReadGrant.description}},
        Row{"403 on the OneDrive folder", false,
            [](Harness& lab) {
                lab.serve(folder_url(), load_fixture("graph", "onedrive-folder-403-accessdenied"));
            },
            rp::exit_code::auth, std::string{rp::graph::kOneDriveReadGrant.description}},
        Row{"404 on the mailbox", false,
            [](Harness& lab) {
                lab.serve_mail(load_fixture("graph", "messages-404-unknown-user"));
            },
            rp::exit_code::service, "HTTP 404 (ErrorInvalidUser)"},
        Row{"404 on the RestoreTarget drive", false,
            [](Harness& lab) { lab.serve(drive_url(), load_fixture("graph", "drive-404-itemnotfound")); },
            rp::exit_code::service, "HTTP 404 (itemNotFound)"},
        Row{"404 on the OneDrive folder", false,
            [](Harness& lab) {
                lab.serve(folder_url(), load_fixture("graph", "onedrive-folder-404-itemnotfound"));
            },
            rp::exit_code::service, "may lack the grant"},
        Row{"the guard refuses the library", false,
            [wrong_library](Harness& lab) { lab.serve(drive_url(), wrong_library()); },
            rp::exit_code::service, "\"RestoreTest\", not \"RestoreTarget\""},
        Row{"the guard refuses the library, with --hash", true,
            [wrong_library](Harness& lab) { lab.serve(drive_url(), wrong_library()); },
            rp::exit_code::service, "\"RestoreTest\", not \"RestoreTarget\""},
        Row{"the guard refuses the OneDrive folder, after the others listed", false,
            [wrong_folder](Harness& lab) { lab.serve(folder_url(), wrong_folder()); },
            rp::exit_code::service,
            "the OneDrive item test_onedrive_folder_id names is \"RestoreTest\", not "
            "\"RestoreTarget\""},
        Row{"503 on the OneDrive folder's children after the retries", false,
            [busy](Harness& lab) { lab.serve(folder_children_url(), busy()); },
            rp::exit_code::transient, "503", 4},
        Row{"a download SharePoint refuses, with --hash", true,
            [](Harness& lab) {
                lab.dl_http.on(HttpMethod::get, location_of(onedrive_location()),
                               {make_response(403)});
            },
            rp::exit_code::service, "SharePoint refused the download of the test OneDrive folder"});
    CAPTURE(row.name);
    Harness lab;
    // Everything recorded as it should be, then the row's failure in its place.
    lab.serve_one_each();
    row.setup(lab);

    const Run result = lab.run_list(row.hash);

    CHECK(result.exit_code == row.exit_code);
    // Nothing on stdout, even when the mailbox and the library listed fine.
    CHECK(result.out.empty());
    CHECK_THAT(result.err, StartsWith("graph error: "));
    CHECK_THAT(result.err, ContainsSubstring(row.contains));
    CHECK(line_count(result.err) == 1);
    CHECK(result.err.back() == '\n');
    // The 503 was tried five times in all; nothing else was tried again.
    CHECK(lab.sleeps.size() == row.sleeps);
}

// The exact line docs/worker-config.md shows for an error.
TEST_CASE("rpworker graph list prints Graph's 403 as one line naming the grant", "[graph_command]")
{
    Harness lab;
    lab.serve_one_each();
    const json fixture = load_fixture_json("graph", "site-403-accessdenied");
    lab.serve(drive_url(), to_response(fixture));

    const Run result = lab.run_list();

    CHECK(result.exit_code == rp::exit_code::auth);
    CHECK(result.out.empty());
    CHECK(result.err == "graph error: Graph denied GET /v1.0/drives/" + lab_values().library_id +
                            " (403 accessDenied): the Worker app relies on " +
                            std::string{rp::graph::kSitesReadGrant.description} +
                            "; see docs/security/graph-permissions.md (request ID " +
                            fixture.at("headers").at("request-id").get<std::string>() + ")\n");
}

TEST_CASE("rpworker graph list reports an unexpected failure without its message",
          "[graph_command]")
{
    SECTION("no Graph HTTP client")
    {
        Harness lab;
        lab.make_graph_http = [] { return std::unique_ptr<rp::IHttpClient>{}; };

        const Run result = lab.run_list();

        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.out.empty());
        CHECK(result.err == "error: unexpected failure\n");
    }
    SECTION("no download client")
    {
        // Only --hash needs one.
        Harness lab;
        lab.make_download_http = [] { return std::unique_ptr<rp::IHttpClient>{}; };

        const Run result = lab.run_list(true);

        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.err == "error: unexpected failure\n");
        CHECK(lab.graph_http.requests().empty());
    }
    SECTION("an exception that isn't a GraphError")
    {
        Harness lab;
        lab.serve_one_each();
        lab.graph_http.on(HttpMethod::get, library_children_url(),
                          [](const HttpRequest&) -> HttpResponse {
                              throw std::logic_error("SENTINEL-8e1a");
                          });

        const Run result = lab.run_list();

        CHECK(result.exit_code == rp::exit_code::config);
        CHECK(result.out.empty());
        CHECK(result.err == "error: unexpected failure\n");
    }
    SECTION("writing the tables")
    {
        // A full disk or a closed pipe: with exceptions on, and off as in
        // production, where only the stream's state tells.
        const bool exceptions = GENERATE(true, false);
        const bool on_flush = GENERATE(false, true);
        CAPTURE(exceptions, on_flush);
        Harness lab;
        lab.serve_empty();
        FailingBuffer failing_write;
        FailingFlushBuffer failing_flush;
        std::ostream out(on_flush ? static_cast<std::streambuf*>(&failing_flush) : &failing_write);
        if (exceptions) {
            out.exceptions(std::ios::badbit);
        }
        std::ostringstream err;
        const std::string path_arg = utf8(lab.config_path);

        const int code =
            rp::run_graph_command(Args{"list", "--config", path_arg}, out, err, lab.env());

        CHECK(code == rp::exit_code::config);
        CHECK(err.str() == "error: unexpected failure\n");
    }
}

TEST_CASE("rpworker graph list without --hash never makes the download client", "[graph_command]")
{
    // Nothing is downloaded, so a download client that can't be made can't
    // fail the listing.
    const bool available = GENERATE(true, false);
    CAPTURE(available);
    Harness lab;
    lab.serve_one_each();
    if (!available) {
        lab.make_download_http = [] { return std::unique_ptr<rp::IHttpClient>{}; };
    }

    const Run result = lab.run_list();

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK_THAT(result.out, EndsWith("3 item(s) in the three restore targets\n"));
    CHECK(result.err.empty());
    CHECK(lab.make_download_http_calls == 0);
}

TEST_CASE("rpworker graph list --hash makes the download client once", "[graph_command]")
{
    Harness lab;
    lab.serve_one_each();

    const Run result = lab.run_list(true);

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK(lab.make_download_http_calls == 1);
}

TEST_CASE("rpworker graph list reports a malformed Graph reply as a Graph error, exit 4",
          "[graph_command]")
{
    // The reader checks Graph's JSON itself: nothing it reads reaches the
    // command as a JSON library exception, which would be exit 1.
    const std::string body = GENERATE(as<std::string>{}, R"({"x":[]})", R"({"value":"a"})",
                                      R"({"value":[{"id":"x","file":{},"name":"n"}]})",
                                      R"({"value":[{"id":"x","file":{},"size":1}]})");
    CAPTURE(body);
    Harness lab;
    lab.serve_one_each();
    lab.serve(library_children_url(), make_response(200, body));

    const Run result = lab.run_list();

    CHECK(result.exit_code == rp::exit_code::service);
    CHECK(result.out.empty());
    CHECK_THAT(result.err,
               StartsWith("graph error: Graph's reply listing the RestoreTarget library"));
}

// --- The tables ------------------------------------------------------------------

TEST_CASE("rpworker graph list prints three empty tables for empty targets", "[graph_command]")
{
    const bool hash = GENERATE(false, true);
    CAPTURE(hash);
    Harness lab;
    lab.serve_empty();

    const Run result = lab.run_list(hash);

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK(result.out == kEmptyOutput);
    CHECK(result.err.empty());
    // The mailbox, then each file target's guard and listing; nothing downloaded.
    CHECK(lab.graph_gets() == std::vector<std::string>{mail_list_url(hash), drive_url(),
                                                       library_children_url(), folder_url(),
                                                       folder_children_url()});
    CHECK(lab.dl_http.requests().empty());
    // The command's logger went to the Graph HTTP client too.
    CHECK(lab.make_graph_http_calls == 1);
    CHECK(lab.graph_http_logger == lab.logger);
}

TEST_CASE("rpworker graph list without --hash lists one item each and downloads nothing",
          "[graph_command]")
{
    Harness lab;
    lab.serve_one_each();

    const Run result = lab.run_list();

    const std::string expected =
        mail_heading(1) + table({{"RECEIVED", "SENDER", "SUBJECT", "ID"}, mail_row()}) +
        "\n"
        "SharePoint (RestoreTarget library): 1 item(s)\n" +
        table({{"NAME", "SIZE", "ID"}, file_row(sharepoint_location())}) +
        "\n"
        "OneDrive (RestoreTarget folder): 1 item(s)\n" +
        table({{"NAME", "SIZE", "ID"}, file_row(onedrive_location())}) +
        "\n"
        "3 item(s) in the three restore targets\n";
    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK(result.out == expected);
    CHECK(result.err.empty());
    // No /content request and nothing for the download client.
    for (const std::string& url : lab.graph_gets()) {
        CAPTURE(url);
        CHECK_FALSE(url.ends_with("/content"));
    }
    CHECK(lab.graph_gets().size() == 5);
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("rpworker graph list --hash downloads each file and shows every hash and its rule",
          "[graph_command]")
{
    Harness lab;
    lab.serve_one_each();

    const Run result = lab.run_list(true);

    const json message = messages_of("mail-list-200-one-item").at(0);
    std::vector<std::string> mail = mail_row();
    mail.push_back(rp::text_v1_sha256(message.at("body").at("content").get<std::string>()));
    mail.push_back("text-v1");
    std::vector<std::string> sharepoint = file_row(sharepoint_location());
    sharepoint.push_back(rp::sha256_hex(bytes_of(sharepoint_location())));
    sharepoint.push_back("bytes");
    std::vector<std::string> onedrive = file_row(onedrive_location());
    onedrive.push_back(rp::sha256_hex(bytes_of(onedrive_location())));
    onedrive.push_back("bytes");
    const std::string expected =
        mail_heading(1) +
        table({{"RECEIVED", "SENDER", "SUBJECT", "ID", "SHA256", "RULE"}, mail}) +
        "\n"
        "SharePoint (RestoreTarget library): 1 item(s)\n" +
        table({{"NAME", "SIZE", "ID", "SHA256", "RULE"}, sharepoint}) +
        "\n"
        "OneDrive (RestoreTarget folder): 1 item(s)\n" +
        table({{"NAME", "SIZE", "ID", "SHA256", "RULE"}, onedrive}) +
        "\n"
        "3 item(s) in the three restore targets\n";
    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK(result.out == expected);
    CHECK(result.err.empty());
    REQUIRE(lab.dl_http.requests().size() == 2);
    for (const HttpRequest& request : lab.dl_http.requests()) {
        CHECK_FALSE(request.headers.contains("Authorization"));
    }
}

TEST_CASE("rpworker graph list keeps Graph's order, pads to the widest row, and skips folders",
          "[graph_command]")
{
    const FileLocation at = sharepoint_location();
    json first = file_of(at);
    first["name"] = "a-much-longer-name-than-the-other.txt";
    json folder = file_of(at);
    folder.erase("file");
    folder["folder"] = {{"childCount", 0}};
    folder["id"] = "01FOLDER";
    json second = file_of(at);
    second["name"] = "b.txt";
    second["id"] = "01SECOND";
    second["size"] = 123456;
    Harness lab;
    lab.serve_empty();
    lab.serve(library_children_url(), page_of(json::array({first, folder, second})));

    const Run result = lab.run_list();

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK_THAT(result.out,
               ContainsSubstring(
                   "SharePoint (RestoreTarget library): 2 item(s)\n" +
                   table({{"NAME", "SIZE", "ID"},
                          {first.at("name").get<std::string>(),
                           std::to_string(first.at("size").get<std::size_t>()),
                           first.at("id").get<std::string>()},
                          {"b.txt", "123456", "01SECOND"}}) +
                   "\n"));
    CHECK_THAT(result.out, ContainsSubstring("\n2 item(s) in the three restore targets\n"));
    CHECK(result.out.find("01FOLDER") == std::string::npos);
}

TEST_CASE("rpworker graph list shows the bytes downloaded as SIZE with --hash, Graph's without",
          "[graph_command]")
{
    // SharePoint rewrites a docx, so its bytes may differ from Graph's size.
    const FileLocation at = onedrive_location();
    json file = file_of(at);
    file["name"] = "rewritten-by-sharepoint.docx";
    const std::string bytes = "short";
    const bool hash = GENERATE(false, true);
    CAPTURE(hash);
    Harness lab;
    lab.serve_empty();
    serve_location(lab.graph_http, lab.dl_http, at, page_of(json::array({file})));
    lab.dl_http.on(HttpMethod::get, location_of(at),
                   {make_response(200, bytes, "application/octet-stream")});

    const Run result = lab.run_list(hash);

    std::vector<std::string> header{"NAME", "SIZE", "ID"};
    std::vector<std::string> row{
        file.at("name").get<std::string>(),
        hash ? std::to_string(bytes.size()) : std::to_string(file.at("size").get<std::size_t>()),
        file.at("id").get<std::string>()};
    if (hash) {
        header.insert(header.end(), {"SHA256", "RULE"});
        row.insert(row.end(), {rp::sha256_hex(bytes), "bytes"});
    }
    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK_THAT(result.out, ContainsSubstring("OneDrive (RestoreTarget folder): 1 item(s)\n" +
                                             table({header, row}) + "\n"));
}

TEST_CASE("rpworker graph list shows a missing mail field as - and an empty subject as such",
          "[graph_command]")
{
    json value = messages_of("mail-list-200-one-item");
    value[0].erase("receivedDateTime");
    // No address, or an empty one.
    value[0]["from"] = GENERATE(json::object(), json{{"emailAddress", {{"address", ""}}}});
    value[0]["subject"] = GENERATE(json(""), json(nullptr));
    Harness lab;
    lab.serve_empty();
    lab.serve_mail(page_of(value));

    const Run result = lab.run_list();

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK_THAT(result.out,
               StartsWith(mail_heading(1) +
                          table({{"RECEIVED", "SENDER", "SUBJECT", "ID"},
                                 {"-", "-", "(no subject)", value[0].at("id").get<std::string>()}})));
}

TEST_CASE("rpworker graph list turns control characters in Graph's text into spaces",
          "[graph_command]")
{
    // A subject and a file name that would forge a line of the output, clear
    // the screen or reorder the text.
    json value = messages_of("mail-list-200-one-item");
    value[0]["subject"] = "evil\r\nOneDrive (RestoreTarget folder): 9 item(s)";
    value[0]["from"]["emailAddress"]["address"] = "a\r\n0 item(s)@example.com";
    json file = file_of(sharepoint_location());
    file["name"] = "x\x1b[2J\xE2\x80\xAE" "txt.exe";
    Harness lab;
    lab.serve_empty();
    lab.serve_mail(page_of(value));
    serve_location(lab.graph_http, lab.dl_http, sharepoint_location(),
                   page_of(json::array({file})));

    const Run result = lab.run_list();

    CHECK(result.exit_code == rp::exit_code::ok);
    CHECK_THAT(result.out, ContainsSubstring("evil  OneDrive (RestoreTarget folder): 9 item(s)"));
    CHECK_THAT(result.out, ContainsSubstring("x [2J txt.exe"));
    CHECK_THAT(result.out, ContainsSubstring("a  0 item(s)@example.com"));
    CHECK(result.out.find('\r') == std::string::npos);
    CHECK(result.out.find('\x1b') == std::string::npos);
    CHECK(result.out.find("\xE2\x80\xAE") == std::string::npos);
    // Three headings, two column headers, two rows, three blank lines and the
    // summary (OneDrive is empty): the subject added no line.
    CHECK(line_count(result.out) == 11);
}

TEST_CASE("rpworker graph list never prints or logs a token, the PFX password or a download link",
          "[graph_command]")
{
    Harness lab;
    lab.serve_one_each();
    // A download link that carries a credential.
    const FileLocation at = sharepoint_location();
    const std::string id = file_of(at).at("id").get<std::string>();
    const std::string link = "https://" + host_of(location_of(at)) +
                             "/sites/s/_layouts/15/download.aspx?UniqueId=u&tempauth=" +
                             kTempauth + "&ApiVersion=2.0";
    HttpResponse redirect = make_response(302);
    redirect.headers["Location"] = link;
    lab.graph_http.on(HttpMethod::get, content_url(at, id), {redirect});
    lab.dl_http.on(HttpMethod::get, link,
                   {make_response(200, bytes_of(at), "application/octet-stream")});

    const Run ok = lab.run_list(true);
    REQUIRE(ok.exit_code == rp::exit_code::ok);
    lab.dl_http.on(HttpMethod::get, link, {make_response(403)});
    const Run failed = lab.run_list(true);
    REQUIRE(failed.exit_code == rp::exit_code::service);

    const std::string everything = ok.out + ok.err + failed.out + failed.err + lab.log();
    for (const std::string& secret :
         {kTempauth, std::string{"tempauth="}, std::string{"download.aspx"},
          std::string{"token-1"}, std::string{kPfxPassword}, pfx_base64().substr(0, 40)}) {
        CAPTURE(secret);
        CHECK(everything.find(secret) == std::string::npos);
    }
}

TEST_CASE("rpworker graph list without a logger logs to stderr, never spdlog's default logger",
          "[graph_command]")
{
    // spdlog's default logger writes to stdout, where the tables are.
    std::ostringstream captured;
    const std::shared_ptr<spdlog::logger> saved = spdlog::default_logger();
    auto spy = std::make_shared<spdlog::logger>(
        "graph_command_default_spy", std::make_shared<spdlog::sinks::ostream_sink_mt>(captured));
    spy->set_level(spdlog::level::trace);
    spdlog::set_default_logger(spy);
    Harness lab;
    lab.serve_one_each();
    rp::GraphCommandEnv env = lab.env();
    env.client_options.logger = nullptr;
    std::ostringstream out;
    std::ostringstream err;
    const std::string path_arg = utf8(lab.config_path);

    const int code =
        rp::run_graph_command(Args{"list", "--hash", "--config", path_arg}, out, err, env);

    spdlog::set_default_logger(saved);
    spy->flush();
    CHECK(code == rp::exit_code::ok);
    CHECK(captured.str().empty());
    CHECK(err.str().empty());
    // The Graph HTTP client got the command's own logger, not null.
    REQUIRE(lab.graph_http_logger != nullptr);
    CHECK(lab.graph_http_logger != spy);
    CHECK(lab.graph_http_logger->level() == spdlog::level::warn);
}

// --- The real environment ----------------------------------------------------------

TEST_CASE("rpworker graph's real environment reads ProgramData and the process environment",
          "[graph_command]")
{
    const rp::GraphCommandEnv env = rp::default_graph_command_env();

    REQUIRE(env.default_config_path() == rp::default_config_path());
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, "pfx-3a7c");
    const rp::test::ScopedEnv password(rp::kEnvGraphCertPassword, std::nullopt);
    const rp::Secrets secrets = env.load_secrets();
    REQUIRE(secrets.graph_cert_pfx_base64 == std::optional<std::string>{"pfx-3a7c"});
    REQUIRE_FALSE(secrets.graph_cert_password);
    // Real HttpClients; making them sends nothing.
    REQUIRE(env.make_graph_http(env.client_options.logger) != nullptr);
    REQUIRE(env.make_download_http() != nullptr);
    // Log lines never go to stdout, where the tables are, and only warnings and
    // worse are written at all.
    REQUIRE(env.client_options.logger != nullptr);
    REQUIRE(env.client_options.logger != spdlog::default_logger());
    REQUIRE(env.client_options.logger->level() == spdlog::level::warn);
    // The real clocks, waits and jitter.
    REQUIRE_FALSE(env.client_options.now);
    REQUIRE_FALSE(env.client_options.wall_now);
}
