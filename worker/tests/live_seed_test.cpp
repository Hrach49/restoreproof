// The live cleanup test's seed paths (tests/live_seed.hpp): before the test
// writes anything, the configured targets are checked for shape and resolved
// through the target guard's Graph checks, and the seed paths come only from
// what those checks established. Graph is one FakeHttpClient serving the
// guard's recorded drive, folder and Inbox replies; each refusal is an edit
// of them, never a canary's ID. Every test ends with no request but GETs and
// the token's: resolving never writes.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "live_seed.hpp"

#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_errors.hpp>
#include <rp/target_guard_graph.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>

using Catch::Matchers::ContainsSubstring;

namespace {

using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::graph::GraphClient;
using rp::graph::GraphClientOptions;
using rp::graph::WrongTargetError;
using rp::test::FakeHttpClient;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::to_response;
using rp::test::live_seed::is_probe_name;
using rp::test::live_seed::resolve_seed_paths;
using rp::test::live_seed::SeedPaths;
using namespace rp::test::graph_lab;

const std::string kProbe = "rp-probe-0f8c2a4e-5b6d-4e7f-8a9b-0c1d2e3f4a5b";

struct SeedLab {
    SeedLab()
    {
        http.on(HttpMethod::post, kTokenUrl, {token_response()});
        GraphClientOptions options;
        options.now = [] { return std::chrono::steady_clock::time_point{}; };
        options.wall_now = [] { return kNow; };
        options.sleep = [](std::chrono::milliseconds) {};
        options.jitter = [] { return 0.0; };
        graph = std::make_unique<GraphClient>(
            http, kTenant, kClient,
            rp::graph::load_client_certificate(pfx_base64(), kPfxPassword, kNow), options);
        http.on(HttpMethod::get, inbox_url(), {load_fixture("graph", "mailbox-inbox-200")});
        http.on(HttpMethod::get, drive_url(), {load_fixture("graph", "restoretarget-drive-200")});
        http.on(HttpMethod::get, folder_url(), {load_fixture("graph", "onedrive-folder-200")});
    }

    SeedPaths resolve(const rp::Config& config = lab_config(), const std::string& probe = kProbe)
    {
        return resolve_seed_paths(*graph, config, probe);
    }

    // No request but GETs and the token's.
    bool only_reads() const
    {
        for (const HttpRequest& request : http.requests()) {
            if (request.method != HttpMethod::get && request.url != kTokenUrl) {
                return false;
            }
        }
        return true;
    }

    FakeHttpClient http;
    std::unique_ptr<GraphClient> graph;
};

} // namespace

TEST_CASE("live seed: a probe name is rp-probe- and a lower-case UUID, nothing else",
          "[live_seed]")
{
    CHECK(is_probe_name(kProbe));
    const std::string bad = GENERATE(std::string{""}, std::string{"rp-probe-"},
                                     std::string{"rp-probe-0F8C2A4E-5B6D-4E7F-8A9B-0C1D2E3F4A5B"},
                                     std::string{"rp-probe-0f8c2a4e-5b6d-4e7f-8a9b-0c1d2e3f4a5"},
                                     std::string{"rp-probe-0f8c2a4e-5b6d-4e7f-8a9b-0c1d2e3f4a5b0"},
                                     std::string{"rp-probe-0f8c2a4e5b6d-4e7f-8a9b-0c1d2e3f4a5b-"},
                                     std::string{"rp-probe-0f8c2a4e-5b6d-4e7f-8a9b-0c1d2e3f4a/b"},
                                     std::string{"xx-probe-0f8c2a4e-5b6d-4e7f-8a9b-0c1d2e3f4a5b"});
    INFO(bad);
    CHECK_FALSE(is_probe_name(bad));
}

TEST_CASE("live seed: the paths are built from what the guard's three checks resolved",
          "[live_seed]")
{
    SeedLab lab;
    const SeedPaths paths = lab.resolve();
    const Lab_values& v = lab_values();
    CHECK(paths.library == "/drives/" + v.library_id + "/items/root:/" + kProbe +
                               ".txt:/content?%40microsoft.graph.conflictBehavior=fail");
    CHECK(paths.onedrive == "/drives/" + v.onedrive_drive_id + "/items/" + v.folder_id + ":/" +
                                kProbe + ".txt:/content?%40microsoft.graph.conflictBehavior=fail");
    CHECK(paths.mail == "/users/" + v.mailbox + "/mailFolders/inbox/messages");
    CHECK(paths.library_drive_id == v.library_id);
    CHECK(paths.onedrive_drive_id == v.onedrive_drive_id);
    CHECK(paths.onedrive_folder_id == v.folder_id);
    // Each of the guard's checks was asked, once.
    CHECK(lab.http.count(HttpMethod::get, inbox_url()) == 1);
    CHECK(lab.http.count(HttpMethod::get, drive_url()) == 1);
    CHECK(lab.http.count(HttpMethod::get, folder_url()) == 1);
    CHECK(lab.only_reads());
}

TEST_CASE("live seed: a target that isn't a RestoreTarget is refused before any write",
          "[live_seed]")
{
    SeedLab lab;
    const std::string which = GENERATE(std::string{"another library"},
                                       std::string{"a subfolder of /RestoreTarget"},
                                       std::string{"the OneDrive root"},
                                       std::string{"another mailbox"});
    INFO(which);
    if (which == "another library") {
        json drive = load_fixture_json("graph", "restoretarget-drive-200");
        drive["body"]["name"] = "Dokumenty";
        drive["body"]["webUrl"] = "https://restoreprooflab.sharepoint.com/sites/RestoreTest/Dokumenty";
        lab.http.on(HttpMethod::get, drive_url(), {to_response(drive)});
    } else if (which == "a subfolder of /RestoreTarget") {
        json folder = load_fixture_json("graph", "onedrive-folder-200");
        folder["body"]["name"] = "Sub";
        folder["body"]["parentReference"]["path"] =
            folder["body"]["parentReference"]["path"].get<std::string>() + "/RestoreTarget";
        lab.http.on(HttpMethod::get, folder_url(), {to_response(folder)});
    } else if (which == "the OneDrive root") {
        json folder = load_fixture_json("graph", "onedrive-folder-200");
        folder["body"]["name"] = "root";
        folder["body"].erase("parentReference");
        lab.http.on(HttpMethod::get, folder_url(), {to_response(folder)});
    } else {
        lab.http.on(HttpMethod::get, inbox_url(),
                    {load_fixture("graph", "mailbox-inbox-403-exchange")});
    }
    CHECK_THROWS_AS(lab.resolve(), WrongTargetError);
    CHECK(lab.only_reads());
}

TEST_CASE("live seed: a refusal's message says nothing was seeded", "[live_seed]")
{
    SeedLab lab;
    json drive = load_fixture_json("graph", "restoretarget-drive-200");
    drive["body"]["name"] = "RestoreTest";
    lab.http.on(HttpMethod::get, drive_url(), {to_response(drive)});
    CHECK_THROWS_WITH(lab.resolve(), ContainsSubstring("nothing was seeded"));
    CHECK(lab.only_reads());
}

TEST_CASE("live seed: an ID of the wrong shape or a bad probe name stops before any request",
          "[live_seed]")
{
    SeedLab lab;
    rp::Config config = lab_config();
    const std::string which = GENERATE(std::string{"folder"}, std::string{"library"},
                                       std::string{"onedrive drive"}, std::string{"mailbox"},
                                       std::string{"probe"});
    INFO(which);
    std::string probe = kProbe;
    if (which == "folder") {
        config.test_onedrive_folder_id = lab_values().folder_id + "/children";
    } else if (which == "library") {
        config.test_library_id = lab_values().library_id + "?x=1";
    } else if (which == "onedrive drive") {
        config.test_onedrive_drive_id = "b!a:b";
    } else if (which == "mailbox") {
        config.test_mailbox = "alice@RestoreProofLab.onmicrosoft.com";
    } else {
        probe = "../RestoreTest/x";
    }
    CHECK_THROWS_AS(lab.resolve(config, probe), std::invalid_argument);
    CHECK(lab.http.requests().empty());
}
