#pragma once

// The live recordings replayed through the whole command on the real
// veeam_m365 connector (W3.2, W3.4; the recordings' README.md say what was
// edited): rp::test::replay_lab::Replay serves tests/fixtures/recordings/<name>/
// back to `rpworker restore` with the lab's config, the canaries' own bytes
// for the recorded downloads and a fake certificate exporter, as
// restore_replay_test.cpp uses it; the W4.9 secret audit runs the same replay
// with secrets of its own (`load_secrets`). No Catch2 assertion in a fake's
// handler: they run on the clients' threads.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "test_support.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/connector.hpp>
#include <rp/http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/secrets.hpp>
#include <rp/step_timer.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp::test::replay_lab {

namespace vrl = rp::test::veeam_restore_lab;
using nlohmann::json;

const std::string kGraphHost = "https://graph.microsoft.com";
// The live runs' IDs: with them the sample is the one the live run drew.
const std::string kRun1 = "rp-20261001T172150Z-b029c118";
const std::string kRun2 = "rp-20261001T172815Z-6285c4a6";
// The W3.4 live run (recordings/w34-live-run1/): its ID, its restore point,
// and its total restore time as the replay's clock gives it (live: 0:02:38).
const std::string kW34Run = "rp-20261002T180310Z-6661beff";
const std::string kW34Point = "2026-10-01T22:01:38.761857Z  "
                              "c2f0f2e7-177f-48ac-992b-93a50cf702e35492ac04-4228-4bb8-bca4-"
                              "b68172c5c582";
const std::string kW34Total = "0:02:30";
// The live runs drew no random SharePoint or OneDrive file: the lab has no real
// files (W3.3: warnings, never a status).
const std::string kShortfalls = "warning: shortfall: sharepoint random: 0 of 2\n"
                                "warning: shortfall: onedrive random: 0 of 2\n";
// W3.4: the clean after, which finds the Cleaner's (empty) listings.
const std::string kCleanAfter = "cleanup after ok: deleted 0 mail, 0 sharepoint, 0 onedrive";

inline std::string read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read " + path.string());
    }
    return {std::istreambuf_iterator<char>(file), {}};
}

inline std::filesystem::path lab_dir()
{
    return std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab";
}

// A recording's service folder's files, in the order they were recorded.
inline std::vector<std::filesystem::path> recorded_files(const std::filesystem::path& dir)
{
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".json") {
            files.push_back(entry.path());
        }
    }
    std::ranges::sort(files, {}, [](const std::filesystem::path& file) {
        return rp::test::recorded_file_number(file);
    });
    return files;
}

// The lab config the live runs used (%LOCALAPPDATA%\RestoreProof\lab\config.json):
// its tenant, organisation and five restore targets. The replay answers any
// Veeam host, and sets up no TLS, so the CA file and pin are left out.
inline json lab_config()
{
    return {
        {"cloud_url", "https://localhost"},
        {"veeam_url", "https://localhost:4443"},
        {"veeam_org_name", "RestoreProofLab.onmicrosoft.com"},
        {"graph_tenant_id", "bcd6bd1a-ea42-489d-aa28-2c19a44ad146"},
        {"graph_client_id", "737da5ef-baf2-4198-b009-e160d8ca77c9"},
        {"test_mailbox", "restoretest@RestoreProofLab.onmicrosoft.com"},
        {"test_site_id", "restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,"
                         "4ecaf399-cc0e-4d95-b3fe-cd091a09e689"},
        {"test_library_id", "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6"},
        {"test_onedrive_drive_id",
         "b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3"},
        {"test_onedrive_folder_id", "01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH"},
    };
}

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

// A live recording served back to `rpworker restore` on the default
// registry's veeam_m365 connector. No Catch2 assertions in the handlers: they
// run on the clients' threads.
// An exchange the Worker's Graph client sent through the replay, with the
// answer it got.
struct Exchange {
    rp::HttpRequest request;
    rp::HttpResponse response;
};

// Forwards to the fake and keeps each exchange, so a test can read what a
// listing answered before a delete. No Catch2 assertions: it runs on the
// clients' threads.
class ExchangeLog final : public rp::IHttpClient {
public:
    ExchangeLog(rp::IHttpClient& target, std::mutex& mutex, std::vector<Exchange>& log)
        : target_(target), mutex_(mutex), log_(log)
    {
    }

    rp::HttpResponse send(const rp::HttpRequest& request) override
    {
        rp::HttpResponse response = target_.send(request);
        const std::lock_guard lock(mutex_);
        log_.push_back({request, response});
        return response;
    }

private:
    rp::IHttpClient& target_;
    std::mutex& mutex_;
    std::vector<Exchange>& log_;
};

// Whether the recording holds the Cleaner's own exchanges (W3.4 and later), or
// was made before the Cleaner existed and the replay must answer its listings.
enum class Cleanup { recorded, not_recorded };

struct Replay {
    explicit Replay(const std::string& name, Cleanup cleanup = Cleanup::not_recorded)
        : dir(std::filesystem::path{RP_FIXTURE_DIR} / "recordings" / name)
    {
        config_path = temp.write("config.json", lab_config().dump(2));
        temp.write("seed-manifest.json", read_file(lab_dir() / "seed-manifest.json"));
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("restore_replay_test", sink);
        logger->set_pattern("[%l] %v");

        veeam_files = veeam.serve_recording(dir / "veeam");
        graph_files = graph.serve_recording(dir / "graph");
        // Recorded before Q3.2: the library root's count wasn't asked for then.
        rp::test::graph_lab::serve_library_root(graph);
        // W3.4: the Cleaner's listings. A recording made before W3.4 doesn't
        // hold them: they are answered empty, so the clean before and after
        // delete nothing; its guard checks are the recorded ones.
        const json config = lab_config();
        const std::string files =
            "?$select=id,name,eTag,file,folder,package,remoteItem,root,parentReference&$top=200";
        for (const std::string& path :
             {"/users/" + config.at("test_mailbox").get<std::string>() +
                  "/mailFolders/inbox/messages?$select=id&$top=100",
              "/drives/" + config.at("test_library_id").get<std::string>() + "/root/children" +
                  files,
              "/drives/" + config.at("test_onedrive_drive_id").get<std::string>() + "/items/" +
                  config.at("test_onedrive_folder_id").get<std::string>() + "/children" + files}) {
            cleanup_urls.push_back(kGraphHost + "/v1.0" + path);
            if (cleanup == Cleanup::not_recorded) {
                graph.on(rp::HttpMethod::get, cleanup_urls.back(),
                         {rp::test::graph_lab::page_of(json::array())});
            }
        }
        // Q3.2: a listing is held to its container's count. The Cleaner's
        // listings answered empty above would contradict the OneDrive folder's
        // recorded count (3 once the restore ran), so with them the folder is
        // answered as first recorded but counting no child: nothing a listing
        // could be short of.
        if (cleanup == Cleanup::not_recorded) {
            const std::string folder = "GET /v1.0/drives/" +
                                       config.at("test_onedrive_drive_id").get<std::string>() +
                                       "/items/" +
                                       config.at("test_onedrive_folder_id").get<std::string>() + "?";
            for (const std::filesystem::path& file : recorded_files(dir / "graph")) {
                json fixture = json::parse(read_file(file));
                const std::string request = fixture.at("request").get<std::string>();
                if (request.starts_with(folder)) {
                    fixture["body"]["folder"]["childCount"] = 0;
                    graph.on(rp::HttpMethod::get, kGraphHost + request.substr(4),
                             {rp::test::to_response(fixture)});
                    break;
                }
            }
        }
        // When each restore POST went out: its duplicate check's startTimeFrom
        // plus the check's 60 s window, so the replayed checks ask for exactly
        // the recorded query.
        const std::string duplicate_check = "GET /v8/RestoreSessions?startTimeFrom=";
        for (const std::filesystem::path& file : recorded_files(dir / "veeam")) {
            const std::string request =
                json::parse(read_file(file)).at("request").get<std::string>();
            if (request.starts_with(duplicate_check)) {
                post_times.push_back(vrl::utc(request.substr(duplicate_check.size(), 20)) +
                                     std::chrono::seconds{60});
            }
        }
        for (const std::filesystem::path& file : recorded_files(dir / "graph")) {
            json fixture = json::parse(read_file(file));
            const std::string request = fixture.at("request").get<std::string>();
            // Each file's name by its driveItem ID, from every listing.
            const json& body = fixture.at("body");
            if (body.is_object() && body.contains("value")) {
                for (const json& item : body.at("value")) {
                    if (item.contains("file")) {
                        names[item.at("id").get<std::string>()] =
                            item.at("name").get<std::string>();
                    }
                }
            }
            // The recorded /content answers are 302s whose link's query is
            // scrubbed: each is served again with the item it was for in
            // UniqueId, so the download knows which file to send.
            if (request.ends_with("/content")) {
                const std::string path = request.substr(4);
                const std::size_t start = path.find("/items/") + 7;
                const std::string id = path.substr(start, path.size() - 8 - start);
                std::string location = fixture.at("headers").at("Location").get<std::string>();
                const std::string scrubbed = "UniqueId=SCRUBBED";
                location.replace(location.find(scrubbed), scrubbed.size(), "UniqueId=" + id);
                fixture["headers"]["Location"] = location;
                graph.on(rp::HttpMethod::get, kGraphHost + path, {rp::test::to_response(fixture)});
            }
        }
        for (const std::string pattern :
             {"/sites/RestoreTest/_layouts/15/download.aspx?UniqueId=*",
              "/personal/alice_restoreprooflab_onmicrosoft_com/_layouts/15/download.aspx?"
              "UniqueId=*"}) {
            download.on_path(rp::HttpMethod::get, pattern,
                             [this](const rp::HttpRequest& request) { return bytes(request); });
        }
    }

    // The canary's own bytes, for the file the link names.
    rp::HttpResponse bytes(const rp::HttpRequest& request)
    {
        const std::size_t start = request.url.find("UniqueId=") + 9;
        const std::string id = request.url.substr(start, request.url.find('&', start) - start);
        const auto name = names.find(id);
        if (name == names.end()) {
            return rp::test::make_response(404);
        }
        {
            const std::lock_guard lock(mutex);
            served.push_back(name->second);
        }
        return rp::test::make_response(200, read_file(lab_dir() / "canary" / name->second),
                                       "application/octet-stream");
    }

    // Every restore POST sent so far.
    std::size_t restore_posts() const
    {
        std::size_t sent = 0;
        for (const rp::HttpRequest& request : veeam.requests()) {
            sent += request.method == rp::HttpMethod::post &&
                            (request.url.ends_with("/restoreTo") || request.url.ends_with("/copyTo"))
                        ? 1
                        : 0;
        }
        return sent;
    }

    // The recorded time of the next restore POST; the last one repeats, and
    // before the first it is the first (the certificates are checked then).
    std::chrono::system_clock::time_point wall_now() const
    {
        return post_times.at(std::min(restore_posts(), post_times.size() - 1));
    }

    rp::RestoreCommandEnv env()
    {
        rp::RestoreCommandEnv env;
        env.default_config_path = [] { return std::filesystem::path{"unused.json"}; };
        env.default_vault_path = [] { return std::filesystem::path{"unused.bin"}; };
        env.load_secrets = [this](const std::filesystem::path&) { return load_secrets(); };
        rp::connector::ConnectorOptions& o = env.connector_options;
        o.make_http = [this](const rp::HttpClientOptions&) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(veeam);
        };
        o.make_graph_http =
            [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<ExchangeLog>(graph, mutex, graph_log);
        };
        o.logger = logger;
        o.now = [this] { return clock.now(); };
        o.sleep = [this](std::chrono::milliseconds wait) { clock.sleep(wait); };
        o.jitter = [] { return 0.0; };
        o.wall_now = [this] { return wall_now(); };
        o.cert_exporter = exporter;
        env.now = [this] { return clock.now(); };
        env.make_download_http = [this](std::function<void(std::chrono::milliseconds)>)
            -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(download);
        };
        // W3.4: a fake run mutex, never the machine's.
        env.take_run_lock = []() -> std::unique_ptr<rp::RunLock> {
            return std::make_unique<rp::RunLock>();
        };
        env.on_timings = [this](const rp::timing::RunTimings& run_timings) {
            timings.push_back(run_timings);
        };
        return env;
    }

    // The Graph exchanges so far, in order.
    std::vector<Exchange> graph_exchanges()
    {
        const std::lock_guard lock(mutex);
        return graph_log;
    }

    // The live runs' command line, with the live run's ID.
    Run run(const std::string& run_id)
    {
        const std::u8string path = config_path.u8string();
        const std::string config{path.begin(), path.end()};
        const std::vector<std::string_view> args{
            "--run-id", run_id, "--mail", "5", "--sp", "5", "--od", "5",
            "--canary-cursor", "0,0,0", "--config", config};
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_restore_command(args, out, err, env());
        return {code, out.str(), err.str()};
    }

    // Serves `edit` applied to the recorded after-restore mail listing (the
    // one with bodies) in its place: an edited copy built in the test.
    void edit_after_mail(const std::function<void(json& messages)>& edit)
    {
        for (const std::filesystem::path& file : recorded_files(dir / "graph")) {
            json fixture = json::parse(read_file(file));
            const std::string request = fixture.at("request").get<std::string>();
            if (request.find("/messages?") != std::string::npos &&
                request.find(",body&") != std::string::npos) {
                edit(fixture["body"]["value"]);
                graph.on(rp::HttpMethod::get, kGraphHost + request.substr(4),
                         {rp::test::to_response(fixture)});
            }
        }
    }

    // The recorded downloads' digests, in order.
    std::vector<std::string> recorded_download_digests() const
    {
        std::vector<std::string> out;
        for (const std::filesystem::path& file : recorded_files(dir / "download")) {
            out.push_back(json::parse(read_file(file)).at("body_sha256").get<std::string>());
        }
        return out;
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    // The run's stdout up to its step timings' table (W3.5): REQUIREs one
    // run's timings, and their table at the end.
    std::string body(const Run& run) const
    {
        REQUIRE(timings.size() == 1);
        const std::string table = "\n" + rp::timing::format_timings(timings[0]);
        REQUIRE(run.out.ends_with(table));
        return run.out.substr(0, run.out.size() - table.size());
    }

    // The vault's five values as the live runs had them (the user name the
    // recording's own, so the duplicate check finds the recorded sessions);
    // the W4.9 audit sets its own.
    std::function<rp::Secrets()> load_secrets = [] {
        return rp::Secrets{vrl::kUsername, vrl::kPassword, rp::test::graph_lab::pfx_base64(),
                           std::string{rp::test::graph_lab::kPfxPassword}};
    };
    std::filesystem::path dir;
    rp::test::TempDir temp;
    std::filesystem::path config_path;
    rp::test::FakeHttpClient veeam;
    rp::test::FakeHttpClient graph;
    rp::test::FakeHttpClient download;
    std::size_t veeam_files = 0;
    std::size_t graph_files = 0;
    std::vector<std::string> cleanup_urls; // the Cleaner's three listings (W3.4)
    vrl::FakeClock clock;
    std::shared_ptr<vrl::FakeExporter> exporter = std::make_shared<vrl::FakeExporter>();
    std::vector<std::chrono::system_clock::time_point> post_times;
    std::map<std::string, std::string> names; // driveItem ID -> name
    std::mutex mutex;
    std::vector<std::string> served; // the canaries downloaded, in order
    std::vector<Exchange> graph_log;  // every Graph exchange, in order
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    std::vector<rp::timing::RunTimings> timings; // W3.5: each run's
};

} // namespace rp::test::replay_lab
