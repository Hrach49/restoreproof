// W3.2 (#36): the two live `rpworker restore --record` runs of 2026-10-01
// replayed offline through the whole command and the real veeam_m365 connector:
// the sample, the restore, the before and after reads and the check. Veeam and
// Graph answer from the recordings in tests/fixtures/recordings/w32-live-run1/
// and w32-live-run2/ (their README.md says what was edited, and why). The
// recorded downloads keep only a digest, so each download is served the
// canary's own bytes from lab/canary/, the file the recorded /content named.
// Run 1 restored 11 items into empty targets: all match. Run 2 restored the
// same canaries over run 1's copies: the files' cTags moved (match), and Veeam
// wrote no new mail (error stale_target, never missing; docs/decisions.md
// 2026-10-01, "W3.2 live run").
// W3.4 (#39): the first live run with the Cleaner (2026-10-02,
// recordings/w34-live-run1/), replayed the same way: its clean before and after
// are recorded too, so every listing, DELETE and permanentDelete is the live
// run's, and the test checks each delete named an item its target's latest
// listing held.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "test_support.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/cli.hpp>
#include <rp/connector.hpp>
#include <rp/http_client.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/secrets.hpp>
#include <rp/sha256.hpp>
#include <rp/step_timer.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

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

using Catch::Matchers::ContainsSubstring;

namespace {

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

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read " + path.string());
    }
    return {std::istreambuf_iterator<char>(file), {}};
}

std::filesystem::path lab_dir()
{
    return std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab";
}

// A recording's service folder's files, in the order they were recorded.
std::vector<std::filesystem::path> recorded_files(const std::filesystem::path& dir)
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
json lab_config()
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
        env.load_secrets = [](const std::filesystem::path&) {
            return rp::Secrets{vrl::kUsername, vrl::kPassword, rp::test::graph_lab::pfx_base64(),
                               std::string{rp::test::graph_lab::kPfxPassword}};
        };
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

std::string lines(const std::vector<std::string>& rows)
{
    std::string out;
    for (const std::string& row : rows) {
        out += row + "\n";
    }
    return out;
}

// What both runs print before the check, as the live consoles show it but
// for the total time, which is the replay's clock's.
const std::string kW32Point = "2026-09-30T22:00:43.4764524Z  "
                              "c2f0f2e7-177f-48ac-992b-93a50cf702e305134a51-8a9e-4298-b39a-"
                              "1be364acd660";

std::string restore_part(const std::string& run_id, const std::string& seed,
                         const std::vector<std::string>& rows, const std::string& total,
                         const std::string& point = kW32Point)
{
    std::vector<std::string> out{
        "restore point " + point + "  (veeam_org_name RestoreProofLab.onmicrosoft.com)",
        "run " + run_id + "  seed " + seed,
        "cleanup before ok: deleted 0 mail, 0 sharepoint, 0 onedrive",
        "canary cursor 0,0,0 -> 3,3,3",
        "  KIND        REQUESTED  CANARIES  RANDOM  NOTE",
        "  mail        5          3 of 3    2 of 2",
        "  sharepoint  5          3 of 3    0 of 2  random shortfall",
        "  onedrive    5          3 of 3    0 of 2  random shortfall",
        "restoring 11 item(s) ...",
    };
    out.insert(out.end(), rows.begin(), rows.end());
    out.push_back("");
    out.push_back("restore succeeded: 11 of 11 item(s) restored in " + total);
    return lines(out);
}

// An item's row of the restore table.
std::string restored_row(const std::string& kind_source_name, const std::string& session,
                         const std::string& elapsed, const std::string& name,
                         const std::string& detail)
{
    return "  " + kind_source_name + "restored  " + session + "  " + elapsed + "  Item " + name +
           " was restored successfully (" + detail + ")";
}

const std::string kAliceMail =
    "type: IPM.Note; source: Alice Test\\Inbox; "
    "target: restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox";
const std::string kOwnerMail =
    "type: IPM.Note; source: Hrachya Harutyunyan\\Inbox; "
    "target: restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox";

std::string sp_detail(const std::string& name)
{
    return "type: File; source: /sites/RestoreTest/RestoreTest/" + name +
           "; target: https://restoreprooflab.sharepoint.com/sites/RestoreTest";
}

std::string od_detail(const std::string& name)
{
    return "type: File; source: personal/alice_restoreprooflab_onmicrosoft_com/Documents/"
           "RestoreTarget/" +
           name +
           "; target: https://restoreprooflab-my.sharepoint.com/personal/"
           "alice_restoreprooflab_onmicrosoft_com";
}

// Run 1's restore table and sessions, as its live console shows them.
std::vector<std::string> run1_rows()
{
    const std::string mail1 = "94540f96-ef00-48d0-af35-fbec567c3096";
    const std::string mail2 = "0eeebe41-92db-4c10-baab-d8fb8adf901c";
    const std::string sp = "923456e5-5a5e-437c-87a3-0c88f1053b92";
    const std::string od = "30e112c7-86a1-4f2a-b952-ad8c00479159";
    return {
        "",
        "  KIND        SOURCE  NAME                                      OUTCOME   SESSION      "
        "                         ELAPSED  MESSAGE",
        restored_row("mail        canary  RP-CANARY-0001                            ", mail1,
                     "0:00:28", "RP-CANARY-0001", kAliceMail),
        restored_row("mail        canary  RP-CANARY-0002                            ", mail1,
                     "0:00:28", "RP-CANARY-0002", kAliceMail),
        restored_row("mail        canary  RP-CANARY-0003                            ", mail1,
                     "0:00:28", "RP-CANARY-0003", kAliceMail),
        restored_row("mail        random  Veeam website registration                ", mail2,
                     "0:00:28", "Veeam website registration", kOwnerMail),
        restored_row("mail        random  Weekly digest: Microsoft service updates  ", mail2,
                     "0:00:28", "Weekly digest: Microsoft service updates", kOwnerMail),
        restored_row("sharepoint  canary  rp-canary-01.pdf                          ", sp,
                     "0:00:37", "rp-canary-01.pdf", sp_detail("rp-canary-01.pdf")),
        restored_row("sharepoint  canary  rp-canary-02.docx                         ", sp,
                     "0:00:37", "rp-canary-02.docx", sp_detail("rp-canary-02.docx")),
        restored_row("sharepoint  canary  rp-canary-03.xlsx                         ", sp,
                     "0:00:37", "rp-canary-03.xlsx", sp_detail("rp-canary-03.xlsx")),
        restored_row("onedrive    canary  rp-canary-11.pdf                          ", od,
                     "0:00:32", "rp-canary-11.pdf", od_detail("rp-canary-11.pdf")),
        restored_row("onedrive    canary  rp-canary-12.docx                         ", od,
                     "0:00:32", "rp-canary-12.docx", od_detail("rp-canary-12.docx")),
        restored_row("onedrive    canary  rp-canary-13.xlsx                         ", od,
                     "0:00:32", "rp-canary-13.xlsx", od_detail("rp-canary-13.xlsx")),
        "",
        "  SESSION                               KIND        RESULT   RESTORED  STARTED        "
        "               ENDED                         ELAPSED",
        "  " + mail1 +
            "  mail        Success  3 of 3    2026-10-01T17:22:12.0600195Z  "
            "2026-10-01T17:22:40.9658657Z  0:00:28",
        "  " + mail2 +
            "  mail        Success  2 of 2    2026-10-01T17:22:42.7173935Z  "
            "2026-10-01T17:23:11.0785475Z  0:00:28",
        "  " + sp +
            "  sharepoint  Success  3 of 3    2026-10-01T17:23:13.5579069Z  "
            "2026-10-01T17:23:51.2851273Z  0:00:37",
        "  " + od +
            "  onedrive    Success  3 of 3    2026-10-01T17:23:54.2673479Z  "
            "2026-10-01T17:24:26.6293116Z  0:00:32",
    };
}

// Run 1's check table with `outcome` for each item, in RestoreSpec order. The
// replay's clock stands still while reading, so each found item's ms is 0.
std::string run1_check(const std::vector<std::string>& outcome_rows, const std::string& summary)
{
    std::vector<std::string> out{
        "", "  KIND        SOURCE  NAME                                      OUTCOME  FIELDS  DUP  MS"};
    out.insert(out.end(), outcome_rows.begin(), outcome_rows.end());
    out.push_back("");
    out.push_back(summary);
    return lines(out);
}

const std::vector<std::string> kRun1Names{
    "mail        canary  RP-CANARY-0001                            ",
    "mail        canary  RP-CANARY-0002                            ",
    "mail        canary  RP-CANARY-0003                            ",
    "mail        random  Veeam website registration                ",
    "mail        random  Weekly digest: Microsoft service updates  ",
    "sharepoint  canary  rp-canary-01.pdf                          ",
    "sharepoint  canary  rp-canary-02.docx                         ",
    "sharepoint  canary  rp-canary-03.xlsx                         ",
    "onedrive    canary  rp-canary-11.pdf                          ",
    "onedrive    canary  rp-canary-12.docx                         ",
    "onedrive    canary  rp-canary-13.xlsx                         ",
};

const std::vector<std::string> kCanaryFiles{
    "rp-canary-01.pdf", "rp-canary-02.docx", "rp-canary-03.xlsx",
    "rp-canary-11.pdf", "rp-canary-12.docx", "rp-canary-13.xlsx",
};

// Each canary file the replay downloaded is the one the live run downloaded,
// in its order, with the bytes the live run got, but for the SharePoint docx
// and xlsx, which SharePoint rewrites (their office-v1 hash is the manifest's
// either way).
void check_downloads_as_recorded(const Replay& replay)
{
    REQUIRE(replay.served == kCanaryFiles);
    const std::vector<std::string> recorded = replay.recorded_download_digests();
    REQUIRE(recorded.size() == kCanaryFiles.size());
    for (std::size_t i = 0; i < kCanaryFiles.size(); ++i) {
        CAPTURE(kCanaryFiles[i]);
        const bool rewritten = i == 1 || i == 2;
        const std::string served = rp::sha256_hex(read_file(lab_dir() / "canary" / kCanaryFiles[i]));
        CHECK((served == recorded[i]) == !rewritten);
    }
}

// Every request line (`METHOD path?query`, as serve_recording matches it)
// whose count in `fake`'s requests differs from its count of files in the
// recording's service folder `dir`, as "<line>: sent <n>, recorded <m>"; empty
// when the fake was asked for each recorded exchange exactly once, and for
// nothing else. A check per route, not of totals: one request too many on one
// route and one too few on another leave the totals equal.
std::vector<std::string> routes_not_as_recorded(const rp::test::FakeHttpClient& fake,
                                                const std::filesystem::path& dir)
{
    std::map<std::string, std::pair<std::size_t, std::size_t>> counts; // sent, recorded
    for (const std::filesystem::path& file : recorded_files(dir)) {
        ++counts[json::parse(read_file(file)).at("request").get<std::string>()].second;
    }
    for (const rp::HttpRequest& request : fake.requests()) {
        ++counts[std::string{rp::to_string(request.method)} + " " +
                 std::string{rp::request_path(request.url)}]
              .first;
    }
    std::vector<std::string> out;
    for (const auto& [line, count] : counts) {
        if (count.first != count.second) {
            out.push_back(line + ": sent " + std::to_string(count.first) + ", recorded " +
                          std::to_string(count.second));
        }
    }
    return out;
}

// The replay served each recorded exchange, restored 4 times with the
// exported credential, and downloaded each of this run's canary files once
// (check_downloads_as_recorded).
void check_replayed_as_recorded(const Replay& replay)
{
    CHECK(replay.veeam.requests().size() == replay.veeam_files);
    // W3.4: and the clean before and after: each resolved the three targets
    // once (the recorded guard checks again) and listed each one twice, empty.
    std::size_t listings = 0;
    for (const std::string& url : replay.cleanup_urls) {
        CHECK(replay.graph.count(rp::HttpMethod::get, url) == 4);
        listings += replay.graph.count(rp::HttpMethod::get, url);
    }
    // Q3.2: and the library root's count, once per read of the library: the
    // before snapshot, the after read and each clean.
    CHECK(replay.graph.requests().size() == replay.graph_files + listings + 6 + 4);
    CHECK(replay.restore_posts() == 4);
    CHECK(replay.exporter->calls == 4);
    check_downloads_as_recorded(replay);
}

// `text` padded with spaces to `width`.
std::string pad(const std::string& text, std::size_t width)
{
    return text + std::string(width > text.size() ? width - text.size() : 0, ' ');
}

// W3.4: every delete the replay sent, each with what the latest listing of its
// target (the Cleaner's own listing URL) held of that item, and its If-Match.
struct DeleteSeen {
    std::string url;
    std::string listing_url;     // empty: no listing of that target came before
    json listed = json::array(); // the listing's entries with the deleted ID
    std::string if_match;        // empty for a mail's permanentDelete
};

std::vector<DeleteSeen> deletes_with_listings(const std::vector<Exchange>& exchanges,
                                              const std::vector<std::string>& cleanup_urls)
{
    const std::string& mail_list = cleanup_urls.at(0);
    const std::string& library_list = cleanup_urls.at(1);
    const std::string& onedrive_list = cleanup_urls.at(2);
    const json config = lab_config();
    const std::string mail_prefix =
        kGraphHost + "/v1.0/users/" + config.at("test_mailbox").get<std::string>() + "/messages/";
    const std::string library_prefix =
        kGraphHost + "/v1.0/drives/" + config.at("test_library_id").get<std::string>() + "/items/";
    const std::string onedrive_prefix = kGraphHost + "/v1.0/drives/" +
                                        config.at("test_onedrive_drive_id").get<std::string>() +
                                        "/items/";
    const std::string_view permanent_delete = "/permanentDelete";
    std::map<std::string, json> last; // a listing URL -> its last answer's `value`
    std::vector<DeleteSeen> out;
    for (const Exchange& e : exchanges) {
        const std::string& url = e.request.url;
        if (e.request.method == rp::HttpMethod::get &&
            (url == mail_list || url == library_list || url == onedrive_list)) {
            last[url] = json::parse(e.response.body).at("value");
            continue;
        }
        const bool mail_delete = e.request.method == rp::HttpMethod::post &&
                                 url.ends_with(permanent_delete);
        if (!mail_delete && e.request.method != rp::HttpMethod::del) {
            continue;
        }
        DeleteSeen seen{url};
        std::string id;
        if (mail_delete && url.starts_with(mail_prefix)) {
            seen.listing_url = mail_list;
            id = url.substr(mail_prefix.size(),
                            url.size() - mail_prefix.size() - permanent_delete.size());
        } else if (!mail_delete && url.starts_with(library_prefix)) {
            seen.listing_url = library_list;
            id = url.substr(library_prefix.size());
        } else if (!mail_delete && url.starts_with(onedrive_prefix)) {
            seen.listing_url = onedrive_list;
            id = url.substr(onedrive_prefix.size());
        }
        const auto listing = last.find(seen.listing_url);
        if (listing == last.end()) {
            seen.listing_url.clear();
        } else {
            for (const json& item : listing->second) {
                if (item.at("id") == id) {
                    seen.listed.push_back(item);
                }
            }
        }
        if (const auto it = e.request.headers.find("If-Match"); it != e.request.headers.end()) {
            seen.if_match = it->second;
        }
        out.push_back(std::move(seen));
    }
    return out;
}

} // namespace

// --- Failure paths first --------------------------------------------------------------

TEST_CASE("replay of live run 2: mails Veeam said it restored over run 1's copies are "
          "stale_target, never missing; the files, whose cTag moved, match; status error "
          "stale_target, exit 4",
          "[restore_replay][checker][veeam_m365]")
{
    // Before the fix (commit 6fd89e9) these five were `missing`, and the run
    // exit 5: an unclean target reported as a failed restore.
    Replay replay("w32-live-run2");

    const Run run = replay.run(kRun2);

    INFO(run.err);
    INFO(replay.log());
    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.err == kShortfalls +
                         "warning: stale_copies: 5 copies from earlier runs in the restore "
                         "targets were ignored (mail 5, sharepoint 0, onedrive 0)\n");
    const std::string mail1 = "cd253eec-c697-4da2-94b7-24b76a19d79a";
    const std::string mail2 = "58b0bbf9-9b12-4f1c-a070-e7f32d7efe41";
    const std::string sp = "8d902916-7d9e-404c-ac0a-99d696e20b7f";
    const std::string od = "f0525c96-4934-452a-9417-aae689d10929";
    const std::vector<std::string> rows{
        "",
        "  KIND        SOURCE  NAME                                      OUTCOME   SESSION      "
        "                         ELAPSED  MESSAGE",
        restored_row("mail        canary  RP-CANARY-0001                            ", mail1,
                     "0:00:33", "RP-CANARY-0001", kAliceMail),
        restored_row("mail        canary  RP-CANARY-0002                            ", mail1,
                     "0:00:33", "RP-CANARY-0002", kAliceMail),
        restored_row("mail        canary  RP-CANARY-0003                            ", mail1,
                     "0:00:33", "RP-CANARY-0003", kAliceMail),
        restored_row("mail        random  Weekly digest: Microsoft service updates  ", mail2,
                     "0:00:28", "Weekly digest: Microsoft service updates", kOwnerMail),
        restored_row("mail        random  Veeam website registration                ", mail2,
                     "0:00:28", "Veeam website registration", kOwnerMail),
        restored_row("sharepoint  canary  rp-canary-01.pdf                          ", sp,
                     "0:00:47", "rp-canary-01.pdf", sp_detail("rp-canary-01.pdf")),
        restored_row("sharepoint  canary  rp-canary-02.docx                         ", sp,
                     "0:00:47", "rp-canary-02.docx", sp_detail("rp-canary-02.docx")),
        restored_row("sharepoint  canary  rp-canary-03.xlsx                         ", sp,
                     "0:00:47", "rp-canary-03.xlsx", sp_detail("rp-canary-03.xlsx")),
        restored_row("onedrive    canary  rp-canary-11.pdf                          ", od,
                     "0:00:41", "rp-canary-11.pdf", od_detail("rp-canary-11.pdf")),
        restored_row("onedrive    canary  rp-canary-12.docx                         ", od,
                     "0:00:41", "rp-canary-12.docx", od_detail("rp-canary-12.docx")),
        restored_row("onedrive    canary  rp-canary-13.xlsx                         ", od,
                     "0:00:41", "rp-canary-13.xlsx", od_detail("rp-canary-13.xlsx")),
        "",
        "  SESSION                               KIND        RESULT   RESTORED  STARTED        "
        "               ENDED                         ELAPSED",
        "  " + mail1 +
            "  mail        Success  3 of 3    2026-10-01T17:28:28.4077833Z  "
            "2026-10-01T17:29:01.9835177Z  0:00:33",
        "  " + mail2 +
            "  mail        Success  2 of 2    2026-10-01T17:29:04.0928765Z  "
            "2026-10-01T17:29:32.1060606Z  0:00:28",
        "  " + sp +
            "  sharepoint  Success  3 of 3    2026-10-01T17:29:34.741611Z   "
            "2026-10-01T17:30:22.3608568Z  0:00:47",
        "  " + od +
            "  onedrive    Success  3 of 3    2026-10-01T17:30:25.6534539Z  "
            "2026-10-01T17:31:07.5816094Z  0:00:41",
    };
    CHECK(replay.body(run) ==
          restore_part(kRun2, "be2461b7", rows, "0:02:40") +
              lines({
                  "",
                  "  KIND        SOURCE  NAME                                      OUTCOME  FIELDS  "
                  "      DUP  MS",
                  "  mail        canary  RP-CANARY-0001                            error    "
                  "stale_target  -    -",
                  "  mail        canary  RP-CANARY-0002                            error    "
                  "stale_target  -    -",
                  "  mail        canary  RP-CANARY-0003                            error    "
                  "stale_target  -    -",
                  "  mail        random  Weekly digest: Microsoft service updates  error    "
                  "stale_target  -    -",
                  "  mail        random  Veeam website registration                error    "
                  "stale_target  -    -",
                  "  sharepoint  canary  rp-canary-01.pdf                          match    -    "
                  "         -    0",
                  "  sharepoint  canary  rp-canary-02.docx                         match    -    "
                  "         -    0",
                  "  sharepoint  canary  rp-canary-03.xlsx                         match    -    "
                  "         -    0",
                  "  onedrive    canary  rp-canary-11.pdf                          match    -    "
                  "         -    0",
                  "  onedrive    canary  rp-canary-12.docx                         match    -    "
                  "         -    0",
                  "  onedrive    canary  rp-canary-13.xlsx                         match    -    "
                  "         -    0",
                  "",
                  "check: 6 match, 0 mismatch, 0 missing, 5 error",
                  "",
                  "status error stale_target: 5 of 11 item(s) couldn't be checked (stale_target "
                  "5); 6 verified",
                  kCleanAfter,
              }));
    CHECK_THAT(run.out, !ContainsSubstring("missing  "));
    check_replayed_as_recorded(replay);
}

TEST_CASE("replay of live run 1 with a canary mail taken out of the after read: it is missing, "
          "status fail, exit 5",
          "[restore_replay][checker][veeam_m365]")
{
    Replay replay("w32-live-run1");
    replay.edit_after_mail([](json& messages) {
        messages.erase(std::ranges::find_if(messages, [](const json& m) {
            return m.at("subject") == "RP-CANARY-0002";
        }));
    });

    const Run run = replay.run(kRun1);

    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::restore);
    CHECK(run.err == kShortfalls);
    std::vector<std::string> outcomes;
    for (std::size_t i = 0; i < kRun1Names.size(); ++i) {
        outcomes.push_back("  " + kRun1Names[i] +
                           (i == 1 ? "missing  -       -    -" : "match    -       -    0"));
    }
    CHECK(replay.body(run) ==
          restore_part(kRun1, "311f1eea", run1_rows(), "0:02:15") +
              run1_check(outcomes, "check: 10 match, 0 mismatch, 1 missing, 0 error") +
              "\nstatus fail: 1 of 11 item(s) didn't verify (1 missing, 0 mismatch)\n" +
              kCleanAfter + "\n");
}

// --- The live runs as they went -------------------------------------------------------

TEST_CASE("replay of live run 1: 11 items restored into empty targets, all match, status pass, "
          "exit 0",
          "[restore_replay][checker][veeam_m365]")
{
    Replay replay("w32-live-run1");

    const Run run = replay.run(kRun1);

    INFO(run.err);
    INFO(replay.log());
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == kShortfalls);
    std::vector<std::string> outcomes;
    for (const std::string& name : kRun1Names) {
        outcomes.push_back("  " + name + "match    -       -    0");
    }
    CHECK(replay.body(run) ==
          restore_part(kRun1, "311f1eea", run1_rows(), "0:02:15") +
              run1_check(outcomes, "check: 11 match, 0 mismatch, 0 missing, 0 error") +
              "\nstatus pass: 11 of 11 item(s) verified: manifest 9, fields 2, "
              "metadata 0\n" +
              kCleanAfter + "\n");
    check_replayed_as_recorded(replay);
    // The recorded restore POSTs' credential is the recorder's placeholder;
    // the replay sent the exporter's, and no log line names it.
    CHECK_THAT(replay.log(), !ContainsSubstring(vrl::kFakePfxPassword));
    CHECK_THAT(replay.log(), !ContainsSubstring(vrl::kPassword));
}

TEST_CASE("replay of the W3.4 live run: the clean before finds the targets empty, 11 items "
          "restored, all match, status pass, the clean after deletes exactly the 11 copies it "
          "listed, exit 0",
          "[restore_replay][checker][cleaner][veeam_m365]")
{
    // The first live run with the Cleaner (2026-10-02,
    // recordings/w34-live-run1/README.md): its listings, DELETEs and
    // permanentDeletes are recorded, so the replay answers none of them itself.
    Replay replay("w34-live-run1", Cleanup::recorded);

    const Run run = replay.run(kW34Run);

    INFO(run.err);
    INFO(replay.log());
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == kShortfalls);
    const std::string mail1 = "fa02805a-e8be-4ae9-8f1c-099f05ab89e5";
    const std::string mail2 = "a085841a-4cdb-45e1-93eb-8dfb11a084d1";
    const std::string sp = "e018de5b-9435-4cff-ad54-891d7350d949";
    const std::string od = "5a915694-76f5-4b55-85b0-475c51c341a7";
    const std::string sent_mail = "type: IPM.Note; source: Hrachya Harutyunyan\\Sent Items; "
                                  "target: restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox";
    const auto row = [](const std::string& kind, const std::string& source,
                        const std::string& name) {
        return pad(kind, 10) + "  " + source + "  " + pad(name, 36);
    };
    const std::vector<std::string> names{
        row("mail", "canary", "RP-CANARY-0001"),
        row("mail", "canary", "RP-CANARY-0002"),
        row("mail", "canary", "RP-CANARY-0003"),
        row("mail", "random", "sub"),
        row("mail", "random", "RestoreProof W2.2 second mail 3n5w"),
        row("sharepoint", "canary", "rp-canary-01.pdf"),
        row("sharepoint", "canary", "rp-canary-02.docx"),
        row("sharepoint", "canary", "rp-canary-03.xlsx"),
        row("onedrive", "canary", "rp-canary-11.pdf"),
        row("onedrive", "canary", "rp-canary-12.docx"),
        row("onedrive", "canary", "rp-canary-13.xlsx"),
    };
    // As the live console shows them (docs/api/veeam-lab/w3.4-live-3-restore.txt).
    const std::vector<std::string> rows{
        "",
        "  KIND        SOURCE  NAME                                OUTCOME   SESSION              "
        "                 ELAPSED  MESSAGE",
        restored_row(names[0], mail1, "0:00:39", "RP-CANARY-0001", kAliceMail),
        restored_row(names[1], mail1, "0:00:39", "RP-CANARY-0002", kAliceMail),
        restored_row(names[2], mail1, "0:00:39", "RP-CANARY-0003", kAliceMail),
        restored_row(names[3], mail2, "0:00:28", "sub", sent_mail),
        restored_row(names[4], mail2, "0:00:28", "RestoreProof W2.2 second mail 3n5w", sent_mail),
        restored_row(names[5], sp, "0:00:38", "rp-canary-01.pdf", sp_detail("rp-canary-01.pdf")),
        restored_row(names[6], sp, "0:00:38", "rp-canary-02.docx", sp_detail("rp-canary-02.docx")),
        restored_row(names[7], sp, "0:00:38", "rp-canary-03.xlsx", sp_detail("rp-canary-03.xlsx")),
        restored_row(names[8], od, "0:00:37", "rp-canary-11.pdf", od_detail("rp-canary-11.pdf")),
        restored_row(names[9], od, "0:00:37", "rp-canary-12.docx", od_detail("rp-canary-12.docx")),
        restored_row(names[10], od, "0:00:37", "rp-canary-13.xlsx", od_detail("rp-canary-13.xlsx")),
        "",
        "  SESSION                               KIND        RESULT   RESTORED  STARTED        "
        "               ENDED                         ELAPSED",
        "  " + mail1 +
            "  mail        Success  3 of 3    2026-10-02T18:03:32.8466307Z  "
            "2026-10-02T18:04:12.2520691Z  0:00:39",
        "  " + mail2 +
            "  mail        Success  2 of 2    2026-10-02T18:04:13.6599107Z  "
            "2026-10-02T18:04:42.4323881Z  0:00:28",
        "  " + sp +
            "  sharepoint  Success  3 of 3    2026-10-02T18:04:44.3486805Z  "
            "2026-10-02T18:05:22.6849024Z  0:00:38",
        "  " + od +
            "  onedrive    Success  3 of 3    2026-10-02T18:05:25.1374022Z  "
            "2026-10-02T18:06:02.9035178Z  0:00:37",
    };
    // The replay's clock stands still while reading, so each item's ms is 0.
    std::vector<std::string> check{
        "", "  KIND        SOURCE  NAME                                OUTCOME  FIELDS  DUP  MS"};
    for (const std::string& name : names) {
        check.push_back("  " + name + "match    -       -    0");
    }
    check.insert(check.end(),
                 {"", "check: 11 match, 0 mismatch, 0 missing, 0 error", "",
                  "status pass: 11 of 11 item(s) verified: manifest 9, fields 2, metadata 0",
                  "cleanup after ok: deleted 5 mail, 3 sharepoint, 3 onedrive"});
    CHECK(replay.body(run) ==
          restore_part(kW34Run, "6933ea77", rows, kW34Total, kW34Point) + lines(check));
    // W3.5: the step timings, last. The replay's clock moves only on the
    // connector's waits between polls, so the four sessions' waits, summed,
    // are the whole restore, and every span is measured.
    CHECK(run.out.substr(replay.body(run).size()) ==
          lines({"", "STEP                  TIME         NOTE",
                 "restore_point_lookup  0:00:00.000", "cleanup_before        0:00:00.000",
                 "sample_select         0:00:00.000", "target_snapshot       0:00:00.000",
                 "restore               " + kW34Total + ".000",
                 "restore_submit        0:00:00.000",
                 "restore_wait          " + kW34Total + ".000",
                 "verify                0:00:00.000",
                 "recovery              " + kW34Total + ".000",
                 "cleanup_after         0:00:00.000",
                 "total                 " + kW34Total + ".000"}));

    // Every recorded exchange was asked for, and nothing else: the replay sent
    // exactly the live run's requests, its Cleaner's included, route by route.
    CHECK(replay.veeam.requests().size() == replay.veeam_files);
    // Q3.2, after this recording: the library root's count, read before each
    // listing that is held to it (the before snapshot, the after read, each
    // clean's first), is the one route the recording doesn't hold. The OneDrive
    // folder's count is in the recorded guard replies, and every recorded
    // listing was as long as its count.
    const std::string root_count =
        "GET /v1.0/drives/" + lab_config().at("test_library_id").get<std::string>() +
        "/root?$select=id,folder: sent 4, recorded 0";
    CHECK(replay.graph.requests().size() == replay.graph_files + 4);
    CHECK(routes_not_as_recorded(replay.veeam, replay.dir / "veeam").empty());
    CHECK(routes_not_as_recorded(replay.graph, replay.dir / "graph") ==
          std::vector<std::string>{root_count});
    CHECK(replay.restore_posts() == 4);
    CHECK(replay.exporter->calls == 4);
    check_downloads_as_recorded(replay);

    // Each delete names an item the latest listing of its own target held,
    // a file with that listing's eTag; 5 mails and 3 + 3 files, each once.
    const std::vector<Exchange> exchanges = replay.graph_exchanges();
    const std::vector<DeleteSeen> deletes = deletes_with_listings(exchanges, replay.cleanup_urls);
    REQUIRE(deletes.size() == 11);
    std::map<std::string, std::size_t> per_target;
    std::vector<std::string> urls;
    for (const DeleteSeen& d : deletes) {
        CAPTURE(d.url);
        REQUIRE_FALSE(d.listing_url.empty());
        REQUIRE(d.listed.size() == 1);
        ++per_target[d.listing_url];
        urls.push_back(d.url);
        if (d.listing_url == replay.cleanup_urls[0]) {
            CHECK(d.if_match.empty());
        } else {
            CHECK(d.listed[0].contains("file"));
            CHECK(d.if_match == d.listed[0].at("eTag").get<std::string>());
        }
    }
    CHECK(per_target[replay.cleanup_urls[0]] == 5);
    CHECK(per_target[replay.cleanup_urls[1]] == 3);
    CHECK(per_target[replay.cleanup_urls[2]] == 3);
    std::ranges::sort(urls);
    CHECK(std::ranges::adjacent_find(urls) == urls.end());
    // All of them in the clean after, once the after read was done: the clean
    // before had nothing to delete.
    const auto first_delete = std::ranges::find_if(exchanges, [](const Exchange& e) {
        return e.request.method == rp::HttpMethod::del ||
               e.request.url.ends_with("/permanentDelete");
    });
    const auto after_read = std::ranges::find_if(exchanges, [](const Exchange& e) {
        return e.request.url.find(",body&") != std::string::npos;
    });
    REQUIRE(after_read != exchanges.end());
    CHECK(after_read < first_delete);
}

TEST_CASE("replay check: a route asked once too often and another once too rarely is caught, "
          "though the totals agree",
          "[restore_replay]")
{
    const std::filesystem::path dir =
        std::filesystem::path{RP_FIXTURE_DIR} / "recordings" / "w34-live-run1" / "graph";
    std::vector<std::string> lines;
    for (const std::filesystem::path& file : recorded_files(dir)) {
        lines.push_back(json::parse(read_file(file)).at("request").get<std::string>());
    }
    // Two different request lines: the first one is left out once, the
    // second one asked for once more.
    const std::string skipped = lines.front();
    const auto other = std::ranges::find_if(lines, [&](const std::string& l) { return l != skipped; });
    REQUIRE(other != lines.end());
    const std::string doubled = *other;
    const auto send_line = [](rp::test::FakeHttpClient& fake, const std::string& line) {
        const std::size_t space = line.find(' ');
        const std::string verb = line.substr(0, space);
        rp::HttpRequest request;
        request.method = verb == "GET"    ? rp::HttpMethod::get
                         : verb == "POST" ? rp::HttpMethod::post
                                          : rp::HttpMethod::del;
        request.url = kGraphHost + line.substr(space + 1);
        (void)fake.send(request);
    };

    rp::test::FakeHttpClient exact;
    exact.serve_recording(dir);
    for (const std::string& line : lines) {
        send_line(exact, line);
    }
    CHECK(routes_not_as_recorded(exact, dir).empty());

    rp::test::FakeHttpClient skewed;
    skewed.serve_recording(dir);
    bool left_out = false;
    for (const std::string& line : lines) {
        if (!left_out && line == skipped) {
            left_out = true;
            continue;
        }
        send_line(skewed, line);
    }
    send_line(skewed, doubled);
    REQUIRE(skewed.requests().size() == lines.size());
    const std::vector<std::string> differences = routes_not_as_recorded(skewed, dir);
    REQUIRE(differences.size() == 2);
    CHECK_THAT(differences[0] + "\n" + differences[1], ContainsSubstring(skipped + ": sent "));
    CHECK_THAT(differences[0] + "\n" + differences[1], ContainsSubstring(doubled + ": sent "));
}
