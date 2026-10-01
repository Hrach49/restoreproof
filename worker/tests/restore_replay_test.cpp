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

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "test_support.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/cli.hpp>
#include <rp/connector.hpp>
#include <rp/http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/secrets.hpp>
#include <rp/sha256.hpp>

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
// The live runs drew no random SharePoint or OneDrive file: the lab has no real
// files (W3.3: warnings, never a status).
const std::string kShortfalls = "warning: shortfall: sharepoint random: 0 of 2\n"
                                "warning: shortfall: onedrive random: 0 of 2\n";

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
struct Replay {
    explicit Replay(const std::string& name)
        : dir(std::filesystem::path{RP_FIXTURE_DIR} / "recordings" / name)
    {
        config_path = temp.write("config.json", lab_config().dump(2));
        temp.write("seed-manifest.json", read_file(lab_dir() / "seed-manifest.json"));
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("restore_replay_test", sink);
        logger->set_pattern("[%l] %v");

        veeam_files = veeam.serve_recording(dir / "veeam");
        graph_files = graph.serve_recording(dir / "graph");
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
        env.load_secrets = [] {
            return rp::Secrets{vrl::kUsername, vrl::kPassword, rp::test::graph_lab::pfx_base64(),
                               std::string{rp::test::graph_lab::kPfxPassword}};
        };
        rp::connector::ConnectorOptions& o = env.connector_options;
        o.make_http = [this](const rp::HttpClientOptions&) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(veeam);
        };
        o.make_graph_http =
            [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(graph);
        };
        o.logger = logger;
        o.now = [this] { return clock.now(); };
        o.sleep = [this](std::chrono::milliseconds wait) { clock.sleep(wait); };
        o.jitter = [] { return 0.0; };
        o.wall_now = [this] { return wall_now(); };
        o.cert_exporter = exporter;
        env.now = [this] { return clock.now(); };
        env.make_download_http = [this]() -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(download);
        };
        return env;
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

    std::filesystem::path dir;
    rp::test::TempDir temp;
    std::filesystem::path config_path;
    rp::test::FakeHttpClient veeam;
    rp::test::FakeHttpClient graph;
    rp::test::FakeHttpClient download;
    std::size_t veeam_files = 0;
    std::size_t graph_files = 0;
    vrl::FakeClock clock;
    std::shared_ptr<vrl::FakeExporter> exporter = std::make_shared<vrl::FakeExporter>();
    std::vector<std::chrono::system_clock::time_point> post_times;
    std::map<std::string, std::string> names; // driveItem ID -> name
    std::mutex mutex;
    std::vector<std::string> served; // the canaries downloaded, in order
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
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
std::string restore_part(const std::string& run_id, const std::string& seed,
                         const std::vector<std::string>& rows, const std::string& total)
{
    std::vector<std::string> out{
        "restore point 2026-09-30T22:00:43.4764524Z  "
        "c2f0f2e7-177f-48ac-992b-93a50cf702e305134a51-8a9e-4298-b39a-1be364acd660  "
        "(veeam_org_name RestoreProofLab.onmicrosoft.com)",
        "run " + run_id + "  seed " + seed,
        "canary cursor 0,0,0 -> 3,3,3",
        "  KIND        REQUESTED  CANARIES  RANDOM  NOTE",
        "  mail        5          3 of 3    2 of 2",
        "  sharepoint  5          3 of 3    0 of 2  random shortfall",
        "  onedrive    5          3 of 3    0 of 2  random shortfall",
        "restoring 11 item(s) ...",
    };
    out.insert(out.end(), rows.begin(), rows.end());
    out.push_back("");
    out.push_back("status succeeded: 11 of 11 item(s) restored in " + total);
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

// The replay served each recorded exchange, restored 4 times with the
// exported credential, and downloaded each of this run's canary files once:
// with the bytes the live run downloaded, but for the SharePoint docx and xlsx,
// which SharePoint rewrites (their office-v1 hash is the manifest's either way).
void check_replayed_as_recorded(const Replay& replay)
{
    CHECK(replay.veeam.requests().size() == replay.veeam_files);
    CHECK(replay.graph.requests().size() == replay.graph_files);
    CHECK(replay.restore_posts() == 4);
    CHECK(replay.exporter->calls == 4);
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
    CHECK(run.out ==
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
    CHECK(run.out == restore_part(kRun1, "311f1eea", run1_rows(), "0:02:15") +
                         run1_check(outcomes, "check: 10 match, 0 mismatch, 1 missing, 0 error") +
                         "\nstatus fail: 1 of 11 item(s) didn't verify (1 missing, 0 mismatch)\n");
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
    CHECK(run.out == restore_part(kRun1, "311f1eea", run1_rows(), "0:02:15") +
                         run1_check(outcomes, "check: 11 match, 0 mismatch, 0 missing, 0 error") +
                         "\nstatus pass: 11 of 11 item(s) verified: manifest 9, fields 2, "
                         "metadata 0\n");
    check_replayed_as_recorded(replay);
    // The recorded restore POSTs' credential is the recorder's placeholder;
    // the replay sent the exporter's, and no log line names it.
    CHECK_THAT(replay.log(), !ContainsSubstring(vrl::kFakePfxPassword));
    CHECK_THAT(replay.log(), !ContainsSubstring(vrl::kPassword));
}
