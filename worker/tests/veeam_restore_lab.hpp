#pragma once

// VeeamM365Connector::restore_sample (W2.5) as its tests see it: Veeam is a
// FakeHttpClient replaying W2.4's recorded runs (tests/fixtures/veeam/w24-*,
// restore-*-200) on the URLs the connector builds, Graph is the guard's lab
// (target_guard_lab.hpp), the certificate exporter a fake that hands out
// sentinel strings and counts its calls, the steady clock one that only the
// connector's waits move (recorded, never slept), and the wall clock a list of
// POST times. No Catch2 assertions in here: FakeHttpClient's handlers may call
// these on the client's threads.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"

#include <rp/cert_export.hpp>
#include <rp/connector.hpp>
#include <rp/http_client.hpp>
#include <rp/veeam_m365_connector.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <deque>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp::test::veeam_restore_lab {

using namespace rp::test::target_guard_lab;
using nlohmann::json;
using nlohmann::ordered_json;

inline const std::string kBase = "https://veeam.test:4443";
inline const std::string kOrgId = "ff96d072-29e2-4cb4-a155-2590f5473176";
inline const std::string kOrgName = "RestoreProofLab.onmicrosoft.com";
inline const std::string kThumbprint = "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7";
// The W2.4 restore point, byte for byte as the recorded explore POSTs sent it.
inline const std::string kBackupTime = "2026-09-27T22:00:48.1447833Z";
// Its ID: the lab repository's ID (restore-points-200) and a made-up point ID;
// the W2.4 recordings don't list the restore points.
inline const std::string kRestorePointId =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e3" "5e1c0a24-0000-4000-8000-000000000924";
inline const std::string kUsername = "DESKTOP-P55CDUM\\rp-veeam";
// Never in an error, a log line or the result.
inline const std::string kPassword = "Sentinel-Veeam-Password-5e1c";
inline const std::string kFakePfx = "Sentinel-Fake-PFX-Base64-5e1c";
inline const std::string kFakePfxPassword = "Sentinel-Fake-PFX-Password-5e1c";
// The canary library's list ID, as the recorded SharePoint run's IDs show it.
inline const std::string kCanaryListId = "7eb0f08a-f57b-418c-8ca6-f2ab81297666";
inline const std::string kAlice = "alice@RestoreProofLab.onmicrosoft.com";
inline const std::string kBob = "bob@RestoreProofLab.onmicrosoft.com";

inline std::string url(const std::string& path)
{
    return kBase + path;
}

// A recorded response, the fixture's body edited by `edit` if given.
inline HttpResponse fixture(const std::string& name, const std::function<void(json&)>& edit = {})
{
    json recorded = load_fixture_json("veeam", name);
    if (edit) {
        edit(recorded["body"]);
    }
    return to_response(recorded);
}

// The fixture file with its objects' keys in their order.
inline ordered_json ordered_fixture(const std::string& name)
{
    const std::string path = std::string{RP_FIXTURE_DIR} + "/veeam/" + name + ".json";
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read fixture " + path);
    }
    return ordered_json::parse(std::string{std::istreambuf_iterator<char>(file), {}});
}

// Percent-encoding as the connector does it (letters, digits, -._~ kept).
inline std::string encoded(std::string_view text)
{
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
            byte == '~') {
            out += c;
        } else {
            out += '%';
            out += hex[byte >> 4];
            out += hex[byte & 0x0F];
        }
    }
    return out;
}

// "YYYY-MM-DDTHH:MM:SSZ" -> a time (the tests' own reading, whole seconds only).
inline std::chrono::system_clock::time_point utc(const std::string& text)
{
    std::istringstream in(text);
    std::chrono::sys_seconds out{};
    in >> std::chrono::parse("%Y-%m-%dT%H:%M:%SZ", out);
    if (in.fail()) {
        throw std::runtime_error("not a UTC time: " + text);
    }
    return out;
}

// A recorded list's results, by value: a range-for over a member of a
// temporary would outlive it.
inline json results_of(const std::string& name)
{
    return load_fixture_json("veeam", name).at("body").at("results");
}

inline std::string paged(const std::string& path)
{
    return path + (path.find('?') == std::string::npos ? "?" : "&") + "limit=1000&offset=0";
}

// The organisation's restore points: the recorded list with the W2.4 point
// (kRestorePointId, kBackupTime) first, `edit` applied to that entry if given.
inline HttpResponse restore_points(const std::function<void(json&)>& edit = {})
{
    return fixture("restore-points-200", [&](json& body) {
        json point = body.at("results").at(0);
        point["id"] = kRestorePointId;
        point["backupTime"] = kBackupTime;
        if (edit) {
            edit(point);
        }
        body["results"].insert(body["results"].begin(), point);
    });
}

inline std::string restore_points_url()
{
    return url(paged("/v8/RestorePoints?organizationId=" + kOrgId));
}

// One of W2.4's recorded runs.
struct Run {
    std::string name;              // mail-x5, mail-x1, sp-x1, od-x1
    rp::connector::ItemKind kind;
    std::string restore_fixture;   // restore-*-200
    std::string type;              // Vex, Vesp, Veod

    std::string file(const std::string& step) const { return "w24-" + name + "-" + step; }
    std::string explore() const
    {
        return load_fixture_json("veeam", file("explore")).at("body").at("id").get<std::string>();
    }
    std::string restore() const
    {
        return load_fixture_json("veeam", restore_fixture)
            .at("body")
            .at("sessionId")
            .get<std::string>();
    }
    // The restore POST's path, as recorded.
    std::string post_path() const
    {
        return load_fixture_json("veeam", restore_fixture).at("request").get<std::string>().substr(5);
    }
    // The source container: the path's seventh segment.
    std::string container() const
    {
        const std::string path = post_path();
        std::size_t at = 0;
        for (int i = 0; i < 6; ++i) {
            at = path.find('/', at) + 1;
        }
        return path.substr(at, path.find('/', at) - at);
    }
    // When the POST went out: the recorded duplicate check's startTimeFrom plus 60 s.
    std::chrono::system_clock::time_point posted() const
    {
        const std::string request =
            load_fixture_json("veeam", file("sessions-after-post")).at("request").get<std::string>();
        const std::size_t at = request.find("startTimeFrom=") + 14;
        return utc(request.substr(at, 20)) + std::chrono::seconds{60};
    }
    std::string duplicate_url() const
    {
        const std::string request =
            load_fixture_json("veeam", file("sessions-after-post")).at("request").get<std::string>();
        return url(request.substr(4));
    }
    std::string session_url(const std::string& id) const { return url("/v8/RestoreSessions/" + id); }
};

inline Run mail_x5() { return {"mail-x5", rp::connector::ItemKind::mail, "restore-mail-x5-200", "Vex"}; }
inline Run mail_x1() { return {"mail-x1", rp::connector::ItemKind::mail, "restore-mail-200", "Vex"}; }
inline Run sp_x1() { return {"sp-x1", rp::connector::ItemKind::sharepoint, "restore-sp-200", "Vesp"}; }
inline Run od_x1() { return {"od-x1", rp::connector::ItemKind::onedrive, "restore-od-200", "Veod"}; }

// The recorded items, as a sample names them.
inline std::vector<rp::connector::MailSelector> mail_x5_items()
{
    std::vector<rp::connector::MailSelector> out;
    const json items = load_fixture_json("veeam", "w24-mail-x5-items").at("body").at("results");
    for (const std::string subject : {"RP-CANARY-0002", "RP-CANARY-0003", "RP-CANARY-0004",
                                      "RP-CANARY-0005", "RP-CANARY-0006"}) {
        std::string received;
        for (const json& item : items) {
            if (item.at("subject") == subject) {
                received = item.at("received").get<std::string>().substr(0, 19) + "Z";
            }
        }
        out.push_back({kAlice, "Inbox", subject, received});
    }
    return out;
}
inline rp::connector::MailSelector mail_x1_item()
{
    return {kBob, "Inbox", "RP-CANARY-0011", "2026-09-24T22:14:46Z"};
}
inline rp::connector::SharePointSelector sp_x1_item()
{
    return {lab_values().site_id, "b!madeUpSourceLibraryDrive", "/", "rp-canary-06.pdf",
            kCanaryListId, 925};
}
inline rp::connector::OneDriveSelector od_x1_item()
{
    return {kAlice, "/RestoreTest", "rp-canary-16.pdf", 925};
}

// A spec on the recorded restore point with the given items.
inline rp::connector::RestoreSpec restore_spec(std::vector<rp::connector::MailSelector> mail = {},
                                               std::vector<rp::connector::SharePointSelector> sp = {},
                                               std::vector<rp::connector::OneDriveSelector> od = {})
{
    rp::connector::RestoreSpec spec = make_spec(std::move(mail), std::move(sp), std::move(od));
    spec.client_ref = kOrgName;
    spec.restore_point.id = kRestorePointId;
    spec.restore_point.backup_time = kBackupTime;
    return spec;
}

// Hands out sentinel strings; counts its calls. Called on the test's thread.
struct FakeExporter final : rp::CertificateExporter {
    rp::ExportedPfx export_pfx(std::string_view sha1_thumbprint) override
    {
        ++calls;
        thumbprints.emplace_back(sha1_thumbprint);
        if (fail) {
            throw rp::CertExportError(*fail);
        }
        rp::ExportedPfx out;
        out.pfx_base64 = pfx;
        out.password = kFakePfxPassword;
        return out;
    }

    std::string pfx = kFakePfx;
    int calls = 0;
    std::vector<std::string> thumbprints;
    std::optional<std::string> fail;
};

// A steady clock only the connector's waits move; each wait recorded.
struct FakeClock {
    std::chrono::steady_clock::time_point now()
    {
        const std::lock_guard lock(mutex);
        return std::chrono::steady_clock::time_point{} + elapsed;
    }
    void sleep(std::chrono::milliseconds wait)
    {
        const std::lock_guard lock(mutex);
        sleeps.push_back(wait);
        elapsed += wait;
    }
    std::vector<std::chrono::milliseconds> waits()
    {
        const std::lock_guard lock(mutex);
        return sleeps;
    }
    // How many waits of exactly `wait`.
    std::size_t count(std::chrono::milliseconds wait)
    {
        const std::lock_guard lock(mutex);
        std::size_t n = 0;
        for (const auto w : sleeps) {
            n += w == wait ? 1 : 0;
        }
        return n;
    }

    std::mutex mutex;
    std::chrono::milliseconds elapsed{0};
    std::vector<std::chrono::milliseconds> sleeps;
};

struct RestoreRig {
    explicit RestoreRig(bool with_exporter = true)
    {
        logger = string_logger("veeam_restore_test", log_stream);
        veeam.on(HttpMethod::post, url("/v8/token"), {load_fixture("veeam", "token-200")});
        veeam.on(HttpMethod::post, url("/v8/token/logout"), {load_fixture("veeam", "logout-204")});
        veeam.on(HttpMethod::get, url("/v8/Organizations?limit=1000&offset=0"),
                 {fixture("w24-mail-x5-org")});
        veeam.on(HttpMethod::get, restore_points_url(), {restore_points()});
        veeam.on(HttpMethod::get, url("/v8/RestoreSessions?limit=200"),
                 {fixture("w24-mail-x5-sweep-before")});
        veeam.on(HttpMethod::post, url("/v8/Organizations/" + kOrgId + "/explore"),
                 [this](const HttpRequest& request) { return explore_response(request); });
        if (with_exporter) {
            exporter = std::make_shared<FakeExporter>();
        }
    }

    // The connector, made on first use.
    rp::VeeamM365Connector& connector()
    {
        if (!source) {
            rp::VeeamM365ConnectorOptions options;
            options.client.logger = logger;
            options.client.now = [this] { return clock.now(); };
            options.client.sleep = [this](std::chrono::milliseconds wait) { clock.sleep(wait); };
            options.client.jitter = [] { return 0.0; };
            options.graph = lab.graph;
            options.guard = lab.options();
            options.cert_exporter = exporter;
            options.wall_now = [this] { return next_post_time(); };
            source = std::make_unique<rp::VeeamM365Connector>(
                std::make_unique<ForwardingHttpClient>(veeam), kBase, kUsername, kPassword,
                std::move(options));
        }
        return *source;
    }

    rp::connector::RestoreResult restore(const rp::connector::RestoreSpec& spec)
    {
        return connector().restore_sample(spec);
    }

    // The recorded time of the next restore POST (the last one repeats); an
    // explore POST before it reads the same time.
    std::chrono::system_clock::time_point next_post_time()
    {
        const std::size_t sent = restore_posts().size();
        const std::lock_guard lock(mutex);
        if (post_times.empty()) {
            return std::chrono::system_clock::time_point{};
        }
        return post_times[std::min(sent, post_times.size() - 1)];
    }

    HttpResponse explore_response(const HttpRequest& request)
    {
        const json body = json::parse(request.body, nullptr, false);
        const std::string type =
            body.is_object() && body.contains("type") && body["type"].is_string()
                ? body["type"].get<std::string>()
                : std::string{};
        const std::lock_guard lock(mutex);
        const auto it = explores.find(type);
        if (it == explores.end()) {
            throw std::logic_error("no explore session for type " + type);
        }
        return it->second;
    }

    // Serves the whole recorded run: its explore session, browsing, the
    // restore POST, the duplicate check, the polls, statistics and events,
    // and the explore session's close.
    void serve(const Run& run)
    {
        {
            const std::lock_guard lock(mutex);
            explores[run.type] = fixture(run.file("explore"));
            post_times.push_back(run.posted());
        }
        const std::string e = run.explore();
        const std::string c = run.container();
        const std::string session = "/v8/RestoreSessions/" + e;
        switch (run.kind) {
        case rp::connector::ItemKind::mail: {
            const std::string base = session + "/organization/mailboxes";
            get(paged(base), fixture(run.file("mailboxes")));
            get(paged(base + "/" + c + "/folders?name=Inbox"), fixture(run.file("folder-inbox")));
            const std::string folder = load_fixture_json("veeam", run.file("folder-inbox"))
                                           .at("body")
                                           .at("results")
                                           .at(0)
                                           .at("id")
                                           .get<std::string>();
            get(paged(base + "/" + c + "/items?parentId=" + encoded(folder)),
                fixture(run.file("items")));
            for (const json& item :
                 results_of(run.file("items"))) {
                get(base + "/" + c + "/items/" + encoded(item.at("id").get<std::string>()),
                    make_response(200, item.dump()));
            }
            break;
        }
        case rp::connector::ItemKind::sharepoint: {
            const std::string base = session + "/Organization/Sites/" + c;
            for (const json& site :
                 results_of(run.file("sites"))) {
                if (site.at("id") == c) {
                    get(base, make_response(200, site.dump()));
                }
            }
            get(paged(base + "/Libraries"), fixture(run.file("libraries")));
            serve_documents(run, base, c + kCanaryListId);
            break;
        }
        case rp::connector::ItemKind::onedrive: {
            const std::string base = session + "/Organization/OneDrives";
            get(paged(base), fixture(run.file("onedrives")));
            get(paged(base + "/" + c + "/Folders?parentId=root"), fixture(run.file("folders-root")));
            std::string folder;
            for (const json& entry :
                 results_of(run.file("folders-root"))) {
                if (entry.at("name") == "RestoreTest") {
                    folder = entry.at("id").get<std::string>();
                }
            }
            serve_documents(run, base + "/" + c, folder);
            break;
        }
        }
        const std::string r = run.restore();
        veeam.on(HttpMethod::post, url(run.post_path()), {load_fixture("veeam", run.restore_fixture)});
        veeam.on(HttpMethod::get, run.duplicate_url(), {fixture(run.file("sessions-after-post"))});
        veeam.on(HttpMethod::get, run.session_url(r),
                 {fixture(run.file("session-working")), fixture(run.file("session"))});
        get("/v8/RestoreSessions/" + r + "/Statistics", fixture(run.file("statistics")));
        get(paged("/v8/RestoreSessions/" + r + "/Events"), fixture(run.file("events")));
        // The finally path: the explore session is still Working, then stopped.
        get(session, make_response(200, load_fixture_json("veeam", run.file("explore"))
                                            .at("body")
                                            .dump()));
        veeam.on(HttpMethod::post, url(session + "/Stop"), {load_fixture("veeam", "stop-204")});
    }

    void serve_documents(const Run& run, const std::string& base, const std::string& parent)
    {
        get(paged(base + "/Documents?parentId=" + encoded(parent)), fixture(run.file("documents")));
        const std::string recorded =
            load_fixture_json("veeam", run.file("document")).at("body").at("id").get<std::string>();
        for (const json& document :
             results_of(run.file("documents"))) {
            const std::string id = document.at("id").get<std::string>();
            get(base + "/Documents/" + encoded(id),
                make_response(200, id == recorded ? ordered_fixture(run.file("document"))
                                                                 .at("body")
                                                                 .dump()
                                                           : document.dump()));
        }
    }

    void get(const std::string& path, const HttpResponse& response)
    {
        veeam.on(HttpMethod::get, url(path), {response});
    }

    // Every POST to a restoreTo or copyTo URL.
    std::vector<HttpRequest> restore_posts() const
    {
        std::vector<HttpRequest> out;
        for (const HttpRequest& request : veeam.requests()) {
            if (request.method == HttpMethod::post &&
                (request.url.ends_with("/restoreTo") || request.url.ends_with("/copyTo"))) {
                out.push_back(request);
            }
        }
        return out;
    }

    std::size_t posts(const std::string& path) const
    {
        return veeam.count(HttpMethod::post, url(path));
    }
    std::size_t gets(const std::string& path) const
    {
        return veeam.count(HttpMethod::get, url(path));
    }
    std::size_t stops(const std::string& explore) const
    {
        return posts("/v8/RestoreSessions/" + explore + "/Stop");
    }
    std::size_t explores_opened() const
    {
        return posts("/v8/Organizations/" + kOrgId + "/explore");
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    std::mutex mutex;
    std::map<std::string, HttpResponse> explores;
    std::deque<std::chrono::system_clock::time_point> post_times;
    FakeHttpClient veeam;
    GuardLab lab;
    FakeClock clock;
    std::shared_ptr<FakeExporter> exporter;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    std::unique_ptr<rp::VeeamM365Connector> source;
};

// What a call threw: the connector error's kind and message.
struct Caught {
    std::string kind = "none";
    std::string what;
};

inline Caught caught_by(const std::function<void()>& call)
{
    try {
        call();
    } catch (const rp::connector::SafetyViolation& e) {
        return {"SafetyViolation", e.what()};
    } catch (const rp::connector::AuthError& e) {
        return {"AuthError", e.what()};
    } catch (const rp::connector::TransientError& e) {
        return {"TransientError", e.what()};
    } catch (const rp::connector::NotFoundError& e) {
        return {"NotFoundError", e.what()};
    } catch (const rp::connector::NotImplementedError& e) {
        return {"NotImplementedError", e.what()};
    } catch (const rp::connector::Error& e) {
        return {"Error", e.what()};
    } catch (const std::invalid_argument& e) {
        return {"invalid_argument", e.what()};
    } catch (const std::exception& e) {
        return {"not a connector error", e.what()};
    }
    return {};
}

} // namespace rp::test::veeam_restore_lab
