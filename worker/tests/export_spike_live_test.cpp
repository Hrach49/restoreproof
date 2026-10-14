// W6.1 (#181): the spike on Veeam's document export in admin mode
// (docs/decisions.md 2026-10-14, W6.1). As rp-veeam, from the vault, it
// exports the lab's 14 real files (L1.8: 7 in the RestoreTest site's default
// library, 7 in alice's OneDrive root; no canary, no mail) from explore
// sessions of its own, restores the same 14 through the connector's guarded
// path (restore_sample), reads them back from the two file restore targets
// with the Worker's own TargetReader and compares: SHA-256 for pdf, txt and
// png, office-v1 on both sides for the xlsx and the docx. It also records
// what asZip gives, the time per export, that a session is still usable
// after an export, and one export beside a running restore.
//
// It WRITES to the lab tenant (the restore into the two file targets):
// skipped unless both RP_LIVE=1 and RP_LIVE_RESTORE=1. Run it by hand, from
// an elevated shell (the certificate export reads LocalMachine\My's private
// key), with the restore targets empty first. It holds the run mutex. It
// does NOT clean: the harness (docs/api/veeam-lab/w6.1-harness/w61-live.ps1)
// reads the copies back with `rpworker graph list --hash` as a second tool
// and then runs the live cleanup test. docs/testing.md, "Live restore".
//
// Environment: the Veeam and Graph variables of the other live tests
// (docs/testing.md, "Live tests"), plus
//   RP_LIVE_RESTORE=1
//   RP_LIVE_EVIDENCE_FILE   optional: where to write the table as JSON
//   RP_LIVE_RECORD_DIR      optional: a new or empty folder; the test's own
//                           Veeam exchanges are recorded there, scrubbed
//                           (under veeam/ the JSON calls, under export/ the
//                           exports as digests, never the bytes)
// No product code under worker/src, include or app is touched by this spike.

#include "live_secrets.hpp"
#include "../src/command_config.hpp"
#include "graph_live_lab.hpp"
#include "test_support.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/cert_export.hpp>
#include <rp/client_profile.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_errors.hpp>
#include <rp/graph_targets.hpp>
#include <rp/http_client.hpp>
#include <rp/office_v1.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/run_lock.hpp>
#include <rp/secrets.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <zip.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

namespace connector = rp::connector;
namespace sampling = rp::sampling;
using nlohmann::json;
using rp::test::graph_live::env_or;

const std::string kLabOrgName = "RestoreProofLab.onmicrosoft.com";
const std::string kLabCertSha256 =
    "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";

// L1.8's real files (lab/tenant.md, "Real data for the random sample").
const std::vector<std::string> kSharePointNames = {
    "team-meeting-notes.txt", "supplier-contacts.txt",  "project-brief.pdf",  "budget-summary.pdf",
    "office-floor-plan.png",  "brand-colours-draft.png", "room-bookings.xlsx"};
const std::vector<std::string> kOneDriveNames = {
    "reading-list.txt",  "travel-notes.txt",      "expense-report-march.pdf", "course-certificate.pdf",
    "holiday-photo.png", "whiteboard-sketch.png", "weekly-status.docx"};
// The one file exported with asZip and again beside the running restore.
const std::string kZipProbe = "project-brief.pdf";

constexpr std::uint64_t kMaxExportBytes = 64ull * 1024 * 1024;
constexpr std::chrono::milliseconds kExportTimeout{120000};
constexpr std::chrono::minutes kRestoreDeadline{25};

std::string ascii_lower(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

std::string bare_account(const std::string& username)
{
    const std::size_t slash = username.rfind('\\');
    return slash == std::string::npos ? username : username.substr(slash + 1);
}

// application/x-www-form-urlencoded, RFC 3986 unreserved characters kept.
std::string form_encode(std::string_view text)
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : text) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
        }
    }
    return out;
}

// "docx" or "xlsx" for a name ending in it (ASCII case-insensitive), else "".
std::string office_type(const std::string& name)
{
    const std::string lower = ascii_lower(name);
    if (lower.ends_with(".docx")) {
        return "docx";
    }
    if (lower.ends_with(".xlsx")) {
        return "xlsx";
    }
    return "";
}

std::string utc_seconds_now()
{
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    return std::format("{:%FT%T}", now);
}

// The test's own Veeam calls: one token chain, JSON calls recorded as
// content, exports as digests. Never a retry of anything that isn't a GET.
class VeeamSpike {
public:
    VeeamSpike(std::unique_ptr<rp::IHttpClient> json_http, std::unique_ptr<rp::IHttpClient> bytes_http,
               std::string base_url)
        : json_http_(std::move(json_http)), bytes_http_(std::move(bytes_http)),
          base_url_(std::move(base_url))
    {
    }
    ~VeeamSpike()
    {
        rp::secure_wipe(token_);
    }

    void login(const std::string& username, const std::string& password)
    {
        rp::HttpRequest request;
        request.method = rp::HttpMethod::post;
        request.url = base_url_ + "/v8/token";
        request.content_type = "application/x-www-form-urlencoded";
        request.body = "grant_type=password&username=" + form_encode(username) +
                       "&password=" + form_encode(password) + "&disable_antiforgery_token=true";
        request.retry_on_status = false;
        request.max_attempts = 1;
        rp::HttpResponse response = json_http_->send(request);
        rp::secure_wipe(request.body);
        if (response.status != 200) {
            throw std::runtime_error("Veeam sign-in answered " + std::to_string(response.status));
        }
        json body = json::parse(response.body);
        rp::secure_wipe(response.body);
        token_ = body.at("access_token").get<std::string>();
        body.clear();
    }

    void logout() noexcept
    {
        try {
            rp::HttpRequest request = make("POST", "/v8/token/logout");
            json_http_->send(request);
        } catch (...) {
        }
        rp::secure_wipe(token_);
    }

    // GET, as JSON. A GET may be retried by HttpClient on a transport error.
    json get(const std::string& path)
    {
        rp::HttpRequest request = make("GET", path);
        const rp::HttpResponse response = json_http_->send(request);
        if (response.status != 200) {
            throw std::runtime_error("GET " + path + " answered " + std::to_string(response.status));
        }
        return json::parse(response.body);
    }

    // Every entry of a paged list, limit 1000 per page.
    std::vector<json> get_all(const std::string& path)
    {
        std::vector<json> out;
        const char joiner = path.find('?') == std::string::npos ? '?' : '&';
        for (std::size_t offset = 0;; offset += 1000) {
            const json page = get(path + joiner + "limit=1000&offset=" + std::to_string(offset));
            const json& results = page.at("results");
            for (const json& entry : results) {
                out.push_back(entry);
            }
            if (results.size() < 1000) {
                break;
            }
        }
        return out;
    }

    // POST with a JSON body, one attempt, any status returned.
    rp::HttpResponse post_json(const std::string& path, const json& body)
    {
        rp::HttpRequest request = make("POST", path);
        request.content_type = "application/json; charset=utf-8";
        request.body = body.dump();
        return json_http_->send(request);
    }

    struct Export {
        int status = 0;
        std::string content_type;
        std::string content_length; // the header as sent, "" when none
        std::string disposition;
        std::string bytes;
        std::int64_t ms = 0;
    };

    // POST .../save {"asZip": as_zip}: one attempt, the body up to 64 MiB.
    Export export_document(const std::string& document_path, bool as_zip)
    {
        rp::HttpRequest request = make("POST", document_path + "/save");
        request.headers["Accept"] = "*/*";
        request.content_type = "application/json; charset=utf-8";
        request.body = json{{"asZip", as_zip}}.dump();
        request.timeout = kExportTimeout;
        request.max_body_bytes = kMaxExportBytes;
        const auto started = std::chrono::steady_clock::now();
        rp::HttpResponse response = bytes_http_->send(request);
        Export out;
        out.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - started)
                     .count();
        out.status = response.status;
        if (const auto it = response.headers.find("Content-Type"); it != response.headers.end()) {
            out.content_type = it->second;
        }
        if (const auto it = response.headers.find("Content-Length"); it != response.headers.end()) {
            out.content_length = it->second;
        }
        if (const auto it = response.headers.find("Content-Disposition");
            it != response.headers.end()) {
            out.disposition = it->second;
        }
        out.bytes = std::move(response.body);
        return out;
    }

    std::string open_explore(const std::string& org_id, const std::string& backup_time,
                             const std::string& type)
    {
        const rp::HttpResponse response =
            post_json("/v8/Organizations/" + org_id + "/explore",
                      json{{"dateTime", backup_time},
                           {"type", type},
                           {"showDeleted", false},
                           {"showAllVersions", false}});
        if (response.status < 200 || response.status >= 300) {
            throw std::runtime_error("explore " + type + " answered " +
                                     std::to_string(response.status));
        }
        return ascii_lower(json::parse(response.body).at("id").get<std::string>());
    }

    // Stops `id` if it is Working; never throws. Returns one line.
    std::string stop_session(const std::string& id) noexcept
    {
        try {
            const json session = get("/v8/RestoreSessions/" + id);
            if (session.value("state", "") != "Working") {
                return "session " + id + " already " + session.value("state", "?");
            }
            const rp::HttpResponse response = post_json("/v8/RestoreSessions/" + id + "/Stop", json{});
            return "stopped session " + id + " -> " + std::to_string(response.status);
        } catch (const std::exception& e) {
            return "could not stop session " + id + ": " + e.what();
        }
    }

private:
    rp::HttpRequest make(std::string_view method, const std::string& path)
    {
        rp::HttpRequest request;
        request.method = method == "POST" ? rp::HttpMethod::post : rp::HttpMethod::get;
        request.url = base_url_ + path;
        request.headers["Accept"] = "application/json";
        if (!token_.empty()) {
            request.headers["Authorization"] = "Bearer " + token_;
        }
        if (request.method == rp::HttpMethod::post) {
            request.retry_on_status = false;
            request.max_attempts = 1;
        }
        return request;
    }

    std::unique_ptr<rp::IHttpClient> json_http_;
    std::unique_ptr<rp::IHttpClient> bytes_http_;
    std::string base_url_;
    std::string token_;
};

// Stops every session it was told about, in reverse, when it goes.
class SessionStops {
public:
    explicit SessionStops(VeeamSpike& veeam) : veeam_(veeam) {}
    ~SessionStops()
    {
        stop_all();
    }
    void add(std::string id)
    {
        ids_.push_back(std::move(id));
    }
    void stop_all() noexcept
    {
        while (!ids_.empty()) {
            std::cout << veeam_.stop_session(ids_.back()) << "\n";
            ids_.pop_back();
        }
    }

private:
    VeeamSpike& veeam_;
    std::vector<std::string> ids_;
};

// One file's row of the table.
struct Row {
    std::string kind; // "sharepoint" or "onedrive"
    std::string name;
    std::string office; // "docx", "xlsx" or ""
    std::int64_t veeam_size = -1;
    std::string document_path; // the Veeam path the export was POSTed to
    int export_status = 0;
    std::string export_content_type;
    std::string export_content_length;
    std::uint64_t export_bytes = 0;
    std::string export_sha256;
    std::string export_office_v1;
    std::string export_office_error;
    std::int64_t export_ms = 0;
    std::optional<std::uint64_t> restored_size;
    std::string restored_sha256;
    std::string restored_office_v1;
    std::string restored_office_error;
    bool found = false;
    bool bytes_equal = false;
    bool content_equal = false; // the verdict: SHA-256, or office-v1 for an Office file
};

json to_json(const Row& r)
{
    return {{"kind", r.kind},
            {"name", r.name},
            {"office", r.office},
            {"veeam_size", r.veeam_size},
            {"document_path", r.document_path},
            {"export",
             {{"status", r.export_status},
              {"content_type", r.export_content_type},
              {"content_length", r.export_content_length},
              {"bytes", r.export_bytes},
              {"sha256", r.export_sha256},
              {"office_v1", r.export_office_v1},
              {"office_v1_error", r.export_office_error},
              {"ms", r.export_ms}}},
            {"restored",
             {{"found", r.found},
              {"size", r.restored_size ? json(*r.restored_size) : json(nullptr)},
              {"sha256", r.restored_sha256},
              {"office_v1", r.restored_office_v1},
              {"office_v1_error", r.restored_office_error}}},
            {"bytes_equal", r.bytes_equal},
            {"content_equal", r.content_equal}};
}

// The documents of a listing named exactly `name` and not folders.
std::vector<json> named(const std::vector<json>& documents, const std::string& name)
{
    std::vector<json> out;
    for (const json& d : documents) {
        if (d.value("isFolder", false)) {
            continue;
        }
        if (d.contains("name") && d["name"].is_string() && d["name"].get<std::string>() == name) {
            out.push_back(d);
        }
    }
    return out;
}

std::string office_hash(const std::string& bytes, const std::string& type, std::string& error)
{
    try {
        return rp::office_v1_sha256(bytes, type);
    } catch (const std::exception& e) {
        error = e.what();
        return "";
    }
}

// What a ZIP body holds: the entry count and the first entry's bytes.
struct ZipLook {
    bool is_zip = false;
    std::int64_t entries = 0;
    std::string first_name;
    std::string first_bytes;
    std::string error;
};

ZipLook look_into_zip(const std::string& bytes)
{
    ZipLook out;
    out.is_zip = bytes.size() >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 3 &&
                 bytes[3] == 4;
    if (!out.is_zip) {
        return out;
    }
    zip_error_t error;
    zip_error_init(&error);
    zip_source_t* source = zip_source_buffer_create(bytes.data(), bytes.size(), 0, &error);
    if (source == nullptr) {
        out.error = zip_error_strerror(&error);
        zip_error_fini(&error);
        return out;
    }
    zip_t* archive = zip_open_from_source(source, ZIP_RDONLY, &error);
    if (archive == nullptr) {
        out.error = zip_error_strerror(&error);
        zip_source_free(source);
        zip_error_fini(&error);
        return out;
    }
    out.entries = zip_get_num_entries(archive, 0);
    if (out.entries > 0) {
        zip_stat_t stat;
        zip_stat_init(&stat);
        if (zip_stat_index(archive, 0, 0, &stat) == 0 && (stat.valid & ZIP_STAT_SIZE) != 0 &&
            stat.size <= kMaxExportBytes) {
            out.first_name = stat.name != nullptr ? stat.name : "";
            if (zip_file_t* file = zip_fopen_index(archive, 0, 0); file != nullptr) {
                out.first_bytes.resize(static_cast<std::size_t>(stat.size));
                const zip_int64_t read =
                    zip_fread(file, out.first_bytes.data(), out.first_bytes.size());
                if (read < 0 || static_cast<zip_uint64_t>(read) != stat.size) {
                    out.error = "short read of the first entry";
                    out.first_bytes.clear();
                }
                zip_fclose(file);
            }
        }
    }
    zip_close(archive);
    zip_error_fini(&error);
    return out;
}

// The default library's root through the Worker app, as a sorted list of
// (id, name, size, eTag, lastModifiedDateTime); the drive is the site's
// default drive (GET /sites/{id}/drive). A refusal is recorded, never worked
// around.
json library_snapshot(rp::graph::GraphClient& graph, const std::string& site_id)
{
    try {
        const json drive = graph.get_json("/sites/" + site_id + "/drive?$select=id,name,webUrl",
                                          rp::graph::kSitesReadGrant);
        const std::string drive_id = drive.at("id").get<std::string>();
        json rows = json::array();
        std::string url = "/drives/" + drive_id +
                          "/root/children?$select=id,name,size,eTag,lastModifiedDateTime&$top=200";
        for (int page = 0; page < 20; ++page) {
            const json listing = graph.get_json(url, rp::graph::kSitesReadGrant);
            for (const json& item : listing.at("value")) {
                rows.push_back({{"id", item.value("id", "")},
                                {"name", item.value("name", "")},
                                {"size", item.value("size", 0)},
                                {"eTag", item.value("eTag", "")},
                                {"lastModifiedDateTime", item.value("lastModifiedDateTime", "")}});
            }
            if (!listing.contains("@odata.nextLink")) {
                break;
            }
            url = listing["@odata.nextLink"].get<std::string>();
        }
        std::vector<json> sorted(rows.begin(), rows.end());
        std::ranges::sort(sorted, [](const json& a, const json& b) {
            return a["id"].get<std::string>() < b["id"].get<std::string>();
        });
        return {{"drive_id", drive_id}, {"drive_name", drive.value("name", "")}, {"items", sorted}};
    } catch (const std::exception& e) {
        return {{"not_read", std::string{e.what()}}};
    }
}

// alice's OneDrive root folder's metadata through the Worker app (what the
// app may read there: the folder's own facet, no listing).
json onedrive_root_snapshot(rp::graph::GraphClient& graph, const std::string& drive_id)
{
    try {
        const json root = graph.get_json(
            "/drives/" + drive_id + "/root?$select=id,eTag,lastModifiedDateTime,folder,size",
            rp::graph::kOneDriveGrant);
        return {{"id", root.value("id", "")},
                {"eTag", root.value("eTag", "")},
                {"lastModifiedDateTime", root.value("lastModifiedDateTime", "")},
                {"size", root.value("size", 0)},
                {"childCount", root.contains("folder") ? root["folder"].value("childCount", -1) : -1}};
    } catch (const std::exception& e) {
        return {{"not_read", std::string{e.what()}}};
    }
}

// Veeam's site ID from a Graph site ID "<host>,<site GUID>,<web GUID>".
std::string veeam_site_id(const std::string& graph_site_id)
{
    const std::size_t first = graph_site_id.find(',');
    const std::size_t second = graph_site_id.find(',', first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        return "";
    }
    return ascii_lower(graph_site_id.substr(first + 1, second - first - 1) +
                       graph_site_id.substr(second + 1));
}

std::string host_of(const std::string& graph_site_id)
{
    return ascii_lower(graph_site_id.substr(0, graph_site_id.find(',')));
}

// "https://<tenant>-my.sharepoint.com/personal/<user with @ and . as _>", lower case.
std::string onedrive_url(const std::string& host, const std::string& user)
{
    const std::string tenant = host.substr(0, host.find('.'));
    std::string personal = ascii_lower(user);
    for (char& c : personal) {
        if (c == '@' || c == '.') {
            c = '_';
        }
    }
    return "https://" + tenant + "-my.sharepoint.com/personal/" + personal;
}

std::string yes_no(bool b)
{
    return b ? "yes" : "no";
}

} // namespace

TEST_CASE("live export spike: Veeam's document export in admin mode against the restored copy",
          "[live][writes]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"} ||
        rp::test::get_env("RP_LIVE_RESTORE") != std::optional<std::string>{"1"}) {
        SKIP("writes to the lab tenant: set both RP_LIVE=1 and RP_LIVE_RESTORE=1 to run");
    }
    const std::optional<std::string> ca_file = rp::test::get_env("RP_LIVE_VEEAM_CA_FILE");
    REQUIRE(ca_file);
    const std::unique_ptr<rp::RunLock> lock = rp::try_take_restore_targets_lock();
    REQUIRE(lock != nullptr); // another RestoreProof run is using the restore targets
    rp::Config config = rp::test::graph_live::live_config();
    config.veeam_url = env_or("RP_LIVE_VEEAM_URL", "https://localhost:4443");
    config.veeam_ca_file = ca_file;
    config.veeam_cert_sha256 = env_or("RP_LIVE_VEEAM_CERT_SHA256", kLabCertSha256);
    config.veeam_org_name = kLabOrgName;
    const rp::Secrets secrets = rp::test::live_secrets();
    REQUIRE(secrets.veeam_username);
    REQUIRE(secrets.veeam_password);
    const std::string account = ascii_lower(bare_account(*secrets.veeam_username));
    const std::string started_at = utc_seconds_now();
    std::cout << "W6.1 export spike started " << started_at << "Z as " << account << "\n";

    auto logger = std::make_shared<spdlog::logger>(
        "live_export", std::make_shared<spdlog::sinks::ostream_sink_mt>(std::cout));
    logger->set_level(spdlog::level::info);

    // The recording folder is opened first: one that isn't new or empty
    // throws here, before anything was sent.
    const std::optional<std::string> record_dir = rp::test::get_env("RP_LIVE_RECORD_DIR");
    const std::shared_ptr<rp::FixtureRecorder> recorder =
        record_dir && !record_dir->empty()
            ? rp::open_recording(*record_dir, "w6.1 export spike", secrets)
            : nullptr;

    // 1. The connector, the restore point, the 14 real files through the
    //    sampler's own listing (canary locations and names left out by rule).
    connector::ConnectorOptions options;
    options.logger = logger;
    options.cert_exporter = rp::make_local_machine_cert_exporter();
    options.client = rp::local_profile(config);
    REQUIRE(options.client.has_value());
    const std::unique_ptr<connector::IConnector> made = connector::default_connector_registry()
        .create(connector::kVeeamM365, config, secrets, options);
    connector::IConnector& source = *made;

    const std::vector<connector::RestorePoint> points = source.list_restore_points(kLabOrgName);
    REQUIRE_FALSE(points.empty());
    const connector::RestorePoint& newest = points.front();
    std::cout << "restore point " << newest.backup_time << " " << newest.id << "\n";

    const connector::RestoreTargets targets = connector::RestoreTargets::from_config(config);
    const sampling::CanaryManifest manifest = sampling::load_canary_manifest(
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json");
    connector::CandidateQuery query{.client_ref = kLabOrgName,
                                    .restore_point = newest,
                                    .targets = targets,
                                    .mail = false,
                                    .sharepoint = true,
                                    .onedrive = true,
                                    .seed = 0x5761,
                                    .exclude = {},
                                    .limits = {}};
    {
        std::vector<std::string> list_ids;
        std::vector<std::string> folders;
        for (const sampling::CanaryMail& mail : manifest.mail) {
            query.exclude.subjects.push_back(mail.subject);
        }
        for (const sampling::CanaryFile& file : manifest.sharepoint) {
            list_ids.push_back(ascii_lower(file.list_id));
            query.exclude.sharepoint_names.push_back(file.name);
        }
        for (const sampling::CanaryFile& file : manifest.onedrive) {
            query.exclude.onedrive_names.push_back(file.name);
            std::string_view path = file.folder_path;
            while (path.starts_with('/')) {
                path.remove_prefix(1);
            }
            const std::string_view first = path.substr(0, path.find('/'));
            if (!first.empty()) {
                folders.emplace_back(first);
            }
        }
        std::ranges::sort(list_ids);
        list_ids.erase(std::unique(list_ids.begin(), list_ids.end()), list_ids.end());
        std::ranges::sort(folders);
        folders.erase(std::unique(folders.begin(), folders.end()), folders.end());
        query.exclude.list_ids = list_ids;
        query.exclude.onedrive_folders = folders;
    }
    // Every container and every root folder: the spike wants the whole pool.
    query.limits.containers_wanted = 16;
    query.limits.containers_tried = 16;
    query.limits.folders_per_container = 8;
    const connector::CandidatePool pool = source.list_candidates(query);
    std::cout << "candidates: " << pool.sharepoint.size() << " sharepoint, " << pool.onedrive.size()
              << " onedrive (containers listed " << pool.sharepoint_browse.containers_listed.size()
              << " and " << pool.onedrive_browse.containers_listed.size() << ")\n";

    std::vector<connector::SharePointSelector> sp_selectors;
    std::vector<connector::OneDriveSelector> od_selectors;
    std::vector<Row> rows;
    for (const std::string& name : kSharePointNames) {
        std::vector<const connector::SharePointCandidate*> hits;
        for (const connector::SharePointCandidate& c : pool.sharepoint) {
            if (c.selector.name == name) {
                hits.push_back(&c);
            }
        }
        CAPTURE(name);
        REQUIRE(hits.size() == 1);
        sp_selectors.push_back(hits.front()->selector);
        Row row;
        row.kind = "sharepoint";
        row.name = name;
        row.office = office_type(name);
        row.veeam_size = hits.front()->size_bytes;
        rows.push_back(row);
    }
    for (const std::string& name : kOneDriveNames) {
        std::vector<const connector::OneDriveCandidate*> hits;
        for (const connector::OneDriveCandidate& c : pool.onedrive) {
            if (c.selector.name == name) {
                hits.push_back(&c);
            }
        }
        CAPTURE(name);
        REQUIRE(hits.size() == 1);
        od_selectors.push_back(hits.front()->selector);
        Row row;
        row.kind = "onedrive";
        row.name = name;
        row.office = office_type(name);
        row.veeam_size = hits.front()->size_bytes;
        rows.push_back(row);
    }
    for (const connector::SharePointSelector& s : sp_selectors) {
        std::cout << "sharepoint candidate " << s.folder_path << " " << s.name << " (list "
                  << s.list_id << ")\n";
    }
    for (const connector::OneDriveSelector& s : od_selectors) {
        std::cout << "onedrive candidate " << s.user << " " << s.folder_path << " " << s.name << "\n";
    }
    const std::string sp_site_id = sp_selectors.front().site_id;
    const std::string od_user = od_selectors.front().user;
    const std::string host = host_of(config.test_site_id);

    // 2. Graph, as the Worker app: the targets empty, and the source
    //    locations' snapshot before any export.
    const std::unique_ptr<rp::IHttpClient> graph_http = rp::graph::make_graph_http_client(logger);
    rp::graph::GraphClientOptions graph_options;
    graph_options.logger = logger;
    rp::graph::GraphClient graph(
        *graph_http, config.graph_tenant_id, config.graph_client_id,
        rp::graph::certificate_from_secrets(secrets, std::chrono::system_clock::now(), logger),
        graph_options);
    const std::unique_ptr<rp::IHttpClient> download = rp::graph::make_download_http_client();
    {
        rp::graph::TargetReaderOptions reader_options;
        reader_options.logger = logger;
        reader_options.hash_items = false;
        rp::graph::TargetReader before(graph, *download, targets, reader_options);
        const std::size_t sp = before.list_sharepoint().size();
        const std::size_t od = before.list_onedrive().size();
        std::cout << "targets before: " << sp << " sharepoint, " << od << " onedrive\n";
        REQUIRE(sp == 0);
        REQUIRE(od == 0);
    }
    const json library_before = library_snapshot(graph, config.test_site_id);
    const json onedrive_before = onedrive_root_snapshot(graph, config.test_onedrive_drive_id);
    std::cout << "source library before: "
              << (library_before.contains("items") ? std::to_string(library_before["items"].size()) + " items"
                                                   : library_before.dump())
              << "\n";
    std::cout << "source onedrive root before: " << onedrive_before.dump() << "\n";

    // 3. The test's own Veeam client: sign in, the organisation.
    rp::HttpClientOptions veeam_options;
    veeam_options.ca_file = config.veeam_ca_file;
    veeam_options.pinned_cert_sha256 = config.veeam_cert_sha256;
    veeam_options.logger = logger;
    VeeamSpike veeam(rp::recorded(std::make_unique<rp::HttpClient>(veeam_options), recorder, "veeam"),
                     rp::recorded(std::make_unique<rp::HttpClient>(veeam_options), recorder, "export",
                                  rp::RecordedBody::digest),
                     config.veeam_url);
    veeam.login(*secrets.veeam_username, *secrets.veeam_password);
    struct LogoutAtEnd {
        VeeamSpike& v;
        ~LogoutAtEnd()
        {
            v.logout();
        }
    } logout_at_end{veeam};
    std::string org_id;
    for (const json& org : veeam.get_all("/v8/Organizations")) {
        if (org.value("name", "") == kLabOrgName) {
            org_id = org.at("id").get<std::string>();
        }
    }
    REQUIRE_FALSE(org_id.empty());

    json notes = json::object();
    SessionStops stops(veeam);

    // 4. Session A (Vesp): the 7 SharePoint files exported.
    const std::string session_a = veeam.open_explore(org_id, newest.backup_time, "Vesp");
    stops.add(session_a);
    std::cout << "session A (Vesp) " << session_a << "\n";
    const std::string veeam_site = veeam_site_id(sp_site_id);
    std::string site_path;
    {
        const std::vector<json> sites =
            veeam.get_all("/v8/RestoreSessions/" + session_a + "/Organization/Sites?parentId=root");
        for (const json& site : sites) {
            if (ascii_lower(site.value("id", "")) == veeam_site) {
                site_path = "/v8/RestoreSessions/" + session_a + "/Organization/Sites/" +
                            site.at("id").get<std::string>();
            }
        }
        std::cout << "sites listed: " << sites.size() << "; RestoreTest site "
                  << (site_path.empty() ? "not found" : "found") << "\n";
    }
    REQUIRE_FALSE(site_path.empty());
    const std::vector<json> sp_documents = veeam.get_all(site_path + "/Documents");
    std::cout << "site documents listed: " << sp_documents.size() << "\n";

    const auto do_export = [&](Row& row, const std::string& document_path) {
        row.document_path = document_path;
        VeeamSpike::Export e = veeam.export_document(document_path, false);
        row.export_status = e.status;
        row.export_content_type = e.content_type;
        row.export_content_length = e.content_length;
        row.export_bytes = e.bytes.size();
        row.export_ms = e.ms;
        if (e.status == 200) {
            row.export_sha256 = rp::sha256_hex(e.bytes);
            if (!row.office.empty()) {
                row.export_office_v1 = office_hash(e.bytes, row.office, row.export_office_error);
            }
        }
        std::cout << "export " << row.kind << " " << row.name << ": " << e.status << " "
                  << e.content_type << " len " << e.content_length << " got " << e.bytes.size()
                  << " B (veeam size " << row.veeam_size << ") in " << e.ms << " ms sha256 "
                  << row.export_sha256
                  << (row.office.empty() ? "" : " office-v1 " + row.export_office_v1 + row.export_office_error)
                  << "\n";
        return e;
    };

    std::string zip_probe_path;
    std::string zip_probe_sha256;
    for (Row& row : rows) {
        if (row.kind != "sharepoint") {
            continue;
        }
        const std::vector<json> hits = named(sp_documents, row.name);
        CAPTURE(row.name);
        REQUIRE(hits.size() == 1);
        const std::string path = site_path + "/Documents/" + hits.front().at("id").get<std::string>();
        do_export(row, path);
        if (row.name == kZipProbe) {
            zip_probe_path = path;
            zip_probe_sha256 = row.export_sha256;
        }
    }

    // asZip once, on the pdf.
    REQUIRE_FALSE(zip_probe_path.empty());
    {
        const VeeamSpike::Export z = veeam.export_document(zip_probe_path, true);
        const ZipLook look = look_into_zip(z.bytes);
        notes["as_zip"] = {{"file", kZipProbe},
                           {"status", z.status},
                           {"content_type", z.content_type},
                           {"content_length", z.content_length},
                           {"content_disposition", z.disposition},
                           {"bytes", z.bytes.size()},
                           {"ms", z.ms},
                           {"is_zip", look.is_zip},
                           {"entries", look.entries},
                           {"first_entry_name", look.first_name},
                           {"first_entry_bytes", look.first_bytes.size()},
                           {"first_entry_sha256",
                            look.first_bytes.empty() ? "" : rp::sha256_hex(look.first_bytes)},
                           {"first_entry_equals_plain_export",
                            !look.first_bytes.empty() &&
                                rp::sha256_hex(look.first_bytes) == zip_probe_sha256},
                           {"error", look.error}};
        std::cout << "asZip " << kZipProbe << ": " << notes["as_zip"].dump() << "\n";
    }
    // The session after the exports: still Working and browsable.
    {
        const json again = veeam.get(rows.front().document_path);
        const json session = veeam.get("/v8/RestoreSessions/" + session_a);
        notes["session_after_exports"] = {{"session", session_a},
                                          {"state", session.value("state", "")},
                                          {"document_reread_name", again.value("name", "")}};
        std::cout << "session A after exports: " << notes["session_after_exports"].dump() << "\n";
        CHECK(session.value("state", "") == "Working");
    }

    // 5. Session B (Veod): the 7 OneDrive files exported.
    const std::string session_b = veeam.open_explore(org_id, newest.backup_time, "Veod");
    stops.add(session_b);
    std::cout << "session B (Veod) " << session_b << "\n";
    std::string onedrive_path;
    {
        const std::string wanted = onedrive_url(host, od_user);
        const std::vector<json> onedrives =
            veeam.get_all("/v8/RestoreSessions/" + session_b + "/Organization/OneDrives");
        for (const json& d : onedrives) {
            if (ascii_lower(d.value("url", "")) == wanted) {
                onedrive_path = "/v8/RestoreSessions/" + session_b + "/Organization/OneDrives/" +
                                d.at("id").get<std::string>();
            }
        }
        std::cout << "onedrives listed: " << onedrives.size() << "; alice's "
                  << (onedrive_path.empty() ? "not found" : "found") << "\n";
    }
    REQUIRE_FALSE(onedrive_path.empty());
    const std::vector<json> od_documents = veeam.get_all(onedrive_path + "/Documents");
    std::cout << "onedrive documents listed: " << od_documents.size() << "\n";
    for (Row& row : rows) {
        if (row.kind != "onedrive") {
            continue;
        }
        const std::vector<json> hits = named(od_documents, row.name);
        CAPTURE(row.name);
        REQUIRE(hits.size() == 1);
        do_export(row, onedrive_path + "/Documents/" + hits.front().at("id").get<std::string>());
    }

    // A and B stopped before the restore: the connector's preflight refuses
    // to start while a session of the account is Working.
    stops.stop_all();

    // The source locations after the exports: unchanged.
    const json library_after = library_snapshot(graph, config.test_site_id);
    const json onedrive_after = onedrive_root_snapshot(graph, config.test_onedrive_drive_id);
    notes["source_unchanged"] = {{"library_equal", library_before == library_after},
                                 {"onedrive_root_equal", onedrive_before == onedrive_after},
                                 {"library_before", library_before},
                                 {"library_after", library_after},
                                 {"onedrive_root_before", onedrive_before},
                                 {"onedrive_root_after", onedrive_after}};
    std::cout << "source library unchanged by the exports: " << yes_no(library_before == library_after)
              << "; onedrive root unchanged: " << yes_no(onedrive_before == onedrive_after) << "\n";
    CHECK(library_before == library_after);
    CHECK(onedrive_before == onedrive_after);

    // 6. The restore through the guarded path, on a thread; one export beside it.
    const connector::RestoreSpec spec{.client_ref = kLabOrgName,
                                      .restore_point = newest,
                                      .targets = targets,
                                      .mail = {},
                                      .sharepoint = sp_selectors,
                                      .onedrive = od_selectors};
    REQUIRE(spec.item_count() == 14);
    std::optional<connector::RestoreResult> restored;
    std::exception_ptr restore_error;
    std::atomic<bool> restore_done{false};
    const std::string restore_started = utc_seconds_now();
    const auto restore_began = std::chrono::steady_clock::now();
    std::thread restore_thread([&] {
        try {
            restored = source.restore_sample(spec);
        } catch (...) {
            restore_error = std::current_exception();
        }
        restore_done = true;
    });

    json overlap = {{"seen", false}};
    try {
        while (!restore_done &&
               std::chrono::steady_clock::now() - restore_began < kRestoreDeadline) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            std::size_t working_vesp = 0;
            json seen = json::array();
            // The page is kept in a local: a range-for over a temporary's
            // member dangles (the temporary goes before the loop).
            const json page = veeam.get("/v8/RestoreSessions?limit=50");
            for (const json& s : page.at("results")) {
                const bool ours = ascii_lower(s.value("initiatedBy", "")) == account;
                const bool working = s.value("state", "") == "Working";
                const bool vesp = s.value("type", "") == "Vesp";
                const bool recent = s.value("creationTime", "").substr(0, 19) >= restore_started;
                if (ours && working && vesp && recent) {
                    ++working_vesp;
                    seen.push_back({{"id", s.value("id", "")},
                                    {"creationTime", s.value("creationTime", "")}});
                }
            }
            // Two Working Vesp sessions of ours: the connector's explore
            // session and the restore it started (the list can't tell the
            // two apart; a restore POST made the second).
            if (working_vesp >= 2) {
                const std::string session_c = veeam.open_explore(org_id, newest.backup_time, "Vesp");
                stops.add(session_c);
                // zip_probe_path is "/v8/RestoreSessions/<A>/Organization/..."; the
                // same document under C (document IDs don't depend on the session).
                const std::string under_c =
                    "/v8/RestoreSessions/" + session_c +
                    zip_probe_path.substr(std::string("/v8/RestoreSessions/").size() + session_a.size());
                const VeeamSpike::Export e = veeam.export_document(under_c, false);
                overlap = {{"seen", true},
                           {"working_vesp_sessions", seen},
                           {"session_c", session_c},
                           {"file", kZipProbe},
                           {"status", e.status},
                           {"bytes", e.bytes.size()},
                           {"ms", e.ms},
                           {"sha256", e.status == 200 ? rp::sha256_hex(e.bytes) : ""},
                           {"equals_first_export",
                            e.status == 200 && rp::sha256_hex(e.bytes) == zip_probe_sha256}};
                std::cout << "export beside the running restore: " << overlap.dump() << "\n";
                stops.stop_all();
                break;
            }
        }
    } catch (const std::exception& e) {
        overlap["error"] = e.what();
        std::cout << "overlap check stopped: " << e.what() << "\n";
    }
    if (restore_thread.joinable()) {
        restore_thread.join();
    }
    notes["export_during_restore"] = overlap;
    if (restore_error) {
        try {
            std::rethrow_exception(restore_error);
        } catch (const std::exception& e) {
            FAIL("restore_sample threw: " << e.what());
        }
    }
    REQUIRE(restored.has_value());
    const connector::RestoreResult& result = *restored;
    std::cout << "restore status " << connector::to_string(result.status) << ": "
              << result.items_restored << " of " << result.items_sent << " item(s) restored\n";
    json sessions = json::array();
    for (const connector::RestoreSessionResult& s : result.sessions) {
        std::cout << "restore session " << s.id << " (" << connector::to_string(s.kind) << ") "
                  << s.started_at << " .. " << s.ended_at << ": " << s.result << ", " << s.details
                  << " (" << s.items_restored << " of " << s.items_sent << ")\n";
        sessions.push_back({{"id", s.id},
                            {"kind", connector::to_string(s.kind)},
                            {"result", s.result},
                            {"details", s.details},
                            {"started_at", s.started_at},
                            {"ended_at", s.ended_at},
                            {"items_sent", s.items_sent},
                            {"items_restored", s.items_restored}});
    }
    json items = json::array();
    for (const connector::ItemRestoreResult& item : result.items) {
        std::cout << "restore item " << connector::to_string(item.kind) << " " << item.name << ": "
                  << connector::to_string(item.outcome)
                  << (item.message.empty() ? "" : " (" + item.message + ")") << "\n";
        items.push_back({{"kind", connector::to_string(item.kind)},
                         {"name", item.name},
                         {"session_id", item.session_id},
                         {"outcome", connector::to_string(item.outcome)},
                         {"message", item.message}});
    }
    notes["restore"] = {{"status", connector::to_string(result.status)},
                        {"items_sent", result.items_sent},
                        {"items_restored", result.items_restored},
                        {"sessions", sessions},
                        {"items", items}};

    // 7. The read-back with the Worker's own reader, and the comparison.
    std::map<std::string, std::pair<std::string, std::string>> office_read; // name -> (hash, error)
    rp::graph::TargetReaderOptions reader_options;
    reader_options.logger = logger;
    reader_options.hash_items = true;
    reader_options.download.logger = logger;
    reader_options.on_file = [&](const rp::graph::FoundItem& item, std::string_view bytes) {
        const std::string name = item.name.value_or("");
        const std::string type = office_type(name);
        if (!type.empty()) {
            std::string error;
            const std::string hash = office_hash(std::string{bytes}, type, error);
            office_read[name] = {hash, error};
        }
    };
    rp::graph::TargetReader after(graph, *download, targets, reader_options);
    const std::vector<rp::graph::FoundItem> sp_found = after.list_sharepoint();
    const std::vector<rp::graph::FoundItem> od_found = after.list_onedrive();
    std::cout << "targets after the restore: " << sp_found.size() << " sharepoint, " << od_found.size()
              << " onedrive\n";
    const auto compare = [&](Row& row, const std::vector<rp::graph::FoundItem>& found) {
        for (const rp::graph::FoundItem& item : found) {
            if (item.name.value_or("") != row.name) {
                continue;
            }
            row.found = true;
            row.restored_size = item.size_bytes;
            row.restored_sha256 = item.sha256;
            if (!row.office.empty()) {
                const auto it = office_read.find(row.name);
                if (it != office_read.end()) {
                    row.restored_office_v1 = it->second.first;
                    row.restored_office_error = it->second.second;
                }
            }
        }
        row.bytes_equal = row.found && !row.export_sha256.empty() &&
                          row.export_sha256 == row.restored_sha256;
        row.content_equal = row.office.empty()
                                ? row.bytes_equal
                                : (row.found && !row.export_office_v1.empty() &&
                                   row.export_office_v1 == row.restored_office_v1);
    };
    for (Row& row : rows) {
        compare(row, row.kind == "sharepoint" ? sp_found : od_found);
    }

    // 8. The table, the evidence file, the checks.
    std::cout << "\nKIND        NAME                      OFFICE  VEEAM_SIZE  EXPORT  MS     EXPORT_BYTES  RESTORED_BYTES  BYTES_EQUAL  CONTENT_EQUAL\n";
    std::size_t exports_ok = 0;
    std::size_t content_ok = 0;
    for (const Row& row : rows) {
        const bool export_ok = row.export_status == 200 &&
                               ascii_lower(row.export_content_type).starts_with("application/octet-stream") &&
                               row.export_content_length == std::to_string(row.export_bytes) &&
                               row.veeam_size == static_cast<std::int64_t>(row.export_bytes);
        exports_ok += export_ok ? 1 : 0;
        content_ok += row.content_equal ? 1 : 0;
        std::cout << std::format("{:<11} {:<25} {:<7} {:<11} {:<7} {:<6} {:<13} {:<15} {:<12} {}\n",
                                 row.kind, row.name, row.office.empty() ? "-" : row.office,
                                 row.veeam_size, row.export_status, row.export_ms, row.export_bytes,
                                 row.restored_size ? std::to_string(*row.restored_size) : "-",
                                 yes_no(row.bytes_equal), yes_no(row.content_equal));
    }
    std::cout << "\nexports with the listed size as octet-stream: " << exports_ok << " of " << rows.size()
              << "; content equal to the restored copy: " << content_ok << " of " << rows.size() << "\n";
    for (const Row& row : rows) {
        std::cout << "hash " << row.kind << " " << row.name << ": export " << row.export_sha256
                  << " restored " << row.restored_sha256;
        if (!row.office.empty()) {
            std::cout << " office-v1 export " << row.export_office_v1 << " restored "
                      << row.restored_office_v1;
        }
        std::cout << "\n";
    }

    if (const std::optional<std::string> evidence = rp::test::get_env("RP_LIVE_EVIDENCE_FILE");
        evidence && !evidence->empty()) {
        json table = json::array();
        for (const Row& row : rows) {
            table.push_back(to_json(row));
        }
        const json out = {{"spike", "W6.1"},
                          {"started_at", started_at + "Z"},
                          {"account", account},
                          {"restore_point", {{"id", newest.id}, {"backup_time", newest.backup_time}}},
                          {"sessions", {{"a_vesp", session_a}, {"b_veod", session_b}}},
                          {"files", table},
                          {"exports_ok", exports_ok},
                          {"content_equal", content_ok},
                          {"notes", notes}};
        std::ofstream file(std::filesystem::path{std::u8string(evidence->begin(), evidence->end())},
                           std::ios::binary);
        REQUIRE(file);
        file << out.dump(2) << "\n";
        std::cout << "evidence written to " << *evidence << "\n";
    }

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.items_restored == 14);
    for (const Row& row : rows) {
        CAPTURE(row.kind, row.name);
        CHECK(row.export_status == 200);
        CHECK(ascii_lower(row.export_content_type).starts_with("application/octet-stream"));
        CHECK(row.export_content_length == std::to_string(row.export_bytes));
        CHECK(row.veeam_size == static_cast<std::int64_t>(row.export_bytes));
        CHECK(row.found);
        CHECK(row.content_equal);
    }
}
