// W2.2: reading the three restore targets through Graph (rp/graph_targets.hpp).
// Graph is served by one FakeHttpClient, SharePoint's download host by
// another. Every lab value (the drive, folder and site IDs, the mailbox) is
// read from the fixtures, so a re-recording in another tenant still works; the
// guard's refusals are edits of the recorded drive and folder replies, never
// the canaries' own IDs, which appear nowhere in the Worker.

#include "fake_http_client.hpp"
#include "test_certs.hpp"

#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_errors.hpp>
#include <rp/graph_targets.hpp>
#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace std::chrono_literals;
using Catch::Matchers::ContainsSubstring;

namespace {

using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::graph::FoundItem;
using rp::graph::GraphClient;
using rp::graph::GraphClientOptions;
using rp::graph::ItemType;
using rp::graph::TargetReader;
using rp::graph::TargetReaderOptions;
using rp::test::FakeHttpClient;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using rp::test::to_response;
using Clock = std::chrono::system_clock;

const std::string kTenant = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";
const std::string kClient = "737da5ef-baf2-4198-b009-e160d8ca77c9";
const std::string kTokenUrl =
    "https://login.microsoftonline.com/" + kTenant + "/oauth2/v2.0/token";
const std::string kGraph = "https://graph.microsoft.com/v1.0";

const Clock::time_point kNow = std::chrono::sys_days{std::chrono::year{2026} / 9 / 28} + 12h;
constexpr const char* kPfxPassword = "Sentinel-Targets-PFX-Password-3b9d";
// Made up, never a lab value.
const std::string kMadeUpGuid = "0a1b2c3d-0000-4000-8000-00000000abcd";

const std::string kMailSelect = "?$select=id,subject,from,receivedDateTime,internetMessageId";
const std::string kChildrenQuery = "/children?$select=id,name,size,file,folder&$top=200";

const std::string& pfx_base64()
{
    static const std::string pfx = rp::test::to_base64(rp::test::make_pfx(
        rp::test::make_client_cert("RestoreProof Worker",
                                   rp::test::ClientCertOptions{.now = Clock::to_time_t(kNow)}),
        kPfxPassword));
    return pfx;
}

HttpResponse token_response()
{
    json fixture = load_fixture_json("graph", "token-200");
    fixture["body"]["access_token"] = "token-1";
    return to_response(fixture);
}

// "https://<host>/..." -> host
std::string host_of(const std::string& url)
{
    const std::size_t start = url.find("://") + 3;
    return url.substr(start, url.find('/', start) - start);
}

// The lab's restore targets, as the recorded replies show them.
struct Lab_values {
    std::string mailbox;
    std::string site_id;
    std::string library_id;
    std::string onedrive_drive_id;
    std::string folder_id;
};

const Lab_values& lab_values()
{
    static const Lab_values values = [] {
        Lab_values out;
        const json drive = load_fixture_json("graph", "restoretarget-drive-200").at("body");
        out.site_id = host_of(drive.at("webUrl").get<std::string>()) + "," +
                      drive.at("sharePointIds").at("siteId").get<std::string>() + "," +
                      drive.at("sharePointIds").at("webId").get<std::string>();
        out.library_id = drive.at("id").get<std::string>();
        const json folder = load_fixture_json("graph", "onedrive-folder-200").at("body");
        out.onedrive_drive_id = folder.at("parentReference").at("driveId").get<std::string>();
        out.folder_id = folder.at("id").get<std::string>();
        const std::string request =
            load_fixture_json("graph", "mail-list-200-empty").at("request").get<std::string>();
        const std::size_t start = request.find("/users/") + 7;
        out.mailbox = request.substr(start, request.find("/mailFolders") - start);
        return out;
    }();
    return values;
}

rp::Config lab_config()
{
    const Lab_values& v = lab_values();
    rp::Config config;
    config.test_mailbox = v.mailbox;
    config.test_site_id = v.site_id;
    config.test_library_id = v.library_id;
    config.test_onedrive_drive_id = v.onedrive_drive_id;
    config.test_onedrive_folder_id = v.folder_id;
    return config;
}

std::string drive_url()
{
    return kGraph + "/drives/" + lab_values().library_id +
           "?$select=id,name,driveType,webUrl,sharePointIds";
}
std::string library_children_url()
{
    return kGraph + "/drives/" + lab_values().library_id + "/root" + kChildrenQuery;
}
std::string folder_url()
{
    return kGraph + "/drives/" + lab_values().onedrive_drive_id + "/items/" +
           lab_values().folder_id + "?$select=id,name,folder,parentReference";
}
std::string folder_children_url()
{
    return kGraph + "/drives/" + lab_values().onedrive_drive_id + "/items/" +
           lab_values().folder_id + kChildrenQuery;
}

// Graph (with its token route) and the download host as a test sees them.
// Waits are recorded, never slept; every log line goes to a string.
struct Lab {
    Lab()
    {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("targets_test", sink);
        logger->set_level(spdlog::level::trace);
        logger->set_formatter(std::make_unique<spdlog::pattern_formatter>(
            "%l %v", spdlog::pattern_time_type::utc, "\n"));
        graph_http.on(HttpMethod::post, kTokenUrl, {token_response()});
        GraphClientOptions options;
        options.logger = logger;
        options.now = [] { return std::chrono::steady_clock::time_point{}; };
        options.wall_now = [] { return kNow; };
        options.sleep = [](std::chrono::milliseconds) {};
        options.jitter = [] { return 0.0; };
        graph = std::make_unique<GraphClient>(
            graph_http, kTenant, kClient,
            rp::graph::load_client_certificate(pfx_base64(), kPfxPassword, kNow), options);
    }

    TargetReaderOptions reader_options()
    {
        TargetReaderOptions out;
        out.logger = logger;
        out.download.logger = logger;
        return out;
    }

    TargetReader reader(const rp::Config& config = lab_config())
    {
        return TargetReader(*graph, dl_http, rp::connector::RestoreTargets::from_config(config),
                            reader_options());
    }

    void serve(const std::string& url, const json& fixture)
    {
        graph_http.on(HttpMethod::get, url, {to_response(fixture)});
    }
    void serve_file(const std::string& url, const std::string& name)
    {
        serve(url, load_fixture_json("graph", name));
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    std::size_t gets(const std::string& url) const { return graph_http.count(HttpMethod::get, url); }

    // Every request Graph got other than token requests.
    std::vector<HttpRequest> graph_gets() const
    {
        std::vector<HttpRequest> out;
        for (const HttpRequest& request : graph_http.requests()) {
            if (request.url != kTokenUrl) {
                out.push_back(request);
            }
        }
        return out;
    }

    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    FakeHttpClient graph_http;
    FakeHttpClient dl_http;
    std::unique_ptr<GraphClient> graph;
};

struct Caught {
    std::string kind = "none";
    std::string what;
    int status = 0;
    std::string grant;
    std::string request_id;
    std::string key;
};

Caught catch_error(const std::function<void()>& call)
{
    const auto fill = [](std::string kind, const rp::graph::GraphError& e) {
        return Caught{std::move(kind), e.what(), e.status(), {}, e.request_id(), {}};
    };
    try {
        call();
    } catch (const rp::graph::WrongTargetError& e) {
        return fill("WrongTargetError", e);
    } catch (const rp::graph::TransientError& e) {
        return fill("TransientError", e);
    } catch (const rp::graph::AuthError& e) {
        return fill("AuthError", e);
    } catch (const rp::graph::PermissionError& e) {
        Caught caught = fill("PermissionError", e);
        caught.grant = e.grant();
        return caught;
    } catch (const rp::graph::NotFoundError& e) {
        return fill("NotFoundError", e);
    } catch (const rp::graph::GraphError& e) {
        return fill("GraphError", e);
    } catch (const rp::ConfigError& e) {
        Caught caught{"ConfigError", e.what()};
        caught.key = e.key();
        return caught;
    } catch (const std::exception& e) {
        return Caught{"other", e.what()};
    }
    return {};
}

// A GUID of the same shape as `guid` that differs from it (built, not spelled out).
std::string other_guid(std::string guid)
{
    guid[0] = guid[0] == '0' ? '1' : '0';
    return guid;
}

} // namespace

// ---- names and configuration ---------------------------------------------------------------

TEST_CASE("to_string names every item type", "[graph][targets]")
{
    const auto [type, name] = GENERATE(table<ItemType, std::string>({
        {ItemType::mail, "mail"},
        {ItemType::sharepoint, "sharepoint"},
        {ItemType::onedrive, "onedrive"},
        {static_cast<ItemType>(99), "unknown"},
    }));

    CHECK(rp::graph::to_string(type) == name);
}

TEST_CASE("the constructor refuses IDs that can't be Graph IDs", "[graph][targets]")
{
    const std::string drive_msg =
        "is not a Graph drive ID (\"b!\" then letters, digits, '-' and '_')";
    const std::string item_msg = "is not a Graph item ID (letters, digits, '!', '-' and '_')";
    const std::string site_msg =
        "is not a Graph site ID (\"<tenant>.sharepoint.com,<site GUID>,<web GUID>\")";
    const std::string g = kMadeUpGuid;
    const auto [key, value, message] = GENERATE_COPY(table<std::string, std::string, std::string>({
        {"test_library_id", "x/children", drive_msg},
        {"test_library_id", "b!a?b", drive_msg},
        {"test_library_id", "b!a%2e", drive_msg},
        {"test_library_id", "b!", drive_msg},
        {"test_library_id", g, drive_msg},
        {"test_library_id", "b!" + std::string(201, 'a'), drive_msg},
        {"test_onedrive_drive_id", "a/b", drive_msg},
        {"test_onedrive_drive_id", "b!a b", drive_msg},
        {"test_onedrive_folder_id", "a/b", item_msg},
        {"test_onedrive_folder_id", "a?b", item_msg},
        {"test_onedrive_folder_id", std::string(201, 'a'), item_msg},
        {"test_site_id", "host", site_msg},
        {"test_site_id", "h,notaguid,alsonot", site_msg},
        {"test_site_id", "evil.com," + g + "," + g, site_msg},
        {"test_site_id", "a.b.sharepoint.com," + g + "," + g, site_msg},
        {"test_site_id", ".sharepoint.com," + g + "," + g, site_msg},
        {"test_site_id", "t.sharepoint.com," + g, site_msg},
        {"test_site_id", "t.sharepoint.com," + g + "," + g + "," + g, site_msg},
        {"test_site_id", "t.sharepoint.com," + g + ",x", site_msg},
        {"test_site_id", "t_x.sharepoint.com," + g + "," + g, site_msg},
        {"test_site_id", std::string(64, 't') + ".sharepoint.com," + g + "," + g, site_msg},
    }));
    CAPTURE(key, value);
    rp::Config config = lab_config();
    if (key == "test_library_id") {
        config.test_library_id = value;
    } else if (key == "test_onedrive_drive_id") {
        config.test_onedrive_drive_id = value;
    } else if (key == "test_onedrive_folder_id") {
        config.test_onedrive_folder_id = value;
    } else {
        config.test_site_id = value;
    }
    Lab lab;

    const Caught caught = catch_error([&] { lab.reader(config); });

    CHECK(caught.kind == "ConfigError");
    CHECK(caught.key == key);
    CHECK(caught.what == key + " " + message);
    CHECK(lab.graph_http.requests().empty());
}

TEST_CASE("the constructor takes Graph IDs of the right shapes", "[graph][targets]")
{
    const std::string g = kMadeUpGuid;
    rp::Config config = lab_config();
    config.test_site_id = GENERATE_COPY(as<std::string>{}, "T-1.SharePoint.COM," + g + "," + g,
                                        std::string(63, 't') + ".sharepoint.com," + g + "," + g);
    config.test_library_id = "b!" + std::string(200, 'a');
    config.test_onedrive_folder_id = "a!b-c_" + std::string(194, 'd');
    Lab lab;

    CHECK(catch_error([&] { lab.reader(config); }).kind == "none");
}

// ---- the guards: failure paths -------------------------------------------------------------

TEST_CASE("the SharePoint guard refuses a drive that isn't the test site's RestoreTarget",
          "[graph][targets]")
{
    const std::string tail = ": the Worker reads only the RestoreTarget library; nothing was listed";
    const std::string not_site =
        "the drive test_library_id names is not in the site test_site_id names; nothing was listed";
    const std::string address = "the drive test_library_id names has the address of another "
                                "library (not .../RestoreTarget)" + tail;
    using Edit = std::function<void(json&)>;
    struct Row {
        std::string name;
        Edit edit;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"name RestoreTest (the canary library's shape)",
            [](json& b) { b["name"] = "RestoreTest"; },
            "the drive test_library_id names is \"RestoreTest\", not \"RestoreTarget\"" + tail},
        Row{"name Documents", [](json& b) { b["name"] = "Documents"; },
            "the drive test_library_id names is \"Documents\", not \"RestoreTarget\"" + tail},
        Row{"name in another case", [](json& b) { b["name"] = "restoretarget"; },
            "the drive test_library_id names is \"restoretarget\", not \"RestoreTarget\"" + tail},
        Row{"name missing", [](json& b) { b.erase("name"); },
            "the drive test_library_id names is \"(none)\", not \"RestoreTarget\"" + tail},
        Row{"name not a string", [](json& b) { b["name"] = 7; },
            "the drive test_library_id names is \"(none)\", not \"RestoreTarget\"" + tail},
        Row{"a renamed canary library",
            [](json& b) {
                std::string url = b["webUrl"].get<std::string>();
                b["webUrl"] = url.substr(0, url.rfind('/')) + "/RestoreTest";
            },
            address},
        Row{"webUrl missing", [](json& b) { b.erase("webUrl"); }, address},
        Row{"webUrl not a string", [](json& b) { b["webUrl"] = json::object(); }, address},
        Row{"webUrl with RestoreTarget only in its query",
            [](json& b) {
                std::string url = b["webUrl"].get<std::string>();
                b["webUrl"] = url.substr(0, url.rfind('/')) + "/Shared%20Documents?x=/RestoreTarget";
            },
            address},
        Row{"driveType personal", [](json& b) { b["driveType"] = "personal"; },
            "the drive test_library_id names is not a document library; nothing was listed"},
        Row{"driveType missing", [](json& b) { b.erase("driveType"); },
            "the drive test_library_id names is not a document library; nothing was listed"},
        Row{"sharePointIds removed", [](json& b) { b.erase("sharePointIds"); },
            "Graph's reply for the drive test_library_id names has no sharePointIds; the "
            "Worker can't check it is in the test site; nothing was listed"},
        Row{"webId removed", [](json& b) { b["sharePointIds"].erase("webId"); },
            "Graph's reply for the drive test_library_id names has no sharePointIds; the "
            "Worker can't check it is in the test site; nothing was listed"},
        Row{"siteId of another GUID",
            [](json& b) {
                b["sharePointIds"]["siteId"] =
                    other_guid(b["sharePointIds"]["siteId"].get<std::string>());
            },
            not_site},
        Row{"webId changed",
            [](json& b) {
                b["sharePointIds"]["webId"] =
                    other_guid(b["sharePointIds"]["webId"].get<std::string>());
            },
            not_site});
    CAPTURE(row.name);
    Lab lab;
    json fixture = load_fixture_json("graph", "restoretarget-drive-200");
    row.edit(fixture["body"]);
    lab.serve(drive_url(), fixture);
    lab.serve_file(library_children_url(), "restoretarget-children-200-empty");
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { reader.list_sharepoint(); });

    CHECK(caught.kind == "WrongTargetError");
    CHECK(caught.what == row.message);
    CHECK(lab.gets(drive_url()) == 1);
    CHECK(lab.gets(library_children_url()) == 0);
    CHECK(lab.graph_gets().size() == 1);
}

TEST_CASE("the OneDrive guard refuses a folder that isn't the configured RestoreTarget",
          "[graph][targets]")
{
    const std::string not_in_drive = "the OneDrive folder test_onedrive_folder_id names is not in "
                                     "the drive test_onedrive_drive_id names; nothing was listed";
    const std::string not_root = "the OneDrive folder test_onedrive_folder_id names is not "
                                 "directly under the drive's root; nothing was listed";
    const std::string od = lab_values().onedrive_drive_id;
    using Edit = std::function<void(json&)>;
    struct Row {
        std::string name;
        Edit edit;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"name RestoreTest", [](json& b) { b["name"] = "RestoreTest"; },
            "the OneDrive item test_onedrive_folder_id names is \"RestoreTest\", not "
            "\"RestoreTarget\": the Worker reads only the RestoreTarget folder; nothing was listed"},
        Row{"name missing", [](json& b) { b.erase("name"); },
            "the OneDrive item test_onedrive_folder_id names is \"(none)\", not "
            "\"RestoreTarget\": the Worker reads only the RestoreTarget folder; nothing was listed"},
        Row{"folder removed", [](json& b) { b.erase("folder"); },
            "the OneDrive item test_onedrive_folder_id names is not a folder; nothing was listed"},
        Row{"parentReference.driveId changed",
            [](json& b) {
                std::string id = b["parentReference"]["driveId"].get<std::string>();
                id.back() = id.back() == 'A' ? 'B' : 'A';
                b["parentReference"]["driveId"] = id;
            },
            not_in_drive},
        Row{"parentReference.driveId removed",
            [](json& b) { b["parentReference"].erase("driveId"); }, not_in_drive},
        Row{"parentReference removed", [](json& b) { b.erase("parentReference"); }, not_in_drive},
        Row{"a nested RestoreTarget (/drive/root: form)",
            [](json& b) { b["parentReference"]["path"] = "/drive/root:/RestoreTest"; }, not_root},
        Row{"a nested RestoreTarget (/drives/<id>/root: form)",
            [od](json& b) { b["parentReference"]["path"] = "/drives/" + od + "/root:/RestoreTest"; },
            not_root},
        Row{"the root of another drive",
            [od](json& b) {
                b["parentReference"]["path"] = "/drives/" + od.substr(0, od.size() - 1) + "x/root:";
            },
            not_root},
        Row{"parentReference.path not a string",
            [](json& b) { b["parentReference"]["path"] = 1; },
            "Graph's reply for the OneDrive folder test_onedrive_folder_id names has no "
            "parentReference.path; the Worker can't check it is at the drive's root; nothing "
            "was listed"},
        Row{"parentReference.path removed", [](json& b) { b["parentReference"].erase("path"); },
            "Graph's reply for the OneDrive folder test_onedrive_folder_id names has no "
            "parentReference.path; the Worker can't check it is at the drive's root; nothing "
            "was listed"});
    CAPTURE(row.name);
    Lab lab;
    json fixture = load_fixture_json("graph", "onedrive-folder-200");
    row.edit(fixture["body"]);
    lab.serve(folder_url(), fixture);
    lab.serve_file(folder_children_url(), "onedrive-children-200-empty");
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { reader.list_onedrive(); });

    CHECK(caught.kind == "WrongTargetError");
    CHECK(caught.what == row.message);
    CHECK(lab.gets(folder_url()) == 1);
    CHECK(lab.gets(folder_children_url()) == 0);
}

TEST_CASE("the OneDrive guard takes the root in both of Graph's path forms", "[graph][targets]")
{
    const std::string path = GENERATE_COPY(
        as<std::string>{}, "/drive/root:", "/drives/" + lab_values().onedrive_drive_id + "/root:");
    CAPTURE(path);
    Lab lab;
    json fixture = load_fixture_json("graph", "onedrive-folder-200");
    fixture["body"]["parentReference"]["path"] = path;
    lab.serve(folder_url(), fixture);
    lab.serve_file(folder_children_url(), "onedrive-children-200-empty");

    CHECK(lab.reader().list_onedrive().empty());
}

TEST_CASE("a missing drive or folder is a NotFoundError, never an empty listing",
          "[graph][targets]")
{
    SECTION("the RestoreTarget drive")
    {
        Lab lab;
        lab.serve_file(drive_url(), "drive-404-itemnotfound");
        TargetReader reader = lab.reader();

        const Caught caught = catch_error([&] { reader.list_sharepoint(); });

        CHECK(caught.kind == "NotFoundError");
        CHECK(caught.status == 404);
        CHECK(lab.gets(library_children_url()) == 0);
    }
    SECTION("the OneDrive folder, whose 404 may also mean a missing grant")
    {
        Lab lab;
        const json fixture = load_fixture_json("graph", "onedrive-folder-404-itemnotfound");
        lab.serve(folder_url(), fixture);
        TargetReader reader = lab.reader();

        const Caught caught = catch_error([&] { reader.list_onedrive(); });

        CHECK(caught.kind == "NotFoundError");
        CHECK(caught.status == 404);
        CHECK(caught.request_id == fixture.at("headers").at("request-id").get<std::string>());
        CHECK_THAT(caught.what,
                   ContainsSubstring(
                       "; if the folder test_onedrive_folder_id names does exist, the Worker app "
                       "may lack the grant \"" +
                       std::string{rp::graph::kOneDriveReadGrant.description} +
                       "\" (SharePoint answers 404 for an item the app may not read)"));
        CHECK_THAT(caught.what, ContainsSubstring("404"));
        CHECK(lab.gets(folder_children_url()) == 0);
    }
}

TEST_CASE("each file location's errors keep their W2.1 type", "[graph][targets]")
{
    struct Row {
        std::string name;
        std::string kind;
        std::string grant;
    };
    const Row row = GENERATE(
        Row{"sharepoint: site-403-accessdenied on the drive", "PermissionError",
            std::string{rp::graph::kSitesReadGrant.description}},
        Row{"onedrive: onedrive-folder-403-accessdenied on the folder", "PermissionError",
            std::string{rp::graph::kOneDriveReadGrant.description}},
        Row{"sharepoint: 503 on the children", "TransientError", ""},
        Row{"onedrive: 503 on the children", "TransientError", ""});
    CAPTURE(row.name);
    Lab lab;
    HttpResponse busy =
        make_response(503, R"({"error":{"code":"serviceNotAvailable","message":"x"}})");
    busy.headers["Retry-After"] = "1";
    const bool sharepoint = row.name.starts_with("sharepoint");
    if (row.name.find("403") != std::string::npos) {
        lab.serve_file(sharepoint ? drive_url() : folder_url(),
                       sharepoint ? "site-403-accessdenied" : "onedrive-folder-403-accessdenied");
    } else {
        lab.serve_file(drive_url(), "restoretarget-drive-200");
        lab.serve_file(folder_url(), "onedrive-folder-200");
        lab.graph_http.on(HttpMethod::get,
                          sharepoint ? library_children_url() : folder_children_url(), {busy});
    }
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] {
        if (sharepoint) {
            reader.list_sharepoint();
        } else {
            reader.list_onedrive();
        }
    });

    CHECK(caught.kind == row.kind);
    CHECK(caught.grant == row.grant);
}

// ---- happy paths ---------------------------------------------------------------------------

TEST_CASE("empty file locations list as empty vectors", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(drive_url(), "restoretarget-drive-200");
    lab.serve_file(library_children_url(), "restoretarget-children-200-empty");
    lab.serve_file(folder_url(), "onedrive-folder-200");
    lab.serve_file(folder_children_url(), "onedrive-children-200-empty");
    TargetReader reader = lab.reader();

    CHECK(reader.list_sharepoint().empty());
    CHECK(reader.list_onedrive().empty());

    CHECK(lab.gets(drive_url()) == 1);
    CHECK(lab.gets(library_children_url()) == 1);
    CHECK(lab.gets(folder_url()) == 1);
    CHECK(lab.gets(folder_children_url()) == 1);
    CHECK(lab.graph_gets().size() == 4);
    for (const HttpRequest& request : lab.graph_gets()) {
        CHECK_FALSE(request.headers.contains("Prefer"));
    }
    CHECK(lab.dl_http.requests().empty());
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 0 item(s) in the RestoreTarget library"));
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 0 item(s) in the test OneDrive folder"));
}
