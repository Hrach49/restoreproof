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
#include <rp/redact.hpp>
#include <rp/sha256.hpp>
#include <rp/text_v1.hpp>

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
#include <utility>
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
    const std::string not_onedrive =
        "the drive test_onedrive_drive_id names is not a OneDrive (Graph's driveType is not "
        "\"business\"): a site library's folder is never read as the test OneDrive's; nothing "
        "was listed";
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
        // Review of W2.2: test_onedrive_drive_id set to a site library's drive,
        // the RestoreTest library's say, with a RestoreTarget folder at its root.
        Row{"parentReference.driveType documentLibrary",
            [](json& b) { b["parentReference"]["driveType"] = "documentLibrary"; }, not_onedrive},
        Row{"parentReference.driveType personal",
            [](json& b) { b["parentReference"]["driveType"] = "personal"; }, not_onedrive},
        Row{"parentReference.driveType in another case",
            [](json& b) { b["parentReference"]["driveType"] = "Business"; }, not_onedrive},
        Row{"parentReference.driveType removed",
            [](json& b) { b["parentReference"].erase("driveType"); }, not_onedrive},
        Row{"parentReference.driveType not a string",
            [](json& b) { b["parentReference"]["driveType"] = 1; }, not_onedrive},
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

TEST_CASE("the SharePoint guard reads the library's URL name, not its spelling",
          "[graph][targets]")
{
    const std::string tail = GENERATE(as<std::string>{}, "/RestoreTarget/", "/restoretarget",
                                      "/Restore%54arget", "/Restore%54arget?web=1");
    CAPTURE(tail);
    Lab lab;
    json fixture = load_fixture_json("graph", "restoretarget-drive-200");
    const std::string url = fixture["body"]["webUrl"].get<std::string>();
    fixture["body"]["webUrl"] = url.substr(0, url.rfind('/')) + tail;
    lab.serve(drive_url(), fixture);
    lab.serve_file(library_children_url(), "restoretarget-children-200-empty");

    CHECK(lab.reader().list_sharepoint().empty());
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

// ---- mail and paging -----------------------------------------------------------------------

namespace {

std::string mail_list_url()
{
    return kGraph + "/users/" + lab_values().mailbox + "/mailFolders/inbox/messages" +
           kMailSelect + "&$top=100";
}

std::string mail_body_url(const std::string& id)
{
    return kGraph + "/users/" + lab_values().mailbox + "/messages/" + id + "?$select=body";
}

// The messages of a recorded listing.
json messages_of(const std::string& name)
{
    return load_fixture_json("graph", name).at("body").at("value");
}

// A listing page holding `value`, with `next_link` if given.
HttpResponse page_of(const json& value, const std::optional<std::string>& next_link = std::nullopt)
{
    json body = {{"value", value}};
    if (next_link) {
        body["@odata.nextLink"] = *next_link;
    }
    return make_response(200, body.dump());
}

const std::string kPrefer = std::string{rp::graph::kMailPrefer};

} // namespace

TEST_CASE("the mail Prefer header is the seeder's", "[graph][targets]")
{
    // lab/seeder/graph.py MAIL_PREFER
    CHECK(rp::graph::kMailPrefer == "outlook.body-content-type=\"text\", IdType=\"ImmutableId\"");
    CHECK(rp::graph::kRestoreTargetName == "RestoreTarget");
    CHECK(rp::graph::kMaxListPages == 100);
}

TEST_CASE("the mailbox's errors keep their W2.1 type", "[graph][targets]")
{
    struct Row {
        std::string fixture;
        std::string kind;
        std::string grant;
    };
    const Row row = GENERATE(
        Row{"messages-403-exchange", "PermissionError",
            std::string{rp::graph::kMailReadGrant.description}},
        Row{"messages-404-unknown-user", "NotFoundError", ""},
        Row{"messages-404-mailbox-not-enabled", "GraphError", ""});
    CAPTURE(row.fixture);
    Lab lab;
    lab.serve_file(mail_list_url(), row.fixture);
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { reader.list_mail(); });

    CHECK(caught.kind == row.kind);
    CHECK(caught.grant == row.grant);
    CHECK(lab.graph_gets().size() == 1);
}

TEST_CASE("a mail body that isn't text is an error", "[graph][targets]")
{
    const std::string not_text_prefix =
        "Graph returned the body of a message in the test mailbox as ";
    const std::string not_text_suffix =
        ", not text, although the Worker asked for text; its text-v1 hash would be wrong";
    const std::string no_content =
        "Graph's reply for a message body in the test mailbox has no body.content";
    using Edit = std::function<void(json&)>;
    struct Row {
        std::string name;
        Edit edit;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"html", [](json& b) { b["body"]["contentType"] = "html"; },
            not_text_prefix + "\"html\"" + not_text_suffix},
        Row{"a long, multi-line contentType",
            [](json& b) { b["body"]["contentType"] = "html\nX: 1234567890123456789"; },
            not_text_prefix + "\"html X: 123456789012...\"" + not_text_suffix},
        Row{"contentType missing", [](json& b) { b["body"].erase("contentType"); },
            not_text_prefix + "\"(none)\"" + not_text_suffix},
        Row{"body missing", [](json& b) { b.erase("body"); },
            not_text_prefix + "\"(none)\"" + not_text_suffix},
        Row{"content removed", [](json& b) { b["body"].erase("content"); }, no_content},
        Row{"content not a string", [](json& b) { b["body"]["content"] = 1; }, no_content});
    CAPTURE(row.name);
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-one-item");
    json body = load_fixture_json("graph", "mail-body-200");
    row.edit(body["body"]);
    const std::string id = messages_of("mail-list-200-one-item").at(0).at("id").get<std::string>();
    lab.serve(mail_body_url(id), body);
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { reader.list_mail(); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == row.message);
}

TEST_CASE("the body's contentType is compared in any case", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-one-item");
    json body = load_fixture_json("graph", "mail-body-200");
    body["body"]["contentType"] = "Text";
    const std::string id = messages_of("mail-list-200-one-item").at(0).at("id").get<std::string>();
    lab.serve(mail_body_url(id), body);

    CHECK(lab.reader().list_mail().size() == 1);
}

TEST_CASE("bad listing replies are errors", "[graph][targets]")
{
    const std::string bad_link =
        "Graph's reply listing the test mailbox's Inbox has a bad @odata.nextLink";
    const std::string first = mail_list_url();
    const json one = messages_of("mail-list-200-one-item");
    const std::string domain = lab_values().mailbox.substr(lab_values().mailbox.find('@') + 1);

    SECTION("no value array")
    {
        const std::string body = GENERATE(as<std::string>{}, R"({"x":[]})", R"({"value":{}})",
                                          R"({"value":"a"})");
        CAPTURE(body);
        Lab lab;
        lab.graph_http.on(HttpMethod::get, first, {make_response(200, body)});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.kind == "GraphError");
        CHECK(caught.what ==
              "Graph's reply listing the test mailbox's Inbox has no \"value\" array");
    }
    SECTION("a nextLink that is empty, not a string, or the URL just fetched")
    {
        const json link = GENERATE_COPY(json(""), json(7), json(nullptr), json(first));
        CAPTURE(link.dump());
        Lab lab;
        const json body = {{"value", json::array()}, {"@odata.nextLink", link}};
        lab.graph_http.on(HttpMethod::get, first, {make_response(200, body.dump())});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.kind == "GraphError");
        CHECK(caught.what == bad_link);
        CHECK(lab.gets(first) == 1);
        CHECK(lab.graph_gets().size() == 1);
    }
    SECTION("an A-B cycle ends when B links back to A, after two GETs")
    {
        Lab lab;
        const std::string b = first + "&$skiptoken=b";
        lab.graph_http.on(HttpMethod::get, first, {page_of(json::array(), b)});
        lab.graph_http.on(HttpMethod::get, b, {page_of(json::array(), first)});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.what == bad_link);
        CHECK(lab.graph_gets().size() == 2);
    }
    SECTION("a nextLink to another resource")
    {
        const std::string link = GENERATE_COPY(
            kGraph + "/users/alice@" + domain + "/messages?$skip=1",
            kGraph + "/users/alice@" + domain + "/mailFolders/inbox/messages?$skip=1",
            kGraph + "/users/" + lab_values().mailbox + "/mailFolders/sentitems/messages?$skip=1",
            kGraph + "/users('alice%40" + domain + "')/mailFolders('Inbox')/messages?$skip=1",
            kGraph + "/users/" + lab_values().mailbox + "/mailFolders/inbox/messages%zz?$skip=1",
            // Relative links: GraphClient would put its v1.0 root in front and send them.
            "/users/alice@" + domain + "/mailFolders/inbox/messages?$skip=1",
            "/users/" + lab_values().mailbox + "/mailFolders/inbox/messages?$skip=1",
            "users/" + lab_values().mailbox + "/mailFolders/inbox/messages?$skip=1");
        CAPTURE(link);
        Lab lab;
        lab.graph_http.on(HttpMethod::get, first, {page_of(json::array(), link)});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.what == bad_link);
        CHECK(lab.graph_gets().size() == 1);
    }
    SECTION("a nextLink to another drive")
    {
        std::string other = lab_values().library_id;
        other.back() = other.back() == 'A' ? 'B' : 'A';
        const std::string link =
            GENERATE_COPY(kGraph + "/drives/" + other + "/root/children?$skiptoken=x",
                          "/drives/" + other + "/root/children?$skiptoken=x");
        CAPTURE(link);
        Lab lab;
        lab.serve_file(drive_url(), "restoretarget-drive-200");
        lab.graph_http.on(HttpMethod::get, library_children_url(),
                          {page_of(json::array(), link)});

        const Caught caught = catch_error([&] { lab.reader().list_sharepoint(); });

        CHECK(caught.what ==
              "Graph's reply listing the RestoreTarget library has a bad @odata.nextLink");
        CHECK(lab.graph_gets().size() == 2);
    }
    SECTION("a nextLink outside Graph's v1.0 root is the listing's own refusal")
    {
        const std::string link = GENERATE_COPY(
            "https://evil.example/v1.0/users/" + lab_values().mailbox +
                "/mailFolders/inbox/messages?$skip=1",
            "https://graph.microsoft.com/beta/users/" + lab_values().mailbox +
                "/mailFolders/inbox/messages?$skip=1");
        CAPTURE(link);
        Lab lab;
        lab.graph_http.on(HttpMethod::get, first, {page_of(json::array(), link)});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.kind == "GraphError");
        CHECK(caught.what == bad_link);
        CHECK(lab.graph_gets().size() == 1);
    }
    SECTION("the page cap: the error comes after exactly 100 GETs")
    {
        Lab lab;
        for (int i = 0; i <= rp::graph::kMaxListPages; ++i) {
            const std::string url = i == 0 ? first : first + "&$skiptoken=" + std::to_string(i);
            lab.graph_http.on(
                HttpMethod::get, url,
                {page_of(json::array(), first + "&$skiptoken=" + std::to_string(i + 1))});
        }

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.kind == "GraphError");
        CHECK(caught.what ==
              "listing the test mailbox's Inbox went past 100 pages; the Worker stops there");
        CHECK(lab.graph_gets().size() == 100);
    }
    SECTION("a message ID the Worker won't put in a URL")
    {
        const json id = GENERATE(json("a/b"), json("a?b"), json("a%2e"), json(""), json(5),
                                 json(std::string(513, 'a')), json(nullptr));
        CAPTURE(id.dump());
        json value = one;
        value[0]["id"] = id;
        Lab lab;
        lab.graph_http.on(HttpMethod::get, first, {page_of(value)});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.kind == "GraphError");
        CHECK(caught.what == "Graph returned a message in the test mailbox's Inbox with an ID "
                             "the Worker won't put in a URL");
        CHECK(lab.graph_gets().size() == 1);
    }
    SECTION("a message that isn't an object")
    {
        Lab lab;
        lab.graph_http.on(HttpMethod::get, first, {page_of(json::array({"x"}))});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK_THAT(caught.what, ContainsSubstring("with an ID the Worker won't put in a URL"));
    }
}

TEST_CASE("a nextLink in Graph's other form names the same resource", "[graph][targets]")
{
    const std::string domain = lab_values().mailbox.substr(lab_values().mailbox.find('@') + 1);
    const std::string link = GENERATE_COPY(
        kGraph + "/users('restoretest%40" + domain + "')/mailFolders('Inbox')/messages?%24skip=1",
        kGraph + "/users(restoretest@" + domain + ")/mailFolders(Inbox)/messages?%24skip=1",
        kGraph + "/Users/RESTORETEST%40" + domain + "/MailFolders/Inbox/Messages?$skip=1",
        kGraph + "/users/restoretest%40" + domain + "/mailFolders/I%6Ebox/%6D%65ssages?$skip=1");
    CAPTURE(link);
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(json::array(), link)});
    lab.graph_http.on(HttpMethod::get, link, {page_of(json::array())});

    CHECK(lab.reader().list_mail().empty());
    CHECK(lab.gets(link) == 1);
}

TEST_CASE("an empty Inbox lists as an empty vector", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-empty");

    CHECK(lab.reader().list_mail().empty());

    REQUIRE(lab.graph_gets().size() == 1);
    CHECK(lab.graph_gets()[0].headers.at("Prefer") == kPrefer);
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 0 item(s) in the test mailbox's Inbox"));
}

TEST_CASE("one mail lists as one FoundItem hashed by text-v1", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-one-item");
    const json message = messages_of("mail-list-200-one-item").at(0);
    const std::string id = message.at("id").get<std::string>();
    const json body = load_fixture_json("graph", "mail-body-200");
    lab.serve(mail_body_url(id), body);

    const std::vector<FoundItem> items = lab.reader().list_mail();

    FoundItem expected;
    expected.type = ItemType::mail;
    expected.id = id;
    expected.subject = message.at("subject").get<std::string>();
    expected.sender = message.at("from").at("emailAddress").at("address").get<std::string>();
    expected.received_at = message.at("receivedDateTime").get<std::string>();
    expected.internet_message_id = message.at("internetMessageId").get<std::string>();
    expected.sha256 =
        rp::text_v1_sha256(body.at("body").at("body").at("content").get<std::string>());
    expected.sha256_rule = "text-v1";
    REQUIRE(items.size() == 1);
    CHECK(items[0] == expected);
    CHECK_FALSE(items[0].name);
    CHECK_FALSE(items[0].size_bytes);
    REQUIRE(lab.graph_gets().size() == 2);
    for (const HttpRequest& request : lab.graph_gets()) {
        CHECK(request.headers.at("Prefer") == kPrefer);
        CHECK(request.headers.at("Authorization") == "Bearer token-1");
    }
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 1 item(s) in the test mailbox's Inbox"));
}

TEST_CASE("a message without the optional fields keeps them empty", "[graph][targets]")
{
    json value = messages_of("mail-list-200-one-item");
    const std::string id = value.at(0).at("id").get<std::string>();
    value[0].erase("receivedDateTime");
    value[0].erase("internetMessageId");
    value[0]["subject"] = "";
    value[0]["from"] = json::object();
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(value)});
    lab.serve_file(mail_body_url(id), "mail-body-200");

    const std::vector<FoundItem> items = lab.reader().list_mail();

    REQUIRE(items.size() == 1);
    CHECK(items[0].subject == std::optional<std::string>{""});
    CHECK_FALSE(items[0].sender);
    CHECK_FALSE(items[0].received_at);
    CHECK_FALSE(items[0].internet_message_id);
}

TEST_CASE("mail follows @odata.nextLink", "[graph][targets]")
{
    Lab lab;
    const json page1 = load_fixture_json("graph", "mail-list-200-page1");
    const std::string link = page1.at("body").at("@odata.nextLink").get<std::string>();
    lab.serve(mail_list_url(), page1);
    lab.serve_file(link, "mail-list-200-page2");
    const std::string first_id = page1.at("body").at("value").at(0).at("id").get<std::string>();
    const std::string second_id =
        messages_of("mail-list-200-page2").at(0).at("id").get<std::string>();
    lab.serve_file(mail_body_url(first_id), "mail-body-200");
    lab.serve_file(mail_body_url(second_id), "mail-body-200");

    const std::vector<FoundItem> items = lab.reader().list_mail();

    REQUIRE(items.size() == 2);
    CHECK(items[0].id == first_id);
    CHECK(items[1].id == second_id);
    REQUIRE(lab.graph_gets().size() == 4);
    CHECK(lab.graph_gets()[1].url == link);
    for (const HttpRequest& request : lab.graph_gets()) {
        CHECK(request.headers.at("Prefer") == kPrefer);
    }
}

TEST_CASE("empty locations list as empty vectors, and list_all too", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-empty");
    lab.serve_file(drive_url(), "restoretarget-drive-200");
    lab.serve_file(library_children_url(), "restoretarget-children-200-empty");
    lab.serve_file(folder_url(), "onedrive-folder-200");
    lab.serve_file(folder_children_url(), "onedrive-children-200-empty");

    CHECK(lab.reader().list_all().empty());

    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 5);
    CHECK(gets[0].url == mail_list_url());
    CHECK(gets[1].url == drive_url());
    CHECK(gets[2].url == library_children_url());
    CHECK(gets[3].url == folder_url());
    CHECK(gets[4].url == folder_children_url());
    CHECK(gets[0].headers.at("Prefer") == kPrefer);
    for (std::size_t i = 1; i < gets.size(); ++i) {
        CHECK_FALSE(gets[i].headers.contains("Prefer"));
    }
}

// ---- the RestoreTarget library and the OneDrive folder -------------------------------------

namespace {

// The download link's credential in the sentinel test: in no message, no log line.
const std::string kTempauth = "v1.SENTINEL-targets-tempauth";

// One file location as the tests serve it: its guard, listing and content fixtures.
struct FileLocation {
    std::string name; // "sharepoint" or "onedrive"
    ItemType type;
    std::string drive;
    std::string guard_url;
    std::string guard_fixture;
    std::string children_url;
    std::string one_item_fixture;
    std::string content_fixture;
    std::string location; // as in messages
    const rp::graph::Grant* grant;
};

FileLocation sharepoint_location()
{
    return {"sharepoint",
            ItemType::sharepoint,
            lab_values().library_id,
            drive_url(),
            "restoretarget-drive-200",
            library_children_url(),
            "restoretarget-children-200-one-item",
            "restoretarget-content-302",
            "the RestoreTarget library",
            &rp::graph::kSitesReadGrant};
}

FileLocation onedrive_location()
{
    return {"onedrive",
            ItemType::onedrive,
            lab_values().onedrive_drive_id,
            folder_url(),
            "onedrive-folder-200",
            folder_children_url(),
            "onedrive-children-200-one-item",
            "onedrive-content-302",
            "the test OneDrive folder",
            &rp::graph::kOneDriveReadGrant};
}

std::string content_url(const FileLocation& at, const std::string& id)
{
    return kGraph + "/drives/" + at.drive + "/items/" + id + "/content";
}

json file_of(const FileLocation& at)
{
    return load_fixture_json("graph", at.one_item_fixture).at("body").at("value").at(0);
}

std::string location_of(const FileLocation& at)
{
    return load_fixture_json("graph", at.content_fixture).at("headers").at("Location").get<std::string>();
}

// The file's bytes, as many as the listing says.
std::string bytes_of(const FileLocation& at)
{
    return std::string(file_of(at).at("size").get<std::size_t>(), 'r');
}

std::vector<FoundItem> list(TargetReader& reader, const FileLocation& at)
{
    return at.type == ItemType::sharepoint ? reader.list_sharepoint() : reader.list_onedrive();
}

// Serves the location's guard, `children` as its listing and, for its one
// file, the recorded 302 and a download of the listed size.
void serve_location(Lab& lab, const FileLocation& at, const HttpResponse& children)
{
    lab.serve_file(at.guard_url, at.guard_fixture);
    lab.graph_http.on(HttpMethod::get, at.children_url, {children});
    const std::string id = file_of(at).at("id").get<std::string>();
    lab.serve_file(content_url(at, id), at.content_fixture);
    lab.dl_http.on(HttpMethod::get, location_of(at),
                   {make_response(200, bytes_of(at), "application/octet-stream")});
}

void serve_location(Lab& lab, const FileLocation& at)
{
    serve_location(lab, at, load_fixture("graph", at.one_item_fixture));
}

} // namespace

TEST_CASE("bad driveItems in a listing are errors", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    using Edit = std::function<void(json&)>;
    struct Row {
        std::string name;
        Edit edit;
        std::string message; // after "Graph returned " / "Graph's reply listing <location> "
    };
    const Row row = GENERATE(
        Row{"an item ID with '/'", [](json& f) { f["id"] = "01A/B"; }, "id"},
        Row{"an item without an ID", [](json& f) { f.erase("id"); }, "id"},
        Row{"a file without a name", [](json& f) { f.erase("name"); }, "name"},
        Row{"a file whose name isn't a string", [](json& f) { f["name"] = 1; }, "name"},
        Row{"a file without a size", [](json& f) { f.erase("size"); }, "size"},
        Row{"a negative size", [](json& f) { f["size"] = -1; }, "size"},
        Row{"a fractional size", [](json& f) { f["size"] = 1.5; }, "size"},
        Row{"a size as text", [](json& f) { f["size"] = "27"; }, "size"});
    CAPTURE(row.name);
    json file = file_of(at);
    const std::string id = file.at("id").get<std::string>();
    row.edit(file);
    Lab lab;
    serve_location(lab, at, page_of(json::array({file})));
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { list(reader, at); });

    CHECK(caught.kind == "GraphError");
    if (row.message == "id") {
        CHECK(caught.what == "Graph returned an item in " + at.location +
                                 " with an ID the Worker won't put in a URL");
    } else if (row.message == "name") {
        CHECK(caught.what == "Graph's reply listing " + at.location + " has a file without a name");
    } else {
        CHECK(caught.what ==
              "Graph's reply listing " + at.location + " has a file without a size: " + id);
    }
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("a failed download fails the whole listing, no item is dropped", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    const json file = file_of(at);
    const std::string id = file.at("id").get<std::string>();
    // A second file after the one that fails: never downloaded, never listed.
    json second = file;
    second["id"] = id.substr(0, id.size() - 1) + "Z";
    Lab lab;
    serve_location(lab, at, page_of(json::array({file, second})));
    lab.dl_http.on(HttpMethod::get, location_of(at), {make_response(403)});
    TargetReader reader = lab.reader();
    std::optional<std::vector<FoundItem>> result;

    const Caught caught = catch_error([&] { result = list(reader, at); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == "SharePoint refused the download of " + at.location + " item " + id +
                             " (403); the link Graph gave may have expired");
    CHECK_FALSE(result);
    CHECK(lab.dl_http.requests().size() == 1);
    CHECK(lab.gets(content_url(at, second.at("id").get<std::string>())) == 0);
}

TEST_CASE("a size mismatch fails the listing", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    Lab lab;
    serve_location(lab, at);
    lab.dl_http.on(HttpMethod::get, location_of(at),
                   {make_response(200, bytes_of(at) + "x", "application/octet-stream")});
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { list(reader, at); });

    CHECK(caught.kind == "GraphError");
    CHECK_THAT(caught.what, ContainsSubstring("SharePoint sent more than the"));
}

// Review of W2.2: SharePoint rewrites docx and xlsx (lab/README.md, office-v1),
// so their bytes may differ from the size Graph lists; W3.2 compares them by
// content. They are read up to the download limit and kept as they came.
TEST_CASE("a docx or xlsx whose bytes differ from Graph's size lists as downloaded",
          "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    const std::string name = GENERATE(as<std::string>{}, "rewritten.docx", "Rewritten.XLSX");
    CAPTURE(name);
    const std::string served = GENERATE(as<std::string>{}, "longer", "");
    json file = file_of(at);
    file["name"] = name;
    const std::string bytes = served.empty() ? std::string{"short"} : bytes_of(at) + served;
    Lab lab;
    serve_location(lab, at, page_of(json::array({file})));
    lab.dl_http.on(HttpMethod::get, location_of(at),
                   {make_response(200, bytes, "application/octet-stream")});
    TargetReader reader = lab.reader();

    const std::vector<FoundItem> items = list(reader, at);

    REQUIRE(items.size() == 1);
    CHECK(items[0].name == name);
    CHECK(items[0].sha256 == rp::sha256_hex(bytes));
    CHECK(items[0].size_bytes == std::optional<std::uint64_t>{bytes.size()});
    REQUIRE(lab.dl_http.requests().size() == 1);
    CHECK(lab.dl_http.requests()[0].max_body_bytes ==
          std::optional<std::uint64_t>{rp::graph::kMaxDownloadBytes});
}

TEST_CASE("a file that isn't a docx or xlsx must be exactly Graph's size", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    const std::string name =
        GENERATE(as<std::string>{}, "notes.txt", "scan.pdf", "docx", "a.docx.txt", "a.pptx");
    CAPTURE(name);
    json file = file_of(at);
    file["name"] = name;
    Lab lab;
    serve_location(lab, at, page_of(json::array({file})));
    lab.dl_http.on(HttpMethod::get, location_of(at),
                   {make_response(200, bytes_of(at) + "x", "application/octet-stream")});
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { list(reader, at); });

    CHECK(caught.kind == "GraphError");
    CHECK_THAT(caught.what, ContainsSubstring("SharePoint sent more than the"));
    REQUIRE(lab.dl_http.requests().size() == 1);
    CHECK(lab.dl_http.requests()[0].max_body_bytes == file.at("size").get<std::uint64_t>());
}

TEST_CASE("on_file's exception propagates", "[graph][targets]")
{
    Lab lab;
    const FileLocation at = sharepoint_location();
    serve_location(lab, at);
    TargetReaderOptions options = lab.reader_options();
    options.on_file = [](const FoundItem&, std::string_view) {
        throw std::runtime_error("office-v1 failed");
    };
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const Caught caught = catch_error([&] { reader.list_sharepoint(); });

    CHECK(caught.kind == "other");
    CHECK(caught.what == "office-v1 failed");
}

TEST_CASE("one file in each file location lists as one FoundItem", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    Lab lab;
    serve_location(lab, at);
    TargetReaderOptions options = lab.reader_options();
    std::vector<std::pair<FoundItem, std::string>> seen;
    options.on_file = [&seen](const FoundItem& item, std::string_view bytes) {
        seen.emplace_back(item, std::string{bytes});
    };
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = list(reader, at);

    const json file = file_of(at);
    const std::string bytes = bytes_of(at);
    FoundItem expected;
    expected.type = at.type;
    expected.id = file.at("id").get<std::string>();
    expected.name = file.at("name").get<std::string>();
    expected.sha256 = rp::sha256_hex(bytes);
    expected.sha256_rule = "bytes";
    expected.size_bytes = file.at("size").get<std::uint64_t>();
    REQUIRE(items.size() == 1);
    CHECK(items[0] == expected);
    CHECK_FALSE(items[0].subject);
    CHECK_FALSE(items[0].sender);
    REQUIRE(seen.size() == 1);
    CHECK(seen[0].first == expected);
    CHECK(seen[0].second == bytes);
    // The content GET carried the token and the right grant's call; the
    // download went to the Location without it.
    CHECK(lab.gets(content_url(at, expected.id)) == 1);
    REQUIRE(lab.dl_http.requests().size() == 1);
    const HttpRequest download = lab.dl_http.requests()[0];
    CHECK(download.url == location_of(at));
    CHECK_FALSE(download.headers.contains("Authorization"));
    CHECK(download.max_body_bytes == expected.size_bytes);
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 1 item(s) in " + at.location));
}

TEST_CASE("folders and non-file items are skipped and logged", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    json folder = file_of(at);
    folder.erase("file");
    folder["folder"] = {{"childCount", 0}};
    folder["id"] = "01FOLDER";
    json package = file_of(at);
    package.erase("file");
    package["package"] = {{"type", "oneNote"}};
    package["id"] = "01PACKAGE";
    Lab lab;
    serve_location(lab, at, page_of(json::array({folder, package})));

    const std::vector<FoundItem> items = [&] {
        TargetReader reader = lab.reader();
        return list(reader, at);
    }();

    CHECK(items.empty());
    CHECK(lab.dl_http.requests().empty());
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring("info skipped a folder in " + at.location +
                                      ": 01FOLDER (restores land files in the root; subfolders "
                                      "aren't read)"));
    CHECK_THAT(log, ContainsSubstring("warning skipped an item that is not a file in " +
                                      at.location + ": 01PACKAGE"));
    CHECK_THAT(log, ContainsSubstring("info listed 0 item(s) in " + at.location));
}

TEST_CASE("list_all returns mail, then SharePoint, then OneDrive", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-one-item");
    const std::string mail_id =
        messages_of("mail-list-200-one-item").at(0).at("id").get<std::string>();
    lab.serve_file(mail_body_url(mail_id), "mail-body-200");
    serve_location(lab, sharepoint_location());
    serve_location(lab, onedrive_location());

    const std::vector<FoundItem> items = lab.reader().list_all();

    REQUIRE(items.size() == 3);
    CHECK(items[0].type == ItemType::mail);
    CHECK(items[1].type == ItemType::sharepoint);
    CHECK(items[2].type == ItemType::onedrive);
}

TEST_CASE("no credential, body, subject or file name reaches the log", "[graph][targets]")
{
    Lab lab;
    lab.logger->set_level(spdlog::level::trace);
    lab.serve_file(mail_list_url(), "mail-list-200-one-item");
    const json message = messages_of("mail-list-200-one-item").at(0);
    lab.serve_file(mail_body_url(message.at("id").get<std::string>()), "mail-body-200");
    serve_location(lab, sharepoint_location());
    serve_location(lab, onedrive_location());
    REQUIRE(lab.reader().list_all().size() == 3);

    // A failed download whose Location holds a credential.
    Lab failing;
    failing.logger->set_level(spdlog::level::trace);
    const FileLocation at = sharepoint_location();
    const std::string id = file_of(at).at("id").get<std::string>();
    const std::string location = "https://" + host_of(location_of(at)) +
                                 "/sites/s/_layouts/15/download.aspx?UniqueId=u&tempauth=" +
                                 kTempauth + "&ApiVersion=2.0";
    failing.serve_file(at.guard_url, at.guard_fixture);
    failing.serve_file(at.children_url, at.one_item_fixture);
    HttpResponse redirect = make_response(302);
    redirect.headers["Location"] = location;
    failing.graph_http.on(HttpMethod::get, content_url(at, id), {redirect});
    failing.dl_http.on(HttpMethod::get, location, {make_response(403)});
    const Caught caught = catch_error([&] { failing.reader().list_sharepoint(); });
    REQUIRE(caught.kind == "GraphError");

    const std::string log = lab.log() + failing.log();
    CHECK_THAT(log, ContainsSubstring("following Graph's redirect to"));
    // What a one-item recording holds (lab/README.md asks for distinctive values):
    // an empty or short one could match the log by chance, so it fails here first.
    const std::vector<std::string> recorded{
        load_fixture_json("graph", "mail-body-200").at("body").at("body").at("content").get<std::string>(),
        message.at("subject").get<std::string>(),
        file_of(sharepoint_location()).at("name").get<std::string>(),
        file_of(onedrive_location()).at("name").get<std::string>(),
    };
    for (const std::string& value : recorded) {
        CAPTURE(value);
        REQUIRE(value.size() >= 12);
    }
    std::vector<std::string> secrets{
        kTempauth,
        "tempauth=v1",
        "Bearer",
        "token-",
        "download.aspx",
    };
    secrets.insert(secrets.end(), recorded.begin(), recorded.end());
    for (const std::string& secret : secrets) {
        CAPTURE(secret);
        CHECK(log.find(secret) == std::string::npos);
    }
    CHECK(caught.what.find(kTempauth) == std::string::npos);
    std::istringstream lines(log);
    for (std::string line; std::getline(lines, line);) {
        CAPTURE(line);
        CHECK(rp::redact(line) == line);
    }
}
