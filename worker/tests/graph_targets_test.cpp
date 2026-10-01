// W2.2: reading the three restore targets through Graph (rp/graph_targets.hpp).
// Graph is served by one FakeHttpClient, SharePoint's download host by
// another. Every lab value (the drive, folder and site IDs, the mailbox) is
// read from the fixtures, so a re-recording in another tenant still works; the
// guard's refusals are edits of the recorded drive and folder replies, never
// the canaries' own IDs, which appear nowhere in the Worker.

#include "fake_http_client.hpp"
#include "found_item_line.hpp"
#include "graph_lab.hpp"
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
using namespace rp::test::graph_lab;

// Made up, never a lab value.
const std::string kMadeUpGuid = "0a1b2c3d-0000-4000-8000-00000000abcd";

// Graph (with its token route) and the download host as a test sees them.
// Waits are recorded, never slept; every log line goes to a string. The lab's
// values, URLs and fixtures helpers are graph_lab.hpp's.
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
        // The guard's mailbox check, which list_mail runs first (W3.2), as recorded.
        serve_file(inbox_url(), "mailbox-inbox-200");
    }

    TargetReaderOptions reader_options()
    {
        TargetReaderOptions out;
        out.logger = logger;
        out.download.logger = logger;
        // A clock that stands still: every read_ms is 0 unless a test says otherwise.
        out.clock = [] { return std::chrono::steady_clock::time_point{}; };
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

// The string at `key` of a recorded entry, if it has one: the fields W3.2 asks
// for are read from a re-recording that has them, absent from one that doesn't.
std::optional<std::string> string_or_none(const json& entry, const std::string& key)
{
    const auto found = entry.find(key);
    return found != entry.end() && found->is_string() ? std::optional{found->get<std::string>()}
                                                      : std::nullopt;
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
    // The mailbox check, then the listing.
    CHECK(lab.graph_gets().size() == 2);
}

TEST_CASE("a mail body that isn't text is an error", "[graph][targets]")
{
    const std::string not_text_prefix =
        "Graph returned the body of a message in the test mailbox as ";
    const std::string not_text_suffix =
        ", not text, although the Worker asked for text; its text-v1 hash would be wrong";
    const std::string no_content =
        "Graph's reply listing the test mailbox's Inbox has a message without body.content";
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
    json value = messages_of("mail-list-200-one-item");
    row.edit(value[0]);
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(value)});
    TargetReader reader = lab.reader();

    const Caught caught = catch_error([&] { reader.list_mail(); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == row.message);
}

TEST_CASE("the body's contentType is compared in any case", "[graph][targets]")
{
    json value = messages_of("mail-list-200-one-item");
    value[0]["body"]["contentType"] = "Text";
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(value)});

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
        CHECK(lab.graph_gets().size() == 2); // the mailbox check and the listing
    }
    SECTION("an A-B cycle ends when B links back to A, after two GETs")
    {
        Lab lab;
        const std::string b = first + "&$skiptoken=b";
        lab.graph_http.on(HttpMethod::get, first, {page_of(json::array(), b)});
        lab.graph_http.on(HttpMethod::get, b, {page_of(json::array(), first)});

        const Caught caught = catch_error([&] { lab.reader().list_mail(); });

        CHECK(caught.what == bad_link);
        CHECK(lab.graph_gets().size() == 3);
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
        CHECK(lab.graph_gets().size() == 2);
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
        CHECK(lab.graph_gets().size() == 2);
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
        CHECK(lab.graph_gets().size() == 101); // the mailbox check, then 100 pages
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
        CHECK(lab.graph_gets().size() == 2);
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

// Review of W2.2: Graph may name the mailbox by its object ID, or the library's
// root by its item ID, in a nextLink. Both still name the guarded target.
TEST_CASE("a nextLink naming the mailbox by object ID is followed", "[graph][targets]")
{
    const std::string link = GENERATE_COPY(
        kGraph + "/users/" + kMadeUpGuid + "/mailFolders/inbox/messages?$skip=1",
        kGraph + "/users('" + kMadeUpGuid + "')/mailFolders('inbox')/messages?%24skip=1");
    CAPTURE(link);
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(json::array(), link)});
    lab.graph_http.on(HttpMethod::get, link, {page_of(json::array())});

    CHECK(lab.reader().list_mail().empty());
    CHECK(lab.gets(link) == 1);
}

TEST_CASE("a library nextLink naming the root by item ID is followed", "[graph][targets]")
{
    const std::string link = GENERATE_COPY(
        kGraph + "/drives/" + lab_values().library_id + "/items/01ROOTITEMID00000000000000000000/children?$skiptoken=x",
        kGraph + "/drives('" + lab_values().library_id + "')/root/children?$skiptoken=y");
    CAPTURE(link);
    Lab lab;
    lab.serve_file(drive_url(), "restoretarget-drive-200");
    lab.graph_http.on(HttpMethod::get, library_children_url(), {page_of(json::array(), link)});
    lab.graph_http.on(HttpMethod::get, link, {page_of(json::array())});

    CHECK(lab.reader().list_sharepoint().empty());
    CHECK(lab.gets(link) == 1);
}

TEST_CASE("a nextLink the target's rule doesn't take is refused", "[graph][targets]")
{
    const Lab_values& v = lab_values();
    const std::string domain = v.mailbox.substr(v.mailbox.find('@') + 1);
    std::string other_item = v.folder_id;
    other_item.back() = other_item.back() == 'A' ? 'B' : 'A';
    struct Row {
        std::string name;
        std::string target; // mail, sharepoint, onedrive
        std::string link;
    };
    const Row row = GENERATE_COPY(
        Row{"a user that is neither the mailbox nor a GUID", "mail",
            kGraph + "/users/alice@" + domain + "/mailFolders/inbox/messages?$skip=1"},
        Row{"a GUID with the wrong shape", "mail",
            kGraph + "/users/0a1b2c3d-0000-4000-8000-00000000abc/mailFolders/inbox/messages"},
        Row{"the mailbox's Sent Items by GUID", "mail",
            kGraph + "/users/" + kMadeUpGuid + "/mailFolders/sentitems/messages?$skip=1"},
        Row{"the whole mailbox by GUID", "mail", kGraph + "/users/" + kMadeUpGuid + "/messages"},
        Row{"a child folder of the Inbox", "mail",
            kGraph + "/users/" + v.mailbox + "/mailFolders/inbox/childFolders/x/messages"},
        Row{"the library's items without children", "sharepoint",
            kGraph + "/drives/" + v.library_id + "/items/01X"},
        Row{"a nested path in the library", "sharepoint",
            kGraph + "/drives/" + v.library_id + "/items/01X/children/01Y/children"},
        Row{"the library by a root path", "sharepoint",
            kGraph + "/drives/" + v.library_id + "/root:/RestoreTest:/children"},
        // alice's canary folder is in the same drive as the test OneDrive folder.
        Row{"another folder in the test OneDrive", "onedrive",
            kGraph + "/drives/" + v.onedrive_drive_id + "/items/" + other_item + "/children"},
        Row{"the test OneDrive's root", "onedrive",
            kGraph + "/drives/" + v.onedrive_drive_id + "/root/children?$skiptoken=x"},
        Row{"the folder in the library's drive", "onedrive",
            kGraph + "/drives/" + v.library_id + "/items/" + v.folder_id + "/children"});
    CAPTURE(row.name);
    Lab lab;
    std::function<void()> call;
    std::string location;
    if (row.target == "mail") {
        lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(json::array(), row.link)});
        call = [&lab] { lab.reader().list_mail(); };
        location = "the test mailbox's Inbox";
    } else if (row.target == "sharepoint") {
        lab.serve_file(drive_url(), "restoretarget-drive-200");
        lab.graph_http.on(HttpMethod::get, library_children_url(),
                          {page_of(json::array(), row.link)});
        call = [&lab] { lab.reader().list_sharepoint(); };
        location = "the RestoreTarget library";
    } else {
        lab.serve_file(folder_url(), "onedrive-folder-200");
        lab.graph_http.on(HttpMethod::get, folder_children_url(),
                          {page_of(json::array(), row.link)});
        call = [&lab] { lab.reader().list_onedrive(); };
        location = "the test OneDrive folder";
    }
    lab.graph_http.on(HttpMethod::get, row.link, {page_of(json::array())});

    const Caught caught = catch_error(call);

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == "Graph's reply listing " + location + " has a bad @odata.nextLink");
    CHECK(lab.gets(row.link) == 0);
}

TEST_CASE("an empty Inbox lists as an empty vector", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-empty");

    CHECK(lab.reader().list_mail().empty());

    // The guard's mailbox check (no Prefer), then the listing.
    REQUIRE(lab.graph_gets().size() == 2);
    CHECK(lab.graph_gets()[0].url == inbox_url());
    CHECK_FALSE(lab.graph_gets()[0].headers.contains("Prefer"));
    CHECK(lab.graph_gets()[1].headers.at("Prefer") == kPrefer);
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 0 item(s) in the test mailbox's Inbox"));
}

TEST_CASE("one mail lists as one FoundItem hashed by text-v1", "[graph][targets]")
{
    Lab lab;
    lab.serve_file(mail_list_url(), "mail-list-200-one-item");
    const json message = messages_of("mail-list-200-one-item").at(0);
    const std::string id = message.at("id").get<std::string>();

    const std::vector<FoundItem> items = lab.reader().list_mail();

    FoundItem expected;
    expected.type = ItemType::mail;
    expected.id = id;
    expected.subject = message.at("subject").get<std::string>();
    expected.sender = message.at("from").at("emailAddress").at("address").get<std::string>();
    expected.sender_name = message.at("from").at("emailAddress").at("name").get<std::string>();
    // Recorded before W3.2 asked for them: read when a re-recording has them.
    expected.sent_at = string_or_none(message, "sentDateTime");
    expected.received_at = message.at("receivedDateTime").get<std::string>();
    expected.created_at = string_or_none(message, "createdDateTime");
    expected.internet_message_id = message.at("internetMessageId").get<std::string>();
    expected.sha256 = rp::text_v1_sha256(message.at("body").at("content").get<std::string>());
    expected.sha256_rule = "text-v1";
    REQUIRE(items.size() == 1);
    CHECK(items[0] == expected);
    CHECK_FALSE(items[0].name);
    CHECK_FALSE(items[0].size_bytes);
    CHECK_FALSE(items[0].listed_size);
    CHECK_FALSE(items[0].ctag);
    CHECK_FALSE(items[0].modified_at);
    CHECK(items[0].read_ms == 0);
    // The bodies come in the listing: the mailbox check, one GET for the page, none per mail.
    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 2);
    CHECK(gets[0].url == inbox_url());
    CHECK(gets[1].url == mail_list_url());
    for (const HttpRequest& request : gets) {
        CHECK(request.headers.at("Authorization") == "Bearer token-1");
    }
    CHECK(gets[1].headers.at("Prefer") == kPrefer);
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 1 item(s) in the test mailbox's Inbox"));
}

TEST_CASE("a message without the optional fields keeps them empty", "[graph][targets]")
{
    json value = messages_of("mail-list-200-one-item");
    value[0].erase("sentDateTime");
    value[0].erase("receivedDateTime");
    value[0].erase("createdDateTime");
    value[0].erase("internetMessageId");
    value[0]["subject"] = "";
    value[0]["from"] = json::object();
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(value)});

    const std::vector<FoundItem> items = lab.reader().list_mail();

    REQUIRE(items.size() == 1);
    CHECK(items[0].subject == std::optional<std::string>{""});
    CHECK_FALSE(items[0].sender);
    CHECK_FALSE(items[0].sender_name);
    CHECK_FALSE(items[0].sent_at);
    CHECK_FALSE(items[0].received_at);
    CHECK_FALSE(items[0].created_at);
    CHECK_FALSE(items[0].internet_message_id);
}

TEST_CASE("mail follows @odata.nextLink", "[graph][targets]")
{
    Lab lab;
    const json page1 = load_fixture_json("graph", "mail-list-200-page1");
    const std::string link = page1.at("body").at("@odata.nextLink").get<std::string>();
    lab.serve(mail_list_url(), page1);
    // Exchange links every full page, the last one too: page 2 has a link, page 3 is empty.
    const json page2 = load_fixture_json("graph", "mail-list-200-page2");
    const std::string link2 = page2.at("body").at("@odata.nextLink").get<std::string>();
    lab.serve(link, page2);
    lab.serve_file(link2, "mail-list-200-page3");
    const std::string first_id = page1.at("body").at("value").at(0).at("id").get<std::string>();
    const std::string second_id = page2.at("body").at("value").at(0).at("id").get<std::string>();

    const std::vector<FoundItem> items = lab.reader().list_mail();

    REQUIRE(items.size() == 2);
    CHECK(items[0].id == first_id);
    CHECK(items[1].id == second_id);
    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 4);
    CHECK(gets[0].url == inbox_url());
    CHECK(gets[2].url == link);
    CHECK(gets[3].url == link2);
    for (std::size_t i = 1; i < gets.size(); ++i) {
        CHECK(gets[i].headers.at("Prefer") == kPrefer);
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
    REQUIRE(gets.size() == 6);
    CHECK(gets[0].url == inbox_url());
    CHECK(gets[1].url == mail_list_url());
    CHECK(gets[2].url == drive_url());
    CHECK(gets[3].url == library_children_url());
    CHECK(gets[4].url == folder_url());
    CHECK(gets[5].url == folder_children_url());
    for (std::size_t i = 0; i < gets.size(); ++i) {
        CHECK(gets[i].headers.contains("Prefer") == (i == 1));
    }
    CHECK(gets[1].headers.at("Prefer") == kPrefer);
}

// ---- the RestoreTarget library and the OneDrive folder -------------------------------------

namespace {

// The download link's credential in the sentinel test: in no message, no log line.
const std::string kTempauth = "v1.SENTINEL-targets-tempauth";

std::vector<FoundItem> list(TargetReader& reader, const FileLocation& at)
{
    return at.type == ItemType::sharepoint ? reader.list_sharepoint() : reader.list_onedrive();
}

// graph_lab.hpp's serve_location on the lab's two clients.
void serve_location(Lab& lab, const FileLocation& at, const HttpResponse& children)
{
    rp::test::graph_lab::serve_location(lab.graph_http, lab.dl_http, at, children);
}

void serve_location(Lab& lab, const FileLocation& at)
{
    rp::test::graph_lab::serve_location(lab.graph_http, lab.dl_http, at);
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

// Review of W2.2: SharePoint rewrites Office files (lab/README.md,
// office-v1), so their bytes may differ from the size Graph lists; W3.2
// compares them by content. They are read up to the download limit and kept
// as they came. Since W3.1 one rule says which files they are
// (src/office_files.hpp): docx, xlsx, pptx and their macro and template types,
// and since the W3.1 review's live check xlsb, doc, xls and ppt.
TEST_CASE("an Office file whose bytes differ from Graph's size lists as downloaded",
          "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    const std::string name = GENERATE(as<std::string>{}, "rewritten.docx", "Rewritten.XLSX",
                                      "deck.pptx", "macros.XLSM", "template.dotx", "Book.xlsb",
                                      "old.DOC", "sheet.xls", "deck.ppt");
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
    // Graph's size is kept beside the downloaded count (W3.2).
    CHECK(items[0].listed_size == file.at("size").get<std::uint64_t>());
    REQUIRE(lab.dl_http.requests().size() == 1);
    CHECK(lab.dl_http.requests()[0].max_body_bytes ==
          std::optional<std::uint64_t>{rp::graph::kMaxDownloadBytes});
}

TEST_CASE("a file SharePoint doesn't rewrite must be exactly Graph's size", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    const std::string name = GENERATE(as<std::string>{}, "notes.txt", "scan.pdf", "docx",
                                      ".docx", "a.docx.txt", ".doc", "a.ppt.txt", "flow.vsdx",
                                      "addin.xlam", "notes.odt");
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

// Review of W3.2: the after read hashes only the files the check compares, so
// an earlier run's leftover that would fail its download (gone, a size that
// changed, too large) is listed, never read.
TEST_CASE("a file hash_file rejects is listed but never downloaded, hashed or given to on_file",
          "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    const json file = file_of(at);
    Lab lab;
    serve_location(lab, at, page_of(json::array({file})));
    // Its download would fail the listing.
    lab.dl_http.on(HttpMethod::get, location_of(at), {make_response(404)});
    TargetReaderOptions options = lab.reader_options();
    std::vector<FoundItem> asked;
    options.hash_file = [&asked](const FoundItem& item) {
        asked.push_back(item);
        return false;
    };
    int on_file_calls = 0;
    options.on_file = [&on_file_calls](const FoundItem&, std::string_view) { ++on_file_calls; };
    // A clock that moves: a file not read still has no read_ms.
    std::chrono::steady_clock::time_point t{};
    options.clock = [&t] {
        t += std::chrono::milliseconds{5};
        return t;
    };
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = list(reader, at);

    FoundItem expected;
    expected.type = at.type;
    expected.id = file.at("id").get<std::string>();
    expected.name = file.at("name").get<std::string>();
    expected.size_bytes = file.at("size").get<std::uint64_t>();
    expected.listed_size = expected.size_bytes;
    expected.ctag = string_or_none(file, "cTag");
    expected.created_at = string_or_none(file, "createdDateTime");
    expected.modified_at = string_or_none(file, "lastModifiedDateTime");
    REQUIRE(items.size() == 1);
    CHECK(items[0] == expected);
    // The predicate saw the file as listed, before anything was read.
    REQUIRE(asked.size() == 1);
    CHECK(asked[0] == expected);
    CHECK(on_file_calls == 0);
    CHECK(lab.gets(content_url(at, expected.id)) == 0);
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("hash_file picks file by file which are downloaded; null hashes every file",
          "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    const bool with_predicate = GENERATE(false, true);
    CAPTURE(with_predicate);
    const json file = file_of(at);
    const std::string id = file.at("id").get<std::string>();
    // A second file the predicate rejects: its /content isn't even served.
    json other = file;
    other["id"] = id.substr(0, id.size() - 1) + "Z";
    other["name"] = "leftover.bin";
    Lab lab;
    serve_location(lab, at, page_of(json::array({other, file})));
    TargetReaderOptions options = lab.reader_options();
    if (with_predicate) {
        options.hash_file = [&id](const FoundItem& item) { return item.id == id; };
    }
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    if (!with_predicate) {
        // Without one, the leftover is downloaded too, and its /content fails.
        CHECK(catch_error([&] { list(reader, at); }).kind != "none");
        return;
    }
    const std::vector<FoundItem> items = list(reader, at);

    REQUIRE(items.size() == 2);
    CHECK(items[0].sha256.empty());
    CHECK(items[1].sha256 == rp::sha256_hex(bytes_of(at)));
    CHECK(items[1].sha256_rule == "bytes");
    CHECK(lab.dl_http.requests().size() == 1);
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
    expected.listed_size = expected.size_bytes;
    // Recorded before W3.2 asked for them: read when a re-recording has them.
    expected.ctag = string_or_none(file, "cTag");
    expected.created_at = string_or_none(file, "createdDateTime");
    expected.modified_at = string_or_none(file, "lastModifiedDateTime");
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

// ---- without hash_items (W2.3: `rpworker graph list` without --hash) ---------------------

TEST_CASE("files are hashed unless hash_items says not to", "[graph][targets]")
{
    CHECK(TargetReaderOptions{}.hash_items);
}

TEST_CASE("without hash_items no file is downloaded and each keeps Graph's size",
          "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    // A docx too: SharePoint may rewrite it, but nothing is read to find out.
    const std::string name = GENERATE(as<std::string>{}, "", "rewritten.docx");
    CAPTURE(name);
    json file = file_of(at);
    if (!name.empty()) {
        file["name"] = name;
    }
    Lab lab;
    serve_location(lab, at, page_of(json::array({file})));
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = false;
    int on_file_calls = 0;
    options.on_file = [&on_file_calls](const FoundItem&, std::string_view) { ++on_file_calls; };
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = list(reader, at);

    FoundItem expected;
    expected.type = at.type;
    expected.id = file.at("id").get<std::string>();
    expected.name = file.at("name").get<std::string>();
    expected.size_bytes = file.at("size").get<std::uint64_t>();
    expected.listed_size = expected.size_bytes;
    expected.ctag = string_or_none(file, "cTag");
    expected.created_at = string_or_none(file, "createdDateTime");
    expected.modified_at = string_or_none(file, "lastModifiedDateTime");
    REQUIRE(items.size() == 1);
    CHECK(items[0] == expected);
    CHECK(items[0].read_ms == 0);
    CHECK(items[0].sha256.empty());
    CHECK(items[0].sha256_rule.empty());
    CHECK(on_file_calls == 0);
    // The guard and the listing, no /content GET, and nothing for the download client.
    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 2);
    CHECK(gets[0].url == at.guard_url);
    CHECK(gets[1].url == at.children_url);
    CHECK(lab.gets(content_url(at, expected.id)) == 0);
    CHECK(lab.dl_http.requests().empty());
    CHECK_THAT(lab.log(), ContainsSubstring("info listed 1 item(s) in " + at.location));
}

TEST_CASE("without hash_items the guards still refuse a wrong drive or folder",
          "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    CAPTURE(at.name);
    Lab lab;
    json guard = load_fixture_json("graph", at.guard_fixture);
    guard["body"]["name"] = "RestoreTest";
    lab.serve(at.guard_url, guard);
    lab.serve_file(at.children_url, at.one_item_fixture);
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = false;
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const Caught caught = catch_error([&] { list(reader, at); });

    CHECK(caught.kind == "WrongTargetError");
    CHECK_THAT(caught.what, ContainsSubstring("\"RestoreTest\", not \"RestoreTarget\""));
    CHECK(lab.gets(at.children_url) == 0);
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("without hash_items no mail body is asked for or checked", "[graph][targets]")
{
    // Even a body Graph sends anyway, as html or without content, is ignored:
    // nothing is hashed, so nothing can be hashed wrongly.
    json value = messages_of("mail-list-200-one-item");
    const std::string body = GENERATE(as<std::string>{}, "as recorded", "html", "no content");
    CAPTURE(body);
    if (body == "html") {
        value[0]["body"]["contentType"] = "html";
    } else if (body == "no content") {
        value[0]["body"].erase("content");
    }
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(false), {page_of(value)});
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = false;
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = reader.list_mail();

    REQUIRE(items.size() == 1);
    CHECK(items[0].id == value[0].at("id").get<std::string>());
    CHECK(items[0].subject == value[0].at("subject").get<std::string>());
    CHECK(items[0].internet_message_id == value[0].at("internetMessageId").get<std::string>());
    CHECK(items[0].sha256.empty());
    CHECK(items[0].sha256_rule.empty());
    // The mailbox check and one listing, without body in $select, and still the
    // Prefer header (ImmutableId).
    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 2);
    CHECK(gets[0].url == inbox_url());
    CHECK(gets[1].url == mail_list_url(false));
    CHECK(gets[1].headers.at("Prefer") == kPrefer);
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
        message.at("body").at("content").get<std::string>(),
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

// ---- W3.2: the mailbox check, the checker's fields and read_ms ----------------------------

TEST_CASE("list_mail runs the guard's mailbox check first; a refusal lists nothing",
          "[graph][targets]")
{
    const json no_id = [] {
        json fixture = load_fixture_json("graph", "mailbox-inbox-200");
        fixture["body"].erase("id");
        return fixture;
    }();
    struct Row {
        std::string name;
        json inbox;
        std::string kind;
        std::string contains;
    };
    const Row row = GENERATE_COPY(
        Row{"403: outside the Exchange scope",
            load_fixture_json("graph", "mailbox-inbox-403-exchange"), "WrongTargetError",
            "Graph refused the Worker app the Inbox of the mailbox test_mailbox names (403)"},
        Row{"an Inbox without an id", no_id, "WrongTargetError",
            "has no id; the Worker can't tell the mailbox is there"},
        Row{"404: no such user", load_fixture_json("graph", "messages-404-unknown-user"),
            "NotFoundError", "ErrorInvalidUser"});
    const bool hash = GENERATE(true, false);
    CAPTURE(row.name, hash);
    Lab lab;
    lab.serve(inbox_url(), row.inbox);
    lab.serve_file(mail_list_url(hash), "mail-list-200-one-item");
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = hash;
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const Caught caught = catch_error([&] { reader.list_mail(); });

    CHECK(caught.kind == row.kind);
    CHECK_THAT(caught.what, ContainsSubstring(row.contains));
    // The check alone: no message listing was asked for.
    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 1);
    CHECK(gets[0].url == inbox_url());
    CHECK(lab.gets(mail_list_url(hash)) == 0);
}

TEST_CASE("the listings ask for exactly the fields W3.2 checks", "[graph][targets]")
{
    // Spelled out here, not taken from graph_lab.hpp, so a change to either shows.
    const bool hash = GENERATE(true, false);
    CAPTURE(hash);
    Lab lab;
    const std::string mail = kGraph + "/users/" + lab_values().mailbox +
                             "/mailFolders/inbox/messages?$select=id,subject,from,sentDateTime,"
                             "receivedDateTime,createdDateTime,internetMessageId" +
                             (hash ? ",body" : "") + "&$top=100";
    const std::string children =
        "/children?$select=id,name,size,cTag,createdDateTime,lastModifiedDateTime,file,folder"
        "&$top=200";
    lab.graph_http.on(HttpMethod::get, mail, {page_of(json::array())});
    lab.serve_file(drive_url(), "restoretarget-drive-200");
    lab.graph_http.on(HttpMethod::get,
                      kGraph + "/drives/" + lab_values().library_id + "/root" + children,
                      {page_of(json::array())});
    lab.serve_file(folder_url(), "onedrive-folder-200");
    lab.graph_http.on(HttpMethod::get,
                      kGraph + "/drives/" + lab_values().onedrive_drive_id + "/items/" +
                          lab_values().folder_id + children,
                      {page_of(json::array())});
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = hash;
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    CHECK(reader.list_all().empty());

    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 6);
    CHECK(gets[1].url == mail);
    CHECK(gets[1].url == mail_list_url(hash));
    CHECK(gets[3].url == library_children_url());
    CHECK(gets[5].url == folder_children_url());
}

TEST_CASE("a mail's sender name, sent and created times are read when Graph lists them",
          "[graph][targets]")
{
    json value = messages_of("mail-list-200-one-item");
    value[0]["sentDateTime"] = "2026-09-28T18:06:20Z";
    value[0]["createdDateTime"] = "2026-09-30T21:44:01Z";
    value[0]["from"]["emailAddress"]["name"] = "Sender Name";
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(value)});

    const std::vector<FoundItem> items = lab.reader().list_mail();

    REQUIRE(items.size() == 1);
    CHECK(items[0].sender_name == std::optional<std::string>{"Sender Name"});
    CHECK(items[0].sent_at == std::optional<std::string>{"2026-09-28T18:06:20Z"});
    CHECK(items[0].created_at == std::optional<std::string>{"2026-09-30T21:44:01Z"});
    CHECK(items[0].sender ==
          value[0].at("from").at("emailAddress").at("address").get<std::string>());
    CHECK_FALSE(items[0].ctag);
    CHECK_FALSE(items[0].modified_at);
    CHECK_FALSE(items[0].listed_size);
    CHECK(items[0].read_ms == 0);
}

TEST_CASE("a mail field that is missing or not a string is left empty", "[graph][targets]")
{
    using Edit = std::function<void(json&)>;
    using Empty = std::function<bool(const FoundItem&)>;
    struct Row {
        std::string name;
        Edit edit;
        Empty empty;
    };
    const auto set = [](const std::string& key, const json& to) {
        return Edit{[key, to](json& m) { m[key] = to; }};
    };
    const auto set_name = [](const json& to) {
        return Edit{[to](json& m) { m["from"]["emailAddress"]["name"] = to; }};
    };
    const Empty no_name = [](const FoundItem& i) { return !i.sender_name; };
    const Empty no_sent = [](const FoundItem& i) { return !i.sent_at; };
    const Empty no_created = [](const FoundItem& i) { return !i.created_at; };
    const Row row = GENERATE_COPY(
        Row{"a sender with an address and no name",
            [](json& m) { m["from"]["emailAddress"].erase("name"); }, no_name},
        Row{"a name that is a number", set_name(7), no_name},
        Row{"a name that is null", set_name(nullptr), no_name},
        Row{"a name that is an object", set_name(json::object()), no_name},
        Row{"emailAddress not an object", [](json& m) { m["from"]["emailAddress"] = "a@b"; },
            no_name},
        Row{"sentDateTime missing", [](json& m) { m.erase("sentDateTime"); }, no_sent},
        Row{"sentDateTime a number", set("sentDateTime", 1), no_sent},
        Row{"sentDateTime null", set("sentDateTime", nullptr), no_sent},
        Row{"createdDateTime missing", [](json& m) { m.erase("createdDateTime"); }, no_created},
        Row{"createdDateTime an array", set("createdDateTime", json::array()), no_created},
        Row{"createdDateTime false", set("createdDateTime", false), no_created});
    CAPTURE(row.name);
    json value = messages_of("mail-list-200-one-item");
    value[0]["sentDateTime"] = "2026-09-28T18:06:20Z";
    value[0]["createdDateTime"] = "2026-09-30T21:44:01Z";
    row.edit(value[0]);
    Lab lab;
    lab.graph_http.on(HttpMethod::get, mail_list_url(), {page_of(value)});

    const std::vector<FoundItem> items = lab.reader().list_mail();

    REQUIRE(items.size() == 1);
    CHECK(row.empty(items[0]));
    // The rest of the message is still read.
    CHECK(items[0].id == value[0].at("id").get<std::string>());
    CHECK(items[0].received_at == value[0].at("receivedDateTime").get<std::string>());
}

TEST_CASE("a file's cTag, created and modified times are read when Graph lists them",
          "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    const bool hash = GENERATE(true, false);
    CAPTURE(at.name, hash);
    json file = file_of(at);
    file["cTag"] = "\"c:{made-up},2\"";
    file["createdDateTime"] = "2026-09-28T18:06:30Z";
    file["lastModifiedDateTime"] = "2026-09-30T21:44:05Z";
    Lab lab;
    serve_location(lab, at, page_of(json::array({file})));
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = hash;
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = list(reader, at);

    REQUIRE(items.size() == 1);
    CHECK(items[0].ctag == file.at("cTag").get<std::string>());
    CHECK(items[0].created_at == std::optional<std::string>{"2026-09-28T18:06:30Z"});
    CHECK(items[0].modified_at == std::optional<std::string>{"2026-09-30T21:44:05Z"});
    CHECK(items[0].listed_size == file.at("size").get<std::uint64_t>());
    CHECK_FALSE(items[0].sender_name);
    CHECK_FALSE(items[0].sent_at);
}

TEST_CASE("a file field that is missing or not a string is left empty", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    const std::string key =
        GENERATE(as<std::string>{}, "cTag", "createdDateTime", "lastModifiedDateTime");
    // "erase": the key removed; otherwise the value it is set to.
    const json to = GENERATE(json("erase"), json(5), json(nullptr), json::object());
    CAPTURE(at.name, key, to.dump());
    json file = file_of(at);
    file["cTag"] = "\"c:{X},1\"";
    file["createdDateTime"] = "2026-09-28T18:06:30Z";
    file["lastModifiedDateTime"] = "2026-09-30T21:44:05Z";
    if (to == "erase") {
        file.erase(key);
    } else {
        file[key] = to;
    }
    Lab lab;
    serve_location(lab, at, page_of(json::array({file})));
    TargetReader reader = lab.reader();

    const std::vector<FoundItem> items = list(reader, at);

    REQUIRE(items.size() == 1);
    CHECK(items[0].ctag.has_value() == (key != "cTag"));
    CHECK(items[0].created_at.has_value() == (key != "createdDateTime"));
    CHECK(items[0].modified_at.has_value() == (key != "lastModifiedDateTime"));
    CHECK(items[0].sha256 == rp::sha256_hex(bytes_of(at)));
}

namespace {

// A clock that moves 5 ms each time it is read; a test may move it further.
struct SteppingClock {
    std::chrono::steady_clock::time_point at{};
    int reads = 0;

    std::function<std::chrono::steady_clock::time_point()> function()
    {
        return [this] {
            ++reads;
            const auto now = at;
            at += 5ms;
            return now;
        };
    }
};

// A Graph reply of W3.2's live run 1 (tests/fixtures/recordings/w32-live-run1/),
// recorded after the restore with the wider $select. Its own request line is
// the URL it is served on.
json live_run1_reply(const std::string& file)
{
    return load_fixture_json("recordings/w32-live-run1/graph", file);
}

void serve_recorded(Lab& lab, const json& fixture)
{
    lab.graph_http.on(HttpMethod::get,
                      "https://graph.microsoft.com" + fixture.at("request").get<std::string>().substr(4),
                      {to_response(fixture)});
}

} // namespace

TEST_CASE("Graph lists the fields W3.2 checks live: a mail's sent and created times, a file's "
          "cTag, created and modified times",
          "[graph][targets]")
{
    // Every message and file of the after-restore listings carries them, and
    // each lands in its FoundItem as Graph gave it.
    Lab lab;
    const json mail = live_run1_reply("013-get-v1-0-users-restoretest-restoreprooflab-onmicrosoft-com-mailf");
    const json library = live_run1_reply("015-get-v1-0-drives-b-xqgi-ndr6ekvpkcbib2y65nzyk4ozjvns-7ncroj5omdbu");
    const json folder = live_run1_reply("020-get-v1-0-drives-b-wa9gbfhleuitgaluxbfonbr-z5getdherm5pj6bmwyxfzj");
    serve_recorded(lab, mail);
    serve_recorded(lab, library);
    serve_recorded(lab, folder);
    lab.serve_file(drive_url(), "restoretarget-drive-200");
    lab.serve_file(folder_url(), "onedrive-folder-200");

    const std::vector<FoundItem> mails = lab.reader().list_mail();
    const json& messages = mail.at("body").at("value");
    REQUIRE(mails.size() == 5);
    REQUIRE(messages.size() == 5);
    for (std::size_t i = 0; i < mails.size(); ++i) {
        CAPTURE(i);
        REQUIRE(messages[i].contains("sentDateTime"));
        REQUIRE(messages[i].contains("createdDateTime"));
        CHECK(mails[i].id == messages[i].at("id").get<std::string>());
        CHECK(mails[i].sent_at == messages[i].at("sentDateTime").get<std::string>());
        CHECK(mails[i].created_at == messages[i].at("createdDateTime").get<std::string>());
        CHECK(mails[i].sender_name ==
              messages[i].at("from").at("emailAddress").at("name").get<std::string>());
        CHECK(mails[i].internet_message_id ==
              messages[i].at("internetMessageId").get<std::string>());
        CHECK(mails[i].sha256_rule == "text-v1");
    }

    // Without hashing, as the before snapshot reads them: nothing downloaded.
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = false;
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);
    const std::vector<std::pair<std::vector<FoundItem>, json>> listings{
        {reader.list_sharepoint(), library.at("body").at("value")},
        {reader.list_onedrive(), folder.at("body").at("value")},
    };
    for (const auto& [items, value] : listings) {
        REQUIRE(items.size() == 3);
        REQUIRE(value.size() == 3);
        for (std::size_t i = 0; i < items.size(); ++i) {
            CAPTURE(value[i].at("name").get<std::string>());
            REQUIRE(value[i].contains("cTag"));
            REQUIRE(value[i].contains("createdDateTime"));
            REQUIRE(value[i].contains("lastModifiedDateTime"));
            CHECK(items[i].name == value[i].at("name").get<std::string>());
            CHECK(items[i].ctag == value[i].at("cTag").get<std::string>());
            CHECK(items[i].created_at == value[i].at("createdDateTime").get<std::string>());
            CHECK(items[i].modified_at == value[i].at("lastModifiedDateTime").get<std::string>());
            CHECK(items[i].listed_size == value[i].at("size").get<std::uint64_t>());
        }
    }
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("read_ms is each file's download, hash and on_file time", "[graph][targets]")
{
    const FileLocation at = GENERATE(sharepoint_location(), onedrive_location());
    const bool with_on_file = GENERATE(false, true);
    CAPTURE(at.name, with_on_file);
    const json file = file_of(at);
    const std::string id = file.at("id").get<std::string>();
    // A second file: its own download, its own time.
    json second = file;
    second["id"] = id.substr(0, id.size() - 1) + "Z";
    Lab lab;
    serve_location(lab, at, page_of(json::array({file, second})));
    lab.graph_http.on(HttpMethod::get, content_url(at, second.at("id").get<std::string>()),
                      {load_fixture("graph", at.content_fixture)});
    SteppingClock clock;
    TargetReaderOptions options = lab.reader_options();
    options.clock = clock.function();
    std::vector<std::int64_t> seen_ms;
    if (with_on_file) {
        // on_file's own time counts: 100 ms the first time, 30 ms the second.
        options.on_file = [&clock, &seen_ms](const FoundItem& item, std::string_view) {
            seen_ms.push_back(item.read_ms);
            clock.at += seen_ms.size() == 1 ? 100ms : 30ms;
        };
    }
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = list(reader, at);

    REQUIRE(items.size() == 2);
    // Read once before the download and once after on_file: 5 ms apart, plus on_file's.
    CHECK(items[0].read_ms == (with_on_file ? 105 : 5));
    CHECK(items[1].read_ms == (with_on_file ? 35 : 5));
    CHECK(clock.reads == 4);
    // on_file sees the item before its time is known.
    CHECK(seen_ms ==
          (with_on_file ? std::vector<std::int64_t>{0, 0} : std::vector<std::int64_t>{}));
}

TEST_CASE("read_ms is 0 for a mail and for a file not hashed, whose clock isn't read",
          "[graph][targets]")
{
    const bool hash = GENERATE(true, false);
    CAPTURE(hash);
    Lab lab;
    lab.serve_file(mail_list_url(hash), "mail-list-200-one-item");
    serve_location(lab, sharepoint_location());
    serve_location(lab, onedrive_location());
    SteppingClock clock;
    TargetReaderOptions options = lab.reader_options();
    options.hash_items = hash;
    options.clock = clock.function();
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = reader.list_all();

    REQUIRE(items.size() == 3);
    CHECK(items[0].read_ms == 0);
    CHECK(items[1].read_ms == (hash ? 5 : 0));
    CHECK(items[2].read_ms == (hash ? 5 : 0));
    CHECK(clock.reads == (hash ? 4 : 0));
}

TEST_CASE("without a clock read_ms is measured on the steady clock", "[graph][targets]")
{
    CHECK_FALSE(TargetReaderOptions{}.clock);
    Lab lab;
    serve_location(lab, sharepoint_location());
    TargetReaderOptions options = lab.reader_options();
    options.clock = nullptr;
    TargetReader reader(*lab.graph, lab.dl_http,
                        rp::connector::RestoreTargets::from_config(lab_config()), options);

    const std::vector<FoundItem> items = reader.list_sharepoint();

    REQUIRE(items.size() == 1);
    CHECK(items[0].read_ms >= 0);
    CHECK(items[0].read_ms < 60'000);
}

// ---- the live test's output line ----------------------------------------------------------

TEST_CASE("the live test's line replaces control characters in Graph's text", "[graph][targets]")
{
    FoundItem mail;
    mail.type = ItemType::mail;
    mail.id = "AAk=";
    mail.subject = "a\rb\nc\xE2\x80\xAE" "d";
    mail.sha256 = "ab";
    mail.sha256_rule = "text-v1";
    CHECK(rp::test::found_item_line(mail) == "mail  AAk=  a b c d  -  ab (text-v1)");

    FoundItem file;
    file.type = ItemType::onedrive;
    file.id = "01X";
    file.name = "x\x1b[2J.txt";
    file.size_bytes = 12;
    file.sha256 = "cd";
    file.sha256_rule = "bytes";
    CHECK(rp::test::found_item_line(file) == "onedrive  01X  x [2J.txt  12  cd (bytes)");
}
