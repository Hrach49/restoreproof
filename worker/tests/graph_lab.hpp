#pragma once

// The lab's restore targets as W2.2's recorded Graph replies show them, for
// the tests of rp::graph::TargetReader (graph_targets_test.cpp) and of
// `rpworker graph list` (graph_command_test.cpp). Every lab value (the drive,
// folder and site IDs, the mailbox) is read from the fixtures in
// tests/fixtures/graph/, so a re-recording in another tenant still works; the
// canaries' own IDs appear nowhere in the Worker. No Catch2 assertions in
// here: FakeHttpClient's handlers may call these on the client's threads.

#include "fake_http_client.hpp"
#include "test_certs.hpp"

#include <rp/config.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_targets.hpp>
#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>

namespace rp::test::graph_lab {

using namespace std::chrono_literals;

inline const std::string kTenant = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";
inline const std::string kClient = "737da5ef-baf2-4198-b009-e160d8ca77c9";
inline const std::string kTokenUrl =
    "https://login.microsoftonline.com/" + kTenant + "/oauth2/v2.0/token";
inline const std::string kGraph = "https://graph.microsoft.com/v1.0";

// The wall clock the tests' certificates and assertions are made for.
inline const std::chrono::system_clock::time_point kNow =
    std::chrono::sys_days{std::chrono::year{2026} / 9 / 28} + 12h;
inline constexpr const char* kPfxPassword = "Sentinel-Targets-PFX-Password-3b9d";

// Without the body when nothing is hashed (`graph list` without --hash).
inline const std::string kMailSelect = "?$select=id,subject,from,receivedDateTime,internetMessageId";
inline const std::string kChildrenQuery = "/children?$select=id,name,size,file,folder&$top=200";
inline const std::string kPrefer = std::string{rp::graph::kMailPrefer};

// The Worker app's certificate as RP_GRAPH_CERT_PFX_BASE64 holds it, valid at kNow.
inline const std::string& pfx_base64()
{
    static const std::string pfx = rp::test::to_base64(rp::test::make_pfx(
        rp::test::make_client_cert("RestoreProof Worker",
                                   rp::test::ClientCertOptions{
                                       .now = std::chrono::system_clock::to_time_t(kNow)}),
        kPfxPassword));
    return pfx;
}

// The recorded token reply, its access token "token-1".
inline HttpResponse token_response()
{
    nlohmann::json fixture = load_fixture_json("graph", "token-200");
    fixture["body"]["access_token"] = "token-1";
    return to_response(fixture);
}

// "https://<host>/..." -> host
inline std::string host_of(const std::string& url)
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

inline const Lab_values& lab_values()
{
    static const Lab_values values = [] {
        Lab_values out;
        const nlohmann::json drive = load_fixture_json("graph", "restoretarget-drive-200").at("body");
        out.site_id = host_of(drive.at("webUrl").get<std::string>()) + "," +
                      drive.at("sharePointIds").at("siteId").get<std::string>() + "," +
                      drive.at("sharePointIds").at("webId").get<std::string>();
        out.library_id = drive.at("id").get<std::string>();
        const nlohmann::json folder = load_fixture_json("graph", "onedrive-folder-200").at("body");
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

// A Config holding the lab's five target values and nothing else.
inline rp::Config lab_config()
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

inline std::string drive_url()
{
    return kGraph + "/drives/" + lab_values().library_id +
           "?$select=id,name,driveType,webUrl,sharePointIds";
}
inline std::string library_children_url()
{
    return kGraph + "/drives/" + lab_values().library_id + "/root" + kChildrenQuery;
}
inline std::string folder_url()
{
    return kGraph + "/drives/" + lab_values().onedrive_drive_id + "/items/" +
           lab_values().folder_id + "?$select=id,name,folder,parentReference,sharepointIds";
}
// The guard's mailbox check (W2.7).
inline std::string inbox_url(const std::string& mailbox = lab_values().mailbox)
{
    return kGraph + "/users/" + mailbox + "/mailFolders/inbox?$select=id";
}
inline std::string folder_children_url()
{
    return kGraph + "/drives/" + lab_values().onedrive_drive_id + "/items/" +
           lab_values().folder_id + kChildrenQuery;
}
inline std::string mail_list_url(bool with_body = true)
{
    return kGraph + "/users/" + lab_values().mailbox + "/mailFolders/inbox/messages" +
           kMailSelect + (with_body ? ",body" : "") + "&$top=100";
}

// The messages of a recorded listing.
inline nlohmann::json messages_of(const std::string& name)
{
    return load_fixture_json("graph", name).at("body").at("value");
}

// A listing page holding `value`, with `next_link` if given.
inline HttpResponse page_of(const nlohmann::json& value,
                            const std::optional<std::string>& next_link = std::nullopt)
{
    nlohmann::json body = {{"value", value}};
    if (next_link) {
        body["@odata.nextLink"] = *next_link;
    }
    return make_response(200, body.dump());
}

// One file location as the tests serve it: its guard, listing and content fixtures.
struct FileLocation {
    std::string name; // "sharepoint" or "onedrive"
    rp::graph::ItemType type;
    std::string drive;
    std::string guard_url;
    std::string guard_fixture;
    std::string children_url;
    std::string one_item_fixture;
    std::string content_fixture;
    std::string location; // as in messages
    const rp::graph::Grant* grant;
};

inline FileLocation sharepoint_location()
{
    return {"sharepoint",
            rp::graph::ItemType::sharepoint,
            lab_values().library_id,
            drive_url(),
            "restoretarget-drive-200",
            library_children_url(),
            "restoretarget-children-200-one-item",
            "restoretarget-content-302",
            "the RestoreTarget library",
            &rp::graph::kSitesReadGrant};
}

inline FileLocation onedrive_location()
{
    return {"onedrive",
            rp::graph::ItemType::onedrive,
            lab_values().onedrive_drive_id,
            folder_url(),
            "onedrive-folder-200",
            folder_children_url(),
            "onedrive-children-200-one-item",
            "onedrive-content-302",
            "the test OneDrive folder",
            &rp::graph::kOneDriveReadGrant};
}

inline std::string content_url(const FileLocation& at, const std::string& id)
{
    return kGraph + "/drives/" + at.drive + "/items/" + id + "/content";
}

// The one file of the location's recorded one-item listing.
inline nlohmann::json file_of(const FileLocation& at)
{
    return load_fixture_json("graph", at.one_item_fixture).at("body").at("value").at(0);
}

// The download link of the location's recorded 302.
inline std::string location_of(const FileLocation& at)
{
    return load_fixture_json("graph", at.content_fixture)
        .at("headers")
        .at("Location")
        .get<std::string>();
}

// The file's bytes, as many as the listing says.
inline std::string bytes_of(const FileLocation& at)
{
    return std::string(file_of(at).at("size").get<std::size_t>(), 'r');
}

// Serves the location's guard on `graph`, `children` as its listing and, for
// its one file, the recorded 302 on `graph` and a download of the listed size
// on `download`.
inline void serve_location(FakeHttpClient& graph, FakeHttpClient& download, const FileLocation& at,
                           const HttpResponse& children)
{
    graph.on(HttpMethod::get, at.guard_url, {load_fixture("graph", at.guard_fixture)});
    graph.on(HttpMethod::get, at.children_url, {children});
    const std::string id = file_of(at).at("id").get<std::string>();
    graph.on(HttpMethod::get, content_url(at, id), {load_fixture("graph", at.content_fixture)});
    download.on(HttpMethod::get, location_of(at),
                {make_response(200, bytes_of(at), "application/octet-stream")});
}

inline void serve_location(FakeHttpClient& graph, FakeHttpClient& download, const FileLocation& at)
{
    serve_location(graph, download, at, load_fixture("graph", at.one_item_fixture));
}

} // namespace rp::test::graph_lab
