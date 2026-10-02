// W3.4: emptying the three restore targets (rp/cleaner.hpp). Graph is one
// FakeHttpClient; the guard's checks are served from the recorded drive,
// folder and Inbox replies, the listings and deletes from the hand-written
// w34-* fixtures (tests/fixtures/graph/README.md). Every lab value is read from
// the fixtures. The fake records which IDs each listing served, and every test
// ends by checking that each write the Cleaner sent was a permanentDelete or
// DELETE of one of them, in its own target: the Cleaner's one promise. The
// guard's refusals are edits of the recorded replies, never a canary's ID.
// GraphClient::remove is reached only through the Cleaner (the source scan in
// graph_client_test.cpp), so its write path is tested here too.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"

#include <rp/cleaner.hpp>
#include <rp/client_assertion.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;

namespace {

using nlohmann::json;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::graph::Cleaner;
using rp::graph::CleanupResult;
using rp::graph::CleanupWhen;
using rp::graph::GraphClient;
using rp::graph::GraphClientOptions;
using rp::graph::TargetCleanup;
using rp::test::FakeHttpClient;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using rp::test::to_response;
using namespace rp::test::graph_lab;

const std::string kFileQuery =
    "?$select=id,name,eTag,file,folder,package,remoteItem,root,parentReference&$top=200";

enum class Which { mail, sharepoint, onedrive };

std::string name_of(Which which)
{
    switch (which) {
    case Which::mail:
        return "mail";
    case Which::sharepoint:
        return "sharepoint";
    case Which::onedrive:
        return "onedrive";
    }
    return "?";
}

const TargetCleanup& of(const CleanupResult& result, Which which)
{
    return which == Which::mail         ? result.mail
           : which == Which::sharepoint ? result.sharepoint
                                        : result.onedrive;
}

// The listing the Cleaner asks for.
std::string listing_url(Which which)
{
    const Lab_values& v = lab_values();
    switch (which) {
    case Which::mail:
        return kGraph + "/users/" + v.mailbox + "/mailFolders/inbox/messages?$select=id&$top=100";
    case Which::sharepoint:
        return kGraph + "/drives/" + v.library_id + "/root/children" + kFileQuery;
    case Which::onedrive:
        break;
    }
    return kGraph + "/drives/" + v.onedrive_drive_id + "/items/" + v.folder_id + "/children" +
           kFileQuery;
}

// The URL of the write that deletes `id` in `which`.
std::string write_url(Which which, const std::string& id)
{
    const Lab_values& v = lab_values();
    switch (which) {
    case Which::mail:
        return kGraph + "/users/" + v.mailbox + "/messages/" + id + "/permanentDelete";
    case Which::sharepoint:
        return kGraph + "/drives/" + v.library_id + "/items/" + id;
    case Which::onedrive:
        break;
    }
    return kGraph + "/drives/" + v.onedrive_drive_id + "/items/" + id;
}

HttpMethod write_method(Which which)
{
    return which == Which::mail ? HttpMethod::post : HttpMethod::del;
}

// The recorded-shape listing of two items, as JSON (its "value" is what the
// tests edit).
json two_items(Which which)
{
    const char* name = which == Which::mail         ? "w34-mail-list-200-two"
                       : which == Which::sharepoint ? "w34-restoretarget-children-200-two"
                                                    : "w34-onedrive-children-200-two";
    return load_fixture_json("graph", name);
}

// The fixture's body with its value replaced.
HttpResponse listing_of(const json& fixture, const json& value)
{
    json edited = fixture;
    edited["body"]["value"] = value;
    return to_response(edited);
}

HttpResponse empty_listing(Which which)
{
    return listing_of(two_items(which), json::array());
}

std::string id_at(const json& fixture, std::size_t i)
{
    return fixture.at("body").at("value").at(i).at("id").get<std::string>();
}

HttpResponse deleted(Which which)
{
    return load_fixture("graph",
                        which == Which::mail ? "w34-mail-permanentdelete-204" : "w34-file-delete-204");
}

// Graph and its token route as a test sees them; the three guards answer as
// recorded and the three targets list empty until a test says otherwise.
struct Lab {
    Lab()
    {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("cleaner_test", sink);
        logger->set_level(spdlog::level::trace);
        logger->set_formatter(std::make_unique<spdlog::pattern_formatter>(
            "%l %v", spdlog::pattern_time_type::utc, "\n"));
        http.on(HttpMethod::post, kTokenUrl, {token_response()});
        GraphClientOptions options;
        options.logger = logger;
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
        for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
            list(which, {empty_listing(which)});
        }
    }

    // Serves `pages` in turn at `url` (the last one repeating), and remembers
    // every ID they held as listed in `which`. No assertions: this runs on the
    // client's thread.
    void serve_listing(Which which, const std::string& url, std::vector<HttpResponse> pages)
    {
        auto state = std::make_shared<std::pair<std::size_t, std::vector<HttpResponse>>>(
            0, std::move(pages));
        http.on(HttpMethod::get, url, [this, which, state](const HttpRequest&) {
            const std::lock_guard lock(mutex);
            HttpResponse page =
                state->second[std::min(state->first, state->second.size() - 1)];
            ++state->first;
            const json body = json::parse(page.body, nullptr, false);
            if (body.is_object() && body.contains("value") && body["value"].is_array()) {
                for (const json& entry : body["value"]) {
                    if (entry.is_object() && entry.contains("id") && entry["id"].is_string()) {
                        listed[which].insert(entry["id"].get<std::string>());
                    }
                }
            }
            return page;
        });
    }

    void list(Which which, std::vector<HttpResponse> pages)
    {
        serve_listing(which, listing_url(which), std::move(pages));
    }

    // Answers the write that deletes `id` in `which` with `responses` in turn.
    void on_delete(Which which, const std::string& id, std::vector<HttpResponse> responses)
    {
        http.on(write_method(which), write_url(which, id), std::move(responses));
    }

    // Both items of the two-item listing are served once, then the target is
    // empty, and both deletes answer 204.
    void serve_two(Which which)
    {
        const json fixture = two_items(which);
        list(which, {to_response(fixture), empty_listing(which)});
        for (std::size_t i = 0; i < 2; ++i) {
            on_delete(which, id_at(fixture, i), {deleted(which)});
        }
    }

    Cleaner cleaner()
    {
        rp::graph::CleanerOptions options;
        options.logger = logger;
        return Cleaner(*graph, rp::connector::RestoreTargets::from_config(lab_config()), options);
    }

    CleanupResult clean(CleanupWhen when = CleanupWhen::after_run)
    {
        Cleaner c = cleaner();
        return c.clean(when);
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    // Every request that wasn't a GET or the token's.
    std::vector<HttpRequest> writes() const
    {
        std::vector<HttpRequest> out;
        for (const HttpRequest& request : http.requests()) {
            if (request.method != HttpMethod::get && request.url != kTokenUrl) {
                out.push_back(request);
            }
        }
        return out;
    }

    std::vector<HttpRequest> writes_to(Which which) const
    {
        std::vector<HttpRequest> out;
        for (const HttpRequest& request : writes()) {
            const auto target = target_of(request.url);
            if (target && target->first == which) {
                out.push_back(request);
            }
        }
        return out;
    }

    // The target a write URL deletes in, and the ID it names.
    static std::optional<std::pair<Which, std::string>> target_of(const std::string& url)
    {
        for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
            const std::string pattern = write_url(which, "*");
            const std::string head = pattern.substr(0, pattern.find('*'));
            const std::string tail = pattern.substr(pattern.find('*') + 1);
            if (url.starts_with(head) && url.ends_with(tail) &&
                url.size() > head.size() + tail.size()) {
                return std::pair{which,
                                 url.substr(head.size(), url.size() - head.size() - tail.size())};
            }
        }
        return std::nullopt;
    }

    // Each write is the right method and shape for its target and deletes an
    // ID that target's listing served; a file's carries an If-Match, a mail's
    // the Prefer and no body.
    void require_only_listed_writes()
    {
        const std::lock_guard lock(mutex);
        for (const HttpRequest& request : writes()) {
            INFO(request.url);
            const auto target = target_of(request.url);
            REQUIRE(target.has_value());
            const auto& [which, id] = *target;
            REQUIRE(request.method == write_method(which));
            if (which == Which::mail) {
                CHECK(request.headers.at("Prefer") == kPrefer);
                CHECK(request.body.empty());
                CHECK_FALSE(request.headers.contains("If-Match"));
            } else {
                CHECK_FALSE(request.headers.at("If-Match").empty());
            }
            CHECK(listed[which].contains(id));
        }
    }

    std::size_t gets(const std::string& url) const { return http.count(HttpMethod::get, url); }

    FakeHttpClient http;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    std::unique_ptr<GraphClient> graph;
    std::mutex mutex;
    std::map<Which, std::set<std::string>> listed;
};

std::size_t occurrences(const std::string& text, const std::string& what)
{
    std::size_t n = 0;
    for (std::size_t at = text.find(what); at != std::string::npos; at = text.find(what, at + 1)) {
        ++n;
    }
    return n;
}

void require_cleaned(const TargetCleanup& t, std::size_t n)
{
    CHECK(t.error_code.empty());
    CHECK(t.found == n);
    CHECK(t.deleted == n);
    CHECK(t.gone == 0);
    CHECK(t.left == 0);
    CHECK(t.skipped == 0);
    CHECK(t.rounds == 1);
    CHECK(t.ok());
}

void require_stopped(const TargetCleanup& t, const std::string& code, unsigned rounds = 1)
{
    CHECK(t.error_code == code);
    CHECK(t.rounds == rounds);
    CHECK_FALSE(t.ok());
}

} // namespace

// ---- failure paths -------------------------------------------------------------------------

TEST_CASE("a target the guard refuses is never listed or deleted in, and the others are cleaned",
          "[cleaner][guard]")
{
    const Which refused = GENERATE(Which::mail, Which::sharepoint, Which::onedrive);
    INFO(name_of(refused));
    Lab lab;
    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        lab.serve_two(which);
    }
    switch (refused) {
    case Which::mail:
        // Outside the Exchange scope: another mailbox.
        lab.http.on(HttpMethod::get, inbox_url(),
                    {load_fixture("graph", "mailbox-inbox-403-exchange")});
        break;
    case Which::sharepoint: {
        json drive = load_fixture_json("graph", "restoretarget-drive-200");
        drive["body"]["name"] = "RestoreTest";
        lab.http.on(HttpMethod::get, drive_url(), {to_response(drive)});
        break;
    }
    case Which::onedrive: {
        json folder = load_fixture_json("graph", "onedrive-folder-200");
        folder["body"]["name"] = "RestoreTest";
        lab.http.on(HttpMethod::get, folder_url(), {to_response(folder)});
        break;
    }
    }

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, refused);
    require_stopped(t, "target_guard");
    CHECK(t.found == 0);
    CHECK(t.deleted == 0);
    CHECK(lab.gets(listing_url(refused)) == 0);
    CHECK(lab.writes_to(refused).empty());
    const std::string log = lab.log();
    CHECK(occurrences(log, "SECURITY") == 1);
    CHECK_THAT(log, ContainsSubstring("critical SECURITY: cleanup: "));
    CHECK_THAT(log, ContainsSubstring("the Worker deletes only in"));
    CHECK_THAT(log, ContainsSubstring("; nothing was deleted\n"));
    for (const Which other : {Which::mail, Which::sharepoint, Which::onedrive}) {
        if (other != refused) {
            require_cleaned(of(result, other), 2);
        }
    }
    CHECK_FALSE(result.ok());
    lab.require_only_listed_writes();
}

TEST_CASE("a 403 on a delete is graph_permission naming the write grant, with no second round",
          "[cleaner][permission]")
{
    struct Row {
        Which which;
        const char* fixture;
        const rp::graph::Grant* grant;
        const char* method;
    };
    const Row row = GENERATE(
        Row{Which::mail, "w34-mail-permanentdelete-403-exchange", &rp::graph::kMailGrant, "POST"},
        Row{Which::sharepoint, "w34-file-delete-403-accessdenied", &rp::graph::kListWriteGrant,
            "DELETE"},
        Row{Which::onedrive, "w34-file-delete-403-accessdenied", &rp::graph::kOneDriveGrant,
            "DELETE"});
    INFO(name_of(row.which));
    Lab lab;
    const json fixture = two_items(row.which);
    lab.list(row.which, {to_response(fixture)});
    for (std::size_t i = 0; i < 2; ++i) {
        lab.on_delete(row.which, id_at(fixture, i), {load_fixture("graph", row.fixture)});
    }

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, row.which);
    require_stopped(t, "graph_permission");
    CHECK(t.found == 2);
    CHECK(t.deleted == 0);
    CHECK(t.left == 2);
    // The first refusal stops the target: one write, one listing.
    CHECK(lab.writes_to(row.which).size() == 1);
    CHECK(lab.gets(listing_url(row.which)) == 1);
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring(std::string{"Graph denied "} + row.method));
    CHECK_THAT(log, ContainsSubstring(std::string{row.grant->description}));
    CHECK_THAT(log, ContainsSubstring("stopped (graph_permission)"));
    for (const Which other : {Which::mail, Which::sharepoint, Which::onedrive}) {
        if (other != row.which) {
            CHECK(of(result, other).ok());
        }
    }
    lab.require_only_listed_writes();
}

TEST_CASE("a token Entra refuses stops every target as graph_auth, nothing deleted",
          "[cleaner][auth]")
{
    Lab lab;
    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        lab.serve_two(which);
    }
    lab.http.on(HttpMethod::post, kTokenUrl, {load_fixture("graph", "token-unknown-thumbprint-401")});

    const CleanupResult result = lab.clean();

    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        INFO(name_of(which));
        require_stopped(of(result, which), "graph_auth");
    }
    CHECK(lab.writes().empty());
    CHECK_FALSE(result.ok());
}

TEST_CASE("a ConfigError is config and anything else internal, its text never copied",
          "[cleaner][errors]")
{
    SECTION("a certificate the token request can't use")
    {
        Lab lab;
        lab.http.on(HttpMethod::post, kTokenUrl, [](const HttpRequest&) -> HttpResponse {
            throw rp::graph::CertificateError("the Worker app's certificate has expired");
        });
        const CleanupResult result = lab.clean();
        for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
            INFO(name_of(which));
            require_stopped(of(result, which), "config");
        }
        CHECK_THAT(lab.log(), ContainsSubstring("stopped (config): the Worker app's certificate"));
    }
    SECTION("an exception the Worker doesn't know, on one target")
    {
        Lab lab;
        lab.serve_two(Which::mail);
        lab.serve_two(Which::onedrive);
        lab.http.on(HttpMethod::get, listing_url(Which::sharepoint),
                    [](const HttpRequest&) -> HttpResponse {
                        throw std::runtime_error("sentinel-internal-5b7e");
                    });
        const CleanupResult result = lab.clean();
        require_stopped(result.sharepoint, "internal");
        require_cleaned(result.mail, 2);
        require_cleaned(result.onedrive, 2);
        const std::string log = lab.log();
        CHECK_THAT(log, ContainsSubstring("the RestoreTarget library: stopped (internal)\n"));
        CHECK_THAT(log, !ContainsSubstring("sentinel-internal-5b7e"));
        CHECK(to_json(result).dump().find("sentinel") == std::string::npos);
        lab.require_only_listed_writes();
    }
}

TEST_CASE("a TransientError ends round 1, and round 2 cleans", "[cleaner][transient]")
{
    const Which which = GENERATE(Which::mail, Which::sharepoint, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = two_items(which);
    // Round 1 lists both; its first delete gives up after five 503s. Round 2
    // lists both again, deletes them, and lists nothing.
    lab.list(which, {to_response(fixture), to_response(fixture), empty_listing(which)});
    const HttpResponse unavailable = load_fixture("graph", "messages-503-unavailable");
    lab.on_delete(which, id_at(fixture, 0),
                  {unavailable, unavailable, unavailable, unavailable, unavailable, deleted(which)});
    lab.on_delete(which, id_at(fixture, 1), {deleted(which)});

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.rounds == 2);
    CHECK(t.found == 2);
    CHECK(t.deleted == 2);
    CHECK(t.left == 0);
    CHECK(t.ok());
    CHECK(lab.writes_to(which).size() == 7);
    CHECK_THAT(lab.log(), ContainsSubstring("; one more round"));
    lab.require_only_listed_writes();
}

TEST_CASE("a TransientError in both rounds is graph_transient", "[cleaner][transient]")
{
    Lab lab;
    lab.http.on(HttpMethod::get, drive_url(), {load_fixture("graph", "messages-503-unavailable")});

    const CleanupResult result = lab.clean();

    require_stopped(result.sharepoint, "graph_transient", 2);
    CHECK(result.sharepoint.found == 0);
    CHECK(lab.gets(drive_url()) == 10);
    CHECK(result.mail.ok());
    CHECK(result.onedrive.ok());
}

TEST_CASE("a TransientError on round 1's last listing still gets round 2", "[cleaner][transient]")
{
    Lab lab;
    // An empty Inbox whose second listing gives up after five 503s: round 1
    // ends with nothing known to be left, so only the error calls round 2.
    const HttpResponse unavailable = load_fixture("graph", "messages-503-unavailable");
    lab.list(Which::mail, {empty_listing(Which::mail), unavailable, unavailable, unavailable,
                           unavailable, unavailable, empty_listing(Which::mail)});

    const CleanupResult result = lab.clean();

    CHECK(result.mail.error_code.empty());
    CHECK(result.mail.rounds == 2);
    CHECK(result.mail.ok());
    CHECK(lab.gets(listing_url(Which::mail)) == 8);
}

TEST_CASE("a 412 leaves the file to round 2, which lists it again and deletes it",
          "[cleaner][changed]")
{
    const Which which = GENERATE(Which::sharepoint, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = two_items(which);
    // The first file changed after it was listed (SharePoint rewrites Office
    // files): a new eTag in every later listing.
    json changed = fixture.at("body").at("value").at(0);
    changed["eTag"] = "\"{0A1B2C3D-0000-4000-8000-00000000ABCD},2\"";
    lab.list(which, {to_response(fixture), listing_of(fixture, json::array({changed})),
                     listing_of(fixture, json::array({changed})), empty_listing(which)});
    lab.on_delete(which, id_at(fixture, 0),
                  {load_fixture("graph", "w34-file-delete-412-resourcemodified"), deleted(which)});
    lab.on_delete(which, id_at(fixture, 1), {deleted(which)});

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.rounds == 2);
    CHECK(t.found == 2);
    CHECK(t.deleted == 2);
    CHECK(t.left == 0);
    CHECK(t.ok());
    const std::vector<HttpRequest> writes = lab.writes_to(which);
    REQUIRE(writes.size() == 3);
    CHECK(writes[0].headers.at("If-Match") ==
          fixture.at("body").at("value").at(0).at("eTag").get<std::string>());
    // Round 2 sends the eTag it listed, never round 1's.
    CHECK(writes[2].url == writes[0].url);
    CHECK(writes[2].headers.at("If-Match") == changed.at("eTag").get<std::string>());
    CHECK_THAT(lab.log(), ContainsSubstring("changed since it was listed"));
    lab.require_only_listed_writes();
}

TEST_CASE("a target still holding items after two rounds ends with them left",
          "[cleaner][left]")
{
    const Which which = GENERATE(Which::mail, Which::sharepoint, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = two_items(which);
    // The listing never empties (Graph lagging, or mail still arriving).
    lab.list(which, {to_response(fixture)});
    lab.on_delete(which, id_at(fixture, 0), {deleted(which)});
    lab.on_delete(which, id_at(fixture, 1), {deleted(which)});

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.rounds == 2);
    CHECK(t.found == 2);
    CHECK(t.deleted == 4);
    CHECK(t.left == 2);
    CHECK_FALSE(t.ok());
    CHECK_FALSE(result.ok());
    CHECK(lab.gets(listing_url(which)) == 4);
    CHECK_THAT(lab.log(), ContainsSubstring("left 2, skipped 0 in 2 round(s)"));
    lab.require_only_listed_writes();
}

TEST_CASE("Graph's 404 for a listed item counts it gone", "[cleaner][gone]")
{
    const Which which = GENERATE(Which::mail, Which::sharepoint, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = two_items(which);
    lab.list(which, {to_response(fixture), empty_listing(which)});
    lab.on_delete(which, id_at(fixture, 0),
                  {load_fixture("graph", which == Which::mail
                                             ? "w34-mail-permanentdelete-404-erroritemnotfound"
                                             : "w34-file-delete-404-itemnotfound")});
    lab.on_delete(which, id_at(fixture, 1), {deleted(which)});

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.deleted == 1);
    CHECK(t.gone == 1);
    CHECK(t.left == 0);
    CHECK(t.rounds == 1);
    CHECK(t.ok());
    lab.require_only_listed_writes();
}

TEST_CASE("a delete resent after a dropped connection and answered 404 counts as gone",
          "[cleaner][gone]")
{
    const Which which = GENERATE(Which::mail, Which::sharepoint);
    INFO(name_of(which));
    Lab lab;
    const json fixture = two_items(which);
    lab.list(which, {listing_of(fixture, json::array({fixture["body"]["value"][0]})),
                     empty_listing(which)});
    const HttpResponse not_found =
        load_fixture("graph", which == Which::mail ? "w34-mail-permanentdelete-404-erroritemnotfound"
                                                   : "w34-file-delete-404-itemnotfound");
    auto sent = std::make_shared<std::atomic<int>>(0);
    lab.http.on(write_method(which), write_url(which, id_at(fixture, 0)),
                [sent, not_found](const HttpRequest&) -> HttpResponse {
                    if (sent->fetch_add(1) == 0) {
                        // The first went out and was acted on; the answer was lost.
                        throw rp::HttpError("dropped", rp::TransportError::dropped, 0, 1);
                    }
                    return not_found;
                });

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.gone == 1);
    CHECK(t.deleted == 0);
    CHECK(t.ok());
    const std::vector<HttpRequest> writes = lab.writes_to(which);
    REQUIRE(writes.size() == 2);
    CHECK(writes[1].url == writes[0].url);
    lab.require_only_listed_writes();
}

TEST_CASE("a 401 on a delete gets one fresh token and the delete again", "[cleaner][auth]")
{
    const Which which = GENERATE(Which::mail, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = two_items(which);
    lab.list(which, {listing_of(fixture, json::array({fixture["body"]["value"][0]})),
                     empty_listing(which)});
    lab.on_delete(which, id_at(fixture, 0),
                  {load_fixture("graph", "api-invalid-token-401"), deleted(which)});

    const CleanupResult result = lab.clean();

    require_cleaned(of(result, which), 1);
    CHECK(lab.writes_to(which).size() == 2);
    CHECK(lab.http.count(HttpMethod::post, kTokenUrl) == 2);
    lab.require_only_listed_writes();
}

TEST_CASE("Graph's other answers to a delete stop the target as graph", "[cleaner][errors]")
{
    struct Row {
        const char* name;
        Which which;
        std::function<HttpResponse()> answer;
        const char* logged;
    };
    const Row row = GENERATE(
        Row{"a 200 to a file's DELETE", Which::sharepoint, [] { return make_response(200, "{}"); },
            "Graph DELETE"},
        Row{"a 302 to a file's DELETE", Which::onedrive,
            [] {
                HttpResponse r = make_response(302);
                r.headers["Location"] = "https://example.invalid/";
                return r;
            },
            "HTTP 302, where 204 was expected"},
        Row{"a 412 to a mail's permanentDelete", Which::mail,
            [] {
                json fixture = load_fixture_json("graph", "w34-file-delete-412-resourcemodified");
                return to_response(fixture);
            },
            "HTTP 412, where 204 was expected"},
        Row{"a 404 naming a missing mailbox", Which::mail,
            [] { return load_fixture("graph", "messages-404-unknown-user"); }, "ErrorInvalidUser"},
        Row{"a 404 without Graph's JSON", Which::sharepoint,
            [] { return make_response(404, "<html>Not Found</html>", "text/html"); },
            "Graph DELETE"});
    INFO(row.name);
    Lab lab;
    const json fixture = two_items(row.which);
    lab.list(row.which, {to_response(fixture)});
    lab.on_delete(row.which, id_at(fixture, 0), {row.answer()});

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, row.which);
    // Not transient: a second round can't change it.
    require_stopped(t, "graph");
    CHECK(t.deleted == 0);
    CHECK(lab.writes_to(row.which).size() == 1);
    CHECK_THAT(lab.log(), ContainsSubstring(row.logged));
    lab.require_only_listed_writes();
}

TEST_CASE("an entry that isn't a plain file in its place is skipped and never deleted",
          "[cleaner][skipped]")
{
    struct Row {
        const char* name;
        Which which;
        std::function<void(json& entry)> edit;
        const char* logged;
    };
    const auto both = [](const char* name, std::function<void(json&)> edit, const char* logged) {
        return std::vector<Row>{{name, Which::sharepoint, edit, logged},
                                {name, Which::onedrive, edit, logged}};
    };
    std::vector<Row> rows;
    const auto add = [&rows](std::vector<Row> more) {
        rows.insert(rows.end(), more.begin(), more.end());
    };
    add(both("a folder",
             [](json& e) {
                 e.erase("file");
                 e["folder"] = {{"childCount", 3}};
             },
             "skipped a folder"));
    add(both("a folder that also says file", [](json& e) { e["folder"] = {{"childCount", 0}}; },
             "skipped a folder"));
    add(both("a package", [](json& e) { e["package"] = {{"type", "oneNote"}}; },
             "skipped a package"));
    add(both("a remoteItem", [](json& e) { e["remoteItem"] = {{"id", "01ABC"}}; },
             "skipped a shortcut to another item"));
    add(both("a root", [](json& e) { e["root"] = json::object(); }, "skipped a drive's root"));
    add(both("no file facet", [](json& e) { e.erase("file"); }, "not a file"));
    add(both("a file facet that isn't an object", [](json& e) { e["file"] = "text/plain"; },
             "not a file"));
    add(both("no parentReference", [](json& e) { e.erase("parentReference"); },
             "names another drive"));
    add(both("another drive",
             [](json& e) { e["parentReference"]["driveId"] = "b!AnotherDrive0000000000"; },
             "names another drive"));
    add(both("its parent's ID",
             [](json& e) { e["id"] = e["parentReference"]["id"]; }, "its parent's ID"));
    add(both("no ID", [](json& e) { e.erase("id"); }, "an ID the Worker won't put in a URL"));
    add(both("an ID with a slash", [](json& e) { e["id"] = "01ABC/../01DEF"; },
             "an ID the Worker won't put in a URL"));
    add(both("an ID with an equals sign", [](json& e) { e["id"] = "01ABC="; },
             "an ID the Worker won't put in a URL"));
    add(both("no eTag", [](json& e) { e.erase("eTag"); }, "without an eTag"));
    add(both("an empty eTag", [](json& e) { e["eTag"] = ""; }, "without an eTag"));
    add(both("an eTag with a line break", [](json& e) { e["eTag"] = "\"{1},1\"\r\nX: y"; },
             "without an eTag"));
    add(both("an eTag too long", [](json& e) { e["eTag"] = std::string(513, 'e'); },
             "without an eTag"));
    rows.push_back({"a OneDrive file under another folder", Which::onedrive,
                    [](json& e) { e["parentReference"]["id"] = "01ZK75LGOTHERFOLDER000000000000000"; },
                    "not the RestoreTarget folder"});
    rows.push_back({"a OneDrive file without a parent ID", Which::onedrive,
                    [](json& e) { e["parentReference"].erase("id"); },
                    "not the RestoreTarget folder"});
    rows.push_back({"a library file in a subfolder", Which::sharepoint,
                    [](json& e) {
                        e["parentReference"]["path"] =
                            "/drives/" + lab_values().library_id + "/root:/Sub";
                    },
                    "not the library's root"});
    rows.push_back({"a library file without a path", Which::sharepoint,
                    [](json& e) { e["parentReference"].erase("path"); },
                    "not the library's root"});
    rows.push_back({"a mail without an ID", Which::mail, [](json& e) { e.erase("id"); },
                    "a message with an ID the Worker won't put in a URL"});
    rows.push_back({"a mail ID with a slash", Which::mail, [](json& e) { e["id"] = "AAk/../AAk="; },
                    "a message with an ID the Worker won't put in a URL"});
    rows.push_back({"a mail ID too long", Which::mail,
                    [](json& e) { e["id"] = std::string(513, 'A'); },
                    "a message with an ID the Worker won't put in a URL"});
    const Row row = GENERATE_COPY(from_range(rows));
    INFO(name_of(row.which) << ": " << row.name);

    Lab lab;
    const json fixture = two_items(row.which);
    json first = fixture["body"]["value"][0];
    row.edit(first);
    const json second = fixture["body"]["value"][1];
    lab.list(row.which, {listing_of(fixture, json::array({first, second})),
                         listing_of(fixture, json::array({first}))});
    lab.on_delete(row.which, id_at(fixture, 1), {deleted(row.which)});

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, row.which);
    CHECK(t.error_code.empty());
    CHECK(t.found == 1);
    CHECK(t.deleted == 1);
    CHECK(t.left == 0);
    CHECK(t.skipped == 1);
    CHECK(t.rounds == 1);
    CHECK_FALSE(t.ok());
    // The one write is the plain file's.
    const std::vector<HttpRequest> writes = lab.writes();
    REQUIRE(writes.size() == 1);
    CHECK(writes[0].url == write_url(row.which, id_at(fixture, 1)));
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring(row.logged));
    CHECK_THAT(log, ContainsSubstring("(never deleted; left for the owner)"));
    lab.require_only_listed_writes();
}

TEST_CASE("a nextLink that leaves the target stops it before any delete", "[cleaner][paging]")
{
    const Lab_values& v = lab_values();
    struct Row {
        const char* name;
        Which which;
        std::string link;
    };
    const Row row = GENERATE_COPY(
        Row{"another mailbox", Which::mail,
            kGraph + "/users/alice@example.invalid/mailFolders/inbox/messages?$skip=2"},
        Row{"another mail folder", Which::mail,
            kGraph + "/users/" + v.mailbox + "/mailFolders/deleteditems/messages?$skip=2"},
        Row{"the OneDrive's drive from the library", Which::sharepoint,
            kGraph + "/drives/" + v.onedrive_drive_id + "/root/children?$skiptoken=x"},
        Row{"another folder of the same OneDrive", Which::onedrive,
            kGraph + "/drives/" + v.onedrive_drive_id +
                "/items/01ZK75LGOTHERFOLDER000000000000000/children?$skiptoken=x"},
        Row{"the OneDrive's root", Which::onedrive,
            kGraph + "/drives/" + v.onedrive_drive_id + "/root/children?$skiptoken=x"},
        Row{"another host", Which::sharepoint,
            "https://example.invalid/v1.0/drives/" + v.library_id + "/root/children"});
    INFO(row.name);
    Lab lab;
    json fixture = two_items(row.which);
    fixture["body"]["@odata.nextLink"] = row.link;
    lab.list(row.which, {to_response(fixture)});

    const CleanupResult result = lab.clean();

    require_stopped(of(result, row.which), "graph");
    CHECK(of(result, row.which).found == 0);
    CHECK(lab.writes().empty());
    CHECK_THAT(lab.log(), ContainsSubstring("has a bad @odata.nextLink"));
}

TEST_CASE("a target past the page limit is cleaned up to it and ends with items left",
          "[cleaner][paging]")
{
    // W3.4 point 2: kMaxListPages bounds a round; what lies past it is `left`,
    // never an error that would stop every later clean at the same listing.
    const Which which = GENERATE(Which::mail, Which::sharepoint, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = two_items(which);
    const json entry = fixture.at("body").at("value").at(0);
    const auto link = [which](int page) {
        return listing_url(which) + "&$skiptoken=" + std::to_string(page);
    };
    // Every page holds one item and links to the next; the chain never ends,
    // and every delete answers 204 (the target refills, as far as the
    // Cleaner can tell).
    for (int page = 1; page <= rp::graph::kMaxListPages + 1; ++page) {
        json item = entry;
        item["id"] = "01PAGEITEM" + std::to_string(page);
        json body = fixture;
        body["body"]["value"] = json::array({item});
        body["body"]["@odata.nextLink"] = link(page + 1);
        lab.serve_listing(which, page == 1 ? listing_url(which) : link(page),
                          {to_response(body)});
        lab.on_delete(which, item["id"].get<std::string>(), {deleted(which)});
    }

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    const std::size_t limit = static_cast<std::size_t>(rp::graph::kMaxListPages);
    CHECK(t.error_code.empty());
    CHECK(t.found == limit);
    CHECK(t.deleted == 2 * limit);
    CHECK(t.left == limit);
    CHECK(t.rounds == 2);
    CHECK_FALSE(t.ok());
    // The page past the limit is never fetched, and nothing on it deleted.
    CHECK(lab.gets(link(rp::graph::kMaxListPages + 1)) == 0);
    CHECK(lab.writes_to(which).size() == 2 * limit);
    CHECK_THAT(lab.log(), ContainsSubstring("more than " +
                                            std::to_string(rp::graph::kMaxListPages) + " pages"));
    lab.require_only_listed_writes();
}

// ---- happy paths ---------------------------------------------------------------------------

TEST_CASE("empty targets are cleaned in one round with nothing to delete", "[cleaner]")
{
    const CleanupWhen when = GENERATE(CleanupWhen::before_run, CleanupWhen::after_run);
    Lab lab;

    const CleanupResult result = lab.clean(when);

    CHECK(result.when == when);
    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        INFO(name_of(which));
        require_cleaned(of(result, which), 0);
        // Listed, and listed again after (no) deletes, as every round.
        CHECK(lab.gets(listing_url(which)) == 2);
    }
    CHECK(result.ok());
    CHECK(lab.writes().empty());
    CHECK_THAT(lab.log(),
               ContainsSubstring(std::string{"cleanup "} +
                                 (when == CleanupWhen::before_run ? "before" : "after") +
                                 ": the test mailbox's Inbox: deleted 0, gone 0, left 0"));
}

TEST_CASE("the Cleaner deletes every mail and plain file each target lists", "[cleaner]")
{
    Lab lab;
    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        lab.serve_two(which);
    }

    const CleanupResult result = lab.clean(CleanupWhen::before_run);

    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        INFO(name_of(which));
        require_cleaned(of(result, which), 2);
        // Listed, deleted, listed again.
        CHECK(lab.gets(listing_url(which)) == 2);
        const json fixture = two_items(which);
        const std::vector<HttpRequest> writes = lab.writes_to(which);
        REQUIRE(writes.size() == 2);
        for (std::size_t i = 0; i < 2; ++i) {
            CHECK(writes[i].url == write_url(which, id_at(fixture, i)));
            if (which != Which::mail) {
                CHECK(writes[i].headers.at("If-Match") ==
                      fixture["body"]["value"][i]["eTag"].get<std::string>());
            }
        }
    }
    CHECK(result.ok());
    // Mail is listed by ID only, with the ImmutableId Prefer the delete reads it by.
    for (const HttpRequest& request : lab.http.requests()) {
        if (request.url == listing_url(Which::mail)) {
            CHECK(request.headers.at("Prefer") == kPrefer);
        }
    }
    CHECK_THAT(lab.log(), !ContainsSubstring("SECURITY"));
    lab.require_only_listed_writes();
}

TEST_CASE("the Cleaner follows a nextLink within the Inbox", "[cleaner][paging]")
{
    Lab lab;
    const json fixture = two_items(Which::mail);
    const std::string next = listing_url(Which::mail) + "&$skip=1";
    json page1 = fixture;
    page1["body"]["value"] = json::array({fixture["body"]["value"][0]});
    page1["body"]["@odata.nextLink"] = next;
    lab.list(Which::mail, {to_response(page1), empty_listing(Which::mail)});
    lab.serve_listing(Which::mail, next,
                      {listing_of(fixture, json::array({fixture["body"]["value"][1]}))});
    lab.on_delete(Which::mail, id_at(fixture, 0), {deleted(Which::mail)});
    lab.on_delete(Which::mail, id_at(fixture, 1), {deleted(Which::mail)});

    const CleanupResult result = lab.clean();

    require_cleaned(result.mail, 2);
    CHECK(lab.gets(next) == 1);
    lab.require_only_listed_writes();
}

TEST_CASE("ok() needs no error, nothing left and nothing skipped, on all three targets",
          "[cleaner]")
{
    TargetCleanup t;
    CHECK(t.ok());
    t.left = 1;
    CHECK_FALSE(t.ok());
    t.left = 0;
    t.skipped = 1;
    CHECK_FALSE(t.ok());
    t.skipped = 0;
    t.error_code = "graph";
    CHECK_FALSE(t.ok());

    CleanupResult result;
    CHECK(result.ok());
    result.onedrive.left = 3;
    CHECK_FALSE(result.ok());
}

TEST_CASE("to_json writes counts and codes, error_code only when set", "[cleaner][json]")
{
    CleanupResult result;
    result.when = CleanupWhen::after_run;
    result.mail = {"", 5, 4, 1, 0, 0, 1};
    result.sharepoint = {"graph_permission", 3, 0, 0, 3, 0, 1};
    result.onedrive = {"", 2, 2, 0, 0, 1, 2};

    CHECK(rp::graph::to_json(result) ==
          json::parse(R"({
              "mail": {"found": 5, "deleted": 4, "gone": 1, "left": 0, "skipped": 0, "rounds": 1},
              "sharepoint": {"found": 3, "deleted": 0, "gone": 0, "left": 3, "skipped": 0,
                             "rounds": 1, "error_code": "graph_permission"},
              "onedrive": {"found": 2, "deleted": 2, "gone": 0, "left": 0, "skipped": 1, "rounds": 2}
          })"));
}
