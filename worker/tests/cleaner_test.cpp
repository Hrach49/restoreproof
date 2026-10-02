// W3.4: emptying the three restore targets (rp/cleaner.hpp). Graph is one
// FakeHttpClient; the guard's checks are served from the recorded drive,
// folder and Inbox replies, the listings and 204s from the W3.4 live run's
// recording (tests/fixtures/recordings/w34-live-run1/: the clean after's
// listings of 5 mails and 3 + 3 files, and its first permanentDelete and
// DELETE), the live cleaner test's second answers to a doubled delete (a
// file's 404 itemNotFound, a mail's 403 ErrorCannotDeleteObject), the
// purged mail as Graph still gives it by its ID, in Recoverable Items' Purges
// (hand-shaped from that run's and a probe's live values), the Purges folder's
// ID (a read-only probe's), and the answers no live run
// gave (the refusing 403s, Exchange's 404, the 412) from the hand-written
// w34-* fixtures (tests/fixtures/graph/README.md). Every lab value is read
// from the fixtures. The fake records which IDs each listing served, and
// every test ends by checking that each write the Cleaner sent was a permanentDelete or
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
#include <cctype>
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

// The first GET remove() sends after a permanentDelete answered 403
// ErrorCannotDeleteObject: which folder is the message in now (W3.4 build
// notes point 15)? The second is the ID of the mailbox's Recoverable Items
// Purges folder, at purges_url(), where a purged message is; only if the
// message isn't there, the third is the Inbox's ID, at inbox_url(), the URL
// the guard reads too, but with the Prefer header the guard's GET doesn't
// send.
std::string message_url(const std::string& id)
{
    return kGraph + "/users/" + lab_values().mailbox + "/messages/" + id +
           "?$select=id,parentFolderId";
}

std::string purges_url()
{
    return kGraph + "/users/" + lab_values().mailbox +
           "/mailFolders/recoverableitemspurges?$select=id";
}

// The Purges folder's ID, as the live read-only probe of 2026-10-02 read it.
const char* const kPurges = "w34-mail-purges-200-id";

std::string purges_id()
{
    return load_fixture_json("graph", kPurges).at("body").at("id").get<std::string>();
}

// The Purges reply with its id set to `id` (nullopt: left out).
HttpResponse purges_with(const std::optional<json>& id)
{
    json edited = load_fixture_json("graph", kPurges);
    if (id) {
        edited["body"]["id"] = *id;
    } else {
        edited["body"].erase("id");
    }
    return to_response(edited);
}

// `text` in ASCII lower case.
std::string lower_case(std::string text)
{
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

// The live cleaner test's second permanentDelete of a mail its first had
// already purged (tests/fixtures/graph/README.md).
const char* const kCannotDelete = "w34-mail-permanentdelete-403-cannotdeleteobject-repeat";

// The purged message, as Graph still gives it by its ID: its parentFolderId
// is, byte for byte, the ID of Recoverable Items' Purges (the live probe's
// values).
const char* const kPurged = "w34-mail-get-200-purged-parentfolder";

// The recorded Inbox reply's ID (mailbox-inbox-200, the guard's).
std::string inbox_id()
{
    return load_fixture_json("graph", "mailbox-inbox-200").at("body").at("id").get<std::string>();
}

// The purged message's reply with its parentFolderId set to `folder`
// (nullopt: left out).
HttpResponse message_in(const std::optional<json>& folder)
{
    json edited = load_fixture_json("graph", kPurged);
    if (folder) {
        edited["body"]["parentFolderId"] = *folder;
    } else {
        edited["body"].erase("parentFolderId");
    }
    return to_response(edited);
}

HttpMethod write_method(Which which)
{
    return which == Which::mail ? HttpMethod::post : HttpMethod::del;
}

// The W3.4 live run's recording (tests/fixtures/recordings/w34-live-run1/).
const char* const kRecording = "recordings/w34-live-run1/graph";

// The clean after's first listing of `which` in the W3.4 live run, as JSON
// (its "value" is what the tests edit): 5 mails, or 3 files, each deleted live.
json recorded_items(Which which)
{
    const char* name =
        which == Which::mail
            ? "034-get-v1-0-users-restoretest-restoreprooflab-onmicrosoft-com-mailf"
        : which == Which::sharepoint
            ? "042-get-v1-0-drives-b-xqgi-ndr6ekvpkcbib2y65nzyk4ozjvns-7ncroj5omdbu"
            : "048-get-v1-0-drives-b-wa9gbfhleuitgaluxbfonbr-z5getdherm5pj6bmwyxfzj";
    return load_fixture_json(kRecording, name);
}

// How many items recorded_items(which) lists.
std::size_t recorded_count(Which which)
{
    return recorded_items(which).at("body").at("value").size();
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
    return listing_of(recorded_items(which), json::array());
}

std::string id_at(const json& fixture, std::size_t i)
{
    return fixture.at("body").at("value").at(i).at("id").get<std::string>();
}

// The live run's first permanentDelete or DELETE, answered 204.
HttpResponse deleted(Which which)
{
    return load_fixture(kRecording,
                        which == Which::mail
                            ? "035-post-v1-0-users-restoretest-restoreprooflab-onmicrosoft-com-messa"
                            : "043-delete-v1-0-drives-b-xqgi-ndr6ekvpkcbib2y65nzyk4ozjvns-7ncroj5omdbu");
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

    // Every item of the recorded listing is served once, then the target is
    // empty, and every delete answers 204.
    void serve_recorded(Which which)
    {
        const json fixture = recorded_items(which);
        list(which, {to_response(fixture), empty_listing(which)});
        for (std::size_t i = 0; i < recorded_count(which); ++i) {
            on_delete(which, id_at(fixture, i), {deleted(which)});
        }
    }

    // Every item but the first of `fixture`'s listing answers its delete 204.
    void delete_rest(Which which, const json& fixture)
    {
        for (std::size_t i = 1; i < fixture.at("body").at("value").size(); ++i) {
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

    // remove()'s Inbox GET after a 403 ErrorCannotDeleteObject answers
    // `answers` in turn (the last repeating); the guard's GET of the same URL,
    // sent without a Prefer header, still gets the recorded Inbox. No
    // assertions: this runs on the client's thread.
    void on_inbox_check(std::vector<HttpResponse> answers)
    {
        auto state = std::make_shared<std::pair<std::size_t, std::vector<HttpResponse>>>(
            0, std::move(answers));
        const HttpResponse guard = load_fixture("graph", "mailbox-inbox-200");
        http.on(HttpMethod::get, inbox_url(), [this, state, guard](const HttpRequest& request) {
            if (!request.headers.contains("Prefer")) {
                return guard;
            }
            const std::lock_guard lock(mutex);
            HttpResponse answer = state->second[std::min(state->first, state->second.size() - 1)];
            ++state->first;
            return answer;
        });
    }

    // How many Purges GETs remove() sent (no one else asks), each checked to
    // carry kPrefer.
    std::size_t purges_checks() const
    {
        std::size_t n = 0;
        for (const HttpRequest& request : http.requests()) {
            if (request.method == HttpMethod::get && request.url == purges_url()) {
                CHECK(request.headers.at("Prefer") == kPrefer);
                ++n;
            }
        }
        return n;
    }

    // How many Inbox GETs remove() sent: those with the Prefer header (the
    // guard's has none), each checked to carry kPrefer.
    std::size_t inbox_checks() const
    {
        std::size_t n = 0;
        for (const HttpRequest& request : http.requests()) {
            if (request.method == HttpMethod::get && request.url == inbox_url() &&
                request.headers.contains("Prefer")) {
                CHECK(request.headers.at("Prefer") == kPrefer);
                ++n;
            }
        }
        return n;
    }

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
        lab.serve_recorded(which);
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
            require_cleaned(of(result, other), recorded_count(other));
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
            "DELETE"},
        // ErrorCannotDeleteObject means "check the message" for a mail only:
        // a file's 403 is a refusal whatever its code.
        Row{Which::sharepoint, kCannotDelete, &rp::graph::kListWriteGrant, "DELETE"});
    INFO(name_of(row.which));
    Lab lab;
    const json fixture = recorded_items(row.which);
    const std::size_t n = recorded_count(row.which);
    lab.list(row.which, {to_response(fixture)});
    for (std::size_t i = 0; i < n; ++i) {
        lab.on_delete(row.which, id_at(fixture, i), {load_fixture("graph", row.fixture)});
    }

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, row.which);
    require_stopped(t, "graph_permission");
    CHECK(t.found == n);
    CHECK(t.deleted == 0);
    CHECK(t.left == n);
    // The first refusal stops the target: one write, one listing.
    CHECK(lab.writes_to(row.which).size() == 1);
    CHECK(lab.gets(listing_url(row.which)) == 1);
    // A 403 that isn't a mail's ErrorCannotDeleteObject is never followed
    // by a GET of the item.
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == 0);
    CHECK(lab.gets(write_url(row.which, id_at(fixture, 0))) == 0);
    CHECK(lab.purges_checks() == 0);
    CHECK(lab.inbox_checks() == 0);
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

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject on a mail still in the Inbox is "
          "graph_permission naming the mail grant",
          "[cleaner][permission][cannot_delete]")
{
    // W3.4 build notes point 15: the message's parentFolderId isn't the
    // Purges folder's ID but is the Inbox's, byte for byte, so the 403 was a
    // refusal and stands, with no second round.
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    const std::size_t n = recorded_count(Which::mail);
    lab.list(Which::mail, {to_response(fixture)});
    for (std::size_t i = 0; i < n; ++i) {
        lab.on_delete(Which::mail, id_at(fixture, i), {load_fixture("graph", kCannotDelete)});
    }
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)), {message_in(json(inbox_id()))});
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    require_stopped(result.mail, "graph_permission");
    CHECK(result.mail.found == n);
    CHECK(result.mail.deleted == 0);
    CHECK(result.mail.gone == 0);
    CHECK(result.mail.left == n);
    CHECK(lab.writes_to(Which::mail).size() == 1);
    CHECK(lab.gets(listing_url(Which::mail)) == 1);
    // One check: the message's folder, the Purges folder's ID, then the
    // Inbox's ID, once each.
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == 1);
    CHECK(lab.purges_checks() == 1);
    CHECK(lab.inbox_checks() == 1);
    // All three GETs read by ImmutableId, as the listing did.
    for (const HttpRequest& request : lab.http.requests()) {
        if (request.url == message_url(id_at(fixture, 0))) {
            CHECK(request.headers.at("Prefer") == kPrefer);
        }
    }
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring("Graph denied POST"));
    CHECK_THAT(log, ContainsSubstring("(403 ErrorCannotDeleteObject)"));
    CHECK_THAT(log, ContainsSubstring(std::string{rp::graph::kMailGrant.description}));
    CHECK_THAT(log, !ContainsSubstring("is gone"));
    CHECK(result.sharepoint.ok());
    CHECK(result.onedrive.ok());
    lab.require_only_listed_writes();
}

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject on a mail whose folder can't be read "
          "is an error, never gone",
          "[cleaner][permission][cannot_delete]")
{
    // Fail closed: a parentFolderId that is missing, empty or not a string, or
    // a reply that isn't a JSON object, says nothing about where the message
    // is, so the target stops (graph) and the mail is left. Neither folder is
    // asked: there is nothing to compare their IDs with.
    struct Row {
        const char* name;
        std::function<HttpResponse()> answer;
        const char* logged;
    };
    const Row row = GENERATE(
        Row{"no parentFolderId", [] { return message_in(std::nullopt); }, "parentFolderId"},
        Row{"an empty parentFolderId", [] { return message_in(json("")); }, "parentFolderId"},
        Row{"a number", [] { return message_in(json(42)); }, "parentFolderId"},
        Row{"a null", [] { return message_in(json(nullptr)); }, "parentFolderId"},
        Row{"an array", [] { return message_in(json::array({"x"})); }, "parentFolderId"},
        Row{"an object", [] { return message_in(json::object({{"id", "x"}})); },
            "parentFolderId"},
        Row{"a reply that isn't JSON",
            [] {
                HttpResponse r = message_in(json("x"));
                r.body = "not json";
                return r;
            },
            "isn't a JSON object"},
        Row{"a JSON array",
            [] {
                HttpResponse r = message_in(json("x"));
                r.body = "[]";
                return r;
            },
            "isn't a JSON object"});
    INFO(row.name);
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    lab.list(Which::mail, {to_response(fixture)});
    lab.on_delete(Which::mail, id_at(fixture, 0), {load_fixture("graph", kCannotDelete)});
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)), {row.answer()});
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    require_stopped(result.mail, "graph");
    CHECK(result.mail.deleted == 0);
    CHECK(result.mail.gone == 0);
    CHECK(result.mail.left == recorded_count(Which::mail));
    CHECK(lab.writes_to(Which::mail).size() == 1);
    CHECK(lab.purges_checks() == 0);
    CHECK(lab.inbox_checks() == 0);
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring(row.logged));
    CHECK_THAT(log, !ContainsSubstring("is gone"));
    CHECK_THAT(log, !ContainsSubstring("): Graph denied POST"));
    lab.require_only_listed_writes();
}

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject whose message GET fails stops the "
          "mail target with that GET's error",
          "[cleaner][permission][cannot_delete]")
{
    struct Row {
        const char* name;
        std::function<std::vector<HttpResponse>()> answers;
        const char* code;
        unsigned rounds;
        const char* logged;
    };
    const Row row = GENERATE(
        Row{"a 403 on the GET",
            [] { return std::vector{load_fixture("graph", "messages-403-exchange")}; },
            "graph_permission", 1, "Graph denied GET"},
        Row{"503s on the GET in both rounds",
            [] { return std::vector{load_fixture("graph", "messages-503-unavailable")}; },
            "graph_transient", 2, "Graph GET"},
        Row{"a 404 naming a missing mailbox",
            [] { return std::vector{load_fixture("graph", "messages-404-unknown-user")}; },
            "graph", 1, "ErrorInvalidUser"},
        Row{"a 412 to the GET", [] { return std::vector{make_response(412)}; }, "graph", 1,
            "HTTP 412, where 200 or 404 was expected"},
        Row{"a 302 to the GET",
            [] {
                HttpResponse r = make_response(302);
                r.headers["Location"] = "https://example.invalid/";
                return std::vector{r};
            },
            "graph", 1, "HTTP 302, where 200 or 404 was expected"});
    INFO(row.name);
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    lab.list(Which::mail, {to_response(fixture)});
    lab.on_delete(Which::mail, id_at(fixture, 0), {load_fixture("graph", kCannotDelete)});
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)), row.answers());
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    require_stopped(result.mail, row.code, row.rounds);
    CHECK(result.mail.deleted == 0);
    CHECK(result.mail.gone == 0);
    CHECK(lab.writes_to(Which::mail).size() == row.rounds);
    CHECK(lab.purges_checks() == 0);
    CHECK(lab.inbox_checks() == 0);
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring(row.logged));
    // The target stops on the GET's error, never on the POST's refusal.
    CHECK_THAT(log, !ContainsSubstring("): Graph denied POST"));
    CHECK_THAT(log, !ContainsSubstring("is gone"));
    lab.require_only_listed_writes();
}

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject whose Inbox GET fails or can't be "
          "read stops the mail target, never gone",
          "[cleaner][permission][cannot_delete]")
{
    // The message's parentFolderId isn't the Purges folder's ID; it is the
    // recorded Inbox's, but without the Inbox's own ID read there is nothing
    // to compare it with, so the target stops on the Inbox GET's error and
    // the mail is never counted gone.
    struct Row {
        const char* name;
        std::function<std::vector<HttpResponse>()> answers;
        const char* code;
        unsigned rounds;
        const char* logged;
    };
    const auto inbox_with = [](std::optional<json> id) {
        json edited = load_fixture_json("graph", "mailbox-inbox-200");
        if (id) {
            edited["body"]["id"] = *id;
        } else {
            edited["body"].erase("id");
        }
        return std::vector{to_response(edited)};
    };
    const Row row = GENERATE_COPY(
        Row{"a 403 on the Inbox",
            [] { return std::vector{load_fixture("graph", "mailbox-inbox-403-exchange")}; },
            "graph_permission", 1, "Graph denied GET"},
        Row{"503s on the Inbox in both rounds",
            [] { return std::vector{load_fixture("graph", "messages-503-unavailable")}; },
            "graph_transient", 2, "Graph GET"},
        Row{"a 404 naming a missing mailbox",
            [] { return std::vector{load_fixture("graph", "messages-404-unknown-user")}; },
            "graph", 1, "ErrorInvalidUser"},
        Row{"a 302 to the Inbox",
            [] {
                HttpResponse r = make_response(302);
                r.headers["Location"] = "https://example.invalid/";
                return std::vector{r};
            },
            "graph", 1, "HTTP 302, where 200 was expected"},
        Row{"no id", [inbox_with] { return inbox_with(std::nullopt); }, "graph", 1,
            "the Inbox's ID"},
        Row{"an empty id", [inbox_with] { return inbox_with(json("")); }, "graph", 1,
            "the Inbox's ID"},
        Row{"a number id", [inbox_with] { return inbox_with(json(7)); }, "graph", 1,
            "the Inbox's ID"},
        Row{"a null id", [inbox_with] { return inbox_with(json(nullptr)); }, "graph", 1,
            "the Inbox's ID"});
    INFO(row.name);
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    lab.list(Which::mail, {to_response(fixture)});
    lab.on_delete(Which::mail, id_at(fixture, 0), {load_fixture("graph", kCannotDelete)});
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)), {message_in(json(inbox_id()))});
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check(row.answers());

    const CleanupResult result = lab.clean();

    require_stopped(result.mail, row.code, row.rounds);
    CHECK(result.mail.deleted == 0);
    CHECK(result.mail.gone == 0);
    CHECK(lab.writes_to(Which::mail).size() == row.rounds);
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == row.rounds);
    CHECK(lab.purges_checks() == row.rounds);
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring(row.logged));
    CHECK_THAT(log, !ContainsSubstring("): Graph denied POST"));
    CHECK_THAT(log, !ContainsSubstring("is gone"));
    lab.require_only_listed_writes();
}

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject whose Purges GET fails or can't be "
          "read stops the mail target, never gone",
          "[cleaner][permission][cannot_delete]")
{
    // The message's parentFolderId is the live purged one; without the
    // Purges folder's own ID read there is nothing to match it with, so the
    // mail is never counted gone, and the Inbox isn't asked.
    struct Row {
        const char* name;
        std::function<std::vector<HttpResponse>()> answers;
        const char* code;
        unsigned rounds;
        const char* logged;
        // The Purges GETs sent: one per round, but a 503's five attempts.
        unsigned sent = 0; // 0: rounds
    };
    const Row row = GENERATE(
        Row{"a 403 on Purges",
            [] { return std::vector{load_fixture("graph", "mailbox-inbox-403-exchange")}; },
            "graph_permission", 1, "Graph denied GET"},
        Row{"503s on Purges in both rounds",
            [] { return std::vector{load_fixture("graph", "messages-503-unavailable")}; },
            "graph_transient", 2, "Graph GET", 10},
        Row{"a 404 naming a missing mailbox",
            [] { return std::vector{load_fixture("graph", "messages-404-unknown-user")}; },
            "graph", 1, "ErrorInvalidUser"},
        Row{"a 404 for the folder",
            [] {
                return std::vector{
                    load_fixture("graph", "w34-mail-permanentdelete-404-erroritemnotfound")};
            },
            "graph", 1, "ErrorItemNotFound"},
        Row{"a 302 to Purges",
            [] {
                HttpResponse r = make_response(302);
                r.headers["Location"] = "https://example.invalid/";
                return std::vector{r};
            },
            "graph", 1, "HTTP 302, where 200 was expected"},
        Row{"a reply that isn't JSON",
            [] {
                HttpResponse r = purges_with(json("x"));
                r.body = "not json";
                return std::vector{r};
            },
            "graph", 1, "isn't a JSON object"},
        Row{"no id", [] { return std::vector{purges_with(std::nullopt)}; }, "graph", 1,
            "the Purges folder's ID"},
        Row{"an empty id", [] { return std::vector{purges_with(json(""))}; }, "graph", 1,
            "the Purges folder's ID"},
        Row{"a number id", [] { return std::vector{purges_with(json(7))}; }, "graph", 1,
            "the Purges folder's ID"},
        Row{"a null id", [] { return std::vector{purges_with(json(nullptr))}; }, "graph", 1,
            "the Purges folder's ID"});
    INFO(row.name);
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    lab.list(Which::mail, {to_response(fixture)});
    lab.on_delete(Which::mail, id_at(fixture, 0), {load_fixture("graph", kCannotDelete)});
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)),
                {load_fixture("graph", kPurged)});
    lab.http.on(HttpMethod::get, purges_url(), row.answers());
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    require_stopped(result.mail, row.code, row.rounds);
    CHECK(result.mail.deleted == 0);
    CHECK(result.mail.gone == 0);
    CHECK(lab.writes_to(Which::mail).size() == row.rounds);
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == row.rounds);
    CHECK(lab.purges_checks() == (row.sent == 0 ? row.rounds : row.sent));
    CHECK(lab.inbox_checks() == 0);
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring(row.logged));
    CHECK_THAT(log, !ContainsSubstring("): Graph denied POST"));
    CHECK_THAT(log, !ContainsSubstring("is gone"));
    lab.require_only_listed_writes();
}

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject on a mail in another folder of the "
          "mailbox is an error, never gone",
          "[cleaner][permission][cannot_delete]")
{
    // W3.4 build notes point 15: only a positive match makes a mail gone. A
    // parentFolderId that is neither the Purges folder's ID nor the Inbox's,
    // byte for byte (a message moved elsewhere, an ID in another form, one
    // differing in case only), fails closed: the target stops (graph) and
    // the mail is left.
    struct Row {
        const char* name;
        std::function<std::string()> folder;
    };
    const Row row = GENERATE(
        Row{"Purges in lower case", [] { return lower_case(purges_id()); }},
        Row{"the Inbox in lower case", [] { return lower_case(inbox_id()); }},
        Row{"another folder", [] { return std::string{"AAMkAnotherFolderOfTheMailbox="}; }});
    INFO(row.name);
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    lab.list(Which::mail, {to_response(fixture)});
    lab.on_delete(Which::mail, id_at(fixture, 0), {load_fixture("graph", kCannotDelete)});
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)),
                {message_in(json(row.folder()))});
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    require_stopped(result.mail, "graph");
    CHECK(result.mail.deleted == 0);
    CHECK(result.mail.gone == 0);
    CHECK(result.mail.left == recorded_count(Which::mail));
    CHECK(lab.writes_to(Which::mail).size() == 1);
    // At most three GETs, no loop.
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == 1);
    CHECK(lab.purges_checks() == 1);
    CHECK(lab.inbox_checks() == 1);
    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring("in another folder of the mailbox"));
    CHECK_THAT(log, ContainsSubstring("the mail isn't counted gone"));
    CHECK_THAT(log, !ContainsSubstring("is gone"));
    CHECK_THAT(log, !ContainsSubstring("): Graph denied POST"));
    CHECK(result.sharepoint.ok());
    CHECK(result.onedrive.ok());
    lab.require_only_listed_writes();
}

TEST_CASE("a token Entra refuses stops every target as graph_auth, nothing deleted",
          "[cleaner][auth]")
{
    Lab lab;
    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        lab.serve_recorded(which);
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
        lab.serve_recorded(Which::mail);
        lab.serve_recorded(Which::onedrive);
        lab.http.on(HttpMethod::get, listing_url(Which::sharepoint),
                    [](const HttpRequest&) -> HttpResponse {
                        throw std::runtime_error("sentinel-internal-5b7e");
                    });
        const CleanupResult result = lab.clean();
        require_stopped(result.sharepoint, "internal");
        require_cleaned(result.mail, recorded_count(Which::mail));
        require_cleaned(result.onedrive, recorded_count(Which::onedrive));
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
    const json fixture = recorded_items(which);
    const std::size_t n = recorded_count(which);
    // Round 1 lists them all; its first delete gives up after five 503s,
    // which ends the round. Round 2 lists them all again, deletes them, and
    // lists nothing.
    lab.list(which, {to_response(fixture), to_response(fixture), empty_listing(which)});
    const HttpResponse unavailable = load_fixture("graph", "messages-503-unavailable");
    lab.on_delete(which, id_at(fixture, 0),
                  {unavailable, unavailable, unavailable, unavailable, unavailable, deleted(which)});
    lab.delete_rest(which, fixture);

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.rounds == 2);
    CHECK(t.found == n);
    CHECK(t.deleted == n);
    CHECK(t.left == 0);
    CHECK(t.ok());
    CHECK(lab.writes_to(which).size() == 5 + n);
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
    const json fixture = recorded_items(which);
    // The first file changed after it was listed (SharePoint rewrites Office
    // files): a new eTag in every later listing.
    json changed = fixture.at("body").at("value").at(0);
    changed["eTag"] = "\"{0A1B2C3D-0000-4000-8000-00000000ABCD},2\"";
    lab.list(which, {to_response(fixture), listing_of(fixture, json::array({changed})),
                     listing_of(fixture, json::array({changed})), empty_listing(which)});
    lab.on_delete(which, id_at(fixture, 0),
                  {load_fixture("graph", "w34-file-delete-412-resourcemodified"), deleted(which)});
    lab.delete_rest(which, fixture);
    const std::size_t n = recorded_count(which);

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.rounds == 2);
    CHECK(t.found == n);
    CHECK(t.deleted == n);
    CHECK(t.left == 0);
    CHECK(t.ok());
    // Round 1: the changed file's 412, then the others; round 2: the changed file.
    const std::vector<HttpRequest> writes = lab.writes_to(which);
    REQUIRE(writes.size() == n + 1);
    CHECK(writes[0].url == write_url(which, id_at(fixture, 0)));
    CHECK(writes[0].headers.at("If-Match") ==
          fixture.at("body").at("value").at(0).at("eTag").get<std::string>());
    // Round 2 sends the eTag it listed, never round 1's.
    CHECK(writes[n].url == writes[0].url);
    CHECK(writes[n].headers.at("If-Match") == changed.at("eTag").get<std::string>());
    CHECK_THAT(lab.log(), ContainsSubstring("changed since it was listed"));
    lab.require_only_listed_writes();
}

TEST_CASE("a target still holding items after two rounds ends with them left",
          "[cleaner][left]")
{
    const Which which = GENERATE(Which::mail, Which::sharepoint, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = recorded_items(which);
    // The listing never empties (Graph lagging, or mail still arriving).
    lab.list(which, {to_response(fixture)});
    lab.on_delete(which, id_at(fixture, 0), {deleted(which)});
    lab.delete_rest(which, fixture);
    const std::size_t n = recorded_count(which);

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.rounds == 2);
    CHECK(t.found == n);
    CHECK(t.deleted == 2 * n);
    CHECK(t.left == n);
    CHECK_FALSE(t.ok());
    CHECK_FALSE(result.ok());
    CHECK(lab.gets(listing_url(which)) == 4);
    CHECK_THAT(lab.log(), ContainsSubstring("left " + std::to_string(n) +
                                            ", skipped 0 in 2 round(s)"));
    lab.require_only_listed_writes();
}

TEST_CASE("Graph's 404 for a listed item counts it gone", "[cleaner][gone]")
{
    const Which which = GENERATE(Which::mail, Which::sharepoint, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = recorded_items(which);
    lab.list(which, {to_response(fixture), empty_listing(which)});
    lab.on_delete(which, id_at(fixture, 0),
                  {load_fixture("graph", which == Which::mail
                                             ? "w34-mail-permanentdelete-404-erroritemnotfound"
                                             : "w34-file-delete-404-itemnotfound")});
    lab.delete_rest(which, fixture);

    const CleanupResult result = lab.clean();

    const TargetCleanup& t = of(result, which);
    CHECK(t.error_code.empty());
    CHECK(t.found == recorded_count(which));
    CHECK(t.deleted == recorded_count(which) - 1);
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
    const json fixture = recorded_items(which);
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

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject on a mail Graph no longer finds counts "
          "it gone, no folder asked",
          "[cleaner][gone][cannot_delete]")
{
    // W3.4 build notes point 15: the message GET's 404 says the mail is gone,
    // with no folder GET, and the round's listing again confirms it. Exchange's
    // code and SharePoint's both count.
    const char* const not_found = GENERATE("w34-mail-permanentdelete-404-erroritemnotfound",
                                           "w34-file-delete-404-itemnotfound");
    INFO(not_found);
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    const std::size_t n = recorded_count(Which::mail);
    lab.list(Which::mail, {to_response(fixture), empty_listing(Which::mail)});
    lab.on_delete(Which::mail, id_at(fixture, 0), {load_fixture("graph", kCannotDelete)});
    lab.delete_rest(Which::mail, fixture);
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)),
                {load_fixture("graph", not_found)});
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    CHECK(result.mail.error_code.empty());
    CHECK(result.mail.found == n);
    CHECK(result.mail.deleted == n - 1);
    CHECK(result.mail.gone == 1);
    CHECK(result.mail.left == 0);
    CHECK(result.mail.rounds == 1);
    CHECK(result.mail.ok());
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == 1);
    CHECK(lab.purges_checks() == 0);
    CHECK(lab.inbox_checks() == 0);
    CHECK(lab.gets(listing_url(Which::mail)) == 2);
    CHECK(lab.writes_to(Which::mail).size() == n);
    CHECK_THAT(lab.log(), ContainsSubstring("is gone"));
    lab.require_only_listed_writes();
}

TEST_CASE("a permanentDelete's 403 ErrorCannotDeleteObject on a mail in Recoverable Items' "
          "Purges counts it gone, the Inbox not asked",
          "[cleaner][gone][cannot_delete]")
{
    // The live case (2026-10-02 21:05): Graph still finds the purged message
    // by its ID (200), and its parentFolderId is, byte for byte, the ID of the
    // mailbox's Recoverable Items Purges folder (the read-only probe's): a
    // positive match, so it is gone.
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    const std::size_t n = recorded_count(Which::mail);
    lab.list(Which::mail, {to_response(fixture), empty_listing(Which::mail)});
    lab.on_delete(Which::mail, id_at(fixture, 0), {load_fixture("graph", kCannotDelete)});
    lab.delete_rest(Which::mail, fixture);
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)),
                {load_fixture("graph", kPurged)});
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    // The two live values are the same ID, and not the Inbox's.
    CHECK(load_fixture_json("graph", kPurged).at("body").at("parentFolderId") == purges_id());
    CHECK(purges_id() != inbox_id());
    CHECK(result.mail.error_code.empty());
    CHECK(result.mail.found == n);
    CHECK(result.mail.deleted == n - 1);
    CHECK(result.mail.gone == 1);
    CHECK(result.mail.left == 0);
    CHECK(result.mail.rounds == 1);
    CHECK(result.mail.ok());
    // One check, no loop: the message GET, then the Purges GET, once each.
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == 1);
    CHECK(lab.purges_checks() == 1);
    CHECK(lab.inbox_checks() == 0);
    CHECK(lab.gets(listing_url(Which::mail)) == 2);
    CHECK(lab.writes_to(Which::mail).size() == n);
    CHECK_THAT(lab.log(), ContainsSubstring("is gone"));
    lab.require_only_listed_writes();
}

TEST_CASE("a permanentDelete resent after a dropped connection and answered 403 "
          "ErrorCannotDeleteObject counts the mail gone",
          "[cleaner][gone][cannot_delete]")
{
    // The production case the live test copies: the first permanentDelete
    // purged the mail but its answer was lost, and the resend is refused. The
    // check finds the message in Purges (as live) or not at all.
    const char* const check = GENERATE(kPurged, "w34-mail-permanentdelete-404-erroritemnotfound");
    INFO(check);
    Lab lab;
    const json fixture = recorded_items(Which::mail);
    lab.list(Which::mail, {listing_of(fixture, json::array({fixture["body"]["value"][0]})),
                           empty_listing(Which::mail)});
    const HttpResponse cannot_delete = load_fixture("graph", kCannotDelete);
    auto sent = std::make_shared<std::atomic<int>>(0);
    lab.http.on(HttpMethod::post, write_url(Which::mail, id_at(fixture, 0)),
                [sent, cannot_delete](const HttpRequest&) -> HttpResponse {
                    if (sent->fetch_add(1) == 0) {
                        // The first went out and purged the mail; its answer was lost.
                        throw rp::HttpError("dropped", rp::TransportError::dropped, 0, 1);
                    }
                    return cannot_delete;
                });
    lab.http.on(HttpMethod::get, message_url(id_at(fixture, 0)), {load_fixture("graph", check)});
    lab.http.on(HttpMethod::get, purges_url(), {load_fixture("graph", kPurges)});
    lab.on_inbox_check({load_fixture("graph", "mailbox-inbox-200")});

    const CleanupResult result = lab.clean();

    CHECK(result.mail.error_code.empty());
    CHECK(result.mail.gone == 1);
    CHECK(result.mail.deleted == 0);
    CHECK(result.mail.ok());
    CHECK(lab.writes_to(Which::mail).size() == 2);
    CHECK(lab.gets(message_url(id_at(fixture, 0))) == 1);
    CHECK(lab.purges_checks() == (std::string{check} == kPurged ? 1u : 0u));
    CHECK(lab.inbox_checks() == 0);
    lab.require_only_listed_writes();
}

TEST_CASE("a 401 on a delete gets one fresh token and the delete again", "[cleaner][auth]")
{
    const Which which = GENERATE(Which::mail, Which::onedrive);
    INFO(name_of(which));
    Lab lab;
    const json fixture = recorded_items(which);
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
    const json fixture = recorded_items(row.which);
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
    const json fixture = recorded_items(row.which);
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
    json fixture = recorded_items(row.which);
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
    const json fixture = recorded_items(which);
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
        lab.serve_recorded(which);
    }

    const CleanupResult result = lab.clean(CleanupWhen::before_run);

    for (const Which which : {Which::mail, Which::sharepoint, Which::onedrive}) {
        INFO(name_of(which));
        const std::size_t n = recorded_count(which);
        require_cleaned(of(result, which), n);
        // Listed, deleted, listed again.
        CHECK(lab.gets(listing_url(which)) == 2);
        const json fixture = recorded_items(which);
        const std::vector<HttpRequest> writes = lab.writes_to(which);
        REQUIRE(writes.size() == n);
        for (std::size_t i = 0; i < n; ++i) {
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
    const json fixture = recorded_items(Which::mail);
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
