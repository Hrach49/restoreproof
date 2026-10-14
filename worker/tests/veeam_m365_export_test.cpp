// W6.3 (#183): the content export inside VeeamM365Connector::restore_sample
// (docs/decisions.md 2026-10-14, W6.3 points 1, 2 and 8), on W2.4's recorded
// SharePoint and OneDrive runs (veeam_restore_lab.hpp) with the export's own
// answers made up here: the bytes are the test's, never a tenant file. The
// export comes after every browsing session is open and before the first
// restore request; its own failure never fails the call; a stop or a sink
// that throws leaves nothing restored. Failure paths first.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/connector.hpp>
#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>
#include <rp/veeam_m365_connector.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;

namespace {

namespace connector = rp::connector;
using namespace rp::test::veeam_restore_lab;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::test::load_fixture_json;
using rp::test::make_response;
using namespace std::chrono_literals;

// Bytes with a sentinel in them: never in a log line or a message. 925 of
// them, the size the recorded documents list.
std::string export_bytes(std::size_t size = 925)
{
    std::string out = "%PDF-1.4 SENTINEL-EXPORT-BYTES\n";
    while (out.size() < size) {
        out += 'x';
    }
    out.resize(size);
    return out;
}

// The recorded document's save path, as the connector builds it.
std::string save_path(const Run& run)
{
    const std::string id =
        load_fixture_json("veeam", run.file("document")).at("body").at("id").get<std::string>();
    const std::string session = "/v8/RestoreSessions/" + run.explore();
    return run.kind == connector::ItemKind::sharepoint
               ? session + "/Organization/Sites/" + run.container() + "/Documents/" + encoded(id) +
                     "/save"
               : session + "/Organization/OneDrives/" + run.container() + "/Documents/" +
                     encoded(id) + "/save";
}

HttpResponse octet_stream(std::string bytes, std::string type = "application/octet-stream")
{
    return make_response(200, std::move(bytes), std::move(type));
}

HttpResponse veeam_error(int status, const std::string& message, const std::string& code = {})
{
    json body = {{"message", message}};
    if (!code.empty()) {
        body["errorCode"] = code;
    }
    return make_response(status, body.dump());
}

using Answer = std::function<HttpResponse(const HttpRequest&)>;

Answer respond(HttpResponse response)
{
    return [response](const HttpRequest&) { return response; };
}

Answer transport(rp::TransportError error)
{
    return [error](const HttpRequest& request) -> HttpResponse {
        throw rp::HttpError("POST " + request.url + ": no response", error, 0, 1);
    };
}

// What the sink was handed, on the connector's thread.
struct Sink final : connector::IContentSink {
    void on_content(connector::ItemKind kind, std::size_t index, std::string_view bytes) override
    {
        const std::lock_guard lock(mutex);
        if (fail) {
            throw std::runtime_error("SENTINEL-SINK");
        }
        calls.emplace_back(kind, index, std::string{bytes});
    }
    std::vector<std::tuple<connector::ItemKind, std::size_t, std::string>> taken()
    {
        const std::lock_guard lock(mutex);
        return calls;
    }
    std::mutex mutex;
    bool fail = false;
    std::vector<std::tuple<connector::ItemKind, std::size_t, std::string>> calls;
};

connector::RestoreSpec spec_wanting_content(const Run& run, Sink* sink)
{
    connector::RestoreSpec spec = run.kind == connector::ItemKind::sharepoint
                                      ? restore_spec({}, {sp_x1_item()})
                                      : restore_spec({}, {}, {od_x1_item()});
    if (run.kind == connector::ItemKind::sharepoint) {
        spec.sharepoint[0].want_content = true;
    } else {
        spec.onedrive[0].want_content = true;
    }
    spec.content_sink = sink;
    return spec;
}

// The positions of the requests of each kind, in the order sent.
struct Order {
    std::vector<std::size_t> explores;
    std::vector<std::size_t> saves;
    std::vector<std::size_t> restores;
};

Order order_of(const RestoreRig& rig)
{
    Order out;
    const std::vector<HttpRequest> requests = rig.veeam.requests();
    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (requests[i].method != HttpMethod::post) {
            continue;
        }
        if (requests[i].url.ends_with("/explore")) {
            out.explores.push_back(i);
        } else if (requests[i].url.ends_with("/save")) {
            out.saves.push_back(i);
        } else if (requests[i].url.ends_with("/restoreTo") || requests[i].url.ends_with("/copyTo")) {
            out.restores.push_back(i);
        }
    }
    return out;
}

void check_no_bytes_in_log(RestoreRig& rig, const connector::RestoreResult& result)
{
    const std::string log = rig.log() + rig.lab.log();
    CHECK_THAT(log, !ContainsSubstring("SENTINEL-EXPORT-BYTES"));
    CHECK_THAT(log, !ContainsSubstring("SENTINEL-SINK"));
    CHECK_THAT(result.log, !ContainsSubstring("SENTINEL-EXPORT-BYTES"));
}

} // namespace

// ---- nothing asked, nothing exported; a sink is required --------------------------------

TEST_CASE("restore_sample: without want_content nothing is exported and the result says so",
          "[veeam_m365][w6.3]")
{
    const Run run = GENERATE(sp_x1(), od_x1());
    CAPTURE(run.name);
    RestoreRig rig;
    rig.serve(run);
    Sink sink;
    connector::RestoreSpec spec = spec_wanting_content(run, &sink);
    if (run.kind == connector::ItemKind::sharepoint) {
        spec.sharepoint[0].want_content = false;
    } else {
        spec.onedrive[0].want_content = false;
    }
    REQUIRE(spec.content_count() == 0);

    const connector::RestoreResult result = rig.restore(spec);

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.content.empty());
    CHECK_FALSE(result.content_time.has_value());
    CHECK(rig.posts(save_path(run)) == 0);
    CHECK(sink.taken().empty());
}

TEST_CASE("restore_sample: want_content without a sink is refused before any request",
          "[veeam_m365][w6.3]")
{
    const Run run = GENERATE(sp_x1(), od_x1());
    CAPTURE(run.name);
    RestoreRig rig;
    rig.serve(run);
    connector::RestoreSpec spec = spec_wanting_content(run, nullptr);

    const Caught caught = caught_by([&] { rig.restore(spec); });

    CHECK(caught.kind == "invalid_argument");
    CHECK_THAT(caught.what, ContainsSubstring("no content sink"));
    CHECK_THAT(caught.what, EndsWith(std::string{connector::kNothingRestored}));
    CHECK(rig.veeam.requests().empty());
}

// ---- every answer of the export, and the restore still runs -----------------------------

TEST_CASE("restore_sample: each export answer is its word, the sink takes exported bytes alone, "
          "and the restore runs whatever the export came to",
          "[veeam_m365][w6.3]")
{
    using Outcome = connector::ContentOutcome;
    struct Row {
        std::string name;
        Answer answer;
        std::uint64_t cap;
        Outcome outcome;
        std::int64_t size_bytes;
        bool sink_called;
    };
    const Run run = GENERATE(sp_x1(), od_x1());
    const Row row = GENERATE_COPY(values<Row>({
        {"timeout", transport(rp::TransportError::timeout), connector::kMaxContentBytes,
         Outcome::no_answer, -1, false},
        {"dropped", transport(rp::TransportError::dropped), connector::kMaxContentBytes,
         Outcome::no_answer, -1, false},
        {"connect", transport(rp::TransportError::connect), connector::kMaxContentBytes,
         Outcome::no_answer, -1, false},
        {"500", respond(veeam_error(500, "Export failed.", "InternalError")),
         connector::kMaxContentBytes, Outcome::refused, -1, false},
        {"404 (the session gone)", respond(veeam_error(404, "Not found.", "ResourceNotFound")),
         connector::kMaxContentBytes, Outcome::refused, -1, false},
        {"401", respond(rp::test::load_fixture("veeam", "api-expired-token-401")),
         connector::kMaxContentBytes, Outcome::refused, -1, false},
        {"200 JSON, not a file", respond(make_response(200, R"({"id":"x"})")),
         connector::kMaxContentBytes, Outcome::refused, -1, false},
        {"200 without a Content-Type", respond(make_response(200, export_bytes(), "")),
         connector::kMaxContentBytes, Outcome::refused, -1, false},
        {"200 of another size", respond(octet_stream(export_bytes(900))),
         connector::kMaxContentBytes, Outcome::size_mismatch, -1, false},
        {"200 over the cap", respond(octet_stream(export_bytes())), 100, Outcome::over_cap, -1,
         false},
        {"200 as listed", respond(octet_stream(export_bytes())), connector::kMaxContentBytes,
         Outcome::exported, 925, true},
        {"200 as listed, the type in another case",
         respond(octet_stream(export_bytes(), "Application/Octet-Stream; x=y")),
         connector::kMaxContentBytes, Outcome::exported, 925, true},
    }));
    CAPTURE(run.name, row.name);
    RestoreRig rig;
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, url(save_path(run)),
                 [&](const HttpRequest& request) {
                     rig.clock.sleep(1500ms); // the export's own time
                     return row.answer(request);
                 });
    Sink sink;
    connector::RestoreSpec spec = spec_wanting_content(run, &sink);
    spec.content_max_bytes = row.cap;

    const connector::RestoreResult result = rig.restore(spec);

    // The export's word, and nothing else of the call changed.
    REQUIRE(result.content.size() == 1);
    CHECK(result.content[0].kind == run.kind);
    CHECK(result.content[0].index == 0);
    CHECK(result.content[0].outcome == row.outcome);
    CHECK(result.content[0].size_bytes == row.size_bytes);
    CHECK(result.content[0].ms == 1500);
    REQUIRE(result.content_time.has_value());
    CHECK(*result.content_time == 1500ms);
    CHECK(result.status == connector::RestoreStatus::succeeded);
    REQUIRE(result.items.size() == 1);
    CHECK(result.items[0].outcome == connector::ItemOutcome::restored);
    CHECK(rig.restore_posts().size() == 1);
    CHECK(rig.stops(run.explore()) == 1);
    // The sink took the bytes of an exported file alone.
    const auto taken = sink.taken();
    if (row.sink_called) {
        REQUIRE(taken.size() == 1);
        CHECK(std::get<0>(taken[0]) == run.kind);
        CHECK(std::get<1>(taken[0]) == 0);
        CHECK(std::get<2>(taken[0]) == export_bytes());
    } else {
        CHECK(taken.empty());
    }
    // One send, in the browsing session, with the cap, between the explore
    // and the restore request; a 401 is not resent, but its dead token is
    // dropped, so the restore request after it signs in afresh (W6.3
    // review, finding 5).
    const std::vector<HttpRequest> requests = rig.veeam.requests();
    std::vector<std::size_t> saves;
    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (requests[i].url.ends_with("/save")) {
            saves.push_back(i);
        }
    }
    REQUIRE(saves.size() == 1);
    const HttpRequest& save = requests[saves[0]];
    CHECK(save.method == HttpMethod::post);
    CHECK(save.body == R"({"asZip":false})");
    CHECK(save.headers.at("Accept") == "*/*");
    CHECK(save.max_attempts == 1);
    CHECK_FALSE(save.retry_on_status);
    CHECK(save.timeout == connector::kContentExportTimeout);
    CHECK(save.max_body_bytes == row.cap);
    const Order order = order_of(rig);
    REQUIRE(order.explores.size() == 1);
    REQUIRE(order.restores.size() == 1);
    CHECK(order.explores[0] < saves[0]);
    CHECK(saves[0] < order.restores[0]);
    CHECK(rig.veeam.count(HttpMethod::post, url("/v8/token")) == (row.name == "401" ? 2 : 1));
    // A failed export is one warning line of fixed words; the bytes nowhere.
    if (row.outcome != Outcome::exported) {
        CHECK_THAT(rig.log(), ContainsSubstring(std::string{connector::to_string(run.kind)} +
                                                " item 0: content export " +
                                                std::string{connector::to_string(row.outcome)}));
    }
    check_no_bytes_in_log(rig, result);
}

// ---- several items: order, the budget, a stop, a failing sink -----------------------------

TEST_CASE("restore_sample: the exports run in spec order, SharePoint then OneDrive, all before "
          "the first restore request, and content_time spans them",
          "[veeam_m365][w6.3]")
{
    RestoreRig rig;
    const Run sp = sp_x1();
    const Run od = od_x1();
    for (const Run& run : {mail_x5(), sp, od}) {
        rig.serve(run);
    }
    for (const Run& run : {sp, od}) {
        rig.veeam.on(HttpMethod::post, url(save_path(run)), [&](const HttpRequest&) {
            rig.clock.sleep(1s);
            return octet_stream(export_bytes());
        });
    }
    Sink sink;
    connector::RestoreSpec spec = restore_spec(mail_x5_items(), {sp_x1_item()}, {od_x1_item()});
    spec.sharepoint[0].want_content = true;
    spec.onedrive[0].want_content = true;
    spec.content_sink = &sink;

    const connector::RestoreResult result = rig.restore(spec);

    CHECK(result.status == connector::RestoreStatus::succeeded);
    REQUIRE(result.content.size() == 2);
    CHECK(result.content[0].kind == connector::ItemKind::sharepoint);
    CHECK(result.content[1].kind == connector::ItemKind::onedrive);
    for (const connector::ContentExport& e : result.content) {
        CHECK(e.index == 0);
        CHECK(e.outcome == connector::ContentOutcome::exported);
        CHECK(e.size_bytes == 925);
        CHECK(e.ms == 1000);
    }
    REQUIRE(result.content_time.has_value());
    CHECK(*result.content_time == 2s);
    const auto taken = sink.taken();
    REQUIRE(taken.size() == 2);
    CHECK(std::get<0>(taken[0]) == connector::ItemKind::sharepoint);
    CHECK(std::get<0>(taken[1]) == connector::ItemKind::onedrive);
    const Order order = order_of(rig);
    REQUIRE(order.explores.size() == 3);
    REQUIRE(order.saves.size() == 2);
    REQUIRE(order.restores.size() == 3);
    CHECK(order.explores.back() < order.saves.front());
    CHECK(order.saves.back() < order.restores.front());
    CHECK(rig.veeam.requests()[order.saves[0]].url == url(save_path(sp)));
    CHECK(rig.veeam.requests()[order.saves[1]].url == url(save_path(od)));
    check_no_bytes_in_log(rig, result);
}

TEST_CASE("restore_sample: an item the restore point doesn't hold is not_in_backup and never "
          "asked for; the other export is made",
          "[veeam_m365][w6.3][q3.1]")
{
    RestoreRig rig;
    const Run sp = sp_x1();
    const Run od = od_x1();
    // OneDrive served first: the rig hands out the recorded POST times in
    // serve order, and the SharePoint item never gets to a POST.
    rig.serve(od);
    rig.serve(sp);
    // Hand-written in the shape of Veeam's recorded 404s, as the Q3.1 test.
    rig.get("/v8/RestoreSessions/" + sp.explore() + "/Organization/Sites/" + sp.container(),
            veeam_error(404, "Site does not exist", "ResourceNotFound"));
    rig.veeam.on(HttpMethod::post, url(save_path(od)), {octet_stream(export_bytes())});
    Sink sink;
    connector::RestoreSpec spec = restore_spec({}, {sp_x1_item()}, {od_x1_item()});
    spec.sharepoint[0].want_content = true;
    spec.onedrive[0].want_content = true;
    spec.content_sink = &sink;

    const connector::RestoreResult result = rig.restore(spec);

    REQUIRE(result.items.size() == 2);
    CHECK(result.items[0].outcome == connector::ItemOutcome::not_in_backup);
    CHECK(result.items[1].outcome == connector::ItemOutcome::restored);
    REQUIRE(result.content.size() == 2);
    CHECK(result.content[0].kind == connector::ItemKind::sharepoint);
    CHECK(result.content[0].outcome == connector::ContentOutcome::not_in_backup);
    CHECK(result.content[0].ms == 0);
    CHECK(result.content[1].kind == connector::ItemKind::onedrive);
    CHECK(result.content[1].outcome == connector::ContentOutcome::exported);
    CHECK(rig.posts(save_path(sp)) == 0);
    CHECK(rig.posts(save_path(od)) == 1);
    CHECK(sink.taken().size() == 1);
}

TEST_CASE("restore_sample: once the export budget is spent the rest are budget and never asked "
          "for, and the restore still runs",
          "[veeam_m365][w6.3]")
{
    RestoreRig rig;
    const Run sp = sp_x1();
    const Run od = od_x1();
    rig.serve(sp);
    rig.serve(od);
    rig.veeam.on(HttpMethod::post, url(save_path(sp)), [&](const HttpRequest&) {
        rig.clock.sleep(connector::kContentExportBudget); // one slow export spends it all
        return octet_stream(export_bytes());
    });
    rig.veeam.on(HttpMethod::post, url(save_path(od)), {octet_stream(export_bytes())});
    Sink sink;
    connector::RestoreSpec spec = restore_spec({}, {sp_x1_item()}, {od_x1_item()});
    spec.sharepoint[0].want_content = true;
    spec.onedrive[0].want_content = true;
    spec.content_sink = &sink;

    const connector::RestoreResult result = rig.restore(spec);

    CHECK(result.status == connector::RestoreStatus::succeeded);
    REQUIRE(result.content.size() == 2);
    CHECK(result.content[0].outcome == connector::ContentOutcome::exported);
    CHECK(result.content[1].outcome == connector::ContentOutcome::budget);
    CHECK(result.content[1].ms == 0);
    CHECK(rig.posts(save_path(od)) == 0);
    CHECK(rig.restore_posts().size() == 2);
    CHECK(sink.taken().size() == 1);
    CHECK_THAT(rig.log(), ContainsSubstring("onedrive item 0: content export budget"));
}

TEST_CASE("restore_sample: a stop asked for during the exports ends the call with nothing "
          "restored, and the browsing sessions closed",
          "[veeam_m365][w6.3][w4.8]")
{
    RestoreRig rig;
    const Run sp = sp_x1();
    const Run od = od_x1();
    rig.serve(sp);
    rig.serve(od);
    // The stop comes once the first export has been sent.
    std::atomic<bool> stop{false};
    rig.stop_requested = [&] { return stop.load(); };
    rig.veeam.on(HttpMethod::post, url(save_path(sp)), [&](const HttpRequest&) {
        stop = true;
        return octet_stream(export_bytes());
    });
    rig.veeam.on(HttpMethod::post, url(save_path(od)), {octet_stream(export_bytes())});
    Sink sink;
    connector::RestoreSpec spec = restore_spec({}, {sp_x1_item()}, {od_x1_item()});
    spec.sharepoint[0].want_content = true;
    spec.onedrive[0].want_content = true;
    spec.content_sink = &sink;

    const Caught caught = caught_by([&] { rig.restore(spec); });

    CHECK(caught.kind == "Interrupted");
    CHECK_THAT(caught.what, ContainsSubstring("asked to stop before the onedrive restore request"));
    CHECK_THAT(caught.what, EndsWith(std::string{connector::kNothingRestored}));
    CHECK(rig.posts(save_path(sp)) == 1);
    CHECK(rig.posts(save_path(od)) == 0);
    CHECK(rig.restore_posts().empty());
    CHECK(rig.stops(sp.explore()) == 1);
    CHECK(rig.stops(od.explore()) == 1);
    CHECK(sink.taken().size() == 1);
}

TEST_CASE("restore_sample: a sink that throws ends the call with nothing restored, its text "
          "never shown",
          "[veeam_m365][w6.3]")
{
    const Run run = GENERATE(sp_x1(), od_x1());
    CAPTURE(run.name);
    RestoreRig rig;
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, url(save_path(run)), {octet_stream(export_bytes())});
    Sink sink;
    sink.fail = true;
    const connector::RestoreSpec spec = spec_wanting_content(run, &sink);

    const Caught caught = caught_by([&] { rig.restore(spec); });

    CHECK(caught.kind == "Error");
    CHECK_THAT(caught.what, ContainsSubstring("the content sink failed on " +
                                              std::string{connector::to_string(run.kind)} +
                                              " item 0"));
    CHECK_THAT(caught.what, EndsWith(std::string{connector::kNothingRestored}));
    CHECK_THAT(caught.what, !ContainsSubstring("SENTINEL-SINK"));
    CHECK(rig.restore_posts().empty());
    CHECK(rig.stops(run.explore()) == 1);
    CHECK_THAT(rig.log(), !ContainsSubstring("SENTINEL-SINK"));
}
