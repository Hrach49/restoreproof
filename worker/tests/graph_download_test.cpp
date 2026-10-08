// W2.2: following Graph's /content redirect without the token
// (rp/graph_download.hpp). Graph is served by one FakeHttpClient, SharePoint's
// download host by another, so the tests see exactly what went where. The
// Location's credential (kTempauth) is a sentinel no message or log line may
// hold. Only "the download client logs nothing" touches a socket, on 127.0.0.1.

#include "fake_http_client.hpp"
#include "local_http_server.hpp"
#include "test_certs.hpp"

#include <rp/client_assertion.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace std::chrono_literals;
using Catch::Matchers::ContainsSubstring;

namespace {

using nlohmann::json;
using rp::HttpError;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::TransportError;
using rp::graph::DownloadOptions;
using rp::graph::GraphClient;
using rp::graph::GraphClientOptions;
using rp::graph::SizeCheck;
using rp::test::FakeHttpClient;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using Clock = std::chrono::system_clock;

const std::string kTenant = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";
const std::string kClient = "737da5ef-baf2-4198-b009-e160d8ca77c9";
const std::string kTokenUrl =
    "https://login.microsoftonline.com/" + kTenant + "/oauth2/v2.0/token";
const std::string kGraph = "https://graph.microsoft.com/v1.0";

const Clock::time_point kNow = std::chrono::sys_days{std::chrono::year{2026} / 9 / 28} + 12h;
constexpr const char* kPfxPassword = "Sentinel-Download-PFX-Password-7c1e";

// The download link's credential: in no message, no log line.
const std::string kTempauth = "v1.SENTINEL-tempauth-value";
const std::string kTenantHost = "t.sharepoint.com";
const std::string kDrive = "b!DriveOfTheUnitTests_0123456789";
const std::string kItem = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const std::string kWhat = "the RestoreTarget library item " + kItem;
const std::string kContentUrl = kGraph + "/drives/" + kDrive + "/items/" + kItem + "/content";
const std::string kLocation = "https://t.sharepoint.com/sites/s/_layouts/15/download.aspx"
                              "?UniqueId=u&Translate=false&tempauth=" +
                              kTempauth + "&ApiVersion=2.0";

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
    return rp::test::to_response(fixture);
}

std::string header(const HttpRequest& request, const std::string& name)
{
    const auto it = request.headers.find(name);
    return it == request.headers.end() ? "(none)" : it->second;
}

HttpResponse redirect_to(const std::string& location, int status = 302)
{
    HttpResponse response = make_response(status);
    response.headers["Location"] = location;
    return response;
}

// Graph (with its token route) and the download host as a test sees them.
// Waits are recorded, never slept; every log line goes to a string.
struct Lab {
    Lab()
    {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("download_test", sink);
        logger->set_level(spdlog::level::trace);
        logger->set_formatter(std::make_unique<spdlog::pattern_formatter>(
            "%l %v", spdlog::pattern_time_type::utc, "\n"));
        graph_http.on(HttpMethod::post, kTokenUrl, {token_response()});
        graph = std::make_unique<GraphClient>(
            graph_http, kTenant, kClient,
            rp::graph::load_client_certificate(pfx_base64(), kPfxPassword, kNow), options());
    }

    GraphClientOptions options()
    {
        GraphClientOptions out;
        out.logger = logger;
        out.now = [] { return std::chrono::steady_clock::time_point{}; };
        out.wall_now = [] { return kNow; };
        out.sleep = [](std::chrono::milliseconds) {};
        out.jitter = [] { return 0.0; };
        return out;
    }

    DownloadOptions download_options()
    {
        DownloadOptions out;
        out.logger = logger;
        return out;
    }

    std::string download(std::uint64_t size, const std::string& tenant_host = kTenantHost,
                         const std::string& drive = kDrive,
                         const rp::graph::Grant& grant = rp::graph::kSitesReadGrant)
    {
        return rp::graph::download_item(*graph, dl_http, grant, tenant_host, drive, kItem, size,
                                        SizeCheck::exact, kWhat, download_options());
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    // The requests Graph got other than token requests.
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
};

Caught catch_download(const std::function<void()>& call)
{
    const auto fill = [](std::string kind, const rp::graph::GraphError& e) {
        return Caught{std::move(kind), e.what(), e.status(), {}};
    };
    try {
        call();
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
    } catch (const std::invalid_argument& e) {
        return Caught{"invalid_argument", e.what()};
    } catch (const std::exception& e) {
        return Caught{"other", e.what()};
    }
    return {};
}

// The drive ID in a recorded content request line ("GET /v1.0/drives/<d>/items/...").
std::string drive_of(const json& fixture)
{
    const std::string line = fixture.at("request").get<std::string>();
    const std::size_t start = line.find("/drives/") + 8;
    return line.substr(start, line.find("/items/") - start);
}

// "https://<host>/..." -> host
std::string host_of(const std::string& url)
{
    const std::size_t start = url.find("://") + 3;
    return url.substr(start, url.find('/', start) - start);
}

} // namespace

// ---- download_url_problem ---------------------------------------------------------------

TEST_CASE("download_url_problem refuses what isn't an https URL on the tenant's SharePoint",
          "[graph][download]")
{
    const std::string not_https = "not https";
    const std::string not_absolute = "not an absolute URL";
    const std::string host = "its host is not the test tenant's SharePoint";
    const std::string userinfo = "it has user info or a port other than 443";
    const std::string chars = "it holds whitespace, a control character, a backslash or '#'";
    const auto [url, reason] = GENERATE_COPY(table<std::string, std::string>({
        {"http://t.sharepoint.com/x", not_https},
        {"ftp://t.sharepoint.com/x", not_https},
        {"file:///c:/x", not_https},
        {"/x", not_absolute},
        {"//t.sharepoint.com/x", not_absolute},
        {"t.sharepoint.com/x", not_absolute},
        {"https:/t.sharepoint.com/x", not_absolute},
        {"https://t.sharepoint.com", not_absolute},
        {"https://t.sharepoint.com?tempauth=a", not_absolute},
        {"", not_absolute},
        {"https://evil.com/x", host},
        {"https://t.sharepoint.com.evil.com/x", host},
        {"https://a.t.sharepoint.com/x", host},
        {"https://sharepoint.com/x", host},
        {"https://graph.microsoft.com/v1.0/x", host},
        {"https://other.sharepoint.com/x", host},
        {"https://other-my.sharepoint.com/x", host},
        {"https:///x", host},
        {"https://u@t.sharepoint.com/x", userinfo},
        {"https://t.sharepoint.com@evil.com/x", userinfo},
        {"https://t.sharepoint.com:8443/x", userinfo},
        {"https://t.sharepoint.com:/x", userinfo},
        {"https://t.sharepoint.com/x y", chars},
        {"https://t.sharepoint.com/x\\y", chars},
        {"https://t.sharepoint.com/x#f", chars},
        {"https://t.sharepoint.com/x\r\n", chars},
        {"https://t.sharepoint.com/x\ty", chars},
        {"https://t.sharepoint.com/x\x7f", chars},
        {"https://t.sharepoint.com/x\xC2\x85", chars},
    }));
    CAPTURE(url);

    CHECK(rp::graph::download_url_problem(url, kTenantHost) == std::optional<std::string>{reason});
}

TEST_CASE("download_url_problem accepts the tenant's SharePoint and OneDrive hosts over https",
          "[graph][download]")
{
    const std::string url = GENERATE(as<std::string>{}, "https://t.sharepoint.com/x",
                                     "HTTPS://T-my.SharePoint.com:443/x?tempauth=a",
                                     "https://t-my.sharepoint.com/personal/a/download.aspx?a=b",
                                     "https://T.SHAREPOINT.COM:443/");
    CAPTURE(url);

    CHECK(rp::graph::download_url_problem(url, kTenantHost) == std::nullopt);
}

TEST_CASE("download_url_problem refuses every host for a tenant host that isn't SharePoint's",
          "[graph][download]")
{
    const std::string tenant_host =
        GENERATE(as<std::string>{}, "", ".sharepoint.com", "evil.com", "sharepoint.com");
    CAPTURE(tenant_host);

    for (const std::string url : {"https://evil.com/x", "https://-my.sharepoint.com/x",
                                  "https://.sharepoint.com/x", "https://sharepoint.com/x"}) {
        CAPTURE(url);
        CHECK(rp::graph::download_url_problem(url, tenant_host) ==
              std::optional<std::string>{"its host is not the test tenant's SharePoint"});
    }
}

// ---- download_item: failure paths ---------------------------------------------------------

TEST_CASE("bad download options are refused before any request", "[graph][download]")
{
    Lab lab;
    DownloadOptions options = lab.download_options();
    const int row = GENERATE(0, 1, 2);
    if (row == 0) {
        options.max_bytes = 0;
    } else {
        options.timeout = row == 1 ? 0ms : -1ms;
    }
    CAPTURE(row);

    const Caught caught = catch_download([&] {
        rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                                 kDrive, kItem, 10, SizeCheck::exact, kWhat, options);
    });

    CHECK(caught.kind == "invalid_argument");
    CHECK(caught.what == "download options: max_bytes and timeout must be above 0");
    CHECK(lab.graph_http.requests().empty());
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("a file over the cap is refused before any request", "[graph][download]")
{
    Lab lab;
    DownloadOptions options = lab.download_options();
    options.max_bytes = 100;

    const Caught caught = catch_download([&] {
        rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                                 kDrive, kItem, 101, SizeCheck::exact, kWhat, options);
    });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == kWhat + " is 101 bytes, over the 100 byte download limit; nothing was "
                                 "downloaded");
    CHECK(lab.graph_http.requests().empty());
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("the default download cap is 64 MiB", "[graph][download]")
{
    CHECK(rp::graph::kMaxDownloadBytes == 64ull * 1024 * 1024);
    CHECK(DownloadOptions{}.max_bytes == rp::graph::kMaxDownloadBytes);
    CHECK(DownloadOptions{}.timeout == 120s);

    Lab lab;
    const Caught caught = catch_download([&] {
        rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                                 kDrive, kItem, rp::graph::kMaxDownloadBytes + 1, SizeCheck::exact, kWhat);
    });
    CHECK(caught.kind == "GraphError");
    CHECK(lab.graph_http.requests().empty());
}

TEST_CASE("Graph's /content errors keep their W2.1 type", "[graph][download]")
{
    struct Row {
        std::string name;
        std::string kind;
        int status;
    };
    const Row row = GENERATE(Row{"onedrive-folder-403-accessdenied", "PermissionError", 403},
                             Row{"onedrive-folder-404-itemnotfound", "NotFoundError", 404},
                             Row{"503", "TransientError", 503});
    CAPTURE(row.name);
    Lab lab;
    if (row.name == "503") {
        HttpResponse busy = make_response(503, R"({"error":{"code":"serviceNotAvailable","message":"x"}})");
        busy.headers["Retry-After"] = "1";
        lab.graph_http.on(HttpMethod::get, kContentUrl, {busy});
    } else {
        lab.graph_http.on(HttpMethod::get, kContentUrl, {load_fixture("graph", row.name)});
    }

    const Caught caught =
        catch_download([&] { lab.download(10, kTenantHost, kDrive, rp::graph::kOneDriveGrant); });

    CHECK(caught.kind == row.kind);
    CHECK(caught.status == row.status);
    if (row.kind == "PermissionError") {
        CHECK(caught.grant == std::string{rp::graph::kOneDriveGrant.description});
    }
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("a redirect without Location, with an empty one or a bad one downloads nothing",
          "[graph][download]")
{
    const auto bad = [](const std::string& problem) {
        return "Graph's redirect for " + kWhat +
               " is not an https URL on the test tenant's SharePoint (" + problem +
               "); nothing was downloaded";
    };
    struct Row {
        std::optional<std::string> location;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{std::nullopt, "Graph's redirect for " + kWhat + " has no Location; nothing was downloaded"},
        Row{"", "Graph's redirect for " + kWhat + " has no Location; nothing was downloaded"},
        Row{"http://t.sharepoint.com/x?tempauth=" + kTempauth, bad("not https")},
        Row{"https://evil.com/x?tempauth=" + kTempauth,
            bad("its host is not the test tenant's SharePoint")},
        Row{"https://graph.microsoft.com/v1.0/x?tempauth=" + kTempauth,
            bad("its host is not the test tenant's SharePoint")},
        Row{"/x?tempauth=" + kTempauth, bad("not an absolute URL")},
        Row{"https://u@t.sharepoint.com/x?tempauth=" + kTempauth,
            bad("it has user info or a port other than 443")},
        Row{"https://t.sharepoint.com/x?tempauth=" + kTempauth + "#f",
            bad("it holds whitespace, a control character, a backslash or '#'")});
    CAPTURE(row.location.value_or("(none)"));
    Lab lab;
    HttpResponse response = make_response(302);
    if (row.location) {
        response.headers["Location"] = *row.location;
    }
    lab.graph_http.on(HttpMethod::get, kContentUrl, {response});

    const Caught caught = catch_download([&] { lab.download(10); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == row.message);
    CHECK(caught.status == 302);
    CHECK(lab.dl_http.requests().empty());
    CHECK_THAT(caught.what, !ContainsSubstring(kTempauth));
    CHECK_THAT(lab.log(), !ContainsSubstring(kTempauth));
    CHECK_THAT(lab.log(), !ContainsSubstring("evil.com"));
}

TEST_CASE("Graph's non-redirect statuses are errors", "[graph][download]")
{
    const auto [status, message] = GENERATE_COPY(table<int, std::string>({
        {204, "Graph answered 204 to the content request for " + kWhat +
                  ", neither the file nor a redirect"},
        {206, "Graph answered 206 to the content request for " + kWhat +
                  ", neither the file nor a redirect"},
        {300, "Graph answered 300 to the content request for " + kWhat +
                  ", not a redirect the Worker follows"},
        {304, "Graph answered 304 to the content request for " + kWhat +
                  ", not a redirect the Worker follows"},
    }));
    CAPTURE(status);
    Lab lab;
    lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation, status)});

    const Caught caught = catch_download([&] { lab.download(10); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == message);
    CHECK(caught.status == status);
    CHECK(lab.dl_http.requests().empty());
}

TEST_CASE("the download's failures map to error types", "[graph][download]")
{
    struct Row {
        std::string name;
        std::optional<int> returned;          // a response dl_http returns
        std::optional<TransportError> thrown; // or an HttpError it throws
        int thrown_status;
        int attempts;
        std::string kind;
        std::string message;
        int status;
    };
    const std::string expired = "SharePoint refused the download of " + kWhat;
    const Row row = GENERATE_COPY(
        Row{"301", 301, {}, 0, 0, "GraphError",
            "SharePoint redirected the download of " + kWhat + " again (301); nothing was downloaded",
            301},
        Row{"302", 302, {}, 0, 0, "GraphError",
            "SharePoint redirected the download of " + kWhat + " again (302); nothing was downloaded",
            302},
        Row{"401", 401, {}, 0, 0, "GraphError",
            expired + " (401); the link Graph gave may have expired", 401},
        Row{"403", 403, {}, 0, 0, "GraphError",
            expired + " (403); the link Graph gave may have expired", 403},
        Row{"404", 404, {}, 0, 0, "GraphError",
            "SharePoint has no content for " + kWhat +
                " (404); it may have been removed while the Worker read it",
            404},
        Row{"429", 429, {}, 0, 0, "TransientError",
            "the download of " + kWhat + " failed: SharePoint answered 429", 429},
        Row{"418", 418, {}, 0, 0, "GraphError",
            "SharePoint answered 418 to the download of " + kWhat, 418},
        Row{"201", 201, {}, 0, 0, "GraphError",
            "SharePoint answered 201 to the download of " + kWhat, 201},
        // HttpClient retries a 5xx and throws when they are used up; one returned
        // all the same is transient too, as its retries would be.
        Row{"500 returned", 500, {}, 0, 0, "TransientError",
            "the download of " + kWhat + " failed: SharePoint answered 500", 500},
        Row{"503 returned", 503, {}, 0, 0, "TransientError",
            "the download of " + kWhat + " failed: SharePoint answered 503", 503},
        Row{"timeout", {}, TransportError::timeout, 0, 5, "TransientError",
            "the download of " + kWhat + " failed after 5 attempt(s)", 0},
        Row{"connect", {}, TransportError::connect, 0, 5, "TransientError",
            "the download of " + kWhat + " failed after 5 attempt(s)", 0},
        Row{"dropped", {}, TransportError::dropped, 0, 5, "TransientError",
            "the download of " + kWhat + " failed after 5 attempt(s)", 0},
        Row{"handshake", {}, TransportError::handshake, 0, 5, "TransientError",
            "the download of " + kWhat + " failed after 5 attempt(s)", 0},
        Row{"5xx used up", {}, TransportError::none, 503, 5, "TransientError",
            "the download of " + kWhat + " failed after 5 attempt(s)", 503},
        Row{"4xx thrown", {}, TransportError::none, 400, 1, "GraphError",
            "SharePoint answered 400 to the download of " + kWhat, 400},
        Row{"tls", {}, TransportError::tls, 0, 1, "GraphError",
            "the download of " + kWhat +
                " failed: SharePoint's certificate was not trusted, or TLS could not be set up",
            0},
        // A refused connection is `connect`, retried above; `other` is the rest.
        Row{"other", {}, TransportError::other, 0, 1, "GraphError",
            "the download of " + kWhat +
                " failed and was not retried: SharePoint's reply was malformed, or the request "
                "failed on this machine",
            0});
    CAPTURE(row.name);
    Lab lab;
    lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation)});
    if (row.returned) {
        HttpResponse response = *row.returned >= 300 && *row.returned < 400
                                    ? redirect_to(kLocation, *row.returned)
                                    : make_response(*row.returned, "0123456789", "text/plain");
        lab.dl_http.on(HttpMethod::get, kLocation, {response});
    } else {
        const TransportError error = *row.thrown;
        const int status = row.thrown_status;
        const int attempts = row.attempts;
        lab.dl_http.on(HttpMethod::get, kLocation, [=](const HttpRequest& request) -> HttpResponse {
            throw HttpError("GET " + request.url + " failed", error, status, attempts);
        });
    }

    const Caught caught = catch_download([&] { lab.download(10); });

    CHECK(caught.kind == row.kind);
    CHECK(caught.what == row.message);
    CHECK(caught.status == row.status);
    CHECK(lab.dl_http.requests().size() == 1);
    CHECK_THAT(caught.what, !ContainsSubstring(kTempauth));
    CHECK_THAT(lab.log(), !ContainsSubstring(kTempauth));
}

TEST_CASE("a size mismatch is an error, not a smaller item", "[graph][download]")
{
    const auto [body, message] = GENERATE_COPY(table<std::string, std::string>({
        {"012345678", "SharePoint sent 9 bytes for " + kWhat + ", Graph lists 10; nothing was hashed"},
        {"", "SharePoint sent 0 bytes for " + kWhat + ", Graph lists 10; nothing was hashed"},
        {"0123456789A", "SharePoint sent more than the 10 bytes Graph lists for " + kWhat +
                            "; nothing was hashed"},
    }));
    CAPTURE(body);
    const bool from_graph = GENERATE(false, true);
    CAPTURE(from_graph);
    Lab lab;
    if (from_graph) {
        lab.graph_http.on(HttpMethod::get, kContentUrl,
                          {make_response(200, body, "application/octet-stream")});
    } else {
        lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation)});
        lab.dl_http.on(HttpMethod::get, kLocation,
                       {make_response(200, body, "application/octet-stream")});
    }

    const Caught caught = catch_download([&] { lab.download(10); });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == message);
}

// W4.8 (docs/decisions.md 2026-10-08 point 13): the one wait of a run that
// didn't go through the pipeline's sleep.
TEST_CASE("the download client waits between its attempts on the sleep it is given",
          "[graph][download]")
{
    rp::test::LocalHttpServer server;
    std::atomic<int> calls{0};
    server.server().Get("/x", [&calls](const httplib::Request&, httplib::Response& res) {
        if (++calls == 1) {
            res.status = 503;
            return;
        }
        res.status = 200;
        res.set_content("ok", "application/octet-stream");
    });
    std::vector<std::chrono::milliseconds> waits;
    const std::unique_ptr<rp::IHttpClient> client = rp::graph::make_download_http_client(
        [&waits](std::chrono::milliseconds wait) { waits.push_back(wait); });

    const HttpResponse response = client->get(server.url("/x"));

    CHECK(response.status == 200);
    CHECK(response.body == "ok");
    CHECK(calls == 2);
    // The wait after the 503, and never a real one.
    REQUIRE(waits.size() == 1);
    CHECK(waits[0] > std::chrono::milliseconds{0});
}

TEST_CASE("the download client logs nothing", "[graph][download]")
{
    std::ostringstream stream;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(stream);
    auto capture = std::make_shared<spdlog::logger>("download_default", sink);
    capture->set_level(spdlog::level::trace);
    const std::shared_ptr<spdlog::logger> saved = spdlog::default_logger();
    spdlog::set_default_logger(capture);
    struct Restore {
        std::shared_ptr<spdlog::logger> logger;
        ~Restore() { spdlog::set_default_logger(logger); }
    } restore{saved};

    rp::test::LocalHttpServer server;
    server.server().Get("/x", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
        res.set_content("ok", "application/octet-stream");
    });
    const std::unique_ptr<rp::IHttpClient> client = rp::graph::make_download_http_client();

    const HttpResponse response = client->get(server.url("/x?tempauth=" + kTempauth));

    capture->flush();
    CHECK(response.status == 200);
    CHECK(response.body == "ok");
    CHECK(stream.str().empty());
}

// ---- download_item: happy paths ----------------------------------------------------------

TEST_CASE("the download goes to Location without the token, with only User-Agent and Accept",
          "[graph][download]")
{
    const std::string name =
        GENERATE(as<std::string>{}, "restoretarget-content-302", "onedrive-content-302");
    CAPTURE(name);
    const json fixture = load_fixture_json("graph", name);
    const std::string location = fixture.at("headers").at("Location").get<std::string>();
    std::string tenant_host = host_of(location);
    if (const std::size_t my = tenant_host.find("-my."); my != std::string::npos) {
        tenant_host.erase(my, 3);
    }
    const std::string drive = drive_of(fixture);
    const std::string content_url = kGraph + "/drives/" + drive + "/items/" + kItem + "/content";
    Lab lab;
    lab.graph_http.on(HttpMethod::get, content_url, {rp::test::to_response(fixture)});
    lab.dl_http.on(HttpMethod::get, location,
                   {make_response(200, "canary-bytes", "application/octet-stream")});

    const std::string bytes = lab.download(12, tenant_host, drive);

    CHECK(bytes == "canary-bytes");
    const std::vector<HttpRequest> downloads = lab.dl_http.requests();
    REQUIRE(downloads.size() == 1);
    const HttpRequest& request = downloads.front();
    CHECK(request.method == HttpMethod::get);
    CHECK(request.url == location);
    CHECK(header(request, "Authorization") == "(none)");
    std::set<std::string> names;
    for (const auto& [key, value] : request.headers) {
        names.insert(key);
    }
    CHECK(names == std::set<std::string>{"Accept", "User-Agent"});
    CHECK(header(request, "Accept") == "*/*");
    CHECK(header(request, "User-Agent") == rp::graph::user_agent());
    CHECK(request.max_body_bytes == std::optional<std::uint64_t>{12});
    CHECK(request.retry_on_status);
    CHECK(request.max_attempts == rp::kMaxHttpAttempts);
    CHECK(request.timeout == 120s);
    CHECK(request.body.empty());
    CHECK(request.url.find("graph.microsoft.com") == std::string::npos);

    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 1);
    CHECK(gets.front().url == content_url);
    CHECK(header(gets.front(), "Authorization") == "Bearer token-1");

    const std::string log = lab.log();
    CHECK_THAT(log, ContainsSubstring("download of " + kWhat + ": following Graph's redirect to " +
                                      host_of(location)));
    CHECK_THAT(log, ContainsSubstring("download of " + kWhat + ": 200, 12 bytes"));
    CHECK_THAT(log, !ContainsSubstring("download.aspx"));
}

TEST_CASE("every redirect status Graph may use is followed", "[graph][download]")
{
    const int status = GENERATE(301, 302, 303, 307, 308);
    CAPTURE(status);
    Lab lab;
    lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation, status)});
    lab.dl_http.on(HttpMethod::get, kLocation, {make_response(200, "abc", "text/plain")});

    CHECK(lab.download(3) == "abc");
}

TEST_CASE("a download timeout from the options goes with the request", "[graph][download]")
{
    Lab lab;
    lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation)});
    lab.dl_http.on(HttpMethod::get, kLocation, {make_response(200, "abc", "text/plain")});
    DownloadOptions options = lab.download_options();
    options.timeout = 7s;

    rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                             kDrive, kItem, 3, SizeCheck::exact, kWhat, options);

    REQUIRE(lab.dl_http.requests().size() == 1);
    CHECK(lab.dl_http.requests().front().timeout == 7s);
}

TEST_CASE("a 200 from Graph's /content is the content", "[graph][download]")
{
    Lab lab;
    lab.graph_http.on(HttpMethod::get, kContentUrl,
                      {make_response(200, "hello", "application/octet-stream")});

    CHECK(lab.download(5) == "hello");
    CHECK(lab.dl_http.requests().empty());
    // Held to the same cap as a download from SharePoint (review of W2.2).
    const std::vector<HttpRequest> gets = lab.graph_gets();
    REQUIRE(gets.size() == 1);
    CHECK(gets.front().max_body_bytes == std::optional<std::uint64_t>{5});
    CHECK_THAT(lab.log(), ContainsSubstring("download of " + kWhat + ": 200, 5 bytes"));
}

TEST_CASE("an empty file downloads as 0 bytes", "[graph][download]")
{
    Lab lab;
    lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation)});
    lab.dl_http.on(HttpMethod::get, kLocation, {make_response(200)});

    CHECK(lab.download(0).empty());
    REQUIRE(lab.dl_http.requests().size() == 1);
    CHECK(lab.dl_http.requests().front().max_body_bytes == std::optional<std::uint64_t>{0});
}

TEST_CASE("the download logs go to the spdlog default when no logger is given", "[graph][download]")
{
    Lab lab;
    lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation)});
    lab.dl_http.on(HttpMethod::get, kLocation, {make_response(200, "abc", "text/plain")});
    std::ostringstream stream;
    auto capture = std::make_shared<spdlog::logger>(
        "download_default_2", std::make_shared<spdlog::sinks::ostream_sink_mt>(stream));
    capture->set_level(spdlog::level::debug);
    const std::shared_ptr<spdlog::logger> saved = spdlog::default_logger();
    spdlog::set_default_logger(capture);
    struct Restore {
        std::shared_ptr<spdlog::logger> logger;
        ~Restore() { spdlog::set_default_logger(logger); }
    } restore{saved};

    rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                             kDrive, kItem, 3, SizeCheck::exact, kWhat);

    capture->flush();
    CHECK_THAT(stream.str(), ContainsSubstring("download of " + kWhat + ": 200, 3 bytes"));
    CHECK_THAT(stream.str(), !ContainsSubstring(kTempauth));
}

// ---- SizeCheck::up_to_limit: an Office package SharePoint may rewrite -------------------

// Review of W2.2: SharePoint rewrites Office files (lab/README.md, office-v1), so
// the bytes served may differ from the size Graph listed. Such a file is read up
// to the download limit, whatever its size, and returned as it came.
TEST_CASE("up_to_limit takes any size up to max_bytes", "[graph][download]")
{
    const std::string body = GENERATE(as<std::string>{}, "", "0123456", "0123456789",
                                       "0123456789abcdef", std::string(20, 'z'));
    CAPTURE(body.size());
    const bool from_graph = GENERATE(false, true);
    CAPTURE(from_graph);
    Lab lab;
    if (from_graph) {
        lab.graph_http.on(HttpMethod::get, kContentUrl,
                          {make_response(200, body, "application/octet-stream")});
    } else {
        lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation)});
        lab.dl_http.on(HttpMethod::get, kLocation,
                       {make_response(200, body, "application/octet-stream")});
    }
    DownloadOptions options = lab.download_options();
    options.max_bytes = 20;

    const std::string bytes =
        rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                                 kDrive, kItem, 10, SizeCheck::up_to_limit, kWhat, options);

    CHECK(bytes == body);
    const HttpRequest request =
        from_graph ? lab.graph_gets().front() : lab.dl_http.requests().front();
    CHECK(request.max_body_bytes == std::optional<std::uint64_t>{20});
    if (body.size() != 10) {
        CHECK_THAT(lab.log(), ContainsSubstring("download of " + kWhat + ": 200, " +
                                                std::to_string(body.size()) +
                                                " bytes; Graph lists 10"));
    }
}

TEST_CASE("up_to_limit refuses a body over max_bytes", "[graph][download]")
{
    const bool from_graph = GENERATE(false, true);
    CAPTURE(from_graph);
    Lab lab;
    const std::string body(21, 'z');
    if (from_graph) {
        lab.graph_http.on(HttpMethod::get, kContentUrl,
                          {make_response(200, body, "application/octet-stream")});
    } else {
        lab.graph_http.on(HttpMethod::get, kContentUrl, {redirect_to(kLocation)});
        lab.dl_http.on(HttpMethod::get, kLocation,
                       {make_response(200, body, "application/octet-stream")});
    }
    DownloadOptions options = lab.download_options();
    options.max_bytes = 20;

    const Caught caught = catch_download([&] {
        rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                                 kDrive, kItem, 10, SizeCheck::up_to_limit, kWhat, options);
    });

    CHECK(caught.kind == "GraphError");
    CHECK(caught.what == "SharePoint sent more than the 20 byte download limit for " + kWhat +
                             "; nothing was hashed");
}

TEST_CASE("up_to_limit still refuses a listed size over max_bytes before any request",
          "[graph][download]")
{
    Lab lab;
    DownloadOptions options = lab.download_options();
    options.max_bytes = 100;

    const Caught caught = catch_download([&] {
        rp::graph::download_item(*lab.graph, lab.dl_http, rp::graph::kSitesReadGrant, kTenantHost,
                                 kDrive, kItem, 101, SizeCheck::up_to_limit, kWhat, options);
    });

    CHECK(caught.kind == "GraphError");
    CHECK(lab.graph_http.requests().empty());
}
