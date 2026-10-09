// W1.7: rp::VeeamM365Connector, the Veeam Backup for Microsoft 365 connector,
// against the recorded Veeam responses in tests/fixtures/veeam/, served by
// FakeHttpClient. No network. The rules are the 2026-09-27 W1.7 entry in
// docs/decisions.md.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>
#include <rp/run_status.hpp>
#include <rp/secrets.hpp>
#include <rp/veeam_m365_connector.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::Message;

namespace {

namespace connector = rp::connector;
using nlohmann::json;
using rp::HttpMethod;
using rp::HttpResponse;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using rp::test::to_response;

const std::string kBase = "https://veeam.test:4443";
const std::string kTokenUrl = kBase + "/v8/token";
const std::string kLogoutUrl = kBase + "/v8/token/logout";
const std::string kOrgId = "ff96d072-29e2-4cb4-a155-2590f5473176";
const std::string kOrgName = "RestoreProofLab.onmicrosoft.com";
const std::string kUsername = "DESKTOP-P55CDUM\\rp-veeam";
// Never in an error, a log line or output.
const std::string kPassword = "SENTINEL-PASSWORD-7d3a";
const std::string kAccessToken = "SENTINEL-ACCESS-TOKEN-7d3a";
const std::string kRefreshToken = "SENTINEL-REFRESH-TOKEN-7d3a";

const std::string kNewestPoint =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e371ac3d9c-eb29-42b6-a391-ae81fcc4681c";
const std::string kOldestPoint =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e32fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7";
const std::string kNewestTime = "2026-09-25T19:37:15.2145203Z";
const std::string kOldestTime = "2026-09-25T19:24:31.0936821Z";

std::string orgs_url()
{
    return kBase + "/v8/Organizations?limit=1000&offset=0";
}

std::string points_url(const std::string& org = kOrgId)
{
    return kBase + "/v8/RestorePoints?organizationId=" + org + "&limit=1000&offset=0";
}

HttpResponse token_response()
{
    json fixture = load_fixture_json("veeam", "token-200");
    fixture["body"]["access_token"] = kAccessToken;
    fixture["body"]["refresh_token"] = kRefreshToken;
    return to_response(fixture);
}

// The recorded organisation list with its one organisation changed by `edit`,
// and copies of it added for each of `extra`.
HttpResponse orgs_response(const std::function<void(json&)>& edit = {},
                           const std::vector<std::pair<std::string, std::string>>& extra = {})
{
    json fixture = load_fixture_json("veeam", "organizations-200");
    json& results = fixture["body"]["results"];
    if (edit) {
        edit(results[0]);
    }
    for (const auto& [id, name] : extra) {
        json copy = results[0];
        copy["id"] = id;
        copy["name"] = name;
        results.push_back(std::move(copy));
    }
    return to_response(fixture);
}

// The lab's restore targets as the recorded Graph replies show them, and the
// Worker app's IDs, so the guard the factory builds can resolve them.
rp::Config lab_config()
{
    rp::Config config = rp::test::graph_lab::lab_config();
    config.cloud_url = "https://cloud.example.invalid";
    config.veeam_url = kBase;
    config.veeam_org_name = kOrgName;
    config.graph_tenant_id = rp::test::graph_lab::kTenant;
    config.graph_client_id = rp::test::graph_lab::kClient;
    return config;
}

// The four secrets: Veeam's, and the Worker app's certificate (graph_lab.hpp).
rp::Secrets lab_secrets()
{
    return {kUsername, kPassword, rp::test::graph_lab::pfx_base64(),
            std::string{rp::test::graph_lab::kPfxPassword}};
}

// A connector on a FakeHttpClient serving the lab's recorded answers, made
// through the default registry as the pipeline will make it; its Graph client
// talks to the guard lab's FakeHttpClient (the recorded replies for the three
// restore targets). Waits are recorded, never slept; every log line lands in a
// string.
struct Harness {
    Harness()
    {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("veeam_m365_connector_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::trace);
        http.on(HttpMethod::post, kTokenUrl, {token_response()});
        http.on(HttpMethod::get, orgs_url(), {orgs_response()});
        http.on(HttpMethod::get, points_url(), {load_fixture("veeam", "restore-points-200")});
        http.on(HttpMethod::post, kLogoutUrl, {load_fixture("veeam", "logout-204")});
    }

    connector::ConnectorOptions options()
    {
        connector::ConnectorOptions o;
        // W4.10: the client's profile, as the pipeline hands it.
        o.client = rp::local_profile(config);
        o.make_http = [this](const rp::HttpClientOptions& given) -> std::unique_ptr<rp::IHttpClient> {
            ++make_http_calls;
            http_options = given;
            if (!give_http) {
                return nullptr;
            }
            return std::make_unique<rp::test::ForwardingHttpClient>(http);
        };
        o.make_graph_http =
            [this](std::shared_ptr<spdlog::logger> given) -> std::unique_ptr<rp::IHttpClient> {
            ++make_graph_http_calls;
            graph_http_logger = std::move(given);
            return std::make_unique<rp::test::ForwardingHttpClient>(guard_lab.graph_http);
        };
        o.logger = logger;
        o.sleep = [this](std::chrono::milliseconds wait) { sleeps.push_back(wait); };
        o.jitter = [] { return 0.0; };
        o.now = [] { return std::chrono::steady_clock::time_point{}; };
        o.wall_now = [] { return rp::test::graph_lab::kNow; };
        return o;
    }

    std::unique_ptr<connector::IConnector> make()
    {
        return connector::default_connector_registry().create(connector::kVeeamM365, config,
                                                              secrets, options());
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    rp::test::FakeHttpClient http;
    rp::test::target_guard_lab::GuardLab guard_lab;
    rp::Config config = lab_config();
    rp::Secrets secrets = lab_secrets();
    bool give_http = true;
    int make_http_calls = 0;
    int make_graph_http_calls = 0;
    std::shared_ptr<spdlog::logger> graph_http_logger;
    std::optional<rp::HttpClientOptions> http_options;
    std::vector<std::chrono::milliseconds> sleeps;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
};

// Which connector error `thrower` throws, as the most derived class's name.
std::string kind_of(const std::function<void()>& thrower, std::string& message)
{
    try {
        thrower();
    } catch (const connector::AuthError& e) {
        message = e.what();
        return "AuthError";
    } catch (const connector::TransientError& e) {
        message = e.what();
        return "TransientError";
    } catch (const connector::NotFoundError& e) {
        message = e.what();
        return "NotFoundError";
    } catch (const connector::NotImplementedError& e) {
        message = e.what();
        return "NotImplementedError";
    } catch (const connector::Error& e) {
        message = e.what();
        return "Error";
    } catch (const std::exception& e) {
        message = e.what();
        return "not a connector error";
    }
    return "nothing thrown";
}

void require_no_secret(const std::string& text)
{
    CHECK_THAT(text, !ContainsSubstring(kPassword));
    CHECK_THAT(text, !ContainsSubstring(kAccessToken));
    CHECK_THAT(text, !ContainsSubstring(kRefreshToken));
}

connector::RestoreSpec one_mail_spec(const rp::Config& config)
{
    connector::RestorePoint point;
    point.id = kNewestPoint;
    point.backup_time = kNewestTime;
    point.has_mail = true;
    return {.client_ref = kOrgName,
            .restore_point = point,
            .targets = connector::RestoreTargets::from_config(config),
            .mail = {{"alice@RestoreProofLab.onmicrosoft.com", "Inbox", "RP-CANARY-0001"}}};
}

} // namespace

// --- Failure paths ---------------------------------------------------------------

TEST_CASE("veeam_m365: the registry's connector runs the target guard through its own Graph "
          "client, before any Veeam request",
          "[veeam_m365][target_guard]")
{
    Harness lab;
    const std::unique_ptr<connector::IConnector> made = lab.make();
    connector::IConnector& source = *made;
    // A mail item sampled from the test mailbox itself: refused before Graph.
    connector::RestoreSpec spec = one_mail_spec(lab.config);
    spec.mail.front().mailbox = lab.config.test_mailbox;

    REQUIRE_THROWS_AS(source.restore_sample(spec), connector::SafetyViolation);
    CHECK(lab.http.requests().empty());
    CHECK(lab.guard_lab.graph_gets() == 0);
    // The refusal's SECURITY line went to the logger the factory was given,
    // not to stdout.
    CHECK_THAT(lab.log(), ContainsSubstring("SECURITY: target guard: mail item 0 is sampled from a "
                                            "restore target"));
}

TEST_CASE("veeam_m365: the registry's connector refuses a target Graph shows is wrong",
          "[veeam_m365][target_guard]")
{
    Harness lab;
    lab.guard_lab.serve_edited(rp::test::graph_lab::drive_url(), "restoretarget-drive-200",
                               [](json& body) { body["name"] = "Dokumenty"; });
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE_THROWS_AS(made->restore_sample(rp::test::target_guard_lab::full_spec()),
                      connector::SafetyViolation);
    CHECK(lab.guard_lab.gets(rp::test::graph_lab::drive_url()) == 1);
    CHECK(lab.http.requests().empty());
    CHECK_THAT(lab.log(), ContainsSubstring("SECURITY: target guard: the drive test_library_id"));
    CHECK(lab.graph_http_logger == lab.logger);
}

TEST_CASE("veeam_m365: each Veeam failure is the matching connector error", "[veeam_m365]")
{
    // Where the failure is and what Veeam answers there.
    struct Case {
        std::string where; // "token", "orgs" or "points"
        HttpResponse answer;
        std::string kind;
        std::string message_part;
    };
    const Case c = GENERATE(
        Case{"token", load_fixture("veeam", "token-rejected-401"), "AuthError",
             "Veeam POST /v8/token: HTTP 401"},
        Case{"token", load_fixture("veeam", "token-rejected-500-empty"), "AuthError", "500"},
        Case{"orgs", make_response(503), "TransientError", "503"},
        Case{"points", make_response(504), "TransientError", "504"},
        Case{"points", load_fixture("veeam", "restore-points-unknown-org-404"), "NotFoundError",
             "404"},
        Case{"orgs", load_fixture("veeam", "explore-500-before-first"), "Error", "500"},
        Case{"points", load_fixture("veeam", "restore-points-bad-query-400"), "Error", "400"});
    CAPTURE(c.where, c.kind);
    Harness lab;
    const std::string url = c.where == "token" ? kTokenUrl
                            : c.where == "orgs" ? orgs_url()
                                                : points_url();
    lab.http.on(c.where == "token" ? HttpMethod::post : HttpMethod::get, url, {c.answer});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    std::string message;
    REQUIRE(kind_of([&] { (void)made->list_restore_points(kOrgName); }, message) == c.kind);
    // The Veeam error's own message, which names the call and the status.
    REQUIRE_THAT(message, ContainsSubstring(c.message_part));
    require_no_secret(message);
    require_no_secret(lab.log());
}

// --- The client's facts (W4.11 point 2) ----------------------------------------------

TEST_CASE("veeam_m365: the client's facts are the organisation's name, msid, type and region as "
          "sent, each empty when Veeam sent none",
          "[veeam_m365][client_check][w4.11]")
{
    struct Row {
        const char* name;
        std::function<void(json&)> edit;
        connector::ClientFacts facts;
    };
    const Row row = GENERATE(
        Row{"as recorded", {},
            {"RestoreProofLab.onmicrosoft.com", "bcd6bd1a-ea42-489d-aa28-2c19a44ad146",
             "Office365", "Worldwide"}},
        Row{"no msid", [](json& org) { org.erase("msid"); },
            {"RestoreProofLab.onmicrosoft.com", "", "Office365", "Worldwide"}},
        Row{"msid null", [](json& org) { org["msid"] = nullptr; },
            {"RestoreProofLab.onmicrosoft.com", "", "Office365", "Worldwide"}},
        Row{"no type", [](json& org) { org.erase("type"); },
            {"RestoreProofLab.onmicrosoft.com", "bcd6bd1a-ea42-489d-aa28-2c19a44ad146", "",
             "Worldwide"}},
        Row{"another type and region, as sent",
            [](json& org) {
                org["type"] = "Office365Germany";
                org["region"] = "Germany";
            },
            {"RestoreProofLab.onmicrosoft.com", "bcd6bd1a-ea42-489d-aa28-2c19a44ad146",
             "Office365Germany", "Germany"}},
        Row{"the name as Veeam has it, whatever case was asked",
            [](json& org) { org["name"] = "restoreprooflab.onmicrosoft.com"; },
            {"restoreprooflab.onmicrosoft.com", "bcd6bd1a-ea42-489d-aa28-2c19a44ad146",
             "Office365", "Worldwide"}});
    CAPTURE(row.name);
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(), {orgs_response(row.edit)});
    lab.secrets.graph_cert_pfx_base64.reset();
    const std::unique_ptr<connector::IConnector> made = lab.make();

    const connector::ClientFacts facts = made->client_facts(kOrgName);

    CHECK(facts == row.facts);
    // Nothing of Graph, and no session.
    CHECK(lab.make_graph_http_calls == 0);
    CHECK(lab.guard_lab.graph_gets() == 0);
}

TEST_CASE("veeam_m365: the client's facts fail as listing restore points fails: an unknown "
          "client, two matches, Veeam's own errors, an empty reference",
          "[veeam_m365][client_check][w4.11]")
{
    Harness lab;
    SECTION("a client Veeam doesn't know is NotFoundError")
    {
        const std::unique_ptr<connector::IConnector> made = lab.make();
        REQUIRE_THROWS_AS(made->client_facts("other.onmicrosoft.com"), connector::NotFoundError);
    }
    SECTION("two organisations of the name are an Error")
    {
        lab.http.on(HttpMethod::get, orgs_url(),
                    {orgs_response({}, {{"22222222-2222-4222-8222-222222222222", kOrgName}})});
        const std::unique_ptr<connector::IConnector> made = lab.make();
        std::string message;
        CHECK(kind_of([&] { (void)made->client_facts(kOrgName); }, message) == "Error");
        CHECK_THAT(message, ContainsSubstring("matches 2 organisations"));
    }
    SECTION("Veeam unavailable is a TransientError, a refused token an AuthError")
    {
        lab.http.on(HttpMethod::get, orgs_url(), {make_response(503)});
        const std::unique_ptr<connector::IConnector> made = lab.make();
        REQUIRE_THROWS_AS(made->client_facts(kOrgName), connector::TransientError);
        lab.http.on(HttpMethod::post, kTokenUrl, {load_fixture("veeam", "token-rejected-401")});
        const std::unique_ptr<connector::IConnector> again = lab.make();
        REQUIRE_THROWS_AS(again->client_facts(kOrgName), connector::AuthError);
    }
    SECTION("an empty reference is refused before any request")
    {
        const std::unique_ptr<connector::IConnector> made = lab.make();
        REQUIRE_THROWS_AS(made->client_facts(""), std::invalid_argument);
        CHECK(lab.http.requests().empty());
    }
}

TEST_CASE("veeam_m365: the registry's connector refuses a restore spec that isn't its client's, "
          "before the guard and before any request (finding 8)",
          "[veeam_m365][client_check][w4.11]")
{
    Harness lab;
    const std::unique_ptr<connector::IConnector> made = lab.make();
    connector::RestoreSpec spec = one_mail_spec(lab.config);
    SECTION("another organisation")
    {
        spec.client_ref = "other.onmicrosoft.com";
    }
    SECTION("another client's targets")
    {
        rp::Config other = lab.config;
        other.test_mailbox = "restoretest@other.onmicrosoft.com";
        spec.targets = connector::RestoreTargets::from_config(other);
    }
    REQUIRE_THROWS_MATCHES(
        made->restore_sample(spec), connector::SafetyViolation,
        Catch::Matchers::Message(
            "target guard: the restore spec isn't the connector's client's; nothing was restored"));
    // A refusal of the guard's kind: target_guard with nothing restored,
    // never `internal`, which would count as a restore that may still run.
    try {
        made->restore_sample(spec);
    } catch (...) {
        const rp::verification::RunStop stop = rp::verification::stop_reason(
            std::current_exception(), rp::verification::RunPhase::restore);
        CHECK(stop.error_code == "target_guard");
        CHECK(stop.nothing_restored);
    }
    CHECK(lab.http.requests().empty());
    CHECK(lab.guard_lab.graph_gets() == 0);
    // The organisation's name in another ASCII case is the same client.
    connector::RestoreSpec same = one_mail_spec(lab.config);
    same.client_ref = "RESTOREPROOFLAB.ONMICROSOFT.COM";
    same.mail.front().mailbox = lab.config.test_mailbox; // refused by the guard, not here
    REQUIRE_THROWS_AS(made->restore_sample(same), connector::SafetyViolation);
}

TEST_CASE("veeam_m365: a transport failure is a TransientError, a TLS failure a plain Error",
          "[veeam_m365]")
{
    const auto [error, kind] = GENERATE(table<rp::TransportError, std::string>({
        {rp::TransportError::connect, "TransientError"},
        {rp::TransportError::timeout, "TransientError"},
        {rp::TransportError::tls, "Error"},
    }));
    CAPTURE(kind);
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(), [error = error](const rp::HttpRequest& request) -> HttpResponse {
        throw rp::HttpError("GET " + request.url + ": failed", error, 0, 1);
    });
    const std::unique_ptr<connector::IConnector> made = lab.make();

    std::string message;
    REQUIRE(kind_of([&] { (void)made->list_restore_points(kOrgName); }, message) == kind);
}

TEST_CASE("veeam_m365: a client Veeam doesn't know is a NotFoundError", "[veeam_m365]")
{
    Harness lab;
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE_THROWS_MATCHES(made->list_restore_points("Other.onmicrosoft.com"),
                           connector::NotFoundError,
                           Message("client Other.onmicrosoft.com not found in Veeam"));
    // Only the organisations were listed; no restore points.
    REQUIRE(lab.http.count(HttpMethod::get, orgs_url()) == 1);
    REQUIRE(lab.http.count(HttpMethod::get, points_url()) == 0);
}

TEST_CASE("veeam_m365: a client that matches two organisations is an Error", "[veeam_m365]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {orgs_response({}, {{"0b6f7c52-4f3e-4a51-9d4a-5f0a3c2b1e90",
                                     "restoreprooflab.ONMICROSOFT.com"}})});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    std::string message;
    REQUIRE(kind_of([&] { (void)made->list_restore_points(kOrgName); }, message) == "Error");
    REQUIRE(message == "client " + kOrgName + " matches 2 organisations in Veeam");
    REQUIRE(lab.http.count(HttpMethod::get, points_url()) == 0);
}

TEST_CASE("veeam_m365: an organisation ID that isn't a UUID is an Error", "[veeam_m365]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {orgs_response([](json& org) { org["id"] = "not-a-uuid"; })});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    std::string message;
    REQUIRE(kind_of([&] { (void)made->list_restore_points(kOrgName); }, message) == "Error");
    REQUIRE(message == "Veeam returned an organisation ID for client " + kOrgName +
                           " that isn't a UUID");
    REQUIRE(lab.http.count(HttpMethod::get, points_url()) == 0);
}

TEST_CASE("veeam_m365: an invalid_argument from below isn't reported as a bad organisation ID",
          "[veeam_m365]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, points_url(), [](const rp::HttpRequest&) -> HttpResponse {
        throw std::invalid_argument("some other argument check");
    });
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE_THROWS_MATCHES(made->list_restore_points(kOrgName), std::invalid_argument,
                           Message("some other argument check"));
}

TEST_CASE("veeam_m365: a client reference's control characters never reach a message",
          "[veeam_m365]")
{
    // client_ref will come from a Cloud job (C5.6): a CR/LF or a bidi override
    // in it must not forge, hide or reorder a log or stderr line.
    const auto [client_ref, shown] = GENERATE(table<std::string, std::string>({
        {"Other\r\nERROR forged", "Other  ERROR forged"},
        {"Other\x1B[31m", "Other [31m"},
        {"Other\xE2\x80\xAE" "moc.tfosorcim", "Other moc.tfosorcim"},
        {"Other\xC2\x85line", "Other line"},
    }));
    CAPTURE(shown);
    Harness lab;
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE_THROWS_MATCHES(made->list_restore_points(client_ref), connector::NotFoundError,
                           Message("client " + shown + " not found in Veeam"));
}

TEST_CASE("veeam_m365: the matches-N message hides control characters too", "[veeam_m365]")
{
    const std::string evil = "Twin\nforged";
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(),
                {orgs_response([&](json& org) { org["name"] = evil; },
                               {{"0b6f7c52-4f3e-4a51-9d4a-5f0a3c2b1e90", evil}})});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    std::string message;
    REQUIRE(kind_of([&] { (void)made->list_restore_points(evil); }, message) == "Error");
    REQUIRE(message == "client Twin forged matches 2 organisations in Veeam");
}

TEST_CASE("veeam_m365: an empty client reference is refused before any request",
          "[veeam_m365]")
{
    Harness lab;
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE_THROWS_MATCHES(made->list_restore_points(""), std::invalid_argument,
                           Message("veeam_m365: the client reference is empty"));
    REQUIRE(lab.http.requests().empty());
}

TEST_CASE("veeam_m365: the factory needs both Veeam secrets", "[veeam_m365]")
{
    const auto [username, password, message] =
        GENERATE(table<std::optional<std::string>, std::optional<std::string>, std::string>({
            {std::nullopt, kPassword, "veeam_username is not in the vault"},
            {std::string{}, kPassword, "veeam_username is not in the vault"},
            {std::nullopt, std::nullopt, "veeam_username is not in the vault"},
            {kUsername, std::nullopt, "veeam_password is not in the vault"},
            {kUsername, std::string{}, "veeam_password is not in the vault"},
        }));
    Harness lab;
    lab.secrets.veeam_username = username;
    lab.secrets.veeam_password = password;
    // The Veeam secrets are reported first, whatever the Graph ones are.
    if (GENERATE(false, true)) {
        lab.secrets.graph_cert_pfx_base64.reset();
    }

    try {
        (void)lab.make();
        FAIL("no exception");
    } catch (const rp::ConfigError& e) {
        REQUIRE(std::string{e.what()} == message);
        REQUIRE(e.key() == message.substr(0, message.find(' ')));
    }
    REQUIRE(lab.make_http_calls == 0);
    REQUIRE(lab.make_graph_http_calls == 0);
}

TEST_CASE("veeam_m365: listing restore points needs nothing of Graph", "[veeam_m365]")
{
    // The W2.5 review: picking a restore point must work without the Worker
    // app's certificate, which only the target guard's Graph client needs.
    Harness lab;
    lab.secrets.graph_cert_pfx_base64.reset();
    lab.secrets.graph_cert_password.reset();
    lab.config.graph_tenant_id = "not-a-guid";
    const std::unique_ptr<connector::IConnector> made = lab.make();

    const std::vector<connector::RestorePoint> points = made->list_restore_points(kOrgName);

    CHECK_FALSE(points.empty());
    CHECK(lab.make_graph_http_calls == 0);
}

TEST_CASE("veeam_m365: restore_sample needs the Worker app's certificate, before any HTTP client "
          "or request",
          "[veeam_m365]")
{
    const std::string pfx_needs_password =
        "graph_cert_password is not in the vault, and the PFX in graph_cert_pfx_base64 needs a "
        "password";
    const std::string password{rp::test::graph_lab::kPfxPassword};
    const auto [pfx, given_password, message] =
        GENERATE_COPY(table<std::optional<std::string>, std::optional<std::string>, std::string>({
            {std::nullopt, password, "graph_cert_pfx_base64 is not in the vault"},
            {std::string{}, password, "graph_cert_pfx_base64 is not in the vault"},
            {std::nullopt, std::nullopt, "graph_cert_pfx_base64 is not in the vault"},
            {rp::test::graph_lab::pfx_base64(), std::nullopt, pfx_needs_password},
            {rp::test::graph_lab::pfx_base64(), std::string{}, pfx_needs_password},
        }));
    Harness lab;
    lab.secrets.graph_cert_pfx_base64 = pfx;
    lab.secrets.graph_cert_password = given_password;
    const std::unique_ptr<connector::IConnector> made = lab.make();
    const connector::RestoreSpec spec = one_mail_spec(lab.config);

    // Tried again on each call: the same answer, nothing sent.
    for (int call = 0; call < 2; ++call) {
        try {
            (void)made->restore_sample(spec);
            FAIL("no exception");
        } catch (const rp::ConfigError& e) {
            REQUIRE(std::string{e.what()} == message);
            REQUIRE(e.key() == message.substr(0, message.find(' ')));
        }
    }
    REQUIRE(lab.make_graph_http_calls == 0);
    REQUIRE(lab.http.requests().empty());
    REQUIRE(lab.guard_lab.graph_http.requests().empty());
}

TEST_CASE("veeam_m365: the certificate must be valid at the options' wall clock", "[veeam_m365]")
{
    Harness lab;
    connector::ConnectorOptions options = lab.options();
    // The lab certificate is valid for a year from kNow.
    options.wall_now = [] { return rp::test::graph_lab::kNow + std::chrono::hours{24 * 400}; };
    const std::unique_ptr<connector::IConnector> made = connector::default_connector_registry().create(
        connector::kVeeamM365, lab.config, lab.secrets, options);

    REQUIRE_THROWS_AS(made->restore_sample(one_mail_spec(lab.config)), rp::graph::CertificateError);
    REQUIRE(lab.make_graph_http_calls == 0);
    REQUIRE(lab.http.requests().empty());
}

TEST_CASE("veeam_m365: restore_sample refuses Graph IDs that aren't GUIDs, before any HTTP "
          "client",
          "[veeam_m365]")
{
    const std::string key = GENERATE(std::string{"graph_tenant_id"}, std::string{"graph_client_id"});
    Harness lab;
    (key == "graph_tenant_id" ? lab.config.graph_tenant_id : lab.config.graph_client_id) =
        "not-a-guid";
    const std::unique_ptr<connector::IConnector> made = lab.make();

    try {
        (void)made->restore_sample(one_mail_spec(lab.config));
        FAIL("no exception");
    } catch (const rp::ConfigError& e) {
        REQUIRE(std::string{e.what()} == key + " is not a GUID");
        REQUIRE(e.key() == key);
    }
    REQUIRE(lab.make_graph_http_calls == 0);
    REQUIRE(lab.http.requests().empty());
}

// W4.10 point 4: the guard's Graph client signs in as the run's client, from
// the options and never from the config.
TEST_CASE("veeam_m365: a connector made without a client profile refuses restore_sample before "
          "any request, and lists restore points still",
          "[veeam_m365][client_profile]")
{
    Harness lab;
    connector::ConnectorOptions options = lab.options();
    options.client.reset();
    const std::unique_ptr<connector::IConnector> made =
        connector::default_connector_registry().create(connector::kVeeamM365, lab.config,
                                                       lab.secrets, options);
    CHECK_FALSE(made->list_restore_points(kOrgName).empty());

    try {
        (void)made->restore_sample(one_mail_spec(lab.config));
        FAIL("no exception");
    } catch (const rp::ConfigError& e) {
        CHECK(std::string{e.what()} ==
              "veeam_m365: the connector has no client profile; nothing was restored");
    }
    CHECK(lab.make_graph_http_calls == 0);
}

TEST_CASE("veeam_m365: the guard's Graph client is the profile's tenant and app, not the "
          "config's",
          "[veeam_m365][client_profile]")
{
    Harness lab;
    // The config names another tenant and app; the profile the run's.
    lab.config.graph_tenant_id = "99999999-9999-9999-9999-999999999999";
    lab.config.graph_client_id = "88888888-8888-8888-8888-888888888888";
    connector::ConnectorOptions options = lab.options();
    options.client->graph_tenant_id = rp::test::graph_lab::kTenant;
    options.client->graph_client_id = rp::test::graph_lab::kClient;
    const std::unique_ptr<connector::IConnector> made =
        connector::default_connector_registry().create(connector::kVeeamM365, lab.config,
                                                       lab.secrets, options);
    // The token is asked for in the profile's tenant (graph_lab's token URL).
    try {
        (void)made->restore_sample(one_mail_spec(lab.config));
    } catch (const std::exception&) {
    }
    bool asked_profile_tenant = false;
    for (const rp::HttpRequest& request : lab.guard_lab.graph_http.requests()) {
        asked_profile_tenant |= request.url == rp::test::graph_lab::kTokenUrl;
    }
    CHECK(asked_profile_tenant);
}

TEST_CASE("veeam_m365: a factory whose Graph HTTP client is missing is refused", "[veeam_m365]")
{
    Harness lab;
    connector::ConnectorOptions options = lab.options();
    options.make_graph_http = [](std::shared_ptr<spdlog::logger>) {
        return std::unique_ptr<rp::IHttpClient>{};
    };
    const std::unique_ptr<connector::IConnector> made = connector::default_connector_registry().create(
        connector::kVeeamM365, lab.config, lab.secrets, options);
    REQUIRE_THROWS_MATCHES(made->restore_sample(one_mail_spec(lab.config)), std::invalid_argument,
                           Message("veeam_m365: no Graph HTTP client"));
    REQUIRE(lab.http.requests().empty());
}

TEST_CASE("veeam_m365: without a logger the factory never logs to spdlog's default logger",
          "[veeam_m365][target_guard]")
{
    // spdlog's default logger writes to stdout, where a command's table goes.
    // Swapped for one writing to a string for this test, then put back.
    std::ostringstream stdout_stand_in;
    const std::shared_ptr<spdlog::logger> previous = spdlog::default_logger();
    spdlog::set_default_logger(std::make_shared<spdlog::logger>(
        "stdout_stand_in", std::make_shared<spdlog::sinks::ostream_sink_mt>(stdout_stand_in)));
    spdlog::default_logger()->set_level(spdlog::level::trace);
    std::string default_log;
    bool refused = false;
    bool own_logger = false;
    {
        Harness lab;
        connector::ConnectorOptions options = lab.options();
        options.logger = nullptr;
        const std::unique_ptr<connector::IConnector> made =
            connector::default_connector_registry().create(connector::kVeeamM365, lab.config,
                                                           lab.secrets, options);
        connector::RestoreSpec spec = one_mail_spec(lab.config);
        spec.mail.front().mailbox = lab.config.test_mailbox;
        try {
            made->restore_sample(spec);
        } catch (const connector::SafetyViolation&) {
            refused = true;
        }
        own_logger = lab.graph_http_logger != nullptr &&
                     lab.graph_http_logger != spdlog::default_logger() &&
                     lab.http_options && lab.http_options->logger == lab.graph_http_logger;
        spdlog::default_logger()->flush();
        default_log = stdout_stand_in.str();
    }
    spdlog::set_default_logger(previous);
    CHECK(refused);
    CHECK(own_logger);
    CHECK(default_log.empty());
}

TEST_CASE("veeam_m365: a factory with no HTTP client, or a URL that isn't https, is refused",
          "[veeam_m365]")
{
    Harness lab;
    SECTION("no HTTP client")
    {
        lab.give_http = false;
        REQUIRE_THROWS_MATCHES(lab.make(), std::invalid_argument,
                               Message("veeam_m365: no HTTP client"));
    }
    SECTION("http://")
    {
        lab.config.veeam_url = "http://veeam.test:4443";
        REQUIRE_THROWS_AS(lab.make(), std::invalid_argument);
    }
    REQUIRE(lab.http.requests().empty());
}

// --- Happy paths -------------------------------------------------------------------

TEST_CASE("veeam_m365: describe names the connector and the API version, offline",
          "[veeam_m365]")
{
    Harness lab;
    const std::unique_ptr<connector::IConnector> made = lab.make();

    const connector::ConnectorInfo info = made->describe();
    REQUIRE(info.name == "veeam_m365");
    REQUIRE(info.version == "v8");
    REQUIRE(lab.http.requests().empty());
}

TEST_CASE("veeam_m365: restore points come newest first, whatever order Veeam sends",
          "[veeam_m365]")
{
    const std::string fixture = GENERATE("restore-points-200", "restore-points-asc-200");
    CAPTURE(fixture);
    Harness lab;
    lab.http.on(HttpMethod::get, points_url(), {load_fixture("veeam", fixture)});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    const std::vector<connector::RestorePoint> points = made->list_restore_points(kOrgName);
    REQUIRE(points.size() == 2);
    REQUIRE(points[0].id == kNewestPoint);
    REQUIRE(points[0].backup_time == kNewestTime);
    REQUIRE(points[1].id == kOldestPoint);
    REQUIRE(points[1].backup_time == kOldestTime);
    for (const connector::RestorePoint& p : points) {
        REQUIRE(p.has_mail);
        REQUIRE(p.has_sharepoint);
        REQUIRE(p.has_onedrive);
        REQUIRE_FALSE(p.is_archive);
    }
}

TEST_CASE("veeam_m365: each restore point flag comes from its own Veeam field", "[veeam_m365]")
{
    const std::string field =
        GENERATE("isExchange", "isSharePoint", "isOneDrive", "isLongTermCopy");
    CAPTURE(field);
    Harness lab;
    json fixture = load_fixture_json("veeam", "restore-points-200");
    for (json& p : fixture["body"]["results"]) {
        p["isExchange"] = false;
        p["isSharePoint"] = false;
        p["isOneDrive"] = false;
        p["isLongTermCopy"] = false;
        p["isTeams"] = true; // Teams isn't part of the neutral point
    }
    fixture["body"]["results"][0][field] = true;
    lab.http.on(HttpMethod::get, points_url(), {to_response(fixture)});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    const std::vector<connector::RestorePoint> points = made->list_restore_points(kOrgName);
    REQUIRE(points.size() == 2);
    const connector::RestorePoint& p = points[0].id == kNewestPoint ? points[0] : points[1];
    REQUIRE(p.has_mail == (field == "isExchange"));
    REQUIRE(p.has_sharepoint == (field == "isSharePoint"));
    REQUIRE(p.has_onedrive == (field == "isOneDrive"));
    REQUIRE(p.is_archive == (field == "isLongTermCopy"));
}

TEST_CASE("veeam_m365: an organisation without restore points gives an empty list",
          "[veeam_m365]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, points_url(), {load_fixture("veeam", "restore-points-empty-200")});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE(made->list_restore_points(kOrgName).empty());
}

TEST_CASE("veeam_m365: the client is matched by name, ASCII case-insensitively",
          "[veeam_m365]")
{
    Harness lab;
    // Another organisation beside the lab's.
    lab.http.on(HttpMethod::get, orgs_url(),
                {orgs_response({}, {{"0b6f7c52-4f3e-4a51-9d4a-5f0a3c2b1e90", "Other.onmicrosoft.com"}})});
    lab.http.on(HttpMethod::get, points_url("0b6f7c52-4f3e-4a51-9d4a-5f0a3c2b1e90"),
                {load_fixture("veeam", "restore-points-empty-200")});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE(made->list_restore_points("restoreprooflab.ONMICROSOFT.com").size() == 2);
    REQUIRE(made->list_restore_points("other.onmicrosoft.com").empty());
}

TEST_CASE("veeam_m365: one sign-in serves every call; the connector logs out when it goes",
          "[veeam_m365]")
{
    Harness lab;
    {
        const std::unique_ptr<connector::IConnector> made = lab.make();
        (void)made->list_restore_points(kOrgName);
        (void)made->list_restore_points(kOrgName);
        REQUIRE(lab.http.count(HttpMethod::post, kTokenUrl) == 1);
        REQUIRE(lab.http.count(HttpMethod::post, kLogoutUrl) == 0);
    }
    REQUIRE(lab.http.count(HttpMethod::post, kLogoutUrl) == 1);
    require_no_secret(lab.log());
}

TEST_CASE("veeam_m365: a connector that never signed in sends nothing when it goes",
          "[veeam_m365]")
{
    Harness lab;
    {
        const std::unique_ptr<connector::IConnector> made = lab.make();
        (void)made->describe();
    }
    REQUIRE(lab.http.requests().empty());
}

TEST_CASE("veeam_m365: the HTTP client gets the config's CA file and pin, TLS never off",
          "[veeam_m365]")
{
    Harness lab;
    lab.config.veeam_ca_file = "C:\\certs\\veeam.pem";
    lab.config.veeam_cert_sha256 = std::string(64, 'A');

    (void)lab.make();
    REQUIRE(lab.make_http_calls == 1);
    REQUIRE(lab.http_options);
    REQUIRE(lab.http_options->ca_file == lab.config.veeam_ca_file);
    REQUIRE(lab.http_options->pinned_cert_sha256 == lab.config.veeam_cert_sha256);
    REQUIRE(lab.http_options->logger == lab.logger);
    REQUIRE(lab.http_options->sleep);
    REQUIRE(lab.http_options->jitter);
}

TEST_CASE("veeam_m365: retries wait through the options' sleep", "[veeam_m365]")
{
    Harness lab;
    lab.http.on(HttpMethod::get, orgs_url(), {make_response(503), orgs_response()});
    const std::unique_ptr<connector::IConnector> made = lab.make();

    REQUIRE(made->list_restore_points(kOrgName).size() == 2);
    REQUIRE(lab.sleeps.size() == 1);
}

TEST_CASE("veeam_m365: without make_http the factory uses the real HTTP client, calling nothing",
          "[veeam_m365]")
{
    Harness lab;
    connector::ConnectorOptions options = lab.options();
    options.make_http = nullptr;
    // And the real Graph HTTP client and certificate exporter: made, not used.
    options.make_graph_http = nullptr;
    options.cert_exporter = nullptr;

    const std::unique_ptr<connector::IConnector> made = connector::default_connector_registry()
        .create(connector::kVeeamM365, lab.config, lab.secrets, options);
    REQUIRE(made->describe().name == "veeam_m365");
    REQUIRE(lab.make_http_calls == 0);
    REQUIRE(lab.make_graph_http_calls == 0);
}

TEST_CASE("the default registry knows veeam_m365 and nothing else", "[veeam_m365]")
{
    REQUIRE(connector::kVeeamM365 == "veeam_m365");
    REQUIRE(connector::default_connector_registry().names() ==
            std::vector<std::string>{"veeam_m365"});
}

TEST_CASE("veeam_m365: the registry's connector works as an IConnector&", "[veeam_m365]")
{
    Harness lab;
    const std::unique_ptr<connector::IConnector> made = lab.make();
    connector::IConnector& source = *made;

    REQUIRE(source.describe().name == connector::kVeeamM365);
    const std::vector<connector::RestorePoint> points = source.list_restore_points(kOrgName);
    REQUIRE(points.size() == 2);
    REQUIRE(points.front().id == kNewestPoint);
}

TEST_CASE("veeam_m365: a connector can be made directly on an HTTP client it owns",
          "[veeam_m365]")
{
    rp::test::FakeHttpClient http;
    http.on(HttpMethod::post, kTokenUrl, {token_response()});
    http.on(HttpMethod::get, orgs_url(), {orgs_response()});
    http.on(HttpMethod::get, points_url(), {load_fixture("veeam", "restore-points-200")});
    http.on(HttpMethod::post, kLogoutUrl, {load_fixture("veeam", "logout-204")});
    rp::VeeamM365ConnectorOptions options;
    options.client.sleep = [](std::chrono::milliseconds) {};
    {
        rp::VeeamM365Connector made(std::make_unique<rp::test::ForwardingHttpClient>(http), kBase,
                                    kUsername, kPassword, std::move(options));
        REQUIRE(made.list_restore_points(kOrgName).size() == 2);
    }
    REQUIRE(http.count(HttpMethod::post, kLogoutUrl) == 1);
    REQUIRE_THROWS_MATCHES(rp::VeeamM365Connector(nullptr, kBase, kUsername, kPassword),
                           std::invalid_argument, Message("veeam_m365: no HTTP client"));
}

TEST_CASE("veeam_m365: the registry's connector asks and tells its caller: the sessions opened, "
          "the word before a restore request, the stop",
          "[veeam_m365][w4.8]")
{
    namespace vrl = rp::test::veeam_restore_lab;
    vrl::RestoreRig rig;
    rig.serve(vrl::mail_x1());
    rp::Config config = rp::test::graph_lab::lab_config();
    config.veeam_url = vrl::kBase;
    config.veeam_org_name = vrl::kOrgName;
    config.graph_tenant_id = rp::test::graph_lab::kTenant;
    config.graph_client_id = rp::test::graph_lab::kClient;
    const rp::Secrets secrets{vrl::kUsername, vrl::kPassword, rp::test::graph_lab::pfx_base64(),
                              std::string{rp::test::graph_lab::kPfxPassword}};
    connector::ConnectorOptions options;
    options.client = rp::local_profile(config);
    options.make_http = [&rig](const rp::HttpClientOptions&) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(rig.veeam);
    };
    options.make_graph_http =
        [&rig](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(rig.lab.graph_http);
    };
    options.logger = rig.logger;
    options.now = [&rig] { return rig.clock.now(); };
    options.sleep = [&rig](std::chrono::milliseconds wait) { rig.clock.sleep(wait); };
    options.jitter = [] { return 0.0; };
    options.wall_now = [&rig] { return rig.next_post_time(); };
    options.cert_exporter = rig.exporter;
    std::vector<std::string> told;
    int asked = 0;
    options.on_session_opened = [&](std::string_view id) { told.emplace_back(id); };
    std::string expected;
    SECTION("the request not let go")
    {
        options.before_restore_request = [&] {
            ++asked;
            return false;
        };
        expected = "veeam_m365: the mail restore request was not let go; nothing was restored";
    }
    SECTION("a stop")
    {
        options.stop_requested = [] { return true; };
        expected = "veeam_m365: the Worker was asked to stop before the mail restore request was "
                   "sent; nothing was restored";
    }

    const std::unique_ptr<connector::IConnector> made =
        connector::default_connector_registry().create(connector::kVeeamM365, config, secrets,
                                                       options);
    // Not a connector::Error: no handler for the backup product's failures takes it.
    REQUIRE_THROWS_MATCHES(made->restore_sample(vrl::restore_spec({vrl::mail_x1_item()})),
                           connector::Interrupted, Message(expected));

    CHECK(told == std::vector<std::string>{vrl::mail_x1().explore()});
    CHECK(asked == (expected.find("not let go") != std::string::npos ? 1 : 0));
    CHECK(rig.restore_posts().empty());
    CHECK(rig.exporter->calls == 0);
    // The two new members reach Veeam through the IConnector alone.
    made->end_session(vrl::mail_x1().explore());
    CHECK(rig.stops(vrl::mail_x1().explore()) == 2);
}

TEST_CASE("veeam_m365: the registry's connector restores through the clients it was given",
          "[veeam_m365][w2.5]")
{
    namespace vrl = rp::test::veeam_restore_lab;
    vrl::RestoreRig rig;
    rig.serve(vrl::mail_x1());
    rp::Config config = rp::test::graph_lab::lab_config();
    config.veeam_url = vrl::kBase;
    config.veeam_org_name = vrl::kOrgName;
    config.graph_tenant_id = rp::test::graph_lab::kTenant;
    config.graph_client_id = rp::test::graph_lab::kClient;
    const rp::Secrets secrets{vrl::kUsername, vrl::kPassword, rp::test::graph_lab::pfx_base64(),
                              std::string{rp::test::graph_lab::kPfxPassword}};
    connector::ConnectorOptions options;
    options.client = rp::local_profile(config);
    options.make_http = [&rig](const rp::HttpClientOptions&) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(rig.veeam);
    };
    options.make_graph_http =
        [&rig](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(rig.lab.graph_http);
    };
    options.logger = rig.logger;
    options.now = [&rig] { return rig.clock.now(); };
    options.sleep = [&rig](std::chrono::milliseconds wait) { rig.clock.sleep(wait); };
    options.jitter = [] { return 0.0; };
    options.wall_now = [&rig] { return rig.next_post_time(); };
    options.cert_exporter = rig.exporter;

    connector::RestoreResult result;
    {
        const std::unique_ptr<connector::IConnector> made =
            connector::default_connector_registry().create(connector::kVeeamM365, config, secrets,
                                                           options);
        result = made->restore_sample(vrl::restore_spec({vrl::mail_x1_item()}));
    }

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.items_restored == 1);
    CHECK(rig.exporter->calls == 1);
    CHECK(rig.restore_posts().size() == 1);
    // The guard read the test mailbox through the Graph HTTP client given.
    CHECK(rig.lab.gets(rp::test::graph_lab::inbox_url()) == 1);
    // The clock given drove the polls: the recorded run was Working once.
    CHECK(rig.clock.count(std::chrono::seconds{5}) >= 1);
    CHECK(rig.stops(vrl::mail_x1().explore()) == 1);
    const std::string log = rig.log();
    CHECK_THAT(log, !ContainsSubstring(vrl::kFakePfxPassword));
    CHECK_THAT(log, !ContainsSubstring(vrl::kPassword));
}
