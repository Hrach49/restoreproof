// W2.1 "Done when": with the Worker app's certificate, GraphClient gets a
// token from the lab tenant's Entra and reads the test mailbox; a mailbox
// outside its Exchange management scope is a PermissionError naming the Mail
// grant. Skipped unless RP_LIVE=1. Read-only: each call is a GET of at most
// one message ID (or the site), nothing is written.
//
// Environment (docs/testing.md):
//   RP_LIVE=1
//   RP_LIVE_VAULT                  the vault with the Worker app's certificate; default
//       %ProgramData%\RestoreProof\vault.bin (live_secrets.hpp)
//   RP_LIVE_GRAPH_TENANT_ID        default: the lab tenant
//   RP_LIVE_GRAPH_CLIENT_ID        default: "RestoreProof Worker"
//   RP_LIVE_GRAPH_MAILBOX          default: restoretest@, in the Mail scope
//   RP_LIVE_GRAPH_DENIED_MAILBOX   default: alice@, outside it
//   RP_LIVE_GRAPH_DENIED_SITE      default: the tenant's root site, which the
//                                  app has no Sites.Selected grant on

#include "live_secrets.hpp"
#include "test_support.hpp"

#include <rp/client_assertion.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>
#include <rp/secrets.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace {

// The lab (lab/tenant.md).
const std::string kLabTenantId = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146";
const std::string kLabWorkerClientId = "de8d4348-08a9-48ee-a04a-47c7189c5006";
const std::string kLabMailbox = "restoretest@RestoreProofLab.onmicrosoft.com";
const std::string kLabDeniedMailbox = "alice@RestoreProofLab.onmicrosoft.com";
const std::string kLabDeniedSite = "restoreprooflab.sharepoint.com";

std::string env_or(const char* name, const std::string& fallback)
{
    const std::optional<std::string> value = rp::test::get_env(name);
    return value && !value->empty() ? *value : fallback;
}

std::string first_message_path(const std::string& mailbox)
{
    return "/users/" + mailbox + "/mailFolders/inbox/messages?$top=1&$select=id";
}

// A GraphClient on the real Graph HttpClient (Windows store, no CA file, no
// pin) and the certificate from the Worker's secrets.
struct LiveGraph {
    std::unique_ptr<rp::IHttpClient> http = rp::graph::make_graph_http_client();
    rp::graph::GraphClient client{
        *http, env_or("RP_LIVE_GRAPH_TENANT_ID", kLabTenantId),
        env_or("RP_LIVE_GRAPH_CLIENT_ID", kLabWorkerClientId),
        rp::graph::certificate_from_secrets(rp::test::live_secrets(),
                                            std::chrono::system_clock::now())};
};

} // namespace

TEST_CASE("live: GraphClient reads the test mailbox and is denied another one, naming the grant",
          "[graph][live]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"}) {
        SKIP("set RP_LIVE=1 to run against the lab tenant's Graph");
    }
    LiveGraph graph;

    // A 200 means Entra took the client assertion and Exchange the token.
    const std::string mailbox = env_or("RP_LIVE_GRAPH_MAILBOX", kLabMailbox);
    const nlohmann::json inbox =
        graph.client.get_json(first_message_path(mailbox), rp::graph::kMailGrant);
    REQUIRE(inbox.contains("value"));
    CHECK(inbox["value"].is_array());
    std::cout << "inbox of " << mailbox << ": " << inbox["value"].size()
              << " message(s) on the first page\n";

    // The Done-when: outside the management scope, Exchange's ErrorAccessDenied
    // comes back as a PermissionError naming the Mail grant. The message holds
    // no secret (a path, a code, the grant, a request ID), so it is shown.
    const std::string denied = env_or("RP_LIVE_GRAPH_DENIED_MAILBOX", kLabDeniedMailbox);
    bool thrown = false;
    try {
        graph.client.get(first_message_path(denied), rp::graph::kMailGrant);
    } catch (const rp::graph::PermissionError& e) {
        thrown = true;
        std::cout << "denied as expected: " << e.what() << "\n";
        const std::string message = e.what();
        CHECK(e.status() == 403);
        CHECK(e.code() == "ErrorAccessDenied");
        CHECK(message.find("ErrorAccessDenied") != std::string::npos);
        CHECK(message.find(rp::graph::kMailGrant.description) != std::string::npos);
        CHECK(e.grant() == rp::graph::kMailGrant.description);
        CHECK(message.find("$top") == std::string::npos);
    }
    CHECK(thrown);
}

TEST_CASE("live: GraphClient is denied a site the app has no Sites.Selected grant on",
          "[graph][live]")
{
    if (rp::test::get_env("RP_LIVE") != std::optional<std::string>{"1"}) {
        SKIP("set RP_LIVE=1 to run against the lab tenant's Graph");
    }
    LiveGraph graph;

    const std::string site = env_or("RP_LIVE_GRAPH_DENIED_SITE", kLabDeniedSite);
    bool thrown = false;
    try {
        graph.client.get("/sites/" + site, rp::graph::kSitesReadGrant);
    } catch (const rp::graph::PermissionError& e) {
        thrown = true;
        std::cout << "denied as expected: " << e.what() << "\n";
        const std::string message = e.what();
        CHECK(e.status() == 403);
        CHECK(message.find(rp::graph::kSitesReadGrant.description) != std::string::npos);
        CHECK(e.grant() == rp::graph::kSitesReadGrant.description);
    }
    CHECK(thrown);
}
