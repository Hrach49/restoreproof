// W2.5 (#30): VeeamM365Connector::restore_sample end to end on W2.4's recorded
// runs (veeam_restore_lab.hpp): browsing, the body, the one restore POST, the
// duplicate check, polling, statistics, events, the verdict and the closing
// of the explore sessions. Failure paths first. No network, no real waits:
// every wait is recorded on a fake clock.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/connector.hpp>
#include <rp/http_client.hpp>
#include <rp/veeam_m365_connector.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

namespace connector = rp::connector;
using namespace rp::test::veeam_restore_lab;
using rp::HttpMethod;
using rp::HttpRequest;
using rp::HttpResponse;
using rp::test::load_fixture;
using rp::test::load_fixture_json;
using rp::test::make_response;
using namespace std::chrono_literals;

// No credential anywhere a person or a log could see it.
void check_no_secrets(RestoreRig& rig, const std::string& text)
{
    const std::string log = rig.log() + rig.lab.log();
    for (const std::string& secret : {kFakePfx, kFakePfxPassword, kPassword}) {
        CHECK_THAT(text, !ContainsSubstring(secret));
        CHECK_THAT(log, !ContainsSubstring(secret));
    }
}

std::string restore_url(const Run& run)
{
    return url(run.post_path());
}

// The recorded restore body with the fake credential in it, keys in their order.
std::string expected_body(const Run& run)
{
    ordered_json body = ordered_fixture(run.restore_fixture).at("request_body");
    body["applicationCertificate"] = kFakePfx;
    body["applicationCertificatePassword"] = kFakePfxPassword;
    return body.dump();
}

HttpResponse veeam_error(int status, const std::string& message, const std::string& code = {})
{
    json body = {{"message", message}};
    if (!code.empty()) {
        body["errorCode"] = code;
    }
    return make_response(status, body.dump());
}

HttpResponse dropped(const HttpRequest& request)
{
    throw rp::HttpError("POST " + request.url + ": connection dropped", rp::TransportError::dropped,
                        0, 1);
}

} // namespace

// ---- the guard, the organisation and the preflight: nothing restored --------------------

TEST_CASE("restore_sample: a restore target in the spec reaches no Veeam request",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    rig.serve(mail_x1());
    const Caught thrown = caught_by(
        [&] { rig.restore(restore_spec({mail_x1_item(), {lab_values().mailbox, "Inbox", "s"}})); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(rig.veeam.requests().empty());
    CHECK(rig.exporter->calls == 0);
}

TEST_CASE("restore_sample: an empty spec is not_run, with no Veeam request", "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const connector::RestoreResult result = rig.restore(restore_spec());
    CHECK(result.status == connector::RestoreStatus::not_run);
    CHECK(result.sessions.empty());
    CHECK(rig.veeam.requests().empty());
}

TEST_CASE("restore_sample: a spec without a client or a usable backup time", "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    connector::RestoreSpec no_client = restore_spec({mail_x1_item()});
    no_client.client_ref.clear();
    connector::RestoreSpec truncated = restore_spec({mail_x1_item()});
    truncated.restore_point.backup_time = "2026-09-27T22:00:48";
    connector::RestoreSpec empty_time = restore_spec({mail_x1_item()});
    empty_time.restore_point.backup_time.clear();

    for (const auto& spec : {no_client, truncated, empty_time}) {
        const Caught thrown = caught_by([&] { rig.restore(spec); });
        CHECK(thrown.kind == "invalid_argument");
    }
    CHECK(rig.veeam.requests().empty());
}

TEST_CASE("restore_sample: without a certificate exporter nothing is explored",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig(false);
    rig.serve(mail_x1());
    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: no certificate exporter, so the restore credential can't be "
                         "exported; nothing was restored");
    CHECK(rig.explores_opened() == 0);
    CHECK(rig.restore_posts().empty());
}

TEST_CASE("restore_sample: the organisation's apps must be set and the same", "[veeam_m365][w2.5]")
{
    struct Row {
        std::string name;
        std::function<void(json&)> edit;
        std::string message;
    };
    const std::string missing = "Veeam's organisation has no application for Exchange or "
                                "SharePoint, so there is no restore credential";
    const std::string different =
        "Veeam's organisation uses different applications for Exchange and SharePoint";
    const Row row = GENERATE_COPY(
        Row{"no Exchange settings", [](json& o) { o.erase("exchangeOnlineSettings"); }, missing},
        Row{"SharePoint settings null", [](json& o) { o["sharePointOnlineSettings"] = nullptr; },
            missing},
        Row{"no thumbprint",
            [](json& o) { o["exchangeOnlineSettings"].erase("applicationCertificateThumbprint"); },
            missing},
        Row{"another application",
            [](json& o) {
                o["sharePointOnlineSettings"]["applicationId"] =
                    "00000000-0000-4000-8000-000000000001";
            },
            different},
        Row{"another certificate",
            [](json& o) {
                o["sharePointOnlineSettings"]["applicationCertificateThumbprint"] =
                    "0000000000000000000000000000000000000000";
            },
            different},
        Row{"no region", [](json& o) { o.erase("region"); },
            "Veeam's organisation has no region"});
    CAPTURE(row.name);
    RestoreRig rig;
    rig.serve(mail_x1());
    rig.get("/v8/Organizations?limit=1000&offset=0",
            fixture("w24-mail-x1-org", [&](json& b) { row.edit(b["results"][0]); }));

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: client RestoreProofLab.onmicrosoft.com: " + row.message +
                             "; nothing was restored");
    CHECK(rig.explores_opened() == 0);
    CHECK(rig.exporter->calls == 0);
}

TEST_CASE("restore_sample: the thumbprints may differ in case only", "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    rig.serve(mail_x1());
    rig.get("/v8/Organizations?limit=1000&offset=0", fixture("w24-mail-x1-org", [](json& b) {
                b["results"][0]["exchangeOnlineSettings"]["applicationCertificateThumbprint"] =
                    "ac3220b58a2b4c438da13816c2dd1e25d1f783a7";
            }));

    const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(rig.exporter->thumbprints == std::vector<std::string>{
                                           "ac3220b58a2b4c438da13816c2dd1e25d1f783a7"});
}

TEST_CASE("restore_sample: an explore session ID Veeam sends in upper case is used in lower case",
          "[veeam_m365][w2.5]")
{
    // The W2.5 review: layer 2 and the duplicate check's known IDs are lower
    // case; an upper-case explore ID would be refused, or taken for another
    // restore.
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    {
        const std::lock_guard lock(rig.mutex);
        json body = load_fixture_json("veeam", run.file("explore")).at("body");
        std::string upper = body.at("id").get<std::string>();
        std::ranges::transform(upper, upper.begin(),
                               [](char c) { return c >= 'a' && c <= 'z' ? char(c - 'a' + 'A') : c; });
        body["id"] = upper;
        rig.explores[run.type] = make_response(201, body.dump());
    }

    const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(rig.restore_posts().size() == 1);
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: an unknown client is an Error, never NotFoundError, before any "
          "explore",
          "[veeam_m365][w2.5]")
{
    // In restore_sample NotFoundError is a sampled item missing from the
    // backup (a `fail` to be); a client Veeam doesn't know is the run's error.
    RestoreRig rig;
    rig.serve(mail_x1());
    connector::RestoreSpec spec = restore_spec({mail_x1_item()});
    spec.client_ref = "other.onmicrosoft.com";

    const Caught thrown = caught_by([&] { rig.restore(spec); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what ==
          "veeam_m365: client other.onmicrosoft.com not found in Veeam; nothing was restored");
    CHECK(rig.explores_opened() == 0);
}

TEST_CASE("restore_sample: organisation settings of an unexpected shape are refused, before any "
          "explore",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    rig.serve(mail_x1());
    rig.get("/v8/Organizations?limit=1000&offset=0", fixture("w24-mail-x1-org", [](json& b) {
                b["results"][0]["exchangeOnlineSettings"]["applicationId"] = 5;
            }));

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what ==
          "veeam_m365: client RestoreProofLab.onmicrosoft.com: Veeam's organisation settings are of "
          "an unexpected shape (exchangeOnlineSettings: \"applicationId\" isn't a string); nothing "
          "was restored");
    CHECK(rig.explores_opened() == 0);
    CHECK(rig.exporter->calls == 0);
}

TEST_CASE("restore_sample: the restore point must be the organisation's, its time byte for byte",
          "[veeam_m365][w2.5]")
{
    // Veeam explores whatever point is at or before an explore's dateTime: a
    // point that isn't the client's, or a time that isn't the point's, would
    // restore other data than the result names.
    struct Row {
        std::string name;
        std::function<void(connector::RestoreSpec&)> edit;
        std::string message;
    };
    const std::string id = kRestorePointId;
    const Row row = GENERATE_COPY(
        Row{"another organisation's point",
            [](connector::RestoreSpec& s) {
                s.restore_point.id = "c2f0f2e7-177f-48ac-992b-93a50cf702e3"
                                     "0b000000-0000-4000-8000-000000000001";
            },
            "veeam_m365: restore point c2f0f2e7-177f-48ac-992b-93a50cf702e30b000000-0000-4000-8000-"
            "000000000001 isn't one of client RestoreProofLab.onmicrosoft.com's restore points in "
            "Veeam; nothing was restored"},
        Row{"a time that isn't the point's",
            [](connector::RestoreSpec& s) {
                s.restore_point.backup_time = "2026-09-28T22:00:48.1447833Z";
            },
            "veeam_m365: restore point " + id +
                " of client RestoreProofLab.onmicrosoft.com has backup time "
                "2026-09-27T22:00:48.1447833Z in Veeam, not 2026-09-28T22:00:48.1447833Z; nothing "
                "was restored"},
        Row{"the time rounded",
            [](connector::RestoreSpec& s) {
                s.restore_point.backup_time = "2026-09-27T22:00:48.144783Z";
            },
            "veeam_m365: restore point " + id +
                " of client RestoreProofLab.onmicrosoft.com has backup time "
                "2026-09-27T22:00:48.1447833Z in Veeam, not 2026-09-27T22:00:48.144783Z; nothing "
                "was restored"});
    CAPTURE(row.name);
    RestoreRig rig;
    rig.serve(mail_x1());
    connector::RestoreSpec spec = restore_spec({mail_x1_item()});
    row.edit(spec);

    const Caught thrown = caught_by([&] { rig.restore(spec); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == row.message);
    CHECK(rig.explores_opened() == 0);
    CHECK(rig.exporter->calls == 0);
    CHECK(rig.veeam.count(HttpMethod::get, restore_points_url()) == 1);
}

TEST_CASE("restore_sample: a session of ours still Working stops it before any explore",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    rig.serve(mail_x1());
    std::string working;
    rig.get("/v8/RestoreSessions?limit=200", fixture("w24-mail-x1-sweep-before", [&](json& b) {
                b["results"][2]["state"] = "Working";
                working = b["results"][2]["id"].get<std::string>();
            }));

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: Veeam has restore sessions of rp-veeam still Working (" +
                             working +
                             "); stop them first (docs/api/veeam-m365/08-sweep-sessions.ps1); "
                             "nothing was restored");
    CHECK(rig.explores_opened() == 0);
}

// ---- browsing: nothing restored, the explore session closed -------------------------------

TEST_CASE("restore_sample: an item browsing can't pin down is refused, and the explore "
          "session closed",
          "[veeam_m365][w2.5]")
{
    const Run run = mail_x5();
    const std::string items = "/v8/RestoreSessions/" + run.explore() +
                              "/organization/mailboxes/" + run.container() + "/items?parentId=" +
                              encoded(load_fixture_json("veeam", run.file("folder-inbox"))
                                          .at("body")
                                          .at("results")
                                          .at(0)
                                          .at("id")
                                          .get<std::string>()) +
                              "&limit=1000&offset=0";
    struct Row {
        std::string name;
        std::function<void(RestoreRig&)> edit;
        std::string kind;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"no such message",
            [=](RestoreRig& rig) {
                rig.get(items, fixture(run.file("items"), [](json& b) {
                            for (json& item : b["results"]) {
                                if (item["subject"] == "RP-CANARY-0004") {
                                    item["subject"] = "renamed";
                                }
                            }
                        }));
            },
            "NotFoundError",
            "veeam_m365: mail item 2 \"RP-CANARY-0004\": the message not found in the restore "
            "point"},
        Row{"two messages of that subject",
            [=](RestoreRig& rig) {
                rig.get(items, fixture(run.file("items"), [](json& b) {
                            json copy = b["results"][0];
                            copy["id"] = "another";
                            copy["subject"] = "RP-CANARY-0004";
                            b["results"].push_back(copy);
                        }));
            },
            "Error",
            "veeam_m365: mail item 2 \"RP-CANARY-0004\": the message matches 2 entries in the "
            "restore point"},
        Row{"a subject of another kind",
            [=](RestoreRig& rig) {
                rig.get(items, fixture(run.file("items"),
                                       [](json& b) { b["results"][0]["subject"] = 7; }));
            },
            "Error", "veeam_m365: unexpected response from Veeam: \"subject\" isn't a string"},
        Row{"no such mailbox",
            [=](RestoreRig& rig) {
                rig.get(paged("/v8/RestoreSessions/" + run.explore() + "/organization/mailboxes"),
                        fixture(run.file("mailboxes"), [](json& b) {
                            for (json& m : b["results"]) {
                                if (m["email"] == kAlice) {
                                    m["email"] = "someone@else";
                                }
                            }
                        }));
            },
            "NotFoundError",
            "veeam_m365: mail item 0 \"RP-CANARY-0002\": mailbox "
            "\"alice@RestoreProofLab.onmicrosoft.com\" not found in the restore point"},
        Row{"received at another second",
            [=](RestoreRig& rig) {
                rig.get(items, fixture(run.file("items"), [](json& b) {
                            for (json& item : b["results"]) {
                                if (item["subject"] == "RP-CANARY-0002") {
                                    item["received"] = "2026-09-24T22:14:44.0000001Z";
                                }
                            }
                        }));
            },
            "Error",
            "veeam_m365: mail item 0 \"RP-CANARY-0002\": the restore point's copy was received "
            "at \"2026-09-24T22:14:44.0000001Z\", the sample says \"2026-09-24T22:14:43Z\""});
    CAPTURE(row.name);
    RestoreRig rig;
    rig.serve(run);
    row.edit(rig);

    const Caught thrown = caught_by([&] { rig.restore(restore_spec(mail_x5_items())); });

    CHECK(thrown.kind == row.kind);
    CHECK(thrown.what == row.message);
    CHECK(rig.restore_posts().empty());
    CHECK(rig.exporter->calls == 0);
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: a file browsing can't pin down is refused, and the explore session "
          "closed",
          "[veeam_m365][w2.5]")
{
    const Run sp = sp_x1();
    const Run od = od_x1();
    const std::string sites =
        "/v8/RestoreSessions/" + sp.explore() + "/Organization/Sites/" + sp.container();
    const std::string sp_document =
        sites + "/Documents/" +
        encoded(load_fixture_json("veeam", sp.file("document")).at("body").at("id").get<std::string>());
    const std::string onedrives = "/v8/RestoreSessions/" + od.explore() + "/Organization/OneDrives";
    struct Row {
        std::string name;
        bool sharepoint;
        std::function<void(RestoreRig&)> edit;
        std::string kind;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"a size other than the sample's", true,
            [=](RestoreRig& rig) {
                json body = load_fixture_json("veeam", sp.file("document")).at("body");
                body["sizeBytes"] = 926;
                rig.get(sp_document, make_response(200, body.dump()));
            },
            "Error",
            "veeam_m365: sharepoint item 0 \"rp-canary-06.pdf\": the restore point's copy isn't "
            "the size the sample says (925 bytes)"},
        Row{"a re-read of another name", true,
            [=](RestoreRig& rig) {
                json body = load_fixture_json("veeam", sp.file("document")).at("body");
                body["name"] = "other.pdf";
                rig.get(sp_document, make_response(200, body.dump()));
            },
            "Error",
            "veeam_m365: sharepoint item 0 \"rp-canary-06.pdf\": the file read again has another "
            "ID or name"},
        Row{"no library of that list", true,
            [=](RestoreRig& rig) {
                rig.get(paged(sites + "/Libraries"), fixture(sp.file("libraries"), [](json& b) {
                            json kept = json::array();
                            for (json& l : b["results"]) {
                                if (!l["id"].get<std::string>().ends_with(kCanaryListId)) {
                                    kept.push_back(l);
                                }
                            }
                            b["results"] = kept;
                        }));
            },
            "NotFoundError",
            "veeam_m365: sharepoint item 0 \"rp-canary-06.pdf\": the library of list "
            "\"7eb0f08a-f57b-418c-8ca6-f2ab81297666\" not found in the restore point"},
        Row{"a site Veeam answers for with another ID", true,
            [=](RestoreRig& rig) {
                rig.get(sites, make_response(200, R"({"id":"other","name":"x","url":"y"})"));
            },
            "Error",
            "veeam_m365: sharepoint item 0 \"rp-canary-06.pdf\": Veeam answered for another site "
            "than its site_id"},
        Row{"a folder of the file's name", true,
            [=](RestoreRig& rig) {
                rig.get(paged(sites + "/Documents?parentId=" + sp.container() + kCanaryListId),
                        fixture(sp.file("documents"), [](json& b) {
                            for (json& d : b["results"]) {
                                if (d["name"] == "rp-canary-06.pdf") {
                                    d["isFolder"] = true;
                                }
                            }
                        }));
            },
            "NotFoundError",
            "veeam_m365: sharepoint item 0 \"rp-canary-06.pdf\": the file not found in the "
            "restore point"},
        Row{"an isFolder of another kind", true,
            [=](RestoreRig& rig) {
                rig.get(paged(sites + "/Documents?parentId=" + sp.container() + kCanaryListId),
                        fixture(sp.file("documents"),
                                [](json& b) { b["results"][0]["isFolder"] = "no"; }));
            },
            "Error", "veeam_m365: unexpected response from Veeam: \"isFolder\" isn't a boolean"},
        Row{"the test OneDrive not listed", false,
            [=](RestoreRig& rig) {
                rig.get(paged(onedrives), fixture(od.file("onedrives"), [](json& b) {
                            b["results"][0]["url"] =
                                "https://restoreprooflab-my.sharepoint.com/personal/someone_else";
                        }));
            },
            "Error",
            "veeam_m365: the restore target: the test OneDrive "
            "\"https://restoreprooflab-my.sharepoint.com/personal/"
            "alice_restoreprooflab_onmicrosoft_com\" isn't in the restore point (is it backed "
            "up?); nothing was restored"},
        Row{"no source folder of that name", false,
            [=](RestoreRig& rig) {
                rig.get(paged(onedrives + "/" + od.container() + "/Folders?parentId=root"),
                        fixture(od.file("folders-root"), [](json& b) {
                            for (json& f : b["results"]) {
                                if (f["name"] == "RestoreTest") {
                                    f["name"] = "Renamed";
                                }
                            }
                        }));
            },
            "NotFoundError",
            "veeam_m365: onedrive item 0 \"rp-canary-16.pdf\": folder \"RestoreTest\" not found "
            "in the restore point"});
    CAPTURE(row.name);
    RestoreRig rig;
    const Run run = row.sharepoint ? sp : od;
    rig.serve(run);
    row.edit(rig);

    const Caught thrown = caught_by([&] {
        rig.restore(row.sharepoint ? restore_spec({}, {sp_x1_item()})
                                   : restore_spec({}, {}, {od_x1_item()}));
    });

    CHECK(thrown.kind == row.kind);
    CHECK(thrown.what == row.message);
    CHECK(rig.restore_posts().empty());
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: a user's archive mailbox is never taken for the mailbox",
          "[veeam_m365][w2.5]")
{
    // Veeam lists an in-place archive as a second entry with the same email
    // and isArchive true (the W2.5 review).
    const Run run = mail_x1();
    const std::string mailboxes =
        paged("/v8/RestoreSessions/" + run.explore() + "/organization/mailboxes");
    const auto with_archive = [&](const json& is_archive) {
        return fixture(run.file("mailboxes"), [&](json& b) {
            for (const json& m : b["results"]) {
                if (m["email"] == kBob) {
                    json archive = m;
                    archive["id"] = "0a000000-0000-4000-8000-00000000a4c1";
                    archive["name"] = "In-Place Archive - Bob Test";
                    archive["isArchive"] = is_archive;
                    b["results"].push_back(archive);
                    break;
                }
            }
        });
    };
    SECTION("the primary mailbox is restored from")
    {
        RestoreRig rig;
        rig.serve(run);
        rig.get(mailboxes, with_archive(true));

        const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

        CHECK(result.status == connector::RestoreStatus::succeeded);
        const std::vector<HttpRequest> posts = rig.restore_posts();
        REQUIRE(posts.size() == 1);
        CHECK(posts[0].url == restore_url(run));
    }
    SECTION("an isArchive of another kind")
    {
        RestoreRig rig;
        rig.serve(run);
        rig.get(mailboxes, with_archive("yes"));

        const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

        CHECK(thrown.kind == "Error");
        CHECK(thrown.what ==
              "veeam_m365: unexpected response from Veeam: \"isArchive\" isn't a boolean");
        CHECK(rig.restore_posts().empty());
    }
}

TEST_CASE("restore_sample: a OneDrive owner Veeam doesn't list", "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = od_x1();
    rig.serve(run);
    connector::OneDriveSelector item = od_x1_item();
    item.user = "carol@RestoreProofLab.onmicrosoft.com";

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({}, {}, {item})); });

    CHECK(thrown.kind == "NotFoundError");
    CHECK(thrown.what == "veeam_m365: onedrive item 0 \"rp-canary-16.pdf\": the OneDrive of "
                         "\"carol@RestoreProofLab.onmicrosoft.com\" not found in the restore "
                         "point");
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: an explore POST that fails after Veeam may have opened the session: "
          "found and stopped",
          "[veeam_m365][w2.5]")
{
    struct Row {
        std::string name;
        std::function<HttpResponse(const HttpRequest&)> answer;
        std::string kind;
    };
    const Row row = GENERATE(values<Row>({
        {"dropped", dropped, "TransientError"},
        {"timed out",
         [](const HttpRequest& r) -> HttpResponse {
             throw rp::HttpError("POST " + r.url + ": timed out", rp::TransportError::timeout, 0,
                                 1);
         },
         "TransientError"},
        {"500", [](const HttpRequest&) { return veeam_error(500, "Internal error"); }, "Error"},
        {"201 without an id", [](const HttpRequest&) { return make_response(201, "{}"); },
         "Error"},
    }));
    CAPTURE(row.name);
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, url("/v8/Organizations/" + kOrgId + "/explore"), row.answer);
    // Veeam lists a Working explore session of ours, made at the POST: the
    // recorded one, renamed, and no restore session (none was posted).
    const std::string orphan = "e0000000-0000-4000-8000-000000000003";
    const std::string restore = run.restore();
    const std::string explore = run.explore();
    rig.veeam.on(HttpMethod::get, run.duplicate_url(),
                 {fixture(run.file("sessions-after-post"), [&](json& b) {
                     json kept = json::array();
                     for (json& s : b["results"]) {
                         if (s["id"] == explore) {
                             s["id"] = orphan;
                         }
                         if (s["id"] != restore) {
                             kept.push_back(s);
                         }
                     }
                     b["results"] = kept;
                 })});
    rig.get("/v8/RestoreSessions/" + orphan,
            make_response(200, json{{"id", orphan}, {"state", "Working"}}.dump()));
    rig.veeam.on(HttpMethod::post, url("/v8/RestoreSessions/" + orphan + "/Stop"),
                 {load_fixture("veeam", "stop-204")});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == row.kind);
    CHECK(rig.explores_opened() == 1);
    CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 1);
    CHECK(rig.stops(orphan) == 1);
    CHECK(rig.restore_posts().empty());
    CHECK_THAT(rig.log(), ContainsSubstring("explore session " + orphan));
}

TEST_CASE("restore_sample: a failed explore POST adopts only one Working session of ours and "
          "the organisation's",
          "[veeam_m365][w2.5]")
{
    // The W2.5 review: the same account may run another restore from another
    // process; a session that can't be told apart from its work is never
    // stopped by this run.
    struct Row {
        std::string name;
        std::function<void(json&)> edit; // on the renamed orphan's list
        std::string log;
    };
    const Row row = GENERATE(values<Row>({
        {"two new Working sessions",
         [](json& b) {
             json copy = b["results"][0];
             copy["id"] = "e0000000-0000-4000-8000-000000000004";
             b["results"].push_back(copy);
         },
         "Veeam lists 2 new Working sessions of ours"},
        {"a new session that stopped", [](json& b) { b["results"][0]["state"] = "Stopped"; }, ""},
        {"another organisation's",
         [](json& b) { b["results"][0]["organization"] = "Other.onmicrosoft.com"; }, ""},
    }));
    CAPTURE(row.name);
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, url("/v8/Organizations/" + kOrgId + "/explore"), dropped);
    const std::string orphan = "e0000000-0000-4000-8000-000000000003";
    const std::string explore = run.explore();
    rig.veeam.on(HttpMethod::get, run.duplicate_url(),
                 {fixture(run.file("sessions-after-post"), [&](json& b) {
                     json kept = json::array();
                     for (json& s : b["results"]) {
                         if (s["id"] == explore) {
                             s["id"] = orphan;
                             kept.push_back(s);
                         }
                     }
                     b["results"] = kept;
                     row.edit(b);
                 })});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "TransientError");
    CHECK(rig.stops(orphan) == 0);
    CHECK(rig.stops("e0000000-0000-4000-8000-000000000004") == 0);
    CHECK(rig.gets("/v8/RestoreSessions/" + orphan) == 0);
    if (!row.log.empty()) {
        CHECK_THAT(rig.log(), ContainsSubstring(row.log));
    }
}

TEST_CASE("restore_sample: a failed explore POST with nothing to find, or a failed look, keeps "
          "its error",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, url("/v8/Organizations/" + kOrgId + "/explore"), dropped);
    SECTION("nothing new listed")
    {
        const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });
        CHECK(thrown.kind == "TransientError");
        CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 1);
    }
    SECTION("the look fails")
    {
        rig.veeam.on(HttpMethod::get, run.duplicate_url(), {veeam_error(400, "Bad filter")});
        const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });
        CHECK(thrown.kind == "TransientError");
        CHECK_THAT(rig.log(), ContainsSubstring("couldn't look for an explore session"));
    }
    SECTION("a refused sign-in: Veeam did nothing, so no look")
    {
        rig.veeam.on(HttpMethod::post, url("/v8/Organizations/" + kOrgId + "/explore"),
                     {load_fixture("veeam", "api-expired-token-401")});
        const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });
        CHECK(thrown.kind == "AuthError");
        CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 0);
    }
    CHECK(rig.restore_posts().empty());
}

TEST_CASE("restore_sample: two selectors of one item are refused before any POST",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);

    const Caught thrown =
        caught_by([&] { rig.restore(restore_spec({mail_x1_item(), mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: mail item 1 \"RP-CANARY-0011\" is the same item in the "
                         "restore point as mail item 0; nothing was restored");
    CHECK(rig.restore_posts().empty());
    CHECK(rig.exporter->calls == 0);
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: two files of one name are refused before any Veeam request",
          "[veeam_m365][w2.5]")
{
    // Both would land on one file in the restore target (restore-flow §12):
    // the second a new version of the first.
    RestoreRig rig;
    rig.serve(sp_x1());
    rig.serve(od_x1());
    connector::SharePointSelector other_folder = sp_x1_item();
    other_folder.folder_path = "/Other";
    other_folder.name = "RP-CANARY-06.PDF";
    connector::OneDriveSelector bobs = od_x1_item();
    bobs.user = kBob;
    const bool sharepoint = GENERATE(true, false);
    CAPTURE(sharepoint);

    const Caught thrown = caught_by([&] {
        rig.restore(sharepoint ? restore_spec({}, {sp_x1_item(), other_folder})
                               : restore_spec({}, {}, {od_x1_item(), bobs}));
    });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == std::string{"veeam_m365: "} + (sharepoint ? "sharepoint" : "onedrive") +
                             " items 0 and 1 are both named \"" +
                             (sharepoint ? "rp-canary-06.pdf" : "rp-canary-16.pdf") +
                             "\" (ignoring case), and would be restored onto one file in the "
                             "restore target; restore them in separate runs; nothing was "
                             "restored");
    CHECK(rig.veeam.requests().empty());
}

TEST_CASE("restore_sample: two files whose names differ in the case of a non-ASCII letter are "
          "refused",
          "[veeam_m365][w2.5]")
{
    // SharePoint and OneDrive fold the case of every letter, not only A-Z.
    const std::string upper = "\xC5\xB9r\xC3\xB3" "d\xC5\x82" "a.pdf"; // Zrodla with Z-acute, o-acute, l-stroke
    const std::string lower = "\xC5\xBAr\xC3\xB3" "d\xC5\x82" "a.pdf"; // the same, z-acute in lower case
    RestoreRig rig;
    connector::SharePointSelector first = sp_x1_item();
    first.name = upper;
    connector::SharePointSelector second = sp_x1_item();
    second.folder_path = "/Other";
    second.name = lower;
    connector::OneDriveSelector mine = od_x1_item();
    mine.name = lower;
    connector::OneDriveSelector bobs = od_x1_item();
    bobs.user = kBob;
    bobs.name = upper;
    const bool sharepoint = GENERATE(true, false);
    CAPTURE(sharepoint);

    const Caught thrown = caught_by([&] {
        rig.restore(sharepoint ? restore_spec({}, {first, second})
                               : restore_spec({}, {}, {mine, bobs}));
    });

    CHECK(thrown.kind == "Error");
    CHECK_THAT(thrown.what, StartsWith(std::string{"veeam_m365: "} +
                                       (sharepoint ? "sharepoint" : "onedrive") +
                                       " items 0 and 1 are both named "));
    CHECK_THAT(thrown.what, ContainsSubstring("(ignoring case), and would be restored onto one "
                                              "file in the restore target"));
    CHECK(rig.veeam.requests().empty());
}

TEST_CASE("restore_sample: Veeam unreachable or refusing the sign-in maps to connector errors",
          "[veeam_m365][w2.5]")
{
    const Run run = mail_x1();
    const std::string mailboxes =
        url(paged("/v8/RestoreSessions/" + run.explore() + "/organization/mailboxes"));
    struct Row {
        std::string name;
        std::function<void(RestoreRig&)> edit;
        std::string kind;
        std::size_t explores;
        std::size_t stops;
        std::string contains;
    };
    const Row row = GENERATE_COPY(
        Row{"the preflight unreachable",
            [](RestoreRig& rig) { rig.get("/v8/RestoreSessions?limit=200", make_response(503)); },
            "TransientError", 0, 0, "HTTP 503"},
        Row{"browsing drops",
            [=](RestoreRig& rig) {
                rig.veeam.on(HttpMethod::get, mailboxes, [](const HttpRequest& r) -> HttpResponse {
                    throw rp::HttpError("GET " + r.url + ": connection dropped",
                                        rp::TransportError::dropped, 0, 1);
                });
            },
            "TransientError", 1, 1, "connection dropped"},
        Row{"browsing refused after a fresh sign-in",
            [=](RestoreRig& rig) {
                rig.veeam.on(HttpMethod::get, mailboxes,
                             {load_fixture("veeam", "api-expired-token-401")});
            },
            "AuthError", 1, 1, "HTTP 401"},
        // A restore may be running: no verdict, never "try again" (the W2.5
        // review), whatever the lookup's own error.
        Row{"no answer, then the duplicate check unreachable",
            [=](RestoreRig& rig) {
                rig.veeam.on(HttpMethod::post, restore_url(run), dropped);
                rig.veeam.on(HttpMethod::get, run.duplicate_url(), {make_response(503)});
            },
            "Error", 1, 0,
            "and the duplicate check failed (Veeam GET " + run.duplicate_url().substr(kBase.size()) +
                ": HTTP 503 after 5 attempts); it was not sent again; no verdict; left open, as a "
                "restore may still be running: explore session(s) " + run.explore()},
        Row{"no answer, then the duplicate check's session gone",
            [=](RestoreRig& rig) {
                rig.veeam.on(HttpMethod::post, restore_url(run), dropped);
                rig.veeam.on(HttpMethod::get, run.duplicate_url(),
                             {veeam_error(404, "Organization does not exist", "ResourceNotFound")});
            },
            "Error", 1, 0,
            "; no verdict; left open, as a restore may still be running: explore session(s) " +
                run.explore()});
    CAPTURE(row.name);
    RestoreRig rig;
    rig.serve(run);
    row.edit(rig);

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == row.kind);
    CHECK_THAT(thrown.what, ContainsSubstring(row.contains));
    CHECK(rig.explores_opened() == row.explores);
    CHECK(rig.stops(run.explore()) == row.stops);
    CHECK(rig.posts(run.post_path()) <= 1);
    check_no_secrets(rig, thrown.what);
}

TEST_CASE("restore_sample: an explore session that can't be closed keeps the run's error, and "
          "the others are still closed",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run mail = mail_x5();
    const Run sp = sp_x1();
    rig.serve(mail);
    rig.serve(sp);
    const std::string sites =
        "/v8/RestoreSessions/" + sp.explore() + "/Organization/Sites/" + sp.container();
    rig.get(paged(sites + "/Libraries"), make_response(200, R"({"results":[]})"));
    rig.veeam.on(HttpMethod::post, url("/v8/RestoreSessions/" + mail.explore() + "/Stop"),
                 {veeam_error(500, "Internal error")});

    const Caught thrown =
        caught_by([&] { rig.restore(restore_spec(mail_x5_items(), {sp_x1_item()})); });

    CHECK(thrown.kind == "NotFoundError");
    CHECK_THAT(thrown.what, StartsWith("veeam_m365: sharepoint item 0 \"rp-canary-06.pdf\": the "
                                       "library of list"));
    CHECK(rig.stops(mail.explore()) == 1);
    CHECK(rig.stops(sp.explore()) == 1);
    CHECK_THAT(rig.log(), ContainsSubstring("couldn't close explore session " + mail.explore()));
    CHECK(rig.restore_posts().empty());
}

TEST_CASE("restore_sample: layer 2 refuses after browsing: no POST, the explore session closed",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = od_x1();
    rig.serve(run);
    // Something browsing takes as it is and the request guard checks: the
    // organisation's region, sent as officeRegion.
    rig.get("/v8/Organizations?limit=1000&offset=0", fixture("w24-od-x1-org", [](json& b) {
                b["results"][0]["region"] = "Worldwide\xC3\xA9";
            }));

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({}, {}, {od_x1_item()})); });

    CHECK(thrown.kind == "SafetyViolation");
    CHECK(thrown.what == "target guard: bad context: office_region is empty or not printable "
                         "ASCII; the restore was not sent");
    CHECK(rig.restore_posts().empty());
    CHECK(rig.stops(run.explore()) == 1);
    CHECK_THAT(rig.lab.log(), StartsWith("critical SECURITY: target guard: bad context"));
    check_no_secrets(rig, thrown.what);
}

TEST_CASE("restore_sample: a certificate that can't be exported sends nothing",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.exporter->fail = "certificate AC32... in LocalMachine\\My has no private key";

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: certificate AC32... in LocalMachine\\My has no private key; "
                         "the restore was not sent");
    CHECK(rig.restore_posts().empty());
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: an exported certificate that isn't Base64 is never put into a body",
          "[veeam_m365][w2.5]")
{
    // The credential is spliced into the body's text unescaped: only what
    // needs no JSON escaping can go in.
    const std::string pfx = GENERATE(std::string{"MIIK\"quoted"}, std::string{"MIIK\\x"},
                                     std::string{"MIIK\nline"}, std::string{"MIIK\xC3\xA9"});
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.exporter->pfx = pfx;

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: the exported certificate or its password isn't Base64; the "
                         "restore was not sent");
    CHECK(rig.restore_posts().empty());
    CHECK(rig.stops(run.explore()) == 1);
}

// ---- the restore POST: refused, no answer, sent once --------------------------------------

TEST_CASE("restore_sample: a refused POST started nothing and is never resent",
          "[veeam_m365][w2.5]")
{
    struct Row {
        std::string name;
        HttpResponse response;
        std::string kind;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"400, no folder", load_fixture("veeam", "w10-mail-restore-400-no-folder"), "Error",
            "HTTP 400 (ParameterValidationFailure): Missing mandatory parameters: Folder."},
        Row{"400, no CasServer", load_fixture("veeam", "w10-mail-restore-400-no-casserver"),
            "Error",
            "HTTP 400 (ParameterValidationFailure): Missing mandatory parameters: CasServer."},
        Row{"401", load_fixture("veeam", "api-expired-token-401"), "AuthError", "HTTP 401"},
        Row{"403", veeam_error(403, "Access denied"), "AuthError", "HTTP 403"},
        // Veeam's auth code with another status (restore-flow §15).
        Row{"400, ResourceAccessDenied",
            veeam_error(400, "Access denied", "ResourceAccessDenied"), "AuthError",
            "HTTP 400 (ResourceAccessDenied): Access denied"});
    CAPTURE(row.name);
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, restore_url(run), {row.response});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == row.kind);
    CHECK_THAT(thrown.what,
               StartsWith("veeam_m365: Veeam POST " + run.post_path() + ": " + row.message));
    CHECK_THAT(thrown.what, ContainsSubstring("; Veeam started no restore"));
    CHECK(rig.posts(run.post_path()) == 1);
    CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 0);
    CHECK(rig.stops(run.explore()) == 1);
    // One sign-in: no fresh one to resend with.
    CHECK(rig.posts("/v8/token") == 1);
    check_no_secrets(rig, thrown.what);
}

TEST_CASE("restore_sample: a POST that never went out started nothing: explore session closed",
          "[veeam_m365][w2.5]")
{
    const rp::TransportError error =
        GENERATE(rp::TransportError::connect, rp::TransportError::handshake);
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, restore_url(run), [error](const HttpRequest& r) -> HttpResponse {
        throw rp::HttpError("POST " + r.url + ": no connection", error, 0, 1);
    });

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "TransientError");
    CHECK_THAT(thrown.what, StartsWith("veeam_m365: Veeam POST " + run.post_path() + ": not sent ("));
    CHECK_THAT(thrown.what, ContainsSubstring("; the restore was not sent"));
    CHECK_THAT(thrown.what, !ContainsSubstring("left open"));
    CHECK(rig.posts(run.post_path()) == 1);
    CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 0);
    CHECK(rig.stops(run.explore()) == 1);
    check_no_secrets(rig, thrown.what);
}

TEST_CASE("restore_sample: no answer to the POST: the duplicate check adopts the one session",
          "[veeam_m365][w2.5]")
{
    struct Row {
        std::string name;
        std::function<HttpResponse(const HttpRequest&)> answer;
    };
    const Row row = GENERATE(values<Row>({
        {"dropped", dropped},
        {"timed out",
         [](const HttpRequest& r) -> HttpResponse {
             throw rp::HttpError("POST " + r.url + ": timed out", rp::TransportError::timeout, 0,
                                 1);
         }},
        {"500", [](const HttpRequest&) { return veeam_error(500, "Internal error"); }},
        {"502", [](const HttpRequest&) { return make_response(502); }},
        {"200 without a session ID", [](const HttpRequest&) { return make_response(200, "{}"); }},
    }));
    CAPTURE(row.name);
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, restore_url(run), row.answer);

    const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.session_ids == std::vector<std::string>{run.restore()});
    CHECK(rig.posts(run.post_path()) == 1);
    CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 1);
    CHECK(rig.stops(run.explore()) == 1);
    CHECK_THAT(rig.log(), ContainsSubstring("looking for the restore session instead of sending"));
    check_no_secrets(rig, result.log);
}

TEST_CASE("restore_sample: no answer and no session after three more looks: left open, not "
          "resent",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, restore_url(run), dropped);
    const std::string restore = run.restore();
    rig.veeam.on(HttpMethod::get, run.duplicate_url(),
                 {fixture(run.file("sessions-after-post"), [&](json& b) {
                     json kept = json::array();
                     for (json& s : b["results"]) {
                         if (s["id"] != restore) {
                             kept.push_back(s);
                         }
                     }
                     b["results"] = kept;
                 })});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK_THAT(thrown.what, StartsWith("veeam_m365: the mail restore POST got no answer ("));
    CHECK_THAT(thrown.what,
               ContainsSubstring("and the duplicate check found 0 candidate sessions; it was not "
                                 "sent again; no verdict; left open, as a restore may still be "
                                 "running: explore session(s) " +
                                 run.explore()));
    CHECK(rig.posts(run.post_path()) == 1);
    CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 4);
    CHECK(rig.clock.waits() == std::vector<std::chrono::milliseconds>{10s, 10s, 10s});
    CHECK(rig.stops(run.explore()) == 0);
    check_no_secrets(rig, thrown.what);
}

TEST_CASE("restore_sample: no answer and two candidate sessions: left open, not resent",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::post, restore_url(run), dropped);
    rig.veeam.on(HttpMethod::get, run.duplicate_url(),
                 {fixture(run.file("sessions-after-post"), [](json& b) {
                     json copy = b["results"][0];
                     copy["id"] = "c0000000-0000-4000-8000-000000000001";
                     b["results"].push_back(copy);
                 })});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK_THAT(thrown.what, ContainsSubstring("the duplicate check found 2 candidate sessions"));
    CHECK(rig.posts(run.post_path()) == 1);
    CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 1);
    CHECK(rig.clock.waits().empty());
    CHECK(rig.stops(run.explore()) == 0);
}

TEST_CASE("restore_sample: a session ID the duplicate check doesn't list alone gets no verdict",
          "[veeam_m365][w2.5]")
{
    struct Row {
        std::string name;
        std::vector<HttpResponse> check;
    };
    const Run run = mail_x1();
    const Row row = GENERATE_COPY(
        Row{"another new session too",
            {fixture(run.file("sessions-after-post"), [](json& b) {
                json copy = b["results"][0];
                copy["id"] = "c0000000-0000-4000-8000-000000000001";
                b["results"].push_back(copy);
            })}},
        Row{"another session instead",
            {fixture(run.file("sessions-after-post"), [](json& b) {
                b["results"][0]["id"] = "c0000000-0000-4000-8000-000000000001";
            })}},
        Row{"the check itself fails", {veeam_error(500, "Internal error")}});
    CAPTURE(row.name);
    RestoreRig rig;
    rig.serve(run);
    rig.veeam.on(HttpMethod::get, run.duplicate_url(), row.check);

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: restore session " + run.restore() +
                             " (mail) ran, but the duplicate check didn't list it alone, so "
                             "another restore can't be ruled out; no verdict; left open, as a "
                             "restore may still be running: explore session(s) " +
                             run.explore());
    // Ours polled to the end and read; the explore session left open, as the
    // other candidate (or one the check couldn't see) may still run under it.
    CHECK(rig.veeam.count(HttpMethod::get, run.session_url(run.restore())) == 2);
    CHECK(rig.gets("/v8/RestoreSessions/" + run.restore() + "/Events?limit=1000&offset=0") == 1);
    CHECK(rig.posts(run.post_path()) == 1);
    CHECK(rig.stops(run.explore()) == 0);
    CHECK(rig.gets("/v8/RestoreSessions/" + run.explore()) == 0);
    CHECK_THAT(rig.log(), ContainsSubstring("explore session(s) left open"));
}

// ---- polling -----------------------------------------------------------------------------

TEST_CASE("restore_sample: still Working after 20 minutes: TransientError, left open",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                 {fixture(run.file("session-working"))});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "TransientError");
    CHECK(thrown.what == "veeam_m365: restore session " + run.restore() +
                             " (mail) still Working after 20 minutes; no verdict; left open, as a "
                             "restore may still be running: restore session " +
                             run.restore() + ", explore session(s) " + run.explore());
    CHECK(rig.clock.count(5s) == 240);
    CHECK(rig.veeam.count(HttpMethod::get, run.session_url(run.restore())) == 241);
    CHECK(rig.stops(run.explore()) == 0);
    CHECK(rig.gets("/v8/RestoreSessions/" + run.explore()) == 0);
    CHECK_THAT(rig.log(), ContainsSubstring("explore session(s) left open"));
}

TEST_CASE("restore_sample: polls that fail now and then, and six in a row", "[veeam_m365][w2.5]")
{
    const Run run = mail_x1();
    const HttpResponse failing = veeam_error(500, "Internal error");
    SECTION("a failure between answers resets the count")
    {
        RestoreRig rig;
        rig.serve(run);
        std::vector<HttpResponse> polls{fixture(run.file("session-working"))};
        for (int round = 0; round < 3; ++round) {
            polls.insert(polls.end(), 5, failing);
            polls.push_back(fixture(run.file("session-working")));
        }
        polls.push_back(fixture(run.file("session")));
        rig.veeam.on(HttpMethod::get, run.session_url(run.restore()), polls);

        const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

        CHECK(result.status == connector::RestoreStatus::succeeded);
        CHECK(rig.stops(run.explore()) == 1);
    }
    SECTION("six in a row: no verdict, left open")
    {
        RestoreRig rig;
        rig.serve(run);
        rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                     {fixture(run.file("session-working")), failing});

        const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

        CHECK(thrown.kind == "Error");
        CHECK_THAT(thrown.what,
                   StartsWith("veeam_m365: restore session " + run.restore() +
                              " (mail): 6 polls failed in a row, the last: Veeam GET"));
        CHECK_THAT(thrown.what, ContainsSubstring("left open"));
        CHECK(rig.veeam.count(HttpMethod::get, run.session_url(run.restore())) == 7);
        CHECK(rig.stops(run.explore()) == 0);
    }
    SECTION("a transient 5xx is retried inside a poll")
    {
        RestoreRig rig;
        rig.serve(run);
        rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                     {make_response(503), make_response(503), fixture(run.file("session"))});

        const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

        CHECK(result.status == connector::RestoreStatus::succeeded);
        CHECK(rig.clock.waits() == std::vector<std::chrono::milliseconds>{1s, 2s});
    }
}

TEST_CASE("restore_sample: a restore session that vanishes gets no verdict, left open",
          "[veeam_m365][w2.5]")
{
    const HttpResponse response = GENERATE(
        veeam_error(404, "Restore session does not exist", "ResourceNotFound"), make_response(404));
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                 {fixture(run.file("session-working")), response});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK_THAT(thrown.what,
               StartsWith("veeam_m365: restore session " + run.restore() + " (mail) is gone ("));
    CHECK_THAT(thrown.what, ContainsSubstring("no verdict; left open"));
    CHECK(rig.stops(run.explore()) == 0);
}

TEST_CASE("restore_sample: a session read that isn't a session gets no verdict, left open",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                 {fixture(run.file("session"), [](json& b) { b["state"] = 2; })});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK_THAT(thrown.what, StartsWith("veeam_m365: unexpected response from Veeam: \"state\" "
                                       "isn't a string; left open"));
    CHECK(rig.stops(run.explore()) == 0);
}

// ---- statistics and events ---------------------------------------------------------------

TEST_CASE("restore_sample: statistics answer 409 for a while", "[veeam_m365][w2.5]")
{
    const Run run = mail_x1();
    const std::string statistics = "/v8/RestoreSessions/" + run.restore() + "/Statistics";
    SECTION("then 200")
    {
        RestoreRig rig;
        rig.serve(run);
        rig.veeam.on(HttpMethod::get, url(statistics),
                     {load_fixture("veeam", "statistics-409"),
                      load_fixture("veeam", "statistics-409"), fixture(run.file("statistics"))});

        const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

        CHECK(result.status == connector::RestoreStatus::succeeded);
        CHECK(rig.gets(statistics) == 3);
        // One poll wait, then two statistics waits.
        CHECK(rig.clock.waits() == std::vector<std::chrono::milliseconds>{5s, 5s, 5s});
    }
    SECTION("six times")
    {
        RestoreRig rig;
        rig.serve(run);
        rig.get(statistics, load_fixture("veeam", "statistics-409"));

        const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

        CHECK(thrown.kind == "Error");
        CHECK(thrown.what == "veeam_m365: restore session " + run.restore() +
                                 " stopped, but its statistics still weren't ready after 6 "
                                 "attempts; no verdict");
        CHECK(rig.gets(statistics) == 6);
        CHECK(rig.stops(run.explore()) == 1);
    }
}

TEST_CASE("restore_sample: statistics or events Veeam garbles get no verdict",
          "[veeam_m365][w2.5]")
{
    const Run run = mail_x1();
    const std::string statistics = "/v8/RestoreSessions/" + run.restore() + "/Statistics";
    const std::string events = "/v8/RestoreSessions/" + run.restore() + "/Events?limit=1000&offset=0";
    struct Row {
        std::string name;
        std::string path;
        HttpResponse response;
        std::string kind;
        std::string message;
    };
    const Row row = GENERATE_COPY(
        Row{"no restoredItemsCount", statistics,
            fixture(run.file("statistics"), [](json& b) { b.erase("restoredItemsCount"); }),
            "Error",
            "veeam_m365: unexpected response from Veeam: no whole \"restoredItemsCount\""},
        Row{"statistics refused", statistics, veeam_error(400, "Something broke"), "Error",
            "veeam_m365: restore session " + run.restore() +
                " stopped, but its statistics couldn't be read: Veeam GET " + statistics +
                ": HTTP 400: Something broke; no verdict"},
        // After the restore ran: never NotFoundError (a missing item) or
        // TransientError (try again), which would read as something else.
        Row{"statistics gone", statistics,
            veeam_error(404, "Restore session does not exist", "ResourceNotFound"), "Error",
            "veeam_m365: restore session " + run.restore() +
                " stopped, but its statistics couldn't be read: "},
        Row{"statistics unreachable", statistics, make_response(503), "Error",
            "veeam_m365: restore session " + run.restore() +
                " stopped, but its statistics couldn't be read: "},
        Row{"events gone", events,
            veeam_error(404, "Restore session does not exist", "ResourceNotFound"), "Error",
            "veeam_m365: restore session " + run.restore() +
                " stopped, but its events couldn't be read: "},
        Row{"events unreachable", events, make_response(503), "Error",
            "veeam_m365: restore session " + run.restore() +
                " stopped, but its events couldn't be read: "},
        Row{"an event of the wrong kind", events,
            fixture(run.file("events"), [](json& b) { b["results"][1]["itemName"] = 1; }),
            "Error", "veeam_m365: unexpected response from Veeam: \"itemName\" isn't a string"},
        // VeeamClient's paging reads the list: its shape error is a VeeamError.
        Row{"events that aren't a list", events, make_response(200, R"({"results":3})"), "Error",
            "veeam_m365: restore session " + run.restore() +
                " stopped, but its events couldn't be read: Veeam GET " + events +
                ": unexpected response: no \"results\" list; no verdict"});
    CAPTURE(row.name);
    RestoreRig rig;
    rig.serve(run);
    rig.get(row.path, row.response);

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == row.kind);
    CHECK_THAT(thrown.what, StartsWith(row.message));
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: a stopped session without a result gets no verdict, and the explore "
          "session closed",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                 {fixture(run.file("session-working")),
                  fixture(run.file("session"), [](json& b) { b.erase("result"); })});

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({mail_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what ==
          "veeam_m365: unexpected response from Veeam: a stopped session without a \"result\"");
    CHECK(rig.gets("/v8/RestoreSessions/" + run.restore() + "/Statistics") == 0);
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: a page of events Veeam caps below the limit is followed by the next",
          "[veeam_m365][w2.5]")
{
    // VeeamClient's paging (the W2.5 review): Veeam echoes the limit it
    // applied, and a full page of that size isn't the last.
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    const std::string events = "/v8/RestoreSessions/" + run.restore() + "/Events";
    json all = load_fixture_json("veeam", run.file("events")).at("body");
    json first = all;
    first["limit"] = 2;
    first["results"] = json::array({all["results"][0], all["results"][1]});
    json second = all;
    second["offset"] = 2;
    second["limit"] = 2;
    second["results"] = json::array();
    for (std::size_t i = 2; i < all["results"].size(); ++i) {
        second["results"].push_back(all["results"][i]);
    }
    REQUIRE(second["results"].size() < 2);
    rig.get(events + "?limit=1000&offset=0", make_response(200, first.dump()));
    rig.get(events + "?limit=1000&offset=2", make_response(200, second.dump()));

    const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item()}));

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(rig.gets(events + "?limit=1000&offset=2") == 1);
}

// ---- verdicts ----------------------------------------------------------------------------

TEST_CASE("restore_sample: a session that restored nothing for lack of Microsoft 365 is an "
          "error, never failed",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = od_x1();
    rig.serve(run);
    const std::string r = "/v8/RestoreSessions/" + run.restore();
    rig.veeam.on(HttpMethod::get, run.session_url(run.restore()), {fixture("w10-od-user-session")});
    rig.get(r + "/Statistics", fixture("w10-od-user-statistics"));
    rig.get(r + "/Events?limit=1000&offset=0", fixture("w10-od-user-events"));

    const Caught thrown = caught_by([&] { rig.restore(restore_spec({}, {}, {od_x1_item()})); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: restore session " + run.restore() +
                             " (onedrive) restored nothing: Cannot connect to Microsoft 365. "
                             "Failed to connect to https://restoreprooflab-my.sharepoint.com/"
                             "personal/alice_restoreprooflab_onmicrosoft_com.");
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: a session that restored nothing for another reason is failed",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = od_x1();
    rig.serve(run);
    const std::string r = "/v8/RestoreSessions/" + run.restore();
    rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                 {fixture(run.file("session"), [](json& b) {
                     b["result"] = "Failed";
                     b["details"] = "1 item processed (1 failed)";
                 })});
    rig.get(r + "/Statistics", fixture(run.file("statistics"), [](json& b) {
                b["restoredItemsCount"] = 0;
                b["failedItemsCount"] = 1;
                b["items"][0]["status"] = "Failed";
            }));
    rig.get(r + "/Events?limit=1000&offset=0", fixture(run.file("events"), [](json& b) {
                b["results"][1]["status"] = "Failed";
                b["results"][1]["message"] = "Item rp-canary-16.pdf: the file is locked";
            }));

    const connector::RestoreResult result = rig.restore(restore_spec({}, {}, {od_x1_item()}));

    CHECK(result.status == connector::RestoreStatus::failed);
    CHECK(result.items_sent == 1);
    CHECK(result.items_restored == 0);
    REQUIRE(result.items.size() == 1);
    CHECK(result.items[0].outcome == connector::ItemOutcome::failed);
    CHECK(result.items[0].message == "Item rp-canary-16.pdf: the file is locked");
    CHECK_FALSE(result.items[0].infrastructure);
    REQUIRE(result.sessions.size() == 1);
    CHECK(result.sessions[0].result == "Failed");
    CHECK(rig.stops(run.explore()) == 1);
}

TEST_CASE("restore_sample: a Warning session with fewer restored is partial", "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x5();
    rig.serve(run);
    const std::string r = "/v8/RestoreSessions/" + run.restore();
    rig.veeam.on(HttpMethod::get, run.session_url(run.restore()),
                 {fixture(run.file("session"), [](json& b) {
                     b["result"] = "Warning";
                     b["details"] = "5 items processed (4 successes, 1 warning)";
                 })});
    rig.get(r + "/Statistics",
            fixture(run.file("statistics"), [](json& b) { b["restoredItemsCount"] = 4; }));
    rig.get(r + "/Events?limit=1000&offset=0", fixture(run.file("events"), [](json& b) {
                for (json& e : b["results"]) {
                    if (e.value("itemName", "") == "RP-CANARY-0005") {
                        e["status"] = "Warning";
                        e["message"] = "Item RP-CANARY-0005 was skipped";
                    }
                }
            }));

    const connector::RestoreResult result = rig.restore(restore_spec(mail_x5_items()));

    CHECK(result.status == connector::RestoreStatus::partial);
    CHECK(result.items_restored == 4);
    CHECK(result.items_sent == 5);
    std::vector<connector::ItemOutcome> outcomes;
    for (const auto& item : result.items) {
        outcomes.push_back(item.outcome);
    }
    using connector::ItemOutcome;
    CHECK(outcomes == std::vector<ItemOutcome>{ItemOutcome::restored, ItemOutcome::restored,
                                               ItemOutcome::restored, ItemOutcome::failed,
                                               ItemOutcome::restored});
    CHECK_THAT(result.log,
               ContainsSubstring("Warning RP-CANARY-0005: Item RP-CANARY-0005 was skipped\n"));
}

// ---- happy paths -------------------------------------------------------------------------

TEST_CASE("restore_sample restores the recorded five mails in one call", "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x5();
    rig.serve(run);

    const connector::RestoreResult result = rig.restore(restore_spec(mail_x5_items()));

    // The explore POST, byte for byte.
    std::vector<HttpRequest> explores;
    for (const HttpRequest& request : rig.veeam.requests()) {
        if (request.url == url("/v8/Organizations/" + kOrgId + "/explore")) {
            explores.push_back(request);
        }
    }
    REQUIRE(explores.size() == 1);
    CHECK(explores[0].body == R"({"dateTime":")" + kBackupTime +
                                  R"(","type":"Vex","showDeleted":false,"showAllVersions":false})");
    // The restore POST: once, the recorded body with the credential in it.
    const std::vector<HttpRequest> posts = rig.restore_posts();
    REQUIRE(posts.size() == 1);
    CHECK(posts[0].url == restore_url(run));
    CHECK(posts[0].body == expected_body(run));
    CHECK(posts[0].max_attempts == 1);
    CHECK_FALSE(posts[0].retry_on_status);
    CHECK(posts[0].timeout == 60s);
    CHECK(rig.exporter->calls == 1);
    CHECK(rig.exporter->thumbprints == std::vector<std::string>{kThumbprint});

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.session_ids == std::vector<std::string>{run.restore()});
    CHECK(result.items_sent == 5);
    CHECK(result.items_restored == 5);
    REQUIRE(result.sessions.size() == 1);
    const connector::RestoreSessionResult& session = result.sessions[0];
    CHECK(session.id == run.restore());
    CHECK(session.kind == connector::ItemKind::mail);
    CHECK(session.result == "Success");
    CHECK(session.details == "5 items processed (5 successes)");
    CHECK(session.started_at == "2026-09-28T21:30:20.3324555Z");
    CHECK(session.ended_at == "2026-09-28T21:31:41.596799Z");
    CHECK(session.items_sent == 5);
    CHECK(session.items_restored == 5);
    REQUIRE(result.items.size() == 5);
    for (std::size_t i = 0; i < 5; ++i) {
        CHECK(result.items[i].kind == connector::ItemKind::mail);
        CHECK(result.items[i].name == mail_x5_items()[i].subject);
        CHECK(result.items[i].session_id == run.restore());
        CHECK(result.items[i].outcome == connector::ItemOutcome::restored);
    }
    CHECK_THAT(result.log,
               StartsWith("session " + run.restore() +
                          " (mail): Success, 5 items processed (5 successes)\n"
                          "Success RP-CANARY-0003: Item RP-CANARY-0003 was restored successfully "
                          "(type: IPM.Note; source: Alice Test\\Inbox; target: "
                          "restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox)\n"));
    // One poll wait: Working, then Stopped.
    CHECK(rig.clock.waits() == std::vector<std::chrono::milliseconds>{5s});
    CHECK(rig.veeam.count(HttpMethod::get, run.duplicate_url()) == 1);
    CHECK(rig.stops(run.explore()) == 1);
    CHECK(rig.lab.log().empty());
    check_no_secrets(rig, result.log);
    for (const auto& item : result.items) {
        check_no_secrets(rig, item.message);
    }
}

TEST_CASE("restore_sample restores the recorded SharePoint and OneDrive files",
          "[veeam_m365][w2.5]")
{
    const bool sharepoint = GENERATE(true, false);
    const Run run = sharepoint ? sp_x1() : od_x1();
    CAPTURE(run.name);
    RestoreRig rig;
    rig.serve(run);

    const connector::RestoreResult result = rig.restore(
        sharepoint ? restore_spec({}, {sp_x1_item()}) : restore_spec({}, {}, {od_x1_item()}));

    const std::vector<HttpRequest> posts = rig.restore_posts();
    REQUIRE(posts.size() == 1);
    CHECK(posts[0].url == restore_url(run));
    CHECK(posts[0].body == expected_body(run));
    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.session_ids == std::vector<std::string>{run.restore()});
    REQUIRE(result.items.size() == 1);
    CHECK(result.items[0].outcome == connector::ItemOutcome::restored);
    CHECK(result.items[0].kind == run.kind);
    CHECK(rig.stops(run.explore()) == 1);
    check_no_secrets(rig, result.log);
}

TEST_CASE("restore_sample restores all three types, one session each, in order",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const std::vector<Run> runs{mail_x5(), sp_x1(), od_x1()};
    for (const Run& run : runs) {
        rig.serve(run);
    }

    const connector::RestoreResult result =
        rig.restore(restore_spec(mail_x5_items(), {sp_x1_item()}, {od_x1_item()}));

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.session_ids ==
          std::vector<std::string>{runs[0].restore(), runs[1].restore(), runs[2].restore()});
    CHECK(result.items_sent == 7);
    CHECK(result.items_restored == 7);
    REQUIRE(result.items.size() == 7);
    CHECK(result.items[5].name == "rp-canary-06.pdf");
    CHECK(result.items[6].name == "rp-canary-16.pdf");
    // Every explore session opened before the first restore POST.
    const std::vector<HttpRequest> requests = rig.veeam.requests();
    std::size_t last_explore = 0;
    std::size_t first_restore = requests.size();
    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (requests[i].url.ends_with("/explore")) {
            last_explore = i;
        }
        if (requests[i].url.ends_with("/restoreTo") || requests[i].url.ends_with("/copyTo")) {
            first_restore = std::min(first_restore, i);
        }
    }
    CHECK(last_explore < first_restore);
    const std::vector<HttpRequest> posts = rig.restore_posts();
    REQUIRE(posts.size() == 3);
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(posts[i].url == restore_url(runs[i]));
        CHECK(posts[i].body == expected_body(runs[i]));
        CHECK(rig.stops(runs[i].explore()) == 1);
    }
    CHECK(rig.exporter->calls == 3);
    check_no_secrets(rig, result.log);
}

TEST_CASE("restore_sample sends same-named mails of one mailbox in separate calls",
          "[veeam_m365][w2.5]")
{
    RestoreRig rig;
    const Run run = mail_x1();
    rig.serve(run);
    // A second RP-CANARY-0011 in bob's Archive folder.
    const std::string mailbox =
        "/v8/RestoreSessions/" + run.explore() + "/organization/mailboxes/" + run.container();
    const std::string archive = "AAAAArchiveFolderMadeUp";
    const std::string copy_id = "LgAAAMadeUpArchivedCopyOfCanary0011";
    json folder = load_fixture_json("veeam", run.file("folder-inbox")).at("body");
    folder["results"][0]["name"] = "Archive";
    folder["results"][0]["id"] = archive;
    rig.get(paged(mailbox + "/folders?name=Archive"), make_response(200, folder.dump()));
    json item = load_fixture_json("veeam", run.file("item")).at("body");
    item["id"] = copy_id;
    rig.get(paged(mailbox + "/items?parentId=" + archive),
            make_response(200, json{{"results", {item}}}.dump()));
    rig.get(mailbox + "/items/" + copy_id, make_response(200, item.dump()));
    // The second call's session, found by the same duplicate check.
    const std::string second = "d0000000-0000-4000-8000-000000000002";
    rig.veeam.on(HttpMethod::post, restore_url(run),
                 {load_fixture("veeam", run.restore_fixture),
                  make_response(200, json{{"sessionId", second}}.dump())});
    rig.veeam.on(HttpMethod::get, run.duplicate_url(),
                 {fixture(run.file("sessions-after-post")),
                  fixture(run.file("sessions-after-post"), [&](json& b) {
                      json copy = b["results"][0];
                      copy["id"] = second;
                      b["results"].push_back(copy);
                  })});
    rig.veeam.on(HttpMethod::get, run.session_url(second),
                 {fixture(run.file("session"), [&](json& b) { b["id"] = second; })});
    rig.get("/v8/RestoreSessions/" + second + "/Statistics", fixture(run.file("statistics")));
    rig.get("/v8/RestoreSessions/" + second + "/Events?limit=1000&offset=0", fixture(run.file("events")));
    connector::MailSelector archived = mail_x1_item();
    archived.folder = "Archive";

    const connector::RestoreResult result = rig.restore(restore_spec({mail_x1_item(), archived}));

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.session_ids == std::vector<std::string>{run.restore(), second});
    const std::vector<HttpRequest> posts = rig.restore_posts();
    REQUIRE(posts.size() == 2);
    CHECK(json::parse(posts[0].body)["items"].size() == 1);
    CHECK(json::parse(posts[1].body)["items"][0]["id"] == copy_id);
    CHECK(rig.exporter->calls == 2);
    CHECK(result.items[0].session_id == run.restore());
    CHECK(result.items[1].session_id == second);
}
