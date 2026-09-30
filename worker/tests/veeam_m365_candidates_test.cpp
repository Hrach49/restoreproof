// W2.6 (#31): VeeamM365Connector::list_candidates, the random half's pool,
// on W2.4's recorded explore sessions and containers (veeam_restore_lab.hpp)
// and W1.4's recorded mail folders and organisation users (w26-*). No
// recorded listing holds a real item, so the items are synthetic, built here
// from recorded entries (tests/fixtures/veeam/README.md). Failure paths
// first. No network, no real waits.

#include "fake_http_client.hpp"
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
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
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

// The recorded containers (w24-*): alice's and bob's mailboxes, the
// RestoreTest site and its "Dokumenty" library (url .../Shared Documents),
// Hrachya's OneDrive, and the tenant's host.
const std::string kAliceMailbox = "e00393b0-a896-4487-ad04-0e1be36468fb";
const std::string kBobMailbox = "12af7578-24c6-48e4-a3a5-3174bda4f4d4";
const std::string kRestoreTestMailbox = "624ded8d-352a-4b55-9cb9-3899b76a14c8";
const std::string kDiscoveryMailbox = "79d11e03-8472-4752-823a-0c8c59ece5a5";
const std::string kHrachyaMailbox = "dcb1746c-fabf-4fc6-a9c2-8c6f50c76f3f";
const std::string kAllCompanyMailbox = "2567d67d-00ea-4a01-ad42-4a2051901a23";
const std::string kSite = "fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e689";
const std::string kPersonalSite =
    "6d600fc0-65f8-4811-ad18-096ec5b7e83498cfff1a-b404-4438-ae6e-6927a6ccc325";
const std::string kAllCompanySite =
    "8940f75b-a091-4115-80e0-418447edb6e3b0066e5e-cea1-4afd-bdc5-4907d626db31";
const std::string kDocumentsList = "7ce76907-31fb-45fe-ad8f-960264f0313b";
const std::string kRestoreTargetList = "ffec069d-65e4-4c3a-9da2-ac086cf9dafa";
const std::string kSitePagesList = "a8c50592-c7e0-4e2b-81b8-b15e97977a63";
const std::string kAliceOneDrive = kPersonalSite;
const std::string kHrachyaOneDrive =
    "41514e3e-02f7-405b-96da-9b8bd8e1d45d98cfff1a-b404-4438-ae6e-6927a6ccc325";
const std::string kHrachya = "HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com";
const std::string kGraphSite = "restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,"
                               "4ecaf399-cc0e-4d95-b3fe-cd091a09e689";
// "Dokumenty"'s Graph drive ID, worked out by hand from its three GUIDs.
const std::string kDocumentsDrive = "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5okHaed8-zH-Ra2PlgJk8DE7";
// Alice's recorded mail folders (w26-mail-folders*); the same IDs serve
// every mailbox here.
const std::string kArchive = "AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAiKEAAA";
const std::string kConversationHistory =
    "AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAWAAAA";
const std::string kSentItems = "AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQkAAA";
const std::string kCalendar = "AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQ0AAA";
const std::string kDeletedItems = "AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQoAAA";
// A top-level folder of alice's recorded OneDrive (w24-od-x1-folders-root),
// by name: its ID is also in Graph's recordings, which a re-recording keeps
// the tests from spelling out (graph_client_test.cpp).
std::string onedrive_folder(const std::string& name)
{
    for (const json& entry : results_of("w24-od-x1-folders-root")) {
        if (entry.at("name") == name) {
            return entry.at("id").get<std::string>();
        }
    }
    throw std::logic_error("no folder " + name + " in w24-od-x1-folders-root");
}

constexpr std::int64_t kCap = 64LL * 1024 * 1024;

using Key = std::pair<std::string, std::string>; // container, folder (or parent)

// A synthetic mail, from a recorded one.
json mail(const std::string& id, const std::string& subject,
          const std::string& item_class = "IPM.Note",
          const std::string& received = "2026-09-26T08:15:02.1234567Z")
{
    json item = results_of("w24-mail-x5-items").at(0);
    item["id"] = id;
    item["subject"] = subject;
    item["itemClass"] = item_class;
    item["received"] = received;
    return item;
}

// A synthetic SharePoint or OneDrive file, from a recorded one; no size:
// sizeBytes left out.
json file(bool sharepoint, const std::string& id, const std::string& name,
          std::optional<std::int64_t> size = 1000)
{
    json entry = results_of(sharepoint ? "w24-sp-x1-documents" : "w24-od-x1-documents").at(0);
    entry["id"] = id;
    entry["name"] = name;
    entry["isFolder"] = false;
    if (size) {
        entry["sizeBytes"] = *size;
    } else {
        entry.erase("sizeBytes");
    }
    return entry;
}

// A synthetic folder, from a recorded one.
json folder(const std::string& id, const std::string& name)
{
    json entry = results_of("w24-od-x1-folders-root").at(0);
    entry["id"] = id;
    entry["name"] = name;
    return entry;
}

// A library of the RestoreTest site, from the recorded "Dokumenty".
json library(const std::string& list, const std::string& url)
{
    for (json entry : results_of("w24-sp-x1-libraries")) {
        if (entry.at("id").get<std::string>().ends_with(kDocumentsList)) {
            entry["id"] = kSite + list;
            entry["url"] = url;
            return entry;
        }
    }
    throw std::logic_error("no Dokumenty library in w24-sp-x1-libraries");
}

HttpResponse listing(const json& results)
{
    return make_response(200, json{{"offset", 0}, {"limit", 1000}, {"results", results}}.dump());
}

std::string lower(std::string text)
{
    std::ranges::transform(text, text.begin(), [](char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    });
    return text;
}

// What the tenant holds in the restore point: the recorded containers, and
// whatever items a test puts in.
struct Tenant {
    json mailboxes = results_of("w24-mail-x5-mailboxes");
    json mail_folders_root = results_of("w26-mail-folders-root");
    json mail_folders = results_of("w26-mail-folders");
    std::map<Key, json> mail;             // (mailbox, folder ID) -> items
    json sites = results_of("w24-sp-x1-sites");
    std::map<std::string, json> libraries{{kSite, results_of("w24-sp-x1-libraries")}};
    std::map<Key, json> sp_folders;       // (site, parent) -> folders
    std::map<Key, json> sp_documents;     // (site, parent) -> documents
    json users = results_of("w26-org-users");
    json onedrives = results_of("w24-od-x1-onedrives");
    std::map<Key, json> od_folders{{{kAliceOneDrive, "root"}, results_of("w24-od-x1-folders-root")}};
    std::map<Key, json> od_documents;     // (OneDrive, parent) -> documents

    void add_mail(const std::string& mailbox, const std::string& folder_id, json item)
    {
        json& items = mail[{mailbox, folder_id}];
        if (items.is_null()) {
            items = json::array();
        }
        items.push_back(std::move(item));
    }
    static void add(std::map<Key, json>& to, const Key& key, json entry)
    {
        json& list = to[key];
        if (list.is_null()) {
            list = json::array();
        }
        list.push_back(std::move(entry));
    }

    // Every listing reversed: the order Veeam lists in must not matter.
    void reverse()
    {
        const auto flip = [](json& list) { std::reverse(list.begin(), list.end()); };
        for (json* list : {&mailboxes, &mail_folders_root, &mail_folders, &sites, &users, &onedrives}) {
            flip(*list);
        }
        for (auto* map : {&mail, &sp_folders, &sp_documents, &od_folders, &od_documents}) {
            for (auto& [key, list] : *map) {
                flip(list);
            }
        }
        for (auto& [key, list] : libraries) {
            flip(list);
        }
    }
};

std::string session_of(const Run& run)
{
    return "/v8/RestoreSessions/" + run.explore();
}

std::string mail_base()
{
    return session_of(mail_x5()) + "/organization/mailboxes";
}
std::string sites_base()
{
    return session_of(sp_x1()) + "/Organization/Sites";
}
std::string onedrives_base()
{
    return session_of(od_x1()) + "/Organization/OneDrives";
}

struct CandidateRig {
    CandidateRig()
    {
        for (const Run& run : {mail_x5(), sp_x1(), od_x1()}) {
            {
                const std::lock_guard lock(rig.mutex);
                rig.explores[run.type] = fixture(run.file("explore"));
            }
            // The close: the explore session is Working, then stopped.
            rig.get(session_of(run),
                    make_response(200, load_fixture_json("veeam", run.file("explore")).at("body").dump()));
            rig.veeam.on(HttpMethod::post, url(session_of(run) + "/Stop"),
                         {load_fixture("veeam", "stop-204")});
        }
    }

    // Routes every listing the connector may ask for, from `tenant`.
    void serve()
    {
        const std::string mail = mail_base();
        rig.get(paged(mail), listing(tenant.mailboxes));
        for (const json& mailbox : tenant.mailboxes) {
            const std::string path = mail + "/" + lower(mailbox.at("id").get<std::string>());
            rig.get(paged(path + "/folders?parentId=root"), listing(tenant.mail_folders_root));
            rig.get(paged(path + "/folders"), listing(tenant.mail_folders));
            for (const json& folder : tenant.mail_folders) {
                const std::string id = folder.at("id").get<std::string>();
                const auto items = tenant.mail.find({lower(mailbox.at("id").get<std::string>()), id});
                rig.get(paged(path + "/items?parentId=" + encoded(id)),
                        listing(items != tenant.mail.end() ? items->second : json::array()));
            }
        }

        const std::string sites = sites_base();
        rig.get(paged(sites + "?parentId=root"), listing(tenant.sites));
        for (const json& site : tenant.sites) {
            const std::string id = lower(site.at("id").get<std::string>());
            const auto libraries = tenant.libraries.find(id);
            const json listed = libraries != tenant.libraries.end() ? libraries->second : json::array();
            rig.get(paged(sites + "/" + id + "/Libraries"), listing(listed));
            std::set<std::string> parents;
            for (const json& entry : listed) {
                parents.insert(lower(entry.at("id").get<std::string>()));
            }
            serve_files(sites + "/" + id, id, tenant.sp_folders, tenant.sp_documents, parents);
        }

        rig.get(paged("/v8/Organizations/" + kOrgId + "/Users"), listing(tenant.users));
        const std::string onedrives = onedrives_base();
        rig.get(paged(onedrives), listing(tenant.onedrives));
        for (const json& onedrive : tenant.onedrives) {
            const std::string id = lower(onedrive.at("id").get<std::string>());
            serve_files(onedrives + "/" + id, id, tenant.od_folders, tenant.od_documents, {"root"});
        }
    }

    // Folders and Documents for every parent the tenant knows in `container`.
    void serve_files(const std::string& path, const std::string& container,
                     const std::map<Key, json>& folders, const std::map<Key, json>& documents,
                     std::set<std::string> parents)
    {
        for (const auto* map : {&folders, &documents}) {
            for (const auto& [key, list] : *map) {
                if (key.first == container) {
                    parents.insert(key.second);
                }
            }
        }
        for (const auto& [key, list] : folders) {
            if (key.first == container) {
                for (const json& entry : list) {
                    parents.insert(entry.at("id").get<std::string>());
                }
            }
        }
        for (const std::string& parent : parents) {
            const auto listed = [&](const std::map<Key, json>& map) {
                const auto it = map.find({container, parent});
                return listing(it != map.end() ? it->second : json::array());
            };
            rig.get(paged(path + "/Folders?parentId=" + encoded(parent)), listed(folders));
            rig.get(paged(path + "/Documents?parentId=" + encoded(parent)), listed(documents));
        }
    }

    connector::CandidatePool list(const connector::CandidateQuery& query)
    {
        return rig.connector().list_candidates(query);
    }

    // GETs whose URL holds `part`.
    std::size_t gets_with(const std::string& part) const
    {
        std::size_t n = 0;
        for (const HttpRequest& request : rig.veeam.requests()) {
            n += request.method == HttpMethod::get && request.url.find(part) != std::string::npos ? 1 : 0;
        }
        return n;
    }

    // Every POST that isn't a token request, an explore session or its Stop.
    std::vector<std::string> other_posts() const
    {
        std::vector<std::string> out;
        for (const HttpRequest& request : rig.veeam.requests()) {
            if (request.method == HttpMethod::post && request.url != url("/v8/token") &&
                request.url != url("/v8/token/logout") &&
                request.url != url("/v8/Organizations/" + kOrgId + "/explore") &&
                !request.url.ends_with("/Stop")) {
                out.push_back(request.url);
            }
        }
        return out;
    }

    RestoreRig rig;
    Tenant tenant;
};

// Looks into everything: every eligible container and folder.
connector::CandidateLimits everything()
{
    connector::CandidateLimits limits;
    limits.containers_wanted = 100;
    limits.containers_tried = 100;
    limits.folders_per_container = 100;
    return limits;
}

connector::CandidateQuery query(bool mail, bool sharepoint, bool onedrive,
                                connector::CandidateLimits limits = everything())
{
    connector::RestorePoint point;
    point.id = kRestorePointId;
    point.backup_time = kBackupTime;
    connector::CandidateExclusions exclude;
    exclude.list_ids = {kCanaryListId};
    exclude.subjects = {"RP-CANARY-0001", "RP-CANARY-0011"};
    return {kOrgName,
            point,
            connector::RestoreTargets::from_config(rp::test::graph_lab::lab_config()),
            mail,
            sharepoint,
            onedrive,
            0x8b26e36a,
            exclude,
            limits};
}

// The pool's items as text, sorted: what was found, whatever the draw order.
std::vector<std::string> found(const connector::CandidatePool& pool)
{
    std::vector<std::string> out;
    for (const connector::MailSelector& s : pool.mail) {
        out.push_back("mail|" + s.mailbox + "|" + s.folder + "|" + s.subject + "|" + s.received_at);
    }
    for (const connector::SharePointCandidate& c : pool.sharepoint) {
        const connector::SharePointSelector& s = c.selector;
        out.push_back("sharepoint|" + s.site_id + "|" + s.drive_id + "|" + s.folder_path + "|" +
                      s.name + "|" + s.list_id + "|" + std::to_string(s.size) + "|" +
                      std::to_string(c.size_bytes));
    }
    for (const connector::OneDriveCandidate& c : pool.onedrive) {
        const connector::OneDriveSelector& s = c.selector;
        out.push_back("onedrive|" + s.user + "|" + s.folder_path + "|" + s.name + "|" +
                      std::to_string(s.size) + "|" + std::to_string(c.size_bytes));
    }
    std::ranges::sort(out);
    return out;
}

// The pool in its order, records included.
std::string as_text(const connector::CandidatePool& pool)
{
    std::string out;
    for (const connector::MailSelector& s : pool.mail) {
        out += s.mailbox + "|" + s.folder + "|" + s.subject + "\n";
    }
    for (const connector::SharePointCandidate& c : pool.sharepoint) {
        out += c.selector.site_id + "|" + c.selector.folder_path + "|" + c.selector.name + "\n";
    }
    for (const connector::OneDriveCandidate& c : pool.onedrive) {
        out += c.selector.user + "|" + c.selector.folder_path + "|" + c.selector.name + "\n";
    }
    for (const connector::BrowseRecord* r :
         {&pool.mail_browse, &pool.sharepoint_browse, &pool.onedrive_browse}) {
        out += std::to_string(r->containers_eligible) + " " + std::to_string(r->folders_listed) +
               " " + (r->short_of_containers ? "short" : "enough") + ":";
        for (const std::string& c : r->containers_listed) {
            out += " " + c;
        }
        out += "\n";
    }
    return out;
}

// The good candidates every exclusion row keeps next to what it adds.
const std::string kKeptMail = "mail|alice@RestoreProofLab.onmicrosoft.com|Conversation "
                              "History|Quarterly plan|2026-09-26T08:15:02Z";
const std::string kKeptSharePoint =
    "sharepoint|" + kGraphSite + "|" + kDocumentsDrive + "|/|Budget.xlsx|" + kDocumentsList + "|-1|1000";
const std::string kKeptOneDrive = "onedrive|" + kHrachya + "|/Projects|Holiday.png|-1|1000";

void keep_good_candidates(Tenant& tenant)
{
    tenant.add_mail(kAliceMailbox, kConversationHistory, mail("real-1", "Quarterly plan"));
    Tenant::add(tenant.sp_documents, {kSite, kSite + kDocumentsList},
                file(true, kSite + kDocumentsList + "00000000-0000-4000-8000-000000000001",
                     "Budget.xlsx"));
    Tenant::add(tenant.od_folders, {kHrachyaOneDrive, "root"},
                folder("00000000-0000-4000-8000-0000000000f1", "Projects"));
    Tenant::add(tenant.od_documents, {kHrachyaOneDrive, "00000000-0000-4000-8000-0000000000f1"},
                file(false, "00000000-0000-4000-8000-000000000011", "Holiday.png"));
}

} // namespace

// ---- before any request ----------------------------------------------------------------------

TEST_CASE("list_candidates: no type with a random half asks Veeam nothing", "[veeam_m365][w2.6]")
{
    CandidateRig rig;

    const connector::CandidatePool pool = rig.list(query(false, false, false));

    CHECK(found(pool).empty());
    CHECK(rig.rig.veeam.requests().empty());
}

TEST_CASE("list_candidates: a query it can't use is refused before any request", "[veeam_m365][w2.6]")
{
    struct Row {
        std::string name;
        std::function<void(connector::CandidateQuery&)> edit;
        std::string message;
    };
    const Row row = GENERATE(
        Row{"no client", [](connector::CandidateQuery& q) { q.client_ref.clear(); },
            "veeam_m365: the client reference is empty"},
        Row{"not Veeam's time",
            [](connector::CandidateQuery& q) {
                q.restore_point.backup_time = "2026-09-27T22:00:48+00:00";
            },
            "veeam_m365: the restore point's backup time isn't Veeam's UTC form, such as "
            "2026-09-25T19:37:15.2145203Z"},
        Row{"a negative limit",
            [](connector::CandidateQuery& q) { q.limits.walk_calls = -1; },
            "veeam_m365: a candidate limit is negative"},
        Row{"a negative size cap",
            [](connector::CandidateQuery& q) { q.limits.max_file_bytes = -1; },
            "veeam_m365: a candidate limit is negative"});
    CAPTURE(row.name);
    CandidateRig rig;
    connector::CandidateQuery q = query(true, true, true);
    row.edit(q);

    const Caught thrown = caught_by([&] { rig.list(q); });

    CHECK(thrown.kind == "invalid_argument");
    CHECK(thrown.what == row.message);
    CHECK(rig.rig.veeam.requests().empty());
}

TEST_CASE("list_candidates: the client, the restore point and the preflight are checked before "
          "any explore session",
          "[veeam_m365][w2.6]")
{
    struct Row {
        std::string name;
        std::function<void(CandidateRig&, connector::CandidateQuery&)> edit;
        std::string message;
    };
    const std::string id = kRestorePointId;
    const Row row = GENERATE_COPY(
        Row{"an unknown client",
            [](CandidateRig&, connector::CandidateQuery& q) { q.client_ref = "Other.onmicrosoft.com"; },
            "veeam_m365: client Other.onmicrosoft.com not found in Veeam; nothing was listed"},
        Row{"a point the client hasn't",
            [](CandidateRig&, connector::CandidateQuery& q) { q.restore_point.id = "made-up"; },
            "veeam_m365: restore point made-up isn't one of client "
            "RestoreProofLab.onmicrosoft.com's restore points in Veeam; nothing was listed"},
        Row{"a backup time one byte off",
            [](CandidateRig&, connector::CandidateQuery& q) {
                q.restore_point.backup_time = "2026-09-27T22:00:48.1447834Z";
            },
            "veeam_m365: restore point " + id +
                " of client RestoreProofLab.onmicrosoft.com has backup time "
                "2026-09-27T22:00:48.1447833Z in Veeam, not 2026-09-27T22:00:48.1447834Z; "
                "nothing was listed"},
        Row{"a session of ours still Working",
            [](CandidateRig& rig, connector::CandidateQuery&) {
                rig.rig.get("/v8/RestoreSessions?limit=200",
                            fixture("w24-mail-x1-sweep-before", [](json& b) {
                                b["results"][2]["state"] = "Working";
                                b["results"][2]["id"] = "5e1c0a24-0000-4000-8000-00000000a0a0";
                            }));
            },
            "veeam_m365: Veeam has restore sessions of rp-veeam still Working "
            "(5e1c0a24-0000-4000-8000-00000000a0a0); stop them first "
            "(docs/api/veeam-m365/08-sweep-sessions.ps1); nothing was listed"});
    CAPTURE(row.name);
    CandidateRig rig;
    rig.serve();
    connector::CandidateQuery q = query(true, true, true);
    row.edit(rig, q);

    const Caught thrown = caught_by([&] { rig.list(q); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == row.message);
    CHECK(rig.rig.explores_opened() == 0);
}

// ---- Veeam's errors ----------------------------------------------------------------------------

TEST_CASE("list_candidates: Veeam's errors map to connector errors, and each explore session "
          "is closed",
          "[veeam_m365][w2.6]")
{
    const std::string mailboxes = url(paged(mail_base()));
    struct Row {
        std::string name;
        std::function<void(CandidateRig&)> edit;
        std::string kind;
        std::size_t explores;
        std::string starts;
    };
    const Row row = GENERATE_COPY(
        Row{"the sign-in refused",
            [](CandidateRig& rig) {
                rig.rig.veeam.on(HttpMethod::post, url("/v8/token"),
                                 {load_fixture("veeam", "token-rejected-401")});
            },
            "AuthError", 0, ""},
        Row{"the mailboxes unreachable",
            [=](CandidateRig& rig) {
                rig.rig.veeam.on(HttpMethod::get, mailboxes, {make_response(503)});
            },
            "TransientError", 1, "Veeam GET " + mailboxes.substr(kBase.size()) + ": HTTP 503 after 5 attempts"},
        Row{"a mailbox without an ID",
            [=](CandidateRig& rig) {
                json listed = rig.tenant.mailboxes;
                listed[0].erase("id");
                rig.rig.veeam.on(HttpMethod::get, mailboxes, {listing(listed)});
            },
            "Error", 1, "Veeam GET "},
        Row{"a mailbox address that isn't text",
            [=](CandidateRig& rig) {
                json listed = rig.tenant.mailboxes;
                listed[0]["email"] = 42;
                rig.rig.veeam.on(HttpMethod::get, mailboxes, {listing(listed)});
            },
            "Error", 1, "veeam_m365: unexpected response from Veeam: \"email\" isn't a string"},
        Row{"the explore session gone",
            [=](CandidateRig& rig) {
                rig.rig.veeam.on(HttpMethod::get, mailboxes,
                                 {make_response(404, R"({"message":"Restore session is not found.",)"
                                                     R"("errorCode":"ResourceNotFound"})")});
            },
            "Error", 1, "Veeam GET "},
        Row{"a folder list that isn't JSON",
            [](CandidateRig& rig) {
                for (const std::string& mailbox : {kAliceMailbox, kBobMailbox, kHrachyaMailbox,
                                                   kAllCompanyMailbox}) {
                    rig.rig.get(paged(mail_base() + "/" + mailbox + "/folders?parentId=root"),
                                make_response(200, "not json"));
                }
            },
            "Error", 1, "Veeam GET "});
    CAPTURE(row.name);
    CandidateRig rig;
    rig.serve();
    row.edit(rig);

    const Caught thrown = caught_by([&] { rig.list(query(true, false, false)); });

    CHECK(thrown.kind == row.kind);
    CHECK_THAT(thrown.what, StartsWith(row.starts));
    CHECK(rig.rig.explores_opened() == row.explores);
    CHECK(rig.rig.stops(mail_x5().explore()) == row.explores);
    CHECK(rig.other_posts().empty());
}

TEST_CASE("list_candidates: an explore session that can't be stopped is an error, the pool "
          "dropped",
          "[veeam_m365][w2.6]")
{
    CandidateRig rig;
    keep_good_candidates(rig.tenant);
    rig.serve();
    const std::string explore = mail_x5().explore();
    rig.rig.veeam.on(HttpMethod::post, url(session_of(mail_x5()) + "/Stop"),
                     {make_response(500, R"({"message":"Internal error"})")});

    const Caught thrown = caught_by([&] { rig.list(query(true, true, false)); });

    CHECK(thrown.kind == "Error");
    CHECK(thrown.what == "veeam_m365: explore session " + explore +
                             " couldn't be stopped, and restore_sample's preflight would refuse "
                             "to run; stop it with docs/api/veeam-m365/08-sweep-sessions.ps1; "
                             "nothing was listed");
    CHECK_THAT(rig.rig.log(), ContainsSubstring("couldn't close explore session " + explore));
    CHECK(rig.rig.stops(sp_x1().explore()) == 1);
    CHECK(rig.other_posts().empty());
}

// ---- what is never a candidate -----------------------------------------------------------------

TEST_CASE("list_candidates: never a restore target, a canary or an item restore_sample can't "
          "find once",
          "[veeam_m365][w2.6]")
{
    struct Row {
        std::string name;
        std::function<void(Tenant&, connector::CandidateQuery&)> edit;
    };
    const auto new_mailbox = [](Tenant& t, const std::string& id, const std::string& email,
                                bool archive, bool is_public) {
        json entry = t.mailboxes.at(0);
        entry["id"] = id;
        entry["email"] = email;
        entry["isArchive"] = archive;
        entry["isPublic"] = is_public;
        t.mailboxes.push_back(entry);
        t.add_mail(id, kArchive, mail("m-" + id, "Kept out"));
    };
    const auto new_library = [](Tenant& t, const std::string& site, const std::string& list,
                                const std::string& url) {
        json entry = library(list, url);
        entry["id"] = site + list;
        json& listed = t.libraries[site];
        if (listed.is_null()) {
            listed = json::array();
        }
        listed.push_back(entry);
        Tenant::add(t.sp_documents, {site, site + list},
                    file(true, site + list + "00000000-0000-4000-8000-0000000000aa", "Kept out.pdf"));
    };
    const auto documents = [](Tenant& t, const std::string& list, json entry) {
        Tenant::add(t.sp_documents, {kSite, kSite + list}, std::move(entry));
    };
    const auto new_onedrive = [](Tenant& t, const std::string& id, const std::string& owner) {
        json entry = t.onedrives.at(0);
        entry["id"] = id;
        entry["url"] = "https://restoreprooflab-my.sharepoint.com/personal/" + owner +
                       "_restoreprooflab_onmicrosoft_com";
        t.onedrives.push_back(entry);
        Tenant::add(t.od_documents, {id, "root"},
                    file(false, "00000000-0000-4000-8000-0000000000bb", "Kept out.pdf"));
    };
    const auto new_user = [](Tenant& t, const std::string& id, const std::string& upn) {
        json entry = t.users.at(0);
        entry["id"] = id;
        entry["name"] = upn;
        t.users.push_back(entry);
    };
    const std::string doc = kSite + kDocumentsList + "00000000-0000-4000-8000-0000000000";
    const Row row = GENERATE_COPY(
        // Mail.
        Row{"the restoretest mailbox",
            [](Tenant& t, auto&) { t.add_mail(kRestoreTestMailbox, kArchive, mail("x", "Offsite")); }},
        Row{"the restoretest mailbox in another case",
            [](Tenant& t, auto&) {
                for (json& m : t.mailboxes) {
                    if (m.at("id") == kRestoreTestMailbox) {
                        m["email"] = "RESTORETEST@RestoreProofLab.onmicrosoft.com";
                    }
                }
                t.add_mail(kRestoreTestMailbox, kArchive, mail("x", "Offsite"));
            }},
        Row{"an archive mailbox",
            [=](Tenant& t, auto&) {
                new_mailbox(t, "0a0a0a0a-0000-4000-8000-000000000001",
                            "carol@RestoreProofLab.onmicrosoft.com", true, false);
            }},
        Row{"a public mailbox",
            [=](Tenant& t, auto&) {
                new_mailbox(t, "0a0a0a0a-0000-4000-8000-000000000002",
                            "carol@RestoreProofLab.onmicrosoft.com", false, true);
            }},
        Row{"the Discovery mailbox",
            [](Tenant& t, auto&) { t.add_mail(kDiscoveryMailbox, kArchive, mail("x", "Hold")); }},
        Row{"an address two primary mailboxes share",
            [=](Tenant& t, auto&) {
                new_mailbox(t, "0a0a0a0a-0000-4000-8000-000000000003",
                            "BOB@RestoreProofLab.onmicrosoft.com", false, false);
                t.add_mail(kBobMailbox, kArchive, mail("x", "Also kept out"));
            }},
        Row{"a canary's copy in Sent Items",
            [](Tenant& t, auto&) {
                t.add_mail(kHrachyaMailbox, kSentItems, mail("x", "RP-CANARY-0012"));
            }},
        Row{"a canary subject in another case",
            [](Tenant& t, auto&) { t.add_mail(kAliceMailbox, kArchive, mail("x", "rp-canary-0013")); }},
        Row{"a subject the manifest names, in another case",
            [](Tenant& t, connector::CandidateQuery& q) {
                q.exclude.subjects.push_back("Board minutes");
                t.add_mail(kAliceMailbox, kArchive, mail("x", "BOARD MINUTES"));
            }},
        Row{"an appointment",
            [](Tenant& t, auto&) {
                t.add_mail(kAliceMailbox, kArchive, mail("x", "Standup", "IPM.Appointment"));
            }},
        Row{"a subject a mail shares with an appointment",
            [](Tenant& t, auto&) {
                t.add_mail(kAliceMailbox, kArchive, mail("x", "Review"));
                t.add_mail(kAliceMailbox, kArchive, mail("y", "Review", "IPM.Appointment"));
            }},
        Row{"a mail without Veeam's received time",
            [](Tenant& t, auto&) {
                t.add_mail(kAliceMailbox, kArchive, mail("x", "Late", "IPM.Note", "yesterday"));
            }},
        Row{"a folder whose name a nested one shares",
            [](Tenant& t, auto&) {
                json nested = t.mail_folders.at(0);
                nested["id"] = "AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAnESTED";
                nested["name"] = "Archive";
                t.mail_folders.push_back(nested);
                t.add_mail(kAliceMailbox, kArchive, mail("x", "Old notes"));
            }},
        Row{"the Calendar",
            [](Tenant& t, auto&) { t.add_mail(kAliceMailbox, kCalendar, mail("x", "Lunch")); }},
        Row{"Deleted Items",
            [](Tenant& t, auto&) { t.add_mail(kAliceMailbox, kDeletedItems, mail("x", "Old")); }},
        // SharePoint.
        Row{"the canary library",
            [=](Tenant& t, auto&) {
                documents(t, kCanaryListId,
                          file(true, kSite + kCanaryListId + "00000000-0000-4000-8000-000000000001",
                               "Report.pdf"));
            }},
        Row{"the RestoreTarget library, renamed, by its drive ID",
            [=](Tenant& t, auto&) {
                for (json& l : t.libraries[kSite]) {
                    if (l.at("id").get<std::string>().ends_with(kRestoreTargetList)) {
                        l["url"] = "sites/RestoreTest/Renamed";
                    }
                }
                documents(t, kRestoreTargetList,
                          file(true,
                               kSite + kRestoreTargetList + "00000000-0000-4000-8000-000000000001",
                               "Restored.pdf"));
            }},
        Row{"a RestoreTarget library by its url",
            [=](Tenant& t, auto&) {
                new_library(t, kSite, "0b5e1d2c-0000-4000-8000-00000000c0de",
                            "sites/RestoreTest/RestoreTarget");
            }},
        Row{"SitePages",
            [=](Tenant& t, auto&) {
                documents(t, kSitePagesList,
                          file(true, kSite + kSitePagesList + "00000000-0000-4000-8000-000000000001",
                               "Home.aspx"));
            }},
        Row{"a library under _catalogs",
            [=](Tenant& t, auto&) {
                new_library(t, kSite, "0b5e1d2c-0000-4000-8000-00000000ca7a",
                            "sites/RestoreTest/_catalogs/masterpage");
            }},
        Row{"a personal site",
            [=](Tenant& t, auto&) {
                new_library(t, kPersonalSite, "0b5e1d2c-0000-4000-8000-0000000000de",
                            "personal/alice_restoreprooflab_onmicrosoft_com/Documents");
            }},
        Row{"a site on another host",
            [=](Tenant& t, auto&) {
                for (json& s : t.sites) {
                    if (s.at("id") == kAllCompanySite) {
                        s["url"] = "https://contoso.sharepoint.com/sites/allcompany";
                    }
                }
                new_library(t, kAllCompanySite, "0b5e1d2c-0000-4000-8000-0000000000de",
                            "sites/allcompany/Shared Documents");
            }},
        Row{"a file above the download cap",
            [=](Tenant& t, auto&) {
                documents(t, kDocumentsList, file(true, doc + "02", "Video.mp4", kCap + 1));
            }},
        Row{"a file of a negative size",
            [=](Tenant& t, auto&) {
                documents(t, kDocumentsList, file(true, doc + "02", "Negative.txt", -5));
            }},
        Row{"a file whose size isn't a number",
            [=](Tenant& t, auto&) {
                json entry = file(true, doc + "02", "Texty.txt");
                entry["sizeBytes"] = "1000";
                documents(t, kDocumentsList, entry);
            }},
        Row{"a site without a url, or not on https",
            [=](Tenant& t, auto&) {
                for (json& s : t.sites) {
                    if (s.at("id") == kAllCompanySite) {
                        s.erase("url");
                    }
                    if (s.at("id") == kPersonalSite) {
                        s["url"] = "http://restoreprooflab.sharepoint.com/sites/plain";
                    }
                }
                new_library(t, kAllCompanySite, "0b5e1d2c-0000-4000-8000-0000000000de",
                            "sites/allcompany/Shared Documents");
                new_library(t, kPersonalSite, "0b5e1d2c-0000-4000-8000-0000000000df",
                            "sites/plain/Shared Documents");
            }},
        Row{"a library without a url",
            [=](Tenant& t, auto&) {
                new_library(t, kSite, "0b5e1d2c-0000-4000-8000-00000000abcd", "unused");
                t.libraries[kSite].back().erase("url");
            }},
        Row{"a file without a size",
            [=](Tenant& t, auto&) {
                documents(t, kDocumentsList, file(true, doc + "02", "Unsized.txt", std::nullopt));
            }},
        Row{"a canary name in another case",
            [=](Tenant& t, auto&) {
                documents(t, kDocumentsList, file(true, doc + "02", "RP-CANARY-03.XLSX"));
            }},
        Row{"a name the manifest names, in another case",
            [=](Tenant& t, connector::CandidateQuery& q) {
                q.exclude.sharepoint_names.push_back("Plan.docx");
                documents(t, kDocumentsList, file(true, doc + "02", "plan.DOCX"));
            }},
        Row{"two files of one name",
            [=](Tenant& t, auto&) {
                documents(t, kDocumentsList, file(true, doc + "02", "Notes.txt"));
                documents(t, kDocumentsList, file(true, doc + "03", "Notes.txt"));
            }},
        Row{"a folder among the documents",
            [=](Tenant& t, auto&) {
                json entry = file(true, doc + "02", "Minutes");
                entry["isFolder"] = true;
                documents(t, kDocumentsList, entry);
            }},
        // OneDrive.
        Row{"alice's /RestoreTarget",
            [](Tenant& t, auto&) {
                Tenant::add(t.od_documents, {kAliceOneDrive, onedrive_folder("RestoreTarget")},
                            file(false, "00000000-0000-4000-8000-000000000021", "Restored.pdf"));
            }},
        Row{"alice's /RestoreTest",
            [](Tenant& t, auto&) {
                Tenant::add(t.od_documents, {kAliceOneDrive, onedrive_folder("RestoreTest")},
                            file(false, "00000000-0000-4000-8000-000000000021", "Draft.pdf"));
            }},
        Row{"a /restoretest and a /RESTORETARGET in another OneDrive",
            [](Tenant& t, auto&) {
                for (const std::string name : {"restoretest", "RESTORETARGET"}) {
                    const std::string id = "folder-" + name;
                    Tenant::add(t.od_folders, {kHrachyaOneDrive, "root"}, folder(id, name));
                    Tenant::add(t.od_documents, {kHrachyaOneDrive, id},
                                file(false, id + "-doc", "In " + name + ".pdf"));
                }
            }},
        Row{"a OneDrive no user owns",
            [=](Tenant& t, auto&) {
                new_onedrive(t,
                             "0d0d0d0d-0000-4000-8000-000000000001"
                             "0d0d0d0d-0000-4000-8000-000000000002",
                             "carol");
            }},
        Row{"a OneDrive two users own",
            [=](Tenant& t, auto&) {
                new_onedrive(t,
                             "0d0d0d0d-0000-4000-8000-000000000003"
                             "0d0d0d0d-0000-4000-8000-000000000004",
                             "dave");
                new_user(t, "user-dave-1", "dave@RestoreProofLab.onmicrosoft.com");
                new_user(t, "user-dave-2", "DAVE@restoreprooflab.onmicrosoft.com");
            }},
        Row{"a canary name in a OneDrive",
            [](Tenant& t, auto&) {
                Tenant::add(t.od_documents,
                            {kHrachyaOneDrive, "00000000-0000-4000-8000-0000000000f1"},
                            file(false, "00000000-0000-4000-8000-000000000031", "rp-canary-15.png"));
            }});
    CAPTURE(row.name);
    CandidateRig rig;
    keep_good_candidates(rig.tenant);
    connector::CandidateQuery q = query(true, true, true);
    row.edit(rig.tenant, q);
    rig.serve();

    const connector::CandidatePool pool = rig.list(q);

    CHECK(found(pool) == std::vector<std::string>{kKeptMail, kKeptOneDrive, kKeptSharePoint});
    CHECK(rig.other_posts().empty());
}

// ---- the draw -----------------------------------------------------------------------------------

namespace {

// Real-looking items in several containers and folders of each type.
void fill(Tenant& tenant)
{
    keep_good_candidates(tenant);
    tenant.add_mail(kAliceMailbox, kArchive, mail("a-1", "Travel plan"));
    tenant.add_mail(kAliceMailbox, kArchive, mail("a-2", "Expenses"));
    tenant.add_mail(kBobMailbox, kArchive, mail("b-1", "Invoice 1042"));
    tenant.add_mail(kHrachyaMailbox, kSentItems, mail("h-1", "Hiring"));
    tenant.add_mail(kAllCompanyMailbox, kConversationHistory, mail("c-1", "Town hall"));
    const std::string root = kSite + kDocumentsList;
    Tenant::add(tenant.sp_documents, {kSite, root},
                file(true, root + "00000000-0000-4000-8000-000000000002", "Roadmap.pptx"));
    Tenant::add(tenant.sp_folders, {kSite, root}, folder("folder-a", "A"));
    Tenant::add(tenant.sp_documents, {kSite, "folder-a"},
                file(true, root + "00000000-0000-4000-8000-000000000003", "Spec.pdf", kCap));
    Tenant::add(tenant.od_documents, {kAliceOneDrive, "root"},
                file(false, "00000000-0000-4000-8000-000000000041", "Notes.txt"));
    Tenant::add(tenant.od_documents, {kHrachyaOneDrive, "root"},
                file(false, "00000000-0000-4000-8000-000000000042", "CV.docx"));
}

connector::CandidateLimits limits(int wanted, int tried, int folders, int depth = 2,
                                  int calls = 20)
{
    connector::CandidateLimits out;
    out.containers_wanted = wanted;
    out.containers_tried = tried;
    out.folders_per_container = folders;
    out.walk_depth = depth;
    out.walk_calls = calls;
    return out;
}

} // namespace

TEST_CASE("list_candidates: the order Veeam lists in doesn't change the pool", "[veeam_m365][w2.6]")
{
    const connector::CandidateLimits defaults; // a draw, not everything
    CandidateRig first;
    fill(first.tenant);
    first.serve();
    CandidateRig reversed;
    fill(reversed.tenant);
    reversed.tenant.reverse();
    reversed.serve();

    const connector::CandidatePool a = first.list(query(true, true, true, defaults));
    const connector::CandidatePool b = reversed.list(query(true, true, true, defaults));

    CHECK(as_text(a) == as_text(b));
    CHECK_FALSE(a.mail.empty());
    // The same query again gives the same pool.
    CandidateRig again;
    fill(again.tenant);
    again.serve();
    CHECK(as_text(again.list(query(true, true, true, defaults))) == as_text(a));
}

TEST_CASE("list_candidates: without a candidate, containers_tried containers and "
          "folders_per_container folders each are looked into",
          "[veeam_m365][w2.6]")
{
    CandidateRig rig;
    rig.serve();

    const connector::CandidatePool pool = rig.list(query(true, false, false, limits(2, 3, 2)));

    CHECK(rig.gets_with("/folders?parentId=root") == 3);
    CHECK(rig.gets_with("/items?parentId=") == 6);
    CHECK(pool.mail_browse.containers_eligible == 4);
    CHECK(pool.mail_browse.containers_listed.size() == 3);
    CHECK(pool.mail_browse.folders_listed == 6);
    CHECK(pool.mail_browse.short_of_containers);
}

TEST_CASE("list_candidates: containers_wanted containers with a candidate end the draw",
          "[veeam_m365][w2.6]")
{
    CandidateRig rig;
    int n = 0;
    for (const std::string& mailbox :
         {kAliceMailbox, kBobMailbox, kHrachyaMailbox, kAllCompanyMailbox}) {
        for (const std::string& folder_id :
             {kArchive, kConversationHistory, kSentItems,
              std::string{"AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQwAAA"}}) {
            ++n;
            rig.tenant.add_mail(mailbox, folder_id,
                                mail("m-" + std::to_string(n), "Mail " + std::to_string(n)));
        }
    }
    rig.serve();

    const connector::CandidatePool pool = rig.list(query(true, false, false, limits(1, 8, 2)));

    CHECK(rig.gets_with("/folders?parentId=root") == 1);
    CHECK(rig.gets_with("/items?parentId=") == 2);
    CHECK(pool.mail.size() == 2);
    CHECK(pool.mail_browse.containers_listed.size() == 1);
    CHECK_FALSE(pool.mail_browse.short_of_containers);
}

TEST_CASE("list_candidates: containers_tried 0 looks into nothing", "[veeam_m365][w2.6]")
{
    CandidateRig rig;
    rig.serve();

    const connector::CandidatePool pool = rig.list(query(true, false, false, limits(2, 0, 3)));

    CHECK(rig.gets_with("/folders") == 0);
    CHECK(pool.mail_browse.containers_eligible == 4);
    CHECK(pool.mail_browse.containers_listed.empty());
    CHECK(pool.mail_browse.short_of_containers);
}

TEST_CASE("list_candidates: walk_depth and walk_calls bound the folder listings",
          "[veeam_m365][w2.6]")
{
    const auto [depth, calls, folder_gets, document_gets] =
        GENERATE(table<int, int, std::size_t, std::size_t>({
            {0, 20, 0, 1}, // the library root only
            {1, 20, 1, 3}, // its folders A and B, not listed
            {2, 20, 3, 4}, // A and B listed: A1 found, not listed
            {2, 2, 2, 4},  // two listings: the root and A
            {3, 20, 4, 5}, // A1 listed too: A2 found
        }));
    CAPTURE(depth, calls);
    CandidateRig rig;
    const std::string root = kSite + kDocumentsList;
    Tenant::add(rig.tenant.sp_folders, {kSite, root}, folder("folder-a", "A"));
    Tenant::add(rig.tenant.sp_folders, {kSite, root}, folder("folder-b", "B"));
    Tenant::add(rig.tenant.sp_folders, {kSite, "folder-a"}, folder("folder-a1", "A1"));
    Tenant::add(rig.tenant.sp_folders, {kSite, "folder-a1"}, folder("folder-a2", "A2"));
    rig.serve();

    const connector::CandidatePool pool =
        rig.list(query(false, true, false, limits(100, 100, 100, depth, calls)));

    CHECK(rig.gets_with(sites_base() + "/" + kSite + "/Folders") == folder_gets);
    CHECK(rig.gets_with(sites_base() + "/" + kSite + "/Documents") == document_gets);
    CHECK(pool.sharepoint_browse.containers_eligible == 4);
    CHECK(pool.sharepoint_browse.folders_listed == static_cast<int>(document_gets));
}

TEST_CASE("list_candidates: a type not asked for opens no explore session and lists nothing",
          "[veeam_m365][w2.6]")
{
    CandidateRig rig;
    fill(rig.tenant);
    rig.serve();

    const connector::CandidatePool pool = rig.list(query(true, false, false));

    CHECK(rig.rig.explores_opened() == 1);
    CHECK(rig.rig.stops(mail_x5().explore()) == 1);
    CHECK(rig.gets_with("/Organization/Sites") == 0);
    CHECK(rig.gets_with("/Organization/OneDrives") == 0);
    CHECK(rig.gets_with("/Users") == 0);
    CHECK(pool.sharepoint.empty());
    CHECK(pool.onedrive.empty());
}

TEST_CASE("list_candidates: real items outside the targets and canaries, as restore_sample will "
          "find them",
          "[veeam_m365][w2.6]")
{
    CandidateRig rig;
    fill(rig.tenant);
    rig.serve();

    const connector::CandidatePool pool = rig.list(query(true, true, true));

    const std::string alice = "alice@RestoreProofLab.onmicrosoft.com";
    const std::string sp = "sharepoint|" + kGraphSite + "|" + kDocumentsDrive + "|";
    CHECK(found(pool) ==
          std::vector<std::string>{
              "mail|HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com|Sent Items|Hiring|"
              "2026-09-26T08:15:02Z",
              "mail|alice@RestoreProofLab.onmicrosoft.com|Archive|Expenses|2026-09-26T08:15:02Z",
              "mail|alice@RestoreProofLab.onmicrosoft.com|Archive|Travel plan|2026-09-26T08:15:02Z",
              kKeptMail,
              "mail|allcompany@RestoreProofLab.onmicrosoft.com|Conversation History|Town hall|"
              "2026-09-26T08:15:02Z",
              "mail|bob@RestoreProofLab.onmicrosoft.com|Archive|Invoice 1042|2026-09-26T08:15:02Z",
              kKeptOneDrive,
              "onedrive|" + kHrachya + "|/|CV.docx|-1|1000",
              "onedrive|" + alice + "|/|Notes.txt|-1|1000",
              sp + "/A|Spec.pdf|" + kDocumentsList + "|-1|" + std::to_string(kCap),
              kKeptSharePoint,
              sp + "/|Roadmap.pptx|" + kDocumentsList + "|-1|1000",
          });
    CHECK(pool.mail_browse.containers_eligible == 4);
    CHECK(pool.mail_browse.containers_listed.size() == 4);
    CHECK(pool.mail_browse.folders_listed == 16);
    // 100 containers wanted, 4 gave candidates.
    CHECK(pool.mail_browse.short_of_containers);
    CHECK(pool.sharepoint_browse.containers_eligible == 4);
    CHECK(pool.onedrive_browse.containers_eligible == 2);
    std::vector<std::string> owners = pool.onedrive_browse.containers_listed;
    std::ranges::sort(owners);
    CHECK(owners == std::vector<std::string>{kHrachya, alice});
    // Every explore session stopped once; no POST but the sign-in, the
    // explore sessions and their Stop; nothing asked of Graph.
    CHECK(rig.rig.explores_opened() == 3);
    for (const Run& run : {mail_x5(), sp_x1(), od_x1()}) {
        CHECK(rig.rig.stops(run.explore()) == 1);
    }
    CHECK(rig.other_posts().empty());
    CHECK(rig.rig.lab.graph_gets() == 0);
}

// ---- list_candidates, then restore_sample -------------------------------------------------------

TEST_CASE("list_candidates then restore_sample: the lister's stopped explore session is never "
          "taken for a duplicate restore",
          "[veeam_m365][w2.6]")
{
    // Veeam lists explore sessions in /v8/RestoreSessions with the type of
    // the restore (restore-flow §12). The lister's Vex session, stopped
    // seconds before the restore POST, is ours, of the type and new since
    // the POST less 5 s: unless restore_sample knows it, the duplicate check
    // takes it for a second restore and the run gets no verdict.
    const bool answered = GENERATE(true, false);
    // The lister threw after its mail session: it is remembered all the same.
    const bool lister_threw = GENERATE(false, true);
    CAPTURE(answered, lister_threw);
    CandidateRig rig;
    keep_good_candidates(rig.tenant);
    rig.serve();
    const std::string lister = mail_x5().explore();
    if (lister_threw) {
        rig.rig.veeam.on(HttpMethod::get, url(paged(sites_base() + "?parentId=root")),
                         {make_response(503)});
        CHECK(caught_by([&] { rig.list(query(true, true, false)); }).kind == "TransientError");
    } else {
        rig.list(query(true, false, false));
    }
    REQUIRE(rig.rig.stops(lister) == 1);

    const Run run = mail_x1();
    rig.rig.serve(run);
    REQUIRE(run.explore() != lister);
    rig.rig.veeam.on(HttpMethod::get, run.duplicate_url(),
                     {fixture(run.file("sessions-after-post"), [&](json& b) {
                         json stopped = b["results"][2]; // a Stopped Vex session of rp-veeam
                         stopped["id"] = lister;
                         stopped["creationTime"] = "2026-09-28T21:27:25.0000000Z";
                         stopped["endTime"] = "2026-09-28T21:27:26.0000000Z";
                         b["results"].push_back(stopped);
                     })});
    if (!answered) {
        rig.rig.veeam.on(HttpMethod::post, url(run.post_path()),
                         [](const HttpRequest& request) -> HttpResponse {
                             throw rp::HttpError("POST " + request.url + ": connection dropped",
                                                 rp::TransportError::dropped, 0, 1);
                         });
    }

    const connector::RestoreResult result =
        rig.rig.restore(restore_spec({mail_x1_item()}));

    CHECK(result.status == connector::RestoreStatus::succeeded);
    CHECK(result.session_ids == std::vector<std::string>{run.restore()});
    CHECK(rig.rig.posts(run.post_path()) == 1);
    CHECK(rig.rig.stops(run.explore()) == 1);
    CHECK(rig.rig.stops(lister) == 1);
    CHECK_THAT(rig.rig.log(), !ContainsSubstring("didn't list restore session"));
}
