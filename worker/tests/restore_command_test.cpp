// W2.8 (#33): `rpworker restore` (rp::run_restore_command). The command's own
// logic runs over a fake IConnector: its arguments, the manifest, the restore
// point, the sample, the output and the exit codes. A few runs go through the
// real veeam_m365 connector from the default registry on W2.4's recorded
// answers (FakeHttpClient): Veeam unreachable, a guard refusal, and a whole
// restore. No network, and nothing live. The choices are the 2026-09-30 W2.8
// entry in docs/decisions.md.

#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "target_guard_lab.hpp"
#include "test_support.hpp"
#include "veeam_restore_lab.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/sample_rng.hpp>
#include <rp/secrets.hpp>
#include <rp/text_v1.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <ostream>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;
using Catch::Matchers::StartsWith;
using Args = std::vector<std::string_view>;
using namespace std::chrono_literals;

namespace {

namespace connector = rp::connector;
namespace sampling = rp::sampling;
using nlohmann::json;
using rp::test::graph_lab::kClient;
using rp::test::graph_lab::kTenant;
using rp::test::graph_lab::lab_values;

const std::string kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] | "
    "rpworker veeam list [--config <path>] [--record <dir>] | "
    "rpworker graph list [--hash] [--config <path>] [--record <dir>] | "
    "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
    "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] "
    "[--record <dir>]\n";

const std::string kOrgName = "RestoreProofLab.onmicrosoft.com";
// Veeam's restore point IDs are two GUIDs run together. Made up.
const std::string kNewestId =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e3" "5e1c0a24-0000-4000-8000-000000000930";
const std::string kOlderId =
    "c2f0f2e7-177f-48ac-992b-93a50cf702e3" "5e1c0a24-0000-4000-8000-000000000929";
const std::string kNewestTime = "2026-09-29T22:00:45.6603083Z";
const std::string kOlderTime = "2026-09-28T22:00:40Z";
const std::string kRunId = "run-0001";
const std::string kGeneratedRunId = "rp-20260930T100000Z-0123abcd";
const std::string kCarol = "carol@RestoreProofLab.onmicrosoft.com";

std::string seed_of(const std::string& run_id)
{
    return sampling::seed_hex(sampling::seed_from_run_id(run_id));
}

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

std::string lab_manifest_text()
{
    const std::filesystem::path path =
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json";
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

// The lab manifest with only the first `mail`, `sp` and `od` entries of each kind.
std::string trimmed_manifest(std::size_t mail, std::size_t sp, std::size_t od)
{
    json manifest = json::parse(lab_manifest_text());
    json kept = json::array();
    std::size_t m = 0;
    std::size_t s = 0;
    std::size_t o = 0;
    for (const json& entry : manifest.at("entries")) {
        const std::string kind = entry.at("kind").get<std::string>();
        if ((kind == "mail" && m++ < mail) || (kind == "sharepoint_file" && s++ < sp) ||
            (kind == "onedrive_file" && o++ < od)) {
            kept.push_back(entry);
        }
    }
    manifest["entries"] = kept;
    return manifest.dump(2);
}

// The lab's restore targets and tenant, Veeam at the recorded runs' URL.
json config_values()
{
    const rp::test::graph_lab::Lab_values& v = lab_values();
    return {
        {"cloud_url", "https://cloud.example.invalid"},
        {"veeam_url", rp::test::veeam_restore_lab::kBase},
        {"veeam_org_name", kOrgName},
        {"graph_tenant_id", kTenant},
        {"graph_client_id", kClient},
        {"test_mailbox", v.mailbox},
        {"test_site_id", v.site_id},
        {"test_library_id", v.library_id},
        {"test_onedrive_drive_id", v.onedrive_drive_id},
        {"test_onedrive_folder_id", v.folder_id},
    };
}

connector::RestorePoint point(const std::string& id, const std::string& time)
{
    connector::RestorePoint p;
    p.id = id;
    p.backup_time = time;
    p.has_mail = p.has_sharepoint = p.has_onedrive = true;
    return p;
}

struct SessionTimes {
    std::string started;
    std::string ended;
};

// A restore that went as planned: one session per type with items, each item
// restored.
connector::RestoreResult restored(const connector::RestoreSpec& spec)
{
    connector::RestoreResult result;
    result.status = spec.item_count() == 0 ? connector::RestoreStatus::not_run
                                           : connector::RestoreStatus::succeeded;
    const auto add = [&](connector::ItemKind kind, const std::vector<std::string>& names,
                         const SessionTimes& times) {
        if (names.empty()) {
            return;
        }
        const std::string id = "sess-" + std::string{connector::to_string(kind)};
        const int n = static_cast<int>(names.size());
        result.session_ids.push_back(id);
        result.sessions.push_back({id, kind, "Success", "", times.started, times.ended, n, n});
        for (const std::string& name : names) {
            result.items.push_back({kind, name, id, connector::ItemOutcome::restored, "", false});
        }
        result.items_sent += n;
        result.items_restored += n;
    };
    std::vector<std::string> mail;
    for (const connector::MailSelector& m : spec.mail) {
        mail.push_back(m.subject);
    }
    std::vector<std::string> sp;
    for (const connector::SharePointSelector& s : spec.sharepoint) {
        sp.push_back(s.name);
    }
    std::vector<std::string> od;
    for (const connector::OneDriveSelector& o : spec.onedrive) {
        od.push_back(o.name);
    }
    add(connector::ItemKind::mail, mail, {"2026-09-30T10:00:00Z", "2026-09-30T10:01:05Z"});
    add(connector::ItemKind::sharepoint, sp, {"2026-09-30T10:01:10Z", "2026-09-30T10:01:52.25Z"});
    add(connector::ItemKind::onedrive, od, {"2026-09-30T10:02:00Z", "2026-09-30T10:04:00.5Z"});
    return result;
}

// A connector that answers from what the test set. Called on the test's thread.
struct FakeConnector {
    std::vector<connector::RestorePoint> points{point(kNewestId, kNewestTime),
                                                point(kOlderId, kOlderTime)};
    connector::CandidatePool pool;
    std::function<void()> points_throw;
    std::function<void()> candidates_throw;
    std::function<void()> restore_throw;
    // Called first in restore_sample, on the test's thread.
    std::function<void()> at_restore;
    std::function<connector::RestoreResult(const connector::RestoreSpec&)> answer = restored;
    // What the command's stdout held when restore_sample was called.
    const std::ostringstream* out = nullptr;
    std::shared_ptr<spdlog::logger> logger;

    int points_calls = 0;
    int candidate_calls = 0;
    int restore_calls = 0;
    std::string client_ref;
    std::string out_at_restore;
    std::optional<connector::RestoreSpec> spec;
};

class ForwardingConnector final : public connector::IConnector {
public:
    explicit ForwardingConnector(FakeConnector& fake) : fake_(fake) {}

    connector::ConnectorInfo describe() const override { return {"fake", "1"}; }

    std::vector<connector::RestorePoint> list_restore_points(const std::string& client_ref) override
    {
        ++fake_.points_calls;
        fake_.client_ref = client_ref;
        if (fake_.points_throw) {
            fake_.points_throw();
        }
        return fake_.points;
    }

    connector::CandidatePool list_candidates(const connector::CandidateQuery&) override
    {
        ++fake_.candidate_calls;
        if (fake_.candidates_throw) {
            fake_.candidates_throw();
        }
        return fake_.pool;
    }

    connector::RestoreResult restore_sample(const connector::RestoreSpec& spec) override
    {
        ++fake_.restore_calls;
        if (fake_.at_restore) {
            fake_.at_restore();
        }
        fake_.out_at_restore = fake_.out ? fake_.out->str() : "";
        fake_.spec = spec;
        // The connector's own log line: never on stdout.
        if (fake_.logger) {
            fake_.logger->warn("fake connector: SENTINEL-LOG-LINE");
        }
        if (fake_.restore_throw) {
            fake_.restore_throw();
        }
        return fake_.answer(spec);
    }

private:
    FakeConnector& fake_;
};

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

// lab/seeder/catalog.py's MAIL_SENTENCES and MAIL_FOOTER: what a canary mail's
// body holds, so a restored copy can carry it (its text-v1 hash is the
// manifest's body_sha256; a test below holds them to it).
const std::vector<std::string> kMailSentences{
    "The lighthouse keeper counted forty-one ships before dawn.",
    "A copper kettle whistled twice in the empty kitchen.",
    "Seven orange kites drifted over the harbour wall.",
    "The night train to Krakow left three minutes early.",
    "A grey heron stood motionless in the shallow reeds.",
    "Twelve jars of plum jam lined the pantry shelf.",
    "The clockmaker replaced a spring worn thin by time.",
    "Fresh snow covered the bicycle left by the gate.",
    "A violinist tuned the strings beneath the old bridge.",
    "The library smelled of cedar, dust and rain.",
    "Nine paper boats raced down the gutter after the storm.",
    "The baker shaped two hundred rolls before sunrise.",
    "A red fox crossed the frozen field without a sound.",
    "The ferry horn echoed across the misty fjord.",
    "Four chess pieces were missing from the park table.",
    "The gardener planted tulips in a perfect spiral.",
    "A brass compass pointed stubbornly to the north-east.",
    "The museum guard hummed an old waltz at closing time.",
    "Silver rain tapped on the greenhouse roof all night.",
    "The cartographer inked a river that no longer exists.",
};
const std::string kMailFooter =
    "RestoreProof canary mail. Do not edit, move or delete this message.\r\n"
    "It is one of the 40 expected items in lab/seed-manifest.json.";

// The body of canary mail "RP-CANARY-00nn" as sent.
std::string canary_body(const std::string& subject)
{
    return kMailSentences.at(std::stoul(subject.substr(10)) - 1) + "\r\n\r\n" + kMailFooter;
}

// A file's bytes, or nullopt when it can't be read. No Catch2 assertion: the
// fakes' handlers call it.
std::optional<std::string> file_bytes(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>(file), {}};
}

// A message as Graph lists it in the test mailbox.
json graph_mail(const std::string& id, const std::string& subject, const std::string& address,
                const std::string& name, const std::string& sent, const std::string& received,
                const std::string& internet_message_id, const std::string& body)
{
    return {{"id", id},
            {"subject", subject},
            {"from", {{"emailAddress", {{"name", name}, {"address", address}}}}},
            {"sentDateTime", sent},
            {"receivedDateTime", received},
            {"createdDateTime", "2026-10-01T10:00:00Z"},
            {"internetMessageId", internet_message_id},
            {"body", {{"contentType", "text"}, {"content", body}}}};
}

// A file as Graph lists it in a file target.
json graph_file(const std::string& id, const std::string& name, std::size_t size,
                const std::string& ctag = "\"c:{restored},1\"")
{
    return {{"id", id},
            {"name", name},
            {"size", size},
            {"cTag", ctag},
            {"createdDateTime", "2026-09-24T22:14:43Z"},
            {"lastModifiedDateTime", "2026-10-01T10:00:00Z"},
            {"file", {{"mimeType", "application/octet-stream"}}}};
}

std::size_t kind_slot(connector::ItemKind kind)
{
    return static_cast<std::size_t>(kind);
}

// The restore targets as the check reads them through Graph (W3.2): the
// guards' recorded replies, and listings the test sets, before the restore and
// after it. After it, unless the test sets `after`, each target holds what it
// held before and a faithful copy of each item the restore was given
// (`mirror`): a canary as the manifest describes it (a mail with its body as
// sent, a file with lab/canary's bytes), a random mail as its candidate. No
// Catch2 assertions in the handlers.
struct TargetsLab {
    TargetsLab()
    {
        namespace gl = rp::test::graph_lab;
        manifest = json::parse(lab_manifest_text());
        graph.on(rp::HttpMethod::post, gl::kTokenUrl, {gl::token_response()});
        graph.on(rp::HttpMethod::get, gl::inbox_url(), {rp::test::load_fixture("graph", "mailbox-inbox-200")});
        graph.on(rp::HttpMethod::get, gl::drive_url(),
                 {rp::test::load_fixture("graph", "restoretarget-drive-200")});
        graph.on(rp::HttpMethod::get, gl::folder_url(),
                 {rp::test::load_fixture("graph", "onedrive-folder-200")});
        const auto serve = [this](const std::string& url, connector::ItemKind kind) {
            graph.on(rp::HttpMethod::get, url,
                     [this, kind](const rp::HttpRequest&) { return listing(kind); });
        };
        serve(gl::mail_list_url(false), connector::ItemKind::mail);
        serve(gl::mail_list_url(true), connector::ItemKind::mail);
        serve(gl::library_children_url(), connector::ItemKind::sharepoint);
        serve(gl::folder_children_url(), connector::ItemKind::onedrive);
        base_location[kind_slot(connector::ItemKind::sharepoint)] =
            gl::location_of(gl::sharepoint_location());
        base_location[kind_slot(connector::ItemKind::onedrive)] =
            gl::location_of(gl::onedrive_location());
        graph.on_path(rp::HttpMethod::get, "/v1.0/drives/*/items/*/content",
                      [this](const rp::HttpRequest& request) { return content(request); });
        for (const connector::ItemKind kind :
             {connector::ItemKind::sharepoint, connector::ItemKind::onedrive}) {
            download.on_path(rp::HttpMethod::get,
                             std::string{rp::request_path(base_location[kind_slot(kind)])} +
                                 "&rp-item=*",
                             [this](const rp::HttpRequest& request) { return bytes(request); });
        }
        // W3.4: the Cleaner's listings and deletes.
        for (const connector::ItemKind kind :
             {connector::ItemKind::mail, connector::ItemKind::sharepoint,
              connector::ItemKind::onedrive}) {
            graph.on(rp::HttpMethod::get, clean_listing_url(kind),
                     [this, kind](const rp::HttpRequest&) { return clean_listing(kind); });
        }
        graph.on_path(rp::HttpMethod::post, "/v1.0/users/*/messages/*/permanentDelete",
                      [this](const rp::HttpRequest& request) { return clean_delete(request); });
        graph.on_path(rp::HttpMethod::del, "/v1.0/drives/*/items/*",
                      [this](const rp::HttpRequest& request) { return clean_delete(request); });
    }

    // The listing the Cleaner asks for (W3.4).
    static std::string clean_listing_url(connector::ItemKind kind)
    {
        namespace gl = rp::test::graph_lab;
        const gl::Lab_values& v = gl::lab_values();
        const std::string files =
            "?$select=id,name,eTag,file,folder,package,remoteItem,root,parentReference&$top=200";
        switch (kind) {
        case connector::ItemKind::mail:
            return gl::kGraph + "/users/" + v.mailbox +
                   "/mailFolders/inbox/messages?$select=id&$top=100";
        case connector::ItemKind::sharepoint:
            return gl::kGraph + "/drives/" + v.library_id + "/root/children" + files;
        case connector::ItemKind::onedrive:
            break;
        }
        return gl::kGraph + "/drives/" + v.onedrive_drive_id + "/items/" + v.folder_id +
               "/children" + files;
    }

    // An item as the Cleaner lists it: a mail's ID, or a plain file in its
    // target's place with an eTag.
    static json clean_entry(connector::ItemKind kind, const std::string& id)
    {
        namespace gl = rp::test::graph_lab;
        const gl::Lab_values& v = gl::lab_values();
        if (kind == connector::ItemKind::mail) {
            return {{"id", id}};
        }
        const bool library = kind == connector::ItemKind::sharepoint;
        json parent = {{"driveId", library ? v.library_id : v.onedrive_drive_id}};
        if (library) {
            parent["path"] = "/drive/root:";
            parent["id"] = "01LIBRARYROOT";
        } else {
            parent["id"] = v.folder_id;
        }
        return {{"id", id},
                {"name", id + ".bin"},
                {"eTag", "\"{" + id + "},1\""},
                {"file", {{"mimeType", "application/octet-stream"}}},
                {"parentReference", parent}};
    }

    // What the Cleaner finds in a target (W3.4): the leftovers the test set,
    // then, once the restore ran, this run's copies (each item the after read
    // lists, as `listing` adds it), but what it deleted.
    rp::HttpResponse clean_listing(connector::ItemKind kind)
    {
        ++clean_listings[kind_slot(kind)];
        const bool after_restore = restored && restored();
        if (clean_fail) {
            if (std::optional<rp::HttpResponse> response = clean_fail(kind, after_restore)) {
                return *response;
            }
        }
        json value = json::array();
        for (const json& entry : leftovers[kind_slot(kind)]) {
            if (!deleted.contains(entry.value("id", ""))) {
                value.push_back(entry);
            }
        }
        if (after_restore) {
            const json added = after[kind_slot(kind)] ? *after[kind_slot(kind)] : mirror(kind);
            for (const json& item : added) {
                const std::string id = item.at("id").get<std::string>();
                if (!deleted.contains(id)) {
                    value.push_back(clean_entry(kind, id));
                }
            }
        }
        return rp::test::graph_lab::page_of(value);
    }

    // A permanentDelete or a file's DELETE: the ID is gone from then on.
    rp::HttpResponse clean_delete(const rp::HttpRequest& request)
    {
        std::string id = request.url.substr(0, request.url.find("/permanentDelete"));
        id = id.substr(id.rfind('/') + 1);
        if (at_delete) {
            at_delete();
        }
        if (delete_answer) {
            if (std::optional<rp::HttpResponse> response = delete_answer(id)) {
                return *response;
            }
        }
        deleted.insert(id);
        return rp::test::make_response(204);
    }

    // A listing page: what the target holds before the restore or after it.
    rp::HttpResponse listing(connector::ItemKind kind)
    {
        const bool after_restore = restored && restored();
        if (fail) {
            if (std::optional<rp::HttpResponse> response = fail(kind, after_restore)) {
                return *response;
            }
        }
        json value = before[kind_slot(kind)];
        if (after_restore) {
            const json added = after[kind_slot(kind)] ? *after[kind_slot(kind)] : mirror(kind);
            for (const json& item : added) {
                value.push_back(item);
            }
            for (const json& item : value) {
                if (item.contains("file") && !files.contains(item["id"].get<std::string>())) {
                    files[item["id"].get<std::string>()] =
                        std::string(item["size"].get<std::size_t>(), 'r');
                }
            }
        }
        return rp::test::graph_lab::page_of(value);
    }

    // The copies a faithful restore of the spec's items makes.
    json mirror(connector::ItemKind kind)
    {
        json out = json::array();
        if (!spec) {
            return out;
        }
        const std::optional<connector::RestoreSpec> s = spec();
        if (!s) {
            return out;
        }
        const auto entry = [&](const std::string& field, const std::string& value) -> const json* {
            for (const json& e : manifest.at("entries")) {
                if (e.value(field, "") == value) {
                    return &e;
                }
            }
            return nullptr;
        };
        const std::string prefix = "restored-" + std::string{connector::to_string(kind)} + "-";
        std::size_t n = 0;
        const auto add_file = [&](const std::string& name, std::int64_t size) {
            const std::string id = prefix + std::to_string(n++);
            const std::optional<std::string> canary =
                entry("name", name) ? file_bytes(std::filesystem::path{RP_SOURCE_DIR} / ".." /
                                                 "lab" / "canary" / name)
                                    : std::nullopt;
            std::string content = canary ? *canary
                                         : std::string(static_cast<std::size_t>(
                                                           std::max<std::int64_t>(size, 0)),
                                                       'r');
            out.push_back(graph_file(id, name, content.size()));
            files[id] = std::move(content);
        };
        switch (kind) {
        case connector::ItemKind::mail:
            for (const connector::MailSelector& m : s->mail) {
                const std::string id = prefix + std::to_string(n++);
                if (const json* e = entry("subject", m.subject)) {
                    out.push_back(graph_mail(id, m.subject, e->at("sender").get<std::string>(),
                                             "Hrachya Harutyunyan",
                                             e->at("sent_at").get<std::string>(),
                                             e->at("received_at").get<std::string>(),
                                             e->at("internet_message_id").get<std::string>(),
                                             canary_body(m.subject)));
                    continue;
                }
                const std::vector<connector::MailCandidate> candidates = candidates_of().mail;
                const auto candidate =
                    std::ranges::find_if(candidates, [&](const connector::MailCandidate& c) {
                        return c.selector == m;
                    });
                const bool known = candidate != candidates.end();
                const std::string name = known ? candidate->sender_name : "";
                const std::string sent = known ? candidate->sent_at : "";
                out.push_back(graph_mail(id, m.subject, "carol@RestoreProofLab.onmicrosoft.com",
                                         name, sent, m.received_at, "<" + id + "@lab.example>",
                                         "a random mail's body"));
            }
            break;
        case connector::ItemKind::sharepoint:
            for (const connector::SharePointSelector& f : s->sharepoint) {
                add_file(f.name, size_of(candidates_of().sharepoint, f));
            }
            break;
        case connector::ItemKind::onedrive:
            for (const connector::OneDriveSelector& f : s->onedrive) {
                add_file(f.name, size_of(candidates_of().onedrive, f));
            }
            break;
        }
        return out;
    }

    connector::CandidatePool candidates_of() const
    {
        return pool ? pool() : connector::CandidatePool{};
    }

    // The size the backup holds of a random file: its candidate's.
    template <typename Candidate, typename Selector>
    static std::int64_t size_of(const std::vector<Candidate>& candidates, const Selector& selector)
    {
        for (const Candidate& c : candidates) {
            if (c.selector == selector) {
                return c.size_bytes;
            }
        }
        return selector.size;
    }

    // A file's /content: a 302 to its download link.
    rp::HttpResponse content(const rp::HttpRequest& request)
    {
        const std::size_t start = request.url.find("/items/") + 7;
        const std::string id = request.url.substr(start, request.url.find("/content") - start);
        const bool onedrive =
            request.url.find(rp::test::graph_lab::lab_values().onedrive_drive_id) != std::string::npos;
        rp::HttpResponse response = rp::test::make_response(302);
        response.headers["Location"] =
            base_location[kind_slot(onedrive ? connector::ItemKind::onedrive
                                             : connector::ItemKind::sharepoint)] +
            "&rp-item=" + id;
        return response;
    }

    rp::HttpResponse bytes(const rp::HttpRequest& request)
    {
        if (download_throw) {
            download_throw();
        }
        const std::string id = request.url.substr(request.url.find("&rp-item=") + 9);
        const auto it = files.find(id);
        if (it == files.end()) {
            return rp::test::make_response(404);
        }
        return rp::test::make_response(200, it->second, "application/octet-stream");
    }

    // Whether the restore has run: the listings are the after ones from then.
    std::function<bool()> restored;
    // The spec the restore was given, and the random mails' candidates.
    std::function<std::optional<connector::RestoreSpec>()> spec;
    std::function<connector::CandidatePool()> pool;
    // Called first on each download: a test throws from it what no Graph
    // failure is (std::bad_alloc, a logic error).
    std::function<void()> download_throw;
    // A listing's answer in place of the page, when it returns one.
    std::function<std::optional<rp::HttpResponse>(connector::ItemKind, bool after)> fail;
    // What each target holds before the restore, and what the restore adds
    // (nullopt: the mirror).
    std::array<json, 3> before{json::array(), json::array(), json::array()};
    std::array<std::optional<json>, 3> after;
    // W3.4: what the Cleaner finds before the restore (clean_entry's shape),
    // a listing's answer in place of the page when `clean_fail` returns one,
    // a delete's in place of 204 when `delete_answer` does, and what was
    // deleted.
    std::array<json, 3> leftovers{json::array(), json::array(), json::array()};
    std::function<std::optional<rp::HttpResponse>(connector::ItemKind, bool after)> clean_fail;
    std::function<std::optional<rp::HttpResponse>(const std::string& id)> delete_answer;
    std::function<void()> at_delete; // called first on each delete
    std::set<std::string> deleted;
    std::array<int, 3> clean_listings{};
    json manifest;
    std::array<std::string, 3> base_location;
    std::map<std::string, std::string> files; // file ID -> its bytes
    rp::test::FakeHttpClient graph;
    rp::test::FakeHttpClient download;
};

// A temp folder with config.json and the lab's manifest beside it, the fake
// connector, Graph and the downloads on TargetsLab, secrets, a clock and a
// run ID the test chose.
struct Harness {
    explicit Harness(const json& config_edit = json::object())
    {
        json config = config_values();
        config.update(config_edit);
        config_path = dir.write("config.json", config.dump(2));
        manifest_path = dir.write("seed-manifest.json", lab_manifest_text());
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_stream);
        logger = std::make_shared<spdlog::logger>("restore_command_test", sink);
        logger->set_pattern("[%l] %v");
        logger->set_level(spdlog::level::trace);
        targets.restored = [this] { return fake.restore_calls > 0; };
        targets.spec = [this] { return fake.spec; };
        targets.pool = [this] { return fake.pool; };
        targets.at_delete = [this] { out_at_delete.push_back(fake.out ? fake.out->str() : ""); };
    }

    rp::RestoreCommandEnv env()
    {
        rp::RestoreCommandEnv env;
        env.default_config_path = [this] {
            ++default_path_calls;
            return config_path;
        };
        env.load_secrets = [this] {
            ++load_secrets_calls;
            return load_secrets();
        };
        env.make_connector = [this](const rp::Config& config, const rp::Secrets&,
                                    const connector::ConnectorOptions& options)
            -> std::unique_ptr<connector::IConnector> {
            ++make_connector_calls;
            made_for_org = config.veeam_org_name;
            fake.logger = options.logger;
            if (connector_throw) {
                connector_throw();
            }
            if (!give_connector) {
                return nullptr;
            }
            return std::make_unique<ForwardingConnector>(fake);
        };
        env.connector_options.logger = logger;
        // The certificate is checked at the time the lab's is valid.
        env.connector_options.wall_now = [] { return rp::test::graph_lab::kNow; };
        // The check's Graph (W3.2): never a wait between attempts.
        env.connector_options.make_graph_http =
            [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            ++graph_clients;
            return std::make_unique<rp::test::ForwardingHttpClient>(targets.graph);
        };
        env.connector_options.sleep = [](std::chrono::milliseconds) {};
        env.connector_options.jitter = [] { return 0.0; };
        env.make_download_http = [this]() -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(targets.download);
        };
        env.make_run_id = [this] {
            ++run_id_calls;
            return kGeneratedRunId;
        };
        env.now = [this] {
            const std::chrono::steady_clock::time_point t =
                std::chrono::steady_clock::time_point{} + clock;
            clock += tick;
            return t;
        };
        // W3.4: a fake run mutex, never the machine's.
        env.take_run_lock = [this]() -> std::unique_ptr<rp::RunLock> {
            ++lock_calls;
            lock_veeam_calls = fake.points_calls + fake.candidate_calls + fake.restore_calls;
            if (lock_throw) {
                lock_throw();
            }
            if (lock_taken) {
                return nullptr;
            }
            return std::make_unique<FakeLock>(lock_held);
        };
        env.on_cleanup = [this](const rp::RunCleanup& cleanup) {
            cleanups.push_back(cleanup);
            out_at_cleanup.push_back(fake.out ? fake.out->str() : "");
        };
        return env;
    }

    // Held while it lives; `held` says so.
    struct FakeLock final : rp::RunLock {
        explicit FakeLock(bool& held) : held_(held) { held_ = true; }
        ~FakeLock() override { held_ = false; }
        bool& held_;
    };

    // `args`, then --config <the temp config>.
    Run run(Args args)
    {
        const std::string path_arg = utf8(config_path);
        args.push_back("--config");
        args.push_back(path_arg);
        return run_raw(args);
    }

    // `args`, then --config, with stdout on `out`: the code and stderr.
    std::pair<int, std::string> run_to(Args args, std::ostream& out)
    {
        const std::string path_arg = utf8(config_path);
        args.push_back("--config");
        args.push_back(path_arg);
        std::ostringstream err;
        const int code = rp::run_restore_command(args, out, err, env());
        return {code, err.str()};
    }

    Run run_raw(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        fake.out = &out;
        const int code = rp::run_restore_command(args, out, err, env());
        fake.out = nullptr;
        return {code, out.str(), err.str()};
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    rp::test::TempDir dir;
    std::filesystem::path config_path;
    std::filesystem::path manifest_path;
    FakeConnector fake;
    std::function<rp::Secrets()> load_secrets = [] {
        return rp::Secrets{"rp-veeam", "Sentinel-Veeam-Password-9c2e",
                           rp::test::graph_lab::pfx_base64(),
                           std::string{rp::test::graph_lab::kPfxPassword}};
    };
    std::function<void()> connector_throw;
    bool give_connector = true;
    std::chrono::nanoseconds clock{0};
    std::chrono::nanoseconds tick = 123s;
    int default_path_calls = 0;
    int load_secrets_calls = 0;
    int make_connector_calls = 0;
    int run_id_calls = 0;
    int graph_clients = 0;
    // W3.4: the run mutex taken by another run, a failure taking it, whether
    // the command holds it, how often it asked, the Veeam calls made by then,
    // and each run's cleanup with stdout as it stood then.
    bool lock_taken = false;
    std::function<void()> lock_throw;
    bool lock_held = false;
    int lock_calls = 0;
    int lock_veeam_calls = -1;
    std::vector<rp::RunCleanup> cleanups;
    std::vector<std::string> out_at_cleanup;
    std::vector<std::string> out_at_delete; // stdout as it stood at each delete
    std::string made_for_org;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    TargetsLab targets;
};

connector::MailCandidate carol_mail(int n)
{
    return {{kCarol, "Archive", "real mail 0" + std::to_string(n),
             "2026-09-20T10:00:0" + std::to_string(n) + "Z"},
            "Carol Test",
            "2026-09-20T09:59:0" + std::to_string(n) + "Z"};
}

// W3.4: the clean before of targets the Cleaner finds empty, and the cleanup
// lines that end a run after its status line.
const std::string kCleanBefore = "cleanup before ok: deleted 0 mail, 0 sharepoint, 0 onedrive\n";
const std::string kNothingRestored = "cleanup after skipped: nothing was restored\n";
// The clean after of `--mail 2 --sp 1 --od 0`'s faithful copies.
const std::string kCleanAfterOfThree =
    "cleanup after ok: deleted 2 mail, 1 sharepoint, 0 onedrive\n";
std::string clean_after_line(int mail, int sharepoint, int onedrive)
{
    return "cleanup after ok: deleted " + std::to_string(mail) + " mail, " +
           std::to_string(sharepoint) + " sharepoint, " + std::to_string(onedrive) + " onedrive\n";
}
// The same when Veeam may still be writing.
const std::string kCleanAfterStillRunning =
    "cleanup after incomplete: deleted 2 mail, 1 sharepoint, 0 onedrive; the restore may "
    "still be running; the next run cleans before\n";

// The first two lines of `--run-id run-0001` on the newest point.
std::string expected_run_lines()
{
    return "restore point " + kNewestTime + "  " + kNewestId + "  (veeam_org_name " + kOrgName +
           ")\n"
           "run run-0001  seed " +
           seed_of(kRunId) + "\n";
}

// What `--run-id run-0001` on the newest point prints before the sample is
// chosen: the run, then the clean before (W3.4).
std::string expected_intro()
{
    return expected_run_lines() + kCleanBefore;
}

// The header of `--mail 2 --sp 1 --od 0 --run-id run-0001` on the newest point
// with one random mail candidate.
std::string expected_header()
{
    return expected_intro() +
           "canary cursor 0,0,0 -> 1,1,0\n"
           "  KIND        REQUESTED  CANARIES  RANDOM  NOTE\n"
           "  mail        2          1 of 1    1 of 1\n"
           "  sharepoint  1          1 of 1    0 of 0\n"
           "  onedrive    0          0 of 0    0 of 0\n"
           "restoring 3 item(s) ...\n";
}

// The check's part of that run's output when each item's copy is faithful:
// a mail's ms is its comparison (one tick of the harness's clock, 123 s), a
// file's its download and hash too (two).
const std::string kCheckOfThree =
    "\n"
    "  KIND        SOURCE  NAME              OUTCOME  FIELDS  DUP  MS\n"
    "  mail        canary  RP-CANARY-0001    match    -       -    123000\n"
    "  mail        random  real mail 01      match    -       -    123000\n"
    "  sharepoint  canary  rp-canary-01.pdf  match    -       -    246000\n"
    "\n"
    "check: 3 match, 0 mismatch, 0 missing, 0 error\n";

// That run's status line: every item verified.
const std::string kPassOfThree =
    "\n"
    "status pass: 3 of 3 item(s) verified: manifest 2, fields 1, metadata 0\n";

// Exactly one stdout line starts with "status ", the run's (W3.3), and only
// the clean after's line follows it (W3.4): a script reads the run's status
// from it, never the restore's own line, which starts with "restore ".
void check_one_status_line(const std::string& out)
{
    std::size_t status_lines = 0;
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < out.size()) {
        const std::size_t end = out.find('\n', start);
        const std::string line =
            out.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (line.starts_with("status ")) {
            ++status_lines;
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
        start = end == std::string::npos ? out.size() : end + 1;
    }
    CHECK(status_lines == 1);
    REQUIRE(lines.size() >= 2);
    CHECK(lines[lines.size() - 2].starts_with("status "));
    CHECK(lines.back().starts_with("cleanup after "));
}

} // namespace

// --- Failure paths: the command line -----------------------------------------------

TEST_CASE("restore: a command line it doesn't understand is a usage error, before the config",
          "[restore_command]")
{
    const std::string long_id(129, 'a');
    const Args args = GENERATE_COPY(values<Args>({
        {"list"},
        {"--mails", "1"},
        {"--mail"},
        {"--mail", "101"},
        {"--mail", "1000"},
        {"--mail", "0100"},
        {"--mail", "-1"},
        {"--mail", "+1"},
        {"--mail", ""},
        {"--mail", "1 "},
        {"--mail", "\xd9\xa3"}, // ARABIC-INDIC DIGIT THREE
        {"--mail", "1", "--mail", "2"},
        {"--sp", "x"},
        {"--sp", "1", "--sp", "1"},
        {"--od", "200"},
        {"--od", "1", "--od", "1"},
        {"--point", "nope!"},
        {"--point", ""},
        {"--point", "Latest!"},
        {"--point", long_id},
        {"--point", "latest", "--point", "latest"},
        {"--point", "c2f0f2e7-177f-48ac-992b-93a50cf702e3\n"},
        {"--run-id", "bad id"},
        {"--run-id", ""},
        {"--run-id", "a", "--run-id", "a"},
        {"--canary-cursor", "1,2"},
        {"--canary-cursor", "1,2,3,4"},
        {"--canary-cursor", "1, 2,3"},
        {"--canary-cursor", "-1,0,0"},
        {"--canary-cursor", "+1,0,0"},
        {"--canary-cursor", "1234567,0,0"},
        {"--canary-cursor", "0,0,4294967296"},
        {"--canary-cursor", "1,,2"},
        {"--canary-cursor", ",1,2"},
        {"--canary-cursor", "1,2,"},
        {"--canary-cursor", "a,b,c"},
        {"--canary-cursor", ""},
        {"--canary-cursor", "0,0,0", "--canary-cursor", "0,0,0"},
        {"--manifest"},
        {"--manifest", "a.json", "--manifest", "b.json"},
        {"--config"},
        {"--config", "a.json", "--config", "b.json"},
    }));
    CAPTURE(args);
    Harness lab;

    const Run run = lab.run_raw(args);

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == kUsage);
    CHECK(lab.default_path_calls == 0);
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: every sample size 0, from the flags or the config, is a usage error",
          "[restore_command]")
{
    const auto [config_edit, args] = GENERATE(table<json, Args>({
        {json::object(), Args{"--mail", "0", "--sp", "0", "--od", "000"}},
        {json{{"sample_mail", 0}, {"sample_sp", 0}, {"sample_od", 1}}, Args{"--od", "0"}},
    }));
    Harness lab(config_edit);

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == "usage error: every sample size is 0 (--mail, --sp, --od, or config's "
                     "sample_mail, sample_sp, sample_od): nothing to restore\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a canary cursor out of the manifest's range is a usage error, before the "
          "connector",
          "[restore_command]")
{
    const auto [cursor, message] = GENERATE(table<std::string, std::string>({
        {"20,0,0", "the mail cursor must be below 20, the manifest's mail canaries"},
        {"0,10,0", "the sharepoint cursor must be below 10, the manifest's sharepoint canaries"},
        {"0,0,999999", "the onedrive cursor must be below 10, the manifest's onedrive canaries"},
    }));
    Harness lab;

    const Run run = lab.run({"--canary-cursor", cursor});

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == "usage error: --canary-cursor: " + message + "\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore --record: a run the checks stop before Veeam makes no folder and prints no "
          "recording line",
          "[restore_command][record]")
{
    // 0: every size 0; 1: a cursor out of range; 2: a manifest that isn't there.
    const int stop = GENERATE(0, 1, 2);
    CAPTURE(stop);
    Harness lab;
    const std::filesystem::path rec = lab.dir.path() / "rec";
    const std::string rec_arg = utf8(rec);
    const std::string missing = utf8(lab.dir.path() / "missing.json");
    Args args{"--record", rec_arg};
    const std::vector<Args> stops{{"--mail", "0", "--sp", "0", "--od", "0"},
                                  {"--canary-cursor", "20,0,0"},
                                  {"--manifest", missing}};
    args.insert(args.end(), stops[stop].begin(), stops[stop].end());

    const Run run = lab.run(args);

    CHECK(run.exit_code == (stop == 2 ? rp::exit_code::config : rp::exit_code::usage));
    CHECK(run.out.empty());
    CHECK_FALSE(std::filesystem::exists(rec));
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a cursor for a type the manifest has no canaries of must be 0",
          "[restore_command]")
{
    Harness lab;
    lab.dir.write("seed-manifest.json", trimmed_manifest(2, 2, 0));

    const Run run = lab.run({"--canary-cursor", "0,0,1"});

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.err == "usage error: --canary-cursor: the onedrive cursor must be 0: the manifest "
                     "has no onedrive canaries\n");
    CHECK(lab.make_connector_calls == 0);
}

// --- Failure paths: config, secrets, manifest --------------------------------------

TEST_CASE("restore: a config that doesn't load is a config error", "[restore_command]")
{
    Harness lab;

    const Run run = lab.run_raw({"--config", "no-such-config.json"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "config error: no-such-config.json: cannot read config file\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: without --config it reads the default config", "[restore_command]")
{
    Harness lab;

    const Run run = lab.run_raw({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(lab.default_path_calls == 1);
}

TEST_CASE("restore: both Veeam secrets and the Graph certificate are needed, before any Veeam "
          "call",
          "[restore_command]")
{
    using Secret = std::optional<std::string>;
    const Secret pfx = rp::test::graph_lab::pfx_base64();
    const Secret pfx_password = std::string{rp::test::graph_lab::kPfxPassword};
    const auto [username, password, pfx_value, password_value, message] =
        GENERATE_COPY(table<Secret, Secret, Secret, Secret, std::string>({
            {std::nullopt, "p", pfx, pfx_password, "config error: RP_VEEAM_USERNAME is not set\n"},
            {std::string{}, "p", pfx, pfx_password, "config error: RP_VEEAM_USERNAME is not set\n"},
            {"u", std::nullopt, pfx, pfx_password, "config error: RP_VEEAM_PASSWORD is not set\n"},
            {"u", std::string{}, pfx, pfx_password, "config error: RP_VEEAM_PASSWORD is not set\n"},
            {"u", "p", std::nullopt, pfx_password,
             "config error: RP_GRAPH_CERT_PFX_BASE64 is not set\n"},
            {"u", "p", std::string{}, std::nullopt,
             "config error: RP_GRAPH_CERT_PFX_BASE64 is not set\n"},
            {"u", "p", pfx, std::nullopt,
             "config error: RP_GRAPH_CERT_PASSWORD is not set, and the PFX in "
             "RP_GRAPH_CERT_PFX_BASE64 needs a password\n"},
            {"u", "p", pfx, std::string{},
             "config error: RP_GRAPH_CERT_PASSWORD is not set, and the PFX in "
             "RP_GRAPH_CERT_PFX_BASE64 needs a password\n"},
        }));
    Harness lab;
    lab.load_secrets = [=] { return rp::Secrets{username, password, pfx_value, password_value}; };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == message);
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a Graph certificate that doesn't open or isn't valid is a config error, "
          "before any Veeam call",
          "[restore_command]")
{
    namespace gl = rp::test::graph_lab;
    const auto [what, message] = GENERATE(table<std::string, std::string>({
        {"wrong password",
         "config error: RP_GRAPH_CERT_PASSWORD does not open the PFX in RP_GRAPH_CERT_PFX_BASE64\n"},
        {"not Base64", "config error: RP_GRAPH_CERT_PFX_BASE64"},
        {"expired", "config error: "},
    }));
    CAPTURE(what);
    Harness lab;
    std::string pfx = gl::pfx_base64();
    std::string password = gl::kPfxPassword;
    if (what == "wrong password") {
        password = "Sentinel-Wrong-Password-7e21";
    } else if (what == "not Base64") {
        pfx = "not base64 at all!";
    } else {
        pfx = rp::test::to_base64(rp::test::make_pfx(
            rp::test::make_client_cert(
                "RestoreProof Worker",
                rp::test::ClientCertOptions{.not_before = -7200,
                                            .not_after = -3600,
                                            .now = std::chrono::system_clock::to_time_t(gl::kNow)}),
            gl::kPfxPassword));
    }
    lab.load_secrets = [=] { return rp::Secrets{"u", "p", pfx, password}; };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    if (what == "wrong password") {
        CHECK(run.err == message);
    } else {
        CHECK_THAT(run.err, StartsWith(message));
    }
    CHECK_THAT(run.err, !ContainsSubstring(password));
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a PFX without a password needs no RP_GRAPH_CERT_PASSWORD, as graph list",
          "[restore_command]")
{
    namespace gl = rp::test::graph_lab;
    using Secret = std::optional<std::string>;
    const Secret password = GENERATE(Secret{std::nullopt}, Secret{std::string{}});
    Harness lab;
    const std::string pfx = rp::test::to_base64(rp::test::make_pfx(
        rp::test::make_client_cert(
            "RestoreProof Worker",
            rp::test::ClientCertOptions{.now = std::chrono::system_clock::to_time_t(gl::kNow)}),
        ""));
    lab.load_secrets = [=] { return rp::Secrets{"u", "p", pfx, password}; };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(lab.fake.restore_calls == 1);
}

TEST_CASE("restore: secrets that fail to load are config errors; an unexpected one hides its "
          "message",
          "[restore_command]")
{
    const auto [kind, message] = GENERATE(table<std::string, std::string>({
        {"ConfigError", "config error: environment variable RP_VEEAM_PASSWORD is not valid Unicode\n"},
        {"other", "config error: unexpected failure\n"},
    }));
    Harness lab;
    lab.load_secrets = [kind = kind]() -> rp::Secrets {
        if (kind == "ConfigError") {
            throw rp::ConfigError("RP_VEEAM_PASSWORD",
                                  "environment variable RP_VEEAM_PASSWORD is not valid Unicode");
        }
        throw std::runtime_error("SENTINEL-SECRET-MESSAGE");
    };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == message);
}

TEST_CASE("restore: a manifest that doesn't load or isn't the tenant's is a config error, "
          "before the connector",
          "[restore_command]")
{
    const auto [what, message] = GENERATE(table<std::string, std::string>({
        {"missing", "cannot read the file"},
        {"not json", "config error: canary manifest: isn't valid JSON\n"},
        {"another tenant",
         "config error: canary manifest: /tenant_id: isn't the client's tenant (graph_tenant_id)\n"},
    }));
    CAPTURE(what);
    Harness lab;
    if (what == "missing") {
        std::filesystem::remove(lab.manifest_path);
    } else if (what == "not json") {
        lab.dir.write("seed-manifest.json", "{not json");
    } else {
        json manifest = json::parse(lab_manifest_text());
        manifest["tenant_id"] = "00000000-0000-4000-8000-000000000001";
        lab.dir.write("seed-manifest.json", manifest.dump());
    }

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    if (what == "missing") {
        CHECK(run.err == "config error: canary manifest: " + utf8(lab.manifest_path) +
                             ": cannot read the file\n");
    } else {
        CHECK(run.err == message);
    }
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: a manifest that names a restore target is a config error, before the "
          "connector",
          "[restore_command]")
{
    Harness lab;
    json manifest = json::parse(lab_manifest_text());
    // Entry 30 is the first OneDrive canary.
    REQUIRE(manifest["entries"][30]["kind"] == "onedrive_file");
    manifest["entries"][30]["location"]["folder_path"] = "/RestoreTarget";
    lab.dir.write("seed-manifest.json", manifest.dump());
    // Veeam unreachable: the manifest must be refused first, never exit 3.
    lab.fake.points_throw = [] { throw connector::TransientError("Veeam unreachable"); };

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "config error: canary manifest: /entries/30/location/folder_path: is in a "
                     "restore target (a RestoreTarget folder)\n");
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("restore: --manifest reads the file it names, not the one beside the config",
          "[restore_command]")
{
    Harness lab;
    std::filesystem::remove(lab.manifest_path);
    rp::test::TempDir other;
    const std::string path = utf8(other.write("pilot-manifest.json", trimmed_manifest(1, 1, 1)));

    const Run run = lab.run({"--manifest", path, "--run-id", kRunId, "--mail", "1", "--sp", "0",
                             "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    REQUIRE(lab.fake.spec);
    CHECK(lab.fake.spec->mail.size() == 1);
}

TEST_CASE("restore: a --manifest path that isn't UTF-8 is a config error", "[restore_command]")
{
    Harness lab;

    const Run run = lab.run({"--manifest", "\xff.json"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "config error: the --manifest path is not valid UTF-8\n");
    CHECK(lab.make_connector_calls == 0);
}

// --- Failure paths: the connector --------------------------------------------------

TEST_CASE("restore: each failure of the restore has its exit code; the header is already out, "
          "and items may be in the targets unless the error says not; the status says which, "
          "never what() says",
          "[restore_command]")
{
    // restore_sample may have sent a restore before it threw.
    const std::string started =
        "restore error: the restore had started: items may be in the restore targets (run "
        "run-0001)\n";
    struct Case {
        std::string name;
        std::function<void()> raise;
        int code;
        std::string err;
        std::string status; // after "status error "
    };
    const std::vector<Case> cases{
        {"AuthError", [] { throw connector::AuthError("Veeam refused the credentials"); },
         rp::exit_code::auth, "restore error: Veeam refused the credentials\n" + started,
         "backup_auth: the restore didn't complete: the backup product refused the credentials "
         "(backup_auth); items may be in the restore targets"},
        {"TransientError", [] { throw connector::TransientError("Veeam unreachable"); },
         rp::exit_code::transient, "restore error: Veeam unreachable\n" + started,
         "backup_transient: the restore didn't complete: the backup product couldn't be reached "
         "or asked to try later (backup_transient); items may be in the restore targets"},
        {"SafetyViolation",
         [] {
             throw connector::SafetyViolation(
                 "target guard: mail item 0 is sampled from a restore target");
         },
         rp::exit_code::service,
         "restore error: target guard: mail item 0 is sampled from a restore target\n" + started,
         "target_guard: the restore didn't complete: the restore-target guard refused "
         "(target_guard); items may be in the restore targets"},
        {"NotFoundError", [] { throw connector::NotFoundError("mail item 0 isn't in the restore point"); },
         rp::exit_code::service, "restore error: mail item 0 isn't in the restore point\n" + started,
         "not_in_backup: the restore didn't complete: the client or a sampled item isn't in the "
         "backup (not_in_backup); items may be in the restore targets"},
        {"NotImplementedError", [] { throw connector::NotImplementedError("not here"); },
         rp::exit_code::service, "restore error: not here\n" + started,
         "backup: the restore didn't complete: the backup product reported an error (backup); "
         "items may be in the restore targets"},
        // The connector's promise that no restore was sent: no note.
        {"nothing restored",
         [] {
             throw connector::SafetyViolation(
                 "target guard: mail item 0 is sampled from a restore target; nothing was "
                 "restored");
         },
         rp::exit_code::service,
         "restore error: target guard: mail item 0 is sampled from a restore target; nothing "
         "was restored\n",
         "target_guard: the restore didn't start: the restore-target guard refused "
         "(target_guard); nothing was restored"},
        // The guard's Graph errors are Graph's, never the backup product's.
        {"graph PermissionError",
         [] {
             throw rp::graph::PermissionError(
                 "Graph denied reading the RestoreTarget library; nothing was restored",
                 "Sites.Selected");
         },
         rp::exit_code::auth,
         "restore error: Graph denied reading the RestoreTarget library; nothing was restored\n",
         "graph_permission: the restore didn't start: Microsoft Graph refused a permission the "
         "Worker relies on (graph_permission); nothing was restored"},
        {"graph TransientError",
         [] { throw rp::graph::TransientError("Graph 429; nothing was restored", 429); },
         rp::exit_code::transient, "restore error: Graph 429; nothing was restored\n",
         "graph_transient: the restore didn't start: Microsoft Graph couldn't be reached or asked "
         "to try later (graph_transient); nothing was restored"},
        {"Error", [] { throw connector::Error("Veeam said no"); }, rp::exit_code::service,
         "restore error: Veeam said no\n" + started,
         "backup: the restore didn't complete: the backup product reported an error (backup); "
         "items may be in the restore targets"},
        {"ConfigError",
         [] {
             throw rp::ConfigError("RP_GRAPH_CERT_PFX_BASE64",
                                   "RP_GRAPH_CERT_PFX_BASE64 is not valid Base64");
         },
         rp::exit_code::config, "config error: RP_GRAPH_CERT_PFX_BASE64 is not valid Base64\n",
         "config: the restore didn't complete: the configuration isn't usable (config); items "
         "may be in the restore targets"},
        {"unexpected", [] { throw std::runtime_error("SENTINEL-UNSAFE-MESSAGE"); },
         rp::exit_code::config, "error: unexpected failure\n" + started,
         "internal: the restore didn't complete: an unexpected failure (internal); items may be "
         "in the restore targets"},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{11}))];
    CAPTURE(c.name);
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.restore_throw = c.raise;

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == c.code);
    CHECK(run.err == c.err);
    // W3.4: unless the error promised nothing was sent, the clean after runs
    // (here the fake had put its copies in), and says Veeam may still be
    // writing: the state it leaves isn't ok.
    const bool sent = !c.status.ends_with("nothing was restored");
    CHECK(run.out == expected_header() + "\nstatus error " + c.status + "\n" +
                         (sent ? kCleanAfterStillRunning : kNothingRestored));
    REQUIRE(lab.cleanups.size() == 1);
    CHECK(lab.cleanups[0].restore_sent == sent);
    CHECK(lab.cleanups[0].restore_may_still_run == sent);
    CHECK(lab.cleanups[0].after.has_value() == sent);
    CHECK(lab.cleanups[0].cleanup_ok() == !sent);
    CHECK(lab.targets.deleted.size() == (sent ? 3u : 0u));
    CHECK_THAT(run.out, !ContainsSubstring("SENTINEL-UNSAFE-MESSAGE"));
    CHECK(lab.fake.restore_calls == 1);
    // The before snapshot was read; nothing is read back after a restore that threw.
    CHECK(lab.targets.graph.count(rp::HttpMethod::get,
                                  rp::test::graph_lab::mail_list_url(false)) == 1);
    CHECK(lab.targets.graph.count(rp::HttpMethod::get,
                                  rp::test::graph_lab::mail_list_url(true)) == 0);
}

TEST_CASE("restore: a failure choosing the sample restores nothing; the run ID is already out",
          "[restore_command]")
{
    struct Case {
        std::string name;
        std::function<void()> raise;
        int code;
        std::string err;
        std::string status; // after "status error "
    };
    const std::vector<Case> cases{
        {"TransientError", [] { throw connector::TransientError("Veeam unreachable"); },
         rp::exit_code::transient, "restore error: Veeam unreachable\n",
         "backup_transient: the run stopped before the restore: the backup product couldn't be "
         "reached or asked to try later (backup_transient); nothing was restored"},
        {"AuthError", [] { throw connector::AuthError("Veeam refused the token"); },
         rp::exit_code::auth, "restore error: Veeam refused the token\n",
         "backup_auth: the run stopped before the restore: the backup product refused the "
         "credentials (backup_auth); nothing was restored"},
        {"Error", [] { throw connector::Error("veeam_m365: an unexpected answer"); },
         rp::exit_code::service, "restore error: veeam_m365: an unexpected answer\n",
         "backup: the run stopped before the restore: the backup product reported an error "
         "(backup); nothing was restored"},
        {"ManifestError",
         [] { throw sampling::ManifestError("canary manifest: /entries/3: a canary in a target"); },
         rp::exit_code::config, "config error: canary manifest: /entries/3: a canary in a target\n",
         "config: the run stopped before the restore: the configuration isn't usable (config); "
         "nothing was restored"},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{4}))];
    CAPTURE(c.name);
    Harness lab;
    lab.fake.candidates_throw = c.raise;

    // --mail 2: a random half, so choose_sample lists candidates.
    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == c.code);
    CHECK(run.err == c.err);
    CHECK(run.out == expected_intro() + "\nstatus error " + c.status + "\n" + kNothingRestored);
    CHECK(lab.fake.candidate_calls == 1);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a failure listing the restore points restores nothing and prints nothing",
          "[restore_command]")
{
    const auto [kind, code] = GENERATE(table<std::string, int>({
        {"NotFoundError", rp::exit_code::service},
        {"TransientError", rp::exit_code::transient},
        {"AuthError", rp::exit_code::auth},
    }));
    Harness lab;
    lab.fake.points_throw = [kind = kind] {
        if (kind == "NotFoundError") {
            throw connector::NotFoundError("no organisation RestoreProofLab.onmicrosoft.com");
        }
        if (kind == "TransientError") {
            throw connector::TransientError("Veeam unreachable");
        }
        throw connector::AuthError("refused");
    };

    const Run run = lab.run({});

    CHECK(run.exit_code == code);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, StartsWith("restore error: "));
    CHECK(lab.fake.restore_calls == 0);
    CHECK(lab.fake.client_ref == kOrgName);
}

TEST_CASE("restore: a connector the registry doesn't know, or none, fails before any call",
          "[restore_command]")
{
    Harness lab;
    SECTION("unknown")
    {
        lab.connector_throw = [] {
            throw connector::UnknownConnectorError("nope", {"veeam_m365"});
        };
        const Run run = lab.run({});
        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.err == "config error: unknown connector \"nope\" (known: veeam_m365)\n");
    }
    SECTION("none")
    {
        lab.give_connector = false;
        const Run run = lab.run({});
        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.err == "error: unexpected failure\n");
    }
    CHECK(lab.fake.points_calls == 0);
}

TEST_CASE("restore: an organisation without restore points is a service error",
          "[restore_command]")
{
    Harness lab;
    lab.fake.points.clear();

    const Run run = lab.run({});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.out.empty());
    CHECK(run.err == "restore error: no restore points for veeam_org_name\n");
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a restore point ID that isn't the organisation's is a service error",
          "[restore_command]")
{
    Harness lab;
    const std::string id = "c2f0f2e7-177f-48ac-992b-93a50cf702e3" "5e1c0a24-0000-4000-8000-000000000999";

    const Run run = lab.run({"--point", id});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.out.empty());
    CHECK(run.err == "restore error: restore point " + id + " not found for veeam_org_name\n");
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a run ID from the generator that check_run_id refuses restores nothing",
          "[restore_command]")
{
    Harness lab;
    rp::RestoreCommandEnv env = lab.env();
    env.make_run_id = [] { return std::string{"not a run id"}; };
    std::ostringstream out;
    std::ostringstream err;
    const std::string path_arg = utf8(lab.config_path);

    const int code = rp::run_restore_command(Args{"--config", path_arg}, out, err, env);

    CHECK(code == rp::exit_code::config);
    CHECK(err.str() == "error: unexpected failure\n");
    CHECK(out.str().empty());
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a stdout that takes nothing stops the command before the restore",
          "[restore_command]")
{
    Harness lab;
    rp::test::FailingStreamBuf failing;
    std::ostream out(&failing);
    std::ostringstream err;
    const std::string path_arg = utf8(lab.config_path);

    const int code = rp::run_restore_command(Args{"--config", path_arg}, out, err, lab.env());

    CHECK(code == rp::exit_code::config);
    CHECK(err.str() == "error: unexpected failure\n");
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
}

namespace {

// A stdout that takes `limit` bytes, then fails, and keeps what it held at
// each sync() (a flush).
class RecordingStreamBuf : public std::streambuf {
public:
    explicit RecordingStreamBuf(std::size_t limit = std::string::npos) : limit_(limit) {}

    std::string text;
    std::vector<std::string> synced;

protected:
    int_type overflow(int_type c) override
    {
        if (traits_type::eq_int_type(c, traits_type::eof())) {
            return traits_type::not_eof(c);
        }
        if (text.size() >= limit_) {
            return traits_type::eof();
        }
        text.push_back(traits_type::to_char_type(c));
        return c;
    }

    std::streamsize xsputn(const char* s, std::streamsize n) override
    {
        const std::size_t room = text.size() >= limit_ ? 0 : limit_ - text.size();
        const std::size_t take = std::min(room, static_cast<std::size_t>(n));
        text.append(s, take);
        return static_cast<std::streamsize>(take);
    }

    int sync() override
    {
        synced.push_back(text);
        return 0;
    }

private:
    std::size_t limit_;
};

} // namespace

TEST_CASE("restore: the run ID is flushed before the sample is chosen, the header before the "
          "restore",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    RecordingStreamBuf buffer;
    std::ostream out(&buffer);
    std::vector<std::string> synced_at_candidates;
    std::vector<std::string> synced_at_restore;
    lab.fake.candidates_throw = [&] { synced_at_candidates = buffer.synced; };
    lab.fake.at_restore = [&] { synced_at_restore = buffer.synced; };

    const auto [code, err] =
        lab.run_to({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"}, out);

    CHECK(code == rp::exit_code::ok);
    CHECK(err.empty());
    // The run line before the clean before (W3.4), its line before the sample.
    CHECK(synced_at_candidates == std::vector<std::string>{expected_run_lines(), expected_intro()});
    CHECK(synced_at_restore == std::vector<std::string>{expected_run_lines(), expected_intro(),
                                                         expected_header()});
    CHECK(lab.fake.restore_calls == 1);
}

TEST_CASE("restore: a stdout that fails after the restore ran says so, with the run ID, the "
          "restore's own account and the run's status; the check still runs and the status "
          "decides the exit code",
          "[restore_command]")
{
    const std::string lost = "error: writing the output failed after the restore ran (run "
                             "run-0001, restore ";
    // W3.4: the clean after still runs, its line on stderr with stdout lost.
    const std::string cleaned = kCleanAfterOfThree;
    const auto [status, infrastructure, sp_missing, code, err] =
        GENERATE_COPY(table<connector::RestoreStatus, bool, bool, int, std::string>({
            // A restore that passed but whose output was lost isn't a success.
            {connector::RestoreStatus::succeeded, false, false, rp::exit_code::config,
             lost + "succeeded: 3 of 3 item(s) restored); run status pass\n" + cleaned},
            // W3.3: a partial restore whose items all verify is a pass, so 1 here too.
            {connector::RestoreStatus::partial, false, false, rp::exit_code::config,
             lost + "partial: 3 of 3 item(s) restored); run status pass\n" + cleaned},
            {connector::RestoreStatus::partial, true, false, rp::exit_code::config,
             lost + "partial: 3 of 3 item(s) restored); run status pass\n"
                    "warning: backup_item: 1 verified item(s) the backup didn't report "
                    "restored\n" +
                 cleaned},
            // A missing item: the run's status is fail.
            {connector::RestoreStatus::partial, false, true, rp::exit_code::restore,
             lost + "partial: 3 of 3 item(s) restored); run status fail\n"
                    "cleanup after ok: deleted 2 mail, 0 sharepoint, 0 onedrive\n"},
            // Veeam said failed, every item matched: an error, with its code.
            {connector::RestoreStatus::failed, false, false, rp::exit_code::service,
             lost + "failed: 3 of 3 item(s) restored); run status error "
                    "restore_contradiction\n" +
                 cleaned},
        }));
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.answer = [status = status, infrastructure = infrastructure](
                          const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = status;
        if (infrastructure) {
            result.items.back().outcome = connector::ItemOutcome::failed;
            result.items.back().infrastructure = true;
        }
        return result;
    };
    if (sp_missing) {
        lab.targets.after[kind_slot(connector::ItemKind::sharepoint)] = json::array();
    }
    // The header fits; the tables don't.
    RecordingStreamBuf buffer(expected_header().size() + 5);
    std::ostream out(&buffer);

    const auto [exit_code, error] =
        lab.run_to({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"}, out);

    CHECK(exit_code == code);
    CHECK(error == err);
    CHECK(lab.fake.restore_calls == 1);
    CHECK(lab.targets.graph.count(rp::HttpMethod::get,
                                  rp::test::graph_lab::mail_list_url(true)) == 1);
    CHECK_THAT(buffer.text, StartsWith(expected_header()));
}

TEST_CASE("restore: a stdout that fails on the run ID stops the command before the sample",
          "[restore_command]")
{
    Harness lab;
    RecordingStreamBuf buffer(10);
    std::ostream out(&buffer);

    const auto [code, err] = lab.run_to({"--run-id", kRunId, "--mail", "2"}, out);

    CHECK(code == rp::exit_code::config);
    CHECK(err == "error: unexpected failure\n");
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: a stdout that fails on the sample's table stops the command before the "
          "restore",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    RecordingStreamBuf buffer(expected_intro().size() + 5);
    std::ostream out(&buffer);

    const auto [code, err] =
        lab.run_to({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"}, out);

    CHECK(code == rp::exit_code::config);
    // Its status line is lost too, so stderr says it.
    CHECK(err == "error: unexpected failure\n"
                 "error: writing the output failed (run run-0001); run status error internal\n" +
                     kNothingRestored);
    CHECK(lab.fake.candidate_calls == 1);
    CHECK(lab.fake.restore_calls == 0);
}

TEST_CASE("restore: an empty sample restores nothing and is status error empty_sample, exit 4, "
          "each shortfall a warning",
          "[restore_command]")
{
    const auto [manifest, sizes, cursor_line, warnings] =
        GENERATE(table<std::string, Args, std::string, std::string>({
            {trimmed_manifest(0, 1, 0), Args{"--mail", "2", "--sp", "0", "--od", "1"},
             "canary cursor 0,0,0 -> 0,0,0\n",
             "warning: shortfall: mail canary: 0 of 1\n"
             "warning: shortfall: mail random: 0 of 1\n"
             "warning: shortfall: onedrive canary: 0 of 1\n"},
            {trimmed_manifest(0, 1, 1), Args{"--mail", "1", "--sp", "0", "--od", "0"},
             "canary cursor 0,0,0 -> 0,0,0\n", "warning: shortfall: mail canary: 0 of 1\n"},
        }));
    Harness lab;
    lab.dir.write("seed-manifest.json", manifest);
    Args args = sizes;
    args.insert(args.end(), {"--run-id", kRunId});

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.err == warnings);
    CHECK_THAT(run.out, StartsWith(expected_intro() + cursor_line));
    CHECK_THAT(run.out, EndsWith("\n"
                                 "\n"
                                 "status error empty_sample: the sample is empty: nothing to "
                                 "restore\n" +
                                 kNothingRestored));
    CHECK_THAT(run.out, !ContainsSubstring("restoring"));
    CHECK(lab.fake.restore_calls == 0);
    // W3.4: the targets were cleaned before, as in every run with a run line.
    REQUIRE(lab.cleanups.size() == 1);
    CHECK(lab.cleanups[0].before.has_value());
    CHECK_FALSE(lab.cleanups[0].after.has_value());
    CHECK(lab.cleanups[0].cleanup_ok());
}

TEST_CASE("restore: a status line lost without a restore is said on stderr, with the run and "
          "its status",
          "[restore_command]")
{
    const Args args{"--mail", "1", "--sp", "0", "--od", "0", "--run-id", kRunId};
    const std::string status_line =
        "status error empty_sample: the sample is empty: nothing to restore\n";
    Harness whole;
    whole.dir.write("seed-manifest.json", trimmed_manifest(0, 1, 1));
    const Run full = whole.run(args);
    REQUIRE(full.out.ends_with(status_line + kNothingRestored));

    Harness lab;
    lab.dir.write("seed-manifest.json", trimmed_manifest(0, 1, 1));
    // Everything but the status line (and the cleanup line after it) fits.
    RecordingStreamBuf buffer(full.out.size() - status_line.size() - kNothingRestored.size() + 5);
    std::ostream out(&buffer);

    const auto [code, err] = lab.run_to(args, out);

    CHECK(code == rp::exit_code::service);
    // W3.4: the cleanup line goes to stderr too, after the status's warnings.
    CHECK(err == "error: writing the output failed (run run-0001); run status error "
                 "empty_sample\n"
                 "warning: shortfall: mail canary: 0 of 1\n" +
                     kNothingRestored);
    CHECK(lab.fake.restore_calls == 0);
}

// --- The restore ---------------------------------------------------------------------

TEST_CASE("restore: a succeeded restore prints the header, both tables and the status, exit 0",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(run.out ==
          expected_header() +
              "\n"
              "  KIND        SOURCE  NAME              OUTCOME   SESSION          ELAPSED  MESSAGE\n"
              "  mail        canary  RP-CANARY-0001    restored  sess-mail        0:01:05  -\n"
              "  mail        random  real mail 01      restored  sess-mail        0:01:05  -\n"
              "  sharepoint  canary  rp-canary-01.pdf  restored  sess-sharepoint  0:00:42  -\n"
              "\n"
              "  SESSION          KIND        RESULT   RESTORED  STARTED               ENDED                    ELAPSED\n"
              "  sess-mail        mail        Success  2 of 2    2026-09-30T10:00:00Z  2026-09-30T10:01:05Z     0:01:05\n"
              "  sess-sharepoint  sharepoint  Success  1 of 1    2026-09-30T10:01:10Z  2026-09-30T10:01:52.25Z  0:00:42\n"
              "\n"
              "restore succeeded: 3 of 3 item(s) restored in 0:02:03\n" +
              kCheckOfThree + kPassOfThree + kCleanAfterOfThree);
    check_one_status_line(run.out);
    // The header went out before the restore began.
    CHECK(lab.fake.out_at_restore == expected_header());
    // W3.4: the copies were deleted after the check read them and after the
    // status line was out, each one this run's.
    REQUIRE_FALSE(lab.out_at_delete.empty());
    CHECK_THAT(lab.out_at_delete.front(), EndsWith(kCheckOfThree + kPassOfThree));
    CHECK(lab.targets.deleted ==
          std::set<std::string>{"restored-mail-0", "restored-mail-1", "restored-sharepoint-0"});
    REQUIRE(lab.cleanups.size() == 1);
    const rp::RunCleanup& cleanup = lab.cleanups[0];
    CHECK(cleanup.cleanup_ok());
    CHECK(cleanup.restore_sent);
    CHECK_FALSE(cleanup.restore_may_still_run);
    REQUIRE(cleanup.before);
    REQUIRE(cleanup.after);
    CHECK(cleanup.after->mail.deleted == 2);
    CHECK(cleanup.after->sharepoint.deleted == 1);
    CHECK(lab.out_at_cleanup.front() == run.out);
    CHECK_FALSE(lab.lock_held); // released when the command returned
    CHECK(lab.lock_calls == 1);
    CHECK(lab.lock_veeam_calls == 0);
    REQUIRE(lab.fake.spec);
    const connector::RestoreSpec& spec = *lab.fake.spec;
    CHECK(spec.client_ref == kOrgName);
    CHECK(spec.restore_point.id == kNewestId);
    CHECK(spec.restore_point.backup_time == kNewestTime);
    CHECK(spec.targets.mailbox() == lab_values().mailbox);
    CHECK(spec.targets.library_id() == lab_values().library_id);
    REQUIRE(spec.mail.size() == 2);
    CHECK(spec.mail[0].subject == "RP-CANARY-0001");
    CHECK(spec.mail[1].subject == "real mail 01");
    REQUIRE(spec.sharepoint.size() == 1);
    CHECK(spec.onedrive.empty());
    CHECK(lab.run_id_calls == 0);
    CHECK(lab.fake.candidate_calls == 1);
    CHECK(lab.made_for_org == kOrgName);
}

TEST_CASE("restore: the backup's own status never decides the run's: a partial restore whose "
          "items all verify passes, a failed one whose items all match is a contradiction, a "
          "missing item fails",
          "[restore_command]")
{
    const auto [status, count, sp_missing, code, status_line] =
        GENERATE(table<connector::RestoreStatus, int, bool, int, std::string>({
            // W3.3: 0, not 5 as before.
            {connector::RestoreStatus::partial, 1, false, rp::exit_code::ok,
             "status pass: 2 of 2 item(s) verified: manifest 2, fields 0, metadata 0"},
            {connector::RestoreStatus::failed, 0, false, rp::exit_code::service,
             "status error restore_contradiction: the backup reported nothing restored, yet "
             "every item verified: the evidence contradicts itself"},
            {connector::RestoreStatus::partial, 1, true, rp::exit_code::restore,
             "status fail: 1 of 2 item(s) didn't verify (1 missing, 0 mismatch)"},
            {connector::RestoreStatus::failed, 0, true, rp::exit_code::restore,
             "status fail: 1 of 2 item(s) didn't verify (1 missing, 0 mismatch)"},
        }));
    Harness lab;
    lab.fake.answer = [status = status, count = count](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = status;
        result.items_restored = count;
        return result;
    };
    if (sp_missing) {
        lab.targets.after[kind_slot(connector::ItemKind::sharepoint)] = json::array();
    }

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == code);
    CHECK(run.err.empty());
    CHECK_THAT(run.out, ContainsSubstring("\nrestore " + std::string{connector::to_string(status)} +
                                          ": " + std::to_string(count) +
                                          " of 2 item(s) restored in 0:02:03\n"));
    CHECK_THAT(run.out, EndsWith("error\n\n" + status_line + "\n" +
                                 clean_after_line(1, sp_missing ? 0 : 1, 0)));
    check_one_status_line(run.out);
}

TEST_CASE("restore: a failed restore whose item only an earlier run's copy matches is error "
          "stale_target, exit 4, never a fail",
          "[restore_command]")
{
    // W3.3: 4, not 5 as before. Veeam leaves a mail already in the target as
    // it is (W3.2 live run), so this run's restore can't be told from one
    // that wrote nothing.
    Harness lab;
    lab.fake.answer = [](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = connector::RestoreStatus::failed;
        result.items_restored = 0;
        result.sessions[0].result = "Failed";
        result.sessions[0].items_restored = 0;
        result.items[0].outcome = connector::ItemOutcome::failed;
        return result;
    };
    lab.targets.before[kind_slot(connector::ItemKind::mail)] = json::array(
        {graph_mail("earlier-mail", "RP-CANARY-0001", "x@lab.example", "X", "2026-09-24T22:14:40Z",
                    "2026-09-24T22:14:43Z", "<earlier@lab.example>", "old")});
    lab.targets.after[kind_slot(connector::ItemKind::mail)] = json::array();

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.err == "warning: backup_session: mail session sess-mail: Failed\n"
                     "warning: stale_copies: 1 copies from earlier runs in the restore targets "
                     "were ignored (mail 1, sharepoint 0, onedrive 0)\n");
    CHECK(run.out.ends_with("check: 0 match, 0 mismatch, 0 missing, 1 error\n"
                            "\n"
                            "status error stale_target: 1 of 1 item(s) couldn't be checked "
                            "(stale_target 1)\n" +
                            clean_after_line(0, 0, 0)));
    check_one_status_line(run.out);
}

TEST_CASE("restore: an item the backup failed for an infrastructure reason is unchecked when the "
          "check doesn't find it, error 4; beside a missing item the run fails, 5; found, it "
          "verifies with a warning",
          "[restore_command]")
{
    const auto [status, outcomes, infrastructure, empty_targets, code, status_line, err] =
        GENERATE(table<connector::RestoreStatus, std::vector<connector::ItemOutcome>,
                       std::vector<bool>, std::vector<bool>, int, std::string, std::string>({
            // The backup blamed infrastructure, yet the copy is there and matches.
            {connector::RestoreStatus::partial,
             {connector::ItemOutcome::restored, connector::ItemOutcome::failed},
             {false, true},
             {false, false},
             rp::exit_code::ok,
             "status pass: 2 of 2 item(s) verified: manifest 2, fields 0, metadata 0",
             "warning: backup_item: 1 verified item(s) the backup didn't report restored\n"},
            {connector::RestoreStatus::partial,
             {connector::ItemOutcome::restored, connector::ItemOutcome::failed},
             {false, true},
             {false, true},
             rp::exit_code::service,
             "status error backup_infrastructure: 1 of 2 item(s) couldn't be checked "
             "(backup_infrastructure 1); 1 verified",
             ""},
            {connector::RestoreStatus::failed,
             {connector::ItemOutcome::unknown, connector::ItemOutcome::failed},
             {true, true},
             {true, true},
             rp::exit_code::service,
             "status error backup_infrastructure: 2 of 2 item(s) couldn't be checked "
             "(backup_infrastructure 2)",
             ""},
            // W3.3: an infrastructure item beside a missing one is 5, not 4 as before.
            {connector::RestoreStatus::failed,
             {connector::ItemOutcome::failed, connector::ItemOutcome::failed},
             {false, true},
             {true, true},
             rp::exit_code::restore,
             "status fail: 1 of 2 item(s) didn't verify (1 missing, 0 mismatch); 1 couldn't be "
             "checked",
             ""},
            // A restored item's flag counts for nothing.
            {connector::RestoreStatus::partial,
             {connector::ItemOutcome::restored, connector::ItemOutcome::failed},
             {true, false},
             {true, true},
             rp::exit_code::restore,
             "status fail: 2 of 2 item(s) didn't verify (2 missing, 0 mismatch)",
             ""},
        }));
    Harness lab;
    lab.fake.answer = [=](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = status;
        result.items_restored = 0;
        for (std::size_t i = 0; i < result.items.size(); ++i) {
            result.items[i].outcome = outcomes.at(i);
            result.items[i].infrastructure = infrastructure.at(i);
            result.items_restored += outcomes.at(i) == connector::ItemOutcome::restored ? 1 : 0;
        }
        return result;
    };
    for (std::size_t i = 0; i < empty_targets.size(); ++i) {
        if (empty_targets[i]) {
            lab.targets.after[i] = json::array();
        }
    }

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == code);
    CHECK(run.err == err);
    CHECK_THAT(run.out, ContainsSubstring("\n  KIND        SOURCE  NAME"));
    CHECK_THAT(run.out, ContainsSubstring("\nrestore " + std::string{connector::to_string(status)}));
    CHECK_THAT(run.out, EndsWith("error\n\n" + status_line + "\n" +
                                 clean_after_line(empty_targets[0] ? 0 : 1,
                                                  empty_targets[1] ? 0 : 1, 0)));
}

TEST_CASE("restore: a restore that returns not_run is exit 4, never 5", "[restore_command]")
{
    Harness lab;
    lab.fake.answer = [](const connector::RestoreSpec&) { return connector::RestoreResult{}; };
    // Nothing was sent, so nothing is in the mailbox.
    lab.targets.after[0] = json::array();

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.err.empty());
    // Without items or sessions, only the status line follows the header.
    const std::string last = "restoring 1 item(s) ...\n";
    CHECK(run.out.substr(run.out.find(last) + last.size()) ==
          "\nrestore not_run: 0 of 0 item(s) restored in 0:02:03\n"
          "\n"
          "  KIND  SOURCE  NAME            OUTCOME  FIELDS  DUP  MS\n"
          "  mail  canary  RP-CANARY-0001  missing  -       -    -\n"
          "\n"
          "check: 0 match, 0 mismatch, 1 missing, 0 error\n"
          "\n"
          "status error not_run: the restore didn't run: nothing was sent\n" +
              kNothingRestored);
    check_one_status_line(run.out);
}

TEST_CASE("restore: --point latest, or none, is the newest; an ID matches in any case",
          "[restore_command]")
{
    const auto [point_args, expected] = GENERATE(table<Args, std::string>({
        {Args{}, kNewestId},
        {Args{"--point", "latest"}, kNewestId},
        {Args{"--point", "LATEST"}, kNewestId},
        {Args{"--point", "Latest"}, kNewestId},
        {Args{"--point", "C2F0F2E7-177F-48AC-992B-93A50CF702E3" "5E1C0A24-0000-4000-8000-000000000929"},
         kOlderId},
    }));
    Harness lab;
    Args args = point_args;
    args.insert(args.end(), {"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::ok);
    REQUIRE(lab.fake.spec);
    CHECK(lab.fake.spec->restore_point.id == expected);
    CHECK_THAT(run.out, StartsWith("restore point " +
                                   (expected == kNewestId ? kNewestTime : kOlderTime) + "  " +
                                   expected + "  "));
}

TEST_CASE("restore: the edges of the command line are accepted", "[restore_command]")
{
    Harness lab;
    SECTION("--mail 100")
    {
        const Run run = lab.run({"--run-id", kRunId, "--mail", "100", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK_THAT(run.out, ContainsSubstring(
                                "  mail        100        20 of 50  0 of 50  canary and random "
                                "shortfall\n"));
    }
    SECTION("a 128-character --point ID passes the command line, and isn't found")
    {
        const std::string id(128, 'a');
        const Run run = lab.run({"--point", id});
        CHECK(run.exit_code == rp::exit_code::service);
        CHECK(run.err == "restore error: restore point " + id + " not found for veeam_org_name\n");
        CHECK(lab.fake.points_calls == 1);
    }
    SECTION("--canary-cursor 0,0,9: the last OneDrive canary")
    {
        const Run run = lab.run(
            {"--run-id", kRunId, "--canary-cursor", "0,0,9", "--mail", "0", "--sp", "0", "--od", "1"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK_THAT(run.out, ContainsSubstring("\ncanary cursor 0,0,9 -> 0,0,0\n"));
        REQUIRE(lab.fake.spec);
        CHECK(lab.fake.spec->onedrive.at(0).name == "rp-canary-20.png");
    }
    SECTION("a cursor of 0 for a type the manifest has no canaries of")
    {
        lab.dir.write("seed-manifest.json", trimmed_manifest(1, 1, 0));
        const Run run = lab.run(
            {"--run-id", kRunId, "--canary-cursor", "0,0,0", "--mail", "1", "--sp", "1", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        REQUIRE(lab.fake.spec);
        CHECK(lab.fake.spec->mail.size() == 1);
        CHECK(lab.fake.spec->sharepoint.size() == 1);
    }
    SECTION("a manifest tenant that differs from graph_tenant_id only in case")
    {
        json manifest = json::parse(lab_manifest_text());
        std::string tenant = kTenant;
        for (char& c : tenant) {
            c = static_cast<char>(c >= 'a' && c <= 'f' ? c - 'a' + 'A' : c);
        }
        REQUIRE(tenant != kTenant);
        manifest["tenant_id"] = tenant;
        lab.dir.write("seed-manifest.json", manifest.dump());
        const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK(run.err.empty());
    }
}

TEST_CASE("restore: an absent size is the config's; a flag overrides it", "[restore_command]")
{
    Harness lab(json{{"sample_mail", 3}, {"sample_sp", 0}, {"sample_od", 2}});

    SECTION("from the config")
    {
        const Run run = lab.run({"--run-id", kRunId});
        CHECK(run.exit_code == rp::exit_code::ok);
        REQUIRE(lab.fake.spec);
        // 3 mails: 2 canaries and 1 random (none in the pool); 2 OneDrive: 1 and 1.
        CHECK(lab.fake.spec->mail.size() == 2);
        CHECK(lab.fake.spec->sharepoint.empty());
        CHECK(lab.fake.spec->onedrive.size() == 1);
        CHECK_THAT(run.out,
                   ContainsSubstring("  mail        3          2 of 2    0 of 1  random shortfall\n"));
    }
    SECTION("from the flags")
    {
        const Run run = lab.run({"--run-id", kRunId, "--sp", "1", "--mail", "007"});
        CHECK(run.exit_code == rp::exit_code::ok);
        REQUIRE(lab.fake.spec);
        CHECK(lab.fake.spec->mail.size() == 4);
        CHECK(lab.fake.spec->sharepoint.size() == 1);
        CHECK(lab.fake.spec->onedrive.size() == 1);
    }
}

TEST_CASE("restore: without --run-id a run ID is made; with it, it is reused and its seed shown",
          "[restore_command]")
{
    Harness lab;
    SECTION("made")
    {
        const Run run = lab.run({"--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK(lab.run_id_calls == 1);
        CHECK_THAT(run.out, ContainsSubstring("\nrun " + kGeneratedRunId + "  seed " +
                                              seed_of(kGeneratedRunId) + "\n" + kCleanBefore +
                                              "canary cursor "));
    }
    SECTION("reused")
    {
        const Run run = lab.run({"--run-id", "repeat-me", "--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK(lab.run_id_calls == 0);
        CHECK_THAT(run.out, ContainsSubstring("\nrun repeat-me  seed " + seed_of("repeat-me") +
                                              "\n" + kCleanBefore + "canary cursor "));
    }
}

TEST_CASE("restore: the canary cursor picks where each rotation starts and the next is shown",
          "[restore_command]")
{
    Harness lab;

    const Run run = lab.run({"--run-id", kRunId, "--canary-cursor", "19,9,0", "--mail", "4",
                             "--sp", "1", "--od", "1"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, ContainsSubstring("\ncanary cursor 19,9,0 -> 1,0,1\n"));
    REQUIRE(lab.fake.spec);
    REQUIRE(lab.fake.spec->mail.size() == 2);
    CHECK(lab.fake.spec->mail[0].subject == "RP-CANARY-0020");
    CHECK(lab.fake.spec->mail[1].subject == "RP-CANARY-0001");
    CHECK(lab.fake.spec->sharepoint.at(0).name == "rp-canary-10.png");
}

TEST_CASE("restore: a shortfall is named in the header and warned of, and is still a pass",
          "[restore_command]")
{
    const auto [pool, sizes, row, warnings] = GENERATE(table<int, Args, std::string, std::string>({
        {0, Args{"--mail", "2"}, "  mail        2          1 of 1    0 of 1  random shortfall\n",
         "warning: shortfall: mail random: 0 of 1\n"},
        {2, Args{"--mail", "4"}, "  mail        4          1 of 2    2 of 2  canary shortfall\n",
         "warning: shortfall: mail canary: 1 of 2\n"},
        {0, Args{"--mail", "4"},
         "  mail        4          1 of 2    0 of 2  canary and random shortfall\n",
         "warning: shortfall: mail canary: 1 of 2\nwarning: shortfall: mail random: 0 of 2\n"},
    }));
    Harness lab;
    lab.dir.write("seed-manifest.json", trimmed_manifest(1, 1, 1));
    for (int n = 1; n <= pool; ++n) {
        lab.fake.pool.mail.push_back(carol_mail(n));
    }
    Args args = sizes;
    args.insert(args.end(), {"--run-id", kRunId, "--sp", "0", "--od", "0"});

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == warnings);
    CHECK_THAT(run.out, ContainsSubstring(row));
    CHECK_THAT(run.out, ContainsSubstring("\nrestore succeeded: "));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
}

TEST_CASE("restore: each item's row: its source, outcome, session time and message",
          "[restore_command]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.answer = [](const connector::RestoreSpec&) {
        using connector::ItemKind;
        using connector::ItemOutcome;
        connector::RestoreResult result;
        result.status = connector::RestoreStatus::partial;
        result.items_sent = 3;
        result.items_restored = 1;
        result.session_ids = {"s-ok", "s-bad", "s-back"};
        result.sessions = {
            {"s-ok", ItemKind::mail, "Warning", "", "2026-09-30T10:00:00Z", "2026-09-30T11:02:03Z", 2, 1},
            {"s-bad", ItemKind::sharepoint, "Failed", "", "2026-09-30T10:00:00Z", "not a time", 1, 0},
            {"s-back", ItemKind::onedrive, "Failed", "", "2026-09-30T10:00:01Z", "2026-09-30T10:00:00Z", 0, 0},
        };
        result.items = {
            {ItemKind::mail, "RP-CANARY-0001", "s-ok", ItemOutcome::restored, "", false},
            {ItemKind::mail, "real\tmail\n01", "s-ok", ItemOutcome::failed,
             "Veeam could not reach\r\nMicrosoft 365", true},
            {ItemKind::sharepoint, "rp-canary-01.pdf", "s-bad", ItemOutcome::unknown, "", false},
            {ItemKind::mail, "an extra", "s-gone", ItemOutcome::unknown, "", false},
            {ItemKind::onedrive, "", "", ItemOutcome::unknown, "", false},
        };
        return result;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    // Five items reported for three sent don't add up: error internal (W3.3, row 1).
    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err.empty());
    const std::string tables = run.out.substr(expected_header().size());
    CHECK(tables ==
          "\n"
          "  KIND        SOURCE  NAME              OUTCOME                  SESSION  ELAPSED  MESSAGE\n"
          "  mail        canary  RP-CANARY-0001    restored                 s-ok     1:02:03  -\n"
          "  mail        random  real mail 01      failed (infrastructure)  s-ok     1:02:03  Veeam could not reach  Microsoft 365\n"
          "  sharepoint  canary  rp-canary-01.pdf  unknown                  s-bad    -        -\n"
          "  mail        -       an extra          unknown                  s-gone   -        -\n"
          "  onedrive    -       -                 unknown                  -        -        -\n"
          "\n"
          "  SESSION  KIND        RESULT   RESTORED  STARTED               ENDED                 ELAPSED\n"
          "  s-ok     mail        Warning  1 of 2    2026-09-30T10:00:00Z  2026-09-30T11:02:03Z  1:02:03\n"
          "  s-bad    sharepoint  Failed   0 of 1    2026-09-30T10:00:00Z  not a time            -\n"
          "  s-back   onedrive    Failed   0 of 0    2026-09-30T10:00:01Z  2026-09-30T10:00:00Z  -\n"
          "\n"
          "restore partial: 1 of 3 item(s) restored in 0:02:03\n" +
          kCheckOfThree +
          "\n"
          "status error internal: the run's results don't add up: the restore reports 5 "
          "item(s), the expected set 3\n" +
          kCleanAfterOfThree);
}

TEST_CASE("restore: a session's elapsed time is cut to whole seconds and never overflows",
          "[restore_command]")
{
    using namespace std::chrono;
    // 1678 and 2261 are the ends of what a time in nanoseconds holds; the span
    // between them is more nanoseconds than a signed 64-bit count holds.
    const seconds span =
        (sys_days{year{2261} / 12 / 31} + 23h + 59min + 59s) - sys_days{year{1678} / 1 / 1};
    const std::string hours = std::to_string(span.count() / 3600);
    const auto [started, ended, elapsed] = GENERATE_COPY(table<std::string, std::string, std::string>({
        {"1678-01-01T00:00:00Z", "2261-12-31T23:59:59Z", hours + ":59:59"},
        {"1678-01-01T00:00:00.5Z", "2261-12-31T23:59:59.25Z", hours + ":59:58"},
        {"2261-12-31T23:59:59Z", "1678-01-01T00:00:00Z", "-"},
        {"2026-09-30T10:00:00.9Z", "2026-09-30T10:00:01.1Z", "0:00:00"},
        {"2026-09-30T10:00:00.1Z", "2026-09-30T10:00:01.9Z", "0:00:01"},
        {"2026-09-30T10:00:01.1Z", "2026-09-30T10:00:01Z", "-"},
        {"not a time", "2026-09-30T10:00:01Z", "-"},
        {"", "2026-09-30T10:00:01Z", "-"},
    }));
    CAPTURE(started, ended);
    Harness lab;
    lab.fake.answer = [=](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.sessions.at(0).started_at = started;
        result.sessions.at(0).ended_at = ended;
        return result;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    // The item's row and the session's row.
    CHECK_THAT(run.out, ContainsSubstring("sess-mail  " + elapsed + " "));
    CHECK_THAT(run.out, ContainsSubstring(ended + "  " + elapsed + "\n"));
}

TEST_CASE("restore: log lines go to the logger, never to stdout; without one the command's "
          "own is used",
          "[restore_command]")
{
    Harness lab;
    SECTION("the env's logger")
    {
        const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::ok);
        CHECK_THAT(run.out, !ContainsSubstring("SENTINEL-LOG-LINE"));
        CHECK_THAT(run.err, !ContainsSubstring("SENTINEL-LOG-LINE"));
        CHECK_THAT(lab.log(), ContainsSubstring("SENTINEL-LOG-LINE"));
        CHECK(lab.fake.logger == lab.logger);
    }
    SECTION("none given")
    {
        rp::RestoreCommandEnv env = lab.env();
        env.connector_options.logger = nullptr;
        std::ostringstream out;
        std::ostringstream err;
        const std::string path_arg = utf8(lab.config_path);
        lab.fake.out = &out;
        const int code = rp::run_restore_command(
            Args{"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0", "--config", path_arg},
            out, err, env);
        lab.fake.out = nullptr;
        CHECK(code == rp::exit_code::ok);
        REQUIRE(lab.fake.logger);
        CHECK(lab.fake.logger != lab.logger);
        CHECK(lab.fake.logger->name() == "rpworker");
        CHECK_THAT(out.str(), !ContainsSubstring("SENTINEL-LOG-LINE"));
    }
}

TEST_CASE("restore: elapsed times are H:MM:SS, cut to whole seconds", "[restore_command]")
{
    const auto [elapsed, text] = GENERATE(table<std::chrono::nanoseconds, std::string>({
        {0ns, "0:00:00"},
        {999ms, "0:00:00"},
        {59s + 999ms, "0:00:59"},
        {3723s, "1:02:03"},
        {100h + 1s, "100:00:01"},
        {-1ns, "-"},
    }));
    CHECK(rp::format_elapsed(elapsed) == text);
}

TEST_CASE("restore: a made run ID is rp-<UTC time>-<8 hex digits> and passes check_run_id",
          "[restore_command]")
{
    const std::string first = rp::make_run_id();
    const std::string second = rp::make_run_id();
    CHECK(std::regex_match(first, std::regex{"rp-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}"}));
    CHECK_NOTHROW(sampling::check_run_id(first));
    // 32 random bits each: equal only by a 1 in 2^32 chance within one second.
    CHECK(first != second);

    // The time is UTC now: read it back and compare it with the system clock
    // (UTC), which a local time would miss by the zone's offset.
    using namespace std::chrono;
    const auto number = [&](std::size_t at, std::size_t n) { return std::stoi(first.substr(at, n)); };
    const year_month_day date{year{number(3, 4)}, month{static_cast<unsigned>(number(7, 2))},
                              day{static_cast<unsigned>(number(9, 2))}};
    REQUIRE(date.ok());
    const sys_seconds made =
        sys_days{date} + hours{number(12, 2)} + minutes{number(14, 2)} + seconds{number(16, 2)};
    const auto off = system_clock::now() - made;
    CHECK(off >= -1min);
    CHECK(off <= 1min);
}

TEST_CASE("restore: the default environment reads the real config and secrets, with a stderr "
          "logger",
          "[restore_command]")
{
    const rp::RestoreCommandEnv env = rp::default_restore_command_env();
    CHECK(env.default_config_path);
    CHECK(env.load_secrets);
    CHECK_FALSE(env.make_connector); // the default registry's veeam_m365
    CHECK_FALSE(env.make_run_id);    // rp::make_run_id
    CHECK_FALSE(env.now);            // steady_clock::now
    REQUIRE(env.connector_options.logger);
    CHECK(env.connector_options.logger->name() == "rpworker");
}

// --- The check (W3.2) ----------------------------------------------------------------

TEST_CASE("restore: the test helper's canary bodies are the ones the manifest hashed",
          "[restore_command][checker]")
{
    std::size_t mails = 0;
    const json manifest = json::parse(lab_manifest_text());
    for (const json& entry : manifest.at("entries")) {
        if (entry.at("kind").get<std::string>() == "mail") {
            ++mails;
            const std::string subject = entry.at("subject").get<std::string>();
            CAPTURE(subject);
            CHECK(rp::text_v1_sha256(canary_body(subject)) == entry.at("body_sha256").get<std::string>());
        }
    }
    CHECK(mails == kMailSentences.size());
}

TEST_CASE("restore: a failure reading the targets before the restore stops the run, nothing "
          "restored, status error with Graph's code",
          "[restore_command][checker]")
{
    namespace gl = rp::test::graph_lab;
    struct Case {
        std::string name;
        connector::ItemKind kind;
        std::string fixture; // the listing's answer; empty: the guard refuses instead
        int code;
        std::string error_code;
    };
    const std::vector<Case> cases{
        {"mail: a token Graph refuses", connector::ItemKind::mail, "api-invalid-token-401",
         rp::exit_code::auth, "graph_auth"},
        {"sharepoint: no permission", connector::ItemKind::sharepoint, "site-403-accessdenied",
         rp::exit_code::auth, "graph_permission"},
        {"onedrive: Graph unavailable", connector::ItemKind::onedrive, "messages-503-unavailable",
         rp::exit_code::transient, "graph_transient"},
        {"sharepoint: a drive Graph doesn't know", connector::ItemKind::sharepoint,
         "drive-404-itemnotfound", rp::exit_code::service, "graph"},
        {"sharepoint: not the RestoreTarget library", connector::ItemKind::sharepoint, "",
         rp::exit_code::service, "target_guard"},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{5}))];
    CAPTURE(c.name);
    Harness lab;
    if (c.fixture.empty()) {
        // The clean before (W3.4) sees the library as recorded; the snapshot
        // after it, another one.
        json drive = rp::test::load_fixture_json("graph", "restoretarget-drive-200");
        drive["body"]["name"] = "Dokumenty";
        lab.targets.graph.on(rp::HttpMethod::get, gl::drive_url(),
                             {rp::test::load_fixture("graph", "restoretarget-drive-200"),
                              rp::test::to_response(drive)});
    } else {
        const rp::HttpResponse answer = rp::test::load_fixture("graph", c.fixture);
        lab.targets.fail = [kind = c.kind, answer](connector::ItemKind k,
                                                   bool) -> std::optional<rp::HttpResponse> {
            return k == kind ? std::optional{answer} : std::nullopt;
        };
    }

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "1", "--od", "1"});

    CHECK(run.exit_code == c.code);
    CHECK_THAT(run.err, StartsWith("check error: "));
    CHECK(run.err.ends_with("; nothing was restored\n"));
    CHECK(std::ranges::count(run.err, '\n') == 1);
    CHECK_THAT(run.out, ContainsSubstring("restoring 3 item(s) ...\n"
                                          "\n"
                                          "status error " +
                                          c.error_code +
                                          ": the run stopped before the restore: "));
    CHECK_THAT(run.out, EndsWith(" (" + c.error_code + "); nothing was restored\n" +
                                 kNothingRestored));
    CHECK(lab.fake.restore_calls == 0);
    CHECK(lab.graph_clients == 1);
}

TEST_CASE("restore: the before snapshot reads only the targets the sample has items for",
          "[restore_command][checker]")
{
    namespace gl = rp::test::graph_lab;
    Harness lab;

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(lab.targets.graph.count(rp::HttpMethod::get, gl::mail_list_url(false)) == 1);
    CHECK(lab.targets.graph.count(rp::HttpMethod::get, gl::mail_list_url(true)) == 1);
    CHECK(lab.targets.graph.count(rp::HttpMethod::get, gl::library_children_url()) == 0);
    CHECK(lab.targets.graph.count(rp::HttpMethod::get, gl::folder_children_url()) == 0);
}

TEST_CASE("restore: every type checked: canaries and random items of each, the Office ones by "
          "office-v1, exit 0",
          "[restore_command][checker]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.pool.sharepoint = {
        {{lab_values().site_id, "b!madeUpSourceLibraryDrive", "/Projects", "report.pdf",
          "0b5e1d2c-0000-4000-8000-00000000c0de"},
         1234}};
    lab.fake.pool.onedrive = {{{kCarol, "/Projects", "deck.pptx"}, 9000}};

    // Cursor 0,1,1: rp-canary-02.docx and rp-canary-12.docx, both office-v1.
    const Run run = lab.run({"--run-id", kRunId, "--canary-cursor", "0,1,1", "--mail", "2",
                             "--sp", "2", "--od", "2"});

    INFO(run.out);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    // deck.pptx, a random Office file, has no size or hash to compare: listed,
    // never downloaded, so its read took one clock step, not two.
    CHECK_THAT(run.out,
               ContainsSubstring(
                   "\n"
                   "  KIND        SOURCE  NAME               OUTCOME  FIELDS  DUP  MS\n"
                   "  mail        canary  RP-CANARY-0001     match    -       -    123000\n"
                   "  mail        random  real mail 01       match    -       -    123000\n"
                   "  sharepoint  canary  rp-canary-02.docx  match    -       -    246000\n"
                   "  sharepoint  random  report.pdf         match    -       -    246000\n"
                   "  onedrive    canary  rp-canary-12.docx  match    -       -    246000\n"
                   "  onedrive    random  deck.pptx          match    -       -    123000\n"
                   "\n"
                   "check: 6 match, 0 mismatch, 0 missing, 0 error\n"
                   "\n"
                   "status pass: 6 of 6 item(s) verified: manifest 3, fields 1, metadata 2\n"));
}

TEST_CASE("restore: an item missing or not matching is status fail, exit 5",
          "[restore_command][checker]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    SECTION("missing")
    {
        lab.targets.after[kind_slot(connector::ItemKind::sharepoint)] = json::array();
        const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::restore);
        CHECK(run.err.empty());
        CHECK_THAT(run.out, ContainsSubstring(
                                "  sharepoint  canary  rp-canary-01.pdf  missing  -       -    -\n"));
        CHECK(run.out.ends_with("check: 2 match, 0 mismatch, 1 missing, 0 error\n"
                                "\n"
                                "status fail: 1 of 3 item(s) didn't verify (1 missing, 0 "
                                "mismatch)\n" +
                                clean_after_line(2, 0, 0)));
    }
    SECTION("a mismatch: a body and a time that differ")
    {
        lab.targets.after[kind_slot(connector::ItemKind::mail)] = json::array({graph_mail(
            "restored-1", "RP-CANARY-0001", "HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com",
            "Hrachya", "2026-09-24T22:14:40Z", "2026-09-24T22:20:00Z", "<x@lab.example>",
            "another body")});
        const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});
        CHECK(run.exit_code == rp::exit_code::restore);
        CHECK(run.err.empty());
        CHECK_THAT(run.out,
                   ContainsSubstring("  mail  canary  RP-CANARY-0001  mismatch  "
                                     "received_at,internet_message_id,sha256  -    123000\n"));
        CHECK(run.out.ends_with("\nstatus fail: 1 of 1 item(s) didn't verify (0 missing, 1 "
                                "mismatch)\n" +
                                clean_after_line(1, 0, 0)));
    }
}

TEST_CASE("restore: a target that can't be read back makes its items unchecked, status error "
          "with its code (graph_permission: exit 2); the others are still checked",
          "[restore_command][checker]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const rp::HttpResponse denied = rp::test::load_fixture("graph", "site-403-accessdenied");
    lab.targets.fail = [denied](connector::ItemKind kind,
                                bool after) -> std::optional<rp::HttpResponse> {
        return after && kind == connector::ItemKind::sharepoint ? std::optional{denied}
                                                                 : std::nullopt;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::auth);
    CHECK_THAT(run.err, StartsWith("check error: "));
    CHECK(std::ranges::count(run.err, '\n') == 1);
    CHECK_THAT(run.out,
               ContainsSubstring(
                   "  mail        canary  RP-CANARY-0001    match    -                 -    123000\n"
                   "  mail        random  real mail 01      match    -                 -    123000\n"
                   "  sharepoint  canary  rp-canary-01.pdf  error    graph_permission  -    -\n"));
    CHECK(run.out.ends_with("check: 2 match, 0 mismatch, 0 missing, 1 error\n"
                            "\n"
                            "status error graph_permission: 1 of 3 item(s) couldn't be checked "
                            "(graph_permission 1); 2 verified\n" +
                            kCleanAfterOfThree));
}

TEST_CASE("restore: copies earlier runs left are ignored and counted; a file only an earlier run "
          "left is an error",
          "[restore_command][checker]")
{
    Harness lab;
    // An earlier run's mail with this run's subject, and the canary file under
    // its own name with a cTag the restore doesn't move.
    lab.targets.before[kind_slot(connector::ItemKind::mail)] = json::array(
        {graph_mail("earlier-mail", "RP-CANARY-0001", "x@lab.example", "X", "2026-09-24T22:14:40Z",
                    "2026-09-24T22:14:43Z", "<earlier@lab.example>", "old")});
    lab.targets.before[kind_slot(connector::ItemKind::sharepoint)] =
        json::array({graph_file("earlier-file", "RP-CANARY-01.PDF", 925, "\"c:{earlier},1\"")});
    lab.targets.after[kind_slot(connector::ItemKind::sharepoint)] = json::array();

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::service);
    // One warning line, on stderr (docs/decisions.md 2026-10-01, W3.2 point 1; W3.3 point 4).
    CHECK(run.err == "warning: stale_copies: 2 copies from earlier runs in the restore targets "
                     "were ignored (mail 1, sharepoint 1, onedrive 0)\n");
    CHECK_THAT(run.out,
               ContainsSubstring(
                   "  mail        canary  RP-CANARY-0001    match    -             -    123000\n"
                   "  sharepoint  canary  rp-canary-01.pdf  error    stale_target  -    -\n"));
    CHECK(run.out.ends_with("check: 1 match, 0 mismatch, 0 missing, 1 error\n"
                            "\n"
                            "status error stale_target: 1 of 2 item(s) couldn't be checked "
                            "(stale_target 1); 1 verified\n" +
                            clean_after_line(1, 0, 0)));
    // The earlier run's file was never downloaded.
    for (const rp::HttpRequest& request : lab.targets.graph.requests()) {
        CHECK(request.url.find("earlier-file") == std::string::npos);
    }
    CHECK(lab.targets.download.requests().empty());
}

TEST_CASE("restore: an earlier run's file that couldn't be downloaded doesn't touch the check; "
          "only this run's expected files are read",
          "[restore_command][checker]")
{
    Harness lab;
    // Two leftovers whose downloads would fail the SharePoint read: one of
    // the canary's name (its bytes no longer the size listed), one of another
    // name, larger than the download limit.
    lab.targets.before[kind_slot(connector::ItemKind::sharepoint)] =
        json::array({graph_file("earlier-file", "RP-CANARY-01.PDF", 925, "\"c:{earlier},1\""),
                     graph_file("earlier-other", "minutes.pdf", 70000000, "\"c:{other},4\"")});
    lab.targets.files["earlier-file"] = "short";
    lab.targets.files["earlier-other"] = "";

    const Run run = lab.run({"--run-id", kRunId, "--mail", "0", "--sp", "1", "--od", "0"});

    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == "warning: stale_copies: 2 copies from earlier runs in the restore targets "
                     "were ignored (mail 0, sharepoint 2, onedrive 0)\n");
    CHECK_THAT(run.out, ContainsSubstring(
                            "  sharepoint  canary  rp-canary-01.pdf  match    -       -    246000\n"));
    for (const rp::HttpRequest& request : lab.targets.graph.requests()) {
        CHECK(request.url.find("earlier-") == std::string::npos);
    }
    REQUIRE(lab.targets.download.requests().size() == 1);
    CHECK(lab.targets.download.requests()[0].url.ends_with("&rp-item=restored-sharepoint-0"));
}

TEST_CASE("restore: a failure in the check that isn't Graph's keeps the restore's tables, says "
          "the restore ran, and is status error internal, exit 1, whatever the restore said",
          "[restore_command][checker]")
{
    using Raise = std::function<void()>;
    const auto [what, raise] = GENERATE(table<std::string, Raise>({
        {"bad_alloc", [] { throw std::bad_alloc(); }},
        {"logic_error", [] { throw std::logic_error("SENTINEL-LOGIC"); }},
        {"invalid_argument", [] { throw std::invalid_argument("SENTINEL-ARGUMENT"); }},
    }));
    const auto [status, code] = GENERATE(table<connector::RestoreStatus, int>({
        {connector::RestoreStatus::succeeded, rp::exit_code::config},
        {connector::RestoreStatus::partial, rp::exit_code::config},
    }));
    CAPTURE(what, connector::to_string(status));
    Harness lab;
    lab.targets.download_throw = raise;
    lab.fake.answer = [status = status](const connector::RestoreSpec& spec) {
        connector::RestoreResult result = restored(spec);
        result.status = status;
        return result;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == code);
    CHECK(run.err == "check error: unexpected failure\n"
                     "restore error: the restore had started: items may be in the restore "
                     "targets (run run-0001)\n");
    CHECK_THAT(run.out, ContainsSubstring("\nrestore " + std::string{connector::to_string(status)} +
                                          ": 2 of 2 item(s) restored in 0:02:03\n"));
    CHECK(run.out.find("check:") == std::string::npos);
    // W3.4: the copies are deleted all the same; the restore's rows are the
    // evidence. The restore returned, so nothing of it still runs.
    CHECK(run.out.ends_with("\nstatus error internal: the restored items couldn't be checked: an "
                            "unexpected failure (internal)\n" +
                            clean_after_line(1, 1, 0)));
    REQUIRE(lab.cleanups.size() == 1);
    CHECK(lab.cleanups[0].after.has_value());
    CHECK_FALSE(lab.cleanups[0].restore_may_still_run);
    CHECK(lab.cleanups[0].cleanup_ok());
    CHECK(run.out.find("SENTINEL") == std::string::npos);
    CHECK(run.err.find("SENTINEL") == std::string::npos);
}

TEST_CASE("restore: two copies of one item: the newest is checked, and DUP says how many",
          "[restore_command][checker]")
{
    Harness lab;
    lab.targets.after[kind_slot(connector::ItemKind::sharepoint)] = json::array();
    lab.targets.spec = [&lab]() -> std::optional<connector::RestoreSpec> {
        if (!lab.fake.spec) {
            return std::nullopt;
        }
        connector::RestoreSpec twice = *lab.fake.spec;
        twice.mail.push_back(twice.mail.front());
        return twice;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == "warning: duplicate: 1 item(s) had more than one restored copy; the newest "
                     "was checked\n");
    CHECK_THAT(run.out,
               ContainsSubstring("  mail  canary  RP-CANARY-0001  match    -       2 copies  123000\n"));
    CHECK(run.out.ends_with("\nstatus pass: 1 of 1 item(s) verified: manifest 1, fields 0, "
                            "metadata 0\n" +
                            clean_after_line(2, 0, 0)));
}

TEST_CASE("restore: a stdout that fails on the check's table says so, with the status's exit "
          "code",
          "[restore_command][checker]")
{
    const auto [missing, code] = GENERATE(table<bool, int>({
        {false, rp::exit_code::config},
        {true, rp::exit_code::restore},
    }));
    Harness lab;
    if (missing) {
        lab.targets.after[kind_slot(connector::ItemKind::mail)] = json::array();
    }
    // Everything up to the status line fits; the check's table doesn't.
    const std::string status = "restore succeeded: 1 of 1 item(s) restored in 0:02:03\n";
    std::string before_check;
    {
        Harness probe;
        before_check = probe.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"}).out;
        before_check = before_check.substr(0, before_check.find(status) + status.size());
    }
    RecordingStreamBuf buffer(before_check.size() + 3);
    std::ostream out(&buffer);

    const auto [exit_code, error] =
        lab.run_to({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"}, out);

    CHECK(exit_code == code);
    CHECK(error == "error: writing the output failed after the restore ran (run run-0001, restore "
                   "succeeded: 1 of 1 item(s) restored); run status " +
                       std::string{missing ? "fail" : "pass"} + "\n" +
                       clean_after_line(missing ? 0 : 1, 0, 0));
    CHECK(buffer.text.starts_with(before_check));
}

TEST_CASE("restore --record: the check's Graph calls and downloads are recorded too, downloads "
          "as a digest",
          "[restore_command][checker][record]")
{
    Harness lab;
    const std::filesystem::path rec = lab.dir.path() / "rec";

    const Run run = lab.run(
        {"--run-id", kRunId, "--mail", "0", "--sp", "1", "--od", "0", "--record", utf8(rec)});

    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    std::vector<std::filesystem::path> downloads;
    for (const auto& entry : std::filesystem::directory_iterator(rec / "download")) {
        downloads.push_back(entry.path());
    }
    REQUIRE(downloads.size() == 1);
    const json fixture = json::parse(*file_bytes(downloads[0]));
    CHECK(fixture["body"].is_null());
    CHECK(fixture.contains("body_sha256"));
    std::size_t graph = 0;
    for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator(rec / "graph")) {
        ++graph;
    }
    CHECK(graph == lab.targets.graph.requests().size());
}

// --- W3.4: the run mutex and the cleanup ----------------------------------------------

TEST_CASE("restore: a run mutex another run holds stops the command before any Veeam call, with "
          "no run line and no status, exit 4",
          "[restore_command][cleanup]")
{
    const bool record = GENERATE(false, true);
    CAPTURE(record);
    Harness lab;
    lab.lock_taken = true;
    const std::filesystem::path rec = lab.dir.path() / "rec";
    Args args{"--run-id", kRunId, "--mail", "1"};
    const std::string rec_arg = utf8(rec);
    if (record) {
        args.insert(args.end(), {"--record", rec_arg});
    }

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.out.empty());
    CHECK(run.err == "restore error: another RestoreProof run is using the restore targets; "
                     "nothing was done\n");
    CHECK(lab.lock_calls == 1);
    CHECK(lab.make_connector_calls == 0);
    CHECK(lab.fake.points_calls == 0);
    CHECK(lab.targets.graph.requests().empty());
    CHECK(lab.cleanups.empty());
    // Taken before the --record folder is made.
    CHECK_FALSE(std::filesystem::exists(rec));
}

TEST_CASE("restore: a run mutex its last holder never released refuses this run once, saying so",
          "[restore_command][cleanup]")
{
    Harness lab;
    lab.lock_throw = [] { throw rp::AbandonedRunLock(); };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1"});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.out.empty());
    CHECK(run.err == "restore error: the last RestoreProof run ended without releasing the "
                     "restore targets; nothing was done; the next run cleans them before it "
                     "restores\n");
    CHECK(lab.make_connector_calls == 0);
    CHECK(lab.fake.points_calls == 0);
    CHECK(lab.targets.graph.requests().empty());
    CHECK(lab.cleanups.empty());
}

TEST_CASE("restore: a failure taking the run mutex is an unexpected failure, its message hidden",
          "[restore_command][cleanup]")
{
    Harness lab;
    lab.lock_throw = [] { throw std::runtime_error("SENTINEL-MUTEX"); };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "error: unexpected failure\n");
    CHECK(lab.fake.points_calls == 0);
}

TEST_CASE("restore: the run mutex is taken once, before the first Veeam call, and held until the "
          "command returns",
          "[restore_command][cleanup]")
{
    Harness lab;
    bool held_at_restore = false;
    lab.fake.at_restore = [&] { held_at_restore = lab.lock_held; };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(lab.lock_calls == 1);
    CHECK(lab.lock_veeam_calls == 0);
    CHECK(held_at_restore);
    CHECK_FALSE(lab.lock_held);
}

TEST_CASE("restore: a clean before the guard refuses stops the run before the sample is chosen: "
          "status error target_guard, exit 4, the other targets cleaned",
          "[restore_command][cleanup][target_guard]")
{
    namespace gl = rp::test::graph_lab;
    const auto [which, url, fixture] = GENERATE_COPY(table<std::string, std::string, std::string>({
        {"sharepoint", gl::drive_url(), "restoretarget-drive-200"},
        {"onedrive", gl::folder_url(), "onedrive-folder-200"},
    }));
    CAPTURE(which);
    Harness lab;
    json edited = rp::test::load_fixture_json("graph", fixture);
    edited["body"]["name"] = "Dokumenty";
    lab.targets.graph.on(rp::HttpMethod::get, url, {rp::test::to_response(edited)});
    lab.fake.pool.mail = {carol_mail(1)};

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "1"});

    CHECK(run.exit_code == rp::exit_code::service);
    CHECK(run.out == expected_run_lines() +
                         "cleanup before incomplete: deleted 0 mail, 0 sharepoint, 0 onedrive; " +
                         which +
                         " target_guard\n"
                         "\n"
                         "status error target_guard: the run stopped before the restore: the "
                         "restore-target guard refused (target_guard); nothing was restored\n" +
                         kNothingRestored);
    CHECK(run.err == "cleanup error: " + which +
                         ": the restore-target guard refused the target; nothing was deleted in it "
                         "(target_guard)\n"
                         "warning: cleanup: " +
                         which + " not emptied before the run (left 0, skipped 0, target_guard)\n");
    // No Veeam session for the sample, nothing restored, nothing read.
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
    CHECK(lab.targets.graph.count(rp::HttpMethod::get, gl::mail_list_url(false)) == 0);
    CHECK_THAT(lab.log(), ContainsSubstring("[critical] SECURITY: cleanup: "));
    // The mailbox was cleaned all the same.
    CHECK(lab.targets.clean_listings[kind_slot(connector::ItemKind::mail)] == 2);
    REQUIRE(lab.cleanups.size() == 1);
    CHECK_FALSE(lab.cleanups[0].cleanup_ok());
    CHECK_FALSE(lab.cleanups[0].restore_sent);
    CHECK(lab.cleanups[0].before->mail.error_code.empty());
}

TEST_CASE("restore: a clean before that fails otherwise lets the run go on; the cleanup never "
          "changes the status or the exit code",
          "[restore_command][cleanup]")
{
    struct Case {
        std::string name;
        connector::ItemKind kind;
        std::string fixture;
        std::string code;
        std::string what;
    };
    const std::vector<Case> cases{
        {"mail: no permission", connector::ItemKind::mail, "site-403-accessdenied",
         "graph_permission", "Microsoft Graph refused a permission the cleanup relies on"},
        {"sharepoint: Graph unavailable", connector::ItemKind::sharepoint,
         "messages-503-unavailable", "graph_transient",
         "Microsoft Graph couldn't be reached or asked to try later, in both rounds"},
        {"onedrive: an answer it can't use", connector::ItemKind::onedrive,
         "drive-404-itemnotfound", "graph", "Microsoft Graph gave an answer the cleanup can't use"},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{3}))];
    CAPTURE(c.name);
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const rp::HttpResponse answer = rp::test::load_fixture("graph", c.fixture);
    lab.targets.clean_fail = [kind = c.kind, answer](connector::ItemKind k,
                                                     bool after) -> std::optional<rp::HttpResponse> {
        return !after && k == kind ? std::optional{answer} : std::nullopt;
    };
    const std::string name{connector::to_string(c.kind)};

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, StartsWith(expected_run_lines() +
                                   "cleanup before incomplete: deleted 0 mail, 0 sharepoint, 0 "
                                   "onedrive; " +
                                   name + " " + c.code + "\ncanary cursor "));
    CHECK(run.err == "cleanup error: " + name + ": " + c.what + " (" + c.code + ")\n" +
                         "warning: cleanup: " + name + " not emptied before the run (left 0, "
                         "skipped 0, " + c.code + ")\n");
    CHECK(run.out.ends_with(kCheckOfThree + kPassOfThree + kCleanAfterOfThree));
    REQUIRE(lab.cleanups.size() == 1);
    CHECK(lab.cleanups[0].cleanup_ok());
}

TEST_CASE("restore: leftovers are deleted before the run; the command's lines say what the "
          "Cleaner leaves in counts, never names or IDs, and a pass still exits 0",
          "[restore_command][cleanup]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    // A leftover mail and file from an earlier run, and a folder the Cleaner
    // never deletes.
    json folder = TargetsLab::clean_entry(connector::ItemKind::sharepoint, "LeftoverFolderId");
    folder.erase("file");
    folder["folder"] = {{"childCount", 3}};
    folder["name"] = "Leftover Folder Name";
    lab.targets.leftovers[kind_slot(connector::ItemKind::mail)] =
        json::array({TargetsLab::clean_entry(connector::ItemKind::mail, "LeftoverMailId")});
    lab.targets.leftovers[kind_slot(connector::ItemKind::sharepoint)] = json::array(
        {TargetsLab::clean_entry(connector::ItemKind::sharepoint, "LeftoverFileId"), folder});

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, StartsWith(expected_run_lines() +
                                   "cleanup before incomplete: deleted 1 mail, 1 sharepoint, 0 "
                                   "onedrive; skipped 1\n"
                                   "canary cursor "));
    CHECK(run.out.ends_with(kCheckOfThree + kPassOfThree +
                            "cleanup after incomplete: deleted 2 mail, 1 sharepoint, 0 onedrive; "
                            "skipped 1\n"));
    CHECK(run.err == "warning: cleanup: sharepoint not emptied before the run (left 0, skipped 1)\n"
                     "warning: cleanup: sharepoint not emptied after the run (left 0, skipped 1)\n");
    CHECK(lab.targets.deleted.contains("LeftoverMailId"));
    CHECK(lab.targets.deleted.contains("LeftoverFileId"));
    CHECK_FALSE(lab.targets.deleted.contains("LeftoverFolderId"));
    // run.out and run.err hold the command's own lines only: the Harness
    // gives the Cleaner its own logger. In production that logger is the
    // command logger (stderr, warn and worse), and the Cleaner's skip line
    // there names the skipped entry's ID, as TargetReader's do, so the owner
    // can find it (docs/worker-config.md, "The cleanup").
    for (const std::string& text : {run.out, run.err}) {
        CHECK(text.find("Leftover") == std::string::npos);
        CHECK(text.find(lab_values().mailbox) == std::string::npos);
        CHECK(text.find(lab_values().library_id) == std::string::npos);
    }
    CHECK_THAT(lab.log(), ContainsSubstring("[warning] cleanup: skipped a folder in the "
                                            "RestoreTarget library: LeftoverFolderId"));
    REQUIRE(lab.cleanups.size() == 1);
    CHECK_FALSE(lab.cleanups[0].cleanup_ok());
    CHECK(lab.cleanups[0].after->sharepoint.skipped == 1);
}

TEST_CASE("restore: a clean after that fails leaves the status and exit code as decided",
          "[restore_command][cleanup]")
{
    Harness lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const rp::HttpResponse denied =
        rp::test::load_fixture("graph", "w34-file-delete-403-accessdenied");
    lab.targets.delete_answer = [denied](const std::string& id) -> std::optional<rp::HttpResponse> {
        return id.starts_with("restored-sharepoint-") ? std::optional{denied} : std::nullopt;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.out.ends_with(kCheckOfThree + kPassOfThree +
                            "cleanup after incomplete: deleted 2 mail, 0 sharepoint, 0 onedrive; "
                            "left 0 mail, 1 sharepoint, 0 onedrive; sharepoint graph_permission\n"));
    CHECK(run.err == "cleanup error: sharepoint: Microsoft Graph refused a permission the cleanup "
                     "relies on (graph_permission)\n"
                     "warning: cleanup: sharepoint not emptied after the run (left 1, skipped 0, "
                     "graph_permission)\n");
    check_one_status_line(run.out);
    REQUIRE(lab.cleanups.size() == 1);
    CHECK_FALSE(lab.cleanups[0].cleanup_ok());
}

TEST_CASE("restore: cleanup_ok is the state the run leaves the targets in", "[restore_command][cleanup]")
{
    using rp::graph::CleanupResult;
    using rp::graph::CleanupWhen;
    CleanupResult clean;
    CleanupResult dirty;
    dirty.onedrive.left = 2;
    const auto [name, before, after, sent, still_running, ok] =
        GENERATE_COPY(table<std::string, std::optional<CleanupResult>,
                            std::optional<CleanupResult>, bool, bool, bool>({
            {"no clean at all", std::nullopt, std::nullopt, false, false, false},
            {"nothing restored, clean before", clean, std::nullopt, false, false, true},
            {"nothing restored, leftovers", dirty, std::nullopt, false, false, false},
            {"restored, no clean after", clean, std::nullopt, true, false, false},
            {"restored, clean after", dirty, clean, true, false, true},
            {"restored, leftovers after", clean, dirty, true, false, false},
            {"restore may still run", clean, clean, true, true, false},
        }));
    CAPTURE(name);
    rp::RunCleanup cleanup;
    cleanup.before = before;
    cleanup.after = after;
    cleanup.restore_sent = sent;
    cleanup.restore_may_still_run = still_running;

    CHECK(cleanup.cleanup_ok() == ok);
    const json written = rp::to_json(cleanup);
    CHECK(written["cleanup_ok"] == ok);
    CHECK(written["restore_may_still_run"] == still_running);
    CHECK(written["before"].is_null() == !before);
    CHECK(written["after"].is_null() == !after);
    if (after) {
        CHECK(written["after"] == rp::graph::to_json(*after));
    }
    CHECK(written.size() == 4);
}

// --- Through the real veeam_m365 connector -------------------------------------------

namespace {

namespace vrl = rp::test::veeam_restore_lab;

// The command on the default registry's connector (env.make_connector null),
// its Veeam and Graph on `rig`'s recorded answers.
struct RealRig {
    RealRig()
    {
        config_path = dir.write("config.json", config_values().dump(2));
        dir.write("seed-manifest.json", lab_manifest_text());
        // W3.4: the Cleaner finds the three targets empty until a test says
        // otherwise.
        for (const connector::ItemKind kind :
             {connector::ItemKind::mail, connector::ItemKind::sharepoint,
              connector::ItemKind::onedrive}) {
            rig.lab.graph_http.on(rp::HttpMethod::get, TargetsLab::clean_listing_url(kind),
                                  {rp::test::graph_lab::page_of(json::array())});
        }
    }

    rp::RestoreCommandEnv env()
    {
        rp::RestoreCommandEnv env;
        env.default_config_path = [] { return std::filesystem::path{"unused.json"}; };
        env.load_secrets = [] {
            return rp::Secrets{vrl::kUsername, vrl::kPassword, rp::test::graph_lab::pfx_base64(),
                               std::string{rp::test::graph_lab::kPfxPassword}};
        };
        connector::ConnectorOptions& o = env.connector_options;
        o.make_http = [this](const rp::HttpClientOptions&) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(rig.veeam);
        };
        o.make_graph_http =
            [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(rig.lab.graph_http);
        };
        o.logger = rig.logger;
        o.now = [this] { return rig.clock.now(); };
        o.sleep = [this](std::chrono::milliseconds wait) { rig.clock.sleep(wait); };
        o.jitter = [] { return 0.0; };
        // The recorded restore POST's time; before any is served, the time
        // the Worker app's test certificate is made for.
        o.wall_now = [this] {
            const auto posted = rig.next_post_time();
            return posted == std::chrono::system_clock::time_point{} ? rp::test::graph_lab::kNow
                                                                     : posted;
        };
        o.cert_exporter = rig.exporter;
        env.now = [this] { return rig.clock.now(); };
        env.make_download_http = [this]() -> std::unique_ptr<rp::IHttpClient> {
            return std::make_unique<rp::test::ForwardingHttpClient>(download);
        };
        // W3.4: a fake run mutex, never the machine's.
        env.take_run_lock = []() -> std::unique_ptr<rp::RunLock> {
            return std::make_unique<rp::RunLock>();
        };
        return env;
    }

    // The test mailbox for the check (W3.2), on the guard's Graph: empty
    // before the restore (the listing without bodies), and after it (with
    // them) holding the restored copy of canary `subject`: W2.2's recorded
    // one-mail listing, edited to carry the canary's fields and its body as
    // sent (tests/fixtures/graph/README.md: edited copies are built in the test).
    void serve_mailbox(const std::string& subject)
    {
        namespace gl = rp::test::graph_lab;
        json entry;
        const json manifest = json::parse(lab_manifest_text());
        for (const json& e : manifest.at("entries")) {
            if (e.value("subject", "") == subject) {
                entry = e;
            }
        }
        REQUIRE(entry.is_object());
        json listing = rp::test::load_fixture_json("graph", "mail-list-200-one-item");
        json& mail = listing["body"]["value"][0];
        mail["subject"] = subject;
        mail["internetMessageId"] = entry["internet_message_id"];
        mail["from"]["emailAddress"]["address"] = entry["sender"];
        mail["sentDateTime"] = entry["sent_at"];
        mail["receivedDateTime"] = entry["received_at"];
        mail["createdDateTime"] = "2026-09-28T21:28:00Z";
        mail["body"]["content"] = canary_body(subject);
        rig.lab.graph_http.on(rp::HttpMethod::get, gl::mail_list_url(false),
                              {rp::test::load_fixture("graph", "mail-list-200-empty")});
        rig.lab.graph_http.on(rp::HttpMethod::get, gl::mail_list_url(true),
                              {rp::test::to_response(listing)});
        // W3.4: the Cleaner's view: empty in the clean before (its listing
        // and its listing again), the copy in the clean after, then gone.
        const json empty = json::array();
        rig.lab.graph_http.on(
            rp::HttpMethod::get, TargetsLab::clean_listing_url(connector::ItemKind::mail),
            {gl::page_of(empty), gl::page_of(empty),
             gl::page_of(json::array({{{"id", mail["id"]}}})), gl::page_of(empty)});
        rig.lab.graph_http.on_path(rp::HttpMethod::post, "/v1.0/users/*/messages/*/permanentDelete",
                                   {rp::test::load_fixture(
                                       "recordings/w34-live-run1/graph",
                                       "035-post-v1-0-users-restoretest-restoreprooflab-"
                                       "onmicrosoft-com-messa")});
    }

    Run run(Args args)
    {
        const std::string path_arg = utf8(config_path);
        args.push_back("--config");
        args.push_back(path_arg);
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_restore_command(args, out, err, env());
        return {code, out.str(), err.str()};
    }

    rp::test::TempDir dir;
    std::filesystem::path config_path;
    vrl::RestoreRig rig;
    rp::test::FakeHttpClient download;
};

} // namespace

TEST_CASE("restore through veeam_m365: Veeam unreachable is exit 3 and nothing is restored",
          "[restore_command][veeam_m365]")
{
    RealRig real;
    real.rig.veeam.on(rp::HttpMethod::post, vrl::url("/v8/token"),
                      [](const rp::HttpRequest& request) -> rp::HttpResponse {
                          throw rp::HttpError("POST " + request.url + ": could not connect",
                                              rp::TransportError::connect, 0, 1);
                      });

    const Run run = real.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::transient);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, StartsWith("restore error: "));
    CHECK_THAT(run.err, !ContainsSubstring(vrl::kPassword));
    CHECK(real.rig.restore_posts().empty());
}

TEST_CASE("restore through veeam_m365: a wrong target is refused, exit 4, before any restore "
          "request",
          "[restore_command][veeam_m365][target_guard]")
{
    RealRig real;
    real.rig.lab.serve_edited(rp::test::graph_lab::drive_url(), "restoretarget-drive-200",
                              [](json& body) { body["name"] = "Dokumenty"; });

    const Run run = real.run({"--run-id", kRunId, "--mail", "0", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::service);
    // Since W3.4 the clean before resolves all three targets first, through
    // the same guard checks (rp/target_guard_graph.hpp), so it is the one that
    // refuses, and the run stops there (W3.4 point 8); the before snapshot's
    // guard is "a failure reading the targets before the restore" above, the
    // connector's veeam_m365_restore_guard_test.cpp's. The other two targets
    // were cleaned all the same.
    CHECK(run.err == "cleanup error: sharepoint: the restore-target guard refused the target; "
                     "nothing was deleted in it (target_guard)\n"
                     "warning: cleanup: sharepoint not emptied before the run (left 0, skipped 0, "
                     "target_guard)\n");
    CHECK_THAT(run.out,
               StartsWith("restore point " + vrl::kBackupTime + "  " + vrl::kRestorePointId));
    CHECK_THAT(run.out,
               EndsWith("\nrun run-0001  seed " + seed_of(kRunId) +
                        "\n"
                        "cleanup before incomplete: deleted 0 mail, 0 sharepoint, 0 onedrive; "
                        "sharepoint target_guard\n"
                        "\n"
                        "status error target_guard: the run stopped before the restore: the "
                        "restore-target guard refused (target_guard); nothing was restored\n" +
                        kNothingRestored));
    // The guard's refusal is one SECURITY line, as layer 1's.
    CHECK_THAT(real.rig.log(), ContainsSubstring("SECURITY: cleanup: the drive test_library_id "
                                                 "names is \"Dokumenty\""));
    // Veeam saw only what comes before the guard: the sign-in, the restore
    // points and the sign-out. No candidates, no explore session, no restore
    // session list, no restore POST.
    std::vector<std::string> veeam_calls;
    for (const rp::HttpRequest& request : real.rig.veeam.requests()) {
        const std::string path = request.url.substr(vrl::kBase.size());
        veeam_calls.push_back(std::string{rp::to_string(request.method)} + " " +
                              path.substr(0, path.find('?')));
    }
    CHECK(veeam_calls == std::vector<std::string>{
                             "POST /v8/token",
                             "GET /v8/Organizations",
                             "GET /v8/RestorePoints",
                             "POST /v8/token/logout",
                         });
    CHECK(real.rig.restore_posts().empty());
    CHECK(real.rig.exporter->calls == 0);
}

TEST_CASE("restore through veeam_m365: a canary restored on the recorded run, exit 0",
          "[restore_command][veeam_m365]")
{
    RealRig real;
    real.rig.serve(vrl::mail_x1());
    real.serve_mailbox("RP-CANARY-0011");

    // RP-CANARY-0011, bob's first, is the manifest's mail canary 10: W2.4's
    // recorded single-mail restore.
    const Run run = real.run({"--run-id", kRunId, "--canary-cursor", "10,0,0", "--mail", "1",
                              "--sp", "0", "--od", "0"});

    INFO(run.out);
    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    // docs/worker-config.md's example ("rpworker restore"): keep them in step.
    CHECK(run.out ==
          "restore point 2026-09-27T22:00:48.1447833Z  "
          "c2f0f2e7-177f-48ac-992b-93a50cf702e35e1c0a24-0000-4000-8000-000000000924  "
          "(veeam_org_name RestoreProofLab.onmicrosoft.com)\n"
          "run run-0001  seed " + seed_of(kRunId) + "\n" + kCleanBefore +
          "canary cursor 10,0,0 -> 11,0,0\n"
          "  KIND        REQUESTED  CANARIES  RANDOM  NOTE\n"
          "  mail        1          1 of 1    0 of 0\n"
          "  sharepoint  0          0 of 0    0 of 0\n"
          "  onedrive    0          0 of 0    0 of 0\n"
          "restoring 1 item(s) ...\n"
          "\n"
          "  KIND  SOURCE  NAME            OUTCOME   SESSION                               ELAPSED  MESSAGE\n"
          "  mail  canary  RP-CANARY-0011  restored  b6fe35ef-9633-481d-9756-3496a717d8a9  0:00:32  "
          "Item RP-CANARY-0011 was restored successfully (type: IPM.Note; source: Bob Test\\Inbox; "
          "target: restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox)\n"
          "\n"
          "  SESSION                               KIND  RESULT   RESTORED  STARTED                       ENDED                         ELAPSED\n"
          "  b6fe35ef-9633-481d-9756-3496a717d8a9  mail  Success  1 of 1    2026-09-28T21:27:28.3281642Z  2026-09-28T21:28:00.6973119Z  0:00:32\n"
          "\n"
          "restore succeeded: 1 of 1 item(s) restored in 0:00:05\n"
          "\n"
          "  KIND  SOURCE  NAME            OUTCOME  FIELDS  DUP  MS\n"
          "  mail  canary  RP-CANARY-0011  match    -       -    0\n"
          "\n"
          "check: 1 match, 0 mismatch, 0 missing, 0 error\n"
          "\n"
          "status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0\n"
          "cleanup after ok: deleted 1 mail, 0 sharepoint, 0 onedrive\n");
    CHECK(real.rig.restore_posts().size() == 1);
    // The mailbox was read once without bodies before the restore, once with
    // them after it.
    CHECK(real.rig.lab.gets(rp::test::graph_lab::mail_list_url(false)) == 1);
    CHECK(real.rig.lab.gets(rp::test::graph_lab::mail_list_url(true)) == 1);
    CHECK(real.rig.exporter->calls == 1);
    CHECK_THAT(run.out, !ContainsSubstring(vrl::kPassword));
    CHECK_THAT(run.out, !ContainsSubstring(vrl::kFakePfxPassword));
}

TEST_CASE("restore through veeam_m365 --record: every exchange written, the restore credential "
          "and the password never",
          "[restore_command][veeam_m365][record]")
{
    RealRig real;
    real.rig.serve(vrl::mail_x1());
    real.serve_mailbox("RP-CANARY-0011");
    const std::filesystem::path rec = real.dir.path() / "rec";

    const Run run = real.run({"--run-id", kRunId, "--canary-cursor", "10,0,0", "--mail", "1",
                              "--sp", "0", "--od", "0", "--record", utf8(rec)});
    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE(run.err.empty());

    const auto files = [](const std::filesystem::path& dir) {
        std::vector<std::filesystem::path> paths;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            paths.push_back(entry.path());
        }
        std::ranges::sort(paths);
        return paths;
    };
    const std::vector<std::filesystem::path> veeam = files(rec / "veeam");
    const std::vector<std::filesystem::path> graph = files(rec / "graph");
    // Every call each service got, and the command says how many in all.
    CHECK(veeam.size() == real.rig.veeam.requests().size());
    CHECK(graph.size() == real.rig.lab.graph_http.requests().size());
    CHECK(run.out.ends_with("check: 1 match, 0 mismatch, 0 missing, 0 error\n"
                            "\n"
                            "status pass: 1 of 1 item(s) verified: manifest 1, fields 0, "
                            "metadata 0\n"
                            "cleanup after ok: deleted 1 mail, 0 sharepoint, 0 onedrive\n"
                            "recorded " +
                            std::to_string(veeam.size() + graph.size()) + " exchange(s) in " +
                            utf8(rec) + "\n"));

    std::size_t restore_posts = 0;
    std::size_t deletes = 0;
    for (const auto& list : {veeam, graph}) {
        for (const std::filesystem::path& path : list) {
            std::ifstream file(path, std::ios::binary);
            const std::string text{std::istreambuf_iterator<char>(file), {}};
            CAPTURE(path.filename().string());
            for (const std::string& secret :
                 {vrl::kPassword, vrl::kFakePfx, vrl::kFakePfxPassword,
                  std::string{rp::test::graph_lab::kPfxPassword}}) {
                CHECK(text.find(secret) == std::string::npos);
            }
            const json fixture = json::parse(text);
            if (fixture["request"].get<std::string>().ends_with("/restoreTo")) {
                ++restore_posts;
                // The body as sent, with its credential scrubbed: what the
                // target guard's tests check a restore body against.
                CHECK(fixture["request_body"]["applicationCertificate"] == "[REDACTED]");
                CHECK(fixture["request_body"]["applicationCertificatePassword"] == "[REDACTED]");
                CHECK(fixture["request_body"]["mailbox"] ==
                      rp::test::graph_lab::lab_values().mailbox);
            }
            // W3.4: the cleanup's traffic is Graph's, recorded with the rest.
            if (fixture["request"].get<std::string>().ends_with("/permanentDelete")) {
                ++deletes;
                CHECK(fixture["status"] == 204);
            }
        }
    }
    CHECK(restore_posts == 1);
    CHECK(deletes == 1);
}
