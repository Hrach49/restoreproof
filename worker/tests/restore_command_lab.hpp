#pragma once

// `rpworker restore` and `rpworker test` (rp/restore_command.hpp,
// rp/test_command.hpp) as their tests see them: a temp folder with the
// config and the lab's manifest, a fake IConnector, Graph and the downloads
// on FakeHttpClients that keep the restore targets (TargetsLab), secrets, a
// clock the test moves and a run ID it chose (Harness). Both commands run the
// same pipeline, so both test files share it. No network, nothing live, and
// no Catch2 assertion in a fake's handler.

#include "tsa_lab.hpp"
#include "fake_http_client.hpp"
#include "graph_lab.hpp"
#include "signing_lab.hpp"
#include "target_guard_lab.hpp"
#include "test_support.hpp"
#include "veeam_restore_lab.hpp"

#include "../src/command_config.hpp"
#include "../src/run_pipeline.hpp"

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
#include <rp/step_timer.hpp>
#include <rp/text_v1.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>
#include <spdlog/sinks/ostream_sink.h>

#include <catch2/catch_test_macros.hpp>

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
#include <optional>
#include <ostream>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::test::restore_command_lab {

using Args = std::vector<std::string_view>;
using namespace std::chrono_literals;

namespace connector = rp::connector;
namespace sampling = rp::sampling;
using nlohmann::json;
using rp::test::graph_lab::kClient;
using rp::test::graph_lab::kTenant;
using rp::test::graph_lab::lab_values;

inline const std::string kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] [--vault <file>] | "
    "rpworker vault set|remove <name> [--vault <file>] | rpworker vault list|test [--vault <file>] | "
    "rpworker vault grant <account> [--vault <file>] | "
    "rpworker veeam list [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker graph list [--hash] [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker client check --profile-file <file> [--vault <file>] [--record <dir>] | "
    "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] | "
    "rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] [--json <file> | --evidence <dir> [--outbox <root>]] | "
    "rpworker outbox flush [--config <path>] [--outbox <root>] [--record <dir>] | "
    "rpworker outbox list [--outbox <root>] | "
    "rpworker signer public-key [--vault <file>] | "
    "rpworker signer verify <folder> --public-key <pem file> [--tsa-ca <pem file>] | "
    "rpworker service install [--config <path>] | rpworker service uninstall|start|stop | "
    "rpworker service run [--config <path>]\n";

inline const std::string kOrgName = "RestoreProofLab.onmicrosoft.com";
// Veeam's restore point IDs are two GUIDs run together: the backup
// repository's ID, here the lab Veeam server's as its fixtures have it, and
// the point's own, made up.
inline const std::string kLabRepositoryId = "c2f0f2e7-177f-48ac-992b-93a50cf702e3";
inline const std::string kNewestId = kLabRepositoryId + "5e1c0a24-0000-4000-8000-000000000930";
inline const std::string kOlderId = kLabRepositoryId + "5e1c0a24-0000-4000-8000-000000000929";
inline const std::string kNewestTime = "2026-09-29T22:00:45.6603083Z";
inline const std::string kOlderTime = "2026-09-28T22:00:40Z";
inline const std::string kRunId = "run-0001";
inline const std::string kGeneratedRunId = "rp-20260930T100000Z-0123abcd";
inline const std::string kCarol = "carol@RestoreProofLab.onmicrosoft.com";

inline std::string seed_of(const std::string& run_id)
{
    return sampling::seed_hex(sampling::seed_from_run_id(run_id));
}

inline std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

inline std::string lab_manifest_text()
{
    const std::filesystem::path path =
        std::filesystem::path{RP_SOURCE_DIR} / ".." / "lab" / "seed-manifest.json";
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

// The lab manifest with only the first `mail`, `sp` and `od` entries of each kind.
inline std::string trimmed_manifest(std::size_t mail, std::size_t sp, std::size_t od)
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
inline json config_values()
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

inline connector::RestorePoint point(const std::string& id, const std::string& time)
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
inline connector::RestoreResult restored(const connector::RestoreSpec& spec)
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

// A restore whose every item the restore point didn't hold (Q3.1): nothing
// sent, no session, the backup's word per item.
inline connector::RestoreResult not_in_point(const connector::RestoreSpec& spec)
{
    connector::RestoreResult result = restored(spec);
    result.status = connector::RestoreStatus::failed;
    result.session_ids.clear();
    result.sessions.clear();
    result.items_sent = 0;
    result.items_restored = 0;
    for (connector::ItemRestoreResult& item : result.items) {
        item.outcome = connector::ItemOutcome::not_in_backup;
        item.session_id.clear();
        item.message = "veeam_m365: an item not found in the restore point";
    }
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
    // What describe() says: the one connector result.v1 knows (W4.1), so a
    // run's result is valid; a test sets another name to see it isn't.
    connector::ConnectorInfo info{std::string{connector::kVeeamM365}, "1"};
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

    connector::ConnectorInfo describe() const override { return fake_.info; }

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

// W3.5: the step timings' table that ends stdout of every run with a run line,
// a paragraph of its own, as the timings on_timings was given print it.
inline std::string timings_table(const rp::timing::RunTimings& timings)
{
    return "\n" + rp::timing::format_timings(timings);
}

// `out` without that table: REQUIREs one run's timings and its table at the end.
inline std::string without_timings(const std::string& out,
                            const std::vector<rp::timing::RunTimings>& timings)
{
    REQUIRE(timings.size() == 1);
    const std::string table = timings_table(timings[0]);
    REQUIRE(out.ends_with(table));
    return out.substr(0, out.size() - table.size());
}

// lab/seeder/catalog.py's MAIL_SENTENCES and MAIL_FOOTER: what a canary mail's
// body holds, so a restored copy can carry it (its text-v1 hash is the
// manifest's body_sha256; a test below holds them to it).
inline const std::vector<std::string> kMailSentences{
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
inline const std::string kMailFooter =
    "RestoreProof canary mail. Do not edit, move or delete this message.\r\n"
    "It is one of the 40 expected items in lab/seed-manifest.json.";

// The body of canary mail "RP-CANARY-00nn" as sent.
inline std::string canary_body(const std::string& subject)
{
    return kMailSentences.at(std::stoul(subject.substr(10)) - 1) + "\r\n\r\n" + kMailFooter;
}

// A file's bytes, or nullopt when it can't be read. No Catch2 assertion: the
// fakes' handlers call it.
inline std::optional<std::string> file_bytes(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>(file), {}};
}

// A message as Graph lists it in the test mailbox.
inline json graph_mail(const std::string& id, const std::string& subject, const std::string& address,
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
inline json graph_file(const std::string& id, const std::string& name, std::size_t size,
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

inline std::size_t kind_slot(connector::ItemKind kind)
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
        gl::serve_library_root(graph);
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
inline constexpr std::string_view kTsaUrl = "http://tsa.test/stamp";

struct Harness {
    explicit Harness(const json& config_edit = json::object())
    {
        json config = config_values();
        // W4.4: the TSA is the test-only one, its root in a file of its own:
        // a test never asks DigiCert, nor trusts the test root by default.
        config["tsa_url"] = std::string{kTsaUrl};
        config["tsa_ca_file"] = utf8(dir.write("tsa-ca.pem", tsa.root_pem()));
        config.update(config_edit);
        tsa.time = std::chrono::system_clock::to_time_t(rp::test::graph_lab::kNow);
        tsa_http.on(rp::HttpMethod::post, std::string{kTsaUrl},
                    [this](const rp::HttpRequest& request) {
                        if (tsa_answer) {
                            return tsa_answer(request);
                        }
                        return rp::test::make_response(200, tsa.respond(request.body),
                                                       "application/timestamp-reply");
                    });
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
        // W4.5: the vault's path reaches the loader; the secrets are the
        // test's.
        env.default_vault_path = [this] {
            ++default_vault_calls;
            return default_vault;
        };
        env.load_secrets = [this](const std::filesystem::path& vault) {
            ++load_secrets_calls;
            vault_read = vault;
            return load_secrets();
        };
        env.make_connector = [this](const rp::Config& config, const rp::Secrets& secrets,
                                    const connector::ConnectorOptions& options)
            -> std::unique_ptr<connector::IConnector> {
            ++make_connector_calls;
            connector_secrets = secrets;
            connector_options = options;
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
        env.connector_options.wall_now = [this] { return wall_now(); };
        // The check's Graph (W3.2): never a wait between attempts.
        env.connector_options.make_graph_http =
            [this](std::shared_ptr<spdlog::logger>) -> std::unique_ptr<rp::IHttpClient> {
            ++graph_clients;
            return std::make_unique<rp::test::ForwardingHttpClient>(targets.graph);
        };
        env.connector_options.sleep = [this](std::chrono::milliseconds wait) {
            slept.push_back(wait);
        };
        env.connector_options.jitter = [] { return 0.0; };
        env.make_download_http = [this](std::function<void(std::chrono::milliseconds)> sleep)
            -> std::unique_ptr<rp::IHttpClient> {
            download_sleep = std::move(sleep);
            if (no_download_http) {
                return nullptr;
            }
            return std::make_unique<rp::test::ForwardingHttpClient>(targets.download);
        };
        env.make_run_id = [this] {
            ++run_id_calls;
            return generated_run_id;
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
        env.on_timings = [this](const rp::timing::RunTimings& run_timings) {
            timings.push_back(run_timings);
            out_at_timings.push_back(fake.out ? fake.out->str() : "");
        };
        // W3.6: `test --json`'s writer; null, the atomic writer, into the
        // temp folder.
        env.write_summary = write_summary;
        // W4.1: null, the real embedded schema's validator.
        env.result_schema_ready = schema_ready;
        // W4.2: `test --evidence`'s writer (null, the atomic one) and the
        // screenshot's capturer (null, the default: no page).
        env.write_evidence_file = write_evidence_file;
        env.capture_screenshot = capture_screenshot;
        // W4.3: the result's signer; null, rp::Signer::sign.
        env.sign_result = sign_result;
        // W4.4: the TSA's client, on the fake.
        env.make_tsa_http = [this]() -> std::unique_ptr<rp::IHttpClient> {
            ++tsa_clients;
            return std::make_unique<rp::test::ForwardingHttpClient>(tsa_http);
        };
        env.timestamp_nonce = timestamp_nonce;
        // W4.6: the outbox's file calls; null, the real ones, in the temp folder.
        env.outbox_files = outbox_files;
        // W4.8: the stop check (null: never) and the run's record, each call
        // kept with stdout and the Graph requests as they stood then.
        env.stop_requested = stop_requested;
        env.connector_options.stop_requested = connector_stop;
        env.on_run_started = [this](const rp::RunStarted& started) {
            run_started.push_back(started);
            out_at_run_started.push_back(fake.out ? fake.out->str() : "");
            graph_requests_at_run_started = targets.graph.requests().size();
            return on_run_started ? on_run_started(started) : true;
        };
        return env;
    }

    // W4.8: from here on the Harness runs the pipeline itself, as the
    // service's loop calls it: the command line parsed as `rpworker test`
    // parses it (no --json), test's presentation, `loaded` and `screenshots`
    // handed on, and what became of the run in `report`.
    void use_pipeline()
    {
        command = [this](std::span<const std::string_view> args, std::ostream& out,
                         std::ostream& err, const rp::RestoreCommandEnv& env) {
            rp::PipelineArgs parsed;
            const std::optional<rp::CommandOptions> options = rp::parse_options(
                args, {"--mail", "--sp", "--od", "--point", "--run-id", "--canary-cursor",
                       "--manifest", "--config", "--vault", "--record", "--evidence", "--outbox"});
            if (!options || !rp::parse_pipeline_args(*options, parsed)) {
                return rp::exit_code::usage;
            }
            parsed.evidence = options->value("--evidence");
            parsed.outbox = options->value("--outbox");
            parsed.loaded = loaded;
            parsed.screenshots = screenshots;
            std::shared_ptr<rp::FixtureRecorder> recorder;
            // What an earlier run left in the report must not survive.
            report.run_id = "an earlier run's";
            report.run_line = true;
            report.restore_may_still_run = true;
            report.folder = rp::RunFolderState::queued;
            return rp::run_pipeline(parsed, out, err, env, recorder, rp::test_presentation(),
                                    &report);
        };
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
        const int code = command(args, out, err, env());
        return {code, err.str()};
    }

    Run run_raw(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        fake.out = &out;
        const int code = command(args, out, err, env());
        fake.out = nullptr;
        return {code, out.str(), err.str()};
    }

    std::string log()
    {
        logger->flush();
        return log_stream.str();
    }

    // The run's stdout up to its step timings' table (W3.5), which it REQUIREs.
    std::string body(const Run& run) const { return without_timings(run.out, timings); }

    // The command run: `restore`, or `test` (W3.6), which runs the same
    // pipeline.
    std::function<int(std::span<const std::string_view>, std::ostream&, std::ostream&,
                      const rp::RestoreCommandEnv&)>
        command = rp::run_restore_command;
    std::function<bool(const std::filesystem::path&, std::string_view)> write_summary;
    std::function<bool(const std::filesystem::path&, std::string_view)> write_evidence_file;
    rp::ScreenshotCapturer capture_screenshot;
    std::function<std::optional<rp::SignedResult>(std::string_view, const rp::SigningKey&)>
        sign_result;
    // W4.4: the test-only TSA (its keys the same for every Harness, made
    // once), the client the run asks it through, and an answer in its place.
    // It stamps the Harness's wall clock's time unless `tsa.time` is changed.
    static const rp::test::TestTsa& shared_tsa()
    {
        static const rp::test::TestTsa one;
        return one;
    }
    rp::test::TestTsa tsa{shared_tsa().root_pem(), shared_tsa().tsa_cert_pem_text(),
                          shared_tsa().tsa_key_pem_text()};
    rp::test::FakeHttpClient tsa_http;
    std::function<rp::HttpResponse(const rp::HttpRequest&)> tsa_answer;
    std::function<std::optional<std::uint64_t>()> timestamp_nonce;
    int tsa_clients = 0;
    rp::OutboxFiles outbox_files;
    // W4.8: the stop check (null: never), on_run_started's answer (null:
    // true), every RunStarted it was given, with stdout and the count of
    // Graph requests as they stood at the last one, the options the
    // connector's maker was handed, and, after use_pipeline(), the config
    // and the screenshots flag the pipeline is handed and its report.
    std::function<bool()> stop_requested;
    // A stop check the connector's options carry already (null: none).
    std::function<bool()> connector_stop;
    std::function<bool(const rp::RunStarted&)> on_run_started;
    std::vector<rp::RunStarted> run_started;
    std::vector<std::string> out_at_run_started;
    std::size_t graph_requests_at_run_started = 0;
    std::optional<connector::ConnectorOptions> connector_options;
    const rp::Config* loaded = nullptr;
    std::optional<bool> screenshots;
    rp::PipelineReport report;
    // The run ID a run without --run-id makes.
    std::string generated_run_id{kGeneratedRunId};
    // The download client's maker returns null: the run stops after its run
    // line, before the clean before.
    bool no_download_http = false;
    // Every wait asked of the pipeline's sleep (connector_options.sleep);
    // none is real.
    std::vector<std::chrono::milliseconds> slept;
    // The sleep make_download_http was handed (W4.8): the pipeline's own.
    std::function<void(std::chrono::milliseconds)> download_sleep;
    // The wall clock: the certificate check, Graph's sign-in and, for `test
    // --json`, started_at and ended_at (W3.6). Fixed at a time the lab's
    // certificate is valid.
    std::function<std::chrono::system_clock::time_point()> wall_now = [] {
        return rp::test::graph_lab::kNow;
    };
    rp::test::TempDir dir;
    std::filesystem::path config_path;
    std::filesystem::path manifest_path;
    FakeConnector fake;
    // The signing key is RFC 8032's published test key 1 (W4.3), never a
    // secret: only `test --evidence` parses it.
    std::function<rp::Secrets()> load_secrets = [] {
        return rp::Secrets{"rp-veeam", "Sentinel-Veeam-Password-9c2e",
                           rp::test::graph_lab::pfx_base64(),
                           std::string{rp::test::graph_lab::kPfxPassword},
                           std::string{rp::test::kSigningKey1Base64}};
    };
    // The secrets the connector's maker was handed.
    std::optional<rp::Secrets> connector_secrets;
    // W4.5: the vault without --vault, the one the loader was given, and
    // whether the default was asked.
    std::filesystem::path default_vault = dir.path() / "default-vault.bin";
    std::filesystem::path vault_read;
    int default_vault_calls = 0;
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
    // W4.1: whether the result's validator is there; null, the real one.
    std::function<bool()> schema_ready;
    bool lock_taken = false;
    std::function<void()> lock_throw;
    bool lock_held = false;
    int lock_calls = 0;
    int lock_veeam_calls = -1;
    std::vector<rp::RunCleanup> cleanups;
    std::vector<std::string> out_at_cleanup;
    std::vector<std::string> out_at_delete; // stdout as it stood at each delete
    // W3.5: each run's step timings, and stdout as it stood then.
    std::vector<rp::timing::RunTimings> timings;
    std::vector<std::string> out_at_timings;
    std::string made_for_org;
    std::ostringstream log_stream;
    std::shared_ptr<spdlog::logger> logger;
    TargetsLab targets;
};

inline connector::MailCandidate carol_mail(int n)
{
    return {{kCarol, "Archive", "real mail 0" + std::to_string(n),
             "2026-09-20T10:00:0" + std::to_string(n) + "Z"},
            "Carol Test",
            "2026-09-20T09:59:0" + std::to_string(n) + "Z"};
}

// W3.4: the clean before of targets the Cleaner finds empty, and the cleanup
// lines that end a run after its status line.
inline const std::string kCleanBefore = "cleanup before ok: deleted 0 mail, 0 sharepoint, 0 onedrive\n";
inline const std::string kNothingRestored = "cleanup after skipped: nothing was restored\n";
// The clean after of `--mail 2 --sp 1 --od 0`'s faithful copies.
inline const std::string kCleanAfterOfThree =
    "cleanup after ok: deleted 2 mail, 1 sharepoint, 0 onedrive\n";
inline std::string clean_after_line(int mail, int sharepoint, int onedrive)
{
    return "cleanup after ok: deleted " + std::to_string(mail) + " mail, " +
           std::to_string(sharepoint) + " sharepoint, " + std::to_string(onedrive) + " onedrive\n";
}
// When Veeam may still be writing: no clean under a restore (W4.8 point 9).
inline const std::string kCleanAfterStillRunning =
    "cleanup after skipped: the restore may still be running; the next run cleans before\n";

// The first two lines of `--run-id run-0001` on the newest point.
inline std::string expected_run_lines()
{
    return "restore point " + kNewestTime + "  " + kNewestId + "  (veeam_org_name " + kOrgName +
           ")\n"
           "run run-0001  seed " +
           seed_of(kRunId) + "\n";
}

// What `--run-id run-0001` on the newest point prints before the sample is
// chosen: the run, then the clean before (W3.4).
inline std::string expected_intro()
{
    return expected_run_lines() + kCleanBefore;
}

// The header of `--mail 2 --sp 1 --od 0 --run-id run-0001` on the newest point
// with one random mail candidate.
inline std::string expected_header()
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
inline const std::string kCheckOfThree =
    "\n"
    "  KIND        SOURCE  NAME              OUTCOME  FIELDS  DUP  MS\n"
    "  mail        canary  RP-CANARY-0001    match    -       -    123000\n"
    "  mail        random  real mail 01      match    -       -    123000\n"
    "  sharepoint  canary  rp-canary-01.pdf  match    -       -    246000\n"
    "\n"
    "check: 3 match, 0 mismatch, 0 missing, 0 error\n";

// That run's status line: every item verified.
inline const std::string kPassOfThree =
    "\n"
    "status pass: 3 of 3 item(s) verified: manifest 2, fields 1, metadata 0\n";

} // namespace rp::test::restore_command_lab
