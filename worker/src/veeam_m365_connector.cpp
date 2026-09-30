#include <rp/veeam_m365_connector.hpp>

#include <rp/client_assertion.hpp>
#include <rp/graph_errors.hpp>
#include <rp/target_guard_veeam.hpp>

#include "command_config.hpp"
#include "json_fields.hpp"
#include "text_util.hpp"
#include "uuid.hpp"
#include "veeam_browse.hpp"
#include "veeam_explore.hpp"
#include "veeam_restore.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace rp {

namespace {

using nlohmann::json;
using nlohmann::ordered_json;
namespace vr = veeam_restore;
using connector::ItemKind;
using veeam_browse::exactly_one;
using veeam_browse::id_of;
using veeam_browse::is_file_named;
using veeam_browse::shown_text;
using veeam_browse::text_at;
using veeam_explore::find_organization;
using veeam_explore::shown;

connector::RestorePoint to_connector(const RestorePoint& point)
{
    connector::RestorePoint out;
    out.id = point.id;
    out.backup_time = point.backup_time;
    out.has_mail = point.is_exchange;
    out.has_sharepoint = point.is_sharepoint;
    out.has_onedrive = point.is_onedrive;
    out.is_archive = point.is_long_term_copy;
    return out;
}

bool is_set(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty();
}

// One item as browsing found it.
struct Resolved {
    std::size_t index = 0;    // in its kind's selectors
    std::string container;    // the source mailbox, site or OneDrive, lower case
    std::string id;           // Veeam's item or document ID
    std::string name;         // the subject or file name
    ordered_json document;    // files: the body's document
};

// One type's explore session and what was found in it.
struct TypeWork {
    ItemKind kind = ItemKind::mail;
    std::string explore;
    std::vector<Resolved> items;
    ordered_json target_onedrive; // OneDrive: {id, name, url} as Veeam listed it
    // The tenant's names this type's messages may quote (source containers'
    // and folders' names and addresses): never read as Veeam's words.
    std::vector<std::string> tenant_texts;
};

// Adds the string at `key` of a Veeam entry, if any, to `texts`.
void add_text(std::vector<std::string>& texts, const json& entry, std::string_view key)
{
    if (const std::string* text = string_at(entry, key); text != nullptr && !text->empty()) {
        texts.push_back(*text);
    }
}

veeam::RestoreKind guard_kind(ItemKind kind) noexcept
{
    switch (kind) {
    case ItemKind::sharepoint:
        return veeam::RestoreKind::sharepoint;
    case ItemKind::onedrive:
        return veeam::RestoreKind::onedrive;
    case ItemKind::mail:
        break;
    }
    return veeam::RestoreKind::mail;
}

// Wipes the credential's copies on the way out, exception or not.
struct CredentialWipe {
    ExportedPfx& pfx;
    std::string& text;

    ~CredentialWipe()
    {
        pfx.wipe();
        secure_wipe(text);
    }
};

// The body's text with the credential in its two keys (every body has them,
// empty, next to each other). Built in one buffer reserved up front, so
// growing it frees no partial copy, and the body itself never holds the
// credential: `text` is its one copy here, wiped after the send. Standard
// Base64 needs no JSON escaping, so the values go in as they are; anything
// else (a quote, a backslash, a control or non-ASCII byte) is refused.
std::string with_credential(const ordered_json& body, const ExportedPfx& pfx)
{
    const auto plain_text = [](const std::string& value) {
        return std::ranges::all_of(value, [](char c) {
            return c >= 0x20 && c <= 0x7E && c != '"' && c != '\\';
        });
    };
    if (!plain_text(pfx.pfx_base64) || !plain_text(pfx.password)) {
        throw connector::Error("veeam_m365: the exported certificate or its password isn't "
                               "Base64; the restore was not sent");
    }
    constexpr std::string_view certificate = R"("applicationCertificate":")";
    constexpr std::string_view password = R"(","applicationCertificatePassword":")";
    // Unescaped quotes: a key of the body, never text inside a value.
    const std::string empty = std::string{certificate} + std::string{password} + "\"";
    const std::string plain = body.dump();
    const std::size_t at = plain.find(empty);
    if (at == std::string::npos || plain.find(empty, at + 1) != std::string::npos) {
        throw std::logic_error("veeam_m365: a restore body without its one pair of credential keys");
    }
    std::string text;
    text.reserve(plain.size() + pfx.pfx_base64.size() + pfx.password.size());
    text.append(plain, 0, at);
    text += certificate;
    text += pfx.pfx_base64;
    text += password;
    text += pfx.password;
    text.append(plain, at + empty.size() - 1);
    return text;
}

// One restore_sample call after layer 1 passed on a spec with items.
class RestoreRun {
public:
    struct Context {
        VeeamClient& client;
        const connector::RestoreSpec& spec;
        const CheckedTargets& checked;
        const TargetGuardOptions& guard_options;
        CertificateExporter* exporter;
        const std::function<std::chrono::system_clock::time_point()>& wall_now;
        const std::function<std::chrono::steady_clock::time_point()>& now;
        const std::function<void(std::chrono::milliseconds)>& sleep;
        const std::shared_ptr<spdlog::logger>& logger;
        const std::string& account;
        // Explore sessions list_candidates opened: never a duplicate restore.
        const std::set<std::string>& candidate_sessions;
    };

    explicit RestoreRun(Context context)
        : c_(context), sessions_({context.client, context.wall_now, context.logger,
                                  context.account, context.spec.restore_point.backup_time})
    {
        for (const std::string& id : context.candidate_sessions) {
            sessions_.know(id);
        }
    }
    RestoreRun(const RestoreRun&) = delete;
    RestoreRun& operator=(const RestoreRun&) = delete;

    connector::RestoreResult run();

    // When a restore may still be running: the sessions left open, for the
    // message of whatever ends the run.
    std::string left_open() const { return sessions_.left_open(); }

private:
    Organization organization();
    TypeWork resolve_mail();
    TypeWork resolve_sharepoint();
    TypeWork resolve_onedrive();
    void restore_call(const TypeWork& work, const std::vector<std::size_t>& call,
                      connector::RestoreResult& result);
    std::vector<std::string> target_texts(const TypeWork& work) const;
    vr::SessionState poll(const std::string& id, ItemKind kind);
    json statistics(const std::string& id);
    std::vector<vr::Event> events(const std::string& id);
    std::string no_verdict(const std::string& why) const;
    void warn(const std::string& line) const noexcept { veeam_explore::warn(c_.logger, line); }

    Context c_;
    vr::OrganizationFacts facts_;
    std::string thumbprint_;
    std::string organization_id_;
    bool all_succeeded_ = true;
    std::int64_t restored_ = 0;
    // Destroyed first: the finally path (step 13), which never throws, stops
    // the explore sessions unless a restore may still be running.
    veeam_explore::ExploreSessions sessions_;
};

std::string RestoreRun::no_verdict(const std::string& why) const
{
    return "veeam_m365: " + why + "; no verdict" + left_open();
}

Organization RestoreRun::organization()
{
    Organization org;
    try {
        org = find_organization(c_.client, c_.spec.client_ref);
    } catch (const connector::NotFoundError& e) {
        // In restore_sample, NotFoundError is a sampled item missing from the
        // restore point; a client Veeam doesn't know is the run's own error.
        throw connector::Error(std::string{"veeam_m365: "} + e.what() + "; nothing was restored");
    }
    const std::string which = "client " + shown(c_.spec.client_ref);
    if (!org.settings_problem.empty()) {
        throw connector::Error("veeam_m365: " + which +
                               ": Veeam's organisation settings are of an unexpected shape (" +
                               one_line(org.settings_problem) + "); nothing was restored");
    }
    if (!org.exchange_app || !org.sharepoint_app) {
        throw connector::Error("veeam_m365: " + which +
                               ": Veeam's organisation has no application for Exchange or "
                               "SharePoint, so there is no restore credential; nothing was "
                               "restored");
    }
    if (org.exchange_app->application_id != org.sharepoint_app->application_id ||
        !ascii_iequals(org.exchange_app->certificate_thumbprint,
                       org.sharepoint_app->certificate_thumbprint)) {
        throw connector::Error("veeam_m365: " + which +
                               ": Veeam's organisation uses different applications for Exchange "
                               "and SharePoint; nothing was restored");
    }
    facts_.application_id = org.exchange_app->application_id;
    facts_.organization_name = !org.office_name.empty() ? org.office_name : org.name;
    facts_.office_region = org.region;
    if (facts_.office_region.empty()) {
        throw connector::Error("veeam_m365: " + which +
                               ": Veeam's organisation has no region; nothing was restored");
    }
    thumbprint_ = org.exchange_app->certificate_thumbprint;
    organization_id_ = org.id;
    sessions_.set_organization(org.id, org.name);
    if (c_.exporter == nullptr) {
        throw connector::Error("veeam_m365: no certificate exporter, so the restore credential "
                               "can't be exported; nothing was restored");
    }
    return org;
}

TypeWork RestoreRun::resolve_mail()
{
    TypeWork work;
    work.kind = ItemKind::mail;
    work.explore = sessions_.open(ItemKind::mail);
    const std::string base = "/v8/RestoreSessions/" + work.explore + "/organization/mailboxes";
    const std::vector<json> mailboxes = c_.client.get_all(base);
    std::map<std::string, std::vector<json>> folders; // by mailbox and folder name
    std::map<std::string, std::vector<json>> items;   // by mailbox and folder ID
    for (std::size_t i = 0; i < c_.spec.mail.size(); ++i) {
        const connector::MailSelector& sel = c_.spec.mail[i];
        const std::string item = "mail item " + std::to_string(i) + " " + shown_text(sel.subject);
        // A user's in-place archive is listed as a second entry with the same
        // email and isArchive true: a sample's mailbox is the primary one.
        const json& mailbox =
            exactly_one(mailboxes, item, "mailbox " + shown_text(sel.mailbox), [&](const json& e) {
                const std::string* email = text_at(e, "email");
                const bool is_archive = veeam_browse::bool_at(e, "isArchive");
                return email != nullptr && ascii_iequals(*email, sel.mailbox) && !is_archive;
            });
        add_text(work.tenant_texts, mailbox, "name");
        add_text(work.tenant_texts, mailbox, "email");
        work.tenant_texts.push_back(sel.folder);
        const std::string mailbox_id = ascii_lower(id_of(mailbox));
        if (!is_uuid(mailbox_id)) {
            throw vr::ShapeError("a mailbox ID that isn't a UUID");
        }
        const std::string mailbox_path = base + "/" + mailbox_id;
        std::vector<json>& in_mailbox = folders[mailbox_id + "\n" + sel.folder];
        if (in_mailbox.empty()) {
            in_mailbox =
                c_.client.get_all(mailbox_path + "/folders?name=" + form_encode(sel.folder));
        }
        const json& folder =
            exactly_one(in_mailbox, item, "folder " + shown_text(sel.folder), [&](const json& e) {
                const std::string* name = text_at(e, "name");
                return name != nullptr && *name == sel.folder;
            });
        const std::string& folder_id = id_of(folder);
        std::vector<json>& listed = items[mailbox_id + "\n" + folder_id];
        if (listed.empty()) {
            listed = c_.client.get_all(mailbox_path + "/items?parentId=" +
                                       form_encode(folder_id));
        }
        const json& found = exactly_one(listed, item, "the message", [&](const json& e) {
            const std::string* subject = text_at(e, "subject");
            return subject != nullptr && *subject == sel.subject;
        });
        const std::string& id = id_of(found);
        if (!sel.received_at.empty()) {
            const std::string* received = text_at(found, "received");
            const std::optional<std::string> second =
                received != nullptr ? vr::to_whole_seconds(*received) : std::nullopt;
            if (!second || *second != sel.received_at) {
                throw connector::Error(
                    "veeam_m365: " + item + ": the restore point's copy was received at " +
                    shown_text(received != nullptr ? *received : std::string{"(none)"}) +
                    ", the sample says " + shown_text(sel.received_at));
            }
        }
        const json reread = c_.client.get_json(mailbox_path + "/items/" + form_encode(id));
        const std::string* subject = text_at(reread, "subject");
        if (subject == nullptr || *subject != sel.subject) {
            throw connector::Error("veeam_m365: " + item +
                                   ": the message read again has another subject");
        }
        work.items.push_back({i, mailbox_id, id, sel.subject, {}});
    }
    return work;
}

// Lists `parent`'s documents, finds `name` in them, re-reads it and checks it
// (restore-flow §4.4): shared by SharePoint and OneDrive.
Resolved resolve_document(VeeamClient& client, const std::string& container_path,
                          const std::string& parent, std::map<std::string, std::vector<json>>& cache,
                          const std::string& item, const std::string& name, std::int64_t size)
{
    std::vector<json>& listed = cache[container_path + "\n" + parent];
    if (listed.empty()) {
        listed = client.get_all(container_path + "/Documents?parentId=" + form_encode(parent));
    }
    const json& found = exactly_one(listed, item, "the file",
                                    [&](const json& e) { return is_file_named(e, name); });
    const std::string id = id_of(found);
    ordered_json reread = client.get_ordered_json(container_path + "/Documents/" +
                                                  form_encode(id));
    if (!reread.is_object()) {
        throw vr::ShapeError("a document that isn't an object");
    }
    const auto reread_id = reread.find("id");
    const auto reread_name = reread.find("name");
    if (reread_id == reread.end() || !reread_id->is_string() || *reread_id != id ||
        reread_name == reread.end() || !reread_name->is_string() || *reread_name != name) {
        throw connector::Error("veeam_m365: " + item +
                               ": the file read again has another ID or name");
    }
    if (size >= 0) {
        const auto bytes = reread.find("sizeBytes");
        if (bytes == reread.end() || !bytes->is_number_integer() ||
            bytes->get<std::int64_t>() != size) {
            throw connector::Error("veeam_m365: " + item +
                                   ": the restore point's copy isn't the size the sample says (" +
                                   std::to_string(size) + " bytes)");
        }
    }
    Resolved out;
    out.id = id;
    out.name = name;
    out.document = vr::body_document(std::move(reread));
    return out;
}

// Walks `segments` from `parent` through `container_path`/Folders?parentId=.
std::string walk_folders(VeeamClient& client, const std::string& container_path, std::string parent,
                         const std::vector<std::string>& segments,
                         std::map<std::string, std::vector<json>>& cache, const std::string& item)
{
    for (const std::string& segment : segments) {
        std::vector<json>& listed = cache[container_path + "\n" + parent];
        if (listed.empty()) {
            listed = client.get_all(container_path + "/Folders?parentId=" +
                                    form_encode(parent));
        }
        const json& folder =
            exactly_one(listed, item, "folder " + shown_text(segment), [&](const json& e) {
                const std::string* name = text_at(e, "name");
                return name != nullptr && *name == segment;
            });
        parent = id_of(folder);
    }
    return parent;
}

TypeWork RestoreRun::resolve_sharepoint()
{
    TypeWork work;
    work.kind = ItemKind::sharepoint;
    work.explore = sessions_.open(ItemKind::sharepoint);
    const std::string base = "/v8/RestoreSessions/" + work.explore + "/Organization/Sites/";
    std::set<std::string> sites_checked;
    std::map<std::string, std::vector<json>> libraries; // by site
    std::map<std::string, std::vector<json>> folders;   // by path and parent
    std::map<std::string, std::vector<json>> documents; // by path and parent
    for (std::size_t i = 0; i < c_.spec.sharepoint.size(); ++i) {
        const connector::SharePointSelector& sel = c_.spec.sharepoint[i];
        const std::string item = "sharepoint item " + std::to_string(i) + " " + shown_text(sel.name);
        const std::optional<std::string> site = vr::veeam_site_id(sel.site_id);
        if (!site) {
            throw connector::Error("veeam_m365: " + item + ": its site_id isn't a Graph site ID");
        }
        const std::string site_path = base + *site;
        if (sites_checked.insert(*site).second) {
            const json listed = c_.client.get_json(site_path);
            const std::string* id = text_at(listed, "id");
            if (id == nullptr || !ascii_iequals(*id, *site)) {
                throw connector::Error("veeam_m365: " + item +
                                       ": Veeam answered for another site than its site_id");
            }
            add_text(work.tenant_texts, listed, "name");
            add_text(work.tenant_texts, listed, "url");
        }
        std::vector<json>& in_site = libraries[*site];
        if (in_site.empty()) {
            in_site = c_.client.get_all(site_path + "/Libraries");
        }
        const std::string library = *site + ascii_lower(sel.list_id);
        exactly_one(in_site, item, "the library of list " + shown_text(sel.list_id),
                    [&](const json& e) { return ascii_iequals(id_of(e), library); });
        const std::vector<std::string> segments = vr::path_segments(sel.folder_path);
        work.tenant_texts.insert(work.tenant_texts.end(), segments.begin(), segments.end());
        const std::string parent =
            walk_folders(c_.client, site_path, library, segments, folders, item);
        Resolved found = resolve_document(c_.client, site_path, parent, documents, item,
                                          sel.name, sel.size);
        found.index = i;
        found.container = *site;
        work.items.push_back(std::move(found));
    }
    return work;
}

TypeWork RestoreRun::resolve_onedrive()
{
    TypeWork work;
    work.kind = ItemKind::onedrive;
    work.explore = sessions_.open(ItemKind::onedrive);
    const std::string base = "/v8/RestoreSessions/" + work.explore + "/Organization/OneDrives";
    const std::vector<json> onedrives = c_.client.get_all(base);

    // The target: the test OneDrive the guard resolved, as Veeam lists it.
    const graph::ResolvedOneDriveFolder& folder = *c_.checked.onedrive_folder();
    const std::string target_id = folder.site_id + folder.web_id;
    const auto is_target = [&](const json& e) {
        const std::string* url = text_at(e, "url");
        return url != nullptr && ascii_iequals(*url, folder.site_url) &&
               ascii_iequals(id_of(e), target_id);
    };
    // Not a sampled item: a target missing from the restore point is the
    // run's own error (connector::Error), never NotFoundError. One at most
    // matches: get_all lists each ID once, and the ID is part of the match.
    const auto target = std::ranges::find_if(onedrives, is_target);
    if (target == onedrives.end()) {
        throw connector::Error("veeam_m365: the restore target: the test OneDrive " +
                               shown_text(folder.site_url) +
                               " isn't in the restore point (is it backed up?); nothing was "
                               "restored");
    }
    const std::string* target_name = text_at(*target, "name");
    if (target_name == nullptr) {
        throw vr::ShapeError("a OneDrive without a \"name\"");
    }
    work.target_onedrive["id"] = id_of(*target);
    work.target_onedrive["name"] = *target_name;
    work.target_onedrive["url"] = *text_at(*target, "url");

    const std::string host = parse_graph_site_id(c_.spec.targets.site_id())->host;
    std::map<std::string, std::vector<json>> folders;   // by path and parent
    std::map<std::string, std::vector<json>> documents; // by path and parent
    for (std::size_t i = 0; i < c_.spec.onedrive.size(); ++i) {
        const connector::OneDriveSelector& sel = c_.spec.onedrive[i];
        const std::string item = "onedrive item " + std::to_string(i) + " " + shown_text(sel.name);
        const std::optional<std::string> url = vr::onedrive_url(host, sel.user);
        if (!url) {
            throw connector::Error("veeam_m365: " + item + ": no OneDrive address for its owner");
        }
        const json& source =
            exactly_one(onedrives, item, "the OneDrive of " + shown_text(sel.user), [&](const json& e) {
                const std::string* listed = text_at(e, "url");
                return listed != nullptr && ascii_iequals(*listed, *url);
            });
        add_text(work.tenant_texts, source, "name");
        add_text(work.tenant_texts, source, "url");
        const std::string onedrive = ascii_lower(id_of(source));
        if (!vr::is_uuid_run(onedrive)) {
            throw vr::ShapeError("a OneDrive ID that isn't UUIDs");
        }
        const std::string od_path = base + "/" + onedrive;
        const std::vector<std::string> segments = vr::path_segments(sel.folder_path);
        work.tenant_texts.insert(work.tenant_texts.end(), segments.begin(), segments.end());
        const std::string parent = walk_folders(c_.client, od_path, "root", segments, folders, item);
        Resolved found = resolve_document(c_.client, od_path, parent, documents, item, sel.name,
                                          sel.size);
        found.index = i;
        found.container = onedrive;
        work.items.push_back(std::move(found));
    }
    return work;
}

// The targets' names as this type's messages may quote them.
std::vector<std::string> RestoreRun::target_texts(const TypeWork& work) const
{
    std::vector<std::string> out = work.tenant_texts;
    switch (work.kind) {
    case ItemKind::mail:
        out.push_back(c_.checked.mailbox()->address);
        break;
    case ItemKind::sharepoint:
        out.push_back(c_.checked.library()->site_url);
        out.push_back(c_.checked.library()->name);
        break;
    case ItemKind::onedrive:
        out.push_back(c_.checked.onedrive_folder()->name);
        for (const char* key : {"name", "url"}) {
            if (const auto it = work.target_onedrive.find(key);
                it != work.target_onedrive.end() && it->is_string()) {
                out.push_back(it->get<std::string>());
            }
        }
        break;
    }
    return out;
}

vr::SessionState RestoreRun::poll(const std::string& id, ItemKind kind)
{
    const std::string path = "/v8/RestoreSessions/" + id;
    const std::string which =
        "restore session " + id + " (" + std::string{connector::to_string(kind)} + ")";
    const auto deadline = c_.now() + vr::kPollDeadline;
    int failures = 0;
    for (;;) {
        try {
            const json session = c_.client.get_json(path);
            failures = 0;
            vr::SessionState state = vr::read_session(session);
            if (state.state == "Stopped") {
                return state;
            }
        } catch (const NotFoundError& e) {
            throw connector::Error(no_verdict(which + " is gone (" + e.what() + ")"));
        } catch (const VeeamError& e) {
            if (e.status() == 404) {
                throw connector::Error(no_verdict(which + " is gone (" + e.what() + ")"));
            }
            if (++failures == vr::kMaxPollFailures) {
                throw connector::Error(no_verdict(which + ": " +
                                                  std::to_string(vr::kMaxPollFailures) +
                                                  " polls failed in a row, the last: " + e.what()));
            }
        }
        if (c_.now() >= deadline) {
            throw connector::TransientError(no_verdict(which + " still Working after 20 minutes"));
        }
        c_.sleep(vr::kPollInterval);
    }
}

json RestoreRun::statistics(const std::string& id)
{
    const std::string path = "/v8/RestoreSessions/" + id + "/Statistics";
    for (int attempt = 1;; ++attempt) {
        try {
            return c_.client.get_json(path);
        } catch (const AuthError&) {
            throw;
        } catch (const VeeamError& e) {
            if (e.status() != 409) {
                // The restore ran: neither a missing item nor "try again".
                throw connector::Error("veeam_m365: restore session " + id +
                                       " stopped, but its statistics couldn't be read: " +
                                       e.what() + "; no verdict" + left_open());
            }
            if (attempt == vr::kStatisticsAttempts) {
                throw connector::Error("veeam_m365: restore session " + id +
                                       " stopped, but its statistics still weren't ready after " +
                                       std::to_string(vr::kStatisticsAttempts) +
                                       " attempts; no verdict" + left_open());
            }
        }
        c_.sleep(vr::kStatisticsWait);
    }
}

std::vector<vr::Event> RestoreRun::events(const std::string& id)
{
    // VeeamClient's paging: each event once, and a page Veeam caps below the
    // limit asked for isn't taken for the last.
    json page = json::object();
    try {
        page["results"] = c_.client.get_all("/v8/RestoreSessions/" + id + "/Events");
    } catch (const AuthError&) {
        throw;
    } catch (const VeeamError& e) {
        // As for the statistics: the restore ran.
        throw connector::Error("veeam_m365: restore session " + id +
                               " stopped, but its events couldn't be read: " + e.what() +
                               "; no verdict" + left_open());
    }
    return vr::read_events(page);
}

void RestoreRun::restore_call(const TypeWork& work, const std::vector<std::size_t>& call,
                              connector::RestoreResult& result)
{
    const std::string& container = work.items[call.front()].container;
    veeam::RestoreRequestContext ctx;
    ctx.kind = guard_kind(work.kind);
    ctx.opened_explore_sessions = sessions_.opened();
    ctx.container_id = container;
    ctx.application_id = facts_.application_id;
    ctx.organization_name = facts_.organization_name;
    ctx.office_region = facts_.office_region;
    std::string path = "/v8/RestoreSessions/" + work.explore;
    ordered_json body;
    std::vector<vr::SentItem> sent;
    switch (work.kind) {
    case ItemKind::mail: {
        std::vector<std::string> ids;
        for (const std::size_t i : call) {
            ids.push_back(work.items[i].id);
            ctx.items.push_back({work.items[i].id, ""});
            sent.push_back({work.items[i].name, work.items[i].id});
        }
        path += "/organization/mailboxes/" + container + "/items/restoreTo";
        body = vr::mail_body(ids, c_.checked.mailbox()->address, facts_);
        break;
    }
    case ItemKind::sharepoint:
    case ItemKind::onedrive: {
        std::vector<ordered_json> documents;
        for (const std::size_t i : call) {
            documents.push_back(work.items[i].document);
            ctx.items.push_back({work.items[i].id, work.items[i].name});
            sent.push_back({work.items[i].name, work.items[i].id});
        }
        if (work.kind == ItemKind::sharepoint) {
            path += "/Organization/Sites/" + container + "/Documents/restoreTo";
            body = vr::sharepoint_body(std::move(documents), c_.checked.library()->site_url,
                                       c_.checked.library()->name, facts_);
        } else {
            ctx.target_onedrive_id = work.target_onedrive.at("id").get<std::string>();
            ctx.target_onedrive_name = work.target_onedrive.at("name").get<std::string>();
            ctx.target_onedrive_url = work.target_onedrive.at("url").get<std::string>();
            path += "/Organization/OneDrives/" + container + "/Documents/copyTo";
            body = vr::onedrive_body(std::move(documents), work.target_onedrive,
                                     c_.checked.onedrive_folder()->name, facts_);
        }
        break;
    }
    }

    // The credential: exported now, spliced into the body's text once,
    // checked and sent as that exact text, then wiped (docs/decisions.md
    // 2026-09-30 W2.5 point 1, and its W2.5 review entry for the copies
    // out of reach).
    ExportedPfx pfx;
    std::string text;
    VeeamClient::RestorePostOutcome outcome;
    std::chrono::system_clock::time_point posted;
    {
        const CredentialWipe wipe{pfx, text};
        try {
            pfx = c_.exporter->export_pfx(thumbprint_);
        } catch (const CertExportError& e) {
            throw connector::Error(std::string{"veeam_m365: "} + e.what() +
                                   "; the restore was not sent");
        }
        text = with_credential(body, pfx);
        veeam::check_restore_request(c_.checked, ctx, path, text, c_.guard_options);
        posted = c_.wall_now();
        outcome = c_.client.post_restore_once(path, text, vr::kPostTimeout);
    }

    const std::string kind_name{connector::to_string(work.kind)};
    std::string id;
    bool confirmed = false;
    switch (outcome.kind) {
    case VeeamClient::RestorePostOutcome::Kind::refused:
        // As VeeamClient classifies any other answer (restore-flow §15).
        if (outcome.status == 401 || outcome.status == 403 ||
            outcome.error_code == "ResourceAccessDenied") {
            throw connector::AuthError("veeam_m365: " + outcome.message +
                                       "; Veeam started no restore");
        }
        throw connector::Error("veeam_m365: " + outcome.message + "; Veeam started no restore");
    case VeeamClient::RestorePostOutcome::Kind::not_sent:
        // Nothing went out, so nothing runs: the explore sessions are closed.
        throw connector::TransientError("veeam_m365: " + outcome.message +
                                        "; the restore was not sent");
    case VeeamClient::RestorePostOutcome::Kind::accepted:
        id = outcome.session_id;
        sessions_.keep_open(true, id);
        try {
            const std::vector<std::string> found = sessions_.duplicates(work.kind, posted);
            confirmed = found.size() == 1 && found.front() == id;
        } catch (const std::exception& e) {
            warn("veeam_m365: the duplicate check after restore session " + id + " failed: " +
                 e.what());
        }
        if (!confirmed) {
            warn("veeam_m365: the duplicate check didn't list restore session " + id +
                 " alone; it is polled, but gets no verdict");
        }
        break;
    case VeeamClient::RestorePostOutcome::Kind::no_answer: {
        sessions_.keep_open(true);
        warn(outcome.message + "; looking for the restore session instead of sending again");
        std::vector<std::string> found;
        try {
            found = sessions_.duplicates(work.kind, posted);
            for (int look = 0; found.empty() && look < vr::kDuplicateRelooks; ++look) {
                c_.sleep(vr::kDuplicateRelookWait);
                found = sessions_.duplicates(work.kind, posted);
            }
        } catch (const std::exception& e) {
            // Whatever failed (a lost sign-in, Veeam restarting, a 404), a
            // restore may be running: no verdict, never a retryable error.
            throw connector::Error(no_verdict("the " + kind_name + " restore POST got no answer (" +
                                              outcome.message + ") and the duplicate check failed (" +
                                              e.what() + "); it was not sent again"));
        }
        if (found.size() != 1) {
            throw connector::Error(no_verdict(
                "the " + kind_name + " restore POST got no answer (" + outcome.message +
                ") and the duplicate check found " + std::to_string(found.size()) +
                " candidate sessions; it was not sent again"));
        }
        id = found.front();
        sessions_.keep_open(true, id);
        confirmed = true;
        break;
    }
    }
    sessions_.know(id);

    const vr::SessionState session = poll(id, work.kind);
    // Stopped: ours runs no more. Only when the duplicate check listed it
    // alone does nothing else of ours run under the explore sessions; else
    // another candidate may, and they stay open (decisions point 8).
    sessions_.keep_open(!confirmed);
    if (session.result.empty()) {
        throw vr::ShapeError("a stopped session without a \"result\"");
    }
    const vr::Statistics stats = vr::read_statistics(statistics(id));
    const std::vector<vr::Event> seen = events(id);
    vr::SessionVerdict verdict =
        vr::judge(work.kind, id, session, stats, seen, sent, target_texts(work));

    connector::RestoreSessionResult record;
    record.id = id;
    record.kind = work.kind;
    record.result = one_line(session.result);
    record.details = one_line(session.details);
    record.started_at = one_line(session.creation_time);
    record.ended_at = one_line(session.end_time);
    record.items_sent = static_cast<int>(call.size());
    record.items_restored = static_cast<int>(std::min<std::int64_t>(stats.restored, std::numeric_limits<int>::max()));
    result.session_ids.push_back(id);
    result.sessions.push_back(record);
    for (const std::string& line : verdict.log_lines) {
        result.log += line + "\n";
    }
    const std::size_t offset = work.kind == ItemKind::mail ? 0
                               : work.kind == ItemKind::sharepoint
                                   ? c_.spec.mail.size()
                                   : c_.spec.mail.size() + c_.spec.sharepoint.size();
    for (std::size_t n = 0; n < call.size(); ++n) {
        result.items[offset + work.items[call[n]].index] = std::move(verdict.items[n]);
    }
    all_succeeded_ = all_succeeded_ && verdict.succeeded;
    restored_ += stats.restored;

    if (stats.restored == 0 && verdict.infrastructure) {
        throw connector::Error("veeam_m365: restore session " + id + " (" + kind_name +
                               ") restored nothing: " + verdict.infrastructure_text +
                               left_open());
    }
    if (!confirmed) {
        throw connector::Error(no_verdict("restore session " + id + " (" + kind_name +
                                          ") ran, but the duplicate check didn't list it alone, "
                                          "so another restore can't be ruled out"));
    }
}

connector::RestoreResult RestoreRun::run()
{
    organization();
    veeam_explore::check_restore_point(c_.client, organization_id_, c_.spec.client_ref,
                                       c_.spec.restore_point, "nothing was restored");
    veeam_explore::preflight(c_.client, c_.account, "nothing was restored");
    std::vector<TypeWork> work;
    if (!c_.spec.mail.empty()) {
        work.push_back(resolve_mail());
    }
    if (!c_.spec.sharepoint.empty()) {
        work.push_back(resolve_sharepoint());
    }
    if (!c_.spec.onedrive.empty()) {
        work.push_back(resolve_onedrive());
    }

    // Two selectors of one item would restore it twice, in two calls.
    for (const TypeWork& type : work) {
        for (std::size_t later = 1; later < type.items.size(); ++later) {
            for (std::size_t earlier = 0; earlier < later; ++earlier) {
                const Resolved& a = type.items[earlier];
                const Resolved& b = type.items[later];
                if (a.container == b.container && a.id == b.id) {
                    const std::string kind{connector::to_string(type.kind)};
                    throw connector::Error("veeam_m365: " + kind + " item " +
                                           std::to_string(b.index) + " " + shown_text(b.name) +
                                           " is the same item in the restore point as " + kind +
                                           " item " + std::to_string(a.index) +
                                           "; nothing was restored");
                }
            }
        }
    }

    connector::RestoreResult result;
    for (const connector::MailSelector& sel : c_.spec.mail) {
        result.items.push_back({ItemKind::mail, sel.subject, {}, {}, {}, false});
    }
    for (const connector::SharePointSelector& sel : c_.spec.sharepoint) {
        result.items.push_back({ItemKind::sharepoint, sel.name, {}, {}, {}, false});
    }
    for (const connector::OneDriveSelector& sel : c_.spec.onedrive) {
        result.items.push_back({ItemKind::onedrive, sel.name, {}, {}, {}, false});
    }
    for (const TypeWork& type : work) {
        std::vector<std::string> containers;
        std::vector<std::string> names;
        for (const Resolved& item : type.items) {
            containers.push_back(item.container);
            names.push_back(item.name);
        }
        for (const std::vector<std::size_t>& call : vr::split_calls(containers, names)) {
            restore_call(type, call, result);
        }
    }
    result.items_sent = static_cast<int>(c_.spec.item_count());
    result.items_restored = static_cast<int>(std::min<std::int64_t>(restored_, std::numeric_limits<int>::max()));
    result.status = vr::overall_status(result.sessions.size(), restored_, all_succeeded_);
    return result;
}

} // namespace

VeeamM365Connector::VeeamM365Connector(std::unique_ptr<IHttpClient> http, std::string base_url,
                                       std::string username, std::string password,
                                       VeeamM365ConnectorOptions options)
    : http_(std::move(http)), graph_http_(std::move(options.graph_http)),
      graph_(std::move(options.graph)), make_graph_(std::move(options.make_graph)),
      guard_options_(std::move(options.guard)),
      cert_exporter_(std::move(options.cert_exporter)), wall_now_(std::move(options.wall_now)),
      logger_(options.client.logger), account_(vr::bare_account(username))
{
    if (!http_) {
        throw std::invalid_argument("veeam_m365: no HTTP client");
    }
    // restore_sample's clock and wait are the client's, so a test drives both.
    if (!options.client.now) {
        options.client.now = [] { return std::chrono::steady_clock::now(); };
    }
    if (!options.client.sleep) {
        options.client.sleep = [](std::chrono::milliseconds wait) {
            std::this_thread::sleep_for(wait);
        };
    }
    if (!wall_now_) {
        wall_now_ = [] { return std::chrono::system_clock::now(); };
    }
    now_ = options.client.now;
    sleep_ = options.client.sleep;
    client_ = std::make_unique<VeeamClient>(*http_, std::move(base_url), std::move(username),
                                            std::move(password), std::move(options.client));
}

VeeamM365Connector::~VeeamM365Connector()
{
    client_->logout();
}

connector::ConnectorInfo VeeamM365Connector::describe() const
{
    return {std::string{connector::kVeeamM365}, std::string{kApiVersion}};
}

std::vector<connector::RestorePoint> VeeamM365Connector::list_restore_points(
    const std::string& client_ref)
{
    if (client_ref.empty()) {
        throw std::invalid_argument("veeam_m365: the client reference is empty");
    }
    // VeeamError's what() went through rp::redact(), so it is passed on as it is.
    try {
        const Organization org = find_organization(*client_, client_ref);
        const std::vector<RestorePoint> points = client_->list_restore_points(org.id);
        std::vector<connector::RestorePoint> out;
        out.reserve(points.size());
        std::ranges::transform(points, std::back_inserter(out), to_connector);
        return out;
    } catch (const AuthError& e) {
        throw connector::AuthError(e.what());
    } catch (const TransientError& e) {
        throw connector::TransientError(e.what());
    } catch (const NotFoundError& e) {
        throw connector::NotFoundError(e.what());
    } catch (const VeeamError& e) {
        throw connector::Error(e.what());
    }
}

connector::RestoreResult VeeamM365Connector::restore_sample(const connector::RestoreSpec& spec)
{
    // The guard is the first line (W2.7, #32): nothing reaches Veeam before
    // layer 1 passed. Its SafetyViolation passes out as it is: status `error`,
    // exit code 4, never `fail`.
    if (!graph_ && make_graph_) {
        VeeamM365GraphParts parts = make_graph_();
        if (parts.client) {
            graph_http_ = std::move(parts.http);
            graph_ = std::move(parts.client);
            // Its copies of the Worker app's certificate go with it.
            make_graph_ = nullptr;
        }
    }
    if (!graph_) {
        throw connector::Error(
            "veeam_m365: no Graph client, so the target guard can't run; nothing was restored");
    }
    std::optional<CheckedTargets> checked;
    try {
        checked.emplace(TargetGuard(*graph_, guard_options_).check_spec(spec));
    } catch (const graph::AuthError& e) {
        throw connector::AuthError(e.what());
    } catch (const graph::PermissionError& e) {
        throw connector::AuthError(e.what());
    } catch (const graph::TransientError& e) {
        throw connector::TransientError(e.what());
    } catch (const graph::GraphError& e) {
        // A NotFoundError among them: a restore target Graph can't find is a
        // configuration problem, not an item missing from the backup.
        throw connector::Error(e.what());
    }
    if (spec.item_count() == 0) {
        return {};
    }
    if (spec.client_ref.empty()) {
        throw std::invalid_argument("veeam_m365: the client reference is empty");
    }
    if (!vr::parse_veeam_time(spec.restore_point.backup_time)) {
        throw std::invalid_argument(
            "veeam_m365: the restore point's backup time isn't Veeam's UTC form, such as "
            "2026-09-25T19:37:15.2145203Z");
    }

    // restoreTo and copyTo drop the source path (restore-flow §12): two files
    // of one name, from any folders or sources, land on one target file, the
    // second a new version of the first, and the read-back sees only it.
    const auto one_name_each = [](std::string_view kind, const auto& selectors) {
        for (std::size_t later = 1; later < selectors.size(); ++later) {
            for (std::size_t earlier = 0; earlier < later; ++earlier) {
                if (ascii_iequals(selectors[earlier].name, selectors[later].name)) {
                    throw connector::Error(
                        "veeam_m365: " + std::string{kind} + " items " + std::to_string(earlier) +
                        " and " + std::to_string(later) + " are both named " +
                        shown_text(selectors[earlier].name) +
                        " (ignoring case), and would be restored onto one file in the restore "
                        "target; restore them in separate runs; nothing was restored");
                }
            }
        }
    };
    one_name_each("sharepoint", spec.sharepoint);
    one_name_each("onedrive", spec.onedrive);

    RestoreRun run({*client_, spec, *checked, guard_options_, cert_exporter_.get(), wall_now_,
                    now_, sleep_, logger_, account_, candidate_sessions_});
    // Veeam's errors as list_restore_points maps them but for a 404, naming
    // what was left open if a restore may still be running. In restore_sample
    // connector::NotFoundError means a sampled item isn't in the restore point
    // (browsing throws it), so Veeam's own 404 (an expired session, a
    // vanished organisation) is connector::Error. Connector errors (the
    // guard's SafetyViolation among them) pass through as they are.
    try {
        return run.run();
    } catch (const AuthError& e) {
        throw connector::AuthError(e.what() + run.left_open());
    } catch (const TransientError& e) {
        throw connector::TransientError(e.what() + run.left_open());
    } catch (const VeeamError& e) {
        throw connector::Error(e.what() + run.left_open());
    } catch (const vr::ShapeError& e) {
        throw connector::Error(std::string{"veeam_m365: unexpected response from Veeam: "} +
                               e.what() + run.left_open());
    } catch (const nlohmann::json::exception& e) {
        throw connector::Error(std::string{"veeam_m365: unexpected response from Veeam: "} +
                               e.what() + run.left_open());
    }
}

std::unique_ptr<connector::IConnector> make_veeam_m365_connector(
    const Config& config, const Secrets& secrets, const connector::ConnectorOptions& options)
{
    if (!is_set(secrets.veeam_username)) {
        throw ConfigError(std::string{kEnvVeeamUsername},
                          std::string{kEnvVeeamUsername} + " is not set");
    }
    if (!is_set(secrets.veeam_password)) {
        throw ConfigError(std::string{kEnvVeeamPassword},
                          std::string{kEnvVeeamPassword} + " is not set");
    }
    // Never spdlog's default logger, which writes to stdout.
    const std::shared_ptr<spdlog::logger> logger =
        options.logger ? options.logger : make_command_logger();
    const auto wall_now = options.wall_now
                              ? options.wall_now
                              : std::function<std::chrono::system_clock::time_point()>{[] {
                                    return std::chrono::system_clock::now();
                                }};

    HttpClientOptions http_options;
    // TLS is never off: the CA file and the pin only choose what to trust.
    http_options.ca_file = config.veeam_ca_file;
    http_options.pinned_cert_sha256 = config.veeam_cert_sha256;
    http_options.logger = logger;
    http_options.sleep = options.sleep;
    http_options.jitter = options.jitter;
    std::unique_ptr<IHttpClient> http = options.make_http
                                            ? options.make_http(http_options)
                                            : std::make_unique<HttpClient>(http_options);

    VeeamM365ConnectorOptions connector_options;
    // The Graph client, on the first restore_sample: the Worker app's
    // certificate and IDs first, before any HTTP client is made (a
    // CertificateError, a ConfigError, keyed by the variable when one is
    // unset, or a Graph ID that isn't a GUID stops there).
    connector_options.make_graph = [tenant_id = config.graph_tenant_id,
                                    client_id = config.graph_client_id, secrets, logger, wall_now,
                                    options]() -> VeeamM365GraphParts {
        graph::ClientCertificate certificate =
            graph::certificate_from_secrets(secrets, wall_now(), logger);
        if (!is_uuid(tenant_id)) {
            throw ConfigError("graph_tenant_id", "graph_tenant_id is not a GUID");
        }
        if (!is_uuid(client_id)) {
            throw ConfigError("graph_client_id", "graph_client_id is not a GUID");
        }
        VeeamM365GraphParts parts;
        parts.http = options.make_graph_http ? options.make_graph_http(logger)
                                             : graph::make_graph_http_client(logger);
        if (!parts.http) {
            throw std::invalid_argument("veeam_m365: no Graph HTTP client");
        }
        graph::GraphClientOptions graph_options;
        graph_options.logger = logger;
        graph_options.now = options.now;
        graph_options.wall_now = wall_now;
        graph_options.sleep = options.sleep;
        graph_options.jitter = options.jitter;
        // The connector keeps parts.http alive as long as the client on it.
        parts.client = std::make_shared<graph::GraphClient>(
            *parts.http, tenant_id, client_id, std::move(certificate), std::move(graph_options));
        return parts;
    };
    connector_options.guard.logger = logger;
    connector_options.cert_exporter = options.cert_exporter
                                          ? options.cert_exporter
                                          : make_local_machine_cert_exporter(wall_now);
    connector_options.wall_now = wall_now;
    connector_options.client.logger = logger;
    connector_options.client.now = options.now;
    connector_options.client.sleep = options.sleep;
    connector_options.client.jitter = options.jitter;
    return std::make_unique<VeeamM365Connector>(std::move(http), config.veeam_url,
                                                *secrets.veeam_username, *secrets.veeam_password,
                                                std::move(connector_options));
}

} // namespace rp
