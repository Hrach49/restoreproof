#include <rp/veeam_m365_connector.hpp>

#include <rp/client_assertion.hpp>
#include <rp/graph_errors.hpp>
#include <rp/redact.hpp>
#include <rp/target_guard_veeam.hpp>

#include "command_config.hpp"
#include "control_chars.hpp"
#include "json_fields.hpp"
#include "text_util.hpp"
#include "uuid.hpp"
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

// A client reference as error messages show it: each control character
// (control_chars.hpp), which could forge, hide or reorder a log or stderr
// line, becomes a space. client_ref will come from a Cloud job (C5.6).
std::string shown(std::string_view client_ref)
{
    std::string out;
    out.reserve(client_ref.size());
    for (std::size_t i = 0; i < client_ref.size();) {
        if (const std::size_t length = control_character_length(client_ref, i); length != 0) {
            out += ' ';
            i += length;
        } else {
            out += client_ref[i];
            ++i;
        }
    }
    return out;
}

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

// The organisation named `client_ref` (ASCII case-insensitive), exactly one,
// with a UUID. Throws connector errors for the rest; Veeam's pass through.
Organization find_organization(VeeamClient& client, const std::string& client_ref)
{
    std::vector<Organization> matches;
    for (Organization& org : client.list_organizations()) {
        if (ascii_iequals(org.name, client_ref)) {
            matches.push_back(std::move(org));
        }
    }
    if (matches.empty()) {
        throw connector::NotFoundError("client " + shown(client_ref) + " not found in Veeam");
    }
    if (matches.size() > 1) {
        throw connector::Error("client " + shown(client_ref) + " matches " +
                               std::to_string(matches.size()) + " organisations in Veeam");
    }
    // VeeamClient would refuse it with std::invalid_argument; checked here
    // so that only this case reads as Veeam's fault.
    if (!is_uuid(matches.front().id)) {
        throw connector::Error("Veeam returned an organisation ID for client " +
                               shown(client_ref) + " that isn't a UUID");
    }
    return std::move(matches.front());
}

// A name, subject or selector value as a message shows it: one line, short.
std::string shown_text(std::string_view text)
{
    return "\"" + one_line(text, 120) + "\"";
}

// The string at `key` of a Veeam object; nullptr when it is missing or null,
// ShapeError for another kind.
const std::string* text_at(const json& object, std::string_view key)
{
    if (!object.is_object()) {
        throw vr::ShapeError("an entry that isn't an object");
    }
    const auto it = object.find(key);
    if (it == object.end() || it->is_null()) {
        return nullptr;
    }
    if (!it->is_string()) {
        throw vr::ShapeError("\"" + std::string{key} + "\" isn't a string");
    }
    return it->get_ptr<const std::string*>();
}

// An entry's "id" (get_all made sure there is one).
const std::string& id_of(const json& entry)
{
    return entry.at("id").get_ref<const std::string&>();
}

// The one entry of `list` that `match` picks; none is NotFoundError, several
// connector::Error, both naming `item` and what was looked for.
template <class Match>
const json& exactly_one(const std::vector<json>& list, const std::string& item,
                        const std::string& looked_for, Match match)
{
    std::vector<const json*> found;
    for (const json& entry : list) {
        if (match(entry)) {
            found.push_back(&entry);
        }
    }
    if (found.empty()) {
        throw connector::NotFoundError("veeam_m365: " + item + ": " + looked_for +
                                       " not found in the restore point");
    }
    if (found.size() > 1) {
        throw connector::Error("veeam_m365: " + item + ": " + looked_for + " matches " +
                               std::to_string(found.size()) + " entries in the restore point");
    }
    return *found.front();
}

// A document entry named `name` that isn't a folder.
bool is_file_named(const json& entry, const std::string& name)
{
    const std::string* entry_name = text_at(entry, "name");
    const auto folder = entry.find("isFolder");
    if (folder != entry.end() && !folder->is_null() && !folder->is_boolean()) {
        throw vr::ShapeError("\"isFolder\" isn't a boolean");
    }
    return entry_name != nullptr && *entry_name == name && folder != entry.end() &&
           folder->is_boolean() && !folder->get<bool>();
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
};

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
    ordered_json& body;

    ~CredentialWipe()
    {
        pfx.wipe();
        secure_wipe(text);
        wipe_body(body);
    }

    static void wipe_body(ordered_json& body) noexcept
    {
        for (const char* key : {"applicationCertificate", "applicationCertificatePassword"}) {
            const auto it = body.find(key);
            if (it != body.end() && it->is_string()) {
                secure_wipe(it->get_ref<std::string&>());
            }
        }
    }
};

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
    };

    explicit RestoreRun(Context context) : c_(context) {}
    RestoreRun(const RestoreRun&) = delete;
    RestoreRun& operator=(const RestoreRun&) = delete;

    // The finally path (step 13): never throws.
    ~RestoreRun() { close_explore_sessions(); }

    connector::RestoreResult run();

    // When a restore may still be running: the sessions left open, for the
    // message of whatever ends the run.
    std::string left_open() const
    {
        if (!restore_may_run_) {
            return {};
        }
        std::string out = "; left open, as a restore may still be running:";
        if (!running_session_.empty()) {
            out += " restore session " + running_session_ + ",";
        }
        out += " explore session(s)";
        for (const std::string& id : opened_) {
            out += " " + id;
        }
        return out;
    }

private:
    Organization organization();
    void preflight();
    TypeWork resolve_mail();
    TypeWork resolve_sharepoint();
    TypeWork resolve_onedrive();
    std::string open_explore(ItemKind kind);
    void restore_call(const TypeWork& work, const std::vector<std::size_t>& call,
                      connector::RestoreResult& result);
    std::vector<std::string> duplicates(ItemKind kind,
                                        std::chrono::system_clock::time_point posted);
    vr::SessionState poll(const std::string& id, ItemKind kind);
    json statistics(const std::string& id);
    std::vector<vr::Event> events(const std::string& id);
    std::string no_verdict(const std::string& why) const;
    void warn(const std::string& line) const noexcept;
    void close_explore_sessions() noexcept;

    Context c_;
    vr::OrganizationFacts facts_;
    std::string thumbprint_;
    std::string organization_id_;
    std::vector<std::string> opened_;  // explore sessions, in order
    std::set<std::string> known_;      // every session ID this run knows
    bool restore_may_run_ = false;
    std::string running_session_;
    bool all_succeeded_ = true;
    std::int64_t restored_ = 0;
};

void RestoreRun::warn(const std::string& line) const noexcept
{
    try {
        const std::shared_ptr<spdlog::logger> logger =
            c_.logger ? c_.logger : spdlog::default_logger();
        if (logger) {
            logger->warn("{}", redact(one_line(line)));
        }
    } catch (...) { // NOLINT(bugprone-empty-catch): logging is best effort
    }
}

void RestoreRun::close_explore_sessions() noexcept
{
    if (restore_may_run_) {
        warn("veeam_m365: explore session(s) left open" + left_open());
        return;
    }
    for (const std::string& id : opened_) {
        try {
            const json session = c_.client.get_json("/v8/RestoreSessions/" + id);
            const std::string* state = string_at(session, "state");
            if (state != nullptr && *state == "Working") {
                c_.client.stop_session(id);
            }
        } catch (const std::exception& e) {
            warn("veeam_m365: couldn't close explore session " + id + ": " + e.what());
        }
    }
}

std::string RestoreRun::no_verdict(const std::string& why) const
{
    return "veeam_m365: " + why + "; no verdict" + left_open();
}

Organization RestoreRun::organization()
{
    Organization org = find_organization(c_.client, c_.spec.client_ref);
    const std::string which = "client " + shown(c_.spec.client_ref);
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
    if (c_.exporter == nullptr) {
        throw connector::Error("veeam_m365: no certificate exporter, so the restore credential "
                               "can't be exported; nothing was restored");
    }
    return org;
}

void RestoreRun::preflight()
{
    const json list = c_.client.get_json("/v8/RestoreSessions?limit=" +
                                         std::to_string(vr::kPreflightLimit));
    const std::vector<std::string> working = vr::working_sessions(list, c_.account);
    if (!working.empty()) {
        std::string ids;
        for (const std::string& id : working) {
            ids += (ids.empty() ? "" : ", ") + id;
        }
        throw connector::Error("veeam_m365: Veeam has restore sessions of " + one_line(c_.account) +
                               " still Working (" + ids +
                               "); stop them first (docs/api/veeam-m365/08-sweep-sessions.ps1); "
                               "nothing was restored");
    }
}

std::string RestoreRun::open_explore(ItemKind kind)
{
    const std::string id = c_.client.open_explore_session(
        organization_id_, c_.spec.restore_point.backup_time, vr::session_type(kind));
    // Recorded at once, so the finally path can stop it.
    opened_.push_back(id);
    known_.insert(id);
    return id;
}

TypeWork RestoreRun::resolve_mail()
{
    TypeWork work;
    work.kind = ItemKind::mail;
    work.explore = open_explore(ItemKind::mail);
    const std::string base = "/v8/RestoreSessions/" + work.explore + "/organization/mailboxes";
    const std::vector<json> mailboxes = c_.client.get_all(base);
    std::map<std::string, std::vector<json>> folders; // by mailbox and folder name
    std::map<std::string, std::vector<json>> items;   // by mailbox and folder ID
    for (std::size_t i = 0; i < c_.spec.mail.size(); ++i) {
        const connector::MailSelector& sel = c_.spec.mail[i];
        const std::string item = "mail item " + std::to_string(i) + " " + shown_text(sel.subject);
        const json& mailbox =
            exactly_one(mailboxes, item, "mailbox " + shown_text(sel.mailbox), [&](const json& e) {
                const std::string* email = text_at(e, "email");
                return email != nullptr && ascii_iequals(*email, sel.mailbox);
            });
        const std::string mailbox_id = ascii_lower(id_of(mailbox));
        if (!is_uuid(mailbox_id)) {
            throw vr::ShapeError("a mailbox ID that isn't a UUID");
        }
        const std::string mailbox_path = base + "/" + mailbox_id;
        std::vector<json>& in_mailbox = folders[mailbox_id + "\n" + sel.folder];
        if (in_mailbox.empty()) {
            in_mailbox =
                c_.client.get_all(mailbox_path + "/folders?name=" + vr::percent_encode(sel.folder));
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
                                       vr::percent_encode(folder_id));
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
        const json reread = c_.client.get_json(mailbox_path + "/items/" + vr::percent_encode(id));
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
        listed = client.get_all(container_path + "/Documents?parentId=" + vr::percent_encode(parent));
    }
    const json& found = exactly_one(listed, item, "the file",
                                    [&](const json& e) { return is_file_named(e, name); });
    const std::string id = id_of(found);
    ordered_json reread = client.get_ordered_json(container_path + "/Documents/" +
                                                  vr::percent_encode(id));
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
                                    vr::percent_encode(parent));
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
    work.explore = open_explore(ItemKind::sharepoint);
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
        }
        std::vector<json>& in_site = libraries[*site];
        if (in_site.empty()) {
            in_site = c_.client.get_all(site_path + "/Libraries");
        }
        const std::string library = *site + ascii_lower(sel.list_id);
        exactly_one(in_site, item, "the library of list " + shown_text(sel.list_id),
                    [&](const json& e) { return ascii_iequals(id_of(e), library); });
        const std::string parent = walk_folders(c_.client, site_path, library,
                                                vr::path_segments(sel.folder_path),
                                                folders, item);
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
    work.explore = open_explore(ItemKind::onedrive);
    const std::string base = "/v8/RestoreSessions/" + work.explore + "/Organization/OneDrives";
    const std::vector<json> onedrives = c_.client.get_all(base);

    // The target: the test OneDrive the guard resolved, as Veeam lists it.
    const graph::ResolvedOneDriveFolder& folder = *c_.checked.onedrive_folder();
    const std::string target_id = folder.site_id + folder.web_id;
    const json& target = exactly_one(
        onedrives, "the restore target", "the test OneDrive " + shown_text(folder.site_url),
        [&](const json& e) {
            const std::string* url = text_at(e, "url");
            return url != nullptr && ascii_iequals(*url, folder.site_url) &&
                   ascii_iequals(id_of(e), target_id);
        });
    const std::string* target_name = text_at(target, "name");
    if (target_name == nullptr) {
        throw vr::ShapeError("a OneDrive without a \"name\"");
    }
    work.target_onedrive["id"] = id_of(target);
    work.target_onedrive["name"] = *target_name;
    work.target_onedrive["url"] = *text_at(target, "url");

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
        const std::string onedrive = ascii_lower(id_of(source));
        if (!vr::is_uuid_run(onedrive)) {
            throw vr::ShapeError("a OneDrive ID that isn't UUIDs");
        }
        const std::string od_path = base + "/" + onedrive;
        const std::string parent = walk_folders(c_.client, od_path, "root",
                                                vr::path_segments(sel.folder_path), folders, item);
        Resolved found = resolve_document(c_.client, od_path, parent, documents, item, sel.name,
                                          sel.size);
        found.index = i;
        found.container = onedrive;
        work.items.push_back(std::move(found));
    }
    return work;
}

std::vector<std::string> RestoreRun::duplicates(ItemKind kind,
                                                std::chrono::system_clock::time_point posted)
{
    const std::string path = "/v8/RestoreSessions?startTimeFrom=" +
                             vr::format_utc_seconds(posted - vr::kDuplicateWindow) +
                             "&orderBy=CreationTime&orderAsc=false&limit=" +
                             std::to_string(vr::kDuplicateLimit);
    vr::DuplicateFilter filter;
    filter.account = c_.account;
    filter.type = std::string{vr::session_type(kind)};
    filter.known = known_;
    filter.floor = std::chrono::time_point_cast<std::chrono::nanoseconds>(posted - vr::kDuplicateFloor);
    return vr::new_restore_sessions(c_.client.get_json(path), filter);
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
        } catch (const VeeamError& e) {
            if (e.status() != 409) {
                throw;
            }
            if (attempt == vr::kStatisticsAttempts) {
                throw connector::Error("veeam_m365: restore session " + id +
                                       " stopped, but its statistics still weren't ready after " +
                                       std::to_string(vr::kStatisticsAttempts) +
                                       " attempts; no verdict");
            }
        }
        c_.sleep(vr::kStatisticsWait);
    }
}

std::vector<vr::Event> RestoreRun::events(const std::string& id)
{
    const std::string path = "/v8/RestoreSessions/" + id + "/Events?limit=" +
                             std::to_string(vr::kEventsPageSize);
    std::vector<vr::Event> out;
    for (int page = 0; page < vr::kMaxEventPages; ++page) {
        const std::vector<vr::Event> got = vr::read_events(c_.client.get_json(
            page == 0 ? path : path + "&offset=" + std::to_string(page * vr::kEventsPageSize)));
        out.insert(out.end(), got.begin(), got.end());
        if (got.size() < static_cast<std::size_t>(vr::kEventsPageSize)) {
            return out;
        }
    }
    throw vr::ShapeError("more than " +
                         std::to_string(vr::kEventsPageSize * vr::kMaxEventPages) + " events");
}

void RestoreRun::restore_call(const TypeWork& work, const std::vector<std::size_t>& call,
                              connector::RestoreResult& result)
{
    const std::string& container = work.items[call.front()].container;
    veeam::RestoreRequestContext ctx;
    ctx.kind = guard_kind(work.kind);
    ctx.opened_explore_sessions = opened_;
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

    // The credential: exported now, in the body once, checked and sent as
    // that exact text, then wiped (docs/decisions.md 2026-09-30 W2.5 point 1).
    ExportedPfx pfx;
    std::string text;
    VeeamClient::RestorePostOutcome outcome;
    std::chrono::system_clock::time_point posted;
    {
        const CredentialWipe wipe{pfx, text, body};
        try {
            pfx = c_.exporter->export_pfx(thumbprint_);
        } catch (const CertExportError& e) {
            throw connector::Error(std::string{"veeam_m365: "} + e.what() +
                                   "; the restore was not sent");
        }
        body["applicationCertificate"] = pfx.pfx_base64;
        body["applicationCertificatePassword"] = pfx.password;
        text = body.dump();
        CredentialWipe::wipe_body(body);
        veeam::check_restore_request(c_.checked, ctx, path, text, c_.guard_options);
        posted = c_.wall_now();
        outcome = c_.client.post_restore_once(path, text, vr::kPostTimeout);
    }

    const std::string kind_name{connector::to_string(work.kind)};
    std::string id;
    bool confirmed = false;
    switch (outcome.kind) {
    case VeeamClient::RestorePostOutcome::Kind::refused:
        if (outcome.status == 401 || outcome.status == 403) {
            throw connector::AuthError("veeam_m365: " + outcome.message +
                                       "; Veeam started no restore");
        }
        throw connector::Error("veeam_m365: " + outcome.message + "; Veeam started no restore");
    case VeeamClient::RestorePostOutcome::Kind::not_sent:
        // Nothing went out, so nothing runs: the explore sessions are closed.
        throw connector::TransientError("veeam_m365: " + outcome.message +
                                        "; the restore was not sent");
    case VeeamClient::RestorePostOutcome::Kind::accepted:
        restore_may_run_ = true;
        id = outcome.session_id;
        running_session_ = id;
        try {
            const std::vector<std::string> found = duplicates(work.kind, posted);
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
        restore_may_run_ = true;
        warn(outcome.message + "; looking for the restore session instead of sending again");
        std::vector<std::string> found = duplicates(work.kind, posted);
        for (int look = 0; found.empty() && look < vr::kDuplicateRelooks; ++look) {
            c_.sleep(vr::kDuplicateRelookWait);
            found = duplicates(work.kind, posted);
        }
        if (found.size() != 1) {
            throw connector::Error(no_verdict(
                "the " + kind_name + " restore POST got no answer (" + outcome.message +
                ") and the duplicate check found " + std::to_string(found.size()) +
                " candidate sessions; it was not sent again"));
        }
        id = found.front();
        running_session_ = id;
        confirmed = true;
        break;
    }
    }
    known_.insert(id);

    const vr::SessionState session = poll(id, work.kind);
    // Stopped: nothing runs under the explore sessions any more.
    restore_may_run_ = false;
    running_session_.clear();
    if (session.result.empty()) {
        throw vr::ShapeError("a stopped session without a \"result\"");
    }
    const vr::Statistics stats = vr::read_statistics(statistics(id));
    const std::vector<vr::Event> seen = events(id);
    vr::SessionVerdict verdict = vr::judge(work.kind, id, session, stats, seen, sent);

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
                               ") restored nothing: " + verdict.infrastructure_text);
    }
    if (!confirmed) {
        throw connector::Error("veeam_m365: restore session " + id + " (" + kind_name +
                               ") ran, but the duplicate check didn't list it alone, so another "
                               "restore can't be ruled out; no verdict");
    }
}

connector::RestoreResult RestoreRun::run()
{
    organization();
    preflight();
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
      graph_(std::move(options.graph)), guard_options_(std::move(options.guard)),
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
    } catch (const graph::NotFoundError& e) {
        throw connector::NotFoundError(e.what());
    } catch (const graph::GraphError& e) {
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

    RestoreRun run({*client_, spec, *checked, guard_options_, cert_exporter_.get(), wall_now_,
                    now_, sleep_, logger_, account_});
    // Veeam's errors as list_restore_points maps them, naming what was left
    // open if a restore may still be running. Connector errors (the guard's
    // SafetyViolation among them) pass through as they are.
    try {
        return run.run();
    } catch (const AuthError& e) {
        throw connector::AuthError(e.what() + run.left_open());
    } catch (const TransientError& e) {
        throw connector::TransientError(e.what() + run.left_open());
    } catch (const NotFoundError& e) {
        throw connector::NotFoundError(e.what() + run.left_open());
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
    // The Worker app's certificate and IDs, before any client is made: a
    // CertificateError (a ConfigError, keyed by the variable when one is
    // unset) or a Graph ID that isn't a GUID stops here.
    graph::ClientCertificate certificate =
        graph::certificate_from_secrets(secrets, wall_now(), logger);
    if (!is_uuid(config.graph_tenant_id)) {
        throw ConfigError("graph_tenant_id", "graph_tenant_id is not a GUID");
    }
    if (!is_uuid(config.graph_client_id)) {
        throw ConfigError("graph_client_id", "graph_client_id is not a GUID");
    }

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
    connector_options.graph_http = options.make_graph_http
                                       ? options.make_graph_http(logger)
                                       : graph::make_graph_http_client(logger);
    if (!connector_options.graph_http) {
        throw std::invalid_argument("veeam_m365: no Graph HTTP client");
    }
    graph::GraphClientOptions graph_options;
    graph_options.logger = logger;
    graph_options.now = options.now;
    graph_options.wall_now = wall_now;
    graph_options.sleep = options.sleep;
    graph_options.jitter = options.jitter;
    // The connector keeps graph_http alive as long as the client on it.
    connector_options.graph = std::make_shared<graph::GraphClient>(
        *connector_options.graph_http, config.graph_tenant_id, config.graph_client_id,
        std::move(certificate), std::move(graph_options));
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
