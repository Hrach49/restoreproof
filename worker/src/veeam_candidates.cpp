// VeeamM365Connector::list_candidates (W2.6): the random half's candidates,
// listed through explore sessions exactly as restore_sample will list them
// later (docs/decisions.md 2026-09-30, W2.6 points 6 and 11;
// docs/api/veeam-notes.md §5). Read-only: the only POSTs are the explore
// sessions' and their Stop.

#include <rp/sample_rng.hpp>
#include <rp/veeam_m365_connector.hpp>

#include "graph_ids.hpp"
#include "text_util.hpp"
#include "uuid.hpp"
#include "veeam_browse.hpp"
#include "veeam_explore.hpp"
#include "veeam_restore.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace rp {

namespace {

using nlohmann::json;
namespace vr = veeam_restore;
using connector::ItemKind;
using veeam_browse::bool_at;
using veeam_browse::id_of;
using veeam_browse::is_file_named;
using veeam_browse::text_at;

constexpr std::string_view kOutcome = "nothing was listed";

// Every canary's subject and file name starts with this (lab/README.md).
constexpr std::string_view kCanaryPrefix = "rp-canary-";

// Mail folders a sample never comes from, by Veeam's category.
constexpr std::array<std::string_view, 4> kSkippedMailCategories = {
    "Deleted", "PermanentlyDeletedItems", "Drafts", "Outbox"};

// A site's own libraries, by the last segment of their url (never localised).
constexpr std::array<std::string_view, 5> kSkippedLibraries = {
    "SitePages", "SiteAssets", "Style Library", "FormServerTemplates", "RestoreTarget"};

// Top-level OneDrive folders never looked into, in any OneDrive: the restore
// target and the lab's canary folder; the query adds the folders its
// manifest's OneDrive canaries are in.
constexpr std::array<std::string_view, 2> kSkippedOneDriveFolders = {"RestoreTarget",
                                                                     "RestoreTest"};

bool starts_with_i(std::string_view text, std::string_view prefix)
{
    return text.size() >= prefix.size() && ascii_iequals(text.substr(0, prefix.size()), prefix);
}

template <class List>
bool one_of_i(const List& list, std::string_view value)
{
    return std::ranges::any_of(list, [&](std::string_view entry) { return ascii_iequals(entry, value); });
}

// A canary's subject or file name: the prefix, or one the manifest names.
bool is_canary(std::string_view text, const std::vector<std::string>& canaries)
{
    return starts_with_i(text, kCanaryPrefix) || one_of_i(canaries, text);
}

// How often each string at `key` occurs in `list` (exactly, as restore_sample
// compares), over the entries `counted` takes.
template <class Counted>
std::map<std::string, int> occurrences(const std::vector<json>& list, std::string_view key,
                                       Counted counted)
{
    std::map<std::string, int> out;
    for (const json& entry : list) {
        if (const std::string* text = text_at(entry, key); text != nullptr && counted(entry, *text)) {
            ++out[*text];
        }
    }
    return out;
}

// The host of an https:// URL, as written; empty for anything else.
std::string_view host_of(std::string_view url)
{
    constexpr std::string_view scheme = "https://";
    if (!starts_with_i(url, scheme)) {
        return {};
    }
    const std::string_view rest = url.substr(scheme.size());
    return rest.substr(0, rest.find('/'));
}

// A mailbox, site or OneDrive that may give candidates.
struct Container {
    std::string key;     // what the draw sorts by
    std::string address; // mailbox address, Graph site ID or OneDrive owner
    std::string id;      // Veeam's ID, lower case
    // A OneDrive no single organisation user owns today: drawn and walked
    // like the others, so the draw stays the restore point's, but nothing
    // in it is listed (restore_sample couldn't address it). `address` is
    // then its url.
    bool unresolved = false;
};

// A folder whose items are listed.
struct Unit {
    std::string list_id;     // SharePoint: the library's list GUID, lower case
    std::string drive_id;    // SharePoint: the library's Graph drive ID
    std::string folder_path; // mail: the folder's name; files: "/" or "/a/b"
    std::string parent;      // the ID its listing is asked for by
    int depth = 0;           // files: folder levels below the library or drive root
};

bool unit_before(const Unit& a, const Unit& b)
{
    return std::tie(a.list_id, a.folder_path) < std::tie(b.list_id, b.folder_path);
}

// A file restore_sample will find exactly once in `documents`, and its size.
struct FoundFile {
    std::string name;
    std::int64_t size = 0;
};

// The files of one listing that may be candidates: restore_sample finds a
// file by its exact name among the entries whose isFolder is false, so a name
// two of them share is never one; nor is a canary's name, or a file without
// a size or above `max_bytes` (the read-back's cap). Sorted by name.
std::vector<FoundFile> files_in(const std::vector<json>& documents,
                                const std::vector<std::string>& canaries, std::int64_t max_bytes)
{
    const std::map<std::string, int> names = occurrences(
        documents, "name", [](const json& e, const std::string& name) { return is_file_named(e, name); });
    std::vector<FoundFile> out;
    for (const json& entry : documents) {
        const std::string* name = text_at(entry, "name");
        if (name == nullptr || name->empty() || !is_file_named(entry, *name) ||
            names.at(*name) != 1 || is_canary(*name, canaries)) {
            continue;
        }
        const auto bytes = entry.find("sizeBytes");
        if (bytes == entry.end() || !bytes->is_number_integer()) {
            continue;
        }
        std::int64_t size = 0;
        if (bytes->is_number_unsigned()) {
            const auto value = bytes->get<std::uint64_t>();
            if (value > static_cast<std::uint64_t>(max_bytes)) {
                continue;
            }
            size = static_cast<std::int64_t>(value);
        } else {
            size = bytes->get<std::int64_t>();
            if (size < 0 || size > max_bytes) {
                continue;
            }
        }
        out.push_back({*name, size});
    }
    std::ranges::sort(out, {}, &FoundFile::name);
    return out;
}

// One list_candidates call after its checks.
class CandidateLister {
public:
    struct Context {
        VeeamClient& client;
        const connector::CandidateQuery& query;
        const std::function<std::chrono::system_clock::time_point()>& wall_now;
        const std::shared_ptr<spdlog::logger>& logger;
        const std::string& account;
        // Where every explore session opened or adopted is remembered, with
        // when.
        std::map<std::string, std::chrono::system_clock::time_point>& opened;
    };

    explicit CandidateLister(Context context)
        : c_(context), sessions_({context.client, context.wall_now, context.logger,
                                  context.account, context.query.restore_point.backup_time})
    {
    }

    // run_checked, remembering every explore session it opened or adopted,
    // whether it returns or throws.
    connector::CandidatePool run();

private:
    connector::CandidatePool run_checked();
    void remember_sessions()
    {
        const auto now = c_.wall_now();
        for (const std::string& id : sessions_.opened()) {
            c_.opened.insert_or_assign(id, now);
        }
    }
    void browse_mail(connector::CandidatePool& pool);
    void browse_sharepoint(connector::CandidatePool& pool);
    void browse_onedrive(connector::CandidatePool& pool, const std::vector<std::string>& owners);

    // The two-level draw: `containers` sorted and drawn one at a time; in
    // each, `units_of` its folders, sorted, and up to folders_per_container
    // of them drawn and handed to `list` (which returns whether it found a
    // candidate), until containers_wanted gave one or containers_tried were
    // looked into.
    template <class UnitsOf, class List>
    void draw(ItemKind kind, std::vector<Container> containers, connector::BrowseRecord& record,
              UnitsOf units_of, List list);

    // The folders below `roots` (breadth first, each listing's children by
    // name) through `path`/Folders?parentId=, down to walk_depth levels and
    // with at most walk_calls listings; `roots` and every folder found are
    // the units. A child is a unit only if restore_sample's walk finds it
    // exactly once among its siblings; `skip_top` leaves out top-level ones.
    std::vector<Unit> walk(const std::string& path, std::vector<Unit> roots,
                           const std::vector<std::string_view>& skip_top);

    Context c_;
    std::string host_; // the tenant's SharePoint host, from the targets' site ID
    std::string organization_id_;
    // Destroyed first: stops the explore sessions left on an exception path.
    veeam_explore::ExploreSessions sessions_;
};

template <class UnitsOf, class List>
void CandidateLister::draw(ItemKind kind, std::vector<Container> containers,
                           connector::BrowseRecord& record, UnitsOf units_of, List list)
{
    const connector::CandidateLimits& limits = c_.query.limits;
    std::ranges::sort(containers, {}, &Container::key);
    record.containers_eligible = containers.size();
    sampling::SampleRng rng(sampling::stream_seed(c_.query.seed, kind, sampling::Stream::browse));
    sampling::Shuffle pick(rng, containers.size());
    int productive = 0;
    int tried = 0;
    while (productive < limits.containers_wanted && tried < limits.containers_tried) {
        const std::optional<std::size_t> at = pick.next();
        if (!at) {
            break;
        }
        ++tried;
        const Container& container = containers[*at];
        record.containers_listed.push_back(container.address);
        record.containers_unresolved += container.unresolved ? 1 : 0;
        std::vector<Unit> units = units_of(container);
        std::ranges::sort(units, unit_before);
        sampling::Shuffle folders(rng, units.size());
        bool found = false;
        for (int listed = 0; listed < limits.folders_per_container; ++listed) {
            const std::optional<std::size_t> unit = folders.next();
            if (!unit) {
                break;
            }
            // Drawn either way, so the rng's sequence doesn't depend on
            // whether an owner resolves; listed only when one does.
            if (!container.unresolved) {
                ++record.folders_listed;
                found = list(container, units[*unit]) || found;
            }
        }
        productive += found ? 1 : 0;
    }
    record.short_of_containers = productive < limits.containers_wanted;
}

std::vector<Unit> CandidateLister::walk(const std::string& path, std::vector<Unit> roots,
                                        const std::vector<std::string_view>& skip_top)
{
    const connector::CandidateLimits& limits = c_.query.limits;
    std::vector<Unit> units = std::move(roots);
    int calls = 0;
    for (std::size_t next = 0; next < units.size(); ++next) {
        if (units[next].depth >= limits.walk_depth || calls >= limits.walk_calls) {
            continue;
        }
        ++calls;
        const Unit parent = units[next];
        const std::vector<json> children =
            c_.client.get_all(path + "/Folders?parentId=" + form_encode(parent.parent));
        const std::map<std::string, int> names =
            occurrences(children, "name", [](const json&, const std::string&) { return true; });
        std::vector<Unit> found;
        for (const json& child : children) {
            const std::string* name = text_at(child, "name");
            if (name == nullptr || name->empty() || *name == "." || *name == ".." ||
                name->find_first_of("/\\:") != std::string::npos || names.at(*name) != 1 ||
                (parent.depth == 0 && one_of_i(skip_top, *name))) {
                continue;
            }
            Unit unit = parent;
            unit.folder_path = (parent.folder_path == "/" ? "" : parent.folder_path) + "/" + *name;
            unit.parent = id_of(child);
            unit.depth = parent.depth + 1;
            found.push_back(std::move(unit));
        }
        std::ranges::sort(found, unit_before);
        units.insert(units.end(), found.begin(), found.end());
    }
    return units;
}

void CandidateLister::browse_mail(connector::CandidatePool& pool)
{
    const connector::CandidateQuery& q = c_.query;
    const std::string base =
        "/v8/RestoreSessions/" + sessions_.open(ItemKind::mail) + "/organization/mailboxes";
    const std::vector<json> mailboxes = c_.client.get_all(base);
    // restore_sample finds a mailbox by its address among the primary
    // entries: an address two of them share is never found once.
    const std::map<std::string, int> addresses = [&] {
        std::map<std::string, int> out;
        for (const auto& [email, n] : occurrences(mailboxes, "email", [](const json& e, const std::string&) {
                 return !bool_at(e, "isArchive");
             })) {
            out[ascii_lower(email)] += n;
        }
        return out;
    }();
    std::vector<Container> containers;
    for (const json& entry : mailboxes) {
        const std::string* email = text_at(entry, "email");
        if (email == nullptr || email->empty() || bool_at(entry, "isArchive") ||
            bool_at(entry, "isPublic") || addresses.at(ascii_lower(*email)) != 1 ||
            starts_with_i(*email, "restoretest@") || is_restore_mailbox(*email) ||
            starts_with_i(*email, "DiscoverySearchMailbox")) {
            continue;
        }
        const std::string id = ascii_lower(id_of(entry));
        if (is_uuid(id)) {
            containers.push_back({ascii_lower(*email), *email, id});
        }
    }

    const auto units_of = [&](const Container& mailbox) {
        const std::string path = base + "/" + mailbox.id;
        const std::vector<json> top = c_.client.get_all(path + "/folders?parentId=root");
        // restore_sample finds a folder by name (folders?name=): one whose
        // name another folder anywhere in the mailbox shares may not be found once.
        const std::map<std::string, int> names =
            occurrences(c_.client.get_all(path + "/folders"), "name",
                        [](const json&, const std::string&) { return true; });
        std::vector<Unit> out;
        for (const json& folder : top) {
            const std::string* name = text_at(folder, "name");
            const std::string* type = text_at(folder, "type");
            const std::string* category = text_at(folder, "category");
            if (name == nullptr || name->empty() || !names.contains(*name) ||
                names.at(*name) != 1 || type == nullptr || *type != "None" ||
                (category != nullptr && one_of_i(kSkippedMailCategories, *category))) {
                continue;
            }
            Unit unit;
            unit.folder_path = *name;
            unit.parent = id_of(folder);
            out.push_back(std::move(unit));
        }
        return out;
    };

    const auto list = [&](const Container& mailbox, const Unit& folder) {
        const std::vector<json> items = c_.client.get_all(base + "/" + mailbox.id +
                                                          "/items?parentId=" +
                                                          form_encode(folder.parent));
        // restore_sample finds a mail by its exact subject among every item
        // of the folder, whatever its class.
        const std::map<std::string, int> subjects =
            occurrences(items, "subject", [](const json&, const std::string&) { return true; });
        std::vector<connector::MailCandidate> found;
        for (const json& item : items) {
            const std::string* subject = text_at(item, "subject");
            const std::string* item_class = text_at(item, "itemClass");
            const std::string* received = text_at(item, "received");
            if (subject == nullptr || subject->empty() || subjects.at(*subject) != 1 ||
                item_class == nullptr || *item_class != "IPM.Note" ||
                is_canary(*subject, q.exclude.subjects) || received == nullptr) {
                continue;
            }
            const std::optional<std::string> second = vr::to_whole_seconds(*received);
            if (!second) {
                continue;
            }
            // The header as the backup lists it, for the expected set (W3.1):
            // left empty when Veeam doesn't say, never a reason to drop the mail.
            connector::MailCandidate candidate{
                {mailbox.address, folder.folder_path, *subject, *second}, {}, {}};
            if (const std::string* from = text_at(item, "from")) {
                candidate.sender_name = *from;
            }
            if (const std::string* sent = text_at(item, "sent")) {
                candidate.sent_at = vr::to_whole_seconds(*sent).value_or("");
            }
            found.push_back(std::move(candidate));
        }
        std::ranges::sort(found, {}, [](const connector::MailCandidate& c) -> const std::string& {
            return c.selector.subject;
        });
        pool.mail.insert(pool.mail.end(), found.begin(), found.end());
        return !found.empty();
    };

    draw(ItemKind::mail, std::move(containers), pool.mail_browse, units_of, list);
}

void CandidateLister::browse_sharepoint(connector::CandidatePool& pool)
{
    const connector::CandidateQuery& q = c_.query;
    const std::string base =
        "/v8/RestoreSessions/" + sessions_.open(ItemKind::sharepoint) + "/Organization/Sites";
    std::vector<Container> containers;
    for (const json& entry : c_.client.get_all(base + "?parentId=root")) {
        const std::string id = ascii_lower(id_of(entry));
        const std::string* url = text_at(entry, "url");
        // Personal sites and the -my host are OneDrives; another host isn't
        // the tenant's.
        if (id.size() != 72 || !vr::is_uuid_run(id) || url == nullptr ||
            !ascii_iequals(host_of(*url), host_)) {
            continue;
        }
        containers.push_back({id, host_ + "," + id.substr(0, 36) + "," + id.substr(36), id});
    }

    const auto units_of = [&](const Container& site) {
        const std::string path = base + "/" + site.id;
        std::vector<Unit> roots;
        for (const json& library : c_.client.get_all(path + "/Libraries")) {
            // restore_sample finds a library by its ID, the site's and the list GUID.
            const std::string id = ascii_lower(id_of(library));
            const std::string* url = text_at(library, "url");
            if (id.size() != 108 || !id.starts_with(site.id) || url == nullptr ||
                url->find("_catalogs") != std::string::npos) {
                continue;
            }
            const std::string list_id = id.substr(72);
            const std::string_view last = std::string_view{*url}.substr(url->rfind('/') + 1);
            const std::optional<std::string> drive =
                graph_drive_id(id.substr(0, 36), id.substr(36, 36), list_id);
            // Never the RestoreTarget library, by its drive ID and its url,
            // nor a canary library.
            if (!drive || ascii_iequals(*drive, q.targets.library_id()) ||
                one_of_i(kSkippedLibraries, last) || one_of_i(q.exclude.list_ids, list_id)) {
                continue;
            }
            roots.push_back({list_id, *drive, "/", id, 0});
        }
        std::ranges::sort(roots, unit_before);
        return walk(path, std::move(roots), {});
    };

    const auto list = [&](const Container& site, const Unit& folder) {
        const std::vector<json> documents = c_.client.get_all(
            base + "/" + site.id + "/Documents?parentId=" + form_encode(folder.parent));
        const std::vector<FoundFile> files =
            files_in(documents, q.exclude.sharepoint_names, q.limits.max_file_bytes);
        for (const FoundFile& file : files) {
            connector::SharePointCandidate candidate;
            candidate.selector = {site.address, folder.drive_id, folder.folder_path, file.name,
                                  folder.list_id, -1};
            candidate.size_bytes = file.size;
            pool.sharepoint.push_back(std::move(candidate));
        }
        return !files.empty();
    };

    draw(ItemKind::sharepoint, std::move(containers), pool.sharepoint_browse, units_of, list);
}

void CandidateLister::browse_onedrive(connector::CandidatePool& pool,
                                      const std::vector<std::string>& owners)
{
    const connector::CandidateQuery& q = c_.query;
    const std::string base =
        "/v8/RestoreSessions/" + sessions_.open(ItemKind::onedrive) + "/Organization/OneDrives";
    const std::vector<json> onedrives = c_.client.get_all(base);
    // restore_sample finds a OneDrive by the address its owner gives it: one
    // two entries share is never found once.
    const std::map<std::string, int> urls = [&] {
        std::map<std::string, int> out;
        for (const auto& [url, n] :
             occurrences(onedrives, "url", [](const json&, const std::string&) { return true; })) {
            out[ascii_lower(url)] += n;
        }
        return out;
    }();
    // Each organisation user's OneDrive address, folded A-Z, and the users
    // that give it: built once, so a OneDrive's owner is one lookup, not a
    // pass over every user.
    const std::map<std::string, std::vector<const std::string*>> owners_at = [&] {
        std::map<std::string, std::vector<const std::string*>> out;
        for (const std::string& owner : owners) {
            if (const std::optional<std::string> address = vr::onedrive_url(host_, owner)) {
                out[ascii_lower(*address)].push_back(&owner);
            }
        }
        return out;
    }();
    // Eligible by the restore point alone: the organisation's users (Veeam's
    // cache of today's tenant, not the restore point's) only decide whether
    // a drawn OneDrive can give candidates, never which are drawn.
    std::vector<Container> containers;
    for (const json& entry : onedrives) {
        const std::string id = ascii_lower(id_of(entry));
        const std::string* url = text_at(entry, "url");
        if (id.size() != 72 || !vr::is_uuid_run(id) || url == nullptr ||
            urls.at(ascii_lower(*url)) != 1) {
            continue;
        }
        // Its owner: the one organisation user whose OneDrive address it is.
        const std::string folded = ascii_lower(*url);
        const auto owned_by = owners_at.find(folded);
        const bool resolved = owned_by != owners_at.end() && owned_by->second.size() == 1;
        containers.push_back({folded, resolved ? *owned_by->second.front() : *url, id, !resolved});
    }

    std::vector<std::string_view> skip_top{kSkippedOneDriveFolders.begin(),
                                           kSkippedOneDriveFolders.end()};
    skip_top.insert(skip_top.end(), q.exclude.onedrive_folders.begin(),
                    q.exclude.onedrive_folders.end());
    const auto units_of = [&](const Container& onedrive) {
        Unit root;
        root.folder_path = "/";
        root.parent = "root";
        return walk(base + "/" + onedrive.id, {root}, skip_top);
    };

    const auto list = [&](const Container& onedrive, const Unit& folder) {
        const std::vector<json> documents = c_.client.get_all(
            base + "/" + onedrive.id + "/Documents?parentId=" + form_encode(folder.parent));
        const std::vector<FoundFile> files =
            files_in(documents, q.exclude.onedrive_names, q.limits.max_file_bytes);
        for (const FoundFile& file : files) {
            connector::OneDriveCandidate candidate;
            candidate.selector = {onedrive.address, folder.folder_path, file.name, -1};
            candidate.size_bytes = file.size;
            pool.onedrive.push_back(std::move(candidate));
        }
        return !files.empty();
    };

    draw(ItemKind::onedrive, std::move(containers), pool.onedrive_browse, units_of, list);
}

connector::CandidatePool CandidateLister::run()
{
    try {
        return run_checked();
    } catch (...) {
        remember_sessions();
        throw;
    }
}

connector::CandidatePool CandidateLister::run_checked()
{
    const connector::CandidateQuery& q = c_.query;
    Organization org;
    try {
        org = veeam_explore::find_organization(c_.client, q.client_ref);
    } catch (const connector::NotFoundError& e) {
        // Nothing is sampled yet: a client Veeam doesn't know is the call's own error.
        throw connector::Error(std::string{"veeam_m365: "} + e.what() + "; " +
                               std::string{kOutcome});
    }
    organization_id_ = org.id;
    sessions_.set_organization(org.id, org.name);
    veeam_explore::check_restore_point(c_.client, org.id, q.client_ref, q.restore_point, kOutcome);
    veeam_explore::preflight(c_.client, c_.account, kOutcome);
    // RestoreTargets checked the site ID's shape.
    host_ = parse_graph_site_id(q.targets.site_id())->host;

    connector::CandidatePool pool;
    if (q.mail) {
        browse_mail(pool);
    }
    if (q.sharepoint) {
        browse_sharepoint(pool);
    }
    if (q.onedrive) {
        // The OneDrives' owners: an organisation user's name is its UPN.
        std::vector<std::string> owners;
        for (const json& user : c_.client.get_all("/v8/Organizations/" + organization_id_ + "/Users")) {
            if (const std::string* name = text_at(user, "name"); name != nullptr && !name->empty()) {
                owners.push_back(*name);
            }
        }
        browse_onedrive(pool, owners);
    }

    remember_sessions(); // close_checked forgets them
    const std::vector<std::string> failed = sessions_.close_checked();
    if (!failed.empty()) {
        std::string ids;
        for (const std::string& id : failed) {
            ids += (ids.empty() ? "" : ", ") + id;
        }
        throw connector::Error("veeam_m365: explore session " + ids +
                               " couldn't be stopped, and restore_sample's preflight would refuse "
                               "to run; stop it with docs/api/veeam-m365/08-sweep-sessions.ps1; " +
                               std::string{kOutcome});
    }
    return pool;
}

} // namespace

connector::CandidatePool VeeamM365Connector::list_candidates(const connector::CandidateQuery& query)
{
    if (!query.mail && !query.sharepoint && !query.onedrive) {
        return {};
    }
    if (query.client_ref.empty()) {
        throw std::invalid_argument("veeam_m365: the client reference is empty");
    }
    if (!vr::parse_veeam_time(query.restore_point.backup_time)) {
        throw std::invalid_argument(
            "veeam_m365: the restore point's backup time isn't Veeam's UTC form, such as "
            "2026-09-25T19:37:15.2145203Z");
    }
    const connector::CandidateLimits& limits = query.limits;
    if (limits.containers_wanted < 0 || limits.containers_tried < 0 ||
        limits.folders_per_container < 0 || limits.walk_depth < 0 || limits.walk_calls < 0 ||
        limits.max_file_bytes < 0) {
        throw std::invalid_argument("veeam_m365: a candidate limit is negative");
    }

    // Those remembered before the duplicate check's window can never be
    // counted again.
    const auto forget_before = wall_now_() - vr::kDuplicateWindow;
    std::erase_if(candidate_sessions_, [&](const auto& entry) { return entry.second < forget_before; });
    CandidateLister lister({*client_, query, wall_now_, logger_, account_, candidate_sessions_});
    // Veeam's errors as restore_sample maps them: nothing is sampled yet, so
    // Veeam's own 404 is connector::Error, never connector::NotFoundError.
    try {
        return lister.run();
    } catch (const AuthError& e) {
        throw connector::AuthError(e.what());
    } catch (const TransientError& e) {
        throw connector::TransientError(e.what());
    } catch (const VeeamError& e) {
        throw connector::Error(e.what());
    } catch (const vr::ShapeError& e) {
        throw connector::Error(std::string{"veeam_m365: unexpected response from Veeam: "} +
                               e.what());
    } catch (const nlohmann::json::exception& e) {
        throw connector::Error(std::string{"veeam_m365: unexpected response from Veeam: "} +
                               e.what());
    }
}

} // namespace rp
