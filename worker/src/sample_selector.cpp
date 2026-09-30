#include <rp/sample_selector.hpp>

#include <rp/sha256.hpp>
#include <rp/target_guard_graph.hpp>

#include "graph_ids.hpp"
#include "name_key.hpp"
#include "text_util.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::sampling {

namespace {

using connector::ItemKind;
using Key = std::vector<std::string>;

constexpr std::string_view kCanaryPrefix = "rp-canary-";
// The canary folder in the lab's OneDrive (docs/decisions.md 2026-09-25): never random.
constexpr std::string_view kCanaryFolderName = "RestoreTest";

// The first folder of a OneDrive path, empty and "." segments skipped ("" for
// the root); nullopt when the path has a ".." segment. The guard's rule
// (target_guard.cpp), so the sampler never offers what it would refuse.
std::optional<std::string_view> first_folder(std::string_view path)
{
    std::optional<std::string_view> first;
    std::size_t at = 0;
    while (at <= path.size()) {
        const std::size_t slash = std::min(path.find('/', at), path.size());
        const std::string_view segment = path.substr(at, slash - at);
        if (segment == "..") {
            return std::nullopt;
        }
        if (!first && !segment.empty() && segment != ".") {
            first = segment;
        }
        at = slash + 1;
    }
    return first.value_or(std::string_view{});
}

bool has_dot_dot(std::string_view path)
{
    return !first_folder(path).has_value();
}

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

struct KindInputs {
    ItemKind kind;
    int size;
    std::size_t canaries;
    std::uint32_t cursor;
};

void check_kind(const KindInputs& in)
{
    if (in.size < 0 || in.size > 100) {
        throw std::invalid_argument("sampler: the " + kind_name(in.kind) +
                                    " sample size must be from 0 to 100");
    }
    if (in.canaries == 0 ? in.cursor != 0 : in.cursor >= in.canaries) {
        throw std::invalid_argument(
            "sampler: the " + kind_name(in.kind) + " cursor must be " +
            (in.canaries == 0 ? std::string{"0: the manifest has no "} + kind_name(in.kind) +
                                    " canaries"
                              : "below " + std::to_string(in.canaries) + ", the manifest's " +
                                    kind_name(in.kind) + " canaries"));
    }
}

void check_inputs(const SamplePlan& plan, const CanaryManifest& manifest, const CanaryCursor& cursor,
                  std::string_view run_id)
{
    check_run_id(run_id);
    check_kind({ItemKind::mail, plan.mail, manifest.mail.size(), cursor.mail});
    check_kind({ItemKind::sharepoint, plan.sharepoint, manifest.sharepoint.size(), cursor.sharepoint});
    check_kind({ItemKind::onedrive, plan.onedrive, manifest.onedrive.size(), cursor.onedrive});
}

[[noreturn]] void refuse_canary(std::size_t entry, std::string_view field, std::string_view rule)
{
    throw ManifestError("canary manifest: /entries/" + std::to_string(entry) + "/location/" +
                        std::string{field} + ": " + std::string{rule});
}

// No canary is in a restore target: the loader can't know the targets, and a
// manifest may be built in code.
void check_canaries(const CanaryManifest& manifest, const connector::RestoreTargets& targets)
{
    for (const CanaryMail& mail : manifest.mail) {
        if (is_restore_mailbox(mail.mailbox)) {
            refuse_canary(mail.entry, "mailbox", "is a restore target (a restoretest mailbox)");
        }
    }
    for (const CanaryFile& file : manifest.sharepoint) {
        if (ascii_iequals(file.drive_id, targets.library_id())) {
            refuse_canary(file.entry, "drive_id",
                          "is a restore target (the library test_library_id names)");
        }
    }
    for (const CanaryFile& file : manifest.onedrive) {
        const std::optional<std::string_view> folder = first_folder(file.folder_path);
        if (!folder) {
            refuse_canary(file.entry, "folder_path",
                          "must start with \"/\" and have no \"..\" segment");
        }
        if (ascii_iequals(*folder, graph::kRestoreTargetName)) {
            refuse_canary(file.entry, "folder_path", "is in a restore target (a RestoreTarget folder)");
        }
    }
}

// What the pool may never hold, folded: every canary's subject and name, and
// the canary libraries.
struct Forbidden {
    std::set<std::string> subjects;
    std::set<std::string> sharepoint_names;
    std::set<std::string> onedrive_names;
    std::set<std::string> list_ids;

    explicit Forbidden(const CanaryManifest& manifest)
    {
        for (const CanaryMail& mail : manifest.mail) {
            subjects.insert(ascii_lower(mail.subject));
        }
        for (const CanaryFile& file : manifest.sharepoint) {
            sharepoint_names.insert(ascii_lower(file.name));
            list_ids.insert(ascii_lower(file.list_id));
        }
        for (const CanaryFile& file : manifest.onedrive) {
            onedrive_names.insert(ascii_lower(file.name));
        }
    }
};

std::optional<std::string> canary_text(std::string_view text, const std::set<std::string>& canaries,
                                       std::string_view what)
{
    const std::string folded = ascii_lower(text);
    if (folded.starts_with(kCanaryPrefix)) {
        return "a canary (its " + std::string{what} + " starts with rp-canary-)";
    }
    if (canaries.contains(folded)) {
        return "a canary (its " + std::string{what} + " is a canary's)";
    }
    return std::nullopt;
}

// Why the connector should never have offered this candidate, or nullopt.
std::optional<std::string> forbidden(const connector::MailSelector& mail, const Forbidden& f)
{
    if (mail.mailbox.empty() || mail.folder.empty() || mail.subject.empty() ||
        mail.received_at.empty()) {
        return "incomplete (no mailbox, folder, subject or received time)";
    }
    if (is_restore_mailbox(mail.mailbox)) {
        return "from a restore target (a restoretest mailbox)";
    }
    return canary_text(mail.subject, f.subjects, "subject");
}

std::optional<std::string> forbidden(const connector::SharePointSelector& file,
                                     const connector::RestoreTargets& targets, const Forbidden& f)
{
    if (file.site_id.empty() || file.drive_id.empty() || file.name.empty()) {
        return "incomplete (no site, drive or file name)";
    }
    constexpr std::string_view library = "from a restore target (the library test_library_id names)";
    constexpr std::string_view onedrive =
        "from a restore target (the OneDrive test_onedrive_drive_id names)";
    if (ascii_iequals(file.drive_id, targets.library_id())) {
        return std::string{library};
    }
    // A OneDrive is a SharePoint site too, on the -my host.
    if (ascii_iequals(file.drive_id, targets.onedrive_drive_id())) {
        return std::string{onedrive};
    }
    if (!is_uuid(file.list_id)) {
        return "from a library whose list ID isn't a GUID";
    }
    const std::optional<GraphSiteId> site = parse_graph_site_id(file.site_id);
    if (!site) {
        return "from a site whose ID isn't a Graph site ID";
    }
    // By the library's own GUIDs too, whatever drive ID the candidate carries.
    if (const std::optional<std::string> derived = graph_drive_id(site->site, site->web, file.list_id)) {
        if (ascii_iequals(*derived, targets.library_id())) {
            return std::string{library};
        }
        if (ascii_iequals(*derived, targets.onedrive_drive_id())) {
            return std::string{onedrive};
        }
    }
    // RestoreTargets checked the site ID's shape. A personal site (-my) or
    // another tenant's is never a source.
    if (!ascii_iequals(site->host, parse_graph_site_id(targets.site_id())->host)) {
        return "from a personal or other-host site";
    }
    if (f.list_ids.contains(ascii_lower(file.list_id))) {
        return "from a canary library";
    }
    if (has_dot_dot(file.folder_path)) {
        return "in a folder path with a \"..\" segment";
    }
    return canary_text(file.name, f.sharepoint_names, "name");
}

std::optional<std::string> forbidden(const connector::OneDriveSelector& file, const Forbidden& f)
{
    if (file.user.empty() || file.name.empty()) {
        return "incomplete (no owner or file name)";
    }
    const std::optional<std::string_view> folder = first_folder(file.folder_path);
    if (!folder) {
        return "in a folder path with a \"..\" segment";
    }
    if (ascii_iequals(*folder, graph::kRestoreTargetName)) {
        return "in a restore target (a RestoreTarget folder)";
    }
    if (ascii_iequals(*folder, kCanaryFolderName)) {
        return "in a canary location (a RestoreTest folder)";
    }
    return canary_text(file.name, f.onedrive_names, "name");
}

void refuse_candidate(ItemKind kind, std::size_t i, const std::string& why)
{
    throw std::logic_error("sampler: the connector offered " + kind_name(kind) + " candidate " +
                           std::to_string(i) + ", which is " + why + "; nothing was sampled");
}

// Every candidate in the pool, all types, before anything is drawn.
void check_pool(const connector::CandidatePool& pool, const connector::RestoreTargets& targets,
                const Forbidden& f)
{
    for (std::size_t i = 0; i < pool.mail.size(); ++i) {
        if (const auto why = forbidden(pool.mail[i], f)) {
            refuse_candidate(ItemKind::mail, i, *why);
        }
    }
    for (std::size_t i = 0; i < pool.sharepoint.size(); ++i) {
        if (const auto why = forbidden(pool.sharepoint[i].selector, targets, f)) {
            refuse_candidate(ItemKind::sharepoint, i, *why);
        }
    }
    for (std::size_t i = 0; i < pool.onedrive.size(); ++i) {
        if (const auto why = forbidden(pool.onedrive[i].selector, f)) {
            refuse_candidate(ItemKind::onedrive, i, *why);
        }
    }
}

Key key_of(const connector::MailSelector& m)
{
    return {ascii_lower(m.mailbox), m.folder, m.subject, m.received_at};
}
Key key_of(const connector::SharePointSelector& s)
{
    return {ascii_lower(s.site_id), ascii_lower(s.list_id), s.folder_path, s.name};
}
Key key_of(const connector::OneDriveSelector& o)
{
    return {ascii_lower(o.user), o.folder_path, o.name};
}

// Every field, so equal keys still sort one way whatever the listing's order.
Key all_of(const connector::MailSelector& m)
{
    return {m.mailbox, m.folder, m.subject, m.received_at};
}
Key all_of(const connector::SharePointSelector& s)
{
    return {s.site_id, s.drive_id, s.folder_path, s.name, s.list_id};
}
Key all_of(const connector::OneDriveSelector& o)
{
    return {o.user, o.folder_path, o.name};
}

const std::string& shown_name(const connector::MailSelector& m)
{
    return m.subject;
}
const std::string& shown_name(const connector::SharePointSelector& s)
{
    return s.name;
}
const std::string& shown_name(const connector::OneDriveSelector& o)
{
    return o.name;
}

void set_unchecked_size(connector::MailSelector&) {}
void set_unchecked_size(connector::SharePointSelector& s)
{
    s.size = -1;
}
void set_unchecked_size(connector::OneDriveSelector& o)
{
    o.size = -1;
}

template <typename Canary, typename Selector, typename ToSelector>
void select_kind(ItemKind kind, int size, const std::vector<Canary>& canaries, std::uint32_t cursor,
                 std::vector<Selector> candidates, const connector::BrowseRecord& browse,
                 std::uint32_t seed, ToSelector to_selector, std::vector<Selector>& out,
                 KindRecord& record)
{
    const std::size_t m = canaries.size();
    const int c = size == 0 ? 0 : static_cast<int>(std::min<std::size_t>((size + 1) / 2, m));
    const int r = size / 2;
    record.requested = size;
    record.cursor = cursor;
    record.cursor_next = m == 0 ? 0 : static_cast<std::uint32_t>((cursor + c) % m);
    record.canary_wanted = c;
    record.random_wanted = r;
    record.browse = browse;

    std::set<std::string> taken;
    for (int j = 0; j < c; ++j) {
        const Canary& canary = canaries[(cursor + static_cast<std::size_t>(j)) % m];
        out.push_back(to_selector(canary));
        record.canary_ids.push_back(canary.id);
        taken.insert(name_key(shown_name(out.back())));
    }

    // Sorted by key and then every field, one per key: the listing's order
    // doesn't matter.
    std::sort(candidates.begin(), candidates.end(), [](const Selector& a, const Selector& b) {
        const Key ka = key_of(a);
        const Key kb = key_of(b);
        return ka != kb ? ka < kb : all_of(a) < all_of(b);
    });
    candidates.erase(std::unique(candidates.begin(), candidates.end(),
                                 [](const Selector& a, const Selector& b) {
                                     return key_of(a) == key_of(b);
                                 }),
                     candidates.end());
    nlohmann::json keys = nlohmann::json::array();
    for (const Selector& candidate : candidates) {
        keys.push_back(key_of(candidate));
    }
    record.pool_size = candidates.size();
    record.pool_sha256 =
        sha256_hex(keys.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));

    if (r == 0 || candidates.empty()) {
        return;
    }
    SampleRng rng(stream_seed(seed, kind, Stream::items));
    Shuffle shuffle(rng, candidates.size());
    while (record.random_taken < r) {
        const std::optional<std::size_t> i = shuffle.next();
        if (!i) {
            break;
        }
        Selector picked = candidates[*i];
        // Skipped, its draw used up: two of one name (the case of any letter
        // aside, as SharePoint and OneDrive compare) can't both be restored.
        if (!taken.insert(name_key(shown_name(picked))).second) {
            continue;
        }
        record.random_keys.push_back(key_of(picked));
        set_unchecked_size(picked);
        out.push_back(std::move(picked));
        ++record.random_taken;
    }
}

template <typename Candidate>
auto selectors_of(const std::vector<Candidate>& candidates)
{
    std::vector<decltype(Candidate::selector)> out;
    out.reserve(candidates.size());
    for (const Candidate& candidate : candidates) {
        out.push_back(candidate.selector);
    }
    return out;
}

nlohmann::json kind_json(const KindRecord& k)
{
    return {
        {"requested", k.requested},
        {"canary",
         {{"cursor", k.cursor}, {"cursor_next", k.cursor_next}, {"wanted", k.canary_wanted},
          {"ids", k.canary_ids}}},
        {"random",
         {{"wanted", k.random_wanted},
          {"taken", k.random_taken},
          {"pool_size", k.pool_size},
          {"pool_sha256", k.pool_sha256},
          {"keys", k.random_keys},
          {"containers_eligible", k.browse.containers_eligible},
          {"containers_listed", k.browse.containers_listed},
          {"containers_unresolved", k.browse.containers_unresolved},
          {"folders_listed", k.browse.folders_listed},
          {"short_of_containers", k.browse.short_of_containers}}},
    };
}

// The canary exclusions a query carries, in manifest order, each once.
std::vector<std::string> unique_folded(std::vector<std::string> values)
{
    std::set<std::string> seen;
    std::vector<std::string> out;
    for (std::string& value : values) {
        if (seen.insert(ascii_lower(value)).second) {
            out.push_back(std::move(value));
        }
    }
    return out;
}

} // namespace

SamplePlan SamplePlan::from_config(const Config& config)
{
    return {config.sample_mail, config.sample_sp, config.sample_od};
}

nlohmann::json to_json(const SampleRecord& record)
{
    return {
        {"algorithm", record.algorithm},
        {"run_id", record.run_id},
        {"seed", seed_hex(record.seed)},
        {"manifest_sha256", record.manifest_sha256},
        {"mail", kind_json(record.mail)},
        {"sharepoint", kind_json(record.sharepoint)},
        {"onedrive", kind_json(record.onedrive)},
    };
}

Selection SampleSelector::select(const SamplePlan& plan, const CanaryManifest& manifest,
                                 const CanaryCursor& cursor,
                                 const connector::RestoreTargets& targets,
                                 const connector::CandidatePool& pool, std::string_view run_id)
{
    check_inputs(plan, manifest, cursor, run_id);
    check_canaries(manifest, targets);
    check_pool(pool, targets, Forbidden(manifest));

    Selection selection;
    SampleRecord& record = selection.record;
    record.run_id = std::string{run_id};
    record.seed = seed_from_run_id(run_id);
    record.manifest_sha256 = manifest.sha256;
    select_kind(ItemKind::mail, plan.mail, manifest.mail, cursor.mail, pool.mail, pool.mail_browse,
                record.seed, to_selector, selection.mail, record.mail);
    select_kind(ItemKind::sharepoint, plan.sharepoint, manifest.sharepoint, cursor.sharepoint,
                selectors_of(pool.sharepoint), pool.sharepoint_browse, record.seed,
                to_sharepoint_selector, selection.sharepoint, record.sharepoint);
    select_kind(ItemKind::onedrive, plan.onedrive, manifest.onedrive, cursor.onedrive,
                selectors_of(pool.onedrive), pool.onedrive_browse, record.seed,
                to_onedrive_selector, selection.onedrive, record.onedrive);
    return selection;
}

Selection choose_sample(connector::IConnector& connector, const std::string& client_ref,
                        const connector::RestorePoint& point,
                        const connector::RestoreTargets& targets,
                        const std::string& graph_tenant_id, const SamplePlan& plan,
                        const CanaryManifest& manifest, const CanaryCursor& cursor,
                        std::string_view run_id, const connector::CandidateLimits& limits)
{
    check_inputs(plan, manifest, cursor, run_id);
    if (!ascii_iequals(manifest.tenant_id, graph_tenant_id)) {
        throw ManifestError("canary manifest: /tenant_id: isn't the client's tenant (graph_tenant_id)");
    }
    // Pure: said before the connector is asked, so an unreachable backup
    // server can't hide a manifest that names a restore target.
    check_canaries(manifest, targets);
    connector::CandidatePool pool;
    if (plan.mail / 2 > 0 || plan.sharepoint / 2 > 0 || plan.onedrive / 2 > 0) {
        connector::CandidateQuery query{
            .client_ref = client_ref,
            .restore_point = point,
            .targets = targets,
            .mail = plan.mail / 2 > 0,
            .sharepoint = plan.sharepoint / 2 > 0,
            .onedrive = plan.onedrive / 2 > 0,
            .seed = seed_from_run_id(run_id),
            .exclude = {},
            .limits = limits,
        };
        std::vector<std::string> list_ids;
        for (const CanaryMail& mail : manifest.mail) {
            query.exclude.subjects.push_back(mail.subject);
        }
        for (const CanaryFile& file : manifest.sharepoint) {
            list_ids.push_back(file.list_id);
            query.exclude.sharepoint_names.push_back(file.name);
        }
        for (const CanaryFile& file : manifest.onedrive) {
            query.exclude.onedrive_names.push_back(file.name);
        }
        query.exclude.list_ids = unique_folded(std::move(list_ids));
        pool = connector.list_candidates(query);
    }
    return SampleSelector::select(plan, manifest, cursor, targets, pool, run_id);
}

} // namespace rp::sampling
