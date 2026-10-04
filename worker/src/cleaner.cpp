#include <rp/cleaner.hpp>

#include <rp/checker.hpp>
#include <rp/config.hpp>
#include <rp/graph_errors.hpp>
#include <rp/redact.hpp>
#include <rp/target_guard_graph.hpp>

#include "graph_paging.hpp"
#include "json_fields.hpp"
#include "target_guard_refuse.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <optional>
#include <utility>
#include <vector>

namespace rp::graph {

namespace {

using nlohmann::json;

// How the guard's Graph checks word a refusal here.
constexpr TargetCheckWording kCleanupWording{"deletes only in", "nothing was deleted"};

// Nothing is downloaded and no body is read (W3.4 point 2).
constexpr std::string_view kMailQuery = "?$select=id&$top=100";
constexpr std::string_view kFileQuery =
    "?$select=id,name,eTag,file,folder,package,remoteItem,root,parentReference&$top=200";

// "One retry" is one more round (W3.4 point 6).
constexpr unsigned kMaxRounds = 2;

// The facets that make an entry something other than a plain file, and what
// the log calls it. Deleting a folder or a package would take content this
// call never listed; a remoteItem is a shortcut to someone else's item.
constexpr std::pair<std::string_view, std::string_view> kNotPlainFile[] = {
    {"folder", "a folder"},
    {"package", "a package"},
    {"remoteItem", "a shortcut to another item"},
    {"root", "a drive's root"},
};

// Whether `etag` can go into If-Match as it is: 1 to 512 printable ASCII
// characters.
bool is_usable_etag(const std::string* etag)
{
    return etag != nullptr && !etag->empty() && etag->size() <= 512 &&
           std::all_of(etag->begin(), etag->end(), [](char c) { return c >= 0x20 && c < 0x7F; });
}

} // namespace

// One of the three targets, as clean_target walks it.
struct Cleaner::Target {
    enum class Kind { mail, sharepoint, onedrive };
    Kind kind;
    std::string_view location; // as in log lines
};

// What resolve() established: the mailbox's address or the drive, and for the
// OneDrive target its folder. Every value comes from the guard's checks.
struct Cleaner::Resolved {
    std::string container;
    std::string folder_id;
    // A file target's own count of its children, read as it was resolved.
    std::optional<std::uint64_t> child_count;
};

// What one listing found that may be deleted, and how many entries it left
// alone.
struct Cleaner::Listing {
    std::vector<ListedItem> items;
    std::size_t skipped = 0;
};

namespace {

// The log line of a listing cut at kMaxListPages.
std::string past_limit_line(const std::string& location)
{
    return "cleanup: " + location + " lists more than " + std::to_string(kMaxListPages) +
           " pages; what lies past them is left for the next round or run";
}

} // namespace

bool TargetCleanup::ok() const noexcept
{
    return error_code.empty() && left == 0 && skipped == 0;
}

bool CleanupResult::ok() const noexcept
{
    return mail.ok() && sharepoint.ok() && onedrive.ok();
}

Cleaner::Cleaner(GraphClient& graph, connector::RestoreTargets targets, CleanerOptions options)
    : graph_(graph), targets_(std::move(targets)), options_(std::move(options))
{
}

CleanupResult Cleaner::clean(CleanupWhen when) noexcept
{
    const std::string_view phase = when == CleanupWhen::before_run ? "before" : "after";
    CleanupResult result;
    result.when = when;
    result.mail = clean_target({Target::Kind::mail, "the test mailbox's Inbox"}, phase);
    result.sharepoint =
        clean_target({Target::Kind::sharepoint, "the RestoreTarget library"}, phase);
    result.onedrive = clean_target({Target::Kind::onedrive, "the test OneDrive folder"}, phase);
    return result;
}

TargetCleanup Cleaner::clean_target(const Target& target, std::string_view phase) noexcept
{
    const std::string where = "cleanup " + std::string{phase} + ": " + std::string{target.location};
    TargetCleanup out;
    bool listed = false;
    // The code of the first delete Graph refused in the last round, while
    // something is left after it: what kept the target from being emptied.
    std::string refused_code;
    const auto stopped = [&](const std::string& code, std::string_view what) {
        out.error_code = code;
        log(spdlog::level::err, where + ": stopped (" + code + ")" +
                                    (what.empty() ? "" : ": " + std::string{what}));
    };
    try {
        for (unsigned round = 1; round <= kMaxRounds; ++round) {
            out.rounds = round;
            bool again = false; // a TransientError ended round 1
            try {
                // Per round: resolve, list, delete what was listed, list again.
                const Resolved resolved = resolve(target);
                Listing listing = list(target, resolved, true);
                if (!listed) {
                    out.found = listing.items.size();
                    listed = true;
                }
                out.left = listing.items.size();
                out.skipped = listing.skipped;
                refused_code.clear();
                std::string round_refused;
                for (const ListedItem& item : listing.items) {
                    try {
                        switch (graph_.remove(item)) {
                        case RemoveOutcome::removed:
                            ++out.deleted;
                            break;
                        case RemoveOutcome::gone:
                            ++out.gone;
                            break;
                        case RemoveOutcome::changed:
                            log(spdlog::level::info, where + ": " + item.id() +
                                                         " changed since it was listed; the next "
                                                         "round lists it again");
                            break;
                        }
                    } catch (const TransientError&) {
                        throw; // the round's, as a listing's
                    } catch (const AuthError&) {
                        throw; // the token's: no other delete would get through
                    } catch (const GraphError& e) {
                        // This item's refusal (a locked or checked-out file, a
                        // labelled mail): the other items are still tried, and
                        // it stays for the next round or run.
                        const std::string code =
                            verification::read_error_code(std::current_exception());
                        if (round_refused.empty()) {
                            round_refused = code;
                        }
                        log(spdlog::level::warn, where + ": " + item.id() + " not deleted (" +
                                                     code + "): " + e.what());
                    }
                }
                // Not held to the count: it was read before this round's deletes.
                listing = list(target, resolved, false);
                out.left = listing.items.size();
                out.skipped = listing.skipped;
                if (out.left > 0) {
                    refused_code = round_refused;
                }
            } catch (const TransientError& e) {
                // A second round may get through; after it, the error stands.
                if (round == kMaxRounds) {
                    throw;
                }
                log(spdlog::level::warn, where + ": " + e.what() + "; one more round");
                again = true;
            }
            // A refused delete gets no second round: Graph would refuse it
            // again.
            if (!again && (out.left == 0 || !refused_code.empty())) {
                break;
            }
        }
        if (!refused_code.empty()) {
            stopped(refused_code, "a delete Graph refused left the target not emptied");
        }
        log(out.ok() ? spdlog::level::info : spdlog::level::warn,
            where + ": deleted " + std::to_string(out.deleted) + ", gone " +
                std::to_string(out.gone) + ", left " + std::to_string(out.left) + ", skipped " +
                std::to_string(out.skipped) + " in " + std::to_string(out.rounds) + " round(s)");
    } catch (const WrongTargetError& e) {
        // The guard refused the target: nothing (more) is deleted in it.
        log_security(options_.logger, "cleanup: " + std::string{e.what()});
        out.error_code = "target_guard";
    } catch (const ConfigError& e) {
        stopped("config", e.what());
    } catch (const GraphError& e) {
        stopped(verification::read_error_code(std::current_exception()), e.what());
    } catch (...) {
        // Anything else is the Worker's own failure; its text is never copied.
        stopped("internal", {});
    }
    return out;
}

Cleaner::Resolved Cleaner::resolve(const Target& target)
{
    if (target.kind == Target::Kind::mail) {
        return {check_restore_mailbox(graph_, targets_, kCleanupWording).address, {}};
    }
    if (target.kind == Target::Kind::sharepoint) {
        std::string drive = check_restore_library(graph_, targets_, kCleanupWording).drive_id;
        const std::optional<std::uint64_t> child_count = library_child_count(graph_, drive);
        return {std::move(drive), {}, child_count};
    }
    // The check resolves the configured folder itself: its folder_id is
    // test_onedrive_folder_id, which it read by that ID and checked.
    const ResolvedOneDriveFolder folder =
        check_restore_onedrive_folder(graph_, targets_, kCleanupWording);
    return {folder.drive_id, targets_.onedrive_folder_id(), folder.child_count};
}

Cleaner::Listing Cleaner::list(const Target& target, const Resolved& resolved, bool whole)
{
    const std::string what{target.location};
    const std::string& container = resolved.container;
    Listing listing;
    if (target.kind == Target::Kind::mail) {
        // The mailbox's place is proved by the resolved address, the
        // Inbox-scoped path and the paging rule (W3.4 point 4.3).
        bool past_limit = false;
        const std::vector<json> pages = list_pages(
            graph_, "/users/" + container + "/mailFolders/inbox/messages" + std::string{kMailQuery},
            kMailGrant, {{"Prefer", std::string{kMailPrefer}}}, what,
            [&container](const std::vector<std::string>& path) {
                return is_inbox_path(path, container);
            },
            &past_limit);
        if (past_limit) {
            log(spdlog::level::warn, past_limit_line(what));
        }
        for (const json& page : pages) {
            for (const json& message : page.at("value")) {
                const std::string* id = string_at(message, "id");
                if (id == nullptr || !is_listed_id(*id)) {
                    skip(listing, what, "a message with an ID the Worker won't put in a URL", id);
                    continue;
                }
                listing.items.push_back(ListedItem::mail(container, *id));
            }
        }
        return listing;
    }
    const bool library = target.kind == Target::Kind::sharepoint;
    const std::string& folder = resolved.folder_id;
    bool past_limit = false;
    const std::vector<json> pages =
        library ? list_pages(graph_, "/drives/" + container + "/root/children" +
                                         std::string{kFileQuery},
                             kSitesReadGrant, {}, what,
                             [&container](const std::vector<std::string>& path) {
                                 return is_library_root_path(path, container);
                             },
                             &past_limit)
                : list_pages(graph_, "/drives/" + container + "/items/" + folder + "/children" +
                                         std::string{kFileQuery},
                             kOneDriveGrant, {}, what,
                             [&container, &folder](const std::vector<std::string>& path) {
                                 return is_folder_path(path, container, folder);
                             },
                             &past_limit);
    if (past_limit) {
        log(spdlog::level::warn, past_limit_line(what));
    } else if (whole) {
        // A listing cut at the page limit is short by design; any other that
        // is shorter than the container's count was trimmed.
        check_listing_whole(resolved.child_count, listed_entries(pages),
                            library ? kSitesReadGrant : kOneDriveGrant, what);
    }
    for (const json& page : pages) {
        for (const json& entry : page.at("value")) {
            const std::string* id = string_at(entry, "id");
            const std::optional<std::string_view> why = not_deletable(entry, target, resolved);
            if (why) {
                skip(listing, what, *why, id);
                continue;
            }
            const std::string etag = *string_at(entry, "eTag");
            listing.items.push_back(library ? ListedItem::library_file(container, *id, etag)
                                            : ListedItem::onedrive_file(container, *id, etag));
        }
    }
    return listing;
}

std::optional<std::string_view> Cleaner::not_deletable(const json& entry, const Target& target,
                                                       const Resolved& resolved)
{
    const std::string* id = string_at(entry, "id");
    if (id == nullptr || !is_graph_item_id(*id)) {
        return "an entry with an ID the Worker won't put in a URL";
    }
    // Only plain files (W3.4 point 4.5).
    for (const auto& [facet, kind] : kNotPlainFile) {
        if (entry.contains(facet)) {
            return kind;
        }
    }
    const auto file = entry.find("file");
    if (file == entry.end() || !file->is_object()) {
        return "an entry that is not a file";
    }
    // The file proves its place (W3.4 point 4.3).
    const auto parent = entry.find("parentReference");
    const json none;
    const json& reference = parent == entry.end() ? none : *parent;
    const std::string* drive = string_at(reference, "driveId");
    if (drive == nullptr || *drive != resolved.container) {
        return "a file whose parentReference names another drive";
    }
    const std::string* parent_id = string_at(reference, "id");
    if (target.kind == Target::Kind::onedrive) {
        if (parent_id == nullptr || *parent_id != resolved.folder_id) {
            return "a file whose parentReference is not the RestoreTarget folder";
        }
    } else {
        const std::string* path = string_at(reference, "path");
        if (path == nullptr ||
            (*path != "/drive/root:" && *path != "/drives/" + resolved.container + "/root:")) {
            return "a file whose parentReference is not the library's root";
        }
    }
    if (parent_id != nullptr && *parent_id == *id) {
        return "an entry with its parent's ID";
    }
    if (!is_usable_etag(string_at(entry, "eTag"))) {
        return "a file without an eTag the Worker can send";
    }
    return std::nullopt;
}

void Cleaner::skip(Listing& listing, const std::string& location, std::string_view kind,
                   const std::string* id) const
{
    ++listing.skipped;
    log(spdlog::level::warn, "cleanup: skipped " + std::string{kind} + " in " + location + ": " +
                                 (id ? *id : std::string{"(no ID)"}) +
                                 " (never deleted; left for the owner)");
}

void Cleaner::log(spdlog::level::level_enum level, const std::string& line) const
{
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger =
        options_.logger ? options_.logger : spdlog::default_logger();
    if (logger && logger->should_log(level)) {
        logger->log(level, "{}", redact(line));
    }
}

json to_json(const CleanupResult& result)
{
    const auto target = [](const TargetCleanup& t) {
        json out = {{"found", t.found},     {"deleted", t.deleted}, {"gone", t.gone},
                    {"left", t.left},       {"skipped", t.skipped}, {"rounds", t.rounds}};
        if (!t.error_code.empty()) {
            out["error_code"] = t.error_code;
        }
        return out;
    };
    return {{"mail", target(result.mail)},
            {"sharepoint", target(result.sharepoint)},
            {"onedrive", target(result.onedrive)}};
}

} // namespace rp::graph
