#pragma once

// Emptying the three restore targets before and after each run (W3.4,
// docs/decisions.md 2026-10-02): the restoretest mailbox's Inbox, the
// RestoreTarget library in the RestoreTest site and alice's OneDrive
// /RestoreTarget folder. The Cleaner is the only Worker code that deletes in
// the tenant, and the only code that can reach GraphClient::remove: it
// resolves each target with the guard's own Graph checks
// (rp/target_guard_graph.hpp), lists it under the resolved IDs, and deletes
// only what that listing showed. Nothing here names the canaries' RestoreTest
// library or /RestoreTest folder.

#include <rp/connector.hpp>
#include <rp/graph_client.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace rp::graph {

enum class CleanupWhen { before_run, after_run };

// What a clean did to one target. Counts and a code only: never a name or an ID.
struct TargetCleanup {
    // "" or what stopped it, or the code of the first delete Graph refused in
    // the last round when something was left after it: target_guard, graph_auth, graph_permission,
    // graph_transient, graph (as verification::read_error_code), config (an
    // rp::ConfigError, such as a CertificateError on the token) or internal
    // (anything else).
    std::string error_code;
    // Mails or plain files in the first listing (round 1's, or round 2's when
    // round 1 stopped before it).
    std::size_t found = 0;
    std::size_t deleted = 0; // Graph answered 204
    std::size_t gone = 0;    // Graph answered 404 for an item this call listed
    // Mails or plain files in the last listing made (after the last round's
    // deletes, or before them if that round stopped there). A listing reads at
    // most kMaxListPages pages: past them, `left` counts only what it read.
    std::size_t left = 0;
    // Entries of the last listing that are not plain files or mails, or fail
    // their place or ID rule: never deleted, left for the owner.
    std::size_t skipped = 0;
    unsigned rounds = 0; // 1 or 2 once clean() has run

    // error_code empty, left == 0 and skipped == 0.
    bool ok() const noexcept;
};

struct CleanupResult {
    CleanupWhen when = CleanupWhen::before_run;
    TargetCleanup mail;
    TargetCleanup sharepoint;
    TargetCleanup onedrive;

    // All three ok.
    bool ok() const noexcept;
};

struct CleanerOptions {
    // Where the Cleaner's lines go (what it skipped, deleted and why it
    // stopped; the SECURITY line of a refusal); null = spdlog's default logger
    // at the time of the call, and nothing if that is null too. Every line
    // goes through rp::redact.
    std::shared_ptr<spdlog::logger> logger;
};

// Not thread-safe, like TargetReader.
class Cleaner {
public:
    // `graph` must outlive the Cleaner. Sends nothing.
    Cleaner(GraphClient& graph, connector::RestoreTargets targets, CleanerOptions options = {});

    // Cleans all three targets, always, whatever a run sampled; one target's
    // failure never stops the others. Never throws: a failure is its target's
    // error_code. Per target, at most two rounds, each one:
    //  1. resolve the target with check_restore_mailbox, check_restore_library
    //     or check_restore_onedrive_folder, worded "deletes only in ...;
    //     nothing was deleted". A WrongTargetError is logged once as
    //     "SECURITY: cleanup: <message>" and is error_code target_guard;
    //  2. list it under the resolved IDs only (mail: $select=id with
    //     kMailPrefer; files: no content), every nextLink pinned to the target
    //     by graph_paging's rules, at most kMaxListPages pages: a target that
    //     holds more is cleaned up to them and ends with `left` > 0, never an
    //     error;
    //  3. keep only what may be deleted: a mail whose ID passes is_listed_id;
    //     a file whose parentReference names the resolved drive and (OneDrive)
    //     the folder or (library) the drive's root, whose ID passes
    //     is_graph_item_id and isn't its parent's (in the library the parent
    //     is the root, so the root's own ID is refused too; an entry with a
    //     `root` facet is never deleted either), with a printable eTag, a
    //     file facet and no folder, package, remoteItem or root facet. Anything
    //     else is logged and counted `skipped`, never deleted;
    //  4. delete each with GraphClient::remove (a mail's permanentDelete, a
    //     file's If-Match DELETE): 204 deleted, 404 gone, 412 left for the
    //     next round. Any other GraphError on one delete, but a TransientError
    //     (which ends the round) and an AuthError (which stops the target), is
    //     that item's: logged, and the other items are still deleted;
    //  5. list again: `left`.
    // Round 2 runs when round 1 ended with something left (a 412 included) or
    // in a TransientError, never after any other error or a refused delete.
    CleanupResult clean(CleanupWhen when) noexcept;

private:
    struct Target;
    struct Resolved;
    struct Listing;

    // At most two rounds on one target; `phase` is "before" or "after", for
    // the log.
    TargetCleanup clean_target(const Target& target, std::string_view phase) noexcept;
    // The guard's check of the target; throws what the check throws.
    Resolved resolve(const Target& target);
    // One listing of the resolved target: the ListedItems it may delete.
    Listing list(const Target& target, const Resolved& resolved);
    // Why a listed file entry may not be deleted (what the log calls it), or
    // nullopt.
    static std::optional<std::string_view> not_deletable(const nlohmann::json& entry,
                                                         const Target& target,
                                                         const Resolved& resolved);
    // Counts and logs an entry left alone; `id` may be null.
    void skip(Listing& listing, const std::string& location, std::string_view kind,
              const std::string* id) const;
    void log(spdlog::level::level_enum level, const std::string& line) const;

    GraphClient& graph_;
    connector::RestoreTargets targets_;
    CleanerOptions options_;
};

// {"mail": {...}, "sharepoint": {...}, "onedrive": {...}}, each target with
// found, deleted, gone, left, skipped, rounds, and error_code only when set:
// the counts and codes of the run's cleanup object (W3.4 point 7).
nlohmann::json to_json(const CleanupResult& result);

} // namespace rp::graph
