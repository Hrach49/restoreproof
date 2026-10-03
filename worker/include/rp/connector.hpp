#pragma once

// The connector interface (W1.7): what the Worker's pipeline and scheduler
// know about a backup product. A connector lists a client's restore points and
// restores a sample of items into the configured test locations; the pipeline
// then reads them back through Graph and decides pass/fail/error itself (W3.3).
// Nothing here names Veeam: the Veeam Backup for Microsoft 365 connector is
// rp/veeam_m365_connector.hpp, and code that holds an IConnector& never needs
// it. The choices are the 2026-09-27 W1.7 entry in docs/decisions.md.

#include <rp/config.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp::connector {

// Describe(): which connector this is, for logs and the result bundle.
struct ConnectorInfo {
    std::string name;    // the registry name, e.g. "veeam_m365"
    std::string version; // what the connector speaks, e.g. "v8" for Veeam's REST API
};

// A restore point as every connector reports it.
struct RestorePoint {
    // Opaque: meaningful only to the connector that returned it.
    std::string id;
    // When the backup ran, as the backup product wrote it (ISO-8601 UTC).
    // Kept byte for byte: Veeam opens a restore point by this exact string.
    std::string backup_time;
    bool has_mail = false;
    bool has_sharepoint = false;
    bool has_onedrive = false;
    // In an archive tier: a restore would need a retrieval first.
    bool is_archive = false;
};

// Where restored items go: the configured test locations, and nowhere else
// (CLAUDE.md, "Restore targets"). There is no way to build one from free-form
// values, so every restore target in the Worker comes from a validated
// Config. TargetGuard (W2.7) checks each item's target against these, inside
// restore_sample, before any call to the backup product.
class RestoreTargets {
public:
    // Copies Config's test_* values and checks them as parse_config does, since
    // a Config built in code skips that. Throws std::invalid_argument ("restore
    // target <key> is empty") for an empty one, and ("restore target
    // test_mailbox must be restoretest@<domain>") for a mailbox that
    // rp::is_restore_mailbox refuses.
    static RestoreTargets from_config(const Config& config);

    const std::string& mailbox() const noexcept { return mailbox_; }
    const std::string& site_id() const noexcept { return site_id_; }
    const std::string& library_id() const noexcept { return library_id_; }
    const std::string& onedrive_drive_id() const noexcept { return onedrive_drive_id_; }
    const std::string& onedrive_folder_id() const noexcept { return onedrive_folder_id_; }

private:
    RestoreTargets() = default;

    std::string mailbox_;            // test_mailbox, restoretest@<domain>
    std::string site_id_;            // test_site_id (Graph)
    std::string library_id_;         // test_library_id (Graph drive ID of RestoreTarget)
    std::string onedrive_drive_id_;  // test_onedrive_drive_id (Graph)
    std::string onedrive_folder_id_; // test_onedrive_folder_id (Graph item ID of /RestoreTarget)
};

// The items to restore, one selector per item, shaped like the entries of
// lab/seed-manifest.json. W2.5 added what the manifest has and the backup
// product needs to find an item without a Graph read of its source
// (docs/decisions.md 2026-09-30, W2.5 point 3).
struct MailSelector {
    std::string mailbox; // the source mailbox, e.g. alice@<domain>
    std::string folder;  // e.g. Inbox
    std::string subject;
    // Optional: when the message was received, "YYYY-MM-DDTHH:MM:SSZ" (the
    // manifest's received_at); set, the backup's copy must agree to the second.
    std::string received_at;

    bool operator==(const MailSelector&) const = default;
};

struct SharePointSelector {
    std::string site_id;     // Graph site ID, "<host>,<site GUID>,<web GUID>"
    std::string drive_id;    // Graph drive ID of the library
    std::string folder_path; // e.g. "/"
    std::string name;        // file name
    // The library's list GUID (the manifest's location.list_id). Required: the
    // library is found by it, never by its (localised) name.
    std::string list_id;
    // Optional: the size SharePoint stores (the manifest's stored_size); -1 = unchecked.
    std::int64_t size = -1;

    bool operator==(const SharePointSelector&) const = default;
};

struct OneDriveSelector {
    std::string user;        // the drive's owner, e.g. alice@<domain>
    std::string folder_path; // e.g. "/RestoreTest"
    std::string name;        // file name
    // Optional: the size OneDrive stores (the manifest's stored_size); -1 = unchecked.
    std::int64_t size = -1;

    bool operator==(const OneDriveSelector&) const = default;
};

// One restore_sample call. RestoreTargets has no default, so a spec can't be
// made without the configured targets.
struct RestoreSpec {
    std::string client_ref;     // as list_restore_points takes it
    RestorePoint restore_point; // as list_restore_points returned it
    RestoreTargets targets;
    std::vector<MailSelector> mail;
    std::vector<SharePointSelector> sharepoint;
    std::vector<OneDriveSelector> onedrive;

    std::size_t item_count() const noexcept
    {
        return mail.size() + sharepoint.size() + onedrive.size();
    }
};

// The restore's own outcome, as the backup product reported it. Not
// pass/fail/error: W3.3 decides those from this and the Graph comparison.
// Decided in this order; the first that fits wins:
//  1. not_run: nothing was sent to restore (an empty spec).
//  2. failed: nothing was restored, whatever the sessions' results say
//     (Veeam: 0 restored in total, so a Warning or a Success with 0 restored
//     is failed too).
//  3. succeeded: every restore session succeeded and every item sent is
//     shown restored (Veeam: result Success, restoredItemsCount equal to the
//     items sent, a Restore event with status Success for each item's name,
//     and for a file a Statistics entry with status Success for its ID).
//  4. partial: anything else: something was restored, but not cleanly (Veeam:
//     Warning; Failed beside restored items; Success with a short
//     restoredItemsCount or an item without its Success event).
// A failure to run at all (unreachable, refused, a guard violation, a session
// that restored nothing because the product couldn't reach Microsoft 365, a
// restore whose session couldn't be pinned down or read) is an exception,
// never a status.
// How the run's status reads it (W3.3, rp/run_status.hpp; docs/decisions.md
// 2026-10-01, W3.3 point 4): never as the verdict, since the check is the
// evidence. not_run is error not_run; failed with every item matching is
// error restore_contradiction; otherwise the items decide: a partial restore
// whose items all verify passes, with a backup_session warning per session
// that wasn't a Success, and an item not restored for an infrastructure
// reason that the check doesn't find is unchecked (backup_infrastructure),
// never failed.
enum class RestoreStatus { not_run, succeeded, partial, failed };

// "not_run", "succeeded", "partial", "failed".
std::string_view to_string(RestoreStatus status) noexcept;

// Which kind of item: a mail, a SharePoint file, a OneDrive file.
enum class ItemKind { mail, sharepoint, onedrive };

// "mail", "sharepoint", "onedrive".
std::string_view to_string(ItemKind kind) noexcept;

// What the backup product says became of one item.
enum class ItemOutcome {
    unknown,  // it said nothing about the item
    restored, // it says restored
    failed,   // it says the item's restore failed
};

// "unknown", "restored", "failed".
std::string_view to_string(ItemOutcome outcome) noexcept;

// One item of the spec, as the backup product reported it.
struct ItemRestoreResult {
    ItemKind kind = ItemKind::mail;
    std::string name;       // the mail's subject or the file's name
    std::string session_id; // the restore session it was sent in
    ItemOutcome outcome = ItemOutcome::unknown;
    // The product's message about it (or, with none, about its session), one
    // line, redacted; empty if none.
    std::string message;
    // Whether that message reads as the product failing to reach Microsoft
    // 365 or lacking permissions, not as the item being wrong.
    bool infrastructure = false;
};

// One restore session, as the backup product reported it.
struct RestoreSessionResult {
    std::string id;
    ItemKind kind = ItemKind::mail;
    std::string result;     // the product's result, e.g. Success, Warning, Failed
    std::string details;    // e.g. "5 items processed (5 successes)"; may be empty
    std::string started_at; // as the product wrote it (Veeam: creationTime)
    std::string ended_at;   // as the product wrote it (Veeam: endTime)
    int items_sent = 0;
    int items_restored = 0; // as the product counts them
    // This session's submit and wait, on the connector's own steady clock;
    // nullopt when the connector didn't measure it.
    std::optional<std::chrono::nanoseconds> submit_time;
    std::optional<std::chrono::nanoseconds> wait_time;
};

struct RestoreResult {
    RestoreStatus status = RestoreStatus::not_run;
    // The backup product's restore session IDs, one per session opened.
    std::vector<std::string> session_ids;
    // The sessions' own logs, as text, for the evidence bundle. Never holds a
    // credential.
    std::string log;
    // How many items the backup product says it restored.
    int items_restored = 0;
    // How many items were sent to restore.
    int items_sent = 0;
    // One per restore session, in the order they ran.
    std::vector<RestoreSessionResult> sessions;
    // One per item of the spec, in its order: mail, then SharePoint, then OneDrive.
    std::vector<ItemRestoreResult> items;
};

// Every error a connector throws. what() is safe to print and log: it never
// holds a credential, a token, a header or a body. The subclasses line up with
// rpworker's exit codes (rp/cli.hpp): AuthError 2, TransientError 3, the rest 4.
// One exception: a connector may let an rp::ConfigError out of the call that
// first needs a configured secret (VeeamM365Connector's restore_sample, for
// the Worker app's certificate), so a broken configuration keeps exit code 1;
// a caller that maps connector errors to a status maps ConfigError too
// (`error`, never `fail`).
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The backup product refused the credentials, the account's role or a token.
class AuthError : public Error {
public:
    using Error::Error;
};

// Might work later: unreachable, a timeout, a gateway error.
class TransientError : public Error {
public:
    using Error::Error;
};

// The client, restore point or item doesn't exist in the backup product.
class NotFoundError : public Error {
public:
    using Error::Error;
};

// The connector doesn't do this (yet).
class NotImplementedError : public Error {
public:
    using Error::Error;
};

// The restore-target guard (W2.7, rp/target_guard.hpp) refused the restore: an
// item sampled from a restore target, a configured target that isn't a
// dedicated RestoreTarget, or a restore request that names anything else.
// Nothing was restored. The run's status is `error`, never `fail`
// (docs/verification.md); rpworker's exit code is 4 (exit_code::service).
// what() starts with "target guard: " and never quotes a credential.
class SafetyViolation : public Error {
public:
    using Error::Error;
};

// W2.6: what the random half of a sample may be drawn from (docs/decisions.md
// 2026-09-30, W2.6). The connector lists a few containers' items, drawn with
// the query's seed, and keeps only those restore_sample will later find exactly
// once; the sampler (rp/sample_selector.hpp) picks from them.

// How far list_candidates looks, per type.
struct CandidateLimits {
    int containers_wanted = 2;     // stop once this many containers gave a candidate
    int containers_tried = 8;      // containers looked into, at most
    int folders_per_container = 3; // folders whose items are listed, per container
    int walk_depth = 2;            // file folder levels below a library or drive root
    int walk_calls = 20;           // folder-list calls per container
    // A file above this can't be read back (rp/graph_download.hpp's cap).
    std::int64_t max_file_bytes = 64ll * 1024 * 1024;
};

// The canary locations and items, from the manifest: never a random candidate.
// Names and subjects compare ASCII case-insensitively.
struct CandidateExclusions {
    std::vector<std::string> list_ids;         // the canary libraries' list GUIDs
    std::vector<std::string> subjects;         // canary mails, their Sent Items copies too
    std::vector<std::string> sharepoint_names; // canary SharePoint file names
    std::vector<std::string> onedrive_names;   // canary OneDrive file names
    // The top-level folders the OneDrive canaries are in (the first segment of
    // each folder_path; none for one at the root): never looked into, in any
    // OneDrive, besides RestoreTarget and RestoreTest, which never are.
    std::vector<std::string> onedrive_folders;
};

// One list_candidates call. RestoreTargets has no default, so neither has this.
struct CandidateQuery {
    std::string client_ref;     // as list_restore_points takes it
    RestorePoint restore_point; // as list_restore_points returned it
    RestoreTargets targets;
    // The types with a random half; the others are not browsed.
    bool mail = false;
    bool sharepoint = false;
    bool onedrive = false;
    // The run's seed (rp/sample_rng.hpp): which containers and folders are
    // looked into is drawn from it, so a run's listing can be repeated.
    std::uint32_t seed = 0;
    CandidateExclusions exclude;
    CandidateLimits limits;
};

// A mail candidate: its selector and what the backup lists of its header
// beyond it (W3.1, the random mail's expected fields): the sender's display
// name (Veeam's `from`, not an address) and the sent time,
// "YYYY-MM-DDTHH:MM:SSZ" cut to the second. Empty: the backup didn't say.
struct MailCandidate {
    MailSelector selector;
    std::string sender_name;
    std::string sent_at;
};

// A file candidate: its selector (size -1) and the size the backup holds.
struct SharePointCandidate {
    SharePointSelector selector;
    std::int64_t size_bytes = -1;
};

struct OneDriveCandidate {
    OneDriveSelector selector;
    std::int64_t size_bytes = -1;
};

// What one type's listing looked into, for the result bundle.
struct BrowseRecord {
    // Taken from the restore point alone, so a replay of the run finds the same.
    std::size_t containers_eligible = 0;
    // Mailbox address, Graph site ID or OneDrive owner, in the order looked
    // into; a OneDrive whose owner didn't resolve by its address.
    std::vector<std::string> containers_listed;
    // Drawn containers the backup product can't be asked to restore from
    // today (Veeam: a OneDrive that no single organisation user owns now, the
    // user deleted or renamed since the backup): they give no candidate, and
    // a replay that differs here explains a different pool.
    std::size_t containers_unresolved = 0;
    int folders_listed = 0;
    // Fewer than containers_wanted containers gave a candidate.
    bool short_of_containers = false;
};

struct CandidatePool {
    std::vector<MailCandidate> mail;
    std::vector<SharePointCandidate> sharepoint;
    std::vector<OneDriveCandidate> onedrive;
    BrowseRecord mail_browse;
    BrowseRecord sharepoint_browse;
    BrowseRecord onedrive_browse;
};

// How a restore_sample error message ends when no restore was sent.
inline constexpr std::string_view kNothingRestored = "; nothing was restored";

// A backup product as the pipeline sees it. One instance talks to one backup
// server with one set of credentials; each call names the client (an MSP's
// customer: one Microsoft 365 tenant) it is about.
class IConnector {
public:
    virtual ~IConnector() = default;

    // Offline: no call to the backup product.
    virtual ConnectorInfo describe() const = 0;

    // Every restore point of the client, newest first. `client_ref` names the
    // client as the backup product knows it (Veeam: the organisation name, as
    // Config::veeam_org_name). Throws NotFoundError for an unknown client and
    // the other Error subclasses as above.
    virtual std::vector<RestorePoint> list_restore_points(const std::string& client_ref) = 0;

    // Restores `spec`'s items from its restore point into its targets and
    // reports how that went. Checks each item's target with TargetGuard
    // (W2.7, rp/target_guard.hpp) before any call to the backup product, and
    // each restore request again just before it is sent; a refusal is a
    // SafetyViolation. A connector that reads the targets through Graph lets
    // Graph's errors (rp/graph_errors.hpp) out as they are, so a caller can
    // tell Graph from the backup product. An error it throws whose message
    // ends with kNothingRestored promises that no restore was sent; any other
    // may come after one was, so items may be in the targets (`rpworker
    // restore` says so).
    virtual RestoreResult restore_sample(const RestoreSpec& spec) = 0;

    // W2.6: the random half's candidates in `query`'s restore point, never
    // from a restore target or a canary location. Read-only for Microsoft 365
    // (it may open and close the product's own browsing sessions). The errors
    // of restore_sample, but never NotFoundError: nothing is sampled yet. The
    // default throws NotImplementedError("<describe().name>: listing
    // candidates isn't implemented").
    virtual CandidatePool list_candidates(const CandidateQuery& query);

protected:
    IConnector() = default;
    IConnector(const IConnector&) = default;
    IConnector& operator=(const IConnector&) = default;
};

} // namespace rp::connector
