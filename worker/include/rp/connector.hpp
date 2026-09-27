#pragma once

// The connector interface (W1.7): what the Worker's pipeline and scheduler
// know about a backup product. A connector lists a client's restore points and
// restores a sample of items into the configured test locations; the pipeline
// then reads them back through Graph and decides pass/fail/error itself (W3.3).
// Nothing here names Veeam: the Veeam Backup for Microsoft 365 connector is
// rp/veeam_m365_connector.hpp, and code that holds an IConnector& never needs
// it. The choices are the 2026-09-27 W1.7 entry in docs/decisions.md.

#include <rp/config.hpp>

#include <cstddef>
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
    // Copies Config's test_* values. Throws std::invalid_argument ("restore
    // target <key> is empty") for an empty one, which load_config never
    // returns but a Config built in code could hold.
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
// lab/seed-manifest.json. W2.5 and W2.6 may add fields (such as an item ID
// from the backup's own listing).
struct MailSelector {
    std::string mailbox; // the source mailbox, e.g. alice@<domain>
    std::string folder;  // e.g. Inbox
    std::string subject;
};

struct SharePointSelector {
    std::string site_id;     // Graph site ID
    std::string drive_id;    // Graph drive ID of the library
    std::string folder_path; // e.g. "/"
    std::string name;        // file name
};

struct OneDriveSelector {
    std::string user;        // the drive's owner, e.g. alice@<domain>
    std::string folder_path; // e.g. "/RestoreTest"
    std::string name;        // file name
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
//  - not_run: nothing was sent to restore (an empty spec).
//  - succeeded: every restore session succeeded and restored every item sent
//    (Veeam: result Success and restoredItemsCount equal to the items sent).
//  - partial: something was restored, but not cleanly: a warning, a failed
//    session beside ones that restored items, or fewer items restored than
//    sent (Veeam: Warning; Failed beside restored items; Success with a short
//    restoredItemsCount).
//  - failed: nothing was restored (Veeam: every session Failed, or 0 restored).
// A failure to run at all (unreachable, refused, a guard violation) is an
// exception, never a status.
enum class RestoreStatus { not_run, succeeded, partial, failed };

// "not_run", "succeeded", "partial", "failed".
std::string_view to_string(RestoreStatus status) noexcept;

struct RestoreResult {
    RestoreStatus status = RestoreStatus::not_run;
    // The backup product's restore session IDs, one per session opened.
    std::vector<std::string> session_ids;
    // The sessions' own logs, as text, for the evidence bundle. Never holds a
    // credential.
    std::string log;
    // How many items the backup product says it restored.
    int items_restored = 0;
};

// Every error a connector throws. what() is safe to print and log: it never
// holds a credential, a token, a header or a body. The subclasses line up with
// rpworker's exit codes (rp/cli.hpp): AuthError 2, TransientError 3, the rest 4.
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
    // (W2.7) before any call for it.
    virtual RestoreResult restore_sample(const RestoreSpec& spec) = 0;

protected:
    IConnector() = default;
    IConnector(const IConnector&) = default;
    IConnector& operator=(const IConnector&) = default;
};

} // namespace rp::connector
