#pragma once

// The pure parts of VeeamM365Connector::restore_sample (W2.5): names and
// times as Veeam writes them, the preflight and duplicate-check filters, how
// items are split into restore calls, the restore bodies, and reading a
// stopped restore session into a verdict. No request is made here; the
// connector (veeam_m365_connector.cpp) does the calls. The flow is
// docs/api/veeam-restore-flow.md §2-§16 and docs/api/veeam-m365/10-restore.ps1;
// the choices are the 2026-09-30 W2.5 entry in docs/decisions.md.

#include <rp/connector.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp::veeam_restore {

// The timings of restore-flow §8-§10.
inline constexpr std::chrono::milliseconds kPollInterval{5'000};
inline constexpr std::chrono::milliseconds kPollDeadline{20 * 60'000};
inline constexpr std::chrono::milliseconds kPostTimeout{60'000};
// No session ID from the POST: the first look, then this many more, this far apart.
inline constexpr int kDuplicateRelooks = 3;
inline constexpr std::chrono::milliseconds kDuplicateRelookWait{10'000};
// Statistics answer 409 for a while after a session stops.
inline constexpr int kStatisticsAttempts = 6;
inline constexpr std::chrono::milliseconds kStatisticsWait{5'000};
// Polls failing in a row before there is no verdict.
inline constexpr int kMaxPollFailures = 6;
// The preflight's one page of GET /v8/RestoreSessions.
inline constexpr int kPreflightLimit = 200;
// The duplicate check asks for sessions from the POST time less the window,
// and keeps those created no earlier than the POST time less the floor.
inline constexpr std::chrono::seconds kDuplicateWindow{60};
inline constexpr std::chrono::seconds kDuplicateFloor{5};
inline constexpr int kDuplicateLimit = 50;
// Events are read a page of this many at a time, at most kMaxEventPages pages.
inline constexpr int kEventsPageSize = 100;
inline constexpr int kMaxEventPages = 100;

using UtcTime = std::chrono::sys_time<std::chrono::nanoseconds>;

// A Veeam reply of an unexpected shape. what() names the field, never a body.
class ShapeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Veeam's session type for the kind: Vex, Vesp, Veod.
std::string_view session_type(connector::ItemKind kind) noexcept;

// Every byte but ASCII letters, digits and -._~ as %XX: for a value put into
// a path segment or a query.
std::string percent_encode(std::string_view text);

// The account as Veeam lists it in initiatedBy: the part after the last '\\'
// (DESKTOP-P55CDUM\rp-veeam -> rp-veeam).
std::string bare_account(std::string_view username);

// "YYYY-MM-DDTHH:MM:SSZ" in UTC, cut (not rounded) to the second.
std::string format_utc_seconds(std::chrono::system_clock::time_point time);

// Veeam's UTC form, "YYYY-MM-DDTHH:MM:SS" with 0 to 7 fractional digits and
// "Z", as a time; nullopt for any other text, an impossible date, or a year
// outside 1678-2261 (what a time in nanoseconds holds).
std::optional<UtcTime> parse_veeam_time(std::string_view text);

// A Veeam time cut (not rounded) to "YYYY-MM-DDTHH:MM:SSZ"; nullopt when it
// isn't Veeam's UTC form.
std::optional<std::string> to_whole_seconds(std::string_view text);

// Veeam's site ID for a Graph site ID "<host>,<site GUID>,<web GUID>": the two
// GUIDs run together, lower case; nullopt when it isn't one.
std::optional<std::string> veeam_site_id(std::string_view graph_site_id);

// The personal OneDrive address SharePoint gives `user` on the tenant of
// `sharepoint_host` ("<tenant>.sharepoint.com"):
// https://<tenant>-my.sharepoint.com/personal/<user, lower case, '@' and '.'
// as '_'>; nullopt for another host or an empty user.
std::optional<std::string> onedrive_url(std::string_view sharepoint_host, std::string_view user);

// A folder path's segments, empty and "." ones skipped ("/" and "" have none).
std::vector<std::string> path_segments(std::string_view folder_path);

// One or more UUIDs run together (any case): safe in a URL path as it is.
bool is_uuid_run(std::string_view id) noexcept;

// Whether `text` reads as Veeam failing to reach Microsoft 365 or lacking
// permissions (ASCII case-insensitive): "Cannot connect to Microsoft 365",
// "Failed to open mailbox", "missing the required application permissions",
// "AADSTS".
bool is_infrastructure_text(std::string_view text);

// The IDs of GET /v8/RestoreSessions results that are Working and were
// started by `account` (ASCII case-insensitive). ShapeError without a
// "results" list, or for a field of the wrong kind.
std::vector<std::string> working_sessions(const nlohmann::json& list, std::string_view account);

// What the duplicate check keeps (restore-flow §8).
struct DuplicateFilter {
    std::string account;          // the bare account name
    std::string type;             // Vex, Vesp or Veod
    std::set<std::string> known;  // every session ID this run already knows
    UtcTime floor{};              // the POST time less kDuplicateFloor
};

// The IDs of GET /v8/RestoreSessions?startTimeFrom=... results that could be
// the restore just posted: initiatedBy the account (ASCII case-insensitive),
// type the call's, a lower-case UUID not already known, and a creationTime
// (Veeam's form) no earlier than the floor. Entries missing any of these
// aren't kept. ShapeError without a "results" list.
std::vector<std::string> new_restore_sessions(const nlohmann::json& list,
                                              const DuplicateFilter& filter);

// One restore call per source container; items of one container whose names
// repeat go into separate calls (the first of a name in call 1, the second in
// call 2, ...). Returns the calls as indices, containers in the order they
// first appear, each call's items in their order. `containers` and `names`
// are the same length.
std::vector<std::vector<std::size_t>> split_calls(const std::vector<std::string>& containers,
                                                  const std::vector<std::string>& names);

// The organisation's values every restore body carries.
struct OrganizationFacts {
    std::string application_id;
    std::string organization_name; // officeName, else name
    std::string office_region;
};

// The restore bodies of restore-flow §5, keys in Veeam's order, as
// docs/api/veeam-m365/10-restore.ps1 sends them. applicationCertificate and
// applicationCertificatePassword are empty strings for the caller to fill.
nlohmann::ordered_json mail_body(const std::vector<std::string>& item_ids,
                                 const std::string& target_mailbox, const OrganizationFacts& org);
nlohmann::ordered_json sharepoint_body(std::vector<nlohmann::ordered_json> documents,
                                       const std::string& site_url, const std::string& list,
                                       const OrganizationFacts& org);
nlohmann::ordered_json onedrive_body(std::vector<nlohmann::ordered_json> documents,
                                     const nlohmann::ordered_json& onedrive,
                                     const std::string& folder, const OrganizationFacts& org);

// A document as a restore body carries it: Veeam's re-read without _links and
// _actions, the other keys in its order.
nlohmann::ordered_json body_document(nlohmann::ordered_json reread);

// GET /v8/RestoreSessions/{id}, the fields read.
struct SessionState {
    std::string state;         // Working or Stopped
    std::string result;        // Success, Warning, Failed; empty if none
    std::string details;       // empty if none
    std::string creation_time; // as Veeam wrote it; empty if none
    std::string end_time;      // as Veeam wrote it; empty if none
};

// ShapeError unless `state` is a string; the others may be missing or null,
// but not of another kind.
SessionState read_session(const nlohmann::json& session);

struct StatisticsItem {
    std::string id;
    std::string status;
};

// GET .../Statistics.
struct Statistics {
    std::int64_t restored = 0; // restoredItemsCount
    std::vector<StatisticsItem> items;
    std::vector<std::string> errors; // errors[], if any
};

// ShapeError unless restoredItemsCount is a whole number of 0 or more, items
// an array of objects, and errors (if there) an array of strings; an item's
// id and status may be missing, not of another kind.
Statistics read_statistics(const nlohmann::json& statistics);

// One entry of GET .../Events; a missing or null field is empty.
struct Event {
    std::string type;   // Restore for an item, None for the session
    std::string status; // Success, Warning, Failed, ...
    std::string item_name;
    std::string title;
    std::string message;
};

// The results of one page of events. ShapeError without a "results" array of
// objects, or for a field of another kind than a string.
std::vector<Event> read_events(const nlohmann::json& page);

// An item as it was sent: its name (subject or file name) and, for a file,
// Veeam's document ID.
struct SentItem {
    std::string name;
    std::string id;
};

// What one stopped restore session says (restore-flow §12).
struct SessionVerdict {
    // One per sent item, in their order; kind, name, session_id, outcome,
    // message and infrastructure set.
    std::vector<connector::ItemRestoreResult> items;
    // A session-level event's title or message, a statistics error, or a
    // failing item event's title or message with the item's name cut out,
    // reads as infrastructure; `infrastructure_text` is the first such, one
    // line. An item name is the tenant's text and never counts.
    bool infrastructure = false;
    std::string infrastructure_text;
    // result Success, restoredItemsCount equal to the items sent, every item restored.
    bool succeeded = false;
    // The session's lines for RestoreResult::log, redacted, one line each.
    std::vector<std::string> log_lines;
};

// An item is restored when an event of type Restore with status Success names
// it (itemName, ordinal) and, for a file, a statistics item with status
// Success has its ID (OneDrive: the document ID; SharePoint: its last 36
// characters; ASCII case-insensitive); failed when a Restore event names it
// with another status; else unknown, with the session's failure message.
SessionVerdict judge(connector::ItemKind kind, const std::string& session_id,
                     const SessionState& session, const Statistics& statistics,
                     const std::vector<Event>& events, const std::vector<SentItem>& sent);

// The W1.7 order with W2.5's stricter succeeded (rp/connector.hpp): not_run
// without a session, failed with nothing restored, succeeded when every
// session succeeded, else partial.
connector::RestoreStatus overall_status(std::size_t sessions, std::int64_t restored,
                                        bool all_succeeded) noexcept;

} // namespace rp::veeam_restore
