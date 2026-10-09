#pragma once

// restoreproof.result.v1 (W4.1, docs/decisions.md 2026-10-04): the document a
// run's parts make, its canonical text and whether that text is valid by the
// embedded schema (rp/result_schema.hpp). Pure: no clock, no file, no network.
// The builder adds nothing the parts' own to_json objects don't say.

#include <rp/checker.hpp>
#include <rp/client_profile.hpp>
#include <rp/connector.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/expected_set.hpp>
#include <rp/restore_command.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_selector.hpp>
#include <rp/step_timer.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace rp {

inline constexpr std::string_view kResultFormat = "restoreproof.result.v1";

// What the client check resolved (W4.11, docs/decisions.md 2026-10-09 point
// 7): the backup product's organisation as it reported it, and the names and
// URLs the three restore targets resolved to in the tenant. Set exactly when
// the check passed; the result's `client.resolved`, with `client.scope`
// "same_tenant" beside it.
struct ResolvedClient {
    std::string organization_name;   // the product's name for the organisation
    std::string organization_tenant; // its tenant ID (Veeam's msid), as sent
    std::string organization_type;   // e.g. Office365
    std::string organization_region; // e.g. Worldwide
    std::string inbox_id;            // the mailbox's Inbox, as Graph wrote it
    std::string library_name;        // RestoreTarget
    std::string library_list_id;     // sharePointIds.listId
    std::string library_site_url;    // sharePointIds.siteUrl
    std::string folder_name;         // RestoreTarget
    std::string folder_site_url;     // the OneDrive's sharepointIds.siteUrl

    bool operator==(const ResolvedClient&) const = default;
};

// The result's `client` object (point 6; W4.10): the job's client_id (null
// at a prompt), and of the client's profile the tenant, the backup product's
// organisation and the three restore targets' IDs. Not the app's ID. Since
// W4.11 also `scope` ("same_tenant" when the client check passed, else null)
// and `resolved` (what it resolved, else null): one field, `resolved`, set
// exactly when the check passed.
struct ResultClient {
    std::optional<std::string> client_id;
    std::string tenant_id;          // graph_tenant_id
    std::string veeam_org_name;
    std::string mailbox;            // test_mailbox
    std::string site_id;            // test_site_id
    std::string library_id;         // test_library_id
    std::string onedrive_drive_id;  // test_onedrive_drive_id
    std::string onedrive_folder_id; // test_onedrive_folder_id
    std::optional<ResolvedClient> resolved;

    bool operator==(const ResultClient&) const = default;
};

// The word `client.scope` holds when the check passed.
inline constexpr std::string_view kScopeSameTenant = "same_tenant";

// The client as a profile gives it (W4.10): the one mapping of a profile to
// the result's object, for the result and for the service's close of a run
// (W4.8). `client_id` is the job's, nullopt at a prompt. `resolved` is left
// unset: the pipeline fills it once the client check passed (W4.11).
ResultClient result_client(const ClientProfile& profile, std::optional<std::string> client_id);

// One run's parts. The pointers are borrowed for the call only; null where a
// step didn't run.
struct ResultParts {
    std::string worker_version;
    std::string run_id;
    // "YYYY-MM-DDTHH:MM:SS.mmmZ"; nullopt when the clock failed, and
    // ended_at while the run hasn't ended.
    std::optional<std::string> started_at;
    std::optional<std::string> ended_at;
    connector::ConnectorInfo connector; // IConnector::describe()
    ResultClient client;
    std::string restore_point_id;
    // The backup product's own text; `backup_time` is it cut to whole seconds
    // (rp::to_whole_seconds), null when it doesn't parse.
    std::string restore_point_time;
    const sampling::SampleRecord* sample = nullptr;
    const verification::ExpectedSet* expected = nullptr;
    const connector::RestoreResult* restore = nullptr;
    const verification::CheckResult* check = nullptr;
    // Required: a result without a status doesn't exist (point 5).
    const verification::RunVerdict* verdict = nullptr;
    const RunCleanup* cleanup = nullptr; // null when no clean ran
    // Null reads as a run that timed nothing: every span null.
    const timing::RunTimings* timings = nullptr;
    // The run folder's files the result covers (not result.json, nor W4.3's
    // signature.json), and its screenshot (W4.2); both null when no run
    // folder is written.
    const std::vector<Attachment>* attachments = nullptr;
    const Screenshot* screenshot = nullptr;
};

// A valid result: the document and the text that validated.
struct BuiltResult {
    nlohmann::json document; // `canonical` parsed back
    std::string canonical;   // rp::canonical_json, what a file holds
};

// Why no result was made.
enum class ResultFailure {
    build_failed,  // a part's to_json threw, or there was no verdict
    not_canonical, // the canonical form refused the document (rp::canonical_json)
    schema         // the canonical text isn't valid by the schema
};

// "build_failed", "not_canonical" or "schema"; "unknown" for a value outside
// the enum.
std::string_view to_string(ResultFailure failure) noexcept;

// Fixed words and counts only: never an exception's text or a value.
struct ResultError {
    ResultFailure cause = ResultFailure::build_failed;
    // `schema` only: validate_result's count and pointer; 0 and "" otherwise.
    std::size_t violations = 0;
    std::string first_pointer;
};

class ResultBuilder {
public:
    // The seventeen keys, always all: format, worker_version, run_id,
    // started_at, ended_at, connector {type, api}, client {client_id (the
    // job's, W4.10), tenant_id, veeam_org_name, targets {mailbox, site_id,
    // library_id, onedrive_drive_id, onedrive_folder_id}, scope, resolved
    // (W4.11: "same_tenant" and {organization {name, tenant_id, type,
    // region}, mailbox {inbox_id}, library {name, list_id, site_url},
    // onedrive_folder {name, site_url}}, both null unless the client check
    // passed)},
    // restore_point {id, backup_time_raw, backup_time}, sample, expected,
    // restore, check, status, cleanup, timings, attachments, screenshot;
    // sample, expected, restore, check, cleanup, attachments and screenshot
    // null where their pointer is. Not validated. Throws
    // std::logic_error("result: no verdict") without a verdict, and whatever
    // a part's to_json throws.
    static nlohmann::json document(const ResultParts& parts);

    // document(), its canonical text, and that text parsed back and
    // validated, so it is the written text that validated. Never throws.
    static std::variant<BuiltResult, ResultError> build(const ResultParts& parts) noexcept;
};

} // namespace rp
