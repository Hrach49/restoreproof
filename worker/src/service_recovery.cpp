#include <rp/service_recovery.hpp>

#include "job_rules.hpp"
#include "run_pipeline.hpp"

#include <rp/canonical_json.hpp>
#include <rp/connector_registry.hpp>
#include <rp/rfc3161.hpp>
#include <rp/signer.hpp>
#include <rp/version.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <format>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;
using std::chrono::system_clock;

// The schema's lengths for what a record hands on to a result, and the
// record's own for what it doesn't.
constexpr std::size_t kMaxTenantId = 128;
constexpr std::size_t kMaxClientText = 1024;
constexpr std::size_t kMaxApi = 64;
constexpr std::size_t kMaxClientId = 128;
constexpr std::size_t kMaxSessionId = 128;
constexpr std::size_t kMaxJobKey = 32;
constexpr std::size_t kRecordKeys = 14;

constexpr std::string_view kKindRun = "run";
constexpr std::string_view kJobInvalid = "job_invalid";
constexpr std::string_view kResultInvalid = "result_invalid";
constexpr std::string_view kInternal = "internal";
constexpr std::string_view kInterrupted = "interrupted";
constexpr std::string_view kChanged = "changed";
constexpr std::string_view kNotWritten = "not_written";
constexpr std::string_view kPass = "pass";
constexpr std::string_view kFail = "fail";
constexpr std::string_view kError = "error";

// What a run folder's shared tail says of a folder it left without a result.
constexpr std::array<std::string_view, 5> kFolderWords{kNotWritten, kChanged, "holds_secret",
                                                       "not_signed", "invalid"};

bool is_printable(std::string_view text, std::size_t max) noexcept
{
    return !text.empty() && text.size() <= max &&
           std::ranges::all_of(text, [](char c) { return c >= ' ' && c <= '~'; });
}

// The jobs reader's word for a key: lower-case letters, '_' and a blank.
bool is_job_key(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= kMaxJobKey &&
           std::ranges::all_of(text,
                               [](char c) { return (c >= 'a' && c <= 'z') || c == '_' || c == ' '; });
}

bool is_error_code(std::string_view code)
{
    const std::vector<std::string_view> codes = verification::error_codes();
    return std::ranges::find(codes, code) != codes.end();
}

// How a run had ended, from ended_detail's text; nothing for any other.
std::optional<std::pair<verification::RunStatus, std::string>> ended_of(std::string_view detail)
{
    using verification::RunStatus;
    if (detail == kPass) {
        return std::pair{RunStatus::pass, std::string{}};
    }
    if (detail == kFail) {
        return std::pair{RunStatus::fail, std::string{}};
    }
    if (detail == kError) {
        return std::pair{RunStatus::error, std::string{}};
    }
    const std::string start = std::string{kError} + " ";
    if (detail.starts_with(start) && is_error_code(detail.substr(start.size()))) {
        return std::pair{RunStatus::error, std::string{detail.substr(start.size())}};
    }
    return std::nullopt;
}

// Whether `detail` is a word `close_as` may carry.
bool is_close_detail(const std::optional<CloseAs>& close_as,
                     const std::optional<std::string>& detail)
{
    if (!close_as) {
        return !detail;
    }
    if (*close_as == CloseAs::result_invalid) {
        return !detail || ended_of(*detail).has_value();
    }
    if (*close_as == CloseAs::internal) {
        return detail && std::ranges::find(kFolderWords, std::string_view{*detail}) !=
                             kFolderWords.end();
    }
    return detail && is_job_key(*detail);
}

json nullable(const std::optional<std::string>& text)
{
    return text ? json(*text) : json(nullptr);
}

json client_json(const ResultClient& client)
{
    return {{"client_id", nullptr},
            {"tenant_id", client.tenant_id},
            {"veeam_org_name", client.veeam_org_name},
            {"targets",
             {{"mailbox", client.mailbox},
              {"site_id", client.site_id},
              {"library_id", client.library_id},
              {"onedrive_drive_id", client.onedrive_drive_id},
              {"onedrive_folder_id", client.onedrive_folder_id}}}};
}

json record_json(const RunningRecord& record)
{
    json document = json::object();
    document["client"] = client_json(record.client);
    document["client_id"] = nullable(record.client_id);
    document["close_as"] = record.close_as ? json(to_string(*record.close_as)) : json(nullptr);
    document["close_detail"] = nullable(record.close_detail);
    document["connector"] =
        record.connector
            ? json{{"type", record.connector->name}, {"api", record.connector->version}}
            : json(nullptr);
    document["format"] = kRunningFormat;
    document["kind"] = to_string(record.kind);
    document["restore_point"] =
        record.restore_point ? json{{"id", record.restore_point->id},
                                    {"backup_time_raw", record.restore_point->backup_time_raw}}
                             : json(nullptr);
    document["restore_requested"] = record.restore_requested;
    document["restore_requested_at"] = nullable(record.restore_requested_at);
    document["run_id"] = record.run_id;
    document["sessions"] = record.sessions;
    document["started_at"] = nullable(record.started_at);
    document["taken_at"] = record.taken_at;
    return document;
}

// Whether `text` is `document`'s canonical form. One return after the handler.
bool is_canonical(const json& document, std::string_view text)
{
    bool same = false;
    try {
        same = canonical_json(document) == text;
    } catch (const CanonicalJsonError&) {
        same = false;
    }
    return same;
}

// The value at `key`, or a null pointer when the object has none.
const json* value_at(const json& object, std::string_view key)
{
    const auto it = object.find(key);
    return it != object.end() ? &*it : nullptr;
}

// The key's string of at most `max` bytes; false for a key that isn't there,
// another kind or a longer one.
bool read_text(const json& object, std::string_view key, std::size_t max, std::string& into)
{
    const json* value = value_at(object, key);
    if (value == nullptr || !value->is_string() ||
        value->get_ref<const std::string&>().size() > max) {
        return false;
    }
    into = value->get<std::string>();
    return true;
}

// The key's string, held to `rule`, or nothing for a null; false for a key
// that isn't there, another kind, or a string the rule refuses.
template <typename Rule>
bool read_nullable(const json& object, std::string_view key, Rule rule,
                   std::optional<std::string>& into)
{
    const json* value = value_at(object, key);
    if (value == nullptr || !(value->is_null() || value->is_string())) {
        return false;
    }
    if (value->is_string()) {
        into = value->get<std::string>();
    }
    return !into || rule(*into);
}

bool is_time(const std::string& text) noexcept
{
    return record_time(text).has_value();
}

// The key's object of exactly `keys` keys, or a null pointer.
const json* object_at(const json& object, std::string_view key, std::size_t keys)
{
    const json* value = value_at(object, key);
    return value != nullptr && value->is_object() && value->size() == keys ? value : nullptr;
}

bool read_client(const json& document, ResultClient& into)
{
    const json* client = object_at(document, "client", 4);
    const json* id = client != nullptr ? value_at(*client, "client_id") : nullptr;
    const json* targets = client != nullptr ? object_at(*client, "targets", 5) : nullptr;
    return id != nullptr && id->is_null() && targets != nullptr &&
           read_text(*client, "tenant_id", kMaxTenantId, into.tenant_id) &&
           read_text(*client, "veeam_org_name", kMaxClientText, into.veeam_org_name) &&
           read_text(*targets, "mailbox", kMaxClientText, into.mailbox) &&
           read_text(*targets, "site_id", kMaxClientText, into.site_id) &&
           read_text(*targets, "library_id", kMaxClientText, into.library_id) &&
           read_text(*targets, "onedrive_drive_id", kMaxClientText, into.onedrive_drive_id) &&
           read_text(*targets, "onedrive_folder_id", kMaxClientText, into.onedrive_folder_id);
}

// connector: null, or {type, api} of the one connector the result's schema
// knows.
bool read_connector(const json& document, std::optional<connector::ConnectorInfo>& into)
{
    const json* value = value_at(document, "connector");
    if (value != nullptr && value->is_null()) {
        return true;
    }
    const json* object = object_at(document, "connector", 2);
    connector::ConnectorInfo read;
    if (object == nullptr || !read_text(*object, "type", kMaxApi, read.name) ||
        read.name != connector::kVeeamM365 || !read_text(*object, "api", kMaxApi, read.version)) {
        return false;
    }
    into = std::move(read);
    return true;
}

bool read_restore_point(const json& document, std::optional<RecordRestorePoint>& into)
{
    const json* value = value_at(document, "restore_point");
    if (value != nullptr && value->is_null()) {
        return true;
    }
    const json* object = object_at(document, "restore_point", 2);
    RecordRestorePoint read;
    if (object == nullptr || !read_text(*object, "id", kMaxClientText, read.id) ||
        !read_text(*object, "backup_time_raw", kMaxClientText, read.backup_time_raw)) {
        return false;
    }
    into = std::move(read);
    return true;
}

bool read_sessions(const json& document, std::vector<std::string>& into)
{
    const json* value = value_at(document, "sessions");
    if (value == nullptr || !value->is_array() ||
        !std::ranges::all_of(*value, [](const json& id) {
            return id.is_string() && is_printable(id.get_ref<const std::string&>(), kMaxSessionId);
        })) {
        return false;
    }
    into = value->get<std::vector<std::string>>();
    return true;
}

// kind, close_as and close_detail, which hang together: job_invalid is the
// one way a job that is no job is closed, and the only thing closed so.
bool read_close(const json& document, RunningRecord& into)
{
    std::string kind;
    std::optional<std::string> close_as;
    const auto any = [](const std::string&) { return true; };
    if (!read_text(document, "kind", kMaxJobKey, kind) || (kind != kKindRun && kind != kJobInvalid) ||
        !read_nullable(document, "close_as", any, close_as) ||
        !read_nullable(document, "close_detail", any, into.close_detail)) {
        return false;
    }
    into.kind = kind == kKindRun ? RecordKind::run : RecordKind::job_invalid;
    if (close_as == kResultInvalid) {
        into.close_as = CloseAs::result_invalid;
    } else if (close_as == kInternal) {
        into.close_as = CloseAs::internal;
    } else if (close_as == kJobInvalid) {
        into.close_as = CloseAs::job_invalid;
    } else if (close_as) {
        return false;
    }
    return (into.kind == RecordKind::job_invalid) == (into.close_as == CloseAs::job_invalid) &&
           is_close_detail(into.close_as, into.close_detail);
}

RunningRecord new_record(std::string_view run_id, std::optional<std::string> client_id,
                         const Config& config, system_clock::time_point taken_at)
{
    RunningRecord record;
    record.run_id = std::string{run_id};
    record.client_id = std::move(client_id);
    record.client = result_client(config);
    record.taken_at = record_time_text(taken_at);
    return record;
}

CloseRunOutcome outcome_of(FolderOutcome folder)
{
    const CloseRunState state = folder.state == FolderEnd::queued     ? CloseRunState::queued
                                : folder.state == FolderEnd::complete ? CloseRunState::not_queued
                                                                      : CloseRunState::not_closed;
    return {state, std::move(folder.word)};
}

} // namespace

std::string record_time_text(system_clock::time_point time)
{
    return std::format("{:%Y-%m-%dT%H:%M:%S}Z", std::chrono::floor<std::chrono::milliseconds>(time));
}

std::optional<system_clock::time_point> record_time(std::string_view text) noexcept
{
    constexpr std::string_view shape = "dddd-dd-ddTdd:dd:dd.dddZ";
    if (text.size() != shape.size()) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < shape.size(); ++i) {
        const bool digit = text[i] >= '0' && text[i] <= '9';
        if (shape[i] == 'd' ? !digit : text[i] != shape[i]) {
            return std::nullopt;
        }
    }
    const auto number = [&](std::size_t from, std::size_t digits) {
        int value = 0;
        for (std::size_t i = from; i < from + digits; ++i) {
            value = value * 10 + (text[i] - '0');
        }
        return value;
    };
    const std::chrono::year_month_day day{std::chrono::year{number(0, 4)},
                                          std::chrono::month{static_cast<unsigned>(number(5, 2))},
                                          std::chrono::day{static_cast<unsigned>(number(8, 2))}};
    const int hour = number(11, 2);
    const int minute = number(14, 2);
    const int second = number(17, 2);
    if (!day.ok() || hour > 23 || minute > 59 || second > 59) {
        return std::nullopt;
    }
    return std::chrono::sys_days{day} + std::chrono::hours{hour} + std::chrono::minutes{minute} +
           std::chrono::seconds{second} + std::chrono::milliseconds{number(20, 3)};
}

std::string_view to_string(RecordKind kind) noexcept
{
    return kind == RecordKind::run ? kKindRun : kJobInvalid;
}

std::string_view to_string(CloseAs close_as) noexcept
{
    return close_as == CloseAs::result_invalid ? kResultInvalid
           : close_as == CloseAs::internal     ? kInternal
                                               : kJobInvalid;
}

bool RunningRecord::operator==(const RunningRecord& other) const
{
    const auto same_connector = [](const std::optional<connector::ConnectorInfo>& a,
                                   const std::optional<connector::ConnectorInfo>& b) {
        return a.has_value() == b.has_value() &&
               (!a || (a->name == b->name && a->version == b->version));
    };
    return client == other.client && client_id == other.client_id &&
           close_as == other.close_as && close_detail == other.close_detail &&
           same_connector(connector, other.connector) && kind == other.kind &&
           restore_point == other.restore_point && restore_requested == other.restore_requested &&
           restore_requested_at == other.restore_requested_at && run_id == other.run_id &&
           sessions == other.sessions && started_at == other.started_at &&
           taken_at == other.taken_at;
}

RunningRecord new_run_record(std::string_view run_id, std::optional<std::string> client_id,
                             const Config& config, system_clock::time_point taken_at)
{
    return new_record(run_id, std::move(client_id), config, taken_at);
}

RunningRecord new_job_invalid_record(std::string_view run_id,
                                     std::optional<std::string> client_id, const Config& config,
                                     system_clock::time_point taken_at, std::string_view key)
{
    RunningRecord record = new_record(run_id, std::move(client_id), config, taken_at);
    record.kind = RecordKind::job_invalid;
    record.close_as = CloseAs::job_invalid;
    record.close_detail = std::string{key};
    return record;
}

RunningRecord with_run_started(RunningRecord record, const RunStarted& started)
{
    record.started_at = started.started_at;
    record.restore_point = RecordRestorePoint{started.restore_point_id, started.restore_point_time};
    record.connector = connector::ConnectorInfo{started.connector_type, started.connector_api};
    return record;
}

RunningRecord with_session(RunningRecord record, std::string_view id)
{
    if (std::find(record.sessions.begin(), record.sessions.end(), id) == record.sessions.end()) {
        record.sessions.emplace_back(id);
    }
    return record;
}

RunningRecord with_restore_request(RunningRecord record, system_clock::time_point time)
{
    record.restore_requested = true;
    record.restore_requested_at = record_time_text(time);
    return record;
}

RunningRecord with_close(RunningRecord record, CloseAs close_as, std::optional<std::string> detail)
{
    record.close_as = close_as;
    record.close_detail = std::move(detail);
    return record;
}

std::string ended_detail(verification::RunStatus status, std::string_view code)
{
    if (status == verification::RunStatus::pass) {
        return std::string{kPass};
    }
    if (status == verification::RunStatus::fail) {
        return std::string{kFail};
    }
    return is_error_code(code) ? std::format("{} {}", kError, code) : std::string{kError};
}

std::string record_text(const RunningRecord& record)
{
    return canonical_json(record_json(record));
}

std::optional<RunningRecord> parse_record(std::string_view text)
{
    const json document = json::parse(text, nullptr, false);
    if (!document.is_object() || document.size() != kRecordKeys || !is_canonical(document, text)) {
        return std::nullopt;
    }
    RunningRecord record;
    std::string format;
    std::optional<std::string> taken_at;
    const json* requested = value_at(document, "restore_requested");
    const auto client_id = [](const std::string& id) { return is_printable(id, kMaxClientId); };
    if (!read_text(document, "format", kRunningFormat.size(), format) ||
        format != kRunningFormat || !read_text(document, "run_id", kMaxClientText, record.run_id) ||
        !job_rules::is_folder_run_id(record.run_id) || !read_client(document, record.client) ||
        !read_nullable(document, "client_id", client_id, record.client_id) ||
        !read_close(document, record) || !read_connector(document, record.connector) ||
        !read_restore_point(document, record.restore_point) || requested == nullptr ||
        !requested->is_boolean() ||
        !read_nullable(document, "restore_requested_at", is_time, record.restore_requested_at) ||
        requested->get<bool>() != record.restore_requested_at.has_value() ||
        !read_sessions(document, record.sessions) ||
        !read_nullable(document, "started_at", is_time, record.started_at) ||
        !read_nullable(document, "taken_at", is_time, taken_at) || !taken_at) {
        return std::nullopt;
    }
    record.restore_requested = requested->get<bool>();
    record.taken_at = std::move(*taken_at);
    return record;
}

RecordStore::RecordStore(std::filesystem::path file, RecordFiles files)
    : file_(std::move(file)), files_(std::move(files))
{
}

RecordRead RecordStore::read() const
{
    TrustedFile file = files_.read(file_, kMaxRecordBytes);
    if (file.state == TrustedRead::absent) {
        return {RecordState::none, std::nullopt};
    }
    if (file.state == TrustedRead::not_trusted) {
        return {RecordState::not_trusted, std::nullopt};
    }
    if (file.state == TrustedRead::unreadable) {
        return {RecordState::unreadable, std::nullopt};
    }
    // A file over the limit is no record: no record is that large.
    std::optional<RunningRecord> record =
        file.state == TrustedRead::read ? parse_record(file.bytes) : std::nullopt;
    const RecordState state = record ? RecordState::record : RecordState::not_record;
    return {state, std::move(record)};
}

bool RecordStore::write(const RunningRecord& record) const
{
    std::string text;
    try {
        text = record_text(record);
    } catch (const CanonicalJsonError&) {
        return false;
    }
    return text.size() <= kMaxRecordBytes && parse_record(text).has_value() &&
           files_.write(file_, text);
}

bool RecordStore::remove() const
{
    return files_.remove(file_);
}

bool RecordStore::move_aside() const
{
    return files_.move_aside(file_, unread_file());
}

std::filesystem::path RecordStore::unread_file() const
{
    return file_.parent_path() / kRunningUnreadName;
}

ClosePlan plan_close(const RunningRecord& record, const FolderContents& folder)
{
    ClosePlan plan;
    plan.run_id = record.run_id;
    if (folder.exists && folder.result) {
        plan.action = CloseAction::queue_only;
        return plan;
    }
    plan.make_folder = !folder.exists;
    if (folder.signature) {
        plan.remove.emplace_back(kSignatureFileName);
    }
    if (folder.timestamp) {
        plan.remove.emplace_back(kTimestampFileName);
    }
    if (folder.screenshot) {
        plan.remove.emplace_back(kScreenshotName);
    }
    plan.remove_temp_files = folder.temp_files;

    const bool requested = record.restore_requested;
    if (!record.close_as) {
        plan.code = std::string{kInterrupted};
        plan.verdict = verification::interrupted_before_result(requested);
    } else if (*record.close_as == CloseAs::internal) {
        plan.code = std::string{kInternal};
        plan.verdict = verification::ended_without_result(requested);
        // The run found one of them altered after it hashed it: the Worker
        // lists no file it knows was changed.
        plan.replace_text_files = record.close_detail == kChanged;
    } else if (*record.close_as == CloseAs::result_invalid) {
        plan.code = std::string{kResultInvalid};
        // An ending that isn't known, or doesn't read, is "error" alone.
        const auto ended = ended_of(record.close_detail.value_or(std::string{kError}))
                               .value_or(std::pair{verification::RunStatus::error, std::string{}});
        plan.verdict = verification::result_invalid_afterwards(ended.first, ended.second, requested);
    } else {
        plan.code = std::string{kJobInvalid};
        plan.verdict = verification::job_invalid(record.close_detail.value_or(std::string{}));
    }

    plan.started_at = record.started_at;
    plan.connector = record.connector.value_or(
        connector::ConnectorInfo{std::string{connector::kVeeamM365}, std::string{}});
    const RecordRestorePoint point = record.restore_point.value_or(RecordRestorePoint{});
    plan.restore_point_id = point.id;
    plan.restore_point_time = point.backup_time_raw;
    plan.client = record.client;
    return plan;
}

Screenshot close_screenshot(bool screenshots_enabled) noexcept
{
    return {false, screenshots_enabled ? ScreenshotReason::no_page : ScreenshotReason::disabled};
}

std::variant<BuiltResult, ResultError> build_close_result(const ClosePlan& plan,
                                                          const Evidence& evidence)
{
    ResultParts parts;
    parts.worker_version = std::string{version()};
    parts.run_id = plan.run_id;
    parts.started_at = plan.started_at;
    parts.connector = plan.connector;
    parts.client = plan.client;
    parts.restore_point_id = plan.restore_point_id;
    parts.restore_point_time = plan.restore_point_time;
    parts.verdict = &plan.verdict;
    parts.attachments = &evidence.attachments;
    parts.screenshot = &evidence.screenshot;
    return ResultBuilder::build(parts);
}

CloseRunOutcome close_run(const RunningRecord& record, const CloseRunCalls& calls)
{
    const ClosePlan plan = plan_close(record, calls.look());
    if (plan.action == CloseAction::queue_only) {
        return outcome_of(calls.queue());
    }
    if (plan.make_folder && !calls.make_folder()) {
        return {CloseRunState::not_closed, std::string{kNotWritten}};
    }
    if (plan.removes() && !calls.remove_unfinished()) {
        return {CloseRunState::not_closed, std::string{kNotWritten}};
    }
    const auto result = [&plan](const Evidence& evidence) -> std::optional<std::string> {
        std::variant<BuiltResult, ResultError> built = build_close_result(plan, evidence);
        BuiltResult* valid = std::get_if<BuiltResult>(&built);
        return valid != nullptr ? std::optional{std::move(valid->canonical)} : std::nullopt;
    };
    return outcome_of(calls.finish(plan.replace_text_files, result));
}

bool needs_hold(const RunningRecord& record) noexcept
{
    return record.restore_requested || !record.sessions.empty();
}

HoldDecision decide_hold(const RunningRecord& record,
                         const std::vector<connector::OwnSession>& running,
                         system_clock::time_point now, system_clock::time_point hold_began)
{
    HoldDecision decision;
    std::vector<std::string> recorded;
    for (const connector::OwnSession& session : running) {
        if (std::ranges::find(record.sessions, session.id) != record.sessions.end()) {
            recorded.push_back(session.id);
            continue;
        }
        ++decision.others;
        if (!decision.others_since || session.created_at < *decision.others_since) {
            decision.others_since = session.created_at;
        }
    }

    if (!record.restore_requested) {
        // No request went out, so nothing of this run is restoring: its own
        // sessions are ended as its finally path would have; the others
        // aren't the run's.
        decision.step = recorded.empty() ? HoldStep::over : HoldStep::end;
        decision.end = std::move(recorded);
        return decision;
    }
    if (decision.others != 0) {
        // One of them may be the restore: nothing is ended.
        return decision;
    }
    if (recorded.empty()) {
        decision.step = HoldStep::over;
        decision.clean_due = true;
        return decision;
    }
    // A restore session the product hadn't listed yet.
    const system_clock::time_point last_request =
        record_time(record.restore_requested_at.value_or(std::string{})).value_or(hold_began);
    if (now - std::max(last_request, hold_began) >= kHoldWait) {
        decision.step = HoldStep::end;
        decision.end = std::move(recorded);
    }
    return decision;
}

bool is_records_client(const Config& config, const RunningRecord& record)
{
    return result_client(config) == record.client;
}

bool record_may_go(const RunningRecord& record, OutboxHolds holds, const PipelineReport* report,
                   bool hold_done) noexcept
{
    const bool no_folder = report != nullptr && !report->run_line &&
                           report->folder == RunFolderState::none;
    if (holds == OutboxHolds::none && !no_folder) {
        return false;
    }
    const bool may_run = report != nullptr
                             ? report->restore_may_still_run && record.restore_requested
                             : needs_hold(record);
    return hold_done || !may_run;
}

} // namespace rp
