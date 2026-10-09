#include <rp/service_jobs.hpp>

#include <rp/connector.hpp>

#include "job_rules.hpp"
#include "path_utf8.hpp"
#include "strict_json.hpp"

#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <limits>
#include <variant>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;

constexpr std::string_view kFormatKey = "format";
constexpr std::string_view kJobsKey = "jobs";
constexpr std::string_view kRunId = "run_id";
constexpr std::string_view kClientId = "client_id";
constexpr std::string_view kClient = "client";
constexpr std::string_view kConnector = "connector";
constexpr std::string_view kType = "type";
constexpr std::string_view kSampleMail = "sample_mail";
constexpr std::string_view kSampleSp = "sample_sp";
constexpr std::string_view kSampleOd = "sample_od";
constexpr std::string_view kRestorePoint = "restore_point";
constexpr std::string_view kScreenshots = "screenshots_enabled";
constexpr std::string_view kCanaryCursor = "canary_cursor";

// Every key a job may have.
constexpr std::array kJobKeys{kRunId,       kClientId,     kClient,      kConnector,   kSampleMail,
                              kSampleSp,    kSampleOd,     kRestorePoint, kScreenshots, kCanaryCursor};

// An integer value as a signed one, or nothing for any other kind (a float,
// 1.0 too). One past the signed range reads as the range's largest, which
// every rule here refuses as it would the number itself.
std::optional<std::int64_t> integer_of(const json& value)
{
    if (!value.is_number_integer()) {
        return std::nullopt;
    }
    constexpr std::uint64_t largest = std::numeric_limits<std::int64_t>::max();
    return value.is_number_unsigned()
               ? static_cast<std::int64_t>(std::min(value.get<std::uint64_t>(), largest))
               : value.get<std::int64_t>();
}

// The string at `key`, or null when there is none or it is another kind.
const std::string* string_at(const json& job, std::string_view key)
{
    const auto it = job.find(key);
    return it != job.end() && it->is_string() ? it->get_ptr<const std::string*>() : nullptr;
}

bool is_client_id(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= kMaxClientIdLength &&
           std::ranges::all_of(text, [](char c) { return c >= ' ' && c <= '~'; });
}

// client_id: a string by its rule, or null. False when it is missing,
// another kind or fails the rule; `into` is then left empty.
bool read_client_id(const json& job, std::optional<std::string>& into)
{
    const auto it = job.find(kClientId);
    if (it == job.end()) {
        return false;
    }
    if (it->is_null()) {
        return true;
    }
    if (!it->is_string() || !is_client_id(it->get_ref<const std::string&>())) {
        return false;
    }
    into = it->get<std::string>();
    return true;
}

// client: the profile, by its own reader (rp/client_profile.hpp). The fault
// word is `client` for a client that is missing, not an object, not the
// profile's format or has a key that isn't the profile's, and
// `client.<key>` for one of the profile's keys at fault; empty when the
// profile was read into `into`.
std::string client_fault(const json& job, std::optional<ClientProfile>& into)
{
    const auto it = job.find(kClient);
    if (it == job.end()) {
        return std::string{kJobClientKey};
    }
    std::variant<ClientProfile, ProfileFault> parsed = parse_client_profile(*it);
    if (const ProfileFault* fault = std::get_if<ProfileFault>(&parsed)) {
        return fault->key.empty() ? std::string{kJobClientKey}
                                  : std::string{kJobClientKey} + "." + fault->key;
    }
    into = std::get<ClientProfile>(std::move(parsed));
    return {};
}

bool read_size(const json& job, std::string_view key, int& into)
{
    const auto it = job.find(key);
    const std::optional<std::int64_t> n = it != job.end() ? integer_of(*it) : std::nullopt;
    if (!n || !job_rules::is_sample_size(*n)) {
        return false;
    }
    into = static_cast<int>(*n);
    return true;
}

bool read_point(const json& job, std::string& into)
{
    const std::string* text = string_at(job, kRestorePoint);
    if (text == nullptr || !job_rules::is_point(*text)) {
        return false;
    }
    into = *text;
    return true;
}

bool read_screenshots(const json& job, bool& into)
{
    const auto it = job.find(kScreenshots);
    if (it == job.end() || !it->is_boolean()) {
        return false;
    }
    into = it->get<bool>();
    return true;
}

// canary_cursor: three integers by the cursor's rule; one that isn't there
// is 0,0,0.
bool read_cursor(const json& job, sampling::CanaryCursor& into)
{
    const auto it = job.find(kCanaryCursor);
    if (it == job.end()) {
        return true;
    }
    if (!it->is_array() || it->size() != 3) {
        return false;
    }
    std::array<std::uint32_t, 3> values{};
    for (std::size_t i = 0; i < values.size(); ++i) {
        const std::optional<std::int64_t> n = integer_of((*it)[i]);
        if (!n || !job_rules::is_cursor_value(*n)) {
            return false;
        }
        values[i] = static_cast<std::uint32_t>(*n);
    }
    into = {values[0], values[1], values[2]};
    return true;
}

bool has_unknown_key(const json& job)
{
    bool unknown = false;
    for (auto it = job.begin(); it != job.end(); ++it) {
        unknown |= std::ranges::find(kJobKeys, std::string_view{it.key()}) == kJobKeys.end();
    }
    return unknown;
}

// connector (W4.11): {"type": <name>} and nothing else. The fault word, or
// empty when `into` took the name.
std::string connector_fault(const json& job, std::string& into)
{
    const auto it = job.find(kConnector);
    if (it == job.end() || !it->is_object() || it->size() != 1) {
        return std::string{kJobConnectorKey};
    }
    const std::string* type = string_at(*it, kType);
    if (type == nullptr || !connector::is_connector_name(*type)) {
        return std::string{kJobConnectorTypeKey};
    }
    into = *type;
    return {};
}

// The first key at fault of a job whose run_id passed, in the header's
// order, or empty when it is valid; `into` takes each value that passed
// before it.
std::string fault_of(const json& job, Job& into)
{
    if (!read_client_id(job, into.client_id)) {
        return std::string{kClientId};
    }
    if (std::string fault = client_fault(job, into.client); !fault.empty()) {
        return fault;
    }
    if (std::string fault = connector_fault(job, into.connector_type); !fault.empty()) {
        return fault;
    }
    if (!read_size(job, kSampleMail, into.sample_mail)) {
        return std::string{kSampleMail};
    }
    if (!read_size(job, kSampleSp, into.sample_sp)) {
        return std::string{kSampleSp};
    }
    if (!read_size(job, kSampleOd, into.sample_od)) {
        return std::string{kSampleOd};
    }
    if (job_rules::is_empty_sample(into.sample_mail, into.sample_sp, into.sample_od)) {
        return std::string{kSampleMail};
    }
    if (!read_point(job, into.restore_point)) {
        return std::string{kRestorePoint};
    }
    if (!read_screenshots(job, into.screenshots_enabled)) {
        return std::string{kScreenshots};
    }
    if (!read_cursor(job, into.canary_cursor)) {
        return std::string{kCanaryCursor};
    }
    return has_unknown_key(job) ? std::string{kJobUnknownKey} : std::string{};
}

JobEntry entry_of(const json& job, std::size_t position)
{
    JobEntry entry;
    entry.position = position;
    const std::string* run_id = job.is_object() ? string_at(job, kRunId) : nullptr;
    if (run_id == nullptr || !job_rules::is_folder_run_id(*run_id)) {
        return entry;
    }
    Job read;
    read.run_id = *run_id;
    entry.fault = fault_of(job, read);
    if (entry.fault.empty()) {
        entry.state = JobState::valid;
        entry.job = std::move(read);
        return entry;
    }
    // What a job_invalid record names: the run and, when it could be read,
    // the client. Nothing else of a job that is no job.
    entry.state = JobState::invalid;
    entry.job.run_id = std::move(read.run_id);
    entry.job.client_id = std::move(read.client_id);
    entry.job.client = std::move(read.client);
    return entry;
}

// Whether `document` is the jobs document's top level: exactly the two keys,
// the format's name and an array.
bool is_jobs_document(const json& document)
{
    if (!document.is_object() || document.size() != 2) {
        return false;
    }
    const std::string* format = string_at(document, kFormatKey);
    const auto jobs = document.find(kJobsKey);
    return format != nullptr && *format == kJobsFormat && jobs != document.end() &&
           jobs->is_array();
}

JobsDocument failed(JobsDocument document, JobsFault fault)
{
    document.state = JobsState::error;
    document.fault = fault;
    return document;
}

} // namespace

std::string_view to_text(JobsFault fault) noexcept
{
    switch (fault) {
    case JobsFault::unreadable:
        return "can't be read";
    case JobsFault::too_large:
        return "over 1 MiB";
    case JobsFault::not_json:
        return "not JSON";
    case JobsFault::not_document:
        return "not a restoreproof.jobs.v1 document";
    case JobsFault::too_many:
        return "more than 5 jobs";
    default:
        return "owned by neither SYSTEM, Administrators nor this account";
    }
}

std::string jobs_error_line(const std::filesystem::path& file, JobsFault fault)
{
    return std::format("jobs error: {}: {}", path_to_utf8(file), to_text(fault));
}

JobsDocument parse_jobs(std::string_view text)
{
    JobsDocument out;
    out.sha256 = sha256_hex(text);
    const std::optional<json> document = parse_strict_json(text);
    if (!document) {
        return failed(std::move(out), JobsFault::not_json);
    }
    if (!is_jobs_document(*document)) {
        return failed(std::move(out), JobsFault::not_document);
    }
    const json& jobs = *document->find(kJobsKey);
    if (jobs.size() > kMaxJobs) {
        return failed(std::move(out), JobsFault::too_many);
    }
    out.state = JobsState::read;
    for (std::size_t i = 0; i < jobs.size(); ++i) {
        out.jobs.push_back(entry_of(jobs[i], i + 1));
    }
    return out;
}

namespace {

// What was read as a document. The file is the caller's temporary and this
// function holds no local, so that its last line is reached: after a switch
// whose every case returns, the closing line of a function with a local to
// destroy is one no run reaches.
JobsDocument document_of(const TrustedFile& bytes)
{
    if (bytes.state == TrustedRead::read) {
        return parse_jobs(bytes.bytes);
    }
    if (bytes.state == TrustedRead::absent) {
        return {};
    }
    return failed({}, bytes.state == TrustedRead::not_trusted ? JobsFault::not_trusted
                      : bytes.state == TrustedRead::too_large ? JobsFault::too_large
                                                              : JobsFault::unreadable);
}

} // namespace

JobsDocument read_jobs(const std::filesystem::path& file, const JobsFileReader& read)
{
    return document_of(read ? read(file, kMaxJobsFileBytes)
                            : read_trusted_file(file, kMaxJobsFileBytes));
}

} // namespace rp
