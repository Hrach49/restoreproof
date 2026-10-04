#include <rp/result_builder.hpp>

#include "veeam_time.hpp"

#include <rp/canonical_json.hpp>
#include <rp/result_schema.hpp>

#include <stdexcept>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;

json text_or_null(const std::optional<std::string>& text)
{
    return text ? json(*text) : json();
}

} // namespace

std::string_view to_string(ResultFailure failure) noexcept
{
    switch (failure) {
    case ResultFailure::build_failed:
        return "build_failed";
    case ResultFailure::not_canonical:
        return "not_canonical";
    case ResultFailure::schema:
        return "schema";
    }
    return "unknown";
}

json ResultBuilder::document(const ResultParts& parts)
{
    if (parts.verdict == nullptr) {
        throw std::logic_error("result: no verdict");
    }
    json result = json::object();
    result["format"] = kResultFormat;
    result["worker_version"] = parts.worker_version;
    result["run_id"] = parts.run_id;
    result["started_at"] = text_or_null(parts.started_at);
    result["ended_at"] = text_or_null(parts.ended_at);
    result["connector"] = {{"type", parts.connector.name}, {"api", parts.connector.version}};
    result["client"] = {{"client_id", nullptr},
                        {"tenant_id", parts.client.tenant_id},
                        {"veeam_org_name", parts.client.veeam_org_name},
                        {"targets",
                         {{"mailbox", parts.client.mailbox},
                          {"site_id", parts.client.site_id},
                          {"library_id", parts.client.library_id},
                          {"onedrive_drive_id", parts.client.onedrive_drive_id},
                          {"onedrive_folder_id", parts.client.onedrive_folder_id}}}};
    result["restore_point"] = {
        {"id", parts.restore_point_id},
        {"backup_time_raw", parts.restore_point_time},
        {"backup_time", text_or_null(to_whole_seconds(parts.restore_point_time))}};
    result["sample"] = parts.sample ? sampling::to_json(*parts.sample) : json();
    result["expected"] = parts.expected ? verification::to_json(*parts.expected) : json();
    result["restore"] = parts.restore ? verification::to_json(*parts.restore) : json();
    result["check"] = parts.check ? verification::to_json(*parts.check) : json();
    result["status"] = verification::to_json(*parts.verdict);
    result["cleanup"] = parts.cleanup ? to_json(*parts.cleanup) : json();
    result["timings"] = timing::to_json(parts.timings ? *parts.timings : timing::RunTimings{});
    return result;
}

std::variant<BuiltResult, ResultError> ResultBuilder::build(const ResultParts& parts) noexcept
{
    try {
        json built;
        try {
            built = document(parts);
        } catch (...) {
            return ResultError{ResultFailure::build_failed, 0, {}};
        }
        BuiltResult result;
        try {
            result.canonical = canonical_json(built);
            // What is validated is the text a file would hold.
            result.document = json::parse(result.canonical);
        } catch (...) {
            return ResultError{ResultFailure::not_canonical, 0, {}};
        }
        ResultValidation validation = validate_result(result.document);
        if (!validation.valid) {
            return ResultError{ResultFailure::schema, validation.violations,
                               std::move(validation.first_pointer)};
        }
        return result;
    } catch (...) {
        // Only a failed allocation while a result is handed back gets here.
        return ResultError{ResultFailure::build_failed, 0, {}};
    }
}

} // namespace rp
