#include <rp/cloud_api.hpp>

#include <rp/canonical_json.hpp>
#include <rp/redact.hpp>

#include "strict_json.hpp"
#include "utf16.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>

namespace rp {

namespace {

using nlohmann::json;

constexpr std::size_t kMaxWorkerName = 128;
constexpr std::size_t kMaxNamedValue = 9;
constexpr std::string_view kAnotherValue = "another value";

bool is_digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

bool is_lower_hex(char c) noexcept
{
    return is_digit(c) || (c >= 'a' && c <= 'f');
}

bool is_key_id(std::string_view text) noexcept
{
    return text.size() == 64 && std::ranges::all_of(text, is_lower_hex);
}

// "YYYY-MM-DDTHH:MM:SSZ", digits where digits stand.
bool is_time_text(std::string_view text) noexcept
{
    constexpr std::string_view kShape = "0000-00-00T00:00:00Z";
    bool matches = text.size() == kShape.size();
    for (std::size_t i = 0; matches && i < text.size(); ++i) {
        matches = kShape[i] == '0' ? is_digit(text[i]) : text[i] == kShape[i];
    }
    return matches;
}

// The header's value, when the answer has it.
const std::string* header_value(const HttpResponse& response)
{
    const auto it = response.headers.find(std::string{kCloudApiHeader});
    return it == response.headers.end() ? nullptr : &it->second;
}

// The string under `key` of an object, or null for none or another kind.
const std::string* text_at(const json& object, std::string_view key)
{
    const auto it = object.find(key);
    return it == object.end() || !it->is_string() ? nullptr : &it->get_ref<const std::string&>();
}

// `object` has exactly these keys.
bool has_exactly(const json& object, std::initializer_list<std::string_view> keys)
{
    return object.is_object() && object.size() == keys.size() &&
           std::ranges::all_of(keys, [&object](std::string_view key) { return object.contains(key); });
}

} // namespace

CloudAnswerKind cloud_answer_kind(const HttpResponse& response) noexcept
{
    const std::string* value = header_value(response);
    if (value == nullptr) {
        return CloudAnswerKind::not_cloud;
    }
    return *value == kCloudApiValue ? CloudAnswerKind::cloud : CloudAnswerKind::other_contract;
}

std::string other_contract_text(const HttpResponse& response)
{
    const std::string* value = header_value(response);
    if (value == nullptr || value->empty() || value->size() > kMaxNamedValue ||
        !std::ranges::all_of(*value, is_digit)) {
        return std::string{kAnotherValue};
    }
    return *value;
}

std::string bearer(std::string_view token)
{
    return "Bearer " + std::string{token};
}

bool is_cloud_token(std::string_view token) noexcept
{
    return token.size() == kCloudTokenLength && std::ranges::all_of(token, is_base64url);
}

bool is_worker_name(std::string_view name) noexcept
{
    // The decoder refuses what isn't UTF-8; it allocates, so no memory is
    // the one way it throws, which noexcept turns into the end it is.
    const std::optional<std::wstring> wide = utf8_to_utf16(name);
    if (!wide || wide->empty()) {
        return false;
    }
    std::size_t points = 0;
    for (const wchar_t unit : *wide) {
        // A low surrogate ends a pair its high one already counted.
        if (unit >= 0xDC00 && unit <= 0xDFFF) {
            continue;
        }
        if (unit < 0x20 || (unit >= 0x7F && unit <= 0x9F)) {
            return false;
        }
        ++points;
    }
    return points <= kMaxWorkerName;
}

std::string registration_body(std::string_view install_token, std::string_view public_key_pem,
                              std::string_view worker_name, std::string_view version)
{
    return canonical_json(json{{"install_token", install_token},
                               {"public_key_pem", public_key_pem},
                               {"version", version},
                               {"worker_name", worker_name}});
}

std::optional<Registration> parse_registration(std::string_view body)
{
    const std::optional<json> parsed = parse_strict_json(body);
    if (!parsed || !has_exactly(*parsed, {"worker_id", "api_token", "key_id"})) {
        return std::nullopt;
    }
    const std::string* worker_id = text_at(*parsed, "worker_id");
    const std::string* api_token = text_at(*parsed, "api_token");
    const std::string* key_id = text_at(*parsed, "key_id");
    if (worker_id == nullptr || !is_uuid(*worker_id) || api_token == nullptr ||
        !is_cloud_token(*api_token) || key_id == nullptr || !is_key_id(*key_id)) {
        return std::nullopt;
    }
    return Registration{*worker_id, *api_token, *key_id};
}

std::string worker_record_text(const WorkerRecord& record)
{
    return canonical_json(json{{"cloud_url", record.cloud_url},
                               {"format", kWorkerFormat},
                               {"key_id", record.key_id},
                               {"registered_at", record.registered_at},
                               {"worker_id", record.worker_id}});
}

std::optional<WorkerRecord> parse_worker_record(std::string_view text)
{
    const std::optional<json> parsed = parse_strict_json(text);
    if (!parsed ||
        !has_exactly(*parsed, {"cloud_url", "format", "key_id", "registered_at", "worker_id"})) {
        return std::nullopt;
    }
    const std::string* cloud_url = text_at(*parsed, "cloud_url");
    const std::string* format = text_at(*parsed, "format");
    const std::string* key_id = text_at(*parsed, "key_id");
    const std::string* registered_at = text_at(*parsed, "registered_at");
    const std::string* worker_id = text_at(*parsed, "worker_id");
    if (cloud_url == nullptr || format == nullptr || *format != kWorkerFormat ||
        key_id == nullptr || !is_key_id(*key_id) || registered_at == nullptr ||
        !is_time_text(*registered_at) || worker_id == nullptr || !is_uuid(*worker_id)) {
        return std::nullopt;
    }
    WorkerRecord record{*worker_id, *key_id, *cloud_url, *registered_at};
    if (worker_record_text(record) != text) {
        return std::nullopt;
    }
    return record;
}

} // namespace rp
