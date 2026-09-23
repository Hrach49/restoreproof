#include <rp/config.hpp>

#include <rp/secrets.hpp>

#include "path_utf8.hpp"

#include <nlohmann/json.hpp>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <memory>
#include <sstream>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;

enum class StringRule { non_empty, https_url, email, log_level };

struct StringField {
    std::string_view key;
    std::string Config::*member;
    bool required;
    StringRule rule;
};

struct IntField {
    std::string_view key;
    int Config::*member;
    int min;
    int max;
    std::string_view range_message;
};

// Declaration order of Config: fields are checked, and errors reported, in
// this order.
constexpr std::array<StringField, 10> kRequiredStrings{{
    {"cloud_url", &Config::cloud_url, true, StringRule::https_url},
    {"veeam_url", &Config::veeam_url, true, StringRule::https_url},
    {"veeam_org_name", &Config::veeam_org_name, true, StringRule::non_empty},
    {"graph_tenant_id", &Config::graph_tenant_id, true, StringRule::non_empty},
    {"graph_client_id", &Config::graph_client_id, true, StringRule::non_empty},
    {"test_mailbox", &Config::test_mailbox, true, StringRule::email},
    {"test_site_id", &Config::test_site_id, true, StringRule::non_empty},
    {"test_library_id", &Config::test_library_id, true, StringRule::non_empty},
    {"test_onedrive_drive_id", &Config::test_onedrive_drive_id, true, StringRule::non_empty},
    {"test_onedrive_folder_id", &Config::test_onedrive_folder_id, true, StringRule::non_empty},
}};

constexpr std::string_view kIntervalRange = "must be an integer from 1 to 86400 (seconds)";
constexpr std::string_view kSampleRange = "must be an integer from 0 to 100";

constexpr std::array<IntField, 5> kIntFields{{
    {"poll_interval_s", &Config::poll_interval_s, 1, 86400, kIntervalRange},
    {"heartbeat_interval_s", &Config::heartbeat_interval_s, 1, 86400, kIntervalRange},
    {"sample_mail", &Config::sample_mail, 0, 100, kSampleRange},
    {"sample_sp", &Config::sample_sp, 0, 100, kSampleRange},
    {"sample_od", &Config::sample_od, 0, 100, kSampleRange},
}};

constexpr StringField kLogLevel{"log_level", &Config::log_level, false, StringRule::log_level};

constexpr std::array<std::string_view, 7> kLogLevels{"trace", "debug", "info", "warn",
                                                      "error", "critical", "off"};

// Lowercased substrings that mark a key as a secret.
constexpr std::array<std::string_view, 6> kSecretMarkers{"password", "passwd", "secret",
                                                          "token",    "api_key", "apikey"};

[[noreturn]] void fail(std::string_view key, std::string_view problem)
{
    std::string message = "config key \"";
    message.append(key).append("\" ").append(problem);
    throw ConfigError(std::string{key}, message);
}

bool is_known_key(std::string_view key)
{
    const auto named = [key](const auto& field) { return field.key == key; };
    return std::any_of(kRequiredStrings.begin(), kRequiredStrings.end(), named) ||
           std::any_of(kIntFields.begin(), kIntFields.end(), named) || key == kLogLevel.key;
}

bool looks_like_secret(std::string_view key)
{
    std::string lower(key);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return std::any_of(kSecretMarkers.begin(), kSecretMarkers.end(),
                       [&lower](std::string_view marker) {
                           return lower.find(marker) != std::string::npos;
                       });
}

std::string secret_key_problem()
{
    std::string names;
    for (std::size_t i = 0; i < kSecretEnvVars.size(); ++i) {
        if (i > 0) {
            names += i + 1 == kSecretEnvVars.size() ? " or " : ", ";
        }
        names += kSecretEnvVars[i];
    }
    return "looks like a secret; secrets don't belong in config.json. Set " + names +
           " in the environment instead (they move to the DPAPI vault in W4.5)";
}

// "https://" in any case, then a host: at least one character that isn't '/'.
bool is_https_url(std::string_view value)
{
    constexpr std::string_view scheme = "https://";
    if (value.size() <= scheme.size() || value[scheme.size()] == '/') {
        return false;
    }
    return std::equal(scheme.begin(), scheme.end(), value.begin(), [](char a, char b) {
        return a == std::tolower(static_cast<unsigned char>(b));
    });
}

bool is_email(std::string_view value)
{
    const std::size_t at = value.find('@');
    return at != std::string_view::npos && at > 0 && at + 1 < value.size();
}

bool follows_rule(StringRule rule, std::string_view value)
{
    switch (rule) {
    case StringRule::https_url:
        return is_https_url(value);
    case StringRule::email:
        return is_email(value);
    case StringRule::log_level:
        return std::find(kLogLevels.begin(), kLogLevels.end(), value) != kLogLevels.end();
    default:
        return true;
    }
}

std::string_view rule_problem(StringRule rule)
{
    switch (rule) {
    case StringRule::https_url:
        return "must be an https:// URL";
    case StringRule::email:
        return "must be an email address";
    default:
        return "must be one of trace, debug, info, warn, error, critical, off";
    }
}

void read_string(const json& doc, const StringField& field, Config& config)
{
    const auto it = doc.find(field.key);
    if (it == doc.end()) {
        if (field.required) {
            fail(field.key, "is missing (required)");
        }
        return;
    }
    if (!it->is_string()) {
        fail(field.key, "must be a string");
    }
    const auto& value = it->get_ref<const std::string&>();
    if (value.empty()) {
        fail(field.key, "must not be empty");
    }
    if (!follows_rule(field.rule, value)) {
        fail(field.key, rule_problem(field.rule));
    }
    config.*field.member = value;
}

void read_int(const json& doc, const IntField& field, Config& config)
{
    const auto it = doc.find(field.key);
    if (it == doc.end()) {
        return;
    }
    if (!it->is_number_integer()) {
        fail(field.key, "must be an integer");
    }
    // Positive JSON integers are stored unsigned, negative ones signed; compare
    // each in its own type so no value overflows on the way to int.
    const bool in_range =
        it->is_number_unsigned()
            ? it->get<std::uint64_t>() >= static_cast<std::uint64_t>(field.min) &&
                  it->get<std::uint64_t>() <= static_cast<std::uint64_t>(field.max)
            : it->get<std::int64_t>() >= field.min && it->get<std::int64_t>() <= field.max;
    if (!in_range) {
        fail(field.key, field.range_message);
    }
    config.*field.member = it->get<int>();
}

} // namespace

ConfigError::ConfigError(std::string key, const std::string& message)
    : std::runtime_error(message), key_(std::move(key))
{
}

const std::string& ConfigError::key() const noexcept
{
    return key_;
}

Config parse_config(std::string_view json_text)
{
    json doc;
    try {
        doc = json::parse(json_text);
    } catch (const json::parse_error& e) {
        // Never e.what(): it quotes the last token read, which may be a secret.
        throw ConfigError("", "config is not valid JSON (error at byte " + std::to_string(e.byte) +
                                  ")");
    }
    if (!doc.is_object()) {
        throw ConfigError("", "config must be a JSON object");
    }

    // Secrets first, so the user takes one out of the file before anything else.
    for (const auto& item : doc.items()) {
        if (looks_like_secret(item.key())) {
            fail(item.key(), secret_key_problem());
        }
    }
    for (const auto& item : doc.items()) {
        if (!is_known_key(item.key())) {
            fail(item.key(), "is not a known setting");
        }
    }

    Config config;
    for (const StringField& field : kRequiredStrings) {
        read_string(doc, field, config);
    }
    for (const IntField& field : kIntFields) {
        read_int(doc, field, config);
    }
    read_string(doc, kLogLevel, config);

    if (config.sample_mail == 0 && config.sample_sp == 0 && config.sample_od == 0) {
        throw ConfigError("", "config keys \"sample_mail\", \"sample_sp\" and \"sample_od\" are "
                              "all 0; at least one must be above 0");
    }
    return config;
}

Config load_config(const std::filesystem::path& path)
{
    const std::string prefix = path_to_utf8(path) + ": ";
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw ConfigError("", prefix + "cannot read config file");
    }
    std::ostringstream text;
    text << file.rdbuf();
    try {
        return parse_config(text.str());
    } catch (const ConfigError& e) {
        throw ConfigError(e.key(), prefix + e.what());
    }
}

std::filesystem::path program_data_dir()
{
    PWSTR raw = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &raw);
    // The buffer must be freed even when the call fails.
    const std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> owner(raw, &CoTaskMemFree);
    if (FAILED(result)) {
        throw ConfigError("", "cannot find the ProgramData folder");
    }
    return std::filesystem::path(raw);
}

std::filesystem::path default_config_path()
{
    return program_data_dir() / "RestoreProof" / "config.json";
}

} // namespace rp
