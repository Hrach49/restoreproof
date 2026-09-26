#include <rp/config.hpp>

#include <rp/cert_pin.hpp>
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
#include <optional>
#include <sstream>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;

enum class StringRule { non_empty, https_url, restore_mailbox, log_level };

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
    {"test_mailbox", &Config::test_mailbox, true, StringRule::restore_mailbox},
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

// Optional, so not StringFields: checked last, after log_level, in this order.
constexpr std::string_view kCaFileKey = "veeam_ca_file";
constexpr std::string_view kCertSha256Key = "veeam_cert_sha256";

constexpr std::array<std::string_view, 7> kLogLevels{"trace", "debug", "info", "warn",
                                                      "error", "critical", "off"};

// Lowercased substrings that mark a key as a secret.
constexpr std::array<std::string_view, 12> kSecretMarkers{
    "password",    "passwd",     "pwd",         "secret",      "token",
    "api_key",     "apikey",     "credential",  "private_key", "access_key",
    "signing_key", "connection_string"};

// The error for a problem with one key: config key "<key>" <problem>.
ConfigError key_error(std::string_view key, std::string_view problem)
{
    std::string message = "config key \"";
    message.append(key).append("\" ").append(problem);
    return ConfigError(std::string{key}, message);
}

// Whether a key name from the file may be printed: 1-64 of [A-Za-z0-9_.-].
// Anything else could be a pasted secret, forge output lines with control
// characters, or flood the output.
bool is_printable_key(std::string_view key)
{
    return !key.empty() && key.size() <= 64 && std::all_of(key.begin(), key.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '-';
    });
}

// The error for a key from the file: named when is_printable_key(), otherwise
// "config has a key that <problem><unnamed_note>" with an empty key().
ConfigError file_key_error(std::string_view key, std::string_view problem,
                           std::string_view unnamed_note)
{
    if (is_printable_key(key)) {
        return key_error(key, problem);
    }
    std::string message = "config has a key that ";
    message.append(problem).append(unnamed_note);
    return ConfigError("", message);
}

bool is_known_key(std::string_view key)
{
    const auto named = [key](const auto& field) { return field.key == key; };
    return std::any_of(kRequiredStrings.begin(), kRequiredStrings.end(), named) ||
           std::any_of(kIntFields.begin(), kIntFields.end(), named) || key == kLogLevel.key ||
           key == kCaFileKey || key == kCertSha256Key;
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
// No user name or password (an '@' before the path) and no query or fragment,
// so a credential can't hide in the URL and get printed by `config check`;
// printable ASCII (0x21-0x7E) only, so a look-alike such as a fullwidth @
// can't stand in for the real one.
bool is_https_url(std::string_view value)
{
    constexpr std::string_view scheme = "https://";
    const auto printable_ascii = [](char c) { return c >= 0x21 && c <= 0x7E; };
    if (!std::all_of(value.begin(), value.end(), printable_ascii) ||
        value.size() <= scheme.size() || value[scheme.size()] == '/' ||
        value.find_first_of("?#") != std::string_view::npos) {
        return false;
    }
    const std::string_view rest = value.substr(scheme.size());
    if (rest.substr(0, rest.find('/')).find('@') != std::string_view::npos) {
        return false;
    }
    return std::equal(scheme.begin(), scheme.end(), value.begin(), [](char a, char b) {
        return a == std::tolower(static_cast<unsigned char>(b));
    });
}

// "restoretest@" in any case, then a domain: two or more non-empty labels of
// ASCII letters, digits and '-', separated by '.'. The mailbox is the only
// mail restore target (docs/decisions.md), so its name is fixed rather than
// trusted: a typo, or a look-alike such as a Cyrillic letter or an invisible
// character, can't point restores at a live mailbox. The domain varies per
// tenant, so it is only checked for shape.
bool is_restore_mailbox(std::string_view value)
{
    constexpr std::string_view local = "restoretest@";
    if (value.size() <= local.size() ||
        !std::equal(local.begin(), local.end(), value.begin(), [](char a, char b) {
            return a == std::tolower(static_cast<unsigned char>(b));
        })) {
        return false;
    }
    const std::string_view domain = value.substr(local.size());
    const auto label_char = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '-';
    };
    std::size_t labels = 0;
    std::size_t start = 0;
    while (true) {
        const std::size_t dot = domain.find('.', start);
        const std::string_view label = domain.substr(start, dot - start);
        if (label.empty() || !std::all_of(label.begin(), label.end(), label_char)) {
            return false;
        }
        ++labels;
        if (dot == std::string_view::npos) {
            return labels >= 2;
        }
        start = dot + 1;
    }
}

// Control and invisible formatting characters that could forge, hide or
// reorder lines of `config check` output: ASCII controls (below 0x20, and
// DEL) and, as UTF-8, C1 controls (U+0080-U+009F), the line and paragraph
// separators (U+2028, U+2029), bidi marks and overrides (U+200E, U+200F,
// U+202A-U+202E, and the Arabic letter mark U+061C) and bidi isolates
// (U+2066-U+2069). The JSON parser has
// already rejected invalid UTF-8, so matching byte sequences is enough.
bool has_control_character(std::string_view value)
{
    const auto byte = [value](std::size_t i) {
        return i < value.size() ? static_cast<unsigned char>(value[i]) : 0;
    };
    for (std::size_t i = 0; i < value.size(); ++i) {
        const unsigned char b0 = byte(i);
        const unsigned char b1 = byte(i + 1);
        const unsigned char b2 = byte(i + 2);
        if (b0 < 0x20 || b0 == 0x7F || (b0 == 0xC2 && b1 >= 0x80 && b1 <= 0x9F) ||
            (b0 == 0xD8 && b1 == 0x9C) ||
            (b0 == 0xE2 && b1 == 0x80 &&
             (b2 == 0x8E || b2 == 0x8F || (b2 >= 0xA8 && b2 <= 0xAE))) ||
            (b0 == 0xE2 && b1 == 0x81 && b2 >= 0xA6 && b2 <= 0xA9)) {
            return true;
        }
    }
    return false;
}

// What is wrong with `value` under `rule`, or nothing when it follows it. One
// switch holds each rule's check and its message together, with no default:
// a rule added to StringRule without a case is a build error (/we4062).
std::optional<std::string_view> rule_problem(StringRule rule, std::string_view value)
{
    switch (rule) {
    case StringRule::non_empty:
        // find_string() has already refused an empty value.
        return std::nullopt;
    case StringRule::https_url:
        if (is_https_url(value)) {
            return std::nullopt;
        }
        return "must be an https:// URL with no user name, password, query or fragment";
    case StringRule::restore_mailbox:
        if (is_restore_mailbox(value)) {
            return std::nullopt;
        }
        return "must be restoretest@<domain>: restores only ever go to the restoretest mailbox";
    case StringRule::log_level:
        if (std::find(kLogLevels.begin(), kLogLevels.end(), value) != kLogLevels.end()) {
            return std::nullopt;
        }
        return "must be one of trace, debug, info, warn, error, critical, off";
    }
    // Only a value outside StringRule gets here: refuse it rather than pass it.
    return "has no known rule";
}

// The string at `key`, checked as every string setting is: a string, not
// empty, no control characters. nullptr when it is absent and not required.
const std::string* find_string(const json& doc, std::string_view key, bool required)
{
    const auto it = doc.find(key);
    if (it == doc.end()) {
        if (required) {
            throw key_error(key, "is missing (required)");
        }
        return nullptr;
    }
    if (!it->is_string()) {
        throw key_error(key, "must be a string");
    }
    const auto& value = it->get_ref<const std::string&>();
    if (value.empty()) {
        throw key_error(key, "must not be empty");
    }
    if (has_control_character(value)) {
        throw key_error(key, "must not contain control characters");
    }
    return &value;
}

void read_string(const json& doc, const StringField& field, Config& config)
{
    const std::string* value = find_string(doc, field.key, field.required);
    if (value == nullptr) {
        return;
    }
    if (const auto problem = rule_problem(field.rule, *value)) {
        throw key_error(field.key, *problem);
    }
    config.*field.member = *value;
}

// A path with a drive and a root (C:\...) or a UNC share (\\server\share\...).
// The Worker runs as a service whose working directory is System32, so a
// relative, rooted-without-drive (\x) or drive-relative (C:x) path would name
// a file that depends on where the process happens to be. The value is valid
// UTF-8 (the JSON parser checked), so the conversion only fails in theory.
bool is_absolute_path(std::string_view value)
{
    const std::optional<std::filesystem::path> path = path_from_utf8(value);
    return path && path->is_absolute();
}

void read_ca_file(const json& doc, Config& config)
{
    const std::string* value = find_string(doc, kCaFileKey, false);
    if (value == nullptr) {
        return;
    }
    if (!is_absolute_path(*value)) {
        throw key_error(kCaFileKey, "must be an absolute path, such as "
                                    "C:\\ProgramData\\RestoreProof\\veeam-ca.pem or "
                                    "\\\\server\\share\\veeam-ca.pem");
    }
    config.veeam_ca_file = *value;
}

// After read_ca_file: the pin names a certificate that veeam_ca_file holds,
// so it means nothing without it. Whether the file really holds it is
// load_config's check, since parse_config never opens files.
void read_cert_sha256(const json& doc, Config& config)
{
    const std::string* value = find_string(doc, kCertSha256Key, false);
    if (value == nullptr) {
        return;
    }
    if (!is_sha256_hex(*value)) {
        throw key_error(kCertSha256Key, "must be the certificate's SHA-256: 64 hexadecimal "
                                        "digits, as Windows shows it");
    }
    if (!config.veeam_ca_file) {
        throw key_error(kCertSha256Key,
                        "needs veeam_ca_file: set it to a PEM file holding that certificate");
    }
    config.veeam_cert_sha256 = *value;
}

void read_int(const json& doc, const IntField& field, Config& config)
{
    const auto it = doc.find(field.key);
    if (it == doc.end()) {
        return;
    }
    if (!it->is_number_integer()) {
        throw key_error(field.key, "must be an integer");
    }
    // Positive JSON integers are stored unsigned, negative ones signed; compare
    // each in its own type so no value overflows on the way to int.
    const bool in_range =
        it->is_number_unsigned()
            ? it->get<std::uint64_t>() >= static_cast<std::uint64_t>(field.min) &&
                  it->get<std::uint64_t>() <= static_cast<std::uint64_t>(field.max)
            : it->get<std::int64_t>() >= field.min && it->get<std::int64_t>() <= field.max;
    if (!in_range) {
        throw key_error(field.key, field.range_message);
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
    } catch (const json::exception&) {
        // out_of_range 406: a number too large for a double, e.g. 1e400. Its
        // message quotes the number, so it isn't shown either.
        throw ConfigError("", "config is not valid JSON (a number is out of range)");
    }
    if (!doc.is_object()) {
        throw ConfigError("", "config must be a JSON object");
    }

    // Secrets first, so the user takes one out of the file before anything else.
    for (const auto& item : doc.items()) {
        if (looks_like_secret(item.key())) {
            throw file_key_error(item.key(), secret_key_problem(), "");
        }
    }
    for (const auto& item : doc.items()) {
        if (!is_known_key(item.key())) {
            throw file_key_error(item.key(), "is not a known setting",
                                 " (its name isn't shown: only 1-64 letters, digits, '_', '.' "
                                 "and '-' are printed)");
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
    read_ca_file(doc, config);
    read_cert_sha256(doc, config);

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
    Config config;
    try {
        config = parse_config(text.str());
    } catch (const ConfigError& e) {
        throw ConfigError(e.key(), prefix + e.what());
    }
    // Here rather than in parse_config, which stays pure over the text. Opening
    // for reading also fails on a directory. Like every message, it names the
    // key, not the value.
    if (config.veeam_ca_file) {
        const std::optional<std::filesystem::path> ca_path = path_from_utf8(*config.veeam_ca_file);
        if (!ca_path || !std::ifstream(*ca_path, std::ios::binary)) {
            const ConfigError e = key_error(kCaFileKey, "names a file that can't be read");
            throw ConfigError(e.key(), prefix + e.what());
        }
    }
    // The pin is discarded: computing it only proves the file holds the named
    // certificate, so a wrong value is reported now rather than as a TLS
    // failure later. CertPinError never quotes the file.
    if (config.veeam_cert_sha256) {
        try {
            static_cast<void>(public_key_pin(*config.veeam_ca_file, *config.veeam_cert_sha256));
        } catch (const CertPinError& e) {
            throw ConfigError(std::string{kCertSha256Key},
                              prefix + "config key \"" + std::string{kCertSha256Key} +
                                  "\": " + e.what());
        }
    }
    return config;
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
