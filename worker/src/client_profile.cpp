#include <rp/client_profile.hpp>

#include "file_read.hpp"
#include "path_utf8.hpp"
#include "strict_json.hpp"
#include "text_table.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;

constexpr std::string_view kFormatKey = "format";
constexpr std::string_view kNotADocument = "not a restoreproof.client-profile.v1 document";
constexpr std::string_view kUnknownKey = "has a key that isn't the profile's";

// The profile's field for `key`.
std::string ClientProfile::*member_of(std::string_view key)
{
    if (key == "veeam_org_name") {
        return &ClientProfile::veeam_org_name;
    }
    if (key == "graph_tenant_id") {
        return &ClientProfile::graph_tenant_id;
    }
    if (key == "graph_client_id") {
        return &ClientProfile::graph_client_id;
    }
    if (key == "test_mailbox") {
        return &ClientProfile::test_mailbox;
    }
    if (key == "test_site_id") {
        return &ClientProfile::test_site_id;
    }
    if (key == "test_library_id") {
        return &ClientProfile::test_library_id;
    }
    if (key == "test_onedrive_drive_id") {
        return &ClientProfile::test_onedrive_drive_id;
    }
    return &ClientProfile::test_onedrive_folder_id;
}

// What is wrong with `value` as `key`'s value, or nothing: the config's rule
// for the same key, with its text.
std::optional<std::string_view> shape_problem(std::string_view key, std::string_view value)
{
    if (key == "graph_tenant_id" || key == "graph_client_id") {
        return is_uuid(value) ? std::nullopt : std::optional{kGuidRule};
    }
    if (key == "test_mailbox") {
        return is_restore_mailbox(value) ? std::nullopt : std::optional{kRestoreMailboxRule};
    }
    if (key == "test_site_id") {
        return parse_graph_site_id(value) ? std::nullopt : std::optional{kGraphSiteIdRule};
    }
    if (key == "test_library_id" || key == "test_onedrive_drive_id") {
        return is_graph_drive_id(value) ? std::nullopt : std::optional{kGraphDriveIdRule};
    }
    if (key == "test_onedrive_folder_id") {
        return is_graph_item_id(value) ? std::nullopt : std::optional{kGraphItemIdRule};
    }
    // veeam_org_name: any text (its length and characters were checked).
    return std::nullopt;
}

bool is_text_key(std::string_view key)
{
    return key == "veeam_org_name" || key == "test_mailbox";
}

// The key's value checked as the config checks a string setting, then by
// its shape; the problem, or nothing when `into` took the value.
std::optional<std::string_view> read_key(const json& object, std::string_view key,
                                         ClientProfile& into)
{
    const auto it = object.find(key);
    if (it == object.end()) {
        return "is missing (required)";
    }
    if (!it->is_string()) {
        return "must be a string";
    }
    const std::string& value = it->get_ref<const std::string&>();
    if (value.empty()) {
        return "must not be empty";
    }
    if (has_control_character(value)) {
        return "must not contain control characters";
    }
    if (is_text_key(key) && value.size() > kMaxProfileText) {
        return "must be at most 1024 characters";
    }
    if (const std::optional<std::string_view> problem = shape_problem(key, value)) {
        return problem;
    }
    into.*member_of(key) = value;
    return std::nullopt;
}

bool is_profile_key(std::string_view key)
{
    return key == kFormatKey ||
           std::ranges::find(kClientProfileKeys, key) != kClientProfileKeys.end();
}

} // namespace

std::string ProfileFault::text() const
{
    return key.empty() ? problem : "key \"" + key + "\" " + problem;
}

std::variant<ClientProfile, ProfileFault> parse_client_profile(const json& value)
{
    const auto format = value.is_object() ? value.find(kFormatKey) : value.end();
    if (!value.is_object() || format == value.end() || !format->is_string() ||
        format->get_ref<const std::string&>() != kClientProfileFormat) {
        return ProfileFault{"", std::string{kNotADocument}};
    }
    for (auto it = value.begin(); it != value.end(); ++it) {
        if (!is_profile_key(it.key())) {
            std::string problem{kUnknownKey};
            if (is_printable_key(it.key())) {
                problem += ": \"" + it.key() + "\"";
            }
            return ProfileFault{"", std::move(problem)};
        }
    }
    ClientProfile profile;
    for (const std::string_view key : kClientProfileKeys) {
        if (const std::optional<std::string_view> problem = read_key(value, key, profile)) {
            return ProfileFault{std::string{key}, std::string{*problem}};
        }
    }
    return profile;
}

json to_json(const ClientProfile& profile)
{
    return {{"format", kClientProfileFormat},
            {"veeam_org_name", profile.veeam_org_name},
            {"graph_tenant_id", profile.graph_tenant_id},
            {"graph_client_id", profile.graph_client_id},
            {"test_mailbox", profile.test_mailbox},
            {"test_site_id", profile.test_site_id},
            {"test_library_id", profile.test_library_id},
            {"test_onedrive_drive_id", profile.test_onedrive_drive_id},
            {"test_onedrive_folder_id", profile.test_onedrive_folder_id}};
}

std::optional<ClientProfile> local_profile(const Config& config)
{
    ClientProfile profile{.veeam_org_name = config.veeam_org_name,
                          .graph_tenant_id = config.graph_tenant_id,
                          .graph_client_id = config.graph_client_id,
                          .test_mailbox = config.test_mailbox,
                          .test_site_id = config.test_site_id,
                          .test_library_id = config.test_library_id,
                          .test_onedrive_drive_id = config.test_onedrive_drive_id,
                          .test_onedrive_folder_id = config.test_onedrive_folder_id};
    // All eight, or none (parse_config's rule): a Config built in code with
    // some of them is no local profile either.
    for (const std::string_view key : kClientProfileKeys) {
        if ((profile.*member_of(key)).empty()) {
            return std::nullopt;
        }
    }
    return profile;
}

ClientProfile read_client_profile_file(const std::filesystem::path& file)
{
    const auto refused = [&file](std::string_view problem) {
        return ConfigError("--profile-file", "--profile-file " + table_cell(path_to_utf8(file)) +
                                                 ": " + std::string{problem});
    };
    const FileRead read = read_whole_file(file, kMaxProfileFileBytes);
    if (read.state == FileState::too_large) {
        throw refused("over 64 KiB");
    }
    if (read.state != FileState::read) {
        throw refused("can't be read");
    }
    std::string_view text = read.bytes;
    // A byte order mark before the document is taken, as the jobs reader
    // takes it.
    if (text.starts_with("\xef\xbb\xbf")) {
        text.remove_prefix(3);
    }
    const std::optional<json> document = parse_strict_json(text);
    if (!document) {
        throw refused("not JSON");
    }
    std::variant<ClientProfile, ProfileFault> parsed = parse_client_profile(*document);
    if (const ProfileFault* fault = std::get_if<ProfileFault>(&parsed)) {
        throw refused(fault->text());
    }
    return std::get<ClientProfile>(std::move(parsed));
}

} // namespace rp
