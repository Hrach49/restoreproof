#pragma once

// The client profile (W4.10, docs/decisions.md 2026-10-09): one client of a
// Worker, as a job carries it (rp/service_jobs.hpp, the job's `client`) and as
// a profile file holds it (`rpworker client check --profile-file`, `restore`
// and `test` with --profile-file). A client is one Microsoft 365 tenant, which
// the backup product backs up as one organisation. IDs only, under the names
// config.json uses for the same values and with config.json's shape rules:
// the organisation's name, the tenant, the Worker app's application (client)
// ID, the restoretest mailbox and the four Graph IDs of the restore targets.
// No name, URL or secret; nothing in it is a secret value.
//
//   {"format": "restoreproof.client-profile.v1",
//    "veeam_org_name": "contoso.onmicrosoft.com",
//    "graph_tenant_id": "<GUID>", "graph_client_id": "<GUID>",
//    "test_mailbox": "restoretest@contoso.onmicrosoft.com",
//    "test_site_id": "contoso.sharepoint.com,<site GUID>,<web GUID>",
//    "test_library_id": "b!...", "test_onedrive_drive_id": "b!...",
//    "test_onedrive_folder_id": "01..."}
//
// The schema is shared/schemas/client-profile.v1.json, the Cloud's copy of
// these rules; the Worker checks them in code, as it does the signature
// file's, and the shared vectors shared/testdata/client-profile-v1/ hold the
// two together. The config's eight client keys, when they are all set, are a
// local profile (local_profile); the service's runs never use it.

#include <rp/config.hpp>

#include <nlohmann/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace rp {

inline constexpr std::string_view kClientProfileFormat = "restoreproof.client-profile.v1";
// The most a profile file may hold: a profile is nine short strings.
inline constexpr std::uintmax_t kMaxProfileFileBytes = 64u * 1024u;
// The longest veeam_org_name and test_mailbox, as the result's schema has
// them; the other keys are bounded by their shapes.
inline constexpr std::size_t kMaxProfileText = 1024;

// The eight keys beside `format`, in the config's order, which is the order
// faults are reported in.
inline constexpr std::array<std::string_view, 8> kClientProfileKeys{
    "veeam_org_name",  "graph_tenant_id",        "graph_client_id",        "test_mailbox",
    "test_site_id",    "test_library_id",        "test_onedrive_drive_id", "test_onedrive_folder_id"};

struct ClientProfile {
    std::string veeam_org_name;
    std::string graph_tenant_id;
    std::string graph_client_id;
    std::string test_mailbox;
    std::string test_site_id;
    std::string test_library_id;
    std::string test_onedrive_drive_id;
    std::string test_onedrive_folder_id;

    bool operator==(const ClientProfile&) const = default;
};

// Why a value isn't a profile. `key` is the profile key at fault, or empty
// when the fault is the object's: not an object, not the format, or a key
// that isn't the profile's. `problem` is config.json's text for the same
// fault: "is missing (required)", "must be a string", "must not be empty",
// "must not contain control characters", "must be at most 1024 characters",
// rp::kGuidRule, rp::kRestoreMailboxRule, rp::kGraphSiteIdRule,
// rp::kGraphDriveIdRule, rp::kGraphItemIdRule; and for the object
// "not a restoreproof.client-profile.v1 document" or "has a key that isn't
// the profile's" (": \"<key>\"" added when the name passes
// rp::is_printable_key). Never a value.
struct ProfileFault {
    std::string key;
    std::string problem;

    // `key "<key>" <problem>`, or the problem alone for the object's.
    std::string text() const;

    bool operator==(const ProfileFault&) const = default;
};

// `value` as a profile, or the first fault, in this order: an object; its
// `format` the format's name; no key that isn't the profile's (the first in
// key order); then each of kClientProfileKeys in that order: there, a
// string, not empty, no control character (rp::has_control_character), at
// most kMaxProfileText characters for veeam_org_name and test_mailbox, and
// its shape (the config's rule). Pure.
std::variant<ClientProfile, ProfileFault> parse_client_profile(const nlohmann::json& value);

// The closed object: `format` and the eight keys. What the record holds
// (W4.8's running.json) and what a job carries.
nlohmann::json to_json(const ClientProfile& profile);

// The config's local profile: its eight client keys, when they are set
// (parse_config takes them all or none); nullopt when the config has none.
// What the commands at a prompt run on without --profile-file; the service
// never asks for it.
std::optional<ClientProfile> local_profile(const Config& config);

// Reads `file` whole, at most kMaxProfileFileBytes, as strict JSON (a key
// twice refused, as the jobs reader refuses it) and parses it. Throws
// ConfigError, key() "--profile-file", with the message
// "--profile-file <file>: <problem>" (the file as UTF-8, control characters
// as spaces): "can't be read", "over 64 KiB", "not JSON", or
// ProfileFault::text(). Never a value of the file.
ClientProfile read_client_profile_file(const std::filesystem::path& file);

} // namespace rp
