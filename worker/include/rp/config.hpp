#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp {

// The Worker's settings, read from config.json (default
// %ProgramData%\RestoreProof\config.json). Secrets are never in this file:
// see rp/secrets.hpp. The keys are documented in docs/worker-config.md.
//
//   key                      required  default  valid values
//   cloud_url                yes       -        https:// URL (1)
//   veeam_url                yes       -        https:// URL (1)
//   veeam_org_name           yes       -        non-empty string
//   graph_tenant_id          yes       -        non-empty string
//   graph_client_id          yes       -        non-empty string
//   test_mailbox             yes       -        email address (contains '@')
//   test_site_id             yes       -        non-empty string
//   test_library_id          yes       -        non-empty string
//   test_onedrive_drive_id   yes       -        non-empty string
//   test_onedrive_folder_id  yes       -        non-empty string
//   poll_interval_s          no        300      integer, 1..86400
//   heartbeat_interval_s     no        900      integer, 1..86400
//   sample_mail              no        5        integer, 0..100
//   sample_sp                no        5        integer, 0..100
//   sample_od                no        5        integer, 0..100
//   log_level                no        "info"   trace, debug, info, warn, error, critical, off
//
// (1) Printable ASCII only, with no user name, password, query or fragment:
//     `config check` prints it.
// No string value may contain a control character: ASCII (below 0x20, 0x7F),
// C1 (U+0080-U+009F), U+2028, U+2029 or a bidi control (U+200E, U+200F,
// U+202A-U+202E, U+2066-U+2069, U+061C).
// At least one of sample_mail, sample_sp and sample_od must be above 0: a run
// that restores nothing must not be able to report `pass`.
struct Config {
    std::string cloud_url;
    std::string veeam_url;
    std::string veeam_org_name;
    std::string graph_tenant_id;
    std::string graph_client_id;
    std::string test_mailbox;
    std::string test_site_id;
    std::string test_library_id;
    std::string test_onedrive_drive_id;
    std::string test_onedrive_folder_id;
    int poll_interval_s = 300;
    int heartbeat_interval_s = 900;
    int sample_mail = 5;
    int sample_sp = 5;
    int sample_od = 5;
    std::string log_level = "info";
};

// A config file that can't be read, isn't valid JSON or breaks a rule above.
// what() is the message for the user; it names the offending key and never
// contains a value from the file.
class ConfigError : public std::runtime_error {
public:
    ConfigError(std::string key, const std::string& message);

    // The offending key, or empty when the error isn't about a single key
    // (unreadable file, invalid JSON, all sample sizes 0).
    const std::string& key() const noexcept;

private:
    std::string key_;
};

// Parses and validates config.json's text. Stops at the first error and
// throws ConfigError.
Config parse_config(std::string_view json_text);

// Reads the file at `path` and parses it. Throws ConfigError, with the path in
// the message, when the file can't be read or fails validation.
Config load_config(const std::filesystem::path& path);

// %ProgramData% (FOLDERID_ProgramData), e.g. C:\ProgramData. Throws
// ConfigError if Windows can't resolve it.
std::filesystem::path program_data_dir();

// program_data_dir() / "RestoreProof" / "config.json".
std::filesystem::path default_config_path();

} // namespace rp
