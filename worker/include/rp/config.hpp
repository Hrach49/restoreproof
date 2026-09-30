#pragma once

#include <filesystem>
#include <optional>
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
//   graph_tenant_id          yes       -        GUID (5)
//   graph_client_id          yes       -        GUID (5)
//   test_mailbox             yes       -        restoretest@<domain> (2)
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
//   veeam_ca_file            no        (none)   absolute path of a readable file (3)
//   veeam_cert_sha256        no        (none)   64 hex digits; needs veeam_ca_file (4)
//
// (1) Printable ASCII only, with no user name, password, query or fragment:
//     `config check` prints it.
// (2) "restoretest" in any case, '@', then two or more '.'-separated labels of
//     ASCII letters, digits and '-'. Restores only ever go to the restoretest
//     mailbox, so no other name, and no look-alike of it, is accepted.
// (3) A PEM file of the CA certificate(s), or Veeam's self-signed certificate
//     itself, trusted for veeam_url instead of the Windows certificate store.
//     Only for the Veeam connection: Graph and the Cloud always use the store.
//     TLS certificate verification is always on; this chooses what to trust,
//     and no setting turns verification off. A drive and root (C:\...) or a
//     UNC share (\\server\share\...): the Worker runs as a service whose
//     working directory is System32, so relative and drive-relative paths are
//     rejected. parse_config checks the form; load_config also checks the file
//     can be opened for reading.
// (4) The SHA-256 of Veeam's REST certificate, as Windows shows it: 64
//     hexadecimal digits in any case, with no separators (PowerShell's
//     GetCertHashString('SHA256')). Requires veeam_ca_file, which must hold
//     that certificate in PEM. With both set, the Worker trusts exactly that
//     certificate's public key and skips only the host-name check, which a
//     certificate with no subject alternative name (Veeam's default,
//     CN=Veeam Software) can never pass; the chain and validity dates are
//     still checked against veeam_ca_file. Not a secret. parse_config checks
//     the form and that veeam_ca_file is set; load_config also checks that
//     veeam_ca_file holds the certificate (rp/cert_pin.hpp).
// (5) 8-4-4-4-12 hexadecimal digits in any case, nothing around them
//     (rp::is_uuid): the tenant's ID and the Worker app's Application
//     (client) ID. Not a domain name nor an app name: both go into Entra and
//     Graph URLs.
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
    // UTF-8; nullopt when absent (trust the Windows certificate store).
    std::optional<std::string> veeam_ca_file;
    // As written in the file (either case); nullopt when absent (the host
    // name is checked).
    std::optional<std::string> veeam_cert_sha256;
};

// A config file that can't be read, isn't valid JSON or breaks a rule above,
// or a secret environment variable that can't be read (rp/secrets.hpp).
// what() is the message for the user; it names the offending key or variable
// and never contains a value.
class ConfigError : public std::runtime_error {
public:
    ConfigError(std::string key, const std::string& message);

    // The offending key or environment variable, or empty when the error isn't
    // about a single one (unreadable file, invalid JSON, all sample sizes 0).
    const std::string& key() const noexcept;

private:
    std::string key_;
};

// "restoretest@" in any case, then a domain: two or more non-empty labels of
// ASCII letters, digits and '-', separated by '.'. The mailbox is the only
// mail restore target (docs/decisions.md), so its name is fixed rather than
// trusted: a typo, or a look-alike such as a Cyrillic letter or an invisible
// character, can't point restores at a live mailbox. The domain varies per
// tenant, so it is only checked for shape. parse_config applies it to
// test_mailbox, and connector::RestoreTargets::from_config again, for a
// Config built in code.
bool is_restore_mailbox(std::string_view value);

// The end of every SharePoint Online host name.
inline constexpr std::string_view kSharePointSuffix = ".sharepoint.com";

// The tenant's OneDrive host for its SharePoint host: "<tenant>-my.sharepoint.com"
// for "<tenant>.sharepoint.com" (ASCII case-insensitive, the tenant one DNS
// label of ASCII letters, digits and '-'), in lower case; nullopt for any other
// host. The one derivation of that host: the download allow-list, a OneDrive's
// address and the target guard all use it.
std::optional<std::string> onedrive_host(std::string_view sharepoint_host);

// The shapes of the Graph IDs of the restore targets, which go into Graph URL
// paths (graph_url() doesn't police '?' or '/' inside an ID). parse_config
// applies them to test_site_id, test_library_id, test_onedrive_drive_id and
// test_onedrive_folder_id, so `rpworker config check` catches a wrong one, and
// connector::RestoreTargets::from_config again, for a Config built in code
// (docs/decisions.md 2026-09-28, W2.2). Each rule's text follows the key name.
inline constexpr std::string_view kGraphSiteIdRule =
    "must be a Graph site ID (\"<tenant>.sharepoint.com,<site GUID>,<web GUID>\")";
inline constexpr std::string_view kGraphDriveIdRule =
    "must be a Graph drive ID (\"b!\" then letters, digits, '-' and '_'), not a list ID";
inline constexpr std::string_view kGraphItemIdRule =
    "must be a Graph item ID (letters, digits, '!', '-' and '_')";

struct GraphSiteId {
    std::string host; // "<tenant>.sharepoint.com", lower case
    std::string site; // the site collection GUID
    std::string web;  // the web GUID
};

// Exactly "<tenant>.sharepoint.com,<site GUID>,<web GUID>", the tenant one DNS
// label (1 to 63 ASCII letters, digits and '-', any case), split; else nullopt.
std::optional<GraphSiteId> parse_graph_site_id(std::string_view value);
// "b!" then 1 to 200 ASCII letters, digits, '-' and '_'.
bool is_graph_drive_id(std::string_view value);
// 1 to 200 ASCII letters, digits, '!', '-' and '_'.
bool is_graph_item_id(std::string_view value);

// Parses and validates config.json's text. Stops at the first error and
// throws ConfigError.
Config parse_config(std::string_view json_text);

// Reads the file at `path` and parses it. Throws ConfigError, with the path in
// the message, when the file can't be read, fails validation, names a
// veeam_ca_file that can't be opened for reading, or has a veeam_cert_sha256
// whose certificate veeam_ca_file doesn't hold.
Config load_config(const std::filesystem::path& path);

// %ProgramData% (FOLDERID_ProgramData), e.g. C:\ProgramData. Throws
// ConfigError if Windows can't resolve it.
std::filesystem::path program_data_dir();

// program_data_dir() / "RestoreProof" / "config.json".
std::filesystem::path default_config_path();

} // namespace rp
