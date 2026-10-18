#pragma once

// `rpworker doctor`'s judgement (W7.2, docs/decisions.md 2026-10-18): what each
// check concludes from what was read, as one line per check, and nothing read
// here. rp/doctor_command.hpp reads the machine, Veeam, Entra, Graph, the
// Cloud and the TSA through its seams and hands the facts to the functions
// below, in the entry's order (point 6); each adds its lines to a Report.
//
// A line is one of four words (point 2): `ok:`, `warning:` (works today, or
// isn't ours to fix; no effect on the exit code), `problem:` (with the fix
// as a line to run) and `skip:` (a check whose input a failed check was to
// give: never counted as a problem, so one missing grant is one problem
// line). Every check has a fixed id and, for a warning or a problem, a fixed
// code: the --json file holds those and never the line's text (point 2).
//
// Nothing here throws but for no memory. Strict (100% line): every word the
// operator acts on is decided here.

#include <rp/cert_export.hpp>
#include <rp/client_profile.hpp>
#include <rp/cloud_api.hpp>
#include <rp/service.hpp>
#include <rp/vault.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::doctor {

// --- The report ---------------------------------------------------------------

enum class Result { ok, warning, problem, skip };

// "ok", "warning", "problem", "skip": the line's first word and --json's.
std::string_view to_string(Result result) noexcept;

struct Check {
    std::string id;   // fixed: "vault.service_read", "veeam.org[2].key_file", "client[1]...."
    Result result = Result::ok;
    std::string code; // a fixed word for a warning or a problem, "ok" or "skip" otherwise
    std::string text; // "<area>: <what>", for the console alone
    std::string fix;  // a warning's or a problem's line to run; a skip's "needs" text

    bool operator==(const Check&) const = default;
};

// The line printed for `check`, without its newline:
//   ok: <text>
//   warning: <text>                    (no fix)
//   warning: <text> (fix: <fix>)
//   problem: <text> (fix: <fix>)
//   skip: <text> (needs <fix>)
std::string line_of(const Check& check);

// Doctor's exit codes: none of its lines a problem, or at least one
// (rp::exit_code::restore, "the thing tested failed").
inline constexpr int kExitHealthy = 0;
inline constexpr int kExitProblem = 5;

class Report {
public:
    void ok(std::string id, std::string text);
    void warning(std::string id, std::string code, std::string text, std::string fix = {});
    void problem(std::string id, std::string code, std::string text, std::string fix);
    void skip(std::string id, std::string text, std::string needs);

    // Whether a check whose id is `id`, or starts with `id` and a '.', is a
    // problem.
    bool failed(std::string_view id) const;

    const std::vector<Check>& checks() const noexcept { return checks_; }
    int count(Result result) const noexcept;

    // "doctor: <n> ok, <w> warning(s), <p> problem(s), <s> skipped".
    std::string summary_line() const;
    int exit_code() const noexcept;

private:
    std::vector<Check> checks_;
};

// What --json says beside the checks (point 2): no text, no path, no
// thumbprint, no name, no tenant value. worker_id and key_id are empty when
// unknown and then left out.
struct JsonFacts {
    std::string worker_version;
    std::string windows_build;
    std::string generated_at; // "YYYY-MM-DDTHH:MM:SSZ"
    bool elevated = false;
    std::string worker_id;
    std::string key_id;
};

inline constexpr std::string_view kDoctorFormat = "restoreproof.doctor.v1";

// The --json document, canonical-json-v1 (rp::canonical_json):
// {"checks":[{"code","id","result"}...],"counts":{"ok","problem","skip","warning"},
//  "elevated","format","generated_at","key_id"?,"windows_build","worker_id"?,"worker_version"}.
std::string json_text(const Report& report, const JsonFacts& facts);

// --- Security descriptors and the wanted ACLs ------------------------------------

// Windows' file rights, as an ACE's mask holds them (FileSystemRights, with
// Synchronize where icacls' simple rights carry it).
inline constexpr std::uint32_t kRightsFull = 0x001F01FF;        // F, FA
inline constexpr std::uint32_t kRightsModify = 0x001301BF;      // M
inline constexpr std::uint32_t kRightsReadExecute = 0x001200A9; // RX
inline constexpr std::uint32_t kRightsRead = 0x00120089;        // R, FR
// The bits that let an account change a file or a folder, or its ACL.
inline constexpr std::uint32_t kWriteBits =
    0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000100 | 0x00010000 | 0x00040000 |
    0x00080000 | 0x10000000 | 0x40000000;

inline constexpr std::string_view kSidSystem = "S-1-5-18";
inline constexpr std::string_view kSidAdministrators = "S-1-5-32-544";
inline constexpr std::string_view kSidOwnerRights = "S-1-3-4";
inline constexpr std::string_view kSidAllServices = "S-1-5-80-0";
inline constexpr std::string_view kSidTrustedInstaller =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

// One access entry as read, every SID as a string ("S-1-...").
struct Ace {
    std::string sid;
    bool allow = true;
    std::uint32_t mask = 0;
    bool to_children = false; // (OI)(CI): inherited by files and folders below
    bool inherit_only = false;
    bool inherited = false;   // came from the parent

    bool operator==(const Ace&) const = default;
};

// An object's owner and DACL as read. `present` false: nothing at the path;
// `readable` false: there, and its security couldn't be read.
struct Security {
    bool present = false;
    bool readable = false;
    std::string owner_sid;
    bool is_protected = false;
    std::vector<Ace> aces;
};

struct WantedRule {
    std::string sid;
    std::uint32_t mask = 0;
    std::string_view icacls; // "F", "M", "RX", "R"
};

// One object's wanted DACL, from shared/testdata/worker-acls-v1.json: `path`
// relative to %ProgramData%\RestoreProof ("" the root, "vault.bin").
struct WantedAcl {
    std::string path;
    bool is_protected = false;
    bool to_children = true; // the folders' rules are (OI)(CI); the vault's aren't
    std::vector<WantedRule> rules;
};

// The root and the six folders, in the vector's order; then the vault.
std::vector<WantedAcl> wanted_folders(std::string_view service_sid);
WantedAcl wanted_vault(std::string_view service_sid);

// The service's SID: S-1-5-80 and the five little-endian DWORDs of the SHA-1
// of the upper-cased UTF-16 name, what `sc showsid` prints. The name is ASCII
// (rp::kServiceName); nullopt for anything else.
std::optional<std::string> service_sid(std::string_view service_name);

// The groups a virtual account's service token carries besides its own SID
// (W4.12 probe 2, and the two every service logon has): what the access
// checks are made for (point 1).
const std::vector<std::string>& service_token_groups();

// What differs between `security` and `wanted`: a wanted rule absent as one
// explicit Allow of exactly that mask and inheritance; every explicit Deny and
// every explicit Allow for a SID the rules don't name (stricter than the
// installer on a folder that inherits: W7.1 review finding 10), each SID and
// kind once; the protection; an owner other than SYSTEM or Administrators.
struct AclDifference {
    std::vector<WantedRule> missing;
    std::vector<Ace> extra;
    bool protection_wrong = false;
    bool owner_wrong = false;

    bool ok() const noexcept
    {
        return missing.empty() && extra.empty() && !protection_wrong && !owner_wrong;
    }
};
AclDifference acl_difference(const Security& security, const WantedAcl& wanted);

// The SIDs whose entries that apply to the object (not inherit-only) allow it
// to be changed (kWriteBits), other than SYSTEM, Administrators and
// TrustedInstaller; each once, in the order found.
std::vector<std::string> unexpected_writers(const Security& security);

// --- The checks, one function per area, in the order doctor runs them --------------
//
// Each adds its lines to `report`. A path is given as text, as printed.

// 1. doctor: elevated (false: one problem line, and the caller stops), the
// exe doctor runs as against the service's.
struct MachineFacts {
    bool elevated = false;
    std::string version;            // this exe's
    std::string exe;                // this exe's full path
    std::optional<std::string> service_exe; // the installed service's exe, if any
};
bool check_doctor(const MachineFacts& facts, Report& report);

// The exe a service command line runs: the text between its first two
// quotes, or up to the first space when it isn't quoted.
std::string exe_of_command_line(std::string_view command_line);

// 2. config.
struct ConfigFacts {
    std::string file;
    std::optional<std::string> load_error; // ConfigError's what(): config check's words
    OwnerTrust owner = OwnerTrust::trusted;
    bool explicit_entries = false;          // an entry of its own beside the inherited
    bool jobs_file_set = false;
    bool client_keys_set = false;
};
// False when the config didn't load: what reads it later is skipped.
bool check_config(const ConfigFacts& facts, Report& report);

// The installer, as the fix for what it sets (W7.1).
inline constexpr std::string_view kInstallerFix = "pwsh -File Install-RestoreProofWorker.ps1";

// 3. folders: the root and the six folders, the outbox, the disk, the log.
struct FolderFacts {
    std::string path;                          // as printed
    Security security;
    std::optional<std::uint32_t> service_access; // Authz's granted mask; nullopt: not asked
};
void check_folders(const std::vector<WantedAcl>& wanted, const std::vector<FolderFacts>& facts,
                   Report& report);

struct OutboxFacts {
    std::string failed_path;
    bool failed_listable = true;
    int queued = 0;
    int sent = 0;
    int failed = 0;
    std::optional<std::chrono::seconds> oldest_queued_age;
};
inline constexpr std::chrono::hours kQueuedTooLong{24};
void check_outbox(const OutboxFacts& facts, Report& report);

struct DiskFacts {
    std::string path;
    std::optional<std::uint64_t> free_bytes; // nullopt: couldn't be read
};
inline constexpr std::uint64_t kDiskProblemBytes = std::uint64_t{1} << 30;
inline constexpr std::uint64_t kDiskWarningBytes = std::uint64_t{5} << 30;
void check_disk(const DiskFacts& facts, Report& report);

struct LogFacts {
    std::string path;
    std::optional<std::uint64_t> live_bytes; // worker.log; nullopt: none
    std::uint64_t set_bytes = 0;             // worker.log and its rotated files
};
void check_log(const LogFacts& facts, Report& report);

// 4. vault.
struct VaultFacts {
    std::string path;
    std::optional<std::string> read_error; // VaultError's what()
    std::vector<std::string> names;        // the names it holds, when it was read
    Security security;
    std::optional<std::uint32_t> service_access;
    // Each SID of the DACL with the account's name, for the ok line; a SID
    // with no name stays a SID.
    std::vector<std::pair<std::string, std::string>> account_names;
    std::string service_sid;
    std::string exe; // rpworker.exe's path, for the fixes
};
// False when the vault couldn't be read: what needs its values is skipped.
bool check_vault(const VaultFacts& facts, Report& report);

// 5. the signing key, against state\worker.json.
struct RecordFacts {
    bool present = false;
    std::optional<WorkerRecord> record; // nullopt and present: unreadable
};
struct SigningFacts {
    std::optional<std::string> key_id; // nullopt: not in the vault, or not a key
    bool in_vault = false;
};
void check_signing_key(const SigningFacts& signing, const RecordFacts& record, Report& report);

// 6. service.
struct LogonFacts {
    std::optional<std::vector<std::string>> allowed; // SeServiceLogonRight; nullopt: unread
    std::vector<std::string> denied;                 // SeDenyServiceLogonRight
};
struct RunRecordFacts {
    bool present = false;
    std::string run_id;                      // empty when unreadable
    std::chrono::seconds age{0};
};
inline constexpr std::chrono::hours kHeldRunAfter{6};
struct ServiceFacts {
    ScmResult read;          // read_setup's answer: 1060 at ScmStep::service = not installed
    ServiceSetup setup;
    ScmResult query;
    ServiceStatus status;
    std::string expected_exe; // the exe the command line must run (the installed one)
    std::string service_sid;
    LogonFacts logon;
    Security exe_security;
    std::optional<std::uint32_t> exe_access;
    RunRecordFacts running;
    std::string log_file;     // for the stopped line
};
void check_service(const ServiceFacts& facts, Report& report);

// 7. cloud.
struct VersionAnswer {
    bool answered = false;
    std::string failure;     // no answer: the HTTP client's word ("unreachable", ...)
    int status = 0;
    CloudAnswerKind kind = CloudAnswerKind::not_cloud;
    std::string body;        // read through strict JSON for "api" and "version" alone
};
struct CloudFacts {
    std::string cloud_url;   // the config's
    RecordFacts record;
    VersionAnswer version;
};
void check_cloud(const CloudFacts& facts, Report& report);

// 8. tsa and clock.
inline constexpr std::chrono::seconds kClockSkewLimit{120};
struct TsaFacts {
    std::string url;
    bool stamped = false;
    std::string error;       // a timestamp_code when not stamped
    std::int64_t gen_time = 0;
    std::int64_t now = 0;    // this machine's clock, seconds since 1970 UTC
};
void check_tsa(const TsaFacts& facts, Report& report);

// 9. veeam.
struct CertificateFacts {
    std::string thumbprint;             // upper case
    std::optional<CertExportFailure> export_failure; // nullopt: exported and discarded
    std::string export_message;         // the exporter's what(), when it failed
    std::optional<std::chrono::system_clock::time_point> not_after;
    std::optional<std::string> key_file; // the resolved path; nullopt: none found
    std::optional<std::uint32_t> service_access;
};
struct OrganisationFacts {
    std::string name;
    std::optional<std::string> newest_point; // Veeam's backupTime of the newest, to the second
    std::vector<CertificateFacts> certificates; // Exchange's, then SharePoint's when another
};
struct VeeamFacts {
    std::string url;
    bool url_local = false;
    ScmResult rest_query;      // Veeam.Archiver.REST.Service
    ServiceStatus rest_status;
    std::optional<std::string> login_error; // "veeam error: ..." words; nullopt: signed in
    std::vector<OrganisationFacts> organisations;
    std::string service_sid;
    std::chrono::system_clock::time_point now;
};
inline constexpr std::chrono::hours kCertificateWarning{30 * 24};
inline constexpr std::string_view kVeeamRestService = "Veeam.Archiver.REST.Service";
void check_veeam(const VeeamFacts& facts, Report& report);

// The key file's grant line: icacls "<file>" /grant "*<sid>:(R)".
std::string key_file_grant(std::string_view key_file, std::string_view sid);

// 10. graph: the Worker's certificate and, without a client, Entra's and
// Graph's reach.
struct GraphFacts {
    std::optional<std::string> certificate_error; // CertificateError's what()
    std::string thumbprint;
    std::chrono::system_clock::time_point not_after{};
    std::chrono::system_clock::time_point now{};
    bool clients_named = false;
    std::string exe; // rpworker.exe's path, for the certificate script's fix
    // Without a client: each host and its failure word, empty when reached.
    std::vector<std::pair<std::string, std::string>> reach;
};
// False when the certificate didn't open: the clients' Graph checks skip.
bool check_graph(const GraphFacts& facts, Report& report);

// 11. one client, numbered from 1 in the order given.
inline constexpr std::string_view kRoleFiles = "Files.SelectedOperations.Selected";
inline constexpr std::string_view kRoleLists = "Lists.SelectedOperations.Selected";
inline constexpr std::string_view kRoleSites = "Sites.Selected";
// The three, in that order: exactly what the app's token must carry.
const std::vector<std::string_view>& wanted_roles();

struct TargetRead {
    bool read = false;
    std::size_t items = 0;
    std::string error; // the GraphError's what(): names the grant the read relies on
};
struct ClientFacts {
    int number = 1;
    std::string file;
    std::optional<std::string> profile_error;  // read_client_profile_file's what()
    ClientProfile profile;
    // The client check against Veeam: nullopt when Veeam wasn't read (its
    // login failed); else the mismatch's words, empty when the client matched.
    std::optional<std::string> veeam_check;
    std::optional<std::string> token_error;    // the sign-in's GraphError what()
    std::vector<std::string> roles;            // the token's, as issued
    TargetRead mail;
    TargetRead library;
    TargetRead folder;
};
void check_client(const ClientFacts& facts, bool graph_ready, Report& report);

} // namespace rp::doctor
