#include <rp/doctor.hpp>

#include <rp/canonical_json.hpp>
#include <rp/secrets.hpp>
#include <rp/service_log.hpp>

#include "strict_json.hpp"
#include "text_table.hpp"
#include "text_util.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <format>
#include <regex>
#include <utility>

namespace rp::doctor {

namespace {

constexpr std::string_view kAccount = kServiceAccount;
constexpr std::string_view kElevatedAgain = "run rpworker doctor again from an elevated prompt";
constexpr std::string_view kReinstall =
    "rpworker service uninstall, then pwsh -File Install-RestoreProofWorker.ps1";
constexpr std::string_view kTenantCheck = "the client's admin runs Initialize-RestoreProofTenant.ps1 -CheckOnly";
constexpr std::string_view kRegisterAgain =
    "uv run python manage.py revoke-worker on the Cloud, a new install token, rpworker vault "
    "remove cloud_api_token, rpworker vault set cloud_install_token, rpworker cloud register";
constexpr std::string_view kRecreate =
    "re-create the organisation's application certificate in Veeam";

std::string utc_text(std::chrono::system_clock::time_point time)
{
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::floor<std::chrono::seconds>(time));
}

bool contains(const std::vector<std::string>& list, std::string_view value)
{
    return std::find(list.begin(), list.end(), value) != list.end();
}

// Text a server or a file chose, shown only when it is plain: a version or a
// role name.
bool is_plain(std::string_view text, std::size_t max)
{
    static const std::regex plain("[A-Za-z0-9._+-]+");
    return !text.empty() && text.size() <= max && std::regex_match(text.begin(), text.end(), plain);
}

bool is_trusted_owner(std::string_view sid)
{
    return sid == kSidSystem || sid == kSidAdministrators;
}

// Whether one of `wanted`'s rules is for `sid`.
bool names_sid(const WantedAcl& wanted, std::string_view sid)
{
    return std::any_of(wanted.rules.begin(), wanted.rules.end(),
                       [&](const WantedRule& rule) { return rule.sid == sid; });
}

// What an AclDifference amounts to, in words: "lacks *S:(OI)(CI)(M), has an
// entry for S, ...".
std::string difference_text(const AclDifference& d, const WantedAcl& wanted, const Security& s)
{
    std::vector<std::string> parts;
    for (const WantedRule& rule : d.missing) {
        parts.push_back(std::format("lacks *{}:{}({})", rule.sid, wanted.to_children ? "(OI)(CI)" : "",
                                    rule.icacls));
    }
    for (const Ace& ace : d.extra) {
        parts.push_back(std::format("has {} for {}",
                                    !ace.allow                   ? "a Deny entry"
                                    : names_sid(wanted, ace.sid) ? "another entry"
                                                                 : "an entry",
                                    ace.sid));
    }
    if (d.protection_wrong) {
        parts.push_back(wanted.is_protected ? "inherits from its parent"
                                            : "doesn't inherit from its parent");
    }
    if (d.owner_wrong) {
        parts.push_back("is owned by " + s.owner_sid);
    }
    return joined(parts, ", ");
}

// The icacls lines that take the extra entries away, one per SID.
std::vector<std::string> remove_lines(std::string_view path, const std::vector<Ace>& extra)
{
    std::vector<std::string> lines;
    for (const Ace& ace : extra) {
        lines.push_back(std::format("icacls \"{}\" /remove:{} *{}", path, ace.allow ? "g" : "d", ace.sid));
    }
    return lines;
}

bool grants(std::optional<std::uint32_t> access, std::uint32_t needed)
{
    return !access || (*access & needed) == needed;
}

std::string stopped_reason(const ServiceStatus& status, std::string_view log_file)
{
    if (status.win32_exit_code == 1066) {
        switch (status.service_exit_code) {
        case 1:
            return std::format(": the config couldn't be loaded; see {}", log_file);
        case 2:
            return std::format(": the log couldn't be opened; see {}", log_file);
        default:
            return std::format(": service error {}; see {}", status.service_exit_code, log_file);
        }
    }
    if (status.win32_exit_code != 0) {
        return std::format(": Windows error {}; see {}", status.win32_exit_code, log_file);
    }
    return {};
}

std::string_view pending_word(ServiceState state) noexcept
{
    switch (state) {
    case ServiceState::start_pending:
        return "starting";
    case ServiceState::stop_pending:
        return "stopping";
    case ServiceState::continue_pending:
        return "continuing";
    case ServiceState::pause_pending:
        return "pausing";
    case ServiceState::paused:
    case ServiceState::stopped:
    case ServiceState::running:
        break;
    }
    return "paused";
}

std::string trimmed_url(std::string_view url)
{
    while (!url.empty() && url.back() == '/') {
        url.remove_suffix(1);
    }
    return std::string(url);
}

} // namespace

// --- The report ---------------------------------------------------------------

std::string_view to_string(Result result) noexcept
{
    switch (result) {
    case Result::ok:
        return "ok";
    case Result::warning:
        return "warning";
    case Result::problem:
        return "problem";
    case Result::skip:
        break;
    }
    return "skip";
}

std::string line_of(const Check& check)
{
    std::string line = std::format("{}: {}", to_string(check.result), check.text);
    if (check.result == Result::skip) {
        line += std::format(" (needs {})", check.fix);
    } else if (!check.fix.empty()) {
        line += std::format(" (fix: {})", check.fix);
    }
    return line;
}

void Report::ok(std::string id, std::string text)
{
    checks_.push_back({std::move(id), Result::ok, "ok", std::move(text), {}});
}

void Report::warning(std::string id, std::string code, std::string text, std::string fix)
{
    checks_.push_back({std::move(id), Result::warning, std::move(code), std::move(text), std::move(fix)});
}

void Report::problem(std::string id, std::string code, std::string text, std::string fix)
{
    checks_.push_back({std::move(id), Result::problem, std::move(code), std::move(text), std::move(fix)});
}

void Report::skip(std::string id, std::string text, std::string needs)
{
    checks_.push_back({std::move(id), Result::skip, "skip", std::move(text), std::move(needs)});
}

bool Report::failed(std::string_view id) const
{
    return std::any_of(checks_.begin(), checks_.end(), [&](const Check& check) {
        return check.result == Result::problem &&
               (check.id == id || (check.id.size() > id.size() && check.id.starts_with(id) &&
                                   check.id[id.size()] == '.'));
    });
}

int Report::count(Result result) const noexcept
{
    return static_cast<int>(std::count_if(checks_.begin(), checks_.end(),
                                          [&](const Check& check) { return check.result == result; }));
}

std::string Report::summary_line() const
{
    return std::format("doctor: {} ok, {} warning(s), {} problem(s), {} skipped", count(Result::ok),
                       count(Result::warning), count(Result::problem), count(Result::skip));
}

int Report::exit_code() const noexcept
{
    return count(Result::problem) == 0 ? kExitHealthy : kExitProblem;
}

std::string json_text(const Report& report, const JsonFacts& facts)
{
    nlohmann::json checks = nlohmann::json::array();
    for (const Check& check : report.checks()) {
        checks.push_back({{"code", check.code}, {"id", check.id}, {"result", std::string(to_string(check.result))}});
    }
    nlohmann::json doc = {
        {"checks", std::move(checks)},
        {"counts",
         {{"ok", report.count(Result::ok)},
          {"problem", report.count(Result::problem)},
          {"skip", report.count(Result::skip)},
          {"warning", report.count(Result::warning)}}},
        {"elevated", facts.elevated},
        {"format", std::string(kDoctorFormat)},
        {"generated_at", facts.generated_at},
        {"windows_build", facts.windows_build},
        {"worker_version", facts.worker_version}};
    if (!facts.worker_id.empty()) {
        doc["worker_id"] = facts.worker_id;
    }
    if (!facts.key_id.empty()) {
        doc["key_id"] = facts.key_id;
    }
    return canonical_json(doc);
}

// --- ACLs -----------------------------------------------------------------------

std::vector<WantedAcl> wanted_folders(std::string_view service_sid)
{
    const std::string svc(service_sid);
    std::vector<WantedAcl> out;
    out.push_back({"", true, true,
                   {{std::string(kSidSystem), kRightsFull, "F"},
                    {std::string(kSidAdministrators), kRightsFull, "F"},
                    {svc, kRightsReadExecute, "RX"}}});
    for (const char* name : {"state", "runs", "outbox", "sent", "failed", "logs"}) {
        out.push_back({name, false, true, {{svc, kRightsModify, "M"}}});
    }
    return out;
}

WantedAcl wanted_vault(std::string_view service_sid)
{
    return {std::string(kVaultFileName), true, false,
            {{std::string(kSidSystem), kRightsFull, "F"},
             {std::string(kSidAdministrators), kRightsFull, "F"},
             {std::string(kSidOwnerRights), kRightsFull, "F"},
             {std::string(service_sid), kRightsRead, "R"}}};
}

std::optional<std::string> service_sid(std::string_view service_name)
{
    static const std::regex name_rule("[A-Za-z0-9_.-]{1,256}");
    if (!std::regex_match(service_name.begin(), service_name.end(), name_rule)) {
        return std::nullopt;
    }
    std::string utf16;
    for (const char c : service_name) {
        const char upper = c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c;
        utf16.push_back(upper);
        utf16.push_back('\0');
    }
    std::array<unsigned char, 20> digest{};
    unsigned int size = 0;
    EVP_Digest(utf16.data(), utf16.size(), digest.data(), &size, EVP_sha1(), nullptr);
    std::string sid = "S-1-5-80";
    for (std::size_t i = 0; i < 5; ++i) {
        const std::uint32_t part = static_cast<std::uint32_t>(digest[i * 4]) |
                                   static_cast<std::uint32_t>(digest[i * 4 + 1]) << 8 |
                                   static_cast<std::uint32_t>(digest[i * 4 + 2]) << 16 |
                                   static_cast<std::uint32_t>(digest[i * 4 + 3]) << 24;
        sid += std::format("-{}", part);
    }
    return sid;
}

const std::vector<std::string>& service_token_groups()
{
    // Everyone, Users, SERVICE, Authenticated Users, NT SERVICE\ALL SERVICES,
    // LOCAL, This Organization.
    static const std::vector<std::string> groups{"S-1-1-0",    "S-1-5-32-545", "S-1-5-6", "S-1-5-11",
                                                 "S-1-5-80-0", "S-1-2-0",      "S-1-5-15"};
    return groups;
}

AclDifference acl_difference(const Security& security, const WantedAcl& wanted)
{
    AclDifference d;
    const auto is_rule = [&](const Ace& ace, const WantedRule& rule) {
        return !ace.inherited && ace.allow && !ace.inherit_only && ace.sid == rule.sid && ace.mask == rule.mask &&
               ace.to_children == wanted.to_children;
    };
    for (const WantedRule& rule : wanted.rules) {
        const auto found = std::count_if(security.aces.begin(), security.aces.end(),
                                         [&](const Ace& ace) { return is_rule(ace, rule); });
        if (found != 1) {
            d.missing.push_back(rule);
        }
    }
    for (const Ace& ace : security.aces) {
        // An Allow for a wanted SID is extra unless it is that SID's rule
        // exactly: a broader one (Modify where Read is wanted) is a right the
        // account mustn't have, whatever exact entry stands beside it.
        const bool a_rule = std::any_of(wanted.rules.begin(), wanted.rules.end(),
                                        [&](const WantedRule& rule) { return is_rule(ace, rule); });
        const bool unwanted = !ace.inherited && (!ace.allow || !a_rule);
        const bool listed = std::any_of(d.extra.begin(), d.extra.end(), [&](const Ace& e) {
            return e.allow == ace.allow && e.sid == ace.sid;
        });
        if (unwanted && !listed) {
            d.extra.push_back(ace);
        }
    }
    d.protection_wrong = security.is_protected != wanted.is_protected;
    d.owner_wrong = !is_trusted_owner(security.owner_sid);
    return d;
}

std::vector<std::string> unexpected_writers(const Security& security)
{
    std::vector<std::string> out;
    for (const Ace& ace : security.aces) {
        if (ace.allow && !ace.inherit_only && (ace.mask & kWriteBits) != 0 &&
            !is_trusted_owner(ace.sid) && ace.sid != kSidTrustedInstaller && !contains(out, ace.sid)) {
            out.push_back(ace.sid);
        }
    }
    return out;
}

// --- 1. doctor -----------------------------------------------------------------

std::string exe_of_command_line(std::string_view command_line)
{
    if (command_line.starts_with('"')) {
        const std::size_t end = command_line.find('"', 1);
        return std::string(command_line.substr(1, end == std::string_view::npos ? end : end - 1));
    }
    return std::string(command_line.substr(0, command_line.find(' ')));
}

bool check_doctor(const MachineFacts& facts, Report& report)
{
    if (!facts.elevated) {
        report.problem("doctor.elevated", "not_elevated", "doctor: not run from an elevated prompt",
                       "open PowerShell as Administrator and run rpworker doctor again");
        return false;
    }
    report.ok("doctor.elevated", std::format("doctor: rpworker {}, {}, elevated", facts.version, facts.exe));
    if (facts.service_exe && !ascii_iequals(*facts.service_exe, facts.exe)) {
        report.warning("doctor.exe", "other_exe",
                       std::format("doctor: the service runs {}, not this exe; these answers are "
                                   "this exe's",
                                   *facts.service_exe),
                       std::format("run {} doctor", *facts.service_exe));
    }
    return true;
}

// --- 2. config -----------------------------------------------------------------

bool check_config(const ConfigFacts& facts, Report& report)
{
    const std::string fix = std::format("read it, then {} -Replace", kInstallerFix);
    if (facts.owner == OwnerTrust::not_trusted) {
        report.problem("config.file", "untrusted_owner",
                       std::format("config: {} is owned by an account other than SYSTEM or "
                                   "Administrators: someone else may have written it",
                                   facts.file),
                       fix);
    } else if (facts.owner == OwnerTrust::unreadable) {
        report.problem("config.file", "unreadable",
                       std::format("config: {}: its owner can't be read", facts.file), fix);
    } else if (facts.owner == OwnerTrust::trusted && facts.explicit_entries) {
        report.problem("config.file", "own_entries",
                       std::format("config: {} has entries of its own beside the folder's", facts.file),
                       fix);
    } else if (facts.owner == OwnerTrust::trusted) {
        report.ok("config.file", std::format("config: {}, owned by SYSTEM or Administrators, the "
                                             "folder's entries alone",
                                             facts.file));
    }
    if (facts.load_error) {
        report.problem("config.load", "config_invalid", "config: " + *facts.load_error,
                       std::format("{} -Replace", kInstallerFix));
        return false;
    }
    report.ok("config.load", std::format("config: {} loads", facts.file));
    if (facts.jobs_file_set) {
        report.warning("config.jobs_file", "jobs_file",
                       "config: jobs_file is set: the service reads its jobs from that file, not "
                       "the Cloud",
                       std::format("remove jobs_file from {}; it is a lab's key", facts.file));
    }
    if (facts.client_keys_set) {
        report.ok("config.client_keys", "config: the eight client keys are set; the service "
                                        "doesn't read them (each job carries its client)");
    }
    return true;
}

// --- 3. folders, outbox, disk, log ---------------------------------------------------

void check_folders(const std::vector<WantedAcl>& wanted, const std::vector<FolderFacts>& facts,
                   Report& report)
{
    for (std::size_t i = 0; i < wanted.size() && i < facts.size(); ++i) {
        const WantedAcl& want = wanted[i];
        const FolderFacts& fact = facts[i];
        const std::string id = "folders." + (want.path.empty() ? std::string("root") : want.path);
        if (!fact.security.present) {
            report.problem(id, "missing", std::format("folders: {} is not there", fact.path),
                           std::string(kInstallerFix));
            continue;
        }
        if (!fact.security.readable) {
            report.problem(id, "unreadable", std::format("folders: {}: its security can't be read", fact.path),
                           std::string(kInstallerFix));
            continue;
        }
        const AclDifference d = acl_difference(fact.security, want);
        if (!d.ok()) {
            // icacls removes a SID's entries whole, so an extra one for a
            // wanted SID takes its rule with it: the installer sets both.
            const bool only_extra =
                d.missing.empty() && !d.protection_wrong && !d.owner_wrong &&
                std::none_of(d.extra.begin(), d.extra.end(), [&](const Ace& ace) { return names_sid(want, ace.sid); });
            report.problem(id, "acl",
                           std::format("folders: {}: {}", fact.path, difference_text(d, want, fact.security)),
                           only_extra ? joined(remove_lines(fact.path, d.extra), "; ")
                                      : std::string(kInstallerFix));
            continue;
        }
        const bool root = want.path.empty();
        if (!grants(fact.service_access, root ? kRightsReadExecute : kRightsModify)) {
            report.problem(id, "service_access",
                           std::format("folders: {}: {} can't {} it, by Windows' own check", fact.path,
                                       kAccount, root ? "read" : "change"),
                           std::string(kInstallerFix));
            continue;
        }
        report.ok(id, std::format("folders: {}: as the installer sets it", fact.path));
    }
}

void check_outbox(const OutboxFacts& facts, Report& report)
{
    if (!facts.failed_listable) {
        report.problem("outbox.failed", "unlistable",
                       std::format("outbox: {} can't be listed, so nothing is uploaded until it can",
                                   facts.failed_path),
                       std::format("remove what is at {} if it is a file, then {}", facts.failed_path,
                                   kInstallerFix));
    }
    report.ok("outbox.counts", std::format("outbox: {} queued, {} sent, {} failed", facts.queued,
                                           facts.sent, facts.failed));
    if (facts.oldest_queued_age && *facts.oldest_queued_age > kQueuedTooLong) {
        report.warning("outbox.oldest", "queued_too_long",
                       std::format("outbox: the oldest queued run is {} h old",
                                   std::chrono::floor<std::chrono::hours>(*facts.oldest_queued_age).count()),
                       "rpworker outbox list; rpworker outbox flush says why each run stays");
    }
    if (facts.failed > 0) {
        report.warning("outbox.failed_runs", "failed_runs",
                       std::format("outbox: {} run(s) the Cloud refused for good are in failed\\",
                                   facts.failed),
                       "rpworker outbox list");
    }
}

void check_disk(const DiskFacts& facts, Report& report)
{
    if (!facts.free_bytes) {
        report.problem("disk.free", "unreadable",
                       std::format("disk: the free space of {}'s volume can't be read", facts.path),
                       "run rpworker doctor again");
        return;
    }
    const std::string text = std::format("disk: {:.1f} GiB free on {}'s volume",
                                         static_cast<double>(*facts.free_bytes) / double(1u << 30), facts.path);
    const std::string fix = "free space on that volume; a run folder takes up to 200 MiB";
    if (*facts.free_bytes < kDiskProblemBytes) {
        report.problem("disk.free", "low", text, fix);
    } else if (*facts.free_bytes < kDiskWarningBytes) {
        report.warning("disk.free", "low", text, fix);
    } else {
        report.ok("disk.free", text);
    }
}

void check_log(const LogFacts& facts, Report& report)
{
    if (!facts.live_bytes) {
        report.ok("log.size", std::format("log: {} not written yet", facts.path));
        return;
    }
    constexpr std::uint64_t MiB = 1024 * 1024;
    const LogLimits limits;
    const std::string sizes = std::format("{} MiB, {} MiB with the rotated files", *facts.live_bytes / MiB,
                                          facts.set_bytes / MiB);
    if (*facts.live_bytes > limits.max_bytes || facts.set_bytes > limits.max_bytes * limits.files) {
        report.warning("log.size", "rotation_stuck",
                       std::format("log: {} is {}: a reader holds it, so it doesn't rotate", facts.path, sizes),
                       std::format("close what has {} open: a viewer, a tail", facts.path));
        return;
    }
    report.ok("log.size", std::format("log: {} {}", facts.path, sizes));
}

// --- 4. vault ------------------------------------------------------------------

bool check_vault(const VaultFacts& facts, Report& report)
{
    const std::string grant = std::format("rpworker vault grant \"{}\"", kAccount);
    if (facts.security.present && !facts.security.readable) {
        report.problem("vault.acl", "unreadable", std::format("vault: {}: its security can't be read", facts.path),
                       std::string(kInstallerFix));
        report.skip("vault.service_read", std::format("vault: {}'s read, by Windows' own check", kAccount),
                    "vault.acl");
    } else if (facts.security.present) {
        const WantedAcl want = wanted_vault(facts.service_sid);
        const AclDifference d = acl_difference(facts.security, want);
        const bool service_alone = d.extra.empty() && !d.protection_wrong && !d.owner_wrong &&
                                   d.missing.size() == 1 && d.missing[0].sid == facts.service_sid;
        if (service_alone) {
            report.problem("vault.acl", "no_service_read",
                           std::format("vault: {}: {} can't read it", facts.path, kAccount), grant);
        } else if (!d.ok()) {
            std::vector<std::string> fixes;
            if (d.protection_wrong) {
                fixes.push_back(std::format("icacls \"{}\" /inheritance:r", facts.path));
            }
            if (d.owner_wrong) {
                fixes.push_back(std::format("icacls \"{}\" /setowner *{}", facts.path, kSidAdministrators));
            }
            // The removals first: icacls takes a SID's entries away whole, so
            // a wanted SID's rule is granted again after its other entry goes.
            for (const std::string& line : remove_lines(facts.path, d.extra)) {
                fixes.push_back(line);
            }
            for (const WantedRule& rule : want.rules) {
                const bool missing = std::any_of(d.missing.begin(), d.missing.end(),
                                                 [&](const WantedRule& m) { return m.sid == rule.sid; });
                const bool removed = std::any_of(d.extra.begin(), d.extra.end(),
                                                 [&](const Ace& ace) { return ace.allow && ace.sid == rule.sid; });
                if (missing || removed) {
                    fixes.push_back(
                        std::format("icacls \"{}\" /grant \"*{}:({})\"", facts.path, rule.sid, rule.icacls));
                }
            }
            report.problem("vault.acl", "acl",
                           std::format("vault: {}: {}", facts.path, difference_text(d, want, facts.security)),
                           joined(fixes, "; "));
        } else {
            std::vector<std::string> names;
            for (const Ace& ace : facts.security.aces) {
                const auto named = std::find_if(facts.account_names.begin(), facts.account_names.end(),
                                                [&](const auto& pair) { return pair.first == ace.sid; });
                const std::string name = named == facts.account_names.end() ? ace.sid : named->second;
                if (!contains(names, name)) {
                    names.push_back(name);
                }
            }
            report.ok("vault.acl", std::format("vault: {}: entries for {}, nothing else", facts.path,
                                               joined(names, ", ")));
        }
        if (!d.ok()) {
            report.skip("vault.service_read", std::format("vault: {}'s read, by Windows' own check", kAccount),
                        "vault.acl");
        } else if (!grants(facts.service_access, kRightsRead)) {
            report.problem("vault.service_read", "no_service_read",
                           std::format("vault: {} can't read it, by Windows' own check", kAccount), grant);
        } else {
            report.ok("vault.service_read", std::format("vault: {} can read it, by Windows' own check", kAccount));
        }
    }
    if (facts.read_error) {
        report.problem("vault.read", "unreadable", "vault: " + *facts.read_error, std::string(kInstallerFix));
        return false;
    }
    report.ok("vault.read", std::format("vault: {} decrypts on this machine", facts.path));
    std::vector<std::string> held;
    for (const std::string_view name : kSecretNames) {
        if (contains(facts.names, name)) {
            held.emplace_back(name);
        }
    }
    report.ok("vault.names", "vault: holds " + (held.empty() ? std::string("nothing") : joined(held, ", ")));
    const auto has = [&](std::string_view name) { return contains(facts.names, name); };
    for (const std::string_view name : {kNameVeeamUsername, kNameVeeamPassword}) {
        if (!has(name)) {
            report.problem(std::format("vault.{}", name), "missing",
                           std::format("vault: {} is not in it", name),
                           std::format("rpworker vault set {}", name));
        }
    }
    const bool pfx = has(kNameGraphCertPfxBase64);
    const bool password = has(kNameGraphCertPassword);
    const std::string script =
        std::format("pwsh -File New-WorkerGraphCertificate.ps1 -Worker \"{}\"", facts.exe);
    if (!pfx && !password) {
        report.problem("vault.graph_certificate", "missing",
                       std::format("vault: no Graph certificate ({}, {})", kNameGraphCertPfxBase64,
                                   kNameGraphCertPassword),
                       script);
    } else if (pfx != password) {
        report.problem("vault.graph_certificate", "half",
                       std::format("vault: half a Graph certificate ({} without {})",
                                   pfx ? kNameGraphCertPfxBase64 : kNameGraphCertPassword,
                                   pfx ? kNameGraphCertPassword : kNameGraphCertPfxBase64),
                       script + " -Replace");
    }
    if (!has(kNameSigningKeyBase64)) {
        report.problem("vault.signing_key_base64", "missing",
                       std::format("vault: {} is not in it", kNameSigningKeyBase64), "rpworker signer new-key");
    }
    const bool install = has(kNameCloudInstallToken);
    if (!has(kNameCloudApiToken)) {
        report.problem("vault.cloud_api_token", "not_registered",
                       std::format("vault: {} is not in it: this Worker isn't registered", kNameCloudApiToken),
                       install ? std::string("rpworker cloud register")
                               : std::string("uv run python manage.py create-worker-token on the Cloud, "
                                             "rpworker vault set cloud_install_token, then rpworker "
                                             "cloud register"));
    } else if (install) {
        report.warning("vault.cloud_install_token", "leftover_install_token",
                       std::format("vault: {} is still there beside {}", kNameCloudInstallToken,
                                   kNameCloudApiToken),
                       std::format("rpworker vault remove {}", kNameCloudInstallToken));
    }
    return true;
}

// --- 5. the signing key ----------------------------------------------------------

void check_signing_key(const SigningFacts& signing, const RecordFacts& record, Report& report)
{
    if (!signing.in_vault) {
        report.skip("signing.key", "signing key: its key_id", "vault.signing_key_base64");
        return;
    }
    if (!signing.key_id) {
        report.problem("signing.key", "not_a_key", "signing key: signing_key_base64 is not an Ed25519 key",
                       std::format("rpworker signer new-key --replace, then register again: {}", kRegisterAgain));
        return;
    }
    report.ok("signing.key", "signing key: key_id " + *signing.key_id);
    if (!record.present || !record.record) {
        return;
    }
    if (record.record->key_id != *signing.key_id) {
        report.problem("signing.registered", "key_mismatch",
                       std::format("signing key: key_id {} is not the one the Cloud registered ({})",
                                   *signing.key_id, record.record->key_id),
                       std::string(kRegisterAgain));
        return;
    }
    report.ok("signing.registered", "signing key: the one registered as worker " + record.record->worker_id);
}

// --- 6. service ----------------------------------------------------------------

void check_service(const ServiceFacts& facts, Report& report)
{
    if (facts.read.error == 1060 && facts.read.step == ScmStep::service) {
        report.problem("service.installed", "not_installed",
                       std::format("service: {} is not installed", kServiceName), std::string(kInstallerFix));
        return;
    }
    if (facts.read.error != 0) {
        report.problem("service.installed", "unreadable",
                       std::format("service: its configuration can't be read (error {})", facts.read.error),
                       std::string(kElevatedAgain));
        return;
    }
    const ServiceSetup& setup = facts.setup;
    if (ascii_iequals(setup.account, kAccount)) {
        report.ok("service.account", std::format("service: {} runs as {}", kServiceName, kAccount));
    } else {
        report.problem("service.account", "account",
                       std::format("service: {} runs as {}, not {}", kServiceName, table_cell(setup.account), kAccount),
                       std::string(kReinstall));
    }
    if (setup.start_type == ServiceStartType::automatic) {
        report.ok("service.start_type", "service: starts automatically");
    } else {
        report.problem("service.start_type", "start_type",
                       setup.start_type == ServiceStartType::manual
                           ? "service: starts by hand, not automatically"
                           : "service: is disabled, not started automatically",
                       std::format("sc.exe config {} start= auto", kServiceName));
    }
    const std::string exe = exe_of_command_line(setup.command_line);
    const std::string_view rest =
        std::string_view(setup.command_line).substr(std::min(setup.command_line.size(),
                                                             exe.size() + (setup.command_line.starts_with('"') ? 2 : 0)));
    const bool command_ok = ascii_iequals(exe, facts.expected_exe) &&
                            (rest == " service run" || rest.starts_with(" service run --config "));
    if (command_ok) {
        report.ok("service.command_line", "service: runs " + table_cell(setup.command_line));
    } else {
        report.problem("service.command_line", "command_line",
                       std::format("service: runs {}, not {}", table_cell(setup.command_line), facts.expected_exe),
                       std::string(kReinstall));
    }
    const ServiceSetup wanted = service_setup(kServiceName, "");
    if (setup.failure_actions == wanted.failure_actions && setup.reset_period_s == wanted.reset_period_s) {
        report.ok("service.recovery", "service: restarts after 60 s three times, then nothing");
    } else {
        report.problem("service.recovery", "recovery",
                       "service: its recovery actions aren't restart after 60 s three times, then "
                       "nothing (services.msc's Recovery tab saves three and drops the fourth)",
                       std::string(kReinstall));
    }
    if (facts.query.error != 0) {
        report.problem("service.state", "unreadable",
                       std::format("service: its state can't be read (error {})", facts.query.error),
                       std::string(kElevatedAgain));
    } else if (facts.status.state == ServiceState::running) {
        report.ok("service.state", "service: running");
    } else if (facts.status.state == ServiceState::stopped) {
        report.problem("service.state", "stopped",
                       "service: stopped" + stopped_reason(facts.status, facts.log_file),
                       "rpworker service start");
    } else {
        report.warning("service.state", "pending", std::format("service: {}", pending_word(facts.status.state)));
    }
    const std::string where = "in secpol.msc, or in the domain's policy if one sets it";
    if (!facts.logon.allowed) {
        report.problem("service.logon_right", "unreadable", "service: the logon rights can't be read",
                       std::string(kElevatedAgain));
    } else {
        std::vector<std::string> token{facts.service_sid};
        token.insert(token.end(), service_token_groups().begin(), service_token_groups().end());
        const auto denied = std::find_if(token.begin(), token.end(),
                                         [&](const std::string& sid) { return contains(facts.logon.denied, sid); });
        const bool allowed = std::any_of(token.begin(), token.end(),
                                         [&](const std::string& sid) { return contains(*facts.logon.allowed, sid); });
        if (denied != token.end()) {
            report.problem("service.logon_right", "denied",
                           std::format("service: a policy denies {} \"Log on as a service\"", kAccount),
                           std::format("take {} out of \"Deny log on as a service\" {}", *denied, where));
        } else if (!allowed) {
            report.problem("service.logon_right", "not_granted",
                           std::format("service: neither {} nor NT SERVICE\\ALL SERVICES may \"Log on as a "
                                       "service\"",
                                       kAccount),
                           std::format("add NT SERVICE\\ALL SERVICES to \"Log on as a service\" {}", where));
        } else {
            report.ok("service.logon_right", std::format("service: {} may log on as a service", kAccount));
        }
    }
    if (!facts.exe_security.present) {
        report.problem("service.exe_access", "missing", std::format("service: {} is not there", facts.expected_exe),
                       std::string(kInstallerFix));
    } else if (!facts.exe_security.readable) {
        report.problem("service.exe_access", "unreadable",
                       std::format("service: {}: its security can't be read", facts.expected_exe),
                       std::string(kElevatedAgain));
    } else {
        const bool runs = grants(facts.exe_access, kRightsReadExecute);
        const std::vector<std::string> writers = unexpected_writers(facts.exe_security);
        if (!runs) {
            report.problem("service.exe_access", "service_access",
                           std::format("service: {} can't read and run {}, by Windows' own check", kAccount,
                                       facts.expected_exe),
                           std::string(kInstallerFix));
        }
        if (!writers.empty()) {
            report.problem("service.exe_writers", "writable",
                           std::format("service: {} can be changed by {}, and the service runs it as {}",
                                       facts.expected_exe, joined(writers, ", "), kAccount),
                           std::format("install it under %ProgramFiles%\\RestoreProof with {}", kInstallerFix));
        }
        if (runs && writers.empty()) {
            report.ok("service.exe", std::format("service: {} can read and run {}, and only SYSTEM, "
                                                 "Administrators and TrustedInstaller can change it",
                                                 kAccount, facts.expected_exe));
        }
    }
    if (!facts.running.present) {
        report.ok("service.run", "service: no run in progress");
    } else if (facts.running.run_id.empty()) {
        report.warning("service.run", "run_unreadable",
                       "service: state\\running.json is there and can't be read, so how long its run has "
                       "been in progress is unknown; a restore target may hold its items",
                       std::format("read {}", facts.log_file));
    } else if (facts.running.age >= kHeldRunAfter) {
        report.problem("service.run", "held_run",
                       std::format("service: run {} has been in progress for {} h", facts.running.run_id,
                                   std::chrono::floor<std::chrono::hours>(facts.running.age).count()),
                       std::format("read {}; rpworker service stop ends it as interrupted", facts.log_file));
    } else {
        report.warning("service.run", "run_in_progress",
                       std::format("service: run {} in progress for {} min; a restore target may hold its "
                                   "items",
                                   facts.running.run_id,
                                   std::chrono::floor<std::chrono::minutes>(facts.running.age).count()));
    }
}

// --- 7. cloud ------------------------------------------------------------------

void check_cloud(const CloudFacts& facts, Report& report)
{
    const std::string register_fix = "rpworker cloud register";
    if (!facts.record.present) {
        report.problem("cloud.registration", "not_registered",
                       "cloud: this Worker isn't registered: state\\worker.json is not there", register_fix);
    } else if (!facts.record.record) {
        report.problem("cloud.registration", "unreadable", "cloud: state\\worker.json can't be read", register_fix);
    } else {
        const WorkerRecord& record = *facts.record.record;
        report.ok("cloud.registration", std::format("cloud: worker {}, registered {} with {}", record.worker_id,
                                                    record.registered_at, record.cloud_url));
        if (!ascii_iequals(trimmed_url(record.cloud_url), trimmed_url(facts.cloud_url))) {
            report.problem("cloud.url", "other_cloud",
                           std::format("cloud: registered with {}, but config.json names {}", record.cloud_url,
                                       facts.cloud_url),
                           "to move: rpworker vault remove cloud_api_token, a new install token from the "
                           "new Cloud, rpworker vault set cloud_install_token, rpworker cloud register");
        }
    }
    const std::string url = trimmed_url(facts.cloud_url) + "/v1/version";
    const std::string fix = "check cloud_url, the network and cloud_ca_file";
    const VersionAnswer& answer = facts.version;
    if (!answer.answered) {
        report.problem("cloud.version", "no_answer", std::format("cloud: {}: {}", url, answer.failure), fix);
        return;
    }
    if (answer.status < 200 || answer.status > 299) {
        report.problem("cloud.version", "http_status", std::format("cloud: {}: HTTP {}", url, answer.status), fix);
        return;
    }
    if (answer.kind != CloudAnswerKind::cloud) {
        report.problem("cloud.version", "not_cloud", "cloud: not a RestoreProof Cloud", fix);
        return;
    }
    const std::optional<nlohmann::json> body = parse_strict_json(answer.body);
    if (!body || !body->is_object() || !body->contains("api") || !body->contains("version") ||
        !(*body)["api"].is_number_integer() || !(*body)["version"].is_string()) {
        report.problem("cloud.version", "bad_body", "cloud: the answer is no version document", fix);
        return;
    }
    const auto api = (*body)["api"].get<std::int64_t>();
    if (api != 1) {
        report.problem("cloud.version", "other_api",
                       std::format("cloud: the Cloud speaks API {}, this Worker API 1", api),
                       "an upgrade of this Worker");
        return;
    }
    const std::string version = (*body)["version"].get<std::string>();
    report.ok("cloud.version", std::format("cloud: RestoreProof Cloud {}, API 1",
                                           is_plain(version, 64) ? version
                                                                 : "(a version this Worker doesn't show)"));
}

// --- 8. tsa and clock ------------------------------------------------------------

void check_tsa(const TsaFacts& facts, Report& report)
{
    if (!facts.stamped) {
        report.problem("tsa.token", facts.error, std::format("tsa: {}: no token ({})", facts.url, facts.error),
                       "check tsa_url and the network to it");
        report.skip("clock.skew", "clock: against the TSA's time", "tsa.token");
        return;
    }
    report.ok("tsa.token", std::format("tsa: {} answered, token verified", facts.url));
    const std::int64_t skew = std::llabs(facts.gen_time - facts.now);
    if (skew > kClockSkewLimit.count()) {
        report.problem("clock.skew", "skew",
                       std::format("clock: {} s from the TSA's time, over {} s", skew, kClockSkewLimit.count()),
                       "set this machine's time source; w32tm /resync");
        return;
    }
    report.ok("clock.skew", std::format("clock: {} s from the TSA's time", skew));
}

// --- 9. veeam ------------------------------------------------------------------

std::string key_file_grant(std::string_view key_file, std::string_view sid)
{
    return std::format("icacls \"{}\" /grant \"*{}:(R)\"", key_file, sid);
}

namespace {

void check_certificate(const VeeamFacts& facts, const std::string& org, const std::string& id,
                       const CertificateFacts& cert, Report& report)
{
    const std::string who = std::format("veeam: {}: certificate {}", org, cert.thumbprint);
    bool key_file_skipped = false;
    if (cert.export_failure) {
        std::string code;
        std::string text;
        std::string fix;
        switch (*cert.export_failure) {
        case CertExportFailure::not_found:
            code = "not_found";
            text = who + " is not in LocalMachine\\My on this machine";
            fix = "the Worker runs on the Veeam server; in Veeam, check the organisation's application "
                  "certificate";
            key_file_skipped = true;
            break;
        case CertExportFailure::expired:
            code = "expired";
            text = who + " has expired";
            fix = "renew it in Veeam's organisation settings, then run rpworker doctor for the key file's line";
            break;
        case CertExportFailure::not_yet_valid:
            code = "not_yet_valid";
            text = who + " is not valid yet";
            fix = "check this machine's clock and the certificate in Veeam";
            break;
        case CertExportFailure::not_exportable:
            code = "not_exportable";
            text = who + "'s private key isn't exportable";
            fix = std::format("Veeam made it so; {}", kRecreate);
            break;
        case CertExportFailure::no_private_key:
            code = "no_private_key";
            text = who + " has no private key on this machine";
            fix = std::string(kRecreate);
            key_file_skipped = true;
            break;
        case CertExportFailure::key_unopenable:
            code = "key_unopenable";
            text = std::format("{}'s private key can't be opened, even elevated ({})", who, cert.export_message);
            fix = std::string(kRecreate);
            break;
        case CertExportFailure::other:
        case CertExportFailure::malformed_thumbprint:
            code = "export_failed";
            text = std::format("{} can't be exported ({})", who, cert.export_message);
            fix = "run rpworker doctor again; the words in brackets are Windows'";
            break;
        }
        report.problem(id + ".export", code, text, fix);
        // A key this account can't open is a key file it can't name either
        // (its name is read through the key): one cause, one line.
        if (*cert.export_failure == CertExportFailure::key_unopenable && !cert.key_file) {
            key_file_skipped = true;
        }
    } else {
        report.ok(id + ".export", who + " exports (in memory, discarded)" +
                                      (cert.not_after ? ", valid to " + utc_text(*cert.not_after) : ""));
    }
    if (cert.not_after && *cert.not_after > facts.now && *cert.not_after - facts.now < kCertificateWarning) {
        report.warning(id + ".expiry", "expires_soon", who + " ends " + utc_text(*cert.not_after),
                       "renew it in Veeam before then, then run rpworker doctor for the key file's line");
    }
    if (key_file_skipped) {
        report.skip(id + ".key_file", std::format("veeam: {}: the key file of certificate {}", org, cert.thumbprint),
                    id + ".export");
        return;
    }
    if (!cert.key_file) {
        report.problem(id + ".key_file", "no_key_file",
                       std::format("veeam: {}: no key file of certificate {} under %ProgramData%\\Microsoft\\Crypto",
                                   org, cert.thumbprint),
                       std::string(kRecreate));
        return;
    }
    if (!grants(cert.service_access, kRightsRead)) {
        report.problem(id + ".key_file", "missing_ace",
                       std::format("veeam: {}: {} can't read the key file of certificate {}", org, kAccount,
                                   cert.thumbprint),
                       key_file_grant(*cert.key_file, facts.service_sid));
        return;
    }
    report.ok(id + ".key_file", std::format("veeam: {}: {} can read the key file {}", org, kAccount, *cert.key_file));
}

} // namespace

void check_veeam(const VeeamFacts& facts, Report& report)
{
    if (facts.url_local) {
        report.ok("veeam.local", std::format("veeam: {} is this machine", facts.url));
        const std::string rest = std::format("veeam: {}", kVeeamRestService);
        if (facts.rest_query.error == 1060 && facts.rest_query.step == ScmStep::service) {
            report.problem("veeam.rest_service", "not_installed", rest + " is not installed here",
                           "run the Worker on the Veeam server");
        } else if (facts.rest_query.error != 0) {
            report.problem("veeam.rest_service", "unreadable",
                           std::format("{}'s state can't be read (error {})", rest, facts.rest_query.error),
                           std::string(kElevatedAgain));
        } else if (facts.rest_status.state == ServiceState::running) {
            report.ok("veeam.rest_service", rest + " is running");
        } else {
            report.problem("veeam.rest_service", "not_running", rest + " is not running",
                           std::format("Start-Service {}", kVeeamRestService));
        }
    } else {
        report.problem("veeam.local", "remote",
                       std::format("veeam: {} is not this machine: the organisation certificates are in "
                                   "the Veeam server's store",
                                   facts.url),
                       "run the Worker on the Veeam server");
        report.skip("veeam.rest_service", std::format("veeam: {}", kVeeamRestService), "veeam.local");
    }
    if (facts.login_needs) {
        report.skip("veeam.login", "veeam: the login, the organisations and their certificates", *facts.login_needs);
        return;
    }
    if (facts.login_error) {
        report.problem("veeam.login", "login", *facts.login_error,
                       "check veeam_username and veeam_password (rpworker vault set), the account's role "
                       "in Veeam's console, and veeam_ca_file and veeam_cert_sha256");
        report.skip("veeam.organisations", "veeam: the organisations and their certificates", "veeam.login");
        return;
    }
    report.ok("veeam.login", "veeam: signed in");
    if (facts.organisations.empty()) {
        report.problem("veeam.organisations", "none", "veeam: no organisation",
                       "add the client's organisation in Veeam's console");
        return;
    }
    for (std::size_t i = 0; i < facts.organisations.size(); ++i) {
        const OrganisationFacts& org = facts.organisations[i];
        const std::string id = std::format("veeam.org[{}]", i + 1);
        const std::string name = table_cell(org.name);
        if (!org.id_ok) {
            report.problem(id, "bad_id", std::format("veeam: {}: Veeam's ID for it isn't a UUID", name),
                           "check that veeam_url is Veeam Backup for Microsoft 365's REST API, v8");
            continue;
        }
        report.ok(id, std::format("veeam: {}: {}", name,
                                  org.newest_point ? "newest restore point " + table_cell(*org.newest_point)
                                                   : std::string("no restore point yet")));
        if (org.certificates.empty()) {
            report.problem(id + ".certificate", "no_app",
                           std::format("veeam: {}: Veeam reports no application certificate", name),
                           "set the organisation's application in Veeam's console");
            continue;
        }
        for (std::size_t j = 0; j < org.certificates.size(); ++j) {
            check_certificate(facts, name, std::format("{}.cert[{}]", id, j + 1), org.certificates[j], report);
        }
    }
}

// --- 10. graph -----------------------------------------------------------------

bool check_graph(const GraphFacts& facts, Report& report)
{
    const std::string script =
        std::format("pwsh -File New-WorkerGraphCertificate.ps1 -Worker \"{}\" -Replace", facts.exe);
    if (facts.certificate_error) {
        report.problem("graph.certificate", "certificate", "graph: " + *facts.certificate_error, script);
        return false;
    }
    report.ok("graph.certificate", std::format("graph: the Worker's certificate {}, valid to {}", facts.thumbprint,
                                               utc_text(facts.not_after)));
    if (facts.not_after - facts.now < kCertificateWarning) {
        report.warning("graph.certificate_expiry", "expires_soon",
                       std::format("graph: the Worker's certificate ends in {} day(s)",
                                   std::chrono::floor<std::chrono::days>(facts.not_after - facts.now).count()),
                       script + ", then give each client's admin its public half: rpworker graph certificate");
    }
    if (facts.clients_named) {
        return true;
    }
    for (std::size_t i = 0; i < facts.reach.size(); ++i) {
        const auto& [host, failure] = facts.reach[i];
        const std::string id = std::format("graph.reach[{}]", i + 1);
        if (failure.empty()) {
            report.ok(id, std::format("graph: {} reached", host));
        } else {
            report.problem(id, "unreachable", std::format("graph: {}: {}", host, failure),
                           std::format("check the network and any proxy to {}", host));
        }
    }
    report.skip("graph.clients", "graph: no client named", "--client <profile file>");
    return true;
}

// --- 11. a client -----------------------------------------------------------------

const std::vector<std::string_view>& wanted_roles()
{
    static const std::vector<std::string_view> roles{kRoleFiles, kRoleLists, kRoleSites};
    return roles;
}

void check_client(const ClientFacts& facts, bool graph_ready, Report& report)
{
    const std::string p = std::format("client[{}]", facts.number);
    const std::string c = std::format("client {}: ", facts.number);
    if (facts.profile_error) {
        report.problem(p + ".profile", "profile", c + *facts.profile_error,
                       "give the profile file Initialize-RestoreProofTenant.ps1 printed for this client");
        return;
    }
    const ClientProfile& profile = facts.profile;
    const std::string org = table_cell(profile.veeam_org_name);
    report.ok(p + ".profile", std::format("{}{}, tenant {}, app {}", c, org, profile.graph_tenant_id,
                                          profile.graph_client_id));
    if (!facts.veeam_check) {
        report.skip(p + ".veeam", c + "Veeam's organisation against the tenant", "veeam.login");
    } else if (facts.veeam_check->empty()) {
        report.ok(p + ".veeam", std::format("{}Veeam's organisation {} is this tenant's", c, org));
    } else {
        report.problem(p + ".veeam", "client_mismatch", c + *facts.veeam_check,
                       "the profile's veeam_org_name must name this tenant's organisation in Veeam");
    }
    const std::string mailbox = std::format("{}graph: {}'s Inbox", c, table_cell(profile.test_mailbox));
    const std::string library = c + "graph: the RestoreTarget library";
    const std::string folder = c + "graph: the OneDrive RestoreTarget folder";
    const std::string write = c + "graph: the write grants on the RestoreTarget list and folder";
    const std::string write_needs = "a role the app must never hold; the next run's clean shows them";
    if (!graph_ready) {
        report.skip(p + ".graph.token", c + "graph: the app's token and the three targets", "graph.certificate");
        return;
    }
    if (facts.token_error) {
        report.problem(p + ".graph.token", "sign_in", c + *facts.token_error,
                       std::format("{}: the app, its certificate, its consent", kTenantCheck));
        const std::string needs = p + ".graph.token";
        report.skip(p + ".graph.mail", mailbox, needs);
        report.skip(p + ".graph.library", library, needs);
        report.skip(p + ".graph.folder", folder, needs);
        report.skip(p + ".graph.write", write, write_needs);
        return;
    }
    const auto has = [&](std::string_view role) { return contains(facts.roles, role); };
    for (const std::string_view role : wanted_roles()) {
        const std::string id = std::format("{}.graph.role.{}", p, role);
        if (has(role)) {
            report.ok(id, std::format("{}graph: the app's token carries {}", c, role));
        } else {
            report.problem(id, "role_missing", std::format("{}graph: the app's token lacks {}", c, role),
                           std::format("the client's admin runs Initialize-RestoreProofTenant.ps1 -TenantId {} "
                                       "-SiteUrl <...> -OneDriveUser <...> -WorkerCertificateFile <...> "
                                       "-ProfileFile <...>, which consents it again",
                                       profile.graph_tenant_id));
        }
    }
    int extra = 0;
    for (const std::string& role : facts.roles) {
        if (std::find(wanted_roles().begin(), wanted_roles().end(), role) != wanted_roles().end()) {
            continue;
        }
        report.problem(std::format("{}.graph.role_extra[{}]", p, ++extra), "role_extra",
                       std::format("{}graph: the app's token carries {}, which it must never hold", c,
                                   is_plain(role, 128) ? role : "a role this Worker doesn't show"),
                       "the client's admin runs Initialize-RestoreProofTenant.ps1, which removes it");
    }
    const std::string read_fix = std::format("{}: the grant the line names", kTenantCheck);
    const auto target = [&](const std::string& id, const std::string& text, const TargetRead& read,
                            std::vector<std::string_view> needs) {
        for (const std::string_view role : needs) {
            if (!has(role)) {
                report.skip(id, text, std::format("{}.graph.role.{}", p, role));
                return;
            }
        }
        if (read.read) {
            report.ok(id, std::format("{} read, {} item(s)", text, read.items));
        } else {
            report.problem(id, "read_failed", c + read.error, read_fix);
        }
    };
    target(p + ".graph.mail", mailbox, facts.mail, {});
    target(p + ".graph.library", library, facts.library, {kRoleSites, kRoleLists});
    target(p + ".graph.folder", folder, facts.folder, {kRoleFiles});
    report.skip(p + ".graph.write", write, write_needs);
}

} // namespace rp::doctor
