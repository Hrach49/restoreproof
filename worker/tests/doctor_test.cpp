// rpworker doctor's judgement (W7.2, docs/decisions.md 2026-10-18): each area's
// facts to its lines, failure paths first. The words here are the operator's
// and the --json codes support reads; docs/worker-config.md "rpworker doctor"
// lists them.

#include <rp/canonical_json.hpp>
#include <rp/doctor.hpp>
#include <rp/service.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace rp::doctor;
using Catch::Matchers::ContainsSubstring;
using namespace std::chrono_literals;

namespace {

constexpr std::string_view kSid = "S-1-5-80-2410341749-1432216181-1010774729-1630443783-2912569396";

std::vector<std::string> lines(const Report& report)
{
    std::vector<std::string> out;
    for (const Check& check : report.checks()) {
        out.push_back(line_of(check));
    }
    return out;
}

// The one check of `report` with that id; a test fails when there is none.
const Check& by_id(const Report& report, std::string_view id)
{
    for (const Check& check : report.checks()) {
        if (check.id == id) {
            return check;
        }
    }
    FAIL("no check " << id);
    static Check none;
    return none;
}

Ace allow(std::string sid, std::uint32_t mask, bool children = true)
{
    return Ace{std::move(sid), true, mask, children, false, false};
}

Security root_as_installed()
{
    Security s;
    s.present = s.readable = true;
    s.owner_sid = std::string(kSidAdministrators);
    s.is_protected = true;
    s.aces = {allow("S-1-5-18", kRightsFull), allow("S-1-5-32-544", kRightsFull),
              allow(std::string(kSid), kRightsReadExecute)};
    return s;
}

Security folder_as_installed()
{
    Security s;
    s.present = s.readable = true;
    s.owner_sid = std::string(kSidAdministrators);
    s.aces = {allow(std::string(kSid), kRightsModify),
              Ace{"S-1-5-18", true, kRightsFull, true, false, true}};
    return s;
}

Security vault_as_installed()
{
    Security s;
    s.present = s.readable = true;
    s.owner_sid = std::string(kSidAdministrators);
    s.is_protected = true;
    s.aces = {allow("S-1-5-18", kRightsFull, false), allow("S-1-5-32-544", kRightsFull, false),
              allow("S-1-3-4", kRightsFull, false), allow(std::string(kSid), kRightsRead, false)};
    return s;
}

std::filesystem::path shared_testdata()
{
    return std::filesystem::path(RP_SOURCE_DIR) / ".." / "shared" / "testdata";
}

} // namespace

// --- The report ---------------------------------------------------------------

TEST_CASE("doctor: the four words, the fix and the needs", "[doctor]")
{
    CHECK(line_of({"a", Result::ok, "ok", "vault: fine", ""}) == "ok: vault: fine");
    CHECK(line_of({"a", Result::warning, "w", "log: big", ""}) == "warning: log: big");
    CHECK(line_of({"a", Result::warning, "w", "log: big", "close it"}) ==
          "warning: log: big (fix: close it)");
    CHECK(line_of({"a", Result::problem, "p", "vault: no", "grant it"}) ==
          "problem: vault: no (fix: grant it)");
    CHECK(line_of({"a", Result::skip, "skip", "client 1: read", "client[1].graph.token"}) ==
          "skip: client 1: read (needs client[1].graph.token)");
    CHECK(to_string(Result::ok) == "ok");
    CHECK(to_string(Result::warning) == "warning");
    CHECK(to_string(Result::problem) == "problem");
    CHECK(to_string(Result::skip) == "skip");
}

TEST_CASE("doctor: a report counts its words and is a problem only for a problem line", "[doctor]")
{
    Report report;
    CHECK(report.exit_code() == kExitHealthy);
    CHECK(report.summary_line() == "doctor: 0 ok, 0 warning(s), 0 problem(s), 0 skipped");
    report.ok("a.b", "a");
    report.warning("a.c", "w", "b");
    report.skip("a.d", "c", "a.b");
    CHECK(report.exit_code() == kExitHealthy);
    CHECK_FALSE(report.failed("a"));
    report.problem("vault.acl", "acl", "d", "fix");
    CHECK(report.exit_code() == kExitProblem);
    CHECK(report.failed("vault.acl"));
    CHECK(report.failed("vault"));
    CHECK_FALSE(report.failed("vaul"));
    CHECK_FALSE(report.failed("vault.acl.x"));
    CHECK(report.count(Result::ok) == 1);
    CHECK(report.count(Result::warning) == 1);
    CHECK(report.count(Result::problem) == 1);
    CHECK(report.count(Result::skip) == 1);
    CHECK(report.summary_line() == "doctor: 1 ok, 1 warning(s), 1 problem(s), 1 skipped");
    CHECK(by_id(report, "a.d").code == "skip");
    CHECK(by_id(report, "a.b").code == "ok");
}

TEST_CASE("doctor: --json holds ids, words and codes, and no text, fix or path", "[doctor]")
{
    Report report;
    report.ok("vault.read", "vault: C:\\ProgramData\\RestoreProof\\vault.bin decrypts");
    report.problem("veeam.org[1].cert[1].key_file", "missing_ace",
                   "veeam: contoso.onmicrosoft.com: ...", "icacls \"C:\\x\" /grant \"*S-1-5-80-1:(R)\"");
    JsonFacts facts{"0.1.0", "10.0.19045", "2026-10-18T10:00:00Z", true,
                    "11111111-2222-4333-8444-555555555555", std::string(64, 'a')};
    const std::string text = json_text(report, facts);
    const nlohmann::json doc = nlohmann::json::parse(text);
    CHECK(text == rp::canonical_json(doc));
    CHECK(doc["format"] == "restoreproof.doctor.v1");
    CHECK(doc["worker_version"] == "0.1.0");
    CHECK(doc["windows_build"] == "10.0.19045");
    CHECK(doc["elevated"] == true);
    CHECK(doc["worker_id"] == facts.worker_id);
    CHECK(doc["key_id"] == facts.key_id);
    CHECK(doc["counts"] == nlohmann::json{{"ok", 1}, {"problem", 1}, {"skip", 0}, {"warning", 0}});
    CHECK(doc["checks"][1] == nlohmann::json{{"code", "missing_ace"},
                                            {"id", "veeam.org[1].cert[1].key_file"},
                                            {"result", "problem"}});
    CHECK(text.find("ProgramData") == std::string::npos);
    CHECK(text.find("contoso") == std::string::npos);
    CHECK(text.find("icacls") == std::string::npos);

    SECTION("an unknown worker and key are left out")
    {
        facts.worker_id.clear();
        facts.key_id.clear();
        const nlohmann::json bare = nlohmann::json::parse(json_text(report, facts));
        CHECK_FALSE(bare.contains("worker_id"));
        CHECK_FALSE(bare.contains("key_id"));
    }
}

// --- The ACLs -----------------------------------------------------------------

TEST_CASE("doctor: the service SID is sc showsid's", "[doctor]")
{
    CHECK(service_sid("RestoreProof") == std::string(kSid));
    CHECK(service_sid("restoreproof") == std::string(kSid));
    CHECK(service_sid("") == std::nullopt);
    CHECK(service_sid("Rest\xc3\xa9") == std::nullopt);
    CHECK(service_sid("a b") == std::nullopt);
    CHECK(service_token_groups() ==
          std::vector<std::string>{"S-1-1-0", "S-1-5-32-545", "S-1-5-6", "S-1-5-11",
                                   "S-1-5-80-0", "S-1-2-0", "S-1-5-15"});
}

TEST_CASE("doctor: the wanted ACLs are shared/testdata/worker-acls-v1.json", "[doctor]")
{
    std::ifstream file(shared_testdata() / "worker-acls-v1.json", std::ios::binary);
    REQUIRE(file);
    const nlohmann::json vector = nlohmann::json::parse(file);
    const std::string service = vector["service_sid"].get<std::string>();
    const auto mask_of = [](const std::string& rights) {
        if (rights == "FullControl") {
            return kRightsFull;
        }
        if (rights == "Modify") {
            return kRightsModify;
        }
        if (rights == "ReadAndExecute") {
            return kRightsReadExecute;
        }
        REQUIRE(rights == "Read");
        return kRightsRead;
    };
    const auto rules_of = [&](const nlohmann::json& rules) {
        std::vector<std::pair<std::string, std::uint32_t>> out;
        for (const auto& rule : rules) {
            const std::string sid = rule["sid"].get<std::string>();
            out.emplace_back(sid == service ? std::string(kSid) : sid, mask_of(rule["rights"].get<std::string>()));
        }
        return out;
    };
    const auto ours = [](const WantedAcl& wanted) {
        std::vector<std::pair<std::string, std::uint32_t>> out;
        for (const WantedRule& rule : wanted.rules) {
            out.emplace_back(rule.sid, rule.mask);
        }
        return out;
    };
    const std::vector<WantedAcl> folders = wanted_folders(kSid);
    REQUIRE(folders.size() == vector["folders"].size());
    for (std::size_t i = 0; i < folders.size(); ++i) {
        CAPTURE(i);
        CHECK(folders[i].path == vector["folders"][i]["path"].get<std::string>());
        CHECK(folders[i].is_protected == vector["folders"][i]["protected"].get<bool>());
        CHECK(folders[i].to_children);
        CHECK(ours(folders[i]) == rules_of(vector["folders"][i]["rules"]));
    }
    const WantedAcl vault = wanted_vault(kSid);
    CHECK(vault.path == vector["vault"]["file"].get<std::string>());
    CHECK(vault.is_protected == vector["vault"]["protected"].get<bool>());
    CHECK_FALSE(vault.to_children);
    CHECK(ours(vault) == rules_of(vector["vault"]["rules"]));
    CHECK(vector["trusted_owners"] ==
          nlohmann::json{std::string(kSidSystem), std::string(kSidAdministrators)});
}

TEST_CASE("doctor: an ACL as the installer sets it differs in nothing", "[doctor]")
{
    CHECK(acl_difference(root_as_installed(), wanted_folders(kSid)[0]).ok());
    CHECK(acl_difference(folder_as_installed(), wanted_folders(kSid)[1]).ok());
    CHECK(acl_difference(vault_as_installed(), wanted_vault(kSid)).ok());
}

TEST_CASE("doctor: what an ACL lacks and has too much of", "[doctor]")
{
    const WantedAcl root = wanted_folders(kSid)[0];
    SECTION("a rule with other rights, or other inheritance, or inherited, is missing")
    {
        Security s = root_as_installed();
        s.aces[2].mask = kRightsModify;
        CHECK(acl_difference(s, root).missing.size() == 1);
        s = root_as_installed();
        s.aces[2].to_children = false;
        CHECK(acl_difference(s, root).missing.size() == 1);
        s = root_as_installed();
        s.aces[2].inherited = true;
        CHECK(acl_difference(s, root).missing.size() == 1);
        s = root_as_installed();
        s.aces[2].allow = false;
        const AclDifference d = acl_difference(s, root);
        CHECK(d.missing.size() == 1);
        REQUIRE(d.extra.size() == 1);
        CHECK_FALSE(d.extra[0].allow);
    }
    SECTION("an entry for another SID, once, and a Deny on a folder that inherits")
    {
        Security s = root_as_installed();
        s.aces.push_back(allow("S-1-5-32-545", kRightsReadExecute));
        s.aces.push_back(allow("S-1-5-32-545", kRightsRead, false));
        const AclDifference d = acl_difference(s, root);
        REQUIRE(d.extra.size() == 1);
        CHECK(d.extra[0].sid == "S-1-5-32-545");
        Security f = folder_as_installed();
        f.aces.push_back(Ace{"S-1-1-0", false, kRightsModify, true, false, false});
        f.aces.push_back(allow("S-1-5-11", kRightsModify));
        CHECK(acl_difference(f, wanted_folders(kSid)[1]).extra.size() == 2);
    }
    SECTION("inheritance and the owner")
    {
        Security s = root_as_installed();
        s.is_protected = false;
        s.owner_sid = "S-1-5-21-1-2-3-1001";
        const AclDifference d = acl_difference(s, root);
        CHECK(d.protection_wrong);
        CHECK(d.owner_wrong);
        CHECK_FALSE(d.ok());
        s.owner_sid = std::string(kSidSystem);
        CHECK_FALSE(acl_difference(s, root).owner_wrong);
    }
}

TEST_CASE("doctor: who besides SYSTEM, Administrators and TrustedInstaller may change a file",
          "[doctor]")
{
    Security s;
    s.aces = {allow("S-1-5-18", kRightsFull), allow("S-1-5-32-544", kRightsFull),
              allow(std::string(kSidTrustedInstaller), kRightsFull),
              allow("S-1-5-32-545", kRightsReadExecute),
              Ace{"S-1-3-0", true, kRightsFull, true, true, true}, // CREATOR OWNER, inherit-only
              Ace{"S-1-1-0", false, kRightsFull, false, false, false}}; // a Deny never writes
    CHECK(unexpected_writers(s).empty());
    s.aces.push_back(allow("S-1-5-32-545", 0x00000002));
    s.aces.push_back(allow("S-1-5-32-545", kRightsModify));
    s.aces.push_back(allow("S-1-5-11", 0x00040000)); // WRITE_DAC
    CHECK(unexpected_writers(s) == std::vector<std::string>{"S-1-5-32-545", "S-1-5-11"});
}

// --- 1. doctor ------------------------------------------------------------------

TEST_CASE("doctor: not elevated is the one problem and the end", "[doctor]")
{
    Report report;
    CHECK_FALSE(check_doctor({false, "0.1.0", "C:\\x\\rpworker.exe", std::nullopt}, report));
    CHECK(lines(report) ==
          std::vector<std::string>{"problem: doctor: not run from an elevated prompt (fix: open "
                                   "PowerShell as Administrator and run rpworker doctor again)"});
    CHECK(by_id(report, "doctor.elevated").code == "not_elevated");
}

TEST_CASE("doctor: the exe it runs as, against the service's", "[doctor]")
{
    Report report;
    CHECK(check_doctor({true, "0.1.0", "C:\\Program Files\\RestoreProof\\rpworker.exe",
                        "c:\\program files\\restoreproof\\RPWORKER.EXE"},
                       report));
    CHECK(lines(report) == std::vector<std::string>{
                               "ok: doctor: rpworker 0.1.0, C:\\Program Files\\RestoreProof\\"
                               "rpworker.exe, elevated"});
    Report other;
    CHECK(check_doctor({true, "0.1.0", "C:\\dev\\rpworker.exe",
                        "C:\\Program Files\\RestoreProof\\rpworker.exe"},
                       other));
    CHECK(line_of(by_id(other, "doctor.exe")) ==
          "warning: doctor: the service runs C:\\Program Files\\RestoreProof\\rpworker.exe, not "
          "this exe; these answers are this exe's (fix: run C:\\Program Files\\RestoreProof\\"
          "rpworker.exe doctor)");
    CHECK(by_id(other, "doctor.exe").code == "other_exe");
}

TEST_CASE("doctor: the exe a service command line runs", "[doctor]")
{
    CHECK(exe_of_command_line("\"C:\\Program Files\\x\\rpworker.exe\" service run") ==
          "C:\\Program Files\\x\\rpworker.exe");
    CHECK(exe_of_command_line("C:\\x\\rpworker.exe service run") == "C:\\x\\rpworker.exe");
    CHECK(exe_of_command_line("C:\\x\\rpworker.exe") == "C:\\x\\rpworker.exe");
    CHECK(exe_of_command_line("\"C:\\x\\rpworker.exe") == "C:\\x\\rpworker.exe");
    CHECK(exe_of_command_line("") == "");
}

// --- 2. config ------------------------------------------------------------------

TEST_CASE("doctor: a config that doesn't load stops what reads it", "[doctor]")
{
    Report report;
    ConfigFacts facts;
    facts.file = "C:\\ProgramData\\RestoreProof\\config.json";
    facts.load_error = "C:\\ProgramData\\RestoreProof\\config.json: config file not found";
    facts.owner = rp::OwnerTrust::absent;
    CHECK_FALSE(check_config(facts, report));
    CHECK(lines(report) ==
          std::vector<std::string>{
              "problem: config: C:\\ProgramData\\RestoreProof\\config.json: config file not found "
              "(fix: pwsh -File Install-RestoreProofWorker.ps1 -Replace)"});
    CHECK(by_id(report, "config.load").code == "config_invalid");
}

TEST_CASE("doctor: a config someone else wrote", "[doctor]")
{
    ConfigFacts facts;
    facts.file = "C:\\R\\config.json";
    const std::string fix = " (fix: read it, then pwsh -File Install-RestoreProofWorker.ps1 -Replace)";
    SECTION("its owner")
    {
        facts.owner = rp::OwnerTrust::not_trusted;
        Report report;
        CHECK(check_config(facts, report));
        CHECK(line_of(by_id(report, "config.file")) ==
              "problem: config: C:\\R\\config.json is owned by an account other than SYSTEM or "
              "Administrators: someone else may have written it" + fix);
        CHECK(by_id(report, "config.file").code == "untrusted_owner");
    }
    SECTION("entries of its own")
    {
        facts.explicit_entries = true;
        Report report;
        check_config(facts, report);
        CHECK(line_of(by_id(report, "config.file")) ==
              "problem: config: C:\\R\\config.json has entries of its own beside the folder's" +
                  fix);
        CHECK(by_id(report, "config.file").code == "own_entries");
    }
    SECTION("unreadable")
    {
        facts.owner = rp::OwnerTrust::unreadable;
        Report report;
        check_config(facts, report);
        CHECK(line_of(by_id(report, "config.file")) ==
              "problem: config: C:\\R\\config.json: its owner can't be read" + fix);
    }
}

TEST_CASE("doctor: a config as the installer writes it, and a lab's", "[doctor]")
{
    ConfigFacts facts;
    facts.file = "C:\\R\\config.json";
    Report report;
    CHECK(check_config(facts, report));
    CHECK(lines(report) == std::vector<std::string>{
                               "ok: config: C:\\R\\config.json, owned by SYSTEM or Administrators, "
                               "the folder's entries alone",
                               "ok: config: C:\\R\\config.json loads"});
    facts.jobs_file_set = true;
    facts.client_keys_set = true;
    Report lab;
    check_config(facts, lab);
    CHECK(line_of(by_id(lab, "config.jobs_file")) ==
          "warning: config: jobs_file is set: the service reads its jobs from that file, not "
          "the Cloud (fix: remove jobs_file from C:\\R\\config.json; it is a lab's key)");
    CHECK(line_of(by_id(lab, "config.client_keys")) ==
          "ok: config: the eight client keys are set; the service doesn't read them (each job "
          "carries its client)");
}

// --- 3. folders, outbox, disk, log -------------------------------------------------

TEST_CASE("doctor: a folder that isn't as the installer sets it", "[doctor]")
{
    const std::vector<WantedAcl> wanted = wanted_folders(kSid);
    std::vector<FolderFacts> facts;
    facts.push_back({"C:\\R", root_as_installed(), kRightsFull});
    for (std::size_t i = 1; i < wanted.size(); ++i) {
        facts.push_back({"C:\\R\\" + wanted[i].path, folder_as_installed(), kRightsModify});
    }
    const std::string installer = " (fix: pwsh -File Install-RestoreProofWorker.ps1)";

    SECTION("as installed")
    {
        Report report;
        check_folders(wanted, facts, report);
        CHECK(report.count(Result::ok) == 7);
        CHECK(line_of(by_id(report, "folders.root")) == "ok: folders: C:\\R: as the installer sets it");
        CHECK(line_of(by_id(report, "folders.failed")) ==
              "ok: folders: C:\\R\\failed: as the installer sets it");
    }
    SECTION("not there, or unreadable")
    {
        facts[1].security = Security{};
        facts[2].security.readable = false;
        Report report;
        check_folders(wanted, facts, report);
        CHECK(line_of(by_id(report, "folders.state")) ==
              "problem: folders: C:\\R\\state is not there" + installer);
        CHECK(by_id(report, "folders.state").code == "missing");
        CHECK(line_of(by_id(report, "folders.runs")) ==
              "problem: folders: C:\\R\\runs: its security can't be read" + installer);
        CHECK(by_id(report, "folders.runs").code == "unreadable");
    }
    SECTION("a missing rule, the protection, the owner")
    {
        facts[0].security.aces.pop_back();
        facts[0].security.is_protected = false;
        facts[0].security.owner_sid = "S-1-5-21-9";
        Report report;
        check_folders(wanted, facts, report);
        CHECK(line_of(by_id(report, "folders.root")) ==
              "problem: folders: C:\\R: lacks *" + std::string(kSid) +
                  ":(OI)(CI)(RX), inherits from its parent, is owned by S-1-5-21-9" + installer);
        CHECK(by_id(report, "folders.root").code == "acl");
        facts[0].security = root_as_installed();
        facts[1].security.is_protected = true;
        Report other;
        check_folders(wanted, facts, other);
        CHECK_THAT(line_of(by_id(other, "folders.state")),
                   ContainsSubstring("C:\\R\\state: doesn't inherit from its parent"));
    }
    SECTION("entries it shouldn't have are the icacls lines that remove them")
    {
        facts[6].security.aces.push_back(allow("S-1-5-32-545", kRightsModify));
        facts[6].security.aces.push_back(Ace{"S-1-1-0", false, kRightsFull, true, false, false});
        Report report;
        check_folders(wanted, facts, report);
        CHECK(line_of(by_id(report, "folders.logs")) ==
              "problem: folders: C:\\R\\logs: has an entry for S-1-5-32-545, has a Deny entry for "
              "S-1-1-0 (fix: icacls \"C:\\R\\logs\" /remove:g *S-1-5-32-545; icacls "
              "\"C:\\R\\logs\" /remove:d *S-1-1-0)");
    }
    SECTION("an ACL as wanted that still gives the service too little")
    {
        facts[0].service_access = kRightsRead;
        facts[3].service_access = kRightsReadExecute;
        Report report;
        check_folders(wanted, facts, report);
        CHECK(line_of(by_id(report, "folders.root")) ==
              "problem: folders: C:\\R: NT SERVICE\\RestoreProof can't read it, by Windows' own "
              "check" + installer);
        CHECK(by_id(report, "folders.root").code == "service_access");
        CHECK(line_of(by_id(report, "folders.outbox")) ==
              "problem: folders: C:\\R\\outbox: NT SERVICE\\RestoreProof can't change it, by "
              "Windows' own check" + installer);
    }
    SECTION("access not asked is not judged")
    {
        facts[0].service_access.reset();
        Report report;
        check_folders(wanted, facts, report);
        CHECK(by_id(report, "folders.root").result == Result::ok);
    }
}

TEST_CASE("doctor: the outbox", "[doctor]")
{
    OutboxFacts facts{"C:\\R\\failed", true, 2, 40, 0, 3h};
    Report report;
    check_outbox(facts, report);
    CHECK(lines(report) == std::vector<std::string>{"ok: outbox: 2 queued, 40 sent, 0 failed"});

    facts.failed_listable = false;
    facts.failed = 1;
    facts.oldest_queued_age = 25h;
    Report bad;
    check_outbox(facts, bad);
    CHECK(lines(bad) ==
          std::vector<std::string>{
              "problem: outbox: C:\\R\\failed can't be listed, so nothing is uploaded until it can "
              "(fix: remove what is at C:\\R\\failed if it is a file, then pwsh -File "
              "Install-RestoreProofWorker.ps1)",
              "ok: outbox: 2 queued, 40 sent, 1 failed",
              "warning: outbox: the oldest queued run is 25 h old (fix: rpworker outbox list; "
              "rpworker outbox flush says why each run stays)",
              "warning: outbox: 1 run(s) the Cloud refused for good are in failed\\ (fix: "
              "rpworker outbox list)"});
    CHECK(by_id(bad, "outbox.failed").code == "unlistable");
    CHECK(by_id(bad, "outbox.oldest").code == "queued_too_long");
    CHECK(by_id(bad, "outbox.failed_runs").code == "failed_runs");
}

TEST_CASE("doctor: the disk", "[doctor]")
{
    const auto line = [](std::optional<std::uint64_t> free) {
        Report report;
        check_disk({"C:\\R", free}, report);
        return lines(report);
    };
    CHECK(line(std::nullopt) ==
          std::vector<std::string>{"problem: disk: the free space of C:\\R's volume can't be "
                                   "read (fix: run rpworker doctor again)"});
    CHECK(line(kDiskProblemBytes - 1) ==
          std::vector<std::string>{"problem: disk: 1.0 GiB free on C:\\R's volume (fix: free "
                                   "space on that volume; a run folder takes up to 200 MiB)"});
    CHECK(line(kDiskWarningBytes - 1) ==
          std::vector<std::string>{"warning: disk: 5.0 GiB free on C:\\R's volume (fix: free "
                                   "space on that volume; a run folder takes up to 200 MiB)"});
    CHECK(line(kDiskWarningBytes * 4) ==
          std::vector<std::string>{"ok: disk: 20.0 GiB free on C:\\R's volume"});
}

TEST_CASE("doctor: the log's size says whether it rotates", "[doctor]")
{
    const auto line = [](std::optional<std::uint64_t> live, std::uint64_t set) {
        Report report;
        check_log({"C:\\R\\logs\\worker.log", live, set}, report);
        return lines(report);
    };
    constexpr std::uint64_t MiB = 1024 * 1024;
    CHECK(line(std::nullopt, 0) ==
          std::vector<std::string>{"ok: log: C:\\R\\logs\\worker.log not written yet"});
    CHECK(line(3 * MiB, 23 * MiB) ==
          std::vector<std::string>{"ok: log: C:\\R\\logs\\worker.log 3 MiB, 23 MiB with the "
                                   "rotated files"});
    const std::string stuck =
        "warning: log: C:\\R\\logs\\worker.log is 12 MiB, 52 MiB with the rotated files: a "
        "reader holds it, so it doesn't rotate (fix: close what has C:\\R\\logs\\worker.log "
        "open: a viewer, a tail)";
    CHECK(line(12 * MiB, 52 * MiB) == std::vector<std::string>{stuck});
    CHECK(line(1 * MiB, 51 * MiB).front().starts_with("warning:"));
}

// --- 4. vault -------------------------------------------------------------------

namespace {

VaultFacts vault_facts()
{
    VaultFacts facts;
    facts.path = "C:\\R\\vault.bin";
    facts.names = {"veeam_username",     "veeam_password",     "graph_cert_pfx_base64",
                   "graph_cert_password", "signing_key_base64", "cloud_api_token"};
    facts.security = vault_as_installed();
    facts.service_access = kRightsRead;
    facts.account_names = {{"S-1-5-18", "NT AUTHORITY\\SYSTEM"},
                           {"S-1-5-32-544", "BUILTIN\\Administrators"},
                           {"S-1-3-4", "OWNER RIGHTS"},
                           {std::string(kSid), "NT SERVICE\\RestoreProof"}};
    facts.service_sid = std::string(kSid);
    facts.exe = "C:\\P\\rpworker.exe";
    return facts;
}

} // namespace

TEST_CASE("doctor: a vault as the installer leaves it", "[doctor]")
{
    Report report;
    CHECK(check_vault(vault_facts(), report));
    CHECK(lines(report) ==
          std::vector<std::string>{
              "ok: vault: C:\\R\\vault.bin: entries for NT AUTHORITY\\SYSTEM, "
              "BUILTIN\\Administrators, OWNER RIGHTS, NT SERVICE\\RestoreProof, nothing else",
              "ok: vault: NT SERVICE\\RestoreProof can read it, by Windows' own check",
              "ok: vault: C:\\R\\vault.bin decrypts on this machine",
              "ok: vault: holds veeam_username, veeam_password, graph_cert_pfx_base64, "
              "graph_cert_password, signing_key_base64, cloud_api_token"});
}

TEST_CASE("doctor: the service's missing Read entry on the vault is one line, the grant",
          "[doctor]")
{
    VaultFacts facts = vault_facts();
    facts.security.aces.pop_back();
    facts.service_access = 0;
    facts.account_names.pop_back();
    Report report;
    CHECK(check_vault(facts, report));
    CHECK(report.count(Result::problem) == 1);
    CHECK(line_of(by_id(report, "vault.acl")) ==
          "problem: vault: C:\\R\\vault.bin: NT SERVICE\\RestoreProof can't read it (fix: "
          "rpworker vault grant \"NT SERVICE\\RestoreProof\")");
    CHECK(by_id(report, "vault.acl").code == "no_service_read");
    CHECK(line_of(by_id(report, "vault.service_read")) ==
          "skip: vault: NT SERVICE\\RestoreProof's read, by Windows' own check (needs vault.acl)");
}

TEST_CASE("doctor: a vault's other ACL faults are icacls lines", "[doctor]")
{
    VaultFacts facts = vault_facts();
    facts.security.aces.erase(facts.security.aces.begin()); // SYSTEM gone
    facts.security.aces.push_back(allow("S-1-5-32-545", kRightsRead, false));
    facts.security.aces.push_back(Ace{"S-1-5-11", false, kRightsRead, false, false, false});
    facts.security.is_protected = false;
    facts.security.owner_sid = "S-1-5-21-7";
    facts.account_names.push_back({"S-1-5-32-545", "BUILTIN\\Users"});
    Report report;
    check_vault(facts, report);
    CHECK(line_of(by_id(report, "vault.acl")) ==
          "problem: vault: C:\\R\\vault.bin: lacks *S-1-5-18:(F), has an entry for S-1-5-32-545, "
          "has a Deny entry for S-1-5-11, inherits from its parent, is owned by S-1-5-21-7 (fix: "
          "icacls \"C:\\R\\vault.bin\" /inheritance:r; icacls \"C:\\R\\vault.bin\" /setowner "
          "*S-1-5-32-544; icacls \"C:\\R\\vault.bin\" /grant \"*S-1-5-18:(F)\"; icacls "
          "\"C:\\R\\vault.bin\" /remove:g *S-1-5-32-545; icacls \"C:\\R\\vault.bin\" /remove:d "
          "*S-1-5-11)");
    CHECK(by_id(report, "vault.acl").code == "acl");
}

TEST_CASE("doctor: a vault whose ACL is right and still keeps the service out", "[doctor]")
{
    VaultFacts facts = vault_facts();
    facts.service_access = 0;
    Report report;
    check_vault(facts, report);
    CHECK(line_of(by_id(report, "vault.service_read")) ==
          "problem: vault: NT SERVICE\\RestoreProof can't read it, by Windows' own check (fix: "
          "rpworker vault grant \"NT SERVICE\\RestoreProof\")");
    facts.service_access.reset();
    Report unasked;
    check_vault(facts, unasked);
    CHECK(by_id(unasked, "vault.service_read").result == Result::ok);
}

TEST_CASE("doctor: a vault that isn't there or can't be read", "[doctor]")
{
    VaultFacts facts = vault_facts();
    facts.security = Security{};
    facts.read_error = "C:\\R\\vault.bin: vault file not found";
    facts.names.clear();
    Report report;
    CHECK_FALSE(check_vault(facts, report));
    CHECK(lines(report) ==
          std::vector<std::string>{"problem: vault: C:\\R\\vault.bin: vault file not found (fix: "
                                   "pwsh -File Install-RestoreProofWorker.ps1)"});
    CHECK(by_id(report, "vault.read").code == "unreadable");

    facts = vault_facts();
    facts.security.readable = false;
    Report unreadable;
    check_vault(facts, unreadable);
    CHECK(line_of(by_id(unreadable, "vault.acl")) ==
          "problem: vault: C:\\R\\vault.bin: its security can't be read (fix: pwsh -File "
          "Install-RestoreProofWorker.ps1)");
}

TEST_CASE("doctor: each name the vault lacks, and its fix", "[doctor]")
{
    VaultFacts facts = vault_facts();
    facts.names = {"graph_cert_pfx_base64", "cloud_install_token"};
    Report report;
    CHECK(check_vault(facts, report));
    CHECK(line_of(by_id(report, "vault.veeam_username")) ==
          "problem: vault: veeam_username is not in it (fix: rpworker vault set veeam_username)");
    CHECK(line_of(by_id(report, "vault.veeam_password")) ==
          "problem: vault: veeam_password is not in it (fix: rpworker vault set veeam_password)");
    CHECK(line_of(by_id(report, "vault.graph_certificate")) ==
          "problem: vault: half a Graph certificate (graph_cert_pfx_base64 without "
          "graph_cert_password) (fix: pwsh -File New-WorkerGraphCertificate.ps1 -Worker "
          "\"C:\\P\\rpworker.exe\" -Replace)");
    CHECK(by_id(report, "vault.graph_certificate").code == "half");
    CHECK(line_of(by_id(report, "vault.signing_key_base64")) ==
          "problem: vault: signing_key_base64 is not in it (fix: rpworker signer new-key)");
    CHECK(line_of(by_id(report, "vault.cloud_api_token")) ==
          "problem: vault: cloud_api_token is not in it: this Worker isn't registered (fix: "
          "rpworker cloud register)");
    CHECK(by_id(report, "vault.cloud_api_token").code == "not_registered");

    facts.names = {"graph_cert_password", "veeam_username", "veeam_password", "signing_key_base64"};
    Report other;
    check_vault(facts, other);
    CHECK_THAT(line_of(by_id(other, "vault.graph_certificate")),
               ContainsSubstring("(graph_cert_password without graph_cert_pfx_base64)"));
    CHECK(line_of(by_id(other, "vault.cloud_api_token")) ==
          "problem: vault: cloud_api_token is not in it: this Worker isn't registered (fix: "
          "uv run python manage.py create-worker-token on the Cloud, rpworker vault set "
          "cloud_install_token, then rpworker cloud register)");

    facts.names = {"veeam_username", "veeam_password", "signing_key_base64"};
    Report none;
    check_vault(facts, none);
    CHECK(line_of(by_id(none, "vault.graph_certificate")) ==
          "problem: vault: no Graph certificate (graph_cert_pfx_base64, graph_cert_password) "
          "(fix: pwsh -File New-WorkerGraphCertificate.ps1 -Worker \"C:\\P\\rpworker.exe\")");
    CHECK(by_id(none, "vault.graph_certificate").code == "missing");

    facts.names = vault_facts().names;
    facts.names.push_back("cloud_install_token");
    Report both;
    check_vault(facts, both);
    CHECK(line_of(by_id(both, "vault.cloud_install_token")) ==
          "warning: vault: cloud_install_token is still there beside cloud_api_token (fix: "
          "rpworker vault remove cloud_install_token)");
}

// --- 5. the signing key ---------------------------------------------------------------

TEST_CASE("doctor: the signing key against the registration", "[doctor]")
{
    const std::string key(64, 'a');
    const rp::WorkerRecord record{"11111111-2222-4333-8444-555555555555", key,
                                  "https://cloud.example.invalid", "2026-10-16T16:00:00Z"};
    SECTION("not in the vault: the vault's line says so")
    {
        Report report;
        check_signing_key({std::nullopt, false}, {true, record}, report);
        CHECK(lines(report) == std::vector<std::string>{
                                   "skip: signing key: its key_id (needs vault.signing_key_base64)"});
    }
    SECTION("not a key")
    {
        Report report;
        check_signing_key({std::nullopt, true}, {true, record}, report);
        CHECK(lines(report) ==
              std::vector<std::string>{
                  "problem: signing key: signing_key_base64 is not an Ed25519 key (fix: rpworker "
                  "signer new-key --replace, then register again: uv run python manage.py "
                  "revoke-worker on the Cloud, a new install token, rpworker vault remove "
                  "cloud_api_token, rpworker vault set cloud_install_token, rpworker cloud "
                  "register)"});
        CHECK(by_id(report, "signing.key").code == "not_a_key");
    }
    SECTION("another key than the one registered")
    {
        Report report;
        check_signing_key({std::string(64, 'b'), true}, {true, record}, report);
        CHECK(line_of(by_id(report, "signing.registered")) ==
              "problem: signing key: key_id " + std::string(64, 'b') +
                  " is not the one the Cloud registered (" + key +
                  ") (fix: uv run python manage.py revoke-worker on the Cloud, a new install "
                  "token, rpworker vault remove cloud_api_token, rpworker vault set "
                  "cloud_install_token, rpworker cloud register)");
        CHECK(by_id(report, "signing.registered").code == "key_mismatch");
    }
    SECTION("the one registered")
    {
        Report report;
        check_signing_key({key, true}, {true, record}, report);
        CHECK(lines(report) ==
              std::vector<std::string>{"ok: signing key: key_id " + key,
                                       "ok: signing key: the one registered as worker "
                                       "11111111-2222-4333-8444-555555555555"});
    }
    SECTION("no registration: the cloud's line says so")
    {
        Report report;
        check_signing_key({key, true}, {false, std::nullopt}, report);
        CHECK(report.checks().size() == 1);
    }
}

// --- 6. service -----------------------------------------------------------------

namespace {

ServiceFacts service_facts()
{
    ServiceFacts facts;
    facts.expected_exe = "C:\\Program Files\\RestoreProof\\rpworker.exe";
    facts.setup = rp::service_setup(rp::kServiceName,
                                    "\"C:\\Program Files\\RestoreProof\\rpworker.exe\" service run");
    facts.status.state = rp::ServiceState::running;
    facts.service_sid = std::string(kSid);
    facts.logon.allowed = std::vector<std::string>{"S-1-5-80-0"};
    facts.exe_security.present = facts.exe_security.readable = true;
    facts.exe_security.aces = {allow("S-1-5-32-544", kRightsFull), allow("S-1-5-32-545", kRightsReadExecute)};
    facts.exe_access = kRightsReadExecute;
    facts.log_file = "C:\\R\\logs\\worker.log";
    return facts;
}

} // namespace

TEST_CASE("doctor: a service as the installer leaves it", "[doctor]")
{
    Report report;
    check_service(service_facts(), report);
    CHECK(lines(report) ==
          std::vector<std::string>{
              "ok: service: RestoreProof runs as NT SERVICE\\RestoreProof",
              "ok: service: starts automatically",
              "ok: service: runs \"C:\\Program Files\\RestoreProof\\rpworker.exe\" service run",
              "ok: service: restarts after 60 s three times, then nothing",
              "ok: service: running",
              "ok: service: NT SERVICE\\RestoreProof may log on as a service",
              "ok: service: NT SERVICE\\RestoreProof can read and run "
              "C:\\Program Files\\RestoreProof\\rpworker.exe, and only SYSTEM, Administrators "
              "and TrustedInstaller can change it",
              "ok: service: no run in progress"});
}

TEST_CASE("doctor: a service that isn't installed, or can't be read", "[doctor]")
{
    ServiceFacts facts = service_facts();
    facts.read = {1060, rp::ScmStep::service};
    Report report;
    check_service(facts, report);
    CHECK(lines(report) == std::vector<std::string>{
                               "problem: service: RestoreProof is not installed (fix: pwsh -File "
                               "Install-RestoreProofWorker.ps1)"});
    CHECK(by_id(report, "service.installed").code == "not_installed");
    facts.read = {5, rp::ScmStep::manager};
    Report denied;
    check_service(facts, denied);
    CHECK(lines(denied) == std::vector<std::string>{
                               "problem: service: its configuration can't be read (error 5) (fix: "
                               "run rpworker doctor again from an elevated prompt)"});
}

TEST_CASE("doctor: a service changed since the install", "[doctor]")
{
    ServiceFacts facts = service_facts();
    const std::string again =
        " (fix: rpworker service uninstall, then pwsh -File Install-RestoreProofWorker.ps1)";
    facts.setup.account = "LocalSystem";
    facts.setup.start_type = rp::ServiceStartType::manual;
    facts.setup.command_line = "\"C:\\dev\\rpworker.exe\" service run";
    facts.setup.failure_actions.pop_back();
    Report report;
    check_service(facts, report);
    CHECK(line_of(by_id(report, "service.account")) ==
          "problem: service: RestoreProof runs as LocalSystem, not NT SERVICE\\RestoreProof" +
              again);
    CHECK(line_of(by_id(report, "service.start_type")) ==
          "problem: service: starts by hand, not automatically (fix: sc.exe config RestoreProof "
          "start= auto)");
    CHECK(line_of(by_id(report, "service.command_line")) ==
          "problem: service: runs \"C:\\dev\\rpworker.exe\" service run, not "
          "C:\\Program Files\\RestoreProof\\rpworker.exe" + again);
    CHECK(line_of(by_id(report, "service.recovery")) ==
          "problem: service: its recovery actions aren't restart after 60 s three times, then "
          "nothing (services.msc's Recovery tab saves three and drops the fourth)" + again);
    facts.setup.start_type = rp::ServiceStartType::disabled;
    facts.setup.command_line = "\"C:\\Program Files\\RestoreProof\\RPWORKER.exe\" service run "
                               "--config \"C:\\R\\config.json\"";
    Report disabled;
    check_service(facts, disabled);
    CHECK_THAT(line_of(by_id(disabled, "service.start_type")), ContainsSubstring("is disabled"));
    CHECK(by_id(disabled, "service.command_line").result == Result::ok);
    facts.setup.command_line = "\"C:\\Program Files\\RestoreProof\\rpworker.exe\" service go";
    Report other;
    check_service(facts, other);
    CHECK(by_id(other, "service.command_line").result == Result::problem);
}

TEST_CASE("doctor: the service's state", "[doctor]")
{
    ServiceFacts facts = service_facts();
    facts.status.state = rp::ServiceState::stopped;
    Report stopped;
    check_service(facts, stopped);
    CHECK(line_of(by_id(stopped, "service.state")) ==
          "problem: service: stopped (fix: rpworker service start)");
    facts.status.win32_exit_code = 1066;
    facts.status.service_exit_code = 1;
    Report config;
    check_service(facts, config);
    CHECK(line_of(by_id(config, "service.state")) ==
          "problem: service: stopped: the config couldn't be loaded; see C:\\R\\logs\\worker.log "
          "(fix: rpworker service start)");
    facts.status.service_exit_code = 2;
    Report log;
    check_service(facts, log);
    CHECK_THAT(line_of(by_id(log, "service.state")), ContainsSubstring("the log couldn't be opened"));
    facts.status.service_exit_code = 3;
    Report three;
    check_service(facts, three);
    CHECK_THAT(line_of(by_id(three, "service.state")), ContainsSubstring("service error 3"));
    facts.status.win32_exit_code = 1067;
    Report win;
    check_service(facts, win);
    CHECK_THAT(line_of(by_id(win, "service.state")), ContainsSubstring("Windows error 1067"));
    facts.status = {};
    facts.status.state = rp::ServiceState::start_pending;
    Report starting;
    check_service(facts, starting);
    CHECK(line_of(by_id(starting, "service.state")) == "warning: service: starting");
    CHECK(by_id(starting, "service.state").code == "pending");
    for (const auto [state, word] :
         {std::pair{rp::ServiceState::stop_pending, "stopping"},
          std::pair{rp::ServiceState::continue_pending, "continuing"},
          std::pair{rp::ServiceState::pause_pending, "pausing"},
          std::pair{rp::ServiceState::paused, "paused"}}) {
        facts.status.state = state;
        Report r;
        check_service(facts, r);
        CHECK(line_of(by_id(r, "service.state")) == std::string("warning: service: ") + word);
    }
    facts.query = {5, rp::ScmStep::service};
    Report unread;
    check_service(facts, unread);
    CHECK(line_of(by_id(unread, "service.state")) ==
          "problem: service: its state can't be read (error 5) (fix: run rpworker doctor again "
          "from an elevated prompt)");
}

TEST_CASE("doctor: the right to log on as a service", "[doctor]")
{
    ServiceFacts facts = service_facts();
    facts.logon.allowed = std::vector<std::string>{std::string(kSid)};
    Report own;
    check_service(facts, own);
    CHECK(by_id(own, "service.logon_right").result == Result::ok);
    facts.logon.allowed = std::vector<std::string>{"S-1-5-32-544"};
    Report not_granted;
    check_service(facts, not_granted);
    CHECK(line_of(by_id(not_granted, "service.logon_right")) ==
          "problem: service: neither NT SERVICE\\RestoreProof nor NT SERVICE\\ALL SERVICES may "
          "\"Log on as a service\" (fix: add NT SERVICE\\ALL SERVICES to \"Log on as a service\" "
          "in secpol.msc, or in the domain's policy if one sets it)");
    CHECK(by_id(not_granted, "service.logon_right").code == "not_granted");
    facts.logon.allowed = std::vector<std::string>{"S-1-5-80-0"};
    facts.logon.denied = {"S-1-5-6"};
    Report denied;
    check_service(facts, denied);
    CHECK(line_of(by_id(denied, "service.logon_right")) ==
          "problem: service: a policy denies NT SERVICE\\RestoreProof \"Log on as a service\" "
          "(fix: take S-1-5-6 out of \"Deny log on as a service\" in secpol.msc, or in the "
          "domain's policy if one sets it)");
    CHECK(by_id(denied, "service.logon_right").code == "denied");
    facts.logon.allowed.reset();
    facts.logon.denied.clear();
    Report unread;
    check_service(facts, unread);
    CHECK(line_of(by_id(unread, "service.logon_right")) ==
          "problem: service: the logon rights can't be read (fix: run rpworker doctor again "
          "from an elevated prompt)");
}

TEST_CASE("doctor: the exe the service runs", "[doctor]")
{
    ServiceFacts facts = service_facts();
    facts.exe_access = kRightsRead;
    facts.exe_security.aces.push_back(allow("S-1-5-32-545", kRightsModify));
    Report report;
    check_service(facts, report);
    CHECK(line_of(by_id(report, "service.exe_access")) ==
          "problem: service: NT SERVICE\\RestoreProof can't read and run "
          "C:\\Program Files\\RestoreProof\\rpworker.exe, by Windows' own check (fix: pwsh -File "
          "Install-RestoreProofWorker.ps1)");
    CHECK(line_of(by_id(report, "service.exe_writers")) ==
          "problem: service: C:\\Program Files\\RestoreProof\\rpworker.exe can be changed by "
          "S-1-5-32-545, and the service runs it as NT SERVICE\\RestoreProof (fix: install it "
          "under %ProgramFiles%\\RestoreProof with pwsh -File Install-RestoreProofWorker.ps1)");
    facts.exe_security = Security{};
    facts.exe_access.reset();
    Report gone;
    check_service(facts, gone);
    CHECK(line_of(by_id(gone, "service.exe_access")) ==
          "problem: service: C:\\Program Files\\RestoreProof\\rpworker.exe is not there (fix: "
          "pwsh -File Install-RestoreProofWorker.ps1)");
}

TEST_CASE("doctor: a run in progress, and a held one", "[doctor]")
{
    ServiceFacts facts = service_facts();
    facts.running = {true, "7cc849e8-0000-4000-8000-000000000001", 12min};
    Report report;
    check_service(facts, report);
    CHECK(line_of(by_id(report, "service.run")) ==
          "warning: service: run 7cc849e8-0000-4000-8000-000000000001 in progress for 12 min; a "
          "restore target may hold its items");
    CHECK(by_id(report, "service.run").code == "run_in_progress");
    facts.running.age = 7h;
    Report held;
    check_service(facts, held);
    CHECK(line_of(by_id(held, "service.run")) ==
          "problem: service: run 7cc849e8-0000-4000-8000-000000000001 has been in progress for "
          "7 h (fix: read C:\\R\\logs\\worker.log; rpworker service stop ends it as "
          "interrupted)");
    CHECK(by_id(held, "service.run").code == "held_run");
    facts.running.run_id.clear();
    facts.running.age = 1min;
    Report unreadable;
    check_service(facts, unreadable);
    CHECK_THAT(line_of(by_id(unreadable, "service.run")),
               ContainsSubstring("run (state\\running.json unreadable) in progress"));
}

// --- 7. cloud -------------------------------------------------------------------

namespace {

CloudFacts cloud_facts()
{
    CloudFacts facts;
    facts.cloud_url = "https://localhost:8443";
    facts.record = {true, rp::WorkerRecord{"11111111-2222-4333-8444-555555555555",
                                           std::string(64, 'a'), "https://localhost:8443",
                                           "2026-10-16T16:00:00Z"}};
    facts.version.answered = true;
    facts.version.status = 200;
    facts.version.kind = rp::CloudAnswerKind::cloud;
    facts.version.body = R"({"api":1,"version":"0.1.0"})";
    return facts;
}

} // namespace

TEST_CASE("doctor: the Cloud as it should be", "[doctor]")
{
    Report report;
    check_cloud(cloud_facts(), report);
    CHECK(lines(report) ==
          std::vector<std::string>{"ok: cloud: worker 11111111-2222-4333-8444-555555555555, "
                                   "registered 2026-10-16T16:00:00Z with https://localhost:8443",
                                   "ok: cloud: RestoreProof Cloud 0.1.0, API 1"});
}

TEST_CASE("doctor: a Worker not registered, or with another Cloud", "[doctor]")
{
    CloudFacts facts = cloud_facts();
    facts.record = {false, std::nullopt};
    Report none;
    check_cloud(facts, none);
    CHECK(line_of(by_id(none, "cloud.registration")) ==
          "problem: cloud: this Worker isn't registered: state\\worker.json is not there (fix: "
          "rpworker cloud register)");
    CHECK(by_id(none, "cloud.registration").code == "not_registered");
    facts.record = {true, std::nullopt};
    Report bad;
    check_cloud(facts, bad);
    CHECK(line_of(by_id(bad, "cloud.registration")) ==
          "problem: cloud: state\\worker.json can't be read (fix: rpworker cloud register)");
    facts = cloud_facts();
    facts.cloud_url = "https://cloud.example.invalid";
    Report moved;
    check_cloud(facts, moved);
    CHECK(line_of(by_id(moved, "cloud.url")) ==
          "problem: cloud: registered with https://localhost:8443, but config.json names "
          "https://cloud.example.invalid (fix: to move: rpworker vault remove cloud_api_token, "
          "a new install token from the new Cloud, rpworker vault set cloud_install_token, "
          "rpworker cloud register)");
    CHECK(by_id(moved, "cloud.url").code == "other_cloud");
    facts.cloud_url = "https://localhost:8443/";
    Report slash;
    check_cloud(facts, slash);
    CHECK(slash.count(Result::problem) == 0);
}

TEST_CASE("doctor: what /v1/version answered", "[doctor]")
{
    const auto version_line = [](VersionAnswer answer) {
        CloudFacts facts = cloud_facts();
        facts.version = std::move(answer);
        Report report;
        check_cloud(facts, report);
        return std::pair{line_of(by_id(report, "cloud.version")), by_id(report, "cloud.version").code};
    };
    const std::string url_fix = " (fix: check cloud_url, the network and cloud_ca_file)";
    CHECK(version_line({false, "unreachable"}) ==
          std::pair{"problem: cloud: https://localhost:8443/v1/version: unreachable" + url_fix,
                    std::string("no_answer")});
    CHECK(version_line({true, "", 404, rp::CloudAnswerKind::cloud, ""}) ==
          std::pair{"problem: cloud: https://localhost:8443/v1/version: HTTP 404" + url_fix,
                    std::string("http_status")});
    CHECK(version_line({true, "", 200, rp::CloudAnswerKind::not_cloud, "{}"}) ==
          std::pair{"problem: cloud: not a RestoreProof Cloud" + url_fix, std::string("not_cloud")});
    CHECK(version_line({true, "", 200, rp::CloudAnswerKind::other_contract, "{}"}).second ==
          "not_cloud");
    const std::string body_line = "problem: cloud: the answer is no version document" + url_fix;
    for (const char* body : {"", "[]", "{\"api\":1}", "{\"api\":\"1\",\"version\":\"x\"}",
                             "{\"api\":1,\"api\":1,\"version\":\"x\"}", "{\"api\":1,\"version\":2}"}) {
        CAPTURE(body);
        CHECK(version_line({true, "", 200, rp::CloudAnswerKind::cloud, body}) ==
              std::pair{body_line, std::string("bad_body")});
    }
    CHECK(version_line({true, "", 200, rp::CloudAnswerKind::cloud, R"({"api":2,"version":"9"})"}) ==
          std::pair{std::string("problem: cloud: the Cloud speaks API 2, this Worker API 1 (fix: "
                                "an upgrade of this Worker)"),
                    std::string("other_api")});
    CHECK(version_line({true, "", 200, rp::CloudAnswerKind::cloud,
                        R"({"api":1,"version":"0.1.0\u001b[2J"})"})
              .first == "ok: cloud: RestoreProof Cloud (a version this Worker doesn't show), API 1");
}

// --- 8. tsa and clock -------------------------------------------------------------

TEST_CASE("doctor: the TSA and the clock", "[doctor]")
{
    TsaFacts facts{"http://timestamp.digicert.com", true, "", 1'760'000'000, 1'760'000'119};
    Report report;
    check_tsa(facts, report);
    CHECK(lines(report) == std::vector<std::string>{
                               "ok: tsa: http://timestamp.digicert.com answered, token verified",
                               "ok: clock: 119 s from the TSA's time"});
    facts.now = facts.gen_time - 121;
    Report skew;
    check_tsa(facts, skew);
    CHECK(line_of(by_id(skew, "clock.skew")) ==
          "problem: clock: 121 s from the TSA's time, over 120 s (fix: set this machine's time "
          "source; w32tm /resync)");
    CHECK(by_id(skew, "clock.skew").code == "skew");
    facts.stamped = false;
    facts.error = "tsa_unreachable";
    Report none;
    check_tsa(facts, none);
    CHECK(lines(none) == std::vector<std::string>{
                             "problem: tsa: http://timestamp.digicert.com: no token "
                             "(tsa_unreachable) (fix: check tsa_url and the network to it)",
                             "skip: clock: against the TSA's time (needs tsa.token)"});
    CHECK(by_id(none, "tsa.token").code == "tsa_unreachable");
}

// --- 9. veeam -------------------------------------------------------------------

namespace {

constexpr std::string_view kThumb = "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7";

VeeamFacts veeam_facts()
{
    VeeamFacts facts;
    facts.url = "https://localhost:4443";
    facts.url_local = true;
    facts.rest_status.state = rp::ServiceState::running;
    facts.service_sid = std::string(kSid);
    facts.now = std::chrono::sys_days{std::chrono::year{2026} / 10 / 18};
    OrganisationFacts org;
    org.name = "RestoreProofLab.onmicrosoft.com";
    org.newest_point = "2026-10-18T01:00:00Z";
    CertificateFacts cert;
    cert.thumbprint = std::string(kThumb);
    cert.not_after = std::chrono::sys_days{std::chrono::year{2028} / 9 / 25};
    cert.key_file = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\76c3_979c";
    cert.service_access = kRightsRead;
    org.certificates.push_back(cert);
    facts.organisations.push_back(org);
    return facts;
}

} // namespace

TEST_CASE("doctor: Veeam as it should be", "[doctor]")
{
    Report report;
    check_veeam(veeam_facts(), report);
    const std::string org = "veeam: RestoreProofLab.onmicrosoft.com: ";
    CHECK(lines(report) ==
          std::vector<std::string>{
              "ok: veeam: https://localhost:4443 is this machine",
              "ok: veeam: Veeam.Archiver.REST.Service is running",
              "ok: veeam: signed in",
              "ok: " + org + "newest restore point 2026-10-18T01:00:00Z",
              "ok: " + org + "certificate " + std::string(kThumb) +
                  " exports (in memory, discarded), valid to 2028-09-25T00:00:00Z",
              "ok: " + org + "NT SERVICE\\RestoreProof can read the key file "
                             "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\76c3_979c"});
}

TEST_CASE("doctor: the renewal case is one line, the key file's grant", "[doctor]")
{
    VeeamFacts facts = veeam_facts();
    facts.organisations[0].certificates[0].service_access = 0;
    Report report;
    check_veeam(facts, report);
    CHECK(report.count(Result::problem) == 1);
    CHECK(line_of(by_id(report, "veeam.org[1].cert[1].key_file")) ==
          "problem: veeam: RestoreProofLab.onmicrosoft.com: NT SERVICE\\RestoreProof can't read the "
          "key file of certificate " + std::string(kThumb) +
              " (fix: icacls \"C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\76c3_979c\" "
              "/grant \"*" + std::string(kSid) + ":(R)\")");
    CHECK(by_id(report, "veeam.org[1].cert[1].key_file").code == "missing_ace");
    CHECK(key_file_grant("C:\\k", "S-1-5-80-1") == "icacls \"C:\\k\" /grant \"*S-1-5-80-1:(R)\"");
}

TEST_CASE("doctor: the export's refusals, worded for doctor", "[doctor]")
{
    using rp::CertExportFailure;
    const std::string who = "veeam: RestoreProofLab.onmicrosoft.com: certificate " + std::string(kThumb);
    struct Row {
        CertExportFailure failure;
        std::string line;
        std::string code;
        bool key_file_skipped;
    };
    const auto row = GENERATE_COPY(
        Row{CertExportFailure::not_found,
            "problem: " + who +
                " is not in LocalMachine\\My on this machine (fix: the Worker runs on the Veeam "
                "server; in Veeam, check the organisation's application certificate)",
            "not_found", true},
        Row{CertExportFailure::expired,
            "problem: " + who + " has expired (fix: renew it in Veeam's organisation settings, "
                                "then run rpworker doctor for the key file's line)",
            "expired", false},
        Row{CertExportFailure::not_yet_valid,
            "problem: " + who + " is not valid yet (fix: check this machine's clock and the "
                                "certificate in Veeam)",
            "not_yet_valid", false},
        Row{CertExportFailure::not_exportable,
            "problem: " + who + "'s private key isn't exportable (fix: Veeam made it so; "
                                "re-create the organisation's application certificate in Veeam)",
            "not_exportable", false},
        Row{CertExportFailure::no_private_key,
            "problem: " + who + " has no private key on this machine (fix: re-create the "
                                "organisation's application certificate in Veeam)",
            "no_private_key", true},
        Row{CertExportFailure::key_unopenable,
            "problem: " + who + "'s private key can't be opened, even elevated (x) (fix: "
                                "re-create the organisation's application certificate in Veeam)",
            "key_unopenable", false},
        Row{CertExportFailure::other,
            "problem: " + who + " can't be exported (x) (fix: run rpworker doctor again; the "
                                "words in brackets are Windows')",
            "export_failed", false},
        Row{CertExportFailure::malformed_thumbprint,
            "problem: " + who + " can't be exported (x) (fix: run rpworker doctor again; the "
                                "words in brackets are Windows')",
            "export_failed", false});
    VeeamFacts facts = veeam_facts();
    facts.organisations[0].certificates[0].export_failure = row.failure;
    facts.organisations[0].certificates[0].export_message = "x";
    Report report;
    check_veeam(facts, report);
    CHECK(line_of(by_id(report, "veeam.org[1].cert[1].export")) == row.line);
    CHECK(by_id(report, "veeam.org[1].cert[1].export").code == row.code);
    CHECK((by_id(report, "veeam.org[1].cert[1].key_file").result == Result::skip) ==
          row.key_file_skipped);
}

TEST_CASE("doctor: a certificate near its end, and one without a key file", "[doctor]")
{
    VeeamFacts facts = veeam_facts();
    facts.organisations[0].certificates[0].not_after = facts.now + 29 * 24h;
    facts.organisations[0].certificates[0].key_file.reset();
    facts.organisations[0].newest_point.reset();
    Report report;
    check_veeam(facts, report);
    CHECK(line_of(by_id(report, "veeam.org[1]")) ==
          "ok: veeam: RestoreProofLab.onmicrosoft.com: no restore point yet");
    CHECK(line_of(by_id(report, "veeam.org[1].cert[1].expiry")) ==
          "warning: veeam: RestoreProofLab.onmicrosoft.com: certificate " + std::string(kThumb) +
              " ends 2026-11-16T00:00:00Z (fix: renew it in Veeam before then, then run rpworker "
              "doctor for the key file's line)");
    CHECK(by_id(report, "veeam.org[1].cert[1].expiry").code == "expires_soon");
    CHECK(line_of(by_id(report, "veeam.org[1].cert[1].key_file")) ==
          "problem: veeam: RestoreProofLab.onmicrosoft.com: no key file of certificate " +
              std::string(kThumb) +
              " under %ProgramData%\\Microsoft\\Crypto (fix: re-create the organisation's "
              "application certificate in Veeam)");
    CHECK(by_id(report, "veeam.org[1].cert[1].key_file").code == "no_key_file");
    facts.organisations[0].certificates[0].not_after.reset();
    facts.organisations[0].certificates[0].service_access.reset();
    facts.organisations[0].certificates[0].key_file = "C:\\k";
    Report unknown;
    check_veeam(facts, unknown);
    CHECK_THAT(line_of(by_id(unknown, "veeam.org[1].cert[1].export")),
               !ContainsSubstring("valid to"));
    CHECK(by_id(unknown, "veeam.org[1].cert[1].key_file").result == Result::ok);
}

TEST_CASE("doctor: Veeam elsewhere, its REST service, its login, no organisation", "[doctor]")
{
    VeeamFacts facts = veeam_facts();
    facts.url_local = false;
    Report remote;
    check_veeam(facts, remote);
    CHECK(line_of(by_id(remote, "veeam.local")) ==
          "problem: veeam: https://localhost:4443 is not this machine: the organisation "
          "certificates are in the Veeam server's store (fix: run the Worker on the Veeam server)");
    CHECK(by_id(remote, "veeam.local").code == "remote");
    CHECK(by_id(remote, "veeam.rest_service").result == Result::skip);

    facts = veeam_facts();
    facts.rest_query = {1060, rp::ScmStep::service};
    Report missing;
    check_veeam(facts, missing);
    CHECK(line_of(by_id(missing, "veeam.rest_service")) ==
          "problem: veeam: Veeam.Archiver.REST.Service is not installed here (fix: run the "
          "Worker on the Veeam server)");
    facts.rest_query = {5, rp::ScmStep::manager};
    Report unread;
    check_veeam(facts, unread);
    CHECK(by_id(unread, "veeam.rest_service").code == "unreadable");
    facts.rest_query = {};
    facts.rest_status.state = rp::ServiceState::stopped;
    Report stopped;
    check_veeam(facts, stopped);
    CHECK(line_of(by_id(stopped, "veeam.rest_service")) ==
          "problem: veeam: Veeam.Archiver.REST.Service is not running (fix: Start-Service "
          "Veeam.Archiver.REST.Service)");

    facts = veeam_facts();
    facts.login_error = "veeam error: Veeam refused the credentials (401)";
    Report login;
    check_veeam(facts, login);
    CHECK(line_of(by_id(login, "veeam.login")) ==
          "problem: veeam error: Veeam refused the credentials (401) (fix: check veeam_username "
          "and veeam_password (rpworker vault set), the account's role in Veeam's console, and "
          "veeam_ca_file and veeam_cert_sha256)");
    CHECK(line_of(by_id(login, "veeam.organisations")) ==
          "skip: veeam: the organisations and their certificates (needs veeam.login)");

    facts = veeam_facts();
    facts.organisations.clear();
    Report none;
    check_veeam(facts, none);
    CHECK(line_of(by_id(none, "veeam.organisations")) ==
          "problem: veeam: no organisation (fix: add the client's organisation in Veeam's console)");

    facts = veeam_facts();
    facts.organisations[0].certificates.clear();
    Report no_app;
    check_veeam(facts, no_app);
    CHECK(line_of(by_id(no_app, "veeam.org[1].certificate")) ==
          "problem: veeam: RestoreProofLab.onmicrosoft.com: Veeam reports no application "
          "certificate (fix: set the organisation's application in Veeam's console)");
}

// --- 10. graph ------------------------------------------------------------------

TEST_CASE("doctor: the Worker's Graph certificate and the two hosts", "[doctor]")
{
    GraphFacts facts;
    facts.thumbprint = std::string(kThumb);
    facts.now = std::chrono::sys_days{std::chrono::year{2026} / 10 / 18};
    facts.not_after = facts.now + 400 * 24h;
    facts.exe = "C:\\P\\rpworker.exe";
    facts.reach = {{"login.microsoftonline.com", ""}, {"graph.microsoft.com", "unreachable"}};
    Report report;
    CHECK(check_graph(facts, report));
    CHECK(lines(report) ==
          std::vector<std::string>{
              "ok: graph: the Worker's certificate " + std::string(kThumb) +
                  ", valid to 2027-11-22T00:00:00Z",
              "ok: graph: login.microsoftonline.com reached",
              "problem: graph: graph.microsoft.com: unreachable (fix: check the network and any "
              "proxy to graph.microsoft.com)",
              "skip: graph: no client named (needs --client <profile file>)"});
    CHECK(by_id(report, "graph.reach[2]").code == "unreachable");

    facts.not_after = facts.now + 10 * 24h;
    facts.clients_named = true;
    Report soon;
    CHECK(check_graph(facts, soon));
    CHECK(lines(soon) ==
          std::vector<std::string>{
              "ok: graph: the Worker's certificate " + std::string(kThumb) +
                  ", valid to 2026-10-28T00:00:00Z",
              "warning: graph: the Worker's certificate ends in 10 day(s) (fix: pwsh -File "
              "New-WorkerGraphCertificate.ps1 -Worker \"C:\\P\\rpworker.exe\" -Replace, then give "
              "each client's admin its public half: rpworker graph certificate)"});
    CHECK(by_id(soon, "graph.certificate_expiry").code == "expires_soon");

    facts.certificate_error = "graph_cert_pfx_base64 is not in the vault";
    Report none;
    CHECK_FALSE(check_graph(facts, none));
    CHECK(lines(none) == std::vector<std::string>{
                             "problem: graph: graph_cert_pfx_base64 is not in the vault (fix: pwsh "
                             "-File New-WorkerGraphCertificate.ps1 -Worker \"C:\\P\\rpworker.exe\" "
                             "-Replace)"});
}

// --- 11. a client ------------------------------------------------------------------

namespace {

ClientFacts client_facts()
{
    ClientFacts facts;
    facts.number = 1;
    facts.file = "C:\\lab\\lab-profile.json";
    facts.profile.veeam_org_name = "RestoreProofLab.onmicrosoft.com";
    facts.profile.graph_tenant_id = "11111111-2222-3333-4444-555555555555";
    facts.profile.graph_client_id = "22222222-3333-4444-5555-666666666666";
    facts.profile.test_mailbox = "restoretest@RestoreProofLab.onmicrosoft.com";
    facts.veeam_check = "";
    facts.roles = {"Sites.Selected", "Files.SelectedOperations.Selected",
                   "Lists.SelectedOperations.Selected"};
    facts.mail = {true, 0, ""};
    facts.library = {true, 2, ""};
    facts.folder = {true, 0, ""};
    return facts;
}

} // namespace

TEST_CASE("doctor: a client as its tenant script left it", "[doctor]")
{
    Report report;
    check_client(client_facts(), true, report);
    const std::string c = "client 1: ";
    CHECK(lines(report) ==
          std::vector<std::string>{
              "ok: " + c + "RestoreProofLab.onmicrosoft.com, tenant "
                           "11111111-2222-3333-4444-555555555555, app "
                           "22222222-3333-4444-5555-666666666666",
              "ok: " + c + "Veeam's organisation RestoreProofLab.onmicrosoft.com is this tenant's",
              "ok: " + c + "graph: the app's token carries Files.SelectedOperations.Selected",
              "ok: " + c + "graph: the app's token carries Lists.SelectedOperations.Selected",
              "ok: " + c + "graph: the app's token carries Sites.Selected",
              "ok: " + c + "graph: restoretest@RestoreProofLab.onmicrosoft.com's Inbox read, 0 "
                           "item(s)",
              "ok: " + c + "graph: the RestoreTarget library read, 2 item(s)",
              "ok: " + c + "graph: the OneDrive RestoreTarget folder read, 0 item(s)",
              "skip: " + c + "graph: the write grants on the RestoreTarget list and folder (needs "
                             "a role the app must never hold; the next run's clean shows them)"});
}

TEST_CASE("doctor: one role removed is one problem line naming it (the Done-when)", "[doctor]")
{
    const auto role = GENERATE(std::string(kRoleFiles), std::string(kRoleLists),
                               std::string(kRoleSites));
    CAPTURE(role);
    ClientFacts facts = client_facts();
    std::erase(facts.roles, role);
    // What Graph would answer without it: the reads that rest on it fail too.
    if (role == kRoleFiles) {
        facts.folder = {false, 0, "Graph denied ..."};
    } else {
        facts.library = {false, 0, "Graph denied ..."};
    }
    Report report;
    check_client(facts, true, report);
    CHECK(report.count(Result::problem) == 1);
    const Check& line = by_id(report, "client[1].graph.role." + role);
    CHECK(line.result == Result::problem);
    CHECK(line.code == "role_missing");
    CHECK(line_of(line) ==
          "problem: client 1: graph: the app's token lacks " + role +
              " (fix: the client's admin runs Initialize-RestoreProofTenant.ps1 -TenantId "
              "11111111-2222-3333-4444-555555555555 -SiteUrl <...> -OneDriveUser <...> "
              "-WorkerCertificateFile <...> -ProfileFile <...>, which consents it again)");
    CHECK(by_id(report, role == kRoleFiles ? "client[1].graph.folder" : "client[1].graph.library")
              .result == Result::skip);
}

TEST_CASE("doctor: a role the app must never hold", "[doctor]")
{
    ClientFacts facts = client_facts();
    facts.roles.push_back("Sites.ReadWrite.All");
    facts.roles.push_back("Bad\nRole");
    Report report;
    check_client(facts, true, report);
    CHECK(line_of(by_id(report, "client[1].graph.role_extra[1]")) ==
          "problem: client 1: graph: the app's token carries Sites.ReadWrite.All, which it must "
          "never hold (fix: the client's admin runs Initialize-RestoreProofTenant.ps1, which "
          "removes it)");
    CHECK(by_id(report, "client[1].graph.role_extra[1]").code == "role_extra");
    CHECK_THAT(line_of(by_id(report, "client[1].graph.role_extra[2]")),
               ContainsSubstring("carries a role this Worker doesn't show, which"));
}

TEST_CASE("doctor: a client whose profile, Veeam check, sign-in or read fails", "[doctor]")
{
    ClientFacts facts = client_facts();
    facts.profile_error = "--profile-file C:\\lab\\x.json: can't be read";
    Report profile;
    check_client(facts, true, profile);
    CHECK(lines(profile) ==
          std::vector<std::string>{"problem: client 1: --profile-file C:\\lab\\x.json: can't be "
                                   "read (fix: give the profile file Initialize-RestoreProofTenant"
                                   ".ps1 printed for this client)"});
    CHECK(by_id(profile, "client[1].profile").code == "profile");

    facts = client_facts();
    facts.veeam_check = "client_mismatch: the organisation's msid is not graph_tenant_id";
    facts.token_error = "graph error: Entra refused the sign-in (AADSTS700016)";
    Report token;
    check_client(facts, true, token);
    CHECK(line_of(by_id(token, "client[1].veeam")) ==
          "problem: client 1: client_mismatch: the organisation's msid is not graph_tenant_id "
          "(fix: the profile's veeam_org_name must name this tenant's organisation in Veeam)");
    CHECK(by_id(token, "client[1].veeam").code == "client_mismatch");
    CHECK(line_of(by_id(token, "client[1].graph.token")) ==
          "problem: client 1: graph error: Entra refused the sign-in (AADSTS700016) (fix: the "
          "client's admin runs Initialize-RestoreProofTenant.ps1 -CheckOnly: the app, its "
          "certificate, its consent)");
    CHECK(by_id(token, "client[1].graph.token").code == "sign_in");
    CHECK(line_of(by_id(token, "client[1].graph.mail")) ==
          "skip: client 1: graph: restoretest@RestoreProofLab.onmicrosoft.com's Inbox (needs "
          "client[1].graph.token)");
    CHECK(token.count(Result::skip) == 4);

    facts = client_facts();
    facts.veeam_check.reset();
    facts.mail = {false, 0, "graph error: Graph denied GET ... Application Mail.ReadWrite scoped "
                            "to restoretest"};
    Report mail;
    check_client(facts, false, mail);
    CHECK(line_of(by_id(mail, "client[1].veeam")) ==
          "skip: client 1: Veeam's organisation against the tenant (needs veeam.login)");
    CHECK(line_of(by_id(mail, "client[1].graph.token")) ==
          "skip: client 1: graph: the app's token and the three targets (needs graph.certificate)");
    check_client(facts, true, mail);
    CHECK(line_of(by_id(mail, "client[1].graph.mail")) ==
          "problem: client 1: graph error: Graph denied GET ... Application Mail.ReadWrite scoped "
          "to restoretest (fix: the client's admin runs Initialize-RestoreProofTenant.ps1 "
          "-CheckOnly: the grant the line names)");
    CHECK(by_id(mail, "client[1].graph.mail").code == "read_failed");
}
