// W3.6 (#41): `rpworker test` (rp::run_test_command). It runs the pipeline
// `rpworker restore` runs (src/run_pipeline.hpp), so these tests run on
// restore's Harness (restore_command_lab.hpp) and pin what differs: the
// command line (no --seed, --json), the table after the check (VERDICT and
// REASON in fixed words), the --json file, restoreproof.result.v1 (W4.1), for
// each way a run ends, a result that isn't valid and a file that can't be
// written. What both share (the guard, the mutex, the status, the cleanup,
// the timings) is tested in restore_command_test.cpp. No network, nothing
// live. The choices are the 2026-10-03 W3.6 and 2026-10-04 W4.1 entries in
// docs/decisions.md.

#include "restore_command_lab.hpp"
#include "result_lab.hpp"
#include "signing_lab.hpp"

#include "../src/file_read.hpp"
#include "../src/text_table.hpp"

#include <rp/canonical_json.hpp>
#include <rp/checker.hpp>
#include <rp/cli.hpp>
#include <rp/connector.hpp>
#include <rp/office_v1.hpp>
#include <rp/restore_command.hpp>
#include <rp/retry_policy.hpp>
#include <rp/timestamper.hpp>
#include <rp/rfc3161.hpp>
#include <rp/result_schema.hpp>
#include <rp/run_status.hpp>
#include <rp/sha256.hpp>
#include <rp/signer.hpp>
#include <rp/step_timer.hpp>
#include <rp/test_command.hpp>
#include <rp/version.hpp>

#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <limits>
#include <new>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;
using Catch::Matchers::StartsWith;

namespace {

using namespace rp::test::restore_command_lab;

// A Harness that runs `rpworker test`.
struct TestLab : Harness {
    explicit TestLab(const json& config_edit = json::object()) : Harness(config_edit)
    {
        command = rp::run_test_command;
    }

    // The --json file in the temp folder, and its argument.
    std::filesystem::path json_path() const { return dir.path() / "run.json"; }
    std::string json_arg() const { return utf8(json_path()); }

    // The --json file, parsed; REQUIREs it, that it is exactly its own
    // canonical text and that the embedded schema takes it.
    json result() const { return result_in(json_path()); }

    // W4.2: the --evidence root in the temp folder, its argument, a run's
    // folder in it and that folder's result.json, REQUIREd as result()'s.
    std::filesystem::path evidence_root() const { return dir.path() / "runs"; }
    std::string evidence_arg() const { return utf8(evidence_root()); }
    std::filesystem::path run_folder(const std::string& run_id = kRunId) const
    {
        return evidence_root() / run_id;
    }
    json evidence_result(const std::string& run_id = kRunId) const
    {
        return result_in(run_folder(run_id) / "result.json");
    }

    json result_in(const std::filesystem::path& file) const
    {
        const std::optional<std::string> text = file_bytes(file);
        REQUIRE(text);
        const json document = json::parse(*text);
        REQUIRE(*text == rp::canonical_json(document));
        const rp::ResultValidation validation = rp::validate_result(document);
        INFO("first violation at \"" << validation.first_pointer << "\"");
        REQUIRE(validation.valid);
        return document;
    }

    // A --json run's stdout up to its timings' table, REQUIREing the table
    // and then "wrote <file>" at its end.
    std::string json_body(const Run& run) const
    {
        REQUIRE(timings.size() == 1);
        const std::string tail = timings_table(timings[0]) + "wrote " + json_arg() + "\n";
        REQUIRE(run.out.ends_with(tail));
        return run.out.substr(0, run.out.size() - tail.size());
    }
};

// What a successful restore of `--mail 2 --sp 1 --od 0` shows after the
// header in `test`: the session rows and the restore's line, no item rows.
const std::string kSessionsOfThree =
    "\n"
    "  SESSION          KIND        RESULT   RESTORED  STARTED               ENDED                    ELAPSED\n"
    "  sess-mail        mail        Success  2 of 2    2026-09-30T10:00:00Z  2026-09-30T10:01:05Z     0:01:05\n"
    "  sess-sharepoint  sharepoint  Success  1 of 1    2026-09-30T10:01:10Z  2026-09-30T10:01:52.25Z  0:00:42\n"
    "\n"
    "restore succeeded: 3 of 3 item(s) restored in 0:02:03\n";

const std::string kCheckLineOfThree = "\ncheck: 3 match, 0 mismatch, 0 missing, 0 error\n";

// The table after the check, laid out by the tables' own rule (its layout is
// text_table's, tested there), with its header.
std::string check_table(const std::vector<std::vector<std::string>>& rows)
{
    std::vector<rp::TableRow> table{
        {"  ", {"TYPE", "NAME", "EXPECTED", "FOUND", "MATCH", "VERDICT", "REASON", "MS"}}};
    for (const std::vector<std::string>& row : rows) {
        table.push_back({"  ", row});
    }
    return "\n" + rp::format_table(table);
}

// The top-level keys of restoreproof.result.v1, every one always there.
const std::set<std::string> kResultKeys{
    "format",        "worker_version", "run_id", "started_at", "ended_at",
    "connector",     "client",         "restore_point", "sample", "expected",
    "restore",       "check",          "status", "cleanup",    "timings",
    "attachments",   "screenshot"};

const std::string kNotValid =
    ": the result isn't valid restoreproof.result.v1; no file was written\n";

std::size_t count_of(const std::string& text, std::string_view part)
{
    std::size_t n = 0;
    for (std::size_t at = text.find(part); at != std::string::npos;
         at = text.find(part, at + part.size())) {
        ++n;
    }
    return n;
}

// The wall clock a run reads once the clean after is done, for ended_at: the
// year 10000, which the result's times can't hold.
std::chrono::system_clock::time_point year_10000()
{
    using namespace std::chrono;
    return sys_days{year{10000} / January / 1};
}

std::set<std::string> keys_of(const json& object)
{
    std::set<std::string> keys;
    for (const auto& [key, value] : object.items()) {
        keys.insert(key);
    }
    return keys;
}

// A stdout that takes `limit` bytes, then fails, until lift() takes the limit
// away again.
class LimitedStreamBuf : public std::streambuf {
public:
    explicit LimitedStreamBuf(std::size_t limit) : limit_(limit) {}
    void lift() { limit_ = std::numeric_limits<std::size_t>::max(); }
    std::string text;

protected:
    int_type overflow(int_type c) override
    {
        if (traits_type::eq_int_type(c, traits_type::eof())) {
            return traits_type::not_eof(c);
        }
        if (text.size() >= limit_) {
            return traits_type::eof();
        }
        text.push_back(traits_type::to_char_type(c));
        return c;
    }

    std::streamsize xsputn(const char* s, std::streamsize n) override
    {
        const std::size_t room = text.size() >= limit_ ? 0 : limit_ - text.size();
        const std::size_t take = std::min(room, static_cast<std::size_t>(n));
        text.append(s, take);
        return static_cast<std::streamsize>(take);
    }

private:
    std::size_t limit_;
};

} // namespace

// --- Failure paths: the command line and --json --------------------------------------

// W4.11: what the client check resolves on the Harness's fixtures, the
// result's client.resolved of a run that got past it.
json resolved_of_lab()
{
    const json drive = rp::test::load_fixture_json("graph", "restoretarget-drive-200").at("body");
    const json folder = rp::test::load_fixture_json("graph", "onedrive-folder-200").at("body");
    const json inbox = rp::test::load_fixture_json("graph", "mailbox-inbox-200").at("body");
    return json{{"organization",
                 {{"name", kOrgName},
                  {"tenant_id", std::string{kTenant}},
                  {"type", "Office365"},
                  {"region", "Worldwide"}}},
                {"mailbox", {{"inbox_id", inbox.at("id")}}},
                {"library",
                 {{"name", "RestoreTarget"},
                  {"list_id", drive.at("sharePointIds").at("listId")},
                  {"site_url", drive.at("sharePointIds").at("siteUrl")}}},
                {"onedrive_folder",
                 {{"name", "RestoreTarget"}, {"site_url", folder.at("sharepointIds").at("siteUrl")}}}};
}

TEST_CASE("test: a command line it doesn't understand is a usage error, before the config; there "
          "is no --seed",
          "[test_command]")
{
    const Args args = GENERATE(values<Args>({
        {"--seed", "1"},
        {"--seed"},
        {"--mail", "10", "--seed", "42"},
        {"--json"},
        {"--json", ""},
        {"--json", "a.json", "--json", "b.json"},
        // W4.2: a runs root, never empty, and --json or --evidence, not both.
        {"--evidence"},
        {"--evidence", ""},
        {"--evidence", "runs", "--evidence", "more"},
        {"--evidence", "runs", "--json", "a.json"},
        {"--mail", "101"},
        {"--point", "nope!"},
        {"--run-id", "bad id"},
        {"--canary-cursor", "1,2"},
        {"--record"},
        {"--keep"},
        {"run"},
    }));
    CAPTURE(args);
    TestLab lab;

    const Run run = lab.run_raw(args);

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == kUsage);
    CHECK(lab.default_path_calls == 0);
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("test --json: a path that isn't UTF-8, a name Windows can't hold, a file already there "
          "or a folder that doesn't exist is a config error once the config is read, before the "
          "secrets",
          "[test_command][json]")
{
    // By index: each run of the case has its own temp folder.
    const std::size_t which = GENERATE(range(std::size_t{0}, std::size_t{16}));
    TestLab lab;
    const std::vector<std::pair<std::string, std::string>> cases{
        {"\xff.json", "not a UTF-8 path"},
        // An NTFS stream: it would make an empty run.json, or change config.json.
        {utf8(lab.json_path()) + ":x", "not a file name"},
        {utf8(lab.config_path) + ":x", "not a file name"},
        // Names Windows refuses, which "not found" would let through to the end.
        {utf8(lab.dir.path() / "run?.json"), "not a file name"},
        {utf8(lab.dir.path() / "a|b.json"), "not a file name"},
        {utf8(lab.dir.path()) + "\\", "not a file name"},
        {utf8(lab.dir.path() / ".."), "not a file name"},
        {utf8(lab.config_path), "the file already exists"},
        {utf8(lab.dir.path()), "the file already exists"},
        // Devices: Win32 says "not found" for PRN, AUX or LPT1 with no such
        // device, and the write would fail after the run, or reach the device.
        {utf8(lab.dir.path() / "NUL"), "not a file name"},
        {utf8(lab.dir.path() / "PRN"), "not a file name"},
        {utf8(lab.dir.path() / "aux.json"), "not a file name"},
        {utf8(lab.dir.path() / "LPT1.json"), "not a file name"},
        // Win32 would write run.json.
        {utf8(lab.dir.path() / "run.json."), "not a file name"},
        {utf8(lab.dir.path() / "missing" / "run.json"), "the folder doesn't exist"},
        // The writer's temp name, 21 characters longer, is too long: found
        // by making it now, not after the run.
        {utf8(lab.dir.path() / (std::string(235, 'r') + ".json")),
         "a file can't be written there"},
    };
    const auto& [arg, message] = cases[which];
    CAPTURE(arg, message);
    const std::optional<std::string> config_before = file_bytes(lab.config_path);
    const auto config_time = std::filesystem::last_write_time(lab.config_path);

    const Run run = lab.run({"--json", arg, "--run-id", kRunId});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "config error: --json " + arg + ": " + message + "\n");
    CHECK(lab.default_path_calls == 0);
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.lock_calls == 0);
    CHECK(lab.make_connector_calls == 0);
    CHECK_FALSE(std::filesystem::exists(lab.json_path()));
    CHECK(file_bytes(lab.config_path) == config_before);
    CHECK(std::filesystem::last_write_time(lab.config_path) == config_time);
}

TEST_CASE("test --json: a config that doesn't load is said first", "[test_command][json]")
{
    TestLab lab;
    lab.dir.write("config.json", "{");

    const Run run = lab.run({"--json", utf8(lab.dir.path() / "missing" / "run.json")});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK_THAT(run.err, StartsWith("config error: "));
    CHECK_THAT(run.err, !ContainsSubstring("--json"));
}

TEST_CASE("test --json: a control character in the path is a space in its messages",
          "[test_command][json]")
{
    TestLab lab;
    const std::string arg = utf8(lab.dir.path() / "missing") + "\x1b[2J/run.json";

    const Run run = lab.run({"--json", arg});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "config error: --json " + utf8(lab.dir.path() / "missing") +
                         " [2J/run.json: the folder doesn't exist\n");
}

TEST_CASE("test: a run stopped before its run line writes no --json file and prints no table",
          "[test_command][json]")
{
    using Setup = std::function<void(TestLab&)>;
    const auto [name, setup, extra, code] = GENERATE(table<std::string, Setup, Args, int>({
        {"the secrets", [](TestLab& lab) { lab.load_secrets = [] { return rp::Secrets{}; }; },
         Args{}, rp::exit_code::config},
        {"a manifest that doesn't load",
         [](TestLab& lab) { lab.write_manifest("{"); }, Args{},
         rp::exit_code::config},
        {"a cursor out of range", [](TestLab&) {}, Args{"--canary-cursor", "99,0,0"},
         rp::exit_code::usage},
        {"the run mutex", [](TestLab& lab) { lab.lock_taken = true; }, Args{},
         rp::exit_code::service},
        // Opened after the mutex: the stop nearest to started_at.
        {"a --record folder neither new nor empty",
         [](TestLab& lab) {
             std::filesystem::create_directory(lab.dir.path() / "rec");
             lab.dir.write("rec/earlier.json", "{}");
         },
         Args{"--record", "rec"}, rp::exit_code::config},
        {"no connector", [](TestLab& lab) { lab.give_connector = false; }, Args{},
         rp::exit_code::config},
        {"Veeam unreachable",
         [](TestLab& lab) {
             lab.fake.points_throw = [] { throw rp::connector::TransientError("Veeam unreachable"); };
         },
         Args{}, rp::exit_code::transient},
        {"no restore point", [](TestLab& lab) { lab.fake.points.clear(); }, Args{},
         rp::exit_code::service},
        {"an unknown restore point", [](TestLab&) {}, Args{"--point", "nope"},
         rp::exit_code::service},
    }));
    CAPTURE(name);
    TestLab lab;
    setup(lab);
    // "rec" stands for the temp folder's rec.
    const std::string rec_arg = utf8(lab.dir.path() / "rec");
    const std::string json_arg = lab.json_arg();
    Args args{"--json", json_arg, "--run-id", kRunId};
    for (const std::string_view arg : extra) {
        args.push_back(arg == "rec" ? std::string_view{rec_arg} : arg);
    }

    const Run run = lab.run(args);

    CHECK(run.exit_code == code);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, !ContainsSubstring("wrote "));
    CHECK_FALSE(std::filesystem::exists(lab.json_path()));
    CHECK(lab.timings.empty());
    CHECK(lab.fake.restore_calls == 0);
}

// --- The run's output ----------------------------------------------------------------

TEST_CASE("test: a pass prints the header, the session rows, one table after the check, the "
          "status and the timings; without --json nothing is written",
          "[test_command]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    bool written = false;
    lab.write_summary = [&](const std::filesystem::path&, std::string_view) {
        written = true;
        return true;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(lab.body(run) ==
          expected_header() + kSessionsOfThree +
              "\n"
              "  TYPE        NAME              EXPECTED  FOUND  MATCH  VERDICT   REASON  MS\n"
              "  mail        RP-CANARY-0001    manifest  yes    match  verified  -       123000\n"
              "  mail        real mail 01      fields    yes    match  verified  -       123000\n"
              "  sharepoint  rp-canary-01.pdf  manifest  yes    match  verified  -       246000\n" +
              kCheckLineOfThree + kPassOfThree + kCleanAfterOfThree);
    // The timings as `restore` times them: the same pipeline.
    CHECK(run.out.ends_with("\ntotal                 0:41:00.000\n"));
    CHECK_FALSE(written);
    CHECK(lab.fake.restore_calls == 1);
    CHECK(lab.cleanups.size() == 1);
    CHECK_FALSE(lab.lock_held);
}

TEST_CASE("test and restore run one pipeline: the same restore, check, status and exit code, "
          "only the tables differ",
          "[test_command]")
{
    const Args args{"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"};
    TestLab test;
    test.fake.pool.mail = {carol_mail(1)};
    Harness restore;
    restore.fake.pool.mail = {carol_mail(1)};
    restore.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
    test.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();

    const Run from_test = test.run(args);
    const Run from_restore = restore.run(args);

    CHECK(from_test.exit_code == rp::exit_code::restore);
    CHECK(from_test.exit_code == from_restore.exit_code);
    CHECK(from_test.err == from_restore.err);
    const std::string status = "\nstatus fail: 1 of 3 item(s) didn't verify (1 missing, 0 mismatch)\n";
    CHECK_THAT(test.body(from_test), StartsWith(expected_header()));
    CHECK_THAT(test.body(from_test), EndsWith(status + clean_after_line(2, 0, 0)));
    CHECK_THAT(restore.body(from_restore), EndsWith(status + clean_after_line(2, 0, 0)));
    REQUIRE(test.fake.spec);
    REQUIRE(restore.fake.spec);
    CHECK(test.fake.spec->mail == restore.fake.spec->mail);
    CHECK(test.fake.spec->sharepoint == restore.fake.spec->sharepoint);
    CHECK(rp::timing::to_json(test.timings.at(0)) == rp::timing::to_json(restore.timings.at(0)));
    CHECK(rp::to_json(test.cleanups.at(0)) == rp::to_json(restore.cleanups.at(0)));
    CHECK_THAT(from_restore.out, ContainsSubstring("  KIND        SOURCE  NAME"));
    CHECK_THAT(from_test.out, !ContainsSubstring("  KIND        SOURCE  NAME"));
}

TEST_CASE("test: VERDICT and REASON: an infrastructure item is unchecked, never failed; a "
          "mismatch names its fields; an error its code",
          "[test_command]")
{
    using Setup = std::function<void(TestLab&)>;
    struct Case {
        std::string name;
        Setup setup;
        Args args;
        int code;
        std::vector<std::vector<std::string>> rows;
    };
    const std::vector<Case> cases{
        {"the backup blamed infrastructure for an item the check doesn't find",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 rp::connector::RestoreResult result = restored(spec);
                 result.status = rp::connector::RestoreStatus::partial;
                 result.items_restored = 1;
                 result.items[1].outcome = rp::connector::ItemOutcome::failed;
                 result.items[1].infrastructure = true;
                 result.items[1].message = "SENTINEL-VEEAM-MESSAGE";
                 return result;
             };
             lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
         },
         Args{"--mail", "1", "--sp", "1", "--od", "0"},
         rp::exit_code::service,
         {{"mail", "RP-CANARY-0001", "manifest", "yes", "match", "verified", "-", "123000"},
          {"sharepoint", "rp-canary-01.pdf", "manifest", "no", "missing",
           "unchecked backup_infrastructure", "missing", "-"}}},
        {"beside a missing item, the run fails and the infrastructure item stays unchecked",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 rp::connector::RestoreResult result = restored(spec);
                 result.status = rp::connector::RestoreStatus::failed;
                 result.items_restored = 0;
                 result.items[0].outcome = rp::connector::ItemOutcome::failed;
                 result.items[1].outcome = rp::connector::ItemOutcome::failed;
                 result.items[1].infrastructure = true;
                 return result;
             };
             lab.targets.after[0] = json::array();
             lab.targets.after[1] = json::array();
         },
         Args{"--mail", "1", "--sp", "1", "--od", "0"},
         rp::exit_code::restore,
         {{"mail", "RP-CANARY-0001", "manifest", "no", "missing", "failed", "missing", "-"},
          {"sharepoint", "rp-canary-01.pdf", "manifest", "no", "missing",
           "unchecked backup_infrastructure", "missing", "-"}}},
        {"a canary the restore point doesn't hold, the point taken after the manifest was seeded",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 return not_in_point(spec);
             };
             lab.targets.after[0] = json::array();
         },
         Args{"--mail", "1", "--sp", "0", "--od", "0"},
         rp::exit_code::restore,
         {{"mail", "RP-CANARY-0001", "manifest", "no", "missing", "failed", "not_in_backup",
           "-"}}},
        {"a canary a restore point taken before the manifest was seeded doesn't hold",
         [](TestLab& lab) {
             lab.fake.points = {point(kNewestId, "2026-09-24T22:00:00Z")};
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 return not_in_point(spec);
             };
             lab.targets.after[0] = json::array();
         },
         Args{"--mail", "1", "--sp", "0", "--od", "0"},
         rp::exit_code::service,
         {{"mail", "RP-CANARY-0001", "manifest", "no", "missing", "unchecked not_in_backup",
           "not_in_backup", "-"}}},
        {"a mail whose time, ID and body differ",
         [](TestLab& lab) {
             lab.targets.after[0] = json::array({graph_mail(
                 "restored-1", "RP-CANARY-0001",
                 "HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com", "Hrachya",
                 "2026-09-24T22:14:40Z", "2026-09-24T22:20:00Z", "<x@lab.example>",
                 "another body")});
         },
         Args{"--mail", "1", "--sp", "0", "--od", "0"},
         rp::exit_code::restore,
         {{"mail", "RP-CANARY-0001", "manifest", "yes", "mismatch", "failed",
           "received_at,internet_message_id,sha256", "123000"}}},
        {"a target Graph won't let the check read",
         [](TestLab& lab) {
             const rp::HttpResponse denied =
                 rp::test::load_fixture("graph", "site-403-accessdenied");
             lab.targets.fail = [denied](rp::connector::ItemKind kind,
                                         bool after) -> std::optional<rp::HttpResponse> {
                 return after && kind == rp::connector::ItemKind::sharepoint ? std::optional{denied}
                                                                              : std::nullopt;
             };
         },
         Args{"--mail", "1", "--sp", "1", "--od", "0"},
         rp::exit_code::auth,
         {{"mail", "RP-CANARY-0001", "manifest", "yes", "match", "verified", "-", "123000"},
          {"sharepoint", "rp-canary-01.pdf", "manifest", "no", "error",
           "unchecked graph_permission", "graph_permission", "-"}}},
        {"an earlier run's copy only",
         [](TestLab& lab) {
             lab.targets.before[1] = json::array(
                 {graph_file("earlier-file", "RP-CANARY-01.PDF", 925, "\"c:{earlier},1\"")});
             lab.targets.after[1] = json::array();
         },
         Args{"--mail", "0", "--sp", "1", "--od", "0"},
         rp::exit_code::service,
         {{"sharepoint", "rp-canary-01.pdf", "manifest", "no", "error", "unchecked stale_target",
           "stale_target", "-"}}},
        {"results that don't add up (row 1): no item verdict",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 rp::connector::RestoreResult result = restored(spec);
                 result.items.push_back({rp::connector::ItemKind::mail, "an extra", "s-gone",
                                         rp::connector::ItemOutcome::unknown, "", false});
                 return result;
             };
         },
         Args{"--mail", "1", "--sp", "0", "--od", "0"},
         rp::exit_code::config,
         {{"mail", "RP-CANARY-0001", "manifest", "yes", "match", "-", "-", "123000"}}},
        {"a restore that didn't run (row 4): no item verdict",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec&) {
                 return rp::connector::RestoreResult{};
             };
             lab.targets.after[0] = json::array();
         },
         Args{"--mail", "1", "--sp", "0", "--od", "0"},
         rp::exit_code::service,
         {{"mail", "RP-CANARY-0001", "manifest", "no", "missing", "-", "missing", "-"}}},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{9}))];
    CAPTURE(c.name);
    TestLab lab;
    c.setup(lab);
    Args args = c.args;
    args.insert(args.end(), {"--run-id", kRunId});

    const Run run = lab.run(args);

    INFO(run.out);
    CHECK(run.exit_code == c.code);
    CHECK_THAT(run.out, ContainsSubstring(check_table(c.rows) + "\ncheck: "));
    // Veeam's per-item message isn't printed by `test`.
    CHECK_THAT(run.out, !ContainsSubstring("SENTINEL"));
}

TEST_CASE("test: an Office file that isn't a valid package is a sha256 mismatch; neither REASON "
          "nor the --json file shows the zip reader's words, only stderr does",
          "[test_command][json]")
{
    TestLab lab;
    // Cursor 0,1,0: rp-canary-02.docx, compared by office-v1.
    lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] =
        json::array({graph_file("restored-sharepoint-0", "rp-canary-02.docx", 9)});
    lab.targets.files["restored-sharepoint-0"] = "not a zip";

    const Run run = lab.run({"--run-id", kRunId, "--canary-cursor", "0,1,0", "--mail", "0", "--sp",
                             "1", "--od", "0", "--json", lab.json_arg()});

    CHECK(run.exit_code == rp::exit_code::restore);
    CHECK_THAT(run.out, ContainsSubstring(check_table({{"sharepoint", "rp-canary-02.docx",
                                                        "manifest", "yes", "mismatch", "failed",
                                                        "sha256", "246000"}})));
    const json result = lab.result();
    const json& item = result.at("check").at("items").at(0);
    CHECK(item.at("mismatches") == json::array({"sha256"}));
    // Fixed words (W4.1 point 7).
    CHECK(item.at("reason") ==
          "fields did not match: sha256; the restored package isn't valid office-v1 input");
    CHECK(run.out.find("office-v1") == std::string::npos);
    // Why the reader refused it, said once, on stderr only: one of its own
    // limits must be told from a broken file.
    std::string refusal;
    try {
        rp::office_v1_sha256("not a zip", "docx");
    } catch (const rp::OfficeContentError& e) {
        refusal = e.what();
    }
    REQUIRE_FALSE(refusal.empty());
    CHECK(run.err == "check note: sharepoint rp-canary-02.docx: not valid office-v1 input: " +
                         refusal + "\n");
    CHECK(result.dump().find(refusal) == std::string::npos);
    CHECK(run.out.find(refusal) == std::string::npos);
}

// --- --json: the result (restoreproof.result.v1) --------------------------------------

TEST_CASE("test --json writes restoreproof.result.v1: valid by the embedded schema and by the "
          "schema file, exactly its own canonical text, the seventeen keys",
          "[test_command][json][result]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0", "--json",
                             lab.json_arg()});

    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    const std::optional<std::string> text = file_bytes(lab.json_path());
    REQUIRE(text);
    const json document = json::parse(*text);
    // (a) Valid by the schema the Worker embeds, and by the file the Cloud reads.
    const rp::ResultValidation embedded = rp::validate_result(document);
    INFO("first violation at \"" << embedded.first_pointer << "\"");
    CHECK(embedded.valid);
    nlohmann::json_schema::json_validator from_file;
    from_file.set_root_schema(json::parse(rp::test::read_shared("schemas/result.v1.json")));
    CHECK_NOTHROW(from_file.validate(document));
    // (b) canonical-json-v1: no whitespace, no trailing newline.
    CHECK(*text == rp::canonical_json(document));
    CHECK(text->find('\n') == std::string::npos);
    CHECK_THAT(*text, StartsWith("{\"attachments\":null,\"check\":{"));
    CHECK(text->ends_with("}"));
    // (c) The seventeen keys; no run folder, so nothing of one (W4.2).
    CHECK(keys_of(document) == kResultKeys);
    CHECK(document.at("attachments").is_null());
    CHECK(document.at("screenshot").is_null());
    CHECK(document.at("format") == "restoreproof.result.v1");
    CHECK(document.at("status").at("status") == "pass");
}

TEST_CASE("test --json: the result is valid and has the seventeen keys for each way a run ends, "
          "null where a step didn't run; the file is written after the timings, then wrote <file>",
          "[test_command][json][result]")
{
    namespace gl = rp::test::graph_lab;
    using Setup = std::function<void(TestLab&)>;
    const Args three{"--mail", "2", "--sp", "1", "--od", "0"};
    struct Case {
        std::string name;
        Setup setup;
        Args args;
        int code;
        std::string status; // "<status>[ <error_code>]"
        std::set<std::string> nulls;
    };
    const std::set<std::string> nothing_chosen{"sample", "expected", "restore", "check"};
    const std::vector<Case> cases{
        {"a pass", [](TestLab&) {}, three, rp::exit_code::ok, "pass", {}},
        {"a fail",
         [](TestLab& lab) {
             lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
         },
         three, rp::exit_code::restore, "fail", {}},
        {"the clean before's guard refuses",
         [](TestLab& lab) {
             json edited = rp::test::load_fixture_json("graph", "restoretarget-drive-200");
             edited["body"]["name"] = "Dokumenty";
             // W4.11: the client check sees the library as recorded first.
             lab.targets.graph.on(rp::HttpMethod::get, gl::drive_url(),
                                  {rp::test::load_fixture("graph", "restoretarget-drive-200"),
                                   rp::test::to_response(edited)});
         },
         three, rp::exit_code::service, "error target_guard", nothing_chosen},
        // W4.11: the client check refuses before the clean: no clean ran.
        {"the client check's guard refuses",
         [](TestLab& lab) {
             json edited = rp::test::load_fixture_json("graph", "restoretarget-drive-200");
             edited["body"]["name"] = "Dokumenty";
             lab.targets.graph.on(rp::HttpMethod::get, gl::drive_url(),
                                  {rp::test::to_response(edited)});
         },
         three, rp::exit_code::service, "error target_guard",
         {"sample", "expected", "restore", "check", "cleanup"}},
        {"choose_sample throws",
         [](TestLab& lab) {
             lab.fake.candidates_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         Args{"--mail", "2", "--sp", "0", "--od", "0"}, rp::exit_code::transient,
         "error backup_transient", nothing_chosen},
        {"an empty sample",
         [](TestLab& lab) { lab.write_manifest(trimmed_manifest(0, 1, 1)); },
         Args{"--mail", "1", "--sp", "0", "--od", "0"}, rp::exit_code::service,
         "error empty_sample", {"restore", "check"}},
        {"the reads before fail",
         [](TestLab& lab) {
             const rp::HttpResponse answer =
                 rp::test::load_fixture("graph", "api-invalid-token-401");
             lab.targets.fail = [answer](rp::connector::ItemKind,
                                         bool) -> std::optional<rp::HttpResponse> { return answer; };
         },
         three, rp::exit_code::auth, "error graph_auth", {"restore", "check"}},
        {"restore_sample throws, nothing restored",
         [](TestLab& lab) {
             lab.fake.restore_throw = [] {
                 throw rp::connector::SafetyViolation("target guard: refused; nothing was restored");
             };
         },
         three, rp::exit_code::service, "error target_guard", {"restore", "check"}},
        {"restore_sample throws, items may be in the targets",
         [](TestLab& lab) {
             lab.fake.restore_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         three, rp::exit_code::transient, "error backup_transient", {"restore", "check"}},
        {"a restore that didn't run (row 4)",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec&) {
                 return rp::connector::RestoreResult{};
             };
         },
         three, rp::exit_code::service, "error not_run", {}},
        {"the check throws",
         [](TestLab& lab) { lab.targets.download_throw = [] { throw std::bad_alloc(); }; },
         Args{"--mail", "0", "--sp", "1", "--od", "0"}, rp::exit_code::config, "error internal",
         {"check"}},
        {"a target's read back fails",
         [](TestLab& lab) {
             const rp::HttpResponse denied =
                 rp::test::load_fixture("graph", "site-403-accessdenied");
             lab.targets.fail = [denied](rp::connector::ItemKind kind,
                                         bool after) -> std::optional<rp::HttpResponse> {
                 return after && kind == rp::connector::ItemKind::sharepoint ? std::optional{denied}
                                                                              : std::nullopt;
             };
         },
         three, rp::exit_code::auth, "error graph_permission", {}},
        {"results that don't add up (row 1)",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 rp::connector::RestoreResult result = restored(spec);
                 result.items.push_back({rp::connector::ItemKind::mail, "an extra", "s-gone",
                                         rp::connector::ItemOutcome::unknown, "", false});
                 return result;
             };
         },
         three, rp::exit_code::config, "error internal", {}},
        {"the backup says failed, every item verified (row 6)",
         [](TestLab& lab) {
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 rp::connector::RestoreResult result = restored(spec);
                 result.status = rp::connector::RestoreStatus::failed;
                 return result;
             };
         },
         three, rp::exit_code::service, "error restore_contradiction", {}},
        {"an earlier run's copy only",
         [](TestLab& lab) {
             lab.targets.before[1] = json::array(
                 {graph_file("earlier-file", "RP-CANARY-01.PDF", 925, "\"c:{earlier},1\"")});
             lab.targets.after[1] = json::array();
         },
         Args{"--mail", "0", "--sp", "1", "--od", "0"}, rp::exit_code::service,
         "error stale_target", {}},
        // After the run line, before the clean before: no clean ran, so
        // `cleanup` is null too.
        {"no download client",
         [](TestLab& lab) { lab.no_download_http = true; }, three, rp::exit_code::config,
         "error internal",
         {"sample", "expected", "restore", "check", "cleanup"}},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{16}))];
    CAPTURE(c.name);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    c.setup(lab);
    Args args = c.args;
    const std::string json_arg = lab.json_arg();
    args.insert(args.end(), {"--run-id", kRunId, "--json", json_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    CHECK(run.exit_code == c.code);
    CHECK_THAT(run.err, !ContainsSubstring("json error"));
    CHECK_THAT(run.err, !ContainsSubstring("result error"));
    // The timings' table, then the file's line, last.
    const std::string body = lab.json_body(run);
    CHECK_THAT(body, ContainsSubstring("\nstatus " + c.status + ": "));
    // Canonical and valid by the embedded schema, whatever the ending.
    const json result = lab.result();
    CHECK(keys_of(result) == kResultKeys);
    for (const std::string& key : kResultKeys) {
        CAPTURE(key);
        // No run folder under --json: nothing of one (W4.2).
        const bool of_folder = key == "attachments" || key == "screenshot";
        CHECK(result.at(key).is_null() == (of_folder || c.nulls.contains(key)));
    }
    CHECK(result.at("format") == "restoreproof.result.v1");
    CHECK(result.at("worker_version") == std::string{rp::version()});
    CHECK(result.at("run_id") == kRunId);
    CHECK(result.at("started_at") == "2026-09-28T12:00:00.000Z");
    CHECK(result.at("ended_at") == "2026-09-28T12:00:00.000Z");
    CHECK(result.at("connector") == json{{"type", "veeam_m365"}, {"api", "1"}});
    const gl::Lab_values& v = gl::lab_values();
    // W4.11: a run that got past the client check says so; one that stopped
    // in or before it (no clean ran) says null for both.
    const bool checked = !c.nulls.contains("cleanup");
    CHECK(result.at("client") ==
          json{{"client_id", nullptr},
               {"tenant_id", kTenant},
               {"veeam_org_name", kOrgName},
               {"targets",
                {{"mailbox", v.mailbox},
                 {"site_id", v.site_id},
                 {"library_id", v.library_id},
                 {"onedrive_drive_id", v.onedrive_drive_id},
                 {"onedrive_folder_id", v.folder_id}}},
               {"scope", checked ? json("same_tenant") : json()},
               {"resolved", checked ? resolved_of_lab() : json()}});
    CHECK(result.at("restore_point") == json{{"id", kNewestId},
                                             {"backup_time_raw", kNewestTime},
                                             {"backup_time", "2026-09-29T22:00:45Z"}});
    const json& status = result.at("status");
    const std::string first = c.status.substr(0, c.status.find(' '));
    CHECK(status.at("status") == first);
    CHECK(status.contains("error_code") == (first == "error"));
    if (first == "error") {
        CHECK(status.at("error_code") == c.status.substr(c.status.find(' ') + 1));
    }
    REQUIRE(lab.cleanups.size() == 1);
    if (!c.nulls.contains("cleanup")) {
        // The finished result: the clean after and its two flags are in it.
        CHECK(result.at("cleanup") == rp::to_json(lab.cleanups[0]));
    }
    CHECK(result.at("timings") == rp::timing::to_json(lab.timings.at(0)));
    CHECK(status.at("restore_sent") == lab.cleanups[0].restore_sent);
    if (!result.at("sample").is_null()) {
        CHECK(result.at("sample").at("run_id") == kRunId);
    }
    if (!result.at("restore").is_null()) {
        const json& restore = result.at("restore");
        // Row 1's restore lists one item it wasn't sent: written as reported.
        CHECK(restore.at("items").size() ==
              restore.at("items_sent").get<std::size_t>() + (c.name.ends_with("(row 1)") ? 1 : 0));
        // No item name in the restore object.
        CHECK(restore.dump().find("RP-CANARY") == std::string::npos);
    }
    // Nothing of the process: v0's command and exit_code are gone.
    const std::string text = *file_bytes(lab.json_path());
    CHECK(text.find("exit_code") == std::string::npos);
    CHECK(text.find("\"command\"") == std::string::npos);
    // canonical-json-v1: one line, no trailing newline.
    CHECK_THAT(text, StartsWith("{\"attachments\":null,\"check\":"));
    CHECK(text.ends_with("}"));
    CHECK(text.find('\n') == std::string::npos);
    // No secret.
    CHECK(text.find("Sentinel-Veeam-Password-9c2e") == std::string::npos);
    CHECK(text.find(rp::test::graph_lab::kPfxPassword) == std::string::npos);
}

// --- --json: a result that isn't valid ------------------------------------------------

TEST_CASE("test: a result that isn't valid when the status is decided is error result_invalid, "
          "exit 1: one status line, no item verdict, the clean after as the run's own status "
          "had it, no --json file",
          "[test_command][json][result]")
{
    using Setup = std::function<void(TestLab&)>;
    struct Case {
        std::string name;
        Setup setup;
        std::string result_error;
        std::string ended; // "<pass|fail|error <code>>", the run's own status
        bool restore_sent;
        std::string cleanup;
    };
    const std::string at_connector =
        "result error: 1 schema violation(s), first at /connector/type\n";
    const std::vector<Case> cases{
        // The one connector the result knows is veeam_m365.
        {"a connector that names itself otherwise, a pass", [](TestLab&) {}, at_connector, "pass",
         true, kCleanAfterOfThree},
        {"a connector that names itself otherwise, a fail",
         [](TestLab& lab) {
             lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
         },
         at_connector, "fail", true, clean_after_line(2, 0, 0)},
        {"a connector that names itself otherwise, a stop before the sample",
         [](TestLab& lab) {
             lab.fake.candidates_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         at_connector, "error backup_transient", false, kNothingRestored},
        {"a connector that names itself otherwise, a restore that may still run",
         [](TestLab& lab) {
             lab.fake.restore_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         at_connector, "error backup_transient", true, kCleanAfterStillRunning},
        {"the backup's words aren't UTF-8",
         [](TestLab& lab) {
             lab.fake.info.name = "veeam_m365";
             lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
                 rp::connector::RestoreResult result = restored(spec);
                 result.sessions[0].result = "Succ\xC3";
                 return result;
             };
         },
         "result error: the result has no canonical form\n", "pass", true, kCleanAfterOfThree},
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{5}))];
    CAPTURE(c.name);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.info.name = "Fake Connector";
    c.setup(lab);
    int writes = 0;
    lab.write_summary = [&](const std::filesystem::path&, std::string_view) {
        ++writes;
        return true;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0", "--json",
                             lab.json_arg()});

    INFO(run.out);
    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::config);
    // One status line, and it is the last word on the run: then the clean
    // after, as the run's own status had it, then the timings.
    const std::string status = "\nstatus error result_invalid: the result isn't valid "
                               "restoreproof.result.v1; the run itself ended " +
                               c.ended + "\n";
    CHECK_THAT(lab.body(run), EndsWith(status + c.cleanup));
    CHECK(count_of(run.out, "\nstatus ") == 1);
    REQUIRE(lab.cleanups.size() == 1);
    CHECK(lab.cleanups[0].restore_sent == c.restore_sent);
    // No clean under a restore that may still run (W4.8 point 9).
    CHECK(lab.cleanups[0].after.has_value() ==
          (c.restore_sent && c.cleanup != kCleanAfterStillRunning));
    // No item verdict: VERDICT reads "-", as when rows 1 to 4 decide.
    CHECK_THAT(run.out, !ContainsSubstring("verified"));
    CHECK_THAT(run.out, !ContainsSubstring("  failed  "));
    CHECK_THAT(run.out, !ContainsSubstring("unchecked"));
    if (c.ended == "pass") {
        CHECK_THAT(run.out,
                   ContainsSubstring(check_table({
                       {"mail", "RP-CANARY-0001", "manifest", "yes", "match", "-", "-", "123000"},
                       {"mail", "real mail 01", "fields", "yes", "match", "-", "-", "123000"},
                       {"sharepoint", "rp-canary-01.pdf", "manifest", "yes", "match", "-", "-",
                        "246000"},
                   }) + kCheckLineOfThree + status));
    }
    // Said once on stderr, in fixed words, before the status line; then, at
    // the end, that no file was written.
    CHECK(count_of(run.err, "result error: ") == 1);
    CHECK_THAT(run.err, ContainsSubstring(c.result_error));
    CHECK_THAT(run.err, EndsWith("json error: " + lab.json_arg() + kNotValid));
    CHECK_THAT(run.err, !ContainsSubstring("Fake"));
    CHECK_THAT(run.out, !ContainsSubstring("wrote "));
    CHECK(writes == 0);
    CHECK_FALSE(std::filesystem::exists(lab.json_path()));
}

TEST_CASE("test: without --json a result that isn't valid is still error result_invalid, and "
          "nothing is said of a file",
          "[test_command][result]")
{
    TestLab lab;
    lab.fake.info.name = "Fake Connector";

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "result error: 1 schema violation(s), first at /connector/type\n");
    CHECK_THAT(lab.body(run),
               EndsWith("\nstatus error result_invalid: the result isn't valid "
                        "restoreproof.result.v1; the run itself ended pass\n" +
                        clean_after_line(1, 0, 0)));
}

TEST_CASE("test --json: a result that is valid when the status is decided and isn't at the end "
          "keeps its status line; no file, exit 0 becomes 1, any other code is kept",
          "[test_command][json][result]")
{
    const auto [outcome, code] = GENERATE(table<std::string, int>({
        {"pass", rp::exit_code::config},
        {"fail", rp::exit_code::restore},
    }));
    CAPTURE(outcome);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    if (outcome == "fail") {
        lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
    }
    // Only the reading for ended_at, once the clean after has handed on its
    // counts, is past the year 9999.
    lab.wall_now = [&lab] {
        return lab.cleanups.empty() ? rp::test::graph_lab::kNow : year_10000();
    };
    int writes = 0;
    lab.write_summary = [&](const std::filesystem::path&, std::string_view) {
        ++writes;
        return true;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0", "--json",
                             lab.json_arg()});

    INFO(run.out);
    CHECK(run.exit_code == code);
    CHECK(run.err == "result error: 1 schema violation(s), first at /ended_at\n"
                     "json error: " +
                         lab.json_arg() + kNotValid);
    // The status line was out before the result was finished, and stays.
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus " + outcome + ": "));
    CHECK_THAT(run.out, !ContainsSubstring("result_invalid"));
    CHECK(count_of(run.out, "\nstatus ") == 1);
    CHECK_THAT(run.out, !ContainsSubstring("wrote "));
    CHECK(writes == 0);
    CHECK_FALSE(std::filesystem::exists(lab.json_path()));
}

TEST_CASE("test --json: a `wrote` line that can't be written changes nothing, whether the stream "
          "throws or only fails: the file is written, exit 0 stays, stderr is empty",
          "[test_command][json]")
{
    const bool throwing = GENERATE(true, false);
    CAPTURE(throwing);
    const Args args{"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0"};
    // What the run prints before "wrote <file>": the same in any temp folder.
    std::size_t before_wrote = 0;
    {
        TestLab lab;
        Args with_json = args;
        const std::string json_arg = lab.json_arg();
        with_json.insert(with_json.end(), {"--json", json_arg});
        const Run run = lab.run(with_json);
        REQUIRE(run.exit_code == rp::exit_code::ok);
        before_wrote = lab.json_body(run).size() + timings_table(lab.timings.at(0)).size();
    }
    TestLab lab;
    Args with_json = args;
    const std::string json_arg = lab.json_arg();
    with_json.insert(with_json.end(), {"--json", json_arg});
    // A stdout that takes everything up to the file's line, then fails: the
    // hook's own write, after the file is written. std::cout only sets its
    // state; a stream told to throws.
    LimitedStreamBuf buffer(before_wrote);
    std::ostream out(&buffer);
    if (throwing) {
        out.exceptions(std::ios::badbit | std::ios::failbit);
    }

    const auto [code, err] = lab.run_to(with_json, out);

    // W3.6 review point 4, as for the timings' table.
    CHECK(code == rp::exit_code::ok);
    CHECK(err.empty());
    CHECK_THAT(buffer.text, ContainsSubstring("\nstatus pass: "));
    CHECK_THAT(buffer.text, !ContainsSubstring("wrote "));
    CHECK(lab.result().at("status").at("status") == "pass");
}

TEST_CASE("test --json: a result that isn't written changes no status; exit 0 becomes 1, any "
          "other code is kept",
          "[test_command][json]")
{
    const auto [how, outcome, code] = GENERATE(table<std::string, std::string, int>({
        {"returns false", "pass", rp::exit_code::config},
        {"throws", "pass", rp::exit_code::config},
        {"returns false", "fail", rp::exit_code::restore},
        {"throws", "fail", rp::exit_code::restore},
        {"returns false", "error", rp::exit_code::auth},
        {"throws", "error", rp::exit_code::auth},
    }));
    CAPTURE(how, outcome);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    std::vector<std::filesystem::path> asked;
    std::string given;
    lab.write_summary = [&, how = how](const std::filesystem::path& path,
                                       std::string_view text) -> bool {
        asked.push_back(path);
        given = text;
        if (how == "throws") {
            throw std::runtime_error("SENTINEL-DISK");
        }
        return text.empty();
    };
    if (outcome == "fail") {
        lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
    }
    if (outcome == "error") {
        const rp::HttpResponse denied = rp::test::load_fixture("graph", "site-403-accessdenied");
        lab.targets.fail = [denied](rp::connector::ItemKind kind,
                                    bool after) -> std::optional<rp::HttpResponse> {
            return after && kind == rp::connector::ItemKind::sharepoint ? std::optional{denied}
                                                                         : std::nullopt;
        };
    }

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0", "--json",
                             lab.json_arg()});

    CHECK(run.exit_code == code);
    CHECK_THAT(run.err, EndsWith("json error: " + lab.json_arg() + ": could not be written\n"));
    CHECK_THAT(run.err, !ContainsSubstring("SENTINEL"));
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus " + outcome));
    CHECK_THAT(run.out, !ContainsSubstring("wrote "));
    CHECK_THAT(run.err, !ContainsSubstring("result error"));
    REQUIRE(asked.size() == 1);
    CHECK(asked[0] == lab.json_path());
    // The writer was handed the canonical text, nothing after it.
    CHECK(given == rp::canonical_json(json::parse(given)));
    CHECK_FALSE(std::filesystem::exists(lab.json_path()));
}

TEST_CASE("test --json: a run ID that holds ':' never names the file or its temp: one file, "
          "nothing beside it",
          "[test_command][json]")
{
    TestLab lab;

    const Run run = lab.run({"--run-id", "rp:20261003:a", "--mail", "1", "--sp", "0", "--od", "0",
                             "--json", lab.json_arg()});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(lab.result().at("run_id") == "rp:20261003:a");
    std::set<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(lab.dir.path())) {
        names.insert(utf8(entry.path().filename()));
    }
    CHECK(names == std::set<std::string>{"canaries", "config.json", "run.json", "tsa-ca.pem"});
}

TEST_CASE("test --json: a file that appeared after the check is never overwritten",
          "[test_command][json]")
{
    TestLab lab;
    lab.fake.at_restore = [&lab] { lab.dir.write("run.json", "a scheduled script's"); };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0", "--json",
                             lab.json_arg()});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "json error: " + lab.json_arg() + ": could not be written\n");
    CHECK(file_bytes(lab.json_path()) == "a scheduled script's");
}

TEST_CASE("test --json: with stdout lost the file is still written, without its line; the exit "
          "code is 1 and the file doesn't say so",
          "[test_command][json]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    // The header fits; the tables don't.
    LimitedStreamBuf buffer(expected_header().size() + 5);
    std::ostream out(&buffer);

    const auto [code, err] = lab.run_to({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od",
                                         "0", "--json", lab.json_arg()},
                                        out);

    CHECK(code == rp::exit_code::config);
    CHECK_THAT(err, StartsWith("error: writing the output failed after the restore ran"));
    // The stream is bad from its first short write on, so the buffer can't
    // show a line written all the same; stderr, where the pipeline sends what
    // it must still say, can.
    CHECK_THAT(buffer.text, !ContainsSubstring("wrote "));
    CHECK_THAT(err, !ContainsSubstring("wrote "));
    const json result = lab.result();
    CHECK(keys_of(result) == kResultKeys);
    for (const std::string& key : kResultKeys) {
        CAPTURE(key);
        // No run folder under --json: nothing of one (W4.2).
        CHECK(result.at(key).is_null() == (key == "attachments" || key == "screenshot"));
    }
    // A fact of this process, not of the run (W4.1 point 1): the run passed.
    CHECK(result.at("status").at("status") == "pass");
    CHECK_FALSE(result.at("status").contains("error_code"));
}

TEST_CASE("test --json --record: a recording that isn't complete makes a pass exit 1; the file "
          "says pass and nothing of the recording",
          "[test_command][json][record]")
{
    namespace gl = rp::test::graph_lab;
    TestLab lab;
    // The recorder refuses an exchange that holds the Veeam password.
    json edited = rp::test::load_fixture_json("graph", "restoretarget-drive-200");
    edited["body"]["description"] = "Sentinel-Veeam-Password-9c2e";
    lab.targets.graph.on(rp::HttpMethod::get, gl::drive_url(), {rp::test::to_response(edited)});
    const std::filesystem::path rec = lab.dir.path() / "rec";

    const Run run = lab.run({"--run-id", kRunId, "--mail", "0", "--sp", "1", "--od", "0", "--json",
                             lab.json_arg(), "--record", utf8(rec)});

    INFO(run.out);
    CHECK(run.exit_code == rp::exit_code::config);
    CHECK_THAT(run.err, ContainsSubstring("record error: graph/"));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    const json result = lab.result();
    CHECK(keys_of(result) == kResultKeys);
    CHECK(result.at("status").at("status") == "pass");
}

TEST_CASE("test --json: started_at and ended_at are the wall clock where total starts and ends, "
          "cut to the millisecond",
          "[test_command][json]")
{
    using namespace std::chrono_literals;
    TestLab lab;
    // 1000.8 ms a reading: cut, not rounded, the second reading, 1.0008 s on, shows .000.
    std::vector<std::chrono::system_clock::time_point> readings;
    std::optional<std::chrono::system_clock::time_point> at_start;
    lab.wall_now = [&] {
        const auto now = rp::test::graph_lab::kNow +
                         std::chrono::duration_cast<std::chrono::system_clock::duration>(
                             1000800us * static_cast<long long>(readings.size()));
        readings.push_back(now);
        // total starts once the connector is made, before the first Veeam call.
        if (lab.make_connector_calls == 1 && lab.fake.points_calls == 0 && !at_start) {
            at_start = now;
        }
        return now;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0", "--json",
                             lab.json_arg()});

    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE(at_start);
    const auto text = [](std::chrono::system_clock::time_point t) {
        return std::format("{:%Y-%m-%dT%H:%M:%S}Z", std::chrono::floor<std::chrono::milliseconds>(t));
    };
    const json result = lab.result();
    // The certificate's check reads it first, before the connector.
    CHECK(*at_start == readings.at(1));
    CHECK(result.at("started_at") == "2026-09-28T12:00:01.000Z");
    CHECK(result.at("started_at") == text(*at_start));
    // The last reading is ended_at's: after the clean after, nothing reads it later.
    CHECK(result.at("ended_at") == text(readings.back()));
    CHECK(readings.size() > 2);
    CHECK(result.at("started_at").get<std::string>() < result.at("ended_at").get<std::string>());
}

TEST_CASE("test --json: a wall clock that fails for started_at and ended_at leaves them null and "
          "changes nothing else",
          "[test_command][json]")
{
    TestLab lab;
    lab.wall_now = [&lab] {
        // Throws only for the result's two readings: at total's start and
        // once the clean after has handed on its counts.
        if ((lab.make_connector_calls == 1 && lab.fake.points_calls == 0) || !lab.cleanups.empty()) {
            throw std::runtime_error("no clock");
        }
        return rp::test::graph_lab::kNow;
    };

    const Run run = lab.run({"--run-id", kRunId, "--mail", "1", "--sp", "0", "--od", "0", "--json",
                             lab.json_arg()});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK_THAT(lab.json_body(run), ContainsSubstring("\nstatus pass: "));
    const json result = lab.result();
    CHECK(result.at("started_at").is_null());
    CHECK(result.at("ended_at").is_null());
    CHECK(result.at("status").at("status") == "pass");
}

TEST_CASE("test --json --record: wrote <file>, then the recording's line, last; the recording "
          "says it came from test",
          "[test_command][json][record]")
{
    TestLab lab;
    const std::filesystem::path rec = lab.dir.path() / "rec";

    const Run run = lab.run({"--run-id", kRunId, "--mail", "0", "--sp", "1", "--od", "0", "--json",
                             lab.json_arg(), "--record", utf8(rec)});

    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    REQUIRE(lab.timings.size() == 1);
    const std::string tail = timings_table(lab.timings[0]) + "wrote " + lab.json_arg() + "\n";
    const std::size_t at = run.out.rfind(tail);
    REQUIRE(at != std::string::npos);
    const std::string last = run.out.substr(at + tail.size());
    CHECK_THAT(last, StartsWith("recorded "));
    CHECK_THAT(last, EndsWith(" exchange(s) in " + utf8(rec) + "\n"));
    CHECK(std::ranges::count(last, '\n') == 1);
    std::size_t files = 0;
    for (const auto& entry : std::filesystem::directory_iterator(rec / "graph")) {
        const json fixture = json::parse(*file_bytes(entry.path()));
        CHECK(fixture.at("source") == "rpworker " + std::string{rp::version()} + " test --record");
        ++files;
    }
    CHECK(files > 0);
}

TEST_CASE("test: a read-back SharePoint trimmed is error graph_permission, exit 2, never a fail "
          "for the restored item it hid (Q3.2 scenario 6)",
          "[test_command][q3.2]")
{
    // Live, 2026-10-04: the app's SharePoint roles revoked, Veeam restored the
    // file, the library's root counted it (childCount 1) and the listing came
    // back 200 and empty. That run said `status fail`, exit 5.
    namespace gl = rp::test::graph_lab;
    TestLab lab;
    lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
    lab.targets.graph.on(rp::HttpMethod::get, gl::library_root_url(),
                         [&lab](const rp::HttpRequest&) {
                             return gl::library_root(lab.targets.restored() ? 1 : 0);
                         });

    const Run run = lab.run({"--mail", "0", "--sp", "1", "--od", "0", "--run-id", kRunId});

    INFO(run.out);
    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::auth);
    CHECK_THAT(run.out, ContainsSubstring("\nrestore succeeded: 1 of 1 item(s) restored in "));
    CHECK_THAT(run.out,
               ContainsSubstring(check_table({{"sharepoint", "rp-canary-01.pdf", "manifest", "no",
                                               "error", "unchecked graph_permission",
                                               "graph_permission", "-"}}) +
                                 "\ncheck: 0 match, 0 mismatch, 0 missing, 1 error\n"));
    CHECK_THAT(run.out,
               ContainsSubstring("\nstatus error graph_permission: 1 of 1 item(s) couldn't be "
                                 "checked (graph_permission 1)\n"));
    CHECK_THAT(run.out, !ContainsSubstring("status fail"));
    // The clean after sees the same thing: it doesn't say the library is empty.
    CHECK_THAT(run.out,
               ContainsSubstring("\ncleanup after incomplete: deleted 0 mail, 0 sharepoint, 0 "
                                 "onedrive; sharepoint graph_permission\n"));
    CHECK_THAT(run.err,
               ContainsSubstring("check error: Graph listed 0 of the 1 entries in the "
                                 "RestoreTarget library: SharePoint leaves out what the app may "
                                 "not read instead of refusing the listing; the Worker app relies "
                                 "on Sites.Selected read on the test site; see "
                                 "docs/security/graph-permissions.md\n"));
    CHECK_THAT(run.err,
               ContainsSubstring("cleanup error: sharepoint: Microsoft Graph refused a permission "
                                 "the cleanup relies on (graph_permission)\n"));
}

// --- shared/testdata/result-v1/valid.json ---------------------------------------------

namespace {

std::string lower(std::string text)
{
    std::ranges::transform(text, text.begin(), [](char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    });
    return text;
}

// The Harness runs on the lab tenant's own IDs and addresses (the Graph
// fixtures and lab/seed-manifest.json are recorded from it), and shared/ holds
// no tenant's: each is renamed here, in any ASCII case, before the text is
// compared with the shared document.
std::vector<std::pair<std::string, std::string>> shared_names()
{
    const rp::test::graph_lab::Lab_values& v = lab_values();
    std::string message_id;
    const json manifest = json::parse(lab_manifest_text());
    for (const json& entry : manifest.at("entries")) {
        if (entry.value("subject", "") == "RP-CANARY-0001") {
            message_id = entry.at("internet_message_id").get<std::string>();
        }
    }
    REQUIRE_FALSE(message_id.empty());
    return {
        {kTenant, "11111111-2222-3333-4444-555555555555"},
        {v.site_id, "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,"
                    "aaaaaaaa-0000-0000-0000-000000000002"},
        {v.library_id, "b!library"},
        {v.onedrive_drive_id, "b!onedrive"},
        {v.folder_id, "01FOLDER"},
        {message_id, "<RP-CANARY-0001@contoso.example>"},
        {"HrachyaHarutyunyan@", "admin@"},
        {kOrgName, "contoso.onmicrosoft.com"},
        // The lab Veeam server's repository, the first half of a restore
        // point's ID.
        {kLabRepositoryId, "bbbbbbbb-0000-4000-8000-000000000001"},
        // W4.11: what the client check resolved (client.resolved): the
        // OneDrive's and the site's URLs, the Inbox's ID and the list's.
        {"alice_restoreprooflab_onmicrosoft_com", "alice_contoso_onmicrosoft_com"},
        {"restoreprooflab-my.sharepoint.com", "contoso-my.sharepoint.com"},
        {"restoreprooflab.sharepoint.com", "contoso.sharepoint.com"},
        {rp::test::load_fixture_json("graph", "mailbox-inbox-200").at("body").at("id"),
         "AAMkADAwMDAwMDAwLUluYm94"},
        {rp::test::load_fixture_json("graph", "restoretarget-drive-200")
             .at("body")
             .at("sharePointIds")
             .at("listId"),
         "cccccccc-0000-0000-0000-000000000003"},
    };
}

// `value` with every string value renamed; keys are the schema's and stay.
json renamed(const json& value, const std::vector<std::pair<std::string, std::string>>& names)
{
    if (value.is_string()) {
        std::string text = value.get<std::string>();
        for (const auto& [from, to] : names) {
            const std::string needle = lower(from);
            for (std::size_t at = lower(text).find(needle); at != std::string::npos;
                 at = lower(text).find(needle, at + to.size())) {
                text.replace(at, from.size(), to);
            }
        }
        return text;
    }
    if (value.is_structured()) {
        json out = value;
        for (json& member : out) {
            member = renamed(member, names);
        }
        return out;
    }
    return value;
}

// What shared/testdata/result-v1/valid.json holds: the run folder's
// result.json (W4.2: with its two attachments, their hashes the Harness
// run's own, and no screenshot: the setting is off) of a pass
// through the whole pipeline, a canary and a random item of each type (the
// SharePoint canary by office-v1, the random SharePoint file restored twice,
// the random OneDrive file an Office one with a name outside ASCII), with the
// lab's names renamed and the version pinned, as canonical-json-v1. The run
// ID and both clocks are the Harness's, so the text is the same every time.
std::string shared_result()
{
    using rp::connector::ItemKind;
    TestLab lab;
    // The manifest's hash is in the result: LF, however the checkout has it.
    std::string manifest = lab_manifest_text();
    std::erase(manifest, '\r');
    lab.write_manifest(manifest);
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.pool.sharepoint = {
        {{lab_values().site_id, "b!madeUpSourceLibraryDrive", "/Projects", "report.pdf",
          "0b5e1d2c-0000-4000-8000-00000000c0de"},
         1234}};
    lab.fake.pool.onedrive = {{{kCarol, "/Projects", "\xC3\x9C" "bersicht.docx"}, 9000}};
    // What the draw looked into, as a connector that browses reports it.
    lab.fake.pool.mail_browse = {.containers_eligible = 3,
                                 .containers_listed = {kCarol},
                                 .folders_listed = 2};
    lab.fake.pool.sharepoint_browse = {.containers_eligible = 2,
                                       .containers_listed = {lab_values().site_id},
                                       .folders_listed = 4};
    lab.fake.pool.onedrive_browse = {.containers_eligible = 3,
                                     .containers_listed = {kCarol},
                                     .containers_unresolved = 1,
                                     .folders_listed = 1,
                                     .short_of_containers = true};
    lab.fake.answer = [&lab](const rp::connector::RestoreSpec& spec) {
        rp::connector::RestoreResult result = restored(spec);
        for (rp::connector::RestoreSessionResult& session : result.sessions) {
            // The OneDrive session's details aren't the backup's counts: null.
            session.details = session.kind == ItemKind::onedrive ? "see the session's log"
                                                                 : "2 items processed (2 successes)";
            session.submit_time = std::chrono::seconds{2};
            session.wait_time = std::chrono::seconds{40};
            // W4.2: a line per session for veeam-session.log.
            result.log += "session " + session.id + " (" +
                          std::string{rp::connector::to_string(session.kind)} + "): Success, " +
                          session.details + "\n";
        }
        json copies = lab.targets.mirror(ItemKind::sharepoint);
        json again = copies.back();
        again["id"] = "restored-sharepoint-again";
        copies.push_back(again);
        lab.targets.after[kind_slot(ItemKind::sharepoint)] = copies;
        return result;
    };

    const Run run = lab.run({"--run-id", "rp-20261004T100000Z-0a1b2c3d", "--canary-cursor",
                             "0,1,0", "--mail", "2", "--sp", "2", "--od", "2", "--evidence",
                             lab.evidence_arg()});

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    json document =
        renamed(lab.evidence_result("rp-20261004T100000Z-0a1b2c3d"), shared_names());
    document["worker_version"] = "0.0.0";
    return rp::canonical_json(document);
}

constexpr const char* kSharedResult = "testdata/result-v1/valid.json";

} // namespace

// --- --evidence: the run folder (W4.2) ------------------------------------------------

namespace {

const Args kThree{"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"};

// `args`, then --evidence <the temp root>.
Run evidence_run(TestLab& lab, Args args = kThree)
{
    const std::string root = lab.evidence_arg();
    // kThree's second mail is a random one: no shortfall warning.
    if (lab.fake.pool.mail.empty()) {
        lab.fake.pool.mail = {carol_mail(1)};
    }
    args.push_back("--evidence");
    args.push_back(root);
    return lab.run(args);
}

std::set<std::string> names_in(const std::filesystem::path& folder)
{
    std::set<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        names.insert(utf8(entry.path().filename()));
    }
    return names;
}

const std::set<std::string> kTextFiles{"items.csv", "veeam-session.log"};
// W4.3: a complete folder, signed.
const std::set<std::string> kUnstampedFolder{"items.csv", "result.json", "signature.json",
                                             "veeam-session.log"};
// W4.4: and timestamped.
const std::set<std::string> kSignedFolder{"items.csv", "result.json", "signature.json",
                                          "timestamp.tst", "veeam-session.log"};
// The Harness's TSA stamps the Harness's wall clock.
const std::string kStampedAt = "2026-09-28T12:00:00Z";

const std::string kPng = std::string{"\x89PNG\r\n\x1a\n"} + "a picture";

// What `rpworker signer verify` will say of the folder under the Harness's
// public key (RFC 8032's test key 1): the stage-2 folder verifier on the
// folder's own files.
rp::Verification verify_folder(const std::filesystem::path& folder,
                               std::string_view key_base64 = rp::test::kSigningKey1Base64)
{
    const rp::SigningKey key = rp::test::signing_key(key_base64);
    const rp::PublicKey public_key = rp::test::public_key_of(key);
    const std::optional<std::vector<std::string>> names = rp::list_folder(folder);
    REQUIRE(names);
    return rp::Signer::verify_folder(rp::folder_reader(folder), *names, public_key);
}

// The two lines that end a signed run's stdout: the signature's, with the
// SHA-256 of result.json as it is on disk and the Harness key's ID, then the
// folder's.
// With `stamped_at` (W4.4) the timestamp's line between them and its file in
// the list; empty for a run that got no token.
std::string signed_lines(const std::filesystem::path& folder, bool screenshot = false,
                         const std::string& stamped_at = kStampedAt)
{
    const std::optional<std::string> result = file_bytes(folder / "result.json");
    REQUIRE(result);
    return "signed " + rp::sha256_hex(*result) + " key " + rp::test::signing_key().key_id() +
           "\n" + (stamped_at.empty() ? "" : "timestamped " + stamped_at + "\n") + "evidence " +
           utf8(folder) + ": result.json, signature.json, " +
           (stamped_at.empty() ? "" : "timestamp.tst, ") + "items.csv, " +
           "veeam-session.log" + (screenshot ? ", screenshot.png" : "") + "\n";
}

} // namespace

TEST_CASE("test --evidence: a --run-id that can't name a folder is a config error once the "
          "config is read, before the secrets",
          "[test_command][evidence]")
{
    const std::string run_id = GENERATE("rp:20261003:a", ".", "..", "CON", "aux.1", "run.");
    CAPTURE(run_id);
    TestLab lab;

    const Run run = evidence_run(lab, {"--run-id", run_id, "--mail", "1"});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "config error: --evidence: the run ID can't name a folder\n");
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.lock_calls == 0);
    CHECK(lab.make_connector_calls == 0);
    CHECK_FALSE(std::filesystem::exists(lab.evidence_root()));
}

TEST_CASE("test --evidence: a root that isn't a UTF-8 path is a config error",
          "[test_command][evidence]")
{
    TestLab lab;

    const Run run = lab.run({"--evidence", "\xff", "--run-id", kRunId});

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "config error: --evidence \xff: not a UTF-8 path\n");
    CHECK(lab.load_secrets_calls == 0);
}

TEST_CASE("test --evidence: a run folder that is already there stops the run before its run "
          "line; nothing is restored and nothing in it is touched",
          "[test_command][evidence]")
{
    const std::string there = GENERATE("run-0001", "RUN-0001");
    TestLab lab;
    std::filesystem::create_directories(lab.evidence_root() / there);
    lab.dir.write(std::filesystem::path{"runs"} / there / "result.json", "an earlier run's");

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "evidence error: " + utf8(lab.run_folder()) +
                         ": the run folder already exists; nothing was done\n");
    CHECK(lab.fake.candidate_calls == 0);
    CHECK(lab.fake.restore_calls == 0);
    CHECK(lab.cleanups.empty());
    CHECK(lab.timings.empty());
    CHECK(names_in(lab.evidence_root() / there) == std::set<std::string>{"result.json"});
    CHECK(file_bytes(lab.evidence_root() / there / "result.json") == "an earlier run's");
}

TEST_CASE("test --evidence: a run folder that can't be made stops the run before its run line",
          "[test_command][evidence]")
{
    TestLab lab;

    SECTION("the root is a file")
    {
        lab.dir.write("runs", "a file");

        const Run run = evidence_run(lab);

        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.out.empty());
        CHECK(run.err == "evidence error: " + utf8(lab.run_folder()) +
                             ": the run folder couldn't be made; nothing was done\n");
    }
    SECTION("the run ID the run made can't name a folder")
    {
        lab.generated_run_id = "rp:made";

        const Run run = evidence_run(lab, {"--mail", "1"});

        CHECK(run.exit_code == rp::exit_code::config);
        CHECK(run.out.empty());
        CHECK(run.err == "evidence error: the run ID can't name a folder; nothing was done\n");
        CHECK_FALSE(std::filesystem::exists(lab.evidence_root()));
    }
    CHECK(lab.fake.restore_calls == 0);
    CHECK(lab.cleanups.empty());
}

TEST_CASE("test --evidence: a run whose run line can't be printed leaves no folder",
          "[test_command][evidence]")
{
    TestLab lab;
    rp::test::FailingStreamBuf buffer;
    std::ostream out(&buffer);
    const std::string root = lab.evidence_arg();

    const auto [code, err] =
        lab.run_to({"--run-id", kRunId, "--mail", "1", "--evidence", root}, out);

    CHECK(code != rp::exit_code::ok);
    CHECK(lab.fake.restore_calls == 0);
    CHECK(lab.timings.empty());
    CHECK_FALSE(std::filesystem::exists(lab.run_folder()));
    // Nor the runs root that was made for it.
    CHECK_FALSE(std::filesystem::exists(lab.evidence_root()));
}

TEST_CASE("test --evidence: a file that can't be written changes no status; exit 0 becomes 1, "
          "any other is kept, and there is no result.json",
          "[test_command][evidence]")
{
    const auto [refused, outcome, code] = GENERATE(table<std::string, std::string, int>({
        {"items.csv", "pass", rp::exit_code::config},
        {"veeam-session.log", "pass", rp::exit_code::config},
        // W4.3: the signature's file, written before the result's.
        {"signature.json", "pass", rp::exit_code::config},
        {"signature.json", "fail", rp::exit_code::restore},
        {"result.json", "pass", rp::exit_code::config},
        {"result.json", "fail", rp::exit_code::restore},
    }));
    CAPTURE(refused, outcome);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    if (outcome == "fail") {
        lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
    }
    const std::string refused_name = refused;
    lab.write_evidence_file = [&](const std::filesystem::path& path, std::string_view content) {
        if (utf8(path.filename()) == refused_name) {
            return false;
        }
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };

    const Run run = evidence_run(lab);

    INFO(run.out);
    CHECK(run.exit_code == code);
    CHECK(run.err == "evidence error: " + utf8(lab.run_folder() / refused) +
                         ": could not be written\n");
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus " + outcome + ": "));
    CHECK_THAT(run.out, !ContainsSubstring("evidence "));
    CHECK_THAT(run.out, !ContainsSubstring("signed "));
    CHECK_FALSE(std::filesystem::exists(lab.run_folder() / "result.json"));
    // Nor a signature beside no result: one written before a result.json
    // that then couldn't be is removed again.
    CHECK_FALSE(std::filesystem::exists(lab.run_folder() / "signature.json"));
}

TEST_CASE("test --evidence: an attachment missing or changed after it was hashed: no "
          "result.json, the status unchanged, exit 0 becomes 1",
          "[test_command][evidence]")
{
    const bool gone = GENERATE(false, true);
    TestLab lab({{"screenshots_enabled", true}});
    // The capturer runs once the text files are written and hashed.
    lab.capture_screenshot =
        [&](const rp::ScreenshotRequest& request) -> std::optional<rp::ScreenshotReason> {
        const std::filesystem::path csv = request.png.parent_path() / "items.csv";
        if (gone) {
            std::filesystem::remove(csv);
        } else {
            std::ofstream(csv, std::ios::binary | std::ios::app) << "9,\"added later\"\n";
        }
        return rp::ScreenshotReason::no_browser;
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "evidence error: " + utf8(lab.run_folder() / "items.csv") +
                         ": changed after it was hashed\n");
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus pass: "));
    CHECK_FALSE(std::filesystem::exists(lab.run_folder() / "result.json"));
}

TEST_CASE("test --evidence: a run that ended result_invalid leaves the text files and no "
          "result.json",
          "[test_command][evidence][result]")
{
    TestLab lab({{"screenshots_enabled", true}});
    lab.fake.info.name = "Fake Connector";
    // No result to list a screenshot: none is asked for.
    int captures = 0;
    lab.capture_screenshot =
        [&](const rp::ScreenshotRequest&) -> std::optional<rp::ScreenshotReason> {
        ++captures;
        return std::nullopt;
    };
    // W4.3: nor is anything signed.
    int signs = 0;
    lab.sign_result = [&](std::string_view canonical, const rp::SigningKey& key) {
        ++signs;
        return rp::Signer::sign(canonical, key);
    };

    const Run run = evidence_run(lab);

    CHECK(captures == 0);
    CHECK(signs == 0);
    CHECK_THAT(run.out, !ContainsSubstring("signed "));
    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "result error: 1 schema violation(s), first at /connector/type\n"
                     "evidence error: " +
                         utf8(lab.run_folder()) +
                         ": the result isn't valid restoreproof.result.v1; no result.json was "
                         "written\n");
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus error result_invalid: "));
    CHECK(names_in(lab.run_folder()) == kTextFiles);
    CHECK_THAT(*file_bytes(lab.run_folder() / "items.csv"),
               ContainsSubstring("\"RP-CANARY-0001\""));
}

TEST_CASE("test --evidence: a result that isn't valid at the end keeps its status line; the "
          "text files, no result.json, exit 0 becomes 1",
          "[test_command][evidence][result]")
{
    TestLab lab;
    lab.wall_now = [&lab] {
        return lab.cleanups.empty() ? rp::test::graph_lab::kNow : year_10000();
    };
    int signs = 0;
    lab.sign_result = [&](std::string_view canonical, const rp::SigningKey& key) {
        ++signs;
        return rp::Signer::sign(canonical, key);
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "result error: 1 schema violation(s), first at /ended_at\n"
                     "evidence error: " +
                         utf8(lab.run_folder()) +
                         ": the result isn't valid restoreproof.result.v1; no result.json was "
                         "written\n");
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus pass: "));
    CHECK(names_in(lab.run_folder()) == kTextFiles);
    CHECK(signs == 0);
}

TEST_CASE("test --evidence: a screenshot never changes the status or the exit code",
          "[test_command][evidence][screenshot]")
{
    using Capturer = rp::ScreenshotCapturer;
    const auto [name, enabled, capturer, expected] =
        GENERATE(table<std::string, bool, Capturer, json>({
            {"off: the capturer isn't asked", false,
             [](const rp::ScreenshotRequest&) -> std::optional<rp::ScreenshotReason> {
                 throw std::logic_error("asked");
             },
             json{{"state", "unavailable"}, {"reason", "disabled"}}},
            {"on, the default capturer", true, Capturer{},
             json{{"state", "unavailable"}, {"reason", "no_page"}}},
            {"it throws", true,
             [](const rp::ScreenshotRequest&) -> std::optional<rp::ScreenshotReason> {
                 throw std::runtime_error("the browser crashed");
             },
             json{{"state", "unavailable"}, {"reason", "failed"}}},
            {"it times out", true,
             [](const rp::ScreenshotRequest&) -> std::optional<rp::ScreenshotReason> {
                 return rp::ScreenshotReason::timeout;
             },
             json{{"state", "unavailable"}, {"reason", "timeout"}}},
            {"it needs a sign-in", true,
             [](const rp::ScreenshotRequest&) -> std::optional<rp::ScreenshotReason> {
                 return rp::ScreenshotReason::login_required;
             },
             json{{"state", "unavailable"}, {"reason", "login_required"}}},
            {"what it left isn't a PNG", true,
             [](const rp::ScreenshotRequest& request) -> std::optional<rp::ScreenshotReason> {
                 std::ofstream(request.png, std::ios::binary) << "<html>Sign in</html>";
                 return std::nullopt;
             },
             json{{"state", "unavailable"}, {"reason", "failed"}}},
        }));
    CAPTURE(name);
    TestLab lab({{"screenshots_enabled", enabled}});
    lab.capture_screenshot = capturer;

    const Run run = evidence_run(lab);

    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    const json result = lab.evidence_result();
    CHECK(result.at("screenshot") == expected);
    CHECK(result.at("attachments").size() == 2);
    CHECK(result.at("status").at("warnings").empty());
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
}

TEST_CASE("test --evidence: a captured screenshot is the third attachment",
          "[test_command][evidence][screenshot]")
{
    TestLab lab({{"screenshots_enabled", true}});
    std::vector<std::string> asked_for;
    lab.capture_screenshot =
        [&](const rp::ScreenshotRequest& request) -> std::optional<rp::ScreenshotReason> {
        asked_for = request.session_ids;
        std::ofstream(request.png, std::ios::binary) << kPng;
        return std::nullopt;
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::ok);
    const json result = lab.evidence_result();
    CHECK(result.at("screenshot") == json{{"state", "captured"}});
    REQUIRE(result.at("attachments").size() == 3);
    CHECK(result.at("attachments").at(1) ==
          json{{"name", "screenshot.png"},
               {"sha256", rp::sha256_hex(kPng)},
               {"size_bytes", kPng.size()}});
    CHECK(file_bytes(lab.run_folder() / "screenshot.png") == kPng);
    CHECK(asked_for == std::vector<std::string>{"sess-mail", "sess-sharepoint"});
    CHECK_THAT(run.out, EndsWith(signed_lines(lab.run_folder(), true)));
    // The screenshot is under the signature too.
    CHECK(rp::to_string(verify_folder(lab.run_folder()).word) == "verified");
    std::ofstream(lab.run_folder() / "screenshot.png", std::ios::binary | std::ios::app) << "x";
    CHECK(rp::to_string(verify_folder(lab.run_folder()).word) == "attachment_size");
}

TEST_CASE("test --evidence: a secret value in Veeam's words never reaches the run folder",
          "[test_command][evidence][secrets]")
{
    TestLab lab;
    lab.fake.answer = [](const rp::connector::RestoreSpec& spec) {
        rp::connector::RestoreResult result = restored(spec);
        result.log = "session sess-mail (mail): Success\n"
                     "Failed proxy: sign-in of rp-veeam with Sentinel-Veeam-Password-9c2e failed\n"
                     "Failed app: certificate password " +
                     std::string{rp::test::graph_lab::kPfxPassword} + " refused\n";
        return result;
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(file_bytes(lab.run_folder() / "veeam-session.log") ==
          "session sess-mail (mail): Success\n[withheld: held a secret value]\n"
          "[withheld: held a secret value]\n");
    CHECK_THAT(*file_bytes(lab.run_folder() / "veeam-session.log"),
               !ContainsSubstring(std::string{rp::test::graph_lab::kPfxPassword}));
    for (const auto& entry : std::filesystem::directory_iterator(lab.run_folder())) {
        CAPTURE(utf8(entry.path().filename()));
        CHECK_THAT(*file_bytes(entry.path()), !ContainsSubstring("Sentinel-Veeam-Password"));
    }
    CHECK_THAT(lab.log(), ContainsSubstring("SECURITY: evidence: 2 line(s) held a secret value "
                                            "and were withheld"));
    CHECK_THAT(lab.log(), !ContainsSubstring("Sentinel-Veeam-Password"));
    CHECK_THAT(run.out + run.err, !ContainsSubstring("Sentinel-Veeam-Password"));
}

TEST_CASE("test --evidence: a result that holds a secret value is never written: the text "
          "files, no result.json, the status unchanged, exit 0 becomes 1",
          "[test_command][evidence][secrets]")
{
    TestLab lab;
    // A real mail whose subject holds the Veeam password: the result names
    // every sampled item in expected.items.
    rp::connector::MailCandidate mail = carol_mail(1);
    mail.selector.subject = "fwd: Sentinel-Veeam-Password-9c2e";
    lab.fake.pool.mail = {mail};

    const Run run = evidence_run(lab);

    INFO(run.out);
    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "evidence error: " + utf8(lab.run_folder()) +
                         ": the result holds a secret value; no result.json was written\n");
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus pass: "));
    CHECK_THAT(run.out, !ContainsSubstring("evidence "));
    CHECK(names_in(lab.run_folder()) == kTextFiles);
    for (const auto& entry : std::filesystem::directory_iterator(lab.run_folder())) {
        CAPTURE(utf8(entry.path().filename()));
        CHECK_THAT(*file_bytes(entry.path()), !ContainsSubstring("Sentinel-Veeam-Password"));
    }
    CHECK_THAT(lab.log(), ContainsSubstring("SECURITY: evidence: the result held a secret value; "
                                            "no result.json was written"));
    CHECK_THAT(lab.log(), !ContainsSubstring("Sentinel-Veeam-Password"));
}

TEST_CASE("test --evidence: a run with no restore session asks for no screenshot",
          "[test_command][evidence][screenshot]")
{
    TestLab lab({{"screenshots_enabled", true}});
    lab.fake.candidates_throw = [] { throw rp::connector::TransientError("Veeam unreachable"); };
    lab.fake.pool.mail = {carol_mail(1)};
    int captures = 0;
    lab.capture_screenshot =
        [&](const rp::ScreenshotRequest& request) -> std::optional<rp::ScreenshotReason> {
        ++captures;
        std::ofstream(request.png, std::ios::binary) << kPng;
        return std::nullopt;
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::transient);
    CHECK(captures == 0);
    const json result = lab.evidence_result();
    CHECK(result.at("restore").is_null());
    CHECK(result.at("screenshot") == json{{"state", "unavailable"}, {"reason", "no_page"}});
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
}

TEST_CASE("test --evidence: a run that stops before the sample still leaves its folder: the "
          "header-only items.csv, an empty log and a valid result that lists them",
          "[test_command][evidence]")
{
    TestLab lab;
    lab.fake.candidates_throw = [] { throw rp::connector::TransientError("Veeam unreachable"); };
    lab.fake.pool.mail = {carol_mail(1)};

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::transient);
    const json result = lab.evidence_result();
    CHECK(result.at("status").at("error_code") == "backup_transient");
    CHECK(result.at("expected").is_null());
    CHECK(file_bytes(lab.run_folder() / "veeam-session.log") == "");
    CHECK(file_bytes(lab.run_folder() / "items.csv") ==
          "index,type,source,canary_id,name,expected_kind,sha256_rule,expected_sha256,"
          "found_sha256,restore_outcome,found,outcome,mismatches,verdict,code,ms\n");
    REQUIRE(result.at("attachments").size() == 2);
    CHECK(result.at("attachments").at(1) ==
          json{{"name", "veeam-session.log"}, {"sha256", rp::sha256_hex("")}, {"size_bytes", 0}});
}

// The Done-when (#45): a run folder contains result.json, the log, items.csv
// and (optionally) a PNG, each hashed in the result.
TEST_CASE("test --evidence: the run folder holds result.json, veeam-session.log and items.csv, "
          "each attachment with the hash and size the result lists; then its line, last",
          "[test_command][evidence][acceptance]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const std::string veeam_log =
        "session sess-mail (mail): Success, 2 items processed (2 successes)\n"
        "Success RP-CANARY-0001: Item RP-CANARY-0001 was restored successfully (type: IPM.Note; "
        "source: Alice Test\\Inbox; target: restoretest@RestoreProofLab.onmicrosoft.com\\Inbox)\n";
    lab.fake.answer = [&](const rp::connector::RestoreSpec& spec) {
        rp::connector::RestoreResult result = restored(spec);
        result.log = veeam_log;
        return result;
    };

    const Run run = evidence_run(lab);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
    CHECK(names_in(lab.evidence_root()) == std::set<std::string>{kRunId});

    // result.json: valid, canonical, the finished result (lab.evidence_result
    // REQUIREs the first two).
    const json result = lab.evidence_result();
    CHECK(keys_of(result) == kResultKeys);
    CHECK(result.at("run_id") == kRunId);
    CHECK(result.at("status").at("status") == "pass");
    CHECK(result.at("ended_at").is_string());
    CHECK(result.at("cleanup").at("after").is_object());
    CHECK(result.at("screenshot") == json{{"state", "unavailable"}, {"reason", "disabled"}});

    // Each attachment hashed in the result, and no other file.
    const json& attachments = result.at("attachments");
    REQUIRE(attachments.size() == 2);
    CHECK(attachments.at(0).at("name") == "items.csv");
    CHECK(attachments.at(1).at("name") == "veeam-session.log");
    for (const json& attachment : attachments) {
        const std::optional<std::string> bytes =
            file_bytes(lab.run_folder() / attachment.at("name").get<std::string>());
        REQUIRE(bytes);
        CHECK(attachment.at("sha256") == rp::sha256_hex(*bytes));
        CHECK(attachment.at("size_bytes") == bytes->size());
    }

    // The log is Veeam's words as the connector gave them; the CSV a row per
    // expected item, a found hash for the canaries only, equal to the
    // manifest's since they matched.
    CHECK(file_bytes(lab.run_folder() / "veeam-session.log") == veeam_log);
    const std::string csv = *file_bytes(lab.run_folder() / "items.csv");
    const json& expected = result.at("expected").at("items");
    REQUIRE(expected.size() == 3);
    const std::string mail_hash = expected.at(0).at("sha256").get<std::string>();
    const std::string file_hash = expected.at(2).at("sha256").get<std::string>();
    CHECK(csv ==
          "index,type,source,canary_id,name,expected_kind,sha256_rule,expected_sha256,"
          "found_sha256,restore_outcome,found,outcome,mismatches,verdict,code,ms\n"
          "0,\"mail\",\"canary\",\"" + expected.at(0).at("canary_id").get<std::string>() +
              "\",\"RP-CANARY-0001\",\"manifest\",\"text-v1\",\"" + mail_hash + "\",\"" + mail_hash +
              "\",\"restored\",\"yes\",\"match\",\"\",\"verified\",\"\",123000\n"
          "1,\"mail\",\"random\",\"\",\"real mail 01\",\"fields\",\"\",\"\",\"\",\"restored\","
          "\"yes\",\"match\",\"\",\"verified\",\"\",123000\n"
          "2,\"sharepoint\",\"canary\",\"" + expected.at(2).at("canary_id").get<std::string>() +
              "\",\"rp-canary-01.pdf\",\"manifest\",\"bytes\",\"" + file_hash + "\",\"" +
              file_hash + "\",\"restored\",\"yes\",\"match\",\"\",\"verified\",\"\",246000\n");

    // The signature's line and then the folder's are the last on stdout,
    // after the timings' table (W4.3).
    REQUIRE(lab.timings.size() == 1);
    CHECK_THAT(run.out,
               EndsWith(timings_table(lab.timings[0]) + signed_lines(lab.run_folder())));
}

TEST_CASE("test --evidence: a run ID the run made names its folder", "[test_command][evidence]")
{
    TestLab lab;

    const Run run = evidence_run(lab, {"--mail", "1", "--sp", "0", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(lab.evidence_result(kGeneratedRunId).at("run_id") == kGeneratedRunId);
}

TEST_CASE("test --evidence: the whole pipeline's result is shared/testdata/result-v1/valid.json, "
          "byte for byte, and names nothing of the lab tenant",
          "[test_command][evidence][json][result]")
{
    const std::string text = shared_result();
    const std::string file = rp::test::read_shared(kSharedResult);

    // After a deliberate change to the result: rptests "[.write_shared_result]".
    REQUIRE(text == file);
    const json document = json::parse(file);
    CHECK(file == rp::canonical_json(document));
    CHECK(rp::validate_result(document).valid);
    CHECK(keys_of(document) == kResultKeys);

    // The run it is: one of every item shape, all verified.
    CHECK(document.at("status").at("status") == "pass");
    CHECK(document.at("status").at("counts").at("items") == 6);
    CHECK(document.at("expected").at("counts") ==
          json{{"manifest", 3}, {"fields", 1}, {"metadata", 0}, {"backup_content", 2}});
    CHECK(document.at("expected").at("items").at(2).at("sha256_rule") == "office-v1");
    CHECK(document.at("expected").at("items").at(4).at("sha256_rule") == "bytes");
    CHECK(document.at("check").at("items").at(3).at("copies") == 2);
    CHECK(document.at("restore").at("sessions").size() == 3);
    CHECK(document.at("restore").at("sessions").at(2).at("details").is_null());
    CHECK(document.at("cleanup").at("after").at("sharepoint").at("deleted") == 3);
    CHECK(document.at("timings").at("spans").at("restore_wait") == json{{"ms", 120000}});
    CHECK(file.find("\xC3\x9C" "bersicht.docx") != std::string::npos);
    REQUIRE(document.at("attachments").size() == 2);
    CHECK(document.at("attachments").at(0).at("name") == "items.csv");
    CHECK(document.at("attachments").at(1).at("name") == "veeam-session.log");
    CHECK(document.at("screenshot") == json{{"state", "unavailable"}, {"reason", "disabled"}});

    // Nothing of the lab tenant, in any case.
    const std::string folded = lower(file);
    for (const auto& [name, unused] : shared_names()) {
        CAPTURE(name);
        CHECK(folded.find(lower(name)) == std::string::npos);
    }
    for (const char* word : {"restoreprooflab", "hrachya", "outlook.com"}) {
        CAPTURE(word);
        CHECK(folded.find(word) == std::string::npos);
    }
    // Nor of the lab's Veeam server: its repository's ID starts every
    // restore point ID of the lab.
    CHECK(folded.find(lower(kLabRepositoryId)) == std::string::npos);
}

// Hidden: run by name only, after a deliberate change to the result, to write
// the shared document again; shared/testdata/result-v1/cases.json and the
// Cloud's test read it.
TEST_CASE("write shared/testdata/result-v1/valid.json from the whole pipeline's run",
          "[.write_shared_result]")
{
    const std::string text = shared_result();
    std::ofstream file(std::filesystem::path{RP_SHARED_DIR} / kSharedResult,
                       std::ios::binary | std::ios::trunc);
    file << text;
    file.close();
    REQUIRE(file);
}

// --- --evidence signs the result (W4.3, docs/decisions.md 2026-10-05) ------------------
// The Harness's signing key is RFC 8032's published test key 1.

// The Done-when (#46), offline: a whole run's folder verifies under the
// Worker's public key, and no longer does once a byte of an item's hash is
// changed.
TEST_CASE("test --evidence: the run folder is signed: it verifies under the public key, and "
          "fails with hash_mismatch after one digit of an item's hash is changed",
          "[test_command][evidence][signing][acceptance]")
{
    TestLab lab;
    // Neither line is out before result.json is written.
    std::optional<std::string> out_at_result;
    std::vector<std::string> written;
    lab.write_evidence_file = [&](const std::filesystem::path& path, std::string_view content) {
        written.push_back(utf8(path.filename()));
        if (written.back() == "result.json") {
            out_at_result = lab.fake.out->str();
        }
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };

    const Run run = evidence_run(lab);

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(written == std::vector<std::string>{"items.csv", "veeam-session.log", "signature.json",
                                              "timestamp.tst", "result.json"});
    REQUIRE(names_in(lab.run_folder()) == kSignedFolder);
    REQUIRE(out_at_result);
    CHECK_THAT(*out_at_result, !ContainsSubstring("signed "));
    CHECK_THAT(*out_at_result, !ContainsSubstring("evidence "));

    // signature.json: its five keys, over the bytes of result.json as they
    // are on disk, by the Harness's key.
    const std::string result_text = *file_bytes(lab.run_folder() / "result.json");
    const std::string signature_text = *file_bytes(lab.run_folder() / "signature.json");
    const json signature = json::parse(signature_text);
    CHECK(signature_text == rp::canonical_json(signature));
    CHECK(keys_of(signature) ==
          std::set<std::string>{"algorithm", "bundle_sha256", "format", "key_id", "signature"});
    CHECK(signature.at("format") == "restoreproof.signature.v1");
    CHECK(signature.at("algorithm") == "ed25519");
    CHECK(signature.at("bundle_sha256") == rp::sha256_hex(result_text));
    CHECK(signature.at("key_id") == rp::test::signing_key().key_id());

    // The result never lists the signature, nor holds any of its fields.
    const json result = lab.evidence_result();
    CHECK(keys_of(result) == kResultKeys);
    REQUIRE(result.at("attachments").size() == 2);
    CHECK_THAT(result_text, !ContainsSubstring("signature"));

    // The two lines, last on stdout.
    REQUIRE(lab.timings.size() == 1);
    CHECK_THAT(run.out,
               EndsWith(timings_table(lab.timings[0]) + signed_lines(lab.run_folder())));

    // The folder verifier's answer, as `rpworker signer verify` will give it.
    const rp::Verification verified = verify_folder(lab.run_folder());
    CHECK(rp::to_string(verified.word) == "verified");
    CHECK(verified.bundle_sha256 == rp::sha256_hex(result_text));
    CHECK(verified.key_id == rp::test::signing_key().key_id());
    CHECK(verified.notes.empty());
    // Under another key it is that key's word.
    CHECK(rp::to_string(verify_folder(lab.run_folder(), rp::test::signing_key2_base64()).word) ==
          "wrong_key");

    // One digit of an item's hash changed: the file is still canonical and
    // still a valid result, and no longer the bytes that were signed.
    const std::string hash = result.at("expected").at("items").at(0).at("sha256");
    std::string edited = result_text;
    const std::size_t at = edited.find(hash);
    REQUIRE(at != std::string::npos);
    edited[at] = edited[at] == '0' ? '1' : '0';
    REQUIRE(rp::validate_result(json::parse(edited)).valid);
    std::ofstream(lab.run_folder() / "result.json", std::ios::binary | std::ios::trunc) << edited;
    CHECK(rp::to_string(verify_folder(lab.run_folder()).word) == "hash_mismatch");
}

TEST_CASE("test --evidence: a signing key that is unset or isn't one stops the run before its "
          "run line, before the schema, the manifest, the mutex and any Veeam call",
          "[test_command][evidence][signing]")
{
    using Key = std::optional<std::string>;
    const std::string not_set =
        "config error: signing_key_base64 is not in the vault; --evidence signs the result\n";
    const std::string not_a_key = "config error: signing_key_base64 is not an Ed25519 "
                                  "private key (Base64 of PKCS#8 DER)\n";
    const std::string seed{rp::test::kSigningSeed1Hex};
    const auto [name, key, line] = GENERATE_COPY(table<std::string, Key, std::string>({
        {"unset", std::nullopt, not_set},
        {"empty", std::string{}, not_set},
        {"not Base64", std::string{"SENTINEL not base64 !!"}, not_a_key},
        {"47 bytes", rp::test::pkcs8_base64(seed.substr(2)), not_a_key},
        {"49 bytes", rp::test::pkcs8_base64(seed + "00"), not_a_key},
        // X25519's header: another algorithm's key of the same length.
        {"another algorithm",
         rp::base64_encode(rp::test::bytes_from_hex("302e020100300506032b656e04220420" + seed)),
         not_a_key},
        {"the bare seed", rp::base64_encode(rp::test::bytes_from_hex(seed)), not_a_key},
        {"the PEM, not its body line",
         "-----BEGIN PRIVATE KEY-----\n" + std::string{rp::test::kSigningKey1Base64} +
             "\n-----END PRIVATE KEY-----\n",
         not_a_key},
        {"a line end after it", std::string{rp::test::kSigningKey1Base64} + "\n", not_a_key},
    }));
    CAPTURE(name);
    TestLab lab;
    const Key value = key;
    lab.load_secrets = [value] {
        return rp::Secrets{"rp-veeam", "Sentinel-Veeam-Password-9c2e",
                           rp::test::graph_lab::pfx_base64(),
                           std::string{rp::test::graph_lab::kPfxPassword}, value};
    };
    int schema_asked = 0;
    lab.schema_ready = [&] {
        ++schema_asked;
        return true;
    };
    // Said before a manifest that doesn't load, too.
    lab.write_manifest("{");

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == line);
    CHECK(lab.load_secrets_calls == 1);
    CHECK(schema_asked == 0);
    CHECK(lab.lock_calls == 0);
    CHECK(lab.make_connector_calls == 0);
    CHECK(lab.fake.points_calls == 0);
    CHECK(lab.timings.empty());
    CHECK_FALSE(std::filesystem::exists(lab.evidence_root()));
    CHECK_THAT(lab.log(), !ContainsSubstring("SENTINEL"));
}

TEST_CASE("test --evidence: the signing key is looked at only after the Graph certificate",
          "[test_command][evidence][signing]")
{
    TestLab lab;
    lab.load_secrets = [] {
        return rp::Secrets{"rp-veeam", "Sentinel-Veeam-Password-9c2e", std::nullopt,
                           std::nullopt, std::nullopt};
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "config error: graph_cert_pfx_base64 is not in the vault\n");
}

TEST_CASE("without --evidence the signing key is never parsed nor required, and nothing is "
          "signed",
          "[test_command][signing]")
{
    using Key = std::optional<std::string>;
    const std::string command = GENERATE("restore", "test", "test --json");
    const Key key = GENERATE(Key{}, Key{"NOT-A-KEY-7f3a !"});
    CAPTURE(command, key.has_value());
    TestLab lab;
    if (command == "restore") {
        lab.command = rp::run_restore_command;
    }
    lab.fake.pool.mail = {carol_mail(1)};
    lab.load_secrets = [key] {
        return rp::Secrets{"rp-veeam", "Sentinel-Veeam-Password-9c2e",
                           rp::test::graph_lab::pfx_base64(),
                           std::string{rp::test::graph_lab::kPfxPassword}, key};
    };
    int signs = 0;
    lab.sign_result = [&](std::string_view, const rp::SigningKey&) -> std::optional<rp::SignedResult> {
        ++signs;
        return std::nullopt;
    };
    Args args = kThree;
    const std::string json_arg = lab.json_arg();
    if (command == "test --json") {
        args.push_back("--json");
        args.push_back(json_arg);
    }

    const Run run = lab.run(args);

    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(signs == 0);
    CHECK_THAT(run.out, !ContainsSubstring("signed "));
    CHECK_THAT(run.out + run.err + lab.log(), !ContainsSubstring("NOT-A-KEY"));
    // --json is one file, unsigned: no signature beside it.
    CHECK(std::filesystem::exists(lab.json_path()) == (command == "test --json"));
    CHECK_FALSE(std::filesystem::exists(lab.dir.path() / "signature.json"));
    // The connector's copy of the secrets never holds the key's text.
    REQUIRE(lab.connector_secrets);
    CHECK_FALSE(lab.connector_secrets->signing_key_base64);
    CHECK(lab.connector_secrets->veeam_password == "Sentinel-Veeam-Password-9c2e");
}

TEST_CASE("test --evidence: the connector's copy of the secrets never holds the signing key",
          "[test_command][evidence][signing]")
{
    TestLab lab;

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::ok);
    REQUIRE(lab.connector_secrets);
    CHECK_FALSE(lab.connector_secrets->signing_key_base64);
    CHECK(lab.connector_secrets->graph_cert_pfx_base64 == rp::test::graph_lab::pfx_base64());
}

TEST_CASE("test --evidence: a result that can't be signed changes no status; exit 0 becomes 1, "
          "any other is kept; the text files, no signature.json and no result.json",
          "[test_command][evidence][signing]")
{
    const auto [outcome, code] = GENERATE(table<std::string, int>({
        {"pass", rp::exit_code::config},
        {"fail", rp::exit_code::restore},
    }));
    const bool throws = GENERATE(false, true);
    CAPTURE(outcome, throws);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    if (outcome == "fail") {
        lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
    }
    std::vector<std::string> signed_texts;
    lab.sign_result = [&](std::string_view canonical,
                          const rp::SigningKey& key) -> std::optional<rp::SignedResult> {
        // The run's own key, and the text that would have been written.
        signed_texts.emplace_back(canonical);
        if (key.key_id() != rp::test::signing_key().key_id()) {
            signed_texts.emplace_back("another key");
        }
        if (throws) {
            throw std::runtime_error("SENTINEL the key store");
        }
        return std::nullopt;
    };

    const Run run = evidence_run(lab);

    INFO(run.out);
    CHECK(run.exit_code == code);
    CHECK(run.err == "evidence error: " + utf8(lab.run_folder()) +
                         ": the result couldn't be signed; no result.json was written\n");
    CHECK_THAT(lab.body(run), ContainsSubstring("\nstatus " + outcome + ": "));
    CHECK_THAT(run.out, !ContainsSubstring("evidence "));
    CHECK_THAT(run.out, !ContainsSubstring("signed "));
    CHECK(names_in(lab.run_folder()) == kTextFiles);
    REQUIRE(signed_texts.size() == 1);
    const json asked = json::parse(signed_texts[0]);
    CHECK(signed_texts[0] == rp::canonical_json(asked));
    CHECK(rp::validate_result(asked).valid);
    CHECK(asked.at("status").at("status") == outcome);
}

TEST_CASE("test --evidence: a run that ended fail or error with a valid result is signed "
          "exactly as a pass is",
          "[test_command][evidence][signing]")
{
    const auto [status, code] = GENERATE(table<std::string, int>({
        {"fail", rp::exit_code::restore},
        {"error", rp::exit_code::transient},
    }));
    CAPTURE(status);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    if (status == "fail") {
        lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
    } else {
        lab.fake.candidates_throw = [] {
            throw rp::connector::TransientError("Veeam unreachable");
        };
    }

    const Run run = evidence_run(lab);

    INFO(run.out);
    CHECK(run.exit_code == code);
    CHECK(lab.evidence_result().at("status").at("status") == status);
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
    CHECK_THAT(run.out, EndsWith(signed_lines(lab.run_folder())));
    const rp::Verification verified = verify_folder(lab.run_folder());
    CHECK(rp::to_string(verified.word) == "verified");
    CHECK(verified.bundle_sha256 ==
          rp::sha256_hex(*file_bytes(lab.run_folder() / "result.json")));
}

TEST_CASE("test --evidence: with stdout lost the folder is still signed and written, without "
          "its two lines",
          "[test_command][evidence][signing]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    // The header fits; the tables don't.
    LimitedStreamBuf buffer(expected_header().size() + 5);
    std::ostream out(&buffer);
    const std::string root = lab.evidence_arg();
    Args args = kThree;
    args.push_back("--evidence");
    args.push_back(root);
    // A stream whose first short write set badbit takes nothing more, so the
    // buffer alone could never show the two lines (PR #158 review, finding
    // 14). The stream comes back right before they would be written: signing
    // is write_result's last step before them.
    int signs = 0;
    lab.sign_result = [&](std::string_view canonical, const rp::SigningKey& key) {
        ++signs;
        out.clear();
        buffer.lift();
        return rp::Signer::sign(canonical, key);
    };

    const auto [code, err] = lab.run_to(args, out);

    INFO(buffer.text);
    INFO(err);
    CHECK(code == rp::exit_code::config);
    CHECK(signs == 1);
    // The control: from the signing on, the buffer stores what it is given.
    out << "probe";
    out.flush();
    CHECK_THAT(buffer.text, EndsWith("probe"));
    CHECK_THAT(buffer.text, !ContainsSubstring("signed "));
    CHECK_THAT(buffer.text, !ContainsSubstring("evidence "));
    // Nor are they sent to stderr in stdout's place.
    CHECK_THAT(err, !ContainsSubstring("signed "));
    CHECK_THAT(err, !ContainsSubstring("evidence "));
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
    CHECK(rp::to_string(verify_folder(lab.run_folder()).word) == "verified");
}

// Point 3's sentinel: the key, as the variable carries it and as its seed
// would leak (Base64, hex), in no file of the folder, no --record fixture, no
// log line and neither stream, also when Veeam's words and a Graph answer
// hold it.
TEST_CASE("test --evidence --record: the signing key is in no file of the run folder, no "
          "fixture, no log line and neither stream",
          "[test_command][evidence][signing][secrets][record]")
{
    namespace gl = rp::test::graph_lab;
    const std::string key_text{rp::test::kSigningKey1Base64};
    const std::string seed_hex{rp::test::kSigningSeed1Hex};
    const std::string seed_base64 = rp::base64_encode(rp::test::bytes_from_hex(seed_hex));
    const std::vector<std::string> shapes{key_text, seed_base64, seed_hex};
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.fake.answer = [&](const rp::connector::RestoreSpec& spec) {
        rp::connector::RestoreResult result = restored(spec);
        result.log = "session sess-mail (mail): Success\n"
                     "Warning agent: environment RP_SIGNING_KEY_BASE64 " + key_text + "\n"
                     "Warning agent: seed " + seed_base64 + "\n"
                     "Warning agent: seed " + seed_hex + "\n";
        return result;
    };
    // An exchange that holds the key's text: the recorder refuses its file.
    json edited = rp::test::load_fixture_json("graph", "restoretarget-drive-200");
    edited["body"]["description"] = key_text;
    lab.targets.graph.on(rp::HttpMethod::get, gl::drive_url(), {rp::test::to_response(edited)});
    const std::filesystem::path rec = lab.dir.path() / "rec";
    const std::string rec_arg = utf8(rec);
    Args args = kThree;
    args.push_back("--record");
    args.push_back(rec_arg);

    const Run run = evidence_run(lab, args);

    INFO(run.out);
    INFO(run.err);
    // The recording isn't complete: a pass exits 1.
    CHECK(run.exit_code == rp::exit_code::config);
    CHECK_THAT(run.err, ContainsSubstring("record error: graph/"));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    // The signature's line, the folder's, then the recording's, last.
    CHECK_THAT(run.out, ContainsSubstring(signed_lines(lab.run_folder()) + "recorded "));
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
    CHECK(rp::to_string(verify_folder(lab.run_folder()).word) == "verified");
    CHECK(file_bytes(lab.run_folder() / "veeam-session.log") ==
          "session sess-mail (mail): Success\n[withheld: held a secret value]\n"
          "[withheld: held a secret value]\n[withheld: held a secret value]\n");
    CHECK_THAT(lab.log(), ContainsSubstring("SECURITY: evidence: 3 line(s) held a secret value "
                                            "and were withheld"));

    std::size_t files = 0;
    for (const std::filesystem::path& root : {lab.run_folder(), rec}) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            ++files;
            const std::string bytes = *file_bytes(entry.path());
            for (const std::string& shape : shapes) {
                CAPTURE(utf8(entry.path()), shape.size());
                CHECK(bytes.find(shape) == std::string::npos);
            }
        }
    }
    // The folder's four files and the recording's fixtures were looked at.
    CHECK(files > 8);
    const std::string said = run.out + run.err + lab.log();
    for (const std::string& shape : shapes) {
        CAPTURE(shape.size());
        CHECK(said.find(shape) == std::string::npos);
    }
}

TEST_CASE("test --evidence: a result that holds the signing key in any of its shapes is never "
          "written nor signed",
          "[test_command][evidence][signing][secrets]")
{
    const std::string seed_hex{rp::test::kSigningSeed1Hex};
    const std::string shape =
        GENERATE_COPY(std::string{rp::test::kSigningKey1Base64},
                      rp::base64_encode(rp::test::bytes_from_hex(seed_hex)), seed_hex);
    TestLab lab;
    rp::connector::MailCandidate mail = carol_mail(1);
    mail.selector.subject = "fwd: " + shape;
    lab.fake.pool.mail = {mail};
    int signs = 0;
    lab.sign_result = [&](std::string_view canonical, const rp::SigningKey& key) {
        ++signs;
        return rp::Signer::sign(canonical, key);
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "evidence error: " + utf8(lab.run_folder()) +
                         ": the result holds a secret value; no result.json was written\n");
    CHECK(signs == 0);
    CHECK(names_in(lab.run_folder()) == kTextFiles);
    for (const auto& entry : std::filesystem::directory_iterator(lab.run_folder())) {
        CAPTURE(utf8(entry.path().filename()));
        CHECK(file_bytes(entry.path())->find(shape) == std::string::npos);
    }
}

// --- W4.4: the timestamp -----------------------------------------------------------

namespace {

// kThree with --evidence <the lab's root>. Args are views: the root's text
// lives here, for as long as the run.
struct EvidenceRun {
    explicit EvidenceRun(const TestLab& lab) : root(lab.evidence_arg())
    {
        args.push_back("--evidence");
        args.push_back(root);
    }
    std::string root;
    Args args = kThree;
};

std::string not_timestamped(const TestLab& lab, std::string_view code, int attempts = 3)
{
    return "timestamp warning: " + utf8(lab.run_folder()) + ": not timestamped: " +
           std::string{code} + " after " + std::to_string(attempts) + " attempt(s)\n";
}

} // namespace

// Failure paths first: whatever the TSA does, the run is the run it was.
TEST_CASE("test --evidence: no token from the TSA is a warning; the folder is complete without "
          "one and the status, the exit code and the result are the same run's",
          "[test_command][evidence][timestamp]")
{
    struct Row {
        const char* name;
        std::string code;
        std::function<rp::HttpResponse(const rp::HttpRequest&)> answer;
    };
    const Row row = GENERATE_COPY(
        Row{"unreachable", "tsa_unreachable",
            [](const rp::HttpRequest&) -> rp::HttpResponse {
                throw rp::HttpError("POST http://tsa.test/stamp: could not connect",
                                    rp::TransportError::connect, 0, 1);
            }},
        Row{"503", "tsa_http_status",
            [](const rp::HttpRequest&) {
                return rp::test::make_response(503, "busy", "text/plain");
            }},
        Row{"a malformed answer", "tsa_response_malformed",
            [](const rp::HttpRequest&) {
                return rp::test::make_response(200, "<html>maintenance</html>", "text/html");
            }},
        Row{"a rejection", "tsa_rejected",
            [](const rp::HttpRequest&) {
                return rp::test::make_response(200, rp::test::TestTsa::rejection(),
                                               "application/timestamp-reply");
            }},
        Row{"a token over another hash", "tsa_imprint_mismatch",
            [](const rp::HttpRequest&) {
                static const rp::test::TestTsa other_request;
                return rp::test::make_response(
                    200,
                    other_request.respond(rp::openssl_rfc3161().request(rp::test::kDigestAbc, 8)),
                    "application/timestamp-reply");
            }},
        Row{"an untrusted TSA", "tsa_untrusted", [](const rp::HttpRequest& request) {
                static const rp::test::TestTsa other("another test root (not a secret)");
                return rp::test::make_response(200, other.respond(request.body),
                                               "application/timestamp-reply");
            }});
    CAPTURE(row.name);
    // The same run with a TSA that answers, to compare with.
    TestLab with;
    with.fake.pool.mail = {carol_mail(1)};
    const Run stamped = with.run(EvidenceRun(with).args);
    REQUIRE(stamped.exit_code == rp::exit_code::ok);

    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.tsa_answer = row.answer;
    lab.timestamp_nonce = [] { return std::optional<std::uint64_t>{8}; };

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code == stamped.exit_code);
    CHECK(run.err == not_timestamped(lab, row.code));
    CHECK(names_in(lab.run_folder()) == kUnstampedFolder);
    CHECK_THAT(run.out, EndsWith(signed_lines(lab.run_folder(), false, "")));
    CHECK_THAT(run.out, !ContainsSubstring("timestamped "));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    // The result is the same document: nothing in it knows of the TSA.
    CHECK(lab.evidence_result() == with.evidence_result());
    CHECK(lab.tsa_http.requests().size() == 3);
    CHECK(rp::to_string(verify_folder(lab.run_folder()).word) == "verified");
}

TEST_CASE("test --evidence: the run mutex is held through the clean after and released before the "
          "TSA is asked",
          "[test_command][evidence][timestamp][cleanup]")
{
    // The wait for a TSA that is down is a minute and a half: the restore
    // targets are idle by then, and the next run must not be refused for it.
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    std::vector<bool> held_at_delete;
    std::vector<bool> held_at_tsa;
    lab.targets.at_delete = [&] { held_at_delete.push_back(lab.lock_held); };
    lab.tsa_answer = [&](const rp::HttpRequest&) {
        held_at_tsa.push_back(lab.lock_held);
        return rp::test::make_response(503, "busy", "text/plain");
    };

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == not_timestamped(lab, "tsa_http_status"));
    REQUIRE_FALSE(held_at_delete.empty());
    CHECK(std::ranges::all_of(held_at_delete, [](bool held) { return held; }));
    CHECK(held_at_tsa == std::vector<bool>{false, false, false});
    CHECK(lab.lock_calls == 1);
}

TEST_CASE("test --evidence: a token that can't be written is a warning too",
          "[test_command][evidence][timestamp]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.write_evidence_file = [&lab](const std::filesystem::path& path, std::string_view content) {
        if (path.filename() == "timestamp.tst") {
            return false;
        }
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == not_timestamped(lab, "timestamp_not_written", 1));
    CHECK(names_in(lab.run_folder()) == kUnstampedFolder);
    CHECK_THAT(run.out, EndsWith(signed_lines(lab.run_folder(), false, "")));
}

TEST_CASE("test --evidence: a tsa_ca_file that holds no certificate is a config error before "
          "anything is done",
          "[test_command][evidence][timestamp]")
{
    TestLab lab;
    const std::string what = GENERATE("empty", "a key", "gone");
    CAPTURE(what);
    const std::filesystem::path ca = lab.dir.path() / "tsa-ca.pem";
    if (what == "gone") {
        // There when the config was read, a folder now: nothing to read.
        std::filesystem::remove(ca);
    } else {
        std::ofstream(ca, std::ios::binary | std::ios::trunc)
            << (what == "empty" ? std::string{} : lab.tsa.tsa_key_pem_text());
    }

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    if (what == "gone") {
        CHECK_THAT(run.err, StartsWith("config error: "));
        CHECK_THAT(run.err,
                   EndsWith("config key \"tsa_ca_file\" names a file that can't be read\n"));
    } else {
        CHECK(run.err == "config error: config key \"tsa_ca_file\" names a file that holds no "
                         "certificate (PEM)\n");
    }
    CHECK(lab.make_connector_calls == 0);
    CHECK(lab.lock_calls == 0);
    CHECK(lab.tsa_clients == 0);
    CHECK_FALSE(std::filesystem::exists(lab.evidence_root()));
}

TEST_CASE("only --evidence asks the TSA: restore, test and test --json never do",
          "[test_command][timestamp]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    // Nor do they read its CA file: one that holds no certificate stops nothing.
    std::ofstream(lab.dir.path() / "tsa-ca.pem", std::ios::binary | std::ios::trunc) << "x";
    const std::string json_arg = lab.json_arg();
    Args args = kThree;
    SECTION("test") {}
    SECTION("test --json")
    {
        args.push_back("--json");
        args.push_back(json_arg);
    }
    SECTION("restore")
    {
        lab.command = rp::run_restore_command;
    }

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(lab.tsa_clients == 0);
    CHECK(lab.tsa_http.requests().empty());
    CHECK_THAT(run.out, !ContainsSubstring("timestamped"));
}

// The happy path.
TEST_CASE("test --evidence: the folder is timestamped: timestamp.tst is the TSA's token over "
          "result.json's own hash, and its line comes between the signature's and the folder's",
          "[test_command][evidence][timestamp][acceptance]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    std::vector<std::string> written;
    lab.write_evidence_file = [&](const std::filesystem::path& path, std::string_view content) {
        written.push_back(path.filename().string());
        lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
        return true;
    };

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    REQUIRE(names_in(lab.run_folder()) == kSignedFolder);
    CHECK(written == std::vector<std::string>{"items.csv", "veeam-session.log", "signature.json",
                                              "timestamp.tst", "result.json"});
    const std::string result = *file_bytes(lab.run_folder() / "result.json");
    const std::string token = *file_bytes(lab.run_folder() / "timestamp.tst");
    CHECK_THAT(run.out, EndsWith(timings_table(lab.timings[0]) +
                                 "signed " + rp::sha256_hex(result) + " key " +
                                 rp::test::signing_key().key_id() + "\ntimestamped " + kStampedAt +
                                 "\nevidence " + utf8(lab.run_folder()) +
                                 ": result.json, signature.json, timestamp.tst, items.csv, "
                                 "veeam-session.log\n"));

    // One request, as the Timestamper sends it.
    CHECK(lab.tsa_clients == 1);
    const std::vector<rp::HttpRequest> requests = lab.tsa_http.requests();
    REQUIRE(requests.size() == 1);
    CHECK(requests.front().url == "http://tsa.test/stamp");
    CHECK(requests.front().content_type == "application/timestamp-query");

    // The token: one TimeStampToken over the SHA-256 of result.json's bytes,
    // which verifies under the test root and under no other.
    const std::optional<rp::TimestampTokenInfo> info = rp::openssl_rfc3161().parse_token(token);
    REQUIRE(info);
    CHECK(info->sha256);
    CHECK(rp::test::hex_from_bytes(info->imprint) == rp::sha256_hex(result));
    CHECK(rp::timestamp_time_text(info->gen_time) == kStampedAt);
    CHECK(rp::openssl_rfc3161().verify_token(token, lab.tsa.root_pem()));
    CHECK_FALSE(rp::openssl_rfc3161().verify_token(token, rp::default_tsa_ca_pem()));

    // Neither the result nor the signature knows of it.
    CHECK_THAT(result, !ContainsSubstring("timestamp"));
    CHECK_THAT(result, !ContainsSubstring("tsa"));
    CHECK(json::parse(*file_bytes(lab.run_folder() / "signature.json")).size() == 5);
    CHECK(keys_of(lab.evidence_result()).size() == 17);
}

TEST_CASE("test --evidence: a run that ends fail or error is timestamped as a pass is",
          "[test_command][evidence][timestamp]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    // The restored mail's body isn't the canary's.
    lab.targets.after[0] = json::array();

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code != rp::exit_code::ok);
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
    CHECK_THAT(run.out, ContainsSubstring("\ntimestamped " + kStampedAt + "\n"));
}

TEST_CASE("test --evidence: a clock more than two minutes from the TSA's is said, and the token "
          "is taken all the same",
          "[test_command][evidence][timestamp]")
{
    const int apart = GENERATE(-300, -121, 121, 86400);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.tsa.time += apart;

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == "timestamp warning: the TSA's time and this machine's clock differ by " +
                         std::to_string(apart < 0 ? -apart : apart) + " s\n");
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
}

TEST_CASE("test --evidence: two minutes from the TSA's clock is not said",
          "[test_command][evidence][timestamp]")
{
    const int apart = GENERATE(-120, -80, 0, 120);
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    lab.tsa.time += apart;

    const Run run = lab.run(EvidenceRun(lab).args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
}

TEST_CASE("test --evidence --record: the TSA's exchange is the recording's tsa folder, both "
          "bodies as Base64, and replays",
          "[test_command][evidence][timestamp][record]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const std::filesystem::path recording = lab.dir.path() / "rec";
    const EvidenceRun evidence(lab);
    const std::string record_arg = utf8(recording);
    Args args = evidence.args;
    args.push_back("--record");
    args.push_back(record_arg);

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    REQUIRE(std::filesystem::is_directory(recording / "tsa"));
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(recording / "tsa")) {
        files.push_back(entry.path());
    }
    REQUIRE(files.size() == 1);
    CHECK(files.front().filename() == "001-post-stamp.json");
    const json fixture = json::parse(*file_bytes(files.front()));
    CHECK(fixture.at("request") == "POST /stamp");
    CHECK(fixture.at("status") == 200);
    CHECK(fixture.at("body").is_null());
    // The answer's last bytes are the token the folder holds.
    const std::string answer = rp::test::to_response(fixture).body;
    CHECK(answer.ends_with(*file_bytes(lab.run_folder() / "timestamp.tst")));
    CHECK(rp::test::request_body_of(fixture) == lab.tsa_http.requests().front().body);
}

// --- W4.6: the outbox --------------------------------------------------------------

#include "outbox_lab.hpp"

#include <rp/outbox.hpp>
#include <rp/outbox_command.hpp>

namespace {

// kThree with --evidence <the lab's runs root> --outbox <a root beside it>.
struct OutboxRun {
    explicit OutboxRun(const TestLab& lab)
        : evidence(lab.evidence_arg()), root_path(lab.dir.path() / "rp"), root(utf8(root_path))
    {
        args.push_back("--evidence");
        args.push_back(evidence);
        args.push_back("--outbox");
        args.push_back(root);
    }
    std::filesystem::path queued(const std::string& run_id = kRunId) const
    {
        return root_path / "outbox" / run_id;
    }
    std::filesystem::path sent(const std::string& run_id = kRunId) const
    {
        return root_path / "sent" / run_id;
    }
    rp::OutboxManifest manifest() const
    {
        const std::optional<std::string> text = file_bytes(queued() / "manifest.json");
        REQUIRE(text);
        const std::optional<rp::OutboxManifest> read = rp::parse_manifest(*text, kRunId);
        REQUIRE(read);
        return *read;
    }
    std::string evidence;
    std::filesystem::path root_path;
    std::string root;
    Args args = kThree;
};

std::set<std::string> with_manifest(std::set<std::string> names)
{
    names.insert("manifest.json");
    return names;
}

} // namespace

// Failure paths first.
TEST_CASE("test --outbox: only with --evidence, and never empty", "[test_command][outbox]")
{
    TestLab lab;
    const std::string root = utf8(lab.dir.path() / "rp");
    const std::string json_arg = lab.json_arg();
    const std::string evidence_arg = lab.evidence_arg();
    Args args = kThree;
    SECTION("alone")
    {
        args.insert(args.end(), {"--outbox", root});
    }
    SECTION("with --json")
    {
        args.insert(args.end(), {"--outbox", root, "--json", json_arg});
    }
    SECTION("empty")
    {
        args.insert(args.end(), {"--evidence", evidence_arg, "--outbox", ""});
    }
    SECTION("twice")
    {
        args.insert(args.end(), {"--evidence", evidence_arg, "--outbox", root, "--outbox", root});
    }

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::usage);
    CHECK(run.out.empty());
    CHECK(run.err == kUsage);
    CHECK(lab.load_secrets_calls == 0);
    CHECK_FALSE(std::filesystem::exists(lab.dir.path() / "rp"));
}

TEST_CASE("test --outbox: a root that isn't a UTF-8 path is a config error before the secrets",
          "[test_command][outbox]")
{
    TestLab lab;
    const std::string evidence_arg = lab.evidence_arg();
    Args args = kThree;
    args.insert(args.end(), {"--evidence", evidence_arg, "--outbox", "bad-\xff"});

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK_THAT(run.err, StartsWith("config error: --outbox "));
    CHECK_THAT(run.err, EndsWith(": not a UTF-8 path\n"));
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.make_connector_calls == 0);
}

TEST_CASE("test --outbox: with --run-id, a run already queued or already sent is refused once the "
          "config is read, before the secrets; nothing is done",
          "[test_command][outbox]")
{
    TestLab lab;
    const OutboxRun outbox(lab);
    const bool in_sent = GENERATE(false, true);
    const std::filesystem::path there = in_sent ? outbox.sent() : outbox.queued();
    std::filesystem::create_directories(there);

    const Run run = lab.run(outbox.args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == "outbox error: " + utf8(there) +
                         (in_sent ? ": already sent" : ": already queued") +
                         "; nothing was done\n");
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.lock_calls == 0);
    CHECK(lab.make_connector_calls == 0);
    CHECK_FALSE(std::filesystem::exists(lab.evidence_root()));
    CHECK(std::filesystem::is_empty(there));
}

TEST_CASE("test --outbox: an outbox folder that can't be made, or an outbox on another volume "
          "than the runs root, is refused before the secrets; nothing is done",
          "[test_command][outbox]")
{
    TestLab lab;
    const OutboxRun outbox(lab);
    std::string expected;
    SECTION("the outbox root is a file")
    {
        lab.dir.write("rp", "a file");
        expected = "outbox error: " + utf8(outbox.root_path / "outbox") +
                   ": the folder couldn't be made; nothing was done\n";
    }
    SECTION("another volume")
    {
        lab.outbox_files.same_volume = [](const std::filesystem::path&,
                                          const std::filesystem::path&) {
            return std::optional<bool>{false};
        };
        expected = "outbox error: " + utf8(lab.evidence_root()) + ": not on the same volume as " +
                   utf8(outbox.root_path / "outbox") + "; nothing was done\n";
    }

    const Run run = lab.run(outbox.args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.out.empty());
    CHECK(run.err == expected);
    CHECK(lab.load_secrets_calls == 0);
    CHECK(lab.lock_calls == 0);
    CHECK(lab.make_connector_calls == 0);
    CHECK_FALSE(std::filesystem::exists(lab.evidence_root()));
}

TEST_CASE("test --outbox: a run already queued or already sent when the run ends (the ID the run "
          "made itself) is said; its folder stays in the runs root, complete, and the status stays",
          "[test_command][outbox]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const OutboxRun outbox(lab);
    // Without --run-id the check before the run has no ID to look for: the
    // one at the end is what catches it.
    const Args args{"--mail",     "2",  "--sp",     "1",           "--od",     "0",
                    "--evidence", outbox.evidence, "--outbox", outbox.root};
    const bool in_sent = GENERATE(false, true);
    const std::filesystem::path there =
        in_sent ? outbox.sent(kGeneratedRunId) : outbox.queued(kGeneratedRunId);
    std::filesystem::create_directories(there);

    const Run run = lab.run(args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "outbox error: " + utf8(there) +
                         (in_sent ? ": already sent\n" : ": already queued\n"));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    CHECK_THAT(run.out, EndsWith(signed_lines(lab.run_folder(kGeneratedRunId))));
    CHECK_THAT(run.out, !ContainsSubstring("queued "));
    CHECK(names_in(lab.run_folder(kGeneratedRunId)) == kSignedFolder);
    CHECK(rp::to_string(verify_folder(lab.run_folder(kGeneratedRunId)).word) == "verified");
    CHECK(std::filesystem::is_empty(there));
}

TEST_CASE("test --outbox: a folder that can't be moved stays where and as it is",
          "[test_command][outbox]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const OutboxRun outbox(lab);
    const unsigned long code = GENERATE(17ul, 32ul);
    lab.outbox_files.move_folder = [code](const std::filesystem::path&,
                                          const std::filesystem::path&) { return code; };

    const Run run = lab.run(outbox.args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "outbox error: " + utf8(lab.run_folder()) + ": couldn't be moved to " +
                         utf8(outbox.queued()) +
                         (code == 17 ? ": not on the same volume\n" : " (error 32)\n"));
    CHECK_THAT(run.out, EndsWith(signed_lines(lab.run_folder())));
    CHECK(names_in(lab.run_folder()) == kSignedFolder);
    CHECK_FALSE(std::filesystem::exists(outbox.queued()));
}

TEST_CASE("test --outbox: a manifest that can't be written leaves the run queued, and says so",
          "[test_command][outbox]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const OutboxRun outbox(lab);
    lab.outbox_files.write_manifest = [](const std::filesystem::path&, std::string_view) {
        return false;
    };

    const Run run = lab.run(outbox.args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "outbox error: " + utf8(outbox.queued() / "manifest.json") +
                         ": could not be written; the next flush makes it\n");
    CHECK_THAT(run.out, EndsWith("queued " + utf8(outbox.queued()) + "\n"));
    CHECK(names_in(outbox.queued()) == kSignedFolder);
    CHECK_FALSE(std::filesystem::exists(lab.run_folder()));
}

TEST_CASE("test --outbox: a run without a result.json is never queued", "[test_command][outbox]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const OutboxRun outbox(lab);
    // The result can't be signed: the two text files are all the folder gets.
    lab.sign_result = [](std::string_view, const rp::SigningKey&) {
        return std::optional<rp::SignedResult>{};
    };

    const Run run = lab.run(outbox.args);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK(run.err == "evidence error: " + utf8(lab.run_folder()) +
                         ": the result couldn't be signed; no result.json was written\n");
    CHECK_THAT(run.out, !ContainsSubstring("queued "));
    CHECK(names_in(lab.run_folder()) == kTextFiles);
    // <root>\outbox was made before the run; nothing went into it.
    CHECK(std::filesystem::is_empty(outbox.root_path / "outbox"));
    CHECK_FALSE(std::filesystem::exists(outbox.root_path / "sent"));
}

TEST_CASE("test --outbox: a run that got no token is queued as not timestamped, with the TSA's "
          "code in its manifest",
          "[test_command][outbox][timestamp]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const OutboxRun outbox(lab);
    lab.tsa_answer = [](const rp::HttpRequest&) {
        return rp::test::make_response(503, "busy", "text/plain");
    };

    const Run run = lab.run(outbox.args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == not_timestamped(lab, "tsa_http_status"));
    CHECK_THAT(run.out, EndsWith("queued " + utf8(outbox.queued()) + "\n"));
    CHECK(names_in(outbox.queued()) == with_manifest(kUnstampedFolder));
    const rp::OutboxManifest manifest = outbox.manifest();
    CHECK_FALSE(manifest.timestamped);
    CHECK(manifest.timestamp_code == "tsa_http_status");
    CHECK(manifest.files == std::vector<std::string>{"items.csv", "result.json", "signature.json",
                                                     "veeam-session.log"});
}

// The happy path, end to end: queued, kept while the Cloud is down, sent.
TEST_CASE("test --evidence --outbox: the signed run folder is queued with its manifest, a flush "
          "with the Cloud down keeps it, the next one sends it, and it still verifies",
          "[test_command][outbox][acceptance]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    const OutboxRun outbox(lab);
    bool held_at_move = true;
    lab.outbox_files.move_folder = [&](const std::filesystem::path& from,
                                       const std::filesystem::path& to) {
        held_at_move = lab.lock_held;
        std::error_code ec;
        std::filesystem::rename(from, to, ec);
        return ec ? 5ul : 0ul;
    };

    const Run run = lab.run(outbox.args);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    // The run mutex was let go before the folder was queued.
    CHECK_FALSE(held_at_move);
    CHECK_FALSE(std::filesystem::exists(lab.run_folder()));
    REQUIRE(names_in(outbox.queued()) == with_manifest(kSignedFolder));
    const std::string result = *file_bytes(outbox.queued() / "result.json");
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    CHECK_THAT(run.out,
               EndsWith("signed " + rp::sha256_hex(result) + " key " +
                        rp::test::signing_key().key_id() + "\ntimestamped " + kStampedAt +
                        "\nevidence " + utf8(lab.run_folder()) +
                        ": result.json, signature.json, timestamp.tst, items.csv, "
                        "veeam-session.log\nqueued " +
                        utf8(outbox.queued()) + "\n"));

    const rp::OutboxManifest manifest = outbox.manifest();
    CHECK(manifest.run_id == kRunId);
    CHECK(manifest.queued_at == "2026-09-28T12:00:00Z");
    CHECK(manifest.attempts == 0);
    CHECK_FALSE(manifest.next_attempt_at);
    CHECK_FALSE(manifest.last_attempt_at);
    CHECK_FALSE(manifest.last_error);
    CHECK(manifest.timestamped);
    CHECK_FALSE(manifest.timestamp_code);
    CHECK_FALSE(manifest.sent_at);
    CHECK(manifest.files == std::vector<std::string>{"items.csv", "result.json", "signature.json",
                                                     "timestamp.tst", "veeam-session.log"});
    // The manifest is the Worker's own: the result neither lists nor names it.
    CHECK_THAT(result, !ContainsSubstring("manifest.json"));
    CHECK_THAT(result, !ContainsSubstring("outbox"));
    const auto before = rp::test::outbox_lab::files_of(outbox.queued());
    const rp::Verification queued = verify_folder(outbox.queued());
    CHECK(rp::to_string(queued.word) == "verified");
    CHECK(queued.notes == std::vector<std::string>{"manifest.json"});

    // `rpworker outbox flush`, the Cloud down, then up.
    rp::test::FakeHttpClient cloud;
    int calls = 0;
    cloud.on(rp::HttpMethod::post, "https://cloud.example.invalid/v1/results",
             [&calls](const rp::HttpRequest&) -> rp::HttpResponse {
                 if (++calls == 1) {
                     throw rp::HttpError("POST: dropped", rp::TransportError::dropped, 0, 1);
                 }
                 return rp::test::cloud_answer(202);
             });
    long long now = 0;
    rp::OutboxCommandEnv env;
    // W5.1: the flush's token.
    env.load_secrets = [](const std::filesystem::path&) {
        rp::Secrets secrets;
        secrets.cloud_api_token = "PipeToken-w51-0123456789abcdefABCDEF_-01234";
        return secrets;
    };
    env.default_vault_path = [&] { return lab.config_path.parent_path() / "vault.bin"; };
    env.default_config_path = [&] { return lab.config_path; };
    env.default_outbox_root = [&] { return outbox.root_path; };
    env.make_cloud_http = [&](const rp::Config&) -> std::unique_ptr<rp::IHttpClient> {
        return std::make_unique<rp::test::ForwardingHttpClient>(cloud);
    };
    env.wall_now = [&] { return rp::test::outbox_lab::at(now); };
    env.take_flush_lock = []() -> std::unique_ptr<rp::RunLock> {
        struct Lock final : rp::RunLock {};
        return std::make_unique<Lock>();
    };
    const auto flush = [&] {
        std::ostringstream out;
        std::ostringstream err;
        const Args args{"flush"};
        const int code = rp::run_outbox_command(args, out, err, env);
        return Run{code, out.str(), err.str()};
    };

    const Run down = flush();
    CHECK(down.exit_code == rp::exit_code::transient);
    CHECK(down.out == "kept run-0001: upload_unreachable; attempt 1, next at "
                      "2026-10-07T12:01:00Z\n1 queued, 0 sent, 0 failed\n");
    CHECK(rp::test::outbox_lab::files_of(outbox.queued()) == before);
    CHECK(outbox.manifest().attempts == 1);

    now = 60;
    const Run up = flush();
    CHECK(up.exit_code == rp::exit_code::ok);
    CHECK(up.out == "sent run-0001\n0 queued, 1 sent, 0 failed\n");
    CHECK(up.err.empty());
    CHECK_FALSE(std::filesystem::exists(outbox.queued()));
    CHECK(rp::test::outbox_lab::files_of(outbox.sent()) == before);
    CHECK(rp::to_string(verify_folder(outbox.sent()).word) == "verified");

    // What the Cloud was sent: the run's own files under the contract's names.
    const std::vector<rp::HttpRequest> requests = cloud.requests();
    REQUIRE(requests.size() == 2);
    std::vector<std::string> names;
    for (const rp::MultipartPart& part : requests.back().parts) {
        names.push_back(part.name);
        CHECK(part.content == before.at(part.filename));
    }
    CHECK(names == std::vector<std::string>{"result", "signature", "timestamp", "items.csv",
                                            "veeam-session.log"});
}

// --- W4.8: the pipeline as the service's loop calls it --------------------------------
// (docs/decisions.md 2026-10-08, W4.8 points 2, 5 and 13): the report of every way
// out, the loaded config, a job's screenshots flag and the Timestamper's stop.

namespace {

// A TestLab that runs the pipeline itself (Harness::use_pipeline) and keeps
// its report. kThree's second mail is a random one.
struct PipelineLab : TestLab {
    explicit PipelineLab(const json& config_edit = json::object()) : TestLab(config_edit)
    {
        use_pipeline();
        fake.pool.mail = {carol_mail(1)};
    }
};

// "<pass|fail|error>[ <code>]", or "-" for none.
std::string status_text(const std::optional<rp::verification::RunStatus>& status,
                        const std::string& code)
{
    if (!status) {
        return "-";
    }
    return std::string{rp::verification::to_string(*status)} + (code.empty() ? "" : " " + code);
}

using rp::RunFolderState;

struct ReportCase {
    std::string name;
    // What the case changes: the lab, and the command line (kThree, then
    // --evidence <runs root> --outbox <outbox root>).
    std::function<void(PipelineLab&, const OutboxRun&, Args&)> setup;
    int exit_code;
    std::string run_id;
    bool run_line;
    std::string status;   // the run's, "-" when none was decided
    std::string replaced; // what result_invalid replaced, "-" when it didn't
    RunFolderState folder;
    std::string word;
    bool may_still_run;
};

const std::vector<ReportCase>& report_cases()
{
    using Lab = PipelineLab;
    const auto nothing = [](Lab&, const OutboxRun&, Args&) {};
    static const std::vector<ReportCase> cases{
        // Before the run line: no status, no folder.
        {"a vault that can't be read",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.load_secrets = []() -> rp::Secrets {
                 throw rp::ConfigError("vault", "vault file not found");
             };
         },
         rp::exit_code::config, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"a run ID already queued",
         [](Lab&, const OutboxRun& outbox, Args&) {
             std::filesystem::create_directories(outbox.queued());
         },
         rp::exit_code::config, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"every sample size 0",
         [](Lab&, const OutboxRun&, Args& args) {
             args[3] = "0";
             args[5] = "0";
         },
         rp::exit_code::usage, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"no result schema",
         [](Lab& lab, const OutboxRun&, Args&) { lab.schema_ready = [] { return false; }; },
         rp::exit_code::config, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"a cursor past the manifest's canaries",
         [](Lab&, const OutboxRun&, Args& args) {
             args.push_back("--canary-cursor");
             args.push_back("999999,0,0");
         },
         rp::exit_code::usage, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"a stop before the mutex",
         [](Lab& lab, const OutboxRun&, Args&) { lab.stop_requested = [] { return true; }; },
         rp::exit_code::service, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"the mutex held",
         [](Lab& lab, const OutboxRun&, Args&) { lab.lock_taken = true; },
         rp::exit_code::service, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"the mutex held, no --run-id",
         [](Lab& lab, const OutboxRun&, Args& args) {
             args.erase(args.begin(), args.begin() + 2);
             lab.lock_taken = true;
         },
         rp::exit_code::service, "", false, "-", "-", RunFolderState::none, "", false},
        {"no restore point",
         [](Lab& lab, const OutboxRun&, Args&) { lab.fake.points.clear(); },
         rp::exit_code::service, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"the backup unreachable when the restore points are listed",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.fake.points_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         rp::exit_code::transient, kRunId, false, "-", "-", RunFolderState::none, "", false},
        {"a run folder already there",
         [](Lab& lab, const OutboxRun&, Args&) {
             std::filesystem::create_directories(lab.run_folder());
         },
         rp::exit_code::config, kRunId, false, "-", "-", RunFolderState::none, "", false},
        // A stop in each phase, the folder signed and queued all the same.
        {"the run not put on record",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.on_run_started = [](const rp::RunStarted&) { return false; };
         },
         rp::exit_code::service, kRunId, true, "error interrupted", "-", RunFolderState::queued,
         "", false},
        {"a stop after the run line",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.stop_requested = [&lab] { return !lab.run_started.empty(); };
         },
         rp::exit_code::service, kRunId, true, "error interrupted", "-", RunFolderState::queued,
         "", false},
        {"the backup unreachable when the sample is chosen",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.fake.candidates_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         rp::exit_code::transient, kRunId, true, "error backup_transient", "-",
         RunFolderState::queued, "", false},
        {"a restore that may still run",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.fake.restore_throw = [] { throw rp::connector::Error("Veeam said no"); };
         },
         rp::exit_code::service, kRunId, true, "error backup", "-", RunFolderState::queued, "",
         true},
        {"a restore request withdrawn before the first",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.fake.restore_throw = [] {
                 throw rp::connector::Interrupted("asked to stop; nothing was restored");
             };
         },
         rp::exit_code::service, kRunId, true, "error interrupted", "-", RunFolderState::queued,
         "", false},
        {"a restore's poll left on a stop",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.fake.restore_throw = [] {
                 throw rp::connector::Interrupted("still Working when asked to stop");
             };
         },
         rp::exit_code::service, kRunId, true, "error interrupted", "-", RunFolderState::queued,
         "", true},
        {"a check that fails unexpectedly",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.targets.download_throw = [] { throw std::logic_error("a bug"); };
         },
         rp::exit_code::config, kRunId, true, "error internal", "-", RunFolderState::queued, "",
         false},
        // The normal ends.
        {"a pass", nothing, rp::exit_code::ok, kRunId, true, "pass", "-", RunFolderState::queued,
         "", false},
        {"a pass under a run ID the run made",
         [](Lab&, const OutboxRun&, Args& args) { args.erase(args.begin(), args.begin() + 2); },
         rp::exit_code::ok, kGeneratedRunId, true, "pass", "-", RunFolderState::queued, "",
         false},
        {"a fail",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.targets.after[kind_slot(rp::connector::ItemKind::sharepoint)] = json::array();
         },
         rp::exit_code::restore, kRunId, true, "fail", "-", RunFolderState::queued, "", false},
        {"a pass without --evidence",
         [](Lab&, const OutboxRun&, Args& args) { args.resize(kThree.size()); },
         rp::exit_code::ok, kRunId, true, "pass", "-", RunFolderState::none, "", false},
        {"a pass without --outbox",
         [](Lab&, const OutboxRun&, Args& args) { args.resize(kThree.size() + 2); },
         rp::exit_code::ok, kRunId, true, "pass", "-", RunFolderState::complete, "", false},
        // result_invalid, and what it replaced.
        {"a result that isn't valid, the run a pass",
         [](Lab& lab, const OutboxRun&, Args&) { lab.fake.info.name = "Fake Connector"; },
         rp::exit_code::config, kRunId, true, "error result_invalid", "pass",
         RunFolderState::incomplete, "invalid", false},
        {"a result that isn't valid, the run an error",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.fake.info.name = "Fake Connector";
             lab.fake.candidates_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         rp::exit_code::config, kRunId, true, "error result_invalid", "error backup_transient",
         RunFolderState::incomplete, "invalid", false},
        {"a result that is valid when the status is decided and isn't at the end",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.wall_now = [&lab] {
                 return lab.cleanups.empty() ? rp::test::graph_lab::kNow : year_10000();
             };
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::incomplete, "invalid",
         false},
        // Each evidence failure: the folder without a result.json.
        {"a text file that can't be written",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.write_evidence_file = [&lab](const std::filesystem::path& path,
                                              std::string_view content) {
                 if (utf8(path.filename()) == "items.csv") {
                     return false;
                 }
                 lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
                 return true;
             };
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::incomplete,
         "not_written", false},
        {"a result.json that can't be written",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.write_evidence_file = [&lab](const std::filesystem::path& path,
                                              std::string_view content) {
                 if (utf8(path.filename()) == "result.json") {
                     return false;
                 }
                 lab.dir.write(std::filesystem::relative(path, lab.dir.path()), content);
                 return true;
             };
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::incomplete,
         "not_written", false},
        {"an attachment changed after it was hashed",
         [](Lab& lab, const OutboxRun&, Args&) {
             // The job's flag: the capturer runs once the text files are hashed.
             lab.screenshots = true;
             lab.capture_screenshot = [](const rp::ScreenshotRequest& request)
                 -> std::optional<rp::ScreenshotReason> {
                 std::ofstream(request.png.parent_path() / "items.csv",
                               std::ios::binary | std::ios::app)
                     << "9,\"added later\"\n";
                 return rp::ScreenshotReason::no_browser;
             };
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::incomplete, "changed",
         false},
        {"a result that holds a secret value",
         [](Lab& lab, const OutboxRun&, Args&) {
             rp::connector::MailCandidate mail = carol_mail(1);
             mail.selector.subject = "fwd: Sentinel-Veeam-Password-9c2e";
             lab.fake.pool.mail = {mail};
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::incomplete,
         "holds_secret", false},
        {"a result that can't be signed",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.sign_result = [](std::string_view, const rp::SigningKey&) {
                 return std::optional<rp::SignedResult>{};
             };
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::incomplete,
         "not_signed", false},
        // The outbox.
        {"a folder the outbox can't take",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.outbox_files.move_folder = [](const std::filesystem::path&,
                                               const std::filesystem::path&) { return 32ul; };
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::complete, "not_moved",
         false},
        {"a queued folder whose manifest can't be written",
         [](Lab& lab, const OutboxRun&, Args&) {
             lab.outbox_files.write_manifest = [](const std::filesystem::path&,
                                                  std::string_view) { return false; };
         },
         rp::exit_code::config, kRunId, true, "pass", "-", RunFolderState::queued,
         "manifest_not_written", false},
    };
    return cases;
}

} // namespace

TEST_CASE("the pipeline's report says what became of the run on every way out: its ID, whether "
          "the run line was written, the status and what result_invalid replaced, the run "
          "folder with its word, and whether a restore may still run",
          "[test_command][report]")
{
    const std::vector<ReportCase>& cases = report_cases();
    const std::size_t count = cases.size();
    const ReportCase& c = cases[GENERATE_COPY(range(std::size_t{0}, count))];
    CAPTURE(c.name);
    PipelineLab lab;
    const OutboxRun outbox(lab);
    Args args = outbox.args;
    c.setup(lab, outbox, args);

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    const rp::PipelineReport& report = lab.report;
    CHECK(run.exit_code == c.exit_code);
    CHECK(report.run_id == c.run_id);
    CHECK(report.run_line == c.run_line);
    CHECK(status_text(report.status, report.error_code) == c.status);
    CHECK(status_text(report.replaced_status, report.replaced_code) == c.replaced);
    CHECK(report.folder == c.folder);
    CHECK(report.folder_word == c.word);
    CHECK(report.restore_may_still_run == c.may_still_run);

    // The report against what the run printed and left.
    CHECK((run.out.find("run " + c.run_id + "  seed ") != std::string::npos) == c.run_line);
    if (c.status != "-") {
        CHECK_THAT(run.out, ContainsSubstring("\nstatus " + c.status + ": "));
    } else {
        CHECK_THAT(run.out, !ContainsSubstring("\nstatus "));
    }
    const std::filesystem::path in_runs = lab.run_folder(c.run_id.empty() ? kRunId : c.run_id);
    const std::filesystem::path in_outbox = outbox.queued(c.run_id.empty() ? kRunId : c.run_id);
    switch (c.folder) {
    case RunFolderState::none:
        CHECK_FALSE(std::filesystem::exists(in_runs / "items.csv"));
        CHECK_FALSE(std::filesystem::exists(in_outbox / "result.json"));
        break;
    case RunFolderState::incomplete:
        CHECK(std::filesystem::is_directory(in_runs));
        CHECK_FALSE(std::filesystem::exists(in_runs / "result.json"));
        CHECK_FALSE(std::filesystem::exists(in_outbox));
        break;
    case RunFolderState::complete:
        CHECK(std::filesystem::exists(in_runs / "result.json"));
        CHECK_FALSE(std::filesystem::exists(in_outbox));
        break;
    case RunFolderState::queued:
        CHECK(std::filesystem::exists(in_outbox / "result.json"));
        CHECK_FALSE(std::filesystem::exists(in_runs));
        break;
    }
    // A restore that may still run skipped its clean after.
    if (c.may_still_run) {
        CHECK_THAT(run.out, ContainsSubstring(kCleanAfterStillRunning));
        CHECK(lab.targets.deleted.empty());
    }
}

TEST_CASE("the pipeline run without a report runs as with one", "[test_command][report]")
{
    PipelineLab lab;
    lab.command = [&lab](std::span<const std::string_view>, std::ostream& out, std::ostream& err,
                         const rp::RestoreCommandEnv& env) {
        rp::PipelineArgs args;
        args.run_id = kRunId;
        args.mail = 2;
        args.sharepoint = 1;
        args.onedrive = 0;
        args.cursor = rp::sampling::CanaryCursor{}; // W6.2: the lab's canaries
        std::shared_ptr<rp::FixtureRecorder> recorder;
        const std::string config = utf8(lab.config_path);
        args.config = config;
        return rp::run_pipeline(args, out, err, env, recorder, rp::test_presentation());
    };

    const Run run = lab.run_raw({});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
}

TEST_CASE("the pipeline handed a loaded config doesn't read the file again; the manifest is "
          "still the one beside it",
          "[test_command][report]")
{
    PipelineLab lab;
    const rp::Config loaded = rp::load_config(lab.config_path);
    lab.loaded = &loaded;
    // What the file holds now is nobody's business until the next start.
    lab.dir.write("config.json", "not a config");

    const Run run = lab.run(kThree);

    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK(lab.made_for_org == kOrgName);
    CHECK(lab.report.status == std::optional{rp::verification::RunStatus::pass});
}

TEST_CASE("without a loaded config the pipeline reads the file, and says when it can't",
          "[test_command][report]")
{
    PipelineLab lab;
    lab.dir.write("config.json", "not a config");

    const Run run = lab.run(kThree);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK_THAT(run.err, StartsWith("config error: "));
    CHECK_FALSE(lab.report.run_line);
    CHECK(lab.report.run_id == kRunId);
}

TEST_CASE("a job's screenshots flag replaces the config's for its run",
          "[test_command][report][evidence]")
{
    const auto [config_says, job_says, asked, reason] =
        GENERATE(table<bool, std::optional<bool>, int, std::string>({
            {true, std::optional<bool>{false}, 0, "disabled"},
            {false, std::optional<bool>{true}, 1, "no_browser"},
            {true, std::optional<bool>{}, 1, "no_browser"},
            {false, std::optional<bool>{}, 0, "disabled"},
        }));
    CAPTURE(config_says, job_says);
    PipelineLab lab({{"screenshots_enabled", config_says}});
    lab.screenshots = job_says;
    int captures = 0;
    lab.capture_screenshot =
        [&](const rp::ScreenshotRequest&) -> std::optional<rp::ScreenshotReason> {
        ++captures;
        return rp::ScreenshotReason::no_browser;
    };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(captures == asked);
    CHECK(lab.evidence_result().at("screenshot") ==
          json{{"state", "unavailable"}, {"reason", reason}});
}

TEST_CASE("test --evidence: after a stop the TSA isn't asked: not timestamped after 0 "
          "attempt(s), the folder complete without a token, the status and the exit code the "
          "run's",
          "[test_command][evidence][timestamp][stop]")
{
    TestLab lab;
    // The stop comes once the status is out: the run is over but for its folder.
    lab.stop_requested = [&lab] { return !lab.cleanups.empty(); };

    const Run run = evidence_run(lab);

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == not_timestamped(lab, "timestamp_internal", 0));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: "));
    CHECK_THAT(run.out, EndsWith(signed_lines(lab.run_folder(), false, "")));
    CHECK(names_in(lab.run_folder()) == kUnstampedFolder);
    CHECK(lab.tsa_http.requests().empty());
    CHECK(lab.slept.empty());
}

// --- The result's client.scope and client.resolved (W4.11 point 7) --------------------------

TEST_CASE("test --json: a run whose client check passed says scope same_tenant and what the "
          "check resolved; one it stopped says null for both",
          "[test_command][json][client_check][w4.11]")
{
    namespace gl = rp::test::graph_lab;
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};
    std::string written;
    lab.write_summary = [&](const std::filesystem::path&, std::string_view text) {
        written = std::string{text};
        return true;
    };
    const bool mismatch = GENERATE(false, true);
    if (mismatch) {
        lab.fake.facts = connector::ClientFacts{kOrgName, "11111111-2222-3333-4444-555555555555",
                                                "Office365", "Worldwide"};
    }

    const Run run = lab.run({"--json", "run.json", "--run-id", kRunId, "--mail", "2", "--sp", "1",
                             "--od", "1"});

    REQUIRE_FALSE(written.empty());
    const json result = json::parse(written);
    REQUIRE(rp::validate_result(result).valid);
    const json& client = result.at("client");
    REQUIRE(client.size() == 6);
    if (mismatch) {
        CHECK(run.exit_code == rp::exit_code::service);
        CHECK(result.at("status").at("error_code") == "client_mismatch");
        CHECK(client.at("scope").is_null());
        CHECK(client.at("resolved").is_null());
        CHECK(result.at("cleanup").is_null());
        return;
    }
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(client.at("scope") == "same_tenant");
    const json drive = rp::test::load_fixture_json("graph", "restoretarget-drive-200").at("body");
    const json folder = rp::test::load_fixture_json("graph", "onedrive-folder-200").at("body");
    const json inbox = rp::test::load_fixture_json("graph", "mailbox-inbox-200").at("body");
    CHECK(client.at("resolved") ==
          json{{"organization",
                {{"name", kOrgName},
                 {"tenant_id", std::string{kTenant}},
                 {"type", "Office365"},
                 {"region", "Worldwide"}}},
               {"mailbox", {{"inbox_id", inbox.at("id")}}},
               {"library",
                {{"name", "RestoreTarget"},
                 {"list_id", drive.at("sharePointIds").at("listId")},
                 {"site_url", drive.at("sharePointIds").at("siteUrl")}}},
               {"onedrive_folder",
                {{"name", "RestoreTarget"},
                 {"site_url", folder.at("sharepointIds").at("siteUrl")}}}});
}

// --- W6.2: the result of a run without canaries -------------------------------------

TEST_CASE("test --json: a run without canaries records no manifest hash and no rotation",
          "[test_command][w6.2]")
{
    TestLab lab;
    lab.canaries = false;
    std::filesystem::remove(lab.manifest_path);
    lab.fake.pool.mail = {carol_mail(1)};

    const Run run = lab.run({"--json", lab.json_arg(), "--run-id", kRunId, "--mail", "1", "--sp",
                             "0", "--od", "0"});

    INFO(run.out);
    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    const json result = lab.result();
    CHECK(result.at("status").at("status") == "pass");
    const json& sample = result.at("sample");
    CHECK_FALSE(sample.contains("manifest_sha256"));
    for (const char* kind : {"mail", "sharepoint", "onedrive"}) {
        CAPTURE(kind);
        CHECK_FALSE(sample.at(kind).contains("canary"));
    }
    CHECK(sample.at("mail").at("random").at("wanted") == 1);
    const json& expected = result.at("expected");
    CHECK_FALSE(expected.contains("manifest_sha256"));
    CHECK(expected.at("counts").at("manifest") == 0);
    CHECK(expected.at("counts").at("fields") == 1);
    CHECK(expected.at("items").at(0).at("source") == "random");
}

// --- W6.3: a random file's content against the backup's copy, through the pipeline -------

namespace {

// A run without canaries of one random pdf, one random docx and one random
// pptx in SharePoint, and one random txt in OneDrive.
void four_random_files(TestLab& lab)
{
    lab.canaries = false;
    lab.fake.pool.sharepoint = {
        {{lab_values().site_id, "b!madeUpSourceLibraryDrive", "/Projects", "plan.pdf",
          "0b5e1d2c-0000-4000-8000-00000000c0de"},
         900},
        {{lab_values().site_id, "b!madeUpSourceLibraryDrive", "/Projects", "notes.docx",
          "0b5e1d2c-0000-4000-8000-00000000c0de"},
         3230},
        {{lab_values().site_id, "b!madeUpSourceLibraryDrive", "/Projects", "deck.pptx",
          "0b5e1d2c-0000-4000-8000-00000000c0de"},
         5000}};
    lab.fake.pool.onedrive = {{{kCarol, "/Projects", "list.txt"}, 60}};
}

const Args kFourFiles{"--run-id", kRunId, "--mail", "0", "--sp", "3", "--od", "1"};

json item_named(const json& result, const std::string& name)
{
    for (const json& item : result.at("expected").at("items")) {
        if (item.value("name", "") == name) {
            return item;
        }
    }
    FAIL("no item " << name);
    return {};
}

} // namespace

TEST_CASE("test --json: random files the backup exported are backup_content, checked by hash, "
          "and a file of no rule stays metadata",
          "[test_command][w6.3][acceptance]")
{
    TestLab lab;
    four_random_files(lab);
    Args args = kFourFiles;
    const std::string json_arg = lab.json_arg(); // Args holds views: the path must outlive it
    args.insert(args.end(), {"--json", json_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    INFO(run.err);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err.empty());
    CHECK_THAT(run.out, ContainsSubstring("\ncontent exports: 3 of 3 file(s) exported from the "
                                          "backup\n"));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: 4 of 4 item(s) verified: manifest 0, "
                                          "fields 0, metadata 1, backup_content 3\n"));
    const json result = lab.result();
    const json pdf = item_named(result, "plan.pdf");
    CHECK(pdf.at("expected_kind") == "backup_content");
    CHECK(pdf.at("sha256_rule") == "bytes");
    CHECK(pdf.at("sha256") == rp::sha256_hex(std::string(900, 'r')));
    CHECK(pdf.at("size_bytes") == 900);
    CHECK(pdf.at("export") == "exported");
    const json docx = item_named(result, "notes.docx");
    CHECK(docx.at("expected_kind") == "backup_content");
    CHECK(docx.at("sha256_rule") == "office-v1");
    CHECK_FALSE(docx.contains("size_bytes"));
    const json pptx = item_named(result, "deck.pptx");
    CHECK(pptx.at("expected_kind") == "metadata");
    CHECK(pptx.at("export") == "no_rule");
    CHECK(item_named(result, "list.txt").at("expected_kind") == "backup_content");
    CHECK(result.at("expected").at("counts") ==
          json{{"manifest", 0}, {"fields", 0}, {"metadata", 1}, {"backup_content", 3}});
    CHECK(result.at("status").at("verified").at("backup_content") == 3);
    CHECK(result.at("status").at("warnings").empty());
    // The fake reports no time of its own: the span is not reported.
    CHECK(result.at("timings").at("spans").at("content_export") ==
          json{{"note", "not_reported"}});
    // The fake backup was asked for exactly the three files with a rule.
    REQUIRE(lab.fake.spec);
    CHECK(lab.fake.spec->content_count() == 3);
    CHECK(lab.fake.spec->content_sink != nullptr);
}

TEST_CASE("test --evidence: items.csv shows a backup_content file's expected and found hash",
          "[test_command][w6.3][evidence]")
{
    TestLab lab;
    four_random_files(lab);
    Args args = kFourFiles;
    const std::string root = lab.evidence_arg();
    args.insert(args.end(), {"--evidence", root});

    const Run run = lab.run(args);

    REQUIRE(run.exit_code == rp::exit_code::ok);
    const std::optional<std::string> csv = file_bytes(lab.run_folder() / "items.csv");
    REQUIRE(csv);
    const std::string hash = rp::sha256_hex(std::string(900, 'r'));
    CHECK_THAT(*csv, ContainsSubstring("\"plan.pdf\",\"backup_content\",\"bytes\",\"" + hash +
                                       "\",\"" + hash + "\""));
    CHECK_THAT(*csv, ContainsSubstring("\"deck.pptx\",\"metadata\",\"\",\"\",\"\""));
}

TEST_CASE("test --json: an export that gives nothing leaves its file metadata with its word, the "
          "run passes on names and sizes, and the warning says so",
          "[test_command][w6.3]")
{
    const auto [outcome, word] = GENERATE(table<rp::connector::ContentOutcome, std::string>({
        {rp::connector::ContentOutcome::refused, "refused"},
        {rp::connector::ContentOutcome::no_answer, "no_answer"},
        {rp::connector::ContentOutcome::size_mismatch, "size_mismatch"},
        {rp::connector::ContentOutcome::over_cap, "over_cap"},
        {rp::connector::ContentOutcome::budget, "budget"},
    }));
    CAPTURE(word);
    TestLab lab;
    four_random_files(lab);
    lab.fake.export_outcome = [outcome](const std::string& name)
        -> std::optional<rp::connector::ContentOutcome> {
        return name == "plan.pdf" ? std::optional{outcome} : std::nullopt;
    };
    Args args = kFourFiles;
    const std::string json_arg = lab.json_arg(); // Args holds views: the path must outlive it
    args.insert(args.end(), {"--json", json_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, ContainsSubstring("\ncontent exports: 2 of 3 file(s) exported from the "
                                          "backup (" + word + " 1)\n"));
    CHECK_THAT(run.out, ContainsSubstring("\nstatus pass: 4 of 4 item(s) verified: manifest 0, "
                                          "fields 0, metadata 2, backup_content 2\n"));
    CHECK(run.err == "warning: content_export: 1 of 3 file(s) couldn't be compared with the "
                     "backup's own copy (" + word + " 1): 1 checked by name and size alone, 0 by "
                     "name alone\n");
    const json result = lab.result();
    const json pdf = item_named(result, "plan.pdf");
    CHECK(pdf.at("expected_kind") == "metadata");
    CHECK(pdf.at("export") == word);
    CHECK(pdf.at("size_bytes") == 900); // the listed size, as before
    CHECK_FALSE(pdf.contains("sha256"));
    const json& warnings = result.at("status").at("warnings");
    REQUIRE(warnings.size() == 1);
    CHECK(warnings[0].at("code") == "content_export");
    CHECK(warnings[0].at("indexes") == json::array({pdf.at("index")}));
}

TEST_CASE("test --json: the content_export warning says which files had their size compared and "
          "names an exported package office-v1 refused as such",
          "[test_command][w6.3]")
{
    // An Office file has no size expectation (SharePoint rewrites it), and an
    // invalid_package file was exported: the warning claims no size check it
    // didn't make and no export that didn't happen (W6.3 review, finding 4).
    TestLab lab;
    four_random_files(lab);
    lab.fake.export_outcome = [](const std::string& name)
        -> std::optional<rp::connector::ContentOutcome> {
        return name == "plan.pdf" ? std::optional{rp::connector::ContentOutcome::refused}
                                  : std::nullopt;
    };
    lab.fake.export_bytes = [](const std::string& name, std::string bytes) {
        return name == "notes.docx" ? std::string{"not a package"} : bytes;
    };
    Args args = kFourFiles;
    const std::string json_arg = lab.json_arg(); // Args holds views: the path must outlive it
    args.insert(args.end(), {"--json", json_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK(run.err == "warning: content_export: 2 of 3 file(s) couldn't be compared with the "
                     "backup's own copy (refused 1, invalid_package 1): 1 checked by name and "
                     "size alone, 1 by name alone\n");
    const json result = lab.result();
    CHECK(item_named(result, "notes.docx").at("export") == "invalid_package");
    CHECK_FALSE(item_named(result, "notes.docx").contains("size_bytes"));
}

TEST_CASE("test --json: a restored copy whose bytes aren't the backup's is a mismatch on "
          "sha256: fail, that item listed",
          "[test_command][w6.3][acceptance]")
{
    TestLab lab;
    four_random_files(lab);
    // The backup's copy one byte apart from what the targets hold: the
    // offline form of the live Done-when's changed byte.
    lab.fake.export_bytes = [](const std::string& name, std::string bytes) {
        if (name == "list.txt") {
            bytes[0] = static_cast<char>(bytes[0] ^ 0x01);
        }
        return bytes;
    };
    Args args = kFourFiles;
    const std::string json_arg = lab.json_arg(); // Args holds views: the path must outlive it
    args.insert(args.end(), {"--json", json_arg});

    const Run run = lab.run(args);

    INFO(run.out);
    CHECK(run.exit_code == rp::exit_code::restore);
    CHECK_THAT(run.out, ContainsSubstring("\nstatus fail: 1 of 4 item(s) didn't verify (0 missing, "
                                          "1 mismatch)\n"));
    const json result = lab.result();
    const json txt = item_named(result, "list.txt");
    CHECK(result.at("status").at("failed_items") == json::array({txt.at("index")}));
    const json& check = result.at("check").at("items").at(txt.at("index").get<std::size_t>());
    CHECK(check.at("outcome") == "mismatch");
    CHECK(check.at("mismatches") == json::array({"sha256"}));
}

TEST_CASE("test: a connector that ignores want_content is the Worker's fault, error internal, "
          "never a fail",
          "[test_command][w6.3]")
{
    TestLab lab;
    four_random_files(lab);
    lab.fake.ignore_content = true;

    const Run run = lab.run(kFourFiles);

    CHECK(run.exit_code == rp::exit_code::config);
    CHECK_THAT(run.out, ContainsSubstring("\nstatus error internal: "));
    CHECK_THAT(run.err, ContainsSubstring("check error: unexpected failure\n"));
}

TEST_CASE("test: a run with canaries alone asks the backup for nothing", "[test_command][w6.3]")
{
    TestLab lab;
    lab.fake.pool.mail = {carol_mail(1)};

    const Run run = lab.run({"--run-id", kRunId, "--mail", "2", "--sp", "1", "--od", "0"});

    CHECK(run.exit_code == rp::exit_code::ok);
    CHECK_THAT(run.out, !ContainsSubstring("content exports"));
    REQUIRE(lab.fake.spec);
    CHECK(lab.fake.spec->content_count() == 0);
    CHECK(lab.fake.spec->content_sink == nullptr);
}
