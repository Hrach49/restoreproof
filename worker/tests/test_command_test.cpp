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

#include "../src/text_table.hpp"

#include <rp/canonical_json.hpp>
#include <rp/checker.hpp>
#include <rp/cli.hpp>
#include <rp/connector.hpp>
#include <rp/restore_command.hpp>
#include <rp/result_schema.hpp>
#include <rp/run_status.hpp>
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
    json result() const
    {
        const std::optional<std::string> text = file_bytes(json_path());
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
    "restore",       "check",          "status", "cleanup",    "timings"};

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

// A stdout that takes `limit` bytes, then fails.
class LimitedStreamBuf : public std::streambuf {
public:
    explicit LimitedStreamBuf(std::size_t limit) : limit_(limit) {}
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
         [](TestLab& lab) { lab.dir.write("seed-manifest.json", "{"); }, Args{},
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
          "nor the --json file shows the zip reader's words",
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
    CHECK(run.err.find("office-v1") == std::string::npos);
}

// --- --json: the result (restoreproof.result.v1) --------------------------------------

TEST_CASE("test --json writes restoreproof.result.v1: valid by the embedded schema and by the "
          "schema file, exactly its own canonical text, the fifteen keys",
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
    CHECK_THAT(*text, StartsWith("{\"check\":{"));
    CHECK(text->ends_with("}"));
    // (c) The fifteen keys.
    CHECK(keys_of(document) == kResultKeys);
    CHECK(document.at("format") == "restoreproof.result.v1");
    CHECK(document.at("status").at("status") == "pass");
}

TEST_CASE("test --json: the result is valid and has the fifteen keys for each way a run ends, "
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
             lab.targets.graph.on(rp::HttpMethod::get, gl::drive_url(),
                                  {rp::test::to_response(edited)});
         },
         three, rp::exit_code::service, "error target_guard", nothing_chosen},
        {"choose_sample throws",
         [](TestLab& lab) {
             lab.fake.candidates_throw = [] {
                 throw rp::connector::TransientError("Veeam unreachable");
             };
         },
         Args{"--mail", "2", "--sp", "0", "--od", "0"}, rp::exit_code::transient,
         "error backup_transient", nothing_chosen},
        {"an empty sample",
         [](TestLab& lab) { lab.dir.write("seed-manifest.json", trimmed_manifest(0, 1, 1)); },
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
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{15}))];
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
        CHECK(result.at(key).is_null() == c.nulls.contains(key));
    }
    CHECK(result.at("format") == "restoreproof.result.v1");
    CHECK(result.at("worker_version") == std::string{rp::version()});
    CHECK(result.at("run_id") == kRunId);
    CHECK(result.at("started_at") == "2026-09-28T12:00:00.000Z");
    CHECK(result.at("ended_at") == "2026-09-28T12:00:00.000Z");
    CHECK(result.at("connector") == json{{"type", "veeam_m365"}, {"api", "1"}});
    const gl::Lab_values& v = gl::lab_values();
    CHECK(result.at("client") == json{{"client_id", nullptr},
                                      {"tenant_id", kTenant},
                                      {"veeam_org_name", kOrgName},
                                      {"targets",
                                       {{"mailbox", v.mailbox},
                                        {"site_id", v.site_id},
                                        {"library_id", v.library_id},
                                        {"onedrive_drive_id", v.onedrive_drive_id},
                                        {"onedrive_folder_id", v.folder_id}}}});
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
    CHECK_THAT(text, StartsWith("{\"check\":"));
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
    lab.fake.info.name = "fake";
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
    CHECK(lab.cleanups[0].after.has_value() == c.restore_sent);
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
    CHECK_THAT(run.err, !ContainsSubstring("fake"));
    CHECK_THAT(run.out, !ContainsSubstring("wrote "));
    CHECK(writes == 0);
    CHECK_FALSE(std::filesystem::exists(lab.json_path()));
}

TEST_CASE("test: without --json a result that isn't valid is still error result_invalid, and "
          "nothing is said of a file",
          "[test_command][result]")
{
    TestLab lab;
    lab.fake.info.name = "fake";

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

TEST_CASE("test --json: an end-of-run hook that throws makes exit 0 exit 1", "[test_command][json]")
{
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
    // A stdout that takes everything up to the file's line, then throws: the
    // hook's own write, after the file is written.
    LimitedStreamBuf buffer(before_wrote);
    std::ostream out(&buffer);
    out.exceptions(std::ios::badbit | std::ios::failbit);

    const auto [code, err] = lab.run_to(with_json, out);

    CHECK(code == rp::exit_code::config);
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
    CHECK(names == std::set<std::string>{"config.json", "run.json", "seed-manifest.json"});
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
    CHECK_THAT(buffer.text, !ContainsSubstring("wrote "));
    const json result = lab.result();
    CHECK(keys_of(result) == kResultKeys);
    for (const std::string& key : kResultKeys) {
        CAPTURE(key);
        CHECK_FALSE(result.at(key).is_null());
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

// What shared/testdata/result-v1/valid.json holds: the --json file of a pass
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
    lab.dir.write("seed-manifest.json", manifest);
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
        }
        json copies = lab.targets.mirror(ItemKind::sharepoint);
        json again = copies.back();
        again["id"] = "restored-sharepoint-again";
        copies.push_back(again);
        lab.targets.after[kind_slot(ItemKind::sharepoint)] = copies;
        return result;
    };

    const Run run = lab.run({"--run-id", "rp-20261004T100000Z-0a1b2c3d", "--canary-cursor",
                             "0,1,0", "--mail", "2", "--sp", "2", "--od", "2", "--json",
                             lab.json_arg()});

    INFO(run.out);
    INFO(run.err);
    REQUIRE(run.exit_code == rp::exit_code::ok);
    json document = renamed(lab.result(), shared_names());
    document["worker_version"] = "0.0.0";
    return rp::canonical_json(document);
}

constexpr const char* kSharedResult = "testdata/result-v1/valid.json";

} // namespace

TEST_CASE("test --json: the whole pipeline's result is shared/testdata/result-v1/valid.json, byte "
          "for byte, and names nothing of the lab tenant",
          "[test_command][json][result]")
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
          json{{"manifest", 3}, {"fields", 1}, {"metadata", 2}});
    CHECK(document.at("expected").at("items").at(2).at("sha256_rule") == "office-v1");
    CHECK(document.at("expected").at("items").at(4).at("sha256_rule") == "bytes");
    CHECK(document.at("check").at("items").at(3).at("copies") == 2);
    CHECK(document.at("restore").at("sessions").size() == 3);
    CHECK(document.at("restore").at("sessions").at(2).at("details").is_null());
    CHECK(document.at("cleanup").at("after").at("sharepoint").at("deleted") == 3);
    CHECK(document.at("timings").at("spans").at("restore_wait") == json{{"ms", 120000}});
    CHECK(file.find("\xC3\x9C" "bersicht.docx") != std::string::npos);

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
