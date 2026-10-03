// W3.6 (#41): `rpworker test` (rp::run_test_command). It runs the pipeline
// `rpworker restore` runs (src/run_pipeline.hpp), so these tests run on
// restore's Harness (restore_command_lab.hpp) and pin what differs: the
// command line (no --seed, --json), the table after the check (VERDICT and
// REASON in fixed words), the --json run summary's v0 shape for each way a
// run ends, and a summary that can't be written. What both share (the guard,
// the mutex, the status, the cleanup, the timings) is tested in
// restore_command_test.cpp. No network, nothing live. The choices are the
// 2026-10-03 W3.6 entry in docs/decisions.md.

#include "restore_command_lab.hpp"

#include "../src/text_table.hpp"

#include <rp/checker.hpp>
#include <rp/cli.hpp>
#include <rp/connector.hpp>
#include <rp/restore_command.hpp>
#include <rp/run_status.hpp>
#include <rp/step_timer.hpp>
#include <rp/test_command.hpp>
#include <rp/version.hpp>

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

    // The --json file, parsed; REQUIREs it.
    json summary() const
    {
        const std::optional<std::string> text = file_bytes(json_path());
        REQUIRE(text);
        return json::parse(*text);
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

// The top-level keys of rp.run-summary.v0, every one always there.
const std::set<std::string> kSummaryKeys{
    "format",  "worker_version", "command", "run_id", "started_at", "ended_at",
    "restore_point", "veeam_org_name", "sample", "expected", "restore", "check",
    "status",  "cleanup",        "timings", "exit_code"};

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
    const std::size_t which = GENERATE(range(std::size_t{0}, std::size_t{11}));
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
        // A device: anything but "not found" is a file there.
        {utf8(lab.dir.path() / "NUL"), "the file already exists"},
        {utf8(lab.dir.path() / "missing" / "run.json"), "the folder doesn't exist"},
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
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{7}))];
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

TEST_CASE("test: an Office file that isn't a valid package is a sha256 mismatch; REASON never "
          "shows the zip reader's words, the --json file's check keeps them",
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
    const json summary = lab.summary();
    const json& item = summary.at("check").at("items").at(0);
    CHECK(item.at("mismatches") == json::array({"sha256"}));
    const std::string reason = item.at("reason").get<std::string>();
    CHECK_THAT(reason, ContainsSubstring("office-v1"));
    CHECK(run.out.find(reason) == std::string::npos);
    CHECK(run.out.find("office-v1") == std::string::npos);
    CHECK(run.err.find("office-v1") == std::string::npos);
}

// --- --json: the run summary (rp.run-summary.v0) --------------------------------------

TEST_CASE("test --json: the v0 summary has every top-level key for each way a run ends, null "
          "where a step didn't run; the file is written after the timings, then wrote <file>",
          "[test_command][json]")
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
    };
    const Case& c = cases[GENERATE(range(std::size_t{0}, std::size_t{14}))];
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
    // The timings' table, then the file's line, last.
    const std::string body = lab.json_body(run);
    CHECK_THAT(body, ContainsSubstring("\nstatus " + c.status + ": "));
    const json summary = lab.summary();
    CHECK(keys_of(summary) == kSummaryKeys);
    for (const std::string& key : kSummaryKeys) {
        CAPTURE(key);
        CHECK(summary.at(key).is_null() == c.nulls.contains(key));
    }
    CHECK(summary.at("format") == "rp.run-summary.v0");
    CHECK(summary.at("worker_version") == std::string{rp::version()});
    CHECK(summary.at("command") == "test");
    CHECK(summary.at("run_id") == kRunId);
    CHECK(summary.at("started_at") == "2026-09-28T12:00:00.000Z");
    CHECK(summary.at("ended_at") == "2026-09-28T12:00:00.000Z");
    CHECK(summary.at("restore_point") == json{{"id", kNewestId}, {"backup_time_raw", kNewestTime}});
    CHECK(summary.at("veeam_org_name") == kOrgName);
    CHECK(summary.at("exit_code") == c.code);
    const json& status = summary.at("status");
    const std::string first = c.status.substr(0, c.status.find(' '));
    CHECK(status.at("status") == first);
    if (first == "error") {
        CHECK(status.at("error_code") == c.status.substr(c.status.find(' ') + 1));
    }
    REQUIRE(lab.cleanups.size() == 1);
    CHECK(summary.at("cleanup") == rp::to_json(lab.cleanups[0]));
    CHECK(summary.at("timings") == rp::timing::to_json(lab.timings.at(0)));
    CHECK(status.at("restore_sent") == lab.cleanups[0].restore_sent);
    if (!summary.at("sample").is_null()) {
        CHECK(summary.at("sample").at("run_id") == kRunId);
    }
    if (!summary.at("restore").is_null()) {
        const json& restore = summary.at("restore");
        // Row 1's restore lists one item it wasn't sent: written as reported.
        CHECK(restore.at("items").size() ==
              restore.at("items_sent").get<std::size_t>() + (c.name.ends_with("(row 1)") ? 1 : 0));
        // No item name in the restore object.
        CHECK(restore.dump().find("RP-CANARY") == std::string::npos);
    }
    // Pretty-printed until W4.1 brings the canonical form.
    const std::string text = *file_bytes(lab.json_path());
    CHECK_THAT(text, StartsWith("{\n  \""));
    CHECK(text.ends_with("}\n"));
    // No secret.
    CHECK(text.find("Sentinel-Veeam-Password-9c2e") == std::string::npos);
    CHECK(text.find(rp::test::graph_lab::kPfxPassword) == std::string::npos);
}

TEST_CASE("test --json: a summary that isn't written changes no status; exit 0 becomes 1, any "
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
    lab.write_summary = [&, how = how](const std::filesystem::path& path,
                                       std::string_view text) -> bool {
        asked.push_back(path);
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
    REQUIRE(asked.size() == 1);
    CHECK(asked[0] == lab.json_path());
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
    CHECK(lab.summary().at("run_id") == "rp:20261003:a");
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

TEST_CASE("test --json: with stdout lost the file is still written, without its line; the "
          "summary keeps the status's exit code",
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
    const json summary = lab.summary();
    CHECK(keys_of(summary) == kSummaryKeys);
    for (const std::string& key : kSummaryKeys) {
        CAPTURE(key);
        CHECK_FALSE(summary.at(key).is_null());
    }
    CHECK(summary.at("exit_code") == rp::exit_code::ok);
    CHECK(summary.at("status").at("status") == "pass");
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
    const json summary = lab.summary();
    // The certificate's check reads it first, before the connector.
    CHECK(*at_start == readings.at(1));
    CHECK(summary.at("started_at") == "2026-09-28T12:00:01.000Z");
    CHECK(summary.at("started_at") == text(*at_start));
    // The last reading is ended_at's: after the clean after, nothing reads it later.
    CHECK(summary.at("ended_at") == text(readings.back()));
    CHECK(readings.size() > 2);
    CHECK(summary.at("started_at").get<std::string>() < summary.at("ended_at").get<std::string>());
}

TEST_CASE("test --json: a wall clock that fails for started_at and ended_at leaves them null and "
          "changes nothing else",
          "[test_command][json]")
{
    TestLab lab;
    lab.wall_now = [&lab] {
        // Throws only for the summary's two readings: at total's start and
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
    const json summary = lab.summary();
    CHECK(summary.at("started_at").is_null());
    CHECK(summary.at("ended_at").is_null());
    CHECK(summary.at("status").at("status") == "pass");
    CHECK(summary.at("exit_code") == rp::exit_code::ok);
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
