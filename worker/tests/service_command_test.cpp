// `rpworker service install|uninstall|start|stop|run` (rp/service_command.hpp;
// W4.7, docs/decisions.md 2026-10-08 points 2 and 9): every line and exit
// code, with the calls made counted, on the fake SCM of tests/service_lab.hpp.
// No test here touches the machine's Service Control Manager, its real
// service or %ProgramData%, and none really waits: the clock is the fake's.
// Failure paths first.

#include <rp/cli.hpp>
#include <rp/service.hpp>
#include <rp/service_command.hpp>
#include <rp/version.hpp>

#include "service_lab.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using Args = std::vector<std::string_view>;
using Calls = std::vector<std::string>;
using rp::ScmResult;
using rp::ScmStep;
using rp::ServiceState;
using rp::test::service_lab::FakeScm;
using rp::test::service_lab::in_state;
using rp::test::service_lab::query_error;
using rp::test::service_lab::QueryAnswer;

const std::string kUsage{rp::kCliUsage};
const std::string kDenied =
    "service error: access denied; run this from an elevated prompt (Administrators)";
const std::string kNotInstalled = "service error: the service RestoreProof is not installed";
const std::string kMarked =
    "service error: the service RestoreProof is marked for deletion; close services.msc and any "
    "other tool that has it open, then try again";
const std::string kNotInstalledAfter = "; the service was not installed";
const std::string kLeftInstalled =
    "; the service was left installed: run rpworker service uninstall";
const std::string kMakeFolder = R"(make_folder C:\ProgramData\RestoreProof\logs)";
const std::string kCommandLine = R"("C:\Program Files\RestoreProof\rpworker.exe" service run)";
const std::string kInstalledSecond =
    "account NT SERVICE\\RestoreProof, automatic start, restart after 60 s up to 3 times; not "
    "started: run rpworker service start\n";

struct Ran {
    int code;
    std::string out;
    std::string err;
};

Ran run(FakeScm& scm, const Args& args)
{
    std::ostringstream out;
    std::ostringstream err;
    const int code = rp::run_service_command(args, out, err, scm.env());
    return {code, out.str(), err.str()};
}

// The command with a stdout that takes nothing.
Ran run_unheard(FakeScm& scm, const Args& args)
{
    std::ostringstream out;
    out.setstate(std::ios::failbit);
    std::ostringstream err;
    const int code = rp::run_service_command(args, out, err, scm.env());
    return {code, out.str(), err.str()};
}

// One refusal: what the call answered, the line it makes and the exit code.
struct Refusal {
    ScmResult answer;
    std::string line;
    int code;
};

// `n` times `first`, then `last`.
std::vector<QueryAnswer> then(std::size_t n, const QueryAnswer& first, const QueryAnswer& last)
{
    std::vector<QueryAnswer> answers(n, first);
    answers.push_back(last);
    return answers;
}

} // namespace

// --- Usage ---------------------------------------------------------------------

TEST_CASE("service: a command line it doesn't take is the usage line, before any call",
          "[service_command]")
{
    const Args args = GENERATE(
        Args{},
        Args{""},
        Args{"Install"},
        Args{"restart"},
        Args{"status"},
        Args{"--config", "C:\\config.json"},
        // A word too many.
        Args{"install", "extra"},
        Args{"install", "run"},
        Args{"uninstall", "extra"},
        Args{"start", "now"},
        Args{"stop", "--force"},
        Args{"run", "extra"},
        Args{"install", "--config", "C:\\config.json", "extra"},
        // --config without its value, with an empty one, twice.
        Args{"install", "--config"},
        Args{"install", "--config", ""},
        Args{"install", "--config", "C:\\a.json", "--config", "C:\\b.json"},
        Args{"run", "--config"},
        Args{"run", "--config", ""},
        Args{"run", "--config", "C:\\a.json", "--config", "C:\\b.json"},
        // An option the subcommand doesn't take.
        Args{"uninstall", "--config", "C:\\config.json"},
        Args{"start", "--config", "C:\\config.json"},
        Args{"stop", "--config", "C:\\config.json"},
        Args{"install", "--vault", "C:\\vault.bin"},
        Args{"run", "--vault", "C:\\vault.bin"},
        Args{"install", "--name", "Other"});
    CAPTURE(args);
    FakeScm scm;

    const Ran ran = run(scm, args);

    CHECK(ran.code == 64);
    CHECK(ran.out.empty());
    CHECK(ran.err == kUsage);
    CHECK(scm.calls.empty());
}

// --- install: refusals -----------------------------------------------------------

TEST_CASE("service install: --config must be an absolute path, and nothing is called",
          "[service_command][install]")
{
    const std::string_view path = GENERATE(
        std::string_view{"config.json"}, std::string_view{"..\\config.json"},
        std::string_view{".\\RestoreProof\\config.json"},
        // No drive, and a drive with no root: both depend on where the process is.
        std::string_view{"\\ProgramData\\RestoreProof\\config.json"},
        std::string_view{"C:config.json"},
        // No file has such a name, and the service's command line couldn't hold it.
        std::string_view{"C:\\Program\"Data\\config.json"});
    CAPTURE(path);
    FakeScm scm;

    const Ran ran = run(scm, {"install", "--config", path});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: --config must be an absolute path; a service's working "
                     "directory is System32\n");
    CHECK(scm.calls.empty());
}

TEST_CASE("service install and run: a --config path that isn't UTF-8 is refused before any call",
          "[service_command][install][run]")
{
    const std::string_view subcommand =
        GENERATE(std::string_view{"install"}, std::string_view{"run"});
    CAPTURE(subcommand);
    FakeScm scm;

    const Ran ran = run(scm, {subcommand, "--config", "C:\\\xff\\config.json"});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the --config path is not valid UTF-8\n");
    CHECK(scm.calls.empty());
}

TEST_CASE("service install: a create that is refused ends there, with no folder made",
          "[service_command][install]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{5, ScmStep::manager}, kDenied, 1},
        Refusal{{5, ScmStep::call}, kDenied, 1},
        Refusal{{1073, ScmStep::call},
                "service error: the service RestoreProof is already installed; uninstall it first",
                1},
        Refusal{{1078, ScmStep::call},
                "service error: the display name RestoreProof Worker is in use by another service",
                1},
        Refusal{{1072, ScmStep::call}, kMarked, 3},
        Refusal{{1722, ScmStep::manager},
                "service error: opening the service control manager failed (error 1722)", 1},
        Refusal{{87, ScmStep::call}, "service error: creating the service failed (error 87)", 1},
        // `install` has no "not installed" line: 1060 is no answer to a create.
        Refusal{{1060, ScmStep::call}, "service error: creating the service failed (error 1060)",
                1},
        Refusal{{8, ScmStep::service}, "service error: opening the service failed (error 8)", 1});
    CAPTURE(row.answer.error, row.line);
    FakeScm scm;
    scm.create = {row.answer};

    const Ran ran = run(scm, {"install"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"create"});
}

TEST_CASE("service install: a step that fails after the create deletes what the create made",
          "[service_command][install]")
{
    // Which step fails: (c) the folder, (d) the description, (e) the actions.
    const char step = GENERATE('c', 'd', 'e');
    struct Deleted {
        ScmResult answer;
        std::string ending;
    };
    const Deleted deleted = GENERATE_REF(
        Deleted{{0, ScmStep::call}, kNotInstalledAfter},
        // Gone already: not installed, whoever took it away.
        Deleted{{1060, ScmStep::service}, kNotInstalledAfter},
        Deleted{{5, ScmStep::service}, kLeftInstalled},
        Deleted{{1072, ScmStep::call}, kLeftInstalled},
        Deleted{{1722, ScmStep::manager}, kLeftInstalled});
    CAPTURE(step, deleted.answer.error);
    FakeScm scm;
    scm.remove = {deleted.answer};
    Calls calls{"create", kMakeFolder};
    std::string line;
    if (step == 'c') {
        scm.make_folder_error = 5;
        // The folder's own failure, never "run this from an elevated prompt":
        // the SCM took the caller for an administrator one step earlier.
        line = "service error: making the log folder failed (error 5)";
    }
    if (step == 'd') {
        scm.description = {{13, ScmStep::call}};
        calls.push_back("set_description");
        line = "service error: setting the description failed (error 13)";
    }
    if (step == 'e') {
        scm.recovery = {{87, ScmStep::call}};
        calls.push_back("set_description");
        calls.push_back("set_recovery");
        line = "service error: setting the recovery actions failed (error 87)";
    }
    calls.push_back("delete");

    const Ran ran = run(scm, {"install"});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == line + deleted.ending + "\n");
    CHECK(scm.calls == calls);
}

TEST_CASE("service install: a failed step's line is the shared refusal, with the roll-back's end",
          "[service_command][install]")
{
    const bool at_description = GENERATE(true, false);
    const Refusal row = GENERATE_REF(
        Refusal{{5, ScmStep::service}, kDenied, 1},
        Refusal{{1072, ScmStep::call}, kMarked, 3},
        Refusal{{1060, ScmStep::service}, "service error: opening the service failed (error 1060)",
                1},
        Refusal{{6, ScmStep::manager},
                "service error: opening the service control manager failed (error 6)", 1});
    CAPTURE(at_description, row.answer.error);
    FakeScm scm;
    (at_description ? scm.description : scm.recovery) = {row.answer};

    const Ran ran = run(scm, {"install"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + kNotInstalledAfter + "\n");
    CHECK(scm.count("delete") == 1);
    CHECK(scm.count("set_recovery") == (at_description ? 0u : 1u));
}

// --- uninstall: refusals ---------------------------------------------------------

TEST_CASE("service uninstall: a state that can't be read ends there",
          "[service_command][uninstall]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{5, ScmStep::manager}, kDenied, 1},
        Refusal{{1060, ScmStep::service}, kNotInstalled, 1},
        Refusal{{1072, ScmStep::service}, kMarked, 3},
        Refusal{{6, ScmStep::call}, "service error: reading the service's state failed (error 6)",
                1},
        Refusal{{1722, ScmStep::manager},
                "service error: opening the service control manager failed (error 1722)", 1},
        Refusal{{8, ScmStep::service}, "service error: opening the service failed (error 8)", 1});
    CAPTURE(row.answer.error, row.line);
    FakeScm scm;
    scm.queries = {query_error(row.answer.error, row.answer.step)};

    const Ran ran = run(scm, {"uninstall"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"query"});
}

TEST_CASE("service uninstall: a service that isn't stopped is not deleted",
          "[service_command][uninstall]")
{
    const ServiceState state =
        GENERATE(ServiceState::running, ServiceState::start_pending, ServiceState::stop_pending,
                 ServiceState::paused, ServiceState::pause_pending, ServiceState::continue_pending);
    CAPTURE(static_cast<int>(state));
    FakeScm scm;
    scm.queries = {in_state(state)};

    const Ran ran = run(scm, {"uninstall"});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof is running; stop it first (rpworker "
                     "service stop)\n");
    CHECK(scm.calls == Calls{"query"});
}

TEST_CASE("service uninstall: a delete that is refused", "[service_command][uninstall]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{5, ScmStep::service}, kDenied, 1},
        Refusal{{1060, ScmStep::service}, kNotInstalled, 1},
        Refusal{{1072, ScmStep::call}, kMarked, 3},
        Refusal{{6, ScmStep::call}, "service error: deleting the service failed (error 6)", 1});
    CAPTURE(row.answer.error, row.line);
    FakeScm scm;
    scm.remove = {row.answer};

    const Ran ran = run(scm, {"uninstall"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"query", "delete"});
}

TEST_CASE("service uninstall: a service still there after 10 s is marked for deletion, exit 3",
          "[service_command][uninstall]")
{
    FakeScm scm;
    // Stopped at every read: something else holds a handle to it.

    const Ran ran = run(scm, {"uninstall"});

    CHECK(ran.code == 3);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof is marked for deletion; it goes when "
                     "services.msc and any other tool that has it open are closed\n");
    CHECK(scm.count("delete") == 1);
    // The read before the delete, then one every 250 ms from 0 s to 10 s.
    CHECK(scm.count("query") == 1 + 41);
    CHECK(scm.count("sleep 250") == 40);
    CHECK(scm.calls.size() == 1 + 1 + 41 + 40);
    CHECK(scm.calls.back() == "query");
    CHECK(scm.clock == std::chrono::milliseconds{10'000});
}

TEST_CASE("service uninstall: a state that can't be read while it waits is that refusal",
          "[service_command][uninstall]")
{
    FakeScm scm;
    scm.queries = {in_state(ServiceState::stopped), in_state(ServiceState::stopped),
                   query_error(5, ScmStep::manager)};

    const Ran ran = run(scm, {"uninstall"});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == kDenied + "\n");
    CHECK(scm.calls == Calls{"query", "delete", "query", "sleep 250", "query"});
}

// --- start: refusals -------------------------------------------------------------

TEST_CASE("service start: a start that is refused", "[service_command][start]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{5, ScmStep::manager}, kDenied, 1},
        Refusal{{5, ScmStep::service}, kDenied, 1},
        Refusal{{1060, ScmStep::service}, kNotInstalled, 1},
        Refusal{{1072, ScmStep::call}, kMarked, 3},
        Refusal{{1058, ScmStep::call}, "service error: the service RestoreProof is disabled", 1},
        Refusal{{1069, ScmStep::call},
                "service error: NT SERVICE\\RestoreProof couldn't log on (error 1069); it needs "
                "the \"Log on as a service\" right",
                1},
        Refusal{{2, ScmStep::call},
                "service error: the service's executable isn't where it was installed from; "
                "uninstall and install again",
                1},
        Refusal{{3, ScmStep::call},
                "service error: the service's executable isn't where it was installed from; "
                "uninstall and install again",
                1},
        // Elevated, and still refused: the start itself was denied, which is
        // the account's access to the executable and not the caller's rights.
        Refusal{{5, ScmStep::call},
                "service error: NT SERVICE\\RestoreProof was denied access when starting (error "
                "5); it must be able to read and run the service's executable",
                1},
        Refusal{{1053, ScmStep::call}, "service error: starting the service failed (error 1053)",
                1},
        Refusal{{1722, ScmStep::manager},
                "service error: opening the service control manager failed (error 1722)", 1},
        Refusal{{8, ScmStep::service}, "service error: opening the service failed (error 8)", 1});
    CAPTURE(row.answer.error, row.line);
    FakeScm scm;
    scm.start = {row.answer};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"start"});
}

TEST_CASE("service start: a service that stops while starting says why and names the log",
          "[service_command][start]")
{
    struct Row {
        unsigned long win32;
        unsigned long own;
        std::string reason;
    };
    const Row row = GENERATE_REF(
        Row{1066, 1, "the config couldn't be loaded"},
        Row{1066, 2, "the log couldn't be opened"},
        Row{1066, 3, "service error 3"},
        Row{1066, 0, "service error 0"},
        Row{1067, 0, "Windows error 1067"},
        // The service's own code counts only under Windows' 1066.
        Row{1067, 1, "Windows error 1067"},
        Row{0, 0, "Windows error 0"});
    CAPTURE(row.win32, row.own);
    FakeScm scm;
    scm.queries = then(2, in_state(ServiceState::start_pending),
                       in_state(ServiceState::stopped, row.win32, row.own));

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof stopped while starting (" +
                         row.reason + "); see C:\\ProgramData\\RestoreProof\\logs\\worker.log\n");
    CHECK(scm.calls == Calls{"start", "query", "sleep 250", "query", "sleep 250", "query"});
}

TEST_CASE("service start: still starting after 30 s is exit 3", "[service_command][start]")
{
    // Stopping at a read is not yet stopped either: the wait goes on.
    const ServiceState state = GENERATE(ServiceState::start_pending, ServiceState::stop_pending);
    FakeScm scm;
    scm.queries = {in_state(state)};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == 3);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof is still starting after 30 s\n");
    CHECK(scm.count("start") == 1);
    // One read every 250 ms from 0 s to 30 s.
    CHECK(scm.count("query") == 121);
    CHECK(scm.count("sleep 250") == 120);
    CHECK(scm.calls.size() == 1 + 121 + 120);
    CHECK(scm.clock == std::chrono::milliseconds{30'000});
}

TEST_CASE("service start: the 30 s count from the command's start, the calls' own time included",
          "[service_command][start]")
{
    FakeScm scm;
    scm.call_cost = std::chrono::milliseconds{750};
    scm.queries = {in_state(ServiceState::start_pending)};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == 3);
    // The start ends at 0.75 s, then a read every second: the 30th ends at 30.5 s.
    CHECK(scm.count("query") == 30);
    CHECK(scm.count("sleep 250") == 29);
}

TEST_CASE("service start: a state that can't be read while it waits is that refusal",
          "[service_command][start]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{1060, ScmStep::service}, kNotInstalled, 1},
        Refusal{{5, ScmStep::manager}, kDenied, 1},
        Refusal{{6, ScmStep::call}, "service error: reading the service's state failed (error 6)",
                1});
    CAPTURE(row.answer.error);
    FakeScm scm;
    scm.queries = {in_state(ServiceState::start_pending),
                   query_error(row.answer.error, row.answer.step)};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"start", "query", "sleep 250", "query"});
}

// 1056 is Windows' one answer for a service that isn't stopped: a reason to
// read the state, never the answer.
TEST_CASE("service start: 1056 with the service running is no error", "[service_command][start]")
{
    FakeScm scm;
    scm.start = {{1056, ScmStep::call}};
    scm.queries = {in_state(ServiceState::running)};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == 0);
    CHECK(ran.out == "RestoreProof is already running\n");
    CHECK(ran.err.empty());
    CHECK(scm.calls == Calls{"start", "query"});
}

TEST_CASE("service start: 1056 with the service starting is waited for like a start that was sent",
          "[service_command][start]")
{
    FakeScm scm;
    scm.start = {{1056, ScmStep::call}};

    SECTION("and it runs")
    {
        scm.queries = then(2, in_state(ServiceState::start_pending),
                           in_state(ServiceState::running));
        const Ran ran = run(scm, {"start"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "started RestoreProof\n");
        CHECK(ran.err.empty());
        // The read 1056 asked for, then the wait's.
        CHECK(scm.calls == Calls{"start", "query", "query", "sleep 250", "query"});
    }
    SECTION("and it is still starting after 30 s")
    {
        scm.queries = {in_state(ServiceState::start_pending)};
        const Ran ran = run(scm, {"start"});
        CHECK(ran.code == 3);
        CHECK(ran.err == "service error: the service RestoreProof is still starting after 30 s\n");
        CHECK(scm.count("start") == 1);
        CHECK(scm.count("query") == 1 + 121);
    }
}

TEST_CASE("service start: 1056 with the service stopping is exit 3, and nothing is waited for",
          "[service_command][start]")
{
    FakeScm scm;
    scm.start = {{1056, ScmStep::call}};
    scm.queries = {in_state(ServiceState::stop_pending)};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == 3);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof is stopping; start it again when it "
                     "has stopped\n");
    CHECK(scm.calls == Calls{"start", "query"});
}

TEST_CASE("service start: 1056 with the service stopped by then sends the start once more",
          "[service_command][start]")
{
    FakeScm scm;

    SECTION("which is taken")
    {
        scm.start = {{1056, ScmStep::call}, {0, ScmStep::call}};
        scm.queries = {in_state(ServiceState::stopped), in_state(ServiceState::start_pending),
                       in_state(ServiceState::running)};
        const Ran ran = run(scm, {"start"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "started RestoreProof\n");
        CHECK(ran.err.empty());
        CHECK(scm.calls == Calls{"start", "query", "start", "query", "sleep 250", "query"});
    }
    SECTION("and a second 1056 is the answer")
    {
        scm.start = {{1056, ScmStep::call}};
        scm.queries = {in_state(ServiceState::stopped)};
        const Ran ran = run(scm, {"start"});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "service error: starting the service failed (error 1056)\n");
        CHECK(scm.calls == Calls{"start", "query", "start"});
    }
    SECTION("which is refused for another reason")
    {
        scm.start = {{1056, ScmStep::call}, {1058, ScmStep::call}};
        scm.queries = {in_state(ServiceState::stopped)};
        const Ran ran = run(scm, {"start"});
        CHECK(ran.code == 1);
        CHECK(ran.err == "service error: the service RestoreProof is disabled\n");
        CHECK(scm.calls == Calls{"start", "query", "start"});
    }
}

TEST_CASE("service start: 1056 with a state the service never has is Windows' answer as it is",
          "[service_command][start]")
{
    const ServiceState state =
        GENERATE(ServiceState::paused, ServiceState::pause_pending, ServiceState::continue_pending);
    FakeScm scm;
    scm.start = {{1056, ScmStep::call}};
    scm.queries = {in_state(state)};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: starting the service failed (error 1056)\n");
    CHECK(scm.calls == Calls{"start", "query"});
}

TEST_CASE("service start: 1056 and a state that can't be read", "[service_command][start]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{1060, ScmStep::service}, kNotInstalled, 1},
        Refusal{{1072, ScmStep::service}, kMarked, 3},
        Refusal{{6, ScmStep::call}, "service error: reading the service's state failed (error 6)",
                1});
    FakeScm scm;
    scm.start = {{1056, ScmStep::call}};
    scm.queries = {query_error(row.answer.error, row.answer.step)};

    const Ran ran = run(scm, {"start"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"start", "query"});
}

// --- stop: refusals --------------------------------------------------------------

TEST_CASE("service stop: a stop that is refused", "[service_command][stop]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{5, ScmStep::manager}, kDenied, 1},
        Refusal{{5, ScmStep::service}, kDenied, 1},
        Refusal{{1060, ScmStep::service}, kNotInstalled, 1},
        Refusal{{1072, ScmStep::call}, kMarked, 3},
        Refusal{{1053, ScmStep::call}, "service error: stopping the service failed (error 1053)",
                1},
        Refusal{{1722, ScmStep::manager},
                "service error: opening the service control manager failed (error 1722)", 1},
        Refusal{{8, ScmStep::service}, "service error: opening the service failed (error 8)", 1});
    CAPTURE(row.answer.error, row.line);
    FakeScm scm;
    scm.stop = {row.answer};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"stop"});
}

TEST_CASE("service stop: still not stopped after 35 s is exit 3", "[service_command][stop]")
{
    // The stop taken, or one already under way (1061): the same wait.
    const unsigned long answer = GENERATE(0ul, 1061ul);
    const ServiceState state = GENERATE(ServiceState::stop_pending, ServiceState::running);
    CAPTURE(answer, static_cast<int>(state));
    FakeScm scm;
    scm.stop = {{answer, ScmStep::call}};
    scm.queries = {in_state(state)};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 3);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof is still stopping after 35 s\n");
    CHECK(scm.count("stop") == 1);
    // One read every 250 ms from 0 s to 35 s.
    CHECK(scm.count("query") == 141);
    CHECK(scm.count("sleep 250") == 140);
    CHECK(scm.calls.size() == 1 + 141 + 140);
    CHECK(scm.clock == std::chrono::milliseconds{35'000});
}

TEST_CASE("service stop: a state that can't be read while it waits is that refusal",
          "[service_command][stop]")
{
    const Refusal row = GENERATE_REF(
        Refusal{{1060, ScmStep::service}, kNotInstalled, 1},
        Refusal{{5, ScmStep::manager}, kDenied, 1},
        Refusal{{6, ScmStep::call}, "service error: reading the service's state failed (error 6)",
                1});
    CAPTURE(row.answer.error);
    FakeScm scm;
    scm.queries = {in_state(ServiceState::stop_pending),
                   query_error(row.answer.error, row.answer.step)};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == row.code);
    CHECK(ran.out.empty());
    CHECK(ran.err == row.line + "\n");
    CHECK(scm.calls == Calls{"stop", "query", "sleep 250", "query"});
}

// 1052: a service still starting accepts no control, so the stop wasn't sent.
TEST_CASE("service stop: 1052 twice and then taken", "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1052, ScmStep::call}, {1052, ScmStep::call}, {0, ScmStep::call}};
    scm.queries = then(1, in_state(ServiceState::stop_pending), in_state(ServiceState::stopped));

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 0);
    // From the command's start: two waits to send it, one to see it stopped.
    CHECK(ran.out == "stopped RestoreProof in 0.7 s\n");
    CHECK(ran.err.empty());
    CHECK(scm.calls == Calls{"stop", "sleep 250", "stop", "sleep 250", "stop", "query", "sleep 250",
                             "query"});
}

TEST_CASE("service stop: 1052 and then a stop already under way is waited for",
          "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1052, ScmStep::call}, {1061, ScmStep::call}};
    scm.queries = {in_state(ServiceState::stopped)};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 0);
    CHECK(ran.out == "stopped RestoreProof in 0.2 s\n");
    CHECK(scm.calls == Calls{"stop", "sleep 250", "stop", "query"});
}

// 1061 is also what Windows may say of a service that is still starting. The
// state tells the two apart: while it reads `start pending` after an answer
// that wasn't "taken", the stop is sent again.
TEST_CASE("service stop: 1061 from a service still starting is sent again",
          "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1061, ScmStep::call}, {1061, ScmStep::call}, {0, ScmStep::call}};
    scm.queries = {in_state(ServiceState::start_pending), in_state(ServiceState::start_pending),
                   in_state(ServiceState::stop_pending), in_state(ServiceState::stopped)};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 0);
    CHECK(ran.out == "stopped RestoreProof in 0.7 s\n");
    CHECK(ran.err.empty());
    CHECK(scm.calls == Calls{"stop", "query", "stop", "sleep 250", "query", "stop", "sleep 250",
                             "query", "sleep 250", "query"});
}

TEST_CASE("service stop: 1061 from a service that starts for 35 s was never sent",
          "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1061, ScmStep::call}};
    scm.queries = {in_state(ServiceState::start_pending)};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 3);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof is still starting after 35 s; the "
                     "stop was not sent\n");
    CHECK(scm.count("query") == 141);
    CHECK(scm.count("stop") == 142);
    CHECK(scm.clock == std::chrono::milliseconds{35'000});
}

TEST_CASE("service stop: a stop sent again and refused is that refusal",
          "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1061, ScmStep::call}, {5, ScmStep::service}};
    scm.queries = {in_state(ServiceState::start_pending)};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 1);
    CHECK(ran.err == kDenied + "\n");
    CHECK(scm.calls == Calls{"stop", "query", "stop"});
}

TEST_CASE("service stop: 1052 and then stopped by itself", "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1052, ScmStep::call}, {1062, ScmStep::call}};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 0);
    CHECK(ran.out == "RestoreProof is already stopped\n");
    CHECK(ran.err.empty());
    CHECK(scm.calls == Calls{"stop", "sleep 250", "stop"});
}

TEST_CASE("service stop: 1052 and then refused", "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1052, ScmStep::call}, {5, ScmStep::service}};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 1);
    CHECK(ran.err == kDenied + "\n");
    CHECK(scm.calls == Calls{"stop", "sleep 250", "stop"});
}

TEST_CASE("service stop: 1052 until the 35 s are up, and the stop was never sent",
          "[service_command][stop]")
{
    FakeScm scm;
    scm.stop = {{1052, ScmStep::call}};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 3);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: the service RestoreProof is still starting after 35 s; the "
                     "stop was not sent\n");
    // Sent every 250 ms from 0 s to 35 s; the state is never read.
    CHECK(scm.count("stop") == 141);
    CHECK(scm.count("sleep 250") == 140);
    CHECK(scm.calls.size() == 141 + 140);
    CHECK(scm.clock == std::chrono::milliseconds{35'000});
}

TEST_CASE("service stop: the 35 s are one budget for sending the stop and for waiting",
          "[service_command][stop]")
{
    FakeScm scm;
    // Taken at the 101st send, 25 s in: 10 s are left to see it stopped.
    scm.stop.assign(100, ScmResult{1052, ScmStep::call});
    scm.stop.push_back({0, ScmStep::call});
    scm.queries = {in_state(ServiceState::stop_pending)};

    const Ran ran = run(scm, {"stop"});

    CHECK(ran.code == 3);
    CHECK(ran.err == "service error: the service RestoreProof is still stopping after 35 s\n");
    CHECK(scm.count("stop") == 101);
    CHECK(scm.count("query") == 41);
    CHECK(scm.clock == std::chrono::milliseconds{35'000});
}

// --- The happy paths -------------------------------------------------------------

TEST_CASE("service install: creates the service, makes the log folder, sets the description and "
          "the recovery actions, in that order, and starts nothing",
          "[service_command][install]")
{
    FakeScm scm;

    const Ran ran = run(scm, {"install"});

    CHECK(ran.code == 0);
    CHECK(ran.err.empty());
    CHECK(ran.out == "installed RestoreProof: " + kCommandLine + "\n" + kInstalledSecond);
    CHECK(scm.calls == Calls{"create", kMakeFolder, "set_description", "set_recovery"});

    // What the create was asked for is service_setup's, whole: the name, the
    // display name, the account, automatic start, the command line.
    REQUIRE(scm.created.size() == 1);
    const rp::ServiceSetup expected = rp::service_setup(rp::kServiceName, kCommandLine);
    CHECK(scm.created[0] == expected);
    CHECK(scm.created[0].name == "RestoreProof");
    CHECK(scm.created[0].display_name == "RestoreProof Worker");
    CHECK(scm.created[0].account == "NT SERVICE\\RestoreProof");
    CHECK(scm.created[0].start_type == rp::ServiceStartType::automatic);
    CHECK(scm.created[0].command_line == kCommandLine);
    CHECK(scm.descriptions == std::vector<std::string>{std::string{rp::kServiceDescription}});
    // Restart after 1 min three times, then nothing; the count reset after a day.
    REQUIRE(scm.actions.size() == 1);
    CHECK(scm.actions[0] == expected.failure_actions);
    CHECK(scm.actions[0] ==
          std::vector<rp::ServiceAction>{{rp::ServiceActionKind::restart, 60'000},
                                         {rp::ServiceActionKind::restart, 60'000},
                                         {rp::ServiceActionKind::restart, 60'000},
                                         {rp::ServiceActionKind::none, 0}});
    CHECK(scm.reset_periods == std::vector<unsigned long>{86'400});
}

TEST_CASE("service install --config: the path follows the command line, quoted, and is not read",
          "[service_command][install]")
{
    struct Row {
        std::string_view path;
        std::string quoted;
    };
    const Row row = GENERATE_REF(
        Row{R"(C:\ProgramData\RestoreProof\config.json)",
            R"("C:\ProgramData\RestoreProof\config.json")"},
        Row{R"(D:\Rp Lab\my config.json)", R"("D:\Rp Lab\my config.json")"},
        Row{R"(\\server\share\config.json)", R"("\\server\share\config.json")"},
        // UTF-8 stays UTF-8.
        Row{"C:\\\xd1\x82\xd0\xb5\xd1\x81\xd1\x82\\config.json",
            "\"C:\\\xd1\x82\xd0\xb5\xd1\x81\xd1\x82\\config.json\""},
        // A backslash before the closing quote would take the quote with it.
        Row{R"(C:\configs\)", R"("C:\configs\\")"},
        Row{R"(C:\configs\\)", R"("C:\configs\\\\")"});
    CAPTURE(row.path);
    FakeScm scm;
    const std::string command_line = kCommandLine + " --config " + row.quoted;

    const Ran ran = run(scm, {"install", "--config", row.path});

    CHECK(ran.code == 0);
    CHECK(ran.err.empty());
    CHECK(ran.out == "installed RestoreProof: " + command_line + "\n" + kInstalledSecond);
    REQUIRE(scm.created.size() == 1);
    CHECK(scm.created[0] == rp::service_setup(rp::kServiceName, command_line));
    CHECK(scm.calls == Calls{"create", kMakeFolder, "set_description", "set_recovery"});
}

TEST_CASE("service install: the command line names the executable it was run from",
          "[service_command][install]")
{
    FakeScm scm;
    scm.own_path = std::filesystem::path{L"D:\\\u0442\u0435\u0441\u0442\\rpworker.exe"};
    scm.log_dir = R"(E:\logs here)";

    const Ran ran = run(scm, {"install"});

    CHECK(ran.code == 0);
    REQUIRE(scm.created.size() == 1);
    CHECK(scm.created[0].command_line ==
          "\"D:\\\xd1\x82\xd0\xb5\xd1\x81\xd1\x82\\rpworker.exe\" service run");
    CHECK(scm.calls[1] == R"(make_folder E:\logs here)");
}

TEST_CASE("service install: the paths are asked for before anything is created",
          "[service_command][install]")
{
    FakeScm scm;
    rp::ServiceCommandEnv env = scm.env();
    const bool log_dir = GENERATE(true, false);
    if (log_dir) {
        env.default_log_dir = []() -> std::filesystem::path {
            throw std::runtime_error("no folder");
        };
    } else {
        env.own_path = []() -> std::filesystem::path { throw std::runtime_error("no path"); };
    }
    std::ostringstream out;
    std::ostringstream err;

    // Not caught here: run_cli's "error: unexpected failure".
    CHECK_THROWS_AS(rp::run_service_command(Args{"install"}, out, err, env), std::runtime_error);

    CHECK(scm.calls.empty());
    CHECK(out.str().empty());
    CHECK(err.str().empty());
}

TEST_CASE("service uninstall: one delete, then gone", "[service_command][uninstall]")
{
    FakeScm scm;

    SECTION("at the first read")
    {
        scm.queries = {in_state(ServiceState::stopped), query_error(1060, ScmStep::service)};
        const Ran ran = run(scm, {"uninstall"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "uninstalled RestoreProof\n");
        CHECK(ran.err.empty());
        CHECK(scm.calls == Calls{"query", "delete", "query"});
    }
    SECTION("at the third read")
    {
        scm.queries = {in_state(ServiceState::stopped), in_state(ServiceState::stopped),
                       in_state(ServiceState::stopped), query_error(1060, ScmStep::service)};
        const Ran ran = run(scm, {"uninstall"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "uninstalled RestoreProof\n");
        CHECK(ran.err.empty());
        CHECK(scm.calls ==
              Calls{"query", "delete", "query", "sleep 250", "query", "sleep 250", "query"});
    }
    SECTION("at the last read, 10 s in")
    {
        scm.queries =
            then(41, in_state(ServiceState::stopped), query_error(1060, ScmStep::service));
        const Ran ran = run(scm, {"uninstall"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "uninstalled RestoreProof\n");
        CHECK(scm.count("query") == 42);
    }
}

TEST_CASE("service start: sends the start and waits until the service runs",
          "[service_command][start]")
{
    FakeScm scm;

    SECTION("running at the first read")
    {
        scm.queries = {in_state(ServiceState::running)};
        const Ran ran = run(scm, {"start"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "started RestoreProof\n");
        CHECK(ran.err.empty());
        CHECK(scm.calls == Calls{"start", "query"});
    }
    SECTION("running at the last read, 30 s in")
    {
        scm.queries = then(120, in_state(ServiceState::start_pending),
                           in_state(ServiceState::running));
        const Ran ran = run(scm, {"start"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "started RestoreProof\n");
        CHECK(ran.err.empty());
        CHECK(scm.count("query") == 121);
        CHECK(scm.count("start") == 1);
    }
}

TEST_CASE("service stop: sends the stop and waits until the service has stopped",
          "[service_command][stop]")
{
    FakeScm scm;

    SECTION("stopped at the first read")
    {
        scm.queries = {in_state(ServiceState::stopped)};
        const Ran ran = run(scm, {"stop"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "stopped RestoreProof in 0.0 s\n");
        CHECK(ran.err.empty());
        CHECK(scm.calls == Calls{"stop", "query"});
    }
    SECTION("the time is the command's, cut to a tenth of a second")
    {
        scm.call_cost = std::chrono::milliseconds{130};
        scm.queries =
            then(5, in_state(ServiceState::stop_pending), in_state(ServiceState::stopped));
        const Ran ran = run(scm, {"stop"});
        CHECK(ran.code == 0);
        // The stop and six reads at 130 ms each, five waits of 250 ms: 2,160 ms.
        CHECK(ran.out == "stopped RestoreProof in 2.1 s\n");
        CHECK(ran.err.empty());
    }
    SECTION("a service that stopped with a code of its own has stopped all the same")
    {
        scm.queries = {in_state(ServiceState::stopped, 1066, 3)};
        const Ran ran = run(scm, {"stop"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "stopped RestoreProof in 0.0 s\n");
    }
    SECTION("stopped at the last read, 35 s in")
    {
        scm.queries = then(140, in_state(ServiceState::stop_pending),
                           in_state(ServiceState::stopped));
        const Ran ran = run(scm, {"stop"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "stopped RestoreProof in 35.0 s\n");
        CHECK(scm.count("query") == 141);
    }
    SECTION("already stopped")
    {
        scm.stop = {{1062, ScmStep::call}};
        const Ran ran = run(scm, {"stop"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "RestoreProof is already stopped\n");
        CHECK(ran.err.empty());
        CHECK(scm.calls == Calls{"stop"});
    }
    SECTION("a stop already under way")
    {
        scm.stop = {{1061, ScmStep::call}};
        scm.queries =
            then(2, in_state(ServiceState::stop_pending), in_state(ServiceState::stopped));
        const Ran ran = run(scm, {"stop"});
        CHECK(ran.code == 0);
        CHECK(ran.out == "stopped RestoreProof in 0.5 s\n");
        CHECK(ran.err.empty());
        CHECK(scm.calls == Calls{"stop", "query", "sleep 250", "query", "sleep 250", "query"});
    }
}

// --- An answer nobody got --------------------------------------------------------

TEST_CASE("service: an answer that didn't reach stdout is exit 1", "[service_command]")
{
    FakeScm scm;
    Args args;
    SECTION("install") { args = {"install"}; }
    SECTION("uninstall")
    {
        args = {"uninstall"};
        scm.queries = {in_state(ServiceState::stopped), query_error(1060, ScmStep::service)};
    }
    SECTION("start")
    {
        args = {"start"};
        scm.queries = {in_state(ServiceState::running)};
    }
    SECTION("start, already running")
    {
        args = {"start"};
        scm.start = {{1056, ScmStep::call}};
        scm.queries = {in_state(ServiceState::running)};
    }
    SECTION("stop") { args = {"stop"}; }
    SECTION("stop, already stopped")
    {
        args = {"stop"};
        scm.stop = {{1062, ScmStep::call}};
    }

    const Ran ran = run_unheard(scm, args);

    CHECK(ran.code == 1);
    CHECK(ran.err == "service error: the answer couldn't be written\n");
    // What was done stays done: nothing is rolled back for a lost line.
    CHECK(scm.count("delete") == (args[0] == "uninstall" ? 1u : 0u));
}

// --- run -------------------------------------------------------------------------

TEST_CASE("service run: in a process the SCM didn't start, one line and exit 1",
          "[service_command][run]")
{
    FakeScm scm;
    // `run` holds --config to nothing: the SCM starts what `install` wrote.
    const Args args = GENERATE(Args{"run"}, Args{"run", "--config", "C:\\config.json"},
                               Args{"run", "--config", "config.json"});

    const Ran ran = run(scm, args);

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: service run is what the Service Control Manager starts; use "
                     "rpworker service start\n");
    // The dispatcher and nothing before it or after it.
    CHECK(scm.calls == Calls{"dispatcher"});
}

TEST_CASE("service run: a dispatcher that fails any other way", "[service_command][run]")
{
    FakeScm scm;
    scm.dispatcher_error = 1056;

    const Ran ran = run(scm, {"run"});

    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "service error: opening the service control manager failed (error 1056)\n");
    CHECK(scm.calls == Calls{"dispatcher"});
}

TEST_CASE("service run: under the SCM it is the service, and its exit code the process's",
          "[service_command][run]")
{
    using namespace rp::test::service_lab;
    const rp::test::TempDir tmp;
    const std::filesystem::path config = tmp.write("config.json", config_json());
    const std::filesystem::path other = tmp.write("other.json", config_json("debug"));
    const std::filesystem::path log_dir = tmp.path() / "logs";
    FakeHost fake;
    rp::ServiceCommandEnv env;
    env.host = fake.host();
    env.default_log_dir = [&] { return log_dir; };
    env.default_config_path = [&] { return config; };
    std::ostringstream out;
    std::ostringstream err;
    int code = -1;
    const auto log_text = [&] {
        std::ifstream stream(log_dir / rp::kLogFileName, std::ios::binary);
        std::ostringstream text;
        text << stream.rdbuf();
        return text.str();
    };

    SECTION("a clean stop is exit 0, with nothing printed")
    {
        const bool with_config = GENERATE(false, true);
        const std::string other_arg = utf8_of(other);
        const Args args = with_config ? Args{"run", "--config", other_arg} : Args{"run"};
        // The command on a thread of its own; this one plays the SCM.
        std::thread runner{[&] { code = rp::run_service_command(args, out, err, env); }};
        const bool running = fake.wait_for_state(ServiceState::running);
        if (fake.has_handler()) {
            fake.control(rp::ServiceControl::stop);
        }
        runner.join();
        fake.forget();

        REQUIRE(running);
        CHECK(code == 0);
        CHECK(out.str().empty());
        CHECK(err.str().empty());
        CHECK(fake.exits().empty());
        // The config it loaded: --config, else the default.
        const std::string started = "service running: rpworker " + std::string{rp::version()} +
                                    ", config " + utf8_of(with_config ? other : config) +
                                    ", log_level " + (with_config ? "debug" : "info");
        CHECK(log_text().find(started) != std::string::npos);
    }
    SECTION("a config that doesn't load is exit 1, and the service's own code says why")
    {
        const std::string missing = utf8_of(tmp.path() / "missing.json");
        const Args args{"run", "--config", missing};

        code = rp::run_service_command(args, out, err, env);
        fake.forget();

        CHECK(code == 1);
        CHECK(out.str().empty());
        CHECK(err.str().empty());
        const std::vector<HostEvent> reports = fake.reports();
        REQUIRE_FALSE(reports.empty());
        CHECK(reports.back().report.state == ServiceState::stopped);
        CHECK(reports.back().report.service_exit_code == rp::kServiceCodeConfig);
        CHECK(log_text().find("error config error: ") != std::string::npos);
    }
}

// --- The real environment --------------------------------------------------------

TEST_CASE("service: the real environment is every function null, and the waits are point 2's",
          "[service_command]")
{
    const rp::ServiceCommandEnv env = rp::default_service_command_env();

    CHECK_FALSE(env.scm.create_service);
    CHECK_FALSE(env.scm.set_description);
    CHECK_FALSE(env.scm.set_recovery);
    CHECK_FALSE(env.scm.delete_service);
    CHECK_FALSE(env.scm.start_service);
    CHECK_FALSE(env.scm.stop_service);
    CHECK_FALSE(env.scm.query_service);
    CHECK_FALSE(env.host.run_dispatcher);
    CHECK_FALSE(env.host.register_handler);
    CHECK_FALSE(env.host.report_status);
    CHECK_FALSE(env.host.exit_process);
    CHECK_FALSE(env.own_path);
    CHECK_FALSE(env.default_log_dir);
    CHECK_FALSE(env.default_config_path);
    CHECK_FALSE(env.make_folder);
    CHECK_FALSE(env.sleep);
    CHECK_FALSE(env.now);

    CHECK(rp::kServicePollInterval == std::chrono::milliseconds{250});
    CHECK(rp::kServiceUninstallWait == std::chrono::seconds{10});
    CHECK(rp::kServiceStartWait == std::chrono::seconds{30});
    CHECK(rp::kServiceStopWait == std::chrono::seconds{35});
}

TEST_CASE("service run: with nothing handed in it asks the real dispatcher, which refuses a "
          "process the SCM didn't start",
          "[service_command][run]")
{
    // The one real call a test here makes: it answers 1063 at once and runs
    // nothing (tests/scm_test.cpp). No log folder is made and no config read.
    // To a later call in one process Windows answers 1056, which is the
    // "anything else" line (rp::test::next_real_dispatcher_answer).
    const bool first = rp::test::next_real_dispatcher_answer() == rp::kNotStartedByScm;
    std::ostringstream out;
    std::ostringstream err;

    const int code =
        rp::run_service_command(Args{"run"}, out, err, rp::default_service_command_env());

    CHECK(code == 1);
    CHECK(out.str().empty());
    CHECK(err.str() ==
          (first ? "service error: service run is what the Service Control Manager starts; use "
                   "rpworker service start\n"
                 : "service error: opening the service control manager failed (error 1056)\n"));
}
