// W4.7: src/scm.hpp, the real calls into the Service Control Manager
// (docs/decisions.md 2026-10-08 points 4, 8 and 9 "The real calls").
//
// What runs unelevated asks only about names that aren't installed. The one
// real service a test makes has the fixed name RestoreProofScmTest, so its own
// display name and its own virtual account; it is created disabled, with a
// command line naming a file that doesn't exist, is never started, and is
// deleted again. A leftover of a run that was cut off is deleted first. No
// test here names the product's service.

#include "../src/scm.hpp"

#include <rp/service.hpp>

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {

// The one service these tests create, and a name nothing ever creates.
constexpr std::string_view kTestService = "RestoreProofScmTest";
constexpr std::string_view kNoService = "RestoreProofScmTestNotInstalled";
static_assert(kTestService != rp::kServiceName && kNoService != rp::kServiceName);

// Windows' codes, as the messages will show them.
constexpr unsigned long kNotInstalled = 1060;       // ERROR_SERVICE_DOES_NOT_EXIST
constexpr unsigned long kMarkedForDeletion = 1072;  // ERROR_SERVICE_MARKED_FOR_DELETE
constexpr unsigned long kAlreadyInstalled = 1073;   // ERROR_SERVICE_EXISTS
constexpr unsigned long kNotStartedByTheScm = 1063; // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT

bool elevated()
{
    HANDLE token = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// Whether the test service is gone, asked every 250 ms for up to 10 s.
bool gone_within_ten_seconds()
{
    for (int i = 0; i < 40; ++i) {
        rp::ServiceStatus status;
        if (rp::scm::query_service(kTestService, status).error == kNotInstalled) {
            return true;
        }
        Sleep(250);
    }
    return false;
}

// Deletes the test service when a test ends, however it ends.
struct TestServiceRemoved {
    TestServiceRemoved() = default;
    TestServiceRemoved(const TestServiceRemoved&) = delete;
    TestServiceRemoved& operator=(const TestServiceRemoved&) = delete;
    ~TestServiceRemoved() { rp::scm::delete_service(kTestService); }
};

} // namespace

// Failure paths first: a service that isn't there.
TEST_CASE("the state of a service that isn't installed is error 1060", "[scm]")
{
    rp::ServiceStatus status;
    status.state = rp::ServiceState::running;
    status.checkpoint = 7;

    const rp::ScmResult result = rp::scm::query_service(kNoService, status);

    CHECK(result.error == kNotInstalled);
    // Connecting worked, anyone may; opening the service is what failed.
    CHECK(result.step == rp::ScmStep::service);
    // Nothing was read, so nothing was written.
    CHECK(status.state == rp::ServiceState::running);
    CHECK(status.checkpoint == 7);
}

TEST_CASE("every call on a service that isn't installed is error 1060 at opening it", "[scm]")
{
    const int call = GENERATE(range(0, 6));
    CAPTURE(call);
    rp::ScmResult result;
    rp::ServiceSetup setup;
    switch (call) {
    case 0:
        result = rp::scm::start_service(kNoService);
        break;
    case 1:
        result = rp::scm::stop_service(kNoService);
        break;
    case 2:
        result = rp::scm::delete_service(kNoService);
        break;
    case 3:
        result = rp::scm::set_description(kNoService, "x");
        break;
    case 4:
        result = rp::scm::set_recovery(kNoService, rp::service_setup(kNoService, "x").failure_actions,
                                       86'400);
        break;
    default:
        setup.name = "as it was";
        result = rp::scm::read_setup(kNoService, setup);
        CHECK(setup.name == "as it was");
        break;
    }
    // Unelevated too: anyone may connect, and Windows looks for the service
    // before it looks at the caller's rights.
    CHECK(result.error == kNotInstalled);
    CHECK(result.step == rp::ScmStep::service);
}

TEST_CASE("a name that isn't UTF-8 is refused before the SCM is asked", "[scm]")
{
    const std::string name = "RestoreProofScmTest\xff";
    rp::ServiceStatus status;

    const rp::ScmResult result = rp::scm::query_service(name, status);

    CHECK(result.error == 87); // ERROR_INVALID_PARAMETER
    CHECK(result.step == rp::ScmStep::call);
}

TEST_CASE("the dispatcher refuses a process the SCM didn't start with error 1063", "[scm]")
{
    std::atomic<int> runs{0};
    // 1063 for the process's first call; Windows answers a later one 1056
    // (seen when every test case runs in one process, as the coverage run's).
    const unsigned long expected = rp::test::next_real_dispatcher_answer();

    const unsigned long error = rp::scm::run_dispatcher(kTestService, [&runs] { ++runs; });

    CHECK(error == expected);
    CHECK((expected == kNotStartedByTheScm || expected == 1056ul));
    CHECK(runs == 0);
}

TEST_CASE("a status can't be reported by a process that registered no handler", "[scm]")
{
    rp::ServiceReport report;
    report.state = rp::ServiceState::running;
    report.accepts_stop = true;

    CHECK(rp::scm::report_status(report) == 6); // ERROR_INVALID_HANDLE
}

// Registering a handler outside a service isn't tried: on this Windows the
// call answers with an access violation's number (0xC0000005) as its error, a
// fault it caught inside itself, and no test should lean on that. The fake
// host runs the handler; the live run registers the real one.

TEST_CASE("a service is created from service_setup, read back, and deleted", "[scm]")
{
    if (!elevated()) {
        SKIP("creating a service needs an administrator's SCM handle: run elevated");
    }
    // A leftover of a run that was cut off goes first.
    const rp::ScmResult leftover = rp::scm::delete_service(kTestService);
    if (leftover.error == kMarkedForDeletion) {
        SKIP("RestoreProofScmTest is marked for deletion: close services.msc and any other "
             "tool that has it open");
    }
    if (leftover.error == 0 && !gone_within_ten_seconds()) {
        SKIP("a leftover RestoreProofScmTest is marked for deletion and didn't go within 10 s: "
             "close services.msc and any other tool that has it open");
    }
    if (leftover.error != 0) {
        REQUIRE(leftover.error == kNotInstalled);
    }

    // The product's setup under the test's name, with two fields changed so
    // that a leftover can never run: disabled, and a file that doesn't exist.
    const rp::test::TempDir dir;
    // UTF-8, as the calls take it: a temp folder's name needn't be ASCII.
    const std::u8string executable_u8 = (dir.path() / "no-such-rpworker.exe").u8string();
    const std::string executable{executable_u8.begin(), executable_u8.end()};
    rp::ServiceSetup setup =
        rp::service_setup(kTestService, "\"" + executable + "\" service run");
    setup.start_type = rp::ServiceStartType::disabled;
    REQUIRE(setup.display_name == "RestoreProofScmTest Worker");
    REQUIRE(setup.account == "NT SERVICE\\RestoreProofScmTest");
    REQUIRE(setup.failure_actions.size() == 4);

    const TestServiceRemoved removed_at_the_end;
    const rp::ScmResult created = rp::scm::create_service(setup);
    if (created.error == kMarkedForDeletion) {
        SKIP("RestoreProofScmTest is marked for deletion: close services.msc and any other "
             "tool that has it open");
    }
    REQUIRE(created.error == 0);

    // It is there, stopped, and has never run.
    rp::ServiceStatus status;
    status.state = rp::ServiceState::running;
    REQUIRE(rp::scm::query_service(kTestService, status).error == 0);
    CHECK(status.state == rp::ServiceState::stopped);
    CHECK(status.win32_exit_code == 1077); // ERROR_SERVICE_NEVER_STARTED
    CHECK(status.checkpoint == 0);

    // A second create changes nothing and says the name is taken.
    const rp::ScmResult again = rp::scm::create_service(setup);
    CHECK(again.error == kAlreadyInstalled);
    CHECK(again.step == rp::ScmStep::call);

    // Before the two calls that set them, no description and no actions.
    rp::ServiceSetup read;
    REQUIRE(rp::scm::read_setup(kTestService, read).error == 0);
    CHECK(read.description.empty());
    CHECK(read.failure_actions.empty());
    CHECK(read.reset_period_s == 0);

    REQUIRE(rp::scm::set_description(kTestService, setup.description).error == 0);
    REQUIRE(rp::scm::set_recovery(kTestService, setup.failure_actions, setup.reset_period_s)
                .error == 0);

    REQUIRE(rp::scm::read_setup(kTestService, read).error == 0);
    CHECK(read.name == kTestService);
    CHECK(read.display_name == "RestoreProofScmTest Worker");
    CHECK(read.description == rp::kServiceDescription);
    CHECK(read.account == "NT SERVICE\\RestoreProofScmTest");
    CHECK(read.start_type == rp::ServiceStartType::disabled);
    CHECK(read.command_line == setup.command_line);
    // The four actions as written, the fourth "none" included.
    const std::vector<rp::ServiceAction> actions{
        {rp::ServiceActionKind::restart, 60'000},
        {rp::ServiceActionKind::restart, 60'000},
        {rp::ServiceActionKind::restart, 60'000},
        {rp::ServiceActionKind::none, 0},
    };
    CHECK(read.failure_actions == actions);
    CHECK(read.reset_period_s == 86'400);
    CHECK(read == setup);

    // Disabled: a start is refused by the SCM itself (1058), nothing runs.
    // (Never sent here: the test never starts anything.)

    // Deleted, and then gone: nothing else holds a handle to it.
    const rp::ScmResult deleted = rp::scm::delete_service(kTestService);
    CHECK(deleted.error == 0);
    CHECK(gone_within_ten_seconds());
}

// ---------------------------------------------------------------------------
// The source scan (point 8). The SCM is reached through its API in one file,
// the process is ended in one place, and nothing ever starts another process
// (no sc.exe, no PowerShell). The scan reads the text as it is, comments
// included, so a comment says "the dispatcher" or "ends the process" and not
// the call's name.

namespace {

// Windows' service functions and handle types, by the part every variant of a
// name shares (the W and A forms, the Ex forms, the Ctrl dispatcher).
constexpr std::array<std::string_view, 21> kServiceNames{
    "OpenSCManager",
    "CreateService",
    "OpenService",
    "DeleteService",
    "StartService",
    "ControlService",
    "QueryServiceStatus",
    "QueryServiceConfig",
    "ChangeServiceConfig",
    "SetServiceStatus",
    "RegisterServiceCtrlHandler",
    "CloseServiceHandle",
    "EnumServicesStatus",
    "EnumDependentServices",
    "NotifyServiceStatusChange",
    "QueryServiceObjectSecurity",
    "SetServiceObjectSecurity",
    "LockServiceDatabase",
    "SC_HANDLE",
    "SERVICE_STATUS_HANDLE",
    "SERVICE_TABLE_ENTRY",
};

// Calls that end the process, as whole identifiers: recorded_exit_code and
// exit_process are other words.
constexpr std::array<std::string_view, 6> kProcessEnders{
    "ExitProcess", "TerminateProcess", "_exit", "_Exit", "quick_exit", "abort",
};
// The same, for names that are also plain words: only when called.
constexpr std::array<std::string_view, 2> kProcessEndersWhenCalled{"exit", "terminate"};

// Calls that start a process: Windows' by the part every variant shares, the
// runtime's as whole identifiers or by their family's start.
constexpr std::array<std::string_view, 3> kProcessStarterNames{
    "CreateProcess",
    "ShellExecute",
    "WinExec",
};
constexpr std::array<std::string_view, 4> kProcessStarters{"_popen", "_wpopen", "popen",
                                                           "_wsystem"};
constexpr std::array<std::string_view, 4> kProcessStarterFamilies{"_spawn", "_wspawn", "_exec",
                                                                  "_wexec"};
constexpr std::array<std::string_view, 1> kProcessStartersWhenCalled{"system"};

bool identifier_char(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

// One identifier of `source` and whether a call's parenthesis follows it,
// white space between them or not.
struct Word {
    std::string_view text;
    bool called = false;
};

std::vector<Word> words_of(std::string_view source)
{
    std::vector<Word> words;
    for (std::size_t at = 0; at < source.size();) {
        if (!identifier_char(source[at])) {
            ++at;
            continue;
        }
        std::size_t end = at;
        while (end < source.size() && identifier_char(source[end])) {
            ++end;
        }
        std::size_t next = end;
        while (next < source.size() && std::isspace(static_cast<unsigned char>(source[next]))) {
            ++next;
        }
        words.push_back({source.substr(at, end - at), next < source.size() && source[next] == '('});
        at = end;
    }
    return words;
}

template <std::size_t N>
bool one_of(const std::array<std::string_view, N>& names, std::string_view word)
{
    return std::find(names.begin(), names.end(), word) != names.end();
}

// What in `source` only src/scm.cpp may hold: a service function or handle
// type of Windows, or a call that ends the process.
std::vector<std::string> find_scm_only(std::string_view source)
{
    std::vector<std::string> found;
    for (std::string_view name : kServiceNames) {
        if (source.find(name) != std::string_view::npos) {
            found.emplace_back(name);
        }
    }
    for (const Word& word : words_of(source)) {
        if (one_of(kProcessEnders, word.text) ||
            (word.called && one_of(kProcessEndersWhenCalled, word.text))) {
            found.emplace_back(word.text);
        }
    }
    return found;
}

// What no Worker source may hold: a call that starts a process.
std::vector<std::string> find_process_starts(std::string_view source)
{
    std::vector<std::string> found;
    for (std::string_view name : kProcessStarterNames) {
        if (source.find(name) != std::string_view::npos) {
            found.emplace_back(name);
        }
    }
    for (const Word& word : words_of(source)) {
        const bool family =
            std::any_of(kProcessStarterFamilies.begin(), kProcessStarterFamilies.end(),
                        [&word](std::string_view start) { return word.text.starts_with(start); });
        if (family || one_of(kProcessStarters, word.text) ||
            (word.called && one_of(kProcessStartersWhenCalled, word.text))) {
            found.emplace_back(word.text);
        }
    }
    return found;
}

} // namespace

TEST_CASE("the scan flags Windows' service functions and calls that end the process", "[scm]")
{
    const std::string_view planted = GENERATE(
        // The SCM's functions, in every form.
        "OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)", "OpenSCManagerA(0, 0, 1)",
        "CreateServiceW(manager, name, display, 0, 0, 0, 0, path, 0, 0, 0, 0, 0)",
        "::OpenServiceW(manager, L\"RestoreProof\", SERVICE_START)", "DeleteService(service);",
        "StartServiceW(service, 0, nullptr)", "StartServiceCtrlDispatcherW(table)",
        "ControlService(service, SERVICE_CONTROL_STOP, &status)",
        "ControlServiceExW(service, 1, 1, &reason)", "QueryServiceStatus(service, &status)",
        "QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, b, n, &m)",
        "QueryServiceConfigW(service, config, n, &m)", "QueryServiceConfig2W(service, 1, b, n, &m)",
        "ChangeServiceConfigW(service", "ChangeServiceConfig2W(service, 2, &actions)",
        "SetServiceStatus(handle, &status)", "RegisterServiceCtrlHandlerExW(name, handler, 0)",
        "RegisterServiceCtrlHandlerW(name, handler)", "CloseServiceHandle(service);",
        "EnumServicesStatusExW(", "EnumDependentServicesW(", "NotifyServiceStatusChangeW(",
        "QueryServiceObjectSecurity(", "SetServiceObjectSecurity(", "LockServiceDatabase(",
        "SC_HANDLE manager = nullptr;", "SERVICE_STATUS_HANDLE g_status;",
        "const SERVICE_TABLE_ENTRYW table[2]{};",
        // A function pointer, a comment, a macro.
        "auto f = &StartServiceW;", "// then DeleteService marks it",
        "#define START StartServiceW",
        // Ending the process.
        "ExitProcess(1);", "::ExitProcess(code)", "TerminateProcess(GetCurrentProcess(), 1);",
        "_exit(1);", "::_exit(code)", "_Exit(1);", "std::_Exit(1)", "quick_exit(1);",
        "std::quick_exit(0)", "abort();", "std::abort();", "std::abort ()", "auto f = &abort;",
        "std::set_terminate(std::abort);", "// escaping wmain it would end in abort()",
        "exit(1);", "std::exit(code)", "exit (1)", "std::exit\n(1)", "std::terminate();",
        "terminate ()");
    CAPTURE(planted);
    CHECK_FALSE(find_scm_only(planted).empty());
}

TEST_CASE("the scan flags every call that starts a process", "[scm]")
{
    const std::string_view planted = GENERATE(
        "CreateProcessW(nullptr, line, 0, 0, FALSE, 0, 0, 0, &si, &pi)", "CreateProcessA(",
        "CreateProcessAsUserW(token, ", "CreateProcessWithLogonW(", "CreateProcessWithTokenW(",
        "ShellExecuteW(nullptr, L\"open\", L\"sc.exe\", args, nullptr, 0)",
        "ShellExecuteExW(&info)", "ShellExecuteA(", "WinExec(\"sc stop RestoreProof\", 0)",
        "system(\"sc stop RestoreProof\");", "std::system(command.c_str())", "::system (line)",
        "std::system\n    (line)", "_wsystem(L\"sc.exe query RestoreProof\")",
        "_popen(\"sc query\", \"r\")", "_wpopen(L\"sc query\", L\"r\")", "popen(\"sc\", \"r\")",
        "auto open = &_popen;", "_spawnl(_P_WAIT, \"sc.exe\", \"sc.exe\", nullptr)",
        "_wspawnvp(_P_NOWAIT, name, args)", "_execl(\"sc.exe\", \"sc.exe\", nullptr)",
        "_wexecvp(name, args)",
        // A comment is read as code is: the price of a scan with no parser.
        "// the file system (as the SCM sees it)");
    CAPTURE(planted);
    CHECK_FALSE(find_process_starts(planted).empty());
}

TEST_CASE("the scan passes the Worker's own names and plain words", "[scm]")
{
    const std::string_view legitimate = GENERATE(
        // The seams' own names.
        "calls.create_service(setup)", "calls.delete_service(name)", "calls.start_service(name)",
        "calls.stop_service(name)", "calls.query_service(name, status)", "host.exit_process(1);",
        "host.report_status(report)", "host.run_dispatcher(name, main)",
        "std::function<void(int code)> exit_process;", "rp::ServiceStatus status;",
        "rp::ServiceSetup setup = rp::service_setup(kServiceName, line);",
        "ServiceControlHandler handler", "ERROR_SERVICE_SPECIFIC_ERROR", "SERVICE_RUNNING",
        // Words that hold a banned one.
        "int recorded_exit_code(const FixtureRecorder* recorder, int code) noexcept",
        "exit_code::transient", "return exit_code_of(status);", "int exit = 0;",
        "the process's exit code", "exits with (or without) a line", "rp::AbandonedRunLock",
        "an abandoned mutex", "terminated(by)", "std::system_category()",
        "throw std::system_error(code, std::system_category(), \"x\");",
        "std::chrono::system_clock::now()", "std::filesystem::path file(folder);",
        "std::filesystem::exists(path)", "// the outbox's calls into the file system, W4.6",
        "// the operating system's own account", "execute(request)", "spawned", "popen_count",
        "process_starts(source)");
    CAPTURE(legitimate);
    CHECK(find_scm_only(legitimate).empty());
    CHECK(find_process_starts(legitimate).empty());
}

TEST_CASE("only src/scm.cpp names a service function or ends the process, and no Worker source "
          "starts one",
          "[scm]")
{
    const std::filesystem::path root{RP_SOURCE_DIR};
    std::size_t scanned = 0;
    bool saw_scm = false;
    for (const char* dir : {"src", "include", "app"}) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root / dir)) {
            const std::filesystem::path& path = entry.path();
            if (!entry.is_regular_file() ||
                (path.extension() != ".cpp" && path.extension() != ".hpp" &&
                 path.extension() != ".h")) {
                continue;
            }
            std::ifstream file(path, std::ios::binary);
            const std::string text{std::istreambuf_iterator<char>(file), {}};
            const std::string name = path.lexically_relative(root).generic_string();
            CAPTURE(name);
            CHECK(find_process_starts(text) == std::vector<std::string>{});
            if (name == "src/scm.cpp") {
                // The scan isn't blind: it sees what this file is there for.
                saw_scm = true;
                const std::vector<std::string> found = find_scm_only(text);
                for (const char* expected :
                     {"OpenSCManager", "CreateService", "StartService", "ControlService",
                      "DeleteService", "QueryServiceStatus", "ChangeServiceConfig",
                      "RegisterServiceCtrlHandler", "SetServiceStatus", "TerminateProcess"}) {
                    CAPTURE(expected);
                    CHECK(std::find(found.begin(), found.end(), expected) != found.end());
                }
            } else {
                CHECK(find_scm_only(text) == std::vector<std::string>{});
            }
            ++scanned;
        }
    }
    // The scan saw the Worker's sources, so it isn't looking in the wrong place.
    CHECK(scanned >= 100);
    CHECK(saw_scm);
}
