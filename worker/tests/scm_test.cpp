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

#include <atomic>
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

    const unsigned long error = rp::scm::run_dispatcher(kTestService, [&runs] { ++runs; });

    CHECK(error == kNotStartedByTheScm);
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
    const std::string executable = (dir.path() / "no-such-rpworker.exe").string();
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
