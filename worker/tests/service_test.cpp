// W4.7: rp/service.hpp. The service's four names (docs/decisions.md 2026-10-08
// point 1) and rp::service_setup, the one function that fills everything a
// create passes (points 2, 4 and 8): what `service install` asks the SCM for is
// decided here and seen here, on no machine's real service.

#include <rp/service.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

TEST_CASE("the service's four names are point 1's", "[service]")
{
    CHECK(rp::kServiceName == "RestoreProof");
    CHECK(rp::kServiceDisplayName == "RestoreProof Worker");
    CHECK(rp::kServiceDescription ==
          "Tests that Microsoft 365 backups in Veeam Backup for Microsoft 365 restore: restores "
          "a sample into test locations and checks it.");
    CHECK(rp::kServiceAccount == "NT SERVICE\\RestoreProof");
}

TEST_CASE("service_setup for the product's name gives the four constants", "[service]")
{
    const std::string command_line = R"("C:\Program Files\RestoreProof\rpworker.exe" service run)";

    const rp::ServiceSetup setup = rp::service_setup(rp::kServiceName, command_line);

    CHECK(setup.name == rp::kServiceName);
    CHECK(setup.display_name == rp::kServiceDisplayName);
    CHECK(setup.description == rp::kServiceDescription);
    CHECK(setup.account == rp::kServiceAccount);
    // As it was handed in, byte for byte: the quoting is the command's.
    CHECK(setup.command_line == command_line);
}

TEST_CASE("service_setup's settings are the product's", "[service]")
{
    const rp::ServiceSetup setup = rp::service_setup(rp::kServiceName, "x");

    // Automatic start, not delayed (there is no delayed start type to ask for).
    CHECK(setup.start_type == rp::ServiceStartType::automatic);
    // Restart after one minute, three times, then nothing. The fourth entry
    // is what makes "three times" true: Windows repeats a list's last action.
    const std::vector<rp::ServiceAction> expected{
        {rp::ServiceActionKind::restart, 60'000},
        {rp::ServiceActionKind::restart, 60'000},
        {rp::ServiceActionKind::restart, 60'000},
        {rp::ServiceActionKind::none, 0},
    };
    CHECK(setup.failure_actions == expected);
    // The failure count goes back to zero after a day without one.
    CHECK(setup.reset_period_s == 86'400);
}

TEST_CASE("service_setup's display name and account follow from the name", "[service]")
{
    const rp::ServiceSetup setup = rp::service_setup("RestoreProofScmTest", "y");

    CHECK(setup.name == "RestoreProofScmTest");
    CHECK(setup.display_name == "RestoreProofScmTest Worker");
    CHECK(setup.account == "NT SERVICE\\RestoreProofScmTest");
    // The description and the settings don't depend on the name.
    const rp::ServiceSetup product = rp::service_setup(rp::kServiceName, "y");
    CHECK(setup.description == product.description);
    CHECK(setup.start_type == product.start_type);
    CHECK(setup.failure_actions == product.failure_actions);
    CHECK(setup.reset_period_s == product.reset_period_s);
    CHECK(setup.command_line == product.command_line);
}

TEST_CASE("two setups are equal exactly when every field is", "[service]")
{
    const rp::ServiceSetup setup = rp::service_setup(rp::kServiceName, "x");
    CHECK(setup == rp::service_setup(rp::kServiceName, "x"));

    rp::ServiceSetup other = setup;
    other.start_type = rp::ServiceStartType::disabled;
    CHECK_FALSE(setup == other);
    other = setup;
    other.failure_actions.pop_back();
    CHECK_FALSE(setup == other);
    other = setup;
    other.reset_period_s = 0;
    CHECK_FALSE(setup == other);
}

TEST_CASE("the SCM's neutral types start out as nothing happened", "[service]")
{
    const rp::ServiceStatus status;
    CHECK(status.state == rp::ServiceState::stopped);
    CHECK(status.win32_exit_code == 0);
    CHECK(status.service_exit_code == 0);
    CHECK(status.wait_hint_ms == 0);
    CHECK(status.checkpoint == 0);

    const rp::ScmResult result;
    CHECK(result.error == 0);
    CHECK(result.step == rp::ScmStep::call);

    const rp::ServiceReport report;
    CHECK(report.state == rp::ServiceState::stopped);
    CHECK_FALSE(report.accepts_stop);
    CHECK(report.service_exit_code == 0);
    CHECK(report.checkpoint == 0);
    CHECK(report.wait_hint_ms == 0);

    // What a control handler answers, as Windows numbers them.
    CHECK(rp::kControlDone == 0);
    CHECK(rp::kControlNotImplemented == 120);
}

TEST_CASE("every SCM call and host function is null until someone sets it", "[service]")
{
    // Null means the real one (src/scm.hpp), as rp::OutboxFiles' members do.
    const rp::ScmCalls calls;
    CHECK_FALSE(calls.create_service);
    CHECK_FALSE(calls.set_description);
    CHECK_FALSE(calls.set_recovery);
    CHECK_FALSE(calls.delete_service);
    CHECK_FALSE(calls.start_service);
    CHECK_FALSE(calls.stop_service);
    CHECK_FALSE(calls.query_service);

    const rp::ServiceHost host;
    CHECK_FALSE(host.run_dispatcher);
    CHECK_FALSE(host.register_handler);
    CHECK_FALSE(host.report_status);
    CHECK_FALSE(host.exit_process);
}
