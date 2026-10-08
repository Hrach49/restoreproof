// W4.7: rp/service.hpp. The service's four names (docs/decisions.md 2026-10-08
// point 1) and rp::service_setup, the one function that fills everything a
// create passes (points 2, 4 and 8): what `service install` asks the SCM for is
// decided here and seen here, on no machine's real service.
//
// Then rp::Service, the running service's state machine (points 5 and 6), on
// the fake host of tests/service_lab.hpp: failures first, then the stop's
// budget, the handler, and the clean start and stop. The service's threads
// only record; every assertion is on the test's thread, and the log is read
// from the temp folder.

#include <rp/config.hpp>
#include <rp/service.hpp>
#include <rp/version.hpp>

#include "service_lab.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::VectorContains;
using rp::test::service_lab::Lab;
using Lines = std::vector<std::string>;

namespace {

// The reports every start makes first, and what follows them.
const std::string kStartPending = "start_pending accepts=0 code=0 checkpoint=1 hint=10000";
const std::string kRunning = "running accepts=1 code=0 checkpoint=0 hint=0";
const std::string kStopped = "stopped accepts=0 code=0 checkpoint=0 hint=0";

std::string stop_pending(unsigned long checkpoint)
{
    return "stop_pending accepts=0 code=0 checkpoint=" + std::to_string(checkpoint) + " hint=5000";
}

std::string stopped_with(unsigned long code)
{
    return "stopped accepts=0 code=" + std::to_string(code) + " checkpoint=0 hint=0";
}

// The line every start that got as far as running logs at info.
std::string running_line(const Lab& lab, std::string_view level = "info")
{
    return "info service running: rpworker " + std::string{rp::version()} + ", config " +
           rp::test::service_lab::utf8_of(lab.config_file) + ", log_level " + std::string{level};
}

// A text no log line may hold: what a body's exception said.
const std::string kBodyText = "SENTINEL-what-the-body-threw";

// A clock that moves 1,234 ms at each reading.
std::function<std::chrono::steady_clock::time_point()> stepping_clock()
{
    auto readings = std::make_shared<std::atomic<int>>(0);
    return [readings] {
        return std::chrono::steady_clock::time_point{} +
               std::chrono::milliseconds{1'234} * (*readings)++;
    };
}

// Starts the service and waits until it runs and its body has started.
void start_running(Lab& lab)
{
    lab.start();
    REQUIRE(lab.fake.wait_for_state(rp::ServiceState::running));
    REQUIRE(lab.body_started.wait_for(rp::test::service_lab::kPatience));
}

} // namespace

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

// --- rp::Service: what never becomes a service --------------------------------

TEST_CASE("service run: in a process the SCM didn't start, the dispatcher's code is handed back "
          "and nothing else is done",
          "[service][run]")
{
    const unsigned long error = GENERATE(1063ul, 1056ul, 5ul);
    Lab lab;
    lab.fake.dispatcher_error = error;
    lab.options.body = lab.body([](rp::ServiceContext&) {});

    const rp::ServiceRun run = lab.run();

    CHECK(run.exit_code == 1);
    CHECK(run.dispatcher_error == error);
    // The dispatcher was the one call, under the service's name.
    const auto events = lab.fake.events();
    REQUIRE(events.size() == 1);
    CHECK(events[0].kind == rp::test::service_lab::HostEvent::Kind::dispatcher_started);
    CHECK(events[0].name == rp::kServiceName);
    // Nothing logged, no log file touched, the body never run.
    CHECK_FALSE(std::filesystem::exists(lab.log_dir));
    CHECK(lab.seen.calls == 0);
    CHECK(rp::kNotStartedByScm == 1063);
}

TEST_CASE("service run: with no host handed in, the real dispatcher refuses a process the SCM "
          "didn't start",
          "[service][run]")
{
    // Every host function null = the real one. rptests wasn't started by the
    // SCM, so the real dispatcher answers 1063 at once and runs nothing: no
    // handler, no report, no exit.
    rp::Service service;

    const rp::ServiceRun run = service.run();

    CHECK(run.exit_code == 1);
    CHECK(run.dispatcher_error == rp::kNotStartedByScm);
}

TEST_CASE("service: a handler that can't be registered ends the process, nothing reported",
          "[service][run]")
{
    Lab lab;
    lab.fake.register_error = 6;
    lab.options.body = lab.body([](rp::ServiceContext&) {});

    const rp::ServiceRun run = lab.run();

    CHECK(run.exit_code == 1);
    CHECK(run.dispatcher_error == 0);
    // No report is possible without the handler's status handle. The main
    // function ends the process, and so does run when the dispatcher is back.
    CHECK(lab.fake.calls() ==
          Lines{"dispatcher", "registered", "exit 1", "dispatcher returned", "exit 1"});
    CHECK_FALSE(std::filesystem::exists(lab.log_dir));
    CHECK(lab.seen.calls == 0);
}

// --- A start that fails with one of the service's own codes -------------------

TEST_CASE("service: a log that can't be opened is `stopped` with the service's code 2",
          "[service][start]")
{
    Lab lab;
    lab.options.body = lab.body([](rp::ServiceContext&) {});
    const bool thrown = GENERATE(false, true);
    CAPTURE(thrown);
    if (thrown) {
        // The log's folder can't even be named (Windows can't resolve
        // %ProgramData%).
        lab.options.default_log_dir = []() -> std::filesystem::path {
            throw rp::ConfigError("", "the ProgramData folder could not be resolved");
        };
    } else {
        // A file where the folder would have to be.
        lab.tmp.write("logs", "not a folder");
    }

    const rp::ServiceRun run = lab.run();

    CHECK(run.exit_code == 1);
    CHECK(run.dispatcher_error == 0);
    CHECK(lab.fake.report_texts() == Lines{kStartPending, stopped_with(2)});
    // `stopped` is the last thing done: the process isn't ended by the service.
    CHECK(lab.fake.exits().empty());
    CHECK(lab.fake.calls().back() == "dispatcher returned");
    CHECK(lab.seen.calls == 0);
    CHECK(rp::kServiceCodeLog == 2);
}

TEST_CASE("service: a config that doesn't load is one error line and `stopped` with code 1",
          "[service][start]")
{
    Lab lab;
    lab.options.body = lab.body([](rp::ServiceContext&) {});
    const int row = GENERATE(0, 1, 2, 3);
    CAPTURE(row);
    std::string expected;
    if (row == 0) {
        // The file isn't there.
        lab.options.config_path = lab.tmp.path() / "missing.json";
    } else if (row == 1) {
        // The whole file must be valid, not only the key the service reads.
        lab.options.config_path = lab.tmp.write("bad.json", R"({"cloud_url": "http://x"})");
    } else if (row == 2) {
        lab.options.config_path =
            lab.tmp.write("level.json", rp::test::service_lab::config_json("loud"));
    } else {
        // No --config, and the default path can't be named.
        lab.options.config_path.reset();
        expected = "the ProgramData folder could not be resolved";
        lab.options.default_config_path = [expected]() -> std::filesystem::path {
            throw rp::ConfigError("", expected);
        };
    }
    if (expected.empty()) {
        // The text `config check` prints for the same file.
        try {
            rp::load_config(*lab.options.config_path);
        } catch (const rp::ConfigError& e) {
            expected = e.what();
        }
    }
    REQUIRE_FALSE(expected.empty());

    const rp::ServiceRun run = lab.run();

    CHECK(run.exit_code == 1);
    CHECK(run.dispatcher_error == 0);
    CHECK(lab.fake.report_texts() == Lines{kStartPending, stopped_with(1)});
    CHECK(lab.fake.exits().empty());
    CHECK(lab.fake.calls().back() == "dispatcher returned");
    CHECK(lab.seen.calls == 0);
    CHECK(lab.log_lines() == Lines{"error config error: " + expected});
    // The log was closed before `stopped` was reported.
    CHECK(lab.log_file_is_closed());
    CHECK(rp::kServiceCodeConfig == 1);
}

// --- The unexpected failure ---------------------------------------------------

TEST_CASE("service: a body that ends while no stop was asked for ends the process with 1 and "
          "never reports `stopped`",
          "[service][failure]")
{
    Lab lab;
    lab.options.now = stepping_clock();
    const bool throws = GENERATE(true, false);
    CAPTURE(throws);
    lab.options.body = lab.body([throws](rp::ServiceContext&) {
        if (throws) {
            throw std::runtime_error(kBodyText);
        }
    });

    const rp::ServiceRun run = lab.run();

    CHECK(run.exit_code == 1);
    CHECK(run.dispatcher_error == 0);
    // To the SCM a failure: no `stopped`, so the recovery actions restart it.
    // The main function ends the process, and run does when the dispatcher
    // returns.
    CHECK(lab.fake.calls() == Lines{"dispatcher", "registered", kStartPending, kRunning, "exit 1",
                                    "dispatcher returned", "exit 1"});
    CHECK(lab.log_lines() ==
          Lines{running_line(lab), throws ? "error the service's work ended on an unexpected failure"
                                          : "error the service's work ended without a stop"});
    // Never the exception's text.
    CHECK_THAT(lab.log_text(), !ContainsSubstring(kBodyText));
    CHECK(lab.seen.calls == 1);
    CHECK(lab.gone());
}

TEST_CASE("service: a body that throws after a stop is `stopped` with the service's code 3, and "
          "the process isn't ended",
          "[service][failure]")
{
    Lab lab;
    lab.options.now = stepping_clock();
    lab.options.body = lab.body([](rp::ServiceContext& context) {
        context.stop.wait();
        throw std::runtime_error(kBodyText);
    });
    start_running(lab);

    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    const rp::ServiceRun run = lab.finish();

    CHECK(run.exit_code == 1);
    CHECK(run.dispatcher_error == 0);
    // No failure to the SCM: nothing restarts a service someone stopped.
    CHECK(lab.fake.calls() == Lines{"dispatcher", "registered", kStartPending, kRunning,
                                    stop_pending(1), stopped_with(3), "dispatcher returned"});
    CHECK(lab.log_lines() == Lines{running_line(lab), "info stop requested (stop)",
                                   "error the service's work ended on an unexpected failure"});
    CHECK_THAT(lab.log_text(), !ContainsSubstring(kBodyText));
    CHECK(lab.gone());
    CHECK(lab.log_file_is_closed());
    CHECK(rp::kServiceCodeFailure == 3);
}

TEST_CASE("service: a failure of the service's own steps before any stop ends the process with 1",
          "[service][failure]")
{
    Lab lab;
    lab.options.body = lab.body([](rp::ServiceContext&) {});
    // Not a ConfigError: nothing the start has a code for.
    lab.options.default_log_dir = []() -> std::filesystem::path {
        throw std::runtime_error(kBodyText);
    };

    const rp::ServiceRun run = lab.run();

    CHECK(run.exit_code == 1);
    CHECK(lab.fake.calls() == Lines{"dispatcher", "registered", kStartPending, "exit 1",
                                    "dispatcher returned", "exit 1"});
    CHECK(lab.seen.calls == 0);
    CHECK_FALSE(std::filesystem::exists(lab.log_dir));
}

TEST_CASE("service: a failure of the service's own steps after a stop is `stopped` with code 3, "
          "then the process is ended",
          "[service][failure]")
{
    Lab lab;
    lab.options.now = stepping_clock();
    // The body doesn't end at the stop; the wait for it throws.
    lab.options.body = lab.body([&lab](rp::ServiceContext&) { lab.release.wait(); });
    lab.options.wait_done = [](const rp::StopSignal&, std::chrono::milliseconds) -> bool {
        throw std::runtime_error(kBodyText);
    };
    start_running(lab);

    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    const rp::ServiceRun run = lab.finish();

    CHECK(run.exit_code == 1);
    // A stop was asked for, so it must not count as a failure; the body may
    // still be working, so the process is ended all the same.
    CHECK(lab.fake.calls() == Lines{"dispatcher", "registered", kStartPending, kRunning,
                                    stop_pending(1), stopped_with(3), "exit 1",
                                    "dispatcher returned", "exit 1"});
    CHECK(lab.log_lines() == Lines{running_line(lab), "info stop requested (stop)",
                                   "error the service ended on an unexpected failure"});
    CHECK_THAT(lab.log_text(), !ContainsSubstring(kBodyText));

    // The body's thread was left running: let it go and wait for it.
    lab.release.request();
    CHECK(lab.gone());
}

// --- The stop's budget ----------------------------------------------------------

TEST_CASE("service: a body that doesn't return is cut off after ten slices of 2.5 s",
          "[service][stop]")
{
    std::vector<std::chrono::milliseconds> slices;
    Lab lab;
    lab.options.now = stepping_clock();
    lab.options.body = lab.body([&lab](rp::ServiceContext&) { lab.release.wait(); });
    // Answers "not ended" at no cost; only the main function's thread calls it.
    lab.options.wait_done = [&slices](const rp::StopSignal& done, std::chrono::milliseconds time) {
        slices.push_back(time);
        return done.requested();
    };
    start_running(lab);

    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    const rp::ServiceRun run = lab.finish();

    CHECK(run.exit_code == 0);
    CHECK(run.dispatcher_error == 0);
    CHECK(slices == std::vector<std::chrono::milliseconds>(10, std::chrono::milliseconds{2'500}));
    CHECK(rp::kStopSlice * rp::kStopSlices == std::chrono::seconds{25});
    // One report after each slice, the checkpoint moving, the hint the same;
    // `stopped` with no error (the stop was asked for), then the process is
    // ended at once as the last host call, and again when the dispatcher
    // returns.
    CHECK(lab.fake.calls() ==
          Lines{"dispatcher", "registered", kStartPending, kRunning, stop_pending(1),
                stop_pending(2), stop_pending(3), stop_pending(4), stop_pending(5),
                stop_pending(6), stop_pending(7), stop_pending(8), stop_pending(9),
                stop_pending(10), stop_pending(11), kStopped, "exit 0", "dispatcher returned",
                "exit 0"});
    CHECK(lab.log_lines() ==
          Lines{running_line(lab), "info stop requested (stop)",
                "error the service's work didn't end within 25 s of the stop; ending the process"});
    // Flushed, not closed: the body's thread may still log.
    CHECK_FALSE(lab.log_file_is_closed());

    // The body's thread was detached and still runs: let it go and wait for it.
    CHECK(lab.seen.calls == 1);
    lab.release.request();
    CHECK(lab.gone());
}

TEST_CASE("service: a body that returns in the k-th slice is a clean stop after k - 1 more reports",
          "[service][stop]")
{
    const int k = GENERATE(range(1, 11));
    CAPTURE(k);
    int slice = 0;
    Lab lab;
    lab.options.now = stepping_clock();
    lab.options.body = lab.body([&lab](rp::ServiceContext&) { lab.release.wait(); });
    lab.options.wait_done = [&](const rp::StopSignal& done, std::chrono::milliseconds) {
        if (++slice < k) {
            return false;
        }
        // The body ends in this slice.
        lab.release.request();
        done.wait();
        return true;
    };
    start_running(lab);

    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    const rp::ServiceRun run = lab.finish();

    CHECK(run.exit_code == 0);
    CHECK(slice == k);
    Lines expected{"dispatcher", "registered", kStartPending, kRunning, stop_pending(1)};
    for (int checkpoint = 2; checkpoint <= k; ++checkpoint) {
        expected.push_back(stop_pending(static_cast<unsigned long>(checkpoint)));
    }
    expected.push_back(kStopped);
    // `stopped` is the last thing done.
    expected.push_back("dispatcher returned");
    CHECK(lab.fake.calls() == expected);
    // The clock moved 1,234 ms between the stop and the end.
    CHECK(lab.log_lines() == Lines{running_line(lab), "info stop requested (stop)",
                                   "info service stopped after 1234 ms"});
    CHECK(lab.gone());
    CHECK(lab.log_file_is_closed());
}

// --- The handler ----------------------------------------------------------------

TEST_CASE("service: the handler reports before it asks for the stop, logs nothing and never "
          "blocks",
          "[service][handler]")
{
    const rp::ServiceControl control =
        GENERATE(rp::ServiceControl::stop, rp::ServiceControl::shutdown);
    rp::StopSignal clock_reached;
    Lab lab;
    lab.options.body = lab.body([](rp::ServiceContext& context) { context.stop.wait(); });
    // The main function reads the clock when the stop wakes it and before it
    // logs: held there, it has logged and reported nothing of the stop.
    lab.options.now = [&] {
        clock_reached.request();
        lab.release.wait();
        return std::chrono::steady_clock::time_point{};
    };
    start_running(lab);

    // Back at once, with the main function held.
    CHECK(lab.fake.control(control) == rp::kControlDone);
    REQUIRE(clock_reached.wait_for(rp::test::service_lab::kPatience));

    // The one report is the handler's, made when no stop was asked for yet.
    const auto reports = lab.fake.reports();
    REQUIRE(reports.size() == 3);
    CHECK(rp::test::service_lab::text_of(reports[2].report) == stop_pending(1));
    CHECK(reports[2].stop_requested == false);
    // Nothing of the stop is in the log: the line is the main function's.
    CHECK(lab.log_lines() == Lines{running_line(lab)});

    // While stopping: a second stop or shutdown, an interrogate and an unknown
    // control each come back at once and report nothing.
    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    CHECK(lab.fake.control(rp::ServiceControl::shutdown) == rp::kControlDone);
    CHECK(lab.fake.control(rp::ServiceControl::interrogate) == rp::kControlDone);
    CHECK(lab.fake.control(rp::ServiceControl::other) == rp::kControlNotImplemented);
    CHECK(lab.fake.reports().size() == 3);

    lab.release.request();
    const rp::ServiceRun run = lab.finish();

    CHECK(run.exit_code == 0);
    CHECK(lab.fake.report_texts() == Lines{kStartPending, kRunning, stop_pending(1), kStopped});
    // The first control is the one the log names.
    CHECK(lab.log_lines() ==
          Lines{running_line(lab),
                control == rp::ServiceControl::shutdown ? "info stop requested (shutdown)"
                                                        : "info stop requested (stop)",
                "info service stopped after 0 ms"});
}

TEST_CASE("service: interrogate and an unknown control change nothing while running",
          "[service][handler]")
{
    Lab lab;
    lab.options.body = lab.body([](rp::ServiceContext& context) { context.stop.wait(); });
    start_running(lab);

    CHECK(lab.fake.control(rp::ServiceControl::interrogate) == rp::kControlDone);
    CHECK(lab.fake.control(rp::ServiceControl::other) == rp::kControlNotImplemented);

    // No report, no stop: the service runs on.
    CHECK(lab.fake.report_texts() == Lines{kStartPending, kRunning});
    {
        const std::lock_guard<std::mutex> lock{lab.seen.mutex};
        const std::shared_ptr<rp::ServiceContext> context = lab.seen.context.lock();
        REQUIRE(context != nullptr);
        CHECK_FALSE(context->stop.requested());
    }
    CHECK(lab.fake.exits().empty());

    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    CHECK(lab.finish().exit_code == 0);
}

// --- The clean start and stop ---------------------------------------------------

TEST_CASE("service: a clean start and stop, every status in order", "[service][clean]")
{
    Lab lab;
    // The product's own: the body that waits for the stop, the real wait for
    // it and the real clock.
    lab.start();
    REQUIRE(lab.fake.wait_for_state(rp::ServiceState::running));

    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    const rp::ServiceRun run = lab.finish();

    CHECK(run.exit_code == 0);
    CHECK(run.dispatcher_error == 0);
    const auto events = lab.fake.events();
    // The handler is registered under the service's name before the first
    // report; `stopped` is the last thing done; the process isn't ended.
    CHECK(lab.fake.calls() == Lines{"dispatcher", "registered", kStartPending, kRunning,
                                    stop_pending(1), kStopped, "dispatcher returned"});
    CHECK(events[1].name == rp::kServiceName);

    const Lines lines = lab.log_lines();
    REQUIRE(lines.size() == 3);
    CHECK(lines[0] == running_line(lab));
    CHECK(lines[1] == "info stop requested (stop)");
    CHECK(std::regex_match(lines[2], std::regex{R"(info service stopped after \d+ ms)"}));
    // Closed before `stopped`.
    CHECK(lab.log_file_is_closed());
}

TEST_CASE("service: the body is handed the stop, the logger, the config and its path, on a "
          "thread of its own",
          "[service][clean]")
{
    // Declared before the Lab, as everything a service thread touches is: the
    // Lab's end waits for those threads.
    rp::StopSignal logged;
    std::atomic<std::thread::id> body_thread{};
    Lab lab{"debug"};
    lab.options.now = stepping_clock();
    // No --config: the default path's seam says where the config is.
    lab.options.config_path.reset();
    lab.options.body = lab.body([&body_thread, &logged](rp::ServiceContext& context) {
        body_thread = std::this_thread::get_id();
        context.logger->debug("the body's own line");
        logged.request();
        context.stop.wait();
    });
    start_running(lab);
    REQUIRE(logged.wait_for(rp::test::service_lab::kPatience));

    CHECK(lab.fake.control(rp::ServiceControl::shutdown) == rp::kControlDone);
    const rp::ServiceRun run = lab.finish();

    CHECK(run.exit_code == 0);
    CHECK(lab.seen.calls == 1);
    CHECK_FALSE(lab.seen.stop_requested_at_start);
    CHECK(lab.seen.had_logger);
    {
        const std::lock_guard<std::mutex> lock{lab.seen.mutex};
        CHECK(lab.seen.log_level == "debug");
        CHECK(lab.seen.config_path == lab.config_file);
    }
    CHECK(body_thread.load() != std::thread::id{});
    CHECK(body_thread.load() != std::this_thread::get_id());
    // The level is the config's by the time the body runs, and the start line
    // says which.
    const Lines lines = lab.log_lines();
    REQUIRE(lines.size() == 4);
    CHECK_THAT(lines, VectorContains(std::string{"debug the body's own line"}));
    CHECK_THAT(lines, VectorContains(running_line(lab, "debug")));
    CHECK(lines[2] == "info stop requested (shutdown)");
    CHECK(lines[3] == "info service stopped after 1234 ms");
    CHECK(lab.gone());
}

TEST_CASE("service: the log's level is the config's from the start line on", "[service][clean]")
{
    // At warn or above a clean start and stop leave no line; that is what the
    // level asks for.
    const std::string level = GENERATE("warn", "error", "critical", "off");
    CAPTURE(level);
    Lab lab{level};
    lab.start();
    REQUIRE(lab.fake.wait_for_state(rp::ServiceState::running));

    CHECK(lab.fake.control(rp::ServiceControl::stop) == rp::kControlDone);
    CHECK(lab.finish().exit_code == 0);

    CHECK(lab.fake.report_texts() == Lines{kStartPending, kRunning, stop_pending(1), kStopped});
    CHECK(std::filesystem::exists(lab.log_file()));
    CHECK(lab.log_text().empty());
}

TEST_CASE("service: a body that asks for the stop itself and returns is a clean stop",
          "[service][clean]")
{
    Lab lab;
    lab.options.now = stepping_clock();
    lab.options.body = lab.body([](rp::ServiceContext& context) { context.stop.request(); });

    const rp::ServiceRun run = lab.run();

    CHECK(run.exit_code == 0);
    // No control came, so no `stop pending` was the handler's to report.
    CHECK(lab.fake.report_texts() == Lines{kStartPending, kRunning, kStopped});
    CHECK(lab.fake.exits().empty());
    CHECK(lab.log_lines() == Lines{running_line(lab), "info stop requested (stop)",
                                   "info service stopped after 1234 ms"});
}
