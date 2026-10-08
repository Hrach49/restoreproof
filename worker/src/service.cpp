#include <rp/service.hpp>

#include <rp/config.hpp>
#include <rp/service_log.hpp>
#include <rp/stop_signal.hpp>
#include <rp/version.hpp>

#include "path_utf8.hpp"
#include "scm.hpp"

#include <spdlog/logger.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <variant>

namespace rp {

namespace {

// Point 4: restart after one minute, three times, then nothing; the count is
// reset after a day without a failure.
constexpr unsigned long kRestartDelayMs = 60'000;
constexpr int kRestarts = 3;
constexpr unsigned long kResetPeriodSeconds = 86'400;

} // namespace

ServiceSetup service_setup(std::string_view name, std::string_view command_line)
{
    ServiceSetup setup;
    setup.name = std::string{name};
    setup.display_name = setup.name + " Worker";
    setup.description = std::string{kServiceDescription};
    setup.account = "NT SERVICE\\" + setup.name;
    setup.start_type = ServiceStartType::automatic;
    setup.command_line = std::string{command_line};
    setup.failure_actions.assign(kRestarts,
                                 ServiceAction{ServiceActionKind::restart, kRestartDelayMs});
    // The fourth entry is what makes "three times" true: with three, Windows
    // would repeat the last one and restart for ever.
    setup.failure_actions.push_back(ServiceAction{ServiceActionKind::none, 0});
    setup.reset_period_s = kResetPeriodSeconds;
    return setup;
}

// --- The running service (points 5 and 6) ------------------------------------

namespace {

// How the work's thread ended, noted by that thread as its last act but one.
enum class BodyEnd { running, returned, threw };

// The control the stop came by: what the handler notes, and the main function
// logs.
constexpr int kNoControl = 0;
constexpr int kStopControl = 1;
constexpr int kShutdownControl = 2;

// Everything the service's threads share: the main function's (a thread of
// the SCM's), the handler's (the dispatcher's), the work's, and the one that
// called Service::run. Held by shared_ptr by each of them, so it lives as
// long as any of them needs it.
struct State {
    explicit State(ServiceOptions made) : options(std::move(made)) {}

    // The options with every null function filled in.
    ServiceOptions options;
    std::shared_ptr<ServiceContext> context = std::make_shared<ServiceContext>();
    // Set by the work's thread when the work has ended.
    StopSignal done;
    // Set by the handler at a stop and by the work's thread at its end: the
    // one event the main function waits on while the service runs.
    StopSignal wake;
    // The handler's one piece of state. Only the first stop or shutdown
    // changes it, so only that one reports and asks: a control that arrives
    // later can't report "stop pending" after the main function's own
    // reports. No lock: the handler never blocks.
    std::atomic<int> control{kNoControl};
    std::atomic<BodyEnd> body_end{BodyEnd::running};
    // The main function's alone.
    std::shared_ptr<ServiceLog> log;
    // What Service::run reads when the dispatcher has returned. Set before
    // the "stopped" report that lets it return.
    std::atomic<int> exit_code{1};
    std::atomic<bool> ends_process{false};
};

// The work's thread while the main function is responsible for it: joined by
// the main function, or detached, by it or when it is left without either.
struct BodyThread {
    std::thread thread;

    BodyThread() = default;
    BodyThread(const BodyThread&) = delete;
    BodyThread& operator=(const BodyThread&) = delete;
    ~BodyThread()
    {
        if (thread.joinable()) {
            thread.detach();
        }
    }
};

ServiceOptions with_defaults(ServiceOptions options)
{
    ServiceHost& host = options.host;
    host.run_dispatcher = host.run_dispatcher ? host.run_dispatcher : &scm::run_dispatcher;
    host.register_handler = host.register_handler ? host.register_handler : &scm::register_handler;
    host.report_status = host.report_status ? host.report_status : &scm::report_status;
    host.exit_process = host.exit_process ? host.exit_process : &scm::exit_process;
    if (!options.body) {
        // W4.7's work: wait for the stop.
        options.body = [](const std::shared_ptr<ServiceContext>& context) { context->stop.wait(); };
    }
    if (!options.default_config_path) {
        options.default_config_path = &default_config_path;
    }
    if (!options.default_log_dir) {
        options.default_log_dir = &default_log_dir;
    }
    if (!options.wait_done) {
        options.wait_done = [](const StopSignal& done, std::chrono::milliseconds time) {
            return done.wait_for(time);
        };
    }
    if (!options.now) {
        options.now = &std::chrono::steady_clock::now;
    }
    return options;
}

void report(State& state, ServiceState service_state, unsigned long service_exit_code = 0,
            unsigned long checkpoint = 0, unsigned long wait_hint_ms = 0)
{
    ServiceReport made;
    made.state = service_state;
    // Stop and shutdown are taken while running and in no other state.
    made.accepts_stop = service_state == ServiceState::running;
    made.service_exit_code = service_exit_code;
    made.checkpoint = checkpoint;
    made.wait_hint_ms = wait_hint_ms;
    state.options.host.report_status(made);
}

// The control handler: on the dispatcher's thread. No lock, no log line, no
// wait.
unsigned long on_control(State& state, ServiceControl control)
{
    if (control == ServiceControl::stop || control == ServiceControl::shutdown) {
        int expected = kNoControl;
        const int by = control == ServiceControl::shutdown ? kShutdownControl : kStopControl;
        if (state.control.compare_exchange_strong(expected, by)) {
            // Reported before the stop is asked for: once it is, the main
            // function reports the checkpoints after this one.
            report(state, ServiceState::stop_pending, 0, 1, kStopWaitHintMs);
            state.context->stop.request();
            state.wake.request();
        }
        return kControlDone;
    }
    if (control == ServiceControl::interrogate) {
        return kControlDone;
    }
    return kControlNotImplemented;
}

// The work's thread, from start to end. It notes how the work ended and sets
// the two signals; it never logs the end, reports a status or ends the
// process: all of that is the main function's, so nothing races.
void run_body(const std::shared_ptr<State>& state)
{
    BodyEnd end = BodyEnd::returned;
    try {
        state->options.body(state->context);
    } catch (...) {
        end = BodyEnd::threw;
    }
    state->body_end = end;
    state->done.request();
    state->wake.request();
}

// Ends the process, as the last thing its caller does. Service::run does the
// same when the dispatcher returns.
void end_process(State& state, int code)
{
    state.exit_code = code;
    state.ends_process = true;
    state.options.host.exit_process(code);
}

// Opens the log at info. Null when it can't be opened, whichever way.
std::shared_ptr<ServiceLog> open_log(const State& state)
{
    std::shared_ptr<ServiceLog> log;
    try {
        auto made = make_service_logger(state.options.default_log_dir(), spdlog::level::info,
                                        state.options.log_limits);
        if (auto* opened = std::get_if<std::shared_ptr<ServiceLog>>(&made)) {
            log = std::move(*opened);
        }
    } catch (const ConfigError&) {
        // The folder can't even be named: Windows didn't resolve %ProgramData%.
    }
    return log;
}

// Loads the config into the context. The ConfigError's text when it doesn't
// load: what `config check` prints, which never holds a value.
std::optional<std::string> load_into(State& state)
{
    std::optional<std::string> error;
    try {
        ServiceContext& context = *state.context;
        context.config_path = state.options.config_path ? *state.options.config_path
                                                        : state.options.default_config_path();
        context.config = load_config(context.config_path);
    } catch (const ConfigError& e) {
        error = e.what();
    }
    return error;
}

// The stop: the work is waited for in slices, with a report after each one it
// hasn't ended in. Whether it ended within the budget.
bool wait_for_body(State& state)
{
    unsigned long checkpoint = 1;
    bool ended = false;
    for (int slice = 0; slice < kStopSlices && !ended; ++slice) {
        ended = state.options.wait_done(state.done, kStopSlice);
        if (!ended) {
            report(state, ServiceState::stop_pending, 0, ++checkpoint, kStopWaitHintMs);
        }
    }
    return ended;
}

// The service's life, on the thread the dispatcher runs it on.
void run_service(const std::shared_ptr<State>& shared)
{
    State& state = *shared;
    const ServiceOptions& options = state.options;
    ServiceContext& context = *state.context;

    const unsigned long registered = options.host.register_handler(
        kServiceName, [shared](ServiceControl control) { return on_control(*shared, control); });
    if (registered != 0) {
        // Without the handler's status handle nothing can be reported.
        end_process(state, 1);
        return;
    }
    // No control is accepted while starting.
    report(state, ServiceState::start_pending, 0, 1, kStartWaitHintMs);

    state.log = open_log(state);
    if (!state.log) {
        report(state, ServiceState::stopped, kServiceCodeLog);
        return;
    }
    ServiceLog& log = *state.log;
    context.logger = log.logger();
    spdlog::logger& logger = *context.logger;

    if (const std::optional<std::string> error = load_into(state)) {
        logger.error("config error: {}", *error);
        log.close();
        report(state, ServiceState::stopped, kServiceCodeConfig);
        return;
    }
    // A loaded config's log_level is one of the seven words.
    log.set_level(log_level_of(context.config.log_level).value_or(spdlog::level::info));

    BodyThread body;
    body.thread = std::thread{[shared] { run_body(shared); }};
    report(state, ServiceState::running);
    logger.info("service running: rpworker {}, config {}, log_level {}", version(),
                path_to_utf8(context.config_path), context.config.log_level);

    // The stop or the work's end, whichever comes first.
    state.wake.wait();

    if (!context.stop.requested()) {
        // The work ended and nobody asked it to: its thread is at its end.
        body.thread.join();
        logger.error(state.body_end == BodyEnd::threw
                         ? "the service's work ended on an unexpected failure"
                         : "the service's work ended without a stop");
        log.flush();
        // No "stopped": to the SCM this is a failure, which it restarts.
        end_process(state, 1);
        return;
    }

    const std::chrono::steady_clock::time_point asked = options.now();
    logger.info("stop requested ({})",
                state.control == kShutdownControl ? "shutdown" : "stop");
    if (!wait_for_body(state)) {
        // Still working: it must not meet the runtime's shutdown, so the
        // process is ended as soon as the SCM knows the service stopped.
        body.thread.detach();
        logger.error("the service's work didn't end within 25 s of the stop; ending the process");
        log.flush();
        state.exit_code = 0;
        state.ends_process = true;
        report(state, ServiceState::stopped);
        options.host.exit_process(0);
        return;
    }
    body.thread.join();
    if (state.body_end == BodyEnd::threw) {
        logger.error("the service's work ended on an unexpected failure");
        log.close();
        // The stop was asked for: no failure to the SCM, and nothing restarts
        // the service; the code says the stop wasn't clean.
        report(state, ServiceState::stopped, kServiceCodeFailure);
        return;
    }
    const auto took =
        std::chrono::duration_cast<std::chrono::milliseconds>(options.now() - asked);
    logger.info("service stopped after {} ms", took.count());
    log.close();
    state.exit_code = 0;
    // The last thing done: the process may be ended at any moment after it.
    report(state, ServiceState::stopped);
}

// A failure of the service's own steps that nothing above has an answer for.
// The work's thread may be running, so the process is ended whatever else.
void fail(State& state)
{
    if (state.log) {
        state.log->logger()->error("the service ended on an unexpected failure");
        state.log->flush();
    }
    state.exit_code = 1;
    state.ends_process = true;
    if (state.context->stop.requested()) {
        // Nothing restarts a service someone stopped.
        report(state, ServiceState::stopped, kServiceCodeFailure);
    }
    state.options.host.exit_process(1);
}

// What the dispatcher runs. Nothing is let out to the SCM's thread.
void service_main(const std::shared_ptr<State>& state)
{
    try {
        run_service(state);
    } catch (...) {
        fail(*state);
    }
}

} // namespace

Service::Service(ServiceOptions options) : options_(std::move(options)) {}

ServiceRun Service::run()
{
    const auto state = std::make_shared<State>(with_defaults(options_));
    ServiceRun result;
    result.dispatcher_error = state->options.host.run_dispatcher(
        kServiceName, [state] { service_main(state); });
    if (result.dispatcher_error != 0) {
        // The service never ran: 1063 in a process the SCM didn't start.
        return result;
    }
    result.exit_code = state->exit_code;
    if (state->ends_process) {
        // The work's thread may live: this thread doesn't go back into the
        // runtime either. Whichever of the two gets here first ends it.
        state->options.host.exit_process(result.exit_code);
    }
    return result;
}

} // namespace rp
