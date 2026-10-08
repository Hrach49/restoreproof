#pragma once

// The Windows service (W4.7, docs/decisions.md 2026-10-08): its names, what a
// create asks the Service Control Manager (SCM) for, and the two seams every
// decision about the service reaches Windows through.
//
//  - ScmCalls: what `rpworker service install|uninstall|start|stop` asks of
//    the SCM, one call sequence each.
//  - ServiceHost: what a running service asks of it: the dispatcher, the
//    control handler, a status report, and ending the process.
// Both are structs of functions with null meaning the real one in
// src/scm.hpp (the rp::OutboxFiles pattern), so the commands and the state
// machine run on fakes: no test touches the machine's real service.
//
// No Windows type is named here. Windows' error codes travel as plain
// numbers, in decimal as `sc` and `net helpmsg` take them; 0 is "no error".
//
// rp::Service, at the end, is the running service's state machine (points 5
// and 6) over a ServiceHost.
//
// Strict (100% line): what is asked of the SCM is decided here, and when a
// process holding a run is ended.

#include <rp/config.hpp>
#include <rp/service_log.hpp>
#include <rp/stop_signal.hpp>

#include <spdlog/logger.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// The names (point 1). One Worker serves one Veeam server, so one machine has
// one such service; they are constants, not options. The account is the
// service's virtual account: its SID follows from the name, so this is the
// name every ACE for the Worker carries.
inline constexpr std::string_view kServiceName = "RestoreProof";
inline constexpr std::string_view kServiceDisplayName = "RestoreProof Worker";
inline constexpr std::string_view kServiceDescription =
    "Tests that Microsoft 365 backups in Veeam Backup for Microsoft 365 restore: restores a "
    "sample into test locations and checks it.";
inline constexpr std::string_view kServiceAccount = "NT SERVICE\\RestoreProof";

// A service's state as the SCM reports it.
enum class ServiceState {
    stopped,
    start_pending,
    stop_pending,
    running,
    continue_pending,
    pause_pending,
    paused
};

// What the SCM answers when asked for a service's state. The two exit codes
// say how a stopped service ended: `service_exit_code` is the service's own
// (point 5: 1 the config, 2 the log, 3 a failure after a stop) and counts only
// while `win32_exit_code` is 1066, Windows' "service-specific error".
struct ServiceStatus {
    ServiceState state = ServiceState::stopped;
    unsigned long win32_exit_code = 0;
    unsigned long service_exit_code = 0;
    unsigned long wait_hint_ms = 0;
    unsigned long checkpoint = 0;
};

// When the SCM starts a service.
enum class ServiceStartType { automatic, manual, disabled };

// What the SCM does at a service's failure (a process that ended without
// reporting "stopped").
enum class ServiceActionKind { none, restart };

struct ServiceAction {
    ServiceActionKind kind = ServiceActionKind::none;
    unsigned long delay_ms = 0;

    bool operator==(const ServiceAction&) const = default;
};

// Everything a create passes, and what a read of an installed service's
// configuration gives back. The service is always one of its own process,
// with error control "normal" and no password (a virtual account has none).
struct ServiceSetup {
    std::string name;
    std::string display_name;
    std::string description;
    // "NT SERVICE\<name>".
    std::string account;
    ServiceStartType start_type = ServiceStartType::automatic;
    // The executable's full path in quotes, then its arguments.
    std::string command_line;
    // The N-th failure since the count was last reset runs action N; past the
    // list's end Windows repeats the last one.
    std::vector<ServiceAction> failure_actions;
    // Seconds without a failure after which the count goes back to zero.
    unsigned long reset_period_s = 0;

    bool operator==(const ServiceSetup&) const = default;
};

// The product's settings for a service named `name` that runs `command_line`
// (points 2 and 4): automatic start (not delayed), restart after 60,000 ms
// three times and then nothing, the count reset after 86,400 s. The display
// name is "<name> Worker" and the account "NT SERVICE\<name>", so for
// kServiceName they are the constants above. The product calls it with
// kServiceName only; the tests' one real service has a name of its own.
ServiceSetup service_setup(std::string_view name, std::string_view command_line);

// Which call of a sequence an error is of: connecting to the SCM, opening the
// service, or the call the sequence is there for (the messages name them
// apart: "opening the service control manager", "opening the service",
// "starting the service").
enum class ScmStep { manager, service, call };

// How one call sequence ended. `error` is Windows' code, 0 when it worked;
// `step` says which call it is of and means nothing when `error` is 0.
struct ScmResult {
    unsigned long error = 0;
    ScmStep step = ScmStep::call;
};

// The commands' calls into the SCM, each null = the real one (src/scm.hpp).
// Each takes the service's name, opens and closes its own handles, and never
// answers "it worked" for a call that failed.
struct ScmCalls {
    // Creates the service: the name, display name, account, start type and
    // command line of `setup`. Its description and failure actions are the two
    // calls below (install's steps (d) and (e), each with its own failure).
    std::function<ScmResult(const ServiceSetup& setup)> create_service;
    std::function<ScmResult(std::string_view name, std::string_view description)> set_description;
    // The failure actions and the reset period, through a handle that may
    // start the service, which a restart action needs.
    std::function<ScmResult(std::string_view name, const std::vector<ServiceAction>& actions,
                            unsigned long reset_period_s)>
        set_recovery;
    // Marks the service for deletion; it goes when no handle to it is open.
    std::function<ScmResult(std::string_view name)> delete_service;
    // Sends the start; returns before the service says it runs.
    std::function<ScmResult(std::string_view name)> start_service;
    // Sends the stop control; returns before the service has stopped.
    std::function<ScmResult(std::string_view name)> stop_service;
    // Reads the state into `status`, which is as it was unless `error` is 0.
    std::function<ScmResult(std::string_view name, ServiceStatus& status)> query_service;
};

// A control the SCM sends a running service. `other` is every control the
// service has no answer for.
enum class ServiceControl { stop, shutdown, interrogate, other };

// What a control handler answers, as Windows numbers them: done (no error),
// or "this control isn't implemented".
inline constexpr unsigned long kControlDone = 0;
inline constexpr unsigned long kControlNotImplemented = 120;

// One status report of a running service to the SCM. `accepts_stop`: whether
// the stop and shutdown controls are taken in this state (never while
// starting or stopping). A `service_exit_code` other than 0 is reported as
// Windows' "service-specific error" with that code; 0 as no error.
struct ServiceReport {
    ServiceState state = ServiceState::stopped;
    bool accepts_stop = false;
    unsigned long service_exit_code = 0;
    unsigned long checkpoint = 0;
    unsigned long wait_hint_ms = 0;
};

// The service's main function: what the dispatcher runs, on a thread of the
// SCM's. It must not let an exception out.
using ServiceMainFunction = std::function<void()>;

// The control handler: called on the dispatcher's thread, must return at once
// and never block, and must not let an exception out. kControlDone or
// kControlNotImplemented.
using ServiceControlHandler = std::function<unsigned long(ServiceControl control)>;

// A running service's calls into Windows, each null = the real one
// (src/scm.hpp).
struct ServiceHost {
    // Connects the process to the SCM and runs `main` on a thread of the
    // SCM's; returns when the service has reported "stopped". 0, or Windows'
    // error code: 1063 in a process the SCM didn't start, where `main` is
    // never run.
    std::function<unsigned long(std::string_view name, ServiceMainFunction main)> run_dispatcher;
    // Called by the main function before its first report. 0, or Windows'
    // error code.
    std::function<unsigned long(std::string_view name, ServiceControlHandler handler)>
        register_handler;
    // 0, or Windows' error code. After a "stopped" report the process may be
    // ended at any moment, so it is the last thing its caller does.
    std::function<unsigned long(const ServiceReport& report)> report_status;
    // Ends the process at once with `code`, without the C++ runtime's
    // shutdown: no static destructor runs under a thread that is still
    // working. The real one doesn't return.
    std::function<void(int code)> exit_process;
};

// --- The running service (points 5 and 6) ------------------------------------

// What the service's work is handed, shared between the service's main
// function and the thread the work runs on. Everything but `stop` is set
// before that thread starts and not changed afterwards.
struct ServiceContext {
    // Asked for by the control handler at a stop or a shutdown. The work
    // starts nothing it couldn't leave once it is: no new job, no wait
    // (wait_for returns at once).
    StopSignal stop;
    // The service's log (rp/service_log.hpp); never null.
    std::shared_ptr<spdlog::logger> logger;
    // The config as loaded at the start, and the file it came from.
    Config config;
    std::filesystem::path config_path;
};

// The service's work: runs on a thread of its own from start to end, and
// returns when it is done, which is when a stop was asked for. W4.7's is
// `context->stop.wait()`; W4.8 fills it. An exception it lets out, and a
// return while no stop was asked for, are the service's unexpected failure.
using ServiceBody = std::function<void(const std::shared_ptr<ServiceContext>& context)>;

// The service's own exit codes, reported with "stopped" as Windows'
// service-specific error (ServiceStatus::service_exit_code): the config
// didn't load; the log couldn't be opened; the work let an exception out
// after a stop was asked for.
inline constexpr unsigned long kServiceCodeConfig = 1;
inline constexpr unsigned long kServiceCodeLog = 2;
inline constexpr unsigned long kServiceCodeFailure = 3;

// The wait hints reported while starting and while stopping, and the stop's
// budget: the work is waited for in ten slices of 2.5 s, 25 s in all, with a
// "stop pending" report after each slice it hasn't ended in.
inline constexpr unsigned long kStartWaitHintMs = 10'000;
inline constexpr unsigned long kStopWaitHintMs = 5'000;
inline constexpr std::chrono::milliseconds kStopSlice{2'500};
inline constexpr int kStopSlices = 10;

// Windows' answer to the dispatcher in a process the SCM didn't start.
inline constexpr unsigned long kNotStartedByScm = 1063;

// What rp::Service is made of; every function null = the real one.
struct ServiceOptions {
    ServiceHost host;
    // Null: `context->stop.wait()`.
    ServiceBody body;
    // --config; nullopt: what `default_config_path` answers.
    std::optional<std::filesystem::path> config_path;
    // Null: rp::default_config_path. May throw ConfigError, which is "the
    // config didn't load".
    std::function<std::filesystem::path()> default_config_path;
    // The log's folder. Null: rp::default_log_dir. May throw ConfigError,
    // which is "the log couldn't be opened".
    std::function<std::filesystem::path()> default_log_dir;
    LogLimits log_limits;
    // Waits up to `time` for `done`, the signal the work's thread sets as its
    // last act; true when it is set. Null: `done.wait_for(time)`.
    std::function<bool(const StopSignal& done, std::chrono::milliseconds time)> wait_done;
    // Null: std::chrono::steady_clock::now.
    std::function<std::chrono::steady_clock::time_point()> now;
};

// How Service::run ended. `dispatcher_error` is Windows' code for a dispatcher
// that didn't run the service (kNotStartedByScm from a prompt), else 0;
// `exit_code` is the process's: 0 after a clean stop, 1 otherwise.
struct ServiceRun {
    int exit_code = 1;
    unsigned long dispatcher_error = 0;
};

// The service's state machine: what is reported when, what a control does,
// the stop's budget, the exit codes and every log line. It reaches Windows
// only through `options.host`.
//
// The main function, in order: registers the handler; reports "start pending"
// (checkpoint 1, kStartWaitHintMs, no control accepted); opens the log at
// info (else: "stopped" with kServiceCodeLog); loads the config (else: one
// error line `config error: <text>`, "stopped" with kServiceCodeConfig); sets
// the log's level; starts the work on its thread; reports "running",
// accepting stop and shutdown; logs `service running: rpworker <version>,
// config <path>, log_level <level>`; then waits for the stop or the work's
// end, whichever is first.
//
// The handler: the first stop or shutdown reports "stop pending" (checkpoint
// 1, kStopWaitHintMs, no control accepted), then asks for the stop;
// kControlDone. A later one, and interrogate: kControlDone, nothing done.
// Anything else: kControlNotImplemented. It logs nothing, takes no lock and
// never blocks.
//
// The endings:
//  - a stop, and the work back within the budget: `stop requested
//    (stop|shutdown)`, `service stopped after <n> ms`, the log closed,
//    "stopped" with no error as the last thing done; exit code 0.
//  - a stop, and the work not back after 25 s: its thread is detached, the
//    error line `the service's work didn't end within 25 s of the stop;
//    ending the process`, "stopped" with no error, then exit_process(0).
//  - a stop, and the work let an exception out: the error line `the service's
//    work ended on an unexpected failure` (never the exception's text),
//    "stopped" with kServiceCodeFailure; exit code 1.
//  - the work ended and no stop was asked for: that error line, or `the
//    service's work ended without a stop` for a return, then exit_process(1)
//    and no "stopped": to the SCM a failure, which the recovery actions
//    restart.
//  - the service's own steps failed where none of the above says what
//    happens (the handler couldn't be registered, a seam threw): the error
//    line `the service ended on an unexpected failure` when the log is open,
//    "stopped" with kServiceCodeFailure only when a stop was asked for, then
//    exit_process(1).
class Service {
public:
    explicit Service(ServiceOptions options = {});

    // Calls the dispatcher and nothing of the above before it; all of it
    // happens in the main function the dispatcher runs. Returns when the
    // dispatcher does. After an ending that called exit_process, it calls
    // exit_process again with the same code before it returns (the real one
    // doesn't return): no thread goes back into the runtime while the work's
    // thread may live.
    ServiceRun run();

private:
    ServiceOptions options_;
};

} // namespace rp
