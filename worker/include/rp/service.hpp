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
// Strict (100% line): what is asked of the SCM is decided here.

#include <functional>
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

} // namespace rp
