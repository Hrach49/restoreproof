#pragma once

// `rpworker service install|uninstall|start|stop|run` (W4.7, docs/decisions.md
// 2026-10-08 point 2): the Worker as a Windows service. The first four ask the
// Service Control Manager (SCM) through rp::ScmCalls and are what an
// administrator, and W7.1's installer, runs; `run` is what the service's
// command line names and what nobody types. None of them reads the vault, and
// only `run` reads the config.
//
// Strict (100% line): every message and exit code of the five is decided
// here, and what `install` leaves behind when a step fails.

#include <rp/service.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// How often `uninstall`, `start` and `stop` read the service's state while
// they wait, and how long each waits: for the service to be gone after the
// delete, to run after the start, and to have stopped after the stop (the
// service's own 30 s and a margin).
inline constexpr std::chrono::milliseconds kServicePollInterval{250};
inline constexpr std::chrono::milliseconds kServiceUninstallWait{10'000};
inline constexpr std::chrono::milliseconds kServiceStartWait{30'000};
inline constexpr std::chrono::milliseconds kServiceStopWait{35'000};

// What the commands reach outside themselves; every function null = the real
// one. run_cli passes default_service_command_env(); the tests pass a fake
// SCM, a fake host, a fake clock and a sleep that costs nothing, so no test
// touches the machine's real service or really waits.
struct ServiceCommandEnv {
    // The SCM's calls of `install`, `uninstall`, `start` and `stop`
    // (rp/service.hpp); each null = the real one in src/scm.hpp.
    ScmCalls scm;
    // What `run` hands rp::Service; each null = the real one.
    ServiceHost host;
    // The service's work (W4.8): what `run` hands rp::Service as its body.
    // Null: W4.7's, which only waits for the stop, so an env that leaves it
    // out never meets the real paths. default_service_command_env() sets the
    // scheduler loop over its real calls (rp::make_worker_body,
    // src/worker_body.hpp).
    ServiceBody body;
    // This executable's full path, which the service's command line names.
    // Null: rp::own_executable_path (src/folder_ops.hpp).
    std::function<std::filesystem::path()> own_path;
    // The log's folder: `install` makes it, `start` names the log file in it,
    // `run` writes there. Null: rp::default_log_dir. May throw ConfigError.
    std::function<std::filesystem::path()> default_log_dir;
    // The config `run` loads without --config. Null: rp::default_config_path.
    std::function<std::filesystem::path()> default_config_path;
    // Makes a folder and the levels above it that aren't there: 0 when it is
    // a folder afterwards, else Windows' error code. Null:
    // rp::make_folder_error (src/folder_ops.hpp).
    std::function<unsigned long(const std::filesystem::path& folder)> make_folder;
    // Null: std::this_thread::sleep_for.
    std::function<void(std::chrono::milliseconds time)> sleep;
    // Null: std::chrono::steady_clock::now.
    std::function<std::chrono::steady_clock::time_point()> now;
};

// The real environment: every member null but `body`, the scheduler loop.
ServiceCommandEnv default_service_command_env();

// `rpworker service ...`. `args` is what follows "service", in UTF-8. Each
// subcommand prints its answer on `out` and its one "service error: ..." line
// on `err`. Exit 0 done; 3 (exit_code::transient) not yet, and trying again
// may do it (the lines marked 3 below); 1 every other "service error" and an
// answer that didn't reach `out` ("service error: the answer couldn't be
// written"); 64 with rp::kCliUsage on `err`, before any call, for no
// subcommand, an unknown one, a word too many, an option the subcommand
// doesn't take, an option twice, without its value or with an empty one.
// <n> is Windows' error code in decimal.
//
// From every call of the SCM, first fit: error 5 "access denied; run this from
// an elevated prompt (Administrators)"; 1060, for `uninstall`, `start` and
// `stop`, "the service RestoreProof is not installed"; 1072 "the service
// RestoreProof is marked for deletion; close services.msc and any other tool
// that has it open, then try again" (3); anything else "<what was tried>
// failed (error <n>)", the first part "opening the service control manager"
// or "opening the service" for those two steps, else the call's own:
// "creating the service", "setting the description", "setting the recovery
// actions", "starting the service", "stopping the service", "deleting the
// service", "reading the service's state".
//
// `install [--config <path>]`, in this order: (a) --config must be an
// absolute path ("--config must be an absolute path; a service's working
// directory is System32"; one holding a quote is none; "the --config path is
// not valid UTF-8"), the file not read; (b) the service is created from
// service_setup(kServiceName, command line), the command line `"<own path>"
// service run` and, with --config, ` --config "<path>"` after it: 1073 "the
// service RestoreProof is already installed; uninstall it first", 1078 "the
// display name RestoreProof Worker is in use by another service", nothing
// made; (c) the log folder is made ("making the log folder failed (error
// <n>)"); (d) the description is set; (e) the recovery actions. When (c), (d)
// or (e) fails the service is deleted again and the line ends "; the service
// was not installed", or, when that delete fails too (with anything but
// 1060), "; the service was left installed: run rpworker service uninstall".
// On `out`: "installed RestoreProof: <command line>" and "account NT
// SERVICE\RestoreProof, automatic start, restart after 60 s up to 3 times;
// not started: run rpworker service start". It starts nothing, reads no
// config and no vault, and grants the account nothing.
//
// `uninstall`: reads the state; anything but stopped is "the service
// RestoreProof is running; stop it first (rpworker service stop)". Then one
// delete, then the state read every 250 ms for up to 10 s until the service
// is gone (1060): "uninstalled RestoreProof"; still there: "the service
// RestoreProof is marked for deletion; it goes when services.msc and any
// other tool that has it open are closed" (3).
//
// `start`: sends the start, then reads the state every 250 ms for up to 30 s
// of the command's start. Running: "started RestoreProof". Stopped again:
// "the service RestoreProof stopped while starting (<reason>); see <log
// file>", the reason "the config couldn't be loaded" or "the log couldn't be
// opened" for the service's own codes 1 and 2, else "service error <n>" or
// "Windows error <n>". Still starting: "the service RestoreProof is still
// starting after 30 s" (3). Windows' 1056 for the start is a reason to read
// the state: running, "RestoreProof is already running" (0); starting, the
// same wait; stopping, "the service RestoreProof is stopping; start it again
// when it has stopped" (3); stopped, the start is sent once more; anything
// else, and a second 1056, "starting the service failed (error 1056)". 1058:
// "the service RestoreProof is disabled". 1069: "NT SERVICE\RestoreProof
// couldn't log on (error 1069); it needs the "Log on as a service" right". 2
// and 3: "the service's executable isn't where it was installed from;
// uninstall and install again".
//
// `stop`: sends the stop, then reads the state every 250 ms for up to 35 s of
// the command's start. Stopped: "stopped RestoreProof in <s.s> s". 1062:
// "RestoreProof is already stopped" (0). 1061, a stop already under way, is
// waited for the same way. 1052, a service still starting: the stop is sent
// again every 250 ms inside the same 35 s until it is taken, 1062 answers, or
// the time is up: "the service RestoreProof is still starting after 35 s; the
// stop was not sent" (3). Still not stopped: "the service RestoreProof is
// still stopping after 35 s" (3).
//
// `run [--config <path>]`: rp::Service::run over `env.host` with `env.body`
// as the service's work, and nothing of the service before the dispatcher. In a process the SCM didn't start
// (1063): "service run is what the Service Control Manager starts; use
// rpworker service start", exit 1, nothing logged and no log file touched;
// any other answer of the dispatcher: "opening the service control manager
// failed (error <n>)", exit 1. Under the SCM: 0 after a clean stop, 1
// otherwise, nothing printed.
//
// No exception is caught here: what a seam throws (a ConfigError from
// default_log_dir included) is run_cli's "error: unexpected failure", and
// `install` asks for the paths before it creates anything.
int run_service_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const ServiceCommandEnv& env);

} // namespace rp
