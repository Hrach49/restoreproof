#include <rp/service_command.hpp>

#include <rp/cli.hpp>
#include <rp/service_log.hpp>

#include "command_config.hpp"
#include "folder_ops.hpp"
#include "path_utf8.hpp"
#include "scm.hpp"
#include "worker_body.hpp"

#include <format>
#include <optional>
#include <ostream>
#include <string>
#include <thread>
#include <utility>

namespace rp {

namespace {

using Clock = std::chrono::steady_clock;

// Windows' error codes the commands have an answer of their own for.
constexpr unsigned long kFileNotFound = 2;
constexpr unsigned long kPathNotFound = 3;
constexpr unsigned long kAccessDenied = 5;
constexpr unsigned long kControlNotAccepted = 1052;  // still starting: the stop wasn't sent
constexpr unsigned long kAlreadyRunning = 1056;      // the start's answer for "not stopped"
constexpr unsigned long kDisabled = 1058;
constexpr unsigned long kNotInstalled = 1060;
constexpr unsigned long kStopUnderWay = 1061;
constexpr unsigned long kNotActive = 1062; // the stop's answer for "stopped"
constexpr unsigned long kSpecificError = 1066;
constexpr unsigned long kLogonFailed = 1069;
constexpr unsigned long kMarkedForDeletion = 1072;
constexpr unsigned long kAlreadyInstalled = 1073;
constexpr unsigned long kDisplayNameTaken = 1078;

// The first parts of "<what was tried> failed (error <n>)".
constexpr std::string_view kOpeningManager = "opening the service control manager";
constexpr std::string_view kOpeningService = "opening the service";
constexpr std::string_view kCreating = "creating the service";
constexpr std::string_view kDescribing = "setting the description";
constexpr std::string_view kRecovery = "setting the recovery actions";
constexpr std::string_view kStarting = "starting the service";
constexpr std::string_view kStopping = "stopping the service";
constexpr std::string_view kDeleting = "deleting the service";
constexpr std::string_view kReading = "reading the service's state";
constexpr std::string_view kMakingFolder = "making the log folder";

// `given`, or the real function when it is null.
template <typename Function, typename Real>
Function or_real(const Function& given, Real* real)
{
    return given ? given : Function{real};
}

// One command's surroundings: the two streams, and the environment with the
// SCM's real calls where none was handed in.
struct Context {
    std::ostream& out;
    std::ostream& err;
    const ServiceCommandEnv& env;
    ScmCalls scm;

    Context(std::ostream& out_stream, std::ostream& err_stream,
            const ServiceCommandEnv& environment)
        : out(out_stream), err(err_stream), env(environment)
    {
        scm.create_service = or_real(env.scm.create_service, &scm::create_service);
        scm.set_description = or_real(env.scm.set_description, &scm::set_description);
        scm.set_recovery = or_real(env.scm.set_recovery, &scm::set_recovery);
        scm.delete_service = or_real(env.scm.delete_service, &scm::delete_service);
        scm.start_service = or_real(env.scm.start_service, &scm::start_service);
        scm.stop_service = or_real(env.scm.stop_service, &scm::stop_service);
        scm.query_service = or_real(env.scm.query_service, &scm::query_service);
    }

    Clock::time_point now() const { return env.now ? env.now() : Clock::now(); }

    void sleep(std::chrono::milliseconds time) const
    {
        env.sleep ? env.sleep(time) : std::this_thread::sleep_for(time);
    }

    std::filesystem::path log_dir() const
    {
        return env.default_log_dir ? env.default_log_dir() : default_log_dir();
    }

    std::filesystem::path own_path() const
    {
        return env.own_path ? env.own_path() : own_executable_path();
    }

    unsigned long make_folder(const std::filesystem::path& folder) const
    {
        return env.make_folder ? env.make_folder(folder) : make_folder_error(folder);
    }
};

// What a "service error: " line says after those words, and its exit code.
struct Refusal {
    std::string text;
    int code = exit_code::config;
};

std::string name()
{
    return std::string{kServiceName};
}

std::string failed(std::string_view tried, unsigned long error)
{
    return std::format("{} failed (error {})", tried, error);
}

// The refusals every call of the SCM shares, first fit. `tried` is the call's
// own first part; `names_missing` is whether 1060 has its own line (not for
// `install`, where it is no answer to anything it asks).
Refusal refusal(const ScmResult& result, std::string_view tried, bool names_missing)
{
    if (result.error == kAccessDenied) {
        return {"access denied; run this from an elevated prompt (Administrators)"};
    }
    if (result.error == kNotInstalled && names_missing) {
        return {"the service " + name() + " is not installed"};
    }
    if (result.error == kMarkedForDeletion) {
        return {"the service " + name() +
                    " is marked for deletion; close services.msc and any other tool that has it "
                    "open, then try again",
                exit_code::transient};
    }
    const std::string_view what = result.step == ScmStep::manager   ? kOpeningManager
                                  : result.step == ScmStep::service ? kOpeningService
                                                                    : tried;
    return {failed(what, result.error)};
}

// The one "service error: ..." line; the refusal's exit code.
int refuse(const Context& context, const Refusal& refusal, std::string_view ending = {})
{
    context.err << "service error: " << refusal.text << ending << '\n';
    return refusal.code;
}

// Exit 0, once the answer is out. An answer that didn't reach stdout isn't
// one: exit 0 would say what no line did.
int answered(const Context& context)
{
    context.out.flush();
    if (!context.out) {
        return refuse(context, {"the answer couldn't be written"});
    }
    return exit_code::ok;
}

// `step` now and then every kServicePollInterval, until it has an answer or
// `limit` has passed since `began`; so the last try is at the limit itself.
template <typename Step>
auto poll(const Context& context, Clock::time_point began, std::chrono::milliseconds limit,
          Step&& step)
{
    auto done = step();
    while (!done && context.now() - began < limit) {
        context.sleep(kServicePollInterval);
        done = step();
    }
    return done;
}

// `text` in quotes as one argument of a command line. A path can't hold a
// quote; backslashes right before the closing quote are doubled, or the
// program's parser would take the quote for a part of the argument.
std::string quoted(std::string_view text)
{
    const std::size_t last = text.find_last_not_of('\\');
    const std::size_t trailing = text.size() - (last == std::string_view::npos ? 0 : last + 1);
    return "\"" + std::string{text} + std::string(trailing, '\\') + "\"";
}

// --config as a path; nullopt, with its line out, when it isn't UTF-8.
std::optional<std::filesystem::path> config_path_of(const Context& context, std::string_view arg)
{
    std::optional<std::filesystem::path> path = path_from_utf8(arg);
    if (!path) {
        refuse(context, {"the --config path is not valid UTF-8"});
    }
    return path;
}

// `rpworker service install [--config <path>]`.
int run_install(const Context& context, std::optional<std::string_view> config_arg)
{
    // (a) A service's working directory is System32: only an absolute path
    // names the same file there. The file itself isn't read.
    std::string config_part;
    if (config_arg) {
        const std::optional<std::filesystem::path> config = config_path_of(context, *config_arg);
        if (!config) {
            return exit_code::config;
        }
        if (!config->is_absolute() || config_arg->find('"') != std::string_view::npos) {
            return refuse(context, {"--config must be an absolute path; a service's working "
                                    "directory is System32"});
        }
        config_part = " --config " + quoted(*config_arg);
    }
    // Both asked for before anything is created: what they throw leaves
    // nothing behind.
    const std::filesystem::path log_dir = context.log_dir();
    const std::string command_line =
        "\"" + path_to_utf8(context.own_path()) + "\" service run" + config_part;
    const ServiceSetup setup = service_setup(kServiceName, command_line);

    // (b) Access denied, a service already there and a display name in use
    // end here, with nothing made.
    const ScmResult created = context.scm.create_service(setup);
    if (created.error == kAlreadyInstalled) {
        return refuse(context,
                      {"the service " + name() + " is already installed; uninstall it first"});
    }
    if (created.error == kDisplayNameTaken) {
        return refuse(context, {"the display name " + std::string{kServiceDisplayName} +
                                " is in use by another service"});
    }
    if (created.error != 0) {
        return refuse(context, refusal(created, kCreating, false));
    }

    // (c) the log folder, (d) the description, (e) the recovery actions: the
    // first that fails ends it.
    std::optional<Refusal> problem;
    if (const unsigned long error = context.make_folder(log_dir); error != 0) {
        problem = Refusal{failed(kMakingFolder, error)};
    }
    if (!problem) {
        const ScmResult described = context.scm.set_description(kServiceName, setup.description);
        if (described.error != 0) {
            problem = refusal(described, kDescribing, false);
        }
    }
    if (!problem) {
        const ScmResult set = context.scm.set_recovery(kServiceName, setup.failure_actions,
                                                       setup.reset_period_s);
        if (set.error != 0) {
            problem = refusal(set, kRecovery, false);
        }
    }
    if (problem) {
        // What (b) made is taken away again: no half-made service stays.
        const ScmResult deleted = context.scm.delete_service(kServiceName);
        const bool gone = deleted.error == 0 || deleted.error == kNotInstalled;
        return refuse(context, *problem,
                      gone ? "; the service was not installed"
                           : "; the service was left installed: run rpworker service uninstall");
    }

    context.out << "installed " << kServiceName << ": " << command_line << '\n'
                << "account " << kServiceAccount
                << ", automatic start, restart after 60 s up to 3 times; not started: run rpworker "
                   "service start\n";
    return answered(context);
}

// `rpworker service uninstall`.
int run_uninstall(const Context& context)
{
    ServiceStatus status;
    if (const ScmResult read = context.scm.query_service(kServiceName, status); read.error != 0) {
        return refuse(context, refusal(read, kReading, true));
    }
    if (status.state != ServiceState::stopped) {
        return refuse(context, {"the service " + name() +
                                " is running; stop it first (rpworker service stop)"});
    }
    if (const ScmResult deleted = context.scm.delete_service(kServiceName); deleted.error != 0) {
        return refuse(context, refusal(deleted, kDeleting, true));
    }
    // Marked for deletion until the last handle to it is closed: gone when
    // the SCM no longer knows the name.
    const std::optional<int> done =
        poll(context, context.now(), kServiceUninstallWait, [&]() -> std::optional<int> {
            ServiceStatus still;
            const ScmResult read = context.scm.query_service(kServiceName, still);
            if (read.error == kNotInstalled) {
                context.out << "uninstalled " << kServiceName << '\n';
                return answered(context);
            }
            if (read.error != 0) {
                return refuse(context, refusal(read, kReading, true));
            }
            return std::nullopt;
        });
    if (done) {
        return *done;
    }
    return refuse(context, {"the service " + name() +
                                " is marked for deletion; it goes when services.msc and any other "
                                "tool that has it open are closed",
                            exit_code::transient});
}

// Why a service is stopped again right after its start.
std::string stop_reason(const ServiceStatus& status)
{
    if (status.win32_exit_code != kSpecificError) {
        return std::format("Windows error {}", status.win32_exit_code);
    }
    if (status.service_exit_code == kServiceCodeConfig) {
        return "the config couldn't be loaded";
    }
    if (status.service_exit_code == kServiceCodeLog) {
        return "the log couldn't be opened";
    }
    return std::format("service error {}", status.service_exit_code);
}

// The line for a start the SCM refused.
Refusal start_refusal(const ScmResult& sent)
{
    if (sent.error == kDisabled) {
        return {"the service " + name() + " is disabled"};
    }
    if (sent.error == kLogonFailed) {
        return {std::string{kServiceAccount} +
                " couldn't log on (error 1069); it needs the \"Log on as a service\" right"};
    }
    if (sent.error == kFileNotFound || sent.error == kPathNotFound) {
        return {"the service's executable isn't where it was installed from; uninstall and "
                "install again"};
    }
    if (sent.error == kAccessDenied && sent.step == ScmStep::call) {
        // The caller opened the service, so it is elevated: the start itself
        // was denied, which is the account's access to the executable.
        return {std::string{kServiceAccount} +
                " was denied access when starting (error 5); it must be able to read and run "
                "the service's executable"};
    }
    return refusal(sent, kStarting, true);
}

// `rpworker service start`.
int run_start(const Context& context)
{
    // W5.1 point 2: the first start registers before anything is started.
    if (context.env.first_start) {
        if (const int code = context.env.first_start(context.out, context.err); code != 0) {
            return code;
        }
    }
    const Clock::time_point began = context.now();
    ScmResult sent = context.scm.start_service(kServiceName);
    if (sent.error == kAlreadyRunning) {
        // Windows' one answer for a service that isn't stopped: a reason to
        // read the state, never the answer.
        ServiceStatus status;
        if (const ScmResult read = context.scm.query_service(kServiceName, status);
            read.error != 0) {
            return refuse(context, refusal(read, kReading, true));
        }
        if (status.state == ServiceState::running) {
            context.out << kServiceName << " is already running\n";
            return answered(context);
        }
        if (status.state == ServiceState::stop_pending) {
            // The stop was someone's: it isn't waited out to undo it.
            return refuse(context, {"the service " + name() +
                                        " is stopping; start it again when it has stopped",
                                    exit_code::transient});
        }
        if (status.state == ServiceState::start_pending) {
            // Someone's start: waited for like one that was sent.
            sent = ScmResult{};
        }
        if (status.state == ServiceState::stopped) {
            // Stopped by now: once more, and a second 1056 is the answer.
            sent = context.scm.start_service(kServiceName);
        }
    }
    if (sent.error != 0) {
        return refuse(context, start_refusal(sent));
    }
    const std::optional<int> done =
        poll(context, began, kServiceStartWait, [&]() -> std::optional<int> {
            ServiceStatus status;
            const ScmResult read = context.scm.query_service(kServiceName, status);
            if (read.error != 0) {
                return refuse(context, refusal(read, kReading, true));
            }
            if (status.state == ServiceState::running) {
                context.out << "started " << kServiceName << '\n';
                return answered(context);
            }
            if (status.state == ServiceState::stopped) {
                const std::filesystem::path log =
                    context.log_dir() / std::filesystem::path{kLogFileName};
                return refuse(context, {"the service " + name() + " stopped while starting (" +
                                        stop_reason(status) + "); see " + path_to_utf8(log)});
            }
            return std::nullopt;
        });
    if (done) {
        return *done;
    }
    return refuse(context, {"the service " + name() + " is still starting after 30 s",
                            exit_code::transient});
}

// `rpworker service stop`.
int run_stop(const Context& context)
{
    const Clock::time_point began = context.now();
    // A service still starting takes no control, so the stop wasn't sent: it
    // is sent again until it is taken or the time is up.
    ScmResult sent = context.scm.stop_service(kServiceName);
    while (sent.error == kControlNotAccepted && context.now() - began < kServiceStopWait) {
        context.sleep(kServicePollInterval);
        sent = context.scm.stop_service(kServiceName);
    }
    if (sent.error == kControlNotAccepted) {
        return refuse(context, {"the service " + name() +
                                    " is still starting after 35 s; the stop was not sent",
                                exit_code::transient});
    }
    if (sent.error == kNotActive) {
        context.out << kServiceName << " is already stopped\n";
        return answered(context);
    }
    // 1061: a stop is already under way, which is waited for the same way.
    if (sent.error != 0 && sent.error != kStopUnderWay) {
        return refuse(context, refusal(sent, kStopping, true));
    }
    // Windows may say 1061 of a service that is still starting, too. The state
    // tells the two apart: while it reads "start pending" and no stop was
    // taken, the stop is sent again.
    bool starting = false;
    const std::optional<int> done =
        poll(context, began, kServiceStopWait, [&]() -> std::optional<int> {
            ServiceStatus status;
            const ScmResult read = context.scm.query_service(kServiceName, status);
            if (read.error != 0) {
                return refuse(context, refusal(read, kReading, true));
            }
            starting = sent.error != 0 && status.state == ServiceState::start_pending;
            if (starting) {
                sent = context.scm.stop_service(kServiceName);
                const bool waits = sent.error == 0 || sent.error == kStopUnderWay ||
                                   sent.error == kControlNotAccepted || sent.error == kNotActive;
                return waits ? std::nullopt
                             : std::optional<int>{
                                   refuse(context, refusal(sent, kStopping, true))};
            }
            if (status.state != ServiceState::stopped) {
                return std::nullopt;
            }
            // From the command's start, cut to a tenth of a second.
            using std::chrono::milliseconds;
            const auto took = std::chrono::duration_cast<milliseconds>(context.now() - began).count();
            context.out << std::format("stopped {} in {}.{} s\n", kServiceName, took / 1000,
                                       took % 1000 / 100);
            return answered(context);
        });
    if (done) {
        return *done;
    }
    return refuse(context, {"the service " + name() +
                                (starting ? " is still starting after 35 s; the stop was not sent"
                                          : " is still stopping after 35 s"),
                            exit_code::transient});
}

// `rpworker service run [--config <path>]`: the service itself.
int run_service(const Context& context, std::optional<std::string_view> config_arg)
{
    ServiceOptions options;
    options.host = context.env.host;
    options.body = context.env.body;
    options.default_config_path = context.env.default_config_path;
    options.default_log_dir = context.env.default_log_dir;
    if (config_arg) {
        options.config_path = config_path_of(context, *config_arg);
        if (!options.config_path) {
            return exit_code::config;
        }
    }
    // The dispatcher and nothing of the service before it: the SCM gives a
    // process 30 s to call it.
    const ServiceRun ran = Service{std::move(options)}.run();
    if (ran.dispatcher_error == kNotStartedByScm) {
        return refuse(context, {"service run is what the Service Control Manager starts; use "
                                "rpworker service start"});
    }
    if (ran.dispatcher_error != 0) {
        return refuse(context, {failed(kOpeningManager, ran.dispatcher_error)});
    }
    return ran.exit_code;
}

} // namespace

ServiceCommandEnv default_service_command_env()
{
    ServiceCommandEnv env;
    // W4.8: the scheduler loop over its real calls and paths.
    env.body = make_worker_body();
    // W5.1: the first start registers.
    env.first_start = service_first_start;
    return env;
}

std::optional<std::string> service_config_argument(std::string_view command_line)
{
    // install's own form: a quoted executable, then exactly this, then a path
    // in quotes holding none (install refuses one).
    constexpr std::string_view kConfigPart = "\" service run --config \"";
    const std::size_t at = command_line.find(kConfigPart);
    if (!command_line.starts_with('"') || at == std::string_view::npos ||
        !command_line.ends_with('"')) {
        return std::nullopt;
    }
    const std::string_view path =
        command_line.substr(at + kConfigPart.size(),
                            command_line.size() - at - kConfigPart.size() - 1);
    if (path.empty() || path.find('"') != std::string_view::npos) {
        return std::nullopt;
    }
    return std::string{path};
}

int run_service_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const ServiceCommandEnv& env)
{
    const std::string_view subcommand = args.empty() ? std::string_view{} : args[0];
    if (subcommand == "install" || subcommand == "run") {
        const std::optional<CommandOptions> options = parse_options(args.subspan(1), {"--config"});
        const std::optional<std::string_view> config =
            options ? options->value("--config") : std::nullopt;
        if (options && config != std::optional<std::string_view>{""}) {
            const Context context{out, err, env};
            return subcommand == "run" ? run_service(context, config)
                                       : run_install(context, config);
        }
    }
    if (args.size() == 1 && subcommand == "uninstall") {
        return run_uninstall(Context{out, err, env});
    }
    if (args.size() == 1 && subcommand == "start") {
        return run_start(Context{out, err, env});
    }
    if (args.size() == 1 && subcommand == "stop") {
        return run_stop(Context{out, err, env});
    }
    err << kCliUsage;
    return exit_code::usage;
}

} // namespace rp
