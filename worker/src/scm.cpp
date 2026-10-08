#include "scm.hpp"

#include "utf16.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>

namespace rp::scm {

namespace {

// Never "it worked" for a call that failed.
unsigned long last_error() noexcept
{
    const unsigned long error = GetLastError();
    return error == 0 ? ERROR_GEN_FAILURE : error;
}

// A handle to the SCM or to a service, closed when it goes away.
class Handle {
public:
    explicit Handle(SC_HANDLE handle) noexcept : handle_(handle) {}
    ~Handle()
    {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
        }
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    SC_HANDLE get() const noexcept { return handle_; }
    explicit operator bool() const noexcept { return handle_ != nullptr; }

private:
    SC_HANDLE handle_;
};

// What a function here answers when it can't even ask: text that isn't UTF-8,
// or no memory for its copy.
constexpr ScmResult kNotAsked{ERROR_INVALID_PARAMETER, ScmStep::call};
constexpr ScmResult kNoMemory{ERROR_NOT_ENOUGH_MEMORY, ScmStep::call};
// What Windows answered that rp/service.hpp has no word for.
constexpr unsigned long kNoWordForIt = ERROR_INVALID_DATA;

// Runs `sequence` and answers what it answers; an exception (no memory for a
// string) is an error like any other, never "it worked".
template <typename Sequence>
ScmResult guarded(Sequence&& sequence) noexcept
{
    try {
        return sequence();
    } catch (...) {
        return kNoMemory;
    }
}

// Connects to the SCM, opens the service `name` with `rights` and runs
// `call(handle)`, which answers Windows' error code (0 = it worked).
template <typename Call>
ScmResult with_service(std::string_view name, DWORD rights, Call&& call) noexcept
{
    return guarded([&]() -> ScmResult {
        const std::optional<std::wstring> wide = utf8_to_utf16(name);
        if (!wide) {
            return kNotAsked;
        }
        const Handle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
        if (!manager) {
            return {last_error(), ScmStep::manager};
        }
        const Handle service{OpenServiceW(manager.get(), wide->c_str(), rights)};
        if (!service) {
            return {last_error(), ScmStep::service};
        }
        return {call(service.get()), ScmStep::call};
    });
}

std::optional<ServiceState> state_of(DWORD state) noexcept
{
    switch (state) {
    case SERVICE_STOPPED:
        return ServiceState::stopped;
    case SERVICE_START_PENDING:
        return ServiceState::start_pending;
    case SERVICE_STOP_PENDING:
        return ServiceState::stop_pending;
    case SERVICE_RUNNING:
        return ServiceState::running;
    case SERVICE_CONTINUE_PENDING:
        return ServiceState::continue_pending;
    case SERVICE_PAUSE_PENDING:
        return ServiceState::pause_pending;
    case SERVICE_PAUSED:
        return ServiceState::paused;
    default:
        return std::nullopt;
    }
}

DWORD state_number(ServiceState state) noexcept
{
    switch (state) {
    case ServiceState::start_pending:
        return SERVICE_START_PENDING;
    case ServiceState::stop_pending:
        return SERVICE_STOP_PENDING;
    case ServiceState::running:
        return SERVICE_RUNNING;
    case ServiceState::continue_pending:
        return SERVICE_CONTINUE_PENDING;
    case ServiceState::pause_pending:
        return SERVICE_PAUSE_PENDING;
    case ServiceState::paused:
        return SERVICE_PAUSED;
    case ServiceState::stopped:
    default:
        return SERVICE_STOPPED;
    }
}

DWORD start_number(ServiceStartType type) noexcept
{
    switch (type) {
    case ServiceStartType::manual:
        return SERVICE_DEMAND_START;
    case ServiceStartType::disabled:
        return SERVICE_DISABLED;
    case ServiceStartType::automatic:
    default:
        return SERVICE_AUTO_START;
    }
}

std::optional<ServiceStartType> start_type_of(DWORD type) noexcept
{
    switch (type) {
    case SERVICE_AUTO_START:
        return ServiceStartType::automatic;
    case SERVICE_DEMAND_START:
        return ServiceStartType::manual;
    case SERVICE_DISABLED:
        return ServiceStartType::disabled;
    default:
        return std::nullopt;
    }
}

// Windows' text as UTF-8; a null pointer is no text.
std::optional<std::string> text_of(const wchar_t* text)
{
    return text == nullptr ? std::optional<std::string>{std::string{}} : utf16_to_utf8(text);
}

// Room for any answer to a configuration query: Windows caps each at 8 K
// bytes. Suitably aligned for the structures read out of it.
constexpr std::size_t kConfigBytes = 8192;
struct ConfigBuffer {
    alignas(std::max_align_t) unsigned char bytes[kConfigBytes];
};

// The three reads behind read_setup, each 0 or Windows' error code.
unsigned long read_config(SC_HANDLE service, ServiceSetup& setup)
{
    ConfigBuffer buffer{};
    DWORD needed = 0;
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.bytes);
    if (QueryServiceConfigW(service, config, kConfigBytes, &needed) == 0) {
        return last_error();
    }
    const std::optional<ServiceStartType> start_type = start_type_of(config->dwStartType);
    std::optional<std::string> display_name = text_of(config->lpDisplayName);
    std::optional<std::string> account = text_of(config->lpServiceStartName);
    std::optional<std::string> command_line = text_of(config->lpBinaryPathName);
    if (!start_type || !display_name || !account || !command_line) {
        return kNoWordForIt;
    }
    setup.start_type = *start_type;
    setup.display_name = std::move(*display_name);
    setup.account = std::move(*account);
    setup.command_line = std::move(*command_line);
    return 0;
}

unsigned long read_description(SC_HANDLE service, ServiceSetup& setup)
{
    ConfigBuffer buffer{};
    DWORD needed = 0;
    if (QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, buffer.bytes, kConfigBytes,
                             &needed) == 0) {
        return last_error();
    }
    std::optional<std::string> description =
        text_of(reinterpret_cast<const SERVICE_DESCRIPTIONW*>(buffer.bytes)->lpDescription);
    if (!description) {
        return kNoWordForIt;
    }
    setup.description = std::move(*description);
    return 0;
}

unsigned long read_recovery(SC_HANDLE service, ServiceSetup& setup)
{
    ConfigBuffer buffer{};
    DWORD needed = 0;
    if (QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, buffer.bytes, kConfigBytes,
                             &needed) == 0) {
        return last_error();
    }
    const auto* recovery = reinterpret_cast<const SERVICE_FAILURE_ACTIONSW*>(buffer.bytes);
    std::vector<ServiceAction> actions;
    for (DWORD i = 0; recovery->lpsaActions != nullptr && i < recovery->cActions; ++i) {
        const SC_ACTION& action = recovery->lpsaActions[i];
        if (action.Type != SC_ACTION_NONE && action.Type != SC_ACTION_RESTART) {
            return kNoWordForIt;
        }
        actions.push_back({action.Type == SC_ACTION_RESTART ? ServiceActionKind::restart
                                                             : ServiceActionKind::none,
                           action.Delay});
    }
    setup.failure_actions = std::move(actions);
    setup.reset_period_s = recovery->dwResetPeriod;
    return 0;
}

// One service per process: what the two callbacks below call back into, and
// the handle a status is reported through.
ServiceMainFunction g_main;
ServiceControlHandler g_handler;
std::atomic<SERVICE_STATUS_HANDLE> g_status{nullptr};

// What the dispatcher runs as the service's main function. The arguments of a
// start are not used: `service run` takes its own from the command line.
VOID WINAPI service_main(DWORD, LPWSTR*)
{
    g_main();
}

// What the SCM calls for each control.
DWORD WINAPI handler_ex(DWORD control, DWORD, LPVOID, LPVOID)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
        return g_handler(ServiceControl::stop);
    case SERVICE_CONTROL_SHUTDOWN:
        return g_handler(ServiceControl::shutdown);
    case SERVICE_CONTROL_INTERROGATE:
        return g_handler(ServiceControl::interrogate);
    default:
        return g_handler(ServiceControl::other);
    }
}

} // namespace

ScmResult create_service(const ServiceSetup& setup) noexcept
{
    return guarded([&]() -> ScmResult {
        const std::optional<std::wstring> name = utf8_to_utf16(setup.name);
        const std::optional<std::wstring> display_name = utf8_to_utf16(setup.display_name);
        const std::optional<std::wstring> command_line = utf8_to_utf16(setup.command_line);
        const std::optional<std::wstring> account = utf8_to_utf16(setup.account);
        if (!name || !display_name || !command_line || !account) {
            return kNotAsked;
        }
        const Handle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
        if (!manager) {
            return {last_error(), ScmStep::manager};
        }
        // No load order group, no dependencies, and no password: a virtual
        // account has none. The handle's rights are those the recovery call
        // needs, though that call opens its own.
        const Handle service{CreateServiceW(
            manager.get(), name->c_str(), display_name->c_str(),
            SERVICE_CHANGE_CONFIG | SERVICE_START, SERVICE_WIN32_OWN_PROCESS,
            start_number(setup.start_type), SERVICE_ERROR_NORMAL, command_line->c_str(), nullptr,
            nullptr, nullptr, account->c_str(), nullptr)};
        return {service ? 0 : last_error(), ScmStep::call};
    });
}

ScmResult set_description(std::string_view name, std::string_view description) noexcept
{
    return guarded([&]() -> ScmResult {
        std::optional<std::wstring> text = utf8_to_utf16(description);
        if (!text) {
            return kNotAsked;
        }
        return with_service(name, SERVICE_CHANGE_CONFIG, [&text](SC_HANDLE service) {
            SERVICE_DESCRIPTIONW change{text->data()};
            return ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &change) != 0
                       ? 0
                       : last_error();
        });
    });
}

ScmResult set_recovery(std::string_view name, const std::vector<ServiceAction>& actions,
                       unsigned long reset_period_s) noexcept
{
    return guarded([&]() -> ScmResult {
        // One entry more than asked for, so the array is never null: with a
        // count of 0, a null array would mean "leave the actions as they are".
        std::vector<SC_ACTION> list(actions.size() + 1);
        for (std::size_t i = 0; i < actions.size(); ++i) {
            list[i].Type =
                actions[i].kind == ServiceActionKind::restart ? SC_ACTION_RESTART : SC_ACTION_NONE;
            list[i].Delay = actions[i].delay_ms;
        }
        // SERVICE_START: Windows refuses a restart action set through a handle
        // that couldn't start the service.
        return with_service(name, SERVICE_CHANGE_CONFIG | SERVICE_START,
                            [&](SC_HANDLE service) {
                                SERVICE_FAILURE_ACTIONSW change{};
                                change.dwResetPeriod = reset_period_s;
                                // Null: no reboot message, no command.
                                change.cActions = static_cast<DWORD>(actions.size());
                                change.lpsaActions = list.data();
                                return ChangeServiceConfig2W(service,
                                                             SERVICE_CONFIG_FAILURE_ACTIONS,
                                                             &change) != 0
                                           ? 0
                                           : last_error();
                            });
    });
}

ScmResult delete_service(std::string_view name) noexcept
{
    return with_service(name, DELETE, [](SC_HANDLE service) {
        return DeleteService(service) != 0 ? 0 : last_error();
    });
}

ScmResult start_service(std::string_view name) noexcept
{
    return with_service(name, SERVICE_START, [](SC_HANDLE service) {
        return StartServiceW(service, 0, nullptr) != 0 ? 0 : last_error();
    });
}

ScmResult stop_service(std::string_view name) noexcept
{
    return with_service(name, SERVICE_STOP, [](SC_HANDLE service) {
        SERVICE_STATUS status{};
        return ControlService(service, SERVICE_CONTROL_STOP, &status) != 0 ? 0 : last_error();
    });
}

ScmResult query_service(std::string_view name, ServiceStatus& status) noexcept
{
    return with_service(name, SERVICE_QUERY_STATUS, [&status](SC_HANDLE service) -> unsigned long {
        SERVICE_STATUS read{};
        if (QueryServiceStatus(service, &read) == 0) {
            return last_error();
        }
        const std::optional<ServiceState> state = state_of(read.dwCurrentState);
        if (!state) {
            return kNoWordForIt;
        }
        status.state = *state;
        status.win32_exit_code = read.dwWin32ExitCode;
        status.service_exit_code = read.dwServiceSpecificExitCode;
        status.wait_hint_ms = read.dwWaitHint;
        status.checkpoint = read.dwCheckPoint;
        return 0;
    });
}

ScmResult read_setup(std::string_view name, ServiceSetup& setup) noexcept
{
    return with_service(name, SERVICE_QUERY_CONFIG, [&](SC_HANDLE service) -> unsigned long {
        ServiceSetup read;
        read.name = std::string{name};
        unsigned long error = read_config(service, read);
        error = error != 0 ? error : read_description(service, read);
        error = error != 0 ? error : read_recovery(service, read);
        if (error == 0) {
            setup = std::move(read);
        }
        return error;
    });
}

unsigned long run_dispatcher(std::string_view name, ServiceMainFunction main) noexcept
{
    unsigned long error = ERROR_NOT_ENOUGH_MEMORY;
    try {
        std::optional<std::wstring> wide = utf8_to_utf16(name);
        if (!wide) {
            return ERROR_INVALID_PARAMETER;
        }
        g_main = std::move(main);
        const SERVICE_TABLE_ENTRYW table[] = {{wide->data(), &service_main}, {nullptr, nullptr}};
        // Returns when the service has reported that it stopped, or at once
        // with 1063 in a process the SCM didn't start.
        if (StartServiceCtrlDispatcherW(table) != 0) {
            // g_main stays: the thread it ran on may not have left it yet.
            return 0;
        }
        error = last_error();
        g_main = nullptr;
    } catch (...) {
    }
    return error;
}

unsigned long register_handler(std::string_view name, ServiceControlHandler handler) noexcept
{
    unsigned long error = ERROR_NOT_ENOUGH_MEMORY;
    try {
        const std::optional<std::wstring> wide = utf8_to_utf16(name);
        if (!wide) {
            return ERROR_INVALID_PARAMETER;
        }
        // Set before it is registered: a control may arrive at once.
        g_handler = std::move(handler);
        const SERVICE_STATUS_HANDLE status =
            RegisterServiceCtrlHandlerExW(wide->c_str(), &handler_ex, nullptr);
        if (status != nullptr) {
            g_status = status;
            return 0;
        }
        error = last_error();
        g_handler = nullptr;
    } catch (...) {
    }
    return error;
}

unsigned long report_status(const ServiceReport& report) noexcept
{
    const SERVICE_STATUS_HANDLE handle = g_status;
    if (handle == nullptr) {
        return ERROR_INVALID_HANDLE;
    }
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state_number(report.state);
    status.dwControlsAccepted =
        report.accepts_stop ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    // The service's own code travels beside Windows' "service-specific error".
    status.dwWin32ExitCode =
        report.service_exit_code != 0 ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    status.dwServiceSpecificExitCode = report.service_exit_code;
    status.dwCheckPoint = report.checkpoint;
    status.dwWaitHint = report.wait_hint_ms;
    return SetServiceStatus(handle, &status) != 0 ? 0 : last_error();
}

void exit_process(int code) noexcept
{
    // Not the runtime's exit: no static destructor and no atexit function may
    // run under a thread that is still working.
    TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
}

} // namespace rp::scm
