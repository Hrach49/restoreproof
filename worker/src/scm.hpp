#pragma once

// The real calls into Windows' Service Control Manager (W4.7,
// docs/decisions.md 2026-10-08 point 8): one call sequence per function, with
// nothing decided here. The service's commands (strict) take them as
// rp::ScmCalls and the running service as rp::ServiceHost, so their own
// branches are tested with fakes in their place.
//
// src/scm.cpp is the only file under src/, include/ and app/ that names a
// service function of Windows or a call that ends the process; a source scan
// in tests/scm_test.cpp holds that, comments included, which is why none is
// named here either.
//
// Each of the first eight takes the service's name, connects to the SCM, opens
// and closes its own handles, and answers Windows' error code with the call it
// is of: never "it worked" for a call that failed. None throws.

#include <rp/service.hpp>

#include <string_view>
#include <vector>

namespace rp::scm {

// Creates the service: one of its own process, error control normal, with
// `setup`'s name, display name, start type, command line and account, and no
// password. Not its description and not its failure actions: the two calls
// below. Needs an administrator's handle to the SCM (error 5 at
// ScmStep::manager otherwise); 1073 when the name is taken, 1078 when the
// display name is, 1072 while a service of that name is marked for deletion.
ScmResult create_service(const ServiceSetup& setup) noexcept;

ScmResult set_description(std::string_view name, std::string_view description) noexcept;

// The failure actions and the reset period, through a handle that may also
// start the service, which a restart action needs.
ScmResult set_recovery(std::string_view name, const std::vector<ServiceAction>& actions,
                       unsigned long reset_period_s) noexcept;

// Marks the service for deletion; it is gone when no handle to it is open.
ScmResult delete_service(std::string_view name) noexcept;

// Sends the start, with no arguments; returns before the service runs.
ScmResult start_service(std::string_view name) noexcept;

// Sends the stop control; returns before the service has stopped.
ScmResult stop_service(std::string_view name) noexcept;

// Reads the service's state into `status`, which is untouched unless the
// answer's error is 0. Anyone may ask; 1060 at ScmStep::service for a service
// that isn't installed.
ScmResult query_service(std::string_view name, ServiceStatus& status) noexcept;

// Reads an installed service's configuration back into `setup` (every field
// of it; untouched unless the answer's error is 0): what the tests hold a
// created service to, and what W7.2's doctor will read. A start type or a
// failure action rp/service.hpp has no word for is error 13 (invalid data).
ScmResult read_setup(std::string_view name, ServiceSetup& setup) noexcept;

// rp::ServiceHost's four. One service per process: the main function, the
// handler and the status handle are this file's statics.

// Connects the process to the SCM and blocks until the service has stopped;
// `main` runs on a thread of the SCM's. 0, or Windows' error code: 1063 in a
// process the SCM didn't start, where `main` is never run.
unsigned long run_dispatcher(std::string_view name, ServiceMainFunction main) noexcept;

// Registers `handler` for the SCM's controls and keeps the status handle for
// report_status. 0, or Windows' error code.
unsigned long register_handler(std::string_view name, ServiceControlHandler handler) noexcept;

// Reports `report`. 0, or Windows' error code; 6 (invalid handle) before a
// handler was registered.
unsigned long report_status(const ServiceReport& report) noexcept;

// Ends this process at once with `code`: no static destructor, no atexit
// function and no stream flush runs. Doesn't return.
void exit_process(int code) noexcept;

} // namespace rp::scm
