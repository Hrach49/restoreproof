#pragma once

// The service's body with its real calls (W4.8, docs/decisions.md 2026-10-08
// points 1, 5, 7 and 10 to 12): rp::make_worker_body builds the
// ServiceLoopEnv the scheduler loop (rp/service_loop.hpp) runs on from the
// service's context and runs the loop until the stop. Nothing is decided
// here: each function of the env is one call of what decides (the pipeline,
// the close plan, the outbox, the connector, the Cleaner, the heartbeat) with
// the service's logger, its stop and its paths.
//
// Not strict: the real calls, as src/uploader.cpp and src/folder_ops.cpp are.

#include <rp/config.hpp>
#include <rp/http_client.hpp>
#include <rp/outbox.hpp>
#include <rp/restore_command.hpp>
#include <rp/run_lock.hpp>
#include <rp/service.hpp>
#include <rp/service_loop.hpp>

#include "run_pipeline.hpp"

#include <spdlog/logger.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>

namespace rp {

// What the body is made of; everything null or absent = the real one. A test
// passes a temp folder for each path and a fake for each factory, so no test
// meets %ProgramData%, the machine's mutexes, the vault or the network.
struct WorkerBodyOptions {
    // Under which a run makes its folder <runs root>\<run_id>; nullopt =
    // rp::default_runs_root().
    std::optional<std::filesystem::path> runs_root;
    // <root>\outbox and <root>\sent; nullopt = rp::default_outbox_root().
    std::optional<std::filesystem::path> outbox_root;
    // Where running.json is; made when it isn't there. nullopt =
    // rp::default_state_dir().
    std::optional<std::filesystem::path> state_dir;
    // The vault, read per run, per close, per recovery clean and when the
    // hold's connector is made; nullopt = rp::default_vault_path().
    std::optional<std::filesystem::path> vault;
    // The client the Cloud is reached through, made once, at the first flush
    // or heartbeat, and kept for the service's life; null =
    // rp::make_cloud_http_client.
    std::function<std::unique_ptr<IHttpClient>(const Config&, std::shared_ptr<spdlog::logger>)>
        make_cloud_http;
    // The pipeline's env, asked for each run, close and clean; null =
    // rp::default_restore_command_env. The body then sets what is the
    // service's: connector_options' logger, sleep, on_session_opened and
    // before_restore_request, stop_requested, on_run_started, take_run_lock,
    // the vault's path and outbox_files.
    std::function<RestoreCommandEnv()> pipeline_env;
    // One try for the run mutex; null = rp::try_take_restore_targets_lock.
    // The body takes an abandoned one again at once (retaking_abandoned).
    std::function<std::unique_ptr<RunLock>()> take_run_lock;
    // One try for the flush mutex, as rp::take_outbox_flush_lock takes it.
    std::function<std::unique_ptr<RunLock>()> take_flush_lock;
    // The outbox's file calls, each null = the real one.
    OutboxFiles outbox_files;
    // Every wait of the loop and of a run (the pipeline's one sleep): waits
    // up to the time, true when a stop was asked for. Null = the context's
    // StopSignal::wait_for. A test's costs no time.
    std::function<bool(std::chrono::milliseconds)> wait;
    // The wall clock of the loop's own times (a record's, a manifest's, a
    // heartbeat's); null = std::chrono::system_clock::now. A run's own are
    // its pipeline env's.
    std::function<std::chrono::system_clock::time_point()> wall_now;
};

// `take`, and once more when it answers rp::AbandonedRunLock (W4.8 point 5):
// the try that found the mutex abandoned released it, so the second has it.
// In the service the record and the hold carry what the commands' refusal
// was there for. Null when the mutex is held; what the second try throws
// goes on to the caller.
std::unique_ptr<RunLock>
retaking_abandoned(const std::function<std::unique_ptr<RunLock>()>& take);

// What the loop is told of a job's run: the pipeline's report and its exit
// code.
JobRun job_run_of(const PipelineReport& report, int exit_code);

// The same when something escaped run_pipeline: what the report had become
// by then, exit code 1, and, once the run line was out, a restore that may
// still be running (nothing says it isn't; the loop holds when the record
// says a request was sent). Before its run line it is a run that did nothing.
JobRun job_run_after_throw(const PipelineReport& report);

// The loop's env over the real calls. `context` is kept by the env's
// functions; none of them may be called from another thread than the one
// that runs the loop.
ServiceLoopEnv make_worker_loop_env(const std::shared_ptr<ServiceContext>& context,
                                    const WorkerBodyOptions& options);

// The service's body: rp::ServiceLoop over make_worker_loop_env, run until
// the stop.
ServiceBody make_worker_body(WorkerBodyOptions options = {});

} // namespace rp
