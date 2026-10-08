#pragma once

// The scheduler loop, the body of the Worker's service (W4.8,
// docs/decisions.md 2026-10-08 points 2, 4, 5, 8, 9, 10 and 11): one
// timeline, one thread, three things due: a poll every poll_interval_s
// (the record's business first, then the jobs, one at a time, then a flush),
// a heartbeat every heartbeat_interval_s, and, while a run's restore may
// still be running, a look at the backup product's sessions at least every
// 30 s. The loop decides what is due, which job runs, what is skipped or put
// off, what becomes of a run's record afterwards and every log line of its
// own; everything else it reaches through ServiceLoopEnv, a struct of
// functions, so each branch is a row a fake drives.
//
// What it rests on: the jobs document's reader (rp/service_jobs.hpp), the
// record and what follows from it (rp/service_recovery.hpp) and the words of
// a heartbeat's last_error (rp/service_errors.hpp).
//
// Strict (100% line), by its name.

#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/outbox.hpp>
#include <rp/restore_command.hpp>
#include <rp/run_lock.hpp>
#include <rp/run_status.hpp>
#include <rp/service_jobs.hpp>
#include <rp/service_recovery.hpp>

#include <spdlog/logger.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp {

// How often a line that says "still so" is written again (points 6, 7, 9).
inline constexpr std::chrono::hours kServiceLineAgain{1};
// A close that failed is tried again at a poll, but not sooner than this:
// each try asks the TSA (point 7).
inline constexpr std::chrono::minutes kCloseAgain{15};
// While the hold lasts, the backup product's sessions are looked at at every
// poll and at least this often (point 9).
inline constexpr std::chrono::seconds kHoldLook{30};

// What became of a job's run folder (the pipeline's RunFolderState).
enum class JobFolder {
    none,       // no folder: the run ended before its run line
    incomplete, // no result.json; JobRun::folder_word why
    complete,   // result.json written, not in the outbox
    queued      // under <outbox root>\outbox
};

// What became of one job's run: the pipeline's PipelineReport
// (src/run_pipeline.hpp) and its exit code. The loop decides from the report
// and names the exit code in one line only.
struct JobRun {
    int exit_code = 0;
    bool run_line = false;
    std::optional<verification::RunStatus> status;
    std::string error_code;
    std::optional<verification::RunStatus> replaced_status;
    std::string replaced_code;
    JobFolder folder = JobFolder::none;
    std::string folder_word;
    bool restore_may_still_run = false;
};

// What a run tells the loop while it runs: writes (b), (c) and (d) of the
// record (point 6). The env hands them to the pipeline
// (RestoreCommandEnv::on_run_started) and the connector
// (ConnectorOptions::on_session_opened, before_restore_request).
struct JobCallbacks {
    // Right after the run line. False: the record couldn't be written, and
    // the run ends before any clean and any session.
    std::function<bool(const RunStarted&)> on_run_started;
    // At every session the run opens and is to close itself. A write that
    // fails is a warning and the run goes on.
    std::function<void(std::string_view id)> on_session_opened;
    // Before every restore request. False: the record couldn't be written,
    // and the request is not sent.
    std::function<bool()> before_restore_request;
};

// One look at the backup product's sessions (IConnector::own_sessions).
struct SessionsLook {
    // The account the connector signs in with, for the "waiting" line.
    std::string account;
    std::vector<connector::OwnSession> running;
};

// What a heartbeat carries beside the Worker's version (src/heartbeat.hpp).
struct LoopHeartbeat {
    std::optional<std::string> last_error;
    std::optional<std::chrono::system_clock::time_point> last_error_at;
    std::uint64_t outbox_depth = 0;
    std::uint64_t uptime_s = 0;
};

// Everything the loop reaches outside itself; every function must be set
// (release_hold alone may be null). None of them may be called from another
// thread: the loop has one.
struct ServiceLoopEnv {
    // The config the service loaded at its start: the intervals, and the
    // client a record's is compared with.
    Config config;
    // For the "scheduler started" line and the jobs' lines; no jobs_file: no
    // job source.
    std::optional<std::filesystem::path> jobs_file;
    std::filesystem::path runs_root;
    std::filesystem::path outbox_root;
    // <state folder>\running.json and its file calls.
    std::filesystem::path record_file;
    RecordFiles record_files;
    std::shared_ptr<spdlog::logger> logger;

    // Waits; true when a stop was asked for (StopSignal::wait_for).
    std::function<bool(std::chrono::milliseconds)> wait;
    std::function<bool()> stop_requested;
    std::function<std::chrono::steady_clock::time_point()> now;
    std::function<std::chrono::system_clock::time_point()> wall_now;

    // rp::read_jobs.
    std::function<JobsDocument(const std::filesystem::path&)> read_jobs;
    // rp::Outbox::holds.
    std::function<OutboxHolds(std::string_view run_id)> outbox_holds;
    // Whether anything is at <runs root>\<run_id>.
    std::function<bool(std::string_view run_id)> run_folder_exists;
    // The runs under outbox\, the ones that can't be sent included.
    std::function<std::uint64_t()> outbox_depth;

    // rp::run_pipeline with `test`'s presentation, --evidence <runs root> and
    // --outbox <outbox root>, its two streams the log's. Never throws.
    std::function<JobRun(const Job&, const JobCallbacks&)> run_job;
    // rp::close_run on <runs root>\<record.run_id>: closes the folder when it
    // has no result.json, then queues it; a folder that has one is only
    // queued.
    std::function<CloseRunOutcome(const RunningRecord&)> close_run;

    // The run mutex, without waiting, an abandoned one taken again at once
    // (point 5); null when a command holds it.
    std::function<std::unique_ptr<RunLock>()> take_run_lock;
    // IConnector::own_sessions and end_session on the hold's one connector;
    // what the connector throws goes on to the loop, which then counts the
    // look or the end as failed.
    std::function<SessionsLook(std::chrono::system_clock::time_point since)> own_sessions;
    std::function<void(const std::string& id)> end_session;
    // The hold is over: its connector may go. Null: nothing.
    std::function<void()> release_hold;
    // rp::clean_restore_targets, its lines the log's; answers its word (ok,
    // incomplete, lock_held, not_started).
    std::function<std::string(const RunningRecord&)> clean_targets;

    // rp::Outbox::flush under the flush mutex; nullopt when another flush
    // holds it. `stop` is asked before each queued run.
    std::function<std::optional<FlushReport>(const std::function<bool()>& stop)> flush;
    // rp::send_heartbeat; empty when taken, else the failure's word
    // (http_<status>, unreachable, timeout, internal).
    std::function<std::string(const LoopHeartbeat&)> heartbeat;
};

class ServiceLoop {
public:
    explicit ServiceLoop(ServiceLoopEnv env);

    // Runs until a stop is asked for: the "scheduler started" line, a record
    // found, the first heartbeat, the first poll, then whatever is due. What
    // a step throws is logged as one fixed error line and the loop goes on.
    void run();

    // The latest of the loop's own troubles since run() began (a word of
    // rp::service_error_codes(), or upload_http_<status>), and when.
    const std::optional<std::string>& last_error() const noexcept { return last_error_; }
    const std::optional<std::chrono::system_clock::time_point>& last_error_at() const noexcept
    {
        return last_error_at_;
    }

private:
    using Steady = std::chrono::steady_clock::time_point;

    template <typename Step> void step(Step&& body);
    bool stopped() const;
    void trouble(std::string_view word);
    bool once(const std::string& key);
    bool again(const std::string& key);

    void send_heartbeat();
    void poll();
    void flush();

    bool record_business();
    bool find_record();
    bool never_started() const;
    void settle_record(bool close);
    void close_record_run();
    bool hold_needed() const;
    void hold();
    bool look_failed(std::string_view reason);
    bool look_and_end(bool& clean);
    void clean_after_hold();
    void drop_record();
    bool write_record(RunningRecord next);
    bool take_record(RunningRecord record);

    JobsDocument read_jobs();
    void run_jobs();
    void take_job(const JobEntry& entry, const JobsDocument& document);
    bool skip_job(const std::string& run_id);
    void run_job(const Job& job);
    JobCallbacks callbacks();

    ServiceLoopEnv env_;
    RecordStore store_;

    Steady started_{};
    Steady next_poll_{};
    Steady next_heartbeat_{};

    std::optional<std::string> last_error_;
    std::optional<std::chrono::system_clock::time_point> last_error_at_;
    std::string heartbeat_word_;

    // The run the service has taken, as running.json has it; the outcome of
    // its run when that ended in this process.
    std::optional<RunningRecord> record_;
    std::optional<JobRun> run_;
    std::optional<Steady> close_not_before_;
    bool hold_done_ = false;
    std::optional<std::chrono::system_clock::time_point> hold_began_;
    std::optional<Steady> next_look_;

    std::optional<JobsFault> jobs_fault_;
    std::set<std::string> said_;
    std::map<std::string, Steady> said_at_;
};

} // namespace rp
