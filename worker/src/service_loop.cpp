#include <rp/service_loop.hpp>

#include "path_utf8.hpp"
#include "run_pipeline.hpp"
#include "target_guard_refuse.hpp"

#include <rp/service_errors.hpp>

#include <algorithm>
#include <array>
#include <exception>
#include <format>

namespace rp {

namespace {

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::seconds;
using verification::RunStatus;

// What the shared tail says of a folder it left without a result
// (RunFolderOutcome::word), the words a record's close_detail takes for
// `internal`; the first stands for any other.
constexpr std::array<std::string_view, 5> kFolderWords{"not_written", "changed", "holds_secret",
                                                       "not_signed", "invalid"};

constexpr std::string_view kResultInvalid = "result_invalid";
constexpr std::string_view kCleanOk = "ok";
constexpr std::string_view kKept = "kept ";
constexpr std::string_view kWaiting = "waiting ";
// How the outbox's own lines for a run that is never sent, and for one it
// couldn't read at this pass, end.
constexpr std::string_view kChangedLine = " changed since it was signed";
constexpr std::string_view kNotReadLine = " couldn't be read";

std::string internal_detail(std::string_view word)
{
    return std::string{std::ranges::find(kFolderWords, word) != kFolderWords.end()
                           ? word
                           : kFolderWords.front()};
}

// "pass", "fail", "error <code>" or "error".
std::string ended(const JobRun& run)
{
    return ended_detail(run.status.value_or(RunStatus::error), run.error_code);
}

// The pipeline's report as record_may_go reads it: whether the run line was
// written, whether there is a folder at all, and the restore.
PipelineReport report_of(const JobRun& run)
{
    PipelineReport report;
    report.run_line = run.run_line;
    report.folder =
        run.folder == JobFolder::none ? RunFolderState::none : RunFolderState::incomplete;
    report.restore_may_still_run = run.restore_may_still_run;
    return report;
}

// A flush's "kept <run>: <word>[; attempt ...]" line's word; empty for any
// other line.
std::string kept_word(std::string_view line)
{
    const std::size_t colon = line.find(": ");
    if (!line.starts_with(kKept) || colon == std::string_view::npos) {
        return {};
    }
    const std::string_view rest = line.substr(colon + 2);
    return std::string{rest.substr(0, rest.find(';'))};
}

} // namespace

ServiceLoop::ServiceLoop(ServiceLoopEnv env)
    : env_(std::move(env)), store_(env_.record_file, env_.record_files)
{
}

template <typename Step> void ServiceLoop::step(Step&& body)
{
    try {
        body();
    } catch (...) {
        // Never what(): it may hold a path, a name or a product's text.
        env_.logger->error("scheduler: a step failed unexpectedly; the loop goes on");
    }
}

bool ServiceLoop::stopped() const
{
    return env_.stop_requested();
}

void ServiceLoop::trouble(std::string_view word)
{
    last_error_ = std::string{word};
    last_error_at_ = env_.wall_now();
}

// Whether this is said for the first time in the service's life.
bool ServiceLoop::once(const std::string& key)
{
    return said_.insert(key).second;
}

// Whether this is said for the first time, or was last said an hour ago.
bool ServiceLoop::again(const std::string& key)
{
    const Steady now = env_.now();
    const auto [said, first] = said_at_.try_emplace(key, now);
    if (!first && now - said->second < kServiceLineAgain) {
        return false;
    }
    said->second = now;
    return true;
}

void ServiceLoop::run()
{
    started_ = env_.now();
    next_poll_ = started_;
    next_heartbeat_ = started_;
    env_.logger->info("scheduler started: poll {} s, heartbeat {} s, jobs {}, runs {}, outbox {}",
                      env_.config.poll_interval_s, env_.config.heartbeat_interval_s,
                      env_.jobs_file ? path_to_utf8(*env_.jobs_file) : std::string{"none"},
                      path_to_utf8(env_.runs_root), path_to_utf8(env_.outbox_root));
    step([this] { record_business(); });
    for (;;) {
        if (stopped()) {
            return;
        }
        step([this] { send_heartbeat(); });
        const Steady now = env_.now();
        if (now >= next_poll_) {
            // Counted from the start of this one: a job that takes longer
            // makes the next poll late, never a second run.
            next_poll_ = now + seconds{env_.config.poll_interval_s};
            poll();
        } else if (next_look_ && now >= *next_look_) {
            step([this] { settle_record(false); });
        }
        Steady due = std::min(next_poll_, next_heartbeat_);
        if (next_look_) {
            due = std::min(due, *next_look_);
        }
        const Steady after = env_.now();
        if (due > after && env_.wait(duration_cast<milliseconds>(due - after))) {
            return;
        }
    }
}

// Sent when one is due; one that fell due during a run is sent once.
void ServiceLoop::send_heartbeat()
{
    const Steady now = env_.now();
    if (stopped() || now < next_heartbeat_) {
        return;
    }
    next_heartbeat_ = now + seconds{env_.config.heartbeat_interval_s};
    LoopHeartbeat beat;
    beat.last_error = last_error_;
    beat.last_error_at = last_error_at_;
    beat.outbox_depth = env_.outbox_depth();
    beat.uptime_s = static_cast<std::uint64_t>(duration_cast<seconds>(now - started_).count());
    const std::string word = env_.heartbeat(beat);
    // Never the last error it reports, and nothing is retried before the
    // next interval.
    if (!word.empty() && word != heartbeat_word_) {
        env_.logger->warn("heartbeat failed: {}", word);
    }
    heartbeat_word_ = word;
}

void ServiceLoop::poll()
{
    bool free = false;
    step([this, &free] { free = record_business(); });
    if (free) {
        run_jobs();
    }
    step([this] { flush(); });
}

// The record's business (point 8). True when no run is taken and nothing
// stands in a job's way.
bool ServiceLoop::record_business()
{
    if (stopped() || (!record_ && !find_record())) {
        return false;
    }
    if (record_) {
        settle_record(true);
    }
    return !record_;
}

// Reads running.json when the loop holds no record. False when a file is
// there that can be neither believed nor moved aside: no job runs.
bool ServiceLoop::find_record()
{
    RecordRead read = store_.read();
    if (read.state == RecordState::none) {
        return true;
    }
    if (read.state == RecordState::record) {
        record_ = std::move(read.record);
        if (record_->close_as) {
            env_.logger->info("unfinished run {} found: to be closed as {}", record_->run_id,
                              to_string(*record_->close_as));
        } else {
            env_.logger->warn("interrupted run {} found: taken {}, restore requested {}",
                              record_->run_id, record_->taken_at,
                              record_->restore_requested ? "yes" : "no");
        }
        return true;
    }
    // Nothing is known: nothing is closed, signed, ended or cleaned on its
    // word.
    trouble(service_error::kRecordUnreadable);
    if (read.state == RecordState::unreadable) {
        if (again("record:unreadable")) {
            env_.logger->error("running.json can't be read; no job runs");
        }
        return false;
    }
    const bool foreign = read.state == RecordState::not_trusted;
    const bool moved = store_.move_aside();
    if (!moved && !again(foreign ? "record:not_trusted" : "record:not_record")) {
        return false;
    }
    if (foreign) {
        log_security(env_.logger,
                     std::string{"service: running.json is owned by neither SYSTEM, "
                                 "Administrators nor this account; "} +
                         (moved ? "moved aside" : "it couldn't be moved aside; no job runs"));
    } else if (moved) {
        env_.logger->error("running.json isn't a restoreproof.running.v1 record; moved aside as "
                           "running.json.unread");
    } else {
        env_.logger->error("running.json isn't a restoreproof.running.v1 record and couldn't be "
                           "moved aside; no job runs");
    }
    return moved;
}

// Whether the run of this process ended before its run line: it has no
// folder, and nothing to close.
bool ServiceLoop::never_started() const
{
    return run_ && !run_->run_line && run_->folder == JobFolder::none;
}

// Point 8's sequence, each step only if still needed: (a) the run's folder
// closed and queued, (b) the hold, (c) the record deleted. `close` is false
// where (a) isn't due: between two polls, and right after a run whose folder
// the pipeline itself has just failed to queue.
void ServiceLoop::settle_record(bool close)
{
    next_look_.reset();
    if (close && !never_started() && !stopped() &&
        env_.outbox_holds(record_->run_id) == OutboxHolds::none) {
        close_record_run();
    }
    if (hold_needed() && !stopped()) {
        hold();
    }
    // After a stop no step is started for a record, its erase included; but
    // a run that ended before its run line did nothing, and its record goes
    // (point 13), or the next start would close it as an interrupted run.
    if (stopped() && !never_started()) {
        return;
    }
    drop_record();
}

void ServiceLoop::close_record_run()
{
    const std::string id = record_->run_id;
    if (run_ && run_->folder != JobFolder::complete && !record_->close_as) {
        // Write (e): the pipeline returned and left the folder without a
        // result, so the close keeps its word even when it is cut short.
        const bool invalid =
            run_->status == RunStatus::error && run_->error_code == kResultInvalid;
        RunningRecord next =
            invalid ? with_close(*record_, CloseAs::result_invalid,
                                 ended_detail(run_->replaced_status.value_or(RunStatus::error),
                                              run_->replaced_code))
                    : with_close(*record_, CloseAs::internal, internal_detail(run_->folder_word));
        if (!write_record(std::move(next))) {
            env_.logger->error("run {}: running.json couldn't be written; not closed", id);
            return;
        }
    }
    const Steady now = env_.now();
    if (close_not_before_ && now < *close_not_before_) {
        return;
    }
    close_not_before_.reset();
    const CloseRunOutcome outcome = env_.close_run(*record_);
    if (outcome.state == CloseRunState::queued) {
        env_.logger->info("run {}: queued", id);
        flush();
        return;
    }
    const bool closed = outcome.state == CloseRunState::not_queued;
    if (!closed) {
        close_not_before_ = now + kCloseAgain;
    }
    trouble(closed ? service_error::kRunNotQueued : service_error::kRunNotClosed);
    const std::string_view what = closed ? "queued" : "closed";
    if (again(std::format("close:{}:{}:{}", id, what, outcome.word))) {
        env_.logger->error("run {}: couldn't be {} ({})", id, what, outcome.word);
    }
}

// Whether a restore of the record's run may still be running, as far as is
// known before the hold: the run of this process says so itself; of a record
// found, whatever the record allows.
bool ServiceLoop::hold_needed() const
{
    if (hold_done_) {
        return false;
    }
    return run_ ? run_->restore_may_still_run && record_->restore_requested : needs_hold(*record_);
}

// Point 9: one look-and-end under the run mutex, then, when nothing of the
// run is running any more, the clean the run never made.
void ServiceLoop::hold()
{
    next_look_ = env_.now() + kHoldLook;
    if (!hold_began_) {
        hold_began_ = env_.wall_now();
    }
    bool clean = false;
    {
        // No command has a session open while the service ends any.
        const std::unique_ptr<RunLock> lock = env_.take_run_lock();
        if (!lock) {
            env_.logger->debug("the run mutex is held; the look at Veeam's sessions waits");
            return;
        }
        if (!look_and_end(clean)) {
            return;
        }
    }
    if (stopped()) {
        // The look ended in a stop: the clean isn't started, and the next
        // start looks again.
        return;
    }
    next_look_.reset();
    if (clean) {
        clean_after_hold();
    }
    hold_done_ = true;
}

bool ServiceLoop::look_failed(std::string_view reason)
{
    trouble(service_error::kVeeamLookFailed);
    if (again(std::format("hold:look:{}", reason))) {
        env_.logger->warn("the look at Veeam's sessions failed: {}", reason);
    }
    return false;
}

// True when the hold is over, with `clean` whether the restore targets are
// to be cleaned. Ends only sessions the record lists, and after ending them
// looks once more. A stop is asked for before each end and before the second
// look: after one nothing more is asked of the backup product.
bool ServiceLoop::look_and_end(bool& clean)
{
    const std::chrono::system_clock::time_point since =
        record_time(record_->taken_at).value_or(std::chrono::system_clock::time_point{});
    for (int look = 0; look < 2; ++look) {
        if (stopped()) {
            return false;
        }
        SessionsLook sessions;
        try {
            sessions = env_.own_sessions(since);
        } catch (const connector::AuthError&) {
            return look_failed("auth");
        } catch (const connector::TransientError&) {
            return look_failed("transient");
        } catch (const std::exception&) {
            return look_failed("other");
        }
        const HoldDecision decision =
            decide_hold(*record_, sessions.running, env_.wall_now(), *hold_began_);
        if (decision.step == HoldStep::over) {
            clean = decision.clean_due;
            return true;
        }
        if (decision.step == HoldStep::wait) {
            if (decision.others != 0) {
                // One of them may be the restore: there is no deadline after
                // which it is ended anyway.
                trouble(service_error::kVeeamSessionsWorking);
                if (again("hold:working")) {
                    env_.logger->warn(
                        "waiting for Veeam: {} session(s) of {} still Working since {}",
                        decision.others, sessions.account,
                        record_time_text(*decision.others_since));
                }
            }
            return false;
        }
        for (const std::string& id : decision.end) {
            if (stopped()) {
                return false;
            }
            try {
                env_.end_session(id);
            } catch (const std::exception&) {
                trouble(service_error::kVeeamLookFailed);
                if (again("hold:end:" + id)) {
                    env_.logger->warn("ending session {} failed", id);
                }
                return false;
            }
        }
    }
    return false;
}

void ServiceLoop::clean_after_hold()
{
    if (!is_records_client(env_.config, *record_)) {
        env_.logger->warn(
            "the config's client is not the run's; the restore targets were not cleaned");
        return;
    }
    env_.logger->info("recovery clean for {}:", record_->run_id);
    const std::string word = env_.clean_targets(*record_);
    if (word != kCleanOk) {
        // Whatever it answers, the record goes: every run cleans before.
        trouble(service_error::kRecoveryCleanIncomplete);
        env_.logger->warn("recovery clean for {}: not completed ({})", record_->run_id, word);
    }
}

// Step (c): the record goes when its run is in the outbox, or never had a
// folder, and no restore of it may still be running.
void ServiceLoop::drop_record()
{
    const std::optional<PipelineReport> report =
        run_ ? std::optional{report_of(*run_)} : std::nullopt;
    if (!record_may_go(*record_, env_.outbox_holds(record_->run_id),
                       report ? &*report : nullptr, hold_done_)) {
        return;
    }
    if (!store_.erase()) {
        trouble(service_error::kRecordNotRemoved);
        if (again("record:not_removed")) {
            env_.logger->error("running.json couldn't be removed");
        }
        return;
    }
    if (hold_began_ && env_.release_hold) {
        env_.release_hold();
    }
    record_.reset();
    run_.reset();
    close_not_before_.reset();
    hold_done_ = false;
    hold_began_.reset();
}

// The record on disk and in memory are one: what couldn't be written isn't
// believed.
bool ServiceLoop::write_record(RunningRecord next)
{
    if (!store_.write(next)) {
        trouble(service_error::kRecordNotWritten);
        return false;
    }
    record_ = std::move(next);
    return true;
}

// Write (a), before anything is done for the job.
bool ServiceLoop::take_record(RunningRecord record)
{
    const std::string id = record.run_id;
    if (write_record(std::move(record))) {
        return true;
    }
    env_.logger->error("run {}: running.json couldn't be written; not run", id);
    return false;
}

JobsDocument ServiceLoop::read_jobs()
{
    if (!env_.jobs_file) {
        return {};
    }
    JobsDocument document = env_.read_jobs(*env_.jobs_file);
    if (document.state == JobsState::error) {
        const JobsFault fault = document.fault.value_or(JobsFault::unreadable);
        trouble(service_error::kJobsUnreadable);
        if (jobs_fault_ != fault) {
            env_.logger->warn("{}", jobs_error_line(*env_.jobs_file, fault));
        }
        jobs_fault_ = fault;
    } else {
        jobs_fault_.reset();
    }
    return document;
}

// The jobs of this poll, in the document's order, one at a time, and only
// while no run is taken.
void ServiceLoop::run_jobs()
{
    JobsDocument document;
    step([this, &document] { document = read_jobs(); });
    for (const JobEntry& entry : document.jobs) {
        if (stopped() || record_) {
            return;
        }
        step([this, &entry, &document] { take_job(entry, document); });
        step([this] { send_heartbeat(); });
    }
}

// Point 4, first fit.
void ServiceLoop::take_job(const JobEntry& entry, const JobsDocument& document)
{
    if (entry.state == JobState::no_run_id) {
        // J1: nothing can be signed under a name the Cloud knows.
        trouble(service_error::kJobInvalid);
        if (once(std::format("job:{}:{}", document.sha256, entry.position))) {
            env_.logger->warn("job {} of {}: no usable run_id; not run", entry.position,
                              path_to_utf8(*env_.jobs_file));
        }
        return;
    }
    const Job& job = entry.job;
    if (skip_job(job.run_id)) {
        return;
    }
    if (entry.state == JobState::invalid) {
        // J3: reported under the job's own ID; nothing is asked of Veeam or
        // Graph.
        trouble(service_error::kJobInvalid);
        env_.logger->warn("job {}: not a valid job ({})", job.run_id, entry.fault);
        if (take_record(new_job_invalid_record(job.run_id, job.client_id, env_.config,
                                               env_.wall_now(), entry.fault))) {
            settle_record(true);
        }
        return;
    }
    run_job(job);
}

// J2: the run is already there.
bool ServiceLoop::skip_job(const std::string& run_id)
{
    const OutboxHolds holds = env_.outbox_holds(run_id);
    std::string_view why = "a run folder is already there";
    if (holds == OutboxHolds::queued) {
        why = "already queued";
    } else if (holds == OutboxHolds::sent) {
        why = "already sent";
    } else if (!env_.run_folder_exists(run_id)) {
        return false;
    }
    if (once("skipped:" + run_id)) {
        env_.logger->info("skipped {}: {}", run_id, why);
    }
    return true;
}

// J4 (point 5).
void ServiceLoop::run_job(const Job& job)
{
    const std::string& id = job.run_id;
    if (!take_record(new_run_record(id, job.client_id, env_.config, env_.wall_now()))) {
        return;
    }
    env_.logger->info("run {}: starting (mail {}, sharepoint {}, onedrive {}, point {})", id,
                      job.sample_mail, job.sample_sp, job.sample_od, job.restore_point);
    run_ = env_.run_job(job, callbacks());
    const JobRun& run = *run_;
    if (never_started()) {
        // No folder and no result, as for the command; the stub offers the
        // job again at the next poll.
        trouble(service_error::kJobNotStarted);
        if (once(std::format("not_started:{}:{}", id, run.exit_code))) {
            env_.logger->warn("run {}: ended before its run line; nothing was done", id);
        }
        settle_record(false);
        return;
    }
    if (run.folder == JobFolder::queued) {
        env_.logger->info("run {}: ended {}; queued", id, ended(run));
        flush();
        settle_record(false);
        return;
    }
    if (run.folder == JobFolder::complete) {
        // The pipeline's "outbox error" line is above this one; the next
        // poll queues the folder.
        trouble(service_error::kRunNotQueued);
        env_.logger->warn("run {}: ended {}; not queued", id, ended(run));
        settle_record(false);
        return;
    }
    env_.logger->warn("run {}: ended without a result", id);
    settle_record(true);
}

// Writes (b), (c) and (d) of the record.
JobCallbacks ServiceLoop::callbacks()
{
    JobCallbacks calls;
    calls.on_run_started = [this](const RunStarted& started) {
        if (write_record(with_run_started(*record_, started))) {
            return true;
        }
        env_.logger->error("run {}: running.json couldn't be written; the run ends",
                           record_->run_id);
        return false;
    };
    calls.on_session_opened = [this](std::string_view session) {
        // The price is one session nobody ends, never a safety rule.
        if (!write_record(with_session(*record_, session))) {
            env_.logger->warn(
                "run {}: running.json couldn't be written; a session the run opened is not on "
                "record",
                record_->run_id);
        }
    };
    calls.before_restore_request = [this] {
        if (write_record(with_restore_request(*record_, env_.wall_now()))) {
            return true;
        }
        env_.logger->error(
            "run {}: running.json couldn't be written; the restore request is not sent",
            record_->run_id);
        return false;
    };
    return calls;
}

// Point 10: one pass under the flush mutex, its lines the log's.
void ServiceLoop::flush()
{
    if (stopped()) {
        return;
    }
    const std::optional<FlushReport> report = env_.flush(env_.stop_requested);
    if (!report) {
        env_.logger->debug("flush skipped: another flush is running");
        return;
    }
    for (const std::string& line : report->out) {
        const std::string word = kept_word(line);
        // A run that is never sent, and one that couldn't be read: once per
        // run and reason, not at every pass.
        const bool lasting =
            word == service_error::kFolderChanged || word == service_error::kNotRead;
        if (lasting && !once("flush:" + line)) {
            continue;
        }
        if (is_service_error(word)) {
            trouble(word);
        }
        env_.logger->log(line.starts_with(kWaiting) ? spdlog::level::debug : spdlog::level::info,
                         "{}", line);
    }
    for (const std::string& line : report->err) {
        const bool lasting = line.ends_with(kChangedLine) || line.ends_with(kNotReadLine);
        if (!lasting || once("flush:" + line)) {
            env_.logger->warn("{}", line);
        }
    }
}

} // namespace rp
