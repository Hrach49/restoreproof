#pragma once

// The service loop on fakes (W4.8, docs/decisions.md 2026-10-08 point 15):
// a ServiceLoopEnv whose clock only moves when the loop waits (or a fake
// says a run took so long), whose wait answers a stop at a scripted wait,
// and whose every call is written down. No test waits, starts a thread or
// touches a file.

#include <rp/service_loop.hpp>

#include <spdlog/details/null_mutex.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/base_sink.h>

#include <chrono>
#include <cstddef>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::test {

// Every log line as "<level> <message>".
class LoopLineSink final : public spdlog::sinks::base_sink<spdlog::details::null_mutex> {
public:
    explicit LoopLineSink(std::vector<std::string>& lines) : lines_(lines) {}

protected:
    void sink_it_(const spdlog::details::log_msg& message) override
    {
        const spdlog::string_view_t level = spdlog::level::to_string_view(message.level);
        lines_.push_back(std::string{level.data(), level.size()} + " " +
                         std::string{message.payload.data(), message.payload.size()});
    }
    void flush_() override {}

private:
    std::vector<std::string>& lines_;
};

// The client a job carries (W4.10): the shared vectors' profile, as text.
inline constexpr std::string_view kProfileText =
    R"({"format":"restoreproof.client-profile.v1","graph_client_id":"22222222-3333-4444-5555-666666666666",)"
    R"("graph_tenant_id":"11111111-2222-3333-4444-555555555555","test_library_id":"b!library",)"
    R"("test_mailbox":"restoretest@contoso.onmicrosoft.com","test_onedrive_drive_id":"b!onedrive",)"
    R"("test_onedrive_folder_id":"01FOLDER","test_site_id":"contoso.sharepoint.com,)"
    R"(aaaaaaaa-0000-0000-0000-000000000001,aaaaaaaa-0000-0000-0000-000000000002",)"
    R"("veeam_org_name":"contoso.onmicrosoft.com"})";

inline std::string job_text(std::string_view run_id, int mail = 5, int sp = 5, int od = 5)
{
    return R"({"run_id":")" + std::string{run_id} + R"(","client_id":"client-7","client":)" +
           std::string{kProfileText} + R"(,"sample_mail":)" + std::to_string(mail) +
           R"(,"sample_sp":)" + std::to_string(sp) + R"(,"sample_od":)" + std::to_string(od) +
           R"(,"restore_point":"latest","screenshots_enabled":false})";
}

inline std::string jobs_text(const std::vector<std::string>& jobs)
{
    std::string text = R"({"format":"restoreproof.jobs.v1","jobs":[)";
    for (std::size_t i = 0; i < jobs.size(); ++i) {
        text += (i == 0 ? "" : ",") + jobs[i];
    }
    return text + "]}";
}

struct LoopLab {
    using Steady = std::chrono::steady_clock::time_point;
    using Wall = std::chrono::system_clock::time_point;

    // The clock: steady time moves only in wait() and when a fake moves it;
    // the wall clock moves with it.
    Steady t0 = Steady{} + std::chrono::hours{5000};
    Steady t = t0;
    Wall wall0 = *rp::record_time("2026-10-08T10:00:00.000Z");
    bool stop = false;
    int waits = 0;
    int stop_at_wait = 1;
    std::vector<std::chrono::milliseconds> waited;
    // Called in each wait, after the clock moved, with the wait's number.
    std::function<void(int)> on_wait;

    std::vector<std::string> lines; // the log
    std::vector<std::string> calls; // what the loop asked of its env, in order

    Config config;

    // running.json
    TrustedFile record{TrustedRead::absent, {}};
    bool write_ok = true;
    bool remove_ok = true;
    bool move_ok = true;
    std::vector<std::string> writes;
    std::optional<std::string> unread; // what was moved aside

    // The jobs file: its text, or why it runs nothing; neither: no file.
    std::optional<std::string> jobs;
    std::optional<JobsFault> jobs_fault;
    bool has_jobs_file = true;

    std::set<std::string, std::less<>> queued;
    std::set<std::string, std::less<>> sent;
    std::set<std::string, std::less<>> folders; // under the runs root
    // The runs marked as run (under the state folder), and whether a mark
    // can be written.
    std::set<std::string, std::less<>> done;
    bool done_ok = true;

    std::vector<std::string> runs;
    std::function<JobRun(const Job&, const JobCallbacks&)> on_run;
    std::vector<RunningRecord> closed;
    std::function<CloseRunOutcome(const RunningRecord&)> on_close;

    bool lock_free = true;
    // One per look, in order; none left: nothing is running.
    std::deque<std::function<SessionsLook()>> looks;
    // When set, every look.
    std::function<SessionsLook()> every_look;
    std::vector<Wall> looked_since;
    std::vector<std::string> ended;
    std::set<std::string> end_fails;
    // Called after each end that didn't fail, with the session's ID.
    std::function<void(const std::string&)> on_end;
    int released = 0;
    std::string clean_word = "ok";
    int cleans = 0;

    std::function<std::optional<FlushReport>()> on_flush;
    int flushes = 0;
    // What the stop function a flush is handed answered: once before
    // `flush_sets_stop` was applied and once after it.
    bool flush_sets_stop = false;
    std::vector<bool> flush_stop_answers;
    std::string heartbeat_word;
    std::vector<LoopHeartbeat> heartbeats;
    std::vector<std::chrono::seconds> heartbeat_at;

    std::optional<std::string> last_error;
    std::optional<Wall> last_error_at;

    LoopLab()
    {
        config.graph_tenant_id = "T";
        config.veeam_org_name = "O";
        config.test_mailbox = "M";
        config.test_site_id = "S";
        config.test_library_id = "L";
        config.test_onedrive_drive_id = "D";
        config.test_onedrive_folder_id = "F";
        config.poll_interval_s = 60;
        config.heartbeat_interval_s = 600;
    }

    Wall wall() const
    {
        return wall0 + std::chrono::duration_cast<std::chrono::system_clock::duration>(t - t0);
    }

    std::chrono::seconds elapsed() const
    {
        return std::chrono::duration_cast<std::chrono::seconds>(t - t0);
    }

    static RunStarted run_started(std::string_view run_id)
    {
        RunStarted started;
        started.run_id = std::string{run_id};
        started.started_at = "2026-10-08T10:00:02.500Z";
        started.restore_point_id = "point-1";
        started.restore_point_time = "2026-10-03T16:16:54.0154727Z";
        started.connector_type = "veeam_m365";
        started.connector_api = "v8";
        return started;
    }

    static JobRun ended_run(JobFolder folder, std::string word = {},
                            verification::RunStatus status = verification::RunStatus::pass,
                            std::string code = {})
    {
        JobRun run;
        run.exit_code = status == verification::RunStatus::pass ? 0 : 1;
        run.run_line = true;
        run.status = status;
        run.error_code = std::move(code);
        run.folder = folder;
        run.folder_word = std::move(word);
        return run;
    }

    // A record of an earlier process: taken ten minutes before the clock's
    // start, its run line reached, these sessions opened, and, with
    // `requested`, a restore request sent five minutes before the start.
    RunningRecord found(std::vector<std::string> sessions = {}, bool requested = false) const
    {
        RunningRecord made = new_run_record("job-1", std::string{"client-7"}, config,
                                            wall0 - std::chrono::minutes{10});
        made = with_run_started(std::move(made), run_started("job-1"));
        for (const std::string& id : sessions) {
            made = with_session(std::move(made), id);
        }
        return requested ? with_restore_request(std::move(made), wall0 - std::chrono::minutes{5})
                         : made;
    }

    void put_record(const RunningRecord& made) { record = {TrustedRead::read, record_text(made)}; }

    bool has_record() const { return record.state != TrustedRead::absent; }

    // The record on disk, read as the loop would.
    RunningRecord on_disk() const { return parse_record(record.bytes).value(); }

    std::size_t count(std::string_view line) const
    {
        std::size_t found_lines = 0;
        for (const std::string& one : lines) {
            found_lines += one == line ? 1u : 0u;
        }
        return found_lines;
    }

    std::size_t count_call(std::string_view call) const
    {
        std::size_t found_calls = 0;
        for (const std::string& one : calls) {
            found_calls += one == call ? 1u : 0u;
        }
        return found_calls;
    }

    ServiceLoopEnv env()
    {
        ServiceLoopEnv env;
        env.config = config;
        if (has_jobs_file) {
            env.jobs_file = std::filesystem::path{"C:\\rp\\jobs.json"};
        }
        env.runs_root = "C:\\rp\\runs";
        env.outbox_root = "C:\\rp";
        env.record_file = "C:\\rp\\state\\running.json";
        env.record_files.read = [this](const std::filesystem::path&, std::uintmax_t) {
            calls.push_back("read record");
            return record;
        };
        env.record_files.write = [this](const std::filesystem::path&, std::string_view text) {
            calls.push_back("write record");
            if (write_ok) {
                writes.emplace_back(text);
                record = {TrustedRead::read, std::string{text}};
            }
            return write_ok;
        };
        env.record_files.erase = [this](const std::filesystem::path&) {
            calls.push_back("remove record");
            if (remove_ok) {
                record = {TrustedRead::absent, {}};
            }
            return remove_ok;
        };
        env.record_files.move_aside = [this](const std::filesystem::path&,
                                             const std::filesystem::path& to) {
            calls.push_back("move record to " + to.filename().string());
            if (move_ok) {
                unread = record.bytes;
                record = {TrustedRead::absent, {}};
            }
            return move_ok;
        };
        auto logger = std::make_shared<spdlog::logger>(
            "loop", std::make_shared<LoopLineSink>(lines));
        logger->set_level(spdlog::level::trace);
        env.logger = std::move(logger);

        env.wait = [this](std::chrono::milliseconds time) {
            waited.push_back(time);
            t += time;
            ++waits;
            if (on_wait) {
                on_wait(waits);
            }
            stop = stop || waits >= stop_at_wait;
            return stop;
        };
        env.stop_requested = [this] { return stop; };
        env.now = [this] { return t; };
        env.wall_now = [this] { return wall(); };

        env.read_jobs = [this](const std::filesystem::path&) {
            calls.push_back("read jobs");
            if (jobs_fault) {
                JobsDocument document;
                document.state = JobsState::error;
                document.fault = jobs_fault;
                return document;
            }
            return jobs ? parse_jobs(*jobs) : JobsDocument{};
        };
        env.outbox_holds = [this](std::string_view run_id) {
            return queued.contains(run_id) ? OutboxHolds::queued
                   : sent.contains(run_id) ? OutboxHolds::sent
                                           : OutboxHolds::none;
        };
        env.run_folder_exists = [this](std::string_view run_id) {
            return folders.contains(run_id);
        };
        env.run_done = [this](std::string_view run_id) { return done.contains(run_id); };
        env.mark_run_done = [this](std::string_view run_id) {
            calls.push_back("mark " + std::string{run_id});
            if (done_ok) {
                done.emplace(run_id);
            }
            return done_ok;
        };
        env.outbox_depth = [this] { return static_cast<std::uint64_t>(queued.size()); };

        env.run_job = [this](const Job& job, const JobCallbacks& callbacks) {
            calls.push_back("run " + job.run_id);
            runs.push_back(job.run_id);
            if (on_run) {
                return on_run(job, callbacks);
            }
            callbacks.on_run_started(run_started(job.run_id));
            queued.insert(job.run_id);
            return ended_run(JobFolder::queued);
        };
        env.close_run = [this](const RunningRecord& closing) {
            calls.push_back("close " + closing.run_id);
            closed.push_back(closing);
            if (on_close) {
                return on_close(closing);
            }
            queued.insert(closing.run_id);
            return CloseRunOutcome{CloseRunState::queued, {}};
        };

        env.take_run_lock = [this]() -> std::unique_ptr<RunLock> {
            calls.push_back(lock_free ? "lock" : "lock held");
            return lock_free ? std::make_unique<RunLock>() : nullptr;
        };
        env.own_sessions = [this](Wall since) {
            calls.push_back("look");
            looked_since.push_back(since);
            if (every_look) {
                return every_look();
            }
            if (looks.empty()) {
                return SessionsLook{"rp-veeam", {}};
            }
            const std::function<SessionsLook()> look = std::move(looks.front());
            looks.pop_front();
            return look();
        };
        env.end_session = [this](const std::string& id) {
            calls.push_back("end " + id);
            if (end_fails.contains(id)) {
                throw connector::Error("veeam_m365: Stop refused for " + id);
            }
            ended.push_back(id);
            if (on_end) {
                on_end(id);
            }
        };
        env.release_hold = [this] {
            calls.push_back("release");
            ++released;
        };
        env.clean_targets = [this](const RunningRecord& cleaning) {
            calls.push_back("clean " + cleaning.run_id);
            ++cleans;
            return clean_word;
        };

        env.flush = [this](const std::function<bool()>& asked) -> std::optional<FlushReport> {
            calls.push_back("flush");
            ++flushes;
            flush_stop_answers.push_back(asked());
            stop = stop || flush_sets_stop;
            flush_stop_answers.push_back(asked());
            if (on_flush) {
                return on_flush();
            }
            FlushReport report;
            for (const std::string& run_id : queued) {
                report.out.push_back("sent " + run_id);
                sent.insert(run_id);
            }
            queued.clear();
            report.sent = sent.size();
            return report;
        };
        env.heartbeat = [this](const LoopHeartbeat& beat) {
            calls.push_back("heartbeat");
            heartbeats.push_back(beat);
            heartbeat_at.push_back(elapsed());
            return heartbeat_word;
        };
        return env;
    }

    // One service life: a new loop, run until its `waits`-th wait, which
    // answers the stop (or until something else sets `stop`).
    void run(int until_wait = 1)
    {
        stop_at_wait = waits + until_wait;
        ServiceLoop loop{env()};
        loop.run();
        last_error = loop.last_error();
        last_error_at = loop.last_error_at();
        stop = false;
    }
};

inline connector::OwnSession session(std::string id, LoopLab::Wall created_at)
{
    return {std::move(id), created_at};
}

} // namespace rp::test
