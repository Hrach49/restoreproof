// The scheduler loop (rp/service_loop.hpp; W4.8, docs/decisions.md 2026-10-08
// points 2, 4, 5, 8, 9, 10 and 11) on the fakes of service_loop_lab.hpp: what
// is due, which job runs, what becomes of the record, the hold, the flush's
// lines and the heartbeat, each against the exact log lines. Failure paths
// first; the last test is one job from poll to queued and sent.

#include "service_loop_lab.hpp"

#include <rp/service_errors.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using rp::CloseAs;
using rp::CloseRunOutcome;
using rp::CloseRunState;
using rp::JobFolder;
using rp::JobRun;
using rp::SessionsLook;
using rp::test::job_text;
using rp::test::jobs_text;
using rp::test::LoopLab;
using rp::test::session;
using rp::verification::RunStatus;
using Lines = std::vector<std::string>;

namespace {

const std::string kStarted = "info scheduler started: poll 60 s, heartbeat 600 s, jobs "
                             "C:\\rp\\jobs.json, runs C:\\rp\\runs, outbox C:\\rp";
const std::string kStepFailed = "error scheduler: a step failed unexpectedly; the loop goes on";
const std::string kFound =
    "warning interrupted run job-1 found: taken 2026-10-08T09:50:00.000Z, restore requested ";

// What the fake run does when a test doesn't say: its run line, then queued.
JobRun queued_run(LoopLab& lab, const rp::Job& job, const rp::JobCallbacks& callbacks,
                  RunStatus status = RunStatus::pass, std::string code = {})
{
    callbacks.on_run_started(LoopLab::run_started(job.run_id));
    lab.queued.insert(job.run_id);
    return LoopLab::ended_run(JobFolder::queued, {}, status, std::move(code));
}

std::ptrdiff_t index_of(const Lines& all, std::string_view one)
{
    return std::ranges::find(all, one) - all.begin();
}

} // namespace

TEST_CASE("the loop does nothing but say it started when a stop was asked for before its first "
          "poll",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a"}, true));
    lab.jobs = jobs_text({job_text("job-2")});
    lab.stop = true;

    lab.run();

    CHECK(lab.lines == Lines{kStarted});
    CHECK(lab.calls.empty());
    CHECK(lab.has_record());
}

TEST_CASE("the loop names no jobs file when the config has none, and still flushes and sends "
          "heartbeats",
          "[service_loop]")
{
    LoopLab lab;
    lab.has_jobs_file = false;

    lab.run(2);

    CHECK(lab.lines == Lines{"info scheduler started: poll 60 s, heartbeat 600 s, jobs none, "
                             "runs C:\\rp\\runs, outbox C:\\rp"});
    CHECK(lab.calls == Lines{"read record", "heartbeat", "read record", "flush", "read record",
                             "flush"});
}

TEST_CASE("the loop starts with the record, then the heartbeat, then the poll, and a stop during "
          "the wait ends it",
          "[service_loop]")
{
    LoopLab lab;

    lab.run();

    CHECK(lab.lines == Lines{kStarted});
    CHECK(lab.calls == Lines{"read record", "heartbeat", "read record", "read jobs", "flush"});
    CHECK(lab.waited == std::vector<std::chrono::milliseconds>{60s});
    CHECK_FALSE(lab.last_error);
}

TEST_CASE("a stop between two jobs ends the poll: no second job and no flush", "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1"), job_text("job-2")});
    lab.on_run = [&lab](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        lab.stop = true;
        return queued_run(lab, job, callbacks);
    };

    lab.run();

    CHECK(lab.runs == Lines{"job-1"});
    CHECK(lab.flushes == 0);
    CHECK(lab.heartbeats.size() == 1);
    // After a stop no step is started for a record, its erase included: the
    // next start finds it and the run in the outbox.
    CHECK(lab.has_record());
    CHECK(lab.count_call("remove record") == 0);
    CHECK(lab.count("info run job-1: ended pass; queued") == 1);
}

TEST_CASE("a stop during a run that ends before its run line: nothing was done, and the record "
          "is deleted",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&lab](const rp::Job&, const rp::JobCallbacks&) {
        lab.stop = true;
        JobRun run;
        run.exit_code = 4;
        return run;
    };

    lab.run();

    // Point 13: the stub offers the job again; a record left here would be
    // closed as an interrupted run at the next start.
    CHECK_FALSE(lab.has_record());
    CHECK(lab.closed.empty());
}

TEST_CASE("a stop during a run that left its folder without a result: no close_as is written, "
          "nothing is closed and the record stays",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&lab](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        lab.stop = true;
        return LoopLab::ended_run(JobFolder::incomplete, "not_signed");
    };

    lab.run();

    CHECK(lab.writes.size() == 2); // taken, started
    CHECK_FALSE(lab.on_disk().close_as);
    CHECK(lab.closed.empty());
    CHECK(lab.has_record());
    CHECK(lab.count_call("remove record") == 0);
    CHECK(lab.flushes == 0);
}

TEST_CASE("a stop during the close of a record found: no lock, no look, and the record stays",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a"}, true));
    lab.on_close = [&lab](const rp::RunningRecord& record) {
        lab.stop = true;
        lab.queued.insert(record.run_id);
        return CloseRunOutcome{CloseRunState::queued, {}};
    };

    lab.run();

    CHECK(lab.calls == Lines{"read record", "close job-1"});
    CHECK(lab.has_record());
    CHECK(lab.cleans == 0);
}

TEST_CASE("a stop during a run that was queued while its restore may still run: no look",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&lab](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        callbacks.on_session_opened("s1");
        callbacks.before_restore_request();
        lab.queued.insert(job.run_id);
        lab.stop = true;
        JobRun run = LoopLab::ended_run(JobFolder::queued, {}, RunStatus::error, "interrupted");
        run.restore_may_still_run = true;
        return run;
    };

    lab.run();

    CHECK(lab.count_call("lock") == 0);
    CHECK(lab.count_call("look") == 0);
    CHECK(lab.flushes == 0);
    CHECK(lab.has_record());
}

TEST_CASE("a stop that comes during a look ends no session, cleans nothing and keeps the record",
          "[service_loop]")
{
    const bool requested = GENERATE(false, true);
    CAPTURE(requested);
    LoopLab lab;
    lab.put_record(lab.found({"a", "b"}, requested));
    lab.queued.insert("job-1");
    lab.every_look = [&lab, requested] {
        lab.stop = true;
        // Without a request: two recorded sessions to end. After one: nothing
        // is running any more, so the hold would be over and the clean due.
        return requested ? SessionsLook{"rp-veeam", {}}
                         : SessionsLook{"rp-veeam",
                                        {session("a", lab.wall0), session("b", lab.wall0)}};
    };

    lab.run();

    CHECK(lab.calls == Lines{"read record", "lock", "look"});
    CHECK(lab.ended.empty());
    CHECK(lab.cleans == 0);
    CHECK(lab.released == 0);
    CHECK(lab.has_record());
}

TEST_CASE("a stop that comes while a session is ended ends no further session and makes no "
          "second look",
          "[service_loop]")
{
    const char* const at = GENERATE("a", "b");
    CAPTURE(at);
    LoopLab lab;
    lab.put_record(lab.found({"a", "b"}));
    lab.queued.insert("job-1");
    lab.every_look = [&lab] {
        return SessionsLook{"rp-veeam", {session("a", lab.wall0), session("b", lab.wall0)}};
    };
    lab.on_end = [&lab, at](const std::string& id) { lab.stop = lab.stop || id == at; };

    lab.run();

    CHECK(lab.ended == (std::string{at} == "a" ? Lines{"a"} : Lines{"a", "b"}));
    CHECK(lab.count_call("look") == 1);
    CHECK(lab.has_record());
    CHECK(lab.count_call("remove record") == 0);
}

TEST_CASE("a run that ended before its run line and whose record couldn't be deleted is not "
          "closed: the erase is tried again at the next poll, and the job runs again",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&lab](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        if (lab.runs.size() > 1) {
            return queued_run(lab, job, callbacks);
        }
        JobRun run;
        run.exit_code = 3;
        return run;
    };
    lab.remove_ok = false;
    std::size_t runs_in_first_poll = 0;
    lab.on_wait = [&](int) {
        runs_in_first_poll = runs_in_first_poll == 0 ? lab.runs.size() : runs_in_first_poll;
        lab.remove_ok = true;
    };

    lab.run(2);

    CHECK(runs_in_first_poll == 1);
    CHECK(lab.closed.empty());
    CHECK(lab.runs == Lines{"job-1", "job-1"});
    // Refused at 0 s; at 60 s the record goes, and then the second run's.
    CHECK(lab.count_call("remove record") == 3);
    CHECK(lab.count("error running.json couldn't be removed") == 1);
    // No close_as was ever written for a run that has no folder.
    for (const std::string& text : lab.writes) {
        CHECK_FALSE(rp::parse_record(text).value().close_as);
    }
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("the flush is handed a stop function that answers the loop's own stop",
          "[service_loop]")
{
    LoopLab lab;
    lab.flush_sets_stop = true;

    lab.run();

    CHECK(lab.flush_stop_answers == std::vector<bool>{false, true});
    CHECK(lab.flushes == 1);
}

TEST_CASE("a job whose run is already queued, sent or has a run folder is skipped, said once",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-q"), job_text("job-s"), job_text("job-f")});
    lab.queued.insert("job-q");
    lab.sent.insert("job-s");
    lab.folders.insert("job-f");
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(3);

    CHECK(lab.lines == Lines{kStarted, "info skipped job-q: already queued",
                             "info skipped job-s: already sent",
                             "info skipped job-f: a run folder is already there"});
    CHECK(lab.runs.empty());
    CHECK(lab.writes.empty());
    CHECK(lab.count_call("read jobs") == 3);
}

TEST_CASE("a job without a usable run_id is not run and said once, and again when the file's "
          "content changed",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({R"({"client_id":null})", job_text("job-2")});
    lab.on_wait = [&lab](int wait) {
        if (wait == 2) {
            lab.jobs = *lab.jobs + " ";
        }
    };

    lab.run(4);

    CHECK(lab.count("warning job 1 of C:\\rp\\jobs.json: no usable run_id; not run") == 2);
    CHECK(lab.runs == Lines{"job-2"});
    CHECK(lab.last_error == rp::service_error::kJobInvalid);
    CHECK(lab.last_error_at == lab.wall0 + 180s);
}

TEST_CASE("a job that is no valid job is reported: its record, the close as job_invalid, then "
          "skipped",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-0", 0, 0, 0)});

    lab.run(2);

    CHECK(lab.lines == Lines{kStarted, "warning job job-0: not a valid job (sample_mail)",
                             "info run job-0: queued", "info sent job-0",
                             "info skipped job-0: already sent"});
    REQUIRE(lab.writes.size() == 1);
    REQUIRE(lab.closed.size() == 1);
    CHECK(lab.closed[0].kind == rp::RecordKind::job_invalid);
    CHECK(lab.closed[0].close_as == CloseAs::job_invalid);
    CHECK(lab.closed[0].close_detail == "sample_mail");
    CHECK(lab.closed[0].client_id == "client-7");
    CHECK(lab.closed[0].taken_at == "2026-10-08T10:00:00.000Z");
    // Nothing is asked of Veeam or Graph.
    CHECK(lab.runs.empty());
    CHECK(lab.count_call("look") == 0);
    CHECK(lab.count_call("lock") == 0);
    CHECK(lab.cleans == 0);
    CHECK_FALSE(lab.has_record());
    CHECK(lab.last_error == rp::service_error::kJobInvalid);
}

TEST_CASE("a job whose record can't be written is not run", "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1"), job_text("job-0", 0, 0, 0)});
    lab.write_ok = false;

    lab.run();

    CHECK(lab.lines == Lines{kStarted,
                             "error run job-1: running.json couldn't be written; not run",
                             "warning job job-0: not a valid job (sample_mail)",
                             "error run job-0: running.json couldn't be written; not run"});
    CHECK(lab.runs.empty());
    CHECK(lab.closed.empty());
    CHECK(lab.last_error == rp::service_error::kRecordNotWritten);
}

TEST_CASE("a run that ends before its run line leaves no record, is said once per exit code and "
          "is offered again",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1"), job_text("job-2")});
    int exit_code = 1;
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        if (job.run_id == "job-2") {
            return queued_run(lab, job, callbacks);
        }
        JobRun run;
        run.exit_code = exit_code;
        return run;
    };
    lab.on_wait = [&](int wait) { exit_code = wait == 2 ? 3 : exit_code; };

    lab.run(3);

    CHECK(lab.count("warning run job-1: ended before its run line; nothing was done") == 2);
    // Offered again at every poll, and the other job runs in the same one.
    CHECK(lab.runs == Lines{"job-1", "job-2", "job-1", "job-1"});
    CHECK(lab.closed.empty());
    CHECK(lab.count_call("remove record") == 4);
    CHECK_FALSE(lab.has_record());
    CHECK(lab.last_error == rp::service_error::kJobNotStarted);
}

TEST_CASE("a run that left its folder without a result has close_as written before the close",
          "[service_loop]")
{
    struct Row {
        const char* word;
        RunStatus status;
        const char* code;
        std::optional<RunStatus> replaced;
        const char* replaced_code;
        CloseAs close_as;
        const char* detail;
    };
    const Row row = GENERATE(
        Row{"not_written", RunStatus::pass, "", {}, "", CloseAs::internal, "not_written"},
        Row{"changed", RunStatus::fail, "", {}, "", CloseAs::internal, "changed"},
        Row{"holds_secret", RunStatus::pass, "", {}, "", CloseAs::internal, "holds_secret"},
        Row{"not_signed", RunStatus::error, "graph", {}, "", CloseAs::internal, "not_signed"},
        Row{"invalid", RunStatus::pass, "", {}, "", CloseAs::internal, "invalid"},
        // A word the record has no place for is the folder not written.
        Row{"", RunStatus::pass, "", {}, "", CloseAs::internal, "not_written"},
        Row{"invalid", RunStatus::error, "result_invalid", RunStatus::fail, "",
            CloseAs::result_invalid, "fail"},
        Row{"invalid", RunStatus::error, "result_invalid", RunStatus::error, "graph",
            CloseAs::result_invalid, "error graph"},
        Row{"invalid", RunStatus::error, "result_invalid", {}, "", CloseAs::result_invalid,
            "error"});
    CAPTURE(row.word, row.code, row.detail);

    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        JobRun run = LoopLab::ended_run(JobFolder::incomplete, row.word, row.status, row.code);
        run.replaced_status = row.replaced;
        run.replaced_code = row.replaced_code;
        return run;
    };

    lab.run();

    CHECK(lab.lines == Lines{kStarted,
                             "info run job-1: starting (mail 5, sharepoint 5, onedrive 5, point "
                             "latest)",
                             "warning run job-1: ended without a result",
                             "info run job-1: queued", "info sent job-1"});
    REQUIRE(lab.closed.size() == 1);
    CHECK(lab.closed[0].close_as == row.close_as);
    CHECK(lab.closed[0].close_detail == row.detail);
    // Written to the file before the close is asked for.
    REQUIRE(lab.writes.size() == 3);
    CHECK(lab.writes.back() == rp::record_text(lab.closed[0]));
    CHECK(lab.calls[static_cast<std::size_t>(index_of(lab.calls, "close job-1")) - 1] ==
          "write record");
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("a close_as that can't be written puts the close off to the next poll",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        lab.write_ok = false;
        return LoopLab::ended_run(JobFolder::incomplete, "changed");
    };
    std::size_t closed_in_first_poll = 99;
    lab.on_wait = [&](int) {
        closed_in_first_poll = std::min(closed_in_first_poll, lab.closed.size());
        lab.write_ok = true;
    };

    lab.run(2);

    CHECK(closed_in_first_poll == 0);
    CHECK(lab.count("error run job-1: running.json couldn't be written; not closed") == 1);
    REQUIRE(lab.closed.size() == 1);
    CHECK(lab.closed[0].close_as == CloseAs::internal);
    CHECK(lab.closed[0].close_detail == "changed");
    CHECK(lab.runs == Lines{"job-1"});
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("a close that fails is tried again no sooner than every 15 min, said once and hourly, "
          "and no job runs meanwhile",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1"), job_text("job-2")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        if (job.run_id == "job-2") {
            return queued_run(lab, job, callbacks);
        }
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        return LoopLab::ended_run(JobFolder::incomplete, "not_signed");
    };
    lab.on_close = [](const rp::RunningRecord&) {
        return CloseRunOutcome{CloseRunState::not_closed, "vault"};
    };
    std::size_t closes_in_the_first_hour = 0;
    std::optional<std::string> error_then;
    lab.on_wait = [&](int wait) {
        if (wait == 62) { // 3720 s: polls at 0 s to 3660 s are done
            closes_in_the_first_hour = lab.closed.size();
            error_then = lab.on_disk().close_detail;
            lab.on_close = nullptr;
        }
    };

    lab.run(77);

    // At 0, 900, 1800, 2700 and 3600 s.
    CHECK(closes_in_the_first_hour == 5);
    CHECK(error_then == "not_signed");
    CHECK(lab.count("error run job-1: couldn't be closed (vault)") == 2);
    // Then at 4500 s, queued, and the next job runs.
    CHECK(lab.closed.size() == 6);
    CHECK(lab.count("info run job-1: queued") == 1);
    CHECK(lab.runs == Lines{"job-1", "job-2"});
    CHECK(lab.last_error == rp::service_error::kRunNotClosed);
    CHECK(lab.last_error_at == lab.wall0 + 3600s);
}

TEST_CASE("a close that itself finds a text file changed puts that on record before it is tried "
          "again, and the run is closed as it would have been",
          "[service_loop]")
{
    struct Row {
        std::optional<CloseAs> close_as;
        std::optional<std::string> detail;
        std::optional<std::string> afterwards;
    };
    const Row row = GENERATE(Row{std::nullopt, std::nullopt, "changed"},
                             Row{CloseAs::internal, "not_signed", "changed"},
                             Row{CloseAs::result_invalid, "fail", "fail; changed"});
    CAPTURE(row.afterwards);
    LoopLab lab;
    rp::RunningRecord found = lab.found();
    found.close_as = row.close_as;
    found.close_detail = row.detail;
    lab.put_record(found);
    int closes = 0;
    lab.on_close = [&](const rp::RunningRecord& record) {
        if (++closes == 1) {
            return CloseRunOutcome{CloseRunState::not_closed, "changed"};
        }
        lab.queued.insert(record.run_id);
        return CloseRunOutcome{CloseRunState::queued, {}};
    };

    lab.run(16); // the close at start, and again at 900 s

    REQUIRE(lab.closed.size() == 2);
    CHECK(lab.closed[0].close_detail == row.detail);
    CHECK(lab.closed[1].close_as == row.close_as);
    CHECK(lab.closed[1].close_detail == row.afterwards);
    // Written to the file right after the close that answered so.
    REQUIRE(lab.writes.size() == 1);
    CHECK(lab.writes[0] == rp::record_text(lab.closed[1]));
    CHECK(lab.calls[static_cast<std::size_t>(index_of(lab.calls, "close job-1")) + 1] ==
          "write record");
    CHECK(lab.count("error run job-1: couldn't be closed (changed)") == 1);
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("changed text files that can't be put on record are said, and nothing is written for "
          "a record that already says so or has no place for it",
          "[service_loop]")
{
    LoopLab lab;
    lab.on_close = [](const rp::RunningRecord&) {
        return CloseRunOutcome{CloseRunState::not_closed, "changed"};
    };
    SECTION("the write fails")
    {
        lab.put_record(lab.found());
        lab.write_ok = false;

        lab.run();

        CHECK(lab.count("error run job-1: running.json couldn't be written; the changed text "
                        "files are not on record") == 1);
        CHECK(lab.count_call("write record") == 1);
        CHECK_FALSE(lab.on_disk().close_detail);
        CHECK(lab.last_error == rp::service_error::kRunNotClosed);
    }
    SECTION("the record says so already")
    {
        lab.put_record(rp::with_changed_text_files(lab.found()));

        lab.run();

        CHECK(lab.count_call("write record") == 0);
        CHECK(lab.count("error run job-1: couldn't be closed (changed)") == 1);
    }
    SECTION("a job that is no job")
    {
        lab.put_record(rp::new_job_invalid_record("job-1", std::nullopt, lab.config,
                                                  lab.wall0 - 10min, "sample_mail"));

        lab.run();

        CHECK(lab.count_call("write record") == 0);
    }
}

TEST_CASE("a folder whose result the service doesn't trust is a SECURITY line, said with the "
          "close's own line once and hourly, and the record stays",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found());
    lab.jobs = jobs_text({job_text("job-2")});
    lab.on_close = [](const rp::RunningRecord&) {
        return CloseRunOutcome{CloseRunState::not_closed, "untrusted"};
    };
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(61); // to 3600 s: closes at 0, 900, 1800, 2700 and 3600 s

    const std::string security =
        "critical SECURITY: service: run job-1: result.json or signature.json is owned by "
        "neither SYSTEM, Administrators nor this account; the folder is not queued";
    const std::string error = "error run job-1: couldn't be closed (untrusted)";
    CHECK(lab.lines == Lines{kStarted, kFound + "no", security, error, security, error});
    CHECK(lab.closed.size() == 5);
    CHECK(lab.has_record());
    CHECK(lab.runs.empty());
    CHECK(lab.writes.empty());
    CHECK(lab.last_error == rp::service_error::kRunNotClosed);
}

TEST_CASE("text files the close replaced because the service doesn't trust their owner are a "
          "SECURITY line, whatever became of the close",
          "[service_loop]")
{
    const bool queued = GENERATE(true, false);
    CAPTURE(queued);
    LoopLab lab;
    lab.put_record(lab.found());
    lab.on_close = [&lab, queued](const rp::RunningRecord& record) {
        CloseRunOutcome outcome{queued ? CloseRunState::queued : CloseRunState::not_closed,
                                queued ? "" : "vault"};
        outcome.untrusted_text_files = true;
        if (queued) {
            lab.queued.insert(record.run_id);
        }
        return outcome;
    };
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(16); // the close at start, and when it failed again at 900 s

    const std::string security =
        "critical SECURITY: service: run job-1: items.csv or veeam-session.log is owned by "
        "neither SYSTEM, Administrators nor this account; both text files are replaced by their "
        "empty forms";
    if (queued) {
        CHECK(lab.lines == Lines{kStarted, kFound + "no", security, "info run job-1: queued"});
    } else {
        // Said once for the record, not at every try.
        CHECK(lab.lines == Lines{kStarted, kFound + "no", security,
                                 "error run job-1: couldn't be closed (vault)"});
        CHECK(lab.closed.size() == 2);
    }
}

TEST_CASE("a folder the pipeline couldn't queue is queued at the next poll, and at every poll "
          "until it is",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1"), job_text("job-2")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        if (job.run_id == "job-2") {
            return queued_run(lab, job, callbacks);
        }
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        return LoopLab::ended_run(JobFolder::complete, "not_moved", RunStatus::fail);
    };
    int closes = 0;
    lab.on_close = [&](const rp::RunningRecord& record) {
        if (++closes < 3) {
            return CloseRunOutcome{CloseRunState::not_queued, "not_moved"};
        }
        lab.queued.insert(record.run_id);
        return CloseRunOutcome{CloseRunState::queued, {}};
    };
    std::size_t closed_in_first_poll = 99;
    lab.on_wait = [&](int) {
        closed_in_first_poll = std::min(closed_in_first_poll, lab.closed.size());
    };

    lab.run(4);

    CHECK(closed_in_first_poll == 0);
    CHECK(lab.lines ==
          Lines{kStarted,
                "info run job-1: starting (mail 5, sharepoint 5, onedrive 5, point latest)",
                "warning run job-1: ended fail; not queued",
                "error run job-1: couldn't be queued (not_moved)", "info run job-1: queued",
                "info sent job-1", "info skipped job-1: already sent",
                "info run job-2: starting (mail 5, sharepoint 5, onedrive 5, point latest)",
                "info run job-2: ended pass; queued", "info sent job-2"});
    // Nothing is signed twice: the record never got a close_as.
    REQUIRE(lab.closed.size() == 3);
    CHECK_FALSE(lab.closed[2].close_as);
    CHECK(lab.last_error == rp::service_error::kRunNotQueued);
    CHECK(lab.last_error_at == lab.wall0 + 120s);
}

TEST_CASE("a record that can't be deleted is said once, tried again at every poll, and no job "
          "runs until it is gone",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1"), job_text("job-2")});
    lab.remove_ok = false;
    lab.on_wait = [&lab](int wait) { lab.remove_ok = wait >= 2; };

    lab.run(3);

    CHECK(lab.count("error running.json couldn't be removed") == 1);
    CHECK(lab.count_call("remove record") == 4); // 0 s, 60 s, then 120 s twice (job-2's)
    CHECK(lab.runs == Lines{"job-1", "job-2"});
    CHECK(lab.closed.empty());
    CHECK(lab.last_error == rp::service_error::kRecordNotRemoved);
    CHECK(lab.last_error_at == lab.wall0 + 60s);
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("a record that can't be deleted is said again after an hour", "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found());
    lab.queued.insert("job-1");
    lab.remove_ok = false;

    lab.run(61);

    CHECK(lab.count("error running.json couldn't be removed") == 2);
}

TEST_CASE("a record the service can't trust or read is moved aside and nothing is done on its "
          "word",
          "[service_loop]")
{
    const bool foreign = GENERATE(true, false);
    CAPTURE(foreign);
    LoopLab lab;
    lab.record = foreign ? rp::TrustedFile{rp::TrustedRead::not_trusted, {}}
                         : rp::TrustedFile{rp::TrustedRead::read, "{\"run_id\":\"job-9\"}"};
    lab.jobs = jobs_text({job_text("job-1")});

    lab.run();

    REQUIRE(lab.lines.size() > 1);
    CHECK(lab.lines[1] ==
          (foreign ? "critical SECURITY: service: running.json is owned by neither SYSTEM, "
                     "Administrators nor this account; moved aside"
                   : "error running.json isn't a restoreproof.running.v1 record; moved aside as "
                     "running.json.unread"));
    CHECK(lab.count_call("move record to running.json.unread") == 1);
    // Nothing is closed, ended or cleaned; the loop goes on with the jobs.
    CHECK(lab.closed.empty());
    CHECK(lab.count_call("look") == 0);
    CHECK(lab.cleans == 0);
    CHECK(lab.runs == Lines{"job-1"});
    CHECK(lab.last_error == rp::service_error::kRecordUnreadable);
}

TEST_CASE("a record that can be neither believed nor moved aside lets no job run, said once and "
          "hourly",
          "[service_loop]")
{
    struct Row {
        rp::TrustedFile file;
        const char* line;
        int moves;
    };
    const Row row = GENERATE(
        Row{{rp::TrustedRead::not_trusted, {}},
            "critical SECURITY: service: running.json is owned by neither SYSTEM, Administrators "
            "nor this account; it couldn't be moved aside; no job runs",
            1},
        Row{{rp::TrustedRead::read, "not a record"},
            "error running.json isn't a restoreproof.running.v1 record and couldn't be moved "
            "aside; no job runs",
            1},
        Row{{rp::TrustedRead::too_large, {}},
            "error running.json isn't a restoreproof.running.v1 record and couldn't be moved "
            "aside; no job runs",
            1},
        Row{{rp::TrustedRead::unreadable, {}}, "error running.json can't be read; no job runs",
            0});
    CAPTURE(row.line);
    LoopLab lab;
    lab.record = row.file;
    lab.move_ok = false;
    lab.jobs = jobs_text({job_text("job-1")});

    lab.run(61); // polls at 0 s to 3600 s

    CHECK(lab.count(row.line) == 2);
    CHECK(lab.lines.size() == 3);
    CHECK(lab.count_call("move record to running.json.unread") ==
          static_cast<std::size_t>(row.moves) * 62u);
    CHECK(lab.runs.empty());
    CHECK(lab.count_call("read jobs") == 0);
    CHECK(lab.flushes == 61);
    CHECK(lab.last_error == rp::service_error::kRecordUnreadable);
}

TEST_CASE("an interrupted run found at start is closed, queued and its record deleted",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found());
    lab.jobs = jobs_text({job_text("job-2")});

    lab.run();

    CHECK(lab.lines == Lines{kStarted, kFound + "no", "info run job-1: queued", "info sent job-1",
                             "info run job-2: starting (mail 5, sharepoint 5, onedrive 5, point "
                             "latest)",
                             "info run job-2: ended pass; queued", "info sent job-2"});
    REQUIRE(lab.closed.size() == 1);
    CHECK_FALSE(lab.closed[0].close_as);
    // No session was opened and no restore requested: no hold.
    CHECK(lab.count_call("lock") == 0);
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("a record found with its close_as is closed with that word", "[service_loop]")
{
    LoopLab lab;
    lab.put_record(rp::with_close(lab.found(), CloseAs::internal, std::string{"changed"}));

    lab.run();

    CHECK(lab.lines == Lines{kStarted, "info unfinished run job-1 found: to be closed as internal",
                             "info run job-1: queued", "info sent job-1"});
    REQUIRE(lab.closed.size() == 1);
    CHECK(lab.closed[0].close_detail == "changed");
}

TEST_CASE("the hold without a restore request ends the recorded sessions at once and leaves the "
          "others",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a", "b", "c"}));
    lab.queued.insert("job-1");
    const auto other = session("x", lab.wall0 - 4min);
    lab.looks.push_back([&] {
        return SessionsLook{"rp-veeam",
                            {session("a", lab.wall0), session("b", lab.wall0), other,
                             session("c", lab.wall0)}};
    });
    lab.looks.push_back([&] { return SessionsLook{"rp-veeam", {other}}; });
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run();

    CHECK(lab.lines == Lines{kStarted, kFound + "no"});
    CHECK(lab.calls == Lines{"read record", "lock", "look", "end a", "end b", "end c", "look",
                             "remove record", "release", "heartbeat", "read record", "read jobs",
                             "flush"});
    REQUIRE(lab.looked_since.size() == 2);
    CHECK(lab.looked_since[0] == lab.wall0 - 10min);
    CHECK(lab.cleans == 0);
    CHECK(lab.closed.empty());
    CHECK_FALSE(lab.last_error);
}

TEST_CASE("recorded sessions that are still running after their end are ended again at the next "
          "look",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a"}));
    lab.queued.insert("job-1");
    lab.every_look = [&] { return SessionsLook{"rp-veeam", {session("a", lab.wall0)}}; };
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(2); // looks at start, at the poll, and 30 s later: two rounds each

    CHECK(lab.ended == Lines{"a", "a", "a", "a", "a", "a"});
    CHECK(lab.waited == std::vector<std::chrono::milliseconds>{30s, 30s});
    CHECK(lab.has_record());
}

TEST_CASE("the hold after a restore request ends nothing while another session runs, and says so "
          "once and hourly",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a"}, true));
    lab.queued.insert("job-1");
    lab.jobs = jobs_text({job_text("job-2")});
    lab.every_look = [&] {
        return SessionsLook{"rp-veeam",
                            {session("a", lab.wall0 - 9min), session("y", lab.wall0 - 2min),
                             session("x", lab.wall0 - 4min)}};
    };
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(121); // a look every 30 s, to 3600 s

    CHECK(lab.lines == Lines{kStarted, kFound + "yes",
                             "warning waiting for Veeam: 2 session(s) of rp-veeam still Working "
                             "since 2026-10-08T09:56:00.000Z",
                             "warning waiting for Veeam: 2 session(s) of rp-veeam still Working "
                             "since 2026-10-08T09:56:00.000Z"});
    CHECK(lab.count_call("look") == 122);
    CHECK(lab.ended.empty());
    CHECK(lab.cleans == 0);
    CHECK(lab.runs.empty());
    CHECK(lab.count_call("read jobs") == 0);
    CHECK(lab.has_record());
    CHECK(lab.last_error == rp::service_error::kVeeamSessionsWorking);
}

TEST_CASE("the hold after a restore request ends the recorded sessions 120 s after it began, "
          "then cleans and deletes the record",
          "[service_loop]")
{
    LoopLab lab;
    // The last request was five minutes before this process began the hold.
    lab.put_record(lab.found({"a"}, true));
    lab.queued.insert("job-1");
    lab.every_look = [&] {
        return lab.ended.empty() ? SessionsLook{"rp-veeam", {session("a", lab.wall0)}}
                                 : SessionsLook{"rp-veeam", {}};
    };
    lab.on_flush = [] { return rp::FlushReport{}; };
    std::size_t ended_before_120 = 99;
    lab.on_wait = [&](int wait) {
        if (wait == 4) { // 120 s reached, the looks at 0, 30, 60 and 90 s made
            ended_before_120 = lab.ended.size();
        }
    };

    lab.run(5);

    CHECK(ended_before_120 == 0);
    CHECK(lab.ended == Lines{"a"});
    CHECK(lab.lines == Lines{kStarted, kFound + "yes", "info recovery clean for job-1:"});
    CHECK(lab.cleans == 1);
    CHECK(lab.released == 1);
    CHECK_FALSE(lab.has_record());
    const Lines tail(lab.calls.end() - 9, lab.calls.end());
    CHECK(tail == Lines{"lock", "look", "end a", "look", "clean job-1", "remove record",
                        "release", "read jobs", "flush"});
}

TEST_CASE("a recorded session that is no longer listed ends the hold at once; the clean is made "
          "once even while the record can't be deleted",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a"}, true));
    lab.queued.insert("job-1");
    lab.remove_ok = false;
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(2);

    CHECK(lab.count_call("look") == 1);
    CHECK(lab.cleans == 1);
    CHECK(lab.count_call("remove record") == 3);
    CHECK(lab.waited == std::vector<std::chrono::milliseconds>{60s, 60s});
}

TEST_CASE("the hold's look waits while a command holds the run mutex", "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a"}, true));
    lab.queued.insert("job-1");
    lab.lock_free = false;
    lab.on_wait = [&lab](int) { lab.lock_free = true; };
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(2);

    CHECK(lab.count("debug the run mutex is held; the look at Veeam's sessions waits") == 2);
    CHECK(lab.calls[1] == "lock held");
    CHECK(index_of(lab.calls, "look") > index_of(lab.calls, "lock"));
    CHECK(lab.count_call("look") == 1);
    CHECK(lab.waited.front() == 30s);
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("a look at Veeam's sessions that fails is not yet, said once per reason and hourly",
          "[service_loop]")
{
    struct Row {
        std::function<SessionsLook()> look;
        const char* reason;
    };
    const Row row = GENERATE(
        Row{[]() -> SessionsLook { throw rp::connector::AuthError("veeam_m365: 401 for rp-veeam"); },
            "auth"},
        Row{[]() -> SessionsLook { throw rp::connector::TransientError("veeam_m365: timeout"); },
            "transient"},
        Row{[]() -> SessionsLook { throw rp::connector::Error("veeam_m365: 500"); }, "other"},
        Row{[]() -> SessionsLook { throw std::runtime_error("the vault"); }, "other"});
    CAPTURE(row.reason);
    LoopLab lab;
    lab.put_record(lab.found({"a"}, true));
    lab.queued.insert("job-1");
    lab.every_look = row.look;
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run(121);

    CHECK(lab.lines == Lines{kStarted, kFound + "yes",
                             std::string{"warning the look at Veeam's sessions failed: "} +
                                 row.reason,
                             std::string{"warning the look at Veeam's sessions failed: "} +
                                 row.reason});
    CHECK(lab.ended.empty());
    CHECK(lab.cleans == 0);
    CHECK(lab.has_record());
    CHECK(lab.last_error == rp::service_error::kVeeamLookFailed);
}

TEST_CASE("an end of a session that fails is not yet", "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a", "b", "c"}));
    lab.queued.insert("job-1");
    lab.end_fails.insert("b");
    lab.every_look = [&] {
        return SessionsLook{"rp-veeam",
                            {session("a", lab.wall0), session("b", lab.wall0),
                             session("c", lab.wall0)}};
    };
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run();

    CHECK(lab.lines == Lines{kStarted, kFound + "no", "warning ending session b failed"});
    CHECK(lab.ended == Lines{"a", "a"});
    CHECK(lab.count_call("end c") == 0);
    CHECK(lab.has_record());
    CHECK(lab.last_error == rp::service_error::kVeeamLookFailed);
}

TEST_CASE("the recovery clean is not made for a config whose client is not the run's, and an "
          "incomplete one still lets the record go",
          "[service_loop]")
{
    const bool other_client = GENERATE(true, false);
    CAPTURE(other_client);
    LoopLab lab;
    lab.put_record(lab.found({}, true));
    lab.queued.insert("job-1");
    lab.clean_word = "incomplete";
    if (other_client) {
        lab.config.test_mailbox = "another@example.test";
    }
    lab.on_flush = [] { return rp::FlushReport{}; };

    lab.run();

    if (other_client) {
        CHECK(lab.lines == Lines{kStarted, kFound + "yes",
                                 "warning the config's client is not the run's; the restore "
                                 "targets were not cleaned"});
        CHECK(lab.cleans == 0);
        CHECK_FALSE(lab.last_error);
    } else {
        CHECK(lab.lines == Lines{kStarted, kFound + "yes", "info recovery clean for job-1:",
                                 "warning recovery clean for job-1: not completed (incomplete)"});
        CHECK(lab.cleans == 1);
        CHECK(lab.last_error == rp::service_error::kRecoveryCleanIncomplete);
    }
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("a run of this process whose restore may still run is held for at once, and the next "
          "job waits for the hold and the clean",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1"), job_text("job-2")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        if (job.run_id == "job-2") {
            return queued_run(lab, job, callbacks);
        }
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        callbacks.on_session_opened("s1");
        CHECK(callbacks.before_restore_request());
        lab.queued.insert(job.run_id);
        JobRun run = LoopLab::ended_run(JobFolder::queued, {}, RunStatus::error, "backup");
        run.restore_may_still_run = true;
        return run;
    };
    bool restoring = true;
    lab.every_look = [&] {
        return restoring ? SessionsLook{"rp-veeam",
                                        {session("s1", lab.wall0), session("r", lab.wall0)}}
                         : SessionsLook{"rp-veeam", {}};
    };
    lab.on_wait = [&](int wait) { restoring = wait < 2; };

    lab.run(3);

    CHECK(lab.lines ==
          Lines{kStarted,
                "info run job-1: starting (mail 5, sharepoint 5, onedrive 5, point latest)",
                "info run job-1: ended error backup; queued", "info sent job-1",
                "warning waiting for Veeam: 1 session(s) of rp-veeam still Working since "
                "2026-10-08T10:00:00.000Z",
                "info recovery clean for job-1:", "info skipped job-1: already sent",
                "info run job-2: starting (mail 5, sharepoint 5, onedrive 5, point latest)",
                "info run job-2: ended pass; queued", "info sent job-2"});
    CHECK(lab.count_call("look") == 3); // 0 s, 30 s, 60 s
    CHECK(lab.ended.empty());
    CHECK(lab.released == 1);
    CHECK(lab.runs == Lines{"job-1", "job-2"});
}

TEST_CASE("a run of this process that closed its own sessions is not held for", "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_session_opened("s1");
        CHECK(callbacks.before_restore_request());
        return queued_run(lab, job, callbacks);
    };

    lab.run();

    CHECK(lab.count_call("lock") == 0);
    CHECK(lab.released == 0);
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("a run that reached the outbox is never closed again, even when the outbox no longer "
          "holds it while the hold lasts",
          "[service_loop]")
{
    // How the loop learns that the run reached the outbox: the pipeline
    // queued it, or a close did.
    const bool by_close = GENERATE(false, true);
    CAPTURE(by_close);
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        callbacks.before_restore_request();
        JobRun run = LoopLab::ended_run(by_close ? JobFolder::complete : JobFolder::queued, {},
                                        RunStatus::error, "backup");
        run.restore_may_still_run = true;
        return run;
    };
    // Neither fake puts the run into the lab's outbox: it was sent and then
    // pruned from sent\ (over the cap) before the loop asked.
    lab.on_close = [](const rp::RunningRecord&) { return CloseRunOutcome{CloseRunState::queued, {}}; };
    bool restoring = true;
    lab.every_look = [&] {
        return restoring ? SessionsLook{"rp-veeam", {session("r", lab.wall0)}}
                         : SessionsLook{"rp-veeam", {}};
    };
    lab.on_flush = [] { return rp::FlushReport{}; };
    std::size_t closes_while_held = 0;
    std::size_t writes_while_held = 0;
    lab.on_wait = [&](int wait) {
        if (wait == 7) { // 210 s: the polls at 60, 120 and 180 s are done
            closes_while_held = lab.closed.size();
            writes_while_held = lab.writes.size();
            restoring = false;
            lab.jobs.reset();
        }
    };

    lab.run(9);

    // The pipeline's own queue needs no close; a close is made once (at the
    // poll after the run the pipeline couldn't queue) and never again.
    CHECK(closes_while_held == (by_close ? 1u : 0u));
    CHECK(lab.closed.size() == closes_while_held);
    // Taken, started, the restore request: no close_as was ever written.
    CHECK(writes_while_held == 3);
    CHECK(lab.writes.size() == 3);
    CHECK(lab.count("error run job-1: couldn't be closed (vault)") == 0);
    // And the record still goes when the hold is over.
    CHECK(lab.cleans == 1);
    CHECK_FALSE(lab.has_record());
    CHECK(lab.runs == Lines{"job-1"});
}

TEST_CASE("a run the outbox was seen to hold at a poll is not closed when it is gone from there "
          "at a later one",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({}, true));
    lab.queued.insert("job-1");
    lab.every_look = [&] { return SessionsLook{"rp-veeam", {session("r", lab.wall0)}}; };
    lab.on_flush = [] { return rp::FlushReport{}; };
    lab.on_wait = [&](int) { lab.queued.clear(); };

    lab.run(5);

    CHECK(lab.closed.empty());
    CHECK(lab.writes.empty());
    CHECK(lab.has_record());
}

TEST_CASE("a flush that throws after a run or a close doesn't keep the record's business from "
          "going on: the hold begins in the same poll",
          "[service_loop]")
{
    const bool found = GENERATE(false, true);
    CAPTURE(found);
    LoopLab lab;
    if (found) {
        lab.put_record(lab.found({}, true));
    } else {
        lab.jobs = jobs_text({job_text("job-1")});
    }
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        callbacks.before_restore_request();
        lab.queued.insert(job.run_id);
        JobRun run = LoopLab::ended_run(JobFolder::queued, {}, RunStatus::error, "backup");
        run.restore_may_still_run = true;
        return run;
    };
    lab.every_look = [&] { return SessionsLook{"rp-veeam", {session("r", lab.wall0)}}; };
    lab.on_flush = []() -> std::optional<rp::FlushReport> {
        throw std::runtime_error("C:\\secret-path\\outbox");
    };
    std::size_t looks_before_first_wait = 99;
    lab.on_wait = [&](int wait) {
        if (wait == 1) {
            looks_before_first_wait = lab.count_call("look");
        }
    };

    lab.run(3);

    // The look right after the flush that threw (for a record found: at
    // start, and again at the first poll), then every 30 s.
    CHECK(looks_before_first_wait == (found ? 2u : 1u));
    CHECK(lab.waited == std::vector<std::chrono::milliseconds>{30s, 30s, 30s});
    CHECK(lab.count_call("look") == looks_before_first_wait + 2);
    // One fixed line per flush, never its text.
    CHECK(lab.flushes == 3);
    CHECK(lab.count(kStepFailed) == 3);
    CHECK(lab.has_record());
}

TEST_CASE("what is said once and hourly of a record is said anew for the next record: two holds "
          "ten minutes apart, the waiting line twice",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        callbacks.on_run_started(LoopLab::run_started(job.run_id));
        callbacks.before_restore_request();
        lab.queued.insert(job.run_id);
        JobRun run = LoopLab::ended_run(JobFolder::queued, {}, RunStatus::error, "backup");
        run.restore_may_still_run = true;
        return run;
    };
    bool restoring = true;
    lab.every_look = [&] {
        return restoring ? SessionsLook{"rp-veeam", {session("r", lab.wall0)}}
                         : SessionsLook{"rp-veeam", {}};
    };
    // The first record's erase is refused once, and so is the second's.
    lab.remove_ok = false;
    lab.on_wait = [&](int wait) {
        // 30 s: the first restore is over. 600 s: the second job is offered.
        // 630 s: its restore is over.
        restoring = wait == 11;
        lab.remove_ok = wait != 1 && wait != 12;
        if (wait == 11) {
            lab.jobs = jobs_text({job_text("job-2")});
        }
    };

    lab.run(14);

    CHECK(lab.runs == Lines{"job-1", "job-2"});
    CHECK(lab.count("warning waiting for Veeam: 1 session(s) of rp-veeam still Working since "
                    "2026-10-08T10:00:00.000Z") == 2);
    CHECK(lab.count("error running.json couldn't be removed") == 2);
    CHECK(lab.cleans == 2);
    CHECK_FALSE(lab.has_record());
}

TEST_CASE("what is said once of a job is forgotten when the document no longer names it",
          "[service_loop]")
{
    LoopLab lab;
    const std::string with = jobs_text({job_text("job-q"), job_text("job-n")});
    lab.jobs = with;
    lab.queued.insert("job-q");
    lab.on_run = [](const rp::Job&, const rp::JobCallbacks&) {
        JobRun run;
        run.exit_code = 1;
        return run;
    };
    lab.on_flush = [] { return rp::FlushReport{}; };
    lab.on_wait = [&](int wait) {
        // Polls at 0 and 60 s with both jobs, at 120 s with neither, at 180 s
        // a file that can't be read, then both again.
        lab.jobs_fault.reset();
        lab.jobs = with;
        if (wait == 2) {
            lab.jobs = jobs_text({});
        } else if (wait == 3) {
            lab.jobs_fault = rp::JobsFault::unreadable;
        }
    };

    lab.run(6);

    // 0 s, and again at 240 s; not at 60 s, and not at 300 s.
    CHECK(lab.count("info skipped job-q: already queued") == 2);
    CHECK(lab.count("warning run job-n: ended before its run line; nothing was done") == 2);
    CHECK(lab.runs.size() == 4);
}

TEST_CASE("a job without a usable run_id is said again when the document's content came back "
          "after another",
          "[service_loop]")
{
    LoopLab lab;
    const std::string first = jobs_text({R"({"run_id":7})"});
    lab.jobs = first;
    lab.on_wait = [&](int wait) {
        lab.jobs = wait == 2 ? jobs_text({R"({"run_id":8})"}) : first;
    };

    lab.run(4); // first, first, the other, first

    CHECK(lab.count("warning job 1 of C:\\rp\\jobs.json: no usable run_id; not run") == 3);
}

TEST_CASE("a run the flush couldn't read is said again when a pass in between didn't name it",
          "[service_loop]")
{
    LoopLab lab;
    lab.on_flush = [&lab] {
        rp::FlushReport report;
        if (lab.flushes != 3) {
            report.out = {"kept run-y: not_read", "kept run-x: folder_changed"};
            report.err = {"outbox error: C:\\rp\\outbox\\run-y: result.json couldn't be read"};
        } else {
            report.out = {"kept run-x: folder_changed"};
        }
        return report;
    };

    lab.run(5); // five passes; the third doesn't name run-y

    CHECK(lab.count("info kept run-y: not_read") == 2);
    CHECK(lab.count("warning outbox error: C:\\rp\\outbox\\run-y: result.json couldn't be read") ==
          2);
    // Named at every pass: once.
    CHECK(lab.count("info kept run-x: folder_changed") == 1);
}

TEST_CASE("a write of the record that fails during the run ends the run, withholds the restore "
          "request, or costs one session its place",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        lab.write_ok = false;
        CHECK_FALSE(callbacks.on_run_started(LoopLab::run_started(job.run_id)));
        callbacks.on_session_opened("s1");
        CHECK_FALSE(callbacks.before_restore_request());
        lab.write_ok = true;
        callbacks.on_session_opened("s2");
        lab.queued.insert(job.run_id);
        return LoopLab::ended_run(JobFolder::queued, {}, RunStatus::error, "interrupted");
    };
    lab.remove_ok = false;

    lab.run();

    CHECK(lab.lines ==
          Lines{kStarted,
                "info run job-1: starting (mail 5, sharepoint 5, onedrive 5, point latest)",
                "error run job-1: running.json couldn't be written; the run ends",
                "warning run job-1: running.json couldn't be written; a session the run opened "
                "is not on record",
                "error run job-1: running.json couldn't be written; the restore request is not "
                "sent",
                "info run job-1: ended error interrupted; queued", "info sent job-1",
                "error running.json couldn't be removed"});
    // What couldn't be written isn't in the record.
    CHECK(lab.on_disk().sessions == Lines{"s2"});
    CHECK_FALSE(lab.on_disk().restore_requested);
    CHECK_FALSE(lab.on_disk().started_at);
}

TEST_CASE("a heartbeat that falls due during a run is sent once after it, and the next poll is "
          "late, never a second run",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1")});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        lab.t += 2000s; // three heartbeats and thirty-three polls missed
        return queued_run(lab, job, callbacks);
    };
    lab.on_flush = [] { return std::optional<rp::FlushReport>{}; };

    lab.run();

    CHECK(lab.heartbeat_at == std::vector<std::chrono::seconds>{0s, 2000s});
    REQUIRE(lab.heartbeats.size() == 2);
    CHECK(lab.heartbeats[0].uptime_s == 0);
    CHECK(lab.heartbeats[0].outbox_depth == 0);
    CHECK(lab.heartbeats[1].uptime_s == 2000);
    CHECK(lab.heartbeats[1].outbox_depth == 1);
    CHECK(lab.runs == Lines{"job-1"});
    CHECK(lab.count("info skipped job-1: already queued") == 1);
    CHECK(lab.count_call("read jobs") == 2);
    CHECK(lab.waited == std::vector<std::chrono::milliseconds>{60s});
}

TEST_CASE("a heartbeat carries the loop's last error and its time, never cleared",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs_fault = rp::JobsFault::not_json;
    lab.on_wait = [&lab](int wait) {
        if (wait == 3) {
            lab.jobs_fault.reset();
        }
    };

    lab.run(21);

    REQUIRE(lab.heartbeats.size() == 3);
    CHECK_FALSE(lab.heartbeats[0].last_error);
    CHECK_FALSE(lab.heartbeats[0].last_error_at);
    CHECK(lab.heartbeats[1].last_error == rp::service_error::kJobsUnreadable);
    CHECK(lab.heartbeats[1].last_error_at == lab.wall0 + 120s);
    CHECK(lab.heartbeats[1].uptime_s == 600);
    CHECK(lab.heartbeats[2].last_error == rp::service_error::kJobsUnreadable);
    CHECK(lab.heartbeats[2].last_error_at == lab.wall0 + 120s);
}

TEST_CASE("a failed heartbeat is said when its word changes, and is never the last error",
          "[service_loop]")
{
    LoopLab lab;
    lab.heartbeat_word = "http_503";
    lab.on_wait = [&lab](int wait) {
        // Heartbeats at 0, 600, ... s: the waits are a minute each.
        lab.heartbeat_word = wait < 20   ? "http_503"
                             : wait < 30 ? "timeout"
                             : wait < 40 ? ""
                                         : "timeout";
    };

    lab.run(41);

    CHECK(lab.lines == Lines{kStarted, "warning heartbeat failed: http_503",
                             "warning heartbeat failed: timeout",
                             "warning heartbeat failed: timeout"});
    CHECK(lab.heartbeats.size() == 5);
    CHECK_FALSE(lab.last_error);
}

TEST_CASE("a jobs file that runs nothing is said when the reason changes", "[service_loop]")
{
    LoopLab lab;
    lab.jobs_fault = rp::JobsFault::not_json;
    lab.jobs = jobs_text({});
    lab.on_wait = [&lab](int wait) {
        lab.jobs_fault = wait < 2    ? std::optional{rp::JobsFault::not_json}
                         : wait == 2 ? std::optional{rp::JobsFault::not_trusted}
                         : wait == 3 ? std::nullopt
                                     : std::optional{rp::JobsFault::not_trusted};
    };

    lab.run(6);

    CHECK(lab.lines ==
          Lines{kStarted, "warning jobs error: C:\\rp\\jobs.json: not JSON",
                "warning jobs error: C:\\rp\\jobs.json: owned by neither SYSTEM, Administrators "
                "nor this account",
                "warning jobs error: C:\\rp\\jobs.json: owned by neither SYSTEM, Administrators "
                "nor this account"});
    CHECK(lab.runs.empty());
    CHECK(lab.last_error == rp::service_error::kJobsUnreadable);
    CHECK(lab.last_error_at == lab.wall0 + 300s);
}

TEST_CASE("the flush's lines go to the log; a run that is never sent or couldn't be read is said "
          "once",
          "[service_loop]")
{
    LoopLab lab;
    lab.on_flush = [] {
        rp::FlushReport report;
        report.out = {"kept run-x: folder_changed", "kept run-y: not_read",
                      "waiting run-w: next at 2026-10-08T10:05:00Z",
                      "kept run-z: upload_http_503; attempt 1, next at 2026-10-08T10:01:00Z",
                      "kept odd", "sent run-s"};
        report.err = {"outbox error: C:\\rp\\outbox\\run-x: items.csv changed since it was signed",
                      "outbox error: C:\\rp\\outbox\\run-y: result.json couldn't be read",
                      "outbox warning: the outbox holds 501 MB, over the 500 MB cap"};
        return report;
    };

    lab.run(3);

    const Lines every_pass{
        "debug waiting run-w: next at 2026-10-08T10:05:00Z",
        "info kept run-z: upload_http_503; attempt 1, next at 2026-10-08T10:01:00Z",
        "info kept odd", "info sent run-s",
        "warning outbox warning: the outbox holds 501 MB, over the 500 MB cap"};
    Lines expected{kStarted, "info kept run-x: folder_changed", "info kept run-y: not_read"};
    expected.insert(expected.end(), every_pass.begin(), every_pass.begin() + 4);
    expected.push_back(
        "warning outbox error: C:\\rp\\outbox\\run-x: items.csv changed since it was signed");
    expected.push_back("warning outbox error: C:\\rp\\outbox\\run-y: result.json couldn't be read");
    expected.push_back(every_pass[4]);
    expected.insert(expected.end(), every_pass.begin(), every_pass.end());
    expected.insert(expected.end(), every_pass.begin(), every_pass.end());
    CHECK(lab.lines == expected);
    CHECK(lab.last_error == "upload_http_503");
    CHECK(lab.last_error_at == lab.wall0 + 120s);
}

TEST_CASE("a run that is never sent is the last error once, when it is first met",
          "[service_loop]")
{
    const char* const word = GENERATE("folder_changed", "not_read");
    LoopLab lab;
    lab.on_flush = [word] {
        rp::FlushReport report;
        report.out = {std::string{"kept run-x: "} + word};
        return report;
    };

    lab.run(3);

    CHECK(lab.lines == Lines{kStarted, std::string{"info kept run-x: "} + word});
    CHECK(lab.last_error == word);
    CHECK(lab.last_error_at == lab.wall0);
}

TEST_CASE("the flush is skipped while another flush holds its mutex", "[service_loop]")
{
    LoopLab lab;
    lab.on_flush = [] { return std::optional<rp::FlushReport>{}; };

    lab.run(2);

    CHECK(lab.lines == Lines{kStarted, "debug flush skipped: another flush is running",
                             "debug flush skipped: another flush is running"});
}

TEST_CASE("a step that throws is one fixed error line, never its text, and the loop goes on",
          "[service_loop]")
{
    LoopLab lab;
    lab.put_record(lab.found({"a"}, true));
    lab.on_close = [](const rp::RunningRecord&) -> CloseRunOutcome {
        throw std::runtime_error("C:\\secret-path\\vault.bin");
    };
    lab.every_look = []() -> SessionsLook { throw 7; };

    lab.run(); // the record at start, then the poll

    CHECK(lab.lines == Lines{kStarted, kFound + "yes", kStepFailed, kStepFailed});
    CHECK(lab.flushes == 1);
    CHECK(lab.heartbeats.size() == 1);
    CHECK(lab.has_record());

    // The close out of the way: the look throws, and is made again 30 s on.
    lab.queued.insert("job-1");
    lab.on_flush = [] { return rp::FlushReport{}; };
    lab.lines.clear();
    lab.waited.clear();
    lab.run(2);

    CHECK(lab.lines == Lines{kStarted, kFound + "yes", kStepFailed, kStepFailed, kStepFailed});
    CHECK(lab.waited == std::vector<std::chrono::milliseconds>{30s, 30s});
}

TEST_CASE("one job from poll to queued and sent: every line in order, the record written ahead "
          "and gone",
          "[service_loop]")
{
    LoopLab lab;
    lab.jobs = jobs_text({job_text("job-1", 5, 3, 2)});
    lab.on_run = [&](const rp::Job& job, const rp::JobCallbacks& callbacks) {
        CHECK(job.sample_mail == 5);
        CHECK(job.sample_sp == 3);
        CHECK(job.sample_od == 2);
        // The record is on disk before the pipeline is called.
        CHECK(lab.on_disk() ==
              rp::new_run_record("job-1", std::string{"client-7"}, lab.config, lab.wall0));
        lab.t += 1s;
        CHECK(callbacks.on_run_started(LoopLab::run_started(job.run_id)));
        callbacks.on_session_opened("s1");
        callbacks.on_session_opened("s2");
        lab.t += 9s;
        CHECK(callbacks.before_restore_request());
        lab.t += 200s;
        lab.queued.insert(job.run_id);
        return LoopLab::ended_run(JobFolder::queued);
    };

    lab.run();

    CHECK(lab.lines ==
          Lines{kStarted,
                "info run job-1: starting (mail 5, sharepoint 3, onedrive 2, point latest)",
                "info run job-1: ended pass; queued", "info sent job-1",
                "info skipped job-1: already sent"});
    CHECK(lab.calls == Lines{"read record", "heartbeat", "read record", "read jobs",
                             "write record", "run job-1", "write record", "write record",
                             "write record", "write record", "flush", "remove record", "flush",
                             "read record", "read jobs", "flush"});
    REQUIRE(lab.writes.size() == 5);
    const rp::RunningRecord last = rp::parse_record(lab.writes[4]).value();
    CHECK(last.kind == rp::RecordKind::run);
    CHECK(last.client_id == "client-7");
    CHECK(last.taken_at == "2026-10-08T10:00:00.000Z");
    CHECK(last.started_at == "2026-10-08T10:00:02.500Z");
    CHECK(last.sessions == Lines{"s1", "s2"});
    CHECK(last.restore_requested);
    CHECK(last.restore_requested_at == "2026-10-08T10:00:10.000Z");
    CHECK_FALSE(last.close_as);
    CHECK(lab.sent.contains("job-1"));
    CHECK(lab.queued.empty());
    CHECK_FALSE(lab.has_record());
    // The run took longer than the interval: the next poll came at once.
    CHECK(lab.waited == std::vector<std::chrono::milliseconds>{60s});
    CHECK(lab.heartbeats.size() == 1);
    CHECK_FALSE(lab.last_error);
}
