#pragma once

// The run `rpworker restore` (W2.8, W3.1 to W3.5) and `rpworker test` (W3.6)
// share: one pipeline, so one guard, one mutex, one status table and one
// cleanup (docs/decisions.md 2026-10-03, W3.6 point 4). Each command keeps
// its own parser and says through a Presentation where its output differs:
// restore's per-item restore rows and check table, test's table after the
// check and its --json file. What the run does and prints is documented on
// run_restore_command (rp/restore_command.hpp).

#include "command_config.hpp"

#include <rp/canary_manifest.hpp>
#include <rp/checker.hpp>
#include <rp/connector.hpp>
#include <rp/expected_set.hpp>
#include <rp/recording_http_client.hpp>
#include <rp/restore_command.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_selector.hpp>
#include <rp/step_timer.hpp>

#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace rp {

// The command line both commands take, as given (UTF-8).
struct PipelineArgs {
    std::optional<int> mail;
    std::optional<int> sharepoint;
    std::optional<int> onedrive;
    std::optional<std::string_view> point; // an ID; nullopt = latest
    std::optional<std::string_view> run_id;
    std::optional<sampling::CanaryCursor> cursor;
    std::optional<std::string_view> manifest;
    std::optional<std::string_view> config;
    std::optional<std::string_view> record;
};

// Whether each of those options in `options` (--mail --sp --od --point
// --run-id --canary-cursor --manifest --config --record, each with its
// value) is well-formed by the rules on run_restore_command, each copied
// into `parsed`.
bool parse_pipeline_args(const CommandOptions& options, PipelineArgs& parsed);

// What one run produced, handed on once at its end (W3.6 point 4; W4.1 signs
// it). The pointers are borrowed for the call only; null where a step didn't
// run.
struct RunSummary {
    std::string run_id;
    // "YYYY-MM-DDTHH:MM:SS.mmmZ" from connector_options.wall_now (else the
    // system clock), read where `total` starts and ends; nullopt when the
    // clock failed.
    std::optional<std::string> started_at;
    std::optional<std::string> ended_at;
    const connector::RestorePoint* restore_point = nullptr;
    std::string veeam_org_name;
    const sampling::SampleRecord* sample = nullptr;
    const verification::ExpectedSet* expected = nullptr;
    const connector::RestoreResult* restore = nullptr;
    const verification::CheckResult* check = nullptr;
    const verification::RunVerdict* verdict = nullptr; // null only after an unexpected failure
    // Null when no clean ran: the run stopped before the clean before.
    const RunCleanup* cleanup = nullptr;
    const timing::RunTimings* timings = nullptr;
};

// Where a command's output differs from the other's.
struct Presentation {
    // The recording's label, "rpworker <version> <command> --record".
    std::string_view command;
    // Restore's per-item rows after the restore (KIND SOURCE NAME OUTCOME
    // SESSION ELAPSED MESSAGE), before the session rows.
    bool restore_rows = true;
    // The check's table, a paragraph with its blank line before it, or "" for
    // no rows; printed after the check and before its count line. `verdict`
    // is the run's, decided from that check.
    std::function<std::string(const verification::ExpectedSet&, const verification::CheckResult&,
                              const verification::RunVerdict&, const connector::RestoreResult*)>
        check_table;
    // Called once the config is read and before the secrets; what it throws
    // is handled as the config's errors are (a ConfigError: "config error:
    // <what()>", exit 1). Null = nothing.
    std::function<void()> after_config;
    // Called once, last, by every run that printed its run line, after the
    // timings and env.on_timings, with `code` the exit code so far and
    // whether stdout was lost; returns the exit code. What it throws keeps
    // `code`. Null = nothing.
    std::function<int(const RunSummary&, int code, bool output_lost)> on_run;
};

// The run but for what --record wrote, which the command prints last:
// `recorder` is set once the recording is open. Returns an rp::exit_code.
// No exception escapes.
int run_pipeline(const PipelineArgs& args, std::ostream& out, std::ostream& err,
                 const RestoreCommandEnv& env, std::shared_ptr<FixtureRecorder>& recorder,
                 const Presentation& presentation);

// "<blank line>\ncheck: <a> match, <b> mismatch, <c> missing, <d> error\n":
// the check's count line, the same in both commands.
std::string format_check_counts(const verification::CheckResult& check);

// The text table helpers' cell for connector or tenant text: "-" when empty,
// else table_cell(text) (a control character becomes a space).
std::string cell_or_dash(std::string_view text);

// The kind's name, "mail", "sharepoint" or "onedrive".
std::string kind_name(connector::ItemKind kind);

} // namespace rp
