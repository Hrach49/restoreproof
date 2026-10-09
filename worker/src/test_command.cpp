#include <rp/test_command.hpp>

#include <rp/checker.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/expected_set.hpp>
#include <rp/run_status.hpp>

#include "atomic_file.hpp"
#include "command_config.hpp"
#include "path_utf8.hpp"
#include "run_pipeline.hpp"
#include "text_table.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

namespace {

namespace verification = rp::verification;

// An item's VERDICT: "-" unless the item verdicts decided the run (rows 5 to
// 8 of the status table: every item verified, failed or unchecked).
std::string verdict_cell(const verification::RunVerdict& verdict, std::size_t index)
{
    const bool decided =
        verdict.items > 0 &&
        verdict.verified() + verdict.failed.size() + verdict.unchecked.size() == verdict.items;
    if (!decided) {
        return "-";
    }
    if (std::ranges::find(verdict.failed, index) != verdict.failed.end()) {
        return "failed";
    }
    for (const verification::UncheckedItem& item : verdict.unchecked) {
        if (item.index == index) {
            return "unchecked " + item.error_code;
        }
    }
    return "verified";
}

// An item's REASON, fixed words only, shorter than ItemCheck::reason's. A
// missing item the backup said the restore point doesn't hold is
// "not_in_backup" (Q3.1).
std::string reason_cell(const verification::ItemCheck& item,
                        const connector::RestoreResult* restore)
{
    switch (item.outcome) {
    case verification::CheckOutcome::match:
        break;
    case verification::CheckOutcome::mismatch:
        return cell_or_dash(joined(item.mismatches, ","));
    case verification::CheckOutcome::missing:
        if (restore && item.index < restore->items.size() &&
            restore->items[item.index].outcome == connector::ItemOutcome::not_in_backup) {
            return "not_in_backup";
        }
        return "missing";
    case verification::CheckOutcome::error:
        return cell_or_dash(item.error_code);
    }
    return "-";
}

// test's table (W3.6 point 4): one row per expected item, after the check.
std::string format_check_table(const verification::ExpectedSet& expected,
                               const verification::CheckResult& check,
                               const verification::RunVerdict& verdict,
                               const connector::RestoreResult* restore)
{
    if (check.items.empty()) {
        return {};
    }
    std::vector<TableRow> rows{
        {"  ", {"TYPE", "NAME", "EXPECTED", "FOUND", "MATCH", "VERDICT", "REASON", "MS"}}};
    for (const verification::ItemCheck& item : check.items) {
        const verification::ExpectedItem& want = expected.items.at(item.index);
        rows.push_back({"  ",
                        {kind_name(item.kind),
                         cell_or_dash(want.mail ? want.mail->subject : want.file->name),
                         std::string{verification::to_string(want.expected_kind)},
                         item.found ? "yes" : "no",
                         std::string{verification::to_string(item.outcome)},
                         verdict_cell(verdict, item.index), reason_cell(item, restore),
                         item.found ? std::to_string(item.ms) : std::string{"-"}}});
    }
    return '\n' + format_table(rows);
}

// The --json path, checked before the secrets: a UTF-8 path the writer could
// write now (rp::check_new_file, which makes and drops the writer's own temp
// file): a path the writer can't use costs no run (W3.6 review, PR #153
// review). Throws ConfigError otherwise.
std::filesystem::path check_json_path(std::string_view arg)
{
    const std::string shown = "--json " + table_cell(arg) + ": ";
    std::optional<std::filesystem::path> path = path_from_utf8(arg);
    if (!path) {
        throw ConfigError("--json", shown + "not a UTF-8 path");
    }
    switch (check_new_file(*path)) {
    case NewFileCheck::ok:
        return std::move(*path);
    case NewFileCheck::not_a_file_name:
        throw ConfigError("--json", shown + "not a file name");
    case NewFileCheck::exists:
        throw ConfigError("--json", shown + "the file already exists");
    case NewFileCheck::no_folder:
        throw ConfigError("--json", shown + "the folder doesn't exist");
    case NewFileCheck::cannot_write:
        break;
    }
    throw ConfigError("--json", shown + "a file can't be written there");
}

} // namespace

Presentation test_presentation()
{
    Presentation presentation;
    presentation.command = "test";
    presentation.restore_rows = false;
    presentation.check_table = format_check_table;
    return presentation;
}

int run_test_command(std::span<const std::string_view> args, std::ostream& out,
                     std::ostream& err, const RestoreCommandEnv& env)
{
    PipelineArgs parsed;
    const std::optional<CommandOptions> options =
        parse_options(args, {"--mail", "--sp", "--od", "--point", "--run-id", "--canary-cursor",
                             "--manifest", "--config", "--vault", "--record", "--profile-file",
                             "--json", "--evidence", "--outbox"});
    // An empty --json or --evidence value is a missing one: no file or folder
    // can have that name. And one or the other (W4.2 point 7): the run
    // folder's result.json is the --json file.
    const auto files_wrong = [&] {
        const std::optional<std::string_view> json = options->value("--json");
        const std::optional<std::string_view> evidence = options->value("--evidence");
        // W4.6: --outbox queues the run folder, so only with --evidence.
        const std::optional<std::string_view> outbox = options->value("--outbox");
        return (json && json->empty()) || (evidence && evidence->empty()) || (json && evidence) ||
               (outbox && (outbox->empty() || !evidence));
    };
    if (!options || !parse_pipeline_args(*options, parsed) || files_wrong()) {
        err << kCliUsage;
        return exit_code::usage;
    }
    parsed.evidence = options->value("--evidence");
    parsed.outbox = options->value("--outbox");
    const std::optional<std::string_view> json_arg = options->value("--json");
    std::optional<std::filesystem::path> json_path;
    std::shared_ptr<FixtureRecorder> recorder;

    Presentation presentation = test_presentation();
    if (json_arg) {
        presentation.after_config = [&] { json_path = check_json_path(*json_arg); };
        // The result goes last, after the timings: the file is exactly its
        // canonical text (W4.1 points 1, 4 and 5). Neither a result that
        // isn't valid, for which no file is written, nor a failed write ever
        // changes the status, only an exit code of 0 (W3.6 point 5).
        presentation.on_run = [&](const RunSummary& run, int code, bool output_lost) {
            const std::string shown = table_cell(*json_arg);
            const auto failed = [&](std::string_view why) {
                err << "json error: " << shown << ": " << why << '\n';
                return code == exit_code::ok ? exit_code::config : code;
            };
            if (!run.result) {
                return failed("the result isn't valid restoreproof.result.v1; no file was "
                              "written");
            }
            bool written = false;
            try {
                written = env.write_summary ? env.write_summary(*json_path, *run.result)
                                            : write_file_atomically(*json_path, *run.result);
            } catch (...) {
                written = false;
            }
            if (!written) {
                return failed("could not be written");
            }
            // The file's line. Lost, it changes nothing, like the timings'
            // table (W3.6 review point 4): the file is written. That holds
            // for a stream that throws as for one that only sets its state.
            if (!output_lost) {
                try {
                    out << "wrote " << shown << '\n';
                    out.flush();
                } catch (...) {
                }
            }
            return code;
        };
    }
    const int code = run_pipeline(parsed, out, err, env, recorder, presentation);
    return finish_recording(recorder.get(), out, err, code);
}

} // namespace rp
