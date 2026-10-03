#include <rp/test_command.hpp>

#include <rp/checker.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/expected_set.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_selector.hpp>
#include <rp/step_timer.hpp>
#include <rp/version.hpp>

#include "atomic_file.hpp"
#include "command_config.hpp"
#include "path_utf8.hpp"
#include "run_pipeline.hpp"
#include "text_table.hpp"
#include "text_util.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace rp {

namespace {

namespace verification = rp::verification;
using nlohmann::json;

constexpr std::string_view kSummaryFormat = "rp.run-summary.v0";

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

// An item's REASON, fixed words only: never ItemCheck::reason, whose
// office-v1 note names a part inside a tenant file.
std::string reason_cell(const verification::ItemCheck& item)
{
    switch (item.outcome) {
    case verification::CheckOutcome::match:
        break;
    case verification::CheckOutcome::mismatch:
        return cell_or_dash(joined(item.mismatches, ","));
    case verification::CheckOutcome::missing:
        return "missing";
    case verification::CheckOutcome::error:
        return cell_or_dash(item.error_code);
    }
    return "-";
}

// test's table (W3.6 point 4): one row per expected item, after the check.
std::string format_check_table(const verification::ExpectedSet& expected,
                               const verification::CheckResult& check,
                               const verification::RunVerdict& verdict)
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
                         verdict_cell(verdict, item.index), reason_cell(item),
                         item.found ? std::to_string(item.ms) : std::string{"-"}}});
    }
    return '\n' + format_table(rows);
}

// The --json file's content (W3.6 point 5): every top-level key always there,
// null where a step didn't run. What it holds of the tenant is listed in
// docs/verification.md.
json summary_json(const RunSummary& run)
{
    const auto text_or_null = [](const std::optional<std::string>& text) {
        return text ? json(*text) : json();
    };
    json summary = json::object();
    summary["format"] = kSummaryFormat;
    summary["worker_version"] = version();
    summary["command"] = "test";
    summary["run_id"] = run.run_id;
    summary["started_at"] = text_or_null(run.started_at);
    summary["ended_at"] = text_or_null(run.ended_at);
    summary["restore_point"] =
        run.restore_point ? json{{"id", run.restore_point->id},
                                 {"backup_time_raw", run.restore_point->backup_time}}
                          : json();
    summary["veeam_org_name"] = run.veeam_org_name;
    summary["sample"] = run.sample ? sampling::to_json(*run.sample) : json();
    summary["expected"] = run.expected ? verification::to_json(*run.expected) : json();
    summary["restore"] = run.restore ? verification::to_json(*run.restore) : json();
    summary["check"] = run.check ? verification::to_json(*run.check) : json();
    summary["status"] = run.verdict ? verification::to_json(*run.verdict) : json();
    summary["cleanup"] = run.cleanup ? to_json(*run.cleanup) : json();
    summary["timings"] = run.timings ? timing::to_json(*run.timings) : json();
    summary["exit_code"] = run.exit_code;
    return summary;
}

// The --json path, checked before the secrets: a UTF-8 path, a plain file
// name (no ':' naming an NTFS stream, nothing Windows refuses), no file there
// yet, in a folder that exists. Throws ConfigError otherwise. Anything but a
// clean "not found" counts as a file there (a device such as NUL, a file it
// may not read): a path the writer can't use costs no run (W3.6 review).
std::filesystem::path check_json_path(std::string_view arg)
{
    const std::string shown = "--json " + table_cell(arg) + ": ";
    std::optional<std::filesystem::path> path = path_from_utf8(arg);
    if (!path) {
        throw ConfigError("--json", shown + "not a UTF-8 path");
    }
    if (!is_plain_file_name(path->filename().native())) {
        throw ConfigError("--json", shown + "not a file name");
    }
    std::error_code ec;
    if (std::filesystem::symlink_status(*path, ec).type() != std::filesystem::file_type::not_found) {
        throw ConfigError("--json", shown + "the file already exists");
    }
    const std::filesystem::path folder =
        path->has_parent_path() ? path->parent_path() : std::filesystem::path{L"."};
    if (!std::filesystem::is_directory(folder, ec)) {
        throw ConfigError("--json", shown + "the folder doesn't exist");
    }
    return std::move(*path);
}

} // namespace

int run_test_command(std::span<const std::string_view> args, std::ostream& out,
                     std::ostream& err, const RestoreCommandEnv& env)
{
    PipelineArgs parsed;
    const std::optional<CommandOptions> options =
        parse_options(args, {"--mail", "--sp", "--od", "--point", "--run-id", "--canary-cursor",
                             "--manifest", "--config", "--record", "--json"});
    // An empty --json value is a missing one: no file can have that name.
    const auto json_empty = [&] {
        const std::optional<std::string_view> value = options->value("--json");
        return value && value->empty();
    };
    if (!options || !parse_pipeline_args(*options, parsed) || json_empty()) {
        err << kCliUsage;
        return exit_code::usage;
    }
    const std::optional<std::string_view> json_arg = options->value("--json");
    std::optional<std::filesystem::path> json_path;

    Presentation presentation;
    presentation.command = "test";
    presentation.restore_rows = false;
    presentation.check_table = format_check_table;
    if (json_arg) {
        presentation.after_config = [&] { json_path = check_json_path(*json_arg); };
        // The summary goes last, after the timings: its write never changes
        // the status, only an exit code of 0 (W3.6 point 5).
        presentation.on_run = [&](const RunSummary& run, int code, bool output_lost) {
            const std::string shown = table_cell(*json_arg);
            bool written = false;
            try {
                const std::string text =
                    summary_json(run).dump(2, ' ', false, json::error_handler_t::replace) + '\n';
                written = env.write_summary ? env.write_summary(*json_path, text)
                                            : write_file_atomically(*json_path, text);
            } catch (...) {
                written = false;
            }
            if (!written) {
                err << "json error: " << shown << ": could not be written\n";
                return code == exit_code::ok ? exit_code::config : code;
            }
            if (!output_lost) {
                out << "wrote " << shown << '\n';
                out.flush();
            }
            return code;
        };
    }
    std::shared_ptr<FixtureRecorder> recorder;
    const int code = run_pipeline(parsed, out, err, env, recorder, presentation);
    return finish_recording(recorder.get(), out, err, code);
}

} // namespace rp
