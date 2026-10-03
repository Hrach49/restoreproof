#include <rp/restore_command.hpp>

#include <rp/checker.hpp>
#include <rp/cleaner.hpp>
#include <rp/cli.hpp>
#include <rp/expected_set.hpp>
#include <rp/run_lock.hpp>
#include <rp/run_status.hpp>
#include <rp/secrets.hpp>

#include "command_config.hpp"
#include "duration_text.hpp"
#include "run_pipeline.hpp"
#include "text_table.hpp"
#include "text_util.hpp"

#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <ostream>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

namespace {

namespace verification = rp::verification;

// restore's check table (W3.2): one row per expected item, KIND SOURCE NAME
// OUTCOME FIELDS DUP MS.
std::string format_check_table(const verification::ExpectedSet& expected,
                               const verification::CheckResult& check,
                               const verification::RunVerdict&)
{
    if (check.items.empty()) {
        return {};
    }
    std::vector<TableRow> rows{{"  ", {"KIND", "SOURCE", "NAME", "OUTCOME", "FIELDS", "DUP", "MS"}}};
    for (const verification::ItemCheck& item : check.items) {
        const verification::ExpectedItem& want = expected.items.at(item.index);
        std::string fields = joined(item.mismatches, ",");
        if (fields.empty()) {
            fields = item.error_code;
        }
        rows.push_back(
            {"  ",
             {kind_name(item.kind), std::string{verification::to_string(want.source)},
              cell_or_dash(want.mail ? want.mail->subject : want.file->name),
              std::string{verification::to_string(item.outcome)}, cell_or_dash(fields),
              item.duplicate ? std::format("{} copies", item.copies) : std::string{"-"},
              item.found ? std::to_string(item.ms) : std::string{"-"}}});
    }
    return '\n' + format_table(rows);
}

} // namespace

bool RunCleanup::cleanup_ok() const noexcept
{
    if (restore_may_still_run) {
        return false;
    }
    if (after) {
        return after->ok();
    }
    if (restore_sent) {
        return false;
    }
    return before && before->ok();
}

nlohmann::json to_json(const RunCleanup& cleanup)
{
    return {{"cleanup_ok", cleanup.cleanup_ok()},
            {"restore_may_still_run", cleanup.restore_may_still_run},
            {"before", cleanup.before ? graph::to_json(*cleanup.before) : nlohmann::json()},
            {"after", cleanup.after ? graph::to_json(*cleanup.after) : nlohmann::json()}};
}

std::string make_run_id()
{
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    std::random_device random;
    return std::format("rp-{:%Y%m%dT%H%M%S}Z-{:08x}", now, static_cast<std::uint32_t>(random()));
}

std::string format_elapsed(std::chrono::nanoseconds elapsed)
{
    return elapsed < std::chrono::nanoseconds::zero()
               ? std::string{"-"}
               : format_hms(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
}

RestoreCommandEnv default_restore_command_env()
{
    RestoreCommandEnv env;
    env.default_config_path = default_config_path;
    env.load_secrets = load_secrets_from_env;
    env.connector_options.logger = make_command_logger();
    env.take_run_lock = try_take_restore_targets_lock;
    return env;
}

int run_restore_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const RestoreCommandEnv& env)
{
    PipelineArgs parsed;
    const std::optional<CommandOptions> options =
        parse_options(args, {"--mail", "--sp", "--od", "--point", "--run-id", "--canary-cursor",
                             "--manifest", "--config", "--record"});
    if (!options || !parse_pipeline_args(*options, parsed)) {
        err << kCliUsage;
        return exit_code::usage;
    }
    Presentation presentation;
    presentation.command = "restore";
    presentation.restore_rows = true;
    presentation.check_table = format_check_table;
    std::shared_ptr<FixtureRecorder> recorder;
    const int code = run_pipeline(parsed, out, err, env, recorder, presentation);
    return finish_recording(recorder.get(), out, err, code);
}

} // namespace rp
