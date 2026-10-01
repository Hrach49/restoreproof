#include <rp/restore_command.hpp>

#include <rp/canary_manifest.hpp>
#include <rp/cli.hpp>
#include <rp/client_assertion.hpp>
#include <rp/graph_client.hpp>
#include <rp/http_client.hpp>
#include <rp/sample_rng.hpp>
#include <rp/sample_selector.hpp>

#include "command_config.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"
#include "text_util.hpp"
#include "veeam_time.hpp"

#include <spdlog/logger.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp {

namespace {

namespace sampling = rp::sampling;
using connector::ItemKind;

constexpr std::size_t kMaxSizeDigits = 3;
constexpr int kMaxSampleSize = 100;
constexpr std::size_t kMaxCursorDigits = 6;
constexpr std::size_t kMaxPointIdLength = 128;
constexpr std::string_view kLatest = "latest";
constexpr std::string_view kManifestFile = "seed-manifest.json";

// The command line, as given (UTF-8).
struct RestoreArgs {
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

bool all_digits(std::string_view text) noexcept
{
    return std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

// 1 to `max_digits` ASCII digits, as a number.
std::optional<std::uint32_t> parse_number(std::string_view text, std::size_t max_digits)
{
    if (text.empty() || text.size() > max_digits || !all_digits(text)) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (const char c : text) {
        value = value * 10 + static_cast<std::uint32_t>(c - '0');
    }
    return value;
}

std::optional<int> parse_size(std::string_view text)
{
    const std::optional<std::uint32_t> n = parse_number(text, kMaxSizeDigits);
    if (!n || *n > static_cast<std::uint32_t>(kMaxSampleSize)) {
        return std::nullopt;
    }
    return static_cast<int>(*n);
}

// "m,s,o": three numbers, commas between, nothing else.
std::optional<sampling::CanaryCursor> parse_cursor(std::string_view text)
{
    std::optional<std::uint32_t> parts[3];
    for (std::size_t i = 0; i < 3; ++i) {
        const std::size_t comma = i < 2 ? text.find(',') : text.size();
        if (comma == std::string_view::npos) {
            return std::nullopt;
        }
        parts[i] = parse_number(text.substr(0, comma), kMaxCursorDigits);
        if (!parts[i]) {
            return std::nullopt;
        }
        text.remove_prefix(i < 2 ? comma + 1 : comma);
    }
    return sampling::CanaryCursor{*parts[0], *parts[1], *parts[2]};
}

// 1 to 128 ASCII letters, digits and hyphens: safe to echo in a message.
bool is_point_id(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= kMaxPointIdLength &&
           std::ranges::all_of(text, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      c == '-';
           });
}

bool valid_run_id(std::string_view text)
{
    try {
        sampling::check_run_id(text);
        return true;
    } catch (const std::invalid_argument&) {
        return false;
    }
}

// Whether `args` are the options in any order, each at most once and with
// its value, every value well-formed.
bool parse_args(std::span<const std::string_view> args, RestoreArgs& parsed)
{
    const std::optional<CommandOptions> options =
        parse_options(args, {"--mail", "--sp", "--od", "--point", "--run-id", "--canary-cursor",
                             "--manifest", "--config", "--record"});
    if (!options) {
        return false;
    }
    const auto size_option = [&](std::string_view name, std::optional<int>& target) {
        if (const std::optional<std::string_view> value = options->value(name)) {
            target = parse_size(*value);
            return target.has_value();
        }
        return true;
    };
    if (!size_option("--mail", parsed.mail) || !size_option("--sp", parsed.sharepoint) ||
        !size_option("--od", parsed.onedrive)) {
        return false;
    }
    parsed.point = options->value("--point");
    // `latest`, in any case, is a point ID too.
    if (parsed.point && !is_point_id(*parsed.point)) {
        return false;
    }
    parsed.run_id = options->value("--run-id");
    if (parsed.run_id && !valid_run_id(*parsed.run_id)) {
        return false;
    }
    if (const std::optional<std::string_view> cursor = options->value("--canary-cursor")) {
        parsed.cursor = parse_cursor(*cursor);
        if (!parsed.cursor) {
            return false;
        }
    }
    parsed.manifest = options->value("--manifest");
    parsed.config = options->value("--config");
    parsed.record = options->value("--record");
    return true;
}

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

// The manifest --manifest names, or seed-manifest.json beside the config file.
std::filesystem::path manifest_path(std::optional<std::string_view> manifest_arg,
                                    const std::filesystem::path& config_path)
{
    if (!manifest_arg) {
        return config_path.parent_path() / kManifestFile;
    }
    std::optional<std::filesystem::path> path = path_from_utf8(*manifest_arg);
    if (!path) {
        throw ConfigError("", "the --manifest path is not valid UTF-8");
    }
    return std::move(*path);
}

// The restore point --point names, or the newest; nullopt with the message on
// `err` when there is none.
const connector::RestorePoint* pick_point(const std::vector<connector::RestorePoint>& points,
                                          std::optional<std::string_view> id, std::ostream& err)
{
    if (points.empty()) {
        err << "restore error: no restore points for veeam_org_name\n";
        return nullptr;
    }
    if (!id || ascii_iequals(*id, kLatest)) {
        return &points.front();
    }
    const auto it = std::ranges::find_if(
        points, [&](const connector::RestorePoint& p) { return ascii_iequals(p.id, *id); });
    if (it == points.end()) {
        // The ID passed is_point_id: safe to echo.
        err << "restore error: restore point " << *id << " not found for veeam_org_name\n";
        return nullptr;
    }
    return &*it;
}

std::string cursor_text(std::uint32_t m, std::uint32_t s, std::uint32_t o)
{
    return std::format("{},{},{}", m, s, o);
}

std::string of(int taken, int wanted)
{
    return std::format("{} of {}", taken, wanted);
}

// "canary shortfall", "random shortfall", both, or "" for none.
std::string shortfall(const sampling::KindRecord& k)
{
    const bool canary_short = static_cast<int>(k.canary_ids.size()) < (k.requested + 1) / 2;
    const bool random_short = k.random_taken < k.random_wanted;
    return canary_short && random_short ? "canary and random shortfall"
           : canary_short               ? "canary shortfall"
           : random_short               ? "random shortfall"
                                        : "";
}

TableRow kind_row(ItemKind kind, const sampling::KindRecord& k)
{
    std::vector<std::string> cells{kind_name(kind), std::to_string(k.requested),
                                   of(static_cast<int>(k.canary_ids.size()), (k.requested + 1) / 2),
                                   of(k.random_taken, k.random_wanted)};
    if (std::string note = shortfall(k); !note.empty()) {
        cells.push_back(std::move(note));
    }
    return {"  ", std::move(cells)};
}

// Why an empty sample is empty: "<kind>: <shortfall>" for each type asked for.
std::string empty_sample_reason(const sampling::SampleRecord& r)
{
    const std::pair<ItemKind, const sampling::KindRecord*> kinds[] = {
        {ItemKind::mail, &r.mail}, {ItemKind::sharepoint, &r.sharepoint},
        {ItemKind::onedrive, &r.onedrive}};
    std::string text;
    for (const auto& [kind, k] : kinds) {
        if (k->requested > 0) {
            text += (text.empty() ? "" : "; ") + kind_name(kind) + ": " + shortfall(*k);
        }
    }
    return text;
}

// What is printed once the run ID exists, before the sample is chosen
// (which browses Veeam and can fail).
std::string format_intro(const std::string& org, const connector::RestorePoint& point,
                         const std::string& run_id)
{
    return std::format("restore point {}  {}  (veeam_org_name {})\nrun {}  seed {}\n",
                       table_cell(point.backup_time), table_cell(point.id), table_cell(org),
                       run_id, sampling::seed_hex(sampling::seed_from_run_id(run_id)));
}

// What is printed once the sample is chosen, before the restore.
std::string format_sample(const sampling::Selection& selection, std::size_t items)
{
    const sampling::SampleRecord& r = selection.record;
    std::string text = std::format(
        "canary cursor {} -> {}\n",
        cursor_text(r.mail.cursor, r.sharepoint.cursor, r.onedrive.cursor),
        cursor_text(r.mail.cursor_next, r.sharepoint.cursor_next, r.onedrive.cursor_next));
    text += format_table({{"  ", {"KIND", "REQUESTED", "CANARIES", "RANDOM", "NOTE"}},
                          kind_row(ItemKind::mail, r.mail),
                          kind_row(ItemKind::sharepoint, r.sharepoint),
                          kind_row(ItemKind::onedrive, r.onedrive)});
    if (items > 0) {
        text += std::format("restoring {} item(s) ...\n", items);
    }
    return text;
}

std::string cell_or_dash(std::string_view text)
{
    return text.empty() ? std::string{"-"} : table_cell(text);
}

// "H:MM:SS" for a whole number of seconds; a negative one is "-".
std::string format_seconds(std::int64_t seconds)
{
    if (seconds < 0) {
        return "-";
    }
    return std::format("{}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60);
}

// A session's end - start, cut to whole seconds; "-" when either doesn't read
// or it's negative. Whole seconds and fractions are subtracted apart: two
// times in nanoseconds can be further apart (1678 to 2261) than a signed
// 64-bit count of nanoseconds holds.
std::string session_elapsed(const connector::RestoreSessionResult& session)
{
    const std::optional<VeeamTime> start = parse_veeam_time(session.started_at);
    const std::optional<VeeamTime> end = parse_veeam_time(session.ended_at);
    if (!start || !end) {
        return "-";
    }
    const auto start_s = std::chrono::floor<std::chrono::seconds>(*start);
    const auto end_s = std::chrono::floor<std::chrono::seconds>(*end);
    const std::int64_t whole = (end_s - start_s).count();
    // Each fraction is in [0 s, 1 s), so their difference is in (-1 s, 1 s).
    const bool fraction_back = (*end - end_s) < (*start - start_s);
    return format_seconds(fraction_back ? whole - 1 : whole);
}

// Per type: how many items were selected, and how many of those (the first)
// are canaries.
struct KindCounts {
    std::size_t selected = 0;
    std::size_t canaries = 0;
};

std::map<ItemKind, KindCounts> kind_counts(const sampling::Selection& s)
{
    return {{ItemKind::mail, {s.mail.size(), s.record.mail.canary_ids.size()}},
            {ItemKind::sharepoint, {s.sharepoint.size(), s.record.sharepoint.canary_ids.size()}},
            {ItemKind::onedrive, {s.onedrive.size(), s.record.onedrive.canary_ids.size()}}};
}

// The tables and the status line, after the restore.
std::string format_result(const connector::RestoreResult& result,
                          const sampling::Selection& selection, std::chrono::nanoseconds total)
{
    // Each session's ELAPSED, worked out once: its items' rows repeat it.
    std::vector<std::string> elapsed;
    std::map<std::string, std::size_t> session_at;
    for (const connector::RestoreSessionResult& s : result.sessions) {
        session_at.emplace(s.id, elapsed.size());
        elapsed.push_back(session_elapsed(s));
    }
    std::string text;
    if (!result.items.empty()) {
        std::vector<TableRow> rows{
            {"  ", {"KIND", "SOURCE", "NAME", "OUTCOME", "SESSION", "ELAPSED", "MESSAGE"}}};
        const std::map<ItemKind, KindCounts> counts = kind_counts(selection);
        std::map<ItemKind, std::size_t> seen;
        for (const connector::ItemRestoreResult& item : result.items) {
            const std::size_t at = seen[item.kind]++;
            const KindCounts& count = counts.at(item.kind);
            // Canaries first in each type (the sampler's order); an item the
            // spec didn't have is "-".
            const std::string source = at >= count.selected   ? "-"
                                       : at < count.canaries ? "canary"
                                                             : "random";
            std::string outcome{connector::to_string(item.outcome)};
            if (item.infrastructure) {
                outcome += " (infrastructure)";
            }
            const auto session = session_at.find(item.session_id);
            rows.push_back({"  ",
                            {kind_name(item.kind), source, cell_or_dash(item.name), outcome,
                             cell_or_dash(item.session_id),
                             session == session_at.end() ? std::string{"-"}
                                                         : elapsed[session->second],
                             cell_or_dash(item.message)}});
        }
        text += '\n' + format_table(rows);
    }
    if (!result.sessions.empty()) {
        std::vector<TableRow> rows{
            {"  ", {"SESSION", "KIND", "RESULT", "RESTORED", "STARTED", "ENDED", "ELAPSED"}}};
        for (std::size_t i = 0; i < result.sessions.size(); ++i) {
            const connector::RestoreSessionResult& s = result.sessions[i];
            rows.push_back({"  ",
                            {cell_or_dash(s.id), kind_name(s.kind), cell_or_dash(s.result),
                             of(s.items_restored, s.items_sent), cell_or_dash(s.started_at),
                             cell_or_dash(s.ended_at), elapsed[i]}});
        }
        text += '\n' + format_table(rows);
    }
    text += std::format("\nstatus {}: {} of {} item(s) restored in {}\n",
                        connector::to_string(result.status), result.items_restored,
                        result.items_sent, format_elapsed(total));
    return text;
}

// A failed write or flush (a full disk, a closed pipe) is never a success.
void flush_or_throw(std::ostream& out)
{
    if (!out.flush()) {
        throw std::runtime_error("writing the output failed");
    }
}

// The exit code of a restore that returned, with its line on `err`: an item
// that failed for an infrastructure reason, or nothing sent, is an error (4),
// never a restore failure; 5 only for partial or failed; 0 for succeeded.
int restore_exit_code(const connector::RestoreResult& result, std::ostream& err)
{
    const auto infrastructure =
        std::ranges::count_if(result.items, [](const connector::ItemRestoreResult& item) {
            return item.infrastructure && item.outcome != connector::ItemOutcome::restored;
        });
    if (infrastructure > 0) {
        err << "restore error: " << infrastructure
            << " item(s) failed for an infrastructure reason (Veeam couldn't reach Microsoft "
               "365, lacked permissions or was throttled); this is an error, not a restore "
               "failure\n";
        return exit_code::service;
    }
    if (result.status == connector::RestoreStatus::not_run) {
        err << "restore error: the restore did not run: nothing was sent (status not_run)\n";
        return exit_code::service;
    }
    return result.status == connector::RestoreStatus::succeeded ? exit_code::ok
                                                                : exit_code::restore;
}

// what() is safe to print: connector::Error's never holds a credential.
int report(std::ostream& err, std::string_view prefix, const std::exception& e, int code)
{
    err << prefix << e.what() << '\n';
    return code;
}

// Opens and checks the Graph certificate as restore_sample will, so a bad one
// is said before any Veeam call. Nothing is logged: restore_sample's own load
// warns of a certificate about to expire.
void check_graph_certificate(const Secrets& secrets, const connector::ConnectorOptions& options)
{
    const auto wall_now =
        options.wall_now ? options.wall_now() : std::chrono::system_clock::now();
    graph::certificate_from_secrets(secrets, wall_now,
                                    std::make_shared<spdlog::logger>("rp-restore-certificate"));
}

} // namespace

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
               : format_seconds(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
}

RestoreCommandEnv default_restore_command_env()
{
    RestoreCommandEnv env;
    env.default_config_path = default_config_path;
    env.load_secrets = load_secrets_from_env;
    env.connector_options.logger = make_command_logger();
    return env;
}

namespace {

// The connector's options with every HTTP client it makes recorded: Veeam's
// under "veeam", Graph's (the target guard's) under "graph". A null maker is
// the connector's own default, made here so it can be wrapped.
connector::ConnectorOptions record_connector(connector::ConnectorOptions options,
                                             const std::shared_ptr<FixtureRecorder>& recorder)
{
    options.make_http = [inner = options.make_http,
                         recorder](const HttpClientOptions& http) -> std::unique_ptr<IHttpClient> {
        return recorded(inner ? inner(http) : std::make_unique<HttpClient>(http), recorder,
                        "veeam");
    };
    options.make_graph_http =
        [inner = options.make_graph_http,
         recorder](std::shared_ptr<spdlog::logger> logger) -> std::unique_ptr<IHttpClient> {
        return recorded(inner ? inner(logger) : graph::make_graph_http_client(std::move(logger)),
                        recorder, "graph");
    };
    return options;
}

// The command but for what --record wrote, which run_restore_command prints
// last: `recorder` is set once the recording is open.
int run_restore(std::span<const std::string_view> args, std::ostream& out, std::ostream& err,
                const RestoreCommandEnv& env, std::shared_ptr<FixtureRecorder>& recorder)
{
    RestoreArgs parsed;
    if (!parse_args(args, parsed)) {
        err << kCliUsage;
        return exit_code::usage;
    }

    std::filesystem::path config_path;
    Config config;
    Secrets secrets;
    try {
        config_path = command_config_path(parsed.config, env.default_config_path);
        config = load_config(config_path);
        secrets = env.load_secrets();
        require_veeam_secrets(secrets);
        // restore_sample opens it only after the sample is chosen, which
        // browses Veeam. An unset password is none, as for `graph list`.
        check_graph_certificate(secrets, env.connector_options);
    } catch (const ConfigError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (...) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
    }
    const sampling::SamplePlan plan{parsed.mail.value_or(config.sample_mail),
                                    parsed.sharepoint.value_or(config.sample_sp),
                                    parsed.onedrive.value_or(config.sample_od)};
    if (plan.mail == 0 && plan.sharepoint == 0 && plan.onedrive == 0) {
        err << "usage error: every sample size is 0 (--mail, --sp, --od, or config's "
               "sample_mail, sample_sp, sample_od): nothing to restore\n";
        return exit_code::usage;
    }
    const sampling::CanaryCursor cursor = parsed.cursor.value_or(sampling::CanaryCursor{});

    // Set while restore_sample runs: unless its error promises nothing was
    // sent, items may be in the targets.
    std::optional<std::string> restoring_run;
    const auto restore_note = [&](std::string_view message = {}) {
        if (restoring_run && !message.ends_with(connector::kNothingRestored)) {
            err << "restore error: the restore had started: items may be in the restore targets "
                   "(run "
                << *restoring_run << ")\n";
        }
    };
    const auto restore_failed = [&](const connector::Error& e, int code) {
        report(err, "restore error: ", e, code);
        restore_note(e.what());
        return code;
    };

    // Everything that can throw is in here, the output included, so no
    // exception escapes.
    try {
        const sampling::CanaryManifest manifest =
            sampling::load_canary_manifest(manifest_path(parsed.manifest, config_path));
        const connector::RestoreTargets targets = connector::RestoreTargets::from_config(config);
        // choose_sample's own checks, said before the connector is made: an
        // unreachable Veeam can't hide a manifest that names a restore target.
        sampling::check_manifest(manifest, targets, config.graph_tenant_id);
        if (const std::optional<std::string> problem = sampling::cursor_problem(manifest, cursor)) {
            err << "usage error: --canary-cursor: " << *problem << '\n';
            return exit_code::usage;
        }
        // Only now, the last check before the connector: a run stopped by
        // the checks above makes no folder and prints no recording line.
        recorder = open_recording(parsed.record, "restore", secrets);

        connector::ConnectorOptions options = recorder
                                                  ? record_connector(env.connector_options, recorder)
                                                  : env.connector_options;
        // Never spdlog's default logger, which writes to stdout.
        if (!options.logger) {
            options.logger = make_command_logger();
        }
        const std::unique_ptr<connector::IConnector> source =
            env.make_connector ? env.make_connector(config, secrets, options)
                               : connector::default_connector_registry().create(
                                     connector::kVeeamM365, config, secrets, options);
        if (!source) {
            throw std::logic_error("no connector");
        }

        const std::vector<connector::RestorePoint> points =
            source->list_restore_points(config.veeam_org_name);
        const connector::RestorePoint* point = pick_point(points, parsed.point, err);
        if (!point) {
            return exit_code::service;
        }
        const std::string run_id = parsed.run_id ? std::string{*parsed.run_id}
                                   : env.make_run_id ? env.make_run_id()
                                                     : make_run_id();
        sampling::check_run_id(run_id); // env.make_run_id's: nothing printed if it fails

        // Once the run ID exists, before the sample is chosen (it browses
        // Veeam) and the restore (it takes minutes): a run that fails from
        // here on still shows its run ID and seed.
        out << format_intro(config.veeam_org_name, *point, run_id);
        flush_or_throw(out);

        const sampling::Selection selection =
            sampling::choose_sample(*source, config.veeam_org_name, *point, targets,
                                    config.graph_tenant_id, plan, manifest, cursor, run_id);
        const connector::RestoreSpec spec{.client_ref = config.veeam_org_name,
                                          .restore_point = *point,
                                          .targets = targets,
                                          .mail = selection.mail,
                                          .sharepoint = selection.sharepoint,
                                          .onedrive = selection.onedrive};

        // No restore when the rest of the header can't be shown.
        out << format_sample(selection, spec.item_count());
        flush_or_throw(out);
        if (spec.item_count() == 0) {
            err << "restore error: the sample is empty: nothing to restore ("
                << empty_sample_reason(selection.record) << ")\n";
            return exit_code::service;
        }

        const auto now = [&env] {
            return env.now ? env.now() : std::chrono::steady_clock::now();
        };
        const auto started = now();
        restoring_run = run_id;
        const connector::RestoreResult result = source->restore_sample(spec);
        restoring_run.reset();
        const auto total = now() - started;

        try {
            out << format_result(result, selection, total);
            flush_or_throw(out);
        } catch (...) {
            // Items may be in the targets now: say so, which run, and how it
            // went. A restore that succeeded but whose output was lost isn't a
            // success.
            err << "error: writing the output failed after the restore ran (run " << run_id
                << ", status " << connector::to_string(result.status) << ": "
                << result.items_restored << " of " << result.items_sent
                << " item(s) restored)\n";
            const int code = restore_exit_code(result, err);
            return code == exit_code::ok ? exit_code::config : code;
        }
        return restore_exit_code(result, err);
    } catch (const ConfigError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (const sampling::ManifestError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (const connector::UnknownConnectorError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (const connector::AuthError& e) {
        return restore_failed(e, exit_code::auth);
    } catch (const connector::TransientError& e) {
        return restore_failed(e, exit_code::transient);
    } catch (const connector::Error& e) {
        return restore_failed(e, exit_code::service);
    } catch (...) {
        // Its message, if it has one, may not be safe to show.
        err << "error: unexpected failure\n";
        restore_note();
        return exit_code::config;
    }
}

} // namespace

int run_restore_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const RestoreCommandEnv& env)
{
    std::shared_ptr<FixtureRecorder> recorder;
    const int code = run_restore(args, out, err, env, recorder);
    return finish_recording(recorder.get(), out, err, code);
}

} // namespace rp
