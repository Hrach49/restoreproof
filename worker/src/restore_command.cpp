#include <rp/restore_command.hpp>

#include <rp/canary_manifest.hpp>
#include <rp/cli.hpp>
#include <rp/sample_rng.hpp>
#include <rp/sample_selector.hpp>

#include "command_config.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"
#include "text_util.hpp"
#include "veeam_time.hpp"

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
    for (std::size_t i = 0; i < args.size(); i += 2) {
        if (i + 1 >= args.size()) {
            return false;
        }
        const std::string_view name = args[i];
        const std::string_view value = args[i + 1];
        const auto size_option = [&](std::optional<int>& target) {
            if (target) {
                return false;
            }
            target = parse_size(value);
            return target.has_value();
        };
        bool ok = false;
        if (name == "--mail") {
            ok = size_option(parsed.mail);
        } else if (name == "--sp") {
            ok = size_option(parsed.sharepoint);
        } else if (name == "--od") {
            ok = size_option(parsed.onedrive);
        } else if (name == "--point" && !parsed.point) {
            ok = value == kLatest || is_point_id(value);
            parsed.point = value;
        } else if (name == "--run-id" && !parsed.run_id) {
            ok = valid_run_id(value);
            parsed.run_id = value;
        } else if (name == "--canary-cursor" && !parsed.cursor) {
            parsed.cursor = parse_cursor(value);
            ok = parsed.cursor.has_value();
        } else if (name == "--manifest" && !parsed.manifest) {
            parsed.manifest = value;
            ok = true;
        } else if (name == "--config" && !parsed.config) {
            parsed.config = value;
            ok = true;
        }
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool is_set(const std::optional<std::string>& secret) noexcept
{
    return secret && !secret->empty();
}

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

// The cursor's usage error for one type, if it is out of the manifest's range.
std::optional<std::string> cursor_error(ItemKind kind, std::uint32_t cursor, std::size_t canaries)
{
    if (canaries == 0 ? cursor == 0 : cursor < canaries) {
        return std::nullopt;
    }
    const std::string k = kind_name(kind);
    return "usage error: --canary-cursor: the " + k + " cursor must be " +
           (canaries == 0 ? "0: the manifest has no " + k + " canaries"
                          : "below " + std::to_string(canaries) + ", the manifest's " + k +
                                " canaries");
}

std::optional<std::string> cursor_error(const sampling::CanaryCursor& cursor,
                                        const sampling::CanaryManifest& manifest)
{
    if (auto e = cursor_error(ItemKind::mail, cursor.mail, manifest.mail.size())) {
        return e;
    }
    if (auto e = cursor_error(ItemKind::sharepoint, cursor.sharepoint, manifest.sharepoint.size())) {
        return e;
    }
    return cursor_error(ItemKind::onedrive, cursor.onedrive, manifest.onedrive.size());
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
    if (!id || *id == kLatest) {
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

TableRow kind_row(ItemKind kind, const sampling::KindRecord& k)
{
    const int canary_wanted = (k.requested + 1) / 2;
    const int canary_taken = static_cast<int>(k.canary_ids.size());
    const bool canary_short = canary_taken < canary_wanted;
    const bool random_short = k.random_taken < k.random_wanted;
    std::vector<std::string> cells{kind_name(kind), std::to_string(k.requested),
                                   of(canary_taken, canary_wanted),
                                   of(k.random_taken, k.random_wanted)};
    if (canary_short || random_short) {
        cells.push_back(canary_short && random_short ? "canary and random shortfall"
                        : canary_short               ? "canary shortfall"
                                                     : "random shortfall");
    }
    return {"  ", std::move(cells)};
}

// Everything printed before the restore.
std::string format_header(const std::string& org, const connector::RestorePoint& point,
                          const sampling::Selection& selection, std::size_t items)
{
    const sampling::SampleRecord& r = selection.record;
    std::string text = std::format("restore point {}  {}  (veeam_org_name {})\n",
                                   table_cell(point.backup_time), table_cell(point.id),
                                   table_cell(org));
    text += std::format("run {}  seed {}  canary cursor {} -> {}\n", r.run_id,
                        sampling::seed_hex(r.seed),
                        cursor_text(r.mail.cursor, r.sharepoint.cursor, r.onedrive.cursor),
                        cursor_text(r.mail.cursor_next, r.sharepoint.cursor_next,
                                    r.onedrive.cursor_next));
    text += format_table({{"  ", {"KIND", "REQUESTED", "CANARIES", "RANDOM", "NOTE"}},
                          kind_row(ItemKind::mail, r.mail),
                          kind_row(ItemKind::sharepoint, r.sharepoint),
                          kind_row(ItemKind::onedrive, r.onedrive)});
    text += std::format("restoring {} item(s) ...\n", items);
    return text;
}

std::string cell_or_dash(std::string_view text)
{
    return text.empty() ? std::string{"-"} : table_cell(text);
}

// A session's end - start, "-" when either doesn't read or it's negative.
std::string session_elapsed(const connector::RestoreSessionResult& session)
{
    const std::optional<VeeamTime> start = parse_veeam_time(session.started_at);
    const std::optional<VeeamTime> end = parse_veeam_time(session.ended_at);
    return start && end ? format_elapsed(*end - *start) : std::string{"-"};
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
    std::map<std::string, const connector::RestoreSessionResult*> sessions;
    for (const connector::RestoreSessionResult& s : result.sessions) {
        sessions.emplace(s.id, &s);
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
            const auto session = sessions.find(item.session_id);
            rows.push_back({"  ",
                            {kind_name(item.kind), source, cell_or_dash(item.name), outcome,
                             cell_or_dash(item.session_id),
                             session == sessions.end() ? std::string{"-"}
                                                       : session_elapsed(*session->second),
                             cell_or_dash(item.message)}});
        }
        text += '\n' + format_table(rows);
    }
    if (!result.sessions.empty()) {
        std::vector<TableRow> rows{
            {"  ", {"SESSION", "KIND", "RESULT", "RESTORED", "STARTED", "ENDED", "ELAPSED"}}};
        for (const connector::RestoreSessionResult& s : result.sessions) {
            rows.push_back({"  ",
                            {cell_or_dash(s.id), kind_name(s.kind), cell_or_dash(s.result),
                             of(s.items_restored, s.items_sent), cell_or_dash(s.started_at),
                             cell_or_dash(s.ended_at), session_elapsed(s)}});
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

// what() is safe to print: connector::Error's never holds a credential.
int report(std::ostream& err, std::string_view prefix, const std::exception& e, int code)
{
    err << prefix << e.what() << '\n';
    return code;
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
    if (elapsed < std::chrono::nanoseconds::zero()) {
        return "-";
    }
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    return std::format("{}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60);
}

RestoreCommandEnv default_restore_command_env()
{
    RestoreCommandEnv env;
    env.default_config_path = default_config_path;
    env.load_secrets = load_secrets_from_env;
    env.connector_options.logger = make_command_logger();
    return env;
}

int run_restore_command(std::span<const std::string_view> args, std::ostream& out,
                        std::ostream& err, const RestoreCommandEnv& env)
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
    } catch (const ConfigError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (...) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
    }
    if (!is_set(secrets.veeam_username)) {
        err << "config error: " << kEnvVeeamUsername << " is not set\n";
        return exit_code::config;
    }
    if (!is_set(secrets.veeam_password)) {
        err << "config error: " << kEnvVeeamPassword << " is not set\n";
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

    // Everything that can throw is in here, the output included, so no
    // exception escapes.
    try {
        const sampling::CanaryManifest manifest =
            sampling::load_canary_manifest(manifest_path(parsed.manifest, config_path));
        if (!ascii_iequals(manifest.tenant_id, config.graph_tenant_id)) {
            // choose_sample's own words, said before any connector call.
            throw sampling::ManifestError(
                "canary manifest: /tenant_id: isn't the client's tenant (graph_tenant_id)");
        }
        if (const std::optional<std::string> e = cursor_error(cursor, manifest)) {
            err << *e << '\n';
            return exit_code::usage;
        }

        connector::ConnectorOptions options = env.connector_options;
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
        const connector::RestoreTargets targets = connector::RestoreTargets::from_config(config);
        const sampling::Selection selection =
            sampling::choose_sample(*source, config.veeam_org_name, *point, targets,
                                    config.graph_tenant_id, plan, manifest, cursor, run_id);
        const connector::RestoreSpec spec{.client_ref = config.veeam_org_name,
                                          .restore_point = *point,
                                          .targets = targets,
                                          .mail = selection.mail,
                                          .sharepoint = selection.sharepoint,
                                          .onedrive = selection.onedrive};

        // Before the restore, which takes minutes: a run that fails still
        // shows its run ID. No restore when it can't be shown.
        out << format_header(config.veeam_org_name, *point, selection, spec.item_count());
        flush_or_throw(out);

        const auto now = [&env] {
            return env.now ? env.now() : std::chrono::steady_clock::now();
        };
        const auto started = now();
        const connector::RestoreResult result = source->restore_sample(spec);
        const auto total = now() - started;

        out << format_result(result, selection, total);
        flush_or_throw(out);
        return result.status == connector::RestoreStatus::succeeded ? exit_code::ok
                                                                    : exit_code::restore;
    } catch (const ConfigError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (const sampling::ManifestError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (const connector::UnknownConnectorError& e) {
        return report(err, "config error: ", e, exit_code::config);
    } catch (const connector::AuthError& e) {
        return report(err, "restore error: ", e, exit_code::auth);
    } catch (const connector::TransientError& e) {
        return report(err, "restore error: ", e, exit_code::transient);
    } catch (const connector::Error& e) {
        return report(err, "restore error: ", e, exit_code::service);
    } catch (...) {
        // Its message, if it has one, may not be safe to show.
        err << "error: unexpected failure\n";
        return exit_code::config;
    }
}

} // namespace rp
