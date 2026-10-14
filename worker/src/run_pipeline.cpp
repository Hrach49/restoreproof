#include "run_pipeline.hpp"

#include <rp/backup_content.hpp>
#include <rp/canary_manifest.hpp>
#include <rp/cert_export.hpp>
#include <rp/checker.hpp>
#include <rp/cleaner.hpp>
#include <rp/cli.hpp>
#include <rp/client_assertion.hpp>
#include <rp/client_check.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/expected_set.hpp>
#include <rp/graph_client.hpp>
#include <rp/graph_download.hpp>
#include <rp/graph_errors.hpp>
#include <rp/graph_targets.hpp>
#include <rp/http_client.hpp>
#include <rp/redact.hpp>
#include <rp/result_builder.hpp>
#include <rp/result_schema.hpp>
#include <rp/outbox.hpp>
#include <rp/run_lock.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_rng.hpp>
#include <rp/secrets.hpp>
#include <rp/target_guard_graph.hpp>
#include <rp/sample_selector.hpp>
#include <rp/step_timer.hpp>
#include <rp/version.hpp>

#include "command_config.hpp"
#include "duration_text.hpp"
#include "job_rules.hpp"
#include "path_utf8.hpp"
#include "run_folder_tail.hpp"
#include "target_guard_refuse.hpp"
#include "text_table.hpp"
#include "text_util.hpp"
#include "veeam_time.hpp"

#include <spdlog/logger.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace rp {

namespace {

namespace sampling = rp::sampling;
namespace timing = rp::timing;
namespace verification = rp::verification;
using connector::ItemKind;

constexpr std::size_t kMaxSizeDigits = 3;
constexpr std::size_t kMaxCursorDigits = 6;
// W6.2: the manifests' folder beside the config file, one file per tenant.
constexpr std::string_view kCanariesFolder = "canaries";

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
    if (!n || !job_rules::is_sample_size(*n)) {
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
        if (!parts[i] || !job_rules::is_cursor_value(*parts[i])) {
            return std::nullopt;
        }
        text.remove_prefix(i < 2 ? comma + 1 : comma);
    }
    return sampling::CanaryCursor{*parts[0], *parts[1], *parts[2]};
}

// The manifest --manifest names, or canaries\<tenant>.json beside the config
// file (W6.2 point 10), the tenant the profile's graph_tenant_id in lower case.
std::filesystem::path manifest_path(std::optional<std::string_view> manifest_arg,
                                    const std::filesystem::path& config_path,
                                    const std::string& graph_tenant_id)
{
    if (!manifest_arg) {
        // The tenant is a GUID (the profile's rule): ASCII, so a path as it is.
        return config_path.parent_path() / kCanariesFolder /
               std::filesystem::path(ascii_lower(graph_tenant_id) + ".json");
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
    if (!id || ascii_iequals(*id, job_rules::kLatest)) {
        return &points.front();
    }
    const auto it = std::ranges::find_if(
        points, [&](const connector::RestorePoint& p) { return ascii_iequals(p.id, *id); });
    if (it == points.end()) {
        // The ID passed job_rules::is_point: safe to echo.
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

// A type's NOTE: "canary shortfall", "random shortfall", both, or "" for none,
// by the one shortfall rule (verification::shortfalls_of).
std::string shortfall_note(ItemKind kind, const std::vector<verification::Shortfall>& shortfalls)
{
    bool canary_short = false;
    bool random_short = false;
    for (const verification::Shortfall& s : shortfalls) {
        if (s.kind == kind) {
            (s.source == verification::ItemSource::canary ? canary_short : random_short) = true;
        }
    }
    return canary_short && random_short ? "canary and random shortfall"
           : canary_short               ? "canary shortfall"
           : random_short               ? "random shortfall"
                                        : "";
}

TableRow kind_row(ItemKind kind, const sampling::KindRecord& k, bool canaries,
                  const std::vector<verification::Shortfall>& shortfalls)
{
    std::vector<std::string> cells{
        kind_name(kind), std::to_string(k.requested),
        canaries ? of(static_cast<int>(k.canary_ids.size()), (k.requested + 1) / 2) : "none",
        of(k.random_taken, k.random_wanted)};
    if (std::string note = shortfall_note(kind, shortfalls); !note.empty()) {
        cells.push_back(std::move(note));
    }
    return {"  ", std::move(cells)};
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
std::string format_sample(const sampling::Selection& selection, std::size_t items,
                          const std::vector<verification::Shortfall>& shortfalls)
{
    const sampling::SampleRecord& r = selection.record;
    // W6.2: a run without canaries says so where the cursor line would be.
    std::string text =
        r.canaries ? std::format("canary cursor {} -> {}\n",
                                 cursor_text(r.mail.cursor, r.sharepoint.cursor, r.onedrive.cursor),
                                 cursor_text(r.mail.cursor_next, r.sharepoint.cursor_next,
                                             r.onedrive.cursor_next))
                   : std::string{"canaries: none\n"};
    text += format_table({{"  ", {"KIND", "REQUESTED", "CANARIES", "RANDOM", "NOTE"}},
                          kind_row(ItemKind::mail, r.mail, r.canaries, shortfalls),
                          kind_row(ItemKind::sharepoint, r.sharepoint, r.canaries, shortfalls),
                          kind_row(ItemKind::onedrive, r.onedrive, r.canaries, shortfalls)});
    if (items > 0) {
        text += std::format("restoring {} item(s) ...\n", items);
    }
    return text;
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
    return format_hms(fraction_back ? whole - 1 : whole);
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

// The tables and the restore's line, after the restore: restore's per-item
// rows with `restore_rows`, then the session rows, then the line.
std::string format_result(const connector::RestoreResult& result,
                          const sampling::Selection& selection, std::chrono::nanoseconds total,
                          bool restore_rows)
{
    // Each session's ELAPSED, worked out once: its items' rows repeat it.
    std::vector<std::string> elapsed;
    std::map<std::string, std::size_t> session_at;
    for (const connector::RestoreSessionResult& s : result.sessions) {
        session_at.emplace(s.id, elapsed.size());
        elapsed.push_back(session_elapsed(s));
    }
    std::string text;
    if (restore_rows && !result.items.empty()) {
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
    text += std::format("\nrestore {}: {} of {} item(s) restored in {}\n",
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

// what() is safe to print: a ConfigError's names no secret.
int say(std::ostream& err, std::string_view prefix, const std::exception& e, int code)
{
    err << prefix << e.what() << '\n';
    return code;
}

// Opens and checks the Graph certificate as restore_sample will, so a bad one
// is said before any Veeam call; the check's own Graph client signs in with
// it. Nothing is logged: restore_sample's own load warns of a certificate
// about to expire.
graph::ClientCertificate check_graph_certificate(const Secrets& secrets,
                                                 const connector::ConnectorOptions& options)
{
    const auto wall_now =
        options.wall_now ? options.wall_now() : std::chrono::system_clock::now();
    return graph::certificate_from_secrets(
        secrets, wall_now, std::make_shared<spdlog::logger>("rp-restore-certificate"));
}

// The wall clock's "YYYY-MM-DDTHH:MM:SS.mmmZ" now, for the result's
// started_at and ended_at; nullopt when the clock fails: it decides nothing.
std::optional<std::string> wall_text(const connector::ConnectorOptions& options) noexcept
{
    try {
        const auto now = options.wall_now ? options.wall_now() : std::chrono::system_clock::now();
        return std::format("{:%Y-%m-%dT%H:%M:%S}Z",
                           std::chrono::floor<std::chrono::milliseconds>(now));
    } catch (...) {
        return std::nullopt;
    }
}

// The status line (W3.3): "status <pass|fail|error>[ <code>]: <message>",
// its own paragraph.
std::string format_status(const verification::RunVerdict& verdict)
{
    return std::format("\nstatus {}{}: {}\n", verification::to_string(verdict.status),
                       verdict.error_code.empty() ? "" : " " + verdict.error_code,
                       verdict.message);
}

// Why a result isn't one (W4.1 point 5), one line for `err`: counts, fixed
// words and a place in the document, never the validator's message, a value
// or an exception's text.
std::string format_result_error(const ResultError& error)
{
    switch (error.cause) {
    case ResultFailure::schema:
        return std::format("result error: {} schema violation(s){}\n", error.violations,
                           error.first_pointer.empty() ? std::string{}
                                                       : ", first at " + error.first_pointer);
    case ResultFailure::not_canonical:
        return "result error: the result has no canonical form\n";
    case ResultFailure::build_failed:
        break;
    }
    return "result error: the result couldn't be built\n";
}

// A clean's three targets, by the names its lines give them, in that order.
std::array<std::pair<std::string_view, const graph::TargetCleanup*>, 3>
cleaned_targets(const graph::CleanupResult& result)
{
    return {{{"mail", &result.mail},
             {"sharepoint", &result.sharepoint},
             {"onedrive", &result.onedrive}}};
}

// What a cleanup error code means, in fixed words: the Cleaner's own log line
// (on stderr through the command's logger) has Graph's message.
std::string_view cleanup_error_text(std::string_view code) noexcept
{
    if (code == "target_guard") {
        return "the restore-target guard refused the target; nothing was deleted in it";
    }
    if (code == "graph_auth") {
        return "Microsoft Entra refused the Worker's sign-in";
    }
    if (code == "graph_permission") {
        return "Microsoft Graph refused a permission the cleanup relies on";
    }
    if (code == "graph_transient") {
        return "Microsoft Graph couldn't be reached or asked to try later, in both rounds";
    }
    if (code == "graph") {
        return "Microsoft Graph gave an answer the cleanup can't use";
    }
    if (code == "config") {
        return "the configuration isn't usable";
    }
    return "an unexpected failure";
}

// A clean's line on stdout (W3.4 point 8): counts and codes, never a name or
// an ID.
std::string format_cleanup(const graph::CleanupResult& result)
{
    const auto targets = cleaned_targets(result);
    std::string line = std::format(
        "cleanup {} {}: deleted {} mail, {} sharepoint, {} onedrive",
        result.when == graph::CleanupWhen::before_run ? "before" : "after",
        result.ok() ? "ok" : "incomplete", result.mail.deleted,
        result.sharepoint.deleted, result.onedrive.deleted);
    if (result.mail.left + result.sharepoint.left + result.onedrive.left > 0) {
        line += std::format("; left {} mail, {} sharepoint, {} onedrive", result.mail.left,
                            result.sharepoint.left, result.onedrive.left);
    }
    if (const std::size_t skipped =
            result.mail.skipped + result.sharepoint.skipped + result.onedrive.skipped;
        skipped > 0) {
        line += std::format("; skipped {}", skipped);
    }
    for (const auto& [name, target] : targets) {
        if (!target->error_code.empty()) {
            line += std::format("; {} {}", name, target->error_code);
        }
    }
    return line + '\n';
}

// A clean's lines on `err`: one per target that stopped on an error, then one
// warning per target it didn't leave empty. Outside run_status's warnings:
// the cleanup never changes the status.
void report_cleanup(std::ostream& err, const graph::CleanupResult& result)
{
    const auto targets = cleaned_targets(result);
    for (const auto& [name, target] : targets) {
        if (!target->error_code.empty()) {
            err << "cleanup error: " << name << ": " << cleanup_error_text(target->error_code)
                << " (" << target->error_code << ")\n";
        }
    }
    const std::string_view when =
        result.when == graph::CleanupWhen::before_run ? "before" : "after";
    for (const auto& [name, target] : targets) {
        if (!target->ok()) {
            err << "warning: cleanup: " << name << " not emptied " << when << " the run (left "
                << target->left << ", skipped " << target->skipped
                << (target->error_code.empty() ? "" : ", " + target->error_code) << ")\n";
        }
    }
}

// Whether the guard refused any target of the clean: a clean-before that did
// stops the run (W3.4 point 8).
bool refused_by_guard(const graph::CleanupResult& result)
{
    const auto targets = cleaned_targets(result);
    return std::ranges::any_of(targets, [](const auto& target) {
        return target.second->error_code == "target_guard";
    });
}

// A run's Graph client, for the cleanup and the check (W3.2, W3.4), and the
// Cleaner over it: made with the connector's logger, clocks, sleep and
// jitter, on `http`, which must outlive both. One construction, the run's
// and the recovery clean's (clean_restore_targets).
void make_graph_and_cleaner(std::optional<graph::GraphClient>& client,
                            std::optional<graph::Cleaner>& cleaner, IHttpClient& http,
                            const ClientProfile& profile, graph::ClientCertificate certificate,
                            const connector::RestoreTargets& targets,
                            const connector::ConnectorOptions& options)
{
    graph::GraphClientOptions client_options;
    client_options.logger = options.logger;
    client_options.now = options.now;
    client_options.wall_now = options.wall_now;
    client_options.sleep = options.sleep;
    client_options.jitter = options.jitter;
    client.emplace(http, profile.graph_tenant_id, profile.graph_client_id,
                   std::move(certificate), client_options);
    graph::CleanerOptions cleaner_options;
    cleaner_options.logger = options.logger;
    cleaner.emplace(*client, targets, cleaner_options);
}

// The reader of the restore targets (W2.2), its lines on `logger`.
graph::TargetReader target_reader(graph::GraphClient& client, IHttpClient& download,
                                  const connector::RestoreTargets& targets,
                                  const std::shared_ptr<spdlog::logger>& logger,
                                  graph::TargetReaderOptions options)
{
    options.logger = logger;
    options.download.logger = logger;
    return graph::TargetReader(client, download, targets, std::move(options));
}

// The before snapshot (W3.2): the targets the spec has items for, listed
// without hashing. Null, or a Graph failure or a ConfigError, its line on
// `err`: nothing has been restored yet, so the run stops there (W3.3: its
// status decides the code). what() is safe to print: GraphError's went
// through rp::redact(), a ConfigError names no secret. Anything else is thrown.
std::exception_ptr read_before(graph::GraphClient& client, IHttpClient& download,
                               const connector::RestoreTargets& targets,
                               const connector::RestoreSpec& spec,
                               const std::shared_ptr<spdlog::logger>& logger,
                               verification::TargetsRead& before, std::ostream& err)
{
    const auto failed = [&](const std::exception& e) {
        err << "check error: " << e.what() << "; nothing was restored\n";
        return std::current_exception();
    };
    try {
        graph::TargetReaderOptions options;
        options.hash_items = false;
        graph::TargetReader reader = target_reader(client, download, targets, logger, options);
        if (!spec.mail.empty()) {
            before.mail.items = reader.list_mail();
        }
        if (!spec.sharepoint.empty()) {
            before.sharepoint.items = reader.list_sharepoint();
        }
        if (!spec.onedrive.empty()) {
            before.onedrive.items = reader.list_onedrive();
        }
        return nullptr;
    } catch (const graph::GraphError& e) {
        return failed(e);
    } catch (const ConfigError& e) {
        return failed(e);
    }
}

// W4.11 point 1: the client check, between the run line and the clean
// before. In order: (a) the organisation the connector reports for
// veeam_org_name against the profile (rp::check_client: type, tenant,
// region), (b) the manifest's tenant against the profile's, (c) the three
// restore targets resolved in the tenant through the run's own Graph client,
// with the guard's wording. Null when all passed, `resolved` filled; else
// the failure, its line `client error: <what()>; nothing was restored` on
// `err`: a ClientMismatchError (client_mismatch), a ManifestError (config),
// a Graph error (the check's code for it) or the connector's (the backup's
// codes). Nothing has been cleaned, sampled or restored, and no session is
// open. Anything else is thrown.
constexpr graph::TargetCheckWording kClientWording{"restores only into", "nothing was restored"};

std::exception_ptr check_client_step(connector::IConnector& source, const ClientProfile& profile,
                                     const sampling::CanaryManifest* manifest,
                                     graph::GraphClient& graph,
                                     const connector::RestoreTargets& targets,
                                     const std::shared_ptr<spdlog::logger>& logger,
                                     std::ostream& err, std::optional<ResolvedClient>& resolved)
{
    const auto failed = [&](const std::exception& e) {
        const std::string_view what{e.what()};
        err << "client error: " << what
            << (what.ends_with(connector::kNothingRestored) ? "" : connector::kNothingRestored)
            << '\n';
        return std::current_exception();
    };
    try {
        const connector::ClientFacts facts = source.client_facts(profile.veeam_org_name);
        if (const std::optional<ClientMismatch> mismatch = check_client(profile, facts)) {
            throw ClientMismatchError(*mismatch);
        }
        if (manifest != nullptr) {
            sampling::check_manifest_tenant(*manifest, profile.graph_tenant_id);
        }
        const graph::ResolvedMailbox mailbox =
            graph::check_restore_mailbox(graph, targets, kClientWording);
        const graph::ResolvedLibrary library =
            graph::check_restore_library(graph, targets, kClientWording);
        const graph::ResolvedOneDriveFolder folder =
            graph::check_restore_onedrive_folder(graph, targets, kClientWording);
        resolved = ResolvedClient{.organization_name = facts.name,
                                  .organization_tenant = facts.tenant_id,
                                  .organization_type = facts.organization_type,
                                  .organization_region = facts.region,
                                  .inbox_id = mailbox.inbox_id,
                                  .library_name = library.name,
                                  .library_list_id = library.list_id,
                                  .library_site_url = library.site_url,
                                  .folder_name = folder.name,
                                  .folder_site_url = folder.site_url};
        return nullptr;
    } catch (const ClientMismatchError& e) {
        return failed(e);
    } catch (const sampling::ManifestError& e) {
        return failed(e);
    } catch (const graph::WrongTargetError& e) {
        // The guard's refusal: one critical SECURITY line, as the Cleaner's
        // and layer 1's.
        log_security(logger, "client check: " + std::string{e.what()});
        return failed(e);
    } catch (const graph::GraphError& e) {
        return failed(e);
    } catch (const connector::Error& e) {
        return failed(e);
    } catch (const ConfigError& e) {
        return failed(e);
    }
}

// The line after a client check that passed.
std::string format_client_ok(const ResolvedClient& resolved)
{
    return "client ok: tenant " + table_cell(resolved.organization_tenant) + ", " +
           table_cell(resolved.organization_type) + ", " +
           table_cell(resolved.organization_region) +
           "; mailbox, library and folder resolved\n";
}

// The after read (W3.2): the targets the spec has items for, each mail body
// hashed, and each file `hash_file` takes (this run's copies of expected
// files, verification::hash_filter) downloaded and hashed, a docx or xlsx by
// office-v1 too (a package it refuses: one "check note: ..." line on `err`
// with the reader's text); every other file, an earlier run's leftover
// included, is listed only. A type whose read fails with a Graph error keeps its error
// code (verification::read_error_code), and its line goes on `err`; anything
// else (an rp::ConfigError included) is thrown.
void read_after(graph::GraphClient& client, IHttpClient& download,
                const connector::RestoreTargets& targets, const connector::RestoreSpec& spec,
                const std::shared_ptr<spdlog::logger>& logger,
                const std::function<std::chrono::steady_clock::time_point()>& clock,
                std::function<bool(const graph::FoundItem&)> hash_file,
                verification::TargetsRead& after, std::ostream& err)
{
    graph::TargetReaderOptions options;
    options.hash_items = true;
    options.hash_file = std::move(hash_file);
    options.on_file = verification::office_hook(after);
    options.clock = clock;
    graph::TargetReader reader = target_reader(client, download, targets, logger, options);
    const auto read = [&](bool wanted, verification::TargetRead& target, const auto& list) {
        if (!wanted) {
            return;
        }
        try {
            target.items = list();
        } catch (const graph::GraphError& e) {
            target.error_code = verification::read_error_code(std::current_exception());
            target.items.clear();
            err << "check error: " << e.what() << '\n';
        }
    };
    read(!spec.mail.empty(), after.mail, [&] { return reader.list_mail(); });
    read(!spec.sharepoint.empty(), after.sharepoint, [&] { return reader.list_sharepoint(); });
    read(!spec.onedrive.empty(), after.onedrive, [&] { return reader.list_onedrive(); });
    // Why office-v1 refused a restored package, here only: the check's reason
    // is fixed words (W4.1 point 7: the result is signed and uploaded), and
    // without the reader's own text one of its limits (a part too large, an
    // encrypted part) can't be told from a broken file.
    const auto refusals = [&](std::string_view kind, const verification::TargetRead& target) {
        for (const graph::FoundItem& file : target.items) {
            const auto it = target.office.find(file.id);
            if (it != target.office.end() && !it->second.error.empty()) {
                err << "check note: " << kind << ' ' << cell_or_dash(file.name.value_or(""))
                    << ": not valid office-v1 input: " << redact(it->second.error) << '\n';
            }
        }
    };
    refusals("sharepoint", after.sharepoint);
    refusals("onedrive", after.onedrive);
}

// The --evidence root (W4.2 point 8), checked before the secrets: a UTF-8
// path, and a --run-id that can name the run's folder in it. Throws
// ConfigError otherwise. Whether the folder can be made is found when it is.
std::filesystem::path check_evidence_root(std::string_view arg,
                                          std::optional<std::string_view> run_id)
{
    std::optional<std::filesystem::path> root = path_from_utf8(arg);
    if (!root) {
        throw ConfigError("--evidence", "--evidence " + table_cell(arg) + ": not a UTF-8 path");
    }
    if (run_id && !job_rules::is_folder_run_id(*run_id)) {
        throw ConfigError("--evidence", "--evidence: the run ID can't name a folder");
    }
    return std::move(*root);
}

} // namespace

RecordedBody veeam_recorded_body(const HttpRequest& request)
{
    const std::string_view path = request_path(request.url);
    return request.method == HttpMethod::post && path.ends_with("/save") &&
                   path.find("/Documents/") != std::string_view::npos
               ? RecordedBody::digest
               : RecordedBody::content;
}

connector::ConnectorOptions record_connector(connector::ConnectorOptions options,
                                             const std::shared_ptr<FixtureRecorder>& recorder)
{
    options.make_http = [inner = options.make_http,
                         recorder](const HttpClientOptions& http) -> std::unique_ptr<IHttpClient> {
        std::unique_ptr<IHttpClient> client =
            inner ? inner(http) : std::make_unique<HttpClient>(http);
        if (!recorder || !client) {
            return client;
        }
        return std::make_unique<RecordingHttpClient>(std::move(client), recorder, "veeam",
                                                     veeam_recorded_body);
    };
    options.make_graph_http =
        [inner = options.make_graph_http,
         recorder](std::shared_ptr<spdlog::logger> logger) -> std::unique_ptr<IHttpClient> {
        return recorded(inner ? inner(logger) : graph::make_graph_http_client(std::move(logger)),
                        recorder, "graph");
    };
    return options;
}

bool parse_pipeline_args(const CommandOptions& options, PipelineArgs& parsed)
{
    const auto size_option = [&](std::string_view name, std::optional<int>& target) {
        if (const std::optional<std::string_view> value = options.value(name)) {
            target = parse_size(*value);
            return target.has_value();
        }
        return true;
    };
    if (!size_option("--mail", parsed.mail) || !size_option("--sp", parsed.sharepoint) ||
        !size_option("--od", parsed.onedrive)) {
        return false;
    }
    parsed.point = options.value("--point");
    // `latest`, in any case, is a point ID too.
    if (parsed.point && !job_rules::is_point(*parsed.point)) {
        return false;
    }
    parsed.run_id = options.value("--run-id");
    if (parsed.run_id && !job_rules::is_run_id(*parsed.run_id)) {
        return false;
    }
    if (const std::optional<std::string_view> cursor = options.value("--canary-cursor")) {
        parsed.cursor = parse_cursor(*cursor);
        if (!parsed.cursor) {
            return false;
        }
    }
    parsed.manifest = options.value("--manifest");
    parsed.config = options.value("--config");
    parsed.vault = options.value("--vault");
    parsed.record = options.value("--record");
    parsed.profile_file = options.value("--profile-file");
    // An empty --profile-file value is a missing one: no file has that name.
    if (parsed.profile_file && parsed.profile_file->empty()) {
        return false;
    }
    return true;
}

std::string_view to_string(TargetsClean clean) noexcept
{
    switch (clean) {
    case TargetsClean::ok:
        return "ok";
    case TargetsClean::incomplete:
        return "incomplete";
    case TargetsClean::lock_held:
        return "lock_held";
    case TargetsClean::not_started:
        break;
    }
    return "not_started";
}

TargetsClean clean_restore_targets(const Config& config, const ClientProfile& client,
                                   const std::filesystem::path& vault, std::ostream& out,
                                   const RestoreCommandEnv& env) noexcept
{
    static_cast<void>(config);
    try {
        // The mutex first, and held to the end: no run reads or fills the
        // targets while they are emptied. Declared first, so it goes last.
        std::unique_ptr<RunLock> lock;
        try {
            lock = env.take_run_lock ? env.take_run_lock() : try_take_restore_targets_lock();
        } catch (const AbandonedRunLock&) {
            // Taken for this one try, as for a run: the next try has it.
            return TargetsClean::lock_held;
        }
        if (!lock) {
            return TargetsClean::lock_held;
        }
        Secrets secrets = env.load_secrets(vault);
        // Nothing here signs: the key's text is wiped with the holder.
        const RunSigningKey signing(secrets);
        connector::ConnectorOptions options = env.connector_options;
        // Never spdlog's default logger, which writes to stdout.
        if (!options.logger) {
            options.logger = make_command_logger();
        }
        graph::ClientCertificate certificate = check_graph_certificate(secrets, options);
        const connector::RestoreTargets targets = connector::RestoreTargets::from_profile(client);
        const std::unique_ptr<IHttpClient> http =
            options.make_graph_http ? options.make_graph_http(options.logger)
                                    : graph::make_graph_http_client(options.logger);
        if (!http) {
            return TargetsClean::not_started;
        }
        std::optional<graph::GraphClient> graph_client;
        std::optional<graph::Cleaner> cleaner;
        make_graph_and_cleaner(graph_client, cleaner, *http, client, std::move(certificate),
                               targets, options);
        // The Cleaner's clean before, as it is: every target, whatever a run
        // sampled, each resolved through the guard's own checks first.
        const graph::CleanupResult result = cleaner->clean(graph::CleanupWhen::before_run);
        // Lines that can't be written change nothing that was done.
        try {
            out << format_cleanup(result);
            report_cleanup(out, result);
            out.flush();
        } catch (...) {
        }
        return result.ok() ? TargetsClean::ok : TargetsClean::incomplete;
    } catch (...) {
        return TargetsClean::not_started;
    }
}

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

std::string cell_or_dash(std::string_view text)
{
    return text.empty() ? std::string{"-"} : table_cell(text);
}

std::string format_check_counts(const verification::CheckResult& check)
{
    std::map<verification::CheckOutcome, std::size_t> counts;
    for (const verification::ItemCheck& item : check.items) {
        ++counts[item.outcome];
    }
    return std::format("\ncheck: {} match, {} mismatch, {} missing, {} error\n",
                       counts[verification::CheckOutcome::match],
                       counts[verification::CheckOutcome::mismatch],
                       counts[verification::CheckOutcome::missing],
                       counts[verification::CheckOutcome::error]);
}

int run_pipeline(const PipelineArgs& parsed, std::ostream& out, std::ostream& err,
                 const RestoreCommandEnv& env, std::shared_ptr<FixtureRecorder>& recorder,
                 const Presentation& presentation, PipelineReport* report_out)
{
    // W4.8 point 5: what became of the run, written as it becomes known, so
    // every way out leaves it filled; a caller that asked for none gets
    // this one.
    PipelineReport own_report;
    PipelineReport& report = report_out ? *report_out : own_report;
    report = {};
    if (parsed.run_id) {
        report.run_id = *parsed.run_id;
    }
    // W4.8 point 13: whether the Worker was asked to stop. A check that
    // throws answered yes: nothing new is started on a doubt.
    const auto stop_asked = [&env]() noexcept {
        try {
            return env.stop_requested && env.stop_requested();
        } catch (...) {
            return true;
        }
    };
    std::filesystem::path config_path;
    Config config;
    // W4.10: the client the run is for, read once, right after the config.
    ClientProfile profile;
    Secrets secrets;
    // After `secrets`, so it goes first: whichever way the run ends, the
    // signing key's text is wiped, here or where it still is.
    RunSigningKey signing(secrets);
    std::optional<graph::ClientCertificate> certificate;
    std::optional<std::filesystem::path> evidence_root;
    // W4.6: set with --evidence --outbox only: where the finished run folder
    // is queued.
    std::optional<std::filesystem::path> outbox_root;
    // W4.4: set with --evidence only; no other run asks a TSA.
    std::optional<TsaSettings> tsa;
    try {
        config_path = command_config_path(parsed.config, env.default_config_path);
        // W4.8 point 2: the service's config was loaded at its start, and an
        // edit of the file waits for the next one.
        config = parsed.loaded ? *parsed.loaded : load_config(config_path);
        if (parsed.screenshots) {
            config.screenshots_enabled = *parsed.screenshots;
        }
        // W4.10 point 4: a job's profile, a file's, or the config's local one.
        if (parsed.client) {
            profile = *parsed.client;
        } else if (parsed.profile_file) {
            const std::optional<std::filesystem::path> file = path_from_utf8(*parsed.profile_file);
            if (!file) {
                throw ConfigError("--profile-file", "--profile-file " +
                                                        table_cell(*parsed.profile_file) +
                                                        ": not a UTF-8 path");
            }
            profile = read_client_profile_file(*file);
        } else if (const std::optional<ClientProfile> local = local_profile(config)) {
            profile = *local;
        } else {
            throw ConfigError("", "the config has no client keys; give --profile-file <file> or "
                                  "set the eight client keys");
        }
        if (presentation.after_config) {
            presentation.after_config();
        }
        if (parsed.evidence) {
            evidence_root = check_evidence_root(*parsed.evidence, parsed.run_id);
        }
        if (parsed.outbox) {
            outbox_root = path_from_utf8(*parsed.outbox);
            if (!outbox_root) {
                throw ConfigError("--outbox",
                                  "--outbox " + table_cell(*parsed.outbox) + ": not a UTF-8 path");
            }
            // The W4.6 review, finding 1: a run whose folder couldn't be
            // queued (its ID already queued or sent, the outbox folder not
            // makeable, the two roots on different volumes) is refused here,
            // before the secrets, the mutex and any Veeam call, not after
            // the restore with a complete folder stranded in the runs root.
            if (evidence_root) {
                const std::string refused = Outbox({*outbox_root, env.outbox_files, nullptr})
                                                .prepare(*evidence_root, parsed.run_id);
                if (!refused.empty()) {
                    err << refused << '\n';
                    return exit_code::config;
                }
            }
        }
        // W4.5: the vault, read once; nothing after this reads a secret from
        // anywhere else.
        secrets = env.load_secrets(command_vault_path(parsed.vault, env.default_vault_path));
        require_veeam_secrets(secrets);
        // restore_sample opens it only after the sample is chosen, which
        // browses Veeam. An unset password is none, as for `graph list`.
        certificate = check_graph_certificate(secrets, env.connector_options);
        // W4.3: --evidence always signs, so a run that couldn't is refused
        // here, before the schema, the manifest, the mutex and any Veeam
        // call. No other run parses the key or needs it.
        if (parsed.evidence) {
            signing.parse();
            // W4.4: and the certificates its timestamp will be held to.
            tsa = tsa_settings(config);
        }
    } catch (const ConfigError& e) {
        return say(err, "config error: ", e, exit_code::config);
    } catch (...) {
        // Not a ConfigError, so its message may not be safe to show.
        err << "config error: unexpected failure\n";
        return exit_code::config;
    }
    const sampling::SamplePlan plan{parsed.mail.value_or(config.sample_mail),
                                    parsed.sharepoint.value_or(config.sample_sp),
                                    parsed.onedrive.value_or(config.sample_od)};
    if (job_rules::is_empty_sample(plan.mail, plan.sharepoint, plan.onedrive)) {
        err << "usage error: every sample size is 0 (--mail, --sp, --od, or config's "
               "sample_mail, sample_sp, sample_od): nothing to restore\n";
        return exit_code::usage;
    }
    // W4.1: a Worker that can't validate its result finds out here, not after
    // the restore, where it would read as a schema violation.
    try {
        if (!(env.result_schema_ready ? env.result_schema_ready() : result_schema_ready())) {
            err << "error: the result schema couldn't be loaded; nothing was done\n";
            return exit_code::config;
        }
    } catch (...) {
        err << "error: unexpected failure\n";
        return exit_code::config;
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

    // W3.3: once the run line is out (`phase` set), every ending is a status
    // (rp/run_status.hpp). What it is decided from outlives the try block, so
    // the catch blocks below can decide it too, and the result (W4.1) can be
    // built from it. The connector says what it is once, as it is made.
    std::optional<verification::RunPhase> phase;
    std::optional<connector::ConnectorInfo> connector_info;
    std::string run_id;
    std::optional<connector::RestorePoint> chosen;
    std::optional<sampling::Selection> selection;
    std::optional<verification::ExpectedSet> expected;
    std::vector<verification::Shortfall> shortfalls;
    std::optional<connector::RestoreResult> result;
    std::optional<std::string> started_at;
    // W4.2: the run's folder, made before the run line when --evidence is
    // given. Until that line is out it is `new_folder`'s, which takes it away
    // again whichever way the run ends; from then on the run has it
    // (`evidence_folder`).
    RunFolder new_folder;
    std::optional<std::filesystem::path> evidence_folder;

    // W3.4: the run mutex, and Graph for the cleanup and the check, made right
    // after the run line and kept here so finish() can clean after a restore
    // however the run ends. Declared in this order so the Cleaner and the
    // client, which hold references to the HTTP clients, go first, and the
    // mutex last.
    std::unique_ptr<RunLock> run_lock;
    std::unique_ptr<IHttpClient> graph_http;
    std::unique_ptr<IHttpClient> download_http;
    std::optional<graph::GraphClient> graph_client;
    std::optional<graph::Cleaner> cleaner;
    RunCleanup cleanup;
    // W4.11: what the client check resolved; set when it passed.
    std::optional<ResolvedClient> resolved;
    // The steady clock everything here is timed by: the restore's line, each
    // checked item's ms, and the step timings (W3.5), read at the boundaries
    // of docs/decisions.md 2026-10-03 point 2. Spans that share a boundary
    // share one reading. env.now, else the connector's own clock, so the
    // sessions' submit and wait are on the clock `restore` is on. A reading
    // for the timings alone is try_now(): a clock that fails there changes
    // no line, status or exit code.
    timing::StepTimer timer(env.now ? env.now : env.connector_options.now);
    const std::function<std::chrono::steady_clock::time_point()> now = [&timer] {
        return timer.now();
    };
    // The clean after, its line (on `err` when stdout is lost) and its lines
    // on `err`, then env.on_cleanup. Never changes the exit code: a failure
    // here is one line on `err`.
    const auto clean_after = [&](bool restore_sent, bool may_still_run,
                                 bool output_lost) noexcept {
        try {
            cleanup.restore_sent = restore_sent;
            cleanup.restore_may_still_run = may_still_run;
            std::string line;
            if (!restore_sent) {
                line = "cleanup after skipped: nothing was restored\n";
            } else if (may_still_run) {
                // W4.8 point 9: never a clean under a restore that may still
                // be writing. The next run cleans before; in the service the
                // hold waits for Veeam first.
                line = "cleanup after skipped: the restore may still be running; the next "
                       "run cleans before\n";
            } else if (!cleaner) {
                line = "cleanup after skipped: no Graph client\n";
            } else {
                timer.start(timing::Span::cleanup_after, timer.try_now());
                cleanup.after = cleaner->clean(graph::CleanupWhen::after_run);
                timer.end(timing::Span::cleanup_after, timer.try_now());
                line = format_cleanup(*cleanup.after);
            }
            (output_lost ? err : out) << line;
            out.flush();
            if (cleanup.after) {
                report_cleanup(err, *cleanup.after);
            }
            if (env.on_cleanup) {
                env.on_cleanup(cleanup);
            }
        } catch (...) {
            err << "cleanup error: unexpected failure\n";
        }
    };
    // W3.5: when a stop ends the run, every span it left open but `total`
    // ends `stopped` on one reading, taken as the stop is handled: before
    // the status line and the clean after, which are no part of what it
    // interrupted. Once the restore had started a POST may have gone out:
    // its submit and wait, unless already reported, are not reported, never
    // not run; so are the content exports, when any was asked (W6.3 point 7:
    // not run when none was).
    bool content_asked = false;
    const auto stop_timings = [&]() noexcept {
        if (timer.state(timing::Span::restore) != timing::SpanState::not_run) {
            timer.report(timing::Span::restore_submit, std::nullopt);
            timer.report(timing::Span::restore_wait, std::nullopt);
            if (content_asked) {
                timer.report(timing::Span::content_export, std::nullopt);
            }
        }
        timer.stop_open(timer.try_now(), timing::Span::total);
    };
    // W3.5: once the clean after is done, `total` ends (and anything still
    // open, which only a bug leaves, ends `stopped`) on one reading; then the
    // table (none when stdout is lost), then env.on_timings. Timings decide
    // nothing: a failure here changes no line, status or exit code. The wall
    // clock is read beside that reading for the result's ended_at (and beside
    // total's start for its started_at), for every run with a run line.
    std::optional<std::string> ended_at;
    const auto end_timings = [&](bool output_lost) noexcept {
        const auto ended = timer.try_now();
        ended_at = wall_text(env.connector_options);
        timer.end(timing::Span::total, ended);
        timer.stop_open(ended);
        const timing::RunTimings timings = timer.timings();
        if (!output_lost) {
            try {
                out << '\n' << timing::format_timings(timings);
                out.flush();
            } catch (...) {
            }
        }
        if (env.on_timings) {
            try {
                env.on_timings(timings);
            } catch (...) {
            }
        }
        return timings;
    };
    // W4.1: restoreproof.result.v1 from what the run has so far, its
    // canonical text validated by the embedded schema (rp::ResultBuilder).
    // Never throws: whatever fails is a ResultError.
    const auto build_result = [&](const verification::RunVerdict& verdict,
                                  const verification::CheckResult* check,
                                  const timing::RunTimings& timings,
                                  const Evidence* evidence = nullptr) noexcept
        -> std::variant<BuiltResult, ResultError> {
        try {
            ResultParts parts;
            parts.worker_version = std::string{version()};
            parts.run_id = run_id;
            parts.started_at = started_at;
            parts.ended_at = ended_at;
            if (connector_info) {
                parts.connector = *connector_info;
            }
            parts.client = result_client(profile, parsed.client_id);
            parts.client.resolved = resolved;
            if (chosen) {
                parts.restore_point_id = chosen->id;
                parts.restore_point_time = chosen->backup_time;
            }
            parts.sample = selection ? &selection->record : nullptr;
            parts.expected = expected ? &*expected : nullptr;
            parts.restore = result ? &*result : nullptr;
            parts.check = check;
            parts.verdict = &verdict;
            // The clean after runs only after the clean before.
            parts.cleanup = cleanup.before ? &cleanup : nullptr;
            parts.timings = &timings;
            parts.attachments = evidence ? &evidence->attachments : nullptr;
            parts.screenshot = evidence ? &evidence->screenshot : nullptr;
            return ResultBuilder::build(parts);
        } catch (...) {
            return ResultError{ResultFailure::build_failed, 0, {}};
        }
    };
    // W4.2 point 9: the run folder's files, last. The two text files (always,
    // also for a run with no valid result), the screenshot's answer, then the
    // finished result with what it lists, validated, each attachment read
    // back against its hash, the result signed with the run's key (W4.3:
    // signature.json), and result.json: the tail the service's close of a
    // run folder shares (finish_run_folder, src/run_folder_tail.hpp). Nothing
    // here changes the status: what fails is one line on `err` and an exit
    // code of 0 becoming 1 (the W3.6 rule). Returns the exit code.
    const auto write_evidence = [&](const std::optional<verification::RunVerdict>& verdict,
                                    bool invalid, const verification::CheckResult* check,
                                    const timing::RunTimings& timings, int code,
                                    bool output_lost) noexcept {
        try {
            RunFolderTail tail;
            tail.folder = *evidence_folder;
            tail.run_id = run_id;
            tail.screenshots_enabled = config.screenshots_enabled;
            tail.secrets = &secrets;
            tail.signing = &signing;
            tail.tsa = tsa ? &*tsa : nullptr;
            tail.env = &env;
            tail.recorder = recorder;
            tail.outbox_root = outbox_root ? &*outbox_root : nullptr;
            // No screenshot for a run that has no valid result to list it.
            tail.attachments = [&](EvidenceBuilder& builder) {
                return builder.write_attachments({expected ? &*expected : nullptr,
                                                  result ? &*result : nullptr, check,
                                                  verdict ? &*verdict : nullptr},
                                                 verdict && !invalid);
            };
            tail.result = [&](const Evidence& evidence) -> std::optional<std::string> {
                if (!verdict || invalid) {
                    return std::nullopt;
                }
                std::variant<BuiltResult, ResultError> finished =
                    build_result(*verdict, check, timings, &evidence);
                if (const ResultError* error = std::get_if<ResultError>(&finished)) {
                    // The status line is out and stays.
                    err << format_result_error(*error);
                    return std::nullopt;
                }
                return std::move(std::get<BuiltResult>(finished).canonical);
            };
            // Whatever happens from here on, the folder is there.
            report.folder = RunFolderState::incomplete;
            report.folder_word = "not_written";
            RunFolderOutcome outcome;
            code = finish_run_folder(tail, out, err, code, output_lost, outcome);
            report.folder = outcome.state;
            report.folder_word = outcome.word;
        } catch (...) {
            // Never an exit code without its line.
            try {
                err << "error: unexpected failure\n";
            } catch (...) {
            }
            code = code == exit_code::ok ? exit_code::config : code;
        }
        return code;
    };
    // The run's status is decided, then the result is built and validated as
    // it stands (W4.1 point 5: ended_at and cleanup.after null, the open
    // spans `open`): a result that isn't valid makes the run `error
    // result_invalid`, said on `err`, before anything says pass. Then the
    // check's table (the command's own) and its count line, then the
    // status line, then each warning on `err`; the exit code is the status's.
    // With `output_lost` (or the check's table or the status line failing
    // too) the output is incomplete: after a restore that says so, with the
    // run and the restore's own account, and a pass becomes 1. Then the clean
    // after (W3.4), only when the status says a restore was sent and none
    // may still be running: the verdict never waits on housekeeping. Then the step timings (W3.5). Then, for a
    // command with an end-of-run hook (W3.6), the finished result is built
    // and validated again and handed to the hook, last: no result when that
    // fails (said on `err`), when the run ended result_invalid or when there
    // is no verdict.
    const auto finish = [&](std::optional<verification::RunStop> stop,
                            const verification::CheckResult* check, bool output_lost) noexcept {
        int code = exit_code::config;
        std::optional<verification::RunVerdict> verdict;
        bool invalid = false;
        if (stop) {
            stop_timings();
        }
        try {
            // Veeam may still be writing: a stop in the restore without the
            // connector's promise that nothing was sent.
            const bool may_still_run = stop && stop->phase == verification::RunPhase::restore &&
                                       !stop->nothing_restored;
            report.restore_may_still_run = may_still_run;
            // W4.8 point 13: asked before the verdict is decided. A wait the
            // stop cut short reads as the failure of whatever was waited
            // for, so an error decided after it is the stop's; a pass or a
            // fail reached in spite of it stays, and so does every verdict
            // decided before the stop came.
            const bool stopped_before_verdict = stop_asked();
            verdict = verification::decide_status(
                {expected ? &*expected : nullptr, shortfalls, std::move(stop),
                 result ? &*result : nullptr, check,
                 chosen ? chosen->backup_time : std::string{}});
            if (stopped_before_verdict && verification::interrupt_replaces(*verdict)) {
                verdict = verification::interrupted(*verdict);
            }
            report.status = verdict->status;
            report.error_code = verdict->error_code;
            const std::variant<BuiltResult, ResultError> provisional =
                build_result(*verdict, check, timer.timings());
            if (const ResultError* error = std::get_if<ResultError>(&provisional)) {
                invalid = true;
                report.replaced_status = verdict->status;
                report.replaced_code = verdict->error_code;
                verdict = verification::result_invalid(*verdict);
                report.status = verdict->status;
                report.error_code = verdict->error_code;
                err << format_result_error(*error);
            }
            code = verification::exit_code_of(*verdict);
            if (check && !output_lost) {
                try {
                    if (presentation.check_table) {
                        out << presentation.check_table(*expected, *check, *verdict,
                                                        result ? &*result : nullptr);
                    }
                    out << format_check_counts(*check);
                    flush_or_throw(out);
                } catch (...) {
                    output_lost = true;
                }
            }
            if (!output_lost) {
                try {
                    out << format_status(*verdict);
                    flush_or_throw(out);
                } catch (...) {
                    output_lost = true;
                }
            }
            if (output_lost) {
                // With or without a restore, the status is said somewhere.
                err << "error: writing the output failed";
                if (result) {
                    err << " after the restore ran (run " << run_id << ", restore "
                        << connector::to_string(result->status) << ": " << result->items_restored
                        << " of " << result->items_sent << " item(s) restored)";
                } else {
                    err << " (run " << run_id << ")";
                }
                err << "; run status " << verification::to_string(verdict->status)
                    << (verdict->error_code.empty() ? "" : " " + verdict->error_code) << '\n';
                code = code == exit_code::ok ? exit_code::config : code;
            }
            for (const verification::StatusWarning& warning : verdict->warnings) {
                err << "warning: " << warning.code << ": " << warning.message << '\n';
            }
            clean_after(verdict->restore_sent, may_still_run, output_lost);
        } catch (...) {
            err << "error: unexpected failure\n";
            code = exit_code::config;
        }
        // The run is done with the restore targets: the mutex goes now, not
        // when the command returns. What is left is local, and with
        // --evidence a wait for the TSA of up to a minute and a half (W4.4),
        // during which the next run must not be refused.
        run_lock.reset();
        const timing::RunTimings timings = end_timings(output_lost);
        if (evidence_folder) {
            return write_evidence(verdict, invalid, check, timings, code, output_lost);
        }
        if (presentation.on_run) {
            try {
                std::optional<std::string> text;
                if (verdict && !invalid) {
                    std::variant<BuiltResult, ResultError> finished =
                        build_result(*verdict, check, timings);
                    if (const ResultError* error = std::get_if<ResultError>(&finished)) {
                        // The status line is out and stays.
                        err << format_result_error(*error);
                    } else {
                        text = std::move(std::get<BuiltResult>(finished).canonical);
                    }
                }
                const RunSummary summary{.run_id = run_id, .result = text ? &*text : nullptr};
                code = presentation.on_run(summary, code, output_lost);
            } catch (...) {
                // Never an exit code without its line.
                try {
                    err << "error: unexpected failure\n";
                } catch (...) {
                }
                code = code == exit_code::ok ? exit_code::config : code;
            }
        }
        return code;
    };
    // The exit code of the exception being handled (its line is already on
    // `err`), from the stop it makes (rp/run_status.hpp), the one mapping of
    // exceptions to codes: before the run line, that code's exit code; after
    // it, the run's status.
    const auto stopped = [&] {
        const verification::RunStop stop = verification::stop_reason(
            std::current_exception(), phase.value_or(verification::RunPhase::before_restore));
        return phase ? finish(stop, nullptr, false) : verification::exit_code_of(stop.error_code);
    };
    const auto restore_failed = [&](const std::exception& e) {
        err << "restore error: " << e.what() << '\n';
        restore_note(e.what());
        return stopped();
    };
    // W4.8 point 13: a stop found at a step's boundary once the run line is
    // out, or a run that couldn't be put on record (point 6): `line` on
    // `err`, then the run ends as every stopped run does, before the
    // restore: error interrupted, nothing restored, the clean after skipped.
    const auto interrupted_before = [&](std::string_view line) {
        err << "restore error: " << line << connector::kNothingRestored << '\n';
        return finish(verification::stop_reason(
                          std::make_exception_ptr(connector::Interrupted(
                              std::string{line} + std::string{connector::kNothingRestored})),
                          verification::RunPhase::before_restore),
                      nullptr, false);
    };
    constexpr std::string_view kAskedToStop = "the Worker was asked to stop";

    // Everything that can throw is in here, the output included, so no
    // exception escapes.
    try {
        // W6.2 point 10: canaries are an opt-in, named by --canary-cursor or
        // --manifest (a job: its canary_cursor key). Without, no manifest is
        // looked for and the whole sample is random items.
        const bool canaries = parsed.cursor.has_value() || parsed.manifest.has_value();
        std::optional<sampling::CanaryManifest> loaded_manifest;
        if (canaries) {
            loaded_manifest = sampling::load_canary_manifest(
                manifest_path(parsed.manifest, config_path, profile.graph_tenant_id));
        }
        const sampling::CanaryManifest* manifest = canaries ? &*loaded_manifest : nullptr;
        const connector::RestoreTargets targets = connector::RestoreTargets::from_profile(profile);
        // choose_sample's own checks, said before the connector is made: an
        // unreachable Veeam can't hide a manifest that names a restore target.
        // The manifest's tenant is the client check's (W4.11), after the run
        // line, so that a job of another tenant is reported.
        if (manifest != nullptr) {
            sampling::check_manifest_targets(*manifest, targets);
        }
        if (const std::optional<std::string> problem = sampling::cursor_problem(manifest, cursor)) {
            err << "usage error: --canary-cursor: " << *problem << '\n';
            return exit_code::usage;
        }
        // W4.8 point 13: the first boundary. A stop asked for by now ends
        // the run before the mutex and any call to a service: nothing was
        // done, and there is no run line.
        if (stop_asked()) {
            err << "restore error: " << kAskedToStop << "; nothing was done\n";
            return verification::exit_code_of("interrupted");
        }
        // W3.4: one run at a time on the restore targets, held until the
        // clean after is over (`finish`), or until the command returns when
        // the run ends before that: another run's cleanup could otherwise delete this
        // run's copies before they are read back (a false fail). Before the
        // --record folder and any Veeam call: a run refused here does nothing.
        try {
            run_lock = env.take_run_lock ? env.take_run_lock() : try_take_restore_targets_lock();
        } catch (const AbandonedRunLock&) {
            // A crashed run's mutex: no run has it now, and the next one takes it.
            err << "restore error: the last RestoreProof run ended without releasing the restore "
                   "targets; nothing was done; the next run cleans them before it restores\n";
            return exit_code::service;
        }
        if (!run_lock) {
            err << "restore error: another RestoreProof run is using the restore targets; "
                   "nothing was done\n";
            return exit_code::service;
        }
        // Only now, the last check before the connector: a run stopped by
        // the checks above makes no folder and prints no recording line.
        recorder = open_recording(parsed.record, presentation.command, secrets);
        // W4.3: the recorder has its copy of every secret value; from here
        // on the Secrets, which the connector copies, are without the
        // signing key's text.
        signing.take();

        connector::ConnectorOptions options = recorder
                                                  ? record_connector(env.connector_options, recorder)
                                                  : env.connector_options;
        // Never spdlog's default logger, which writes to stdout.
        if (!options.logger) {
            options.logger = make_command_logger();
        }
        // W4.8 point 13: the connector learns of a stop through its options,
        // unless its caller put a check of its own there.
        if (!options.stop_requested) {
            options.stop_requested = env.stop_requested;
        }
        // W4.10: the guard's Graph client signs in as the run's client.
        options.client = profile;
        const std::unique_ptr<connector::IConnector> source =
            env.make_connector ? env.make_connector(config, secrets, options)
                               : connector::default_connector_registry().create(
                                     parsed.connector_type.value_or(
                                         std::string{connector::kVeeamM365}),
                                     config, secrets, options);
        if (!source) {
            throw std::logic_error("no connector");
        }
        connector_info = source->describe();

        // W3.5: the run's first call to a service starts `total`. What came
        // before is local and untimed, and a run that stops before its run
        // line shows no timings.
        const auto listing = timer.try_now();
        started_at = wall_text(env.connector_options);
        timer.start(timing::Span::total, listing);
        timer.start(timing::Span::restore_point_lookup, listing);
        const std::vector<connector::RestorePoint> points =
            source->list_restore_points(profile.veeam_org_name);
        const connector::RestorePoint* point = pick_point(points, parsed.point, err);
        if (!point) {
            return exit_code::service;
        }
        timer.end(timing::Span::restore_point_lookup, timer.try_now());
        run_id = parsed.run_id ? std::string{*parsed.run_id}
                 : env.make_run_id ? env.make_run_id()
                                   : make_run_id();
        sampling::check_run_id(run_id); // env.make_run_id's: nothing printed if it fails
        report.run_id = run_id;

        // W4.2 point 8: the run's folder, before the run line and anything
        // that writes. One that is there already is another run's: never
        // written into.
        if (evidence_root) {
            const RunFolderCheck made =
                EvidenceBuilder::make_run_folder(*evidence_root, run_id, new_folder);
            if (made == RunFolderCheck::not_a_folder_name) {
                err << "evidence error: the run ID can't name a folder; nothing was done\n";
                return exit_code::config;
            }
            if (made != RunFolderCheck::ok) {
                err << "evidence error: " << table_cell(path_to_utf8(new_folder.path()))
                    << ": the run folder "
                    << (made == RunFolderCheck::exists ? "already exists" : "couldn't be made")
                    << "; nothing was done\n";
                return exit_code::config;
            }
        }

        // Once the run ID exists, before the sample is chosen (it browses
        // Veeam) and the restore (it takes minutes): a run that fails from
        // here on still shows its run ID and seed, and ends with its status.
        out << format_intro(profile.veeam_org_name, *point, run_id);
        flush_or_throw(out);
        chosen = *point;
        phase = verification::RunPhase::before_restore;
        // The run has its run line, and with it its folder: nothing is
        // written into it before the end, so a run that ended before this
        // line left none (and no level of the root made for it).
        report.run_line = true;
        if (evidence_root) {
            new_folder.keep();
            evidence_folder = new_folder.path();
            report.folder = RunFolderState::incomplete;
            report.folder_word = "not_written";
        }

        // W4.8 point 6: the run is told to whoever keeps a record of it,
        // before it does anything in the tenant or opens a session in the
        // backup product. A record that couldn't be written ends the run
        // here: nothing is done that nobody wrote down.
        if (env.on_run_started) {
            bool recorded_run = false;
            try {
                recorded_run = env.on_run_started({.run_id = run_id,
                                                   .started_at = started_at,
                                                   .restore_point_id = point->id,
                                                   .restore_point_time = point->backup_time,
                                                   .connector_type = connector_info->name,
                                                   .connector_api = connector_info->version});
            } catch (...) {
                recorded_run = false;
            }
            if (!recorded_run) {
                return interrupted_before("the run couldn't be recorded as started");
            }
        }
        // W4.8 point 13: a stop before the client check.
        if (stop_asked()) {
            return interrupted_before(kAskedToStop);
        }

        // Graph for the client check, the cleanup and the check (W3.2, W3.4,
        // W4.11), one client for all. `options` records Graph under "graph"
        // with --record, the cleanup's deletes included; downloads are
        // recorded as their size and SHA-256 only.
        graph_http = options.make_graph_http ? options.make_graph_http(options.logger)
                                             : graph::make_graph_http_client(options.logger);
        // The download client's own retries wait on the run's sleep too.
        download_http =
            recorded(env.make_download_http ? env.make_download_http(options.sleep)
                                            : graph::make_download_http_client(options.sleep),
                     recorder, "download", RecordedBody::digest);
        if (!graph_http || !download_http) {
            throw std::logic_error("no HTTP client");
        }
        make_graph_and_cleaner(graph_client, cleaner, *graph_http, profile,
                               std::move(*certificate), targets, options);

        // W4.11 point 1: the client check, before anything is cleaned,
        // sampled or restored. A failure is a before_restore stop.
        if (const std::exception_ptr failed =
                check_client_step(*source, profile, manifest, *graph_client, targets,
                                  options.logger, err, resolved)) {
            return finish(verification::stop_reason(failed, *phase), nullptr, false);
        }
        out << format_client_ok(*resolved);
        flush_or_throw(out);
        // W4.8 point 13: a stop before the clean before, which deletes. The
        // check's Graph reads may have waited long enough for one to come.
        if (stop_asked()) {
            return interrupted_before(kAskedToStop);
        }

        // W3.4: every run with a run line empties all three targets first,
        // whatever it samples, so an earlier run's copies can't pass for this
        // run's. Leftovers or a Graph failure let the run go on (the before
        // snapshot is the second guard); a guard refusal stops it before
        // choose_sample opens any Veeam session, as layer 1 would, and layer 1
        // sees only the sampled types.
        timer.start(timing::Span::cleanup_before, timer.try_now());
        cleanup.before = cleaner->clean(graph::CleanupWhen::before_run);
        timer.end(timing::Span::cleanup_before, timer.try_now());
        out << format_cleanup(*cleanup.before);
        flush_or_throw(out);
        report_cleanup(err, *cleanup.before);
        if (refused_by_guard(*cleanup.before)) {
            return finish(verification::stop_reason(
                              std::make_exception_ptr(graph::WrongTargetError(
                                  "cleanup: the restore-target guard refused a restore "
                                  "target; nothing was restored")),
                              *phase),
                          nullptr, false);
        }

        // W4.8 point 13: a stop before choose_sample, which opens the run's
        // first sessions in the backup product.
        if (stop_asked()) {
            return interrupted_before(kAskedToStop);
        }
        timer.start(timing::Span::sample_select, timer.try_now());
        selection = sampling::choose_sample(*source, profile.veeam_org_name, *point, targets,
                                            profile.graph_tenant_id, plan, manifest, cursor, run_id);
        timer.end(timing::Span::sample_select, timer.try_now());
        shortfalls = verification::shortfalls_of(selection->record);
        connector::RestoreSpec spec{.client_ref = profile.veeam_org_name,
                                    .restore_point = *point,
                                    .targets = targets,
                                    .mail = selection->mail,
                                    .sharepoint = selection->sharepoint,
                                    .onedrive = selection->onedrive};
        // W6.3 point 4: every random file with a content rule asks for its
        // bytes from the backup; the connector exports them into the hasher
        // before its first restore request, and the hasher keeps their hashes.
        std::vector<std::string> sharepoint_names;
        for (const connector::SharePointSelector& s : spec.sharepoint) {
            sharepoint_names.push_back(s.name);
        }
        std::vector<std::string> onedrive_names;
        for (const connector::OneDriveSelector& o : spec.onedrive) {
            onedrive_names.push_back(o.name);
        }
        verification::ContentHasher hasher(std::move(sharepoint_names), std::move(onedrive_names));
        if (verification::mark_wanted(spec, selection->record) > 0) {
            spec.content_sink = &hasher;
            content_asked = true;
        }

        // No restore when the rest of the header can't be shown.
        out << format_sample(*selection, spec.item_count(), shortfalls);
        flush_or_throw(out);

        // W3.1: what each restored copy should look like. An empty sample
        // (row 3 of the status table) is said by the status, its shortfalls
        // as warnings, and nothing is restored.
        expected = verification::build_expected_set(*selection, manifest);
        if (spec.item_count() == 0) {
            return finish(std::nullopt, nullptr, false);
        }

        // W3.2: the targets as they are before the restore, read through
        // Graph as `graph list` reads them. A failure here stops the run
        // before anything is restored.
        // W4.8 point 13: a stop before the read before.
        if (stop_asked()) {
            return interrupted_before(kAskedToStop);
        }
        verification::TargetsRead before;
        timer.start(timing::Span::target_snapshot, timer.try_now());
        if (const std::exception_ptr failed = read_before(*graph_client, *download_http, targets,
                                                          spec, options.logger, before, err)) {
            return finish(verification::stop_reason(failed, *phase), nullptr, false);
        }

        // W4.8 point 13: the last boundary, a stop before restore_sample.
        // From there on the connector asks before each restore request.
        if (stop_asked()) {
            timer.end(timing::Span::target_snapshot, timer.try_now());
            return interrupted_before(kAskedToStop);
        }
        // The restore's own two readings bound `restore` (W3.5), and no other
        // reading falls between them; `recovery` runs from here to the last
        // item's verdict.
        const auto started = timer.now();
        timer.end(timing::Span::target_snapshot, started);
        timer.start(timing::Span::restore, started);
        timer.start(timing::Span::recovery, started);
        phase = verification::RunPhase::restore;
        restoring_run = run_id;
        result = source->restore_sample(spec);
        restoring_run.reset();
        phase = verification::RunPhase::check;
        const auto restored_at = timer.now();
        // W6.3: the exports ran inside restore_sample, but they verify and
        // restore nothing: their time is left out of `restore`, `recovery`
        // and the restore line's elapsed time, held to the span they're in
        // (another clock's measure could be longer). A restore_sample that
        // throws has handed no time back, and its spans keep them.
        const std::chrono::nanoseconds exports = std::clamp<std::chrono::nanoseconds>(
            result->content_time.value_or(std::chrono::nanoseconds{0}),
            std::chrono::nanoseconds{0},
            std::max<std::chrono::nanoseconds>(restored_at - started, std::chrono::nanoseconds{0}));
        timer.delay_start(timing::Span::restore, exports);
        timer.delay_start(timing::Span::recovery, exports);
        const auto elapsed = restored_at - started - exports;
        // Each session's submit and wait, summed: the time spent in each
        // phase, or a state, never a partial number. Reported before
        // `restore` ends, with nothing between that can throw.
        timer.report(timing::Span::restore_submit,
                     timing::sum_session_durations(result->sessions,
                                                   &connector::RestoreSessionResult::submit_time));
        timer.report(timing::Span::restore_wait,
                     timing::sum_session_durations(result->sessions,
                                                   &connector::RestoreSessionResult::wait_time));
        // W6.3: the exports, as the connector measured them; not run when
        // none was asked (W6.3 point 7: null), not reported when asked and
        // the connector gave no time.
        if (content_asked) {
            timer.report(timing::Span::content_export, result->content_time);
        }
        timer.end(timing::Span::restore, restored_at);
        timer.start(timing::Span::verify, restored_at);

        // Items may be in the targets now: say how it went. Output that is
        // lost from here on doesn't stop the check: the status still decides
        // the exit code, and a restore whose output was lost isn't a success.
        bool output_lost = false;
        try {
            out << format_result(*result, *selection, elapsed, presentation.restore_rows)
                << verification::content_exports_line(*result);
            flush_or_throw(out);
        } catch (...) {
            output_lost = true;
        }

        // Read back, hashing, and compare: a read that fails makes its type's
        // items `error`, never a stop. Anything else that fails here (no
        // memory, a bug) stops the run in its check phase: error internal,
        // the restore's tables already out.
        std::optional<verification::CheckResult> checked;
        try {
            // W6.3 point 3: the exported files' expectation raised to
            // backup_content before anything is read back; facts that don't
            // add up (a connector that ignored want_content) are the Worker's
            // fault, error internal.
            verification::add_backup_content(*expected, *result, hasher.digests());
            const verification::TargetSnapshot snapshot = verification::snapshot_of(before);
            verification::TargetsRead after;
            read_after(*graph_client, *download_http, targets, spec, options.logger, now,
                       verification::hash_filter(*expected, snapshot), after, err);
            checked = verification::check(*expected, snapshot, after, now);
        } catch (...) {
            try {
                throw;
            } catch (const ConfigError& e) {
                err << "check error: " << e.what() << '\n';
            } catch (...) {
                // Its message, if it has one, may not be safe to show.
                err << "check error: unexpected failure\n";
            }
            err << "restore error: the restore had started: items may be in the restore targets "
                   "(run "
                << run_id << ")\n";
            return finish(verification::stop_reason(std::current_exception(), *phase), nullptr,
                          output_lost);
        }
        // Every item's verdict came from that one call, after the reads; the
        // check's table follows the status's decision (finish).
        const auto verified = timer.try_now();
        timer.end(timing::Span::verify, verified);
        timer.end(timing::Span::recovery, verified);
        return finish(std::nullopt, &*checked, output_lost);
    } catch (const ConfigError& e) {
        err << "config error: " << e.what() << '\n';
        return stopped();
    } catch (const sampling::ManifestError& e) {
        err << "config error: " << e.what() << '\n';
        return stopped();
    } catch (const connector::UnknownConnectorError& e) {
        err << "config error: " << e.what() << '\n';
        return stopped();
    } catch (const connector::Error& e) {
        return restore_failed(e);
    } catch (const connector::Interrupted& e) {
        // W4.8 point 13: the connector withdrew a restore request, or left
        // its poll, on a stop. Its text says whether anything was sent, as
        // the connector's errors do.
        return restore_failed(e);
    } catch (const graph::GraphError& e) {
        // restore_sample's target guard, which lets Graph's errors out as Graph's.
        return restore_failed(e);
    } catch (...) {
        // Its message, if it has one, may not be safe to show.
        err << "error: unexpected failure\n";
        restore_note();
        return stopped();
    }
}

} // namespace rp
