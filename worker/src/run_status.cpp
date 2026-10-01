#include <rp/run_status.hpp>

#include <rp/canary_manifest.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/connector_registry.hpp>
#include <rp/graph_errors.hpp>
#include <rp/target_guard_graph.hpp>

#include "text_util.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::verification {

namespace {

using connector::ItemKind;
using connector::ItemOutcome;
using connector::RestoreStatus;
using nlohmann::json;

constexpr std::string_view kInternal = "internal";
constexpr std::string_view kBackupInfrastructure = "backup_infrastructure";

// Decision point 2: the unchecked items' codes, the most severe first.
constexpr std::array<std::string_view, 7> kSeverity{
    "target_guard", "graph_auth",      "graph_permission", "backup_infrastructure",
    "graph",        "graph_transient", "stale_target"};

// The codes CheckResult's item errors carry.
constexpr std::array<std::string_view, 6> kCheckCodes{
    "graph_auth", "graph_permission", "graph_transient", "target_guard", "graph", "stale_target"};

// A stop's code, and what it says in the status line: never a tenant value.
struct StopCode {
    std::string_view code;
    std::string_view text;
};

constexpr std::array<StopCode, 12> kStopCodes{{
    {"config", "the configuration isn't usable"},
    {"internal", "an unexpected failure"},
    {"backup_auth", "the backup product refused the credentials"},
    {"backup_transient", "the backup product couldn't be reached or asked to try later"},
    {"not_in_backup", "the client or a sampled item isn't in the backup"},
    {"no_restore_point", "no restore point to restore from"},
    {"target_guard", "the restore-target guard refused"},
    {"backup", "the backup product reported an error"},
    {"graph_auth", "Microsoft Graph refused the Worker's sign-in"},
    {"graph_permission", "Microsoft Graph refused a permission the Worker relies on"},
    {"graph_transient", "Microsoft Graph couldn't be reached or asked to try later"},
    {"graph", "Microsoft Graph reported an error"},
}};

const StopCode* stop_code(std::string_view code) noexcept
{
    const auto it = std::ranges::find(kStopCodes, code, &StopCode::code);
    return it == kStopCodes.end() ? nullptr : &*it;
}

bool is_check_code(std::string_view code) noexcept
{
    return std::ranges::find(kCheckCodes, code) != kCheckCodes.end();
}

std::string kind_name(ItemKind kind)
{
    return std::string{connector::to_string(kind)};
}

// Why the facts don't add up (row 1), in words without a tenant value; nullopt
// when they do.
std::optional<std::string> inconsistency(const RunFacts& facts)
{
    const ExpectedSet* expected = facts.expected;
    const connector::RestoreResult* restore = facts.restore;
    const CheckResult* check = facts.check;
    if (facts.stop) {
        if (!stop_code(facts.stop->error_code)) {
            return "the stop's code isn't one the status knows";
        }
        switch (facts.stop->phase) {
        case RunPhase::before_restore:
            if (restore || check) {
                return "a stop before the restore beside a restore result or a check";
            }
            break;
        case RunPhase::restore:
            if (restore || check) {
                return "a stop in the restore beside a restore result or a check";
            }
            if (!expected) {
                return "a stop in the restore without an expected set";
            }
            break;
        case RunPhase::check:
            if (!restore || check) {
                return "a stop in the check without a restore result or beside a check";
            }
            break;
        default:
            return "the stop's phase isn't one the status knows";
        }
    } else if (!expected) {
        return "no expected set and no stop";
    }
    if (restore && !expected) {
        return "a restore result without an expected set";
    }
    if (check && !restore) {
        return "a check without a restore result";
    }
    if (!expected) {
        return std::nullopt; // a stop before the sample: nothing else to line up
    }
    const std::vector<ExpectedItem>& items = expected->items;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (items[i].index != i) {
            return std::format("expected item {} isn't at its index", i);
        }
    }
    if (restore && items.empty()) {
        return "a restore of an empty sample";
    }
    if (!restore && !facts.stop && !items.empty()) {
        return "a sample without a restore result and no stop";
    }
    if (restore && restore->status != RestoreStatus::not_run) {
        if (restore->items.size() != items.size()) {
            return std::format("the restore reports {} item(s), the expected set {}",
                               restore->items.size(), items.size());
        }
        for (std::size_t i = 0; i < items.size(); ++i) {
            if (restore->items[i].kind != items[i].kind) {
                return std::format("restore item {} isn't its expected item's kind", i);
            }
        }
    }
    if (check) {
        if (check->items.size() != items.size()) {
            return std::format("the check has {} item(s), the expected set {}",
                               check->items.size(), items.size());
        }
        for (std::size_t i = 0; i < items.size(); ++i) {
            const ItemCheck& item = check->items[i];
            if (item.index != i || item.kind != items[i].kind) {
                return std::format("check item {} isn't its expected item", i);
            }
            if (item.outcome == CheckOutcome::error && !is_check_code(item.error_code)) {
                return std::format("check item {} is an error without a code the checker gives",
                                   i);
            }
        }
    }
    if (restore && !check && !facts.stop) {
        return "a restore result without a check";
    }
    return std::nullopt;
}

// The backup's account of item `i`, when the restore reports items lined up
// with the expected set.
const connector::ItemRestoreResult* restore_item(const RunFacts& facts, std::size_t i)
{
    if (!facts.restore || facts.restore->status == RestoreStatus::not_run ||
        i >= facts.restore->items.size()) {
        return nullptr;
    }
    return &facts.restore->items[i];
}

enum class Verdict { verified, failed, unchecked };

struct ItemVerdict {
    Verdict verdict = Verdict::failed;
    std::string code; // unchecked only
};

// Decision point 1's item rules, first fit wins.
ItemVerdict item_verdict(const RunFacts& facts, std::size_t i)
{
    const ItemCheck& item = facts.check->items[i];
    if (item.outcome == CheckOutcome::error) {
        return {Verdict::unchecked, item.error_code};
    }
    if (item.outcome == CheckOutcome::match) {
        return {Verdict::verified, {}};
    }
    const connector::ItemRestoreResult* restored = restore_item(facts, i);
    if (restored && restored->outcome != ItemOutcome::restored && restored->infrastructure) {
        return {Verdict::unchecked, std::string{kBackupInfrastructure}};
    }
    return {Verdict::failed, {}};
}

std::string or_dash(std::string text)
{
    return text.empty() ? std::string{"-"} : text;
}

std::vector<StatusWarning> warnings_of(const RunFacts& facts,
                                       const std::vector<ItemVerdict>& verdicts)
{
    std::vector<StatusWarning> warnings;
    const std::size_t items = facts.expected ? facts.expected->items.size() : 0;
    if (facts.restore) {
        for (const connector::RestoreSessionResult& session : facts.restore->sessions) {
            if (session.result == "Success") {
                continue;
            }
            std::string message = std::format("{} session {}: {}", kind_name(session.kind),
                                              or_dash(one_line(session.id)),
                                              or_dash(one_line(session.result)));
            if (!session.details.empty()) {
                message += " (" + one_line(session.details) + ")";
            }
            std::vector<std::size_t> indexes;
            for (std::size_t i = 0; i < items; ++i) {
                const connector::ItemRestoreResult* restored = restore_item(facts, i);
                if (restored && restored->session_id == session.id) {
                    indexes.push_back(i);
                }
            }
            warnings.push_back({"backup_session", std::move(message), std::move(indexes)});
        }
    }
    std::vector<std::size_t> unreported;
    std::vector<std::size_t> duplicates;
    for (std::size_t i = 0; i < verdicts.size(); ++i) {
        const connector::ItemRestoreResult* restored = restore_item(facts, i);
        if (verdicts[i].verdict == Verdict::verified && restored &&
            restored->outcome != ItemOutcome::restored) {
            unreported.push_back(i);
        }
        if (facts.check->items[i].duplicate) {
            duplicates.push_back(i);
        }
    }
    if (!unreported.empty()) {
        warnings.push_back({"backup_item",
                            std::format("{} verified item(s) the backup didn't report restored",
                                        unreported.size()),
                            std::move(unreported)});
    }
    if (!duplicates.empty()) {
        warnings.push_back({"duplicate",
                            std::format("{} item(s) had more than one restored copy; the newest "
                                        "was checked",
                                        duplicates.size()),
                            std::move(duplicates)});
    }
    for (const Shortfall& s : facts.shortfalls) {
        warnings.push_back({"shortfall",
                            std::format("{} {}: {} of {}", kind_name(s.kind), to_string(s.source),
                                        s.taken, s.wanted),
                            {}});
    }
    if (facts.check) {
        const CheckResult& c = *facts.check;
        if (const std::size_t stale = c.stale_mail + c.stale_sharepoint + c.stale_onedrive;
            stale > 0) {
            warnings.push_back(
                {"stale_copies",
                 std::format("{} copies from earlier runs in the restore targets were ignored "
                             "(mail {}, sharepoint {}, onedrive {})",
                             stale, c.stale_mail, c.stale_sharepoint, c.stale_onedrive),
                 {}});
        }
    }
    return warnings;
}

RunVerdict error_verdict(RunVerdict verdict, std::string_view code, std::string message)
{
    verdict.status = RunStatus::error;
    verdict.error_code = std::string{code};
    verdict.message = std::move(message);
    return verdict;
}

std::string stop_message(const RunStop& stop)
{
    const std::string_view text = stop_code(stop.error_code)->text;
    switch (stop.phase) {
    case RunPhase::restore:
        return std::format("the restore didn't complete: {} ({})", text, stop.error_code);
    case RunPhase::check:
        return std::format("the restored items couldn't be checked: {} ({})", text,
                           stop.error_code);
    default:
        return std::format("the run stopped before the restore: {} ({}); nothing was restored",
                           text, stop.error_code);
    }
}

// "<code> <n>, ..." for the unchecked items, in severity order.
std::string unchecked_codes(const std::vector<UncheckedItem>& unchecked)
{
    std::string text;
    for (const std::string_view code : kSeverity) {
        const auto n = std::ranges::count(unchecked, code, &UncheckedItem::error_code);
        if (n > 0) {
            text += std::format("{}{} {}", text.empty() ? "" : ", ", code, n);
        }
    }
    return text;
}

} // namespace

std::string_view to_string(RunStatus status) noexcept
{
    switch (status) {
    case RunStatus::pass:
        return "pass";
    case RunStatus::fail:
        return "fail";
    case RunStatus::error:
        return "error";
    }
    return "unknown";
}

std::string_view to_string(RunPhase phase) noexcept
{
    switch (phase) {
    case RunPhase::before_restore:
        return "before_restore";
    case RunPhase::restore:
        return "restore";
    case RunPhase::check:
        return "check";
    }
    return "unknown";
}

RunStop stop_reason(std::exception_ptr error, RunPhase phase)
{
    if (!error) {
        throw std::invalid_argument("stop_reason: no exception");
    }
    const auto stop = [phase](std::string_view code, const std::exception& e) {
        return RunStop{phase, std::string{code}, e.what()};
    };
    try {
        std::rethrow_exception(error);
    } catch (const ConfigError& e) {
        return stop("config", e);
    } catch (const sampling::ManifestError& e) {
        return stop("config", e);
    } catch (const connector::UnknownConnectorError& e) {
        return stop("config", e);
    } catch (const graph::WrongTargetError& e) {
        return stop("target_guard", e);
    } catch (const graph::AuthError& e) {
        return stop("graph_auth", e);
    } catch (const graph::PermissionError& e) {
        return stop("graph_permission", e);
    } catch (const graph::TransientError& e) {
        return stop("graph_transient", e);
    } catch (const graph::GraphError& e) {
        return stop("graph", e);
    } catch (const connector::SafetyViolation& e) {
        return stop("target_guard", e);
    } catch (const connector::AuthError& e) {
        return stop("backup_auth", e);
    } catch (const connector::TransientError& e) {
        return stop("backup_transient", e);
    } catch (const connector::NotFoundError& e) {
        return stop("not_in_backup", e);
    } catch (const connector::Error& e) {
        return stop("backup", e);
    } catch (...) {
        // Below: its message, if it has one, may not be safe to show.
    }
    return RunStop{phase, std::string{kInternal}, "unexpected failure"};
}

std::vector<Shortfall> shortfalls_of(const sampling::SampleRecord& record)
{
    std::vector<Shortfall> shortfalls;
    const std::pair<ItemKind, const sampling::KindRecord*> kinds[] = {
        {ItemKind::mail, &record.mail},
        {ItemKind::sharepoint, &record.sharepoint},
        {ItemKind::onedrive, &record.onedrive}};
    for (const auto& [kind, k] : kinds) {
        const int canary_wanted = (k->requested + 1) / 2;
        const int canary_taken = static_cast<int>(k->canary_ids.size());
        if (canary_taken < canary_wanted) {
            shortfalls.push_back({kind, ItemSource::canary, canary_wanted, canary_taken});
        }
        if (k->random_taken < k->random_wanted) {
            shortfalls.push_back({kind, ItemSource::random, k->random_wanted, k->random_taken});
        }
    }
    return shortfalls;
}

RunVerdict decide_status(const RunFacts& facts)
{
    RunVerdict verdict;
    verdict.items = facts.expected ? facts.expected->items.size() : 0;
    // Row 1.
    if (const std::optional<std::string> why = inconsistency(facts)) {
        return error_verdict(std::move(verdict), kInternal,
                             "the run's results don't add up: " + *why);
    }
    std::vector<ItemVerdict> verdicts;
    if (facts.check) {
        for (std::size_t i = 0; i < facts.check->items.size(); ++i) {
            verdicts.push_back(item_verdict(facts, i));
        }
    }
    verdict.warnings = warnings_of(facts, verdicts);
    // Row 2.
    if (facts.stop) {
        return error_verdict(std::move(verdict), facts.stop->error_code,
                             stop_message(*facts.stop));
    }
    // Row 3.
    if (verdict.items == 0) {
        return error_verdict(std::move(verdict), "empty_sample",
                             "the sample is empty: nothing to restore");
    }
    // Row 4.
    if (facts.restore->status == RestoreStatus::not_run) {
        return error_verdict(std::move(verdict), "not_run",
                             "the restore didn't run: nothing was sent");
    }
    std::size_t missing = 0;
    std::size_t mismatch = 0;
    for (std::size_t i = 0; i < verdicts.size(); ++i) {
        switch (verdicts[i].verdict) {
        case Verdict::verified:
            switch (facts.expected->items[i].expected_kind) {
            case ExpectedKind::manifest:
                ++verdict.verified_manifest;
                break;
            case ExpectedKind::fields:
                ++verdict.verified_fields;
                break;
            case ExpectedKind::metadata:
                ++verdict.verified_metadata;
                break;
            }
            break;
        case Verdict::failed:
            verdict.failed.push_back(i);
            ++(facts.check->items[i].outcome == CheckOutcome::missing ? missing : mismatch);
            break;
        case Verdict::unchecked:
            verdict.unchecked.push_back({i, verdicts[i].code});
            break;
        }
    }
    const std::size_t n = verdict.items;
    // Row 5.
    if (!verdict.failed.empty()) {
        verdict.status = RunStatus::fail;
        verdict.message = std::format("{} of {} item(s) didn't verify ({} missing, {} mismatch)",
                                      verdict.failed.size(), n, missing, mismatch);
        if (!verdict.unchecked.empty()) {
            verdict.message += std::format("; {} couldn't be checked", verdict.unchecked.size());
        }
        return verdict;
    }
    // Row 6.
    if (facts.restore->status == RestoreStatus::failed && verdict.unchecked.empty()) {
        return error_verdict(std::move(verdict), "restore_contradiction",
                             "the backup reported nothing restored, yet every item verified: the "
                             "evidence contradicts itself");
    }
    // Row 7.
    if (!verdict.unchecked.empty()) {
        const auto code = std::ranges::find_if(kSeverity, [&](std::string_view c) {
            return std::ranges::find(verdict.unchecked, c, &UncheckedItem::error_code) !=
                   verdict.unchecked.end();
        });
        std::string message =
            std::format("{} of {} item(s) couldn't be checked ({})", verdict.unchecked.size(), n,
                        unchecked_codes(verdict.unchecked));
        if (verdict.verified() > 0) {
            message += std::format("; {} verified", verdict.verified());
        }
        return error_verdict(std::move(verdict), *code, std::move(message));
    }
    // Row 8.
    verdict.status = RunStatus::pass;
    verdict.message = std::format("{} of {} item(s) verified: manifest {}, fields {}, metadata {}",
                                  n, n, verdict.verified_manifest, verdict.verified_fields,
                                  verdict.verified_metadata);
    return verdict;
}

json to_json(const RunVerdict& verdict)
{
    json out = json::object();
    out["status"] = to_string(verdict.status);
    if (verdict.status == RunStatus::error) {
        out["error_code"] = verdict.error_code;
    }
    out["message"] = verdict.message;
    out["counts"] = {{"items", verdict.items},
                     {"verified", verdict.verified()},
                     {"failed", verdict.failed.size()},
                     {"unchecked", verdict.unchecked.size()}};
    out["verified"] = {{"manifest", verdict.verified_manifest},
                       {"fields", verdict.verified_fields},
                       {"metadata", verdict.verified_metadata}};
    out["failed_items"] = verdict.failed;
    json unchecked = json::array();
    for (const UncheckedItem& item : verdict.unchecked) {
        unchecked.push_back({{"index", item.index}, {"error_code", item.error_code}});
    }
    out["unchecked_items"] = std::move(unchecked);
    json warnings = json::array();
    for (const StatusWarning& w : verdict.warnings) {
        warnings.push_back({{"code", w.code}, {"message", w.message}, {"indexes", w.indexes}});
    }
    out["warnings"] = std::move(warnings);
    return out;
}

int exit_code_of(const RunVerdict& verdict) noexcept
{
    switch (verdict.status) {
    case RunStatus::pass:
        return exit_code::ok;
    case RunStatus::fail:
        return exit_code::restore;
    default:
        break;
    }
    const std::string_view code = verdict.error_code;
    if (code == "config" || code == kInternal) {
        return exit_code::config;
    }
    if (code == "backup_auth" || code == "graph_auth" || code == "graph_permission") {
        return exit_code::auth;
    }
    if (code == "backup_transient" || code == "graph_transient") {
        return exit_code::transient;
    }
    return exit_code::service;
}

} // namespace rp::verification
