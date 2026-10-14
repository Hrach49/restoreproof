#include <rp/run_status.hpp>

#include <rp/canary_manifest.hpp>
#include <rp/cli.hpp>
#include <rp/client_check.hpp>
#include <rp/config.hpp>
#include <rp/connector_registry.hpp>
#include <rp/graph_errors.hpp>
#include <rp/target_guard_graph.hpp>

#include "text_util.hpp"
#include "veeam_time.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <map>
#include <optional>
#include <regex>
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
constexpr std::string_view kNotInBackup = "not_in_backup";
constexpr std::string_view kRestoreContradiction = "restore_contradiction";
constexpr std::string_view kResultInvalid = "result_invalid";
constexpr std::string_view kInterrupted = "interrupted";
constexpr std::string_view kJobInvalid = "job_invalid";
constexpr std::string_view kClientMismatch = "client_mismatch";
constexpr std::string_view kConnectorUnknown = "connector_unknown";
constexpr std::string_view kTargetGuard = "target_guard";

// StatusWarning's codes, in the order a verdict lists them: warning_codes().
constexpr std::string_view kBackupSession = "backup_session";
constexpr std::string_view kBackupItem = "backup_item";
constexpr std::string_view kDuplicate = "duplicate";
constexpr std::string_view kShortfall = "shortfall";
constexpr std::string_view kStaleCopies = "stale_copies";
// W6.3: files whose export from the backup gave nothing, checked by name and
// size alone (docs/decisions.md 2026-10-14, W6.3 and W6.2, point 5).
constexpr std::string_view kContentExport = "content_export";
constexpr std::array<std::string_view, 6> kWarningCodes{kBackupSession, kBackupItem, kDuplicate,
                                                        kShortfall, kStaleCopies, kContentExport};

constexpr int kNoSeverity = -1;

// Decision point 2, the one vocabulary: each error code, what it says in a
// stop's status line (empty: never a stop's code), whether CheckResult's item
// errors carry it, its rank among the unchecked items' codes (0 the most
// severe; kNoSeverity: never an unchecked item's) and its exit code. Never a
// tenant value. Every code a status carries is here (error_codes()); a code
// that isn't exits with exit_code::service.
struct ErrorCode {
    std::string_view code;
    std::string_view stop_text;
    bool check = false;
    int severity = kNoSeverity;
    int exit = exit_code::service;
};

constexpr std::array<ErrorCode, 22> kCodes{{
    {"config", "the configuration isn't usable", false, kNoSeverity, exit_code::config},
    {"internal", "an unexpected failure", false, kNoSeverity, exit_code::config},
    {"backup_auth", "the backup product refused the credentials", false, kNoSeverity,
     exit_code::auth},
    {"backup_transient", "the backup product couldn't be reached or asked to try later", false,
     kNoSeverity, exit_code::transient},
    {"not_in_backup", "the client or a sampled item isn't in the backup", false, 4,
     exit_code::service},
    // In the vocabulary, not yet a stop's (docs/decisions.md, W3.3 build notes 8).
    {"no_restore_point", "no restore point to restore from", false, kNoSeverity,
     exit_code::service},
    {kTargetGuard, "the restore-target guard refused", true, 0, exit_code::service},
    {"backup", "the backup product reported an error", false, kNoSeverity, exit_code::service},
    {"graph_auth", "Microsoft Graph refused the Worker's sign-in", true, 1, exit_code::auth},
    {"graph_permission", "Microsoft Graph refused a permission the Worker relies on", true, 2,
     exit_code::auth},
    {"backup_infrastructure", "", false, 3, exit_code::service},
    {"graph", "Microsoft Graph reported an error", true, 5, exit_code::service},
    {"graph_transient", "Microsoft Graph couldn't be reached or asked to try later", true, 6,
     exit_code::transient},
    {"stale_target", "", true, 7, exit_code::service},
    {"empty_sample", "", false, kNoSeverity, exit_code::service},
    {"not_run", "", false, kNoSeverity, exit_code::service},
    // Row 6's own code.
    {kRestoreContradiction, "", false, kNoSeverity, exit_code::service},
    // result_invalid()'s: the Worker's own fault, as internal (W4.1 point 5).
    {kResultInvalid, "", false, kNoSeverity, exit_code::config},
    // A stop asked of the Worker itself (W4.8 points 13 and 14): a stop's
    // code, no service's fault.
    {kInterrupted, "the run was interrupted", false, kNoSeverity, exit_code::service},
    // job_invalid()'s: a job the Worker was handed and can't run (W4.8 point 4).
    {kJobInvalid, "", false, kNoSeverity, exit_code::config},
    // W4.11 point 4: the client check's refusal, a stop's code; the job's
    // claim and the backup's facts disagree, no service refused the Worker.
    {kClientMismatch, "the backup's organisation doesn't match the client's profile", false,
     kNoSeverity, exit_code::service},
    // W4.11 point 4: a job asking for a connector this Worker lacks, as
    // job_invalid; a stop's code too (one type, one code), and the loop's.
    {kConnectorUnknown, "the connector type isn't one this Worker has", false, kNoSeverity,
     exit_code::config},
}};

// Every item error's code ranks, or row 7 would have nothing to pick; each
// rank once, 0 to n - 1.
consteval bool codes_hold_together()
{
    int ranked = 0;
    for (const ErrorCode& c : kCodes) {
        if (c.check && c.severity == kNoSeverity) {
            return false;
        }
        ranked += c.severity != kNoSeverity ? 1 : 0;
    }
    for (int rank = 0; rank < ranked; ++rank) {
        int n = 0;
        for (const ErrorCode& c : kCodes) {
            n += c.severity == rank ? 1 : 0;
        }
        if (n != 1) {
            return false;
        }
    }
    return true;
}
static_assert(codes_hold_together(), "every check code ranks, each rank once");

const ErrorCode* find_code(std::string_view code) noexcept
{
    const auto it = std::ranges::find(kCodes, code, &ErrorCode::code);
    return it == kCodes.end() ? nullptr : &*it;
}

// A stop's code: one with a status-line text.
const ErrorCode* stop_code(std::string_view code) noexcept
{
    const ErrorCode* found = find_code(code);
    return found && !found->stop_text.empty() ? found : nullptr;
}

bool is_check_code(std::string_view code) noexcept
{
    const ErrorCode* found = find_code(code);
    return found && found->check;
}

// An unchecked item's code's rank; row 1 has made sure each has one.
int severity_of(std::string_view code) noexcept
{
    const ErrorCode* found = find_code(code);
    return found ? found->severity : kNoSeverity;
}

// Whether a value is one of its enum's: a value cast from outside it can't
// be decided on (row 1). No default, so a new enumerator must be added here.
bool known(RunPhase phase) noexcept
{
    switch (phase) {
    case RunPhase::before_restore:
    case RunPhase::restore:
    case RunPhase::check:
        return true;
    }
    return false;
}

bool known(CheckOutcome outcome) noexcept
{
    switch (outcome) {
    case CheckOutcome::match:
    case CheckOutcome::mismatch:
    case CheckOutcome::missing:
    case CheckOutcome::error:
        return true;
    }
    return false;
}

bool known(ExpectedKind kind) noexcept
{
    switch (kind) {
    case ExpectedKind::manifest:
    case ExpectedKind::fields:
    case ExpectedKind::metadata:
    case ExpectedKind::backup_content:
        return true;
    }
    return false;
}

bool known(RestoreStatus status) noexcept
{
    switch (status) {
    case RestoreStatus::not_run:
    case RestoreStatus::succeeded:
    case RestoreStatus::partial:
    case RestoreStatus::failed:
        return true;
    }
    return false;
}

bool known(ItemOutcome outcome) noexcept
{
    switch (outcome) {
    case ItemOutcome::unknown:
    case ItemOutcome::restored:
    case ItemOutcome::failed:
    case ItemOutcome::not_in_backup:
        return true;
    }
    return false;
}

// Whether a check item's `found` is what its outcome says: a match or a
// mismatch compared a copy, missing and error didn't.
bool found_fits(const ItemCheck& item) noexcept
{
    return item.found ==
           (item.outcome == CheckOutcome::match || item.outcome == CheckOutcome::mismatch);
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
        if (!known(facts.stop->phase)) {
            return "the stop's phase isn't one the status knows";
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
    if (restore) {
        if (!known(restore->status)) {
            return "the restore's status isn't one the status knows";
        }
        for (std::size_t i = 0; i < restore->items.size(); ++i) {
            if (!known(restore->items[i].outcome)) {
                return std::format("restore item {}'s outcome isn't one the status knows", i);
            }
        }
    }
    if (!expected) {
        return std::nullopt; // a stop before the sample: nothing else to line up
    }
    const std::vector<ExpectedItem>& items = expected->items;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (items[i].index != i) {
            return std::format("expected item {} isn't at its index", i);
        }
        if (!known(items[i].expected_kind)) {
            return std::format("expected item {}'s expected kind isn't one the status knows", i);
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
            if (!known(item.outcome)) {
                return std::format("check item {}'s outcome isn't one the status knows", i);
            }
            if (!found_fits(item)) {
                return std::format("check item {}'s outcome contradicts whether a copy was found",
                                   i);
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

// Whether the restore point should hold item `i`, which the backup said it
// doesn't though it holds the item's container: a canary, and the point
// taken strictly after the canaries were seeded. Anything not known (a time
// that doesn't read) says no.
bool point_should_hold(const RunFacts& facts, std::size_t i)
{
    if (facts.expected->items[i].source != ItemSource::canary) {
        return false; // a random item's pool came from this very restore point
    }
    const std::optional<VeeamTime> seeded = parse_veeam_time(facts.expected->canaries_seeded_at);
    const std::optional<VeeamTime> point = parse_veeam_time(facts.restore_point_time);
    return seeded && point && *seeded < *point;
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
    // A point without the item's whole container doesn't cover the item: a
    // job or configuration matter, never the backup losing a canary.
    if (restored && restored->outcome == ItemOutcome::not_in_backup &&
        (restored->container_missing || !point_should_hold(facts, i))) {
        return {Verdict::unchecked, std::string{kNotInBackup}};
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
            if (is_backup_counts(session.details)) {
                message += " (" + session.details + ")";
            }
            std::vector<std::size_t> indexes;
            for (std::size_t i = 0; i < items; ++i) {
                const connector::ItemRestoreResult* restored = restore_item(facts, i);
                if (restored && !session.id.empty() && restored->session_id == session.id) {
                    indexes.push_back(i);
                }
            }
            warnings.push_back(
                {std::string{kBackupSession}, std::move(message), std::move(indexes)});
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
        warnings.push_back({std::string{kBackupItem},
                            std::format("{} verified item(s) the backup didn't report restored",
                                        unreported.size()),
                            std::move(unreported)});
    }
    if (!duplicates.empty()) {
        warnings.push_back({std::string{kDuplicate},
                            std::format("{} item(s) had more than one restored copy; the newest "
                                        "was checked",
                                        duplicates.size()),
                            std::move(duplicates)});
    }
    for (const Shortfall& s : facts.shortfalls) {
        warnings.push_back({std::string{kShortfall},
                            std::format("{} {}: {} of {}", kind_name(s.kind), to_string(s.source),
                                        s.taken, s.wanted),
                            {}});
    }
    if (facts.check) {
        const CheckResult& c = *facts.check;
        if (const std::size_t stale = c.stale_mail + c.stale_sharepoint + c.stale_onedrive;
            stale > 0) {
            warnings.push_back(
                {std::string{kStaleCopies},
                 std::format("{} copies from earlier runs in the restore targets were ignored "
                             "(mail {}, sharepoint {}, onedrive {})",
                             stale, c.stale_mail, c.stale_sharepoint, c.stale_onedrive),
                 {}});
        }
    }
    // W6.3: the files an export was asked for and gave nothing, so they were
    // checked by name and size alone; counted by word in the words' order.
    if (facts.expected) {
        std::vector<std::size_t> failed;
        std::size_t asked = 0;
        std::map<std::string_view, std::size_t> by_word;
        for (const ExpectedItem& item : facts.expected->items) {
            const std::string& word = item.export_word;
            if (word.empty() || word == "no_rule" || word == "not_in_backup") {
                continue;
            }
            ++asked;
            if (is_failed_export(word)) {
                failed.push_back(item.index);
                ++by_word[word];
            }
        }
        if (!failed.empty()) {
            std::string counts;
            for (const std::string_view word : export_words()) {
                if (const auto it = by_word.find(word); it != by_word.end()) {
                    counts += (counts.empty() ? "" : ", ") + std::string{word} + " " +
                              std::to_string(it->second);
                }
            }
            warnings.push_back(
                {std::string{kContentExport},
                 std::format("{} of {} file(s) couldn't be exported from the backup and were "
                             "checked by name and size alone ({})",
                             failed.size(), asked, counts),
                 std::move(failed)});
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
    const std::string_view text = stop_code(stop.error_code)->stop_text;
    switch (stop.phase) {
    case RunPhase::restore:
        if (stop.nothing_restored) {
            return std::format("the restore didn't start: {} ({}); nothing was restored", text,
                               stop.error_code);
        }
        return std::format(
            "the restore didn't complete: {} ({}); items may be in the restore targets", text,
            stop.error_code);
    case RunPhase::check:
        return std::format("the restored items couldn't be checked: {} ({})", text,
                           stop.error_code);
    case RunPhase::before_restore:
        break;
    }
    // before_restore; row 1 has refused a phase outside the enum.
    return std::format("the run stopped before the restore: {} ({}); nothing was restored", text,
                       stop.error_code);
}

// Whether a restore may have been sent, so items may be in the targets: a
// restore that ran, or a stop in the restore that didn't promise nothing was.
bool restore_sent(const RunFacts& facts) noexcept
{
    if (facts.restore) {
        return facts.restore->status != RestoreStatus::not_run;
    }
    return facts.stop && facts.stop->phase == RunPhase::restore && !facts.stop->nothing_restored;
}

// How a run ended, in the status's own words: "pass", "fail", "error <code>",
// the code only when the table holds it, so nothing else is ever repeated.
std::string ended_as(RunStatus status, std::string_view code)
{
    std::string ended{to_string(status)};
    if (status == RunStatus::error && find_code(code)) {
        ended += " " + std::string{code};
    }
    return ended;
}

// What a replaced verdict keeps: whether items may be in the targets, the
// item count and the warnings. The item verdicts go, as rows 1 to 4 leave them.
RunVerdict kept_of(const RunVerdict& verdict)
{
    RunVerdict out;
    out.restore_sent = verdict.restore_sent;
    out.items = verdict.items;
    out.warnings = verdict.warnings;
    return out;
}

// A verdict that says nothing of items, for a result written afterwards.
RunVerdict bare_verdict(bool restore_sent)
{
    RunVerdict out;
    out.restore_sent = restore_sent;
    return out;
}

// "<code> <n>, ..." for the unchecked items, in severity order.
std::string unchecked_codes(const std::vector<UncheckedItem>& unchecked)
{
    std::string text;
    for (const std::string_view code : unchecked_item_codes()) {
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
        RunStop out{phase, std::string{code}};
        out.nothing_restored = phase == RunPhase::restore &&
                               std::string_view{e.what()}.ends_with(connector::kNothingRestored);
        return out;
    };
    try {
        std::rethrow_exception(error);
    } catch (const ConfigError& e) {
        return stop("config", e);
    } catch (const sampling::ManifestError& e) {
        return stop("config", e);
    } catch (const connector::UnknownConnectorError& e) {
        return stop(kConnectorUnknown, e);
    } catch (const ClientMismatchError& e) {
        return stop(kClientMismatch, e);
    } catch (const graph::GraphError& e) {
        // The check's own mapping: a Graph failure has one code wherever it happens.
        return stop(read_error_code(std::current_exception()), e);
    } catch (const connector::SafetyViolation& e) {
        return stop(kTargetGuard, e);
    } catch (const connector::Interrupted& e) {
        return stop(kInterrupted, e);
    } catch (const connector::AuthError& e) {
        return stop("backup_auth", e);
    } catch (const connector::TransientError& e) {
        return stop("backup_transient", e);
    } catch (const connector::NotFoundError& e) {
        return stop("not_in_backup", e);
    } catch (const connector::Error& e) {
        return stop("backup", e);
    } catch (...) {
        // Below: an exception the Worker doesn't know promises nothing.
    }
    return RunStop{phase, std::string{kInternal}};
}

std::vector<Shortfall> shortfalls_of(const sampling::SampleRecord& record)
{
    std::vector<Shortfall> shortfalls;
    const std::pair<ItemKind, const sampling::KindRecord*> kinds[] = {
        {ItemKind::mail, &record.mail},
        {ItemKind::sharepoint, &record.sharepoint},
        {ItemKind::onedrive, &record.onedrive}};
    for (const auto& [kind, k] : kinds) {
        // W6.2: a run without canaries wanted none.
        const int canary_wanted = record.canaries ? (k->requested + 1) / 2 : 0;
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
    verdict.restore_sent = restore_sent(facts);
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
            case ExpectedKind::backup_content:
                ++verdict.verified_backup_content;
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
        return error_verdict(std::move(verdict), kRestoreContradiction,
                             "the backup reported nothing restored, yet every item verified: the "
                             "evidence contradicts itself");
    }
    // Row 7.
    if (!verdict.unchecked.empty()) {
        const UncheckedItem& worst = std::ranges::min(
            verdict.unchecked, {},
            [](const UncheckedItem& item) { return severity_of(item.error_code); });
        std::string message =
            std::format("{} of {} item(s) couldn't be checked ({})", verdict.unchecked.size(), n,
                        unchecked_codes(verdict.unchecked));
        if (verdict.verified() > 0) {
            message += std::format("; {} verified", verdict.verified());
        }
        const std::string code = worst.error_code;
        return error_verdict(std::move(verdict), code, std::move(message));
    }
    // Row 8.
    verdict.status = RunStatus::pass;
    verdict.message = std::format(
        "{} of {} item(s) verified: manifest {}, fields {}, metadata {}, backup_content {}", n, n,
        verdict.verified_manifest, verdict.verified_fields, verdict.verified_metadata,
        verdict.verified_backup_content);
    return verdict;
}

RunVerdict result_invalid(const RunVerdict& verdict)
{
    // Only words of the status's own: a code the table doesn't hold isn't
    // repeated.
    return error_verdict(kept_of(verdict), kResultInvalid,
                         "the result isn't valid restoreproof.result.v1; the run itself ended " +
                             ended_as(verdict.status, verdict.error_code));
}

bool interrupt_replaces(const RunVerdict& verdict) noexcept
{
    return verdict.status == RunStatus::error && verdict.error_code != kInterrupted &&
           verdict.error_code != kTargetGuard && verdict.error_code != kResultInvalid &&
           verdict.error_code != kClientMismatch && verdict.error_code != kConnectorUnknown;
}

RunVerdict interrupted(const RunVerdict& verdict)
{
    return error_verdict(kept_of(verdict), kInterrupted,
                         "the Worker was stopped during the run; the run itself ended " +
                             ended_as(verdict.status, verdict.error_code));
}

RunVerdict interrupted_before_result(bool restore_requested)
{
    return error_verdict(
        bare_verdict(restore_requested), kInterrupted,
        restore_requested ? "the run was interrupted before its result was written; a restore "
                            "request may have been sent, so items may be in the restore targets"
                          : "the run was interrupted before its result was written; no restore "
                            "request had been sent");
}

RunVerdict ended_without_result(bool restore_requested)
{
    return error_verdict(bare_verdict(restore_requested), kInternal,
                         "the run ended without a result the Worker could write; this result "
                         "was written afterwards");
}

RunVerdict result_invalid_afterwards(RunStatus ended_status, std::string_view ended_code,
                                     bool restore_requested)
{
    RunVerdict ended = bare_verdict(restore_requested);
    ended.status = ended_status;
    ended.error_code = std::string{ended_code};
    return result_invalid(ended);
}

RunVerdict connector_unknown()
{
    return error_verdict(bare_verdict(false), kConnectorUnknown,
                         "the job's connector type isn't one this Worker has; nothing was done");
}

RunVerdict job_invalid(std::string_view key)
{
    return error_verdict(bare_verdict(false), kJobInvalid,
                         std::format("the job isn't a valid job ({}); nothing was done", key));
}

std::vector<std::string_view> error_codes()
{
    std::vector<std::string_view> codes;
    for (const ErrorCode& c : kCodes) {
        codes.push_back(c.code);
    }
    return codes;
}

std::vector<std::string_view> unchecked_item_codes()
{
    std::vector<const ErrorCode*> ranked;
    for (const ErrorCode& c : kCodes) {
        if (c.severity != kNoSeverity) {
            ranked.push_back(&c);
        }
    }
    std::ranges::sort(ranked, {}, &ErrorCode::severity);
    std::vector<std::string_view> codes;
    for (const ErrorCode* c : ranked) {
        codes.push_back(c->code);
    }
    return codes;
}

std::vector<std::string_view> warning_codes()
{
    return {kWarningCodes.begin(), kWarningCodes.end()};
}

bool is_backup_counts(std::string_view details)
{
    // Any other text, inside the parenthesis too, may name a tenant value (an
    // item, an address), so it never goes into a warning or the result.
    static const std::string count =
        R"(\d+ (successes|success|warnings?|failures?|errors?|skipped))";
    static const std::regex counts(R"(\d+ items? processed( \()" + count + "(, " + count +
                                   R"()*\))?)");
    return std::regex_match(details.begin(), details.end(), counts);
}

json to_json(const connector::RestoreResult& result)
{
    json sessions = json::array();
    for (const connector::RestoreSessionResult& s : result.sessions) {
        sessions.push_back({{"id", s.id},
                            {"kind", connector::to_string(s.kind)},
                            {"result", s.result},
                            {"details", is_backup_counts(s.details) ? json(s.details) : json()},
                            {"items_sent", s.items_sent},
                            {"items_restored", s.items_restored},
                            {"started_at_raw", s.started_at},
                            {"ended_at_raw", s.ended_at}});
    }
    json items = json::array();
    for (std::size_t i = 0; i < result.items.size(); ++i) {
        const connector::ItemRestoreResult& item = result.items[i];
        items.push_back({{"index", i},
                         {"kind", connector::to_string(item.kind)},
                         {"outcome", connector::to_string(item.outcome)},
                         {"infrastructure", item.infrastructure},
                         {"container_missing", item.container_missing},
                         {"session_id", item.session_id}});
    }
    return {{"status", connector::to_string(result.status)},
            {"items_sent", result.items_sent},
            {"items_restored", result.items_restored},
            {"sessions", std::move(sessions)},
            {"items", std::move(items)}};
}

json to_json(const RunVerdict& verdict)
{
    json out = json::object();
    out["status"] = to_string(verdict.status);
    if (verdict.status == RunStatus::error) {
        out["error_code"] = verdict.error_code;
    }
    out["message"] = verdict.message;
    out["restore_sent"] = verdict.restore_sent;
    out["counts"] = {{"items", verdict.items},
                     {"verified", verdict.verified()},
                     {"failed", verdict.failed.size()},
                     {"unchecked", verdict.unchecked.size()}};
    out["verified"] = {{"manifest", verdict.verified_manifest},
                       {"fields", verdict.verified_fields},
                       {"metadata", verdict.verified_metadata},
                       {"backup_content", verdict.verified_backup_content}};
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

int exit_code_of(std::string_view error_code) noexcept
{
    const ErrorCode* found = find_code(error_code);
    return found ? found->exit : exit_code::service;
}

int exit_code_of(const RunVerdict& verdict) noexcept
{
    switch (verdict.status) {
    case RunStatus::pass:
        return exit_code::ok;
    case RunStatus::fail:
        return exit_code::restore;
    case RunStatus::error:
        break;
    }
    return exit_code_of(verdict.error_code);
}

} // namespace rp::verification
