// The status decision table (W3.3, rp/run_status.hpp): what a run produced,
// turned into pass, fail or error. Pure: the facts are built here as
// `rpworker restore` gathers them. The tables below are the decision itself,
// row for row: R<n><x> is row n of the run table in docs/verification.md
// ("The status decision table"), I<n><x> rule n of the item verdicts, S<n> a
// step of the severity order, E<n> an exception type of error-code table, X<n>
// an exit code. Failure paths first: facts that don't add up, stops, then
// fail before error before pass. The choices are the 2026-10-01 W3.3 entry in
// docs/decisions.md.

#include <rp/canary_manifest.hpp>
#include <rp/checker.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/connector.hpp>
#include <rp/connector_registry.hpp>
#include <rp/expected_set.hpp>
#include <rp/graph_errors.hpp>
#include <rp/run_status.hpp>
#include <rp/sample_selector.hpp>
#include <rp/target_guard_graph.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <exception>
#include <functional>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

namespace connector = rp::connector;
namespace verification = rp::verification;
using connector::ItemKind;
using connector::ItemOutcome;
using connector::RestoreStatus;
using nlohmann::json;
using verification::CheckOutcome;
using verification::ExpectedKind;
using verification::ItemSource;
using verification::RunPhase;
using verification::RunStatus;
using verification::RunStop;
using verification::Shortfall;

// One item of a run: what the check found and what the backup said.
struct It {
    CheckOutcome check = CheckOutcome::match;
    std::string code;                              // the check's, for an error
    ItemOutcome restored = ItemOutcome::restored;  // the backup's word
    bool infrastructure = false;                   // the backup's reading of its message
    bool duplicate = false;
    ItemKind kind = ItemKind::mail;
    ExpectedKind expected_kind = ExpectedKind::manifest;
    std::string session = "s-1";
};

It match()
{
    return It{};
}

It missing()
{
    return It{.check = CheckOutcome::missing};
}

It mismatch()
{
    return It{.check = CheckOutcome::mismatch};
}

It error(const std::string& code)
{
    return It{.check = CheckOutcome::error, .code = code};
}

// The facts of one run, owned, with RunFacts pointing into them.
struct Run {
    verification::ExpectedSet expected;
    connector::RestoreResult restore;
    verification::CheckResult check;
    bool with_expected = true;
    bool with_restore = true;
    bool with_check = true;
    std::optional<RunStop> stop;
    std::vector<Shortfall> shortfalls;

    verification::RunFacts facts() const
    {
        return {with_expected ? &expected : nullptr, shortfalls, stop,
                with_restore ? &restore : nullptr, with_check ? &check : nullptr};
    }
};

// A run of `items`, its restore `status`, one session per session name in
// `items`, each with `session_result`.
Run run_of(const std::vector<It>& items, RestoreStatus status = RestoreStatus::succeeded,
           const std::string& session_result = "Success")
{
    Run run;
    run.expected.manifest_sha256 = std::string(64, 'f');
    run.restore.status = status;
    std::set<std::string> sessions;
    for (std::size_t i = 0; i < items.size(); ++i) {
        const It& it = items[i];
        verification::ExpectedItem want;
        want.index = i;
        want.kind = it.kind;
        want.expected_kind = it.expected_kind;
        want.source = it.expected_kind == ExpectedKind::manifest ? ItemSource::canary
                                                                 : ItemSource::random;
        run.expected.items.push_back(want);

        connector::ItemRestoreResult restored;
        restored.kind = it.kind;
        restored.name = "Item " + std::to_string(i);
        restored.session_id = it.session;
        restored.outcome = it.restored;
        restored.infrastructure = it.infrastructure;
        run.restore.items.push_back(restored);
        ++run.restore.items_sent;
        run.restore.items_restored += it.restored == ItemOutcome::restored ? 1 : 0;

        verification::ItemCheck checked;
        checked.index = i;
        checked.kind = it.kind;
        checked.outcome = it.check;
        checked.found = it.check == CheckOutcome::match || it.check == CheckOutcome::mismatch;
        checked.error_code = it.code;
        checked.duplicate = it.duplicate;
        checked.copies = it.duplicate ? 2 : (checked.found ? 1 : 0);
        run.check.items.push_back(checked);

        if (sessions.insert(it.session).second) {
            connector::RestoreSessionResult session;
            session.id = it.session;
            session.kind = it.kind;
            session.result = session_result;
            run.restore.sessions.push_back(session);
            run.restore.session_ids.push_back(it.session);
        }
    }
    return run;
}

Run with_stop(Run run, RunPhase phase, const std::string& code)
{
    run.stop = RunStop{phase, code, "what() of the exception"};
    return run;
}

// Only what a stop before the sample leaves: the stop.
Run stop_only(RunPhase phase, const std::string& code)
{
    Run run;
    run.with_expected = false;
    run.with_restore = false;
    run.with_check = false;
    run.stop = RunStop{phase, code, "what() of the exception"};
    return run;
}

// The sample's facts only: the expected set, no restore, no check.
Run sample_only(const std::vector<It>& items)
{
    Run run = run_of(items);
    run.with_restore = false;
    run.with_check = false;
    return run;
}

using Unchecked = std::vector<std::pair<std::size_t, std::string>>;

struct Row {
    std::string id;
    std::string what;
    std::function<Run()> make;
    RunStatus status;
    std::string code;
    std::vector<std::size_t> failed;
    Unchecked unchecked;
    std::vector<std::string> warnings; // codes, in order
};

std::vector<std::string> warning_codes(const verification::RunVerdict& verdict)
{
    std::vector<std::string> codes;
    for (const verification::StatusWarning& w : verdict.warnings) {
        codes.push_back(w.code);
    }
    return codes;
}

Unchecked unchecked_of(const verification::RunVerdict& verdict)
{
    Unchecked out;
    for (const verification::UncheckedItem& item : verdict.unchecked) {
        out.emplace_back(item.index, item.error_code);
    }
    return out;
}

void check_row(const Row& row)
{
    INFO(row.id << ": " << row.what);
    const Run run = row.make();
    const verification::RunVerdict verdict = verification::decide_status(run.facts());
    CHECK(verdict.status == row.status);
    CHECK(verdict.error_code == row.code);
    CHECK(verdict.failed == row.failed);
    CHECK(unchecked_of(verdict) == row.unchecked);
    CHECK(warning_codes(verdict) == row.warnings);
    CHECK_FALSE(verdict.message.empty());
    CHECK(verdict.message.find('\n') == std::string::npos);
}

constexpr auto kPass = RunStatus::pass;
constexpr auto kFail = RunStatus::fail;
constexpr auto kError = RunStatus::error;

// Row 1: facts that don't add up are error internal, before anything else,
// with no warnings.
std::vector<Row> row1()
{
    const auto internal = [](std::string id, std::string what, std::function<Run()> make) {
        return Row{std::move(id), std::move(what), std::move(make), kError, "internal", {}, {}, {}};
    };
    return {
        internal("R1a", "a check without a restore result",
                 [] {
                     Run r = run_of({match()});
                     r.with_restore = false;
                     return r;
                 }),
        internal("R1b", "no expected set and no stop",
                 [] {
                     Run r = run_of({match()});
                     r.with_expected = false;
                     r.with_restore = false;
                     r.with_check = false;
                     return r;
                 }),
        internal("R1c", "a restore result without an expected set (a stop in the check)",
                 [] {
                     Run r = with_stop(run_of({match()}), RunPhase::check, "internal");
                     r.with_expected = false;
                     r.with_check = false;
                     return r;
                 }),
        internal("R1d", "an expected item not at its index",
                 [] {
                     Run r = run_of({match(), match()});
                     r.expected.items[1].index = 5;
                     return r;
                 }),
        internal("R1e", "a restore reporting fewer items than expected",
                 [] {
                     Run r = run_of({match(), match()});
                     r.restore.items.pop_back();
                     return r;
                 }),
        internal("R1f", "a restore item of another kind than its expected item",
                 [] {
                     Run r = run_of({match(), match()});
                     r.restore.items[1].kind = ItemKind::sharepoint;
                     return r;
                 }),
        internal("R1g", "a check of fewer items than expected",
                 [] {
                     Run r = run_of({match(), match()});
                     r.check.items.pop_back();
                     return r;
                 }),
        internal("R1h", "check items out of order",
                 [] {
                     Run r = run_of({match(), match()});
                     r.check.items[1].index = 0;
                     return r;
                 }),
        internal("R1i", "a check item of another kind than its expected item",
                 [] {
                     Run r = run_of({match(), match()});
                     r.check.items[0].kind = ItemKind::onedrive;
                     return r;
                 }),
        internal("R1j", "a check error with a code the checker doesn't give",
                 [] { return run_of({match(), error("teapot")}); }),
        internal("R1k", "a check error without a code", [] { return run_of({error("")}); }),
        internal("R1l", "a restore result without a check and no stop",
                 [] {
                     Run r = run_of({match()});
                     r.with_check = false;
                     return r;
                 }),
        internal("R1m", "a sample without a restore result and no stop",
                 [] { return sample_only({match()}); }),
        internal("R1n", "a restore of an empty sample", [] { return run_of({}); }),
        internal("R1o", "a stop whose code isn't one of the table's",
                 [] { return stop_only(RunPhase::before_restore, "teapot"); }),
        internal("R1p", "a stop before the restore beside a restore result",
                 [] {
                     Run r = with_stop(run_of({match()}), RunPhase::before_restore, "backup");
                     r.with_check = false;
                     return r;
                 }),
        internal("R1q", "a stop in the restore beside a restore result",
                 [] {
                     Run r = with_stop(run_of({match()}), RunPhase::restore, "backup");
                     r.with_check = false;
                     return r;
                 }),
        internal("R1r", "a stop in the restore without an expected set",
                 [] { return stop_only(RunPhase::restore, "backup"); }),
        internal("R1s", "a stop in the check without a restore result",
                 [] { return stop_only(RunPhase::check, "internal"); }),
        internal("R1t", "a stop in the check beside a check",
                 [] { return with_stop(run_of({match()}), RunPhase::check, "internal"); }),
        internal("R1u", "a stop whose phase isn't one of the table's",
                 [] { return stop_only(static_cast<RunPhase>(7), "backup"); }),
        // Values outside their enums, and a check item whose `found` contradicts its outcome.
        internal("R1v", "a check outcome outside its enum",
                 [] {
                     Run r = run_of({match()});
                     r.check.items[0].outcome = static_cast<CheckOutcome>(9);
                     return r;
                 }),
        internal("R1w", "an expected kind outside its enum",
                 [] {
                     Run r = run_of({match()});
                     r.expected.items[0].expected_kind = static_cast<ExpectedKind>(9);
                     return r;
                 }),
        internal("R1x", "a restore status outside its enum",
                 [] {
                     Run r = run_of({match()});
                     r.restore.status = static_cast<RestoreStatus>(9);
                     return r;
                 }),
        internal("R1y", "a restore item outcome outside its enum",
                 [] {
                     Run r = run_of({match()});
                     r.restore.items[0].outcome = static_cast<ItemOutcome>(9);
                     return r;
                 }),
        internal("R1z", "a match that found no copy",
                 [] {
                     Run r = run_of({match()});
                     r.check.items[0].found = false;
                     return r;
                 }),
        internal("R1aa", "a mismatch that found no copy",
                 [] {
                     Run r = run_of({mismatch()});
                     r.check.items[0].found = false;
                     return r;
                 }),
        internal("R1ab", "a missing item that found a copy",
                 [] {
                     Run r = run_of({missing()});
                     r.check.items[0].found = true;
                     return r;
                 }),
        internal("R1ac", "an error item that found a copy",
                 [] {
                     Run r = run_of({error("graph")});
                     r.check.items[0].found = true;
                     return r;
                 }),
    };
}

// Rows 2 to 8, and the precedence between them.
std::vector<Row> rows2to8()
{
    const auto failed_restore = It{.check = CheckOutcome::missing, .restored = ItemOutcome::failed};
    const auto infra_missing = It{.check = CheckOutcome::missing,
                                  .restored = ItemOutcome::failed,
                                  .infrastructure = true};
    const auto infra_match = It{.restored = ItemOutcome::failed, .infrastructure = true};
    return {
        // Row 2: a stop, in any phase, is error with its code.
        {"R2a", "a stop before the sample: only the stop",
         [] { return stop_only(RunPhase::before_restore, "backup_transient"); }, kError,
         "backup_transient", {}, {}, {}},
        {"R2b", "a stop in the before snapshot, a shortfall noted",
         [] {
             Run r = with_stop(sample_only({match()}), RunPhase::before_restore,
                               "graph_permission");
             r.shortfalls = {{ItemKind::mail, ItemSource::random, 1, 0}};
             return r;
         },
         kError, "graph_permission", {}, {}, {"shortfall"}},
        {"R2c", "restore_sample threw",
         [] { return with_stop(sample_only({match()}), RunPhase::restore, "target_guard"); },
         kError, "target_guard", {}, {}, {}},
        {"R2d", "the check threw after a partial restore",
         [] {
             Run r = with_stop(run_of({match()}, RestoreStatus::partial, "Warning"),
                               RunPhase::check, "internal");
             r.with_check = false;
             return r;
         },
         kError, "internal", {}, {}, {"backup_session"}},
        // Row 3.
        {"R3", "an empty sample: nothing restored, the shortfall noted",
         [] {
             Run r = sample_only({});
             r.shortfalls = {{ItemKind::mail, ItemSource::canary, 1, 0}};
             return r;
         },
         kError, "empty_sample", {}, {}, {"shortfall"}},
        // Row 4.
        {"R4a", "the restore returned not_run",
         [] {
             Run r = run_of({missing(), missing()}, RestoreStatus::not_run);
             r.restore.items.clear();
             r.restore.sessions.clear();
             return r;
         },
         kError, "not_run", {}, {}, {}},
        {"R4b", "not_run, earlier copies in the targets",
         [] {
             Run r = run_of({error("stale_target")}, RestoreStatus::not_run);
             r.restore.items.clear();
             r.restore.sessions.clear();
             r.check.stale_mail = 1;
             return r;
         },
         kError, "not_run", {}, {}, {"stale_copies"}},
        // Row 5: any item failed.
        {"R5a", "one item missing", [] { return run_of({match(), missing()}); }, kFail, "", {1},
         {}, {}},
        {"R5b", "one item mismatched", [] { return run_of({mismatch(), match()}); }, kFail, "",
         {0}, {}, {}},
        {"R5c", "a failed item beside an unchecked one: fail, both listed",
         [] { return run_of({missing(), error("graph_transient"), match()}); }, kFail, "", {0},
         {{1, "graph_transient"}}, {}},
        {"R5d", "partial and an item missing",
         [=] { return run_of({match(), failed_restore}, RestoreStatus::partial, "Warning"); },
         kFail, "", {1}, {}, {"backup_session"}},
        {"R5e", "failed and its items missing",
         [=] { return run_of({failed_restore, failed_restore}, RestoreStatus::failed, "Failed"); },
         kFail, "", {0, 1}, {}, {"backup_session"}},
        {"R5f", "an infrastructure item beside a missing one: fail, not error",
         [=] { return run_of({missing(), infra_missing}, RestoreStatus::partial, "Warning"); },
         kFail, "", {0}, {{1, "backup_infrastructure"}}, {"backup_session"}},
        {"R5g", "the backup said every item restored, two are missing (W3.2 live run 2b)",
         [] { return run_of({missing(), missing(), match()}); }, kFail, "", {0, 1}, {}, {}},
        {"R5h", "a mismatch among two copies: fail, the duplicate noted",
         [] {
             It dup = mismatch();
             dup.duplicate = true;
             return run_of({dup});
         },
         kFail, "", {0}, {}, {"duplicate"}},
        // Row 6.
        {"R6", "failed, yet every item matched",
         [=] { return run_of({infra_match, It{.restored = ItemOutcome::failed}},
                             RestoreStatus::failed, "Failed"); },
         kError, "restore_contradiction", {}, {}, {"backup_session", "backup_item"}},
        // Row 7: any item unchecked.
        {"R7a", "one item's target couldn't be read",
         [] { return run_of({match(), error("graph_transient")}); }, kError, "graph_transient",
         {}, {{1, "graph_transient"}}, {}},
        {"R7b", "several codes: the most severe",
         [] {
             return run_of(
                 {error("stale_target"), error("graph_transient"), error("graph_permission")});
         },
         kError, "graph_permission", {},
         {{0, "stale_target"}, {1, "graph_transient"}, {2, "graph_permission"}}, {}},
        {"R7c", "partial, an infrastructure item that didn't match",
         [=] { return run_of({match(), infra_missing}, RestoreStatus::partial, "Warning"); },
         kError, "backup_infrastructure", {}, {{1, "backup_infrastructure"}}, {"backup_session"}},
        {"R7d", "failed, every item stale",
         [] {
             Run r = run_of({error("stale_target"), error("stale_target")},
                            RestoreStatus::failed, "Failed");
             r.check.stale_mail = 2;
             return r;
         },
         kError, "stale_target", {}, {{0, "stale_target"}, {1, "stale_target"}},
         {"backup_session", "stale_copies"}},
        {"R7e", "failed, one matched and one stale: not a contradiction",
         [] {
             return run_of({It{.restored = ItemOutcome::failed},
                            It{.check = CheckOutcome::error,
                               .code = "stale_target",
                               .restored = ItemOutcome::failed}},
                           RestoreStatus::failed, "Failed");
         },
         kError, "stale_target", {}, {{1, "stale_target"}}, {"backup_session", "backup_item"}},
        {"R7f", "the backup said restored, only an earlier copy is there",
         [] {
             Run r = run_of({match(), error("stale_target")});
             r.check.stale_mail = 1;
             return r;
         },
         kError, "stale_target", {}, {{1, "stale_target"}}, {"stale_copies"}},
        // Row 8: every item verified.
        {"R8a", "every item matched", [] { return run_of({match(), match()}); }, kPass, "", {},
         {}, {}},
        {"R8b", "partial, every item verified",
         [] { return run_of({match(), match()}, RestoreStatus::partial, "Warning"); }, kPass, "",
         {}, {}, {"backup_session"}},
        {"R8c", "an infrastructure item that still matched",
         [=] { return run_of({match(), infra_match}, RestoreStatus::partial, "Warning"); }, kPass,
         "", {}, {}, {"backup_session", "backup_item"}},
        {"R8d", "a duplicate",
         [] {
             It dup = match();
             dup.duplicate = true;
             return run_of({dup, match()});
         },
         kPass, "", {}, {}, {"duplicate"}},
        {"R8e", "a shortfall",
         [] {
             Run r = run_of({match()});
             r.shortfalls = {{ItemKind::mail, ItemSource::random, 1, 0}};
             return r;
         },
         kPass, "", {}, {}, {"shortfall"}},
        {"R8f", "earlier runs' copies ignored",
         [] {
             Run r = run_of({match()});
             r.check.stale_sharepoint = 2;
             return r;
         },
         kPass, "", {}, {}, {"stale_copies"}},
        {"R8g", "an item the backup said nothing of, matched",
         [] { return run_of({It{.restored = ItemOutcome::unknown}}); }, kPass, "", {}, {},
         {"backup_item"}},
        {"R8h", "every warning, in order",
         [=] {
             It dup = match();
             dup.duplicate = true;
             Run r = run_of({dup, infra_match}, RestoreStatus::partial, "Warning");
             r.shortfalls = {{ItemKind::onedrive, ItemSource::random, 2, 1}};
             r.check.stale_onedrive = 1;
             return r;
         },
         kPass, "", {}, {}, {"backup_session", "backup_item", "duplicate", "shortfall",
                             "stale_copies"}},
    };
}

// The item verdicts, one item each.
std::vector<Row> item_rules()
{
    return {
        {"I1a", "check error: unchecked with the check's code",
         [] { return run_of({error("graph")}); },
         kError, "graph", {}, {{0, "graph"}}, {}},
        {"I1b", "check error beside an infrastructure failure: the check's code wins",
         [] {
             return run_of({It{.check = CheckOutcome::error,
                               .code = "stale_target",
                               .restored = ItemOutcome::failed,
                               .infrastructure = true}},
                           RestoreStatus::partial, "Warning");
         },
         kError, "stale_target", {}, {{0, "stale_target"}}, {"backup_session"}},
        {"I2a", "match after an infrastructure failure: verified",
         [] {
             return run_of({It{.restored = ItemOutcome::failed, .infrastructure = true}},
                           RestoreStatus::partial, "Warning");
         },
         kPass, "", {}, {}, {"backup_session", "backup_item"}},
        {"I2b", "match the backup said nothing of: verified",
         [] { return run_of({It{.restored = ItemOutcome::unknown}}); }, kPass, "", {}, {},
         {"backup_item"}},
        {"I3a", "missing, failed for an infrastructure reason: unchecked",
         [] {
             return run_of({It{.check = CheckOutcome::missing,
                               .restored = ItemOutcome::failed,
                               .infrastructure = true}},
                           RestoreStatus::partial, "Warning");
         },
         kError, "backup_infrastructure", {}, {{0, "backup_infrastructure"}}, {"backup_session"}},
        {"I3b", "mismatch, unknown for an infrastructure reason: unchecked",
         [] {
             return run_of({It{.check = CheckOutcome::mismatch,
                               .restored = ItemOutcome::unknown,
                               .infrastructure = true}},
                           RestoreStatus::partial);
         },
         kError, "backup_infrastructure", {}, {{0, "backup_infrastructure"}}, {}},
        {"I4a", "missing, the backup said restored: failed", [] { return run_of({missing()}); },
         kFail, "", {0}, {}, {}},
        {"I4b", "missing, failed not for infrastructure: failed",
         [] {
             return run_of({It{.check = CheckOutcome::missing, .restored = ItemOutcome::failed}},
                           RestoreStatus::partial);
         },
         kFail, "", {0}, {}, {}},
        {"I4c", "missing, restored though the message reads as infrastructure: failed",
         [] {
             return run_of({It{.check = CheckOutcome::missing, .infrastructure = true}});
         },
         kFail, "", {0}, {}, {}},
        {"I4d", "mismatch, unknown not for infrastructure: failed",
         [] {
             return run_of({It{.check = CheckOutcome::mismatch, .restored = ItemOutcome::unknown}},
                           RestoreStatus::partial);
         },
         kFail, "", {0}, {}, {}},
    };
}

It unchecked_by(const std::string& code)
{
    if (code == "backup_infrastructure") {
        return It{.check = CheckOutcome::missing,
                  .restored = ItemOutcome::failed,
                  .infrastructure = true};
    }
    return error(code);
}

} // namespace

TEST_CASE("run status, row 1: facts that don't add up are error internal, no warnings",
          "[run_status]")
{
    const Row row = GENERATE(from_range(row1()));
    check_row(row);
    const Run run = row.make();
    CHECK_THAT(verification::decide_status(run.facts()).message,
               StartsWith("the run's results don't add up: "));
}

TEST_CASE("run status, rows 2 to 8: the run table, first fit wins", "[run_status]")
{
    check_row(GENERATE(from_range(rows2to8())));
}

TEST_CASE("run status, item verdicts: error, match, infrastructure, failed, first fit wins",
          "[run_status]")
{
    check_row(GENERATE(from_range(item_rules())));
}

TEST_CASE("run status, severity: each unchecked code outranks the ones after it", "[run_status]")
{
    const std::vector<std::string> order{"target_guard",          "graph_auth", "graph_permission",
                                         "backup_infrastructure", "graph",      "graph_transient",
                                         "stale_target"};
    const std::size_t step = GENERATE(range(std::size_t{0}, std::size_t{6}));
    INFO("S" << step + 1 << ": " << order[step] << " over " << order[step + 1]);
    // The weaker code first, then the stronger: the order of items doesn't matter.
    const Run run = run_of({unchecked_by(order[step + 1]), unchecked_by(order[step]), match()},
                           RestoreStatus::partial);
    const verification::RunVerdict verdict = verification::decide_status(run.facts());
    CHECK(verdict.status == kError);
    CHECK(verdict.error_code == order[step]);
    CHECK(verdict.message == "2 of 3 item(s) couldn't be checked (" + order[step] + " 1, " +
                                 order[step + 1] + " 1); 1 verified");
}

TEST_CASE("run status, error codes: each exception type is its code, in every phase, its "
          "what() kept for stderr only",
          "[run_status]")
{
    struct ErrorRow {
        std::string id;
        std::function<void()> raise;
        std::string code;
        bool known; // its what() is kept
    };
    const ErrorRow row = GENERATE(values<ErrorRow>({
        {"E1", [] { throw rp::ConfigError("veeam_url", "veeam_url: not a URL"); }, "config", true},
        {"E2", [] { throw rp::graph::CertificateError("RP_GRAPH_CERT_PFX_BASE64 expired"); },
         "config", true},
        {"E3", [] { throw rp::sampling::ManifestError("canary manifest: /entries/0: bad"); },
         "config", true},
        {"E4", [] { throw connector::UnknownConnectorError("nope", {"veeam_m365"}); }, "config",
         true},
        {"E5", [] { throw rp::graph::WrongTargetError("not the RestoreTarget library"); },
         "target_guard", true},
        {"E6", [] { throw rp::graph::AuthError("AADSTS700027"); }, "graph_auth", true},
        {"E7", [] { throw rp::graph::PermissionError("denied", "Sites.Selected"); },
         "graph_permission", true},
        {"E8", [] { throw rp::graph::TransientError("Graph 503"); }, "graph_transient", true},
        {"E9", [] { throw rp::graph::NotFoundError("no such drive"); }, "graph", true},
        {"E10", [] { throw rp::graph::GraphError("Graph said no"); }, "graph", true},
        {"E11", [] { throw connector::SafetyViolation("target guard: no"); }, "target_guard",
         true},
        {"E12", [] { throw connector::AuthError("Veeam refused the credentials"); },
         "backup_auth", true},
        {"E13", [] { throw connector::TransientError("Veeam unreachable"); }, "backup_transient",
         true},
        {"E14", [] { throw connector::NotFoundError("client Contoso not found in Veeam"); },
         "not_in_backup", true},
        {"E15", [] { throw connector::NotImplementedError("not here"); }, "backup", true},
        {"E16", [] { throw connector::Error("Veeam said no"); }, "backup", true},
        {"E17", [] { throw std::logic_error("secret=hunter2"); }, "internal", false},
        {"E18", [] { throw 42; }, "internal", false},
    }));
    const RunPhase phase =
        GENERATE(RunPhase::before_restore, RunPhase::restore, RunPhase::check);
    INFO(row.id << " in " << verification::to_string(phase));
    std::exception_ptr error;
    std::string what;
    try {
        row.raise();
    } catch (const std::exception& e) {
        error = std::current_exception();
        what = e.what();
    } catch (...) {
        error = std::current_exception();
    }
    const RunStop stop = verification::stop_reason(error, phase);
    CHECK(stop.phase == phase);
    CHECK(stop.error_code == row.code);
    CHECK(stop.message == (row.known ? what : "unexpected failure"));

    // Through the table: error with that code, and a message that never quotes what().
    Run run = phase == RunPhase::check    ? run_of({match()})
              : phase == RunPhase::restore ? sample_only({match()})
                                           : stop_only(phase, row.code);
    if (phase == RunPhase::check) {
        run.with_check = false;
    }
    if (phase == RunPhase::restore) {
        run.with_restore = false;
    }
    run.stop = stop;
    const verification::RunVerdict verdict = verification::decide_status(run.facts());
    CHECK(verdict.status == kError);
    CHECK(verdict.error_code == row.code);
    CHECK_THAT(verdict.message, ContainsSubstring("(" + row.code + ")"));
    if (!what.empty()) {
        CHECK_THAT(verdict.message, !ContainsSubstring(what));
    }
}

TEST_CASE("run status: stop_reason needs an exception", "[run_status]")
{
    CHECK_THROWS_AS(verification::stop_reason(nullptr, RunPhase::check), std::invalid_argument);
}

TEST_CASE("run status: a stop's message says where the run stopped, never what() says",
          "[run_status]")
{
    const Run before = stop_only(RunPhase::before_restore, "not_in_backup");
    CHECK(verification::decide_status(before.facts()).message ==
          "the run stopped before the restore: the client or a sampled item isn't in the backup "
          "(not_in_backup); nothing was restored");
    const Run restore = with_stop(sample_only({match()}), RunPhase::restore, "backup_auth");
    CHECK(verification::decide_status(restore.facts()).message ==
          "the restore didn't complete: the backup product refused the credentials "
          "(backup_auth)");
    Run check = with_stop(run_of({match()}), RunPhase::check, "internal");
    check.with_check = false;
    CHECK(verification::decide_status(check.facts()).message ==
          "the restored items couldn't be checked: an unexpected failure (internal)");

    const std::string texts[][2] = {
        {"config", "the configuration isn't usable"},
        {"backup_transient", "the backup product couldn't be reached or asked to try later"},
        {"no_restore_point", "no restore point to restore from"},
        {"target_guard", "the restore-target guard refused"},
        {"backup", "the backup product reported an error"},
        {"graph_auth", "Microsoft Graph refused the Worker's sign-in"},
        {"graph_permission", "Microsoft Graph refused a permission the Worker relies on"},
        {"graph_transient", "Microsoft Graph couldn't be reached or asked to try later"},
        {"graph", "Microsoft Graph reported an error"},
    };
    for (const auto& [code, text] : texts) {
        const Run run = stop_only(RunPhase::before_restore, code);
        CHECK(verification::decide_status(run.facts()).message ==
              "the run stopped before the restore: " + text + " (" + code +
                  "); nothing was restored");
    }
}

TEST_CASE("run status: the messages of each row count, never name", "[run_status]")
{
    SECTION("R1: why the facts don't add up")
    {
        Run run = run_of({match(), match()});
        run.check.items.pop_back();
        CHECK(verification::decide_status(run.facts()).message ==
              "the run's results don't add up: the check has 1 item(s), the expected set 2");
        run = run_of({match(), match()});
        run.restore.items.pop_back();
        CHECK(verification::decide_status(run.facts()).message ==
              "the run's results don't add up: the restore reports 1 item(s), the expected set "
              "2");
    }
    SECTION("R3 and R4")
    {
        const Run empty = sample_only({});
        CHECK(verification::decide_status(empty.facts()).message ==
              "the sample is empty: nothing to restore");
        Run not_run = run_of({missing()}, RestoreStatus::not_run);
        not_run.restore.items.clear();
        CHECK(verification::decide_status(not_run.facts()).message ==
              "the restore didn't run: nothing was sent");
    }
    SECTION("R5: failed, then unchecked beside")
    {
        CHECK(verification::decide_status(run_of({missing(), mismatch(), match()}).facts())
                  .message == "2 of 3 item(s) didn't verify (1 missing, 1 mismatch)");
        CHECK(verification::decide_status(
                  run_of({missing(), error("graph"), error("stale_target")}).facts())
                  .message == "1 of 3 item(s) didn't verify (1 missing, 0 mismatch); 2 couldn't "
                              "be checked");
    }
    SECTION("R6")
    {
        CHECK(verification::decide_status(
                  run_of({It{.restored = ItemOutcome::failed}}, RestoreStatus::failed, "Failed")
                      .facts())
                  .message == "the backup reported nothing restored, yet every item verified: the "
                              "evidence contradicts itself");
    }
    SECTION("R7: the codes in severity order; none verified says nothing of it")
    {
        CHECK(verification::decide_status(
                  run_of({error("stale_target"), error("graph"), error("stale_target")}).facts())
                  .message == "3 of 3 item(s) couldn't be checked (graph 1, stale_target 2)");
    }
    SECTION("R8: by expected kind")
    {
        const Run run =
            run_of({match(), It{.expected_kind = ExpectedKind::fields},
                    It{.kind = ItemKind::sharepoint, .expected_kind = ExpectedKind::metadata},
                    It{.kind = ItemKind::onedrive, .expected_kind = ExpectedKind::manifest}});
        const verification::RunVerdict verdict = verification::decide_status(run.facts());
        CHECK(verdict.message == "4 of 4 item(s) verified: manifest 2, fields 1, metadata 1");
        CHECK(verdict.verified() == 4);
        CHECK(verdict.items == 4);
    }
}

TEST_CASE("run status: each warning's message and indexes, never an item's name or message",
          "[run_status]")
{
    It warned = It{.restored = ItemOutcome::failed, .infrastructure = true, .session = "s-2"};
    It dup = It{.duplicate = true, .session = "s-2"};
    Run run = run_of({match(), warned, dup}, RestoreStatus::partial, "Warning");
    run.restore.items[1].message = "Alice's secret plan.docx: access denied";
    run.restore.sessions[1].details = "2 items processed\n(1 failure)";
    run.restore.sessions[0].result = "Success";
    run.shortfalls = {{ItemKind::sharepoint, ItemSource::canary, 2, 1},
                      {ItemKind::onedrive, ItemSource::random, 2, 0}};
    run.check.stale_mail = 1;
    run.check.stale_sharepoint = 2;
    const verification::RunVerdict verdict = verification::decide_status(run.facts());
    REQUIRE(verdict.status == kPass);
    REQUIRE(verdict.warnings.size() == 6);
    CHECK(verdict.warnings[0].code == "backup_session");
    CHECK(verdict.warnings[0].message ==
          "mail session s-2: Warning (2 items processed (1 failure))");
    CHECK(verdict.warnings[0].indexes == std::vector<std::size_t>{1, 2});
    CHECK(verdict.warnings[1].code == "backup_item");
    CHECK(verdict.warnings[1].message == "1 verified item(s) the backup didn't report restored");
    CHECK(verdict.warnings[1].indexes == std::vector<std::size_t>{1});
    CHECK(verdict.warnings[2].code == "duplicate");
    CHECK(verdict.warnings[2].message ==
          "1 item(s) had more than one restored copy; the newest was checked");
    CHECK(verdict.warnings[2].indexes == std::vector<std::size_t>{2});
    CHECK(verdict.warnings[3].message == "sharepoint canary: 1 of 2");
    CHECK(verdict.warnings[4].message == "onedrive random: 0 of 2");
    CHECK(verdict.warnings[4].indexes.empty());
    CHECK(verdict.warnings[5].code == "stale_copies");
    CHECK(verdict.warnings[5].message ==
          "3 copies from earlier runs in the restore targets were ignored (mail 1, sharepoint 2, "
          "onedrive 0)");
    for (const verification::StatusWarning& w : verdict.warnings) {
        CHECK_THAT(w.message, !ContainsSubstring("Alice"));
    }

    SECTION("a session without an ID, result or details")
    {
        Run bare = run_of({It{.session = ""}}, RestoreStatus::partial, "");
        const verification::RunVerdict v = verification::decide_status(bare.facts());
        REQUIRE(v.warnings.size() == 1);
        CHECK(v.warnings[0].message == "mail session -: -");
    }
}

TEST_CASE("run status: shortfalls_of is the sample's NOTE rule", "[run_status]")
{
    rp::sampling::SampleRecord record;
    record.mail.requested = 3; // 2 canaries wanted, 1 random
    record.mail.canary_ids = {"RP-CANARY-0001"};
    record.mail.random_wanted = 1;
    record.mail.random_taken = 0;
    record.sharepoint.requested = 2; // 1 and 1, both taken
    record.sharepoint.canary_ids = {"a.txt"};
    record.sharepoint.random_wanted = 1;
    record.sharepoint.random_taken = 1;
    record.onedrive.requested = 1; // 1 canary, none taken
    const std::vector<Shortfall> shortfalls = verification::shortfalls_of(record);
    REQUIRE(shortfalls.size() == 3);
    CHECK(shortfalls[0].kind == ItemKind::mail);
    CHECK(shortfalls[0].source == ItemSource::canary);
    CHECK(shortfalls[0].wanted == 2);
    CHECK(shortfalls[0].taken == 1);
    CHECK(shortfalls[1].kind == ItemKind::mail);
    CHECK(shortfalls[1].source == ItemSource::random);
    CHECK(shortfalls[1].wanted == 1);
    CHECK(shortfalls[1].taken == 0);
    CHECK(shortfalls[2].kind == ItemKind::onedrive);
    CHECK(shortfalls[2].source == ItemSource::canary);
    CHECK(shortfalls[2].wanted == 1);
    CHECK(shortfalls[2].taken == 0);
    CHECK(verification::shortfalls_of(rp::sampling::SampleRecord{}).empty());
}

TEST_CASE("run status: to_json is the result's status object", "[run_status]")
{
    SECTION("an error: its code, the unchecked items, warnings")
    {
        Run run = run_of(
            {match(), error("stale_target"), It{.expected_kind = ExpectedKind::fields}});
        run.check.stale_mail = 1;
        const json want = json::parse(R"j({
                  "status": "error", "error_code": "stale_target",
                  "message": "1 of 3 item(s) couldn't be checked (stale_target 1); 2 verified",
                  "counts": {"items": 3, "verified": 2, "failed": 0, "unchecked": 1},
                  "verified": {"manifest": 1, "fields": 1, "metadata": 0},
                  "failed_items": [],
                  "unchecked_items": [{"index": 1, "error_code": "stale_target"}],
                  "warnings": [{"code": "stale_copies", "indexes": [],
                                "message": "1 copies from earlier runs in the restore targets were ignored (mail 1, sharepoint 0, onedrive 0)"}]
              })j");
        CHECK(verification::to_json(verification::decide_status(run.facts())) == want);
    }
    SECTION("a fail: no error_code key")
    {
        const json out =
            verification::to_json(verification::decide_status(run_of({missing()}).facts()));
        CHECK_FALSE(out.contains("error_code"));
        const json want = json::parse(R"j({
                  "status": "fail",
                  "message": "1 of 1 item(s) didn't verify (1 missing, 0 mismatch)",
                  "counts": {"items": 1, "verified": 0, "failed": 1, "unchecked": 0},
                  "verified": {"manifest": 0, "fields": 0, "metadata": 0},
                  "failed_items": [0], "unchecked_items": [], "warnings": []
              })j");
        CHECK(out == want);
    }
    SECTION("a pass")
    {
        const json out = verification::to_json(
            verification::decide_status(run_of({It{.duplicate = true}}).facts()));
        const json want = json::parse(R"j({
                  "status": "pass",
                  "message": "1 of 1 item(s) verified: manifest 1, fields 0, metadata 0",
                  "counts": {"items": 1, "verified": 1, "failed": 0, "unchecked": 0},
                  "verified": {"manifest": 1, "fields": 0, "metadata": 0},
                  "failed_items": [], "unchecked_items": [],
                  "warnings": [{"code": "duplicate", "indexes": [0],
                                "message": "1 item(s) had more than one restored copy; the newest was checked"}]
              })j");
        CHECK(out == want);
    }
    SECTION("a stop before the sample: no items")
    {
        const json out = verification::to_json(verification::decide_status(
            stop_only(RunPhase::before_restore, "backup_transient").facts()));
        CHECK(out["error_code"] == "backup_transient");
        const json counts =
            json::parse(R"j({"items": 0, "verified": 0, "failed": 0, "unchecked": 0})j");
        CHECK(out["counts"] == counts);
    }
}

TEST_CASE("run status: the exit code of each status and error code", "[run_status]")
{
    struct ExitRow {
        std::string id;
        RunStatus status;
        std::string code;
        int exit;
    };
    const ExitRow row = GENERATE(values<ExitRow>({
        {"X1", RunStatus::pass, "", rp::exit_code::ok},
        {"X2", RunStatus::fail, "", rp::exit_code::restore},
        {"X3", RunStatus::error, "config", rp::exit_code::config},
        {"X4", RunStatus::error, "internal", rp::exit_code::config},
        {"X5", RunStatus::error, "backup_auth", rp::exit_code::auth},
        {"X6", RunStatus::error, "graph_auth", rp::exit_code::auth},
        {"X7", RunStatus::error, "graph_permission", rp::exit_code::auth},
        {"X8", RunStatus::error, "backup_transient", rp::exit_code::transient},
        {"X9", RunStatus::error, "graph_transient", rp::exit_code::transient},
        {"X10", RunStatus::error, "not_in_backup", rp::exit_code::service},
        {"X11", RunStatus::error, "no_restore_point", rp::exit_code::service},
        {"X12", RunStatus::error, "target_guard", rp::exit_code::service},
        {"X13", RunStatus::error, "backup", rp::exit_code::service},
        {"X14", RunStatus::error, "backup_infrastructure", rp::exit_code::service},
        {"X15", RunStatus::error, "empty_sample", rp::exit_code::service},
        {"X16", RunStatus::error, "not_run", rp::exit_code::service},
        {"X17", RunStatus::error, "restore_contradiction", rp::exit_code::service},
        {"X18", RunStatus::error, "graph", rp::exit_code::service},
        {"X19", RunStatus::error, "stale_target", rp::exit_code::service},
    }));
    INFO(row.id << ": " << row.code);
    verification::RunVerdict verdict;
    verdict.status = row.status;
    verdict.error_code = row.code;
    CHECK(verification::exit_code_of(verdict) == row.exit);
}

TEST_CASE("run status: the names of statuses and phases", "[run_status]")
{
    CHECK(verification::to_string(RunStatus::pass) == "pass");
    CHECK(verification::to_string(RunStatus::fail) == "fail");
    CHECK(verification::to_string(RunStatus::error) == "error");
    CHECK(verification::to_string(static_cast<RunStatus>(9)) == "unknown");
    CHECK(verification::to_string(RunPhase::before_restore) == "before_restore");
    CHECK(verification::to_string(RunPhase::restore) == "restore");
    CHECK(verification::to_string(RunPhase::check) == "check");
    CHECK(verification::to_string(static_cast<RunPhase>(9)) == "unknown");
}
