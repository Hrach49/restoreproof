// ResultBuilder (W4.1, docs/decisions.md 2026-10-04, points 1, 5 and 6): the
// seventeen keys from a run's parts, the canonical text, and that text parsed
// back and validated. The failures come back as fixed words, never as an
// exception or its text.

#include <rp/result_builder.hpp>

#include "result_lab.hpp"

#include <rp/canonical_json.hpp>
#include <rp/result_schema.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <variant>

namespace {

using nlohmann::json;
using rp::BuiltResult;
using rp::ResultBuilder;
using rp::ResultError;
using rp::ResultFailure;
using rp::ResultParts;
using rp::test::full_result_facts;
using rp::test::ResultFacts;

// The failure build() gave; fails the test when it built a result.
ResultError error_of(const ResultParts& parts)
{
    const std::variant<BuiltResult, ResultError> built = ResultBuilder::build(parts);
    REQUIRE(std::holds_alternative<ResultError>(built));
    return std::get<ResultError>(built);
}

// The result build() gave; fails the test, naming the cause, when it gave none.
BuiltResult result_of(const ResultParts& parts)
{
    std::variant<BuiltResult, ResultError> built = ResultBuilder::build(parts);
    if (const ResultError* error = std::get_if<ResultError>(&built)) {
        FAIL("no result: " << rp::to_string(error->cause) << ", " << error->violations
                           << " violation(s), first at \"" << error->first_pointer << "\"");
    }
    return std::get<BuiltResult>(std::move(built));
}

// A run that stopped before its sample: an error verdict and nothing else.
ResultFacts stopped_run_facts()
{
    ResultFacts facts;
    rp::verification::RunFacts run;
    run.stop = rp::verification::RunStop{};
    run.stop->error_code = "backup_transient";
    facts.verdict = rp::verification::decide_status(run);
    return facts;
}

} // namespace

TEST_CASE("ResultBuilder: no verdict, no result", "[result_builder]")
{
    const ResultFacts facts = full_result_facts();
    ResultParts parts = facts.parts();
    parts.verdict = nullptr;

    REQUIRE_THROWS_AS(ResultBuilder::document(parts), std::logic_error);
    const ResultError error = error_of(parts);
    REQUIRE(error.cause == ResultFailure::build_failed);
    REQUIRE(error.violations == 0);
    REQUIRE(error.first_pointer.empty());
}

TEST_CASE("ResultBuilder: a part whose to_json throws is build_failed", "[result_builder]")
{
    ResultFacts facts = full_result_facts();
    SECTION("an expected item that isn't at its index")
    {
        facts.expected.items[1].index = 5;
    }
    SECTION("a check item whose fields contradict its outcome")
    {
        facts.check.items[0].reason = "alice@contoso.example";
    }
    const ResultParts parts = facts.parts();
    REQUIRE_THROWS(ResultBuilder::document(parts));
    const ResultError error = error_of(parts);
    REQUIRE(error.cause == ResultFailure::build_failed);
    REQUIRE(error.violations == 0);
    REQUIRE(error.first_pointer.empty());
}

TEST_CASE("ResultBuilder: text that isn't UTF-8 is not_canonical, not an exception",
          "[result_builder]")
{
    ResultFacts facts = full_result_facts();
    ResultParts parts = facts.parts();
    SECTION("in a tenant value")
    {
        facts.expected.items[1].mail->subject = "caf\xE9 \xFF";
    }
    SECTION("in the backup's words")
    {
        facts.restore.sessions[0].result = "Succ\xC3";
    }
    SECTION("in the client's facts")
    {
        parts.client.veeam_org_name = "\x80";
    }
    // The document itself holds the bytes; only the canonical form refuses.
    REQUIRE_NOTHROW(ResultBuilder::document(parts));
    const ResultError error = error_of(parts);
    REQUIRE(error.cause == ResultFailure::not_canonical);
    REQUIRE(error.violations == 0);
    REQUIRE(error.first_pointer.empty());
}

TEST_CASE("ResultBuilder: a document the schema refuses is `schema`, with where",
          "[result_builder]")
{
    ResultFacts facts = full_result_facts();
    ResultParts parts = facts.parts();
    std::string where;
    SECTION("a wall clock past the year 9999")
    {
        parts.ended_at = "10000-01-01T00:00:00.000Z";
        where = "/ended_at";
    }
    SECTION("a run ID the sampler would refuse")
    {
        parts.run_id = "run 1\nstatus pass";
        where = "/run_id";
    }
    SECTION("a connector the schema doesn't know")
    {
        parts.connector.name = "fake";
        where = "/connector/type";
    }
    SECTION("a hand-made check reason")
    {
        facts.check.items[0].outcome = rp::verification::CheckOutcome::missing;
        facts.check.items[0].found = false;
        facts.check.items[0].reason = "the copy of alice@contoso.example is gone";
        where = "/check/items/0/reason";
    }
    SECTION("a status code outside the table")
    {
        facts.verdict.status = rp::verification::RunStatus::error;
        facts.verdict.error_code = "teapot";
        where = "/status/error_code";
    }
    const ResultError error = error_of(parts);
    REQUIRE(error.cause == ResultFailure::schema);
    REQUIRE(error.violations >= 1);
    REQUIRE(error.first_pointer == where);
}

TEST_CASE("ResultFailure's words", "[result_builder]")
{
    REQUIRE(rp::to_string(ResultFailure::build_failed) == "build_failed");
    REQUIRE(rp::to_string(ResultFailure::not_canonical) == "not_canonical");
    REQUIRE(rp::to_string(ResultFailure::schema) == "schema");
    REQUIRE(rp::to_string(static_cast<ResultFailure>(99)) == "unknown");
}

TEST_CASE("ResultBuilder: the restore point's time cut to whole seconds, or null",
          "[result_builder]")
{
    struct Row {
        const char* raw;
        std::optional<std::string> seconds;
    };
    const Row row = GENERATE(Row{"2026-10-03T22:00:45.6603083Z", "2026-10-03T22:00:45Z"},
                             Row{"2026-10-03T22:00:45Z", "2026-10-03T22:00:45Z"},
                             Row{"2026-10-03T22:00:45.9Z", "2026-10-03T22:00:45Z"},
                             Row{"2026-10-03T22:00:45+02:00", std::nullopt},
                             Row{"2026-10-03T22:00:45", std::nullopt},
                             Row{"2026-02-30T22:00:45Z", std::nullopt},
                             Row{"yesterday", std::nullopt}, Row{"", std::nullopt});
    INFO(row.raw);
    const ResultFacts facts = full_result_facts();
    ResultParts parts = facts.parts();
    parts.restore_point_time = row.raw;

    const BuiltResult built = result_of(parts);
    const json& point = built.document.at("restore_point");
    REQUIRE(point.size() == 3);
    REQUIRE(point.at("id") == parts.restore_point_id);
    REQUIRE(point.at("backup_time_raw") == row.raw);
    REQUIRE(point.at("backup_time") == (row.seconds ? json(*row.seconds) : json()));
}

TEST_CASE("ResultBuilder: the full run's document", "[result_builder]")
{
    const ResultFacts facts = full_result_facts();
    const ResultParts parts = facts.parts();
    const json document = ResultBuilder::document(parts);

    const std::set<std::string> wanted = {
        "format",        "worker_version", "run_id",   "started_at", "ended_at",
        "connector",     "client",         "restore_point", "sample", "expected",
        "restore",       "check",          "status",   "cleanup",    "timings",
        "attachments",   "screenshot"};
    std::set<std::string> keys;
    for (const auto& [key, unused] : document.items()) {
        keys.insert(key);
    }
    REQUIRE(keys == wanted);

    REQUIRE(document.at("format") == "restoreproof.result.v1");
    REQUIRE(document.at("worker_version") == "0.0.0");
    REQUIRE(document.at("run_id") == "rp-20261004T100000Z-0a1b2c3d");
    REQUIRE(document.at("started_at") == "2026-10-04T10:00:00.125Z");
    REQUIRE(document.at("ended_at") == "2026-10-04T10:04:09.500Z");
    REQUIRE(document.at("connector") == json{{"type", "veeam_m365"}, {"api", "v8"}});
    REQUIRE(document.at("client") ==
            json{{"client_id", nullptr},
                 {"tenant_id", "11111111-2222-3333-4444-555555555555"},
                 {"veeam_org_name", "contoso.onmicrosoft.com"},
                 {"targets",
                  {{"mailbox", "restoretest@contoso.example"},
                   {"site_id", parts.client.site_id},
                   {"library_id", "b!library"},
                   {"onedrive_drive_id", "b!onedrive"},
                   {"onedrive_folder_id", "01FOLDER"}}}});
    // Each part is its own to_json, nothing added and nothing left out.
    REQUIRE(document.at("sample") == rp::sampling::to_json(facts.sample));
    REQUIRE(document.at("expected") == rp::verification::to_json(facts.expected));
    REQUIRE(document.at("restore") == rp::verification::to_json(facts.restore));
    REQUIRE(document.at("check") == rp::verification::to_json(facts.check));
    REQUIRE(document.at("status") == rp::verification::to_json(facts.verdict));
    REQUIRE(document.at("cleanup") == rp::to_json(facts.cleanup));
    REQUIRE(document.at("timings") == rp::timing::to_json(facts.timings));
    REQUIRE(document.at("status").at("status") == "pass");

    const BuiltResult built = result_of(parts);
    REQUIRE(built.document == document);
    REQUIRE(built.canonical == rp::canonical_json(document));
    REQUIRE(json::parse(built.canonical) == built.document);
    REQUIRE(rp::validate_result(built.document).valid);
}

TEST_CASE("ResultBuilder: a step that didn't run is null", "[result_builder]")
{
    ResultFacts facts = full_result_facts();
    ResultParts parts = facts.parts();
    const char* key = GENERATE("sample", "expected", "restore", "check", "cleanup", "started_at",
                               "ended_at");
    INFO(key);
    const std::string name = key;
    if (name == "sample") {
        parts.sample = nullptr;
    } else if (name == "expected") {
        parts.expected = nullptr;
    } else if (name == "restore") {
        parts.restore = nullptr;
    } else if (name == "check") {
        parts.check = nullptr;
    } else if (name == "cleanup") {
        parts.cleanup = nullptr;
    } else if (name == "started_at") {
        parts.started_at.reset();
    } else {
        parts.ended_at.reset();
    }
    const BuiltResult built = result_of(parts);
    REQUIRE(built.document.size() == 17);
    REQUIRE(built.document.at(key).is_null());
}

TEST_CASE("ResultBuilder: a run that stopped before its sample", "[result_builder]")
{
    const ResultFacts facts = stopped_run_facts();
    ResultParts parts = facts.parts();
    parts.sample = nullptr;
    parts.expected = nullptr;
    parts.restore = nullptr;
    parts.check = nullptr;
    parts.cleanup = nullptr;
    parts.timings = nullptr;
    parts.ended_at.reset();

    const BuiltResult built = result_of(parts);
    const json& document = built.document;
    REQUIRE(document.size() == 17);
    for (const char* key : {"sample", "expected", "restore", "check", "cleanup", "ended_at",
                            "attachments", "screenshot"}) {
        INFO(key);
        REQUIRE(document.at(key).is_null());
    }
    REQUIRE(document.at("status").at("status") == "error");
    REQUIRE(document.at("status").at("error_code") == "backup_transient");
    // No timings handed in: a run that timed nothing, every span null.
    const json& spans = document.at("timings").at("spans");
    REQUIRE(spans.size() == rp::timing::kSpanCount);
    for (const auto& [name, span] : spans.items()) {
        INFO(name);
        REQUIRE(span.is_null());
    }
}

TEST_CASE("ResultBuilder: the result as it is first validated, before the clean after",
          "[result_builder]")
{
    // Point 5: ended_at and cleanup.after null, the open spans `open`.
    ResultFacts facts = full_result_facts();
    facts.cleanup.after.reset();
    using rp::timing::Span;
    using rp::timing::SpanState;
    facts.timings.spans[static_cast<std::size_t>(Span::cleanup_after)] = {};
    facts.timings.spans[static_cast<std::size_t>(Span::total)] = {SpanState::open, std::nullopt};
    facts.timings.spans[static_cast<std::size_t>(Span::restore_submit)] = {SpanState::not_reported,
                                                                          std::nullopt};
    facts.timings.spans[static_cast<std::size_t>(Span::verify)] = {SpanState::clock_backwards,
                                                                  std::nullopt};
    facts.timings.spans[static_cast<std::size_t>(Span::restore)] = {
        SpanState::stopped, std::chrono::milliseconds{12}};
    ResultParts parts = facts.parts();
    parts.ended_at.reset();

    const BuiltResult built = result_of(parts);
    const json& spans = built.document.at("timings").at("spans");
    REQUIRE(built.document.at("cleanup").at("after").is_null());
    REQUIRE(spans.at("cleanup_after").is_null());
    REQUIRE(spans.at("total") == json{{"note", "open"}});
    REQUIRE(spans.at("restore_submit") == json{{"note", "not_reported"}});
    REQUIRE(spans.at("verify") == json{{"note", "clock_backwards"}});
    REQUIRE(spans.at("restore") == json{{"ms", 12}, {"note", "stopped"}});
}

TEST_CASE("ResultBuilder: what the checker and the status table really give validates",
          "[result_builder]")
{
    namespace v = rp::verification;
    ResultFacts facts = full_result_facts();
    const char* scenario = GENERATE("a missing canary: fail", "an office-v1 mismatch: fail",
                                    "a target that couldn't be read: error",
                                    "the backup's own words, whatever they are");
    const bool as_result_invalid = GENERATE(false, true);
    INFO(scenario << (as_result_invalid ? ", as result_invalid" : ""));
    const std::string name = scenario;

    if (name == "a missing canary: fail") {
        v::ItemCheck& item = facts.check.items[0];
        item = {};
        item.kind = rp::connector::ItemKind::mail;
        item.outcome = v::CheckOutcome::missing;
        item.reason = "no restored copy found";
    } else if (name == "an office-v1 mismatch: fail") {
        v::ItemCheck& item = facts.check.items[2];
        item.outcome = v::CheckOutcome::mismatch;
        item.mismatches = {"sha256"};
        item.reason =
            "fields did not match: sha256; the restored package isn't valid office-v1 input";
    } else if (name == "a target that couldn't be read: error") {
        for (const std::size_t i : {std::size_t{4}, std::size_t{5}}) {
            v::ItemCheck& item = facts.check.items[i];
            item = {};
            item.index = i;
            item.kind = rp::connector::ItemKind::onedrive;
            item.outcome = v::CheckOutcome::error;
            item.error_code = "graph_permission";
            item.reason = "the onedrive restore target couldn't be read (graph_permission)";
        }
    } else {
        facts.restore.status = rp::connector::RestoreStatus::partial;
        facts.restore.sessions[0].result = "Warning";
        facts.restore.sessions[0].details = "2 items processed (1 success, 1 warning)";
        facts.restore.sessions[1].result = "A word Veeam adds later";
        facts.restore.sessions[1].details = "the file Budget 2026.pdf of carol@contoso.example";
        facts.restore.items[1].outcome = rp::connector::ItemOutcome::failed;
        facts.restore.items[1].infrastructure = true;
    }
    v::RunFacts run;
    run.expected = &facts.expected;
    run.restore = &facts.restore;
    run.check = &facts.check;
    facts.verdict = v::decide_status(run);
    const std::string decided{v::to_string(facts.verdict.status)};
    REQUIRE(name.ends_with(decided) == (decided != "pass"));
    if (as_result_invalid) {
        facts.verdict = v::result_invalid(facts.verdict);
    }

    const BuiltResult built = result_of(facts.parts());
    REQUIRE(built.document.at("status") == v::to_json(facts.verdict));
    REQUIRE(built.document.at("status").at("status") ==
            (as_result_invalid ? "error" : decided));
}

TEST_CASE("ResultBuilder: the run folder's attachments and screenshot, null without one (W4.2)",
          "[result_builder]")
{
    const ResultFacts facts = full_result_facts();
    ResultParts parts = facts.parts();

    const BuiltResult without = result_of(parts);
    REQUIRE(without.document.at("attachments").is_null());
    REQUIRE(without.document.at("screenshot").is_null());

    const std::vector<rp::Attachment> attachments{{"items.csv", std::string(64, 'a'), 1234},
                                                  {"veeam-session.log", std::string(64, 'b'), 0}};
    const rp::Screenshot screenshot{false, rp::ScreenshotReason::no_page};
    parts.attachments = &attachments;
    parts.screenshot = &screenshot;

    const BuiltResult with = result_of(parts);
    REQUIRE(with.document.size() == 17);
    REQUIRE(with.document.at("attachments") == rp::to_json(attachments));
    REQUIRE(with.document.at("screenshot") ==
            json{{"state", "unavailable"}, {"reason", "no_page"}});
    REQUIRE(with.canonical.starts_with("{\"attachments\":[{\"name\":\"items.csv\",\"sha256\":\""));
}

TEST_CASE("ResultBuilder: attachments the schema doesn't take are a schema error (W4.2)",
          "[result_builder]")
{
    const ResultFacts facts = full_result_facts();
    ResultParts parts = facts.parts();
    const rp::Screenshot screenshot{true, rp::ScreenshotReason::failed};
    parts.screenshot = &screenshot;
    // One file is no run folder; a name it doesn't know; a hash that isn't one.
    const std::vector<rp::Attachment> attachments = GENERATE(
        std::vector<rp::Attachment>{{"items.csv", std::string(64, 'a'), 1}},
        std::vector<rp::Attachment>{{"items.csv", std::string(64, 'a'), 1},
                                    {"result.json", std::string(64, 'b'), 1}},
        std::vector<rp::Attachment>{{"items.csv", std::string(64, 'A'), 1},
                                    {"veeam-session.log", std::string(64, 'b'), 1}});
    parts.attachments = &attachments;

    const std::variant<BuiltResult, ResultError> built = ResultBuilder::build(parts);

    REQUIRE(std::holds_alternative<ResultError>(built));
    REQUIRE(std::get<ResultError>(built).cause == ResultFailure::schema);
}
