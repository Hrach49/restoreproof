// Step timings (W3.5, rp/step_timer.hpp; docs/decisions.md 2026-10-03 W3.5,
// points 1, 3, 4 and 5): named spans of one run on one injected steady clock.
// Every test runs on a fake clock whose readings are counted, so "reads no
// clock" is checked, not assumed. Failure paths first: a misused span, a
// clock that goes back, a span never closed, then the measured ones, then the
// table and the JSON.

#include <rp/step_timer.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace timing = rp::timing;
using timing::Span;
using timing::SpanState;
using timing::StepTimer;
using nlohmann::json;
using std::chrono::hours;
using std::chrono::milliseconds;
using std::chrono::minutes;
using std::chrono::nanoseconds;
using std::chrono::seconds;
using TimePoint = std::chrono::steady_clock::time_point;

// Any fixed instant: the timer only ever subtracts two of them.
const TimePoint t0 = TimePoint{} + hours{1000};

// A steady clock that moves only when told to and counts its readings.
struct FakeClock {
    TimePoint at = t0;
    int reads = 0;

    StepTimer::Clock clock()
    {
        return [this] {
            ++reads;
            return at;
        };
    }
};

timing::SpanTiming span_of(const StepTimer& timer, Span span)
{
    return timer.timings().spans[static_cast<std::size_t>(span)];
}

const Span kAllSpans[] = {Span::restore_point_lookup, Span::cleanup_before, Span::sample_select,
                          Span::target_snapshot,      Span::restore,        Span::restore_submit,
                          Span::restore_wait,         Span::verify,         Span::recovery,
                          Span::cleanup_after,        Span::total};

// A Span outside the enum: a caller's cast gone wrong.
const Span kBadSpan = static_cast<Span>(timing::kSpanCount);

} // namespace

TEST_CASE("step timer: a misused span is ignored, returns false and the first call holds",
          "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};

    struct Misuse {
        const char* name;
        // Brings the span into a state with legal calls, then makes the misuse.
        bool (*misuse)(StepTimer&);
        SpanState state;
        std::optional<nanoseconds> duration;
    };
    const Misuse row = GENERATE(
        Misuse{"end before any start",
               [](StepTimer& t) { return t.end(Span::verify, t0 + seconds{1}); },
               SpanState::not_run, std::nullopt},
        Misuse{"a stopped end before any start",
               [](StepTimer& t) { return t.end(Span::verify, t0 + seconds{1}, true); },
               SpanState::not_run, std::nullopt},
        Misuse{"a second start: the first start holds",
               [](StepTimer& t) {
                   t.start(Span::verify, t0);
                   const bool second = t.start(Span::verify, t0 + seconds{5});
                   t.end(Span::verify, t0 + seconds{7});
                   return second;
               },
               SpanState::measured, nanoseconds{seconds{7}}},
        Misuse{"a second end: the first end holds",
               [](StepTimer& t) {
                   t.start(Span::verify, t0);
                   t.end(Span::verify, t0 + seconds{2});
                   return t.end(Span::verify, t0 + seconds{9}, true);
               },
               SpanState::measured, nanoseconds{seconds{2}}},
        Misuse{"a start after the end",
               [](StepTimer& t) {
                   t.start(Span::verify, t0);
                   t.end(Span::verify, t0 + seconds{2}, true);
                   return t.start(Span::verify, t0 + seconds{3});
               },
               SpanState::stopped, nanoseconds{seconds{2}}},
        Misuse{"a report on an open span",
               [](StepTimer& t) {
                   t.start(Span::verify, t0);
                   return t.report(Span::verify, seconds{4});
               },
               SpanState::open, std::nullopt},
        Misuse{"a report on a measured span",
               [](StepTimer& t) {
                   t.start(Span::verify, t0);
                   t.end(Span::verify, t0 + seconds{2});
                   return t.report(Span::verify, seconds{4});
               },
               SpanState::measured, nanoseconds{seconds{2}}},
        Misuse{"a second report: the first report holds",
               [](StepTimer& t) {
                   t.report(Span::verify, seconds{3});
                   return t.report(Span::verify, seconds{4});
               },
               SpanState::measured, nanoseconds{seconds{3}}},
        Misuse{"a report after a not-reported one",
               [](StepTimer& t) {
                   t.report(Span::verify, std::nullopt);
                   return t.report(Span::verify, seconds{4});
               },
               SpanState::not_reported, std::nullopt},
        Misuse{"a start after a report",
               [](StepTimer& t) {
                   t.report(Span::verify, seconds{3});
                   return t.start(Span::verify, t0);
               },
               SpanState::measured, nanoseconds{seconds{3}}},
        Misuse{"an end after a report",
               [](StepTimer& t) {
                   t.report(Span::verify, std::nullopt);
                   return t.end(Span::verify, t0 + seconds{1});
               },
               SpanState::not_reported, std::nullopt},
        Misuse{"an end after the clock went back",
               [](StepTimer& t) {
                   t.start(Span::verify, t0);
                   t.end(Span::verify, t0 - seconds{1});
                   return t.end(Span::verify, t0 + seconds{1});
               },
               SpanState::clock_backwards, std::nullopt});
    INFO(row.name);

    CHECK_FALSE(row.misuse(timer));
    const timing::SpanTiming span = span_of(timer, Span::verify);
    CHECK(span.state == row.state);
    CHECK(span.duration == row.duration);
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: a span outside the enum is refused by every call", "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    CHECK_FALSE(timer.start(kBadSpan, t0));
    CHECK_FALSE(timer.end(kBadSpan, t0));
    CHECK_FALSE(timer.report(kBadSpan, seconds{1}));
    for (const timing::SpanTiming& span : timer.timings().spans) {
        CHECK(span.state == SpanState::not_run);
        CHECK_FALSE(span.duration);
    }
    CHECK(timing::to_string(kBadSpan) == "unknown");
    CHECK(timing::to_string(static_cast<SpanState>(99)) == "unknown");
    CHECK(timing::note(static_cast<SpanState>(99)).empty());
}

TEST_CASE("step timer: a clock that goes back never yields a duration", "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};

    SECTION("an end before its start")
    {
        REQUIRE(timer.start(Span::restore, t0));
        CHECK(timer.end(Span::restore, t0 - nanoseconds{1}));
    }
    SECTION("a stopped end before its start")
    {
        REQUIRE(timer.start(Span::restore, t0));
        CHECK(timer.end(Span::restore, t0 - seconds{30}, true));
    }
    SECTION("an open span stopped before its start")
    {
        REQUIRE(timer.start(Span::restore, t0));
        timer.stop_open(t0 - milliseconds{1});
    }
    SECTION("a negative reported duration")
    {
        CHECK(timer.report(Span::restore, nanoseconds{-1}));
    }

    const timing::SpanTiming span = span_of(timer, Span::restore);
    CHECK(span.state == SpanState::clock_backwards);
    CHECK_FALSE(span.duration);
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: a span never closed is open, with no duration and no clock read",
          "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    REQUIRE(timer.start(Span::sample_select, t0));
    fake.at = t0 + minutes{3};

    const timing::RunTimings timings = timer.timings();
    const timing::SpanTiming& span = timings.spans[static_cast<std::size_t>(Span::sample_select)];
    CHECK(span.state == SpanState::open);
    CHECK_FALSE(span.duration);
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: stop_open ends every open span stopped and leaves the rest",
          "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    REQUIRE(timer.start(Span::total, t0));
    REQUIRE(timer.start(Span::restore, t0 + seconds{10}));
    REQUIRE(timer.start(Span::recovery, t0 + seconds{10}));
    REQUIRE(timer.start(Span::verify, t0 + seconds{20}));
    REQUIRE(timer.end(Span::verify, t0 + seconds{25}));
    REQUIRE(timer.report(Span::restore_wait, std::nullopt));
    // Started after the stop's reading: the clock went back for it alone.
    REQUIRE(timer.start(Span::cleanup_after, t0 + seconds{90}));

    timer.stop_open(t0 + seconds{60});

    const timing::RunTimings timings = timer.timings();
    auto at = [&](Span s) { return timings.spans[static_cast<std::size_t>(s)]; };
    CHECK(at(Span::total).state == SpanState::stopped);
    CHECK(at(Span::total).duration == nanoseconds{seconds{60}});
    CHECK(at(Span::restore).state == SpanState::stopped);
    CHECK(at(Span::restore).duration == nanoseconds{seconds{50}});
    CHECK(at(Span::recovery).state == SpanState::stopped);
    CHECK(at(Span::recovery).duration == nanoseconds{seconds{50}});
    CHECK(at(Span::verify).state == SpanState::measured);
    CHECK(at(Span::verify).duration == nanoseconds{seconds{5}});
    CHECK(at(Span::restore_wait).state == SpanState::not_reported);
    CHECK(at(Span::cleanup_after).state == SpanState::clock_backwards);
    CHECK_FALSE(at(Span::cleanup_after).duration);
    CHECK(at(Span::sample_select).state == SpanState::not_run);
    CHECK(fake.reads == 0);

    // A second stop finds nothing open.
    timer.stop_open(t0 + seconds{120});
    CHECK(timer.timings().spans[static_cast<std::size_t>(Span::total)].duration ==
          nanoseconds{seconds{60}});
}

TEST_CASE("step timer: stop_open leaves the span it keeps open", "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    REQUIRE(timer.start(Span::total, t0));
    REQUIRE(timer.start(Span::restore, t0 + seconds{10}));

    timer.stop_open(t0 + seconds{30}, Span::total);

    CHECK(timer.state(Span::total) == SpanState::open);
    CHECK(span_of(timer, Span::restore).duration == nanoseconds{seconds{20}});
    CHECK(timer.state(Span::restore) == SpanState::stopped);
    // Kept, not spoiled: it still ends with its own reading.
    CHECK(timer.end(Span::total, t0 + seconds{90}));
    CHECK(span_of(timer, Span::total).duration == nanoseconds{seconds{90}});
    CHECK(fake.reads == 0);
}

// Review of W3.5, points 1 and 2: a clock that throws must never stop a run,
// so the timings read it through try_now, and a failed reading leaves its
// span as it was (a start) or open for good (an end), never closed later
// with a duration it never had.
TEST_CASE("step timer: try_now is nullopt when the clock throws, and never throws",
          "[step_timer]")
{
    int reads = 0;
    const StepTimer timer{[&reads]() -> TimePoint {
        if (++reads == 2) {
            throw std::runtime_error("SENTINEL-CLOCK");
        }
        return t0;
    }};
    CHECK(timer.try_now() == t0);
    CHECK_FALSE(timer.try_now());
    CHECK(timer.try_now() == t0);
    CHECK(reads == 3);
    // now() still throws what the clock throws.
    reads = 1;
    CHECK_THROWS_AS(timer.now(), std::runtime_error);
}

TEST_CASE("step timer: a failed reading starts nothing, and an end that fails leaves its span open "
          "for good",
          "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    SECTION("a start")
    {
        CHECK_FALSE(timer.start(Span::sample_select, std::nullopt));
        CHECK(timer.state(Span::sample_select) == SpanState::not_run);
        // The span can still be started.
        CHECK(timer.start(Span::sample_select, t0));
        CHECK(timer.state(Span::sample_select) == SpanState::open);
    }
    SECTION("an end")
    {
        REQUIRE(timer.start(Span::cleanup_after, t0));
        CHECK_FALSE(timer.end(Span::cleanup_after, std::nullopt));
        CHECK(timer.state(Span::cleanup_after) == SpanState::open);
        // Nothing closes it later: not an end, not a stop.
        CHECK_FALSE(timer.end(Span::cleanup_after, t0 + seconds{5}));
        timer.stop_open(t0 + seconds{9});
        const timing::SpanTiming span = span_of(timer, Span::cleanup_after);
        CHECK(span.state == SpanState::open);
        CHECK_FALSE(span.duration);
    }
    SECTION("a stop whose reading failed")
    {
        REQUIRE(timer.start(Span::restore, t0));
        REQUIRE(timer.start(Span::recovery, t0));
        REQUIRE(timer.start(Span::total, t0));
        timer.stop_open(std::nullopt, Span::total);
        // A later stop doesn't close them with its own reading.
        timer.stop_open(t0 + seconds{60});
        CHECK(timer.state(Span::restore) == SpanState::open);
        CHECK(timer.state(Span::recovery) == SpanState::open);
        CHECK(span_of(timer, Span::total).duration == nanoseconds{seconds{60}});
    }
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: state reads one span, not_run for a span outside the enum", "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    REQUIRE(timer.start(Span::verify, t0));
    REQUIRE(timer.report(Span::restore_wait, std::nullopt));
    CHECK(timer.state(Span::verify) == SpanState::open);
    CHECK(timer.state(Span::restore_wait) == SpanState::not_reported);
    CHECK(timer.state(Span::total) == SpanState::not_run);
    CHECK(timer.state(static_cast<Span>(99)) == SpanState::not_run);
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: a fresh timer has every span not_run", "[step_timer]")
{
    FakeClock fake;
    const StepTimer timer{fake.clock()};
    const timing::RunTimings timings = timer.timings();
    REQUIRE(timings.spans.size() == timing::kSpanCount);
    for (const timing::SpanTiming& span : timings.spans) {
        CHECK(span.state == SpanState::not_run);
        CHECK_FALSE(span.duration);
    }
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: start and end measure, a stopped end keeps its duration",
          "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};

    CHECK(timer.start(Span::cleanup_before, t0));
    CHECK(timer.end(Span::cleanup_before, t0 + milliseconds{3106}));
    CHECK(timer.start(Span::target_snapshot, t0));
    CHECK(timer.end(Span::target_snapshot, t0 + milliseconds{1204}, true));
    CHECK(timer.start(Span::restore_point_lookup, t0));
    CHECK(timer.end(Span::restore_point_lookup, t0));

    CHECK(span_of(timer, Span::cleanup_before).state == SpanState::measured);
    CHECK(span_of(timer, Span::cleanup_before).duration == nanoseconds{milliseconds{3106}});
    CHECK(span_of(timer, Span::target_snapshot).state == SpanState::stopped);
    CHECK(span_of(timer, Span::target_snapshot).duration == nanoseconds{milliseconds{1204}});
    // The same instant twice is a duration of zero, not a clock that went back.
    CHECK(span_of(timer, Span::restore_point_lookup).state == SpanState::measured);
    CHECK(span_of(timer, Span::restore_point_lookup).duration == nanoseconds{0});
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: report takes a connector's duration or marks it not reported",
          "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    CHECK(timer.report(Span::restore_submit, nanoseconds{4'120'000'001}));
    CHECK(timer.report(Span::restore_wait, std::nullopt));
    CHECK(timer.report(Span::verify, nanoseconds{0}));

    CHECK(span_of(timer, Span::restore_submit).state == SpanState::measured);
    CHECK(span_of(timer, Span::restore_submit).duration == nanoseconds{4'120'000'001});
    CHECK(span_of(timer, Span::restore_wait).state == SpanState::not_reported);
    CHECK_FALSE(span_of(timer, Span::restore_wait).duration);
    CHECK(span_of(timer, Span::verify).state == SpanState::measured);
    CHECK(span_of(timer, Span::verify).duration == nanoseconds{0});
    CHECK(fake.reads == 0);
}

TEST_CASE("step timer: spans that share a reading share it exactly", "[step_timer]")
{
    FakeClock fake;
    StepTimer timer{fake.clock()};

    fake.at = t0 + nanoseconds{17};
    const TimePoint started = timer.now();
    timer.start(Span::restore, started);
    timer.start(Span::recovery, started);
    fake.at += nanoseconds{1'234'567'891};
    const TimePoint restored = timer.now();
    timer.end(Span::restore, restored);
    timer.start(Span::verify, restored);
    fake.at += nanoseconds{987'654'321};
    const TimePoint verified = timer.now();
    timer.end(Span::verify, verified);
    timer.end(Span::recovery, verified);

    CHECK(fake.reads == 3);
    CHECK(*span_of(timer, Span::recovery).duration ==
          *span_of(timer, Span::restore).duration + *span_of(timer, Span::verify).duration);
}

TEST_CASE("step timer: now reads the injected clock once per call", "[step_timer]")
{
    FakeClock fake;
    const StepTimer timer{fake.clock()};
    fake.at = t0 + seconds{42};
    CHECK(timer.now() == t0 + seconds{42});
    CHECK(fake.reads == 1);
}

TEST_CASE("step timer: a null clock falls back to steady_clock::now", "[step_timer]")
{
    const StepTimer timer{nullptr};
    const TimePoint before = std::chrono::steady_clock::now();
    const TimePoint reading = timer.now();
    const TimePoint after = std::chrono::steady_clock::now();
    CHECK(before <= reading);
    CHECK(reading <= after);
}

TEST_CASE("step timer: format_span is H:MM:SS.mmm, cut to the millisecond", "[step_timer]")
{
    struct Row {
        nanoseconds span;
        std::string_view text;
    };
    const Row row = GENERATE(
        Row{nanoseconds{-1}, "-"},
        Row{nanoseconds{std::numeric_limits<std::int64_t>::min()}, "-"},
        Row{nanoseconds{0}, "0:00:00.000"},
        Row{nanoseconds{999'999}, "0:00:00.000"},
        Row{milliseconds{1}, "0:00:00.001"},
        Row{nanoseconds{1'999'999}, "0:00:00.001"},
        Row{milliseconds{412}, "0:00:00.412"},
        Row{seconds{59} + milliseconds{999}, "0:00:59.999"},
        Row{seconds{60}, "0:01:00.000"},
        Row{minutes{12} + seconds{41} + milliseconds{880}, "0:12:41.880"},
        Row{hours{1}, "1:00:00.000"},
        Row{hours{9} + minutes{59} + seconds{59} + milliseconds{999}, "9:59:59.999"},
        Row{hours{123} + minutes{4} + seconds{5} + milliseconds{6}, "123:04:05.006"},
        Row{nanoseconds{std::numeric_limits<std::int64_t>::max()}, "2562047:47:16.854"});
    INFO(row.text);
    CHECK(timing::format_span(row.span) == row.text);
}

TEST_CASE("step timer: span and state names, and the table's notes", "[step_timer]")
{
    const std::vector<std::string_view> names = {
        "restore_point_lookup", "cleanup_before", "sample_select", "target_snapshot",
        "restore",              "restore_submit", "restore_wait",  "verify",
        "recovery",             "cleanup_after",  "total"};
    REQUIRE(names.size() == timing::kSpanCount);
    for (std::size_t i = 0; i < timing::kSpanCount; ++i) {
        CHECK(timing::to_string(kAllSpans[i]) == names[i]);
        CHECK(static_cast<std::size_t>(kAllSpans[i]) == i);
    }

    struct Row {
        SpanState state;
        std::string_view name;
        std::string_view note;
    };
    const Row row = GENERATE(Row{SpanState::not_run, "not_run", "not run"},
                             Row{SpanState::open, "open", "not closed"},
                             Row{SpanState::measured, "measured", ""},
                             Row{SpanState::stopped, "stopped", "stopped"},
                             Row{SpanState::not_reported, "not_reported", "not reported"},
                             Row{SpanState::clock_backwards, "clock_backwards", "clock went back"});
    CHECK(timing::to_string(row.state) == row.name);
    CHECK(timing::note(row.state) == row.note);
}

namespace {

// One span in each state, the rest not run.
timing::RunTimings every_state()
{
    FakeClock fake;
    StepTimer timer{fake.clock()};
    timer.start(Span::total, t0);
    timer.end(Span::total, t0 + minutes{12} + seconds{41} + milliseconds{880} + nanoseconds{999'999});
    timer.start(Span::restore, t0);
    timer.end(Span::restore, t0 + seconds{490} + nanoseconds{4'000'000}, true);
    timer.report(Span::restore_submit, std::nullopt);
    timer.report(Span::restore_wait, nanoseconds{-5});
    timer.start(Span::verify, t0);
    timer.report(Span::cleanup_before, nanoseconds{0});
    return timer.timings();
}

} // namespace

TEST_CASE("step timer: format_timings prints all eleven rows in span order", "[step_timer]")
{
    CHECK(timing::format_timings(every_state()) ==
          "STEP                  TIME         NOTE\n"
          "restore_point_lookup  -            not run\n"
          "cleanup_before        0:00:00.000\n"
          "sample_select         -            not run\n"
          "target_snapshot       -            not run\n"
          "restore               0:08:10.004  stopped\n"
          "restore_submit        -            not reported\n"
          "restore_wait          -            clock went back\n"
          "verify                -            not closed\n"
          "recovery              -            not run\n"
          "cleanup_after         -            not run\n"
          "total                 0:12:41.880\n");
}

TEST_CASE("step timer: to_json has every span as a key, null when it didn't run",
          "[step_timer]")
{
    const json expected = json::parse(R"({"spans": {
        "restore_point_lookup": null,
        "cleanup_before": {"ms": 0},
        "sample_select": null,
        "target_snapshot": null,
        "restore": {"ms": 490004, "note": "stopped"},
        "restore_submit": {"note": "not_reported"},
        "restore_wait": {"note": "clock_backwards"},
        "verify": {"note": "open"},
        "recovery": null,
        "cleanup_after": null,
        "total": {"ms": 761880}}})");
    CHECK(timing::to_json(every_state()) == expected);
}

TEST_CASE("step timer: a hand-built span without a usable duration reads as clock_backwards",
          "[step_timer]")
{
    // RunTimings is plain data: only a caller that builds one by hand can give
    // a measured span no duration, or a negative one. Nothing is made up for it.
    timing::RunTimings timings;
    auto& lookup = timings.spans[static_cast<std::size_t>(Span::restore_point_lookup)];
    lookup.state = SpanState::measured;
    auto& total = timings.spans[static_cast<std::size_t>(Span::total)];
    total.state = SpanState::stopped;
    total.duration = nanoseconds{-1};
    // A duration beside a state that has none is ignored.
    auto& verify = timings.spans[static_cast<std::size_t>(Span::verify)];
    verify.state = SpanState::not_reported;
    verify.duration = seconds{3};

    const json spans = timing::to_json(timings)["spans"];
    CHECK(spans["restore_point_lookup"] == json{{"note", "clock_backwards"}});
    CHECK(spans["total"] == json{{"note", "clock_backwards"}});
    CHECK(spans["verify"] == json{{"note", "not_reported"}});

    const std::string table = timing::format_timings(timings);
    CHECK(table.find("restore_point_lookup  -     clock went back\n") != std::string::npos);
    CHECK(table.find("verify                -     not reported\n") != std::string::npos);
    CHECK(table.find("total                 -     clock went back\n") != std::string::npos);
}

TEST_CASE("step timer: a session sum is the sum, or a state, never a partial number",
          "[step_timer]")
{
    using Sessions = std::vector<std::optional<nanoseconds>>;
    constexpr auto kMax = nanoseconds{std::numeric_limits<std::int64_t>::max()};
    struct Row {
        const char* name;
        Sessions sessions;
        SpanState state;
        std::optional<nanoseconds> duration;
    };
    const Row row = GENERATE_COPY(
        Row{"no sessions", {}, SpanState::not_reported, std::nullopt},
        Row{"one session without it", {std::nullopt}, SpanState::not_reported, std::nullopt},
        Row{"one of three without it",
            {seconds{4}, std::nullopt, seconds{5}},
            SpanState::not_reported,
            std::nullopt},
        Row{"a missing one before a negative one",
            {std::nullopt, nanoseconds{-1}},
            SpanState::not_reported,
            std::nullopt},
        Row{"a negative one before a missing one",
            {nanoseconds{-1}, std::nullopt},
            SpanState::not_reported,
            std::nullopt},
        Row{"one negative", {nanoseconds{-1}}, SpanState::clock_backwards, std::nullopt},
        Row{"a negative one among others",
            {seconds{4}, nanoseconds{-7}, seconds{5}},
            SpanState::clock_backwards,
            std::nullopt},
        Row{"a negative one that the others outweigh",
            {seconds{10}, nanoseconds{-1}},
            SpanState::clock_backwards,
            std::nullopt},
        Row{"one session", {milliseconds{4120}}, SpanState::measured, nanoseconds{milliseconds{4120}}},
        Row{"a zero", {nanoseconds{0}}, SpanState::measured, nanoseconds{0}},
        Row{"three sessions",
            {seconds{1}, milliseconds{2500}, nanoseconds{1}},
            SpanState::measured,
            nanoseconds{3'500'000'001}},
        Row{"a sum past the clock's range stays at its largest",
            {kMax, nanoseconds{1}},
            SpanState::measured,
            kMax},
        Row{"the largest duration alone", {kMax}, SpanState::measured, kMax});
    INFO(row.name);

    FakeClock fake;
    StepTimer timer{fake.clock()};
    // Read in place, from each session's own field.
    struct Session {
        int other = 0;
        std::optional<nanoseconds> wait;
    };
    std::vector<Session> sessions;
    for (const std::optional<nanoseconds>& wait : row.sessions) {
        sessions.push_back({1, wait});
    }
    CHECK(timer.report(Span::restore_wait, timing::sum_session_durations(sessions, &Session::wait)));
    const timing::SpanTiming span = span_of(timer, Span::restore_wait);
    CHECK(span.state == row.state);
    CHECK(span.duration == row.duration);
}
