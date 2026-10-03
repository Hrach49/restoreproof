#pragma once

// Step timings (W3.5, docs/decisions.md 2026-10-03): named spans of one run on
// one injected steady clock. `rpworker restore` prints them as a table at the
// end of the run and hands them on as the result's `timings` object. A span is
// measured, or it says why it has no duration: never run, stopped by an early
// end, not reported by the connector, or a clock that went back. No duration
// is ever made up, and nothing here throws inside a run or reads a wall clock.

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::timing {

// The table's and the JSON's order. The spans overlap and don't add up to
// `total`: `restore` holds `restore_submit` and `restore_wait`, `recovery`
// holds `restore` and `verify`.
enum class Span {
    restore_point_lookup,
    cleanup_before,
    sample_select,
    target_snapshot,
    restore,
    restore_submit,
    restore_wait,
    verify,
    recovery,
    cleanup_after,
    total
};
inline constexpr std::size_t kSpanCount = 11;

// "restore_point_lookup", ...; "unknown" for a value outside the enum.
std::string_view to_string(Span span) noexcept;

enum class SpanState {
    not_run,         // never started or reported
    open,            // started and never ended: a caller's bug, or a clock that threw
    measured,        // ended, or reported, with its duration
    stopped,         // ended early by a stop; its duration up to the time point it ended at
    not_reported,    // the connector didn't measure it
    clock_backwards  // an end before its start, or a negative reported duration
};

// "not_run", "open", ...; "unknown" for a value outside the enum.
std::string_view to_string(SpanState state) noexcept;

// The table's NOTE: "" for measured, else "not run", "not closed", "stopped",
// "not reported" or "clock went back"; "" for a value outside the enum.
std::string_view note(SpanState state) noexcept;

struct SpanTiming {
    SpanState state = SpanState::not_run;
    // Only when measured or stopped; never negative.
    std::optional<std::chrono::nanoseconds> duration;
};

// Indexed by Span.
struct RunTimings {
    std::array<SpanTiming, kSpanCount> spans;
};

// Not thread-safe. A misused call (a second start, an end or a report on a
// span not in the state it needs, a Span outside the enum) changes nothing and
// returns false: the first call holds. A caller's bug never stops a run.
class StepTimer {
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    // Null: std::chrono::steady_clock::now.
    explicit StepTimer(Clock now);

    // One reading of the clock. Spans that share a boundary share one reading.
    std::chrono::steady_clock::time_point now() const;

    // not_run -> open at `at`; false otherwise.
    bool start(Span span, std::chrono::steady_clock::time_point at) noexcept;

    // open -> measured (stopped when `stopped`) with at - start, or
    // clock_backwards with no duration when `at` is before the start; false
    // unless open.
    bool end(Span span, std::chrono::steady_clock::time_point at, bool stopped = false) noexcept;

    // A duration measured elsewhere (the connector's): not_run -> measured,
    // not_reported for nullopt, clock_backwards for a negative one; false
    // unless not_run.
    bool report(Span span, std::optional<std::chrono::nanoseconds> duration) noexcept;

    // Every open span ends `stopped` at `at` (clock_backwards when `at` is
    // before its start).
    void stop_open(std::chrono::steady_clock::time_point at) noexcept;

    // Reads no clock: a span still open shows as open, with no duration.
    RunTimings timings() const noexcept;

private:
    struct Entry {
        SpanTiming timing;
        std::chrono::steady_clock::time_point started;
    };

    Clock now_;
    std::array<Entry, kSpanCount> entries_{};
};

// "H:MM:SS.mmm", cut to the millisecond, hours not capped; "-" for a negative one.
std::string format_span(std::chrono::nanoseconds span);

// The sessions' durations summed, for StepTimer::report: nullopt (not
// reported) when there are none or any session has none, then a negative
// session's duration (clock went back) when any is negative, else the sum,
// held at nanoseconds' largest value rather than wrapping.
std::optional<std::chrono::nanoseconds> sum_session_durations(
    const std::vector<std::optional<std::chrono::nanoseconds>>& sessions) noexcept;

// The table: a "STEP TIME NOTE" header, then all eleven spans in Span order,
// one line each, ending in '\n'. TIME is format_span, or "-" without a usable
// duration; NOTE is note(). A measured or stopped span with no duration or a
// negative one (a hand-built RunTimings) reads as clock_backwards.
std::string format_timings(const RunTimings& timings);

// The result's `timings` object: {"spans": {"<span>": ...}} with all eleven
// names as keys; null for not_run, {"ms": n} for measured, {"ms": n, "note":
// "stopped"} for stopped, else {"note": "<state>"}. ms is whole milliseconds,
// cut toward zero. Unusable durations as in format_timings.
nlohmann::json to_json(const RunTimings& timings);

} // namespace rp::timing
