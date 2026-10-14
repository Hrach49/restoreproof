#include <rp/step_timer.hpp>

#include "duration_text.hpp"
#include "text_table.hpp"

#include <format>
#include <limits>
#include <utility>

namespace rp::timing {

namespace {

using std::chrono::nanoseconds;
using TimePoint = std::chrono::steady_clock::time_point;

constexpr std::array<std::string_view, kSpanCount> kSpanNames = {
    "restore_point_lookup", "cleanup_before", "sample_select",  "target_snapshot",
    "restore",              "restore_submit", "restore_wait",   "content_export",
    "verify",               "recovery",       "cleanup_after",  "total"};
static_assert(static_cast<std::size_t>(Span::total) + 1 == kSpanCount);

constexpr std::size_t kStateCount = 6;
constexpr std::array<std::string_view, kStateCount> kStateNames = {
    "not_run", "open", "measured", "stopped", "not_reported", "clock_backwards"};
constexpr std::array<std::string_view, kStateCount> kStateNotes = {
    "not run", "not closed", "", "stopped", "not reported", "clock went back"};
static_assert(static_cast<std::size_t>(SpanState::clock_backwards) + 1 == kStateCount);

// Index of `span`, or kSpanCount for a value outside the enum.
std::size_t index_of(Span span) noexcept
{
    const auto i = static_cast<std::size_t>(span);
    return i < kSpanCount ? i : kSpanCount;
}

// What the table and the JSON show: a measured or stopped span whose duration
// is missing or negative (only in a hand-built RunTimings) is clock_backwards,
// and a duration beside any other state is ignored.
SpanTiming usable(const SpanTiming& span)
{
    const bool timed = span.state == SpanState::measured || span.state == SpanState::stopped;
    if (!timed) {
        return {span.state, std::nullopt};
    }
    if (!span.duration || *span.duration < nanoseconds{0}) {
        return {SpanState::clock_backwards, std::nullopt};
    }
    return span;
}

} // namespace

std::string_view to_string(Span span) noexcept
{
    const std::size_t i = index_of(span);
    return i < kSpanCount ? kSpanNames[i] : "unknown";
}

std::string_view to_string(SpanState state) noexcept
{
    const auto i = static_cast<std::size_t>(state);
    return i < kStateCount ? kStateNames[i] : "unknown";
}

std::string_view note(SpanState state) noexcept
{
    const auto i = static_cast<std::size_t>(state);
    return i < kStateCount ? kStateNotes[i] : "";
}

StepTimer::StepTimer(Clock now) : now_(std::move(now))
{
    if (!now_) {
        now_ = [] { return std::chrono::steady_clock::now(); };
    }
}

TimePoint StepTimer::now() const
{
    return now_();
}

std::optional<TimePoint> StepTimer::try_now() const noexcept
{
    try {
        return now_();
    } catch (...) {
        return std::nullopt;
    }
}

bool StepTimer::start(Span span, std::optional<TimePoint> at) noexcept
{
    const std::size_t i = index_of(span);
    if (!at || i == kSpanCount || entries_[i].timing.state != SpanState::not_run) {
        return false;
    }
    entries_[i].timing.state = SpanState::open;
    entries_[i].started = *at;
    return true;
}

bool StepTimer::end(Span span, std::optional<TimePoint> at, bool stopped) noexcept
{
    const std::size_t i = index_of(span);
    if (i == kSpanCount || entries_[i].timing.state != SpanState::open ||
        entries_[i].unclosable) {
        return false;
    }
    if (!at) {
        entries_[i].unclosable = true;
        return false;
    }
    SpanTiming& timing = entries_[i].timing;
    if (*at < entries_[i].started) {
        timing.state = SpanState::clock_backwards;
        return true;
    }
    timing.state = stopped ? SpanState::stopped : SpanState::measured;
    timing.duration = *at - entries_[i].started;
    return true;
}

bool StepTimer::report(Span span, std::optional<nanoseconds> duration) noexcept
{
    const std::size_t i = index_of(span);
    if (i == kSpanCount || entries_[i].timing.state != SpanState::not_run) {
        return false;
    }
    SpanTiming& timing = entries_[i].timing;
    if (!duration) {
        timing.state = SpanState::not_reported;
    } else if (*duration < nanoseconds{0}) {
        timing.state = SpanState::clock_backwards;
    } else {
        timing.state = SpanState::measured;
        timing.duration = duration;
    }
    return true;
}

void StepTimer::stop_open(std::optional<TimePoint> at, std::optional<Span> keep) noexcept
{
    for (std::size_t i = 0; i < kSpanCount; ++i) {
        const auto span = static_cast<Span>(i);
        if (span != keep) {
            end(span, at, true);
        }
    }
}

SpanState StepTimer::state(Span span) const noexcept
{
    const std::size_t i = index_of(span);
    return i < kSpanCount ? entries_[i].timing.state : SpanState::not_run;
}

RunTimings StepTimer::timings() const noexcept
{
    RunTimings timings;
    for (std::size_t i = 0; i < kSpanCount; ++i) {
        timings.spans[i] = entries_[i].timing;
    }
    return timings;
}

std::string format_span(nanoseconds span)
{
    if (span < nanoseconds{0}) {
        return "-";
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(span).count();
    return format_hms(ms / 1000) + std::format(".{:03}", ms % 1000);
}

std::string format_timings(const RunTimings& timings)
{
    std::vector<TableRow> rows{{"", {"STEP", "TIME", "NOTE"}}};
    for (std::size_t i = 0; i < kSpanCount; ++i) {
        const SpanTiming span = usable(timings.spans[i]);
        rows.push_back({"",
                        {std::string{kSpanNames[i]},
                         span.duration ? format_span(*span.duration) : std::string{"-"},
                         std::string{note(span.state)}}});
    }
    return format_table(rows);
}

nlohmann::json to_json(const RunTimings& timings)
{
    nlohmann::json spans = nlohmann::json::object();
    for (std::size_t i = 0; i < kSpanCount; ++i) {
        const SpanTiming span = usable(timings.spans[i]);
        nlohmann::json& value = spans[std::string{kSpanNames[i]}];
        if (span.state == SpanState::not_run) {
            continue; // stays null
        }
        if (span.duration) {
            value["ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(*span.duration).count();
        }
        if (span.state != SpanState::measured) {
            value["note"] = to_string(span.state);
        }
    }
    nlohmann::json result;
    result["spans"] = std::move(spans);
    return result;
}

} // namespace rp::timing
