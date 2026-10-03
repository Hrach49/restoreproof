#pragma once

// The one "H:MM:SS" of the CLI's durations: the restore's line
// (rp::format_elapsed) and the step timings' table (timing::format_span),
// which adds ".mmm". Hours are not padded or capped.

#include <cstdint>
#include <format>
#include <string>

namespace rp {

// "H:MM:SS" for a whole number of seconds; a negative one is "-".
inline std::string format_hms(std::int64_t seconds)
{
    if (seconds < 0) {
        return "-";
    }
    return std::format("{}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60);
}

} // namespace rp
