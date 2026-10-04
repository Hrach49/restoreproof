#pragma once

// Veeam's UTC time form, read in one place: VeeamClient sorts restore points
// by it and checks an explore session's backup time with it, and
// restore_sample (veeam_restore.hpp) checks the restore point's time and
// reads session times with it. to_whole_seconds is the same form cut to the
// second: a sampled mail's received time and the result's restore point time.

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace rp {

using VeeamTime = std::chrono::sys_time<std::chrono::nanoseconds>;

// Veeam's UTC form, "YYYY-MM-DDTHH:MM:SS" with 0 to 7 fractional digits and
// "Z" (Veeam drops a fraction's trailing zeros, and the '.' with them), as a
// time; nullopt for any other text (an offset, no zone, 8 or more digits), an
// impossible date, or a year outside 1678-2261 (what a time in nanoseconds
// holds). Explore sessions are opened by this exact string, and Veeam
// answers 500 to any other form (veeam-notes §4.2).
std::optional<VeeamTime> parse_veeam_time(std::string_view text);

// A Veeam time cut (not rounded) to "YYYY-MM-DDTHH:MM:SSZ"; nullopt when it
// isn't Veeam's UTC form (parse_veeam_time).
std::optional<std::string> to_whole_seconds(std::string_view text);

} // namespace rp
