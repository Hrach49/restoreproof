#include "veeam_time.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace rp {

namespace {

// The years parse_veeam_time accepts.
constexpr int kFirstYear = 1678;
constexpr int kLastYear = 2261;

bool all_digits(std::string_view text) noexcept
{
    return !text.empty() && std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

int number(std::string_view digits) noexcept
{
    int out = 0;
    for (const char c : digits) {
        out = out * 10 + (c - '0');
    }
    return out;
}

} // namespace

std::optional<VeeamTime> parse_veeam_time(std::string_view text)
{
    // YYYY-MM-DDTHH:MM:SS, then .1-7 digits or nothing, then Z.
    if (text.size() < 20 || text.back() != 'Z' || text[4] != '-' || text[7] != '-' ||
        text[10] != 'T' || text[13] != ':' || text[16] != ':') {
        return std::nullopt;
    }
    const std::string_view year = text.substr(0, 4);
    const std::string_view month = text.substr(5, 2);
    const std::string_view day = text.substr(8, 2);
    const std::string_view hour = text.substr(11, 2);
    const std::string_view minute = text.substr(14, 2);
    const std::string_view second = text.substr(17, 2);
    for (const std::string_view part : {year, month, day, hour, minute, second}) {
        if (!all_digits(part)) {
            return std::nullopt;
        }
    }
    // The fraction's length is checked before its digits are read.
    std::string_view fraction = text.substr(19, text.size() - 20);
    if (!fraction.empty()) {
        if (fraction.front() != '.') {
            return std::nullopt;
        }
        fraction.remove_prefix(1);
        if (fraction.size() > 7 || !all_digits(fraction)) {
            return std::nullopt;
        }
    }
    const std::chrono::year_month_day date{std::chrono::year{number(year)},
                                           std::chrono::month{static_cast<unsigned>(number(month))},
                                           std::chrono::day{static_cast<unsigned>(number(day))}};
    // A time in nanoseconds holds 1677-09-21 to 2262-04-11: whole years
    // inside that, so no date overflows it (Veeam's 9999 "never" among them).
    if (!date.ok() || number(year) < kFirstYear || number(year) > kLastYear || number(hour) > 23 ||
        number(minute) > 59 || number(second) > 59) {
        return std::nullopt;
    }
    std::int64_t nanos = 0;
    for (std::size_t i = 0; i < 9; ++i) {
        nanos = nanos * 10 + (i < fraction.size() ? fraction[i] - '0' : 0);
    }
    return VeeamTime{std::chrono::sys_days{date}} + std::chrono::hours{number(hour)} +
           std::chrono::minutes{number(minute)} + std::chrono::seconds{number(second)} +
           std::chrono::nanoseconds{nanos};
}

} // namespace rp
