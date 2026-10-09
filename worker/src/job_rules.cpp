#include "job_rules.hpp"

#include <rp/evidence_builder.hpp>
#include <rp/sample_rng.hpp>

#include <algorithm>
#include <stdexcept>

namespace rp::job_rules {

bool is_sample_size(std::int64_t n) noexcept
{
    return n >= 0 && n <= kMaxSampleSize;
}

bool is_empty_sample(std::int64_t mail, std::int64_t sharepoint, std::int64_t onedrive) noexcept
{
    return mail == 0 && sharepoint == 0 && onedrive == 0;
}

bool is_point(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= kMaxPointIdLength &&
           std::ranges::all_of(text, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      c == '-';
           });
}

bool is_cursor_value(std::int64_t n) noexcept
{
    return n >= 0 && n <= kMaxCursor;
}

bool is_run_id(std::string_view text)
{
    try {
        sampling::check_run_id(text);
        return true;
    } catch (const std::invalid_argument&) {
        return false;
    }
}

bool is_folder_run_id(std::string_view text)
{
    return is_run_id(text) && EvidenceBuilder::can_name_folder(text);
}

} // namespace rp::job_rules
