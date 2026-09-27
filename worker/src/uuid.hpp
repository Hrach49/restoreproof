#pragma once

#include <cstddef>
#include <string_view>

namespace rp {

// 8-4-4-4-12 hex digits, nothing else: safe to put in a URL as it is.
inline bool is_uuid(std::string_view id) noexcept
{
    const auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    if (id.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < id.size(); ++i) {
        const bool dash_here = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash_here ? id[i] != '-' : !is_hex(id[i])) {
            return false;
        }
    }
    return true;
}

} // namespace rp
