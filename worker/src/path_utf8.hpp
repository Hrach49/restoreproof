#pragma once

#include "utf16.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace rp {

// A path as UTF-8, for messages and output. path::string() would use the
// ANSI code page and fail on characters outside it.
inline std::string path_to_utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// A UTF-8 path as a path, or nullopt when it isn't valid UTF-8. Not
// path(std::string), which reads the ANSI code page, nor path(std::u8string),
// which throws a system_error whose message isn't meant for the user.
inline std::optional<std::filesystem::path> path_from_utf8(std::string_view text)
{
    std::optional<std::wstring> wide = utf8_to_utf16(text);
    if (!wide) {
        return std::nullopt;
    }
    return std::filesystem::path(std::move(*wide));
}

} // namespace rp
