#pragma once

#include <filesystem>
#include <string>

namespace rp {

// A path as UTF-8, for messages and output. path::string() would use the
// ANSI code page and fail on characters outside it.
inline std::string path_to_utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

} // namespace rp
