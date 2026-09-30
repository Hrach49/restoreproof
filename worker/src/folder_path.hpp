#pragma once

// How the Worker reads a selector's or a canary's folder_path ("/a/b"). One
// rule for the target guard's layer 1 (target_guard.cpp), the sampler's pool
// check (sample_selector.cpp) and the canary manifest loader
// (canary_manifest.cpp), so the sampler never offers what the guard would
// refuse (W2.6 review).

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string_view>

namespace rp {

// The first folder of a path split on '/', empty and "." segments skipped
// ("" for the root); nullopt when the path has a ".." segment, which no check
// here follows.
inline std::optional<std::string_view> first_folder(std::string_view path)
{
    std::optional<std::string_view> first;
    std::size_t at = 0;
    while (at <= path.size()) {
        const std::size_t slash = std::min(path.find('/', at), path.size());
        const std::string_view segment = path.substr(at, slash - at);
        if (segment == "..") {
            return std::nullopt;
        }
        if (!first && !segment.empty() && segment != ".") {
            first = segment;
        }
        at = slash + 1;
    }
    return first.value_or(std::string_view{});
}

// Whether the path has a ".." segment.
inline bool has_dot_dot_segment(std::string_view path)
{
    return !first_folder(path).has_value();
}

} // namespace rp
