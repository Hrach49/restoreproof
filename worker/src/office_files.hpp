#pragma once

// The one Office package rule (docs/decisions.md 2026-10-01, W3.1 point 5):
// which files SharePoint may rewrite, so their stored bytes and size may
// differ from what was uploaded or backed up. The Graph reader reads them up
// to the download limit (graph_targets.cpp) and the expected set takes no
// size for them (expected_set.cpp).

#include <algorithm>
#include <array>
#include <cstddef>
#include <string_view>

namespace rp {

// The Office Open XML family: Word, Excel and PowerPoint documents, macro
// documents, templates and shows.
inline constexpr std::array<std::string_view, 14> kOfficePackageExtensions{
    ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx",
    ".xltm", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"};

// Whether `file_name` ends in one of them, ASCII case-insensitive, with
// something before it: a name that is only an extension (".docx") isn't a
// package's.
inline bool is_office_package(std::string_view file_name) noexcept
{
    constexpr std::size_t n = 5; // each extension: a dot and four letters
    if (file_name.size() <= n) {
        return false;
    }
    std::array<char, n> tail{};
    for (std::size_t i = 0; i < n; ++i) {
        const char c = file_name[file_name.size() - n + i];
        tail[i] = c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    }
    return std::ranges::find(kOfficePackageExtensions, std::string_view{tail.data(), n}) !=
           kOfficePackageExtensions.end();
}

} // namespace rp
