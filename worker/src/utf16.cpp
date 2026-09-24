#include "utf16.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <limits>

namespace rp {

std::optional<std::string> utf16_to_utf8(std::wstring_view text)
{
    if (text.empty()) {
        return std::string{};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    const int length = static_cast<int>(text.size());
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), length,
                                         nullptr, 0, nullptr, nullptr);
    if (size == 0) {
        return std::nullopt;
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), length, result.data(), size,
                        nullptr, nullptr);
    return result;
}

std::optional<std::wstring> utf8_to_utf16(std::string_view text)
{
    if (text.empty()) {
        return std::wstring{};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    const int length = static_cast<int>(text.size());
    const int size =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
    if (size == 0) {
        return std::nullopt;
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, result.data(), size);
    return result;
}

} // namespace rp
