#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace rp {

// Conversions between the UTF-16 of the wide Windows APIs (environment,
// command line, file names) and the UTF-8 rpcore works in. Neither ever
// substitutes a character: text that doesn't convert exactly is nullopt, so a
// secret or a path is never silently changed.

// nullopt when `text` isn't valid UTF-16 (an unpaired surrogate).
std::optional<std::string> utf16_to_utf8(std::wstring_view text);

// nullopt when `text` isn't valid UTF-8.
std::optional<std::wstring> utf8_to_utf16(std::string_view text);

} // namespace rp
