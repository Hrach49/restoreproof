#pragma once

// Characters that can forge, hide or reorder a line of output: the C0 controls
// and DEL, the C1 controls (U+0080-U+009F, such as NEL), the Arabic letter mark
// (U+061C), the left-to-right and right-to-left marks (U+200E, U+200F), the
// line and paragraph separators (U+2028, U+2029), the bidi embeddings and
// overrides (U+202A-U+202E) and the bidi isolates (U+2066-U+2069). Config
// values refuse them; text from a server has them replaced.

#include <cstddef>
#include <string_view>

namespace rp {

// The length in bytes of the control character that starts at `at` in the
// UTF-8 `text`, or 0 if none does.
inline std::size_t control_character_length(std::string_view text, std::size_t at) noexcept
{
    const auto byte = [text](std::size_t i) {
        return i < text.size() ? static_cast<unsigned char>(text[i]) : 0;
    };
    if (at >= text.size()) {
        return 0;
    }
    const unsigned char b0 = byte(at);
    const unsigned char b1 = byte(at + 1);
    const unsigned char b2 = byte(at + 2);
    if (b0 < 0x20 || b0 == 0x7F) {
        return 1;
    }
    if ((b0 == 0xC2 && b1 >= 0x80 && b1 <= 0x9F) || (b0 == 0xD8 && b1 == 0x9C)) {
        return 2;
    }
    if ((b0 == 0xE2 && b1 == 0x80 && (b2 == 0x8E || b2 == 0x8F || (b2 >= 0xA8 && b2 <= 0xAE))) ||
        (b0 == 0xE2 && b1 == 0x81 && b2 >= 0xA6 && b2 <= 0xA9)) {
        return 3;
    }
    return 0;
}

} // namespace rp
