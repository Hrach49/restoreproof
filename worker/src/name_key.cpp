#include "name_key.hpp"

#include "utf16.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <optional>
#include <string>

namespace rp {

namespace {

std::string ascii_upper(std::string_view text)
{
    std::string out{text};
    for (char& c : out) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
    }
    return out;
}

} // namespace

std::string name_key(std::string_view text)
{
    const std::optional<std::wstring> wide = utf8_to_utf16(text);
    if (!wide) {
        return ascii_upper(text);
    }
    if (wide->empty()) {
        return {};
    }
    // Upper-casing maps one UTF-16 unit to one (LCMAP_UPPERCASE never
    // changes the length), so the output buffer is the input's size;
    // utf8_to_utf16 already refused a length above INT_MAX.
    std::wstring upper(wide->size(), L'\0');
    const int length = static_cast<int>(wide->size());
    const int written = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, wide->data(), length,
                                      upper.data(), length, nullptr, nullptr, 0);
    if (written != length) {
        return ascii_upper(text); // never seen: keep a key rather than throw
    }
    // Valid UTF-16 in, valid UTF-16 out: the conversion back can't fail.
    return utf16_to_utf8(upper).value_or(ascii_upper(text));
}

bool same_name(std::string_view a, std::string_view b)
{
    return name_key(a) == name_key(b);
}

} // namespace rp
