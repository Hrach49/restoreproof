#pragma once

// Text helpers shared by the service clients (VeeamClient, GraphClient) and
// the commands: encoding a form value, decoding a URL's path, joining names
// and making a server's text fit one log line.

#include "control_chars.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// What one_line keeps of a server's text by default: a service's messages are
// a sentence, so anything longer is cut and a strange response can't flood a
// log line.
inline constexpr std::size_t kOneLineMaxBytes = 500;

// `text` with A-Z folded to a-z and every other byte kept. Not std::tolower:
// it follows the C locale, which under a Western code page folds bytes above
// 0x7F, the parts of UTF-8 characters included.
inline std::string ascii_lower(std::string_view text)
{
    std::string out{text};
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

// Equal but for the case of A-Z.
inline bool ascii_iequals(std::string_view a, std::string_view b)
{
    return ascii_lower(a) == ascii_lower(b);
}

// Whether `text` ends with `suffix` but for the case of A-Z, and is longer.
inline bool ascii_ends_with_i(std::string_view text, std::string_view suffix)
{
    return text.size() > suffix.size() &&
           ascii_iequals(text.substr(text.size() - suffix.size()), suffix);
}

// `names` one after another with `separator` between them.
inline std::string joined(const std::vector<std::string>& names, std::string_view separator)
{
    std::string text;
    for (const std::string& name : names) {
        if (!text.empty()) {
            text += separator;
        }
        text += name;
    }
    return text;
}

// Percent-encoding for an application/x-www-form-urlencoded value: every byte
// but ASCII letters, digits and -._~ becomes %XX, so a password may hold any
// character.
inline std::string form_encode(std::string_view text)
{
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(text.size() * 3);
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
            byte == '~') {
            out += c;
        } else {
            out += '%';
            out += hex[byte >> 4];
            out += hex[byte & 0x0F];
        }
    }
    return out;
}

// `text` with each "%XX" (two hex digits, either case) turned into its byte;
// a '%' not followed by two hex digits is kept as it is.
inline std::string percent_decode(std::string_view text)
{
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    };
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size() && hex(text[i + 1]) >= 0 &&
            hex(text[i + 2]) >= 0) {
            out += static_cast<char>(hex(text[i + 1]) * 16 + hex(text[i + 2]));
            i += 2;
        } else {
            out += text[i];
        }
    }
    return out;
}

// `text` with each control character (control_chars.hpp) replaced by a
// space: text from a server that the Worker keeps or prints.
inline std::string without_controls(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size();) {
        if (const std::size_t length = control_character_length(text, i); length != 0) {
            out += ' ';
            i += length;
        } else {
            out += text[i];
            ++i;
        }
    }
    return out;
}

// Text from a response, made fit for one log line: each control character
// (control_chars.hpp: the multi-byte ones that forge or reorder lines too)
// becomes a space, and it is cut at `max_bytes` bytes, back to the start of a
// UTF-8 character so none is split, with "..." after a cut.
inline std::string one_line(std::string_view text, std::size_t max_bytes = kOneLineMaxBytes)
{
    std::size_t cut = std::min(text.size(), max_bytes);
    if (cut < text.size()) {
        while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80) {
            --cut;
        }
    }
    std::string out = without_controls(text.substr(0, cut));
    if (text.size() > max_bytes) {
        out += "...";
    }
    return out;
}

} // namespace rp
