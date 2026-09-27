#pragma once

// Text helpers shared by the service clients (VeeamClient, GraphClient):
// encoding a form value and making a server's text fit one log line.

#include "control_chars.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace rp {

// What one_line keeps of a server's text by default: a service's messages are
// a sentence, so anything longer is cut and a strange response can't flood a
// log line.
inline constexpr std::size_t kOneLineMaxBytes = 500;

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
    const std::string_view kept = text.substr(0, cut);
    std::string out;
    out.reserve(kept.size());
    for (std::size_t i = 0; i < kept.size();) {
        if (const std::size_t length = control_character_length(kept, i); length != 0) {
            out += ' ';
            i += length;
        } else {
            out += kept[i];
            ++i;
        }
    }
    if (text.size() > max_bytes) {
        out += "...";
    }
    return out;
}

} // namespace rp
