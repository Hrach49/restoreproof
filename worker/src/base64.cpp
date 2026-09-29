#include <rp/base64.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace rp {

namespace {

constexpr std::string_view kStandard =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr std::string_view kUrl =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr std::int8_t kInvalid = -1;

// The value of each byte in the standard alphabet, kInvalid for every other.
constexpr std::array<std::int8_t, 256> make_decode_table()
{
    std::array<std::int8_t, 256> table{};
    table.fill(kInvalid);
    for (std::size_t i = 0; i < kStandard.size(); ++i) {
        table[static_cast<unsigned char>(kStandard[i])] = static_cast<std::int8_t>(i);
    }
    return table;
}

constexpr std::array<std::int8_t, 256> kDecode = make_decode_table();

int value_of(char c) noexcept
{
    return kDecode[static_cast<unsigned char>(c)];
}

} // namespace

std::optional<std::vector<unsigned char>> base64_decode(std::string_view text)
{
    if (text.size() % 4 != 0) {
        return std::nullopt;
    }
    std::size_t padding = 0;
    if (!text.empty() && text.back() == '=') {
        padding = text[text.size() - 2] == '=' ? 2 : 1;
    }
    const std::size_t data_chars = text.size() - padding;
    for (std::size_t i = 0; i < data_chars; ++i) {
        if (value_of(text[i]) == kInvalid) {
            return std::nullopt; // '=' before the end lands here too
        }
    }
    // The last data character carries 4 (one '=') or 2 (two) bits of
    // padding, which must be zero: "Zh==" and "Zg==" can't both mean "f".
    if (padding != 0) {
        const int last = value_of(text[data_chars - 1]);
        const int unused_mask = padding == 2 ? 0x0F : 0x03;
        if ((last & unused_mask) != 0) {
            return std::nullopt;
        }
    }

    std::vector<unsigned char> out;
    out.reserve(text.size() / 4 * 3 - padding);
    std::uint32_t bits = 0;
    int bit_count = 0;
    for (std::size_t i = 0; i < data_chars; ++i) {
        bits = (bits << 6) | static_cast<std::uint32_t>(value_of(text[i]));
        bit_count += 6;
        if (bit_count >= 8) {
            bit_count -= 8;
            out.push_back(static_cast<unsigned char>((bits >> bit_count) & 0xFF));
        }
    }
    return out;
}

namespace {

// `bytes` in `alphabet`, with '=' padding to a multiple of four when `pad`.
std::string encode(std::span<const unsigned char> bytes, std::string_view alphabet, bool pad)
{
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        const std::uint32_t group = (std::uint32_t{bytes[i]} << 16) |
                                    (std::uint32_t{bytes[i + 1]} << 8) | bytes[i + 2];
        out += alphabet[(group >> 18) & 0x3F];
        out += alphabet[(group >> 12) & 0x3F];
        out += alphabet[(group >> 6) & 0x3F];
        out += alphabet[group & 0x3F];
    }
    const std::size_t rest = bytes.size() - i;
    if (rest != 0) {
        std::uint32_t group = std::uint32_t{bytes[i]} << 16;
        if (rest == 2) {
            group |= std::uint32_t{bytes[i + 1]} << 8;
        }
        out += alphabet[(group >> 18) & 0x3F];
        out += alphabet[(group >> 12) & 0x3F];
        if (rest == 2) {
            out += alphabet[(group >> 6) & 0x3F];
        }
        if (pad) {
            out.append(3 - rest, '=');
        }
    }
    return out;
}

} // namespace

std::string base64_encode(std::span<const unsigned char> bytes)
{
    return encode(bytes, kStandard, true);
}

std::string base64url_encode(std::span<const unsigned char> bytes)
{
    return encode(bytes, kUrl, false);
}

std::string base64url_encode(std::string_view bytes)
{
    return base64url_encode(
        std::span{reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()});
}

} // namespace rp
