#include "graph_ids.hpp"

#include "uuid.hpp"

#include <rp/base64.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <utility>

namespace rp {

namespace {

// Only called on is_uuid's hex digits.
unsigned char hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9') {
        return static_cast<unsigned char>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<unsigned char>(c - 'a' + 10);
    }
    return static_cast<unsigned char>(c - 'A' + 10);
}

// The UUID's 16 bytes as written, then its first three fields byte-swapped:
// how Windows (and SharePoint) stores a GUID.
std::array<unsigned char, 16> bytes_le(std::string_view uuid)
{
    std::array<unsigned char, 16> bytes{};
    std::size_t at = 0;
    for (std::size_t i = 0; i < uuid.size(); i += 2) {
        if (uuid[i] == '-') {
            ++i;
        }
        bytes[at++] = static_cast<unsigned char>(hex_value(uuid[i]) * 16 + hex_value(uuid[i + 1]));
    }
    std::swap(bytes[0], bytes[3]);
    std::swap(bytes[1], bytes[2]);
    std::swap(bytes[4], bytes[5]);
    std::swap(bytes[6], bytes[7]);
    return bytes;
}

} // namespace

std::optional<std::string> graph_drive_id(std::string_view site_guid, std::string_view web_guid,
                                          std::string_view list_guid)
{
    if (!is_uuid(site_guid) || !is_uuid(web_guid) || !is_uuid(list_guid)) {
        return std::nullopt;
    }
    std::array<unsigned char, 48> bytes{};
    std::size_t at = 0;
    for (const std::string_view guid : {site_guid, web_guid, list_guid}) {
        for (const unsigned char b : bytes_le(guid)) {
            bytes[at++] = b;
        }
    }
    return "b!" + base64url_encode(std::span<const unsigned char>{bytes});
}

} // namespace rp
