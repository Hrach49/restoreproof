#include <rp/canonical_json.hpp>

#include <rp/sha256.hpp>

#include <algorithm>
#include <cstdint>

namespace rp {

namespace {

// 2^53 - 1: the largest integer every reader (a double included) holds exactly.
constexpr std::int64_t kMaxInteger = 9007199254740991;

// Throws for the first value under `value` the form refuses. Invalid UTF-8 in a
// string is left to dump's strict handler.
void check(const nlohmann::json& value)
{
    using value_t = nlohmann::json::value_t;
    switch (value.type()) {
    case value_t::object:
        for (const auto& [key, member] : value.items()) {
            if (std::any_of(key.begin(), key.end(), [](char c) { return static_cast<unsigned char>(c) > 0x7F; })) {
                throw CanonicalJsonError("canonical-json-v1: an object key that isn't ASCII");
            }
            check(member);
        }
        return;
    case value_t::array:
        for (const nlohmann::json& element : value) {
            check(element);
        }
        return;
    case value_t::number_float:
        throw CanonicalJsonError("canonical-json-v1: a floating-point number");
    case value_t::number_integer: {
        const std::int64_t n = value.get<std::int64_t>();
        if (n < -kMaxInteger || n > kMaxInteger) {
            throw CanonicalJsonError("canonical-json-v1: an integer outside +-(2^53 - 1)");
        }
        return;
    }
    case value_t::number_unsigned:
        if (value.get<std::uint64_t>() > static_cast<std::uint64_t>(kMaxInteger)) {
            throw CanonicalJsonError("canonical-json-v1: an integer outside +-(2^53 - 1)");
        }
        return;
    case value_t::binary:
    case value_t::discarded:
        throw CanonicalJsonError("canonical-json-v1: a value that isn't JSON");
    case value_t::null:
    case value_t::boolean:
    case value_t::string:
        return;
    }
}

} // namespace

std::string canonical_json(const nlohmann::json& value)
{
    check(value);
    try {
        // nlohmann::json keeps an object's keys in a std::map, so in byte order.
        return value.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
    } catch (const nlohmann::json::type_error&) {
        // 316, the only error dump has; its text quotes the bytes.
        throw CanonicalJsonError("canonical-json-v1: a string that isn't valid UTF-8");
    }
}

std::size_t json_nesting_depth(std::string_view bytes) noexcept
{
    std::size_t depth = 0;
    std::size_t deepest = 0;
    bool in_string = false;
    bool escaped = false;
    for (const char c : bytes) {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else if (c == '"') {
            in_string = true;
        } else if (c == '[' || c == '{') {
            ++depth;
            deepest = std::max(deepest, depth);
        } else if ((c == ']' || c == '}') && depth > 0) {
            --depth;
        }
    }
    return deepest;
}

std::string canonical_sha256(const nlohmann::json& value)
{
    return sha256_hex(canonical_json(value));
}

} // namespace rp
