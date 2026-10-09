#pragma once

// Strict JSON for a document the Worker reads and judges (W4.8's jobs
// document, W4.10's profile file): nested no deeper than rp::kMaxJsonNesting
// (never handed to the parser past it), JSON as the parser reads it, and no
// object with a key twice, of which nlohmann would silently keep the last.
// Nothing of the text reaches a message: the parser's own error quotes the
// text around the fault, and it is never passed on.

#include <rp/canonical_json.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

inline std::optional<nlohmann::json> parse_strict_json(std::string_view text)
{
    using nlohmann::json;
    if (json_nesting_depth(text) > kMaxJsonNesting) {
        return std::nullopt;
    }
    // The keys of each object being read, innermost last.
    std::vector<std::set<std::string>> open;
    bool twice = false;
    const auto watch = [&](int, json::parse_event_t event, json& parsed) {
        if (event == json::parse_event_t::object_start) {
            open.emplace_back();
        } else if (event == json::parse_event_t::key) {
            twice |= !open.back().insert(parsed.get_ref<const std::string&>()).second;
        } else if (event == json::parse_event_t::object_end) {
            open.pop_back();
        }
        return true;
    };
    std::optional<json> document;
    try {
        document = json::parse(text.begin(), text.end(), watch);
    } catch (const json::exception&) {
        document.reset();
    }
    if (twice) {
        document.reset();
    }
    return document;
}

} // namespace rp
