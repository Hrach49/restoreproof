#pragma once

// Reading a field of a JSON reply without trusting its shape: shared by the
// Graph code that reads the restore targets (graph_targets.cpp,
// target_guard_graph.cpp).

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>

namespace rp {

// The string at `key` of the object `object`, if both are what they should be.
inline const std::string* string_at(const nlohmann::json& object, std::string_view key)
{
    if (!object.is_object()) {
        return nullptr;
    }
    const auto it = object.find(key);
    return it != object.end() && it->is_string() ? it->get_ptr<const std::string*>() : nullptr;
}

} // namespace rp
