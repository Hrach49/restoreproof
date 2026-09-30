#include "veeam_browse.hpp"

#include "veeam_restore.hpp"

#include <string>

namespace rp::veeam_browse {

namespace {

using nlohmann::json;
namespace vr = veeam_restore;

// The value at `key`; nullptr when it is missing or null.
const json* value_at(const json& object, std::string_view key)
{
    if (!object.is_object()) {
        throw vr::ShapeError("an entry that isn't an object");
    }
    const auto it = object.find(key);
    return it == object.end() || it->is_null() ? nullptr : &*it;
}

} // namespace

std::string shown_text(std::string_view text)
{
    return "\"" + one_line(text, 120) + "\"";
}

const std::string* text_at(const json& object, std::string_view key)
{
    const json* value = value_at(object, key);
    if (value == nullptr) {
        return nullptr;
    }
    if (!value->is_string()) {
        throw vr::ShapeError("\"" + std::string{key} + "\" isn't a string");
    }
    return value->get_ptr<const std::string*>();
}

bool bool_at(const json& object, std::string_view key)
{
    const json* value = value_at(object, key);
    if (value == nullptr) {
        return false;
    }
    if (!value->is_boolean()) {
        throw vr::ShapeError("\"" + std::string{key} + "\" isn't a boolean");
    }
    return value->get<bool>();
}

const std::string& id_of(const json& entry)
{
    return entry.at("id").get_ref<const std::string&>();
}

bool is_file_named(const json& entry, const std::string& name)
{
    const std::string* entry_name = text_at(entry, "name");
    const auto folder = entry.find("isFolder");
    if (folder != entry.end() && !folder->is_null() && !folder->is_boolean()) {
        throw vr::ShapeError("\"isFolder\" isn't a boolean");
    }
    return entry_name != nullptr && *entry_name == name && folder != entry.end() &&
           folder->is_boolean() && !folder->get<bool>();
}

} // namespace rp::veeam_browse
