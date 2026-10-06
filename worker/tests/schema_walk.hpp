#pragma once

// The keyword walk over a shared schema (W4.1, docs/decisions.md 2026-10-04,
// point 3): result.v1.json and signature.v1.json (W4.3) keep to the keywords
// JSON Schema draft 7 (the C++ validator) and 2020-12 (Python's) read alike.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rp::test {

// Point 3's list: what draft 7 (the C++ validator) and 2020-12 (Python's)
// read alike.
inline const std::set<std::string> kSchemaKeywords = {
    "$schema", "$id",       "title",     "description", "type",       "enum",
    "const",   "properties", "required", "additionalProperties",      "items",
    "minItems", "maxItems", "minLength", "maxLength",   "pattern",    "minimum",
    "maximum", "allOf",     "anyOf",     "oneOf",       "not",        "if",
    "then",    "else",      "$defs",     "$ref"};

// Every problem of the schema at `where`: a keyword outside the list, a $ref
// with a sibling, `items` that isn't one schema, an object type left open, a
// pattern with a backslash class. Descends through schema positions only, so
// a property of the result named `format`, `items`, `type` or `status` is
// never read as a keyword.
inline void walk(const nlohmann::json& node, const std::string& where,
                 std::vector<std::string>& problems)
{
    if (!node.is_object()) {
        problems.push_back(where + ": not an object schema");
        return;
    }
    if (node.contains("$ref") && node.size() != 1) {
        problems.push_back(where + ": a $ref with a sibling");
    }
    if (node.contains("type") && node.at("type") == "object" &&
        (!node.contains("additionalProperties") || node.at("additionalProperties") != false)) {
        problems.push_back(where + ": an object left open");
    }
    for (const auto& [key, value] : node.items()) {
        const std::string here = where + "/" + key;
        if (!kSchemaKeywords.contains(key)) {
            problems.push_back(here + ": not an allowed keyword");
            continue;
        }
        if (key == "properties" || key == "$defs") {
            if (!value.is_object()) {
                problems.push_back(here + ": not an object");
                continue;
            }
            for (const auto& [name, member] : value.items()) {
                walk(member, here + "/" + name, problems);
            }
        } else if (key == "items" || key == "not" || key == "if" || key == "then" ||
                   key == "else") {
            walk(value, here, problems);
        } else if (key == "allOf" || key == "anyOf" || key == "oneOf") {
            if (!value.is_array() || value.empty()) {
                problems.push_back(here + ": not a list of schemas");
                continue;
            }
            for (std::size_t i = 0; i < value.size(); ++i) {
                walk(value[i], here + "/" + std::to_string(i), problems);
            }
        } else if (key == "additionalProperties") {
            if (value.is_object()) {
                walk(value, here, problems);
            } else if (!value.is_boolean()) {
                problems.push_back(here + ": neither a schema nor a boolean");
            }
        } else if (key == "pattern") {
            if (!value.is_string()) {
                problems.push_back(here + ": not a string");
                continue;
            }
            const std::string& pattern = value.get_ref<const std::string&>();
            for (std::size_t i = 0; i + 1 < pattern.size(); ++i) {
                if (pattern[i] == '\\') {
                    if (std::string_view{"dDwWsSbB"}.find(pattern[i + 1]) !=
                        std::string_view::npos) {
                        problems.push_back(here + ": a backslash class");
                    }
                    ++i; // an escaped backslash escapes nothing after it
                }
            }
        }
    }
}

inline std::vector<std::string> problems_of(const nlohmann::json& root)
{
    std::vector<std::string> problems;
    walk(root, "", problems);
    return problems;
}

} // namespace rp::test
