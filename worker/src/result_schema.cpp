#include <rp/result_schema.hpp>

#include "result_schema_detail.hpp"

#include <nlohmann/json-schema.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>

namespace rp {

namespace detail {

// Generated at build time from shared/schemas/result.v1.json
// (cmake/embed_bytes.cmake): the file's bytes, never a string literal.
extern const unsigned char kResultSchemaBytes[];
extern const std::size_t kResultSchemaSize;

} // namespace detail

namespace {

using nlohmann::json;

using Names = std::set<std::string, std::less<>>;

// The names under every `properties` of the schema, wherever it sits.
void collect_property_names(const json& node, Names& names)
{
    if (node.is_object()) {
        for (const auto& [key, value] : node.items()) {
            if (key == "properties" && value.is_object()) {
                for (const auto& [name, unused] : value.items()) {
                    names.insert(name);
                }
            }
            collect_property_names(value, names);
        }
    } else if (node.is_array()) {
        for (const json& member : node) {
            collect_property_names(member, names);
        }
    }
}

// The embedded schema, loaded. The validator can fail to load: the schema not
// JSON, or refused by the validator (a pattern its regex engine can't compile
// throws std::regex_error there), or no memory.
struct Loaded {
    nlohmann::json_schema::json_validator validator;
    Names names;
};

std::shared_ptr<const Loaded> load() noexcept
{
    try {
        json schema = json::parse(result_schema_text());
        auto loaded = std::make_shared<Loaded>();
        collect_property_names(schema, loaded->names);
        loaded->validator.set_root_schema(std::move(schema));
        return loaded;
    } catch (...) {
        return nullptr;
    }
}

// The loaded schema, kept once it has loaded; null when it couldn't be. A
// failure isn't kept: the next call tries again, so a process that was once
// short of memory isn't without a validator for the rest of its life.
std::shared_ptr<const Loaded> loaded() noexcept
{
    static std::mutex mutex;
    static std::shared_ptr<const Loaded> kept;
    try {
        const std::scoped_lock lock(mutex);
        if (!kept) {
            kept = load();
        }
        return kept;
    } catch (...) {
        return nullptr;
    }
}

// Whether `deeper` is a pointer below `pointer`.
bool is_below(std::string_view deeper, std::string_view pointer)
{
    return deeper.size() > pointer.size() && deeper.starts_with(pointer) &&
           deeper[pointer.size()] == '/';
}

// Counts the violations and keeps the first one's place. The validator's
// message quotes the instance, and `instance` is it: neither is kept. Of the
// message only its own prefix is read: when a oneOf or anyOf fails, the
// validator reports that once and then why each branch failed, each such line
// starting "[combination: ". Those lines are no violations of their own, but
// they say where below a nullable section the first violation is.
class Violations : public nlohmann::json_schema::error_handler {
public:
    void error(const json::json_pointer& pointer, const json& /*instance*/,
               const std::string& message) override
    {
        const bool branch = count_ > 0 && message.starts_with("[combination: ");
        if (!branch) {
            if (++count_ == 1) {
                first_ = pointer.to_string();
            }
            return;
        }
        if (count_ == 1) {
            std::string place = pointer.to_string();
            if (is_below(place, first_)) {
                first_ = std::move(place);
            }
        }
    }

    std::size_t count() const noexcept { return count_; }
    const std::string& first() const noexcept { return first_; }

private:
    std::size_t count_ = 0;
    std::string first_;
};

bool is_index(std::string_view part)
{
    return !part.empty() &&
           std::ranges::all_of(part, [](char c) { return c >= '0' && c <= '9'; });
}

// The pointer of the first unsigned integer in `node` that a signed 64-bit
// value can't hold, or nullopt. The validator library (2.4.0) reads an
// unsigned instance into one before it compares it with `minimum` and
// `maximum`, so 2^64 - 1 would be -1 there and pass $defs/integer. Every
// integer of the schema ends at 2^53 - 1 and every object is closed, so such
// a number is valid nowhere in a result.
std::optional<std::string> oversized_integer(const json& node, const std::string& pointer)
{
    if (node.is_number_unsigned()) {
        if (node.get<std::uint64_t>() >
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return pointer;
        }
    } else if (node.is_object()) {
        for (const auto& [key, value] : node.items()) {
            // A key with "~" or "/" would need escaping; known_result_pointer
            // drops a pointer holding a key the schema doesn't know anyway.
            if (auto found = oversized_integer(value, pointer + "/" + key)) {
                return found;
            }
        }
    } else if (node.is_array()) {
        for (std::size_t i = 0; i < node.size(); ++i) {
            if (auto found = oversized_integer(node[i], pointer + "/" + std::to_string(i))) {
                return found;
            }
        }
    }
    return std::nullopt;
}

} // namespace

namespace detail {

std::string known_result_pointer(std::string_view pointer)
{
    // With no schema loaded no part is known: no pointer.
    const std::shared_ptr<const Loaded> schema = loaded();
    if (!schema) {
        return {};
    }
    const Names& names = schema->names;
    std::string_view rest = pointer;
    while (!rest.empty()) {
        if (rest.front() != '/') {
            return {};
        }
        rest.remove_prefix(1);
        const std::string_view part = rest.substr(0, rest.find('/'));
        rest.remove_prefix(part.size());
        // An escaped part ("~0", "~1") is no property name of the schema.
        if (!is_index(part) && !names.contains(part)) {
            return {};
        }
    }
    return std::string{pointer};
}

} // namespace detail

std::string_view result_schema_text()
{
    return {reinterpret_cast<const char*>(detail::kResultSchemaBytes), detail::kResultSchemaSize};
}

bool result_schema_ready() noexcept
{
    return loaded() != nullptr;
}

ResultValidation validate_result(const nlohmann::json& document) noexcept
{
    try {
        const std::shared_ptr<const Loaded> schema = loaded();
        if (!schema) {
            return {false, 1, {}};
        }
        if (const auto oversized = oversized_integer(document, {})) {
            return {false, 1, detail::known_result_pointer(*oversized)};
        }
        Violations violations;
        schema->validator.validate(document, violations);
        if (violations.count() == 0) {
            return {true, 0, {}};
        }
        return {false, violations.count(), detail::known_result_pointer(violations.first())};
    } catch (...) {
        // Whatever the validator threw: its text may quote the document.
        return {false, 1, {}};
    }
}

} // namespace rp
