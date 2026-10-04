#pragma once

// validate_result's own rule for the pointer it hands out (rp/result_schema.hpp),
// here so its test can reach it.

#include <string>
#include <string_view>

namespace rp::detail {

// `pointer`, a JSON pointer's text, when each of its parts is a property name
// of the embedded result schema or an array index (digits only); "" otherwise,
// and for text that isn't a pointer. So a key of a document that the schema
// doesn't name is never repeated, whatever it looks like.
std::string known_result_pointer(std::string_view pointer);

} // namespace rp::detail
