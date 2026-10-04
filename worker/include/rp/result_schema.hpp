#pragma once

// The result's schema, shared/schemas/result.v1.json, as the build embedded
// it (W4.1, docs/decisions.md 2026-10-04, points 2, 3 and 5): the Worker never
// reads a schema from disk, so an installed Worker can't validate against an
// edited one.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace rp {

// The schema file's bytes, exactly as they were at build time.
std::string_view result_schema_text();

// What validating a document found. Counts and a place only: never the
// validator's message and never a value of the document.
struct ResultValidation {
    bool valid = false;
    // 0 when valid; else as the validator counts them: one per keyword that
    // refused, and one for a nullable section or a time whose alternatives
    // all refused.
    std::size_t violations = 0;
    // The JSON pointer of the first violation ("" is the document itself),
    // as deep as the validator names it, and kept only when each of its
    // parts is one of the schema's property names or an array index; empty
    // otherwise, so no key of the document that the schema doesn't know is
    // ever repeated.
    std::string first_pointer;
};

// Whether `document` is a restoreproof.result.v1 by the embedded schema. The
// validator is built once, on the first call; thread-safe. Never throws: a
// schema that can't be loaded, or anything the validator throws, is one
// violation with no pointer.
ResultValidation validate_result(const nlohmann::json& document) noexcept;

} // namespace rp
