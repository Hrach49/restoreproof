#pragma once

// The result's canonical form "canonical-json-v1" (W4.1, docs/decisions.md
// 2026-10-04, point 4): the bytes the `--json` file holds and W4.3 hashes and
// signs. The vectors the Worker and the Cloud must agree on are
// shared/testdata/canonical-json-v1.json. Pure.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp {

inline constexpr std::string_view kCanonicalJsonV1 = "canonical-json-v1";

// A document the canonical form refuses. The message names the rule broken in
// fixed words, never the value, the key or where it was found.
class CanonicalJsonError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// `value` as canonical-json-v1: object keys sorted by byte, `,` and `:` only,
// no whitespace and no trailing newline, strings as raw UTF-8 with JSON's short
// escapes (\" \\ \b \f \n \r \t) and lower-case \u00xx for the other control
// characters; nothing else escaped (not `/`, DEL, U+2028 or U+2029).
//
// Throws CanonicalJsonError for what Python's json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=False) or RFC 8785 would write
// differently, anywhere in `value`:
//   - a floating-point number (1.0 too; NaN and the infinities),
//   - an integer outside +-(2^53 - 1), signed or unsigned,
//   - an object key with a non-ASCII byte,
//   - a binary or discarded value,
//   - a string that isn't valid UTF-8 (strict: never replaced by U+FFFD).
std::string canonical_json(const nlohmann::json& value);

// More arrays and objects than this open at once, and a text whose word the
// Worker would act on isn't parsed at all: a result (rp/signer.hpp), the
// service's record and its jobs document, none of which needs a fifth of it.
// verify_bundle.py has the same limit.
inline constexpr std::size_t kMaxJsonNesting = 32;

// The most arrays and objects open at once in `bytes`, counted on the bytes
// and outside strings, without parsing: what keeps a file of a hundred
// thousand '[' from the parser and from canonical_json, which calls itself
// once per level. Counts as verify_bundle.py's nesting_depth.
std::size_t json_nesting_depth(std::string_view bytes) noexcept;

// sha256_hex(canonical_json(value)): lower-case hex, 64 characters.
std::string canonical_sha256(const nlohmann::json& value);

} // namespace rp
