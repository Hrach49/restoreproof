#pragma once

// Base64 for the Graph sign-in (W2.1): the PFX arrives in an environment
// variable as standard Base64, and a JWT's parts are base64url (RFC 7515).
// And for the restore credential (W2.5): an exported PFX goes out in Base64.

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// The bytes `text` encodes in standard Base64 (RFC 4648 section 4), or nullopt
// unless it is exactly that: only A-Z, a-z, 0-9, '+' and '/', padded with '='
// to a multiple of four characters, '=' only at the end, and the unused bits
// of the last character zero (section 3.5). Whitespace anywhere, line breaks
// included, is refused rather than skipped, as are base64url's '-' and '_':
// a value that isn't one clean encoding is reported, not half-read. "" is the
// empty encoding. Nothing is allocated before the whole text is checked, and
// the result is allocated once at its final size, so a secret's bytes aren't
// left behind in a freed buffer.
std::optional<std::vector<unsigned char>> base64_decode(std::string_view text);

// `bytes` in standard Base64 (RFC 4648 section 4), padded with '=', on one
// line: how a restore body carries a PFX (W2.5), the form base64_decode reads.
// The result is allocated once at its final size.
std::string base64_encode(std::span<const unsigned char> bytes);

// `bytes` in base64url (RFC 4648 section 5) without padding, as a JWT's
// header, claims and signature are written.
std::string base64url_encode(std::span<const unsigned char> bytes);
std::string base64url_encode(std::string_view bytes);

} // namespace rp
