#pragma once

// The mail body rule "text-v1" (lab/README.md, "Mail body hash";
// lab/seeder/normalize.py). The vectors both implementations must agree on are
// shared/testdata/body-normalization-text-v1.json. W2.2 hashes the bodies it
// reads with it, and W3.2's checker reuses it.

#include <string>
#include <string_view>

namespace rp {

inline constexpr std::string_view kTextV1 = "text-v1";

// `utf8` normalised: one leading U+FEFF (EF BB BF) dropped; CRLF, then lone CR,
// to LF; trailing U+0020 and U+0009 removed from every line; trailing LFs
// removed. Nothing else: no leading trim, no Unicode normalisation, no NBSP
// handling. Works byte-wise, which is exact for UTF-8 because the bytes it
// touches are ASCII and never occur inside a multibyte sequence. Does not
// validate the UTF-8.
std::string normalize_text_v1(std::string_view utf8);

// sha256_hex(normalize_text_v1(utf8)): what the manifest's body_sha256 holds.
std::string text_v1_sha256(std::string_view utf8);

} // namespace rp
