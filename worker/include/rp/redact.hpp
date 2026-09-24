#pragma once

#include <string>
#include <string_view>

namespace rp {

// What a secret is replaced with in logged text.
inline constexpr std::string_view kRedacted = "[REDACTED]";

// Whether a header's value is a secret: Authorization or Proxy-Authorization,
// in any case.
bool is_secret_header(std::string_view name) noexcept;

// `text` with every secret value replaced by kRedacted. The HTTP client passes
// every string it logs through this (CLAUDE.md "Secrets"). Names match in any
// case:
//  - Authorization / Proxy-Authorization as a header ("Name: value"): the whole
//    value, any scheme, up to the end of the line;
//  - client_secret, password, refresh_token, access_token as key=value (URL
//    query strings, application/x-www-form-urlencoded bodies): the value;
//  - those four and authorization as JSON object keys, at any nesting: the
//    whole value.
// Over-redacting is preferred to leaking: a key or JSON key that ends in one
// of the names after a non-alphanumeric character ("new_password",
// "db.password") counts as the name; a JSON value of any type becomes the
// string "[REDACTED]"; an unterminated JSON value is redacted to the end of
// the text. The rules are in docs/decisions.md.
// Text with nothing to redact comes back unchanged.
std::string redact(std::string_view text);

} // namespace rp
