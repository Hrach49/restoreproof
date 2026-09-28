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
// case. The forms:
//  - header "Name: value", Name exactly Authorization or Proxy-Authorization:
//    the whole value, any scheme, up to "\r\n", "\n" or the end of the text
//    (a bare '\r' doesn't end it);
//  - key=value, key one of client_secret, password, refresh_token,
//    access_token, authorization, tempauth, sig, client_assertion, id_token,
//    pfx, pfx_base64 (URL query strings and fragments, form bodies, log
//    lines; blanks allowed around '='): the value up to '&', '#', '"', ',' or whitespace, but for
//    authorization up to the end of the line;
//  - "key: value" for client_secret, password, refresh_token, access_token
//    and pfx_base64 only: the value up to the end of the line;
//  - in both forms a value starting with a quote (' or ") goes up to its
//    matching quote, backslash escapes honoured, and keeps its quotes;
//  - JSON object keys, any of the eleven key=value names, at any nesting: the
//    whole value, of any type, becomes the string "[REDACTED]";
//  - URL userinfo, "scheme://user:password@host": everything between "://"
//    and the last '@' before the first '/', '?' or '#';
//  - a raw JWT anywhere: "eyJ" (case matters) not run into a preceding
//    base64url character, then base64url parts joined by '.', at least two
//    non-empty ones; the whole token, unsigned ("header.claims." or
//    "header.claims") and five-part forms included;
//  - "Bearer <token>", Bearer in any case and not run into a preceding letter
//    or digit, then blanks: the token up to whitespace, a quote or ','. A
//    known auth-param and '=' after the scheme (WWW-Authenticate's
//    `Bearer realm=""`, `error="..."`, scope, claims, client_id, ...) is not
//    a token and stays; any other name=value is.
// A JWT or bearer token ends before a secret key inside it whose value goes
// on past it ("Bearer password = x", "eyJ...def.password=x"): that value is
// the key rules' to replace.
// A key that ends in one of the names after a non-alphanumeric byte
// ("new_password", "db.password", "x_sig") counts as the name; a name run
// into a letter or digit ("xpassword", "signature") doesn't. A quoted value
// or JSON value left unterminated is redacted to the end of the text, and a
// value inside a JSON-escaped string (\"password\":\"...\") to the end of
// the enclosing string. An empty unquoted value is left as it is. Over-
// redacting is preferred to leaking (docs/decisions.md).
// Text with nothing to redact comes back unchanged.
std::string redact(std::string_view text);

} // namespace rp
