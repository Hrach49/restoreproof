#include <rp/redact.hpp>

#include <array>
#include <cstddef>
#include <optional>

namespace rp {

namespace {

// A hand-written scan rather than std::regex: std::regex is slow, and MSVC's
// recursive matcher overflows the stack on long input. Every byte is looked at
// a bounded number of times, so the whole pass is linear in the text's length.

// Header names whose whole value is a secret ("Name: value").
constexpr std::array<std::string_view, 2> kSecretHeaders{"authorization", "proxy-authorization"};

// A name whose value is a secret wherever it appears as key=value or as a
// JSON key.
struct SecretKey {
    std::string_view name;
    // key=value runs to the end of the line, not to '&' or a space: an
    // authorization value has a space after its scheme.
    bool value_to_line_end;
    // Also "name: value" (a hand-written log line or YAML-like text). Only
    // for names that aren't header names nor short enough to show up in
    // prose ("sig: ...").
    bool colon_form;
};

constexpr std::array<SecretKey, 18> kSecretKeys{{
    {"client_secret", false, true},
    {"password", false, true},
    {"refresh_token", false, true},
    {"access_token", false, true},
    {"authorization", true, false},
    // Tokens that travel in URLs: Graph's pre-authenticated downloadUrl, an
    // Azure SAS signature, OAuth's client assertion and ID token. Not "code":
    // Graph error JSON ({"code":"ErrorItemNotFound"}) must stay readable.
    {"tempauth", false, false},
    {"sig", false, false},
    {"client_assertion", false, false},
    {"id_token", false, false},
    // The Graph certificate (W2.1): its Base64 PFX, under any name ending in
    // pfx or pfx_base64 (RP_GRAPH_CERT_PFX_BASE64=...). "pfx: ..." is too
    // likely in prose to take the colon form.
    {"pfx", false, false},
    {"pfx_base64", false, true},
    // A Veeam restore body (W2.5): the organisation app's certificate as a
    // Base64 PFX, and its one-time password, which runs into its name without
    // a separator ("applicationCertificatePassword") so "password" misses it.
    // "applicationCertificateThumbprint" goes on past the name: not a match.
    {"applicationcertificate", false, true},
    {"applicationcertificatepassword", false, true},
    // The Worker's signing key (W4.3): the variable that carries it
    // (RP_SIGNING_KEY_BASE64=...) and the vault's name for it (W4.5).
    // "signing_key_id" goes on past the name: not a match.
    {"signing_key", false, true},
    {"signing_key_base64", false, true},
    {"signing_private_key", false, true},
    // The Cloud's tokens (W5.1): registration's install_token and the
    // api_token it answers, and the vault's names for them, which end in these
    // (cloud_install_token, cloud_api_token). No colon form: the Cloud's audit
    // rows name an install token's row as "install_token:<id>".
    {"api_token", false, false},
    {"install_token", false, false},
}};

// A PEM block's header and footer (RFC 7468): "-----BEGIN <label>-----" and
// "-----END <label>-----". A label that holds these words is a private key's,
// of any kind ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY",
// "ED25519 PRIVATE KEY", "PGP PRIVATE KEY BLOCK").
constexpr std::string_view kPemBegin = "-----BEGIN ";
constexpr std::string_view kPemEnd = "-----END ";
constexpr std::string_view kPemDashes = "-----";
constexpr std::string_view kPrivateKeyLabel = "PRIVATE KEY";
// No label is nearly this long, and a header is looked at no further.
constexpr std::size_t kMaxPemLabel = 64;

constexpr std::string_view kSchemeSeparator = "://";

// The HTTP authentication scheme whose token follows it after blanks
// (RFC 6750), in any case.
constexpr std::string_view kBearer = "bearer";

// The auth-params a Bearer challenge starts with (RFC 6750, RFC 9728, Entra's
// and Graph's WWW-Authenticate), in any case. Only these, followed by '=', are
// taken for a challenge rather than a token.
constexpr std::array<std::string_view, 13> kAuthParams{
    "realm",       "scope",           "error",       "error_description", "error_uri",
    "claims",      "client_id",       "resource",    "authorization_uri", "resource_id",
    "token_types", "trusted_issuers", "resource_metadata"};

// ASCII only: a byte of a multi-byte UTF-8 sequence is never a letter here,
// so non-ASCII text can't match a name or be changed by case folding.
constexpr char ascii_lower(char c) noexcept
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr bool is_alnum(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

constexpr bool is_blank(char c) noexcept
{
    return c == ' ' || c == '\t';
}

constexpr bool is_json_space(char c) noexcept
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// Whether `text` at `pos` starts with `name` (lower case), in any case.
bool starts_with_name(std::string_view text, std::size_t pos, std::string_view name) noexcept
{
    if (text.size() - pos < name.size()) {
        return false;
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        if (ascii_lower(text[pos + i]) != name[i]) {
            return false;
        }
    }
    return true;
}

// The first position at or after `pos` that isn't a space or tab.
std::size_t skip_blanks(std::string_view text, std::size_t pos) noexcept
{
    while (pos < text.size() && is_blank(text[pos])) {
        ++pos;
    }
    return pos;
}

std::size_t skip_json_space(std::string_view text, std::size_t pos) noexcept
{
    while (pos < text.size() && is_json_space(text[pos])) {
        ++pos;
    }
    return pos;
}

// Where the line holding `pos` ends: at "\r\n", "\n" or the end of the text.
// A bare '\r' can't end a header line on the wire, so it doesn't end one here.
std::size_t end_of_line(std::string_view text, std::size_t pos) noexcept
{
    while (pos < text.size() && text[pos] != '\n' &&
           !(text[pos] == '\r' && pos + 1 < text.size() && text[pos + 1] == '\n')) {
        ++pos;
    }
    return pos;
}

// The closing `quote` of a string whose content starts at `pos` (just after
// the opening quote), honouring backslash escapes; npos when unterminated.
std::size_t find_closing_quote(std::string_view text, std::size_t pos, char quote) noexcept
{
    while (pos < text.size()) {
        if (text[pos] == quote) {
            return pos;
        }
        // A backslash escapes the byte after it, even a quote.
        pos += text[pos] == '\\' ? 2 : 1;
    }
    return std::string_view::npos;
}

// The position after that string's closing quote; text.size() when
// unterminated.
std::size_t end_of_quoted(std::string_view text, std::size_t pos, char quote) noexcept
{
    const std::size_t close = find_closing_quote(text, pos, quote);
    return close == std::string_view::npos ? text.size() : close + 1;
}

// The end of the JSON value starting at `pos`, a non-space byte: a string, an
// object or array (balanced brackets, strings skipped), or anything else up to
// the next ',', '}', ']' or whitespace. text.size() when unterminated, so a
// truncated value is redacted to the end.
std::size_t end_of_json_value(std::string_view text, std::size_t pos) noexcept
{
    if (text[pos] == '"') {
        return end_of_quoted(text, pos + 1, '"');
    }
    if (text[pos] == '{' || text[pos] == '[') {
        std::size_t depth = 0;
        while (pos < text.size()) {
            const char c = text[pos];
            if (c == '"') {
                pos = end_of_quoted(text, pos + 1, '"');
                continue;
            }
            if (c == '{' || c == '[') {
                ++depth;
            } else if ((c == '}' || c == ']') && --depth == 0) {
                return pos + 1;
            }
            ++pos;
        }
        return text.size();
    }
    while (pos < text.size() && text[pos] != ',' && text[pos] != '}' && text[pos] != ']' &&
           !is_json_space(text[pos])) {
        ++pos;
    }
    return pos;
}

// Where an unquoted key=value value ends: '&' and '#' end a query parameter;
// whitespace, '"' and ',' end it inside a log line or a JSON string.
constexpr bool ends_form_value(char c) noexcept
{
    return c == '&' || c == '#' || c == '"' || c == ',' || c == ' ' || c == '\t' || c == '\r' ||
           c == '\n' || c == '\f' || c == '\v';
}

// One replacement: text[from, to) becomes `with`.
struct Replacement {
    std::size_t from;
    std::size_t to;
    std::string_view with;
};

constexpr std::string_view kRedactedDoubleQuoted = "\"[REDACTED]\"";
constexpr std::string_view kRedactedSingleQuoted = "'[REDACTED]'";
constexpr std::string_view kRedactedEscapedQuoted = "\\\"[REDACTED]\\\"";

// An escaped value inside a JSON string: finding its own end means counting
// backslashes by nesting level, so instead everything up to the end of the
// enclosing string (its first quote no backslash escapes) goes.
Replacement redact_to_enclosing_quote(std::string_view text, std::size_t from)
{
    const std::size_t quote = find_closing_quote(text, from, '"');
    return Replacement{from, quote == std::string_view::npos ? text.size() : quote,
                       kRedactedEscapedQuoted};
}

// A value starting at `from` with one or more backslashes and then a '"'. An
// odd run escapes the quote: a quoted value inside a JSON string, redacted to
// the end of the enclosing string. An even run is escaped backslashes before a
// real quote, which opens the value: redacted up to its matching quote.
std::optional<Replacement> match_backslashed_value(std::string_view text, std::size_t from)
{
    std::size_t quote = from;
    while (quote < text.size() && text[quote] == '\\') {
        ++quote;
    }
    if (quote == from || quote == text.size() || text[quote] != '"') {
        return std::nullopt;
    }
    if ((quote - from) % 2 == 1) {
        return redact_to_enclosing_quote(text, from);
    }
    return Replacement{from, end_of_quoted(text, quote + 1, '"'), kRedactedDoubleQuoted};
}

// The value of key=value or "name: value" starting at `from`: a quoted value
// up to its matching quote (the end of the text when unterminated), or an
// unquoted one up to the end of the line or the end of a form value. An empty
// unquoted value has nothing to hide and is left alone.
std::optional<Replacement> match_plain_value(std::string_view text, std::size_t from,
                                             bool to_line_end)
{
    if (from == text.size()) {
        return std::nullopt;
    }
    const char first = text[from];
    if (first == '"' || first == '\'') {
        return Replacement{from, end_of_quoted(text, from + 1, first),
                           first == '"' ? kRedactedDoubleQuoted : kRedactedSingleQuoted};
    }
    if (auto r = match_backslashed_value(text, from)) {
        return r;
    }
    std::size_t to = from;
    if (to_line_end) {
        to = end_of_line(text, from);
    } else {
        while (to < text.size() && !ends_form_value(text[to])) {
            ++to;
        }
    }
    if (to == from) {
        return std::nullopt;
    }
    return Replacement{from, to, kRedacted};
}

// "Name: value", a secret header's name ending at `name_end`. The value runs
// from the first non-blank after ':' to the end of the line: it can hold
// quotes and commas (Digest), so nothing shorter is safe. An empty value has
// nothing to hide and is left alone.
std::optional<Replacement> match_header(std::string_view text, std::size_t name_end)
{
    const std::size_t colon = skip_blanks(text, name_end);
    if (colon == text.size() || text[colon] != ':') {
        return std::nullopt;
    }
    const std::size_t from = skip_blanks(text, colon + 1);
    const std::size_t to = end_of_line(text, from);
    if (to == from) {
        return std::nullopt;
    }
    return Replacement{from, to, kRedacted};
}

// "name=value" (blanks allowed around '=', for hand-written log lines), or,
// for a key with colon_form, "name: value" up to the end of the line.
std::optional<Replacement> match_key_value(std::string_view text, std::size_t name_end,
                                           const SecretKey& key)
{
    const std::size_t sep = skip_blanks(text, name_end);
    if (sep == text.size()) {
        return std::nullopt;
    }
    if (text[sep] == '=') {
        return match_plain_value(text, skip_blanks(text, sep + 1), key.value_to_line_end);
    }
    if (text[sep] == ':' && key.colon_form) {
        return match_plain_value(text, skip_blanks(text, sep + 1), true);
    }
    return std::nullopt;
}

// "name": value, the key's closing quote at `name_end`. Also \"name\": value
// (or \\\"name\\\", and so on), a JSON body logged inside a JSON string, whose
// value goes up to the end of the enclosing string. Only an odd run of
// backslashes escapes the key's quote; an even one is escaped backslashes
// before a real closing quote.
std::optional<Replacement> match_json_key(std::string_view text, std::size_t name_end)
{
    std::size_t quote = name_end;
    while (quote < text.size() && text[quote] == '\\') {
        ++quote;
    }
    if (quote == text.size() || text[quote] != '"') {
        return std::nullopt;
    }
    const bool escaped = (quote - name_end) % 2 == 1;
    const std::size_t colon = skip_json_space(text, quote + 1);
    if (colon == text.size() || text[colon] != ':') {
        return std::nullopt;
    }
    const std::size_t from = skip_json_space(text, colon + 1);
    if (from == text.size()) {
        return std::nullopt;
    }
    if (auto r = match_backslashed_value(text, from)) {
        return r;
    }
    if (escaped && text[from] != '"') {
        return redact_to_enclosing_quote(text, from);
    }
    const std::size_t to = end_of_json_value(text, from);
    if (to == from) {
        return std::nullopt;
    }
    return Replacement{from, to, kRedactedDoubleQuoted};
}

// URL userinfo, with "://" at `pos`: "scheme://user:password@host". The
// authority ends at the first '/', '?' or '#' (or a byte that can't be in a
// URL); an '@' before that ends the userinfo. The last such '@' counts, so an
// unencoded '@' in a password doesn't leak what follows it.
std::optional<Replacement> match_userinfo(std::string_view text, std::size_t pos)
{
    const std::size_t from = pos + kSchemeSeparator.size();
    std::size_t at = std::string_view::npos;
    for (std::size_t p = from; p < text.size(); ++p) {
        const char c = text[p];
        if (c == '/' || c == '?' || c == '#' || c == '"' || c == '\'' || c == '<' || c == '>' ||
            is_json_space(c)) {
            break;
        }
        if (c == '@') {
            at = p;
        }
    }
    if (at == std::string_view::npos || at == from) {
        return std::nullopt;
    }
    return Replacement{from, at, kRedacted};
}

// A secret header or secret key at `pos`, the name not run into a preceding
// letter or digit: a header colon, '=', a key's colon or a JSON key's quote
// after it. A name after '_', '-', '.' or any other non-alphanumeric byte
// still counts, so "new_password" is as secret as "password".
std::optional<Replacement> match_key_at(std::string_view text, std::size_t pos)
{
    if (pos > 0 && is_alnum(text[pos - 1])) {
        return std::nullopt;
    }
    // Header names match exactly: "X-Authorization" is not Authorization.
    const bool header_start = pos == 0 || (text[pos - 1] != '_' && text[pos - 1] != '-');
    if (header_start) {
        for (const std::string_view name : kSecretHeaders) {
            if (starts_with_name(text, pos, name)) {
                if (auto r = match_header(text, pos + name.size())) {
                    return r;
                }
            }
        }
    }
    for (const SecretKey& key : kSecretKeys) {
        if (starts_with_name(text, pos, key.name)) {
            const std::size_t name_end = pos + key.name.size();
            if (auto r = match_key_value(text, name_end, key)) {
                return r;
            }
            if (auto r = match_json_key(text, name_end)) {
                return r;
            }
        }
    }
    return std::nullopt;
}

// Where the first secret header or key in text[from, to) starts whose value
// goes on past `to`: a token rule ending at `to` would leave that value in the
// clear, so it stops before the key and leaves it to the key rules.
std::optional<std::size_t> key_reaching_past(std::string_view text, std::size_t from,
                                             std::size_t to)
{
    for (std::size_t p = from; p < to; ++p) {
        if (const auto r = match_key_at(text, p); r && r->to > to) {
            return p;
        }
    }
    return std::nullopt;
}

// A raw JWT starting at `pos`: "eyJ" not run into a preceding base64url
// character, base64url characters, '.', at least one more, then any number of
// further '.'-separated parts, empty ones included. That covers a signed JWT
// (three parts), an unsigned one ("header.claims." or "header.claims") and an
// encrypted one (five parts). It ends before a part holding a secret key
// whose value goes on past it ("eyJ...def.password=x"), and is no JWT if that
// leaves fewer than two parts.
std::optional<Replacement> match_jwt(std::string_view text, std::size_t pos)
{
    if (text.substr(pos, kJwtStart.size()) != kJwtStart ||
        (pos > 0 && is_base64url(text[pos - 1]))) {
        return std::nullopt;
    }
    const auto skip_part = [text](std::size_t p) {
        while (p < text.size() && is_base64url(text[p])) {
            ++p;
        }
        return p;
    };
    const std::size_t dot = skip_part(pos + kJwtStart.size());
    if (dot == text.size() || text[dot] != '.') {
        return std::nullopt;
    }
    std::size_t to = skip_part(dot + 1);
    if (to == dot + 1) {
        return std::nullopt;
    }
    while (to < text.size() && text[to] == '.') {
        to = skip_part(to + 1);
    }
    if (const auto key = key_reaching_past(text, pos, to)) {
        // The '.' before the part the key starts in.
        const std::size_t cut = text.substr(0, *key).find_last_of('.');
        if (cut == std::string_view::npos || cut <= dot) {
            return std::nullopt;
        }
        to = cut;
    }
    return Replacement{pos, to, kRedacted};
}

bool is_auth_param(std::string_view name) noexcept
{
    for (const std::string_view param : kAuthParams) {
        if (name.size() == param.size() && starts_with_name(name, 0, param)) {
            return true;
        }
    }
    return false;
}

// "Bearer <token>", the scheme name ending at `name_end`: one or more blanks,
// then the token up to whitespace, a quote or ','. A known auth-param name
// followed by '=' (WWW-Authenticate's `Bearer realm="", error="invalid_token"`)
// is a challenge, not a token, and is left alone. Anything else after the
// blanks goes, even characters a token can't hold: over-redacting is preferred
// to leaking. But a secret key in it whose value goes on past it ("Bearer
// password = x", "Bearer refresh_token: x") is left to the key rules: only
// what comes before the key goes here.
std::optional<Replacement> match_bearer(std::string_view text, std::size_t name_end)
{
    if (name_end == text.size() || !is_blank(text[name_end])) {
        return std::nullopt;
    }
    const std::size_t from = skip_blanks(text, name_end);
    std::size_t name_to = from;
    while (name_to < text.size() &&
           (is_alnum(text[name_to]) || text[name_to] == '_' || text[name_to] == '-')) {
        ++name_to;
    }
    if (name_to < text.size() && text[name_to] == '=' &&
        is_auth_param(text.substr(from, name_to - from))) {
        return std::nullopt;
    }
    std::size_t to = from;
    while (to < text.size() && !is_json_space(text[to]) && text[to] != '"' && text[to] != '\'' &&
           text[to] != ',') {
        ++to;
    }
    if (const auto key = key_reaching_past(text, from, to)) {
        to = *key;
    }
    if (to == from) {
        return std::nullopt;
    }
    return Replacement{from, to, kRedacted};
}

// A PEM private key block starting at `pos`: "-----BEGIN <label>-----", the
// label upper-case letters, digits and blanks holding "PRIVATE KEY" ("ED25519
// PRIVATE KEY", "PGP PRIVATE KEY BLOCK"), up to and with "-----END
// <label>-----" of the same label, whatever is between (line ends as they are
// or escaped inside a JSON string). Without that footer the block goes to the
// end of the text: over-redacting is preferred to leaking.
std::optional<Replacement> match_private_key(std::string_view text, std::size_t pos)
{
    if (text.substr(pos, kPemBegin.size()) != kPemBegin) {
        return std::nullopt;
    }
    const std::size_t label_from = pos + kPemBegin.size();
    std::size_t label_to = label_from;
    while (label_to < text.size() && label_to - label_from < kMaxPemLabel &&
           ((text[label_to] >= 'A' && text[label_to] <= 'Z') ||
            (text[label_to] >= '0' && text[label_to] <= '9') || text[label_to] == ' ')) {
        ++label_to;
    }
    const std::string_view label = text.substr(label_from, label_to - label_from);
    if (label.find(kPrivateKeyLabel) == std::string_view::npos ||
        text.substr(label_to, kPemDashes.size()) != kPemDashes) {
        return std::nullopt;
    }
    std::string footer{kPemEnd};
    footer += label;
    footer += kPemDashes;
    const std::size_t end = text.find(footer, label_to + kPemDashes.size());
    return Replacement{pos, end == std::string_view::npos ? text.size() : end + footer.size(),
                       kRedacted};
}

// Whether a line ends at `pos`, as end_of_line reads one. Asked of the bytes
// at `pos` alone: reading on to the line's end for every value would make a
// long line of secrets quadratic.
bool at_line_end(std::string_view text, std::size_t pos) noexcept
{
    return pos == text.size() || text[pos] == '\n' ||
           (text[pos] == '\r' && pos + 1 < text.size() && text[pos + 1] == '\n');
}

std::optional<Replacement> match_at(std::string_view text, std::size_t pos, bool line_tails);

// `r`, a bearer token's or a secret value's replacement, going on to the end
// of a PEM private key block that starts inside it. Such a value ends at a
// blank or at the line's end, which is inside "-----BEGIN PRIVATE KEY-----" or
// right after it; the scan would go on behind the header, and the key's own
// lines would stay as they are.
//
// With `line_tail`, a value that ran to its line's end (a header's, a "name:
// value" one) runs to the end of the block's last line too: what stands after
// "-----END ...-----" there would be the value's on a second pass, and
// redacting twice must be redacting once (W4.7: the service's log redacts
// every line again in its sink). That rest of the line is read before it
// goes, as the scan would have read it: a secret that starts in it and ends
// behind the line's end (a second block, a quoted value over two lines) goes
// whole, and the replacement with it to the end of that secret's last line,
// where the same holds again. Those secrets are matched without their own
// line tails, which this loop reads itself: one level of calls however many
// blocks follow one another, and every byte of the tails read once.
Replacement through_private_key(std::string_view text, Replacement r, bool line_tail)
{
    const bool to_line_end = line_tail && at_line_end(text, r.to);
    bool block_found = false;
    for (std::size_t p = r.from; p < r.to; ++p) {
        if (const auto block = match_private_key(text, p); block && block->to > r.to) {
            r.to = block->to;
            block_found = true;
            break;
        }
    }
    if (!block_found || !to_line_end) {
        return r;
    }
    std::size_t end = end_of_line(text, r.to);
    for (std::size_t p = r.to; p < end;) {
        if (const auto secret = match_at(text, p, false)) {
            p = secret->to;
            if (p > end) {
                end = end_of_line(text, p);
            }
        } else {
            ++p;
        }
    }
    r.to = end;
    return r;
}

// The secret at `pos`, if one starts there: URL userinfo after "://", a PEM
// private key block, a raw JWT, a bearer token, or a secret header or key
// (match_key_at), the last two with the private key block that starts in them
// and, with `line_tails`, the rest of that block's last line
// (through_private_key).
std::optional<Replacement> match_at(std::string_view text, std::size_t pos, bool line_tails)
{
    if (starts_with_name(text, pos, kSchemeSeparator)) {
        return match_userinfo(text, pos);
    }
    if (auto r = match_private_key(text, pos)) {
        return r;
    }
    if (auto r = match_jwt(text, pos)) {
        return r;
    }
    if (pos > 0 && is_alnum(text[pos - 1])) {
        return std::nullopt;
    }
    if (starts_with_name(text, pos, kBearer)) {
        if (auto r = match_bearer(text, pos + kBearer.size())) {
            return through_private_key(text, *r, line_tails);
        }
    }
    if (auto r = match_key_at(text, pos)) {
        return through_private_key(text, *r, line_tails);
    }
    return std::nullopt;
}

} // namespace

bool is_secret_header(std::string_view name) noexcept
{
    for (const std::string_view secret : kSecretHeaders) {
        if (name.size() == secret.size() && starts_with_name(name, 0, secret)) {
            return true;
        }
    }
    return false;
}

std::string redact(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    std::size_t copied = 0; // text[0, copied) is in `out`
    std::size_t pos = 0;
    while (pos < text.size()) {
        if (auto r = match_at(text, pos, true)) {
            out.append(text.substr(copied, r->from - copied));
            out.append(r->with);
            copied = r->to;
            pos = r->to;
        } else {
            ++pos;
        }
    }
    out.append(text.substr(copied));
    return out;
}

} // namespace rp
