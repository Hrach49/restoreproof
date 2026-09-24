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

constexpr std::array<SecretKey, 9> kSecretKeys{{
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
}};

constexpr std::string_view kSchemeSeparator = "://";

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

// The secret at `pos`, if one starts there: URL userinfo after "://", or a
// secret name not run into a preceding letter or digit, then a header colon,
// '=', a key's colon or a JSON key's quote. A name after '_', '-', '.' or any
// other non-alphanumeric byte still counts, so "new_password" is as secret as
// "password".
std::optional<Replacement> match_at(std::string_view text, std::size_t pos)
{
    if (starts_with_name(text, pos, kSchemeSeparator)) {
        return match_userinfo(text, pos);
    }
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
        if (auto r = match_at(text, pos)) {
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
