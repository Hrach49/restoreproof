#include <rp/redact.hpp>

#include <array>
#include <cstddef>
#include <optional>

namespace rp {

namespace {

// A hand-written scan rather than std::regex: std::regex is slow, and MSVC's
// recursive matcher overflows the stack on long input. Every byte is looked at
// a bounded number of times, so the whole pass is linear in the text's length.

constexpr std::string_view kAuthorization = "authorization";
constexpr std::string_view kProxyAuthorization = "proxy-authorization";

// Header names whose whole value is a secret ("Name: value").
constexpr std::array<std::string_view, 2> kSecretHeaders{kAuthorization, kProxyAuthorization};

// Keys whose value is a secret in key=value text and in JSON.
constexpr std::array<std::string_view, 4> kSecretKeys{"client_secret", "password", "refresh_token",
                                                      "access_token"};

// JSON keys also include authorization: a logged header map is an object.
constexpr std::array<std::string_view, 5> kSecretJsonKeys{
    "client_secret", "password", "refresh_token", "access_token", kAuthorization};

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

// The closing quote of a JSON string whose content starts at `pos` (just
// after the opening quote), honouring backslash escapes; npos when the string
// is unterminated.
std::size_t find_closing_quote(std::string_view text, std::size_t pos) noexcept
{
    while (pos < text.size()) {
        if (text[pos] == '"') {
            return pos;
        }
        // A backslash escapes the byte after it, even a quote.
        pos += text[pos] == '\\' ? 2 : 1;
    }
    return std::string_view::npos;
}

// The position after that string's closing quote; text.size() when
// unterminated.
std::size_t end_of_json_string(std::string_view text, std::size_t pos) noexcept
{
    const std::size_t quote = find_closing_quote(text, pos);
    return quote == std::string_view::npos ? text.size() : quote + 1;
}

// The end of the JSON value starting at `pos`, a non-space byte: a string, an
// object or array (balanced brackets, strings skipped), or anything else up to
// the next ',', '}', ']' or whitespace. text.size() when unterminated, so a
// truncated value is redacted to the end.
std::size_t end_of_json_value(std::string_view text, std::size_t pos) noexcept
{
    if (text[pos] == '"') {
        return end_of_json_string(text, pos + 1);
    }
    if (text[pos] == '{' || text[pos] == '[') {
        std::size_t depth = 0;
        while (pos < text.size()) {
            const char c = text[pos];
            if (c == '"') {
                pos = end_of_json_string(text, pos + 1);
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

// Where a key=value value ends: '&' and '#' end a query parameter; whitespace,
// '"' and ',' end it inside a log line or a JSON string.
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

constexpr std::string_view kRedactedJsonString = "\"[REDACTED]\"";
constexpr std::string_view kRedactedEscapedJsonString = "\\\"[REDACTED]\\\"";

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
    std::size_t to = from;
    while (to < text.size() && text[to] != '\r' && text[to] != '\n') {
        ++to;
    }
    if (to == from) {
        return std::nullopt;
    }
    return Replacement{from, to, kRedacted};
}

// "name=value": blanks are allowed around '=', for hand-written log lines.
std::optional<Replacement> match_key_value(std::string_view text, std::size_t name_end)
{
    const std::size_t equals = skip_blanks(text, name_end);
    if (equals == text.size() || text[equals] != '=') {
        return std::nullopt;
    }
    const std::size_t from = skip_blanks(text, equals + 1);
    std::size_t to = from;
    while (to < text.size() && !ends_form_value(text[to])) {
        ++to;
    }
    if (to == from) {
        return std::nullopt;
    }
    return Replacement{from, to, kRedacted};
}

// "name": value, the key's closing quote at `name_end`. Also \"name\": value
// (or \\\"name\\\", and so on), a JSON body logged inside a JSON string: finding
// the end of the inner value there means counting backslashes by nesting
// level, so instead everything up to the end of the enclosing string (its
// next unescaped quote) goes.
std::optional<Replacement> match_json_key(std::string_view text, std::size_t name_end)
{
    std::size_t quote = name_end;
    while (quote < text.size() && text[quote] == '\\') {
        ++quote;
    }
    if (quote == text.size() || text[quote] != '"') {
        return std::nullopt;
    }
    const bool escaped = quote > name_end;
    const std::size_t colon = skip_json_space(text, quote + 1);
    if (colon == text.size() || text[colon] != ':') {
        return std::nullopt;
    }
    const std::size_t from = skip_json_space(text, colon + 1);
    if (from == text.size()) {
        return std::nullopt;
    }
    if (escaped) {
        // The enclosing string ends at the first quote a backslash doesn't
        // escape, which is where a string scan from here stops.
        const std::size_t quote = find_closing_quote(text, from);
        return Replacement{from, quote == std::string_view::npos ? text.size() : quote,
                           kRedactedEscapedJsonString};
    }
    const std::size_t to = end_of_json_value(text, from);
    if (to == from) {
        return std::nullopt;
    }
    return Replacement{from, to, kRedactedJsonString};
}

// The secret at `pos`, if one starts there: a secret name not run into a
// preceding letter or digit, then a header colon, '=' or a JSON key's quote.
// A name after '_', '-', '.' or any other non-alphanumeric byte still counts,
// so "new_password" is as secret as "password".
std::optional<Replacement> match_at(std::string_view text, std::size_t pos)
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
    for (const std::string_view name : kSecretKeys) {
        if (starts_with_name(text, pos, name)) {
            if (auto r = match_key_value(text, pos + name.size())) {
                return r;
            }
        }
    }
    for (const std::string_view name : kSecretJsonKeys) {
        if (starts_with_name(text, pos, name)) {
            if (auto r = match_json_key(text, pos + name.size())) {
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
