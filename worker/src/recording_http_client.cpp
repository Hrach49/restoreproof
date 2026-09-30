#include <rp/recording_http_client.hpp>

#include <rp/cert_export.hpp>
#include <rp/config.hpp>
#include <rp/redact.hpp>
#include <rp/sha256.hpp>

#include "path_utf8.hpp"
#include "utf16.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <format>
#include <fstream>
#include <optional>
#include <system_error>
#include <utility>

namespace rp {

namespace {

using ordered_json = nlohmann::ordered_json;

// What a scrubbed query value or other credential reads as in a fixture, as
// the lab's Graph recorder writes it.
constexpr std::string_view kScrubbed = "SCRUBBED";

constexpr std::size_t kMaxSlug = 60;

// The recorder's JWT rule, stricter than redact()'s on purpose: a written
// file has already been through redact(), which needs a token's dots, so this
// looks for a long base64url run starting like a JWT (kJwtStart), dots or
// not: kJwtStart and at least this many more base64url characters.
constexpr std::size_t kMinJwtTail = 37;

// The names whose value a file may hold only as a placeholder, looked for in
// any case and in forms redact() doesn't know (URL-encoded "%3D", a key
// ending in quotes), with the refusal each gives.
struct UnscrubbedRule {
    std::string_view name;
    std::string_view why;
};
constexpr std::array<UnscrubbedRule, 2> kUnscrubbedRules{{
    {"tempauth", "it holds a tempauth download credential"},
    {"client_assertion", "it holds a client assertion"},
}};

// A driveItem's pre-authenticated download link: dropped from bodies.
constexpr std::array<std::string_view, 2> kDownloadUrlKeys{"@microsoft.graph.downloadUrl",
                                                           "@content.downloadUrl"};

// The response headers a fixture keeps, spelled as written.
constexpr std::array<std::string_view, 3> kKeptHeaders{"Content-Type", "Retry-After",
                                                       "WWW-Authenticate"};
constexpr std::string_view kLocation = "Location";

constexpr char ascii_lower(char c) noexcept
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr bool is_alnum_lower(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

bool iequals_prefix(std::string_view text, std::string_view prefix) noexcept
{
    return text.size() >= prefix.size() &&
           std::ranges::equal(text.substr(0, prefix.size()), prefix,
                              [](char a, char b) { return ascii_lower(a) == ascii_lower(b); });
}

// The URL without "scheme://host": its path, query and fragment ("/" when
// there is no path). A text without "://" is taken to be that already.
std::string_view path_query_fragment(std::string_view url) noexcept
{
    const std::size_t scheme = url.find("://");
    if (scheme == std::string_view::npos) {
        return url;
    }
    const std::size_t path = url.find_first_of("/?#", scheme + 3);
    return path == std::string_view::npos ? std::string_view{"/"} : url.substr(path);
}

// `path_query` ("/a/b?x=1&y=2#f") with the fragment dropped and every query
// value, and every query part without '=', written as kScrubbed.
std::string scrub_query_values(std::string_view path_query)
{
    path_query = path_query.substr(0, path_query.find('#'));
    const std::size_t mark = path_query.find('?');
    if (mark == std::string_view::npos) {
        return std::string{path_query};
    }
    std::string out{path_query.substr(0, mark + 1)};
    std::string_view query = path_query.substr(mark + 1);
    for (bool first = true;; first = false) {
        const std::size_t amp = query.find('&');
        const std::string_view pair = query.substr(0, amp);
        if (!first) {
            out += '&';
        }
        if (const std::size_t eq = pair.find('='); eq != std::string_view::npos) {
            out += pair.substr(0, eq + 1);
            out += kScrubbed;
        } else if (!pair.empty()) {
            out += kScrubbed;
        }
        if (amp == std::string_view::npos) {
            return out;
        }
        query = query.substr(amp + 1);
    }
}

// A Location's scheme, host and path kept, every query value kScrubbed.
std::string scrub_location(std::string_view location)
{
    const std::string_view rest = path_query_fragment(location);
    return std::string{location.substr(0, location.size() - rest.size())} +
           scrub_query_values(rest);
}

// Whether rp::redact() hides the value of `key` in JSON: the one list of
// secret names, not a second copy of it.
bool is_secret_json_key(const std::string& key)
{
    const std::string probe = ordered_json(key).dump(-1, ' ', false,
                                                     ordered_json::error_handler_t::replace) +
                              ":\"probe-value\"";
    return redact(probe) != probe;
}

bool is_secret_form_key(std::string_view key)
{
    const std::string probe = std::string{key} + "=probe-value";
    return redact(probe) != probe;
}

int hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = ascii_lower(c);
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

// application/x-www-form-urlencoded decoding: '+' is a space, %XX a byte; a
// '%' not followed by two hex digits stays as it is.
std::string form_decode(std::string_view text)
{
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '+') {
            out += ' ';
        } else if (text[i] == '%' && i + 2 < text.size() && hex_value(text[i + 1]) >= 0 &&
                   hex_value(text[i + 2]) >= 0) {
            out += static_cast<char>(hex_value(text[i + 1]) * 16 + hex_value(text[i + 2]));
            i += 2;
        } else {
            out += text[i];
        }
    }
    return out;
}

// A placeholder a scrubbed value already reads as: a replayed fixture's token
// is one, and the next file would hold it again by design.
bool is_placeholder(std::string_view value) noexcept
{
    return value == kRedacted || value == kScrubbed || value == "Bearer [REDACTED]";
}

// Every string under `value` wiped: a parsed body's copies of what it
// carried, a restore credential among them. Keys are names, not secrets.
void wipe_strings(ordered_json& value) noexcept
{
    if (value.is_string()) {
        secure_wipe(value.get_ref<std::string&>());
    } else if (value.is_structured()) {
        for (ordered_json& child : value) {
            wipe_strings(child);
        }
    }
}

// Wipes a parsed body's strings on the way out, exception or not.
struct JsonWipe {
    ordered_json& doc;

    ~JsonWipe() { wipe_strings(doc); }
};

void add_secret(std::vector<std::string>& out, std::string value)
{
    if (value.size() >= kMinRecordedSecret && !is_placeholder(value) &&
        std::ranges::find(out, value) == out.end()) {
        out.push_back(std::move(value));
    }
}

// The values of secret keys in `form` ("a=1&b=2"), raw and decoded.
void form_secrets(std::string_view form, std::vector<std::string>& out)
{
    while (!form.empty()) {
        const std::size_t amp = form.find('&');
        const std::string_view pair = form.substr(0, amp);
        const std::size_t eq = pair.find('=');
        if (eq != std::string_view::npos && is_secret_form_key(form_decode(pair.substr(0, eq)))) {
            add_secret(out, std::string{pair.substr(eq + 1)});
            add_secret(out, form_decode(pair.substr(eq + 1)));
        }
        if (amp == std::string_view::npos) {
            break;
        }
        form = form.substr(amp + 1);
    }
}

// Every string under `value`.
void string_leaves(const ordered_json& value, std::vector<std::string>& out)
{
    if (value.is_string()) {
        add_secret(out, value.get<std::string>());
    } else if (value.is_structured()) {
        for (const ordered_json& child : value) {
            string_leaves(child, out);
        }
    }
}

// The strings under each secret key anywhere in `value`.
void json_secrets(const ordered_json& value, std::vector<std::string>& out)
{
    if (value.is_object()) {
        for (const auto& [key, child] : value.items()) {
            if (is_secret_json_key(key)) {
                string_leaves(child, out);
            }
            json_secrets(child, out);
        }
    } else if (value.is_array()) {
        for (const ordered_json& child : value) {
            json_secrets(child, out);
        }
    }
}

// A JSON object or array; nullopt for anything else (a scalar is text here).
std::optional<ordered_json> parse_structured(std::string_view text)
{
    ordered_json doc = ordered_json::parse(text, nullptr, false);
    if (doc.is_discarded() || !doc.is_structured()) {
        return std::nullopt;
    }
    return doc;
}

// The secrets of a JSON body into `json_out`, of a form body into `form_out`.
void body_secrets(std::string_view body, std::vector<std::string>& json_out,
                  std::vector<std::string>& form_out)
{
    if (std::optional<ordered_json> doc = parse_structured(body)) {
        const JsonWipe wipe{*doc};
        json_secrets(*doc, json_out);
    } else {
        form_secrets(body, form_out);
    }
}

void drop_download_urls(ordered_json& value)
{
    if (value.is_object()) {
        for (const std::string_view key : kDownloadUrlKeys) {
            value.erase(std::string{key});
        }
    }
    if (value.is_structured()) {
        for (ordered_json& child : value) {
            drop_download_urls(child);
        }
    }
}

std::string dump(const ordered_json& value, int indent = -1)
{
    return value.dump(indent, ' ', false, ordered_json::error_handler_t::replace);
}

// A JSON body without its download links, redacted; still JSON if redacting
// left it JSON, which it does unless a secret sat inside a key. The parsed
// body and its text before redaction, which may hold a restore credential,
// are wiped.
ordered_json scrub_json(ordered_json doc)
{
    const JsonWipe wipe{doc};
    drop_download_urls(doc);
    std::string raw = dump(doc);
    std::string text = redact(raw);
    secure_wipe(raw);
    std::optional<ordered_json> again = parse_structured(text);
    return again ? std::move(*again) : ordered_json(std::move(text));
}

// Whether `text` holds `secret`, as written or JSON-escaped. The escaped copy
// is wiped.
bool holds_secret(std::string_view text, const std::string& secret)
{
    if (secret.size() < kMinRecordedSecret) {
        return false;
    }
    if (text.find(secret) != std::string_view::npos) {
        return true;
    }
    ordered_json as_json(secret);
    std::string escaped = dump(as_json);
    const bool found =
        text.find(std::string_view{escaped}.substr(1, escaped.size() - 2)) != std::string_view::npos;
    wipe_strings(as_json);
    secure_wipe(escaped);
    return found;
}

// Whether `text` holds a value of `name` (any case) other than a placeholder:
// the name not run on into a longer key ("tempauthority",
// "client_assertion_type"), perhaps a closing quote (plain, single or
// escaped), blanks, then '=', "%3D" or ':', then the value, which must start,
// after blanks and quotes, with kScrubbed or kRedacted.
bool holds_unscrubbed_value(std::string_view text, std::string_view name)
{
    for (std::size_t at = 0; at < text.size(); ++at) {
        if (!iequals_prefix(text.substr(at), name)) {
            continue;
        }
        std::string_view rest = text.substr(at + name.size());
        if (rest.starts_with("\\\"")) {
            rest.remove_prefix(2);
        } else if (rest.starts_with("\"") || rest.starts_with("'")) {
            rest.remove_prefix(1);
        }
        const std::size_t sep = rest.find_first_not_of(" \t");
        rest.remove_prefix(sep == std::string_view::npos ? rest.size() : sep);
        if (iequals_prefix(rest, "%3d")) {
            rest.remove_prefix(3);
        } else if (rest.starts_with("=") || rest.starts_with(":")) {
            rest.remove_prefix(1);
        } else {
            continue;
        }
        const std::size_t value = rest.find_first_not_of(" \t\"\\'");
        rest.remove_prefix(value == std::string_view::npos ? rest.size() : value);
        if (!rest.starts_with(kScrubbed) && !rest.starts_with(kRedacted)) {
            return true;
        }
    }
    return false;
}

// The first rule the fixture text breaks, or nullopt.
template <typename Secrets>
std::optional<std::string_view> broken_rule(std::string_view text, const Secrets& secrets,
                                            const std::vector<std::string>& one_time)
{
    const auto held = [text](const std::string& secret) { return holds_secret(text, secret); };
    if (std::ranges::any_of(secrets, held) || std::ranges::any_of(one_time, held)) {
        return "it holds a known secret";
    }
    for (std::size_t at = text.find(kJwtStart); at != std::string_view::npos;
         at = text.find(kJwtStart, at + 1)) {
        std::size_t end = at + kJwtStart.size();
        while (end < text.size() && is_base64url(text[end])) {
            ++end;
        }
        if (end - at - kJwtStart.size() >= kMinJwtTail) {
            return "it holds what looks like a JWT";
        }
    }
    for (const UnscrubbedRule& rule : kUnscrubbedRules) {
        if (holds_unscrubbed_value(text, rule.name)) {
            return rule.why;
        }
    }
    return std::nullopt;
}

// scrub_exchange over any list of kept secrets: the recorder's is a deque.
template <typename Secrets>
ScrubbedExchange scrub(std::size_t index, std::string_view source, const HttpRequest& request,
                       const HttpResponse& response, RecordedBody body, const Secrets& secrets,
                       const std::vector<std::string>& one_time)
{
    ScrubbedExchange out;
    out.file_name = fixture_file_name(index, request.method, request.url);

    // Redacted first, then (for a download) every query value scrubbed, so a
    // tempauth reads SCRUBBED like the rest rather than [REDACTED].
    const std::string line = redact(std::string{to_string(request.method)} + " " +
                                    std::string{request_path(request.url)});
    ordered_json doc;
    doc["source"] = std::string{source};
    doc["request"] = body == RecordedBody::digest ? scrub_query_values(line) : line;
    doc["status"] = response.status;
    ordered_json headers = ordered_json::object();
    for (const std::string_view name : kKeptHeaders) {
        if (const auto it = response.headers.find(name); it != response.headers.end()) {
            headers[std::string{name}] = redact(it->second);
        }
    }
    if (const auto it = response.headers.find(kLocation); it != response.headers.end()) {
        headers[std::string{kLocation}] = scrub_location(redact(it->second));
    }
    doc["headers"] = std::move(headers);

    // A digest body is never looked at beyond its size and hash.
    if (response.body.empty()) {
        doc["body"] = nullptr;
    } else if (body == RecordedBody::digest || !utf8_to_utf16(response.body)) {
        doc["body"] = nullptr;
        doc["body_size"] = response.body.size();
        doc["body_sha256"] = sha256_hex(response.body);
    } else if (std::optional<ordered_json> json = parse_structured(response.body)) {
        doc["body"] = scrub_json(std::move(*json));
    } else {
        doc["body"] = redact(response.body);
    }
    if (request.parts.empty()) {
        if (std::optional<ordered_json> json = parse_structured(request.body)) {
            doc["request_body"] = scrub_json(std::move(*json));
        }
    }

    out.text = dump(doc, 2) + "\n";
    if (const std::optional<std::string_view> rule = broken_rule(out.text, secrets, one_time)) {
        // The refused text holds a secret: no copy of it outlives the refusal.
        wipe_strings(doc);
        secure_wipe(out.text);
        throw RecordRefused(std::string{"refused: "} + std::string{*rule});
    }
    return out;
}

} // namespace

std::string_view request_path(std::string_view url) noexcept
{
    const std::string_view path = path_query_fragment(url);
    return path.substr(0, path.find('#'));
}

std::string fixture_file_name(std::size_t index, HttpMethod method, std::string_view url)
{
    std::string_view path = path_query_fragment(url);
    path = path.substr(0, path.find_first_of("?#"));
    std::string slug;
    for (const char c : path) {
        const char lower = ascii_lower(c);
        if (is_alnum_lower(lower)) {
            slug += lower;
        } else if (!slug.empty() && slug.back() != '-') {
            slug += '-';
        }
    }
    if (slug.size() > kMaxSlug) {
        slug.resize(kMaxSlug);
    }
    while (!slug.empty() && slug.back() == '-') {
        slug.pop_back();
    }
    std::string verb{to_string(method)};
    std::ranges::transform(verb, verb.begin(), ascii_lower);
    return std::format("{:03}-{}-{}.json", index, verb, slug.empty() ? "root" : slug);
}

LearnedSecrets::~LearnedSecrets()
{
    for (std::vector<std::string>* list : {&kept, &one_time}) {
        for (std::string& secret : *list) {
            secure_wipe(secret);
        }
    }
}

LearnedSecrets secrets_in(const HttpRequest& request, const HttpResponse& response,
                          RecordedBody body)
{
    LearnedSecrets out;
    for (const auto& [name, value] : request.headers) {
        if (is_secret_header(name)) {
            add_secret(out.kept, value);
            if (iequals_prefix(value, "bearer ")) {
                add_secret(out.kept, value.substr(7));
            }
        }
    }
    const std::string_view path_query = path_query_fragment(request.url);
    if (const std::size_t mark = path_query.find('?'); mark != std::string_view::npos) {
        form_secrets(path_query.substr(mark + 1, path_query.find('#') - mark - 1), out.kept);
    }
    body_secrets(request.body, out.one_time, out.kept);
    for (const MultipartPart& part : request.parts) {
        if (is_secret_form_key(part.name)) {
            add_secret(out.kept, part.content);
        }
    }
    if (body == RecordedBody::content) {
        body_secrets(response.body, out.kept, out.kept);
    }
    if (const auto location = response.headers.find(kLocation);
        location != response.headers.end()) {
        const std::string_view query = path_query_fragment(location->second);
        if (const std::size_t mark = query.find('?'); mark != std::string_view::npos) {
            form_secrets(query.substr(mark + 1, query.find('#') - mark - 1), out.kept);
        }
    }
    return out;
}

ScrubbedExchange scrub_exchange(std::size_t index, std::string_view source,
                                const HttpRequest& request, const HttpResponse& response,
                                RecordedBody body, const std::vector<std::string>& secrets,
                                const std::vector<std::string>& one_time)
{
    return scrub(index, source, request, response, body, secrets, one_time);
}

FixtureRecorder::FixtureRecorder(std::filesystem::path dir, std::string source,
                                 const std::vector<std::string>& known_secrets)
    : dir_(std::move(dir)), source_(std::move(source))
{
    const std::string shown = path_to_utf8(dir_);
    std::error_code ec;
    const std::filesystem::file_status status = std::filesystem::status(dir_, ec);
    if (std::filesystem::exists(status)) {
        if (!std::filesystem::is_directory(status)) {
            throw ConfigError("--record", shown + ": the --record path is not a folder");
        }
        if (std::filesystem::directory_iterator(dir_, ec) != std::filesystem::directory_iterator{} ||
            ec) {
            throw ConfigError("--record", shown + ": the --record folder is not empty");
        }
    } else {
        // Not create_directories' result: MSVC's is false for a path ending in
        // a separator even when it made the folder.
        std::filesystem::create_directories(dir_, ec);
        if (ec || !std::filesystem::is_directory(dir_, ec)) {
            throw ConfigError("--record", shown + ": the --record folder can't be made");
        }
    }
    for (const std::string& secret : known_secrets) {
        if (secret.size() >= kMinRecordedSecret &&
            std::ranges::find(secrets_, secret) == secrets_.end()) {
            secrets_.push_back(secret);
        }
    }
}

FixtureRecorder::~FixtureRecorder()
{
    for (std::string& secret : secrets_) {
        secure_wipe(secret);
    }
}

void FixtureRecorder::record(std::string_view service, const HttpRequest& request,
                             const HttpResponse& response, RecordedBody body) noexcept
{
    try {
        // Learned outside every lock: scanning a large body holds up no one.
        LearnedSecrets learned = secrets_in(request, response, body);
        {
            const std::unique_lock lock(secrets_mutex_);
            for (std::string& secret : learned.kept) {
                if (std::ranges::find(secrets_, secret) == secrets_.end()) {
                    secrets_.push_back(std::move(secret));
                }
            }
        }
        std::size_t index = 0;
        {
            const std::lock_guard lock(mutex_);
            auto it = next_index_.find(service);
            if (it == next_index_.end()) {
                it = next_index_.emplace(std::string{service}, 1).first;
            }
            index = it->second++;
        }
        std::optional<std::string> problem;
        try {
            ScrubbedExchange file;
            {
                // Other exchanges scrub at the same time; only learning waits.
                const std::shared_lock lock(secrets_mutex_);
                file = scrub(index, source_, request, response, body, secrets_, learned.one_time);
            }
            const std::filesystem::path folder = dir_ / std::filesystem::path(std::string{service});
            std::filesystem::create_directories(folder);
            std::ofstream stream(folder / file.file_name, std::ios::binary | std::ios::trunc);
            stream << file.text;
            stream.close();
            if (!stream) {
                problem = "could not be written";
            }
        } catch (const RecordRefused& e) {
            problem = e.what();
        } catch (...) {
            problem = "could not be written";
        }
        const std::string where =
            std::string{service} + "/" + fixture_file_name(index, request.method, request.url);
        const std::lock_guard lock(mutex_);
        if (problem) {
            problems_.push_back(where + ": " + *problem);
        } else {
            ++written_;
        }
    } catch (...) {
        // Out of memory: the exchange goes unrecorded, and the command on.
    }
}

const std::filesystem::path& FixtureRecorder::dir() const noexcept
{
    return dir_;
}

std::size_t FixtureRecorder::written() const
{
    const std::lock_guard lock(mutex_);
    return written_;
}

std::vector<std::string> FixtureRecorder::problems() const
{
    const std::lock_guard lock(mutex_);
    return problems_;
}

RecordingHttpClient::RecordingHttpClient(std::unique_ptr<IHttpClient> inner,
                                         std::shared_ptr<FixtureRecorder> recorder,
                                         std::string service, RecordedBody body)
    : inner_(std::move(inner)), recorder_(std::move(recorder)), service_(std::move(service)),
      body_(body)
{
    if (!inner_ || !recorder_) {
        throw std::invalid_argument("a recording HTTP client needs a client and a recorder");
    }
}

HttpResponse RecordingHttpClient::send(const HttpRequest& request)
{
    HttpResponse response = inner_->send(request);
    recorder_->record(service_, request, response, body_);
    return response;
}

} // namespace rp
