#include <rp/graph_client.hpp>

#include <rp/redact.hpp>
#include <rp/retry_policy.hpp>
#include <rp/version.hpp>

#include "text_util.hpp"
#include "uuid.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <random>
#include <stdexcept>
#include <thread>
#include <utility>

namespace rp::graph {

namespace {

using nlohmann::json;
using std::chrono::milliseconds;
using std::chrono::seconds;

// The token is renewed when this little is left, so one never expires on the
// way to Graph ...
constexpr seconds kRenewMargin{60};
// ... and a lifetime above this counts as this: Entra gives about an hour, and
// no later arithmetic on the clock can overflow.
constexpr seconds kMaxTokenLifetime{86400};
// A Retry-After number above this is kept as this: far over any cap, and no
// arithmetic on it can overflow.
constexpr std::int64_t kHugeRetryAfter = 1'000'000'000'000;
// How much of Entra's error_description and Graph's message a message keeps.
constexpr std::size_t kMaxServerText = 300;
// How much of a request ID a message keeps: a GUID is 36 characters.
constexpr std::size_t kMaxRequestId = 64;

// The Entra codes that say to try again (reference-error-codes): 90006,
// 90033, 90090 and 50033 are transient faults, 90055 throttling.
constexpr std::array<std::string_view, 5> kTransientCodes{"90006", "90033", "90090", "50033",
                                                          "90055"};

bool is_digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

std::string ascii_lower(std::string_view text)
{
    std::string out{text};
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

std::string_view trim_ows(std::string_view text) noexcept
{
    const auto is_ows = [](char c) { return c == ' ' || c == '\t'; };
    while (!text.empty() && is_ows(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && is_ows(text.back())) {
        text.remove_suffix(1);
    }
    return text;
}

// The request ID Microsoft can look a call up by, from the headers.
std::string header_request_id(const HttpResponse& response)
{
    for (const char* name : {"request-id", "client-request-id", "x-ms-request-id"}) {
        if (const auto it = response.headers.find(name);
            it != response.headers.end() && !it->second.empty()) {
            return one_line(it->second, kMaxRequestId);
        }
    }
    return {};
}

std::string request_id_suffix(const std::string& request_id)
{
    return request_id.empty() ? std::string{} : " (request ID " + request_id + ")";
}

// Entra's error reply: {"error", "error_description", "error_codes", ...}.
struct EntraReply {
    bool is_entra = false; // a JSON object with a string "error"
    std::string error;
    // The AADSTS number: the first of error_codes, else the one in
    // error_description; empty if neither has one.
    std::string aadsts;
    // error_description without its "AADSTS<n>: " prefix, on one line.
    std::string description;
};

// The digits after the first "AADSTS" in `text` that has any; empty if none.
std::string aadsts_in(std::string_view text)
{
    constexpr std::string_view prefix = "AADSTS";
    for (std::size_t at = text.find(prefix); at != std::string_view::npos;
         at = text.find(prefix, at + prefix.size())) {
        std::size_t end = at + prefix.size();
        while (end < text.size() && is_digit(text[end]) && end - at - prefix.size() < 10) {
            ++end;
        }
        if (end > at + prefix.size()) {
            return std::string{text.substr(at + prefix.size(), end - at - prefix.size())};
        }
    }
    return {};
}

EntraReply parse_entra_reply(std::string_view body)
{
    EntraReply out;
    const json doc = json::parse(body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        return out;
    }
    const auto error = doc.find("error");
    if (error == doc.end() || !error->is_string()) {
        return out;
    }
    out.is_entra = true;
    out.error = one_line(error->get_ref<const std::string&>(), 100);
    std::string_view description;
    if (const auto it = doc.find("error_description"); it != doc.end() && it->is_string()) {
        description = it->get_ref<const std::string&>();
    }
    if (const auto codes = doc.find("error_codes");
        codes != doc.end() && codes->is_array() && !codes->empty() &&
        codes->front().is_number_unsigned()) {
        out.aadsts = std::to_string(codes->front().get<std::uint64_t>());
    } else {
        out.aadsts = aadsts_in(description);
    }
    // "AADSTS700027: Key was found, ..." → "Key was found, ...".
    if (description.starts_with("AADSTS")) {
        const std::size_t colon = description.find(": ");
        if (colon != std::string_view::npos && colon < 20) {
            description.remove_prefix(colon + 2);
        }
    }
    out.description = one_line(description, kMaxServerText);
    return out;
}

// Graph's error reply: {"error": {"code", "message", "innerError": {...}}}.
struct GraphReply {
    std::string code;
    std::string message;
    std::string inner_code;
    std::string request_id;
};

GraphReply parse_graph_reply(const HttpResponse& response)
{
    GraphReply out;
    const json doc = json::parse(response.body, nullptr, false);
    const auto error = doc.is_object() ? doc.find("error") : doc.end();
    if (!doc.is_discarded() && doc.is_object() && error != doc.end() && error->is_object()) {
        if (const auto it = error->find("code"); it != error->end() && it->is_string()) {
            out.code = one_line(it->get_ref<const std::string&>(), 100);
        }
        if (const auto it = error->find("message"); it != error->end() && it->is_string()) {
            out.message = one_line(it->get_ref<const std::string&>(), kMaxServerText);
        }
        for (const auto& [key, inner] : error->items()) {
            if (ascii_lower(key) != "innererror" || !inner.is_object()) {
                continue;
            }
            if (const auto it = inner.find("code"); it != inner.end() && it->is_string()) {
                out.inner_code = one_line(it->get_ref<const std::string&>(), 100);
            }
            if (const auto it = inner.find("request-id"); it != inner.end() && it->is_string()) {
                out.request_id = one_line(it->get_ref<const std::string&>(), kMaxRequestId);
            }
        }
    }
    if (out.request_id.empty()) {
        out.request_id = header_request_id(response);
    }
    return out;
}

enum class Kind { auth, transient, graph };

// Why a token attempt failed, before it is thrown or retried.
struct Failure {
    Kind kind = Kind::graph;
    // "HTTP 401 (invalid_client, AADSTS700027)" or the transport error.
    std::string summary;
    std::string hint;
    // What Entra said, when it said anything.
    std::string said;
    int status = 0;
    std::string code;
    std::string request_id;
    std::optional<seconds> retry_after;
};

[[noreturn]] void throw_failure(const Failure& failure, int attempts, std::string_view extra = {})
{
    std::string message = failure.kind == Kind::auth ? "Entra refused the Worker's Graph sign-in: "
                                                     : "Entra token request: ";
    message += failure.summary;
    if (attempts > 1) {
        message += " after " + std::to_string(attempts) + " attempts";
    }
    message += extra;
    if (!failure.hint.empty()) {
        message += ": " + failure.hint;
    }
    if (!failure.said.empty()) {
        message += (message.back() == '?' ? " " : ". ") + std::string{"Entra said: "} + failure.said;
    }
    message += request_id_suffix(failure.request_id);
    switch (failure.kind) {
    case Kind::auth:
        throw AuthError(message, failure.status, failure.code, {}, failure.request_id);
    case Kind::transient:
        throw TransientError(message, failure.status, failure.code, {}, failure.request_id,
                             failure.retry_after);
    case Kind::graph:
        break;
    }
    throw GraphError(message, failure.status, failure.code, {}, failure.request_id);
}

std::string utc_text(std::chrono::system_clock::time_point time)
{
    return std::format("{:%FT%T}Z", std::chrono::floor<seconds>(time));
}

std::function<double()> default_jitter()
{
    struct State {
        std::mutex mutex;
        std::mt19937_64 engine{std::random_device{}()};
        std::uniform_real_distribution<double> uniform{0.0, 1.0};
    };
    auto state = std::make_shared<State>();
    return [state] {
        const std::lock_guard lock(state->mutex);
        return state->uniform(state->engine);
    };
}

// Visible ASCII only: a token goes into a header line as it is.
bool is_header_safe(std::string_view token) noexcept
{
    return std::all_of(token.begin(), token.end(), [](char c) { return c > ' ' && c < 0x7F; });
}

HttpHeaders common_headers()
{
    HttpHeaders headers;
    headers["Accept"] = "application/json";
    headers["User-Agent"] = user_agent();
    return headers;
}

// Maps a token reply that isn't 2xx (see the class comment).
// What the hints name.
struct HintContext {
    std::string_view thumbprint;
    std::string_view client_id;
    std::string_view tenant_id;
    std::chrono::system_clock::time_point wall_now;
};

Failure token_failure(const HttpResponse& response, const HintContext& context)
{
    Failure failure;
    failure.status = response.status;
    failure.request_id = header_request_id(response);
    failure.summary = "HTTP " + std::to_string(response.status);
    if (response.status >= 300 && response.status <= 399) {
        failure.summary += ", a redirect, not followed";
        return failure;
    }
    const bool status_transient =
        response.status == 429 || (response.status >= 500 && response.status <= 599);
    if (response.status == 429 || response.status == 503) {
        if (const auto it = response.headers.find("Retry-After"); it != response.headers.end()) {
            failure.retry_after = parse_retry_after(it->second, context.wall_now);
        }
    }
    const EntraReply reply = parse_entra_reply(response.body);
    if (!reply.is_entra) {
        // Not Entra speaking (a proxy, a gateway): its body is never quoted.
        failure.kind = status_transient ? Kind::transient : Kind::graph;
        return failure;
    }
    failure.code = reply.aadsts.empty() ? reply.error : reply.aadsts;
    failure.summary += " (" + reply.error;
    if (!reply.aadsts.empty()) {
        failure.summary += ", AADSTS" + reply.aadsts;
    }
    failure.summary += ")";
    failure.said = reply.description;

    const std::string& code = reply.aadsts;
    const auto is = [&code](std::initializer_list<std::string_view> codes) {
        return std::find(codes.begin(), codes.end(), code) != codes.end();
    };
    failure.kind = Kind::auth;
    if (is({"700016"})) {
        failure.hint = "check graph_client_id and graph_tenant_id";
    } else if (is({"90002", "900023", "50059"})) {
        failure.hint = "check graph_tenant_id";
    } else if (is({"700027", "7000274", "50012", "700030"})) {
        failure.hint = "is the certificate with SHA-1 thumbprint " + std::string{context.thumbprint} +
                       " uploaded to app " + std::string{context.client_id} + "?";
    } else if (is({"700024", "50027"})) {
        failure.hint = "the clocks disagree: this machine's clock reads " +
                       utc_text(context.wall_now) +
                       " (UTC); set it right (w32tm /resync) and try again";
    } else if (is({"53003"})) {
        failure.hint = "a Conditional Access policy blocks the sign-in; exclude the Worker app "
                       "from it or allow this machine";
    } else if (is({"70001", "7000112", "500014", "1000031"})) {
        failure.hint = "the app " + std::string{context.client_id} +
                       " is disabled, deleted or not found in tenant " +
                       std::string{context.tenant_id};
    } else if (std::find(kTransientCodes.begin(), kTransientCodes.end(), code) !=
                   kTransientCodes.end() ||
               reply.error == "temporarily_unavailable" || status_transient) {
        failure.kind = Kind::transient;
    }
    return failure;
}

// Where the token may go: Graph's v1.0 root and a '/'.
std::string graph_prefix()
{
    return std::string{kGraphBaseUrl} + "/";
}

// The URL a GET for `path_or_url` goes to (see GraphClient::get); throws
// GraphError for anything else. Checked as text, before anything is sent.
std::string graph_url(std::string_view path_or_url)
{
    const std::string prefix = graph_prefix();
    const auto refuse = [&](std::string_view why) {
        throw GraphError("Graph GET: refused \"" + one_line(path_or_url, 200) + "\": " +
                         std::string{why} + "; the token goes only to " + prefix);
    };
    if (path_or_url.empty()) {
        refuse("neither a path starting with '/' nor a URL");
    }
    const std::string url = path_or_url.front() == '/'
                                ? std::string{kGraphBaseUrl} + std::string{path_or_url}
                                : std::string{path_or_url};
    if (!url.starts_with(prefix)) {
        refuse(path_or_url.front() == '/' ? "not a path under v1.0"
                                          : "a URL outside Graph's v1.0");
    }
    for (const char c : url) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte <= 0x20 || byte == 0x7F || c == '\\' || c == '#') {
            refuse("it holds whitespace, a control character, a backslash or a '#'");
        }
    }
    // curl resolves dot segments ("/v1.0/../beta"), and a server may decode
    // "%2e" first; "//" is what a protocol-relative URL ("//host/...") passed
    // as a path looks like. None has any use in a Graph path. The query is
    // Graph's (a $skiptoken is opaque).
    const std::string_view rest = std::string_view{url}.substr(prefix.size() - 1);
    const std::string path = ascii_lower(rest.substr(0, rest.find('?')));
    if (path.find("%2e") != std::string::npos || path.find("/./") != std::string::npos ||
        path.find("/../") != std::string::npos || path.ends_with("/.") ||
        path.ends_with("/..") || path.find("//") != std::string::npos) {
        refuse("its path has a dot segment or an empty one");
    }
    return url;
}

// "/v1.0/users/x/messages" for a URL graph_url() gave: the path without the
// query (a $filter may name what is looked for), on one line.
std::string display_path(std::string_view url)
{
    constexpr std::string_view root = "https://graph.microsoft.com";
    url.remove_prefix(root.size());
    return one_line(url.substr(0, url.find('?')), 200);
}

// Graph asks for a token with more claims (Conditional Access, continuous
// access evaluation): WWW-Authenticate: Bearer ..., error="insufficient_claims".
bool asks_for_claims(const HttpResponse& response)
{
    const auto it = response.headers.find("WWW-Authenticate");
    return it != response.headers.end() &&
           ascii_lower(it->second).find("insufficient_claims") != std::string::npos;
}

std::string relies_on(const Grant& grant)
{
    return "the Worker app relies on " + std::string{grant.description} +
           "; see docs/security/graph-permissions.md";
}

} // namespace

std::string user_agent()
{
    return "ISV|RestoreProof|RestoreProofWorker/" + std::string{version()};
}

std::optional<seconds> parse_retry_after(std::string_view value,
                                         std::chrono::system_clock::time_point wall_now)
{
    const std::string_view text = trim_ows(value);
    if (text.empty()) {
        return std::nullopt;
    }
    if (std::all_of(text.begin(), text.end(), is_digit)) {
        std::int64_t total = 0;
        for (const char c : text) {
            total = std::min(total * 10 + (c - '0'), kHugeRetryAfter);
        }
        return seconds{total};
    }

    // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT", exactly.
    constexpr std::array<std::string_view, 7> days{"Mon", "Tue", "Wed", "Thu",
                                                   "Fri", "Sat", "Sun"};
    constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (text.size() != 29 || text.substr(3, 2) != ", " || text[7] != ' ' || text[11] != ' ' ||
        text[16] != ' ' || text[19] != ':' || text[22] != ':' || text.substr(25) != " GMT" ||
        std::find(days.begin(), days.end(), text.substr(0, 3)) == days.end()) {
        return std::nullopt;
    }
    const auto number = [text](std::size_t at, std::size_t count) -> std::optional<int> {
        int out = 0;
        for (std::size_t i = at; i < at + count; ++i) {
            if (!is_digit(text[i])) {
                return std::nullopt;
            }
            out = out * 10 + (text[i] - '0');
        }
        return out;
    };
    const auto month = std::find(months.begin(), months.end(), text.substr(8, 3));
    const auto day = number(5, 2);
    const auto year = number(12, 4);
    const auto hour = number(17, 2);
    const auto minute = number(20, 2);
    const auto second = number(23, 2);
    if (month == months.end() || !day || !year || !hour || !minute || !second || *hour > 23 ||
        *minute > 59 || *second > 60) {
        return std::nullopt;
    }
    const std::chrono::year_month_day date{
        std::chrono::year{*year},
        std::chrono::month{static_cast<unsigned>(month - months.begin() + 1)},
        std::chrono::day{static_cast<unsigned>(*day)}};
    if (!date.ok()) {
        return std::nullopt;
    }
    const auto at = std::chrono::sys_days{date} + std::chrono::hours{*hour} +
                    std::chrono::minutes{*minute} + seconds{*second};
    return std::max(std::chrono::ceil<seconds>(at - wall_now), seconds{0});
}

GraphClient::GraphClient(IHttpClient& http, std::string tenant_id, std::string client_id,
                         ClientCertificate certificate, GraphClientOptions options)
    : http_(http), tenant_id_(std::move(tenant_id)), client_id_(std::move(client_id)),
      token_url_(entra_token_url(tenant_id_)), certificate_(std::move(certificate)),
      options_(std::move(options))
{
    if (!is_uuid(client_id_)) {
        throw GraphError("the Graph client ID is not a GUID");
    }
    if (options_.timeout <= milliseconds::zero()) {
        throw std::invalid_argument("GraphClient timeout must be above 0 ms");
    }
    if (!options_.now) {
        options_.now = [] { return std::chrono::steady_clock::now(); };
    }
    if (!options_.wall_now) {
        options_.wall_now = [] { return std::chrono::system_clock::now(); };
    }
    if (!options_.sleep) {
        options_.sleep = [](milliseconds wait) { std::this_thread::sleep_for(wait); };
    }
    if (!options_.jitter) {
        options_.jitter = default_jitter();
    }
}

void GraphClient::log_debug(const std::string& line) const
{
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger =
        options_.logger ? options_.logger : spdlog::default_logger();
    if (logger && logger->should_log(spdlog::level::debug)) {
        logger->debug("{}", redact(line));
    }
}

HttpRequest GraphClient::token_request() const
{
    HttpRequest request;
    request.method = HttpMethod::post;
    request.url = token_url_;
    request.headers = common_headers();
    request.content_type = "application/x-www-form-urlencoded";
    // A new assertion (and jti) for every attempt: Entra refuses a replayed one.
    request.body = "client_id=" + form_encode(client_id_) + "&scope=" + form_encode(kGraphScope) +
                   "&client_assertion_type=" +
                   form_encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") +
                   "&client_assertion=" +
                   form_encode(make_client_assertion(certificate_, tenant_id_, client_id_,
                                                     options_.wall_now())) +
                   "&grant_type=client_credentials";
    request.timeout = options_.timeout;
    // This client decides what is worth another attempt and counts them.
    request.retry_on_status = false;
    request.max_attempts = 1;
    return request;
}

void GraphClient::store_token_locked(const HttpResponse& response)
{
    // The body holds the token: no message below may quote it.
    const auto refuse = [&response](std::string_view why) {
        throw GraphError("Entra token request: HTTP " + std::to_string(response.status) +
                             ", but " + std::string{why},
                         response.status, {}, {}, header_request_id(response));
    };
    const json doc = json::parse(response.body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        refuse("the reply isn't a JSON object");
    }
    const auto type = doc.find("token_type");
    if (type == doc.end() || !type->is_string() ||
        ascii_lower(type->get_ref<const std::string&>()) != "bearer") {
        refuse("the reply's token_type isn't Bearer");
    }
    const auto access = doc.find("access_token");
    if (access == doc.end() || !access->is_string() ||
        access->get_ref<const std::string&>().empty()) {
        refuse("the reply has no access_token");
    }
    if (!is_header_safe(access->get_ref<const std::string&>())) {
        refuse("the reply's access_token has characters a token can't have");
    }
    // A positive integer (the parser gives those the unsigned type, however
    // large); anything above kMaxTokenLifetime counts as that.
    const auto expires_in = doc.find("expires_in");
    if (expires_in == doc.end() || !expires_in->is_number_unsigned() ||
        expires_in->get<std::uint64_t>() == 0) {
        refuse("the reply has no valid expires_in");
    }
    const seconds lifetime{static_cast<std::int64_t>(std::min<std::uint64_t>(
        expires_in->get<std::uint64_t>(), static_cast<std::uint64_t>(kMaxTokenLifetime.count())))};
    // A lifetime of twice the margin or less is renewed at its half, so a
    // short-lived token isn't renewed on every call.
    const milliseconds margin = std::min<milliseconds>(kRenewMargin, milliseconds{lifetime} / 2);

    // Built first, then swapped in without anything that can throw.
    std::string token = access->get<std::string>();
    // Counted from now, on the local clock.
    const auto renew_at = options_.now() + lifetime - margin;
    access_token_.swap(token);
    renew_at_ = renew_at;
    ++generation_;
    // A token now works: an earlier failure is no answer for anyone.
    last_renewal_failure_ = nullptr;
    log_debug("Graph: signed in to Entra as app " + client_id_ + "; the token expires in " +
              std::to_string(lifetime.count()) + " s");
}

void GraphClient::fetch_token_locked()
{
    try {
        milliseconds waited{0};
        for (int attempt = 1;; ++attempt) {
            Failure failure;
            try {
                const HttpResponse response = http_.send(token_request());
                if (response.status >= 200 && response.status <= 299) {
                    store_token_locked(response);
                    return;
                }
                failure = token_failure(response, {certificate_.sha1_thumbprint(), client_id_,
                                                   tenant_id_, options_.wall_now()});
            } catch (const HttpError& e) {
                // No connection, no handshake, a dropped connection or a
                // timeout: all resent, since every attempt is a new assertion
                // and a token request changes nothing on Entra's side. A
                // certificate failure or a malformed URL won't fix itself.
                const TransportError error = e.error();
                failure.kind = is_retryable(AttemptOutcome{error, 0}) ||
                                       error == TransportError::none
                                   ? Kind::transient
                                   : Kind::graph;
                failure.summary = e.what();
                failure.status = e.status();
            }
            if (failure.kind != Kind::transient || attempt >= kMaxHttpAttempts) {
                throw_failure(failure, attempt);
            }
            if (failure.retry_after && *failure.retry_after > kMaxRetryWait) {
                throw_failure(failure, attempt,
                              "; Entra asked to wait " +
                                  std::to_string(failure.retry_after->count()) +
                                  " s, more than the " + std::to_string(kMaxRetryWait.count()) +
                                  " s the Worker waits");
            }
            milliseconds wait =
                std::max<milliseconds>(retry_delay(attempt, options_.jitter()), kMinTokenRetryWait);
            if (failure.retry_after) {
                wait = std::max<milliseconds>(wait, *failure.retry_after);
            }
            if (waited + wait > kMaxRetryWaitPerCall) {
                throw_failure(failure, attempt,
                              "; another wait would pass the " +
                                  std::to_string(kMaxRetryWaitPerCall.count()) +
                                  " s the Worker waits for one call");
            }
            log_debug("Entra token request: " + failure.summary + " on attempt " +
                      std::to_string(attempt) + "; retrying in " + std::to_string(wait.count()) +
                      " ms");
            options_.sleep(wait);
            waited += wait;
        }
    } catch (...) {
        last_renewal_failure_ = std::current_exception();
        ++renewal_failures_;
        throw;
    }
}

void GraphClient::rethrow_failure_since_locked(std::uint64_t failures_seen) const
{
    // A renewal failed while this caller waited for the lock, and none has
    // succeeded since: the same answer, without spending the retries again.
    if (renewal_failures_.load() != failures_seen && last_renewal_failure_) {
        std::rethrow_exception(last_renewal_failure_);
    }
}

void GraphClient::renew_if_due_locked(std::uint64_t failures_seen)
{
    if (!access_token_.empty() && options_.now() < renew_at_) {
        return;
    }
    // Only a caller that has to renew shares a failure: one that finds a
    // good token (another caller's success) uses it.
    rethrow_failure_since_locked(failures_seen);
    fetch_token_locked();
}

GraphClient::Token GraphClient::current_token()
{
    const std::uint64_t failures_seen = renewal_failures_.load();
    const std::lock_guard lock(mutex_);
    renew_if_due_locked(failures_seen);
    return {access_token_, generation_, renewal_failures_.load()};
}

HttpRequest GraphClient::api_request(const std::string& url, const std::string& token) const
{
    HttpRequest request;
    request.method = HttpMethod::get;
    request.url = url;
    request.headers = common_headers();
    request.headers["Authorization"] = "Bearer " + token;
    request.timeout = options_.timeout;
    // This client decides what is worth another attempt and counts them.
    request.retry_on_status = false;
    request.max_attempts = 1;
    return request;
}

HttpResponse GraphClient::get(std::string_view path_or_url, const Grant& grant)
{
    // Before anything is sent, the token request included.
    const std::string url = graph_url(path_or_url);
    const std::string path = display_path(url);
    const std::string what = "Graph GET " + path;

    Token token = current_token();
    bool renewed = false; // this call fetched a fresh token after a 401
    int unauthorized = 0;
    milliseconds waited{0};
    for (int attempt = 1;;) {
        // What went wrong with an attempt worth another.
        struct Retry {
            std::string summary;
            int status = 0;
            std::string code;
            std::string inner_code;
            std::string request_id;
            std::optional<seconds> retry_after;
        } retry;

        HttpResponse response;
        try {
            response = http_.send(api_request(url, token.access));
        } catch (const HttpError& e) {
            // A GET changes nothing, so a lost connection or a timeout is
            // sent again; a certificate failure or a malformed URL won't fix
            // itself.
            if (!is_retryable(AttemptOutcome{e.error(), 0})) {
                throw GraphError(what + ": " + e.what(), e.status());
            }
            retry.summary = e.what();
            retry.status = e.status();
        }

        if (retry.summary.empty()) {
            const int status = response.status;
            if (status >= 200 && status <= 399) {
                return response;
            }
            const GraphReply reply = parse_graph_reply(response);
            const std::string code_part = reply.code.empty() ? "" : " (" + reply.code + ")";
            const std::string head = what + ": HTTP " + std::to_string(status) + code_part;
            const std::string rid = request_id_suffix(reply.request_id);

            if (status == 401) {
                if (asks_for_claims(response)) {
                    throw AuthError(head +
                                        ": Graph wants a token with more claims "
                                        "(insufficient_claims): a Conditional Access policy or "
                                        "continuous access evaluation blocks the Worker app, "
                                        "which can't satisfy it; exclude the app from the policy" +
                                        rid,
                                    status, reply.code, reply.inner_code, reply.request_id);
                }
                if (renewed || unauthorized == kMaxUnauthorizedResends) {
                    throw AuthError(head + " again " +
                                        (renewed ? "after a fresh token" : "with a newer token") +
                                        ": " + relies_on(grant) + rid,
                                    status, reply.code, reply.inner_code, reply.request_id);
                }
                {
                    const std::lock_guard lock(mutex_);
                    if (generation_ == token.generation) {
                        // Graph no longer takes the token: a fresh one, once
                        // (its failure is thrown as it is).
                        log_debug(head + "; getting a fresh token");
                        rethrow_failure_since_locked(token.failures_seen);
                        fetch_token_locked();
                        renewed = true;
                    } else {
                        // Another call replaced the token meanwhile: the
                        // current one is newer.
                        log_debug(head + " for a replaced token; resending with the current one");
                        renew_if_due_locked(token.failures_seen);
                    }
                    token = {access_token_, generation_, renewal_failures_.load()};
                }
                ++unauthorized;
                continue;
            }

            if (status != 429 && (status < 500 || status > 599)) {
                // A licence lapsed, the mailbox is inactive or on-premises:
                // not an item missing from a restore.
                if (reply.code == "MailboxNotEnabledForRESTAPI" ||
                    reply.code == "MailboxNotSupportedForRESTAPI") {
                    throw GraphError(head +
                                         ": Graph can't read this mailbox: it has no Exchange "
                                         "Online licence, is inactive or soft-deleted, or is "
                                         "on-premises" +
                                         rid,
                                     status, reply.code, reply.inner_code, reply.request_id);
                }
                if (status == 403) {
                    throw PermissionError("Graph denied GET " + path + " (403" +
                                              (reply.code.empty() ? "" : " " + reply.code) +
                                              "): " + relies_on(grant) + rid,
                                          std::string{grant.description}, status, reply.code,
                                          reply.inner_code, reply.request_id);
                }
                const std::string message =
                    head + (reply.message.empty() ? "" : ": " + reply.message) + rid;
                if (status == 404) {
                    throw NotFoundError(message, status, reply.code, reply.inner_code,
                                        reply.request_id);
                }
                throw GraphError(message, status, reply.code, reply.inner_code, reply.request_id);
            }

            // 429 or 5xx: a body that isn't Graph's JSON is never quoted.
            retry.summary = "HTTP " + std::to_string(status) + code_part;
            retry.status = status;
            retry.code = reply.code;
            retry.inner_code = reply.inner_code;
            retry.request_id = reply.request_id;
            if (status == 429 || status == 503) {
                if (const auto it = response.headers.find("Retry-After");
                    it != response.headers.end()) {
                    retry.retry_after = parse_retry_after(it->second, options_.wall_now());
                }
            }
        }

        // Another attempt, within the budget.
        const auto give_up = [&](const std::string& extra) {
            throw TransientError(what + ": " + retry.summary +
                                     (attempt > 1 ? " after " + std::to_string(attempt) +
                                                        " attempts"
                                                  : std::string{}) +
                                     extra + request_id_suffix(retry.request_id),
                                 retry.status, retry.code, retry.inner_code, retry.request_id,
                                 retry.retry_after);
        };
        if (attempt >= kMaxHttpAttempts) {
            give_up({});
        }
        if (retry.retry_after && *retry.retry_after > kMaxRetryWait) {
            give_up("; Graph asked to wait " + std::to_string(retry.retry_after->count()) +
                    " s, more than the " + std::to_string(kMaxRetryWait.count()) +
                    " s the Worker waits");
        }
        milliseconds wait = retry_delay(attempt, options_.jitter());
        if (retry.retry_after) {
            wait = std::max<milliseconds>(wait, *retry.retry_after);
        }
        if (waited + wait > kMaxRetryWaitPerCall) {
            give_up("; another wait would pass the " +
                    std::to_string(kMaxRetryWaitPerCall.count()) +
                    " s the Worker waits for one call");
        }
        log_debug(what + ": " + retry.summary + " on attempt " + std::to_string(attempt) +
                  "; retrying in " + std::to_string(wait.count()) + " ms");
        options_.sleep(wait);
        waited += wait;
        ++attempt;
        // A long wait can outlast the token.
        token = current_token();
    }
}

json GraphClient::get_json(std::string_view path_or_url, const Grant& grant)
{
    const HttpResponse response = get(path_or_url, grant);
    const std::string what = "Graph GET " + display_path(graph_url(path_or_url)) + ": HTTP " +
                             std::to_string(response.status);
    const std::string request_id = header_request_id(response);
    if (response.status >= 300) {
        throw GraphError(what + ", a redirect where JSON was expected" +
                             request_id_suffix(request_id),
                         response.status, {}, {}, request_id);
    }
    // Not const: the caller gets it moved.
    json doc = json::parse(response.body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        throw GraphError(what + ", but the reply isn't a JSON object" +
                             request_id_suffix(request_id),
                         response.status, {}, {}, request_id);
    }
    return doc;
}

HttpClientOptions graph_http_client_options(std::shared_ptr<spdlog::logger> logger)
{
    // Public hosts under public certificates: the Windows store, full checks.
    // Never a CA file or a pin (those are for Veeam's own certificate).
    HttpClientOptions options;
    options.logger = std::move(logger);
    return options;
}

std::unique_ptr<IHttpClient> make_graph_http_client(std::shared_ptr<spdlog::logger> logger)
{
    return std::make_unique<HttpClient>(graph_http_client_options(std::move(logger)));
}

} // namespace rp::graph
