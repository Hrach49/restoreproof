#include <rp/veeam_client.hpp>

#include <rp/redact.hpp>
#include <rp/retry_policy.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <thread>
#include <tuple>
#include <utility>

namespace rp {

namespace {

using nlohmann::json;
using std::chrono::milliseconds;

// ensure_token() refreshes when this little is left: Veeam allows no clock
// skew past a token's expiry (docs/api/veeam-notes.md §1.5).
constexpr std::chrono::seconds kRefreshMargin{60};
// A token lifetime above this is taken as this: Veeam gives 3600 s, and no
// later arithmetic on the clock can overflow.
constexpr std::chrono::seconds kMaxTokenLifetime{86400};
// Veeam's messages are a sentence; anything longer is cut, so a strange
// response can't flood a log line.
constexpr std::size_t kMaxMessageChars = 500;
constexpr int kMaxPageSize = 10000;

// Percent-encoding for an application/x-www-form-urlencoded value: every byte
// but ASCII letters, digits and -._~ becomes %XX, so a password may hold any
// character.
std::string form_encode(std::string_view text)
{
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(text.size() * 3);
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
            byte == '~') {
            out += c;
        } else {
            out += '%';
            out += hex[byte >> 4];
            out += hex[byte & 0x0F];
        }
    }
    return out;
}

bool is_hex(char c) noexcept
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// 8-4-4-4-12 hex digits, nothing else: safe to put in a URL as it is.
bool is_uuid(std::string_view id) noexcept
{
    if (id.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < id.size(); ++i) {
        const bool dash_here = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash_here ? id[i] != '-' : !is_hex(id[i])) {
            return false;
        }
    }
    return true;
}

bool is_blank(std::string_view text) noexcept
{
    return std::all_of(text.begin(), text.end(),
                       [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
}

// Text from a response, made fit for one log line: control characters become
// spaces, and it is cut at kMaxMessageChars bytes, back to the start of a
// UTF-8 character so none is split.
std::string one_line(std::string_view text)
{
    std::size_t cut = std::min(text.size(), kMaxMessageChars);
    if (cut < text.size()) {
        while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80) {
            --cut;
        }
    }
    std::string out{text.substr(0, cut)};
    std::replace_if(
        out.begin(), out.end(),
        [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7F; }, ' ');
    if (text.size() > kMaxMessageChars) {
        out += "...";
    }
    return out;
}

// What an error response says. Veeam's own shape is {"message", "errorCode"?};
// query-string binding errors come in ASP.NET's ProblemDetails instead
// ({"title", "errors": {"<name>": ["..."]}}) (veeam-notes §8).
struct ErrorBody {
    std::string message;
    std::string error_code;
    // A JSON object with a string "message": Veeam reporting an error, as
    // opposed to a proxy or a crash answering for it.
    bool veeam_message = false;
};

ErrorBody parse_error_body(std::string_view body)
{
    ErrorBody out;
    const json doc = json::parse(body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        return out;
    }
    if (const auto code = doc.find("errorCode"); code != doc.end() && code->is_string()) {
        out.error_code = one_line(code->get_ref<const std::string&>());
    }
    if (const auto message = doc.find("message"); message != doc.end() && message->is_string()) {
        out.message = one_line(message->get_ref<const std::string&>());
        out.veeam_message = true;
        return out;
    }
    if (const auto title = doc.find("title"); title != doc.end() && title->is_string()) {
        std::string text = title->get_ref<const std::string&>();
        if (const auto errors = doc.find("errors"); errors != doc.end() && errors->is_object()) {
            for (const auto& [name, list] : errors->items()) {
                text += " " + name + ":";
                for (const json& item : list) {
                    if (item.is_string()) {
                        text += " " + item.get<std::string>();
                    }
                }
            }
        }
        out.message = one_line(text);
    }
    return out;
}

enum class ErrorKind { auth, not_found, transient, veeam };

// An API call's status (after the 401 recovery) as an error kind.
ErrorKind classify_api(int status, const ErrorBody& body) noexcept
{
    if (status == 401 || status == 403 || body.error_code == "ResourceAccessDenied") {
        return ErrorKind::auth;
    }
    if (status == 404 && body.error_code == "ResourceNotFound") {
        return ErrorKind::not_found;
    }
    // Gateways and a service starting up answer these, whatever the body.
    if (status == 502 || status == 503 || status == 504) {
        return ErrorKind::transient;
    }
    // Veeam answers 500 with a message for many requests that will never
    // succeed; a 5xx without one isn't Veeam deciding anything.
    if (status >= 500 && status <= 599) {
        return body.veeam_message ? ErrorKind::veeam : ErrorKind::transient;
    }
    return ErrorKind::veeam;
}

// /v8/token's status as an error kind: Veeam has refused a sign-in with an
// empty 500 (veeam-notes §1.2), so no 5xx there is transient.
ErrorKind classify_token(int status, const ErrorBody& body) noexcept
{
    if (status == 401 || status == 403 || (status >= 500 && status <= 599) ||
        body.error_code == "ResourceAccessDenied") {
        return ErrorKind::auth;
    }
    return ErrorKind::veeam;
}

// "HTTP 404 (ResourceNotFound): Organization does not exist: ..."
std::string describe(int status, const ErrorBody& body)
{
    std::string out = "HTTP " + std::to_string(status);
    if (!body.error_code.empty()) {
        out += " (" + body.error_code + ")";
    }
    if (!body.message.empty()) {
        out += ": " + body.message;
    }
    return out;
}

[[noreturn]] void throw_error(ErrorKind kind, const std::string& message, int status,
                              const ErrorBody& parsed, const std::string& body)
{
    switch (kind) {
    case ErrorKind::auth:
        throw AuthError(message, status, parsed.error_code, body);
    case ErrorKind::not_found:
        throw NotFoundError(message, status, parsed.error_code, body);
    case ErrorKind::transient:
        throw TransientError(message, status, parsed.error_code, body);
    case ErrorKind::veeam:
        break;
    }
    throw VeeamError(message, status, parsed.error_code, body);
}

// HttpClient gave up: it has already retried what can be retried.
[[noreturn]] void throw_transport_error(const HttpError& e)
{
    const std::string message = std::string{"Veeam "} + e.what();
    switch (e.error()) {
    case TransportError::connect:
    case TransportError::timeout:
    case TransportError::handshake:
        throw TransientError(message, e.status());
    case TransportError::none:
        // Only with retry_on_status on, which this client never sends: a 5xx
        // after every retry.
        throw TransientError(message, e.status());
    case TransportError::tls:
    case TransportError::other:
        break;
    }
    throw VeeamError(message, e.status());
}

// Whether a GET that got `response` is worth another attempt.
bool is_transient(const HttpResponse& response)
{
    return response.status >= 500 && response.status <= 599 &&
           classify_api(response.status, parse_error_body(response.body)) ==
               ErrorKind::transient;
}

// WWW-Authenticate's error_description, which only an expired token carries
// ("The token expired at '...'") and which isn't secret; empty if none.
std::string auth_description(const HttpResponse& response)
{
    const auto header = response.headers.find("WWW-Authenticate");
    if (header == response.headers.end()) {
        return {};
    }
    constexpr std::string_view key = "error_description=\"";
    const std::size_t start = header->second.find(key);
    if (start == std::string::npos) {
        return {};
    }
    const std::size_t from = start + key.size();
    const std::size_t end = header->second.find('"', from);
    return one_line(std::string_view{header->second}.substr(from, end - from));
}

// Reading one entry of a list. Messages name the field, never a value.
class ShapeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string required_string(const json& item, const char* key)
{
    const auto it = item.find(key);
    if (it == item.end() || !it->is_string() || it->get_ref<const std::string&>().empty()) {
        throw ShapeError(std::string{"an entry without a \""} + key + "\"");
    }
    return it->get<std::string>();
}

std::string optional_string(const json& item, const char* key)
{
    const auto it = item.find(key);
    if (it == item.end() || it->is_null()) {
        return {};
    }
    if (!it->is_string()) {
        throw ShapeError(std::string{"\""} + key + "\" isn't a string");
    }
    return it->get<std::string>();
}

bool optional_bool(const json& item, const char* key)
{
    const auto it = item.find(key);
    if (it == item.end() || it->is_null()) {
        return false;
    }
    if (!it->is_boolean()) {
        throw ShapeError(std::string{"\""} + key + "\" isn't true or false");
    }
    return it->get<bool>();
}

// A backupTime as a sortable value: year, month, day, hour, minute, second,
// then the fraction in 100 ns ticks. Veeam writes UTC as
// "2026-09-25T19:37:15.2145203Z", dropping trailing zeros of the fraction
// (and the '.' with them), so the text alone doesn't sort. Anything else
// (an offset, no zone, more than 7 digits) is refused: explore sessions are
// opened by this exact string, and Veeam answers 500 to any other form.
using TimeKey = std::array<int, 7>;

std::optional<TimeKey> parse_backup_time(std::string_view text)
{
    const auto digits = [text](std::size_t at, std::size_t count) -> std::optional<int> {
        if (at + count > text.size()) {
            return std::nullopt;
        }
        int value = 0;
        for (std::size_t i = at; i < at + count; ++i) {
            if (text[i] < '0' || text[i] > '9') {
                return std::nullopt;
            }
            value = value * 10 + (text[i] - '0');
        }
        return value;
    };
    // YYYY-MM-DDTHH:MM:SS
    constexpr std::array<std::pair<std::size_t, char>, 5> separators{
        {{4, '-'}, {7, '-'}, {10, 'T'}, {13, ':'}, {16, ':'}}};
    if (text.size() < 20 || text.back() != 'Z') {
        return std::nullopt;
    }
    for (const auto& [at, c] : separators) {
        if (text[at] != c) {
            return std::nullopt;
        }
    }
    const auto year = digits(0, 4);
    const auto month = digits(5, 2);
    const auto day = digits(8, 2);
    const auto hour = digits(11, 2);
    const auto minute = digits(14, 2);
    const auto second = digits(17, 2);
    if (!year || !month || !day || !hour || !minute || !second || *month < 1 || *month > 12 ||
        *day < 1 || *day > 31 || *hour > 23 || *minute > 59 || *second > 59) {
        return std::nullopt;
    }
    int ticks = 0;
    const std::size_t rest = text.size() - 20; // between the seconds and 'Z'
    if (rest > 0) {
        // '.' and 1 to 7 digits.
        const std::size_t count = rest - 1;
        const auto fraction = digits(20, count);
        if (text[19] != '.' || count < 1 || count > 7 || !fraction) {
            return std::nullopt;
        }
        ticks = *fraction;
        for (std::size_t i = count; i < 7; ++i) {
            ticks *= 10;
        }
    } else if (text[19] != 'Z') {
        return std::nullopt;
    }
    return TimeKey{*year, *month, *day, *hour, *minute, *second, ticks};
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

} // namespace

VeeamError::VeeamError(std::string_view message, int status, std::string error_code,
                       std::string body)
    : std::runtime_error(redact(message)), status_(status), error_code_(std::move(error_code)),
      body_(std::move(body))
{
}

int VeeamError::status() const noexcept
{
    return status_;
}

const std::string& VeeamError::error_code() const noexcept
{
    return error_code_;
}

const std::string& VeeamError::body() const noexcept
{
    return body_;
}

VeeamClient::VeeamClient(IHttpClient& http, std::string base_url, std::string username,
                         std::string password, VeeamClientOptions options)
    : http_(http), base_url_(std::move(base_url)), username_(std::move(username)),
      password_(std::move(password)), options_(std::move(options))
{
    while (!base_url_.empty() && base_url_.back() == '/') {
        base_url_.pop_back();
    }
    // The password grant goes to this URL: never over plain HTTP. Config
    // checks veeam_url the same way; this holds for any other caller too.
    constexpr std::string_view https = "https://";
    const bool is_https =
        base_url_.size() > https.size() &&
        std::equal(https.begin(), https.end(), base_url_.begin(), [](char a, char b) {
            return a == (b >= 'A' && b <= 'Z' ? static_cast<char>(b - 'A' + 'a') : b);
        });
    if (!is_https || username_.empty() || password_.empty()) {
        throw std::invalid_argument(
            "VeeamClient needs an https:// URL, a username and a password");
    }
    if (options_.page_size < 1 || options_.page_size > kMaxPageSize) {
        throw std::invalid_argument("VeeamClient page_size must be from 1 to 10000");
    }
    if (options_.timeout <= milliseconds::zero()) {
        throw std::invalid_argument("VeeamClient timeout must be above 0 ms");
    }
    if (!options_.now) {
        options_.now = [] { return std::chrono::steady_clock::now(); };
    }
    if (!options_.sleep) {
        options_.sleep = [](milliseconds wait) { std::this_thread::sleep_for(wait); };
    }
    if (!options_.jitter) {
        options_.jitter = default_jitter();
    }
}

void VeeamClient::log_debug(const std::string& line) const
{
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger =
        options_.logger ? options_.logger : spdlog::default_logger();
    if (logger && logger->should_log(spdlog::level::debug)) {
        logger->debug("{}", redact(line));
    }
}

HttpResponse VeeamClient::send_token_request(const std::string& form)
{
    HttpRequest request;
    request.method = HttpMethod::post;
    request.url = base_url_ + "/v8/token";
    request.headers["Accept"] = "application/json";
    request.body = form;
    request.content_type = "application/x-www-form-urlencoded";
    request.timeout = options_.timeout;
    // Never retried on a 5xx: Veeam has answered a refused sign-in with one.
    request.retry_on_status = false;
    try {
        return http_.send(request);
    } catch (const HttpError& e) {
        throw_transport_error(e);
    }
}

void VeeamClient::store_tokens_locked(const HttpResponse& response, std::string_view event)
{
    // The body holds the tokens: no message below may quote it, and no error
    // keeps it.
    constexpr std::string_view what = "Veeam POST /v8/token: ";
    const json doc = json::parse(response.body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        throw VeeamError(std::string{what} + "the response isn't a JSON object", response.status);
    }
    const auto access = doc.find("access_token");
    if (access == doc.end() || !access->is_string() ||
        access->get_ref<const std::string&>().empty()) {
        throw VeeamError(std::string{what} + "the response has no access_token", response.status);
    }
    const auto expires_in = doc.find("expires_in");
    if (expires_in == doc.end() || !expires_in->is_number_integer() ||
        expires_in->get<std::int64_t>() <= 0) {
        throw VeeamError(std::string{what} + "the response has no valid expires_in",
                         response.status);
    }
    const auto refresh = doc.find("refresh_token");
    const std::chrono::seconds lifetime{
        std::min<std::int64_t>(expires_in->get<std::int64_t>(), kMaxTokenLifetime.count())};
    // A lifetime of twice the margin or less is refreshed at its half, so a
    // short-lived token isn't refreshed on every call.
    const std::chrono::milliseconds margin =
        std::min<std::chrono::milliseconds>(kRefreshMargin, milliseconds{lifetime} / 2);

    // Built first, then swapped in without anything that can throw, so a
    // failure leaves the old pair whole.
    std::string new_access = access->get<std::string>();
    // Without one, the next renewal is a password sign-in.
    std::string new_refresh =
        refresh != doc.end() && refresh->is_string() ? refresh->get<std::string>() : std::string{};
    // Counted from now, on the local clock: `.expires` is the server's clock.
    const auto refresh_at = options_.now() + lifetime - margin;
    access_token_.swap(new_access);
    refresh_token_.swap(new_refresh);
    refresh_at_ = refresh_at;
    ++generation_;
    log_debug("Veeam: " + std::string{event} + "; the token expires in " +
              std::to_string(lifetime.count()) + " s");
}

void VeeamClient::login_locked()
{
    try {
        const HttpResponse response =
            send_token_request("grant_type=password&username=" + form_encode(username_) +
                               "&password=" + form_encode(password_) +
                               "&disable_antiforgery_token=true");
        if (response.status < 200 || response.status > 299) {
            // The body isn't kept: a proxy or a broken server could echo the
            // posted form, password included.
            const ErrorBody body = parse_error_body(response.body);
            throw_error(classify_token(response.status, body),
                        "Veeam POST /v8/token: " + describe(response.status, body),
                        response.status, body, {});
        }
        store_tokens_locked(response, "signed in");
    } catch (...) {
        last_sign_in_failure_ = std::current_exception();
        ++sign_in_failures_;
        throw;
    }
}

void VeeamClient::rethrow_failure_since_locked(std::uint64_t failures_seen) const
{
    // A sign-in failed while this caller waited for the lock. Behind a server
    // that is down, each attempt takes HttpClient's five tries; N callers
    // trying in turn would wait N times as long for the same answer.
    if (sign_in_failures_.load() != failures_seen && last_sign_in_failure_) {
        std::rethrow_exception(last_sign_in_failure_);
    }
}

void VeeamClient::refresh_locked()
{
    if (!refresh_token_.empty()) {
        // A refresh revokes the access token it replaces at once, and the
        // refresh token is single-use, so both are swapped together here,
        // under the lock every caller takes (veeam-notes §1.4).
        try {
            const HttpResponse response = send_token_request(
                "grant_type=refresh_token&refresh_token=" + form_encode(refresh_token_) +
                "&disable_antiforgery_token=true");
            if (response.status >= 200 && response.status <= 299) {
                store_tokens_locked(response, "token refreshed");
                return;
            }
            log_debug("Veeam: token refresh failed (" +
                      describe(response.status, parse_error_body(response.body)) +
                      "); signing in again");
        } catch (const VeeamError& e) {
            log_debug(std::string{"Veeam: token refresh failed ("} + e.what() +
                      "); signing in again");
        } catch (const std::exception&) {
            // Not ours, so its message may not be safe to log.
            log_debug("Veeam: token refresh failed; signing in again");
        }
    }
    // Whatever went wrong (a used or restart-killed refresh token, Veeam
    // restarting, a garbled answer), the password still works.
    login_locked();
}

VeeamClient::Token VeeamClient::current_token()
{
    const std::uint64_t failures_seen = sign_in_failures_.load();
    const std::lock_guard lock(mutex_);
    rethrow_failure_since_locked(failures_seen);
    if (access_token_.empty()) {
        login_locked();
    } else if (options_.now() >= refresh_at_) {
        refresh_locked();
    }
    return {access_token_, generation_};
}

void VeeamClient::login()
{
    const std::lock_guard lock(mutex_);
    login_locked();
}

void VeeamClient::ensure_token()
{
    current_token();
}

void VeeamClient::logout() noexcept
{
    try {
        const std::lock_guard lock(mutex_);
        if (access_token_.empty()) {
            return;
        }
        // Forgotten first: whatever the answer, this chain is done with.
        const std::string token = std::exchange(access_token_, {});
        refresh_token_.clear();
        ++generation_;

        HttpRequest request;
        request.method = HttpMethod::post;
        request.url = base_url_ + "/v8/token/logout";
        request.headers["Authorization"] = "Bearer " + token;
        request.headers["Accept"] = "application/json";
        request.timeout = options_.timeout;
        request.retry_on_status = false;
        try {
            const HttpResponse response = http_.send(request);
            if (response.status >= 200 && response.status <= 299) {
                log_debug("Veeam: logged out");
            } else {
                log_debug("Veeam: logout answered HTTP " + std::to_string(response.status) +
                          "; the tokens are forgotten anyway");
            }
        } catch (const HttpError& e) {
            log_debug(std::string{"Veeam: logout failed ("} + e.what() +
                      "); the tokens are forgotten anyway");
        }
    } catch (...) {
        // Best effort, and callable from cleanup paths: never throws.
    }
}

HttpResponse VeeamClient::send_get(const std::string& path_and_query, const std::string& token,
                                   const std::string& what, int& attempts)
{
    HttpRequest request;
    request.method = HttpMethod::get;
    request.url = base_url_ + path_and_query;
    request.headers["Authorization"] = "Bearer " + token;
    request.headers["Accept"] = "application/json";
    request.timeout = options_.timeout;
    // This client decides which 5xx are worth another attempt.
    request.retry_on_status = false;
    for (int attempt = 1;; ++attempt) {
        HttpResponse response;
        try {
            response = http_.send(request);
        } catch (const HttpError& e) {
            throw_transport_error(e);
        }
        // A GET changes nothing, so a transient 5xx can be sent again, as
        // HttpClient would for any 5xx.
        if (is_transient(response) && attempt < kMaxHttpAttempts) {
            const milliseconds wait = retry_delay(attempt, options_.jitter());
            log_debug(what + ": HTTP " + std::to_string(response.status) + " on attempt " +
                      std::to_string(attempt) + "; retrying in " + std::to_string(wait.count()) +
                      " ms");
            options_.sleep(wait);
            continue;
        }
        attempts = attempt;
        return response;
    }
}

HttpResponse VeeamClient::get(const std::string& path_and_query)
{
    const std::string what = "Veeam GET " + path_and_query;
    Token token = current_token();
    int attempts = 0;
    HttpResponse response = send_get(path_and_query, token.access, what, attempts);

    // An empty 401 is a token Veeam no longer accepts: expired, revoked by a
    // refresh or logout, or killed by a REST service restart (veeam-notes
    // §1.3). A 401 with a message is the account's role: signing in again
    // wouldn't change it.
    if (response.status == 401 && is_blank(response.body)) {
        const std::string description = auth_description(response);
        const std::string reason = description.empty() ? "" : " (" + description + ")";
        bool signed_in = false;
        const std::uint64_t failures_seen = sign_in_failures_.load();
        {
            const std::lock_guard lock(mutex_);
            rethrow_failure_since_locked(failures_seen);
            if (generation_ == token.generation || access_token_.empty()) {
                log_debug(what + ": HTTP 401" + reason + "; signing in again");
                login_locked();
                signed_in = true;
            } else {
                // Someone refreshed or signed in since this token was handed
                // out, which revoked it: the current one is newer, though
                // perhaps itself near its end by now.
                log_debug(what + ": HTTP 401" + reason +
                          " for a replaced token; resending with the current one");
                if (options_.now() >= refresh_at_) {
                    refresh_locked();
                }
            }
            token = {access_token_, generation_};
        }
        response = send_get(path_and_query, token.access, what, attempts);
        if (response.status == 401) {
            const ErrorBody body = parse_error_body(response.body);
            throw AuthError(what + ": HTTP 401 again " +
                                (signed_in ? "after signing in afresh" : "with a newer token"),
                            401, body.error_code, response.body);
        }
    }

    if (response.status >= 200 && response.status <= 299) {
        return response;
    }
    const ErrorBody body = parse_error_body(response.body);
    const ErrorKind kind = classify_api(response.status, body);
    std::string detail = describe(response.status, body);
    if (attempts > 1) {
        detail += " after " + std::to_string(attempts) + " attempts";
    }
    throw_error(kind, what + ": " + detail, response.status, body, response.body);
}

std::vector<json> VeeamClient::get_all_pages(const std::string& path_and_query)
{
    const char separator = path_and_query.find('?') == std::string::npos ? '?' : '&';
    const auto page_size = static_cast<std::size_t>(options_.page_size);
    std::vector<json> items;
    std::set<std::string> seen;
    for (std::size_t offset = 0;;) {
        const std::string page = path_and_query + separator + "limit=" +
                                 std::to_string(page_size) + "&offset=" + std::to_string(offset);
        const std::string what = "Veeam GET " + page;
        const HttpResponse response = get(page);
        const json doc = json::parse(response.body, nullptr, false);
        const auto results = doc.is_object() ? doc.find("results") : doc.end();
        if (!doc.is_object() || results == doc.end() || !results->is_array()) {
            throw VeeamError(what + ": unexpected response: no \"results\" list", response.status);
        }
        std::size_t added = 0;
        for (const json& item : *results) {
            const auto id = item.is_object() ? item.find("id") : item.end();
            if (!item.is_object() || id == item.end() || !id->is_string() ||
                id->get_ref<const std::string&>().empty()) {
                throw VeeamError(what + ": unexpected response: an entry without an \"id\"",
                                 response.status);
            }
            // A point added while the list is read shifts later pages by one,
            // so an entry can come round twice.
            if (seen.insert(id->get<std::string>()).second) {
                items.push_back(item);
                ++added;
            }
        }
        // Veeam echoes the limit it applied. Should it ever cap the one asked
        // for, a page of its size isn't the end, and stopping there would cut
        // the list short without a word.
        std::size_t applied = page_size;
        if (const auto limit = doc.find("limit");
            limit != doc.end() && limit->is_number_unsigned() && limit->get<std::uint64_t>() > 0 &&
            limit->get<std::uint64_t>() < page_size) {
            applied = static_cast<std::size_t>(limit->get<std::uint64_t>());
        }
        if (results->size() < applied) {
            return items;
        }
        // A full page of nothing new: the server isn't honouring offset.
        if (added == 0) {
            throw VeeamError(what + ": the page repeats earlier results; paging stopped",
                             response.status);
        }
        offset += results->size();
    }
}

std::vector<Organization> VeeamClient::list_organizations()
{
    const std::string path = "/v8/Organizations";
    const std::vector<json> items = get_all_pages(path);
    std::vector<Organization> out;
    out.reserve(items.size());
    try {
        for (const json& item : items) {
            Organization org;
            org.id = required_string(item, "id");
            org.name = required_string(item, "name");
            org.msid = optional_string(item, "msid");
            org.region = optional_string(item, "region");
            org.office_name = optional_string(item, "officeName");
            out.push_back(std::move(org));
        }
    } catch (const ShapeError& e) {
        throw VeeamError("Veeam GET " + path + ": unexpected response: " + e.what(), 200);
    }
    return out;
}

std::vector<RestorePoint> VeeamClient::list_restore_points(const std::string& organization_id)
{
    if (!is_uuid(organization_id)) {
        // Veeam reads a malformed ID as the all-zero GUID (veeam-notes §2.1);
        // and a checked UUID needs no escaping in the query string.
        throw std::invalid_argument("organisation ID must be a UUID");
    }
    const std::string path = "/v8/RestorePoints?organizationId=" + organization_id;
    const std::vector<json> items = get_all_pages(path);

    std::vector<std::pair<TimeKey, RestorePoint>> keyed;
    keyed.reserve(items.size());
    try {
        for (const json& item : items) {
            RestorePoint point;
            point.id = required_string(item, "id");
            point.backup_time = optional_string(item, "backupTime");
            const std::optional<TimeKey> key = parse_backup_time(point.backup_time);
            if (!key) {
                throw VeeamError("Veeam GET " + path + ": restore point " + one_line(point.id) +
                                     " has a backupTime that isn't a UTC time such as "
                                     "2026-09-25T19:37:15.2145203Z: \"" +
                                     one_line(point.backup_time) + "\"",
                                 200);
            }
            point.organization_id = optional_string(item, "organizationId");
            point.repository_id = optional_string(item, "repositoryId");
            point.job_id = optional_string(item, "jobId");
            point.is_exchange = optional_bool(item, "isExchange");
            point.is_sharepoint = optional_bool(item, "isSharePoint");
            point.is_onedrive = optional_bool(item, "isOneDrive");
            point.is_teams = optional_bool(item, "isTeams");
            point.is_deleted = optional_bool(item, "isDeleted");
            point.is_long_term_copy = optional_bool(item, "isLongTermCopy");
            point.is_copy = optional_bool(item, "isCopy");
            keyed.emplace_back(*key, std::move(point));
        }
    } catch (const ShapeError& e) {
        throw VeeamError("Veeam GET " + path + ": unexpected response: " + e.what(), 200);
    }

    // Newest first by time, whatever order Veeam used; equal times by ID, so
    // the order is the same on every call.
    std::sort(keyed.begin(), keyed.end(), [](const auto& a, const auto& b) {
        return std::tie(b.first, a.second.id) < std::tie(a.first, b.second.id);
    });
    std::vector<RestorePoint> out;
    out.reserve(keyed.size());
    for (auto& [key, point] : keyed) {
        out.push_back(std::move(point));
    }
    return out;
}

} // namespace rp
