#include <rp/veeam_client.hpp>

#include <rp/cert_export.hpp>
#include <rp/redact.hpp>
#include <rp/retry_policy.hpp>

#include "json_fields.hpp"
#include "text_util.hpp"
#include "uuid.hpp"
#include "veeam_time.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
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
constexpr int kMaxPageSize = 10000;
// A 401 with an empty body is followed by at most this many resends: with a
// newer token another caller brought, then with one fresh sign-in.
constexpr int kMaxUnauthorizedResends = 3;
// Full pages in a row that bring nothing new before paging gives up: a point
// added in front while the list is read repeats the last one on the next page,
// but a server that ignores offset repeats a page for ever.
constexpr int kMaxStalePages = 3;
// What an API request with a JSON body says it carries.
constexpr std::string_view kJsonContentType = "application/json; charset=utf-8";

bool is_blank(std::string_view text) noexcept
{
    return std::all_of(text.begin(), text.end(),
                       [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
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

// /v8/token's status as an error kind. Veeam has refused a sign-in with an
// empty 500 (veeam-notes §1.2), so a 500 there is a refusal whatever its body;
// any other status means what it means on any call (a 502, 503 or 504 is a
// gateway or a service starting up, not the credentials).
ErrorKind classify_token(int status, const ErrorBody& body) noexcept
{
    if (status == 500) {
        return ErrorKind::auth;
    }
    const ErrorKind kind = classify_api(status, body);
    return kind == ErrorKind::not_found ? ErrorKind::veeam : kind;
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

// The client gave up on a request after `attempts` attempts, the last of which
// got no response.
[[noreturn]] void throw_transport_error(const HttpError& e, int attempts)
{
    std::string message = std::string{"Veeam "} + e.what();
    if (attempts > 1) {
        message += " (" + std::to_string(attempts) + " attempts)";
    }
    switch (e.error()) {
    case TransportError::connect:
    case TransportError::dropped:
    case TransportError::timeout:
    case TransportError::handshake:
        throw TransientError(message, e.status());
    case TransportError::none:
        // Only with retry_on_status on, which this client never sends.
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

// An organisation's exchangeOnlineSettings or sharePointOnlineSettings app:
// set only with both strings there and not empty. A value of another JSON
// kind leaves it unset and says why in `problem` (the first such).
std::optional<OrganizationApp> optional_app(const json& item, const char* key,
                                            std::string& problem)
{
    const auto it = item.find(key);
    if (it == item.end() || it->is_null()) {
        return std::nullopt;
    }
    OrganizationApp app;
    try {
        if (!it->is_object()) {
            throw ShapeError("it isn't an object");
        }
        app.application_id = optional_string(*it, "applicationId");
        app.certificate_thumbprint = optional_string(*it, "applicationCertificateThumbprint");
    } catch (const ShapeError& e) {
        if (problem.empty()) {
            problem = std::string{key} + ": " + e.what();
        }
        return std::nullopt;
    }
    if (app.application_id.empty() || app.certificate_thumbprint.empty()) {
        return std::nullopt;
    }
    return app;
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

// Whether `path` is one of the API's own ("/v8/..."): the client puts
// base_url_ in front, so anything else would leave it.
void check_api_path(const std::string& path)
{
    if (!path.starts_with("/v8/")) {
        throw std::invalid_argument("a Veeam API path must start with /v8/");
    }
}

// The body of a 2xx as JSON, or a VeeamError naming the call.
template <typename Json>
Json parse_json_body(const HttpResponse& response, const std::string& what)
{
    Json doc = Json::parse(response.body, nullptr, false);
    if (doc.is_discarded()) {
        throw VeeamError(what + ": unexpected response: not JSON", response.status);
    }
    return doc;
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

HttpResponse VeeamClient::send_with_retries(HttpRequest request, const std::string& what,
                                            bool idempotent, int max_attempts, int& attempts)
{
    request.timeout = options_.timeout;
    // This client decides which failures are worth another attempt and counts
    // them: HttpClient retrying underneath would multiply its attempts by
    // these (25 requests for one GET).
    request.retry_on_status = false;
    request.max_attempts = 1;
    for (int attempt = 1;; ++attempt) {
        attempts = attempt;
        std::string reason;
        try {
            HttpResponse response = http_.send(request);
            // A GET changes nothing, so a transient 5xx can be sent again.
            if (!idempotent || !is_transient(response) || attempt >= max_attempts) {
                return response;
            }
            reason = "HTTP " + std::to_string(response.status);
        } catch (const HttpError& e) {
            // No connection or no handshake: the request never went out, so
            // even a token request can go again. After a timeout or a dropped
            // connection Veeam may have acted on it: only a GET is resent.
            const TransportError error = e.error();
            const bool unsent =
                error == TransportError::connect || error == TransportError::handshake;
            const bool worth_it = unsent || (idempotent && is_retryable(AttemptOutcome{error, 0}));
            if (!worth_it || attempt >= max_attempts) {
                throw_transport_error(e, attempt);
            }
            reason = std::string{"no response ("} + e.what() + ")";
        }
        const milliseconds wait = retry_delay(attempt, options_.jitter());
        log_debug(what + ": " + reason + " on attempt " + std::to_string(attempt) + "; retrying in " +
                  std::to_string(wait.count()) + " ms");
        options_.sleep(wait);
    }
}

HttpResponse VeeamClient::send_token_request(const std::string& form, int max_attempts)
{
    HttpRequest request;
    request.method = HttpMethod::post;
    request.url = base_url_ + "/v8/token";
    request.headers["Accept"] = "application/json";
    request.body = form;
    request.content_type = "application/x-www-form-urlencoded";
    // Never resent after it may have reached Veeam, and never on a 5xx: a
    // second password grant is a second logon (a wrong password counts twice
    // towards a lockout), a second refresh presents a used token.
    int attempts = 0;
    return send_with_retries(std::move(request), "Veeam POST /v8/token", false, max_attempts,
                             attempts);
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
    // A positive integer (the parser gives those the unsigned type, however
    // large); anything above kMaxTokenLifetime counts as that.
    const auto expires_in = doc.find("expires_in");
    if (expires_in == doc.end() || !expires_in->is_number_unsigned() ||
        expires_in->get<std::uint64_t>() == 0) {
        throw VeeamError(std::string{what} + "the response has no valid expires_in",
                         response.status);
    }
    const auto refresh = doc.find("refresh_token");
    const std::chrono::seconds lifetime{static_cast<std::int64_t>(std::min<std::uint64_t>(
        expires_in->get<std::uint64_t>(), static_cast<std::uint64_t>(kMaxTokenLifetime.count())))};
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
    // A token now works: an earlier failure is no answer for anyone.
    last_renewal_failure_ = nullptr;
    log_debug("Veeam: " + std::string{event} + "; the token expires in " +
              std::to_string(lifetime.count()) + " s");
}

void VeeamClient::record_failure_locked()
{
    last_renewal_failure_ = std::current_exception();
    ++renewal_failures_;
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
        record_failure_locked();
        throw;
    }
}

void VeeamClient::rethrow_failure_since_locked(std::uint64_t failures_seen) const
{
    // A renewal failed while this caller waited for the lock, and none has
    // succeeded since. Behind a server that is down, each attempt takes the
    // client's retries; N callers trying in turn would wait N times as long
    // for the same answer.
    if (renewal_failures_.load() != failures_seen && last_renewal_failure_) {
        std::rethrow_exception(last_renewal_failure_);
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
            const ErrorBody body = parse_error_body(response.body);
            if (classify_token(response.status, body) == ErrorKind::transient) {
                throw TransientError("Veeam POST /v8/token: " + describe(response.status, body),
                                     response.status, body.error_code);
            }
            log_debug("Veeam: token refresh failed (" + describe(response.status, body) +
                      "); signing in again");
        } catch (const TransientError&) {
            // Veeam can't be reached, or a gateway answers for it: a password
            // sign-in would spend the same retries on the same answer, with
            // every other caller waiting on the lock.
            record_failure_locked();
            throw;
        } catch (const VeeamError& e) {
            log_debug(std::string{"Veeam: token refresh failed ("} + e.what() +
                      "); signing in again");
        } catch (const std::exception&) {
            // Not ours, so its message may not be safe to log.
            log_debug("Veeam: token refresh failed; signing in again");
        }
    }
    // Veeam answered, and not with a token (a used or restart-killed refresh
    // token, a garbled answer): the password still works.
    login_locked();
}

void VeeamClient::renew_if_due_locked(std::uint64_t failures_seen)
{
    if (!access_token_.empty() && options_.now() < refresh_at_) {
        return;
    }
    // Only a caller that has to renew shares a failure: one that finds a
    // good token (another caller's success) uses it.
    rethrow_failure_since_locked(failures_seen);
    if (access_token_.empty()) {
        login_locked();
    } else {
        refresh_locked();
    }
}

VeeamClient::Token VeeamClient::current_token()
{
    const std::uint64_t failures_seen = renewal_failures_.load();
    const std::lock_guard lock(mutex_);
    renew_if_due_locked(failures_seen);
    return {access_token_, generation_, renewal_failures_.load()};
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
        std::string token;
        {
            const std::lock_guard lock(mutex_);
            if (access_token_.empty()) {
                return;
            }
            // Veeam refuses a logout with an expired access token, and the
            // refresh token it would end outlives it (veeam-notes §1.5): one
            // due for renewal is refreshed first. One try, no password
            // sign-in: a logout is best effort.
            if (options_.now() >= refresh_at_ && !refresh_token_.empty()) {
                try {
                    const HttpResponse response = send_token_request(
                        "grant_type=refresh_token&refresh_token=" + form_encode(refresh_token_) +
                            "&disable_antiforgery_token=true",
                        1);
                    if (response.status >= 200 && response.status <= 299) {
                        store_tokens_locked(response, "token refreshed for the logout");
                    } else {
                        log_debug("Veeam: token refresh before the logout answered HTTP " +
                                  std::to_string(response.status));
                    }
                } catch (const std::exception&) {
                    log_debug("Veeam: token refresh before the logout failed");
                }
            }
            // Forgotten first: whatever the answer, this chain is done with.
            token = std::exchange(access_token_, {});
            refresh_token_.clear();
            ++generation_;
        }

        HttpRequest request;
        request.method = HttpMethod::post;
        request.url = base_url_ + "/v8/token/logout";
        request.headers["Authorization"] = "Bearer " + token;
        request.headers["Accept"] = "application/json";
        request.timeout = options_.timeout;
        request.retry_on_status = false;
        request.max_attempts = 1;
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

HttpResponse VeeamClient::send_call(HttpMethod method, const std::string& path_and_query,
                                    const std::string& json_body, bool idempotent,
                                    const std::string& token, const std::string& what,
                                    int& attempts)
{
    HttpRequest request;
    request.method = method;
    request.url = base_url_ + path_and_query;
    request.headers["Authorization"] = "Bearer " + token;
    request.headers["Accept"] = "application/json";
    if (!json_body.empty()) {
        request.body = json_body;
        request.content_type = std::string{kJsonContentType};
    }
    return send_with_retries(std::move(request), what, idempotent, kMaxHttpAttempts, attempts);
}

HttpResponse VeeamClient::get(const std::string& path_and_query)
{
    return call(HttpMethod::get, path_and_query, {}, true);
}

HttpResponse VeeamClient::call(HttpMethod method, const std::string& path_and_query,
                               const std::string& json_body, bool idempotent)
{
    const std::string what = "Veeam " + std::string{to_string(method)} + " " + path_and_query;
    Token token = current_token();
    int attempts = 0;
    HttpResponse response =
        send_call(method, path_and_query, json_body, idempotent, token.access, what, attempts);

    // An empty 401 is a token Veeam no longer accepts: expired, revoked by a
    // refresh or logout, or killed by a REST service restart (veeam-notes
    // §1.3). A 401 with a message is the account's role: signing in again
    // wouldn't change it. A token another caller brought meanwhile is tried
    // first; one this call has to replace itself, once, with a fresh sign-in.
    bool signed_in = false;
    for (int resends = 0; response.status == 401 && is_blank(response.body); ++resends) {
        if (signed_in || resends == kMaxUnauthorizedResends) {
            const ErrorBody body = parse_error_body(response.body);
            throw AuthError(what + ": HTTP 401 again " +
                                (signed_in ? "after signing in afresh" : "with a newer token"),
                            401, body.error_code, response.body);
        }
        const std::string description = auth_description(response);
        const std::string reason = description.empty() ? "" : " (" + description + ")";
        {
            const std::lock_guard lock(mutex_);
            if (generation_ == token.generation || access_token_.empty()) {
                log_debug(what + ": HTTP 401" + reason + "; signing in again");
                rethrow_failure_since_locked(token.failures_seen);
                login_locked();
                signed_in = true;
            } else {
                // Someone refreshed or signed in since this token was handed
                // out, which revoked it: the current one is newer, though
                // perhaps itself near its end by now.
                log_debug(what + ": HTTP 401" + reason +
                          " for a replaced token; resending with the current one");
                renew_if_due_locked(token.failures_seen);
            }
            token = {access_token_, generation_, renewal_failures_.load()};
        }
        response =
            send_call(method, path_and_query, json_body, idempotent, token.access, what, attempts);
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
    int stale_pages = 0;
    for (std::size_t offset = 0;;) {
        const std::string page = path_and_query + separator + "limit=" +
                                 std::to_string(page_size) + "&offset=" + std::to_string(offset);
        const std::string what = "Veeam GET " + page;
        const HttpResponse response = get(page);
        // Not const: entries are moved out. Parsing and destroying a JSON
        // value are iterative, but copying one recurses once per level, and a
        // deeply nested value would overflow the stack.
        json doc = json::parse(response.body, nullptr, false);
        const auto results = doc.is_object() ? doc.find("results") : doc.end();
        if (!doc.is_object() || results == doc.end() || !results->is_array()) {
            throw VeeamError(what + ": unexpected response: no \"results\" list", response.status);
        }
        const std::size_t count = results->size();
        std::size_t added = 0;
        for (json& item : *results) {
            const auto id = item.is_object() ? item.find("id") : item.end();
            if (!item.is_object() || id == item.end() || !id->is_string() ||
                id->get_ref<const std::string&>().empty()) {
                throw VeeamError(what + ": unexpected response: an entry without an \"id\"",
                                 response.status);
            }
            // A point added while the list is read shifts later pages by one,
            // so an entry can come round twice.
            if (seen.insert(id->get<std::string>()).second) {
                items.push_back(std::move(item));
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
        if (count < applied) {
            return items;
        }
        stale_pages = added == 0 ? stale_pages + 1 : 0;
        if (stale_pages == kMaxStalePages) {
            throw VeeamError(what + ": " + std::to_string(kMaxStalePages) +
                                 " full pages in a row brought nothing new; paging stopped",
                             response.status);
        }
        offset += count;
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
            org.type = optional_string(item, "type");
            org.region = optional_string(item, "region");
            org.office_name = optional_string(item, "officeName");
            org.exchange_app = optional_app(item, "exchangeOnlineSettings", org.settings_problem);
            org.sharepoint_app =
                optional_app(item, "sharePointOnlineSettings", org.settings_problem);
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

    std::vector<std::pair<VeeamTime, RestorePoint>> keyed;
    keyed.reserve(items.size());
    try {
        for (const json& item : items) {
            RestorePoint point;
            point.id = required_string(item, "id");
            point.backup_time = optional_string(item, "backupTime");
            // Veeam writes UTC as "2026-09-25T19:37:15.2145203Z", dropping
            // trailing zeros of the fraction, so the text alone doesn't sort.
            const std::optional<VeeamTime> key = parse_veeam_time(point.backup_time);
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

json VeeamClient::get_json(const std::string& path)
{
    check_api_path(path);
    return parse_json_body<json>(get(path), "Veeam GET " + path);
}

nlohmann::ordered_json VeeamClient::get_ordered_json(const std::string& path)
{
    check_api_path(path);
    return parse_json_body<nlohmann::ordered_json>(get(path), "Veeam GET " + path);
}

std::vector<json> VeeamClient::get_all(const std::string& path)
{
    check_api_path(path);
    return get_all_pages(path);
}

std::string VeeamClient::open_explore_session(const std::string& organization_id,
                                              const std::string& backup_time,
                                              std::string_view type)
{
    if (!is_uuid(organization_id)) {
        throw std::invalid_argument("organisation ID must be a UUID");
    }
    if (!parse_veeam_time(backup_time)) {
        // Veeam answers 500 to any other form, and one earlier than the
        // point (truncated) opens the point before it (veeam-notes §4.2).
        throw std::invalid_argument(
            "an explore session's backup time must be a UTC time such as "
            "2026-09-25T19:37:15.2145203Z");
    }
    if (type != "Vex" && type != "Vesp" && type != "Veod") {
        throw std::invalid_argument("an explore session's type must be Vex, Vesp or Veod");
    }
    const std::string path = "/v8/Organizations/" + organization_id + "/explore";
    // Both strings were checked above: nothing in them needs escaping.
    const std::string body = R"({"dateTime":")" + backup_time + R"(","type":")" +
                             std::string{type} +
                             R"(","showDeleted":false,"showAllVersions":false})";
    const HttpResponse response = call(HttpMethod::post, path, body, false);
    const std::string what = "Veeam POST " + path;
    const json doc = parse_json_body<json>(response, what);
    const std::string* id = doc.is_object() ? string_at(doc, "id") : nullptr;
    if (id == nullptr || !is_uuid(*id)) {
        throw VeeamError(what + ": unexpected response: no session \"id\"", response.status);
    }
    // As GET /v8/RestoreSessions lists it, as post_restore_once keeps a
    // restore session's: the duplicate check and layer 2 compare in lower case.
    const std::string session = ascii_lower(*id);
    log_debug(what + ": explore session " + session + " opened");
    return session;
}

VeeamClient::RestorePostOutcome VeeamClient::post_restore_once(const std::string& path,
                                                               const std::string& body,
                                                               std::chrono::milliseconds timeout)
{
    check_api_path(path);
    if (timeout <= milliseconds::zero()) {
        throw std::invalid_argument("a restore POST's timeout must be above 0 ms");
    }
    const std::string what = "Veeam POST " + path;
    // Taken before the send: a failure here has sent nothing, and is thrown.
    const Token token = current_token();

    HttpRequest request;
    request.method = HttpMethod::post;
    request.url = base_url_ + path;
    request.headers["Authorization"] = "Bearer " + token.access;
    request.headers["Accept"] = "application/json";
    request.body = body;
    request.content_type = std::string{kJsonContentType};
    request.timeout = timeout;
    // One send and no more, whatever comes back: the restore must not run
    // twice (docs/decisions.md 2026-09-28 W2.4, 2026-09-30 W2.5).
    request.retry_on_status = false;
    request.max_attempts = 1;

    RestorePostOutcome out;
    HttpResponse response;
    try {
        response = http_.send(request);
    } catch (const HttpError& e) {
        // No connection or no handshake: nothing went out, as for any other
        // request (send_with_retries). After that, Veeam may have acted.
        const bool unsent =
            e.error() == TransportError::connect || e.error() == TransportError::handshake;
        out.kind = unsent ? RestorePostOutcome::Kind::not_sent : RestorePostOutcome::Kind::no_answer;
        out.status = e.status();
        out.message = redact(one_line(what + (unsent ? ": not sent (" : ": no answer (") +
                                      e.what() + ")"));
    } catch (const std::exception&) {
        // Not ours, so its message may not be safe to show; and the request
        // may have gone out.
        out.kind = RestorePostOutcome::Kind::no_answer;
        out.message = redact(one_line(what + ": no answer (the send failed)"));
    }
    // The request held the certificate: gone before anything else happens.
    secure_wipe(request.body);
    if (!out.message.empty()) {
        log_debug(out.message);
        return out;
    }

    out.status = response.status;
    const ErrorBody error = parse_error_body(response.body);
    out.error_code = error.error_code;
    if (response.status >= 200 && response.status <= 299) {
        const json doc = json::parse(response.body, nullptr, false);
        const std::string* id =
            !doc.is_discarded() && doc.is_object() ? string_at(doc, "sessionId") : nullptr;
        if (id != nullptr && is_uuid(*id)) {
            out.kind = RestorePostOutcome::Kind::accepted;
            // As GET /v8/RestoreSessions lists it, for the duplicate check.
            out.session_id = ascii_lower(*id);
            out.message = what + ": HTTP " + std::to_string(response.status) +
                          ", restore session " + out.session_id;
        } else {
            out.kind = RestorePostOutcome::Kind::no_answer;
            out.message = what + ": HTTP " + std::to_string(response.status) +
                          " without a restore session ID";
        }
    } else if (response.status >= 400 && response.status <= 499) {
        out.kind = RestorePostOutcome::Kind::refused;
        out.message = what + ": " + describe(response.status, error);
    } else {
        out.kind = RestorePostOutcome::Kind::no_answer;
        out.message = what + ": " + describe(response.status, error);
    }
    out.message = redact(one_line(out.message));
    log_debug(out.message);
    return out;
}

VeeamClient::ExportAnswer VeeamClient::export_document(const std::string& path,
                                                       std::chrono::milliseconds timeout,
                                                       std::uint64_t max_bytes)
{
    check_api_path(path);
    if (!path.ends_with("/save")) {
        throw std::invalid_argument("a document export's path must end with /save");
    }
    if (timeout <= milliseconds::zero()) {
        throw std::invalid_argument("a document export's timeout must be above 0 ms");
    }
    if (max_bytes == 0) {
        throw std::invalid_argument("a document export's cap must be above 0 bytes");
    }
    const std::string what = "Veeam POST " + path;
    // Taken before the send: a failure here has sent nothing, and is thrown.
    const Token token = current_token();

    HttpRequest request;
    request.method = HttpMethod::post;
    request.url = base_url_ + path;
    request.headers["Authorization"] = "Bearer " + token.access;
    // As the spike sent it and was answered (veeam-notes §12.1); the
    // answer's type is what the caller holds.
    request.headers["Accept"] = "*/*";
    request.body = R"({"asZip":false})";
    request.content_type = std::string{kJsonContentType};
    request.timeout = timeout;
    request.max_body_bytes = max_bytes;
    // One send and no more, whatever comes back.
    request.retry_on_status = false;
    request.max_attempts = 1;

    ExportAnswer out;
    HttpResponse response;
    try {
        response = http_.send(request);
    } catch (const HttpError& e) {
        out.message = redact(one_line(what + ": no answer (" + e.what() + ")"));
    } catch (const std::exception&) {
        // Not ours, so its message may not be safe to show.
        out.message = redact(one_line(what + ": no answer (the send failed)"));
    }
    if (!out.message.empty()) {
        log_debug(out.message);
        return out;
    }

    out.status = response.status;
    if (const auto it = response.headers.find("Content-Type"); it != response.headers.end()) {
        out.content_type = it->second;
    }
    if (response.status >= 200 && response.status <= 299) {
        out.body = std::move(response.body);
        out.message = what + ": HTTP " + std::to_string(response.status) + ", " +
                      std::to_string(out.body.size()) + " byte(s)";
    } else {
        const ErrorBody error = parse_error_body(response.body);
        out.error_code = error.error_code;
        out.message = what + ": " + describe(response.status, error);
    }
    out.message = redact(one_line(out.message));
    log_debug(out.message);
    return out;
}

void VeeamClient::stop_session(const std::string& session_id)
{
    if (!is_uuid(session_id)) {
        throw std::invalid_argument("a restore session ID must be a UUID");
    }
    const std::string path = "/v8/RestoreSessions/" + session_id + "/Stop";
    call(HttpMethod::post, path, {}, false);
    log_debug("Veeam POST " + path + ": session stopped");
}

} // namespace rp
