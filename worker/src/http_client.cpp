#include <rp/http_client.hpp>

#include <rp/redact.hpp>

#include "http_client_detail.hpp"

#include <cpr/cpr.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <mutex>
#include <random>
#include <thread>
#include <utility>

namespace rp {

namespace detail {

cpr::SslOptions make_ssl_options(const std::optional<std::string>& ca_file)
{
    cpr::SslOptions options;
    options.verify_peer = true;
    options.verify_host = true;
    if (ca_file) {
        // The UTF-8 bytes go straight to CURLOPT_CAINFO, which curl's Schannel
        // backend reads as UTF-8. cpr::ssl::CaInfo would take a path and call
        // path::string(), converting to the ANSI code page and mangling any
        // character outside it.
        options.ca_info = *ca_file;
    }
    return options;
}

TransportError classify(cpr::ErrorCode code) noexcept
{
    using E = cpr::ErrorCode;
    switch (code) {
    case E::OK:
        return TransportError::none;
    // No connection, or it dropped before a whole response arrived: the
    // server (or the network to it) may be back on a later attempt.
    case E::COULDNT_RESOLVE_PROXY:
    case E::COULDNT_RESOLVE_HOST:
    case E::COULDNT_CONNECT:
    case E::SEND_ERROR:
    case E::RECV_ERROR:
    case E::GOT_NOTHING:
    case E::PARTIAL_FILE:
    case E::NO_CONNECTION_AVAILABLE:
        return TransportError::connect;
    case E::OPERATION_TIMEDOUT:
        return TransportError::timeout;
    // A TLS or certificate problem doesn't fix itself between attempts, and
    // retrying would only hide it.
    case E::SSL_CONNECT_ERROR:
    case E::SSL_ENGINE_NOTFOUND:
    case E::SSL_ENGINE_SETFAILED:
    case E::SSL_CERTPROBLEM:
    case E::SSL_CIPHER:
    case E::PEER_FAILED_VERIFICATION:
    case E::USE_SSL_FAILED:
    case E::SSL_ENGINE_INITFAILED:
    case E::SSL_CACERT_BADFILE:
    case E::SSL_SHUTDOWN_FAILED:
    case E::SSL_CRL_BADFILE:
    case E::SSL_ISSUER_ERROR:
    case E::SSL_PINNEDPUBKEYNOTMATCH:
    case E::SSL_INVALIDCERTSTATUS:
    case E::SSL_CLIENTCERT:
        return TransportError::tls;
    default:
        return TransportError::other;
    }
}

std::string_view describe(cpr::ErrorCode code) noexcept
{
    using E = cpr::ErrorCode;
    switch (classify(code)) {
    case TransportError::connect:
        // These come after the request went out, so "could not connect" would
        // mislead: the server may have received it.
        return code == E::SEND_ERROR || code == E::RECV_ERROR || code == E::GOT_NOTHING ||
                       code == E::PARTIAL_FILE
                   ? "connection dropped"
                   : "could not connect";
    case TransportError::timeout:
        return "timed out";
    case TransportError::tls:
        return "TLS failure";
    default:
        return "request failed";
    }
}

std::string error_text(const cpr::Error& error)
{
    if (!error.message.empty()) {
        return error.message;
    }
    const auto& names = cpr::get_error_code_to_string_mapping();
    const auto name = names.find(error.code);
    return "curl error " + (name != names.end() ? name->second
                                                : std::to_string(static_cast<int>(error.code)));
}

} // namespace detail

namespace {

using std::chrono::milliseconds;

cpr::Multipart make_multipart(const std::vector<MultipartPart>& parts)
{
    std::vector<cpr::Part> out;
    out.reserve(parts.size());
    for (const MultipartPart& part : parts) {
        if (part.filename.empty()) {
            out.emplace_back(part.name, part.content, part.content_type);
            continue;
        }
        // A buffer part is sent with its length, so '\0' and any other byte
        // survive. It points into `part`, which outlives the request.
        const char* begin = part.content.data();
        cpr::Part file(part.name,
                       cpr::Buffer{begin, begin + part.content.size(), std::filesystem::path{}},
                       part.content_type);
        // cpr takes the file name from path::string() (ANSI code page); the
        // part's value is what it hands curl, so put the UTF-8 name there.
        file.value = part.filename;
        out.push_back(std::move(file));
    }
    return cpr::Multipart{std::move(out)};
}

cpr::Response perform(const HttpRequest& request, const cpr::SslOptions& ssl)
{
    cpr::Session session;
    session.SetUrl(cpr::Url{request.url});
    cpr::Header header(request.headers.begin(), request.headers.end());
    if (!request.content_type.empty() && request.parts.empty()) {
        header["Content-Type"] = request.content_type;
    }
    session.SetHeader(header);
    session.SetTimeout(cpr::Timeout{request.timeout});
    // Redirects are never followed: a 3xx goes back to the caller. Following
    // one could send the Authorization header, or a token request's body, to
    // another host.
    session.SetRedirect(cpr::Redirect{0L, false, false, cpr::PostRedirectFlags::NONE});
    session.SetSslOptions(ssl);
    if (!request.parts.empty()) {
        session.SetMultipart(make_multipart(request.parts));
    } else if (!request.body.empty()) {
        session.SetBody(cpr::Body{request.body});
    }
    switch (request.method) {
    case HttpMethod::get:
        return session.Get();
    case HttpMethod::post:
        return session.Post();
    default:
        return session.Delete();
    }
}

// Plain form fields go to curl as C strings, so a '\0' would silently cut the
// value short.
void check_parts(const std::vector<MultipartPart>& parts)
{
    for (const MultipartPart& part : parts) {
        if (part.filename.empty() && part.content.find('\0') != std::string::npos) {
            throw std::invalid_argument("multipart form field \"" + redact(part.name) +
                                        "\" contains a NUL byte; send it as a file part");
        }
    }
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

std::string_view to_string(HttpMethod method) noexcept
{
    switch (method) {
    case HttpMethod::get:
        return "GET";
    case HttpMethod::post:
        return "POST";
    default:
        return "DELETE";
    }
}

bool CaseInsensitiveLess::operator()(std::string_view a, std::string_view b) const noexcept
{
    // ASCII only: std::tolower follows the C locale, which under a Western
    // code page would fold bytes above 0x7F too. Header names are ASCII.
    const auto fold = [](char c) {
        const auto byte = static_cast<unsigned char>(c);
        return byte >= 'A' && byte <= 'Z' ? static_cast<unsigned char>(byte + ('a' - 'A')) : byte;
    };
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(),
                                        [&fold](char x, char y) { return fold(x) < fold(y); });
}

HttpError::HttpError(std::string_view message, TransportError error, int status, int attempts)
    : std::runtime_error(redact(message)), error_(error), status_(status), attempts_(attempts)
{
}

TransportError HttpError::error() const noexcept
{
    return error_;
}

int HttpError::status() const noexcept
{
    return status_;
}

int HttpError::attempts() const noexcept
{
    return attempts_;
}

namespace {

HttpRequest make_request(HttpMethod method, const std::string& url, const RequestOptions& options)
{
    HttpRequest request;
    request.method = method;
    request.url = url;
    request.headers = options.headers;
    request.timeout = options.timeout;
    return request;
}

} // namespace

HttpResponse IHttpClient::get(const std::string& url, const RequestOptions& options)
{
    return send(make_request(HttpMethod::get, url, options));
}

HttpResponse IHttpClient::post(const std::string& url, std::string body, std::string content_type,
                               const RequestOptions& options)
{
    HttpRequest request = make_request(HttpMethod::post, url, options);
    request.body = std::move(body);
    request.content_type = std::move(content_type);
    return send(request);
}

HttpResponse IHttpClient::post_multipart(const std::string& url, std::vector<MultipartPart> parts,
                                         const RequestOptions& options)
{
    HttpRequest request = make_request(HttpMethod::post, url, options);
    request.parts = std::move(parts);
    return send(request);
}

HttpResponse IHttpClient::del(const std::string& url, const RequestOptions& options)
{
    return send(make_request(HttpMethod::del, url, options));
}

HttpClient::HttpClient(HttpClientOptions options) : options_(std::move(options))
{
    if (!options_.sleep) {
        options_.sleep = [](milliseconds wait) { std::this_thread::sleep_for(wait); };
    }
    if (!options_.jitter) {
        options_.jitter = default_jitter();
    }
    if (!options_.now) {
        options_.now = [] { return std::chrono::steady_clock::now(); };
    }
}

HttpResponse HttpClient::send(const HttpRequest& request)
{
    check_parts(request.parts);
    // curl reads 0 as "no timeout", which could hang a job for ever.
    if (request.timeout <= milliseconds::zero()) {
        throw std::invalid_argument("HTTP request timeout must be above 0 ms, got " +
                                    std::to_string(request.timeout.count()) + " ms");
    }
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger =
        options_.logger ? options_.logger : spdlog::default_logger();
    const cpr::SslOptions ssl = detail::make_ssl_options(options_.ca_file);
    // Every line and message below is built from this and passed through
    // redact() whole: the URL may carry a client_secret.
    const std::string target = std::string{to_string(request.method)} + " " + request.url;

    for (int attempt = 1;; ++attempt) {
        const auto start = options_.now();
        const cpr::Response response = perform(request, ssl);
        const auto elapsed = std::chrono::duration_cast<milliseconds>(options_.now() - start);

        const TransportError error = detail::classify(response.error.code);
        const AttemptOutcome outcome{error, error == TransportError::none
                                                ? static_cast<int>(response.status_code)
                                                : 0};
        const bool retry = should_retry(outcome, attempt);
        const milliseconds wait =
            retry ? retry_delay(attempt, options_.jitter()) : milliseconds::zero();

        // The line is only built (and redacted) when it will be written.
        if (logger && logger->should_log(spdlog::level::debug)) {
            // "HTTP 503" or "could not connect (curl's message)".
            const std::string result =
                error == TransportError::none
                    ? "HTTP " + std::to_string(outcome.status)
                    : std::string{detail::describe(response.error.code)} + " (" +
                          detail::error_text(response.error) + ")";
            std::string line = target + " attempt " + std::to_string(attempt) + "/" +
                               std::to_string(kMaxHttpAttempts) + ": " + result + " in " +
                               std::to_string(elapsed.count()) + " ms";
            if (retry) {
                line += "; retrying in " + std::to_string(wait.count()) + " ms";
            }
            logger->debug("{}", redact(line));
        }
        if (retry) {
            options_.sleep(wait);
            continue;
        }

        if (error == TransportError::none && !is_retryable(outcome)) {
            HttpResponse out;
            out.status = outcome.status;
            out.headers.insert(response.header.begin(), response.header.end());
            out.body = response.text;
            return out;
        }
        const std::string how = is_retryable(outcome)
                                    ? " after " + std::to_string(attempt) + " attempts"
                                    : " on attempt " + std::to_string(attempt) + " (not retried)";
        const std::string message =
            error == TransportError::none
                ? target + ": HTTP " + std::to_string(outcome.status) + how
                : target + ": " + std::string{detail::describe(response.error.code)} + how +
                      ": " + detail::error_text(response.error);
        throw HttpError(message, error, outcome.status, attempt);
    }
}

} // namespace rp
