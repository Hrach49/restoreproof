#pragma once

// The Worker's HTTP client (W1.3). Everything that talks to Veeam, Graph, the
// TSA or the Cloud goes through IHttpClient, so tests can put a fake in its
// place (Q2.1's FakeHttpClient and the --record wrapper implement send() only).
// No cpr or curl types appear here: cpr is private to rpcore.

#include <rp/retry_policy.hpp>

#include <spdlog/logger.h>

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

enum class HttpMethod { get, post, del };

// "GET", "POST" or "DELETE"; "UNKNOWN" for a value outside the enum, which
// HttpClient::send() refuses with std::invalid_argument before sending.
std::string_view to_string(HttpMethod method) noexcept;

// Orders ASCII case-insensitively: HTTP header names are case-insensitive.
struct CaseInsensitiveLess {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const noexcept;
};

using HttpHeaders = std::map<std::string, std::string, CaseInsensitiveLess>;

// One part of a multipart/form-data body.
struct MultipartPart {
    std::string name;
    // Sent byte for byte when `filename` is set (binary is fine). A plain form
    // field is text: it must not contain '\0' (send() throws
    // std::invalid_argument, rather than cut it short).
    std::string content;
    // UTF-8. Empty = a plain form field; otherwise a file part.
    std::string filename;
    // Empty = none sent for the part.
    std::string content_type;
};

inline constexpr std::chrono::milliseconds kDefaultHttpTimeout{30000};

struct HttpRequest {
    HttpMethod method = HttpMethod::get;
    std::string url;
    HttpHeaders headers;
    std::string body;
    // Sets Content-Type for `body` when not empty. Ignored with `parts`, whose
    // Content-Type (with its boundary) curl writes itself.
    std::string content_type;
    // When not empty, the request body is multipart/form-data built from these
    // and `body` is not sent.
    std::vector<MultipartPart> parts;
    // For the whole attempt: connect, send, and receive. Each retry gets it again.
    std::chrono::milliseconds timeout = kDefaultHttpTimeout;
};

// Per-call extras for the IHttpClient helpers.
struct RequestOptions {
    HttpHeaders headers;
    std::chrono::milliseconds timeout = kDefaultHttpTimeout; // raise it for long polls
};

struct HttpResponse {
    int status = 0;
    HttpHeaders headers;
    std::string body;
};

// A request that got no usable response: every attempt failed with a transport
// error or a 5xx, or one failed in a way that isn't retried (a certificate
// failure, a malformed URL), or the URL wasn't http:// or https:// and nothing
// was sent (other, attempts() 0). Any other status (2xx, 3xx, 4xx) is returned, not thrown.
class HttpError : public std::runtime_error {
public:
    // `message` goes through rp::redact(), so what() never holds a secret.
    HttpError(std::string_view message, TransportError error, int status, int attempts);

    // The last attempt's transport error; none when it ended with a 5xx.
    TransportError error() const noexcept;
    // The last attempt's HTTP status; 0 when no response came back.
    int status() const noexcept;
    // Attempts made, the failing one included.
    int attempts() const noexcept;

private:
    TransportError error_;
    int status_;
    int attempts_;
};

class IHttpClient {
public:
    virtual ~IHttpClient() = default;

    // Sends the request, retrying as the implementation sees fit. Returns any
    // response it doesn't retry; throws HttpError when none is usable.
    virtual HttpResponse send(const HttpRequest& request) = 0;

    // Shorthands that build an HttpRequest and call send(). Not virtual: a fake
    // only has to implement send().
    HttpResponse get(const std::string& url, const RequestOptions& options = {});
    HttpResponse post(const std::string& url, std::string body, std::string content_type,
                      const RequestOptions& options = {});
    HttpResponse post_multipart(const std::string& url, std::vector<MultipartPart> parts,
                                const RequestOptions& options = {});
    HttpResponse del(const std::string& url, const RequestOptions& options = {});
};

struct HttpClientOptions {
    // UTF-8 path of a PEM bundle of trusted certificates, for a self-signed
    // Veeam certificate (Config::veeam_ca_file). Only the Veeam connection
    // sets it. curl's Schannel backend builds the chain against the CA file
    // alone (its exclusive-root engine), so the file replaces the Windows
    // store rather than adding to it. With a CA file, revocation is checked
    // on a best-effort basis: a certificate on its CA's revocation list is
    // rejected, but one whose status can't be learned (no CRL published, or
    // not reachable) is accepted, as a private CA often publishes none. A
    // file that can't be read is a TLS failure. There is no way to turn
    // verification off.
    std::optional<std::string> ca_file;
    // Where the per-attempt debug lines go; null = spdlog::default_logger() at
    // the time of the call, and if that is null too (after spdlog::drop_all()
    // or shutdown()), nothing is logged.
    std::shared_ptr<spdlog::logger> logger;
    // The wait between attempts; null = std::this_thread::sleep_for. Tests
    // record it instead of sleeping.
    std::function<void(std::chrono::milliseconds)> sleep;
    // Jitter for retry_delay(), in [0, 1); null = uniform from a
    // random_device-seeded engine.
    std::function<double()> jitter;
    // The clock for the logged durations; null = steady_clock::now.
    std::function<std::chrono::steady_clock::time_point()> now;
};

// IHttpClient over cpr/libcurl (Schannel on Windows).
//  - Up to kMaxHttpAttempts attempts, as rp::should_retry() and
//    rp::retry_delay() decide: connect errors, timeouts, broken-off TLS
//    handshakes and 5xx are retried; 4xx, certificate failures and malformed
//    URLs are not.
//  - A request timeout of zero or less throws std::invalid_argument before
//    anything is sent (curl would read 0 as "no timeout").
//  - Only http:// and https:// URLs are sent (the scheme in any case); any
//    other URL, or one without a scheme, throws HttpError (other, 0 attempts)
//    before anything is sent, so a URL from a server response can't read a
//    local file or open an FTP, SMB or LDAP connection.
//  - Redirects are never followed: a 3xx is returned to the caller.
//  - TLS peer and host verification are always on.
//  - One debug line per attempt, redacted with rp::redact(); headers and
//    bodies are never logged.
// send() may be called from several threads at once if the injected options
// may (the defaults can).
class HttpClient final : public IHttpClient {
public:
    explicit HttpClient(HttpClientOptions options = {});

    HttpResponse send(const HttpRequest& request) override;

private:
    HttpClientOptions options_;
};

} // namespace rp
