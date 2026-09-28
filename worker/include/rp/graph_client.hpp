#pragma once

// The Worker's Microsoft Graph client (W2.1). It signs in to Entra as the
// Worker's own app, "RestoreProof Worker", with the client-credentials grant
// and a certificate: each token request carries a fresh client assertion
// (rp/client_assertion.hpp), never a client secret. The token is kept in
// memory only, renewed before it expires, and attached only to requests to
// https://graph.microsoft.com/v1.0/. Hosts are the worldwide cloud's,
// hard-wired. The decisions are in docs/decisions.md (W2.1), the permissions
// the calls rely on in docs/security/graph-permissions.md.

#include <rp/client_assertion.hpp>
#include <rp/graph_errors.hpp>
#include <rp/http_client.hpp>

#include <nlohmann/json.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace rp::graph {

// What an authenticated call relies on, in words a customer can act on. A
// 403 names it, since Graph's own answer doesn't say which permission is
// missing. Generic: no lab names (docs/security/graph-permissions.md).
struct Grant {
    std::string_view description;
};

// Reading a mailbox: Exchange Online RBAC for applications, not a Graph
// application permission.
inline constexpr Grant kMailReadGrant{
    "Exchange RBAC \"Application Mail.Read\" in a management scope covering the test mailbox"};
// Reading the test site's RestoreTarget library.
inline constexpr Grant kSitesReadGrant{"Sites.Selected read on the test site"};

// Graph's v1.0 root; every token-bearing URL starts with it and a '/'.
inline constexpr std::string_view kGraphBaseUrl = "https://graph.microsoft.com/v1.0";
// The scope of the client-credentials grant: the app's Graph roles.
inline constexpr std::string_view kGraphScope = "https://graph.microsoft.com/.default";

// A token renewal that failed with a TransientError is retried after at least
// this long, following Microsoft's guidance for Entra's 5xx.
inline constexpr std::chrono::seconds kMinTokenRetryWait{5};
// The longest wait the client accepts for one retry (a Retry-After above it
// ends the call at once, as a TransientError carrying it) ...
inline constexpr std::chrono::seconds kMaxRetryWait{120};
// ... and for all the retries of one call together.
inline constexpr std::chrono::seconds kMaxRetryWaitPerCall{300};

// "ISV|RestoreProof|RestoreProofWorker/<version>", sent as User-Agent on
// every request, as Microsoft asks of ISVs (it helps their throttling support
// find the Worker's calls).
std::string user_agent();

// A Retry-After header's value (RFC 9110 §10.2.3) as a wait counted from
// `wall_now`: delta-seconds ("120"), or an HTTP date in the IMF-fixdate form
// ("Sun, 06 Nov 1994 08:49:37 GMT"; a date already past is 0 s). Spaces and
// tabs around it are ignored. Anything else (a negative or fractional number,
// the obsolete date forms, junk) is nullopt: ignored, the normal backoff
// applies. A wait over 1e9 s (about 31 years), a number too large to hold or a
// date in year 9999 included, is kept as 1e9 s, never wrapped: over the cap,
// and safe to add to either clock's now().
std::optional<std::chrono::seconds> parse_retry_after(
    std::string_view value, std::chrono::system_clock::time_point wall_now);

struct GraphClientOptions {
    // Where the client's own debug lines go (sign-ins, retries); null =
    // spdlog::default_logger() at the time of the call, and nothing if that is
    // null too. HttpClient logs each request itself.
    std::shared_ptr<spdlog::logger> logger;
    // The clock tokens expire by; null = steady_clock::now.
    std::function<std::chrono::steady_clock::time_point()> now;
    // The clock the client assertion's nbf, iat and exp and Retry-After dates
    // are read by; null = system_clock::now.
    std::function<std::chrono::system_clock::time_point()> wall_now;
    // The wait between attempts; null = std::this_thread::sleep_for.
    std::function<void(std::chrono::milliseconds)> sleep;
    // Jitter for retry_delay(), in [0, 1); null = uniform random.
    std::function<double()> jitter;
    // Per request, as HttpRequest::timeout; above 0.
    std::chrono::milliseconds timeout = kDefaultHttpTimeout;
};

// The resends one call makes for 401s while other calls keep replacing the
// token (as VeeamClient's).
inline constexpr int kMaxUnauthorizedResends = 3;

// The options of the HttpClient for Graph and Entra: the Windows certificate
// store with full checks, no CA file, no pin (both are public, worldwide
// hosts). `logger` as HttpClientOptions::logger. GraphClient makes every
// attempt itself, so HttpClient's retry settings stay at their defaults.
HttpClientOptions graph_http_client_options(std::shared_ptr<spdlog::logger> logger = nullptr);

// An HttpClient built from graph_http_client_options(), for GraphClient.
std::unique_ptr<IHttpClient> make_graph_http_client(
    std::shared_ptr<spdlog::logger> logger = nullptr);

// Every public member may be called from several threads at once, if the
// IHttpClient's send() may (HttpClient's can). The client holds one token;
// renewals happen one at a time under a lock. Callers that waited for the
// lock while a renewal failed, and still need a token when they get it (none
// has been fetched since), get that failure instead of trying again one after
// another; the next call tries again.
//
// The token: requested from entra_token_url(tenant_id) with the
// client-credentials grant, scope kGraphScope and a new client assertion on
// every attempt (a new jti, never reused). Up to kMaxHttpAttempts attempts
// (HttpClient makes one per send): again after any transport failure (no
// connection, no handshake, a dropped connection, a timeout: every attempt is
// a new assertion and nothing changes on Entra's side), a 5xx, a 429 and the
// Entra codes that say to try again; never after a 400 or 401 otherwise. Waits
// are rp::retry_delay() but at least kMinTokenRetryWait, and at least a
// Retry-After on a 429 or 503, within kMaxRetryWait each and
// kMaxRetryWaitPerCall in all. Entra's refusals map on the AADSTS code (the
// first of error_codes, else the number in error_description), then on
// "error", never on the status alone; each AuthError message says what to
// check. A 3xx is a GraphError and nothing is sent to its Location. The reply
// must have token_type Bearer (any case), a non-empty access_token of
// printable ASCII and an integer expires_in above 0 (a day at most counts);
// it is renewed 60 s before it expires on the steady clock, or at half its
// lifetime when that is 120 s or less.
class GraphClient {
public:
    // `http` must outlive the client; it should be the Graph one (Windows
    // certificate store, no CA file, no pin). `tenant_id` and `client_id`
    // are the Entra tenant and the Worker app's client ID, GUIDs both
    // (GraphError otherwise: they go into URLs and the assertion). Throws
    // std::invalid_argument for a timeout of 0 or less. Sends nothing.
    GraphClient(IHttpClient& http, std::string tenant_id, std::string client_id,
                ClientCertificate certificate, GraphClientOptions options = {});

    GraphClient(const GraphClient&) = delete;
    GraphClient& operator=(const GraphClient&) = delete;

    // GET `path_or_url` with the token, for a call relying on `grant`.
    //  - Where: a path starting with '/' is taken relative to kGraphBaseUrl
    //    ("/users/x/messages?$top=1"); an absolute URL (an @odata.nextLink)
    //    must start with exactly "https://graph.microsoft.com/v1.0/". Either
    //    way the URL may hold no whitespace, control character (those of
    //    control_chars.hpp, the UTF-8 ones included), backslash or '#', and
    //    its path no dot segment ("/../", "%2e"), encoded separator ("%2f",
    //    "%5c"), double-encoded one ("%252e", "%252f", "%255c") or empty
    //    segment ("//", a protocol-relative URL passed as a path). Anything
    //    else is a
    //    GraphError before anything is sent, the token request included: the
    //    token goes to Graph's v1.0 and nowhere else (a text compare, so the
    //    client can't read a URL differently from curl).
    //  - Returns a 2xx or 3xx response. A redirect is never followed (W2.2's
    //    downloads follow theirs without the token).
    //  - 401: one fresh token and the call is sent again (at most
    //    kMaxUnauthorizedResends resends when other calls keep replacing the
    //    token); another 401 is an AuthError naming `grant`. A 401 asking for
    //    more claims (WWW-Authenticate error="insufficient_claims") is an
    //    AuthError at once.
    //  - 403 with Graph's JSON error: a PermissionError naming `grant`:
    //    "Graph denied GET <path> (403 <code>): the Worker app relies on
    //    <grant>; see docs/security/graph-permissions.md", the path without
    //    its query. A 403 without it (a TLS-inspecting proxy's page) is a
    //    GraphError that says something on the way may have refused it.
    //  - 404 with Graph's JSON error: a NotFoundError (a 404 without it, from
    //    a proxy or a wrong path, is a GraphError); but a mailbox Graph can't
    //    read (MailboxNotEnabledForRESTAPI, MailboxNotSupportedForRESTAPI) is
    //    a plain GraphError, whatever the status.
    //  - 429, 5xx and a lost connection or a timeout (connect, handshake,
    //    dropped, timeout; a GET changes nothing) share kMaxHttpAttempts
    //    attempts, waiting rp::retry_delay() and at least a Retry-After on a
    //    429 or 503, within kMaxRetryWait each and kMaxRetryWaitPerCall in
    //    all, the waits of a token renewal inside the call included; then a
    //    TransientError (carrying the Retry-After). The token is checked
    //    before every attempt. A TLS failure or a malformed URL is a
    //    GraphError after one. Their messages hold the path, never the
    //    query.
    //  - Any other status is a GraphError with Graph's code and message.
    // Errors keep Graph's code, inner code and request ID, never the body.
    // Whatever the token renewal throws is thrown as it is.
    HttpResponse get(std::string_view path_or_url, const Grant& grant);

    // get(), and the body as a JSON object: a 3xx, or a body that isn't a
    // JSON object, is a GraphError (the body is never quoted).
    nlohmann::json get_json(std::string_view path_or_url, const Grant& grant);

private:
    struct Token {
        std::string access;
        std::uint64_t generation = 0;
        // renewal_failures_ when the token was handed out.
        std::uint64_t failures_seen = 0;
    };

    // The token to call with, renewed first if due. `waited` is the calling
    // get()'s wait so far: a renewal's waits add to it, within
    // kMaxRetryWaitPerCall in all.
    Token current_token(std::chrono::milliseconds& waited);
    // Renews the token if there is none or it is due, rethrowing a renewal
    // failure that happened since the caller read `failures_seen` (before
    // waiting for the lock) instead of trying again. True if it fetched one.
    bool renew_if_due_locked(std::uint64_t failures_seen, std::chrono::milliseconds& waited);
    void rethrow_failure_since_locked(std::uint64_t failures_seen) const;
    // These expect mutex_ held. fetch_token_locked records its failure for
    // rethrow_failure_since_locked; a stored token clears it.
    void fetch_token_locked(std::chrono::milliseconds& waited);
    void store_token_locked(const HttpResponse& response);
    // One GET of `url` with `token`, one attempt.
    HttpRequest api_request(const std::string& url, const std::string& token) const;
    // One token request with a new assertion.
    HttpRequest token_request() const;
    void log_debug(const std::string& line) const;

    IHttpClient& http_;
    std::string tenant_id_;
    std::string client_id_;
    std::string token_url_;
    ClientCertificate certificate_;
    GraphClientOptions options_;

    std::mutex mutex_; // guards everything below
    std::string access_token_;
    // When the token is renewed: its expiry less the margin.
    std::chrono::steady_clock::time_point renew_at_{};
    std::uint64_t generation_ = 0; // bumped whenever the token changes
    // Counts failed renewals; atomic so a caller can read it before taking
    // the lock. The last failure is kept for callers that waited on it, until
    // a renewal succeeds.
    std::atomic<std::uint64_t> renewal_failures_ = 0;
    std::exception_ptr last_renewal_failure_;
};

} // namespace rp::graph
