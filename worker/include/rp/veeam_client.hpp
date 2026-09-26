#pragma once

// The client for Veeam Backup for Microsoft 365's REST API v8 (W1.5). The
// calls, tokens and errors it handles are in docs/api/veeam-notes.md; §1.7 is
// the token recipe and §8 the error table. Admin mode only: the account is a
// local or domain Windows account in the Veeam Backup Administrator role
// (docs/decisions.md 2026-09-26).

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
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// Any failure of a VeeamClient call. what() is safe to print and log: it went
// through rp::redact() and never holds a token or the password. It names the
// call ("Veeam GET /v8/Organizations?limit=1000&offset=0: ...") and, when
// Veeam answered, the status, Veeam's errorCode and its message.
class VeeamError : public std::runtime_error {
public:
    VeeamError(std::string_view message, int status = 0, std::string error_code = {},
               std::string body = {});

    // The HTTP status of Veeam's answer; 0 when none came back (no connection,
    // a timeout, a TLS failure).
    int status() const noexcept;
    // Veeam's errorCode ("ResourceNotFound", "ParameterValidationFailure",
    // ...); empty when the body had none.
    const std::string& error_code() const noexcept;
    // The error response's body as received, for a caller that needs more than
    // the message. Never the body of a successful response (a token call's
    // holds tokens). Don't log it.
    const std::string& body() const noexcept;

private:
    int status_;
    std::string error_code_;
    std::string body_;
};

// Veeam refused the credentials, the account's role, or the token: 401 or 403
// (after one fresh sign-in for an API call's 401 with an empty body), an
// errorCode of ResourceAccessDenied, or a 500 from /v8/token (Veeam sometimes
// answers a refused sign-in with an empty 500).
class AuthError : public VeeamError {
public:
    using VeeamError::VeeamError;
};

// 404 with errorCode ResourceNotFound: an unknown organisation, restore point,
// session or item. (A 404 without it is a route that doesn't exist: a plain
// VeeamError.)
class NotFoundError : public VeeamError {
public:
    using VeeamError::VeeamError;
};

// Might work later: no connection, a dropped connection, a timeout or a
// broken-off TLS handshake, or a 5xx that isn't Veeam reporting an error: 502,
// 503 and 504, and any other 5xx (but a 500 from /v8/token) whose body isn't a
// JSON object with a string "message" (and whose errorCode isn't
// ResourceAccessDenied). The client makes every attempt itself, five at most
// per request (HttpClient one per send): a GET is retried after any of these;
// a token request only when it never went out (no connection, no handshake),
// as Veeam may have acted on one that did; a logout never.
class TransientError : public VeeamError {
public:
    using VeeamError::VeeamError;
};

// A Microsoft 365 organisation Veeam backs up (GET /v8/Organizations).
struct Organization {
    std::string id;          // Veeam's organisation ID, a UUID: every later call takes it
    std::string name;        // e.g. RestoreProofLab.onmicrosoft.com
    std::string msid;        // the Entra tenant ID; empty if Veeam sent none
    std::string region;      // e.g. Worldwide; empty if none
    std::string office_name; // officeName; empty if none
};

// A restore point (GET /v8/RestorePoints). There is no "isModified": the guide
// named a field v8 doesn't have (docs/api/veeam-notes.md §3).
struct RestorePoint {
    // Repository ID and point ID run together (72 characters). Opaque.
    std::string id;
    // Exactly as Veeam sent it, e.g. "2026-09-25T19:37:15.2145203Z" (7
    // fractional digits and Z). Explore sessions are opened by this string,
    // unchanged: truncated, it is earlier than the point, and any other form
    // (+00:00, no offset) makes Veeam answer 500 (veeam-notes §4.2).
    std::string backup_time;
    std::string organization_id;
    std::string repository_id;
    std::string job_id;
    bool is_exchange = false;
    bool is_sharepoint = false;
    bool is_onedrive = false;
    bool is_teams = false;
    bool is_deleted = false;
    bool is_long_term_copy = false; // archive tier: a restore needs a retrieval first
    bool is_copy = false;
};

struct VeeamClientOptions {
    // Where the client's own debug lines go (sign-ins, refreshes, 401s);
    // null = spdlog::default_logger() at the time of the call, and nothing if
    // that is null too. HttpClient logs each request itself.
    std::shared_ptr<spdlog::logger> logger;
    // The clock tokens expire by; null = steady_clock::now.
    std::function<std::chrono::steady_clock::time_point()> now;
    // The wait between retries of a transient 5xx on a GET; null =
    // std::this_thread::sleep_for.
    std::function<void(std::chrono::milliseconds)> sleep;
    // Jitter for retry_delay(), in [0, 1); null = uniform random.
    std::function<double()> jitter;
    // `limit` of each page of a list; 1 to 10000. The server's default of 30
    // would cut lists short, so every list pages until a page is shorter than
    // the limit Veeam says it applied.
    int page_size = 1000;
    // Per request, as HttpRequest::timeout; above 0.
    std::chrono::milliseconds timeout = kDefaultHttpTimeout;
};

// Every public member may be called from several threads at once, if the
// IHttpClient's send() may (HttpClient's can). The client holds one token
// pair: a refresh revokes the previous access token at once, so refreshes and
// sign-ins happen one at a time under a lock, and every caller then uses the
// new token. Callers that waited for the lock while a renewal failed, and
// still need one when they get it (none has succeeded since), get that
// failure instead of trying again one after another.
class VeeamClient {
public:
    // `base_url`: the REST API's root, as Config::veeam_url, e.g.
    // https://veeam.example:4443 (a trailing '/' is ignored). `username` is
    // MACHINE\user or DOMAIN\user; it and `password` come from the
    // environment (rp/secrets.hpp), never config.json, and are never logged.
    // `http` must outlive the client. Throws std::invalid_argument for a URL
    // that isn't https:// (the password would go out in clear), an empty
    // username or password, a page_size outside 1..10000, or a timeout of
    // 0 or less.
    VeeamClient(IHttpClient& http, std::string base_url, std::string username,
                std::string password, VeeamClientOptions options = {});

    VeeamClient(const VeeamClient&) = delete;
    VeeamClient& operator=(const VeeamClient&) = delete;

    // Signs in with the password (POST /v8/token, grant_type=password) and
    // keeps the new token pair. Throws AuthError when Veeam refuses (401, 403
    // or 500; never retried), TransientError when it can't be reached or a
    // gateway answers for it (502, 503, 504; not retried either, once the
    // request may have gone out), and VeeamError for any other answer (a 400,
    // a 3xx, a 200 without a usable token). None of them keeps the response
    // body.
    void login();

    // Makes sure the access token isn't about to expire: none yet → login();
    // within 60 s of expiry → refresh (grant_type=refresh_token). A refresh
    // Veeam refuses or garbles falls back to login(); one that fails with a
    // TransientError is thrown as it is, since a sign-in would meet the same
    // unreachable server. The expiry is expires_in counted on the local clock
    // from when the token arrived, capped at a day; a token that lives 120 s
    // or less is refreshed at half its lifetime instead. Every API call does
    // this first.
    void ensure_token();

    // Ends the token chain (POST /v8/token/logout). Veeam refuses a logout
    // with an expired access token, so one within 60 s of expiry is refreshed
    // first (one try). Best effort: one attempt, and any failure is logged at
    // debug and swallowed. The tokens are forgotten either way, so a later
    // call signs in again; so may a call still in flight when logout() runs,
    // if Veeam refuses its token, so log out after the last call. Does
    // nothing when not signed in.
    void logout() noexcept;

    // GET /v8/Organizations, every page.
    std::vector<Organization> list_organizations();

    // GET /v8/RestorePoints?organizationId=..., every page, sorted newest
    // first by backupTime (whatever order Veeam sent), ties by ID. Empty when
    // the organisation has none. `organization_id` must be a UUID
    // (std::invalid_argument otherwise, before any request: Veeam reads a
    // malformed ID as the all-zero one). An unknown organisation →
    // NotFoundError.
    std::vector<RestorePoint> list_restore_points(const std::string& organization_id);

private:
    struct Token {
        std::string access;
        std::uint64_t generation = 0;
    };

    // The token to call with, after ensure_token()'s checks.
    Token current_token();
    // Renews the token if there is none or it is within the margin of its
    // expiry, rethrowing a renewal failure that happened since the caller
    // read `failures_seen` (before waiting for the lock) instead of trying
    // again.
    void renew_if_due_locked(std::uint64_t failures_seen);
    // Rethrows the last renewal failure if one happened since the caller read
    // `failures_seen` and none has succeeded since.
    void rethrow_failure_since_locked(std::uint64_t failures_seen) const;
    // These expect mutex_ held. login_locked, and refresh_locked when it
    // throws TransientError, record the failure (record_failure_locked, from
    // inside a catch block) for rethrow_failure_since_locked; a stored token
    // clears it.
    void login_locked();
    void refresh_locked();
    void store_tokens_locked(const HttpResponse& response, std::string_view event);
    void record_failure_locked();
    // POST /v8/token with `form`, through send_with_retries (not idempotent).
    HttpResponse send_token_request(const std::string& form,
                                    int max_attempts = kMaxHttpAttempts);
    // Sends `request` with HttpClient making one attempt per send, up to
    // `max_attempts` sends: again after a transport failure that never went
    // out (connect, handshake), and, when `idempotent`, after any transport
    // failure worth another attempt and any transient 5xx. Returns the last
    // response, whatever its status; a transport failure it gives up on is
    // thrown as a VeeamError. `attempts` is set to the number of sends.
    HttpResponse send_with_retries(HttpRequest request, const std::string& what, bool idempotent,
                                   int max_attempts, int& attempts);
    // GET base_url_ + `path_and_query` with the current token: the 401
    // recovery, retries, and the status mapping. Returns a 2xx response;
    // throws VeeamError (or a subclass) for anything else.
    HttpResponse get(const std::string& path_and_query);
    // One GET with `token`, through send_with_retries.
    HttpResponse send_get(const std::string& path_and_query, const std::string& token,
                          const std::string& what, int& attempts);
    // Every entry of a paged list, each `id` once, in the order received.
    std::vector<nlohmann::json> get_all_pages(const std::string& path_and_query);
    void log_debug(const std::string& line) const;

    IHttpClient& http_;
    std::string base_url_;
    std::string username_;
    std::string password_;
    VeeamClientOptions options_;

    std::mutex mutex_; // guards everything below
    std::string access_token_;
    std::string refresh_token_;
    // When ensure_token() refreshes: the expiry less the margin.
    std::chrono::steady_clock::time_point refresh_at_{};
    std::uint64_t generation_ = 0; // bumped whenever the token pair changes
    // Counts failed renewals; atomic so a caller can read it before taking
    // the lock. The last failure is kept for callers that waited on it, until
    // a renewal succeeds.
    std::atomic<std::uint64_t> renewal_failures_ = 0;
    std::exception_ptr last_renewal_failure_;
};

} // namespace rp
