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
#include <utility>

namespace rp::graph {

// What an authenticated call relies on, in words a customer can act on. A
// 403 names it, since Graph's own answer doesn't say which permission is
// missing. Generic: no lab names (docs/security/graph-permissions.md).
struct Grant {
    std::string_view description;
};

// The test mailbox: Exchange Online RBAC for applications, not a Graph
// application permission. ReadWrite since W3.4: the Cleaner deletes there; the
// readers rely on the same assignment.
inline constexpr Grant kMailGrant{
    "Exchange RBAC \"Application Mail.ReadWrite\" in a management scope covering the test "
    "mailbox"};
// Reading the test site's RestoreTarget library.
inline constexpr Grant kSitesReadGrant{"Sites.Selected read on the test site"};
// The test OneDrive folder (a grant on that folder only): write since W3.4, for
// the Cleaner; the readers rely on the same grant.
inline constexpr Grant kOneDriveGrant{
    "Files.SelectedOperations.Selected write on the test OneDrive folder"};
// Deleting in the test site's RestoreTarget library (a grant on that list
// only, W3.4); listing it still relies on kSitesReadGrant.
inline constexpr Grant kListWriteGrant{
    "Lists.SelectedOperations.Selected write on the test library"};

// Sent as Prefer on every mail call, as the seeder does (lab/README.md,
// "text-v1"): bodies as text, IDs that survive a move. GraphClient::remove
// sends it with a mail's permanentDelete, so the listed ImmutableId is read as
// one.
inline constexpr std::string_view kMailPrefer =
    "outlook.body-content-type=\"text\", IdType=\"ImmutableId\"";

// The only headers a caller may add (any case). Everything else, Authorization
// included, is the client's own.
inline constexpr std::string_view kCallerHeaders[] = {"Prefer"};

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

class Cleaner;

// An item the Cleaner listed in a restore target, the one thing
// GraphClient::remove deletes (docs/decisions.md 2026-10-02, W3.4 point 3):
// a mail in the test mailbox (its address and the message's ImmutableId) or a
// file in the RestoreTarget library or the test OneDrive folder (the drive, the
// item ID and the eTag it was listed with). Only the Cleaner can make one, and
// only from its own listing under a target it resolved; a source scan in
// tests/graph_client_test.cpp keeps the name out of every other Worker file.
class ListedItem {
public:
    enum class Kind { mail, file };

    Kind kind() const noexcept { return kind_; }
    // The mailbox's address, or the drive ID.
    const std::string& container() const noexcept { return container_; }
    const std::string& id() const noexcept { return id_; }
    // Files: the eTag sent as If-Match. Mail: empty.
    const std::string& etag() const noexcept { return etag_; }
    // What the delete relies on: kMailGrant, kListWriteGrant or kOneDriveGrant.
    const Grant& grant() const noexcept { return *grant_; }

private:
    friend class Cleaner;

    ListedItem(Kind kind, std::string container, std::string id, std::string etag,
               const Grant& grant)
        : kind_(kind), container_(std::move(container)), id_(std::move(id)),
          etag_(std::move(etag)), grant_(&grant)
    {
    }
    static ListedItem mail(std::string mailbox, std::string id)
    {
        return {Kind::mail, std::move(mailbox), std::move(id), {}, kMailGrant};
    }
    static ListedItem library_file(std::string drive, std::string id, std::string etag)
    {
        return {Kind::file, std::move(drive), std::move(id), std::move(etag), kListWriteGrant};
    }
    static ListedItem onedrive_file(std::string drive, std::string id, std::string etag)
    {
        return {Kind::file, std::move(drive), std::move(id), std::move(etag), kOneDriveGrant};
    }

    Kind kind_;
    std::string container_;
    std::string id_;
    std::string etag_;
    const Grant* grant_;
};

// What became of a ListedItem GraphClient::remove was asked to delete.
enum class RemoveOutcome {
    removed, // 204
    gone,    // 404 itemNotFound / ErrorItemNotFound: not there (any more)
    changed, // 412: the file changed since it was listed; nothing was deleted
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
// renewals happen one at a time under a lock. A call whose token is still good
// never waits for a renewal in flight; one that needs a new token waits, and
// that wait counts toward its kMaxRetryWaitPerCall. Callers that waited for the
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
    //  - 404 with Graph's JSON error: a NotFoundError: what get() addresses
    //    must be there (the test mailbox, site or drive), so its absence means
    //    the run can't test (status `error`); an item a restore should have
    //    put there is looked up with find(). A 404 without Graph's JSON, from
    //    a proxy or a wrong path, is a GraphError; so is a mailbox Graph can't
    //    read (MailboxNotEnabledForRESTAPI, MailboxNotSupportedForRESTAPI),
    //    whatever the status.
    //  - 429, 5xx and a lost connection or a timeout (connect, handshake,
    //    dropped, timeout; a GET changes nothing) share kMaxHttpAttempts
    //    attempts, waiting rp::retry_delay() and at least a Retry-After on a
    //    429 or 503, within kMaxRetryWait each and kMaxRetryWaitPerCall in
    //    all, the waits of a token renewal inside the call and the wait for
    //    another call's renewal included; then a
    //    TransientError (carrying the Retry-After). The token is checked
    //    before every attempt. A TLS failure or a malformed URL is a
    //    GraphError after one. Their messages hold the path, never the
    //    query.
    //  - Any other status is a GraphError with Graph's code and message.
    // Errors keep Graph's code, inner code and request ID, never the body.
    // Whatever the token renewal throws is thrown as it is.
    //
    // `headers` go with every attempt, resends after a 401 and retries
    // included, next to the client's own (Accept, User-Agent, Authorization).
    // Only the names in kCallerHeaders are allowed (any case), each with a
    // value that isn't empty and holds no control character (those of
    // control_chars.hpp, CR and LF included); anything else is a GraphError
    // before anything is sent, the token request included, so a caller can
    // never replace the token or split a header line.
    //
    // `max_body_bytes` goes with every attempt as HttpRequest::max_body_bytes:
    // a 2xx body longer than it comes back cut one byte past it, for the
    // caller to check (W2.2's downloads). nullopt: no limit.
    HttpResponse get(std::string_view path_or_url, const Grant& grant,
                     const HttpHeaders& headers = {},
                     std::optional<std::uint64_t> max_body_bytes = std::nullopt);

    // get(), and the body as a JSON object: a 3xx, or a body that isn't a
    // JSON object, is a GraphError (the body is never quoted).
    nlohmann::json get_json(std::string_view path_or_url, const Grant& grant,
                            const HttpHeaders& headers = {});

    // get() for an item a restore should have put there (W2.2's
    // verification): nullopt when Graph answers 404 with its JSON error, the
    // one answer that means the item is missing (a `fail`, not an `error`).
    // Everything else as get(): a 404 whose code says the mailbox or user
    // doesn't exist (ErrorInvalidUser, ErrorNonExistentMailbox,
    // Request_ResourceNotFound) is still a NotFoundError. SharePoint and
    // OneDrive say itemNotFound for a missing drive as for a missing item, so
    // the caller checks the drive with get() first.
    std::optional<HttpResponse> find(std::string_view path_or_url, const Grant& grant,
                                     const HttpHeaders& headers = {});
    // find(), and the body as a JSON object, as get_json().
    std::optional<nlohmann::json> find_json(std::string_view path_or_url, const Grant& grant,
                                            const HttpHeaders& headers = {});

    // Waits `wait` on the client's own sleep (GraphClientOptions::sleep): a
    // caller's pause between two reads (the listing recheck,
    // src/graph_paging.hpp) is then a test's to record, never slept there.
    void wait(std::chrono::milliseconds wait);

    // Deletes `item` (W3.4; only the Cleaner can make one). The path is built
    // here, from the item alone, in one of two shapes:
    //  - a mail: POST /users/{mailbox}/messages/{id}/permanentDelete, bodiless,
    //    with Prefer: kMailPrefer (the ID is an ImmutableId). The mail goes to
    //    Recoverable Items/Purges, never to Deleted Items;
    //  - a file: DELETE /drives/{drive}/items/{id} with If-Match: the eTag it
    //    was listed with. The file goes to the site recycle bin.
    // An item whose container, ID or eTag can't go into the path or a header
    // is a GraphError before anything is sent. Everything else as get(): the
    // URL checks, 401, 403 (a PermissionError naming item.grant()), the
    // retries (a write is retried like a GET: a resent permanentDelete or
    // If-Match DELETE of the same ID can only answer 204, 404 or 412, or a
    // mail's 403 ErrorCannotDeleteObject, below) and the
    // messages, which name the method.
    //  - 204: removed. Any other 2xx or a 3xx is a GraphError.
    //  - 404 with Graph's itemNotFound or ErrorItemNotFound: gone. Any other
    //    404 Graph explains (names_missing_container's codes included: a
    //    missing mailbox) is a NotFoundError; one it doesn't, a GraphError.
    //  - 412, for a file: changed. For a mail, a GraphError.
    //  - 403 ErrorCannotDeleteObject, for a mail: what Exchange answers a
    //    permanentDelete of a message already purged (a resend whose first
    //    answer was lost; seen live, W3.4 build notes point 15). One check
    //    follows, is the message gone, at most three GETs with Prefer:
    //    kMailPrefer, every path built here from the item's mailbox and ID
    //    alone, no loop: GET /users/{mailbox}/messages/{id}?$select=id,
    //    parentFolderId; only if that answers 200, GET /users/{mailbox}/
    //    mailFolders/recoverableitemspurges?$select=id; only if that doesn't
    //    match, GET /users/{mailbox}/mailFolders/inbox?$select=id. Gone is a
    //    positive answer only: the message's 404 with itemNotFound or
    //    ErrorItemNotFound (no folder GET), or a non-empty string
    //    parentFolderId equal, byte for byte, to the Purges folder's
    //    non-empty string id (a purged message still answers by its ID, from
    //    Purges, seen live; the Inbox not asked). Equal to the Inbox's id: the
    //    PermissionError naming item.grant() stands. Equal to neither (moved
    //    to another folder, an ID in another form): a GraphError, the message
    //    "in another folder of the mailbox", never gone. Anything else fails
    //    closed too: any GET's own error (its 403, 5xx after the retries, a
    //    404 of a folder or naming a missing mailbox), any other status a
    //    GraphError ("where 200 or 404 was expected" for the message, "where
    //    200 was expected" for a folder), and a reply that isn't a JSON
    //    object or has no such ID a GraphError. Any other 403, and every 403
    //    for a file, is the PermissionError with no GET.
    RemoveOutcome remove(const ListedItem& item);

private:
    struct Token {
        std::string access;
        std::uint64_t generation = 0;
        // renewal_failures_ when the token was handed out.
        std::uint64_t failures_seen = 0;
    };

    // The token to call with, renewed first if due. A good token is taken at
    // once, even while another call renews. `waited` is the calling get()'s
    // wait so far: the time spent waiting for another call's renewal and a
    // renewal's own waits add to it, within kMaxRetryWaitPerCall in all.
    Token current_token(std::chrono::milliseconds& waited);
    // Whether there is no token or it is due; the token held now.
    bool token_due();
    Token token_now();
    // renew_mutex_, the time spent waiting for it (on options.now) added to
    // `waited`.
    std::unique_lock<std::mutex> lock_renewal(std::chrono::milliseconds& waited);
    // These expect renew_mutex_ held.
    // Renews the token if there is none or it is due, rethrowing a renewal
    // failure that happened since the caller read `failures_seen` (before
    // waiting for the lock) instead of trying again. True if it fetched one.
    bool renew_if_due_locked(std::uint64_t failures_seen, std::chrono::milliseconds& waited);
    void rethrow_failure_since_locked(std::uint64_t failures_seen) const;
    // fetch_token_locked records its failure for rethrow_failure_since_locked;
    // a stored token clears it.
    void fetch_token_locked(std::chrono::milliseconds& waited);
    void store_token_locked(const HttpResponse& response);
    // How send() reads a 404 and a 412.
    enum class Mode {
        get,    // get(): a 404 is a NotFoundError
        find,   // find(): a 404 Graph explains that doesn't name a missing
                // mailbox or user is nullopt
        remove, // remove(): a 404 itemNotFound/ErrorItemNotFound is nullopt, a
                // 412 is returned
    };
    // One call of `method` (see get() and remove()). `caller_headers` are
    // checked as get() says; `own_headers` are the client's own for this call
    // (remove()'s If-Match and Prefer), each value checked for control
    // characters. Both are checked before anything is sent.
    std::optional<HttpResponse> send(HttpMethod method, std::string_view path_or_url,
                                     const Grant& grant, Mode mode,
                                     const HttpHeaders& caller_headers,
                                     const HttpHeaders& own_headers,
                                     std::optional<std::uint64_t> max_body_bytes);
    // remove()'s check after a mail's 403 ErrorCannotDeleteObject: true if
    // the message is gone (not found, or in Recoverable Items' Purges), false
    // if it is still in the Inbox; anything else throws (see remove()).
    bool purged_or_gone(const ListedItem& item);
    // The body of a response get() or find() returned, as a JSON object.
    static nlohmann::json json_body(std::string_view path_or_url, const HttpResponse& response);
    // One `method` request of `url` with `token` and `headers`, one attempt,
    // bodiless.
    HttpRequest api_request(HttpMethod method, const std::string& url, const std::string& token,
                            const HttpHeaders& headers,
                            std::optional<std::uint64_t> max_body_bytes) const;
    // One token request with a new assertion.
    HttpRequest token_request() const;
    void log_debug(const std::string& line) const;

    IHttpClient& http_;
    std::string tenant_id_;
    std::string client_id_;
    std::string token_url_;
    ClientCertificate certificate_;
    GraphClientOptions options_;

    // Held by the one call renewing the token, across its sends and waits.
    // Guards last_renewal_failure_. Taken before mutex_, never while holding it.
    std::mutex renew_mutex_;
    std::exception_ptr last_renewal_failure_;

    // Guards the token below, briefly: never held across a send or a wait.
    std::mutex mutex_;
    std::string access_token_;
    // When the token is renewed: its expiry less the margin.
    std::chrono::steady_clock::time_point renew_at_{};
    std::uint64_t generation_ = 0; // bumped whenever the token changes
    // Counts failed renewals; atomic so a caller can read it before taking
    // a lock. The last failure is kept for callers that waited on it, until a
    // renewal succeeds.
    std::atomic<std::uint64_t> renewal_failures_ = 0;
};

} // namespace rp::graph
