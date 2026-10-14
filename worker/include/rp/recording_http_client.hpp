#pragma once

// `--record <dir>` (Q2.1): an IHttpClient that passes every request through
// to another one unchanged and writes each exchange, scrubbed, as a fixture
// FakeHttpClient can serve. The file format, the scrub rules and what is never
// recorded are the 2026-10-01 Q2.1 entry in docs/decisions.md;
// docs/testing.md ("Recording fixtures") says how to record and replay.

#include <rp/http_client.hpp>

#include <cstddef>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

// What a fixture keeps of a response body.
enum class RecordedBody {
    // The body itself, scrubbed: JSON as JSON, other UTF-8 text as a string.
    // A body that isn't UTF-8 is kept as `digest` would.
    content,
    // Only its size and SHA-256 ("body": null, "body_size", "body_sha256"),
    // never a byte of it: downloaded file contents.
    digest,
    // A binary exchange, a TSA's (W4.4): "body": null and the response's
    // bytes as standard Base64 in "body_base64", the request's in
    // "request_body_base64" (a timestamp query holds a hash and a nonce, no
    // secret). Neither field goes through redact() or the JWT-shape rule,
    // which Base64 of DER would break by chance; the bytes themselves are
    // checked against the known secrets instead, and the rest of the file is
    // held to every rule as always.
    base64,
};

// The shortest known secret the recorder looks for in what it writes: a
// shorter one would turn up in ordinary text and refuse good files.
inline constexpr std::size_t kMinRecordedSecret = 6;

// What scrubbing makes of one exchange: the fixture file's name and text.
struct ScrubbedExchange {
    // "<nnn>-<method>-<path slug>.json" (fixture_file_name).
    std::string file_name;
    std::string text;
};

// An exchange a fixture may not hold: something secret survived scrubbing.
// what() says which rule refused it, never the text.
class RecordRefused : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The URL's path and query, without scheme, host and fragment ("/" when it
// has no path; a text without "://" is taken to be that already): what a
// fixture's request line holds after the method, before redaction.
// FakeHttpClient::serve_recording matches a replayed request by it.
std::string_view request_path(std::string_view url) noexcept;

// "<nnn>-<method>-<slug>.json": `index` as at least three digits, the method
// in lower case, and the URL's path in lower case with every run of
// characters other than a-z and 0-9 made one '-', cut to 60 characters,
// "root" when nothing is left. The query never goes into the name.
std::string fixture_file_name(std::size_t index, HttpMethod method, std::string_view url);

// The secret values an exchange carries, as the recorder learns them before
// scrubbing. Both lists are wiped (secure_wipe) when it goes. Move-only.
struct LearnedSecrets {
    // Checked in this exchange's file and every later one: the Authorization
    // header's value and its token after "Bearer ", and the value of every key
    // rp::redact() treats as secret (password, access_token, refresh_token,
    // client_assertion, tempauth, ...) in a form body (URL-decoded too), the
    // query, a response body and a Location's query.
    std::vector<std::string> kept;
    // Checked in this exchange's file only, never kept: the secret values of
    // a JSON request body, which is a restore POST's, whose credential
    // (applicationCertificate and its password) is exported for that one call
    // (docs/decisions.md 2026-09-30 W2.5 point 1).
    std::vector<std::string> one_time;

    LearnedSecrets() = default;
    LearnedSecrets(LearnedSecrets&&) noexcept = default;
    LearnedSecrets& operator=(LearnedSecrets&&) noexcept = default;
    LearnedSecrets(const LearnedSecrets&) = delete;
    LearnedSecrets& operator=(const LearnedSecrets&) = delete;
    ~LearnedSecrets();
};

// What `request` and `response` carry (LearnedSecrets). A `digest` response
// body is never written, so nothing is learned from it. Values shorter than
// kMinRecordedSecret, and the placeholders, are left out.
LearnedSecrets secrets_in(const HttpRequest& request, const HttpResponse& response,
                          RecordedBody body = RecordedBody::content);

// One exchange as a fixture (the format of tests/fixtures/veeam/README.md):
//   {"source", "request": "<METHOD> <path>?<query>", "status",
//    "headers": {...}, "body", ["body_size", "body_sha256"], ["request_body"]}
// Indented JSON, key order as received, UTF-8, a final newline.
//  - request: request_path(url) through redact(); then, when `body` is
//    digest (a download link is a credential), every query value
//    "SCRUBBED".
//  - headers: only Content-Type, Retry-After, WWW-Authenticate and a
//    Location, each through redact(), the Location's query values then all
//    "SCRUBBED".
//    No request header is ever written.
//  - body: null when empty; JSON as JSON with every
//    "@microsoft.graph.downloadUrl" and "@content.downloadUrl" key dropped;
//    other UTF-8 text as a string; the whole of it through redact(), so a
//    token is "[REDACTED]" (the placeholder a replay signs in with).
//  - request_body: only for a JSON request body (a restore's), scrubbed as a
//    body is. A form body (a token request's password or client assertion)
//    and a multipart one are never written.
// Then refuses (RecordRefused) text that still holds any of `secrets` or
// `one_time`, as written or JSON-escaped, something shaped like a JWT
// (kJwtStart and 37 or more base64url characters, dots or not), or a
// tempauth or client_assertion value (the name in any case, then '=', "%3D"
// or ':') other than a placeholder. The copies of a JSON request body's
// values it makes while scrubbing are wiped, and so is a refused text.
ScrubbedExchange scrub_exchange(std::size_t index, std::string_view source,
                                const HttpRequest& request, const HttpResponse& response,
                                RecordedBody body, const std::vector<std::string>& secrets,
                                const std::vector<std::string>& one_time = {});

// A recording: one folder, a subfolder per service, a numbered fixture per
// exchange. Shared by the RecordingHttpClients of one command; record() may be
// called from several threads at once, and scrubs and writes outside the lock
// that numbers the files, so one exchange's disk write never holds up
// another's send.
class FixtureRecorder {
public:
    // `dir` must not exist or be an empty folder; it is created (a trailing
    // separator is fine). Throws
    // ConfigError (key "--record") otherwise, or when it can't be made.
    // `source` goes into every file's "source". `known_secrets` (the Veeam
    // password, the Graph certificate and its password, ...) must never be
    // written; empty ones and ones shorter than kMinRecordedSecret are left out.
    // The list is taken: its values are moved in or wiped (secure_wipe), so
    // the caller's vector holds no secret afterwards, also when this throws.
    FixtureRecorder(std::filesystem::path dir, std::string source,
                    std::vector<std::string>&& known_secrets);
    // Wipes (secure_wipe) every secret it knows.
    ~FixtureRecorder();
    FixtureRecorder(const FixtureRecorder&) = delete;
    FixtureRecorder& operator=(const FixtureRecorder&) = delete;

    // Learns the exchange's secrets (secrets_in; only the kept ones stay),
    // scrubs it and writes it as <dir>/<service>/<file name>. Never
    // throws: a refused or failed write is kept in problems(), and the next
    // exchange of the service still gets the next number, so the gap shows.
    void record(std::string_view service, const HttpRequest& request,
                const HttpResponse& response, RecordedBody body) noexcept;

    const std::filesystem::path& dir() const noexcept;
    // Files written so far.
    std::size_t written() const;
    // One line per exchange not written: "<service>/<file name>: <why>".
    std::vector<std::string> problems() const;

private:
    std::filesystem::path dir_;
    std::string source_;
    // The known and kept secrets. A deque: adding one never moves the others,
    // so no copy is left behind unwiped. Written under a unique lock, read
    // under a shared one while scrubbing.
    mutable std::shared_mutex secrets_mutex_;
    std::deque<std::string> secrets_;
    // The numbering and the counts.
    mutable std::mutex mutex_;
    std::map<std::string, std::size_t, std::less<>> next_index_;
    std::size_t written_ = 0;
    std::vector<std::string> problems_;
};

// Sends through `inner` and hands each response it returns to `recorder`
// under `service` ("veeam", "graph", "download"). A request `inner` throws on
// is not recorded, and the exception goes on unchanged: recording never
// changes what the command sends or sees.
class RecordingHttpClient final : public IHttpClient {
public:
    // Throws std::invalid_argument for a null `inner` or `recorder`.
    RecordingHttpClient(std::unique_ptr<IHttpClient> inner,
                        std::shared_ptr<FixtureRecorder> recorder, std::string service,
                        RecordedBody body = RecordedBody::content);

    // What each exchange keeps, decided per request: a service whose
    // exchanges are mostly JSON but some carry a file's bytes (a Veeam
    // document export). Throws std::invalid_argument for a null `body_for`
    // too.
    using BodyRule = std::function<RecordedBody(const HttpRequest&)>;
    RecordingHttpClient(std::unique_ptr<IHttpClient> inner,
                        std::shared_ptr<FixtureRecorder> recorder, std::string service,
                        BodyRule body_for);

    HttpResponse send(const HttpRequest& request) override;

private:
    std::unique_ptr<IHttpClient> inner_;
    std::shared_ptr<FixtureRecorder> recorder_;
    std::string service_;
    BodyRule body_for_;
};

} // namespace rp
