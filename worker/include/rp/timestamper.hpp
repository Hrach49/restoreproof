#pragma once

// The result's RFC 3161 timestamp (W4.4, docs/decisions.md 2026-10-06 W4.4,
// points 4, 6 and 7): asks a TSA for a token over the 32 bytes bundle_sha256
// shows as hex, the bytes the signature signs, and takes the token only when
// every check holds. A failure is never the run's: it is a code and a number
// of attempts, the folder is "not timestamped", and the status and the exit
// code stay.
//
// Held to 100% line coverage (worker/tools/coverage_gate.py): it decides which
// token is written. It never calls OpenSSL itself: it works over rp::Rfc3161
// (rp/rfc3161.hpp) and an rp::IHttpClient.

#include <rp/http_client.hpp>
#include <rp/rfc3161.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace spdlog {
class logger;
}

namespace rp {

// DigiCert's public TSA, plain HTTP: it has no HTTPS endpoint. Integrity comes
// from the token, never from the transport (W4.4 point 4).
inline constexpr std::string_view kDefaultTsaUrl = "http://timestamp.digicert.com";

inline constexpr std::string_view kTimestampQueryType = "application/timestamp-query";

// The guide's budget: three attempts in all, about two minutes at worst.
inline constexpr int kTimestampAttempts = 3;
inline constexpr std::chrono::milliseconds kTimestampTimeout{10000};
inline constexpr std::chrono::milliseconds kTimestampFirstWait{30000};
inline constexpr std::chrono::milliseconds kTimestampSecondWait{60000};

// Why there is no token: what `timestamp warning: ... not timestamped: <code>`
// names and W4.6 hands on as tsa_error.
namespace timestamp_code {
inline constexpr std::string_view kUnreachable = "tsa_unreachable";     // no HTTP answer
inline constexpr std::string_view kHttpStatus = "tsa_http_status";      // an answer that isn't 200
inline constexpr std::string_view kTooLarge = "tsa_token_too_large";    // over kMaxTimestampFileBytes
inline constexpr std::string_view kMalformed = "tsa_response_malformed"; // not one TimeStampResp
                                                                        // with one token
inline constexpr std::string_view kRejected = "tsa_rejected";           // a status other than granted
inline constexpr std::string_view kNonce = "tsa_nonce_mismatch";        // not the nonce sent
inline constexpr std::string_view kImprint = "tsa_imprint_mismatch";    // not SHA-256 of our bytes
inline constexpr std::string_view kUntrusted = "tsa_untrusted";         // doesn't verify under the CA
// The request couldn't be made, or the primitive or the HTTP client failed
// in a way that is neither's answer.
inline constexpr std::string_view kInternal = "timestamp_internal";
// The run folder's own (rp/evidence_builder.hpp): a token that couldn't be
// written beside the result.
inline constexpr std::string_view kNotWritten = "timestamp_not_written";
} // namespace timestamp_code

// Every code above, in that order: what a test holds the docs' list to.
const std::vector<std::string>& timestamp_codes();

// A token with its time, or why there is none.
struct TimestampOutcome {
    std::string token;         // the TimeStampToken's DER; empty when there is none
    std::int64_t gen_time = 0; // the token's genTime, seconds since 1970 UTC
    std::string_view error;    // a timestamp_code, with no token only
    int attempts = 0;          // requests sent or tried, 1 to kTimestampAttempts

    bool stamped() const noexcept { return !token.empty(); }
};

struct TimestamperOptions {
    // The TSA's URL (Config::tsa_url) and the PEM certificates a token must
    // chain to (Config::tsa_ca_file's text, or the embedded root).
    std::string url;
    std::string ca_pem;
    // Must outlive the Timestamper. Each request is sent once
    // (HttpRequest::max_attempts 1): the attempts are counted here.
    IHttpClient* http = nullptr;
    const Rfc3161* primitive = &openssl_rfc3161();
    // The nonce of each request; null = the primitive's random_nonce.
    std::function<std::optional<std::uint64_t>()> nonce;
    // The wait between attempts (the pipeline's own sleep, which W4.8 can
    // interrupt); null = the attempts follow at once.
    std::function<void(std::chrono::milliseconds)> sleep;
    // One debug line per attempt (never a body); null = none.
    std::shared_ptr<spdlog::logger> logger;
};

class Timestamper {
public:
    explicit Timestamper(TimestamperOptions options);

    // A token over `digest`, the SHA-256 of result.json's bytes. At most
    // kTimestampAttempts requests, each a POST of the TimeStampReq (version 1,
    // a SHA-256 imprint, a new nonce, certReq) with a 10 s timeout, a wait of
    // 30 s and then 60 s between them; every kind of failure is tried again
    // and the last one's code is the answer. A response is taken only when,
    // in this order: HTTP 200; at most kMaxTimestampFileBytes; one
    // TimeStampResp; status granted (0), never grantedWithMods; a token that
    // is one TimeStampToken; the nonce sent; a SHA-256 imprint equal to
    // `digest`; and the token verifies under the CA at its own time
    // (Rfc3161::verify_token, the verifiers' own check). Never throws.
    TimestampOutcome stamp(std::span<const unsigned char, kSha256Bytes> digest) const noexcept;

private:
    TimestamperOptions options_;
};

} // namespace rp
