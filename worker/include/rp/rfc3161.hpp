#pragma once

// RFC 3161 as the Timestamper and the Signer use it (W4.4, docs/decisions.md
// 2026-10-06 W4.4, points 4, 5 and 7): a small interface they work over, so a
// test can hand them a primitive that fails, and the real one over OpenSSL's
// TS functions (src/rfc3161.cpp). No OpenSSL type appears here, and no rule of
// the timestamp lives behind it but "is this one token" and "does it verify
// under these certificates": which imprint and which nonce are right is the
// caller's to say.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

inline constexpr std::string_view kTimestampFileName = "timestamp.tst";

// A token larger than this isn't read or written; a response larger isn't
// taken. Measured tokens are 3.9 to 7.7 KB.
inline constexpr std::uintmax_t kMaxTimestampFileBytes = 64u * 1024u;

inline constexpr std::size_t kSha256Bytes = 32;

// PKIStatus "granted" (RFC 3161 2.4.2): the only status a token is taken with.
inline constexpr int kTimestampGranted = 0;

// A TimeStampResp, read.
struct TimestampResponse {
    int status = -1;   // PKIStatus
    std::string token; // the TimeStampToken's bytes as the TSA sent them; empty when none
};

// What a TimeStampToken says of itself. Nothing here is verified.
struct TimestampTokenInfo {
    bool sha256 = false;                // the imprint's algorithm is SHA-256
    std::vector<unsigned char> imprint; // the hashed message
    // The nonce, when there is one and it fits 64 bits.
    std::optional<std::uint64_t> nonce;
    std::int64_t gen_time = 0; // genTime, seconds since 1970-01-01T00:00:00Z, fractions cut
};

// The primitive. The real one never throws; its callers take one that does.
class Rfc3161 {
public:
    virtual ~Rfc3161() = default;

    // A TimeStampReq's DER: version 1, a SHA-256 imprint of `digest`, `nonce`,
    // certReq true, no policy. Empty when it can't be made.
    virtual std::string request(std::span<const unsigned char, kSha256Bytes> digest,
                                std::uint64_t nonce) const = 0;

    // `der` read as exactly one TimeStampResp (nothing after it), or nullopt.
    virtual std::optional<TimestampResponse> parse_response(std::string_view der) const = 0;

    // `der` read as exactly one TimeStampToken: a CMS SignedData with one
    // signer whose content is a TSTInfo of version 1, and no byte after it.
    // nullopt for anything else, a whole TimeStampResp included.
    virtual std::optional<TimestampTokenInfo> parse_token(std::string_view der) const = 0;

    // Whether the token's signature verifies and its signer chains to one of
    // the certificates in `ca_pem`, each certificate valid at the token's own
    // genTime: the signer among the token's certificates, named by the
    // token's ESSCertID (v1 or v2), its extended key usage critical and
    // timeStamping alone. A certificate of `ca_pem` ends the chain wherever it
    // is met. Revocation isn't checked. False for anything else.
    virtual bool verify_token(std::string_view token, std::string_view ca_pem) const = 0;

    // How many certificates the PEM text `pem` holds; 0 when none or when the
    // text can't be read as PEM certificates to its end.
    virtual std::size_t certificates_in(std::string_view pem) const = 0;
};

// The real primitive, over OpenSSL: one object for the process, thread-safe.
const Rfc3161& openssl_rfc3161() noexcept;

// `gen_time` as both verifiers print it: YYYY-MM-DDTHH:MM:SSZ.
std::string timestamp_time_text(std::int64_t gen_time);

} // namespace rp
