#include <rp/timestamper.hpp>

#include <spdlog/logger.h>

#include <algorithm>
#include <array>
#include <utility>

// Held to 100% line coverage (worker/tools/coverage_gate.py): every line here
// is one a test runs. The calls into OpenSSL are in rfc3161.cpp, behind
// rp::Rfc3161.

namespace rp {

namespace detail {
// shared/tsa/tsa-ca.pem, embedded at build time (cmake/embed_bytes.cmake).
extern const unsigned char kTsaRootBytes[];
extern const std::size_t kTsaRootSize;
} // namespace detail

std::string_view default_tsa_ca_pem() noexcept
{
    return {reinterpret_cast<const char*>(detail::kTsaRootBytes), detail::kTsaRootSize};
}

namespace {

constexpr std::array<std::chrono::milliseconds, kTimestampAttempts - 1> kWaits = {
    kTimestampFirstWait, kTimestampSecondWait};

} // namespace

const std::vector<std::string>& timestamp_codes()
{
    static const std::vector<std::string> codes = {
        std::string{timestamp_code::kUnreachable}, std::string{timestamp_code::kHttpStatus},
        std::string{timestamp_code::kTooLarge},    std::string{timestamp_code::kMalformed},
        std::string{timestamp_code::kRejected},    std::string{timestamp_code::kNonce},
        std::string{timestamp_code::kImprint},     std::string{timestamp_code::kUntrusted},
        std::string{timestamp_code::kInternal},    std::string{timestamp_code::kNotWritten}};
    return codes;
}

Timestamper::Timestamper(TimestamperOptions options) : options_(std::move(options)) {}

namespace {

// One request and its answer's checks, in the documented order: the token and
// its time, or the code of the first check that didn't hold. Whatever the
// primitive or the client throws that isn't the client's own "no answer" is
// timestamp_internal.
TimestampOutcome attempt(const TimestamperOptions& options,
                         std::span<const unsigned char, kSha256Bytes> digest)
{
    TimestampOutcome out;
    out.error = timestamp_code::kInternal;
    if (options.http == nullptr || options.primitive == nullptr) {
        return out;
    }
    const std::optional<std::uint64_t> nonce =
        options.nonce ? options.nonce() : options.primitive->random_nonce();
    HttpRequest request;
    request.method = HttpMethod::post;
    request.url = options.url;
    request.body = nonce ? options.primitive->request(digest, *nonce) : std::string{};
    request.content_type = std::string{kTimestampQueryType};
    request.timeout = kTimestampTimeout;
    request.retry_on_status = false;
    request.max_attempts = 1;
    request.max_body_bytes = kMaxTimestampFileBytes;
    if (request.body.empty()) {
        return out;
    }
    HttpResponse response;
    try {
        response = options.http->send(request);
    } catch (const HttpError&) {
        out.error = timestamp_code::kUnreachable;
        return out;
    }
    if (response.status != 200) {
        out.error = timestamp_code::kHttpStatus;
        return out;
    }
    if (response.body.size() > kMaxTimestampFileBytes) {
        out.error = timestamp_code::kTooLarge;
        return out;
    }
    std::optional<TimestampResponse> answer = options.primitive->parse_response(response.body);
    if (!answer) {
        out.error = timestamp_code::kMalformed;
        return out;
    }
    if (answer->status != kTimestampGranted) {
        out.error = timestamp_code::kRejected;
        return out;
    }
    const std::optional<TimestampTokenInfo> info =
        answer->token.empty() ? std::nullopt : options.primitive->parse_token(answer->token);
    if (!info) {
        out.error = timestamp_code::kMalformed;
        return out;
    }
    if (info->nonce != nonce) {
        out.error = timestamp_code::kNonce;
        return out;
    }
    if (!info->sha256 || !std::ranges::equal(info->imprint, digest)) {
        out.error = timestamp_code::kImprint;
        return out;
    }
    if (!options.primitive->verify_token(answer->token, options.ca_pem)) {
        out.error = timestamp_code::kUntrusted;
        return out;
    }
    out.error = {};
    out.token = std::move(answer->token);
    out.gen_time = info->gen_time;
    return out;
}

} // namespace

TimestampOutcome
Timestamper::stamp(std::span<const unsigned char, kSha256Bytes> digest) const noexcept
{
    TimestampOutcome out;
    out.error = timestamp_code::kInternal;
    for (int n = 1; n <= kTimestampAttempts; ++n) {
        try {
            if (n > 1 && options_.sleep) {
                options_.sleep(kWaits[static_cast<std::size_t>(n - 2)]);
            }
            out = attempt(options_, digest);
        } catch (...) {
            out = TimestampOutcome{};
            out.error = timestamp_code::kInternal;
        }
        out.attempts = n;
        // spdlog catches what its sinks and its formatting throw.
        if (options_.logger) {
            options_.logger->debug("timestamp: attempt {} of {}: {}", n, kTimestampAttempts,
                                   out.stamped() ? std::string_view{"granted"} : out.error);
        }
        if (out.stamped()) {
            break;
        }
    }
    return out;
}

} // namespace rp
