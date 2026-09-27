#pragma once

// Internals of http_client.cpp that the tests inspect directly. Not part of
// rpcore's interface: it names cpr types, and cpr is private to rpcore.

#include <rp/retry_policy.hpp>

#include <cpr/error.h>
#include <cpr/ssl_options.h>

#include <optional>
#include <string>
#include <string_view>

namespace rp::detail {

// The TLS options every attempt uses: peer and host verification on, no
// revocation opt-out, and, when `ca_file` (UTF-8) is set, that PEM bundle as
// CURLOPT_CAINFO, which curl's Schannel backend verifies against alone. (With
// a CA file, perform() then makes the revocation check best effort, which
// SslOptions can't express.) With `public_key_pin` (rp::public_key_pin's
// base64), that key is pinned and the host-name check is off; the pin
// requires a CA file, so the chain is still verified against it, and an
// empty pin is refused: both throw std::invalid_argument.
cpr::SslOptions make_ssl_options(const std::optional<std::string>& ca_file,
                                 const std::optional<std::string>& public_key_pin = std::nullopt);

// How a failed attempt is retried (rp::retry_policy): which TransportError a
// curl error code is.
TransportError classify(cpr::ErrorCode code) noexcept;

// What went wrong, for logs and HttpError: "could not connect",
// "connection dropped" (after the request went out: the server may have acted
// on it), "timed out", "TLS handshake failed", "TLS failure" or
// "request failed".
std::string_view describe(cpr::ErrorCode code) noexcept;

// curl's message, or "curl error <code name>" when it is empty, as it often is
// for Schannel failures.
std::string error_text(const cpr::Error& error);

} // namespace rp::detail
