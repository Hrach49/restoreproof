#pragma once

// Internals of http_client.cpp that the tests inspect directly. Not part of
// rpcore's interface: it names cpr types, and cpr is private to rpcore.

#include <rp/retry_policy.hpp>

#include <cpr/error.h>
#include <cpr/ssl_options.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

struct sockaddr; // winsock2.h's

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

// Q2.1's network guard, for the unit tests only (tests/test_main.cpp turns it
// on unless RP_LIVE=1; the Worker never does). While it is on, HttpClient
// connects to the loopback range alone (127.0.0.0/8 and ::1): a URL whose host
// isn't "localhost", an IPv4 literal starting 127. or "[::1]" is refused
// before anything is looked up or sent (HttpError, TransportError::connect,
// attempts() 0), and any other address curl would open a socket to is
// refused before the socket exists (curl's connect error). Each refusal is
// counted. Process-wide; returns the previous setting.
bool set_loopback_only(bool on) noexcept;

// The refusals counted since the last call, and the count back to 0.
std::uint64_t take_refused_connections() noexcept;

// Whether the URL's host is one set_loopback_only lets through by name:
// "localhost" in any case, an IPv4 literal whose first part is 127, or
// "[::1]". Userinfo and port are ignored. An IPv6 host without its closing
// ']' is let through too: curl refuses that URL before any lookup.
bool is_loopback_url(std::string_view url) noexcept;

// Whether a socket address curl would connect to is one set_loopback_only
// lets through: IPv4 127.0.0.0/8 or IPv6 ::1. Anything else, an IPv4-mapped
// IPv6 address included, isn't.
bool is_loopback_sockaddr(const ::sockaddr* address) noexcept;

} // namespace rp::detail
