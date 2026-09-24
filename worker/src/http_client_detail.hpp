#pragma once

// Internals of http_client.cpp that the tests inspect directly. Not part of
// rpcore's interface: it names cpr types, and cpr is private to rpcore.

#include <rp/retry_policy.hpp>

#include <cpr/error.h>
#include <cpr/ssl_options.h>

#include <optional>
#include <string>

namespace rp::detail {

// The TLS options every attempt uses: peer and host verification on, no
// revocation opt-out, and, when `ca_file` (UTF-8) is set, that PEM bundle as
// the only trusted roots in place of the Windows store.
cpr::SslOptions make_ssl_options(const std::optional<std::string>& ca_file);

// How a failed attempt is retried (rp::retry_policy): which TransportError a
// curl error code is.
TransportError classify(cpr::ErrorCode code) noexcept;

} // namespace rp::detail
