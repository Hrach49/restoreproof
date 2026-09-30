#pragma once

// cert_export.cpp's core on a store the caller has opened, so a test can run
// it on an in-memory store built from a test PFX instead of LocalMachine\My.

#include <rp/cert_export.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <wincrypt.h>

#include <array>
#include <chrono>
#include <string_view>

namespace rp::cert_export_detail {

// `thumbprint` as 20 bytes, or CertExportError unless it is exactly 40 hex
// digits (either case).
std::array<BYTE, 20> parse_thumbprint(std::string_view thumbprint);

// The certificate with that SHA-1 thumbprint in `store`, exported with its
// private key as a PFX (standard Base64) under a fresh password of 32 random
// bytes (Base64). `store_name` only names the store in messages. Refuses (as
// CertExportError) a malformed thumbprint before touching the store, then a
// certificate that isn't there, isn't valid at `wall_now`, has no private key
// or whose key can't be exported.
ExportedPfx export_from_store(HCERTSTORE store, std::string_view thumbprint,
                              std::chrono::system_clock::time_point wall_now,
                              std::string_view store_name);

// A FILETIME (100 ns ticks since 1601-01-01 UTC) on the system clock.
std::chrono::system_clock::time_point to_time_point(const FILETIME& time) noexcept;

} // namespace rp::cert_export_detail
