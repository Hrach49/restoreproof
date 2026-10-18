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
#include <string>
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

// What an export says of a private key this process couldn't acquire, Windows' `code` given
// (W7.2 point 7): CRYPT_E_NO_KEY_PROPERTY is no key at all; NTE_BAD_KEYSET (0x80090016), which
// CAPI and CNG answer both for a key file this account may not read and for no key file, names
// both and points to rpworker doctor, which tells them apart; any other code is said as it is.
std::string private_key_refusal(std::string_view name, unsigned long code);

// The reason that goes with private_key_refusal's words: no_private_key for
// CRYPT_E_NO_KEY_PROPERTY, key_unopenable for every other code.
CertExportFailure private_key_failure(unsigned long code) noexcept;

// A FILETIME (100 ns ticks since 1601-01-01 UTC) on the system clock.
std::chrono::system_clock::time_point to_time_point(const FILETIME& time) noexcept;

} // namespace rp::cert_export_detail
