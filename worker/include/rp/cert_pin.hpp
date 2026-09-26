#pragma once

// Pinning Veeam's REST certificate (W1.5, docs/decisions.md 2026-09-26).
// Veeam's default certificate is self-signed with no subject alternative name
// (CN=Veeam Software), so no host name ever verifies against it. The Worker
// names it by its SHA-256 (Config::veeam_cert_sha256, as Windows shows it)
// and trusts it through veeam_ca_file; curl then pins its public key, which
// is what this file computes.

#include <stdexcept>
#include <string>
#include <string_view>

namespace rp {

// Whether `text` is a SHA-256 written as exactly 64 hexadecimal digits, in any
// case, with no separators: what PowerShell's GetCertHashString('SHA256')
// prints.
bool is_sha256_hex(std::string_view text) noexcept;

// Why a pin couldn't be computed. what() names the setting at fault and never
// quotes the file's contents.
class CertPinError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The public-key pin of the certificate in the PEM file `ca_file` (a UTF-8
// path) whose SHA-256, over its DER encoding, is `cert_sha256`: the base64
// SHA-256 of that certificate's SubjectPublicKeyInfo, the form curl's
// CURLOPT_PINNEDPUBLICKEY takes after "sha256//". The file may hold other
// certificates too (a CA and its leaf); only PEM is read, as curl's Schannel
// backend reads only PEM from a CA file. Throws CertPinError when
// `cert_sha256` isn't is_sha256_hex(), the file can't be read or is over
// 1 MiB, or it holds no such certificate.
std::string public_key_pin(std::string_view ca_file, std::string_view cert_sha256);

} // namespace rp
