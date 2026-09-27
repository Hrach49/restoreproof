#pragma once

// The Worker's client certificate for the Graph sign-in (W2.1,
// docs/decisions.md). The Worker signs in to Entra as its own app,
// "RestoreProof Worker", with a certificate rather than a client secret: a
// PFX that arrives as Base64 in RP_GRAPH_CERT_PFX_BASE64, with its password
// in RP_GRAPH_CERT_PASSWORD, until the vault (W4.5). It is opened once,
// checked in full before any network call, and from then on only the key and
// certificate objects are kept. No OpenSSL type appears here.

#include <rp/graph_errors.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>

namespace spdlog {
class logger;
}

namespace rp::graph {

// A certificate the Worker can sign its client assertions with: an RSA key
// of at least 2048 bits, the certificate it belongs to, valid now. Made only
// by load_client_certificate. Movable, not copyable; a moved-from one must
// not be used.
class ClientCertificate {
public:
    // Opaque: holds the OpenSSL key and certificate. Defined in rpcore only.
    struct Impl;

    explicit ClientCertificate(std::unique_ptr<Impl> impl) noexcept;
    ~ClientCertificate();
    ClientCertificate(ClientCertificate&&) noexcept;
    ClientCertificate& operator=(ClientCertificate&&) noexcept;
    ClientCertificate(const ClientCertificate&) = delete;
    ClientCertificate& operator=(const ClientCertificate&) = delete;

    // The SHA-1 of the certificate's DER encoding in uppercase hex: its
    // thumbprint as Windows and the Entra portal show it, which is how
    // messages name it.
    const std::string& sha1_thumbprint() const noexcept;
    // The base64url SHA-256 of the certificate's DER encoding, without
    // padding: the assertion header's "x5t#S256", by which Entra finds the
    // key.
    const std::string& x5t_s256() const noexcept;
    // The certificate's validity, to the second.
    std::chrono::system_clock::time_point not_before() const noexcept;
    std::chrono::system_clock::time_point not_after() const noexcept;

    // For rpcore's own use (the assertion signer).
    const Impl& impl() const noexcept;

private:
    std::unique_ptr<Impl> impl_;
};

// What the messages call the two secrets: the variables they come from.
struct CertificateSecretNames {
    std::string_view pfx_base64 = "RP_GRAPH_CERT_PFX_BASE64";
    std::string_view password = "RP_GRAPH_CERT_PASSWORD";
};

// A warning is logged when the certificate expires this soon.
inline constexpr std::chrono::hours kCertificateExpiryWarning{30 * 24};

// Opens the PFX that `pfx_base64` holds in standard Base64 with `password` and
// checks it, in this order, throwing CertificateError at the first problem:
// `pfx_base64` is empty ("<name> is not set"); it isn't strict Base64
// (rp::base64_decode: one line, no spaces); the bytes aren't a PFX; the PFX
// has no MAC, so the password can't be checked (refused); the password doesn't
// open it (an empty password is tried both as "" and as no password, and is
// right only if the PFX really has none); it can't be read because it uses a
// legacy cipher (RC2 and the like, which OpenSSL 3 no longer reads: re-export
// it with AES256_SHA256); it holds no private key, or no certificate, or a
// key that matches none of its certificates; the key isn't RSA of at least
// 2048 bits; or the certificate isn't valid at `wall_now` (expired, or not
// valid yet). Messages name the variables of `names`, never a value.
//
// A certificate that expires within kCertificateExpiryWarning is loaded and
// a warning logged to `logger`, or spdlog's default logger when null (and
// nothing when that's gone too). The decoded bytes and the copy of the
// password are wiped on every path, errors included.
ClientCertificate load_client_certificate(std::string_view pfx_base64, std::string_view password,
                                          std::chrono::system_clock::time_point wall_now,
                                          const CertificateSecretNames& names = {},
                                          std::shared_ptr<spdlog::logger> logger = nullptr);

} // namespace rp::graph
