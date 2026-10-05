#pragma once

// Ed25519 (RFC 8032) as the Signer uses it (W4.3, docs/decisions.md 2026-10-05,
// point 4 "Files"): a small interface the Signer works over, so a test can
// hand it a primitive that fails, and the real one over OpenSSL
// (src/ed25519.cpp). No OpenSSL type appears here.

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

inline constexpr std::size_t kEd25519SeedBytes = 32;
inline constexpr std::size_t kEd25519SignatureBytes = 64;
// A public key's SubjectPublicKeyInfo DER: twelve bytes of header and the key.
inline constexpr std::size_t kEd25519PublicDerBytes = 44;

using Ed25519Signature = std::array<unsigned char, kEd25519SignatureBytes>;

// A private key. It never gives its seed back.
class Ed25519Key {
public:
    virtual ~Ed25519Key() = default;

    // The public half as SubjectPublicKeyInfo DER (kEd25519PublicDerBytes), or
    // empty when it can't be made.
    virtual std::vector<unsigned char> public_key_der() const = 0;

    // The signature of `message` (pure Ed25519: the message itself, no
    // prehash), or nullopt.
    virtual std::optional<Ed25519Signature> sign(std::span<const unsigned char> message) const = 0;
};

// The primitive. The real one never throws; the Signer takes one that does.
class Ed25519 {
public:
    virtual ~Ed25519() = default;

    // The key of the 32-byte seed (RFC 8032's "secret key"), or null. The seed
    // goes to the library as raw bytes, never through an ASN.1 reader, and no
    // copy of it is made here.
    virtual std::unique_ptr<Ed25519Key>
    make_key(std::span<const unsigned char, kEd25519SeedBytes> seed) const = 0;

    // Whether `signature` is `message`'s under the public key `public_key_der`
    // (SubjectPublicKeyInfo DER). False for anything else, a key that isn't an
    // Ed25519 public key included.
    virtual bool verify(std::span<const unsigned char> public_key_der,
                        std::span<const unsigned char> message,
                        std::span<const unsigned char, kEd25519SignatureBytes> signature) const = 0;

    // The public key as PEM ("-----BEGIN PUBLIC KEY-----", one body line, each
    // line ending in LF), or empty when `public_key_der` isn't an Ed25519
    // public key.
    virtual std::string public_key_pem(std::span<const unsigned char> public_key_der) const = 0;

    // The SubjectPublicKeyInfo DER of the public key `pem` holds, or empty
    // unless it is one PEM block of an Ed25519 public key.
    virtual std::vector<unsigned char> public_key_from_pem(std::string_view pem) const = 0;
};

// The real primitive, over OpenSSL: one object for the process, thread-safe.
const Ed25519& openssl_ed25519() noexcept;

} // namespace rp
