#pragma once

// Test keys and fakes for the Signer (W4.3). The only keys here are RFC 8032's
// published test keys (section 7.1, tests 1 and 2), the ones
// shared/testdata/signing-v1/keys.json names: never a secret.

#include <rp/base64.hpp>
#include <rp/ed25519.hpp>
#include <rp/signer.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rp::test {

inline constexpr std::string_view kSigningKey1Name = "rfc8032-test-1";
inline constexpr std::string_view kSigningKey2Name = "rfc8032-test-2";
inline constexpr std::string_view kSigningSeed1Hex =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
inline constexpr std::string_view kSigningSeed2Hex =
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

// Ed25519's PKCS#8 header (RFC 8410): the 32-byte seed follows.
inline constexpr std::string_view kPkcs8PrefixHex = "302e020100300506032b657004220420";

// Test 1's key as RP_SIGNING_KEY_BASE64 carries it, as measured with OpenSSL.
inline constexpr std::string_view kSigningKey1Base64 =
    "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g";

inline std::vector<unsigned char> bytes_from_hex(std::string_view hex)
{
    const auto nibble = [](char c) {
        return static_cast<unsigned char>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    REQUIRE(hex.size() % 2 == 0);
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<unsigned char>(nibble(hex[i]) << 4 | nibble(hex[i + 1])));
    }
    return bytes;
}

inline std::string hex_from_bytes(std::span<const unsigned char> bytes)
{
    constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    for (const unsigned char byte : bytes) {
        hex += kHex[byte >> 4];
        hex += kHex[byte & 0x0f];
    }
    return hex;
}

// The Base64 of the PKCS#8 DER of the Ed25519 key with this seed.
inline std::string pkcs8_base64(std::string_view seed_hex)
{
    return base64_encode(bytes_from_hex(std::string{kPkcs8PrefixHex} + std::string{seed_hex}));
}

inline std::string signing_key2_base64()
{
    return pkcs8_base64(kSigningSeed2Hex);
}

inline SigningKey signing_key(std::string_view base64 = kSigningKey1Base64,
                              const Ed25519& primitive = openssl_ed25519())
{
    std::optional<SigningKey> key = SigningKey::from_base64(base64, primitive);
    REQUIRE(key);
    return std::move(*key);
}

inline PublicKey public_key_of(const SigningKey& key, const Ed25519& primitive = openssl_ed25519())
{
    const std::optional<PublicKey> pub = PublicKey::from_pem(key.public_key_pem(), primitive);
    REQUIRE(pub);
    return *pub;
}

// Where a FakeEd25519 fails. Everything else it hands to the real primitive.
enum class Ed25519Fault {
    none,
    make_key_null,
    make_key_throws,
    der_empty,
    der_short, // 43 bytes
    der_throws,
    pem_empty,
    pem_throws,
    sign_none,
    sign_throws,
    sign_other, // a good signature of another message
    check_false,
    check_throws,
    is_key_false,
    is_key_throws,
    is_key_any // a primitive that takes whatever it is asked about
};

class FakeEd25519 final : public Ed25519 {
public:
    // May be changed after a key is made: the key reads it at each call.
    mutable Ed25519Fault fault = Ed25519Fault::none;

    explicit FakeEd25519(Ed25519Fault at = Ed25519Fault::none) : fault(at) {}

    std::unique_ptr<Ed25519Key>
    make_key(std::span<const unsigned char, kEd25519SeedBytes> seed) const override
    {
        if (fault == Ed25519Fault::make_key_throws) {
            throw std::runtime_error("make_key");
        }
        if (fault == Ed25519Fault::make_key_null) {
            return nullptr;
        }
        return std::make_unique<Key>(*this, openssl_ed25519().make_key(seed));
    }

    bool verify(std::span<const unsigned char> public_key_der,
                std::span<const unsigned char> message,
                std::span<const unsigned char, kEd25519SignatureBytes> signature) const override
    {
        if (fault == Ed25519Fault::check_throws) {
            throw std::runtime_error("verify");
        }
        return fault != Ed25519Fault::check_false &&
               openssl_ed25519().verify(public_key_der, message, signature);
    }

    std::string public_key_pem(std::span<const unsigned char> public_key_der) const override
    {
        if (fault == Ed25519Fault::pem_throws) {
            throw std::runtime_error("public_key_pem");
        }
        return fault == Ed25519Fault::pem_empty ? std::string{}
                                                : openssl_ed25519().public_key_pem(public_key_der);
    }

    bool is_public_key(std::span<const unsigned char> public_key_der) const override
    {
        if (fault == Ed25519Fault::is_key_throws) {
            throw 42; // not a std::exception
        }
        if (fault == Ed25519Fault::is_key_any) {
            return true;
        }
        return fault != Ed25519Fault::is_key_false &&
               openssl_ed25519().is_public_key(public_key_der);
    }

private:
    class Key final : public Ed25519Key {
    public:
        Key(const FakeEd25519& owner, std::unique_ptr<Ed25519Key> real)
            : owner_(owner), real_(std::move(real))
        {
        }

        std::vector<unsigned char> public_key_der() const override
        {
            if (owner_.fault == Ed25519Fault::der_throws) {
                throw std::runtime_error("public_key_der");
            }
            if (owner_.fault == Ed25519Fault::der_empty) {
                return {};
            }
            std::vector<unsigned char> der = real_->public_key_der();
            if (owner_.fault == Ed25519Fault::der_short) {
                der.pop_back();
            }
            return der;
        }

        std::optional<Ed25519Signature>
        sign(std::span<const unsigned char> message) const override
        {
            if (owner_.fault == Ed25519Fault::sign_throws) {
                throw 42; // not a std::exception
            }
            if (owner_.fault == Ed25519Fault::sign_none) {
                return std::nullopt;
            }
            if (owner_.fault == Ed25519Fault::sign_other) {
                const unsigned char other[] = {'o', 't', 'h', 'e', 'r'};
                return real_->sign(other);
            }
            return real_->sign(message);
        }

    private:
        const FakeEd25519& owner_;
        std::unique_ptr<Ed25519Key> real_;
    };
};

// A folder held in memory, and what its reader was asked for.
struct MemoryFolder {
    std::map<std::string, std::string> files;
    std::shared_ptr<std::vector<std::pair<std::string, std::uintmax_t>>> asked =
        std::make_shared<std::vector<std::pair<std::string, std::uintmax_t>>>();

    FileReader reader() const
    {
        return [files = files, asked = asked](std::string_view name,
                                              std::uintmax_t limit) -> FileRead {
            asked->emplace_back(std::string{name}, limit);
            const auto it = files.find(std::string{name});
            if (it == files.end()) {
                return {};
            }
            if (it->second.size() > limit) {
                return {FileState::too_large, {}};
            }
            return {FileState::read, it->second};
        };
    }

    std::vector<std::string> names() const
    {
        std::vector<std::string> out;
        for (const auto& [name, bytes] : files) {
            out.push_back(name);
        }
        return out;
    }
};

} // namespace rp::test
