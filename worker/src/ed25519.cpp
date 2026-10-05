#include <rp/ed25519.hpp>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <utility>

// The real primitive (W4.3, docs/decisions.md 2026-10-05, point 4 "Files"):
// each function is one checked call sequence into OpenSSL, whose failures for a
// good key no test can provoke, which is why this file isn't held to the
// Signer's 100% and holds no rule of its own beyond "is this an Ed25519 key".
// Nothing here copies a seed: make_key hands the caller's bytes to the library
// and keeps only the key object.

namespace rp {

namespace {

using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using CtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

constexpr std::string_view kPemBegin = "-----BEGIN PUBLIC KEY-----";
constexpr std::string_view kPemEnd = "-----END PUBLIC KEY-----";

// Leaves OpenSSL's error queue (per thread) empty on the way out, so a refused
// key here can't show up later as someone else's TLS error.
struct ClearOpenSslErrors {
    ClearOpenSslErrors() = default;
    ~ClearOpenSslErrors() { ERR_clear_error(); }
    ClearOpenSslErrors(const ClearOpenSslErrors&) = delete;
    ClearOpenSslErrors& operator=(const ClearOpenSslErrors&) = delete;
};

// The key's SubjectPublicKeyInfo DER, or empty.
std::vector<unsigned char> spki_der(EVP_PKEY* key)
{
    unsigned char* raw = nullptr;
    const int size = i2d_PUBKEY(key, &raw);
    if (size <= 0 || raw == nullptr) {
        return {};
    }
    std::vector<unsigned char> der(raw, raw + size);
    OPENSSL_free(raw);
    return der;
}

// The Ed25519 public key `der` is the SubjectPublicKeyInfo of, or null: the 44
// bytes exactly, nothing after them, and the encoding the library itself
// writes, so one key has one DER and one key_id.
KeyPtr public_key_of(std::span<const unsigned char> der)
{
    KeyPtr none(nullptr, &EVP_PKEY_free);
    if (der.size() != kEd25519PublicDerBytes) {
        return none;
    }
    const unsigned char* cursor = der.data();
    KeyPtr key(d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der.size())), &EVP_PKEY_free);
    if (!key || cursor != der.data() + der.size() ||
        EVP_PKEY_get_base_id(key.get()) != EVP_PKEY_ED25519) {
        return none;
    }
    const std::vector<unsigned char> again = spki_der(key.get());
    if (!std::equal(again.begin(), again.end(), der.begin(), der.end())) {
        return none;
    }
    return key;
}

bool is_space(char c) noexcept
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// An encrypted PEM block would have OpenSSL ask the console for a password.
int no_password(char*, int, int, void*)
{
    return -1;
}

class OpenSslKey final : public Ed25519Key {
public:
    explicit OpenSslKey(KeyPtr key) noexcept : key_(std::move(key)) {}

    std::vector<unsigned char> public_key_der() const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            return spki_der(key_.get());
        } catch (...) {
            return {};
        }
    }

    std::optional<Ed25519Signature> sign(std::span<const unsigned char> message) const override
    {
        const ClearOpenSslErrors clear_errors;
        const CtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        Ed25519Signature signature{};
        std::size_t size = signature.size();
        // An empty message still needs a pointer.
        const unsigned char none = 0;
        // One-shot, no digest named: pure Ed25519 hashes the message itself.
        if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key_.get()) != 1 ||
            EVP_DigestSign(ctx.get(), signature.data(), &size,
                           message.empty() ? &none : message.data(), message.size()) != 1 ||
            size != signature.size()) {
            return std::nullopt;
        }
        return signature;
    }

private:
    KeyPtr key_;
};

class OpenSslEd25519 final : public Ed25519 {
public:
    std::unique_ptr<Ed25519Key>
    make_key(std::span<const unsigned char, kEd25519SeedBytes> seed) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            KeyPtr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(),
                                                    seed.size()),
                       &EVP_PKEY_free);
            if (!key) {
                return nullptr;
            }
            return std::make_unique<OpenSslKey>(std::move(key));
        } catch (...) {
            return nullptr;
        }
    }

    bool verify(std::span<const unsigned char> public_key_der,
                std::span<const unsigned char> message,
                std::span<const unsigned char, kEd25519SignatureBytes> signature) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            const KeyPtr key = public_key_of(public_key_der);
            const CtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
            const unsigned char none = 0;
            return key && ctx &&
                   EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
                   EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                    message.empty() ? &none : message.data(),
                                    message.size()) == 1;
        } catch (...) {
            return false;
        }
    }

    std::string public_key_pem(std::span<const unsigned char> public_key_der) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            const KeyPtr key = public_key_of(public_key_der);
            const BioPtr bio(BIO_new(BIO_s_mem()), &BIO_free);
            if (!key || !bio || PEM_write_bio_PUBKEY(bio.get(), key.get()) != 1) {
                return {};
            }
            char* data = nullptr;
            const long size = BIO_get_mem_data(bio.get(), &data);
            if (size <= 0 || data == nullptr) {
                return {};
            }
            return std::string(data, static_cast<std::size_t>(size));
        } catch (...) {
            return {};
        }
    }

    std::vector<unsigned char> public_key_from_pem(std::string_view pem) const override
    {
        try {
            // One block and nothing around it but white space: the library's
            // reader would skip any lines before the block and stop after it.
            while (!pem.empty() && is_space(pem.front())) {
                pem.remove_prefix(1);
            }
            while (!pem.empty() && is_space(pem.back())) {
                pem.remove_suffix(1);
            }
            if (!pem.starts_with(kPemBegin) || !pem.ends_with(kPemEnd) ||
                pem.find("-----BEGIN", 1) != std::string_view::npos ||
                pem.find('\0') != std::string_view::npos) {
                return {};
            }
            const ClearOpenSslErrors clear_errors;
            const BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
            if (!bio) {
                return {};
            }
            const KeyPtr key(PEM_read_bio_PUBKEY(bio.get(), nullptr, &no_password, nullptr),
                             &EVP_PKEY_free);
            if (!key || EVP_PKEY_get_base_id(key.get()) != EVP_PKEY_ED25519) {
                return {};
            }
            std::vector<unsigned char> der = spki_der(key.get());
            if (der.size() != kEd25519PublicDerBytes) {
                return {};
            }
            return der;
        } catch (...) {
            return {};
        }
    }
};

} // namespace

const Ed25519& openssl_ed25519() noexcept
{
    static const OpenSslEd25519 primitive;
    return primitive;
}

} // namespace rp
