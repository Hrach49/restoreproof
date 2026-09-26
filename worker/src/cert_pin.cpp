#include <rp/cert_pin.hpp>

#include "path_utf8.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>

namespace rp {

namespace {

// A CA bundle is a few kilobytes; the whole Mozilla store is about 200 KiB.
constexpr std::size_t kMaxCaFileBytes = 1024 * 1024;

using Digest = std::array<unsigned char, SHA256_DIGEST_LENGTH>;

int hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// `hex` is is_sha256_hex().
Digest parse_hex(std::string_view hex) noexcept
{
    Digest out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>(hex_value(hex[2 * i]) * 16 + hex_value(hex[2 * i + 1]));
    }
    return out;
}

std::string read_ca_file(std::string_view ca_file)
{
    const std::optional<std::filesystem::path> path = path_from_utf8(ca_file);
    std::ifstream file;
    if (path) {
        file.open(*path, std::ios::binary);
    }
    if (!file) {
        throw CertPinError("veeam_ca_file can't be read");
    }
    std::string text;
    text.resize(kMaxCaFileBytes + 1);
    file.read(text.data(), static_cast<std::streamsize>(text.size()));
    text.resize(static_cast<std::size_t>(file.gcount()));
    if (text.size() > kMaxCaFileBytes) {
        throw CertPinError("veeam_ca_file is larger than 1 MiB");
    }
    return text;
}

// SHA-256 over `size` bytes that OpenSSL allocated at `der`, which it frees.
Digest sha256_and_free(unsigned char* der, int size)
{
    Digest digest{};
    const std::unique_ptr<unsigned char, void (*)(unsigned char*)> owner(
        der, [](unsigned char* p) { OPENSSL_free(p); });
    if (size <= 0 || SHA256(der, static_cast<std::size_t>(size), digest.data()) == nullptr) {
        throw CertPinError("veeam_ca_file holds a certificate that can't be encoded");
    }
    return digest;
}

std::string base64(const Digest& digest)
{
    // 32 bytes -> 44 characters, plus EVP_EncodeBlock's terminating NUL.
    std::array<unsigned char, 4 * ((SHA256_DIGEST_LENGTH + 2) / 3) + 1> out{};
    const int length = EVP_EncodeBlock(out.data(), digest.data(), static_cast<int>(digest.size()));
    return {reinterpret_cast<const char*>(out.data()), static_cast<std::size_t>(length)};
}

} // namespace

bool is_sha256_hex(std::string_view text) noexcept
{
    return text.size() == 2 * SHA256_DIGEST_LENGTH &&
           std::all_of(text.begin(), text.end(), [](char c) { return hex_value(c) >= 0; });
}

std::string public_key_pin(std::string_view ca_file, std::string_view cert_sha256)
{
    if (!is_sha256_hex(cert_sha256)) {
        throw CertPinError("veeam_cert_sha256 must be 64 hexadecimal digits");
    }
    const Digest wanted = parse_hex(cert_sha256);
    const std::string text = read_ca_file(ca_file);
    // Reading to the end of the PEM data leaves a "no start line" error
    // queued, and a failed encoding leaves its own; none may surface in some
    // later, unrelated OpenSSL call, whichever way this function ends.
    struct ClearErrors {
        ~ClearErrors() { ERR_clear_error(); }
    } const clear_errors;

    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(text.data(), static_cast<int>(text.size())), &BIO_free);
    if (!bio) {
        throw CertPinError("veeam_ca_file can't be read");
    }
    // PEM_read_bio_X509 skips anything between certificates (text, a private
    // key) and returns null at the end of the data.
    std::optional<std::string> pin;
    for (;;) {
        const std::unique_ptr<X509, decltype(&X509_free)> cert(
            PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free);
        if (!cert) {
            break;
        }
        unsigned char* cert_der = nullptr;
        const int cert_size = i2d_X509(cert.get(), &cert_der);
        if (sha256_and_free(cert_der, cert_size) != wanted) {
            continue;
        }
        unsigned char* key_der = nullptr;
        const int key_size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert.get()), &key_der);
        pin = base64(sha256_and_free(key_der, key_size));
        break;
    }
    if (!pin) {
        throw CertPinError("veeam_ca_file holds no certificate whose SHA-256 is veeam_cert_sha256");
    }
    return *pin;
}

} // namespace rp
