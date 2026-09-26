#include <rp/cert_pin.hpp>

#include "path_utf8.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <vector>

namespace rp {

namespace {

// A CA bundle is a few kilobytes; the whole Mozilla store is about 200 KiB.
// curl's Schannel backend refuses a larger CA file too (MAX_CAFILE_SIZE).
constexpr std::size_t kMaxCaFileBytes = 1024 * 1024;

// The markers curl's Schannel backend looks for (BEGIN_CERT, END_CERT).
constexpr std::string_view kBeginCert = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view kEndCert = "\n-----END CERTIFICATE-----";

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

// The DER encoding of each certificate curl's Schannel backend loads from the
// CA file `text`, read the way it reads it (add_certs_data_to_store in curl's
// lib/vtls/schannel_verify.c), with the same Windows decoder: from each
// "-----BEGIN CERTIFICATE-----" followed by CR or LF through the next
// "\n-----END CERTIFICATE-----", decoded by CryptQueryObject. Like curl, it
// stops at the first BEGIN marker that doesn't end its line (curl loads what
// it has so far and says nothing), and fails on a block without its end or
// one it can't decode (curl fails the whole file). OpenSSL's PEM reader is
// more lenient (a trailing space, the old "X509 CERTIFICATE" label), and
// would ask for a pass phrase on the console for a block with PEM encryption
// headers.
std::vector<std::string> certificates_curl_loads(const std::string& text)
{
    std::vector<std::string> out;
    std::size_t at = 0;
    while (at < text.size()) {
        // curl searches all but the last byte, then reads the byte after the
        // marker, which is its buffer's terminating NUL at the very end.
        const std::size_t found =
            std::string_view{text}.substr(0, text.size() - 1).find(kBeginCert, at);
        if (found == std::string_view::npos) {
            break;
        }
        const std::size_t after = found + kBeginCert.size();
        const char next = after < text.size() ? text[after] : '\0';
        if (next != '\r' && next != '\n') {
            break;
        }
        const std::size_t end = text.find(kEndCert, found);
        if (end == std::string::npos) {
            throw CertPinError(
                "veeam_ca_file has a BEGIN CERTIFICATE line without its END CERTIFICATE line");
        }
        const std::size_t block_end = end + kEndCert.size();
        CERT_BLOB blob{};
        blob.cbData = static_cast<DWORD>(block_end - found);
        blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(text.data() + found));
        const CERT_CONTEXT* context = nullptr;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_CERT,
                              CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED, 0, nullptr, nullptr, nullptr,
                              nullptr, nullptr, reinterpret_cast<const void**>(&context))) {
            throw CertPinError("veeam_ca_file holds a certificate block that can't be read");
        }
        const std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)> owner(
            context, &CertFreeCertificateContext);
        out.emplace_back(reinterpret_cast<const char*>(context->pbCertEncoded),
                         static_cast<std::size_t>(context->cbCertEncoded));
        at = block_end;
    }
    return out;
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
    const std::vector<std::string> certificates = certificates_curl_loads(read_ca_file(ca_file));
    if (certificates.empty()) {
        throw CertPinError("veeam_ca_file holds no certificate curl can read: each must begin "
                           "with a line that is exactly -----BEGIN CERTIFICATE-----");
    }
    // A failed decoding or encoding leaves an error queued; none may surface
    // in some later, unrelated OpenSSL call, whichever way this function ends.
    struct ClearErrors {
        ~ClearErrors() { ERR_clear_error(); }
    } const clear_errors;

    for (const std::string& der : certificates) {
        Digest digest{};
        SHA256(reinterpret_cast<const unsigned char*>(der.data()), der.size(), digest.data());
        if (digest != wanted) {
            continue;
        }
        const auto* bytes = reinterpret_cast<const unsigned char*>(der.data());
        const std::unique_ptr<X509, decltype(&X509_free)> cert(
            d2i_X509(nullptr, &bytes, static_cast<long>(der.size())), &X509_free);
        if (!cert) {
            throw CertPinError("veeam_ca_file holds a certificate that can't be read");
        }
        unsigned char* key_der = nullptr;
        const int key_size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert.get()), &key_der);
        return base64(sha256_and_free(key_der, key_size));
    }
    throw CertPinError("veeam_ca_file holds no certificate whose SHA-256 is veeam_cert_sha256");
}

} // namespace rp
