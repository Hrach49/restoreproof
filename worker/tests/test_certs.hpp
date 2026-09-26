#pragma once

// Certificates made at test time, for the TLS and certificate-pin tests: EC
// P-256 keys (RSA 2048 for the Veeam-shaped one), valid from an hour ago for a
// day unless asked otherwise.

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <memory>
#include <random>
#include <string>
#include <string_view>

namespace rp::test {

struct Pem {
    std::string cert;
    std::string key;
};

inline std::string bio_to_string(BIO* bio)
{
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio, &data);
    return {data, static_cast<std::size_t>(length)};
}

using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;

// A certificate and its private key.
struct Cert {
    KeyPtr key{nullptr, &EVP_PKEY_free};
    CertPtr cert{nullptr, &X509_free};

    Pem pem() const
    {
        const std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new(BIO_s_mem()), &BIO_free);
        const std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new(BIO_s_mem()), &BIO_free);
        REQUIRE(PEM_write_bio_X509(cert_bio.get(), cert.get()) == 1);
        REQUIRE(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr,
                                         nullptr) == 1);
        return {bio_to_string(cert_bio.get()), bio_to_string(key_bio.get())};
    }
};

// `issuer` is null for a self-signed certificate.
inline void add_extension(X509* cert, const X509* issuer, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, const_cast<X509*>(issuer ? issuer : cert), cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    REQUIRE(ext != nullptr);
    REQUIRE(X509_add_ext(cert, ext, -1) == 1);
    X509_EXTENSION_free(ext);
}

enum class Role {
    self_signed_server, // CA:TRUE and a server certificate at once, naming 127.0.0.1
    ca,                 // a private CA that issues server certificates
    leaf,               // a server certificate issued by `issuer`, naming 127.0.0.1
    // Veeam's default REST certificate: self-signed RSA 2048, subject
    // CN=Veeam Software, O=Veeam Software, OU=Veeam Software, and no
    // extensions at all, so no subject alternative name and no host name
    // that could ever match.
    veeam_default,
};

// A certificate for `role`. Server certificates (self_signed_server and leaf)
// name 127.0.0.1 and localhost. `crl_url`, for a leaf, is its CRL distribution
// point. The validity runs from an hour ago for a day, or, with `expired`,
// ended an hour ago.
inline Cert make_cert(const char* common_name, Role role, const Cert* issuer = nullptr,
                      const char* crl_url = nullptr, bool expired = false)
{
    REQUIRE((role == Role::leaf) == (issuer != nullptr));
    Cert out;
    out.key.reset(role == Role::veeam_default ? EVP_RSA_gen(2048) : EVP_EC_gen("P-256"));
    REQUIRE(out.key);
    out.cert.reset(X509_new());
    REQUIRE(out.cert);
    X509* cert = out.cert.get();
    REQUIRE(X509_set_version(cert, X509_VERSION_3) == 1);
    // A random serial: two certificates with the same issuer name and serial
    // could confuse the verifier (and a CRL names certificates by serial).
    std::random_device rd;
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert), static_cast<long>(rd() >> 1)) == 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), expired ? -2 * 86400 : -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert), expired ? -3600 : 86400);
    X509_NAME* name = X509_get_subject_name(cert);
    const auto add_name = [name](const char* field, const char* value) {
        REQUIRE(X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                                           reinterpret_cast<const unsigned char*>(value), -1, -1,
                                           0) == 1);
    };
    add_name("CN", common_name);
    if (role == Role::veeam_default) {
        add_name("O", common_name);
        add_name("OU", common_name);
    }
    const X509* issuer_cert = issuer ? issuer->cert.get() : nullptr;
    REQUIRE(X509_set_issuer_name(cert, issuer_cert ? X509_get_subject_name(issuer_cert) : name) ==
            1);
    REQUIRE(X509_set_pubkey(cert, out.key.get()) == 1);
    if (role != Role::veeam_default) {
        add_extension(cert, issuer_cert, NID_subject_key_identifier, "hash");
        add_extension(cert, issuer_cert, NID_authority_key_identifier, "keyid:always");
    }
    switch (role) {
    case Role::self_signed_server:
        add_extension(cert, nullptr, NID_basic_constraints, "critical,CA:TRUE");
        add_extension(cert, nullptr, NID_key_usage, "critical,digitalSignature,keyCertSign");
        break;
    case Role::ca:
        add_extension(cert, nullptr, NID_basic_constraints, "critical,CA:TRUE");
        add_extension(cert, nullptr, NID_key_usage, "critical,keyCertSign,cRLSign");
        break;
    case Role::leaf:
        add_extension(cert, issuer_cert, NID_basic_constraints, "critical,CA:FALSE");
        add_extension(cert, issuer_cert, NID_key_usage, "critical,digitalSignature");
        if (crl_url) {
            add_extension(cert, issuer_cert, NID_crl_distribution_points,
                          (std::string{"URI:"} + crl_url).c_str());
        }
        break;
    case Role::veeam_default:
        break;
    }
    if (role == Role::self_signed_server || role == Role::leaf) {
        add_extension(cert, issuer_cert, NID_subject_alt_name, "IP:127.0.0.1,DNS:localhost");
        add_extension(cert, issuer_cert, NID_ext_key_usage, "serverAuth");
    }
    EVP_PKEY* signer = issuer ? issuer->key.get() : out.key.get();
    REQUIRE(X509_sign(cert, signer, EVP_sha256()) > 0);
    return out;
}

inline Pem make_self_signed(const char* common_name)
{
    return make_cert(common_name, Role::self_signed_server).pem();
}

// `bytes` as uppercase hex, as PowerShell's GetCertHashString('SHA256') prints.
inline std::string to_hex(const unsigned char* bytes, std::size_t size)
{
    std::string out;
    char pair[3];
    for (std::size_t i = 0; i < size; ++i) {
        std::snprintf(pair, sizeof(pair), "%02X", bytes[i]);
        out += pair;
    }
    return out;
}

// The certificate's SHA-256 over its DER encoding, uppercase hex: the value
// Windows shows and veeam_cert_sha256 holds.
inline std::string cert_sha256_hex(const Cert& cert)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    REQUIRE(X509_digest(cert.cert.get(), EVP_sha256(), digest, &size) == 1);
    return to_hex(digest, size);
}

// The base64 SHA-256 of the certificate's SubjectPublicKeyInfo: what curl's
// CURLOPT_PINNEDPUBLICKEY takes after "sha256//". Computed from the key, not
// the certificate, so it checks the code under test from another side.
inline std::string spki_sha256_base64(const Cert& cert)
{
    unsigned char* der = nullptr;
    const int length = i2d_PUBKEY(cert.key.get(), &der);
    REQUIRE(length > 0);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der, static_cast<std::size_t>(length), digest);
    OPENSSL_free(der);
    unsigned char base64[4 * ((SHA256_DIGEST_LENGTH + 2) / 3) + 1];
    REQUIRE(EVP_EncodeBlock(base64, digest, SHA256_DIGEST_LENGTH) == 44);
    return reinterpret_cast<const char*>(base64);
}

} // namespace rp::test
