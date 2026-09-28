#pragma once

// Certificates made at test time, for the TLS and certificate-pin tests: EC
// P-256 keys (RSA 2048 for the Veeam-shaped one), valid from an hour ago for a
// day unless asked otherwise. Also the Graph sign-in's client certificates and
// the PFX files that carry them (make_client_cert, make_pfx), in every shape
// the loader must refuse. No key material is committed: all of it is made
// here, at test time.

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <ctime>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

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

// --- The Graph sign-in's client certificate and its PFX (W2.1) ---

enum class KeyType {
    rsa2048, // what Entra's PS256 client assertion needs (RSA, at least 2048 bits)
    rsa1024, // too short: refused
    ec_p256, // not RSA: refused
};

// One RSA-2048 key for the whole test run, since making one takes a good part
// of a second. Each call returns a new reference to the same key.
inline KeyPtr shared_rsa2048_key()
{
    static EVP_PKEY* const key = EVP_RSA_gen(2048);
    REQUIRE(key != nullptr);
    REQUIRE(EVP_PKEY_up_ref(key) == 1);
    return KeyPtr(key, &EVP_PKEY_free);
}

// A key of `type`: the shared RSA-2048 one unless `fresh`.
inline KeyPtr make_key(KeyType type, bool fresh = false)
{
    KeyPtr key(nullptr, &EVP_PKEY_free);
    switch (type) {
    case KeyType::rsa2048:
        if (!fresh) {
            return shared_rsa2048_key();
        }
        key.reset(EVP_RSA_gen(2048));
        break;
    case KeyType::rsa1024:
        key.reset(EVP_RSA_gen(1024));
        break;
    case KeyType::ec_p256:
        key.reset(EVP_EC_gen("P-256"));
        break;
    }
    REQUIRE(key);
    return key;
}

struct ClientCertOptions {
    KeyType key = KeyType::rsa2048;
    // A key of its own rather than the shared RSA-2048 one (for a key that
    // must not match another certificate's).
    bool fresh_key = false;
    // The validity, in seconds from `now`; negative is in the past.
    long not_before = -3600;
    long not_after = 365L * 86400;
    // What the offsets count from; 0 is the real current time.
    std::time_t now = 0;
    // A GeneralizedTime ("99991231235959Z") that replaces the offset, for
    // dates no time_t offset reaches.
    const char* not_before_text = nullptr;
    const char* not_after_text = nullptr;
};

// A self-signed client certificate as lab/entra/new-worker-app.ps1 makes for
// the Worker's Entra app: CN=`common_name`, digitalSignature, clientAuth.
inline Cert make_client_cert(const char* common_name, const ClientCertOptions& options = {})
{
    Cert out;
    out.key = make_key(options.key, options.fresh_key);
    out.cert.reset(X509_new());
    REQUIRE(out.cert);
    X509* cert = out.cert.get();
    REQUIRE(X509_set_version(cert, X509_VERSION_3) == 1);
    std::random_device rd;
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert), static_cast<long>(rd() >> 1)) == 1);
    std::time_t now = options.now != 0 ? options.now : std::time(nullptr);
    REQUIRE(X509_time_adj_ex(X509_getm_notBefore(cert), 0, options.not_before, &now) != nullptr);
    REQUIRE(X509_time_adj_ex(X509_getm_notAfter(cert), 0, options.not_after, &now) != nullptr);
    if (options.not_before_text != nullptr) {
        REQUIRE(ASN1_TIME_set_string_X509(X509_getm_notBefore(cert), options.not_before_text) == 1);
    }
    if (options.not_after_text != nullptr) {
        REQUIRE(ASN1_TIME_set_string_X509(X509_getm_notAfter(cert), options.not_after_text) == 1);
    }
    X509_NAME* name = X509_get_subject_name(cert);
    REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>(common_name), -1,
                                       -1, 0) == 1);
    REQUIRE(X509_set_issuer_name(cert, name) == 1);
    REQUIRE(X509_set_pubkey(cert, out.key.get()) == 1);
    add_extension(cert, nullptr, NID_basic_constraints, "critical,CA:FALSE");
    add_extension(cert, nullptr, NID_key_usage, "critical,digitalSignature");
    add_extension(cert, nullptr, NID_ext_key_usage, "clientAuth");
    REQUIRE(X509_sign(cert, out.key.get(), EVP_sha256()) > 0);
    return out;
}

enum class PfxCipher {
    // OpenSSL 3's PKCS12_create default and Windows' AES256_SHA256
    // (Export-PfxCertificate -CryptoAlgorithmOption): PBES2 with AES-256-CBC
    // and PBKDF2-HMAC-SHA256, and a SHA-256 MAC.
    aes256,
    // Windows' older TripleDES_SHA1: key and certificate under
    // pbeWithSHA1And3-KeyTripleDES-CBC, and a SHA-1 MAC. OpenSSL 3's default
    // provider still reads (and writes) it.
    legacy_3des,
    // The older still, OpenSSL 1.1's default: the certificate under
    // pbeWithSHA1And40BitRC2-CBC, which only OpenSSL 3's legacy provider
    // reads. The default provider can't write RC2 either, and loading the
    // legacy provider here would let the code under test read it too, so the
    // certificate's safe is built by hand: the RC2 algorithm, with random
    // bytes for its ciphertext. A reader without RC2 stops at the algorithm
    // before decrypting anything, which is what the test needs. The key is
    // 3DES and the MAC (SHA-1) is real, so the password still checks out.
    legacy_rc2,
    // A hostile file: the certificate's place taken by an encryptedData safe
    // with no content at all (the CVE-2024-0727 shape), the key under AES and
    // a real SHA-256 MAC, so the password checks out and PKCS12_parse fails.
    empty_encrypted,
};

struct PfxOptions {
    PfxCipher cipher = PfxCipher::aes256;
    // false: no MAC at all (as PKCS12_create with mac_iter -1), so nothing
    // can check the password.
    bool mac = true;
};

inline std::vector<unsigned char> pfx_to_der(PKCS12* p12)
{
    unsigned char* der = nullptr;
    const int length = i2d_PKCS12(p12, &der);
    REQUIRE(length > 0);
    std::vector<unsigned char> out(der, der + length);
    OPENSSL_free(der);
    return out;
}

// An encrypted safe that claims pbeWithSHA1And40BitRC2-CBC and holds random
// bytes (PfxCipher::legacy_rc2).
inline PKCS7* make_fake_rc2_safe()
{
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> p7(PKCS7_new(), &PKCS7_free);
    REQUIRE(p7);
    REQUIRE(PKCS7_set_type(p7.get(), NID_pkcs7_encrypted) == 1);
    PKCS7_ENC_CONTENT* content = p7->d.encrypted->enc_data;
    X509_ALGOR* algorithm =
        PKCS5_pbe_set(NID_pbe_WithSHA1And40BitRC2_CBC, PKCS12_DEFAULT_ITER, nullptr, 8);
    REQUIRE(algorithm != nullptr);
    X509_ALGOR_free(content->algorithm);
    content->algorithm = algorithm;
    unsigned char junk[64];
    REQUIRE(RAND_bytes(junk, sizeof(junk)) == 1);
    content->enc_data = ASN1_OCTET_STRING_new();
    REQUIRE(content->enc_data != nullptr);
    REQUIRE(ASN1_OCTET_STRING_set(content->enc_data, junk, sizeof(junk)) == 1);
    return p7.release();
}

// An authsafe that says pkcs7-encryptedData and carries no [0] content, which
// OpenSSL's template allows, so it decodes with d.encrypted null
// (PfxCipher::empty_encrypted).
inline PKCS7* make_empty_encrypted_safe()
{
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> p7(PKCS7_new(), &PKCS7_free);
    REQUIRE(p7);
    p7->type = OBJ_nid2obj(NID_pkcs7_encrypted);
    p7->d.encrypted = nullptr;
    return p7.release();
}

// A PFX (PKCS#12) holding `key` and `cert` under `password`; either may be
// null. Built from bags and safes the way PKCS12_create builds one (the
// certificate in an encrypted safe, the key in a shrouded key bag in a plain
// safe, both tagged with the certificate's SHA-1 as localKeyID, then the
// MAC), but without its check that key and certificate belong together, so a
// mismatched pair can be packed too.
inline std::vector<unsigned char> make_pfx(EVP_PKEY* key, X509* cert, const char* password,
                                           const PfxOptions& options = {})
{
    const bool modern =
        options.cipher == PfxCipher::aes256 || options.cipher == PfxCipher::empty_encrypted;
    const int pbe = modern ? NID_aes_256_cbc : NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    unsigned char key_id[SHA_DIGEST_LENGTH];
    unsigned int key_id_length = 0;
    if (cert) {
        REQUIRE(X509_digest(cert, EVP_sha1(), key_id, &key_id_length) == 1);
    }
    struct Safes {
        STACK_OF(PKCS7)* stack = nullptr;
        ~Safes() { sk_PKCS7_pop_free(stack, PKCS7_free); }
    } safes;
    struct Bags {
        STACK_OF(PKCS12_SAFEBAG)* stack = nullptr;
        ~Bags() { sk_PKCS12_SAFEBAG_pop_free(stack, PKCS12_SAFEBAG_free); }
    };
    if (cert && options.cipher == PfxCipher::legacy_rc2) {
        safes.stack = sk_PKCS7_new_null();
        REQUIRE(safes.stack != nullptr);
        REQUIRE(sk_PKCS7_push(safes.stack, make_fake_rc2_safe()) > 0);
    } else if (cert && options.cipher == PfxCipher::empty_encrypted) {
        safes.stack = sk_PKCS7_new_null();
        REQUIRE(safes.stack != nullptr);
        REQUIRE(sk_PKCS7_push(safes.stack, make_empty_encrypted_safe()) > 0);
    } else if (cert) {
        Bags bags;
        PKCS12_SAFEBAG* bag = PKCS12_add_cert(&bags.stack, cert);
        REQUIRE(bag != nullptr);
        REQUIRE(PKCS12_add_localkeyid(bag, key_id, static_cast<int>(key_id_length)) == 1);
        REQUIRE(PKCS12_add_safe(&safes.stack, bags.stack, pbe, PKCS12_DEFAULT_ITER, password) ==
                1);
    }
    if (key) {
        Bags bags;
        PKCS12_SAFEBAG* bag =
            PKCS12_add_key(&bags.stack, key, 0, PKCS12_DEFAULT_ITER, pbe, password);
        REQUIRE(bag != nullptr);
        if (cert) {
            REQUIRE(PKCS12_add_localkeyid(bag, key_id, static_cast<int>(key_id_length)) == 1);
        }
        REQUIRE(PKCS12_add_safe(&safes.stack, bags.stack, -1, 0, nullptr) == 1);
    }
    REQUIRE(safes.stack != nullptr);
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(PKCS12_add_safes(safes.stack, 0),
                                                        &PKCS12_free);
    REQUIRE(p12);
    if (options.mac) {
        const EVP_MD* md = modern ? EVP_sha256() : EVP_sha1();
        REQUIRE(PKCS12_set_mac(p12.get(), password, -1, nullptr, 0, PKCS12_DEFAULT_ITER, md) ==
                1);
    }
    return pfx_to_der(p12.get());
}

inline std::vector<unsigned char> make_pfx(const Cert& cert, const char* password,
                                           const PfxOptions& options = {})
{
    return make_pfx(cert.key.get(), cert.cert.get(), password, options);
}

// `bytes` in standard Base64 on one line, as RP_GRAPH_CERT_PFX_BASE64 holds a
// PFX ([Convert]::ToBase64String in PowerShell).
inline std::string to_base64(const std::vector<unsigned char>& bytes)
{
    std::string out(4 * ((bytes.size() + 2) / 3) + 1, '\0');
    const int length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), bytes.data(),
                                       static_cast<int>(bytes.size()));
    REQUIRE(length >= 0);
    out.resize(static_cast<std::size_t>(length));
    return out;
}

// The certificate's SHA-1 over its DER encoding, uppercase hex: the thumbprint
// Windows and the Entra portal show.
inline std::string cert_sha1_hex(const Cert& cert)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    REQUIRE(X509_digest(cert.cert.get(), EVP_sha1(), digest, &size) == 1);
    return to_hex(digest, size);
}

} // namespace rp::test
