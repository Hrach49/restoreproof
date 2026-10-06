#pragma once

// A test-only timestamp authority (W4.4): a root, a TSA certificate under it
// and OpenSSL's own responder, with the time it stamps fixed, so a token made
// here verifies for good (a chain is checked at the token's own time). Its
// keys are made per object, or loaded from the published ones in
// shared/testdata/timestamp-v1/keys.json: never a secret, and never trusted by
// anything but a test.

#include <rp/rfc3161.hpp>

#include <catch2/catch_test_macros.hpp>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp::test {

// 2026-10-06T12:00:00Z: the time a TestTsa stamps unless told otherwise.
inline constexpr std::int64_t kTestTsaTime = 1791288000;
// 2026-01-01T00:00:00Z: its certificates are valid from here, for 100 years.
inline constexpr std::int64_t kTestTsaNotBefore = 1767225600;

using TsaKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using TsaCertPtr = std::unique_ptr<X509, decltype(&X509_free)>;

inline std::string tsa_bio_text(BIO* bio)
{
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    REQUIRE(size > 0);
    return std::string(data, static_cast<std::size_t>(size));
}

inline std::string tsa_cert_pem(X509* cert)
{
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(PEM_write_bio_X509(bio.get(), cert) == 1);
    return tsa_bio_text(bio.get());
}

inline std::string tsa_key_pem(EVP_PKEY* key)
{
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    return tsa_bio_text(bio.get());
}

inline TsaKeyPtr tsa_key_from_pem(std::string_view pem)
{
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    TsaKeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free);
    REQUIRE(key);
    return key;
}

inline TsaCertPtr tsa_cert_from_pem(std::string_view pem)
{
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    TsaCertPtr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free);
    REQUIRE(cert);
    return cert;
}

// A certificate for `key`, named `common_name`, signed by `issuer_key` in
// `issuer`'s name (itself when `issuer` is null), valid for 100 years from
// kTestTsaNotBefore. A CA when `ca`, else a TSA's: extended key usage
// critical and timeStamping alone.
inline TsaCertPtr make_tsa_cert(EVP_PKEY* key, const char* common_name, long serial, bool ca,
                                X509* issuer, EVP_PKEY* issuer_key)
{
    TsaCertPtr cert(X509_new(), &X509_free);
    REQUIRE(cert);
    REQUIRE(X509_set_version(cert.get(), 2) == 1);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) == 1);
    X509_NAME* name = X509_get_subject_name(cert.get());
    REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>(common_name), -1, -1,
                                       0) == 1);
    REQUIRE(X509_set_issuer_name(cert.get(),
                                 issuer ? X509_get_subject_name(issuer) : name) == 1);
    const time_t from = static_cast<time_t>(kTestTsaNotBefore);
    REQUIRE(ASN1_TIME_set(X509_getm_notBefore(cert.get()), from) != nullptr);
    REQUIRE(ASN1_TIME_adj(X509_getm_notAfter(cert.get()), from, 36500, 0) != nullptr);
    REQUIRE(X509_set_pubkey(cert.get(), key) == 1);
    const auto add = [&](int nid, const char* value) {
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, issuer ? issuer : cert.get(), cert.get(), nullptr, nullptr, 0);
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
        REQUIRE(extension != nullptr);
        REQUIRE(X509_add_ext(cert.get(), extension, -1) == 1);
        X509_EXTENSION_free(extension);
    };
    if (ca) {
        add(NID_basic_constraints, "critical,CA:TRUE");
        add(NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add(NID_key_usage, "critical,digitalSignature");
        add(NID_ext_key_usage, "critical,timeStamping");
    }
    REQUIRE(X509_sign(cert.get(), issuer_key ? issuer_key : key, EVP_sha256()) > 0);
    return cert;
}

class TestTsa {
public:
    // A new root and a TSA certificate under it, each with a new P-256 key.
    explicit TestTsa(const char* root_name = "RestoreProof test TSA root (not a secret)")
        : root_key_(EVP_EC_gen("P-256"), &EVP_PKEY_free),
          tsa_key_(EVP_EC_gen("P-256"), &EVP_PKEY_free), root_(nullptr, &X509_free),
          tsa_(nullptr, &X509_free)
    {
        REQUIRE(root_key_);
        REQUIRE(tsa_key_);
        root_ = make_tsa_cert(root_key_.get(), root_name, 1, true, nullptr, nullptr);
        tsa_ = make_tsa_cert(tsa_key_.get(), "RestoreProof test TSA (not a secret)", 2, false,
                             root_.get(), root_key_.get());
    }

    // The published ones (shared/testdata/timestamp-v1/keys.json).
    TestTsa(std::string_view root_pem, std::string_view tsa_cert_pem_text,
            std::string_view tsa_key_pem_text)
        : root_key_(nullptr, &EVP_PKEY_free), tsa_key_(tsa_key_from_pem(tsa_key_pem_text)),
          root_(tsa_cert_from_pem(root_pem)), tsa_(tsa_cert_from_pem(tsa_cert_pem_text))
    {
    }

    // The time it stamps, seconds since 1970 UTC.
    std::int64_t time = kTestTsaTime;

    std::string root_pem() const { return tsa_cert_pem(root_.get()); }
    std::string tsa_cert_pem_text() const { return tsa_cert_pem(tsa_.get()); }
    std::string tsa_key_pem_text() const { return tsa_key_pem(tsa_key_.get()); }

    // The TimeStampResp's DER for the TimeStampReq `request`: OpenSSL's own
    // responder, so granted with a token for a good request, and the token
    // carries the TSA's certificate when the request asks for it.
    std::string respond(std::string_view request) const
    {
        const std::unique_ptr<TS_RESP_CTX, decltype(&TS_RESP_CTX_free)> ctx(TS_RESP_CTX_new(),
                                                                            &TS_RESP_CTX_free);
        REQUIRE(ctx);
        REQUIRE(TS_RESP_CTX_set_signer_cert(ctx.get(), tsa_.get()) == 1);
        REQUIRE(TS_RESP_CTX_set_signer_key(ctx.get(), tsa_key_.get()) == 1);
        REQUIRE(TS_RESP_CTX_set_signer_digest(ctx.get(), EVP_sha256()) == 1);
        ASN1_OBJECT* policy = OBJ_txt2obj("1.2.3.4.1", 1);
        REQUIRE(policy != nullptr);
        REQUIRE(TS_RESP_CTX_set_def_policy(ctx.get(), policy) == 1);
        ASN1_OBJECT_free(policy);
        REQUIRE(TS_RESP_CTX_add_md(ctx.get(), EVP_sha256()) == 1);
        REQUIRE(TS_RESP_CTX_add_md(ctx.get(), EVP_sha512()) == 1);
        TS_RESP_CTX_set_serial_cb(ctx.get(), &serial_cb, nullptr);
        TS_RESP_CTX_set_time_cb(ctx.get(), &time_cb, const_cast<TestTsa*>(this));
        const std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(request.data(), static_cast<int>(request.size())), &BIO_free);
        const std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> response(
            TS_RESP_create_response(ctx.get(), bio.get()), &TS_RESP_free);
        REQUIRE(response);
        return der_of(response.get());
    }

    // The bare token for `digest` and `nonce`, through the real primitive's
    // request and response reader.
    std::string token(std::span<const unsigned char, kSha256Bytes> digest,
                      std::uint64_t nonce = 0x1122334455667788ULL) const
    {
        const std::string request = openssl_rfc3161().request(digest, nonce);
        REQUIRE_FALSE(request.empty());
        const std::optional<TimestampResponse> response =
            openssl_rfc3161().parse_response(respond(request));
        REQUIRE(response);
        REQUIRE(response->status == kTimestampGranted);
        REQUIRE_FALSE(response->token.empty());
        return response->token;
    }

    // `response` with its PKIStatus set to `status` and everything else kept.
    static std::string with_status(std::string_view response_der, int status)
    {
        const unsigned char* p = reinterpret_cast<const unsigned char*>(response_der.data());
        const std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> response(
            d2i_TS_RESP(nullptr, &p, static_cast<long>(response_der.size())), &TS_RESP_free);
        REQUIRE(response);
        REQUIRE(TS_STATUS_INFO_set_status(TS_RESP_get_status_info(response.get()), status) == 1);
        return der_of(response.get());
    }

    // A response that grants nothing: PKIStatus rejection (2), no token.
    static std::string rejection() { return std::string("\x30\x05\x30\x03\x02\x01\x02", 7); }

private:
    static std::string der_of(TS_RESP* response)
    {
        unsigned char* raw = nullptr;
        const int size = i2d_TS_RESP(response, &raw);
        REQUIRE(size > 0);
        std::string der(reinterpret_cast<const char*>(raw), static_cast<std::size_t>(size));
        OPENSSL_free(raw);
        return der;
    }

    static ASN1_INTEGER* serial_cb(TS_RESP_CTX*, void*)
    {
        ASN1_INTEGER* serial = ASN1_INTEGER_new();
        if (serial != nullptr) {
            ASN1_INTEGER_set(serial, 4404);
        }
        return serial;
    }

    static int time_cb(TS_RESP_CTX*, void* self, long* sec, long* usec)
    {
        *sec = static_cast<long>(static_cast<const TestTsa*>(self)->time);
        *usec = 0;
        return 1;
    }

    TsaKeyPtr root_key_;
    TsaKeyPtr tsa_key_;
    TsaCertPtr root_;
    TsaCertPtr tsa_;
};

// A request's DER from the library's own object.
inline std::string tsa_request_der(TS_REQ* request)
{
    unsigned char* raw = nullptr;
    const int size = i2d_TS_REQ(request, &raw);
    REQUIRE(size > 0);
    std::string der(reinterpret_cast<const char*>(raw), static_cast<std::size_t>(size));
    OPENSSL_free(raw);
    return der;
}

// The token `tsa` gives a request that doesn't ask for its certificate: one
// no verifier can find the signer of.
inline std::string token_without_certificate(const TestTsa& tsa,
                                             std::span<const unsigned char, kSha256Bytes> digest)
{
    const std::string request = openssl_rfc3161().request(digest, 0x0102030405060708ULL);
    const unsigned char* p = reinterpret_cast<const unsigned char*>(request.data());
    const std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)> parsed(
        d2i_TS_REQ(nullptr, &p, static_cast<long>(request.size())), &TS_REQ_free);
    REQUIRE(parsed);
    REQUIRE(TS_REQ_set_cert_req(parsed.get(), 0) == 1);
    const std::optional<TimestampResponse> response =
        openssl_rfc3161().parse_response(tsa.respond(tsa_request_der(parsed.get())));
    REQUIRE(response);
    REQUIRE_FALSE(response->token.empty());
    return response->token;
}

// A token of `tsa` whose imprint is SHA-512 (of nothing in particular).
inline std::string sha512_token(const TestTsa& tsa)
{
    const std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)> request(TS_REQ_new(), &TS_REQ_free);
    REQUIRE(TS_REQ_set_version(request.get(), 1) == 1);
    const std::unique_ptr<TS_MSG_IMPRINT, decltype(&TS_MSG_IMPRINT_free)> imprint(
        TS_MSG_IMPRINT_new(), &TS_MSG_IMPRINT_free);
    X509_ALGOR* algorithm = X509_ALGOR_new();
    REQUIRE(X509_ALGOR_set0(algorithm, OBJ_nid2obj(NID_sha512), V_ASN1_NULL, nullptr) == 1);
    REQUIRE(TS_MSG_IMPRINT_set_algo(imprint.get(), algorithm) == 1);
    X509_ALGOR_free(algorithm);
    unsigned char digest[64];
    for (unsigned char& byte : digest) {
        byte = 0x5a;
    }
    REQUIRE(TS_MSG_IMPRINT_set_msg(imprint.get(), digest, sizeof digest) == 1);
    REQUIRE(TS_REQ_set_msg_imprint(request.get(), imprint.get()) == 1);
    REQUIRE(TS_REQ_set_cert_req(request.get(), 1) == 1);
    const std::optional<TimestampResponse> response =
        openssl_rfc3161().parse_response(tsa.respond(tsa_request_der(request.get())));
    REQUIRE(response);
    REQUIRE_FALSE(response->token.empty());
    return response->token;
}

// Where a FakeRfc3161 fails. Everything else it hands to the real primitive.
enum class Rfc3161Fault {
    none,
    request_empty,
    request_throws,
    response_throws,
    token_none,
    token_throws,
    verify_false,
    verify_throws,
    nonce_none,
    certificates_none,
    certificates_throws
};

class FakeRfc3161 final : public Rfc3161 {
public:
    mutable Rfc3161Fault fault = Rfc3161Fault::none;

    explicit FakeRfc3161(Rfc3161Fault at = Rfc3161Fault::none) : fault(at) {}

    std::string request(std::span<const unsigned char, kSha256Bytes> digest,
                        std::uint64_t nonce) const override
    {
        if (fault == Rfc3161Fault::request_throws) {
            throw std::runtime_error("request");
        }
        return fault == Rfc3161Fault::request_empty ? std::string{}
                                                    : openssl_rfc3161().request(digest, nonce);
    }

    std::optional<TimestampResponse> parse_response(std::string_view der) const override
    {
        if (fault == Rfc3161Fault::response_throws) {
            throw 42; // not a std::exception
        }
        return openssl_rfc3161().parse_response(der);
    }

    std::optional<TimestampTokenInfo> parse_token(std::string_view der) const override
    {
        if (fault == Rfc3161Fault::token_throws) {
            throw std::runtime_error("parse_token");
        }
        if (fault == Rfc3161Fault::token_none) {
            return std::nullopt;
        }
        return openssl_rfc3161().parse_token(der);
    }

    bool verify_token(std::string_view token, std::string_view ca_pem) const override
    {
        if (fault == Rfc3161Fault::verify_throws) {
            throw std::runtime_error("verify_token");
        }
        return fault != Rfc3161Fault::verify_false &&
               openssl_rfc3161().verify_token(token, ca_pem);
    }

    std::optional<std::uint64_t> random_nonce() const override
    {
        if (fault == Rfc3161Fault::nonce_none) {
            return std::nullopt;
        }
        return openssl_rfc3161().random_nonce();
    }

    std::size_t certificates_in(std::string_view pem) const override
    {
        if (fault == Rfc3161Fault::certificates_throws) {
            throw std::runtime_error("certificates_in");
        }
        return fault == Rfc3161Fault::certificates_none ? 0
                                                        : openssl_rfc3161().certificates_in(pem);
    }
};

// SHA-256 of "abc" (FIPS 180-2), and of the empty text: two digests to stamp.
inline constexpr std::array<unsigned char, kSha256Bytes> kDigestAbc = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
inline constexpr std::array<unsigned char, kSha256Bytes> kDigestEmpty = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

} // namespace rp::test
