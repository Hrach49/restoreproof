#include <rp/rfc3161.hpp>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <chrono>
#include <ctime>
#include <format>
#include <limits>
#include <memory>
#include <utility>

// The real primitive (W4.4, docs/decisions.md 2026-10-06 W4.4, point 7): each
// function is one checked call sequence into OpenSSL's TS, PKCS#7 and X.509
// code. Like ed25519.cpp it isn't held to the strict files' 100%: the
// library's allocation and encoding failures can't be provoked by a test. It
// holds no rule of the timestamp beyond "is this exactly one response / one
// token" and "does the token verify under these certificates at its own
// time"; which imprint, which nonce and which status are right is the
// Timestamper's and the Signer's to say.

namespace rp {

namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using ReqPtr = std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)>;
using RespPtr = std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)>;
using ImprintPtr = std::unique_ptr<TS_MSG_IMPRINT, decltype(&TS_MSG_IMPRINT_free)>;
using AlgorPtr = std::unique_ptr<X509_ALGOR, decltype(&X509_ALGOR_free)>;
using IntegerPtr = std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
using Pkcs7Ptr = std::unique_ptr<PKCS7, decltype(&PKCS7_free)>;
using TstInfoPtr = std::unique_ptr<TS_TST_INFO, decltype(&TS_TST_INFO_free)>;
using StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
using VerifyCtxPtr = std::unique_ptr<TS_VERIFY_CTX, decltype(&TS_VERIFY_CTX_free)>;

// Leaves OpenSSL's error queue (per thread) empty on the way out, so a refused
// token here can't show up later as someone else's TLS error.
struct ClearOpenSslErrors {
    ClearOpenSslErrors() = default;
    ~ClearOpenSslErrors() { ERR_clear_error(); }
    ClearOpenSslErrors(const ClearOpenSslErrors&) = delete;
    ClearOpenSslErrors& operator=(const ClearOpenSslErrors&) = delete;
};

const unsigned char* bytes_of(std::string_view text) noexcept
{
    return reinterpret_cast<const unsigned char*>(text.data());
}

// Whether a DER length fits what d2i takes.
bool fits(std::string_view der) noexcept
{
    return !der.empty() &&
           der.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

std::string take(unsigned char* raw, int size)
{
    std::string der;
    if (raw != nullptr && size > 0) {
        der.assign(reinterpret_cast<const char*>(raw), static_cast<std::size_t>(size));
    }
    OPENSSL_free(raw);
    return der;
}

// `der` as exactly one PKCS#7 object whose content is a TSTInfo, or null. The
// library's reader must end at the text's last byte.
Pkcs7Ptr token_of(std::string_view der)
{
    Pkcs7Ptr token(nullptr, &PKCS7_free);
    if (!fits(der)) {
        return token;
    }
    const unsigned char* p = bytes_of(der);
    token.reset(d2i_PKCS7(nullptr, &p, static_cast<long>(der.size())));
    if (token && p != bytes_of(der) + der.size()) {
        token.reset();
    }
    return token;
}

// One PEM block as the library's reader hands it out, freed when it goes.
struct PemBlock {
    char* name = nullptr;
    char* header = nullptr;
    unsigned char* data = nullptr;
    long size = 0;
    PemBlock() = default;
    PemBlock(const PemBlock&) = delete;
    PemBlock& operator=(const PemBlock&) = delete;
    ~PemBlock()
    {
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }
};

// The certificates of `pem`, every block of it one, or an empty store's worth
// (count 0) when a block isn't a certificate: one of another label (a key, a
// CRL, the old "X509 CERTIFICATE"), one with a header, one whose bytes aren't
// exactly one certificate, one that is cut off. The blocks are read one by
// one here: PEM_read_bio_X509 skips a block of another label, so a file that
// also held a key would count as its certificates. Text outside the blocks
// is a comment.
std::size_t add_certificates(std::string_view pem, X509_STORE* store)
{
    if (!fits(pem)) {
        return 0;
    }
    const BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    if (!bio) {
        return 0;
    }
    std::size_t count = 0;
    for (;;) {
        PemBlock block;
        if (PEM_read_bio(bio.get(), &block.name, &block.header, &block.data, &block.size) != 1) {
            break;
        }
        if (std::string_view{block.name} != PEM_STRING_X509 || block.header[0] != '\0') {
            return 0;
        }
        const unsigned char* p = block.data;
        const CertPtr cert(d2i_X509(nullptr, &p, block.size), &X509_free);
        if (!cert || p != block.data + block.size) {
            return 0;
        }
        if (store != nullptr && X509_STORE_add_cert(store, cert.get()) != 1) {
            return 0;
        }
        ++count;
    }
    // The reader stops at the first block it can't read: only "no more PEM
    // in the text" is an end, and only when the text is used up.
    const unsigned long error = ERR_peek_last_error();
    const bool at_end = ERR_GET_LIB(error) == ERR_LIB_PEM &&
                        ERR_GET_REASON(error) == PEM_R_NO_START_LINE && BIO_eof(bio.get()) == 1;
    return at_end ? count : 0;
}

std::optional<std::int64_t> seconds_of(const ASN1_GENERALIZEDTIME* time)
{
    std::tm parts{};
    if (time == nullptr || ASN1_TIME_to_tm(time, &parts) != 1) {
        return std::nullopt;
    }
    const std::chrono::sys_days day =
        std::chrono::year{parts.tm_year + 1900} / std::chrono::month{
            static_cast<unsigned>(parts.tm_mon + 1)} /
        std::chrono::day{static_cast<unsigned>(parts.tm_mday)};
    return std::int64_t{day.time_since_epoch().count()} * 86400 + parts.tm_hour * 3600 +
           parts.tm_min * 60 + parts.tm_sec;
}

class OpenSslRfc3161 final : public Rfc3161 {
public:
    std::string request(std::span<const unsigned char, kSha256Bytes> digest,
                        std::uint64_t nonce) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            const ReqPtr request(TS_REQ_new(), &TS_REQ_free);
            const ImprintPtr imprint(TS_MSG_IMPRINT_new(), &TS_MSG_IMPRINT_free);
            const AlgorPtr algorithm(X509_ALGOR_new(), &X509_ALGOR_free);
            const IntegerPtr number(ASN1_INTEGER_new(), &ASN1_INTEGER_free);
            if (!request || !imprint || !algorithm || !number ||
                X509_ALGOR_set0(algorithm.get(), OBJ_nid2obj(NID_sha256), V_ASN1_NULL, nullptr) !=
                    1 ||
                TS_MSG_IMPRINT_set_algo(imprint.get(), algorithm.get()) != 1 ||
                TS_MSG_IMPRINT_set_msg(imprint.get(), const_cast<unsigned char*>(digest.data()),
                                       static_cast<int>(digest.size())) != 1 ||
                TS_REQ_set_version(request.get(), 1) != 1 ||
                TS_REQ_set_msg_imprint(request.get(), imprint.get()) != 1 ||
                ASN1_INTEGER_set_uint64(number.get(), nonce) != 1 ||
                TS_REQ_set_nonce(request.get(), number.get()) != 1 ||
                TS_REQ_set_cert_req(request.get(), 1) != 1) {
                return {};
            }
            unsigned char* raw = nullptr;
            const int size = i2d_TS_REQ(request.get(), &raw);
            return take(raw, size);
        } catch (...) {
            return {};
        }
    }

    std::optional<TimestampResponse> parse_response(std::string_view der) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            if (!fits(der)) {
                return std::nullopt;
            }
            const unsigned char* begin = bytes_of(der);
            const unsigned char* end = begin + der.size();
            const unsigned char* p = begin;
            const RespPtr response(d2i_TS_RESP(nullptr, &p, static_cast<long>(der.size())),
                                   &TS_RESP_free);
            if (!response || p != end) {
                return std::nullopt;
            }
            TimestampResponse out;
            out.status = static_cast<int>(
                ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(TS_RESP_get_status_info(response.get()))));
            if (TS_RESP_get_token(response.get()) == nullptr) {
                return out;
            }
            // The token's own bytes, not a re-encoding (the library sorts a
            // SET OF it writes, and real TSAs don't): the response is a
            // SEQUENCE of the status and the token, so the token is what
            // follows the status, to the end.
            long length = 0;
            int tag = 0;
            int cls = 0;
            const unsigned char* at = begin;
            if ((ASN1_get_object(&at, &length, &tag, &cls, static_cast<long>(der.size())) & 0x81) !=
                0) {
                return std::nullopt;
            }
            const unsigned char* status = at;
            if ((ASN1_get_object(&status, &length, &tag, &cls, static_cast<long>(end - at)) &
                 0x81) != 0 ||
                length >= end - status) {
                return std::nullopt;
            }
            out.token.assign(reinterpret_cast<const char*>(status + length),
                             static_cast<std::size_t>(end - (status + length)));
            return out;
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<TimestampTokenInfo> parse_token(std::string_view der) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            const Pkcs7Ptr token = token_of(der);
            if (!token || PKCS7_type_is_signed(token.get()) == 0 ||
                sk_PKCS7_SIGNER_INFO_num(PKCS7_get_signer_info(token.get())) != 1) {
                return std::nullopt;
            }
            const TstInfoPtr info(PKCS7_to_TS_TST_INFO(token.get()), &TS_TST_INFO_free);
            if (!info || TS_TST_INFO_get_version(info.get()) != 1) {
                return std::nullopt;
            }
            TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(info.get());
            const std::optional<std::int64_t> time = seconds_of(TS_TST_INFO_get_time(info.get()));
            if (imprint == nullptr || !time) {
                return std::nullopt;
            }
            TimestampTokenInfo out;
            out.gen_time = *time;
            out.sha256 =
                OBJ_obj2nid(TS_MSG_IMPRINT_get_algo(imprint)->algorithm) == NID_sha256;
            const ASN1_OCTET_STRING* message = TS_MSG_IMPRINT_get_msg(imprint);
            out.imprint.assign(ASN1_STRING_get0_data(message),
                               ASN1_STRING_get0_data(message) + ASN1_STRING_length(message));
            std::uint64_t nonce = 0;
            const ASN1_INTEGER* sent = TS_TST_INFO_get_nonce(info.get());
            if (sent != nullptr && ASN1_INTEGER_get_uint64(&nonce, sent) == 1) {
                out.nonce = nonce;
            }
            return out;
        } catch (...) {
            return std::nullopt;
        }
    }

    bool verify_token(std::string_view token_der, std::string_view ca_pem) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            const std::optional<TimestampTokenInfo> info = parse_token(token_der);
            const Pkcs7Ptr token = token_of(token_der);
            StorePtr store(X509_STORE_new(), &X509_STORE_free);
            const VerifyCtxPtr ctx(TS_VERIFY_CTX_new(), &TS_VERIFY_CTX_free);
            if (!info || !token || !store || !ctx ||
                add_certificates(ca_pem, store.get()) == 0) {
                return false;
            }
            ERR_clear_error();
            // The chain is good or not at the token's own time, and a
            // certificate of the caller's file ends it wherever it is met.
            X509_VERIFY_PARAM* param = X509_STORE_get0_param(store.get());
            X509_VERIFY_PARAM_set_time(param, static_cast<time_t>(info->gen_time));
            if (X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN) != 1) {
                return false;
            }
            TS_VERIFY_CTX_set_flags(ctx.get(), TS_VFY_VERSION | TS_VFY_SIGNATURE);
            if (TS_VERIFY_CTX_set0_store(ctx.get(), store.get()) != 1) {
                return false;
            }
            static_cast<void>(store.release()); // the context's now
            return TS_RESP_verify_token(ctx.get(), token.get()) == 1;
        } catch (...) {
            return false;
        }
    }

    std::optional<std::uint64_t> random_nonce() const override
    {
        const ClearOpenSslErrors clear_errors;
        std::uint64_t nonce = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&nonce), sizeof nonce) != 1) {
            return std::nullopt;
        }
        return nonce;
    }

    std::size_t certificates_in(std::string_view pem) const override
    {
        try {
            const ClearOpenSslErrors clear_errors;
            return add_certificates(pem, nullptr);
        } catch (...) {
            return 0;
        }
    }
};

} // namespace

const Rfc3161& openssl_rfc3161() noexcept
{
    static const OpenSslRfc3161 primitive;
    return primitive;
}

std::string timestamp_time_text(std::int64_t gen_time)
{
    const std::chrono::sys_seconds time{std::chrono::seconds{gen_time}};
    return std::format("{:%Y-%m-%dT%H:%M:%S}Z", time);
}

} // namespace rp
