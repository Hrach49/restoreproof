#include <rp/client_assertion.hpp>

#include <rp/base64.hpp>
#include <rp/redact.hpp>

#include "uuid.hpp"

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <format>
#include <optional>
#include <utility>
#include <vector>

namespace rp::graph {

using Clock = std::chrono::system_clock;

struct ClientCertificate::Impl {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr, &EVP_PKEY_free};
    std::unique_ptr<X509, decltype(&X509_free)> cert{nullptr, &X509_free};
    std::string sha1_thumbprint;
    std::string x5t_s256;
    Clock::time_point not_before;
    Clock::time_point not_after;
};

ClientCertificate::ClientCertificate(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl))
{
}

ClientCertificate::~ClientCertificate() = default;
ClientCertificate::ClientCertificate(ClientCertificate&&) noexcept = default;
ClientCertificate& ClientCertificate::operator=(ClientCertificate&&) noexcept = default;

const std::string& ClientCertificate::sha1_thumbprint() const noexcept
{
    return impl_->sha1_thumbprint;
}

const std::string& ClientCertificate::x5t_s256() const noexcept
{
    return impl_->x5t_s256;
}

Clock::time_point ClientCertificate::not_before() const noexcept
{
    return impl_->not_before;
}

Clock::time_point ClientCertificate::not_after() const noexcept
{
    return impl_->not_after;
}

const ClientCertificate::Impl& ClientCertificate::impl() const noexcept
{
    return *impl_;
}

namespace {

// Overwrites `size` bytes at `data` when it goes out of scope, on every path:
// for the decoded PFX and the copy of its password.
class Wipe {
public:
    Wipe(void* data, std::size_t size) noexcept : data_(data), size_(size) {}
    ~Wipe() { OPENSSL_cleanse(data_, size_); }
    Wipe(const Wipe&) = delete;
    Wipe& operator=(const Wipe&) = delete;

private:
    void* data_;
    std::size_t size_;
};

// Leaves OpenSSL's error queue (per thread) empty on the way out, so a failed
// parse here can't show up later as someone else's TLS error.
struct ClearOpenSslErrors {
    ClearOpenSslErrors() = default;
    ~ClearOpenSslErrors() { ERR_clear_error(); }
    ClearOpenSslErrors(const ClearOpenSslErrors&) = delete;
    ClearOpenSslErrors& operator=(const ClearOpenSslErrors&) = delete;
};

std::string to_hex_upper(const unsigned char* bytes, std::size_t size)
{
    static constexpr char kDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(2 * size);
    for (std::size_t i = 0; i < size; ++i) {
        out += kDigits[bytes[i] >> 4];
        out += kDigits[bytes[i] & 0x0F];
    }
    return out;
}

std::optional<Clock::time_point> to_time_point(const ASN1_TIME* time)
{
    std::tm tm{};
    if (ASN1_TIME_to_tm(time, &tm) != 1) {
        return std::nullopt;
    }
    using namespace std::chrono;
    const sys_days day = year{tm.tm_year + 1900} / month{static_cast<unsigned>(tm.tm_mon + 1)} /
                         std::chrono::day{static_cast<unsigned>(tm.tm_mday)};
    // In seconds from the start: MSVC's hours and minutes count in int, and a
    // sum in minutes wraps from about year 6053 (99991231235959Z is RFC 5280's
    // "no expiry").
    return sys_seconds{day} + hours{tm.tm_hour} + minutes{tm.tm_min} + seconds{tm.tm_sec};
}

std::string format_utc(Clock::time_point time)
{
    return std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::seconds>(time));
}

// Whether this OpenSSL can run the cipher `nid` names: the default provider
// has no RC2, RC4, DES or Blowfish, but does have 3DES and AES.
bool can_run_cipher(int nid)
{
    const char* name = OBJ_nid2sn(nid);
    if (name == nullptr) {
        return false;
    }
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, name, nullptr);
    EVP_CIPHER_free(cipher);
    return cipher != nullptr;
}

// Whether `algorithm` names a cipher this OpenSSL can't run: one of PKCS#12's
// own password-based ciphers (RC2, RC4, DES, 3DES under SHA-1 or MD5), or
// PBES2 with such a cipher. An algorithm it can't make out isn't blamed.
bool is_unrunnable_pbe(const X509_ALGOR* algorithm)
{
    const ASN1_OBJECT* oid = nullptr;
    int parameter_type = 0;
    const void* parameter = nullptr;
    X509_ALGOR_get0(&oid, &parameter_type, &parameter, algorithm);
    const int nid = OBJ_obj2nid(oid);
    if (nid == NID_pbes2) {
        if (parameter_type != V_ASN1_SEQUENCE || parameter == nullptr) {
            return false;
        }
        const auto* sequence = static_cast<const ASN1_STRING*>(parameter);
        const unsigned char* cursor = ASN1_STRING_get0_data(sequence);
        const std::unique_ptr<PBE2PARAM, decltype(&PBE2PARAM_free)> pbe2(
            d2i_PBE2PARAM(nullptr, &cursor, ASN1_STRING_length(sequence)), &PBE2PARAM_free);
        return pbe2 && pbe2->encryption != nullptr &&
               !can_run_cipher(OBJ_obj2nid(pbe2->encryption->algorithm));
    }
    int cipher_nid = NID_undef;
    return EVP_PBE_find(EVP_PBE_TYPE_OUTER, nid, &cipher_nid, nullptr, nullptr) == 1 &&
           cipher_nid != NID_undef && !can_run_cipher(cipher_nid);
}

// Whether any encrypted part of `p12` uses a cipher this OpenSSL can't run:
// asked only once PKCS12_parse has failed with the right password, to say why.
bool uses_unrunnable_pbe(const PKCS12* p12)
{
    STACK_OF(PKCS7)* safes = PKCS12_unpack_authsafes(p12);
    bool unrunnable = false;
    for (int i = 0; i < sk_PKCS7_num(safes); ++i) {
        PKCS7* safe = sk_PKCS7_value(safes, i);
        if (PKCS7_type_is_encrypted(safe)) {
            // The content is optional in the ASN.1, so a hostile file can
            // leave it out (CVE-2024-0727): nothing to diagnose then.
            if (safe->d.encrypted != nullptr && safe->d.encrypted->enc_data != nullptr) {
                unrunnable =
                    unrunnable || is_unrunnable_pbe(safe->d.encrypted->enc_data->algorithm);
            }
            continue;
        }
        STACK_OF(PKCS12_SAFEBAG)* bags = PKCS12_unpack_p7data(safe);
        for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags); ++j) {
            const PKCS12_SAFEBAG* bag = sk_PKCS12_SAFEBAG_value(bags, j);
            if (PKCS12_SAFEBAG_get_nid(bag) == NID_pkcs8ShroudedKeyBag) {
                const X509_ALGOR* algorithm = nullptr;
                X509_SIG_get0(PKCS12_SAFEBAG_get0_pkcs8(bag), &algorithm, nullptr);
                unrunnable = unrunnable || is_unrunnable_pbe(algorithm);
            }
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }
    sk_PKCS7_pop_free(safes, PKCS7_free);
    return unrunnable;
}

void log_warning(const std::shared_ptr<spdlog::logger>& given, const std::string& message)
{
    // May be null: spdlog::drop_all() and shutdown() clear the default logger.
    const std::shared_ptr<spdlog::logger> logger = given ? given : spdlog::default_logger();
    if (logger) {
        logger->warn("{}", redact(message));
    }
}

} // namespace

ClientCertificate load_client_certificate(std::string_view pfx_base64, std::string_view password,
                                          Clock::time_point wall_now,
                                          const CertificateSecretNames& names,
                                          std::shared_ptr<spdlog::logger> logger)
{
    const std::string pfx_name(names.pfx_base64);
    const std::string password_name(names.password);
    if (pfx_base64.empty()) {
        throw CertificateError(pfx_name + " is not set");
    }
    std::optional<std::vector<unsigned char>> der = base64_decode(pfx_base64);
    if (!der) {
        throw CertificateError(pfx_name + " is not valid Base64 (one line of A-Z, a-z, 0-9, + "
                                          "and /, padded with =)");
    }
    const Wipe wipe_der(der->data(), der->size());
    // PKCS12 functions take a NUL-terminated password.
    std::string pass(password);
    const Wipe wipe_pass(pass.data(), pass.size());
    const ClearOpenSslErrors clear_errors;

    const unsigned char* cursor = der->data();
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(
        d2i_PKCS12(nullptr, &cursor, static_cast<long>(der->size())), &PKCS12_free);
    if (!p12 || cursor != der->data() + der->size()) {
        throw CertificateError(pfx_name + " does not hold a PFX (PKCS#12) file");
    }
    if (!PKCS12_mac_present(p12.get())) {
        throw CertificateError("the PFX in " + pfx_name +
                               " has no integrity check (MAC), so its password can't be "
                               "checked; re-export it with a password and AES256_SHA256");
    }
    // A PFX without a password is MACed either with "" or with no password at
    // all, depending on who wrote it; PKCS12_parse tries both for "" too.
    const bool opens = pass.empty() ? PKCS12_verify_mac(p12.get(), "", 0) == 1 ||
                                          PKCS12_verify_mac(p12.get(), nullptr, 0) == 1
                                    : PKCS12_verify_mac(p12.get(), pass.c_str(),
                                                        static_cast<int>(pass.size())) == 1;
    if (!opens) {
        throw CertificateError(pass.empty() ? password_name + " is not set, and the PFX in " +
                                                  pfx_name + " needs a password"
                                            : password_name + " does not open the PFX in " +
                                                  pfx_name);
    }

    EVP_PKEY* raw_key = nullptr;
    X509* raw_cert = nullptr;
    STACK_OF(X509)* others = nullptr;
    const bool parsed = PKCS12_parse(p12.get(), pass.c_str(), &raw_key, &raw_cert, &others) == 1;
    auto impl = std::make_unique<ClientCertificate::Impl>();
    impl->key.reset(raw_key);
    impl->cert.reset(raw_cert);
    const int other_count = sk_X509_num(others);
    sk_X509_pop_free(others, X509_free);
    if (!parsed) {
        // The MAC checked out, so the password is right: what's left is a
        // cipher this OpenSSL can't run, or a damaged or odd file.
        throw CertificateError(
            "the PFX in " + pfx_name +
            (uses_unrunnable_pbe(p12.get())
                 ? " uses a legacy cipher (RC2 or similar) the Worker can't read"
                 : " can't be read: it is damaged, or built in a way the Worker can't read") +
            "; re-export it with AES256_SHA256");
    }
    if (!impl->key) {
        throw CertificateError("the PFX in " + pfx_name + " holds no private key");
    }
    // PKCS12_parse returns as `cert` only a certificate the key matches; any
    // other lands in `others`.
    if (!impl->cert) {
        throw CertificateError(other_count > 0 ? "the private key in the PFX in " + pfx_name +
                                                     " does not match its certificate"
                                               : "the PFX in " + pfx_name +
                                                     " holds no certificate");
    }
    if (EVP_PKEY_get_base_id(impl->key.get()) != EVP_PKEY_RSA) {
        throw CertificateError("the key in the PFX in " + pfx_name +
                               " is not RSA; Entra's PS256 client assertion needs an RSA key of "
                               "at least 2048 bits");
    }
    const int bits = EVP_PKEY_get_bits(impl->key.get());
    if (bits < 2048) {
        throw CertificateError(std::format("the key in the PFX in {} is RSA {} bits; Entra's "
                                           "PS256 client assertion needs at least 2048",
                                           pfx_name, bits));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    X509_digest(impl->cert.get(), EVP_sha1(), digest, &size);
    impl->sha1_thumbprint = to_hex_upper(digest, size);
    X509_digest(impl->cert.get(), EVP_sha256(), digest, &size);
    impl->x5t_s256 = base64url_encode(std::span<const unsigned char>(digest, size));

    const std::optional<Clock::time_point> not_before =
        to_time_point(X509_get0_notBefore(impl->cert.get()));
    const std::optional<Clock::time_point> not_after =
        to_time_point(X509_get0_notAfter(impl->cert.get()));
    if (!not_before || !not_after) {
        throw CertificateError("the certificate in " + pfx_name + " has a validity period the "
                                                                  "Worker can't read");
    }
    impl->not_before = *not_before;
    impl->not_after = *not_after;
    const std::string which =
        "the certificate in " + pfx_name + " (SHA-1 thumbprint " + impl->sha1_thumbprint + ")";
    if (wall_now > impl->not_after) {
        throw CertificateError(which + " expired at " + format_utc(impl->not_after) +
                               "; make a new one and upload it to the app");
    }
    if (wall_now < impl->not_before) {
        throw CertificateError(which + " is not valid until " + format_utc(impl->not_before) +
                               "; check this machine's clock");
    }
    if (impl->not_after - wall_now <= kCertificateExpiryWarning) {
        const auto days = std::chrono::floor<std::chrono::days>(impl->not_after - wall_now);
        log_warning(logger, std::format("{} expires at {}, in {} day(s); make a new one and "
                                        "upload it to the app",
                                        which, format_utc(impl->not_after), days.count()));
    }
    return ClientCertificate(std::move(impl));
}

namespace {

// PS256's salt: as long as its SHA-256 digest (RFC 7518 section 3.5).
constexpr int kPssSaltLength = 32;

// A random UUID v4 (RFC 9562 section 5.4) in lowercase, from OpenSSL's CSPRNG.
std::string random_uuid_v4()
{
    std::array<unsigned char, 16> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw GraphError("could not make a random ID for the client assertion");
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0F) | 0x40); // version 4
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3F) | 0x80); // RFC variant
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out += '-';
        }
        out += kDigits[bytes[i] >> 4];
        out += kDigits[bytes[i] & 0x0F];
    }
    return out;
}

// An RSASSA-PSS signature over `input` with SHA-256, MGF1-SHA-256 and a
// 32-byte salt.
std::vector<unsigned char> sign_ps256(EVP_PKEY* key, std::string_view input)
{
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                                       &EVP_MD_CTX_free);
    EVP_PKEY_CTX* pctx = nullptr; // owned by ctx
    std::size_t size = 0;
    const auto* data = reinterpret_cast<const unsigned char*>(input.data());
    const bool ready = ctx &&
                       EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key) == 1 &&
                       EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                       EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) == 1 &&
                       EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, kPssSaltLength) == 1 &&
                       EVP_DigestSign(ctx.get(), nullptr, &size, data, input.size()) == 1;
    std::vector<unsigned char> signature(ready ? size : 0);
    if (!ready || EVP_DigestSign(ctx.get(), signature.data(), &size, data, input.size()) != 1) {
        throw GraphError("could not sign the client assertion with the certificate's key");
    }
    signature.resize(size);
    return signature;
}

} // namespace

ClientCertificate certificate_from_secrets(const Secrets& secrets, Clock::time_point wall_now,
                                           std::shared_ptr<spdlog::logger> logger)
{
    // Views, not value_or(): that would leave an unwiped copy of each secret.
    const auto view = [](const std::optional<std::string>& secret) {
        return secret ? std::string_view{*secret} : std::string_view{};
    };
    return load_client_certificate(view(secrets.graph_cert_pfx_base64),
                                   view(secrets.graph_cert_password), wall_now, {},
                                   std::move(logger));
}

std::string entra_token_url(std::string_view tenant_id)
{
    if (!is_uuid(tenant_id)) {
        throw GraphError("the Graph tenant ID is not a GUID");
    }
    return "https://login.microsoftonline.com/" + std::string(tenant_id) + "/oauth2/v2.0/token";
}

std::string make_client_assertion(const ClientCertificate& certificate,
                                  std::string_view tenant_id, std::string_view client_id,
                                  Clock::time_point wall_now)
{
    const std::string audience = entra_token_url(tenant_id);
    if (!is_uuid(client_id)) {
        throw GraphError("the Graph client ID is not a GUID");
    }
    const ClearOpenSslErrors clear_errors;
    const std::int64_t now =
        std::chrono::floor<std::chrono::seconds>(wall_now.time_since_epoch()).count();

    // nlohmann::json keeps keys sorted and dump() is compact.
    const nlohmann::json header = {
        {"alg", "PS256"}, {"typ", "JWT"}, {"x5t#S256", certificate.x5t_s256()}};
    const nlohmann::json claims = {
        {"aud", audience},
        {"iss", client_id},
        {"sub", client_id},
        {"jti", random_uuid_v4()},
        {"nbf", now},
        {"iat", now},
        {"exp", now + kClientAssertionLifetime.count()},
    };
    const std::string signing_input =
        base64url_encode(header.dump()) + "." + base64url_encode(claims.dump());
    const std::vector<unsigned char> signature =
        sign_ps256(certificate.impl().key.get(), signing_input);
    return signing_input + "." + base64url_encode(signature);
}

} // namespace rp::graph
