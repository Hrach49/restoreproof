#include <rp/base64.hpp>
#include <rp/client_assertion.hpp>
#include <rp/redact.hpp>
#include <rp/secrets.hpp>

#include "../src/uuid.hpp"
#include "test_certs.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using rp::graph::certificate_from_secrets;
using rp::graph::CertificateError;
using rp::graph::CertificateSecretNames;
using rp::graph::ClientCertificate;
using rp::graph::entra_token_url;
using rp::graph::GraphError;
using rp::graph::load_client_certificate;
using rp::graph::make_client_assertion;
using rp::test::Cert;
using rp::test::ClientCertOptions;
using rp::test::KeyType;
using rp::test::make_client_cert;
using rp::test::make_pfx;
using rp::test::PfxCipher;
using rp::test::PfxOptions;
using rp::test::to_base64;
using namespace std::chrono_literals;

namespace {

using Clock = std::chrono::system_clock;

// Every test runs at this wall-clock time, so dates in messages are fixed.
const Clock::time_point kNow = std::chrono::sys_days{std::chrono::year{2026} / 9 / 28} + 12h;
const std::time_t kNowT = Clock::to_time_t(kNow);

// A sentinel no message or log line may contain.
constexpr const char* kPassword = "Sentinel-PFX-Password-7c1e";

ClientCertOptions at_now(ClientCertOptions options = {})
{
    options.now = kNowT;
    return options;
}

Cert good_cert()
{
    return make_client_cert("RestoreProof Worker", at_now());
}

// What load_client_certificate throws for `pfx_base64` and `password`, after
// checking that the message quotes neither.
std::string load_error(const std::string& pfx_base64, const std::string& password = kPassword,
                       const CertificateSecretNames& names = {})
{
    try {
        load_client_certificate(pfx_base64, password, kNow, names);
    } catch (const CertificateError& error) {
        const std::string what = error.what();
        if (!password.empty()) {
            CHECK(what.find(password) == std::string::npos);
        }
        if (pfx_base64.size() >= 8) {
            CHECK(what.find(pfx_base64.substr(0, 8)) == std::string::npos);
        }
        return what;
    }
    FAIL("load_client_certificate did not throw CertificateError");
    return {};
}

std::shared_ptr<spdlog::logger> string_logger(std::ostringstream& out)
{
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(out);
    auto logger = std::make_shared<spdlog::logger>("client-cert-test", sink);
    logger->set_level(spdlog::level::trace);
    // "\n" rather than Windows' default "\r\n", so lines compare as written.
    logger->set_formatter(std::make_unique<spdlog::pattern_formatter>(
        "%l %v", spdlog::pattern_time_type::utc, "\n"));
    return logger;
}

} // namespace

TEST_CASE("An unset PFX variable is reported by name", "[graph][certificate]")
{
    CHECK(load_error("") == "RP_GRAPH_CERT_PFX_BASE64 is not set");
    CHECK(load_error("", kPassword, {"MY_PFX", "MY_PASSWORD"}) == "MY_PFX is not set");
}

TEST_CASE("A PFX variable that isn't strict Base64 is refused", "[graph][certificate]")
{
    const std::string pfx = to_base64(make_pfx(good_cert(), kPassword));
    std::string url_safe = pfx;
    for (char& c : url_safe) {
        c = c == '+' ? '-' : c == '/' ? '_' : c;
    }
    // Whitespace whose length keeps the text a multiple of four long too, so
    // only the alphabet check can refuse it.
    const std::string bad = GENERATE_COPY(
        std::string("not base64!"), pfx + "\n", pfx.substr(0, 40) + "\r\n" + pfx.substr(40),
        " " + pfx, pfx.substr(0, pfx.size() - 1),
        pfx.substr(0, 40) + "\r\n" + pfx.substr(40, 40) + "\r\n" + pfx.substr(80),
        "  " + pfx + "  ", pfx + "\r\n\r\n");
    CHECK(load_error(bad) ==
          "RP_GRAPH_CERT_PFX_BASE64 is not valid Base64 (one line of A-Z, a-z, 0-9, + and /, "
          "padded with =)");
    if (url_safe != pfx) {
        CHECK_THAT(load_error(url_safe), ContainsSubstring("is not valid Base64"));
    }
}

TEST_CASE("Base64 that isn't a PFX is refused", "[graph][certificate]")
{
    const Cert cert = good_cert();
    std::vector<unsigned char> pfx = make_pfx(cert, kPassword);
    std::vector<unsigned char> truncated(pfx.begin(), pfx.end() - 10);
    std::vector<unsigned char> trailing = pfx;
    trailing.push_back(0);
    unsigned char* der = nullptr;
    const int der_length = i2d_X509(cert.cert.get(), &der);
    REQUIRE(der_length > 0);
    std::vector<unsigned char> cert_der(der, der + der_length);
    OPENSSL_free(der);
    const std::string text = "hello, not a PFX";

    const std::vector<unsigned char> bytes = GENERATE_COPY(
        std::vector<unsigned char>(text.begin(), text.end()), truncated, trailing, cert_der);
    CHECK(load_error(to_base64(bytes)) ==
          "RP_GRAPH_CERT_PFX_BASE64 does not hold a PFX (PKCS#12) file");
}

TEST_CASE("A PFX without a MAC is refused, whatever the password", "[graph][certificate]")
{
    const std::string password = GENERATE(std::string(kPassword), std::string());
    const std::string pfx =
        to_base64(make_pfx(good_cert(), password.c_str(), PfxOptions{.mac = false}));
    CHECK(load_error(pfx, password) ==
          "the PFX in RP_GRAPH_CERT_PFX_BASE64 has no integrity check (MAC), so its password "
          "can't be checked; re-export it with a password and AES256_SHA256");
}

TEST_CASE("A wrong password is reported by the variable's name", "[graph][certificate]")
{
    const Cert cert = good_cert();

    SECTION("a PFX with a password, and another password")
    {
        const std::string pfx = to_base64(make_pfx(cert, "the right one"));
        CHECK(load_error(pfx) ==
              "RP_GRAPH_CERT_PASSWORD does not open the PFX in RP_GRAPH_CERT_PFX_BASE64");
    }
    SECTION("a PFX with a password, and none")
    {
        const std::string pfx = to_base64(make_pfx(cert, kPassword));
        CHECK(load_error(pfx, "") == "RP_GRAPH_CERT_PASSWORD is not set, and the PFX in "
                                     "RP_GRAPH_CERT_PFX_BASE64 needs a password");
    }
    SECTION("a PFX without a password, and a password")
    {
        const std::string pfx = to_base64(make_pfx(cert, ""));
        CHECK(load_error(pfx) ==
              "RP_GRAPH_CERT_PASSWORD does not open the PFX in RP_GRAPH_CERT_PFX_BASE64");
    }
    SECTION("the names come from the caller")
    {
        const std::string pfx = to_base64(make_pfx(cert, "the right one"));
        CHECK(load_error(pfx, kPassword, {"MY_PFX", "MY_PASSWORD"}) ==
              "MY_PASSWORD does not open the PFX in MY_PFX");
    }
}

TEST_CASE("A PFX with a cipher OpenSSL 3 no longer reads asks for a re-export",
          "[graph][certificate]")
{
    // RC2 in the certificate's safe, whether the key is under 3DES or AES
    // (review of W2.1: with a 3DES key alone, a check that never looked at
    // the safe passed), and PBES2 with DES.
    const PfxCipher cipher =
        GENERATE(PfxCipher::legacy_rc2, PfxCipher::rc2_cert_aes_key, PfxCipher::des_pbes2);
    CAPTURE(static_cast<int>(cipher));
    const std::string pfx = to_base64(make_pfx(good_cert(), kPassword, PfxOptions{.cipher = cipher}));
    CHECK(load_error(pfx) ==
          "the PFX in RP_GRAPH_CERT_PFX_BASE64 uses a legacy cipher (RC2 or similar) the Worker "
          "can't read; re-export it with AES256_SHA256");
}

// Review of W2.1: once the MAC has checked out with the password, the password
// is right; a file that still doesn't parse is damaged or built in a way the
// Worker can't read, and its cipher (3DES included) is not to blame if
// OpenSSL runs it.
TEST_CASE("A PFX that fails to parse with the right password doesn't blame the password",
          "[graph][certificate]")
{
    // The MAC is real, so this gets past the password check to PKCS12_parse,
    // which fails, then to the diagnosis without a crash (CVE-2024-0727).
    const PfxCipher cipher =
        GENERATE(PfxCipher::empty_encrypted, PfxCipher::empty_encrypted_3des);
    CAPTURE(static_cast<int>(cipher));
    const std::string pfx = to_base64(make_pfx(good_cert(), kPassword, PfxOptions{.cipher = cipher}));
    CHECK(load_error(pfx) ==
          "the PFX in RP_GRAPH_CERT_PFX_BASE64 can't be read: it is damaged, or built in a way "
          "the Worker can't read; re-export it with AES256_SHA256");
}

TEST_CASE("A PFX must hold a private key and its certificate", "[graph][certificate]")
{
    const Cert cert = good_cert();

    SECTION("no private key")
    {
        const std::string pfx = to_base64(make_pfx(nullptr, cert.cert.get(), kPassword));
        CHECK(load_error(pfx) == "the PFX in RP_GRAPH_CERT_PFX_BASE64 holds no private key");
    }
    SECTION("no certificate")
    {
        const std::string pfx = to_base64(make_pfx(cert.key.get(), nullptr, kPassword));
        CHECK(load_error(pfx) == "the PFX in RP_GRAPH_CERT_PFX_BASE64 holds no certificate");
    }
    SECTION("a key that isn't the certificate's")
    {
        const Cert other = make_client_cert("Someone Else", at_now({.fresh_key = true}));
        const std::string pfx =
            to_base64(make_pfx(other.key.get(), cert.cert.get(), kPassword));
        CHECK(load_error(pfx) == "the private key in the PFX in RP_GRAPH_CERT_PFX_BASE64 does "
                                 "not match its certificate");
    }
}

TEST_CASE("The key must be RSA of at least 2048 bits", "[graph][certificate]")
{
    SECTION("an EC key")
    {
        const Cert cert = make_client_cert("EC", at_now({.key = KeyType::ec_p256}));
        CHECK(load_error(to_base64(make_pfx(cert, kPassword))) ==
              "the key in the PFX in RP_GRAPH_CERT_PFX_BASE64 is not RSA; Entra's PS256 client "
              "assertion needs an RSA key of at least 2048 bits");
    }
    SECTION("RSA 1024")
    {
        const Cert cert = make_client_cert("RSA 1024", at_now({.key = KeyType::rsa1024}));
        CHECK(load_error(to_base64(make_pfx(cert, kPassword))) ==
              "the key in the PFX in RP_GRAPH_CERT_PFX_BASE64 is RSA 1024 bits; Entra's PS256 "
              "client assertion needs at least 2048");
    }
    SECTION("checked before the validity")
    {
        const Cert cert = make_client_cert(
            "EC", at_now({.key = KeyType::ec_p256, .not_before = -7200, .not_after = -3600}));
        CHECK_THAT(load_error(to_base64(make_pfx(cert, kPassword))),
                   ContainsSubstring("is not RSA"));
    }
}

TEST_CASE("The certificate must be valid at the wall-clock time", "[graph][certificate]")
{
    SECTION("expired")
    {
        const Cert cert = make_client_cert("Old", at_now({.not_before = -86400, .not_after = -1}));
        CHECK(load_error(to_base64(make_pfx(cert, kPassword))) ==
              "the certificate in RP_GRAPH_CERT_PFX_BASE64 (SHA-1 thumbprint " +
                  rp::test::cert_sha1_hex(cert) +
                  ") expired at 2026-09-28T11:59:59Z; make a new one and upload it to the app");
    }
    SECTION("not valid yet")
    {
        const Cert cert =
            make_client_cert("Future", at_now({.not_before = 3600, .not_after = 86400}));
        CHECK(load_error(to_base64(make_pfx(cert, kPassword))) ==
              "the certificate in RP_GRAPH_CERT_PFX_BASE64 (SHA-1 thumbprint " +
                  rp::test::cert_sha1_hex(cert) +
                  ") is not valid until 2026-09-28T13:00:00Z; check this machine's clock");
    }
}

// Review of W2.1: MSVC's chrono hours and minutes count in int, so a date from
// about year 6053 on wrapped into the past. 99991231235959Z is RFC 5280's
// value for a certificate with no well-defined expiry.
TEST_CASE("Validity dates far in the future are read without wrapping", "[graph][certificate]")
{
    const auto end_of_9999 = std::chrono::sys_seconds{std::chrono::sys_days{
                                 std::chrono::year{9999} / 12 / 31}} +
                             23h + 59min + 59s;
    SECTION("a notAfter of 99991231235959Z loads")
    {
        const Cert cert = make_client_cert("Forever", at_now({.not_after_text = "99991231235959Z"}));
        std::ostringstream log;
        const ClientCertificate loaded = load_client_certificate(
            to_base64(make_pfx(cert, kPassword)), kPassword, kNow, {}, string_logger(log));
        CHECK(loaded.not_after() == end_of_9999);
        CHECK(log.str().empty());
    }
    SECTION("a notBefore in year 6054 is not valid yet")
    {
        const Cert cert = make_client_cert(
            "Later", at_now({.not_before_text = "60540101000000Z",
                             .not_after_text = "99991231235959Z"}));
        CHECK(load_error(to_base64(make_pfx(cert, kPassword))) ==
              "the certificate in RP_GRAPH_CERT_PFX_BASE64 (SHA-1 thumbprint " +
                  rp::test::cert_sha1_hex(cert) +
                  ") is not valid until 6054-01-01T00:00:00Z; check this machine's clock");
    }
}

TEST_CASE("A good PFX loads, and its thumbprints and validity are the certificate's",
          "[graph][certificate]")
{
    const Cert cert = good_cert();
    const PfxCipher cipher = GENERATE(PfxCipher::aes256, PfxCipher::legacy_3des);
    const std::string password =
        GENERATE(std::string(kPassword), std::string("p\xC3\xA4sswort \xE2\x82\xAC"));
    const ClientCertificate loaded = load_client_certificate(
        to_base64(make_pfx(cert, password.c_str(), PfxOptions{.cipher = cipher})), password,
        kNow);

    CHECK(loaded.sha1_thumbprint() == rp::test::cert_sha1_hex(cert));
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    REQUIRE(X509_digest(cert.cert.get(), EVP_sha256(), digest, &size) == 1);
    CHECK(loaded.x5t_s256() == rp::base64url_encode(std::span<const unsigned char>(digest, size)));
    CHECK(loaded.x5t_s256().size() == 43);
    CHECK(loaded.not_before() == kNow - 1h);
    CHECK(loaded.not_after() == kNow + 365 * 24h);
}

TEST_CASE("A PFX without a password loads with an empty one", "[graph][certificate]")
{
    const Cert cert = good_cert();
    // "" and no password at all are different MAC keys; Windows writes either.
    const char* password = GENERATE(as<const char*>{}, "", nullptr);
    const ClientCertificate loaded =
        load_client_certificate(to_base64(make_pfx(cert, password)), "", kNow);
    CHECK(loaded.sha1_thumbprint() == rp::test::cert_sha1_hex(cert));
}

TEST_CASE("A certificate valid right up to its end loads", "[graph][certificate]")
{
    // From exactly now, and until exactly now: both ends are inside.
    const long not_before = GENERATE(0L, -1L);
    const Cert cert =
        make_client_cert("Edge", at_now({.not_before = not_before, .not_after = not_before + 1}));
    std::ostringstream log;
    CHECK_NOTHROW(load_client_certificate(to_base64(make_pfx(cert, kPassword)), kPassword, kNow,
                                          {}, string_logger(log)));
    CHECK_THAT(log.str(), ContainsSubstring("in 0 day(s)"));
}

TEST_CASE("A certificate that expires within 30 days logs a warning", "[graph][certificate]")
{
    std::ostringstream log;
    const auto logger = string_logger(log);

    SECTION("29 days left")
    {
        const Cert cert = make_client_cert("Soon", at_now({.not_after = 29L * 86400}));
        const std::string pfx = to_base64(make_pfx(cert, kPassword));
        load_client_certificate(pfx, kPassword, kNow, {}, logger);
        CHECK(log.str() == "warning the certificate in RP_GRAPH_CERT_PFX_BASE64 (SHA-1 "
                           "thumbprint " +
                               rp::test::cert_sha1_hex(cert) +
                               ") expires at 2026-10-27T12:00:00Z, in 29 day(s); make a new one "
                               "and upload it to the app\n");
        CHECK(log.str().find(kPassword) == std::string::npos);
        CHECK(log.str().find(pfx.substr(0, 8)) == std::string::npos);
    }
    SECTION("less than a day left")
    {
        const Cert cert = make_client_cert("Sooner", at_now({.not_after = 3600}));
        load_client_certificate(to_base64(make_pfx(cert, kPassword)), kPassword, kNow, {}, logger);
        CHECK_THAT(log.str(), ContainsSubstring("in 0 day(s)"));
    }
    SECTION("31 days left: nothing")
    {
        const Cert cert = make_client_cert("Later", at_now({.not_after = 31L * 86400}));
        load_client_certificate(to_base64(make_pfx(cert, kPassword)), kPassword, kNow, {}, logger);
        CHECK(log.str().empty());
    }
}

TEST_CASE("A ClientCertificate can be moved", "[graph][certificate]")
{
    const Cert cert = good_cert();
    ClientCertificate first =
        load_client_certificate(to_base64(make_pfx(cert, kPassword)), kPassword, kNow);
    ClientCertificate second = std::move(first);
    CHECK(second.sha1_thumbprint() == rp::test::cert_sha1_hex(cert));
    ClientCertificate third =
        load_client_certificate(to_base64(make_pfx(good_cert(), kPassword)), kPassword, kNow);
    third = std::move(second);
    CHECK(third.sha1_thumbprint() == rp::test::cert_sha1_hex(cert));
}

// --- From the Worker's secrets ---

TEST_CASE("The certificate's messages name the variables of rp/secrets.hpp",
          "[graph][certificate]")
{
    const CertificateSecretNames names;
    CHECK(names.pfx_base64 == rp::kEnvGraphCertPfxBase64);
    CHECK(names.password == rp::kEnvGraphCertPassword);
}

TEST_CASE("certificate_from_secrets reports an unset or wrong secret by its variable",
          "[graph][certificate]")
{
    const std::string pfx = to_base64(make_pfx(good_cert(), kPassword));
    const auto error_of = [](const rp::Secrets& secrets) {
        try {
            certificate_from_secrets(secrets, kNow);
        } catch (const CertificateError& error) {
            return std::string{error.what()};
        }
        return std::string{"(no error)"};
    };

    SECTION("no PFX")
    {
        // Whether or not the password is set: the PFX is reported first.
        rp::Secrets secrets;
        CHECK(error_of(secrets) == "RP_GRAPH_CERT_PFX_BASE64 is not set");
        secrets.graph_cert_pfx_base64 = "";
        secrets.graph_cert_password = kPassword;
        CHECK(error_of(secrets) == "RP_GRAPH_CERT_PFX_BASE64 is not set");
    }
    SECTION("a PFX that needs a password, and none set")
    {
        const std::optional<std::string> password =
            GENERATE(std::optional<std::string>{}, std::optional<std::string>{""});
        rp::Secrets secrets;
        secrets.graph_cert_pfx_base64 = pfx;
        secrets.graph_cert_password = password;
        CHECK(error_of(secrets) == "RP_GRAPH_CERT_PASSWORD is not set, and the PFX in "
                                   "RP_GRAPH_CERT_PFX_BASE64 needs a password");
    }
    SECTION("the wrong password")
    {
        rp::Secrets secrets;
        secrets.graph_cert_pfx_base64 = pfx;
        secrets.graph_cert_password = "Sentinel-Wrong-3f0d";
        const std::string what = error_of(secrets);
        CHECK(what == "RP_GRAPH_CERT_PASSWORD does not open the PFX in RP_GRAPH_CERT_PFX_BASE64");
        CHECK(what.find("Sentinel") == std::string::npos);
    }
    SECTION("the Veeam secrets play no part")
    {
        rp::Secrets secrets;
        secrets.veeam_username = pfx;
        secrets.veeam_password = kPassword;
        CHECK(error_of(secrets) == "RP_GRAPH_CERT_PFX_BASE64 is not set");
    }
}

TEST_CASE("certificate_from_secrets loads the PFX the secrets hold", "[graph][certificate]")
{
    SECTION("with its password")
    {
        const Cert cert = good_cert();
        rp::Secrets secrets;
        secrets.graph_cert_pfx_base64 = to_base64(make_pfx(cert, kPassword));
        secrets.graph_cert_password = kPassword;
        CHECK(certificate_from_secrets(secrets, kNow).sha1_thumbprint() ==
              rp::test::cert_sha1_hex(cert));
    }
    SECTION("without a password, when the PFX has none")
    {
        const Cert cert = good_cert();
        rp::Secrets secrets;
        secrets.graph_cert_pfx_base64 = to_base64(make_pfx(cert, ""));
        CHECK(certificate_from_secrets(secrets, kNow).sha1_thumbprint() ==
              rp::test::cert_sha1_hex(cert));
    }
    SECTION("at the wall-clock time given, warning the logger given")
    {
        const Cert cert = make_client_cert("Soon", at_now({.not_after = 10L * 86400}));
        rp::Secrets secrets;
        secrets.graph_cert_pfx_base64 = to_base64(make_pfx(cert, kPassword));
        secrets.graph_cert_password = kPassword;
        std::ostringstream log;
        certificate_from_secrets(secrets, kNow, string_logger(log));
        CHECK_THAT(log.str(), ContainsSubstring("the certificate in RP_GRAPH_CERT_PFX_BASE64"));
        CHECK_THAT(log.str(), ContainsSubstring("in 10 day(s)"));
        CHECK_THROWS_AS(certificate_from_secrets(secrets, kNow + 11 * 24h), CertificateError);
    }
}

// --- The client assertion ---

namespace {

constexpr const char* kTenant = "bcd6bd1a-0000-4000-8000-2c19a44ad146";
constexpr const char* kClient = "737da5ef-0000-4000-8000-e160d8ca77c9";

// kNow in whole seconds since the epoch, as the claims carry it.
const long long kNowSeconds =
    std::chrono::duration_cast<std::chrono::seconds>(kNow.time_since_epoch()).count();

// A JWT's three parts, and what they encode.
struct Jwt {
    std::string header_part;
    std::string payload_part;
    std::string signature_part;
    nlohmann::json header;
    nlohmann::json payload;
    std::vector<unsigned char> signature;

    std::string signing_input() const { return header_part + "." + payload_part; }
};

// base64url without padding, as RFC 7515 wants it, decoded through the strict
// standard decoder.
std::vector<unsigned char> b64url_decode(std::string text)
{
    REQUIRE(text.find_first_of("+/=") == std::string::npos);
    std::replace(text.begin(), text.end(), '-', '+');
    std::replace(text.begin(), text.end(), '_', '/');
    REQUIRE(text.size() % 4 != 1);
    text.append((4 - text.size() % 4) % 4, '=');
    std::optional<std::vector<unsigned char>> bytes = rp::base64_decode(text);
    REQUIRE(bytes);
    return *bytes;
}

std::string as_text(const std::vector<unsigned char>& bytes)
{
    return {bytes.begin(), bytes.end()};
}

Jwt split(const std::string& jwt)
{
    const auto first = jwt.find('.');
    REQUIRE(first != std::string::npos);
    const auto second = jwt.find('.', first + 1);
    REQUIRE(second != std::string::npos);
    REQUIRE(jwt.find('.', second + 1) == std::string::npos);
    Jwt out;
    out.header_part = jwt.substr(0, first);
    out.payload_part = jwt.substr(first + 1, second - first - 1);
    out.signature_part = jwt.substr(second + 1);
    out.header = nlohmann::json::parse(as_text(b64url_decode(out.header_part)));
    out.payload = nlohmann::json::parse(as_text(b64url_decode(out.payload_part)));
    out.signature = b64url_decode(out.signature_part);
    return out;
}

ClientCertificate load(const Cert& cert)
{
    return load_client_certificate(to_base64(make_pfx(cert, kPassword)), kPassword, kNow);
}

// How a verifier is set up; the message digest is SHA-256 every time.
struct Verifier {
    int padding = RSA_PKCS1_PSS_PADDING;
    int salt_length = 32;
    const EVP_MD* mgf1 = nullptr; // SHA-256 when null
};

// Whether `signature` over `input` verifies with the certificate's public key
// under `verifier`. Every PSS parameter is set, none left to OpenSSL.
bool verifies(const Cert& cert, std::string_view input, const std::vector<unsigned char>& signature,
              const Verifier& verifier = {})
{
    EVP_PKEY* public_key = X509_get0_pubkey(cert.cert.get());
    REQUIRE(public_key != nullptr);
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                                       &EVP_MD_CTX_free);
    REQUIRE(ctx);
    EVP_PKEY_CTX* pctx = nullptr;
    REQUIRE(EVP_DigestVerifyInit(ctx.get(), &pctx, EVP_sha256(), nullptr, public_key) == 1);
    REQUIRE(EVP_PKEY_CTX_set_rsa_padding(pctx, verifier.padding) == 1);
    if (verifier.padding == RSA_PKCS1_PSS_PADDING) {
        REQUIRE(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, verifier.mgf1 ? verifier.mgf1 : EVP_sha256()) ==
                1);
        REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, verifier.salt_length) == 1);
    }
    const int result =
        EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                         reinterpret_cast<const unsigned char*>(input.data()), input.size());
    ERR_clear_error();
    return result == 1;
}

// What make_client_assertion throws for these IDs.
std::string id_error(const ClientCertificate& certificate, std::string_view tenant,
                     std::string_view client)
{
    try {
        make_client_assertion(certificate, tenant, client, kNow);
    } catch (const CertificateError&) {
        FAIL("a bad ID is a plain GraphError, not a CertificateError");
    } catch (const GraphError& error) {
        CHECK(error.status() == 0);
        return error.what();
    }
    FAIL("make_client_assertion did not throw GraphError");
    return {};
}

std::string lowercase(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

} // namespace

TEST_CASE("The token URL takes only a GUID tenant", "[graph][assertion]")
{
    const std::string bad =
        GENERATE(std::string(), std::string("contoso.onmicrosoft.com"), std::string("common"),
                 std::string(kTenant) + "/../x", std::string(kTenant).substr(1),
                 "{" + std::string(kTenant) + "}");
    CHECK_THROWS_MATCHES(entra_token_url(bad), GraphError,
                         Catch::Matchers::Message("the Graph tenant ID is not a GUID"));
}

TEST_CASE("A client assertion needs GUID tenant and client IDs", "[graph][assertion]")
{
    const ClientCertificate certificate = load(good_cert());
    const std::string bad = GENERATE(std::string(), std::string("contoso.onmicrosoft.com"),
                                     std::string(kClient) + " ", std::string(kClient) + "\n",
                                     std::string("737da5ef_0000_4000_8000_e160d8ca77c9"));
    CHECK(id_error(certificate, bad, kClient) == "the Graph tenant ID is not a GUID");
    CHECK(id_error(certificate, kTenant, bad) == "the Graph client ID is not a GUID");
}

TEST_CASE("The token URL is Entra's v2 endpoint for the tenant", "[graph][assertion]")
{
    CHECK(entra_token_url(kTenant) ==
          "https://login.microsoftonline.com/bcd6bd1a-0000-4000-8000-2c19a44ad146/oauth2/v2.0/"
          "token");
}

TEST_CASE("A tampered assertion does not verify", "[graph][assertion]")
{
    const Cert cert = good_cert();
    const Jwt jwt = split(make_client_assertion(load(cert), kTenant, kClient, kNow));
    REQUIRE(verifies(cert, jwt.signing_input(), jwt.signature));

    SECTION("a payload with another subject")
    {
        nlohmann::json payload = jwt.payload;
        payload["sub"] = "00000000-0000-4000-8000-000000000000";
        CHECK_FALSE(verifies(cert, jwt.header_part + "." + rp::base64url_encode(payload.dump()),
                             jwt.signature));
    }
    SECTION("a later exp")
    {
        nlohmann::json payload = jwt.payload;
        payload["exp"] = kNowSeconds + 3600;
        CHECK_FALSE(verifies(cert, jwt.header_part + "." + rp::base64url_encode(payload.dump()),
                             jwt.signature));
    }
    SECTION("one flipped bit in the signature")
    {
        std::vector<unsigned char> signature = jwt.signature;
        signature[signature.size() / 2] ^= 0x01;
        CHECK_FALSE(verifies(cert, jwt.signing_input(), signature));
    }
    SECTION("another certificate's key")
    {
        const Cert other = make_client_cert("Someone Else", at_now({.fresh_key = true}));
        CHECK_FALSE(verifies(other, jwt.signing_input(), jwt.signature));
    }
}

TEST_CASE("The assertion is RSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt",
          "[graph][assertion]")
{
    const Cert cert = good_cert();
    const Jwt jwt = split(make_client_assertion(load(cert), kTenant, kClient, kNow));

    // RSA-2048: a 256-byte signature.
    CHECK(jwt.signature.size() == 256);
    // Not RS256 (PKCS#1 v1.5).
    CHECK_FALSE(
        verifies(cert, jwt.signing_input(), jwt.signature, {.padding = RSA_PKCS1_PADDING}));
    // Not MGF1 with SHA-1.
    CHECK_FALSE(verifies(cert, jwt.signing_input(), jwt.signature, {.mgf1 = EVP_sha1()}));
    // The salt is exactly the digest's length: any other fails, and a
    // verifier that reads the length from the signature accepts it.
    const int wrong_salt = GENERATE(0, 20, 31, 33, 64, RSA_PSS_SALTLEN_MAX);
    const std::string input = jwt.signing_input();
    CHECK_FALSE(verifies(cert, input, jwt.signature, {.salt_length = wrong_salt}));
    CHECK(verifies(cert, input, jwt.signature, {.salt_length = 32}));
    CHECK(verifies(cert, input, jwt.signature, {.salt_length = RSA_PSS_SALTLEN_AUTO}));
    CHECK(verifies(cert, input, jwt.signature, {.salt_length = RSA_PSS_SALTLEN_DIGEST}));
}

TEST_CASE("The assertion's header names PS256 and the certificate's SHA-256 thumbprint",
          "[graph][assertion]")
{
    const ClientCertificate certificate = load(good_cert());
    const Jwt jwt = split(make_client_assertion(certificate, kTenant, kClient, kNow));

    // Compact, keys in order: the exact bytes Entra gets.
    CHECK(as_text(b64url_decode(jwt.header_part)) ==
          R"({"alg":"PS256","typ":"JWT","x5t#S256":")" + certificate.x5t_s256() + R"("})");
    // No SHA-1 "x5t", no "kid".
    CHECK(jwt.header.size() == 3);
}

TEST_CASE("The assertion's claims are the token URL, the app, and five minutes from now",
          "[graph][assertion]")
{
    const ClientCertificate certificate = load(good_cert());
    // A fraction of a second is dropped, not rounded up.
    const auto offset = GENERATE(0ms, 1ms, 999ms);
    const Jwt jwt = split(make_client_assertion(certificate, kTenant, kClient, kNow + offset));

    const std::string jti = jwt.payload.at("jti").get<std::string>();
    // Compact, keys sorted, times as integers: the exact bytes Entra gets.
    CHECK(as_text(b64url_decode(jwt.payload_part)) ==
          R"({"aud":"https://login.microsoftonline.com/)" + std::string(kTenant) +
              R"(/oauth2/v2.0/token","exp":)" + std::to_string(kNowSeconds + 300) +
              R"(,"iat":)" + std::to_string(kNowSeconds) + R"(,"iss":")" + kClient +
              R"(","jti":")" + jti + R"(","nbf":)" + std::to_string(kNowSeconds) +
              R"(,"sub":")" + kClient + R"("})");
    CHECK(jwt.payload.at("aud") == entra_token_url(kTenant));
    CHECK(jwt.payload.at("exp").get<long long>() - jwt.payload.at("nbf").get<long long>() ==
          rp::graph::kClientAssertionLifetime.count());
}

TEST_CASE("Each assertion has a new random UUID v4 as its jti", "[graph][assertion]")
{
    const ClientCertificate certificate = load(good_cert());
    std::set<std::string> jtis;
    std::set<std::string> signatures;
    for (int i = 0; i < 20; ++i) {
        const Jwt jwt = split(make_client_assertion(certificate, kTenant, kClient, kNow));
        const std::string jti = jwt.payload.at("jti").get<std::string>();
        CHECK(rp::is_uuid(jti));
        CHECK(jti == lowercase(jti));
        CHECK(jti[14] == '4');
        CHECK(std::string_view("89ab").find(jti[19]) != std::string_view::npos);
        jtis.insert(jti);
        signatures.insert(jwt.signature_part);
    }
    CHECK(jtis.size() == 20);
    CHECK(signatures.size() == 20);
}

TEST_CASE("An assertion is plain base64url, logs nothing, and redact() hides it",
          "[graph][assertion]")
{
    const ClientCertificate certificate = load(good_cert());
    std::ostringstream log;
    const std::shared_ptr<spdlog::logger> previous = spdlog::default_logger();
    spdlog::set_default_logger(string_logger(log));
    const std::string assertion = make_client_assertion(certificate, kTenant, kClient, kNow);
    spdlog::set_default_logger(previous);

    CHECK(log.str().empty());
    CHECK(assertion.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                      "0123456789-_.") == std::string::npos);
    CHECK(assertion.rfind("eyJ", 0) == 0);
    const Jwt jwt = split(assertion);
    const std::string redacted = rp::redact("sending " + assertion);
    CHECK(redacted.find(jwt.payload_part) == std::string::npos);
    CHECK(redacted.find(jwt.signature_part) == std::string::npos);
}
