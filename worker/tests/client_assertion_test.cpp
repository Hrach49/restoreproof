#include <rp/base64.hpp>
#include <rp/client_assertion.hpp>

#include "test_certs.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/ostream_sink.h>

#include <chrono>
#include <ctime>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using rp::graph::CertificateError;
using rp::graph::CertificateSecretNames;
using rp::graph::ClientCertificate;
using rp::graph::load_client_certificate;
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
        CHECK(error.status() == 0);
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
    const std::string bad = GENERATE_COPY(std::string("not base64!"), pfx + "\n",
                                          pfx.substr(0, 40) + "\r\n" + pfx.substr(40),
                                          " " + pfx, pfx.substr(0, pfx.size() - 1));
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
    const std::string pfx =
        to_base64(make_pfx(good_cert(), kPassword, PfxOptions{.cipher = PfxCipher::legacy_rc2}));
    CHECK(load_error(pfx) ==
          "the PFX in RP_GRAPH_CERT_PFX_BASE64 uses a legacy cipher (RC2 or similar) the Worker "
          "can't read; re-export it with AES256_SHA256");
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
