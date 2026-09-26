// W1.5: the certificate pin for Veeam's REST certificate (docs/decisions.md,
// 2026-09-26). veeam_cert_sha256 names the certificate by its SHA-256, as
// Windows shows it; curl pins the public key. public_key_pin() finds the named
// certificate in veeam_ca_file and gives the key pin curl needs.

#include "test_certs.hpp"
#include "test_support.hpp"

#include <rp/cert_pin.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <string_view>

namespace {

using rp::test::Cert;
using rp::test::Role;

std::string to_utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

std::string lowercase(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

// The lab's Veeam REST certificate (public; any TLS client sees it) and the
// two hashes .NET computed for it on the Veeam server: GetCertHashString('SHA256')
// and SHA256.HashData(PublicKey.ExportSubjectPublicKeyInfo()) as base64.
constexpr std::string_view kLabCertSha256 =
    "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213";
constexpr std::string_view kLabKeyPin = "jSOf+h9iDQY3dg41YdNXwUU7XTKxMeNbPlcqP1xhD0Q=";

std::string lab_cert_path()
{
    return std::string{RP_FIXTURE_DIR} + "/veeam/rest-certificate.pem";
}

} // namespace

TEST_CASE("is_sha256_hex accepts 64 hex digits in any case and nothing else", "[cert_pin]")
{
    CHECK(rp::is_sha256_hex(kLabCertSha256));
    CHECK(rp::is_sha256_hex(lowercase(std::string{kLabCertSha256})));

    const std::string refused = GENERATE(
        std::string{}, std::string(63, 'A'), std::string(65, 'A'),
        // The colon-separated form `openssl x509 -fingerprint` prints.
        std::string{"9F:B1:9E:0E"},
        std::string{kLabCertSha256.substr(0, 63)} + "G",
        " " + std::string{kLabCertSha256.substr(1)},
        std::string{kLabCertSha256.substr(0, 63)} + "\n",
        // A SHA-1 thumbprint, as the Veeam console shows it: 40 digits.
        std::string(40, 'A'));
    CAPTURE(refused);
    CHECK_FALSE(rp::is_sha256_hex(refused));
}

TEST_CASE("public_key_pin gives the lab certificate's key pin that .NET computed", "[cert_pin]")
{
    CHECK(rp::public_key_pin(lab_cert_path(), kLabCertSha256) == kLabKeyPin);
    // Any case: Windows prints uppercase, other tools lowercase.
    CHECK(rp::public_key_pin(lab_cert_path(), lowercase(std::string{kLabCertSha256})) ==
          kLabKeyPin);
}

TEST_CASE("public_key_pin finds the named certificate among several", "[cert_pin]")
{
    const Cert veeam = rp::test::make_cert("Veeam Software", Role::veeam_default);
    const Cert ca = rp::test::make_cert("rp-test-private-ca", Role::ca);
    const Cert other = rp::test::make_cert("rp-test-other", Role::self_signed_server);
    const rp::test::TempDir dir;
    // "тест": outside the ANSI code page, so the path must go through as UTF-8.
    const std::filesystem::path file =
        dir.write(std::filesystem::path{std::u8string{u8"тест-veeam.pem"}},
                  ca.pem().cert + veeam.pem().cert + other.pem().cert);

    CHECK(rp::public_key_pin(to_utf8(file), rp::test::cert_sha256_hex(veeam)) ==
          rp::test::spki_sha256_base64(veeam));
    CHECK(rp::public_key_pin(to_utf8(file), rp::test::cert_sha256_hex(other)) ==
          rp::test::spki_sha256_base64(other));
}

TEST_CASE("public_key_pin refuses what it can't pin, without quoting the file", "[cert_pin]")
{
    const Cert veeam = rp::test::make_cert("Veeam Software", Role::veeam_default);
    const Cert other = rp::test::make_cert("Veeam Software", Role::veeam_default);
    const rp::test::TempDir dir;
    const std::string pem = veeam.pem().cert;
    const std::string hash = rp::test::cert_sha256_hex(veeam);

    SECTION("the file holds no certificate with that SHA-256")
    {
        const std::string file = to_utf8(dir.write("veeam.pem", other.pem().cert));
        try {
            rp::public_key_pin(file, hash);
            FAIL("a certificate that isn't in the file was pinned");
        } catch (const rp::CertPinError& e) {
            CHECK(std::string{e.what()} ==
                  "veeam_ca_file holds no certificate whose SHA-256 is veeam_cert_sha256");
        }
    }

    SECTION("the file doesn't exist")
    {
        try {
            rp::public_key_pin(to_utf8(dir.path() / "missing.pem"), hash);
            FAIL("a missing file was accepted");
        } catch (const rp::CertPinError& e) {
            CHECK(std::string{e.what()} == "veeam_ca_file can't be read");
        }
    }

    SECTION("the file holds a private key and no certificate")
    {
        // The key is the secret a careless export could put here: the message
        // must not quote any of it.
        const std::string file = to_utf8(dir.write("key.pem", veeam.pem().key));
        try {
            rp::public_key_pin(file, hash);
            FAIL("a file without certificates was accepted");
        } catch (const rp::CertPinError& e) {
            CHECK(std::string{e.what()} ==
                  "veeam_ca_file holds no certificate whose SHA-256 is veeam_cert_sha256");
        }
    }

    SECTION("the certificate is in DER, not PEM: curl's Schannel backend reads PEM only")
    {
        unsigned char* der = nullptr;
        const int length = i2d_X509(veeam.cert.get(), &der);
        REQUIRE(length > 0);
        const std::string bytes(reinterpret_cast<const char*>(der), static_cast<std::size_t>(length));
        OPENSSL_free(der);
        const std::string file = to_utf8(dir.write("veeam.cer", bytes));
        CHECK_THROWS_AS(rp::public_key_pin(file, hash), rp::CertPinError);
    }

    SECTION("the hash isn't 64 hex digits")
    {
        const std::string file = to_utf8(dir.write("veeam.pem", pem));
        try {
            rp::public_key_pin(file, hash.substr(0, 40));
            FAIL("a malformed hash was accepted");
        } catch (const rp::CertPinError& e) {
            CHECK(std::string{e.what()} == "veeam_cert_sha256 must be 64 hexadecimal digits");
        }
    }

    SECTION("the path isn't valid UTF-8")
    {
        CHECK_THROWS_AS(rp::public_key_pin("C:\\bad\xff.pem", hash), rp::CertPinError);
    }
}

TEST_CASE("public_key_pin refuses a file too large to be a certificate bundle", "[cert_pin]")
{
    const Cert veeam = rp::test::make_cert("Veeam Software", Role::veeam_default);
    const rp::test::TempDir dir;
    // The certificate, then padding past the 1 MiB limit.
    const std::string file = to_utf8(
        dir.write("big.pem", veeam.pem().cert + std::string(1024 * 1024, '\n')));
    try {
        rp::public_key_pin(file, rp::test::cert_sha256_hex(veeam));
        FAIL("an oversized file was read");
    } catch (const rp::CertPinError& e) {
        CHECK(std::string{e.what()} == "veeam_ca_file is larger than 1 MiB");
    }
}
