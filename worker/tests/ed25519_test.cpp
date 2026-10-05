// The Ed25519 primitive over OpenSSL (W4.3, docs/decisions.md 2026-10-05,
// points 4 and 6): RFC 8032's tests from shared/testdata/signing-v1/ed25519.json
// reproduced byte for byte, and every key or PEM it must refuse. The keys of
// that file are the RFC's published test keys; every other key is made here.

#include <rp/ed25519.hpp>

#include "result_lab.hpp"
#include "test_certs.hpp"

#include <rp/base64.hpp>

#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using nlohmann::json;
using rp::Ed25519;
using rp::Ed25519Key;
using rp::Ed25519Signature;

constexpr const char* kVectors = "testdata/signing-v1/ed25519.json";

// SubjectPublicKeyInfo's header for Ed25519 (RFC 8410): the raw key follows.
constexpr std::array<unsigned char, 12> kSpkiPrefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
                                                       0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

std::vector<unsigned char> from_hex(std::string_view hex)
{
    const auto nibble = [](char c) {
        return static_cast<unsigned char>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    REQUIRE(hex.size() % 2 == 0);
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<unsigned char>(nibble(hex[i]) << 4 | nibble(hex[i + 1])));
    }
    return bytes;
}

std::vector<unsigned char> hex_of(const json& test, const char* key)
{
    return from_hex(test.at(key).get<std::string>());
}

json vectors()
{
    return json::parse(rp::test::read_shared(kVectors)).at("tests");
}

std::unique_ptr<Ed25519Key> key_of(const json& test)
{
    const std::vector<unsigned char> seed = hex_of(test, "seed_hex");
    REQUIRE(seed.size() == rp::kEd25519SeedBytes);
    return rp::openssl_ed25519().make_key(
        std::span<const unsigned char, rp::kEd25519SeedBytes>(seed.data(), seed.size()));
}

std::vector<unsigned char> spki_of(const json& test)
{
    std::vector<unsigned char> der(kSpkiPrefix.begin(), kSpkiPrefix.end());
    const std::vector<unsigned char> raw = hex_of(test, "public_key_hex");
    der.insert(der.end(), raw.begin(), raw.end());
    return der;
}

Ed25519Signature signature_of(const json& test)
{
    const std::vector<unsigned char> bytes = hex_of(test, "signature_hex");
    REQUIRE(bytes.size() == rp::kEd25519SignatureBytes);
    Ed25519Signature signature{};
    std::copy(bytes.begin(), bytes.end(), signature.begin());
    return signature;
}

// A public key OpenSSL made, as PEM.
std::string public_pem(EVP_PKEY* key)
{
    REQUIRE(key != nullptr);
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(PEM_write_bio_PUBKEY(bio.get(), key) == 1);
    return rp::test::bio_to_string(bio.get());
}

std::string private_pem(EVP_PKEY* key)
{
    REQUIRE(key != nullptr);
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    return rp::test::bio_to_string(bio.get());
}

std::string pem_of_named_key(const char* type)
{
    const rp::test::KeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, type), &EVP_PKEY_free);
    return public_pem(key.get());
}

} // namespace

TEST_CASE("ed25519.json holds RFC 8032's three tests", "[ed25519]")
{
    const json tests = vectors();
    REQUIRE(tests.size() == 3);
    CHECK(tests.at(0).at("message_hex") == "");
    CHECK(tests.at(1).at("message_hex") == "72");
    CHECK(tests.at(2).at("message_hex") == "af82");
}

TEST_CASE("a key made from an RFC 8032 seed has the RFC's public key", "[ed25519]")
{
    const json test = vectors().at(GENERATE(range(0, 3)));
    CAPTURE(test.at("name"));
    const std::unique_ptr<Ed25519Key> key = key_of(test);
    REQUIRE(key);
    CHECK(key->public_key_der() == spki_of(test));
}

TEST_CASE("RFC 8032's signatures are reproduced byte for byte and accepted", "[ed25519]")
{
    const json test = vectors().at(GENERATE(range(0, 3)));
    CAPTURE(test.at("name"));
    const std::unique_ptr<Ed25519Key> key = key_of(test);
    REQUIRE(key);
    const std::vector<unsigned char> message = hex_of(test, "message_hex");

    const std::optional<Ed25519Signature> signature = key->sign(message);
    REQUIRE(signature);
    CHECK(*signature == signature_of(test));
    // Twice the same: Ed25519 draws nothing at random.
    CHECK(key->sign(message) == signature);
    CHECK(rp::openssl_ed25519().verify(spki_of(test), message, *signature));
}

TEST_CASE("a signature is refused for another message, another key or one bit changed",
          "[ed25519]")
{
    const Ed25519& ed = rp::openssl_ed25519();
    const json tests = vectors();
    const json& test = tests.at(1);
    const std::vector<unsigned char> message = hex_of(test, "message_hex");
    const Ed25519Signature signature = signature_of(test);
    REQUIRE(ed.verify(spki_of(test), message, signature));

    CHECK_FALSE(ed.verify(spki_of(test), hex_of(tests.at(2), "message_hex"), signature));
    CHECK_FALSE(ed.verify(spki_of(test), {}, signature));
    CHECK_FALSE(ed.verify(spki_of(tests.at(0)), message, signature));

    const std::size_t byte = GENERATE(std::size_t{0}, std::size_t{31}, std::size_t{32},
                                      std::size_t{63});
    CAPTURE(byte);
    Ed25519Signature changed = signature;
    changed[byte] ^= 0x01;
    CHECK_FALSE(ed.verify(spki_of(test), message, changed));
}

// S + L is the same number modulo the group's order, so a verifier that
// doesn't check S < L would take it (RFC 8032 section 5.1.7).
TEST_CASE("a signature whose S is S + L is refused", "[ed25519]")
{
    const json test = vectors().at(GENERATE(range(0, 3)));
    CAPTURE(test.at("name"));
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const std::vector<unsigned char> order =
        from_hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    Ed25519Signature signature = signature_of(test);
    unsigned carry = 0;
    for (std::size_t i = 0; i < 32; ++i) {
        const unsigned sum = signature[32 + i] + order[i] + carry;
        signature[32 + i] = static_cast<unsigned char>(sum & 0xff);
        carry = sum >> 8;
    }
    REQUIRE(carry == 0); // S + L fits 32 bytes
    CHECK_FALSE(rp::openssl_ed25519().verify(spki_of(test), hex_of(test, "message_hex"),
                                             signature));
}

TEST_CASE("verify refuses a public key that isn't Ed25519's 44 bytes of DER", "[ed25519]")
{
    const Ed25519& ed = rp::openssl_ed25519();
    const json test = vectors().at(0);
    const Ed25519Signature signature = signature_of(test);
    std::vector<unsigned char> der = spki_of(test);
    REQUIRE(ed.verify(der, {}, signature));

    SECTION("no key at all")
    {
        CHECK_FALSE(ed.verify({}, {}, signature));
    }
    SECTION("the raw 32 bytes without their header")
    {
        CHECK_FALSE(ed.verify(hex_of(test, "public_key_hex"), {}, signature));
    }
    SECTION("a byte after the key")
    {
        der.push_back(0x00);
        CHECK_FALSE(ed.verify(der, {}, signature));
    }
    SECTION("cut short")
    {
        der.pop_back();
        CHECK_FALSE(ed.verify(der, {}, signature));
    }
    SECTION("X25519's algorithm (the same length)")
    {
        der[8] = 0x6e;
        CHECK_FALSE(ed.verify(der, {}, signature));
    }
    SECTION("an RSA public key")
    {
        const rp::test::KeyPtr rsa = rp::test::shared_rsa2048_key();
        unsigned char* raw = nullptr;
        const int size = i2d_PUBKEY(rsa.get(), &raw);
        REQUIRE(size > 0);
        const std::vector<unsigned char> rsa_der(raw, raw + size);
        OPENSSL_free(raw);
        CHECK_FALSE(ed.verify(rsa_der, {}, signature));
    }
}

TEST_CASE("the public key's PEM is what OpenSSL writes and reads back to the same DER",
          "[ed25519]")
{
    const Ed25519& ed = rp::openssl_ed25519();
    const json test = vectors().at(GENERATE(range(0, 3)));
    CAPTURE(test.at("name"));
    const std::vector<unsigned char> der = spki_of(test);

    const std::string pem = ed.public_key_pem(der);
    CHECK(pem == "-----BEGIN PUBLIC KEY-----\n" + rp::base64_encode(der) +
                     "\n-----END PUBLIC KEY-----\n");
    CHECK(ed.public_key_from_pem(pem) == der);
}

// RFC 8032 test 1, as measured with OpenSSL when the entry was written.
TEST_CASE("RFC 8032 test 1's public PEM has the measured body", "[ed25519]")
{
    const json test = vectors().at(0);
    CHECK(rp::openssl_ed25519().public_key_pem(spki_of(test)) ==
          "-----BEGIN PUBLIC KEY-----\n"
          "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
          "-----END PUBLIC KEY-----\n");
}

TEST_CASE("public_key_pem refuses bytes that aren't an Ed25519 public key", "[ed25519]")
{
    const Ed25519& ed = rp::openssl_ed25519();
    std::vector<unsigned char> der = spki_of(vectors().at(0));
    CHECK(ed.public_key_pem({}) == "");
    CHECK(ed.public_key_pem(std::span<const unsigned char>(der).first(43)) == "");
    der.push_back(0x00);
    CHECK(ed.public_key_pem(der) == "");
}

TEST_CASE("public_key_from_pem takes CRLF line ends and blank lines around the block",
          "[ed25519]")
{
    const Ed25519& ed = rp::openssl_ed25519();
    const std::vector<unsigned char> der = spki_of(vectors().at(0));
    const std::string body = rp::base64_encode(der);
    CHECK(ed.public_key_from_pem("-----BEGIN PUBLIC KEY-----\r\n" + body +
                                 "\r\n-----END PUBLIC KEY-----\r\n") == der);
    CHECK(ed.public_key_from_pem("\n-----BEGIN PUBLIC KEY-----\n" + body +
                                 "\n-----END PUBLIC KEY-----\n\n") == der);
    CHECK(ed.public_key_from_pem("-----BEGIN PUBLIC KEY-----\n" + body +
                                 "\n-----END PUBLIC KEY-----") == der);
}

TEST_CASE("public_key_from_pem refuses everything but one Ed25519 public key", "[ed25519]")
{
    const Ed25519& ed = rp::openssl_ed25519();
    const json tests = vectors();
    const std::string good = ed.public_key_pem(spki_of(tests.at(0)));
    REQUIRE_FALSE(good.empty());

    SECTION("nothing")
    {
        CHECK(ed.public_key_from_pem("").empty());
    }
    SECTION("garbage")
    {
        CHECK(ed.public_key_from_pem("not a key").empty());
        CHECK(ed.public_key_from_pem(std::string("\0\xff\x01", 3)).empty());
    }
    SECTION("the bare Base64 line without its armour")
    {
        CHECK(ed.public_key_from_pem(rp::base64_encode(spki_of(tests.at(0)))).empty());
    }
    SECTION("a body that isn't a key")
    {
        CHECK(ed.public_key_from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n"
                                     "-----END PUBLIC KEY-----\n")
                  .empty());
    }
    SECTION("an RSA public key")
    {
        CHECK(ed.public_key_from_pem(public_pem(rp::test::shared_rsa2048_key().get())).empty());
    }
    SECTION("an X25519 public key")
    {
        CHECK(ed.public_key_from_pem(pem_of_named_key("X25519")).empty());
    }
    SECTION("an Ed448 public key")
    {
        CHECK(ed.public_key_from_pem(pem_of_named_key("ED448")).empty());
    }
    SECTION("an Ed25519 private key")
    {
        const rp::test::KeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"),
                                   &EVP_PKEY_free);
        CHECK(ed.public_key_from_pem(private_pem(key.get())).empty());
    }
    SECTION("a block that says it is encrypted")
    {
        // The library would ask the console for the password.
        CHECK(ed.public_key_from_pem("-----BEGIN PUBLIC KEY-----\n"
                                     "Proc-Type: 4,ENCRYPTED\n"
                                     "DEK-Info: AES-256-CBC,000102030405060708090A0B0C0D0E0F\n\n" +
                                     rp::base64_encode(spki_of(tests.at(0))) +
                                     "AAAA\n-----END PUBLIC KEY-----\n")
                  .empty());
    }
    SECTION("two keys")
    {
        CHECK(ed.public_key_from_pem(good + ed.public_key_pem(spki_of(tests.at(1)))).empty());
    }
    SECTION("text after the key")
    {
        CHECK(ed.public_key_from_pem(good + "x").empty());
    }
    SECTION("a NUL inside the text")
    {
        std::string text = good;
        text.insert(text.size() - 1, 1, '\0');
        CHECK(ed.public_key_from_pem(text).empty());
    }
}

// The W4.3 review's rule: the bytes between the armour lines are the key's 44
// bytes exactly, in strict Base64, and the block is three kinds of line and
// nothing else. shared/testdata/signing-v1/key-files.json holds every row
// (tests/signer_test.cpp runs them); these are the ones the old reader took.
TEST_CASE("public_key_from_pem takes only the key's own 44 bytes in the block", "[ed25519]")
{
    const Ed25519& ed = rp::openssl_ed25519();
    const std::vector<unsigned char> der = spki_of(vectors().at(0));
    const std::string body = rp::base64_encode(der);
    const std::string begin = "-----BEGIN PUBLIC KEY-----";
    const std::string end = "-----END PUBLIC KEY-----";
    const auto pem_of = [&](std::span<const unsigned char> bytes) {
        return begin + "\n" + rp::base64_encode(bytes) + "\n" + end + "\n";
    };
    REQUIRE(ed.public_key_from_pem(pem_of(der)) == der);

    SECTION("a byte after the key")
    {
        std::vector<unsigned char> longer = der;
        longer.push_back(0x00);
        CHECK(ed.public_key_from_pem(pem_of(longer)).empty());
    }
    SECTION("the BIT STRING's unused bits set to 1")
    {
        std::vector<unsigned char> unused = der;
        unused[11] = 0x01;
        CHECK(ed.public_key_from_pem(pem_of(unused)).empty());
    }
    SECTION("a long-form length")
    {
        std::vector<unsigned char> long_form = {0x30, 0x81, 0x2a};
        long_form.insert(long_form.end(), der.begin() + 2, der.end());
        CHECK(ed.public_key_from_pem(pem_of(long_form)).empty());
    }
    SECTION("Base64 with a pad bit set")
    {
        REQUIRE(body.ends_with("o="));
        CHECK(ed.public_key_from_pem(begin + "\n" + body.substr(0, body.size() - 2) + "p=\n" +
                                     end + "\n")
                  .empty());
    }
    SECTION("the body wrapped at another column is the same key")
    {
        CHECK(ed.public_key_from_pem(begin + "\n" + body.substr(0, 32) + "\n" + body.substr(32) +
                                     "\n" + end + "\n") == der);
        CHECK(ed.public_key_from_pem(begin + "\r\n" + body.substr(0, body.size() - 1) +
                                     "\r\n=\r\n" + end) == der);
    }
    SECTION("a lone CR is no line end")
    {
        CHECK(ed.public_key_from_pem(begin + "\r" + body + "\r" + end + "\r").empty());
        CHECK(ed.public_key_from_pem(begin + "\n" + body + "\r" + end + "\n").empty());
        // Around the block it is white space.
        CHECK(ed.public_key_from_pem("\r" + pem_of(der) + "\r") == der);
    }
    SECTION("no line end between the lines")
    {
        CHECK(ed.public_key_from_pem(begin + body + end).empty());
        CHECK(ed.public_key_from_pem(begin + body + "\n" + end).empty());
        CHECK(ed.public_key_from_pem(begin + "\n" + body + end).empty());
    }
    SECTION("a header line, a blank line, a space, no body")
    {
        CHECK(ed.public_key_from_pem(begin + "\nComment: x\n\n" + body + "\n" + end + "\n")
                  .empty());
        CHECK(ed.public_key_from_pem(begin + "\n\n" + body + "\n" + end + "\n").empty());
        CHECK(ed.public_key_from_pem(begin + "\n" + body + "\n " + end + "\n").empty());
        CHECK(ed.public_key_from_pem(begin + " \n" + body + "\n" + end + "\n").empty());
        CHECK(ed.public_key_from_pem(begin + "\n" + body.substr(0, 32) + " " + body.substr(32) +
                                     "\n" + end + "\n")
                  .empty());
        CHECK(ed.public_key_from_pem(begin + "\n" + end + "\n").empty());
        CHECK(ed.public_key_from_pem(begin).empty());
        CHECK(ed.public_key_from_pem(begin + "\n").empty());
        CHECK(ed.public_key_from_pem(begin + "\n" + body).empty());
        CHECK(ed.public_key_from_pem(begin + "\n" + body + "\n").empty());
    }
}

TEST_CASE("the real primitive is one object", "[ed25519]")
{
    CHECK(&rp::openssl_ed25519() == &rp::openssl_ed25519());
}
