// The RFC 3161 primitive over OpenSSL (W4.4, docs/decisions.md 2026-10-06 W4.4,
// points 4 and 5): what is one token, what a token says of itself, and whether
// it verifies under the caller's certificates. Tokens come from the test-only
// TSA in tsa_lab.hpp, whose time is fixed.

#include "tsa_lab.hpp"

#include <rp/rfc3161.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <openssl/ts.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

using rp::Rfc3161;
using rp::TimestampResponse;
using rp::TimestampTokenInfo;
using rp::test::kDigestAbc;
using rp::test::kDigestEmpty;
using rp::test::TestTsa;

constexpr std::uint64_t kNonce = 0x0123456789abcdefULL;

const Rfc3161& ts()
{
    return rp::openssl_rfc3161();
}

const TestTsa& tsa()
{
    static const TestTsa one;
    return one;
}

std::vector<unsigned char> bytes_of(const std::array<unsigned char, 32>& digest)
{
    return {digest.begin(), digest.end()};
}

} // namespace

// --- Failure paths: what is no response and no token --------------------------

TEST_CASE("parse_response refuses what isn't one TimeStampResp", "[rfc3161]")
{
    const std::string good = tsa().respond(ts().request(kDigestAbc, kNonce));
    REQUIRE(ts().parse_response(good));

    SECTION("nothing")
    {
        CHECK_FALSE(ts().parse_response(""));
    }
    SECTION("text")
    {
        CHECK_FALSE(ts().parse_response("<html><body>503 Service Unavailable</body></html>"));
    }
    SECTION("cut short")
    {
        CHECK_FALSE(ts().parse_response(good.substr(0, good.size() - 1)));
        CHECK_FALSE(ts().parse_response(good.substr(0, 20)));
    }
    SECTION("a byte after it")
    {
        CHECK_FALSE(ts().parse_response(good + std::string(1, '\0')));
    }
    SECTION("a bare token")
    {
        CHECK_FALSE(ts().parse_response(tsa().token(kDigestAbc)));
    }
}

TEST_CASE("parse_token refuses what isn't one TimeStampToken", "[rfc3161]")
{
    const std::string token = tsa().token(kDigestAbc);
    REQUIRE(ts().parse_token(token));

    SECTION("nothing")
    {
        CHECK_FALSE(ts().parse_token(""));
    }
    SECTION("text")
    {
        CHECK_FALSE(ts().parse_token("not a token"));
    }
    SECTION("cut short")
    {
        CHECK_FALSE(ts().parse_token(token.substr(0, token.size() - 1)));
    }
    SECTION("a byte after it")
    {
        CHECK_FALSE(ts().parse_token(token + std::string(1, '\0')));
    }
    SECTION("the whole response")
    {
        CHECK_FALSE(ts().parse_token(tsa().respond(ts().request(kDigestAbc, kNonce))));
    }
    SECTION("a rejection")
    {
        CHECK_FALSE(ts().parse_token(TestTsa::rejection()));
    }
    SECTION("a certificate")
    {
        CHECK_FALSE(ts().parse_token(tsa().root_pem()));
    }
}

TEST_CASE("verify_token refuses a token that doesn't verify under the caller's CA", "[rfc3161]")
{
    const std::string ca = tsa().root_pem();
    const std::string token = tsa().token(kDigestAbc);
    REQUIRE(ts().verify_token(token, ca));

    SECTION("another root")
    {
        const TestTsa other("another test root (not a secret)");
        CHECK_FALSE(ts().verify_token(token, other.root_pem()));
        CHECK(ts().verify_token(other.token(kDigestAbc), other.root_pem()));
        CHECK_FALSE(ts().verify_token(other.token(kDigestAbc), ca));
    }
    SECTION("no CA at all")
    {
        CHECK_FALSE(ts().verify_token(token, ""));
        CHECK_FALSE(ts().verify_token(token, "not a certificate"));
    }
    SECTION("one bit of the signature flipped")
    {
        std::string changed = token;
        changed[changed.size() - 5] = static_cast<char>(changed[changed.size() - 5] ^ 0x01);
        CHECK_FALSE(ts().verify_token(changed, ca));
    }
    SECTION("one bit of the stamped hash flipped")
    {
        // The TSTInfo's bytes are what the signer's messageDigest covers.
        std::string changed = token;
        const std::string imprint(reinterpret_cast<const char*>(kDigestAbc.data()),
                                  kDigestAbc.size());
        const std::size_t at = changed.find(imprint);
        REQUIRE(at != std::string::npos);
        changed[at] = static_cast<char>(changed[at] ^ 0x01);
        REQUIRE(ts().parse_token(changed));
        CHECK_FALSE(ts().verify_token(changed, ca));
    }
    SECTION("stamped before its certificates were valid")
    {
        TestTsa early(tsa().root_pem(), tsa().tsa_cert_pem_text(), tsa().tsa_key_pem_text());
        early.time = rp::test::kTestTsaNotBefore - 86400;
        CHECK_FALSE(ts().verify_token(early.token(kDigestAbc), ca));
    }
    SECTION("a token without its signer's certificate")
    {
        // certReq false: build the request by hand.
        const std::string request = ts().request(kDigestAbc, kNonce);
        const unsigned char* p = reinterpret_cast<const unsigned char*>(request.data());
        const std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)> parsed(
            d2i_TS_REQ(nullptr, &p, static_cast<long>(request.size())), &TS_REQ_free);
        REQUIRE(parsed);
        REQUIRE(TS_REQ_set_cert_req(parsed.get(), 0) == 1);
        unsigned char* raw = nullptr;
        const int size = i2d_TS_REQ(parsed.get(), &raw);
        REQUIRE(size > 0);
        const std::string bare_request(reinterpret_cast<const char*>(raw),
                                       static_cast<std::size_t>(size));
        OPENSSL_free(raw);
        const std::optional<TimestampResponse> response =
            ts().parse_response(tsa().respond(bare_request));
        REQUIRE(response);
        REQUIRE(ts().parse_token(response->token));
        CHECK_FALSE(ts().verify_token(response->token, ca));
    }
    SECTION("what isn't a token")
    {
        CHECK_FALSE(ts().verify_token("", ca));
        CHECK_FALSE(ts().verify_token(token + std::string(1, '\0'), ca));
        CHECK_FALSE(ts().verify_token(tsa().respond(ts().request(kDigestAbc, kNonce)), ca));
    }
}

// --- The request ---------------------------------------------------------------

TEST_CASE("request is version 1, a SHA-256 imprint, the nonce and certReq", "[rfc3161]")
{
    const std::uint64_t nonce = GENERATE(std::uint64_t{0}, std::uint64_t{1}, kNonce,
                                         std::uint64_t{0xffffffffffffffffULL});
    const std::string der = ts().request(kDigestAbc, nonce);
    REQUIRE_FALSE(der.empty());

    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    const std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)> request(
        d2i_TS_REQ(nullptr, &p, static_cast<long>(der.size())), &TS_REQ_free);
    REQUIRE(request);
    CHECK(p == reinterpret_cast<const unsigned char*>(der.data()) + der.size());
    CHECK(TS_REQ_get_version(request.get()) == 1);
    CHECK(TS_REQ_get_cert_req(request.get()) != 0);
    CHECK(TS_REQ_get_policy_id(request.get()) == nullptr);
    TS_MSG_IMPRINT* imprint = TS_REQ_get_msg_imprint(request.get());
    CHECK(OBJ_obj2nid(TS_MSG_IMPRINT_get_algo(imprint)->algorithm) == NID_sha256);
    const ASN1_OCTET_STRING* message = TS_MSG_IMPRINT_get_msg(imprint);
    CHECK(std::vector<unsigned char>(ASN1_STRING_get0_data(message),
                                     ASN1_STRING_get0_data(message) +
                                         ASN1_STRING_length(message)) == bytes_of(kDigestAbc));
    std::uint64_t sent = 0;
    REQUIRE(ASN1_INTEGER_get_uint64(&sent, TS_REQ_get_nonce(request.get())) == 1);
    CHECK(sent == nonce);
}

// --- The happy path ------------------------------------------------------------

TEST_CASE("a granted response gives its status and the token's own bytes", "[rfc3161]")
{
    const std::string der = tsa().respond(ts().request(kDigestEmpty, kNonce));
    const std::optional<TimestampResponse> response = ts().parse_response(der);
    REQUIRE(response);
    CHECK(response->status == rp::kTimestampGranted);
    // The token as the TSA sent it: the response's last bytes, never a re-encoding.
    REQUIRE(response->token.size() < der.size());
    CHECK(der.ends_with(response->token));

    const std::optional<TimestampTokenInfo> info = ts().parse_token(response->token);
    REQUIRE(info);
    CHECK(info->sha256);
    CHECK(info->imprint == bytes_of(kDigestEmpty));
    CHECK(info->nonce == kNonce);
    CHECK(info->gen_time == rp::test::kTestTsaTime);
    CHECK(ts().verify_token(response->token, tsa().root_pem()));
}

TEST_CASE("a response that grants nothing is read with its status and no token", "[rfc3161]")
{
    const std::optional<TimestampResponse> rejected = ts().parse_response(TestTsa::rejection());
    REQUIRE(rejected);
    CHECK(rejected->status == 2);
    CHECK(rejected->token.empty());

    // grantedWithMods (1) still carries a token; the caller refuses the status.
    const std::string good = tsa().respond(ts().request(kDigestAbc, kNonce));
    const std::optional<TimestampResponse> mods =
        ts().parse_response(TestTsa::with_status(good, 1));
    REQUIRE(mods);
    CHECK(mods->status == 1);
    CHECK_FALSE(mods->token.empty());
}

TEST_CASE("a token over another hash algorithm says so", "[rfc3161]")
{
    // A SHA-512 imprint: the request built by hand, the responder takes it.
    const std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)> request(TS_REQ_new(), &TS_REQ_free);
    REQUIRE(TS_REQ_set_version(request.get(), 1) == 1);
    const std::unique_ptr<TS_MSG_IMPRINT, decltype(&TS_MSG_IMPRINT_free)> imprint(
        TS_MSG_IMPRINT_new(), &TS_MSG_IMPRINT_free);
    X509_ALGOR* algorithm = X509_ALGOR_new();
    REQUIRE(X509_ALGOR_set0(algorithm, OBJ_nid2obj(NID_sha512), V_ASN1_NULL, nullptr) == 1);
    REQUIRE(TS_MSG_IMPRINT_set_algo(imprint.get(), algorithm) == 1);
    X509_ALGOR_free(algorithm);
    const std::vector<unsigned char> digest(64, 0x5a);
    REQUIRE(TS_MSG_IMPRINT_set_msg(imprint.get(), const_cast<unsigned char*>(digest.data()),
                                   static_cast<int>(digest.size())) == 1);
    REQUIRE(TS_REQ_set_msg_imprint(request.get(), imprint.get()) == 1);
    REQUIRE(TS_REQ_set_cert_req(request.get(), 1) == 1);
    unsigned char* raw = nullptr;
    const int size = i2d_TS_REQ(request.get(), &raw);
    REQUIRE(size > 0);
    const std::string der(reinterpret_cast<const char*>(raw), static_cast<std::size_t>(size));
    OPENSSL_free(raw);

    const std::optional<TimestampResponse> response = ts().parse_response(tsa().respond(der));
    REQUIRE(response);
    const std::optional<TimestampTokenInfo> info = ts().parse_token(response->token);
    REQUIRE(info);
    CHECK_FALSE(info->sha256);
    CHECK(info->imprint == digest);
    CHECK_FALSE(info->nonce); // none was sent
}

TEST_CASE("the TSA's own certificate ends the chain when the caller gives it", "[rfc3161]")
{
    // A certificate of the CA file ends the chain wherever it is met.
    const std::string token = tsa().token(kDigestAbc);
    CHECK(ts().verify_token(token, tsa().tsa_cert_pem_text()));
    const TestTsa other("another test root (not a secret)");
    CHECK(ts().verify_token(token, other.root_pem() + tsa().root_pem()));
}

TEST_CASE("certificates_in counts the certificates of a PEM text", "[rfc3161]")
{
    const TestTsa other("another test root (not a secret)");
    CHECK(ts().certificates_in("") == 0);
    CHECK(ts().certificates_in("not a certificate") == 0);
    CHECK(ts().certificates_in(tsa().root_pem()) == 1);
    CHECK(ts().certificates_in(tsa().root_pem() + other.root_pem()) == 2);
    CHECK(ts().certificates_in(tsa().tsa_key_pem_text()) == 0);
    // A block that is cut off is no certificate file.
    const std::string pem = tsa().root_pem();
    CHECK(ts().certificates_in(pem + pem.substr(0, pem.size() / 2)) == 0);
}

TEST_CASE("timestamp_time_text is the time in UTC to the second", "[rfc3161]")
{
    CHECK(rp::timestamp_time_text(0) == "1970-01-01T00:00:00Z");
    CHECK(rp::timestamp_time_text(rp::test::kTestTsaTime) == "2026-10-06T12:00:00Z");
    CHECK(rp::timestamp_time_text(951782399) == "2000-02-28T23:59:59Z");
    CHECK(rp::timestamp_time_text(951868800) == "2000-03-01T00:00:00Z");
    CHECK(rp::timestamp_time_text(4102444799) == "2099-12-31T23:59:59Z");
}

TEST_CASE("random_nonce gives a new nonce each time", "[rfc3161]")
{
    const std::optional<std::uint64_t> a = ts().random_nonce();
    const std::optional<std::uint64_t> b = ts().random_nonce();
    REQUIRE(a);
    REQUIRE(b);
    CHECK(*a != *b);
}

TEST_CASE("the real RFC 3161 primitive is one object", "[rfc3161]")
{
    CHECK(&rp::openssl_rfc3161() == &rp::openssl_rfc3161());
}
