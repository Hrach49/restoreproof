// W1.3: TLS against a real HTTPS server on 127.0.0.1, with certificates made
// at test time. This is the Veeam case: a self-signed certificate, or one from
// a private CA, that the Windows store doesn't trust, trusted through
// HttpClientOptions::ca_file (curl's Schannel backend and CURLOPT_CAINFO).
// Offline, these tests show that the CA file's certificate is accepted and
// that others are rejected. They can't show that the Windows store is left
// out when a CA file is set: no certificate the store trusts can be served
// from 127.0.0.1. That rests on how curl's Schannel backend verifies (see
// HttpClientOptions::ca_file).

#include "local_http_server.hpp" // first: httplib needs winsock2.h before windows.h
#include "test_certs.hpp"
#include "test_support.hpp"

#include <rp/http_client.hpp>
#include <rp/retry_policy.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>

namespace {

using rp::test::Cert;
using rp::test::Pem;
using rp::test::Role;
using rp::test::bio_to_string;
using rp::test::make_cert;
using rp::test::make_self_signed;

// A DER CRL from `ca`, valid from an hour ago for a day, listing `revoked`
// (none when null).
std::string make_crl(const Cert& ca, const Cert* revoked)
{
    const std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(X509_CRL_new(),
                                                                  &X509_CRL_free);
    REQUIRE(crl);
    REQUIRE(X509_CRL_set_version(crl.get(), X509_CRL_VERSION_2) == 1);
    REQUIRE(X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(ca.cert.get())) == 1);
    const std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> last(
        X509_gmtime_adj(nullptr, -3600), &ASN1_TIME_free);
    const std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> next(
        X509_gmtime_adj(nullptr, 86400), &ASN1_TIME_free);
    REQUIRE(X509_CRL_set1_lastUpdate(crl.get(), last.get()) == 1);
    REQUIRE(X509_CRL_set1_nextUpdate(crl.get(), next.get()) == 1);
    if (revoked) {
        X509_REVOKED* entry = X509_REVOKED_new();
        REQUIRE(entry != nullptr);
        REQUIRE(X509_REVOKED_set_serialNumber(entry,
                                              X509_get_serialNumber(revoked->cert.get())) == 1);
        REQUIRE(X509_REVOKED_set_revocationDate(entry, last.get()) == 1);
        REQUIRE(X509_CRL_add0_revoked(crl.get(), entry) == 1);
    }
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca.cert.get(), nullptr, nullptr, crl.get(), 0);
    X509_EXTENSION* aki =
        X509V3_EXT_conf_nid(nullptr, &ctx, NID_authority_key_identifier, "keyid:always");
    REQUIRE(aki != nullptr);
    REQUIRE(X509_CRL_add_ext(crl.get(), aki, -1) == 1);
    X509_EXTENSION_free(aki);
    REQUIRE(X509_CRL_sort(crl.get()) == 1);
    REQUIRE(X509_CRL_sign(crl.get(), ca.key.get(), EVP_sha256()) > 0);

    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(i2d_X509_CRL_bio(bio.get(), crl.get()) == 1);
    return bio_to_string(bio.get());
}

std::unique_ptr<httplib::SSLServer> make_https_server(const Pem& pem)
{
    const httplib::SSLServer::PemMemory memory{pem.cert.data(), pem.cert.size(), pem.key.data(),
                                               pem.key.size(), nullptr, 0, nullptr};
    auto server = std::make_unique<httplib::SSLServer>(memory);
    REQUIRE(server->is_valid());
    server->Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("secure", "text/plain");
    });
    return server;
}

rp::HttpClient make_client(std::optional<std::string> ca_file)
{
    rp::HttpClientOptions options;
    options.ca_file = std::move(ca_file);
    options.sleep = [](std::chrono::milliseconds) {};
    options.jitter = [] { return 0.0; };
    return rp::HttpClient(std::move(options));
}

std::string to_utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

} // namespace

TEST_CASE("a self-signed server certificate is trusted through a CA file holding it", "[http][tls]")
{
    const Pem server_pem = make_self_signed("rp-test-server");
    const Pem other_pem = make_self_signed("rp-test-other");
    rp::test::BasicLocalServer<httplib::SSLServer> server(make_https_server(server_pem));
    const std::string url = server.url("/");
    const rp::test::TempDir dir;
    // "тест-ca.pem": Cyrillic is outside the ANSI code page, so this proves
    // the path reaches curl as UTF-8.
    const std::filesystem::path ca_path =
        dir.write(std::filesystem::path{std::u8string{u8"тест-ca.pem"}},
                  server_pem.cert);
    const std::filesystem::path other_path = dir.write("other-ca.pem", other_pem.cert);

    SECTION("without a CA file it is rejected: TLS failure, not retried")
    {
        rp::HttpClient client = make_client(std::nullopt);
        try {
            client.get(url);
            FAIL("an untrusted self-signed certificate was accepted");
        } catch (const rp::HttpError& e) {
            const std::string what = e.what();
            CAPTURE(what);
            CHECK(e.error() == rp::TransportError::tls);
            CHECK(e.attempts() == 1);
            // Some reason follows, even when curl gives no message of its own.
            constexpr std::string_view marker = "(not retried): ";
            const std::size_t at = what.find(marker);
            REQUIRE(at != std::string::npos);
            CHECK(what.size() > at + marker.size());
        }
    }

    SECTION("its own certificate as the CA file: the request succeeds")
    {
        rp::HttpClient client = make_client(to_utf8(ca_path));
        rp::HttpResponse response;
        try {
            response = client.get(url);
        } catch (const rp::HttpError& e) {
            FAIL("HttpError: " << e.what());
        }
        CHECK(response.status == 200);
        CHECK(response.body == "secure");
    }

    SECTION("a CA file that doesn't exist: TLS failure, not retried")
    {
        rp::HttpClient client = make_client(to_utf8(dir.path() / "missing.pem"));
        try {
            client.get(url);
            FAIL("a missing CA file was ignored");
        } catch (const rp::HttpError& e) {
            CAPTURE(e.what());
            CHECK(e.error() == rp::TransportError::tls);
            CHECK(e.attempts() == 1);
        }
    }

    // The Windows store doesn't trust either certificate, so this shows only
    // that a certificate outside the CA file is rejected, not that the store
    // is ignored when a CA file is set.
    SECTION("another certificate as the CA file: TLS failure, not retried")
    {
        rp::HttpClient client = make_client(to_utf8(other_path));
        try {
            client.get(url);
            FAIL("a certificate outside the CA file was accepted");
        } catch (const rp::HttpError& e) {
            CAPTURE(e.what());
            CHECK(e.error() == rp::TransportError::tls);
            CHECK(e.attempts() == 1);
        }
    }
}

// A CA file makes curl verify the chain itself, with a revocation check on
// every certificate. A private CA often publishes no CRL at all, or one the
// Worker can't reach, and a strict check fails on "status unknown" with no
// setting to fix it. So revocation is checked on a best-effort basis: a
// certificate the CA has revoked is still rejected.
TEST_CASE("a certificate from a private CA is checked for revocation as far as it can be",
          "[http][tls]")
{
    const Cert ca = make_cert("rp-test-private-ca", Role::ca);
    const rp::test::TempDir dir;
    const std::filesystem::path ca_path = dir.write("private-ca.pem", ca.pem().cert);
    rp::HttpClient client = make_client(to_utf8(ca_path));

    // The CRL is served over plain HTTP from 127.0.0.1, as a CA's CDP would be.
    std::string crl;
    rp::test::LocalHttpServer crl_server;
    crl_server.server().Get("/ca.crl", [&crl](const httplib::Request&, httplib::Response& res) {
        res.set_content(crl, "application/pkix-crl");
    });
    const std::string crl_url = crl_server.url("/ca.crl");
    const std::string offline_url =
        "http://127.0.0.1:" + std::to_string(rp::test::closed_local_port()) + "/ca.crl";

    const auto get = [&client](const Cert& leaf) {
        rp::test::BasicLocalServer<httplib::SSLServer> server(make_https_server(leaf.pem()));
        return client.get(server.url("/"));
    };
    const auto check_accepted = [&get](const Cert& leaf) {
        try {
            const rp::HttpResponse response = get(leaf);
            CHECK(response.status == 200);
            CHECK(response.body == "secure");
        } catch (const rp::HttpError& e) {
            FAIL("HttpError: " << e.what());
        }
    };

    SECTION("a leaf with no CRL distribution point is accepted")
    {
        check_accepted(make_cert("rp-test-leaf", Role::leaf, &ca));
    }

    SECTION("a leaf whose CRL can't be fetched is accepted")
    {
        check_accepted(make_cert("rp-test-leaf", Role::leaf, &ca, offline_url.c_str()));
    }

    SECTION("a leaf the CA's CRL doesn't list is accepted")
    {
        const Cert leaf = make_cert("rp-test-leaf", Role::leaf, &ca, crl_url.c_str());
        crl = make_crl(ca, nullptr);
        check_accepted(leaf);
    }

    SECTION("a leaf the CA's CRL lists as revoked is rejected: TLS failure, not retried")
    {
        const Cert leaf = make_cert("rp-test-leaf", Role::leaf, &ca, crl_url.c_str());
        crl = make_crl(ca, &leaf);
        try {
            get(leaf);
            FAIL("a revoked certificate was accepted");
        } catch (const rp::HttpError& e) {
            const std::string what = e.what();
            CAPTURE(what);
            CHECK(e.error() == rp::TransportError::tls);
            CHECK(e.attempts() == 1);
            CHECK(what.find("revoked") != std::string::npos);
        }
    }
}

// W1.5 (docs/decisions.md 2026-09-26): Veeam's default REST certificate is
// self-signed, CN=Veeam Software, with no subject alternative name, so the
// host-name check can never pass. With veeam_cert_sha256 set, the client
// verifies the chain against the CA file as usual, pins the named
// certificate's public key, and skips only the host-name check. Without a
// pin, nothing is relaxed.
TEST_CASE("Veeam's SAN-less certificate is accepted only with its pin and a CA file holding it",
          "[http][tls]")
{
    using rp::test::cert_sha256_hex;
    const Cert veeam = make_cert("Veeam Software", Role::veeam_default);
    const Cert impostor = make_cert("Veeam Software", Role::veeam_default);
    rp::test::BasicLocalServer<httplib::SSLServer> server(make_https_server(veeam.pem()));
    const std::string url = server.url("/");
    const rp::test::TempDir dir;
    const std::string ca_file = to_utf8(dir.write("veeam.pem", veeam.pem().cert));
    // Both certificates, so either can be pinned.
    const std::string both_file =
        to_utf8(dir.write("both.pem", impostor.pem().cert + veeam.pem().cert));

    const auto client = [](std::optional<std::string> ca, std::optional<std::string> pin) {
        rp::HttpClientOptions options;
        options.ca_file = std::move(ca);
        options.pinned_cert_sha256 = std::move(pin);
        options.sleep = [](std::chrono::milliseconds) {};
        options.jitter = [] { return 0.0; };
        return rp::HttpClient(std::move(options));
    };
    // The request fails with a certificate verdict (tls) and `attempts`.
    const auto check_refused = [&url](rp::HttpClient c, int attempts, std::string_view reason) {
        try {
            c.get(url);
            FAIL("the request succeeded");
        } catch (const rp::HttpError& e) {
            const std::string what = e.what();
            CAPTURE(what);
            CHECK(e.error() == rp::TransportError::tls);
            CHECK(e.attempts() == attempts);
            CHECK(what.find(reason) != std::string::npos);
        }
    };

    SECTION("the right pin and a CA file holding the certificate: accepted")
    {
        rp::HttpClient c = client(ca_file, cert_sha256_hex(veeam));
        rp::HttpResponse response;
        try {
            response = c.get(url);
        } catch (const rp::HttpError& e) {
            FAIL("HttpError: " << e.what());
        }
        CHECK(response.status == 200);
        CHECK(response.body == "secure");
    }

    SECTION("the pin of another certificate in the CA file: rejected, not retried")
    {
        check_refused(client(both_file, cert_sha256_hex(impostor)), 1, "pinned public key");
    }

    SECTION("the right pin, but the server presents another certificate: rejected")
    {
        // The server's key is the impostor's; the CA file and pin name veeam's.
        rp::test::BasicLocalServer<httplib::SSLServer> other(make_https_server(impostor.pem()));
        rp::HttpClient c = client(both_file, cert_sha256_hex(veeam));
        try {
            c.get(other.url("/"));
            FAIL("a certificate other than the pinned one was accepted");
        } catch (const rp::HttpError& e) {
            CAPTURE(e.what());
            CHECK(e.error() == rp::TransportError::tls);
            CHECK(e.attempts() == 1);
        }
    }

    SECTION("no pin, no CA file: rejected (untrusted)")
    {
        check_refused(client(std::nullopt, std::nullopt), 1, "(not retried): ");
    }

    SECTION("a CA file holding the certificate but no pin: rejected, the host name still checked")
    {
        // This is why the pin exists: the certificate is trusted, but it
        // names no host, and without a pin nothing is relaxed.
        check_refused(client(ca_file, std::nullopt), 1, "(not retried): ");
    }

    SECTION("a pin without a CA file: refused before anything is sent")
    {
        check_refused(client(std::nullopt, cert_sha256_hex(veeam)), 0,
                      "refused before sending: veeam_cert_sha256 needs veeam_ca_file");
    }

    SECTION("a pin whose certificate isn't in the CA file: refused before anything is sent")
    {
        check_refused(client(ca_file, cert_sha256_hex(impostor)), 0,
                      "refused before sending: veeam_ca_file holds no certificate whose SHA-256 "
                      "is veeam_cert_sha256");
    }
}

TEST_CASE("an expired Veeam certificate is rejected even with its pin", "[http][tls]")
{
    // Peer verification stays on with a pin, so validity dates still count.
    const Cert expired = make_cert("Veeam Software", Role::veeam_default, nullptr, nullptr, true);
    rp::test::BasicLocalServer<httplib::SSLServer> server(make_https_server(expired.pem()));
    const rp::test::TempDir dir;
    rp::HttpClientOptions options;
    options.ca_file = to_utf8(dir.write("veeam.pem", expired.pem().cert));
    options.pinned_cert_sha256 = rp::test::cert_sha256_hex(expired);
    options.sleep = [](std::chrono::milliseconds) {};
    rp::HttpClient client(std::move(options));

    try {
        client.get(server.url("/"));
        FAIL("an expired certificate was accepted");
    } catch (const rp::HttpError& e) {
        const std::string what = e.what();
        CAPTURE(what);
        CHECK(e.error() == rp::TransportError::tls);
        CHECK(e.attempts() == 1);
        CHECK(what.find("time valid") != std::string::npos);
    }
}
