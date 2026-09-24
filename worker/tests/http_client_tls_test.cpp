// W1.3: TLS against a real HTTPS server on 127.0.0.1, with self-signed
// certificates made at test time. This is the Veeam case: a self-signed
// certificate the Windows store doesn't trust, trusted through
// HttpClientOptions::ca_file (curl's Schannel backend and CURLOPT_CAINFO).

#include "local_http_server.hpp" // first: httplib needs winsock2.h before windows.h
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

namespace {

struct Pem {
    std::string cert;
    std::string key;
};

std::string bio_to_string(BIO* bio)
{
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio, &data);
    return {data, static_cast<std::size_t>(length)};
}

void add_extension(X509* cert, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    REQUIRE(ext != nullptr);
    REQUIRE(X509_add_ext(cert, ext, -1) == 1);
    X509_EXTENSION_free(ext);
}

// A self-signed EC P-256 server certificate for 127.0.0.1 and localhost,
// valid from an hour ago for a day.
Pem make_self_signed(const char* common_name)
{
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_EC_gen("P-256"),
                                                                  &EVP_PKEY_free);
    REQUIRE(key);
    const std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), &X509_free);
    REQUIRE(cert);
    REQUIRE(X509_set_version(cert.get(), X509_VERSION_3) == 1);
    // A random serial: two certificates with the same issuer name and serial
    // could confuse the verifier.
    std::random_device rd;
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), static_cast<long>(rd() >> 1)) == 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0);
    REQUIRE(X509_set_issuer_name(cert.get(), name) == 1);
    REQUIRE(X509_set_pubkey(cert.get(), key.get()) == 1);
    add_extension(cert.get(), NID_subject_alt_name, "IP:127.0.0.1,DNS:localhost");
    add_extension(cert.get(), NID_basic_constraints, "critical,CA:TRUE");
    add_extension(cert.get(), NID_key_usage, "critical,digitalSignature,keyCertSign");
    add_extension(cert.get(), NID_ext_key_usage, "serverAuth");
    REQUIRE(X509_sign(cert.get(), key.get(), EVP_sha256()) > 0);

    const std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new(BIO_s_mem()), &BIO_free);
    const std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(PEM_write_bio_X509(cert_bio.get(), cert.get()) == 1);
    REQUIRE(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr,
                                     nullptr) == 1);
    return {bio_to_string(cert_bio.get()), bio_to_string(key_bio.get())};
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

TEST_CASE("a self-signed server certificate is trusted only through its CA file", "[http][tls]")
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

    SECTION("the Windows store alone doesn't trust it: TLS failure, not retried")
    {
        rp::HttpClient client = make_client(std::nullopt);
        try {
            client.get(url);
            FAIL("an untrusted self-signed certificate was accepted");
        } catch (const rp::HttpError& e) {
            CAPTURE(e.what());
            CHECK(e.error() == rp::TransportError::tls);
            CHECK(e.attempts() == 1);
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

    SECTION("a CA file that doesn't exist: TLS failure, not a fallback to the Windows store")
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
