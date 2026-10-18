// W2.5: the restore credential's export (rp/cert_export.hpp,
// docs/decisions.md 2026-09-30 point 1). The core runs on an in-memory store
// made from a test PFX (tests/test_certs.hpp), and its export is read back by
// the Graph certificate loader and by Windows. LocalMachine\My itself is only
// opened read-only, for a thumbprint no certificate has.

#include "test_certs.hpp"

#include "../src/cert_export_detail.hpp"

#include <rp/base64.hpp>
#include <rp/cert_export.hpp>
#include <rp/client_assertion.hpp>

#include <ncrypt.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace std::chrono_literals;

namespace {

constexpr const char* kPfxPassword = "test-pfx-password";

struct StoreCloser {
    void operator()(HCERTSTORE store) const noexcept { CertCloseStore(store, 0); }
};
using Store = std::unique_ptr<void, StoreCloser>;

// A store holding what `pfx` holds, as Windows reads a PFX: the key stays in
// memory (never persisted), exportable unless `exportable` is false.
Store import_pfx(std::vector<unsigned char> pfx, const char* password, bool exportable = true)
{
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(pfx.size()), pfx.data()};
    const std::wstring wide(password, password + std::char_traits<char>::length(password));
    const DWORD flags = PKCS12_NO_PERSIST_KEY | (exportable ? CRYPT_EXPORTABLE : 0);
    Store store(PFXImportCertStore(&blob, wide.c_str(), flags));
    REQUIRE(store);
    return store;
}

// A client certificate valid from an hour ago for a year, and a store with it
// and its key.
struct Lab {
    rp::test::Cert cert = rp::test::make_client_cert("RestoreProof Veeam app test");
    std::string thumbprint = rp::test::cert_sha1_hex(cert);
    Store store = import_pfx(rp::test::make_pfx(cert, kPfxPassword), kPfxPassword);
};

std::string export_error(HCERTSTORE store, const std::string& thumbprint,
                         std::chrono::system_clock::time_point wall_now =
                             std::chrono::system_clock::now())
{
    try {
        rp::cert_export_detail::export_from_store(store, thumbprint, wall_now, "the test store");
    } catch (const rp::CertExportError& e) {
        return e.what();
    }
    return "(no error)";
}

std::string lower(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

} // namespace

// --- Failure paths ----------------------------------------------------------

TEST_CASE("a thumbprint that isn't 40 hex digits is refused before the store is read",
          "[cert_export]")
{
    const std::string thumbprint = GENERATE(
        "", "AC3220B58A2B4C438DA13816C2DD1E25D1F783A", "AC3220B58A2B4C438DA13816C2DD1E25D1F783A70",
        "AC3220B58A2B4C438DA13816C2DD1E25D1F783AG", "AC32 20B58A2B4C438DA13816C2DD1E25D1F783A",
        "0xAC3220B58A2B4C438DA13816C2DD1E25D1F783");
    CAPTURE(thumbprint);

    // A null store: any use of it would fail differently.
    CHECK(export_error(nullptr, thumbprint) == "a certificate thumbprint must be 40 hex digits");
    const auto exporter = rp::make_local_machine_cert_exporter();
    CHECK_THROWS_WITH(exporter->export_pfx(thumbprint),
                      "a certificate thumbprint must be 40 hex digits");
}

TEST_CASE("a certificate that isn't in the store is not found", "[cert_export]")
{
    Lab lab;
    const std::string other = "0123456789ABCDEF0123456789ABCDEF01234567";

    CHECK(export_error(lab.store.get(), other) ==
          "certificate " + other + " in the test store: not found");
}

TEST_CASE("LocalMachine\\My is read without elevation, and an unknown thumbprint isn't there",
          "[cert_export]")
{
    // SHA-1 of nothing any store should hold; lower case, as any case goes.
    const std::string thumbprint = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const auto exporter = rp::make_local_machine_cert_exporter();

    CHECK_THROWS_WITH(exporter->export_pfx(thumbprint),
                      "certificate DA39A3EE5E6B4B0D3255BFEF95601890AFD80709 in "
                      "LocalMachine\\My: not found");
}

TEST_CASE("a certificate outside its validity is refused", "[cert_export]")
{
    Lab lab;
    const auto now = std::chrono::system_clock::now();

    SECTION("expired")
    {
        const std::string what = export_error(lab.store.get(), lab.thumbprint, now + 400 * 24h);
        CHECK_THAT(what, ContainsSubstring("certificate " + lab.thumbprint +
                                           " in the test store: expired at "));
    }
    SECTION("not yet valid")
    {
        const std::string what = export_error(lab.store.get(), lab.thumbprint, now - 2h);
        CHECK_THAT(what, ContainsSubstring("in the test store: not valid before "));
    }
}

TEST_CASE("a certificate without a private key is refused", "[cert_export]")
{
    Lab lab;
    const Store cert_only = import_pfx(
        rp::test::make_pfx(nullptr, lab.cert.cert.get(), kPfxPassword), kPfxPassword);

    CHECK(export_error(cert_only.get(), lab.thumbprint) ==
          "certificate " + lab.thumbprint + " in the test store: the certificate has no private key");
}

TEST_CASE("a private key that isn't exportable is refused", "[cert_export]")
{
    // Windows keeps an in-memory key only when it may be exported, so this
    // one goes into a CNG key file of the current user, as a machine key
    // lives in one, and is deleted again at the end.
    Lab lab;
    auto pfx = rp::test::make_pfx(lab.cert, kPfxPassword);
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(pfx.size()), pfx.data()};
    const std::wstring password(kPfxPassword,
                                kPfxPassword + std::char_traits<char>::length(kPfxPassword));
    const Store locked(PFXImportCertStore(&blob, password.c_str(), PKCS12_ALWAYS_CNG_KSP));
    REQUIRE(locked);
    struct KeyFile {
        HCERTSTORE store;
        ~KeyFile()
        {
            const CERT_CONTEXT* cert = CertEnumCertificatesInStore(store, nullptr);
            DWORD size = 0;
            if (cert == nullptr ||
                !CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, nullptr,
                                                   &size)) {
                CertFreeCertificateContext(cert);
                return;
            }
            std::vector<BYTE> buffer(size);
            if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, buffer.data(),
                                                  &size)) {
                const auto* info = reinterpret_cast<const CRYPT_KEY_PROV_INFO*>(buffer.data());
                NCRYPT_PROV_HANDLE provider = 0;
                NCRYPT_KEY_HANDLE key = 0;
                if (NCryptOpenStorageProvider(&provider, info->pwszProvName, 0) == ERROR_SUCCESS) {
                    if (NCryptOpenKey(provider, &key, info->pwszContainerName, 0, 0) ==
                        ERROR_SUCCESS) {
                        NCryptDeleteKey(key, 0); // frees the handle too
                    }
                    NCryptFreeObject(provider);
                }
            }
            CertFreeCertificateContext(cert);
        }
    } key_file{locked.get()};

    const std::string what = export_error(locked.get(), lab.thumbprint);
    CHECK_THAT(what, ContainsSubstring("certificate " + lab.thumbprint +
                                       " in the test store: its private key isn't exportable "
                                       "(error 0x"));
}

// --- Happy paths ------------------------------------------------------------

TEST_CASE("the export is a PFX of that certificate and key under a fresh password",
          "[cert_export]")
{
    // Veeam reports the thumbprint in upper case; any case finds it.
    const bool lower_case = GENERATE(false, true);
    Lab lab;
    const auto now = std::chrono::system_clock::now();
    const std::string thumbprint = lower_case ? lower(lab.thumbprint) : lab.thumbprint;

    const rp::ExportedPfx pfx =
        rp::cert_export_detail::export_from_store(lab.store.get(), thumbprint, now, "the test store");

    // 32 random bytes in Base64, and a different password every time.
    CHECK(pfx.password.size() == 44);
    CHECK(pfx.password.back() == '=');
    const rp::ExportedPfx again =
        rp::cert_export_detail::export_from_store(lab.store.get(), thumbprint, now, "the test store");
    CHECK(again.password != pfx.password);

    // The Graph loader (OpenSSL) opens it: the same certificate, with its key.
    const rp::graph::ClientCertificate loaded =
        rp::graph::load_client_certificate(pfx.pfx_base64, pfx.password, now);
    CHECK(loaded.sha1_thumbprint() == lab.thumbprint);
    // And the password matters.
    CHECK_THROWS(rp::graph::load_client_certificate(pfx.pfx_base64, again.password, now));
}

TEST_CASE("Windows reads the export back with its key, still exportable", "[cert_export]")
{
    Lab lab;
    const auto now = std::chrono::system_clock::now();
    const rp::ExportedPfx pfx =
        rp::cert_export_detail::export_from_store(lab.store.get(), lab.thumbprint, now, "x");
    const auto bytes = rp::base64_decode(pfx.pfx_base64);
    REQUIRE(bytes.has_value());

    const Store store = import_pfx(*bytes, pfx.password.c_str());
    // The re-imported copy exports again: key and certificate made the trip.
    const rp::ExportedPfx second =
        rp::cert_export_detail::export_from_store(store.get(), lab.thumbprint, now, "x");
    CHECK_FALSE(second.pfx_base64.empty());
}

// --- The W4.12 spike's probe (#135) --------------------------------------------
//
// Hidden: it runs only when named, `rptests "[spike_cert_export]"`, from a
// process running as a candidate service account, with RP_SPIKE_THUMBPRINT
// naming a certificate of the real LocalMachine\My. It prints what the
// Worker's own exporter says of that certificate, which is what `rpworker
// doctor` will say later: one line, never a byte of the export or the
// password, only their lengths. Without the variable it does nothing.
TEST_CASE("spike: what the Worker's exporter says of RP_SPIKE_THUMBPRINT in LocalMachine\\My",
          "[.][spike_cert_export]")
{
    wchar_t wide[64]{};
    const DWORD length = GetEnvironmentVariableW(L"RP_SPIKE_THUMBPRINT", wide, 64);
    if (length == 0 || length >= 64) {
        WARN("RP_SPIKE_THUMBPRINT is not set: nothing probed");
        return;
    }
    std::string thumbprint;
    for (DWORD i = 0; i < length; ++i) {
        REQUIRE(wide[i] < 128);
        thumbprint += static_cast<char>(wide[i]);
    }
    const auto exporter = rp::make_local_machine_cert_exporter();
    try {
        const rp::ExportedPfx pfx = exporter->export_pfx(thumbprint);
        std::cout << "spike export " << thumbprint << ": exported in memory: PFX "
                  << pfx.pfx_base64.size() << " Base64 characters, password " << pfx.password.size()
                  << " characters; nothing written\n";
        CHECK(pfx.password.size() == 44);
    } catch (const rp::CertExportError& e) {
        std::cout << "spike export " << thumbprint << ": refused: " << e.what() << "\n";
        SUCCEED();
    }
}

TEST_CASE("to_time_point reads a FILETIME on the system clock", "[cert_export]")
{
    // 1970-01-01T00:00:00Z and 2026-09-30T12:00:00Z.
    FILETIME epoch{};
    const std::uint64_t epoch_ticks = 116444736000000000ULL;
    epoch.dwLowDateTime = static_cast<DWORD>(epoch_ticks & 0xFFFFFFFF);
    epoch.dwHighDateTime = static_cast<DWORD>(epoch_ticks >> 32);
    CHECK(rp::cert_export_detail::to_time_point(epoch).time_since_epoch() == 0s);

    const std::uint64_t later = epoch_ticks + 1790769600ULL * 10'000'000ULL;
    FILETIME time{static_cast<DWORD>(later & 0xFFFFFFFF), static_cast<DWORD>(later >> 32)};
    CHECK(std::chrono::duration_cast<std::chrono::seconds>(
              rp::cert_export_detail::to_time_point(time).time_since_epoch()) ==
          1790769600s);
}

TEST_CASE("secure_wipe empties a string and zeroes the bytes it held", "[cert_export]")
{
    std::string secret(100, 'S');
    secret.resize(10); // 90 bytes of 'S' left in the capacity
    const char* data = secret.data();
    const std::size_t capacity = secret.capacity();

    rp::secure_wipe(secret);

    CHECK(secret.empty());
    CHECK(secret.data() == data); // no reallocation: the same buffer was zeroed
    for (std::size_t i = 0; i < capacity; ++i) {
        CHECK(data[i] == '\0');
    }
}

TEST_CASE("an ExportedPfx wipes itself, and what it was moved from", "[cert_export]")
{
    rp::ExportedPfx a;
    a.pfx_base64 = "MIIK-short"; // short enough to live inside the string
    a.password = "pw";

    rp::ExportedPfx b(std::move(a));
    CHECK(b.pfx_base64 == "MIIK-short");
    CHECK(b.password == "pw");
    CHECK(a.pfx_base64.empty());
    CHECK(a.password.empty());

    rp::ExportedPfx c;
    c.password = "old";
    c = std::move(b);
    CHECK(c.password == "pw");
    CHECK(b.password.empty());
    c = std::move(c); // self-move leaves it whole
    CHECK(c.password == "pw");

    c.wipe();
    CHECK(c.pfx_base64.empty());
    CHECK(c.password.empty());
}

// W7.2 point 7: the words for a private key this account can't open. NTE_BAD_KEYSET is what
// CAPI and CNG answer both for a key file the account may not read and for no key file, so the
// words name both and send the operator to doctor, which tells them apart; never "elevated or
// LocalSystem", which was wrong for the service (W4.12).
TEST_CASE("a private key that can't be opened is worded for the account, not for elevation",
          "[cert_export]")
{
    using rp::cert_export_detail::private_key_refusal;
    CHECK(private_key_refusal("certificate AB in LocalMachine\My", 0x80090016UL) ==
          "certificate AB in LocalMachine\My: its private key can't be opened by this account "
          "(error 0x80090016: no read access to its key file, or no key file); rpworker doctor "
          "names the line that grants it");
    const auto other = GENERATE(0x80090009UL, 0x8009000BUL, 5UL);
    const std::string text = private_key_refusal("c", other);
    CHECK(text.starts_with("c: its private key can't be opened (error 0x"));
    CHECK(text.find("LocalSystem") == std::string::npos);
    CHECK(text.find("elevated") == std::string::npos);
    CHECK(private_key_refusal("c", static_cast<unsigned long>(CRYPT_E_NO_KEY_PROPERTY)) ==
          "c: the certificate has no private key");
}
