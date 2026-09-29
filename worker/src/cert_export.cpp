// The restore credential's export (W2.5, docs/decisions.md 2026-09-30 point
// 1): Veeam's organisation app certificate, from LocalMachine\My by its SHA-1
// thumbprint, into a PFX held in memory under a one-time password. It does in
// CryptoAPI what 10-restore.ps1 did with Export-PfxCertificate, without the
// script's temporary file.

#include <rp/cert_export.hpp>

#include <rp/base64.hpp>

#include "cert_export_detail.hpp"

#include <bcrypt.h>

#include <cstdint>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace rp {

namespace {

constexpr DWORD kEncoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
// 32 random bytes: the password is their Base64 (44 characters), as the
// script made it.
constexpr ULONG kPasswordBytes = 32;

void wipe_bytes(std::vector<BYTE>& bytes) noexcept
{
    try {
        bytes.resize(bytes.capacity()); // within the capacity: no allocation
    } catch (...) {
    }
    if (!bytes.empty()) {
        SecureZeroMemory(bytes.data(), bytes.size());
    }
    bytes.clear();
}

void wipe_wide(std::wstring& text) noexcept
{
    if (!text.empty()) {
        SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t));
    }
    text.clear();
}

struct CertContextDeleter {
    void operator()(const CERT_CONTEXT* cert) const noexcept { CertFreeCertificateContext(cert); }
};
using CertContextPtr = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;

struct StoreDeleter {
    void operator()(HCERTSTORE store) const noexcept { CertCloseStore(store, 0); }
};
using StorePtr = std::unique_ptr<void, StoreDeleter>;

// "0x8009200B": how Windows names its error codes.
std::string error_code(DWORD code)
{
    return std::format("0x{:08X}", static_cast<std::uint32_t>(code));
}

std::string utc_text(std::chrono::system_clock::time_point time)
{
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::floor<std::chrono::seconds>(time));
}

// Whether this process can use the certificate's private key, without any
// UI. With CRYPT_ACQUIRE_CACHE_FLAG the handle is cached on the context and
// goes with it (the caller never frees it); a key held only in memory is
// found only that way.
bool acquire_private_key(const CERT_CONTEXT* cert) noexcept
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD key_spec = 0;
    BOOL caller_frees = FALSE;
    return CryptAcquireCertificatePrivateKey(cert,
                                             CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_CACHE_FLAG |
                                                 CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                                             nullptr, &key, &key_spec, &caller_frees) != FALSE;
}

// Proves the certificate has a private key this process may use.
void check_private_key(const CERT_CONTEXT* cert, const std::string& name)
{
    if (!acquire_private_key(cert)) {
        const DWORD code = GetLastError();
        if (code == static_cast<DWORD>(CRYPT_E_NO_KEY_PROPERTY)) {
            throw CertExportError(name + ": the certificate has no private key");
        }
        throw CertExportError(name + ": its private key can't be opened (error " +
                              error_code(code) +
                              "); run elevated or as LocalSystem, which a machine key needs");
    }
}

// Whether `pfx` opens under `password` with a private key, read in memory and
// never persisted. Windows has exported a PFX without the key, and without an
// error, when the key was out of its reach; Veeam would refuse the restore.
bool holds_private_key(std::vector<BYTE>& pfx, const std::wstring& password)
{
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(pfx.size()), pfx.data()};
    const StorePtr store(
        PFXImportCertStore(&blob, password.c_str(), CRYPT_EXPORTABLE | PKCS12_NO_PERSIST_KEY));
    if (!store) {
        return false;
    }
    for (const CERT_CONTEXT* cert = CertEnumCertificatesInStore(store.get(), nullptr);
         cert != nullptr; cert = CertEnumCertificatesInStore(store.get(), cert)) {
        if (acquire_private_key(cert)) {
            CertFreeCertificateContext(cert);
            return true;
        }
    }
    return false;
}

// 32 random bytes as Base64, the password as text and as UTF-16 (ASCII only).
void make_password(std::string& text, std::wstring& wide)
{
    std::vector<BYTE> random(kPasswordBytes);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, random.data(), kPasswordBytes,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        wipe_bytes(random);
        throw CertExportError("no random bytes for the PFX password");
    }
    text = base64_encode(random);
    wipe_bytes(random);
    wide.assign(text.begin(), text.end());
}

class LocalMachineCertExporter final : public CertificateExporter {
public:
    explicit LocalMachineCertExporter(
        std::function<std::chrono::system_clock::time_point()> wall_now)
        : wall_now_(std::move(wall_now))
    {
    }

    ExportedPfx export_pfx(std::string_view sha1_thumbprint) override
    {
        // A malformed thumbprint is refused before the store is opened.
        cert_export_detail::parse_thumbprint(sha1_thumbprint);
        const StorePtr store(CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, 0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG |
                CERT_STORE_OPEN_EXISTING_FLAG,
            L"MY"));
        if (!store) {
            throw CertExportError("the LocalMachine\\My certificate store can't be opened (error " +
                                  error_code(GetLastError()) + ")");
        }
        return cert_export_detail::export_from_store(store.get(), sha1_thumbprint, wall_now_(),
                                                     "LocalMachine\\My");
    }

private:
    std::function<std::chrono::system_clock::time_point()> wall_now_;
};

} // namespace

void secure_wipe(std::string& s) noexcept
{
    try {
        // Up to the capacity: a string that once held more keeps those bytes.
        // Growing within the capacity doesn't allocate.
        s.resize(s.capacity());
    } catch (...) {
        // Can't happen within the capacity; wipe what is there anyway.
    }
    if (!s.empty()) {
        SecureZeroMemory(s.data(), s.size());
    }
    s.clear();
}

ExportedPfx::ExportedPfx(ExportedPfx&& other) noexcept
    : pfx_base64(std::move(other.pfx_base64)), password(std::move(other.password))
{
    // A short string moves by copy: its bytes stay behind in `other`.
    other.wipe();
}

ExportedPfx& ExportedPfx::operator=(ExportedPfx&& other) noexcept
{
    if (this != &other) {
        wipe();
        pfx_base64 = std::move(other.pfx_base64);
        password = std::move(other.password);
        other.wipe();
    }
    return *this;
}

ExportedPfx::~ExportedPfx()
{
    wipe();
}

void ExportedPfx::wipe() noexcept
{
    secure_wipe(pfx_base64);
    secure_wipe(password);
}

std::shared_ptr<CertificateExporter> make_local_machine_cert_exporter(
    std::function<std::chrono::system_clock::time_point()> wall_now)
{
    if (!wall_now) {
        wall_now = [] { return std::chrono::system_clock::now(); };
    }
    return std::make_shared<LocalMachineCertExporter>(std::move(wall_now));
}

namespace cert_export_detail {

std::array<BYTE, 20> parse_thumbprint(std::string_view thumbprint)
{
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    };
    std::array<BYTE, 20> out{};
    if (thumbprint.size() != out.size() * 2) {
        throw CertExportError("a certificate thumbprint must be 40 hex digits");
    }
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int high = hex(thumbprint[2 * i]);
        const int low = hex(thumbprint[2 * i + 1]);
        if (high < 0 || low < 0) {
            throw CertExportError("a certificate thumbprint must be 40 hex digits");
        }
        out[i] = static_cast<BYTE>(high * 16 + low);
    }
    return out;
}

std::chrono::system_clock::time_point to_time_point(const FILETIME& time) noexcept
{
    // 100 ns ticks from 1601-01-01 to 1970-01-01, the system clock's epoch.
    constexpr std::int64_t kUnixEpochTicks = 116444736000000000;
    const std::int64_t ticks =
        static_cast<std::int64_t>((std::uint64_t{time.dwHighDateTime} << 32) |
                                  time.dwLowDateTime) -
        kUnixEpochTicks;
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::duration<std::int64_t, std::ratio<1, 10'000'000>>{ticks})};
}

ExportedPfx export_from_store(HCERTSTORE store, std::string_view thumbprint,
                              std::chrono::system_clock::time_point wall_now,
                              std::string_view store_name)
{
    std::array<BYTE, 20> hash = parse_thumbprint(thumbprint);
    std::string upper;
    for (const BYTE b : hash) {
        upper += std::format("{:02X}", b);
    }
    const std::string name = "certificate " + upper + " in " + std::string{store_name};

    CRYPT_HASH_BLOB blob{static_cast<DWORD>(hash.size()), hash.data()};
    const CertContextPtr cert(
        CertFindCertificateInStore(store, kEncoding, 0, CERT_FIND_SHA1_HASH, &blob, nullptr));
    if (!cert) {
        throw CertExportError(name + ": not found");
    }
    const auto not_before = to_time_point(cert->pCertInfo->NotBefore);
    const auto not_after = to_time_point(cert->pCertInfo->NotAfter);
    if (wall_now < not_before) {
        throw CertExportError(name + ": not valid before " + utc_text(not_before));
    }
    if (wall_now >= not_after) {
        throw CertExportError(name + ": expired at " + utc_text(not_after));
    }
    check_private_key(cert.get(), name);

    // The one certificate on its own, so the PFX holds nothing else of the
    // store's.
    const StorePtr memory(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr));
    if (!memory) {
        throw CertExportError(name + ": no memory store (error " + error_code(GetLastError()) +
                              ")");
    }
    // A link, not a copy: it carries the original's key, which a copy loses
    // when the key is held in memory only.
    if (!CertAddCertificateLinkToStore(memory.get(), cert.get(), CERT_STORE_ADD_ALWAYS,
                                       nullptr)) {
        throw CertExportError(name + ": can't be copied for the export (error " +
                              error_code(GetLastError()) + ")");
    }

    ExportedPfx out;
    std::wstring wide_password;
    make_password(out.password, wide_password);
    std::vector<BYTE> pfx;
    try {
        constexpr DWORD kFlags =
            EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | REPORT_NO_PRIVATE_KEY;
        CRYPT_DATA_BLOB data{0, nullptr};
        // Twice: the size first, then the bytes.
        for (int pass = 0; pass < 2; ++pass) {
            if (pass == 1) {
                pfx.resize(data.cbData);
                data.pbData = pfx.data();
            }
            if (!PFXExportCertStoreEx(memory.get(), &data, wide_password.c_str(), nullptr,
                                      kFlags)) {
                const DWORD code = GetLastError();
                if (code == static_cast<DWORD>(NTE_BAD_KEY_STATE) ||
                    code == static_cast<DWORD>(NTE_PERM)) {
                    throw CertExportError(name + ": its private key isn't exportable (error " +
                                          error_code(code) + ")");
                }
                throw CertExportError(name + ": the PFX export failed (error " +
                                      error_code(code) + ")");
            }
        }
        pfx.resize(data.cbData);
        if (!holds_private_key(pfx, wide_password)) {
            throw CertExportError(name + ": the exported PFX holds no private key");
        }
        out.pfx_base64 = base64_encode(pfx);
    } catch (...) {
        wipe_bytes(pfx);
        wipe_wide(wide_password);
        throw;
    }
    wipe_bytes(pfx);
    wipe_wide(wide_password);
    return out;
}

} // namespace cert_export_detail

} // namespace rp
