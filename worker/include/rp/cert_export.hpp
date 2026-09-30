#pragma once

// The restore credential (W2.5, docs/decisions.md 2026-09-30 point 1): Veeam's
// own organisation app certificate, exported per restore in memory as a
// Base64 PFX under a one-time password, since a restore body must carry it
// (docs/api/veeam-restore-flow.md). Nothing is written to disk and nothing is
// kept: the caller wipes both strings once the body is sent. This header is
// neutral (no Windows type), so the restore logic can be tested with a fake
// exporter; the one the Worker uses reads the LocalMachine\My store.

#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rp {

// Overwrites every byte `s` holds, its spare capacity included, in a way the
// compiler can't drop, then empties it.
void secure_wipe(std::string& s) noexcept;

// A PFX exported in memory with a one-time password. Move-only; both strings
// are wiped (secure_wipe) in the destructor and by wipe(), and a moved-from
// one is wiped too.
struct ExportedPfx {
    std::string pfx_base64; // standard Base64, one line
    std::string password;   // Base64 of 32 random bytes

    ExportedPfx() = default;
    ExportedPfx(ExportedPfx&& other) noexcept;
    ExportedPfx& operator=(ExportedPfx&& other) noexcept;
    ExportedPfx(const ExportedPfx&) = delete;
    ExportedPfx& operator=(const ExportedPfx&) = delete;
    ~ExportedPfx();

    void wipe() noexcept;
};

// An export that failed. what() is safe to print: it names the thumbprint and
// the reason, never key material or the password.
class CertExportError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class CertificateExporter {
public:
    virtual ~CertificateExporter() = default;

    // The certificate whose SHA-1 thumbprint is `sha1_thumbprint` (40 hex
    // digits, either case: Veeam reports upper case), with its private key,
    // as a PFX. Throws CertExportError: a thumbprint that isn't 40 hex
    // digits, no such certificate, one expired or not yet valid, no private
    // key, a key that can't be exported (or can't be read without elevation).
    virtual ExportedPfx export_pfx(std::string_view sha1_thumbprint) = 0;
};

// The exporter for LocalMachine\My, opened read-only on each export. Reading
// a machine key needs an elevated process or LocalSystem, and the key must be
// exportable (W4.12 #135 decides the service account). `wall_now` decides
// whether the certificate is valid; null = system_clock::now.
std::shared_ptr<CertificateExporter> make_local_machine_cert_exporter(
    std::function<std::chrono::system_clock::time_point()> wall_now = {});

} // namespace rp
