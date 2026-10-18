#pragma once

// The machine as `rpworker doctor` reads it (W7.2, docs/decisions.md
// 2026-10-18 point 1): one Win32 sequence per function, nothing decided here,
// nothing written. rp/doctor_command.hpp takes each as a seam, so its own
// branches run on fakes; these real ones are held by tests on files and
// certificates of the test's own (tests/machine_reads_test.cpp), never on
// %ProgramData% or the store of the machine. Not strict. No service function
// of Windows is named here: the SCM is read through src/scm.hpp.

#include <rp/doctor.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp::machine {

// Whether this process runs with an elevated token.
bool is_elevated() noexcept;

// "10.0.19045": the major, minor and build of this Windows, from the
// registry; empty when it can't be read.
std::string windows_build();

// The owner and the DACL of `path` (a file or a folder). `present` false when
// nothing is there; `readable` false when it is there and its security can't
// be read. Never throws but for no memory.
doctor::Security read_security(const std::filesystem::path& path);

// What an account with `sid` and `groups` (each "S-1-...") would be granted on
// `path` by Windows' own access check (AuthzAccessCheck, MAXIMUM_ALLOWED,
// over a context made from the SID alone and the groups added to it): the
// granted mask, or nullopt when the check couldn't be made (the path's
// security unreadable, a SID that isn't one).
std::optional<std::uint32_t> access_for(const std::filesystem::path& path, std::string_view sid,
                                        const std::vector<std::string>& groups);

// The SIDs holding "Log on as a service" and "Deny log on as a service" in
// this machine's local policy (which a domain policy writes into). `allowed`
// nullopt when the policy can't be read (not elevated).
doctor::LogonFacts service_logon_rights();

// The bytes free to this account on the volume of `path`; nullopt when
// Windows can't say.
std::optional<std::uint64_t> free_bytes(const std::filesystem::path& path) noexcept;

// "DOMAIN\name" for a SID, "name" when the domain is empty, or the SID itself
// when it has no name on this machine.
std::string account_name(std::string_view sid);

// A certificate of LocalMachine\My by its SHA-1 thumbprint (40 hex digits):
// whether it is there, its end, and its private key's file when its key can
// be opened by this account (doctor runs elevated, so an administrator's
// Read on the file is enough) and the file is found under
// `program_data`\Microsoft\Crypto.
struct MachineCertificate {
    bool found = false;
    std::optional<std::chrono::system_clock::time_point> not_after;
    std::optional<std::filesystem::path> key_file;
};
MachineCertificate machine_certificate(std::string_view thumbprint,
                                       const std::filesystem::path& program_data);

// Where a key container's file of that unique name may be, in the order
// tried: a CAPI machine key's folder, then CNG's.
std::vector<std::filesystem::path> key_file_candidates(const std::filesystem::path& program_data,
                                                       std::string_view unique_name);

// The unique container name of the private key of the certificate with that
// thumbprint in `store` (an HCERTSTORE), as CAPI (PP_UNIQUE_CONTAINER) or
// CNG (NCRYPT_UNIQUE_NAME_PROPERTY) names its file; nullopt when there is no
// such certificate or its key can't be opened. For the tests, which give an
// in-memory store; machine_certificate is it on LocalMachine\My.
std::optional<std::string> key_unique_name(void* store, std::string_view thumbprint);

// %ProgramFiles% (FOLDERID_ProgramFiles). Throws std::runtime_error when
// Windows can't say.
std::filesystem::path program_files_dir();

} // namespace rp::machine
