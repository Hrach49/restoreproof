#include "machine_reads.hpp"

#include "cert_export_detail.hpp"
#include "utf16.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <authz.h>
#include <ncrypt.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <wincrypt.h>

#include <array>
#include <format>
#include <memory>

namespace rp::machine {

namespace {

struct LocalFreer {
    void operator()(void* p) const noexcept { LocalFree(p); }
};

std::string sid_text(PSID sid)
{
    LPWSTR text = nullptr;
    if (sid == nullptr || !ConvertSidToStringSidW(sid, &text)) {
        return {};
    }
    const std::unique_ptr<void, LocalFreer> hold(text);
    return utf16_to_utf8(text).value_or(std::string{});
}

std::unique_ptr<void, LocalFreer> sid_of(std::string_view text)
{
    const std::optional<std::wstring> wide = utf8_to_utf16(text);
    PSID sid = nullptr;
    if (!wide || !ConvertStringSidToSidW(wide->c_str(), &sid)) {
        return nullptr;
    }
    return std::unique_ptr<void, LocalFreer>(sid);
}

bool absent_error(DWORD error) noexcept
{
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
           error == ERROR_INVALID_NAME;
}

std::vector<std::string> sids_with_right(LSA_HANDLE policy, const wchar_t* right, bool& ok)
{
    LSA_UNICODE_STRING name{};
    name.Buffer = const_cast<PWSTR>(right);
    name.Length = static_cast<USHORT>(wcslen(right) * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    void* buffer = nullptr;
    ULONG count = 0;
    const NTSTATUS status = LsaEnumerateAccountsWithUserRight(policy, &name, &buffer, &count);
    std::vector<std::string> out;
    // STATUS_NO_MORE_ENTRIES: nobody holds it.
    if (status == static_cast<NTSTATUS>(0x8000001AL)) {
        return out;
    }
    if (status != 0) {
        ok = false;
        return out;
    }
    const auto* info = static_cast<const LSA_ENUMERATION_INFORMATION*>(buffer);
    for (ULONG i = 0; i < count; ++i) {
        out.push_back(sid_text(info[i].Sid));
    }
    LsaFreeMemory(buffer);
    return out;
}

DWORD dword_value(HKEY key, const wchar_t* name)
{
    DWORD value = 0;
    DWORD size = sizeof(value);
    RegGetValueW(key, nullptr, name, RRF_RT_REG_DWORD, nullptr, &value, &size);
    return value;
}

} // namespace

bool is_elevated() noexcept
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok != FALSE && elevation.TokenIsElevated != 0;
}

std::string windows_build()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                      KEY_READ, &key) != ERROR_SUCCESS) {
        return {};
    }
    std::array<wchar_t, 32> build{};
    DWORD size = static_cast<DWORD>(build.size() * sizeof(wchar_t));
    const LSTATUS read = RegGetValueW(key, nullptr, L"CurrentBuild", RRF_RT_REG_SZ, nullptr,
                                      build.data(), &size);
    const DWORD major = dword_value(key, L"CurrentMajorVersionNumber");
    const DWORD minor = dword_value(key, L"CurrentMinorVersionNumber");
    RegCloseKey(key);
    if (read != ERROR_SUCCESS) {
        return {};
    }
    return std::format("{}.{}.{}", major, minor, utf16_to_utf8(build.data()).value_or(""));
}

doctor::Security read_security(const std::filesystem::path& path)
{
    doctor::Security out;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        out.present = !absent_error(error);
        return out;
    }
    out.present = true;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                              nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS) {
        return out;
    }
    const std::unique_ptr<void, LocalFreer> hold(descriptor);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision)) {
        return out;
    }
    out.readable = true;
    out.owner_sid = sid_text(owner);
    out.is_protected = (control & SE_DACL_PROTECTED) != 0;
    for (DWORD i = 0; dacl != nullptr && i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) {
            continue;
        }
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) {
            continue;
        }
        // Both ACE kinds share this layout: header, mask, the SID's first DWORD.
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        doctor::Ace entry;
        entry.sid = sid_text(const_cast<DWORD*>(&ace->SidStart));
        entry.allow = header->AceType == ACCESS_ALLOWED_ACE_TYPE;
        entry.mask = ace->Mask;
        entry.to_children = (header->AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) ==
                            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        entry.inherit_only = (header->AceFlags & INHERIT_ONLY_ACE) != 0;
        entry.inherited = (header->AceFlags & INHERITED_ACE) != 0;
        out.aces.push_back(std::move(entry));
    }
    return out;
}

std::optional<std::uint32_t> access_for(const std::filesystem::path& path, std::string_view sid,
                                        const std::vector<std::string>& groups)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                  DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, nullptr, nullptr, &descriptor) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    const std::unique_ptr<void, LocalFreer> hold(descriptor);
    const auto user = sid_of(sid);
    if (!user) {
        return std::nullopt;
    }
    std::vector<std::unique_ptr<void, LocalFreer>> group_sids;
    std::vector<SID_AND_ATTRIBUTES> attributes;
    for (const std::string& group : groups) {
        auto g = sid_of(group);
        if (!g) {
            return std::nullopt;
        }
        attributes.push_back({g.get(), SE_GROUP_ENABLED});
        group_sids.push_back(std::move(g));
    }
    AUTHZ_RESOURCE_MANAGER_HANDLE manager = nullptr;
    if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, nullptr, nullptr, nullptr, nullptr,
                                        &manager)) {
        return std::nullopt;
    }
    std::optional<std::uint32_t> granted_mask;
    AUTHZ_CLIENT_CONTEXT_HANDLE context = nullptr;
    AUTHZ_CLIENT_CONTEXT_HANDLE with_groups = nullptr;
    if (AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, user.get(), manager, nullptr, LUID{},
                                      nullptr, &context) &&
        AuthzAddSidsToContext(context, attributes.empty() ? nullptr : attributes.data(),
                              static_cast<DWORD>(attributes.size()), nullptr, 0, &with_groups)) {
        AUTHZ_ACCESS_REQUEST request{};
        request.DesiredAccess = MAXIMUM_ALLOWED;
        ACCESS_MASK granted = 0;
        DWORD error = 0;
        AUTHZ_ACCESS_REPLY reply{};
        reply.ResultListLength = 1;
        reply.GrantedAccessMask = &granted;
        reply.Error = &error;
        if (AuthzAccessCheck(0, with_groups, &request, nullptr, descriptor, nullptr, 0, &reply,
                             nullptr)) {
            granted_mask = error == ERROR_SUCCESS ? granted : 0;
        }
    }
    if (with_groups != nullptr) {
        AuthzFreeContext(with_groups);
    }
    if (context != nullptr) {
        AuthzFreeContext(context);
    }
    AuthzFreeResourceManager(manager);
    return granted_mask;
}

doctor::LogonFacts service_logon_rights()
{
    doctor::LogonFacts out;
    LSA_OBJECT_ATTRIBUTES attributes{};
    LSA_HANDLE policy = nullptr;
    if (LsaOpenPolicy(nullptr, &attributes, POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION,
                      &policy) != 0) {
        return out;
    }
    bool ok = true;
    std::vector<std::string> allowed = sids_with_right(policy, L"SeServiceLogonRight", ok);
    out.denied = sids_with_right(policy, L"SeDenyServiceLogonRight", ok);
    LsaClose(policy);
    if (ok) {
        out.allowed = std::move(allowed);
    }
    return out;
}

std::optional<std::uint64_t> free_bytes(const std::filesystem::path& path) noexcept
{
    ULARGE_INTEGER available{};
    if (!GetDiskFreeSpaceExW(path.c_str(), &available, nullptr, nullptr)) {
        return std::nullopt;
    }
    return available.QuadPart;
}

std::string account_name(std::string_view sid)
{
    const auto value = sid_of(sid);
    if (!value) {
        return std::string(sid);
    }
    std::array<wchar_t, 256> name{};
    std::array<wchar_t, 256> domain{};
    DWORD name_size = static_cast<DWORD>(name.size());
    DWORD domain_size = static_cast<DWORD>(domain.size());
    SID_NAME_USE use{};
    if (!LookupAccountSidW(nullptr, value.get(), name.data(), &name_size, domain.data(),
                           &domain_size, &use)) {
        return std::string(sid);
    }
    const std::string n = utf16_to_utf8(name.data()).value_or(std::string(sid));
    const std::string d = utf16_to_utf8(domain.data()).value_or("");
    return d.empty() ? n : d + "\\" + n;
}

std::vector<std::filesystem::path> key_file_candidates(const std::filesystem::path& program_data,
                                                       std::string_view unique_name)
{
    const std::filesystem::path crypto = program_data / "Microsoft" / "Crypto";
    const std::optional<std::wstring> name = utf8_to_utf16(unique_name);
    if (!name || name->empty() || name->find_first_of(L"\\/:") != std::wstring::npos ||
        *name == L"." || *name == L"..") {
        return {};
    }
    return {crypto / "RSA" / "MachineKeys" / *name, crypto / "Keys" / *name};
}

std::optional<std::string> key_unique_name(void* store, std::string_view thumbprint)
{
    std::array<BYTE, 20> hash{};
    try {
        hash = cert_export_detail::parse_thumbprint(thumbprint);
    } catch (const CertExportError&) {
        return std::nullopt;
    }
    CRYPT_HASH_BLOB blob{static_cast<DWORD>(hash.size()), hash.data()};
    const CERT_CONTEXT* cert = CertFindCertificateInStore(
        static_cast<HCERTSTORE>(store), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SHA1_HASH, &blob, nullptr);
    if (cert == nullptr) {
        return std::nullopt;
    }
    std::optional<std::string> out;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL caller_frees = FALSE;
    if (CryptAcquireCertificatePrivateKey(cert,
                                          CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                                          nullptr, &key, &spec, &caller_frees)) {
        if (spec == CERT_NCRYPT_KEY_SPEC) {
            std::array<wchar_t, 512> name{};
            DWORD size = 0;
            if (NCryptGetProperty(key, NCRYPT_UNIQUE_NAME_PROPERTY, reinterpret_cast<PBYTE>(name.data()),
                                  static_cast<DWORD>(name.size() * sizeof(wchar_t) - sizeof(wchar_t)),
                                  &size, 0) == ERROR_SUCCESS) {
                out = utf16_to_utf8(name.data());
            }
            if (caller_frees) {
                NCryptFreeObject(key);
            }
        } else {
            std::array<char, 512> name{};
            DWORD size = static_cast<DWORD>(name.size() - 1);
            if (CryptGetProvParam(key, PP_UNIQUE_CONTAINER, reinterpret_cast<BYTE*>(name.data()), &size,
                                  0)) {
                out = std::string(name.data());
            }
            if (caller_frees) {
                CryptReleaseContext(key, 0);
            }
        }
    }
    CertFreeCertificateContext(cert);
    if (out && out->empty()) {
        out.reset();
    }
    return out;
}

MachineCertificate machine_certificate(std::string_view thumbprint,
                                       const std::filesystem::path& program_data)
{
    MachineCertificate out;
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG |
                                         CERT_STORE_OPEN_EXISTING_FLAG,
                                     L"MY");
    if (store == nullptr) {
        return out;
    }
    std::array<BYTE, 20> hash{};
    try {
        hash = cert_export_detail::parse_thumbprint(thumbprint);
    } catch (const CertExportError&) {
        CertCloseStore(store, 0);
        return out;
    }
    CRYPT_HASH_BLOB blob{static_cast<DWORD>(hash.size()), hash.data()};
    const CERT_CONTEXT* cert = CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr);
    if (cert != nullptr) {
        out.found = true;
        out.not_after = cert_export_detail::to_time_point(cert->pCertInfo->NotAfter);
        CertFreeCertificateContext(cert);
        if (const std::optional<std::string> name = key_unique_name(store, thumbprint)) {
            for (const std::filesystem::path& candidate : key_file_candidates(program_data, *name)) {
                std::error_code ec;
                if (std::filesystem::is_regular_file(candidate, ec)) {
                    out.key_file = candidate;
                    break;
                }
            }
        }
    }
    CertCloseStore(store, 0);
    return out;
}

} // namespace rp::machine
