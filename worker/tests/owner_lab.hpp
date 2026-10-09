#pragma once

// A file of another owner, for the tests of the owner rule (the vault's, and
// the files whose word the service acts on: W4.5, W4.8). Changing a file's
// owner needs SeRestorePrivilege, so a test that calls give_to skips itself
// unless elevated() answers true.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <sddl.h>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

namespace rp::test {

inline bool elevated()
{
    HANDLE token = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// Turns a privilege of the process token on or off. With SeRestorePrivilege
// (or SeBackupPrivilege) enabled, Windows reads any file's security for the
// process whatever its DACL says, so a test that enables one puts it back:
// every test case runs in one process under the coverage run.
inline void set_privilege(const wchar_t* name, bool enabled)
{
    HANDLE token = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token));
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    REQUIRE(LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid));
    privileges.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;
    REQUIRE(AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr));
    CloseHandle(token);
}

// Makes `path` owned by `sid` (S-1-5-19, LocalService, is "another account"):
// needs SeRestorePrivilege (elevation), enabled for this call alone.
inline void give_to(const std::filesystem::path& path, const wchar_t* sid_text)
{
    set_privilege(L"SeRestorePrivilege", true);
    PSID sid = nullptr;
    REQUIRE(ConvertStringSidToSidW(sid_text, &sid));
    const DWORD result = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                                               OWNER_SECURITY_INFORMATION, sid, nullptr, nullptr,
                                               nullptr);
    LocalFree(sid);
    set_privilege(L"SeRestorePrivilege", false);
    REQUIRE(result == ERROR_SUCCESS);
}

// Gives `path` the DACL `sddl` (for instance "D:P(D;;0x1;;;WD)(A;;FA;;;WD)":
// nobody may list the folder). The owner can always set it back: owning an
// object grants changing its DACL. Needs no privilege.
inline void set_dacl(const std::filesystem::path& path, const wchar_t* sddl)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
                                                                 &descriptor, nullptr));
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    REQUIRE(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted));
    const DWORD result = SetNamedSecurityInfoW(
        const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl,
        nullptr);
    LocalFree(descriptor);
    REQUIRE(result == ERROR_SUCCESS);
}

} // namespace rp::test
