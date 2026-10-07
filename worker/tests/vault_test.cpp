// W4.5: the DPAPI vault (rp/vault.hpp). Every test writes and reads vaults
// under a temp folder of its own, through the real DPAPI on this machine;
// none touches %ProgramData%.

#include <rp/canonical_json.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>
#include <rp/vault.hpp>

#include "test_support.hpp"
#include "../src/vault_detail.hpp"

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <dpapi.h>
#include <sddl.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using nlohmann::json;

namespace {

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

rp::Secrets five()
{
    return rp::Secrets{"DESKTOP\\rp-veeam", "Veeam-Password-3f1a", "MIIK-PFX-3f1a", "pfx-pw-3f1a",
                       "MC4CAQAwBQYDK2VwBCIEI-key-3f1a"};
}

// `text` as a DPAPI blob under machine scope, with `description` and
// `entropy`: what a vault file holds, or what one that isn't a vault holds.
std::string protect(std::string_view text, std::wstring_view description,
                    std::string_view entropy)
{
    DATA_BLOB in{static_cast<DWORD>(text.size()),
                 reinterpret_cast<BYTE*>(const_cast<char*>(text.data()))};
    DATA_BLOB salt{static_cast<DWORD>(entropy.size()),
                   reinterpret_cast<BYTE*>(const_cast<char*>(entropy.data()))};
    DATA_BLOB out{};
    const std::wstring descr{description};
    REQUIRE(CryptProtectData(&in, descr.c_str(), &salt, nullptr, nullptr,
                             CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out));
    std::string blob(reinterpret_cast<const char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return blob;
}

// A vault file's plaintext and the description it was written with.
struct Unprotected {
    std::wstring description;
    std::string text;
};

Unprotected unprotect(const std::string& blob)
{
    DATA_BLOB in{static_cast<DWORD>(blob.size()),
                 reinterpret_cast<BYTE*>(const_cast<char*>(blob.data()))};
    DATA_BLOB salt{static_cast<DWORD>(rp::kVaultEntropy.size()),
                   reinterpret_cast<BYTE*>(const_cast<char*>(rp::kVaultEntropy.data()))};
    DATA_BLOB out{};
    LPWSTR description = nullptr;
    REQUIRE(CryptUnprotectData(&in, &description, &salt, nullptr, nullptr,
                               CRYPTPROTECT_UI_FORBIDDEN, &out));
    Unprotected result{description ? description : L"",
                       std::string(reinterpret_cast<const char*>(out.pbData), out.cbData)};
    LocalFree(out.pbData);
    LocalFree(description);
    return result;
}

std::string read_bytes(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);
    return {std::istreambuf_iterator<char>(file), {}};
}

// The file's DACL as SDDL, "D:<flags>(ace)(ace)...".
std::string dacl_of(const std::filesystem::path& path)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    REQUIRE(GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                  nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS);
    LPWSTR text = nullptr;
    REQUIRE(ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text, nullptr));
    const std::string sddl = rp::test::narrow(text);
    LocalFree(text);
    LocalFree(descriptor);
    return sddl;
}

// The DACL's entries, sorted: SetEntriesInAcl puts a new entry first and marks
// the DACL auto-inherited ("AI"), which changes nothing of what it grants; a
// write copies the entries in the order it finds them.
std::vector<std::string> aces_of(const std::filesystem::path& path)
{
    const std::string sddl = dacl_of(path);
    REQUIRE(sddl.starts_with("D:P"));
    std::vector<std::string> aces;
    for (std::size_t open = sddl.find('('); open != std::string::npos; open = sddl.find('(', open + 1)) {
        aces.push_back(sddl.substr(open, sddl.find(')', open) - open + 1));
    }
    std::sort(aces.begin(), aces.end());
    return aces;
}

const std::vector<std::string> kDefaultAces{"(A;;FA;;;BA)", "(A;;FA;;;OW)", "(A;;FA;;;SY)"};

bool elevated()
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
void set_privilege(const wchar_t* name, bool enabled)
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

// Makes `path` owned by `sid`: needs SeRestorePrivilege (elevation), enabled
// for this call alone.
void give_to(const std::filesystem::path& path, const wchar_t* sid_text)
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

struct Lab {
    rp::test::TempDir dir;
    std::filesystem::path file = dir.path() / "vault.bin";
    std::string arg = utf8(file);

    // A file holding `blob` as it is.
    void put(const std::string& blob) const
    {
        std::ofstream out(file, std::ios::binary);
        out.write(blob.data(), static_cast<std::streamsize>(blob.size()));
        REQUIRE(out);
    }

    std::string read_error() const
    {
        try {
            rp::read_vault(file);
        } catch (const rp::VaultError& e) {
            return e.what();
        }
        FAIL("read_vault didn't throw");
        return {};
    }
};

} // namespace

TEST_CASE("the vault's default path is vault.bin in RestoreProof under ProgramData", "[vault]")
{
    const std::filesystem::path path = rp::default_vault_path();
    REQUIRE(path.filename() == "vault.bin");
    REQUIRE(path.parent_path().filename() == "RestoreProof");
    REQUIRE(path.parent_path().parent_path() == rp::program_data_dir());
    REQUIRE(path == rp::default_config_path().parent_path() / "vault.bin");
}

TEST_CASE("VaultError is a ConfigError keyed vault", "[vault]")
{
    const rp::VaultError error("x: vault file not found");
    const rp::ConfigError& as_config = error;
    CHECK(as_config.key() == "vault");
    CHECK(std::string{as_config.what()} == "x: vault file not found");
}

TEST_CASE("secret_field maps each of the five names to its field and nothing else", "[vault]")
{
    rp::Secrets secrets = five();
    CHECK(rp::secret_field(secrets, "veeam_username") == &secrets.veeam_username);
    CHECK(rp::secret_field(secrets, "veeam_password") == &secrets.veeam_password);
    CHECK(rp::secret_field(secrets, "graph_cert_pfx_base64") == &secrets.graph_cert_pfx_base64);
    CHECK(rp::secret_field(secrets, "graph_cert_password") == &secrets.graph_cert_password);
    CHECK(rp::secret_field(secrets, "signing_key_base64") == &secrets.signing_key_base64);
    const std::string_view other =
        GENERATE("", "VEEAM_USERNAME", "RP_VEEAM_PASSWORD", "api_token", "signing_private_key",
                 "veeam_username ");
    CAPTURE(other);
    CHECK(rp::secret_field(secrets, other) == nullptr);
    const rp::Secrets& constant = secrets;
    CHECK(rp::secret_field(constant, "veeam_password") == &constant.veeam_password);
    CHECK(rp::secret_field(constant, other) == nullptr);
}

TEST_CASE("a vault round-trips the five secrets through DPAPI", "[vault]")
{
    const Lab lab;
    rp::write_vault(lab.file, five());

    const rp::Secrets back = rp::read_vault(lab.file);
    CHECK(back.veeam_username == "DESKTOP\\rp-veeam");
    CHECK(back.veeam_password == "Veeam-Password-3f1a");
    CHECK(back.graph_cert_pfx_base64 == "MIIK-PFX-3f1a");
    CHECK(back.graph_cert_password == "pfx-pw-3f1a");
    CHECK(back.signing_key_base64 == "MC4CAQAwBQYDK2VwBCIEI-key-3f1a");
    // Nothing of the values is in the file.
    const std::string bytes = read_bytes(lab.file);
    CHECK_THAT(bytes, !ContainsSubstring("3f1a"));
    CHECK_THAT(bytes, !ContainsSubstring("veeam_username"));
}

TEST_CASE("a name that is empty or unset isn't stored; a vault of nothing reads as nothing",
          "[vault]")
{
    const Lab lab;
    rp::Secrets some;
    some.veeam_password = "pw-9b2c";
    some.graph_cert_password = "";
    rp::write_vault(lab.file, some);

    const rp::Secrets back = rp::read_vault(lab.file);
    CHECK_FALSE(back.veeam_username.has_value());
    CHECK(back.veeam_password == "pw-9b2c");
    CHECK_FALSE(back.graph_cert_pfx_base64.has_value());
    CHECK_FALSE(back.graph_cert_password.has_value());
    CHECK_FALSE(back.signing_key_base64.has_value());
    CHECK(unprotect(read_bytes(lab.file)).text == R"({"veeam_password":"pw-9b2c"})");

    rp::write_vault(lab.file, rp::Secrets{});
    const rp::Secrets none = rp::read_vault(lab.file);
    CHECK_FALSE(none.veeam_password.has_value());
    CHECK(unprotect(read_bytes(lab.file)).text == "{}");
}

TEST_CASE("the file is a machine-scope DPAPI blob with the vault's description, of the canonical "
          "JSON of the names",
          "[vault]")
{
    const Lab lab;
    rp::write_vault(lab.file, five());

    const Unprotected plain = unprotect(read_bytes(lab.file));
    CHECK(plain.description == L"restoreproof.vault.v1");
    const json expected = {{"veeam_username", "DESKTOP\\rp-veeam"},
                           {"veeam_password", "Veeam-Password-3f1a"},
                           {"graph_cert_pfx_base64", "MIIK-PFX-3f1a"},
                           {"graph_cert_password", "pfx-pw-3f1a"},
                           {"signing_key_base64", "MC4CAQAwBQYDK2VwBCIEI-key-3f1a"}};
    CHECK(plain.text == rp::canonical_json(expected));
    CHECK(plain.text.starts_with(R"({"graph_cert_password":)"));
}

TEST_CASE("a value outside the ANSI code page round-trips as UTF-8", "[vault]")
{
    const Lab lab;
    rp::Secrets secrets;
    secrets.veeam_password = "p\xD0\xB6ss\xE2\x82\xAC"; // Cyrillic zhe, the euro sign
    rp::write_vault(lab.file, secrets);
    CHECK(rp::read_vault(lab.file).veeam_password == "p\xD0\xB6ss\xE2\x82\xAC");
}

TEST_CASE("a new vault file gets the protected DACL: SYSTEM, Administrators and its owner",
          "[vault]")
{
    const Lab lab;
    rp::write_vault(lab.file, five());
    CHECK(dacl_of(lab.file) == "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)");
}

// Puts `sddl`'s DACL on the file, protected. The test owns the file, so it
// may change the DACL whatever it says, and the folder's rights delete the
// file afterwards.
void set_dacl(const std::filesystem::path& file, const std::wstring& sddl)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                                 &descriptor, nullptr));
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    REQUIRE(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted));
    REQUIRE(SetNamedSecurityInfoW(const_cast<wchar_t*>(file.c_str()), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                  nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS);
    LocalFree(descriptor);
}

TEST_CASE("a vault whose security this account can't ask for can't be read, written or granted",
          "[vault]")
{
    // Everyone denied READ_CONTROL, and an OWNER RIGHTS entry (FILE_READ_DATA
    // alone) so the owner's implicit READ_CONTROL doesn't stand in: the owner
    // rule can't be checked, so nothing is done. (With a backup or restore
    // privilege enabled the process would read the security all the same.)
    set_privilege(L"SeRestorePrivilege", false);
    set_privilege(L"SeBackupPrivilege", false);
    const Lab lab;
    rp::write_vault(lab.file, five());
    set_dacl(lab.file, L"D:P(D;;RC;;;WD)(A;;0x1;;;OW)(A;;FA;;;SY)");

    CHECK(lab.read_error() == lab.arg + ": the vault file can't be read");
    try {
        rp::write_vault(lab.file, five());
        FAIL("write_vault didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == lab.arg + ": the vault file can't be read");
    }
    try {
        rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
        FAIL("grant_vault_read didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == lab.arg + ": the vault file can't be read");
    }
}

TEST_CASE("a vault whose bytes this account can't read can't be read", "[vault]")
{
    // READ_CONTROL alone for the owner: the owner rule passes, the bytes don't.
    const Lab lab;
    rp::write_vault(lab.file, five());
    set_dacl(lab.file, L"D:P(A;;FA;;;SY)(A;;RC;;;OW)");

    CHECK(lab.read_error() == lab.arg + ": the vault file can't be read");
}

TEST_CASE("a write makes the vault's folder when it isn't there", "[vault]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path file = dir.path() / "RestoreProof" / "vault.bin";
    rp::write_vault(file, five());
    CHECK(rp::read_vault(file).veeam_username == "DESKTOP\\rp-veeam");
}

TEST_CASE("vault grant adds one Read entry for the account and keeps the rest", "[vault]")
{
    const Lab lab;
    rp::write_vault(lab.file, five());

    rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
    const std::vector<std::string> with_ls{"(A;;FA;;;BA)", "(A;;FA;;;OW)", "(A;;FA;;;SY)",
                                           "(A;;FR;;;LS)"};
    CHECK(aces_of(lab.file) == with_ls);

    SECTION("granted twice, the account has one entry")
    {
        rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
        CHECK(aces_of(lab.file) == with_ls);
    }
    SECTION("a second account gets its own entry")
    {
        rp::grant_vault_read(lab.file, "NT AUTHORITY\\NETWORK SERVICE");
        CHECK(aces_of(lab.file) == std::vector<std::string>{"(A;;FA;;;BA)", "(A;;FA;;;OW)",
                                                            "(A;;FA;;;SY)", "(A;;FR;;;LS)",
                                                            "(A;;FR;;;NS)"});
    }
    SECTION("a write keeps the DACL it finds, so a grant survives a rotation")
    {
        rp::Secrets rotated = five();
        rotated.veeam_password = "rotated-3f1a";
        rp::write_vault(lab.file, rotated);
        CHECK(rp::read_vault(lab.file).veeam_password == "rotated-3f1a");
        CHECK(aces_of(lab.file) == with_ls);
        // Still protected, and no entry of the folder's came in.
        CHECK(dacl_of(lab.file) == "D:P(A;;FR;;;LS)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)");
    }
    SECTION("the account can be given as its SID")
    {
        rp::grant_vault_read(lab.file, "S-1-5-20");
        CHECK(aces_of(lab.file) == std::vector<std::string>{"(A;;FA;;;BA)", "(A;;FA;;;OW)",
                                                            "(A;;FA;;;SY)", "(A;;FR;;;LS)",
                                                            "(A;;FR;;;NS)"});
    }
}

TEST_CASE("vault grant refuses an account this machine doesn't know, naming it as a cell",
          "[vault]")
{
    const Lab lab;
    rp::write_vault(lab.file, five());
    const std::string account = GENERATE(std::string{"NT SERVICE\\NoSuchService-7e3d"},
                                         std::string{"no\tsuch\x01user"}, std::string{""},
                                         std::string{"\xFF"});
    CAPTURE(account);

    try {
        rp::grant_vault_read(lab.file, account);
        FAIL("grant_vault_read didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} ==
              lab.arg + ": the account " +
                  (account == "no\tsuch\x01user" ? std::string{"no such user"}
                   : account == "\xFF"           ? std::string{"\xFF"}
                                                 : account) +
                  " isn't known on this machine");
    }
    CHECK(aces_of(lab.file) == kDefaultAces);
}

TEST_CASE("vault grant never reads an account's name as one of SDDL's two-letter SID aliases",
          "[vault]")
{
    // ConvertStringSidToSidW takes "WD" for Everyone, "AU" for Authenticated
    // Users and so on: a local user called ED would be granted as Enterprise
    // Domain Controllers, and `grant WD` would open the vault to everyone.
    // Only "S-1-..." is a SID string; these are names, and no account here
    // has one of them.
    const Lab lab;
    rp::write_vault(lab.file, five());
    const std::string account =
        GENERATE(std::string{"WD"}, std::string{"AU"}, std::string{"BA"}, std::string{"BU"},
                 std::string{"AN"}, std::string{"ED"}, std::string{"SY"}, std::string{"IU"},
                 std::string{"wd"}, std::string{"S-1"}, std::string{"S-1-"});
    CAPTURE(account);

    try {
        rp::grant_vault_read(lab.file, account);
        FAIL("grant_vault_read didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} ==
              lab.arg + ": the account " + account + " isn't known on this machine");
    }
    CHECK(aces_of(lab.file) == kDefaultAces);
}

TEST_CASE("vault grant says when the DACL can't be changed, with Windows' error", "[vault]")
{
    // Read alone for the owner: the owner rule passes, WRITE_DAC is refused
    // (ERROR_ACCESS_DENIED, 5).
    const Lab lab;
    rp::write_vault(lab.file, five());
    set_dacl(lab.file, L"D:P(A;;FA;;;SY)(A;;FR;;;OW)");

    try {
        rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
        FAIL("grant_vault_read didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} ==
              lab.arg + ": read on the vault file couldn't be granted (error 5)");
    }
    CHECK(aces_of(lab.file) == std::vector<std::string>{"(A;;FA;;;SY)", "(A;;FR;;;OW)"});
}

// Calls `swap` once, when a vault file's owner has passed the owner rule:
// where another account would move a file of its own onto the path.
struct SwapAfterOwnerCheck {
    explicit SwapAfterOwnerCheck(std::function<void()> swap)
    {
        rp::detail::set_vault_owner_checked_hook([this, swap = std::move(swap)] {
            if (!std::exchange(done, true)) {
                swap();
            }
        });
    }
    SwapAfterOwnerCheck(const SwapAfterOwnerCheck&) = delete;
    SwapAfterOwnerCheck& operator=(const SwapAfterOwnerCheck&) = delete;
    ~SwapAfterOwnerCheck() { rp::detail::set_vault_owner_checked_hook({}); }
    bool done = false;
};

TEST_CASE("the file that passed the owner rule is the file that is read, whatever is moved onto "
          "its path meanwhile",
          "[vault]")
{
    // The check and the read are one open: a vault planted between them (a
    // valid one, which any account of this machine can make) is never read.
    const Lab lab;
    rp::write_vault(lab.file, five());
    const std::filesystem::path planted = lab.dir.path() / "planted.bin";
    rp::Secrets other = five();
    other.veeam_password = "planted-password-3f1a";
    rp::write_vault(planted, other);
    const std::filesystem::path aside = lab.dir.path() / "aside.bin";

    rp::Secrets read;
    {
        const SwapAfterOwnerCheck swapping{[&] {
            std::filesystem::rename(lab.file, aside);
            std::filesystem::rename(planted, lab.file);
        }};
        read = rp::read_vault(lab.file);
        REQUIRE(swapping.done);
    }
    CHECK(read.veeam_password == "Veeam-Password-3f1a");
    // The swap did happen: the path now holds the planted vault.
    CHECK(rp::read_vault(lab.file).veeam_password == "planted-password-3f1a");
}

TEST_CASE("vault grant changes the DACL of the file that passed the owner rule, never of one "
          "moved onto its path meanwhile",
          "[vault]")
{
    const Lab lab;
    rp::write_vault(lab.file, five());
    const std::filesystem::path planted = lab.dir.path() / "planted.bin";
    rp::write_vault(planted, five());
    const std::filesystem::path aside = lab.dir.path() / "aside.bin";

    {
        const SwapAfterOwnerCheck swapping{[&] {
            std::filesystem::rename(lab.file, aside);
            std::filesystem::rename(planted, lab.file);
        }};
        rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
        REQUIRE(swapping.done);
    }
    CHECK(aces_of(lab.file) == kDefaultAces);
    CHECK(aces_of(aside) == std::vector<std::string>{"(A;;FA;;;BA)", "(A;;FA;;;OW)",
                                                     "(A;;FA;;;SY)", "(A;;FR;;;LS)"});
}

TEST_CASE("a write over a vault swapped after the owner rule keeps the checked file's DACL",
          "[vault]")
{
    // The new file never takes its DACL from what was planted.
    const Lab lab;
    rp::write_vault(lab.file, five());
    rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
    const std::filesystem::path planted = lab.dir.path() / "planted.bin";
    rp::write_vault(planted, five());
    rp::grant_vault_read(planted, "NT AUTHORITY\\NETWORK SERVICE");
    const std::filesystem::path aside = lab.dir.path() / "aside.bin";

    {
        const SwapAfterOwnerCheck swapping{[&] {
            std::filesystem::rename(lab.file, aside);
            std::filesystem::rename(planted, lab.file);
        }};
        rp::write_vault(lab.file, five());
        REQUIRE(swapping.done);
    }
    CHECK(aces_of(lab.file) == std::vector<std::string>{"(A;;FA;;;BA)", "(A;;FA;;;OW)",
                                                        "(A;;FA;;;SY)", "(A;;FR;;;LS)"});
}

TEST_CASE("a device is never a vault", "[vault]")
{
    // NUL opens and has an owner; it is no file on a disk.
    const std::filesystem::path device{"NUL"};
    try {
        rp::read_vault(device);
        FAIL("read_vault didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == "NUL: the vault file can't be read");
    }
}

TEST_CASE("vault grant needs the file to be there", "[vault]")
{
    const Lab lab;
    try {
        rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
        FAIL("grant_vault_read didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == lab.arg + ": vault file not found");
    }
}

TEST_CASE("reading a vault that isn't there, or can't be read, says which", "[vault]")
{
    const Lab lab;
    SECTION("not there")
    {
        CHECK(lab.read_error() == lab.arg + ": vault file not found");
    }
    SECTION("a folder")
    {
        std::filesystem::create_directory(lab.file);
        CHECK(lab.read_error() == lab.arg + ": the vault file can't be read");
    }
    SECTION("larger than the limit")
    {
        lab.put(std::string(static_cast<std::size_t>(rp::kMaxVaultFileBytes) + 1, 'x'));
        CHECK(lab.read_error() == lab.arg + ": the vault file can't be read");
    }
    SECTION("exactly the limit, not a blob: read, then refused by DPAPI")
    {
        // Long enough for DPAPI to read a header out of it: ERROR_INVALID_DATA,
        // not the ERROR_INVALID_PARAMETER of a short one (below).
        lab.put(std::string(static_cast<std::size_t>(rp::kMaxVaultFileBytes), 'x'));
        CHECK(lab.read_error() == lab.arg +
                                      ": the vault can't be decrypted on this machine by this "
                                      "account (error 0x0000000d)");
    }
}

// DPAPI's own codes, as measured: bytes that are no blob at all are
// ERROR_INVALID_PARAMETER (0x57); a blob that doesn't decrypt (another
// entropy, a changed byte) is ERROR_INVALID_DATA (0x0d).
TEST_CASE("DPAPI's refusal is one message with its error code", "[vault]")
{
    const Lab lab;
    SECTION("not a DPAPI blob")
    {
        lab.put("not a blob at all");
        CHECK(lab.read_error() == lab.arg +
                                      ": the vault can't be decrypted on this machine by this "
                                      "account (error 0x00000057)");
    }
    SECTION("empty")
    {
        lab.put("");
        CHECK(lab.read_error() == lab.arg +
                                      ": the vault can't be decrypted on this machine by this "
                                      "account (error 0x00000057)");
    }
    SECTION("a blob under another entropy")
    {
        lab.put(protect(R"({"veeam_password":"pw"})", rp::kVaultDescription, "another-program"));
        CHECK(lab.read_error() == lab.arg +
                                      ": the vault can't be decrypted on this machine by this "
                                      "account (error 0x0000000d)");
    }
    SECTION("a vault with one byte changed")
    {
        rp::write_vault(lab.file, five());
        std::string blob = read_bytes(lab.file);
        blob[blob.size() / 2] ^= 0x01;
        lab.put(blob);
        CHECK(lab.read_error() == lab.arg +
                                      ": the vault can't be decrypted on this machine by this "
                                      "account (error 0x0000000d)");
    }
}

TEST_CASE("a blob that decrypts but isn't a vault is refused without a value", "[vault]")
{
    const Lab lab;
    const auto [name, description, text] = GENERATE(table<std::string, std::wstring, std::string>({
        {"another description", L"another.program.v1", R"({"veeam_password":"pw-SENTINEL"})"},
        {"no description", L"", R"({"veeam_password":"pw-SENTINEL"})"},
        {"not JSON", L"restoreproof.vault.v1", "veeam_password=pw-SENTINEL"},
        {"empty", L"restoreproof.vault.v1", ""},
        {"an array", L"restoreproof.vault.v1", R"(["pw-SENTINEL"])"},
        {"a string", L"restoreproof.vault.v1", R"("pw-SENTINEL")"},
        {"a value that isn't a string", L"restoreproof.vault.v1", R"({"veeam_password":1})"},
        {"a null value", L"restoreproof.vault.v1", R"({"veeam_password":null})"},
        {"an empty value", L"restoreproof.vault.v1", R"({"veeam_password":""})"},
        {"not canonical: a space", L"restoreproof.vault.v1", R"({"veeam_password": "pw-SENTINEL"})"},
        {"not canonical: a trailing newline", L"restoreproof.vault.v1",
         "{\"veeam_password\":\"pw-SENTINEL\"}\n"},
        {"not canonical: keys out of order", L"restoreproof.vault.v1",
         R"({"veeam_username":"u","veeam_password":"pw-SENTINEL"})"},
        {"a duplicate key", L"restoreproof.vault.v1",
         R"({"veeam_password":"pw-SENTINEL","veeam_password":"pw-2"})"},
        {"a BOM", L"restoreproof.vault.v1", "\xEF\xBB\xBF{\"veeam_password\":\"pw-SENTINEL\"}"},
        {"a lone surrogate escape", L"restoreproof.vault.v1", R"({"veeam_password":"\ud800"})"},
        // What the canonical form refuses in a parsed document: a float, a
        // key that isn't ASCII.
        {"a float", L"restoreproof.vault.v1", R"({"veeam_password":1.5})"},
        {"a key that isn't ASCII", L"restoreproof.vault.v1",
         "{\"v\xC3\xAB" "eam\":\"pw-SENTINEL\"}"},
        {"a value that isn't UTF-8", L"restoreproof.vault.v1",
         "{\"veeam_password\":\"pw-\xFF-SENTINEL\"}"},
        {"a value over the limit", L"restoreproof.vault.v1",
         "{\"veeam_password\":\"" + std::string(rp::kMaxVaultValueBytes + 1, 'p') + "\"}"},
    }));
    CAPTURE(name);
    lab.put(protect(text, description, rp::kVaultEntropy));

    const std::string error = lab.read_error();
    CHECK(error == lab.arg + ": not a RestoreProof vault");
    CHECK_THAT(error, !ContainsSubstring("SENTINEL"));
}

TEST_CASE("a value of exactly the limit is read", "[vault]")
{
    const Lab lab;
    const std::string value(rp::kMaxVaultValueBytes, 'p');
    lab.put(protect("{\"veeam_password\":\"" + value + "\"}", rp::kVaultDescription,
                    rp::kVaultEntropy));
    CHECK(rp::read_vault(lab.file).veeam_password == value);
}

TEST_CASE("a vault holding a name that isn't one of the five is refused, the name never echoed",
          "[vault]")
{
    const Lab lab;
    const std::string text = GENERATE(
        std::string{R"({"api_token":"t-SENTINEL","veeam_password":"pw"})"},
        std::string{R"({"RP_VEEAM_PASSWORD":"pw"})"},
        std::string{R"({"signing_private_key":"k"})"}, std::string{R"({"veeam_passw0rd":"pw"})"});
    CAPTURE(text);
    lab.put(protect(text, rp::kVaultDescription, rp::kVaultEntropy));

    const std::string error = lab.read_error();
    CHECK(error == lab.arg + ": the vault holds a name that isn't one of the five secrets");
    CHECK_THAT(error, !ContainsSubstring("SENTINEL"));
    CHECK_THAT(error, !ContainsSubstring("api_token"));
}

TEST_CASE("a write refuses a value over the limit before anything is written", "[vault]")
{
    const Lab lab;
    rp::Secrets secrets;
    secrets.graph_cert_pfx_base64 = std::string(rp::kMaxVaultValueBytes + 1, 'M');
    try {
        rp::write_vault(lab.file, secrets);
        FAIL("write_vault didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == lab.arg + ": a value is longer than 65536 bytes");
    }
    CHECK_FALSE(std::filesystem::exists(lab.file));
}

TEST_CASE("a write says when the folder can't be made or the file can't be written", "[vault]")
{
    const rp::test::TempDir dir;
    SECTION("the folder's place is taken by a file")
    {
        const std::filesystem::path blocker = dir.write("RestoreProof", "a file");
        const std::filesystem::path file = blocker / "vault.bin";
        try {
            rp::write_vault(file, five());
            FAIL("write_vault didn't throw");
        } catch (const rp::VaultError& e) {
            CHECK(std::string{e.what()} == utf8(file) + ": the vault's folder couldn't be made");
        }
    }
    SECTION("the vault's path is a folder")
    {
        const std::filesystem::path file = dir.path() / "vault.bin";
        std::filesystem::create_directory(file);
        try {
            rp::write_vault(file, five());
            FAIL("write_vault didn't throw");
        } catch (const rp::VaultError& e) {
            CHECK(std::string{e.what()} == utf8(file) + ": the vault file couldn't be written");
        }
        // No temp file left beside it.
        std::size_t entries = 0;
        for (const auto& entry : std::filesystem::directory_iterator(dir.path())) {
            (void)entry;
            ++entries;
        }
        CHECK(entries == 1);
    }
    SECTION("a file name that isn't plain")
    {
        const std::filesystem::path file = dir.path() / "vault.bin:stream";
        try {
            rp::write_vault(file, five());
            FAIL("write_vault didn't throw");
        } catch (const rp::VaultError& e) {
            CHECK(std::string{e.what()} == utf8(file) + ": the vault file couldn't be written");
        }
    }
}

TEST_CASE("a vault owned by another account is refused by read, write and grant", "[vault]")
{
    if (!elevated()) {
        SKIP("changing a file's owner needs SeRestorePrivilege: run elevated");
    }
    const Lab lab;
    rp::write_vault(lab.file, five());
    give_to(lab.file, L"S-1-5-19");
    const std::string expected =
        lab.arg + ": the vault file is owned by neither SYSTEM, Administrators nor this account";

    CHECK(lab.read_error() == expected);
    try {
        rp::write_vault(lab.file, five());
        FAIL("write_vault didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == expected);
    }
    try {
        rp::grant_vault_read(lab.file, "NT AUTHORITY\\NETWORK SERVICE");
        FAIL("grant_vault_read didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == expected);
    }
    // Nothing granted. (Windows marks the OWNER RIGHTS entry inherit-only
    // when the owner changes, so the new owner doesn't get it: "(A;IO;FA;;;OW)".)
    CHECK(aces_of(lab.file) == std::vector<std::string>{"(A;;FA;;;BA)", "(A;;FA;;;SY)",
                                                        "(A;IO;FA;;;OW)"});
}

TEST_CASE("a vault owned by SYSTEM or Administrators is read", "[vault]")
{
    if (!elevated()) {
        SKIP("changing a file's owner needs SeRestorePrivilege: run elevated");
    }
    const std::wstring sid = GENERATE(std::wstring{L"S-1-5-18"}, std::wstring{L"S-1-5-32-544"});
    const Lab lab;
    rp::write_vault(lab.file, five());
    give_to(lab.file, sid.c_str());

    CHECK(rp::read_vault(lab.file).veeam_username == "DESKTOP\\rp-veeam");
    rp::write_vault(lab.file, five());
    rp::grant_vault_read(lab.file, "NT AUTHORITY\\LOCAL SERVICE");
}

TEST_CASE("the messages name the path as given, outside the ANSI code page too", "[vault]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path file = dir.path() / std::filesystem::path(u8"тест-vault.bin");
    try {
        rp::read_vault(file);
        FAIL("read_vault didn't throw");
    } catch (const rp::VaultError& e) {
        CHECK(std::string{e.what()} == utf8(file) + ": vault file not found");
    }
    rp::write_vault(file, five());
    CHECK(rp::read_vault(file).veeam_password == "Veeam-Password-3f1a");
}
