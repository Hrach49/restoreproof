// The real machine reads under rpworker doctor (W7.2, docs/decisions.md
// 2026-10-18 point 1), each on a file, a folder or a certificate of the test's
// own: never %ProgramData%, the SCM or LocalMachine\My. The access check is
// held against Windows' own evaluation of a DACL the test sets, for a
// made-up service's SID that no machine has, so the model doctor uses for the
// service account is shown without a service.

#include "test_certs.hpp"
#include "test_support.hpp"

#include "../src/machine_reads.hpp"

#include <rp/doctor.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <ncrypt.h>
#include <sddl.h>
#include <wincrypt.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <regex>
#include <string>
#include <vector>

using rp::doctor::Ace;
using rp::doctor::kRightsFull;
using rp::doctor::kRightsRead;

namespace {

// A made-up service's SID: S-1-5-80 of a name no machine runs.
const std::string& made_up_service()
{
    static const std::string sid = *rp::doctor::service_sid("rp-test-w72-no-such-service");
    return sid;
}

// Sets `path`'s owner to the calling account and its DACL to `sddl` (a "D:..." string).
void set_dacl(const std::filesystem::path& path, const std::string& sddl)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(rp::test::widen(sddl).c_str(),
                                                                SDDL_REVISION_1, &descriptor, nullptr));
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    REQUIRE(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted));
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    REQUIRE(GetSecurityDescriptorControl(descriptor, &control, &revision));
    const SECURITY_INFORMATION what =
        DACL_SECURITY_INFORMATION | ((control & SE_DACL_PROTECTED) != 0
                                         ? PROTECTED_DACL_SECURITY_INFORMATION
                                         : UNPROTECTED_DACL_SECURITY_INFORMATION);
    const DWORD set = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, what,
                                            nullptr, nullptr, dacl, nullptr);
    LocalFree(descriptor);
    REQUIRE(set == ERROR_SUCCESS);
}

// The calling account's SID, so the test keeps the right to clean its file up.
std::string own_sid()
{
    HANDLE token = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    std::vector<BYTE> buffer(256);
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenUser, buffer.data(),
                                        static_cast<DWORD>(buffer.size()), &size);
    CloseHandle(token);
    REQUIRE(ok);
    LPWSTR text = nullptr;
    REQUIRE(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text));
    const std::string sid = rp::test::narrow(text);
    LocalFree(text);
    return sid;
}

} // namespace

TEST_CASE("machine reads: a file's owner and DACL as Windows holds them", "[machine_reads]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path file = dir.write("vault.bin", "x");
    set_dacl(file, "D:P(A;;FA;;;" + own_sid() + ")(A;;FR;;;" + made_up_service() +
                       ")(D;;FA;;;S-1-5-32-545)(A;OICI;FA;;;BA)");
    const rp::doctor::Security security = rp::machine::read_security(file);
    CHECK(security.present);
    CHECK(security.readable);
    CHECK(security.is_protected);
    CHECK(security.owner_sid.starts_with("S-1-5-"));
    REQUIRE(security.aces.size() == 4);
    const auto has = [&](const Ace& wanted) {
        return std::find(security.aces.begin(), security.aces.end(), wanted) != security.aces.end();
    };
    CHECK(has(Ace{"S-1-5-32-545", false, kRightsFull, false, false, false}));
    CHECK(has(Ace{made_up_service(), true, kRightsRead, false, false, false}));
    CHECK(has(Ace{"S-1-5-32-544", true, kRightsFull, false, false, false}));

    // On a folder, (OI)(CI) is kept, and an inherit-only entry is told apart.
    const std::filesystem::path sub = dir.path() / "logs";
    std::filesystem::create_directory(sub);
    set_dacl(sub, "D:P(A;OICI;FA;;;" + own_sid() + ")(A;OICIIO;FA;;;S-1-3-0)(A;OICI;0x1301bf;;;" +
                      made_up_service() + ")");
    const rp::doctor::Security folder = rp::machine::read_security(sub);
    CHECK(folder.present);
    CHECK(folder.readable);
    CHECK(std::find(folder.aces.begin(), folder.aces.end(),
                    Ace{made_up_service(), true, rp::doctor::kRightsModify, true, false, false}) !=
          folder.aces.end());
    CHECK(std::find(folder.aces.begin(), folder.aces.end(),
                    Ace{"S-1-3-0", true, kRightsFull, true, true, false}) != folder.aces.end());
    const rp::doctor::Security inherited = rp::machine::read_security(dir.write("other", "y"));
    CHECK_FALSE(inherited.is_protected);
    CHECK(std::all_of(inherited.aces.begin(), inherited.aces.end(),
                      [](const Ace& ace) { return ace.inherited; }));
}

TEST_CASE("machine reads: nothing at a path is not there", "[machine_reads]")
{
    const rp::test::TempDir dir;
    CHECK_FALSE(rp::machine::read_security(dir.path() / "absent").present);
    CHECK_FALSE(rp::machine::read_security(dir.path() / "no" / "such" / "file").present);
    CHECK_FALSE(rp::machine::access_for(dir.path() / "absent", made_up_service(), {}).has_value());
}

TEST_CASE("machine reads: the access check is Windows' own, for a SID and its groups",
          "[machine_reads]")
{
    const rp::test::TempDir dir;
    const std::string me = own_sid();
    const std::vector<std::string> groups = rp::doctor::service_token_groups();
    const std::filesystem::path file = dir.write("f", "x");

    SECTION("an entry for the SID")
    {
        set_dacl(file, "D:P(A;;FA;;;" + me + ")(A;;FR;;;" + made_up_service() + ")");
        const auto granted = rp::machine::access_for(file, made_up_service(), groups);
        REQUIRE(granted);
        CHECK((*granted & kRightsRead) == kRightsRead);
        CHECK((*granted & 0x2) == 0); // no write
    }
    SECTION("no entry for it or its groups")
    {
        set_dacl(file, "D:P(A;;FA;;;" + me + ")(A;;FA;;;BA)");
        CHECK(rp::machine::access_for(file, made_up_service(), groups) == 0u);
    }
    SECTION("an entry for NT SERVICE\\ALL SERVICES reaches it only with its groups")
    {
        set_dacl(file, "D:P(A;;FA;;;" + me + ")(A;;FR;;;S-1-5-80-0)");
        CHECK((*rp::machine::access_for(file, made_up_service(), groups) & kRightsRead) == kRightsRead);
        CHECK(rp::machine::access_for(file, made_up_service(), {}) == 0u);
    }
    SECTION("a Deny for a group wins")
    {
        set_dacl(file, "D:P(D;;FR;;;S-1-5-6)(A;;FA;;;" + me + ")(A;;FR;;;" + made_up_service() + ")");
        CHECK((*rp::machine::access_for(file, made_up_service(), groups) & kRightsRead) != kRightsRead);
    }
    SECTION("a SID that isn't one")
    {
        CHECK_FALSE(rp::machine::access_for(file, "not-a-sid", groups).has_value());
        CHECK_FALSE(rp::machine::access_for(file, made_up_service(), {"nope"}).has_value());
    }
}

TEST_CASE("machine reads: a key file's candidates, and a name that is no file name",
          "[machine_reads]")
{
    const auto candidates = rp::machine::key_file_candidates("C:\\PD", "76c3_979c");
    REQUIRE(candidates.size() == 2);
    CHECK(candidates[0] == std::filesystem::path("C:\\PD\\Microsoft\\Crypto\\RSA\\MachineKeys\\76c3_979c"));
    CHECK(candidates[1] == std::filesystem::path("C:\\PD\\Microsoft\\Crypto\\Keys\\76c3_979c"));
    for (const char* bad : {"", ".", "..", "a\\b", "a/b", "c:x"}) {
        CAPTURE(bad);
        CHECK(rp::machine::key_file_candidates("C:\\PD", bad).empty());
    }
}

TEST_CASE("machine reads: the unique name of a CNG key is its file's name", "[machine_reads]")
{
    // The key goes into a CNG key file of the current user, as a machine key lives in one
    // under ProgramData, and is deleted again at the end (cert_export_test's way).
    const rp::test::Cert cert = rp::test::make_client_cert("RestoreProof W7.2 key file test");
    const std::string thumbprint = rp::test::cert_sha1_hex(cert);
    constexpr const char* kPassword = "w72-test-only";
    auto pfx = rp::test::make_pfx(cert, kPassword);
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(pfx.size()), pfx.data()};
    HCERTSTORE store = PFXImportCertStore(&blob, rp::test::widen(kPassword).c_str(), PKCS12_ALWAYS_CNG_KSP);
    REQUIRE(store != nullptr);
    struct Cleanup {
        HCERTSTORE store;
        ~Cleanup()
        {
            const CERT_CONTEXT* c = CertEnumCertificatesInStore(store, nullptr);
            HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
            DWORD spec = 0;
            BOOL frees = FALSE;
            if (c != nullptr && CryptAcquireCertificatePrivateKey(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                                                                  nullptr, &key, &spec, &frees)) {
                NCryptDeleteKey(key, 0);
            }
            CertFreeCertificateContext(c);
            CertCloseStore(store, 0);
        }
    } cleanup{store};

    const std::optional<std::string> name = rp::machine::key_unique_name(store, thumbprint);
    REQUIRE(name);
    const auto appdata = rp::test::get_env("APPDATA");
    REQUIRE(appdata);
    CHECK(std::filesystem::is_regular_file(std::filesystem::path(rp::test::widen(*appdata)) /
                                           "Microsoft" / "Crypto" / "Keys" / rp::test::widen(*name)));
    CHECK_FALSE(rp::machine::key_unique_name(store, std::string(40, '0')).has_value());
    CHECK_FALSE(rp::machine::key_unique_name(store, "not a thumbprint").has_value());
}

TEST_CASE("machine reads: free space, a SID's name, this Windows", "[machine_reads]")
{
    const rp::test::TempDir dir;
    CHECK(rp::machine::free_bytes(dir.path()).value_or(0) > 0);
    CHECK_FALSE(rp::machine::free_bytes(dir.path() / "no" / "such" / "folder").has_value());
    CHECK(rp::machine::account_name("S-1-5-18") == "NT AUTHORITY\\SYSTEM");
    CHECK(rp::machine::account_name(made_up_service()) == made_up_service());
    CHECK(rp::machine::account_name("not-a-sid") == "not-a-sid");
    CHECK(std::regex_match(rp::machine::windows_build(), std::regex(R"(\d+\.\d+\.\d+)")));
    // Whatever the token, the answer is a bool and costs nothing.
    (void)rp::machine::is_elevated();
}

TEST_CASE("machine reads: a thumbprint LocalMachine\\My doesn't hold is not found",
          "[machine_reads]")
{
    // SHA-1 of nothing: no store holds it. A read-only open, nothing touched.
    const rp::machine::MachineCertificate none = rp::machine::machine_certificate(
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", std::filesystem::temp_directory_path());
    CHECK_FALSE(none.found);
    CHECK_FALSE(none.key_file.has_value());
    CHECK_FALSE(rp::machine::machine_certificate("xyz", std::filesystem::temp_directory_path()).found);
}
