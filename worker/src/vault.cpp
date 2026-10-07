#include <rp/vault.hpp>

#include <rp/canonical_json.hpp>
#include <rp/cert_export.hpp>

#include "atomic_file.hpp"
#include "file_read.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"
#include "utf16.hpp"

#include <nlohmann/json.hpp>

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

#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <random>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace rp {

namespace {

using nlohmann::json;

// Frees a LocalAlloc'd pointer when it goes. Move-only: a copy would free it
// twice.
struct Local {
    void* pointer = nullptr;
    Local() = default;
    explicit Local(void* p) noexcept : pointer(p) {}
    Local(Local&& other) noexcept : pointer(std::exchange(other.pointer, nullptr)) {}
    Local& operator=(Local&& other) noexcept
    {
        LocalFree(std::exchange(pointer, std::exchange(other.pointer, nullptr)));
        return *this;
    }
    Local(const Local&) = delete;
    Local& operator=(const Local&) = delete;
    ~Local() { LocalFree(pointer); }
};

// Wipes the string it holds when it goes (secure_wipe).
struct Wiped {
    std::string& text;
    ~Wiped() { secure_wipe(text); }
};

std::string hex_error(DWORD error)
{
    return std::format("0x{:08x}", static_cast<unsigned long>(error));
}

DATA_BLOB blob_of(std::string_view bytes) noexcept
{
    return {static_cast<DWORD>(bytes.size()),
            reinterpret_cast<BYTE*>(const_cast<char*>(bytes.data()))};
}

// The calling process's user SID, or empty when it can't be read.
std::vector<BYTE> process_user_sid()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { return {}; }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    const bool read = size > 0 && GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
    CloseHandle(token);
    if (!read) { return {}; }
    const PSID sid = reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid;
    return {static_cast<BYTE*>(sid), static_cast<BYTE*>(sid) + GetLengthSid(sid)};
}

// The owner rule: SYSTEM, the Administrators group or this process's user.
bool owner_allowed(PSID owner)
{
    const std::vector<BYTE> user = process_user_sid();
    return IsWellKnownSid(owner, WinLocalSystemSid) ||
           IsWellKnownSid(owner, WinBuiltinAdministratorsSid) ||
           (!user.empty() && EqualSid(owner, const_cast<BYTE*>(user.data())));
}

// What the file's security says: its descriptor (owner and DACL, freed when
// this goes) and its DACL.
struct Security {
    Local descriptor;
    PACL dacl = nullptr;
};

// Throws "not found" when `file` isn't there and "can't be read" when it
// can't be asked. `name` is the path for the messages.
void require_present(const std::filesystem::path& file, const std::string& name)
{
    std::error_code ec;
    const std::filesystem::file_status status = std::filesystem::status(file, ec);
    if (status.type() == std::filesystem::file_type::not_found) {
        throw VaultError(name + ": vault file not found");
    }
    // One line: a lookup that fails with anything but "not found" couldn't be
    // provoked (a folder that denies everything doesn't stop a lookup by
    // path: traverse checking is bypassed by default).
    if (ec) { throw VaultError(name + ": the vault file can't be read"); }
}

// The file's owner and DACL, the owner rule applied. The file must be there.
Security inspect(const std::filesystem::path& file, const std::string& name)
{
    Security security;
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD result =
        GetNamedSecurityInfoW(file.c_str(), SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                              nullptr, &security.dacl, nullptr, &descriptor);
    security.descriptor.pointer = descriptor;
    if (result != ERROR_SUCCESS) {
        throw VaultError(name + ": the vault file can't be read");
    }
    if (!owner_allowed(owner)) {
        throw VaultError(name +
                         ": the vault file is owned by neither SYSTEM, Administrators nor this "
                         "account");
    }
    return security;
}

// DPAPI's plaintext for `blob`, or a throw: DPAPI's refusal with its code, or
// a blob that isn't ours (another description).
std::string unprotect(std::string_view blob, const std::string& name)
{
    DATA_BLOB in = blob_of(blob);
    DATA_BLOB entropy = blob_of(kVaultEntropy);
    DATA_BLOB out{};
    LPWSTR description = nullptr;
    if (!CryptUnprotectData(&in, &description, &entropy, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        const DWORD error = GetLastError();
        throw VaultError(name +
                         ": the vault can't be decrypted on this machine by this account (error " +
                         hex_error(error) + ")");
    }
    const Local freed_description{description};
    std::string text(reinterpret_cast<const char*>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    const bool ours = description != nullptr && std::wstring_view{description} == kVaultDescription;
    if (!ours) {
        secure_wipe(text);
        throw VaultError(name + ": not a RestoreProof vault");
    }
    return text;
}

// Whether `text` is the canonical-json-v1 form of `doc`.
bool is_canonical(const json& doc, const std::string& text)
{
    // No return inside the handler (see signer.cpp): its closing brace would
    // be a line no test runs.
    bool same = false;
    try {
        std::string canonical = canonical_json(doc);
        const Wiped wiped{canonical};
        same = canonical == text;
    } catch (const CanonicalJsonError&) {
        same = false;
    }
    return same;
}

Secrets parse_vault(const std::string& text, const std::string& name)
{
    const json doc = json::parse(text, nullptr, false, false);
    if (doc.is_discarded() || !doc.is_object() || !is_canonical(doc, text)) {
        throw VaultError(name + ": not a RestoreProof vault");
    }
    Secrets secrets;
    for (const auto& [key, value] : doc.items()) {
        std::optional<std::string>* field = secret_field(secrets, key);
        if (field == nullptr) {
            throw VaultError(name + ": the vault holds a name that isn't one of the five secrets");
        }
        if (!value.is_string() || value.get_ref<const std::string&>().empty() ||
            value.get_ref<const std::string&>().size() > kMaxVaultValueBytes) {
            throw VaultError(name + ": not a RestoreProof vault");
        }
        *field = value.get_ref<const std::string&>();
    }
    return secrets;
}

// The security a new vault file is made with: the default DACL, or the old
// file's DACL alone (never its owner: a file owned by SYSTEM, as an
// installer's would be, must still be written over by an administrator, and
// only a restore privilege could assign another owner). `absolute` points
// into `buffer`, which outlives it.
struct FileSecurity {
    Local buffer;
    SECURITY_DESCRIPTOR absolute{};
    bool from_old_file = false;

    PSECURITY_DESCRIPTOR descriptor() noexcept
    {
        return from_old_file ? &absolute : buffer.pointer;
    }
};

// The security for `file`'s new contents: the old file's DACL, protected,
// when one is there (and passes the owner rule), else the default.
FileSecurity security_for(const std::filesystem::path& file, const std::string& name)
{
    FileSecurity security;
    std::error_code ec;
    const std::filesystem::file_status status = std::filesystem::status(file, ec);
    if (status.type() == std::filesystem::file_type::not_found) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const std::wstring sddl{kVaultDefaultDacl};
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) { throw VaultError(name + ": the vault file couldn't be written"); }
        security.buffer = Local{descriptor};
        return security;
    }
    if (ec) { throw VaultError(name + ": the vault file can't be read"); } // as require_present's
    Security old = inspect(file, name);
    // Kept protected whatever the old file's flags said, so no entry of the
    // folder's is added to the new file.
    InitializeSecurityDescriptor(&security.absolute, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&security.absolute, TRUE, old.dacl, FALSE);
    SetSecurityDescriptorControl(&security.absolute, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
    security.buffer = std::move(old.descriptor);
    security.from_old_file = true;
    return security;
}

std::string protect(std::string_view text, const std::string& name)
{
    DATA_BLOB in = blob_of(text);
    DATA_BLOB entropy = blob_of(kVaultEntropy);
    DATA_BLOB out{};
    const std::wstring description{kVaultDescription};
    if (!CryptProtectData(&in, description.c_str(), &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out)) { const DWORD error = GetLastError(); throw VaultError(name + ": the vault couldn't be encrypted (error " + hex_error(error) + ")"); }
    std::string blob(reinterpret_cast<const char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return blob;
}

std::wstring random_suffix()
{
    std::random_device random;
    const std::uint64_t value = (static_cast<std::uint64_t>(random()) << 32) | random();
    const std::string text = std::format("{:016x}", value);
    return {text.begin(), text.end()};
}

// `blob` to `file` whole or not at all: a temp file beside it made with
// `descriptor`, flushed, moved onto it (replacing it). Throws "couldn't be
// written".
void write_atomically(const std::filesystem::path& file, std::string_view blob,
                      PSECURITY_DESCRIPTOR descriptor, const std::string& name)
{
    const std::wstring temp = file.native() + L"." + random_suffix() + L".tmp";
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const bool plain = is_plain_file_name(file.filename().native());
    const HANDLE handle = plain ? CreateFileW(temp.c_str(), GENERIC_WRITE, 0, &attributes,
                                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)
                                : INVALID_HANDLE_VALUE;
    if (handle == INVALID_HANDLE_VALUE) {
        throw VaultError(name + ": the vault file couldn't be written");
    }
    DWORD written = 0;
    bool ok = WriteFile(handle, blob.data(), static_cast<DWORD>(blob.size()), &written, nullptr) && written == blob.size() && FlushFileBuffers(handle);
    ok = CloseHandle(handle) && ok;
    ok = ok && MoveFileExW(temp.c_str(), file.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok) {
        DeleteFileW(temp.c_str());
        throw VaultError(name + ": the vault file couldn't be written");
    }
}

// `account`'s SID: a SID string as it is, else the name looked up on this
// machine. Empty when neither.
std::vector<BYTE> sid_of(std::string_view account)
{
    const std::optional<std::wstring> wide = utf8_to_utf16(account);
    // LookupAccountNameW maps "" to the machine itself: never an account.
    if (!wide || wide->empty()) {
        return {};
    }
    PSID parsed = nullptr;
    if (ConvertStringSidToSidW(wide->c_str(), &parsed)) {
        const Local freed{parsed};
        return {static_cast<BYTE*>(parsed), static_cast<BYTE*>(parsed) + GetLengthSid(parsed)};
    }
    DWORD size = 0;
    DWORD domain_size = 0;
    SID_NAME_USE use{};
    LookupAccountNameW(nullptr, wide->c_str(), nullptr, &size, nullptr, &domain_size, &use);
    std::vector<BYTE> sid(size);
    std::wstring domain(domain_size, L'\0');
    if (size == 0 || !LookupAccountNameW(nullptr, wide->c_str(), sid.data(), &size, domain.data(), &domain_size, &use)) { return {}; }
    return sid;
}

} // namespace

VaultError::VaultError(const std::string& message) : ConfigError("vault", message) {}

std::filesystem::path default_vault_path()
{
    return program_data_dir() / "RestoreProof" / kVaultFileName;
}

Secrets read_vault(const std::filesystem::path& file)
{
    const std::string name = path_to_utf8(file);
    require_present(file, name);
    inspect(file, name);
    FileRead read = read_whole_file(file, kMaxVaultFileBytes);
    const Wiped wiped_bytes{read.bytes};
    if (read.state != FileState::read) {
        throw VaultError(name + ": the vault file can't be read");
    }
    std::string text = unprotect(read.bytes, name);
    const Wiped wiped_text{text};
    return parse_vault(text, name);
}

void write_vault(const std::filesystem::path& file, const Secrets& secrets)
{
    const std::string name = path_to_utf8(file);
    json doc = json::object();
    for (const std::string_view key : kSecretNames) {
        const std::optional<std::string>* field = secret_field(secrets, key);
        if (*field && !(*field)->empty()) {
            if ((*field)->size() > kMaxVaultValueBytes) {
                throw VaultError(name + ": a value is longer than " +
                                 std::to_string(kMaxVaultValueBytes) + " bytes");
            }
            doc[std::string{key}] = **field;
        }
    }
    std::string text = canonical_json(doc);
    const Wiped wiped_text{text};
    FileSecurity security = security_for(file, name);
    std::error_code ec;
    if (file.has_parent_path()) {
        std::filesystem::create_directories(file.parent_path(), ec);
    }
    if (ec) {
        throw VaultError(name + ": the vault's folder couldn't be made");
    }
    write_atomically(file, protect(text, name), security.descriptor(), name);
}

void grant_vault_read(const std::filesystem::path& file, std::string_view account)
{
    const std::string name = path_to_utf8(file);
    require_present(file, name);
    const Security security = inspect(file, name);
    std::vector<BYTE> sid = sid_of(account);
    if (sid.empty()) {
        throw VaultError(name + ": the account " + table_cell(account) +
                         " isn't known on this machine");
    }
    EXPLICIT_ACCESS_W entry{};
    entry.grfAccessPermissions = FILE_GENERIC_READ;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid.data());
    PACL merged = nullptr;
    DWORD result = SetEntriesInAclW(1, &entry, security.dacl, &merged);
    const Local freed{merged};
    result = result == ERROR_SUCCESS ? SetNamedSecurityInfoW(const_cast<wchar_t*>(file.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, merged, nullptr) : result;
    if (result != ERROR_SUCCESS) { throw VaultError(name + ": read on the vault file couldn't be granted (error " + std::to_string(result) + ")"); }
}

} // namespace rp
