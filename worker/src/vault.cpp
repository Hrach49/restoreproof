#include <rp/vault.hpp>

#include <rp/canonical_json.hpp>
#include <rp/cert_export.hpp>

#include "atomic_file.hpp"
#include "path_utf8.hpp"
#include "text_table.hpp"
#include "utf16.hpp"
#include "vault_detail.hpp"

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
#include <functional>
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

// Closes the file handle it holds when it goes. Move-only.
struct File {
    HANDLE handle = INVALID_HANDLE_VALUE;
    explicit File(HANDLE h) noexcept : handle(h) {}
    File(File&& other) noexcept : handle(std::exchange(other.handle, INVALID_HANDLE_VALUE)) {}
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    File& operator=(File&&) = delete;
    ~File()
    {
        if (valid()) {
            CloseHandle(handle);
        }
    }
    bool valid() const noexcept { return handle != INVALID_HANDLE_VALUE; }
};

// Nobody is kept out while the vault is open: a rotation moves a new file
// onto the path whoever is reading the old one.
constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

// Wipes the string it holds when it goes (secure_wipe).
struct Wiped {
    std::string& text;
    ~Wiped() { secure_wipe(text); }
};

// Wipes the document's string values when it goes: a vault's plaintext as
// parsed holds every secret, each in a buffer of its own. (The parser's own
// working buffer is nlohmann's and out of reach.)
struct WipedValues {
    json& doc;
    ~WipedValues()
    {
        for (json& value : doc) {
            if (value.is_string()) {
                secure_wipe(value.get_ref<std::string&>());
            }
        }
    }
};

std::function<void()>& owner_checked_hook()
{
    static std::function<void()> hook;
    return hook;
}

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

// One open of `file` with `access` (`flags` is CreateFileW's): the handle,
// valid or not, and whether it isn't because nothing is at the path.
File open_once(const std::filesystem::path& file, DWORD access, DWORD flags, bool& absent)
{
    File opened{CreateFileW(file.c_str(), access, kShareAll, nullptr, OPEN_EXISTING, flags, nullptr)};
    const DWORD error = GetLastError();
    absent = !opened.valid() &&
             (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
              error == ERROR_INVALID_NAME || error == ERROR_BAD_NETPATH ||
              error == ERROR_BAD_NET_NAME);
    return opened;
}

// The owner rule on what open_once answered: `security` is the open file's
// owner and DACL. Something that is no file on a disk (a device, a pipe) is
// unreadable.
OwnerTrust owner_trust(const File& opened, bool absent, Security& security)
{
    if (!opened.valid()) {
        return absent ? OwnerTrust::absent : OwnerTrust::unreadable;
    }
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD result =
        GetSecurityInfo(opened.handle, SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
                        &security.dacl, nullptr, &descriptor);
    security.descriptor.pointer = descriptor;
    const bool disk_file = result == ERROR_SUCCESS && GetFileType(opened.handle) == FILE_TYPE_DISK;
    return !disk_file ? OwnerTrust::unreadable
                      : owner_allowed(owner) ? OwnerTrust::trusted : OwnerTrust::not_trusted;
}

// Reads the open file from its start into `bytes`, as much as `bytes` holds:
// how many bytes that was, or nullopt when a read failed.
std::optional<std::size_t> read_into(HANDLE file, std::string& bytes)
{
    std::size_t total = 0;
    bool ok = true;
    bool ended = false;
    while (ok && !ended && total < bytes.size()) {
        DWORD got = 0;
        ok = ReadFile(file, bytes.data() + total, static_cast<DWORD>(bytes.size() - total), &got,
                      nullptr) != FALSE;
        total += got;
        ended = got == 0;
    }
    return ok ? std::optional<std::size_t>{total} : std::nullopt;
}

// Opens `file` once, with the `access` its caller needs for everything it
// will do: the owner rule, the read and a grant all work on this one handle,
// so the file that passed the rule is the file that is read or changed,
// whatever is moved onto the path meanwhile. nullopt when it isn't there;
// throws "can't be read" when it can't be opened. `flags` is CreateFileW's: a
// folder opens only with FILE_FLAG_BACKUP_SEMANTICS.
std::optional<File> open_present(const std::filesystem::path& file, const std::string& name,
                                 DWORD access, DWORD flags)
{
    bool absent = false;
    File opened = open_once(file, access, flags, absent);
    // No throw as the last statement: the brace after it would be a line no
    // test runs.
    if (!opened.valid() && !absent) {
        throw VaultError(name + ": the vault file can't be read");
    }
    return opened.valid() ? std::optional<File>{std::move(opened)} : std::nullopt;
}

// open_present for a file that must be there: throws "not found".
File open_vault(const std::filesystem::path& file, const std::string& name, DWORD access)
{
    std::optional<File> opened = open_present(file, name, access, 0);
    if (!opened) {
        throw VaultError(name + ": vault file not found");
    }
    return std::move(*opened);
}

// The open file's owner and DACL, the owner rule applied. Something that is
// no file on a disk (a device, a pipe) is never a vault.
Security inspect(const File& file, const std::string& name)
{
    Security security;
    const OwnerTrust owner = owner_trust(file, false, security);
    if (owner == OwnerTrust::unreadable) {
        throw VaultError(name + ": the vault file can't be read");
    }
    if (owner == OwnerTrust::not_trusted) {
        throw VaultError(name +
                         ": the vault file is owned by neither SYSTEM, Administrators nor this "
                         "account");
    }
    if (owner_checked_hook()) {
        owner_checked_hook()();
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
    json doc = json::parse(text, nullptr, false, false);
    const WipedValues wiped_doc{doc};
    if (doc.is_discarded() || !doc.is_object() || !is_canonical(doc, text)) {
        throw VaultError(name + ": not a RestoreProof vault");
    }
    // Checked whole before a value is copied, so no refusal leaves a copy
    // behind.
    Secrets secrets;
    for (const auto& [key, value] : doc.items()) {
        if (secret_field(secrets, key) == nullptr) {
            throw VaultError(name + ": the vault holds a name that isn't one of the five secrets");
        }
        if (!value.is_string() || value.get_ref<const std::string&>().empty() ||
            value.get_ref<const std::string&>().size() > kMaxVaultValueBytes) {
            throw VaultError(name + ": not a RestoreProof vault");
        }
    }
    for (const auto& [key, value] : doc.items()) {
        *secret_field(secrets, key) = value.get_ref<const std::string&>();
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
    // A folder in the vault's place opens too, and is what the write then
    // fails on ("couldn't be written").
    const std::optional<File> opened = open_present(file, name, READ_CONTROL, FILE_FLAG_BACKUP_SEMANTICS);
    if (!opened) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const std::wstring sddl{kVaultDefaultDacl};
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) { throw VaultError(name + ": the vault file couldn't be written"); }
        security.buffer = Local{descriptor};
        return security;
    }
    Security old = inspect(*opened, name);
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

// `account`'s SID: a SID string ("S-1-...") as it is, else the name looked up
// on this machine. Empty when neither. Only "S-1-" is a SID string here:
// ConvertStringSidToSidW also takes SDDL's two-letter aliases ("WD" is
// Everyone, "AU" Authenticated Users), and an account named like one must
// never be granted as the alias.
std::vector<BYTE> sid_of(std::string_view account)
{
    const std::optional<std::wstring> wide = utf8_to_utf16(account);
    // LookupAccountNameW maps "" to the machine itself: never an account.
    if (!wide || wide->empty()) {
        return {};
    }
    const bool sid_string = wide->starts_with(L"S-1-") || wide->starts_with(L"s-1-");
    PSID parsed = nullptr;
    if (sid_string && ConvertStringSidToSidW(wide->c_str(), &parsed)) {
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

void detail::set_vault_owner_checked_hook(std::function<void()> hook)
{
    owner_checked_hook() = std::move(hook);
}

std::filesystem::path default_vault_path()
{
    return program_data_dir() / "RestoreProof" / kVaultFileName;
}

OwnerTrust check_trusted_owner(const std::filesystem::path& file)
{
    bool absent = false;
    // READ_CONTROL alone: the rule needs the owner, never the bytes.
    const File opened = open_once(file, READ_CONTROL, 0, absent);
    Security security;
    return owner_trust(opened, absent, security);
}

TrustedFile read_trusted_file(const std::filesystem::path& file, std::uintmax_t max_bytes)
{
    TrustedFile out;
    bool absent = false;
    const File opened = open_once(file, GENERIC_READ, 0, absent);
    Security security;
    const OwnerTrust owner = owner_trust(opened, absent, security);
    out.state = owner == OwnerTrust::absent
                    ? TrustedRead::absent
                    : owner == OwnerTrust::not_trusted ? TrustedRead::not_trusted
                                                       : TrustedRead::unreadable;
    if (owner != OwnerTrust::trusted) {
        return out;
    }
    if (owner_checked_hook()) {
        owner_checked_hook()();
    }
    // One byte more than the limit, which shows a file that is too large.
    std::string bytes(static_cast<std::size_t>(max_bytes) + 1, '\0');
    const std::optional<std::size_t> total = read_into(opened.handle, bytes);
    out.state = !total ? TrustedRead::unreadable
                       : *total > max_bytes ? TrustedRead::too_large : TrustedRead::read;
    if (out.state == TrustedRead::read) {
        bytes.resize(*total);
        out.bytes = std::move(bytes);
    }
    return out;
}

Secrets read_vault(const std::filesystem::path& file)
{
    const std::string name = path_to_utf8(file);
    const File opened = open_vault(file, name, GENERIC_READ);
    inspect(opened, name);
    // One byte more than the limit, which shows a file that is too large.
    std::string bytes(static_cast<std::size_t>(kMaxVaultFileBytes) + 1, '\0');
    const Wiped wiped_bytes{bytes};
    const std::optional<std::size_t> total = read_into(opened.handle, bytes);
    if (!total || *total > kMaxVaultFileBytes) {
        throw VaultError(name + ": the vault file can't be read");
    }
    std::string text = unprotect(std::string_view{bytes.data(), *total}, name);
    const Wiped wiped_text{text};
    return parse_vault(text, name);
}

void write_vault(const std::filesystem::path& file, const Secrets& secrets)
{
    const std::string name = path_to_utf8(file);
    json doc = json::object();
    const WipedValues wiped_doc{doc};
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
    // With the right to change the DACL when the file gives it. When it
    // doesn't, the file is opened without, so the owner rule still says what
    // it has to before the grant is refused.
    File changeable{CreateFileW(file.c_str(), READ_CONTROL | WRITE_DAC, kShareAll, nullptr,
                                OPEN_EXISTING, 0, nullptr)};
    const DWORD refused = GetLastError();
    const bool may_change = changeable.valid();
    const File opened =
        may_change ? std::move(changeable) : open_vault(file, name, READ_CONTROL);
    const Security security = inspect(opened, name);
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
    // Set through the handle: on the file that passed the owner rule.
    PACL merged = nullptr;
    DWORD result = may_change ? SetEntriesInAclW(1, &entry, security.dacl, &merged) : refused;
    const Local freed{merged};
    if (result == ERROR_SUCCESS) {
        result = SetSecurityInfo(opened.handle, SE_FILE_OBJECT,
                                 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                 nullptr, nullptr, merged, nullptr);
    }
    if (result != ERROR_SUCCESS) {
        throw VaultError(name + ": read on the vault file couldn't be granted (error " +
                         std::to_string(result) + ")");
    }
}

} // namespace rp
