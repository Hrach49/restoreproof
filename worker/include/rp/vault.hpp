#pragma once

// The DPAPI vault (W4.5, docs/decisions.md 2026-10-07): the one place the
// Worker's secrets live, %ProgramData%\RestoreProof\vault.bin. The file is the
// blob CryptProtectData returned under machine scope
// (CRYPTPROTECT_LOCAL_MACHINE) with a fixed entropy and the description
// kVaultDescription; its plaintext is one canonical-json-v1 object whose keys
// are a subset of rp::kSecretNames, each value a non-empty string. The file's
// ACL is what keeps other accounts out: a new file gets SYSTEM, Administrators
// and its owner (Full), `rpworker vault grant <account>` adds Read for one
// account, and a write keeps the ACL it finds. Reading and writing refuse a
// file owned by neither SYSTEM, Administrators nor the calling account (a file
// another local user planted). Strict (100% line): every message here is what
// a command prints after "vault error: " or "config error: ".

#include <rp/config.hpp>
#include <rp/secrets.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace rp {

inline constexpr std::string_view kVaultFileName = "vault.bin";
// The blob's description (what CryptUnprotectData gives back) and its entropy:
// a label that tells a vault from another program's blob, not a secret.
inline constexpr std::wstring_view kVaultDescription = L"restoreproof.vault.v1";
inline constexpr std::string_view kVaultEntropy = "restoreproof.vault.v1";
// A file larger than this isn't read; a value longer than this isn't stored.
inline constexpr std::uintmax_t kMaxVaultFileBytes = std::uintmax_t{1} << 20;
inline constexpr std::size_t kMaxVaultValueBytes = std::size_t{64} << 10;
// The DACL of a new vault file: protected (no inheritance), SYSTEM, the
// Administrators group and the file's owner (OWNER RIGHTS) with full access.
inline constexpr std::wstring_view kVaultDefaultDacl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";

// A vault that can't be used. A ConfigError (key "vault"), so every command
// reports it as it reports a config that doesn't load. The message starts with
// the file's path as given and never holds a value or a name from the file:
//   <file>: vault file not found
//   <file>: the vault file can't be read
//   <file>: the vault file is owned by neither SYSTEM, Administrators nor this account
//   <file>: the vault can't be decrypted on this machine by this account (error 0x<8 hex>)
//   <file>: not a RestoreProof vault
//   <file>: the vault holds a name that isn't one of the five secrets
//   <file>: a value is longer than <kMaxVaultValueBytes> bytes
//   <file>: the vault's folder couldn't be made
//   <file>: the vault couldn't be encrypted (error 0x<8 hex>)
//   <file>: the vault file couldn't be written
//   <file>: the account <account> isn't known on this machine
//   <file>: read on the vault file couldn't be granted (error <n>)
class VaultError : public ConfigError {
public:
    explicit VaultError(const std::string& message);
};

// program_data_dir() / "RestoreProof" / kVaultFileName. Throws what
// program_data_dir throws.
std::filesystem::path default_vault_path();

// The owner rule by itself (W4.8, docs/decisions.md 2026-10-08 points 3 and
// 6): what read_vault, write_vault and grant_vault_read hold the vault to, for
// the other files whose word the service acts on (its jobs file, its record).
enum class OwnerTrust {
    trusted,     // owned by SYSTEM, Administrators or the calling account
    not_trusted, // owned by anybody else
    unreadable,  // there, but it can't be opened or its owner can't be asked;
                 // a folder and a device too
    absent       // nothing is at the path
};

// Whether `file`'s owner passes the rule. The file is opened once, without
// the right to read its bytes, and never changed. Never throws but for no
// memory.
OwnerTrust check_trusted_owner(const std::filesystem::path& file);

enum class TrustedRead {
    read,        // the owner passed and `bytes` is the file, whole
    absent,      // as OwnerTrust's
    unreadable,  // as OwnerTrust's, or the read failed
    not_trusted, // as OwnerTrust's: nothing was read
    too_large    // the owner passed; the file is over the limit
};

struct TrustedFile {
    TrustedRead state = TrustedRead::unreadable;
    std::string bytes; // empty unless `read`
};

// Reads `file` whole, at most `max_bytes`, only when its owner passes the
// rule: one open, the rule and the read on that handle, as read_vault does,
// so the file that passed is the file that is read, whatever is moved onto
// the path meanwhile. Never throws but for no memory.
TrustedFile read_trusted_file(const std::filesystem::path& file, std::uintmax_t max_bytes);

// Reads and decrypts `file` into Secrets: a name that isn't in the vault
// leaves its field empty. The file is opened once, for reading, and the owner
// rule and the read both work on that handle, so the file that passed the
// rule is the file that is decrypted, whatever is moved onto the path
// meanwhile. In this order: the file is there (else "not found") and opens
// (else "can't be read", a folder and a device too); its owner passes the
// rule above; it is at most kMaxVaultFileBytes and reads whole; DPAPI
// decrypts it; the description is
// kVaultDescription and the plaintext is a canonical-json-v1 object of
// non-empty strings of at most kMaxVaultValueBytes each ("not a RestoreProof
// vault"); every key is one of kSecretNames. The file's bytes and DPAPI's
// plaintext buffer and the parsed values are wiped before they go. Throws
// VaultError.
Secrets read_vault(const std::filesystem::path& file);

// Writes `secrets` as `file`, whole or not at all: a temp file beside it,
// flushed, moved onto it. A field that is empty or holds "" isn't stored. A
// file that is there must pass the owner rule and keeps its DACL (the DACL of
// the file that passed, read through the same handle); a new one gets
// kVaultDefaultDacl, and its folder is made when it isn't there. Throws
// VaultError.
void write_vault(const std::filesystem::path& file, const Secrets& secrets);

// Adds a Read entry (FILE_GENERIC_READ, not inherited) for `account` (UTF-8,
// as LookupAccountNameW takes it: "NT SERVICE\\name", "DOMAIN\\user", or a
// SID string, which is "S-1-..." and nothing else: SDDL's two-letter aliases
// such as "WD" (Everyone) are names here, looked up like any other) to
// `file`'s DACL, merged into an entry it already has, the DACL kept protected.
// The file must be there and pass the owner rule; the DACL is read and set
// through one handle, on the file that passed. Throws VaultError.
void grant_vault_read(const std::filesystem::path& file, std::string_view account);

} // namespace rp
