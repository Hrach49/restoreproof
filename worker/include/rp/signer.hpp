#pragma once

// The result's signature (W4.3, docs/decisions.md 2026-10-05, points 2 to 5):
// an Ed25519 signature over the SHA-256 of result.json's bytes, kept in
// signature.json beside it, never in the result. Here are the key's parsing
// rules, the signature file's text and rules, the checks of a run folder in
// their order and the one word each answers with. `rpworker signer verify` and
// shared/tools/verify_bundle.py give the same word for the same folder;
// shared/testdata/signing-v1/ holds them to it.
//
// No OpenSSL type appears here, and the Signer never calls the library itself:
// it works over rp::Ed25519 (rp/ed25519.hpp) and reads a folder through a
// reader handed in.

#include <rp/ed25519.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

inline constexpr std::string_view kSignatureFileName = "signature.json";
inline constexpr std::string_view kSignatureFormat = "restoreproof.signature.v1";
inline constexpr std::string_view kSignatureAlgorithm = "ed25519";

// A result.json or a signature.json larger than this isn't read. A result of
// 300 items is well under a megabyte; a signature file is 322 bytes.
inline constexpr std::uintmax_t kMaxResultFileBytes = 16u * 1024u * 1024u;
inline constexpr std::uintmax_t kMaxSignatureFileBytes = 4096;

// More arrays and objects than this open at once, and a file isn't parsed at
// all (a result has far fewer). verify_bundle.py has the same limit.
inline constexpr std::size_t kMaxJsonNesting = 32;

// The Worker's private signing key, parsed. Made only by from_base64. Movable,
// not copyable; a moved-from one must not be used.
class SigningKey {
public:
    // Opaque: holds the primitive's key. Defined in rpcore only.
    struct Impl;

    // The key `text` holds: one line of standard Base64 (strict:
    // rp::base64_decode) of an Ed25519 private key's PKCS#8 DER, the body line
    // of the PEM OpenSSL writes. Exactly 48 bytes that start with Ed25519's 16
    // bytes of PKCS#8 header (302e020100300506032b657004220420); the 32 after
    // them are the seed, handed to `primitive` as raw bytes. Anything else is
    // nullopt: other Base64, 47 or 49 bytes, another algorithm's header, an
    // RSA key, a key the primitive can't make or whose public half it can't
    // write. The decoded bytes are wiped before this returns, on every path.
    // `primitive` must outlive the key. Never throws.
    static std::optional<SigningKey>
    from_base64(std::string_view text, const Ed25519& primitive = openssl_ed25519()) noexcept;

    explicit SigningKey(std::unique_ptr<Impl> impl) noexcept;
    ~SigningKey();
    SigningKey(SigningKey&&) noexcept;
    SigningKey& operator=(SigningKey&&) noexcept;
    SigningKey(const SigningKey&) = delete;
    SigningKey& operator=(const SigningKey&) = delete;

    // The public half as SubjectPublicKeyInfo PEM: what is registered with the
    // Cloud and handed to a verifier.
    const std::string& public_key_pem() const noexcept;

    // The SHA-256 of the public key's SubjectPublicKeyInfo DER, 64 lower-case
    // hex: `openssl pkey -pubin -outform DER | sha256sum` of the PEM.
    const std::string& key_id() const noexcept;

    // The other shapes the key could leak in, beside the text it came from:
    // the seed in standard Base64 and in lower-case hex. For the run's list of
    // secret values; wiped when the key goes.
    const std::vector<std::string>& secret_shapes() const noexcept;

    // For rpcore's own use (the Signer).
    const Impl& impl() const noexcept;

private:
    std::unique_ptr<Impl> impl_;
};

// A public key a verifier was given by its caller: the Cloud's registered key,
// an auditor's PEM file. Never taken from the folder that is checked.
class PublicKey {
public:
    // The Ed25519 public key in `pem` (one "PUBLIC KEY" block), or nullopt.
    // `primitive` must outlive the key. Never throws.
    static std::optional<PublicKey>
    from_pem(std::string_view pem, const Ed25519& primitive = openssl_ed25519()) noexcept;

    // As SigningKey::key_id of the same pair.
    const std::string& key_id() const noexcept;
    const std::vector<unsigned char>& der() const noexcept;
    const Ed25519& primitive() const noexcept;

private:
    PublicKey(std::vector<unsigned char> der, std::string key_id,
              const Ed25519& primitive) noexcept;

    std::vector<unsigned char> der_;
    std::string key_id_;
    const Ed25519* primitive_;
};

// What Signer::sign made.
struct SignedResult {
    // signature.json's bytes, its own canonical form:
    // {"algorithm":"ed25519","bundle_sha256":"<64 hex>",
    //  "format":"restoreproof.signature.v1","key_id":"<64 hex>",
    //  "signature":"<88 Base64>"}
    std::string signature_file;
    std::string bundle_sha256; // the SHA-256 of the signed bytes, 64 lower-case hex
    std::string key_id;
};

// A verifier's answer: `verified`, or the first check that failed, in the
// checks' order.
enum class VerifyWord {
    verified,
    result_unreadable,    // result.json isn't there, can't be read, or is too large
    result_not_canonical, // anything else that keeps its bytes from being the
                          // canonical form of a document
    result_schema,        // not a restoreproof.result.v1
    attachment_twice,     // one name listed twice
    screenshot_missing,   // `captured`, and screenshot.png isn't listed
    signature_file,       // signature.json not there, not canonical, or not its
                          // five keys and their shapes
    hash_mismatch,        // its bundle_sha256 isn't the result's SHA-256
    wrong_key,            // its key_id isn't the caller's key's
    signature_invalid,    // 64 well-formed bytes the primitive refuses under that key
    attachment_missing,   // a listed file isn't there or can't be read
    attachment_size,      // not the listed size
    attachment_hash       // not the listed SHA-256
};

// The word as both verifiers print it; "unknown" for a value outside the enum.
std::string_view to_string(VerifyWord word) noexcept;

// Every word, `verified` first and then the failures in the checks' order:
// what a test holds the shared vectors and the Python verifier's set to.
const std::vector<std::string>& verify_words();

struct Verification {
    VerifyWord word = VerifyWord::result_unreadable;
    // Both set with `verified` only.
    std::string bundle_sha256;
    std::string key_id;
    // With `verified` only, from verify_folder: each name of the folder that
    // isn't result.json, signature.json or a listed attachment (W4.6's
    // manifest.json, W4.4's token), in the order given. A note, never a
    // failure.
    std::vector<std::string> notes;
};

// What a reader says of one file.
enum class FileState {
    read,       // `bytes` is the whole file
    unreadable, // not there, or it couldn't be read whole
    too_large   // more than the limit; not read
};

struct FileRead {
    FileState state = FileState::unreadable;
    std::string bytes;
};

// Reads the file `name` of the folder that is checked, at most `limit` bytes of
// it. The real one is rp::folder_reader (src/file_read.hpp); a test hands in
// its own.
using FileReader = std::function<FileRead(std::string_view name, std::uintmax_t limit)>;

class Signer {
public:
    // Signs `canonical`, the bytes result.json is about to be written with:
    // bundle_sha256 is their SHA-256 and the Ed25519 message its 32 raw bytes.
    // nullopt, and nothing signed, unless `canonical` is its own
    // canonical-json-v1 form; nullopt too when the primitive doesn't sign, or
    // when the new signature doesn't verify under the key's own public half
    // (the self-check). Never throws: whatever the primitive throws is nullopt.
    static std::optional<SignedResult> sign(std::string_view canonical,
                                            const SigningKey& key) noexcept;

    // Checks a result's bytes and a signature file's bytes against the
    // caller's key, first failure wins: result_not_canonical, result_schema
    // (rp::validate_result), attachment_twice, screenshot_missing,
    // signature_file, hash_mismatch, wrong_key, signature_invalid; else
    // `verified` with the hash and the key's ID. The attachments aren't read.
    static Verification verify(std::string_view result, std::string_view signature,
                               const PublicKey& key);

    // The same over a run folder, as `rpworker signer verify` runs it:
    // result.json through `read` (result_unreadable unless it is read), the
    // checks above with signature.json (signature_file when it isn't read),
    // then each listed attachment in the result's order: attachment_missing
    // (not read), attachment_size (larger than listed, so not read, or
    // shorter), attachment_hash. `files` are the folder's names, for the
    // notes. What `read` or the primitive throws is let through: a failure of
    // the verifier is never a verdict.
    static Verification verify_folder(const FileReader& read,
                                      const std::vector<std::string>& files,
                                      const PublicKey& key);
};

} // namespace rp
