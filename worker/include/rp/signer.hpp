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

#include <rp/canonical_json.hpp> // kMaxJsonNesting, the limit a result is held to
#include <rp/ed25519.hpp>
#include <rp/rfc3161.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
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
    // The Ed25519 public key in the file `pem`, or nullopt unless it is a
    // public key file by the one rule both verifiers hold, row for row
    // (shared/testdata/signing-v1/key-files.json; verify_bundle.py's
    // public_key_from_pem): optional white space (space, tab, CR, LF); the
    // line "-----BEGIN PUBLIC KEY-----"; one or more body lines of standard
    // Base64 characters only; the line "-----END PUBLIC KEY-----"; optional
    // white space. Line ends LF or CRLF (a lone CR is refused); no header
    // line, no blank line, no text on the armour lines, no space in the body.
    // The body lines joined must be strict Base64 (rp::base64_decode: padded,
    // no pad bit set) of exactly the 44 bytes of an Ed25519
    // SubjectPublicKeyInfo (Ed25519::is_public_key). The key's DER is those
    // bytes, never a re-encoding. The rule is the Signer's own, in the strict
    // signer.cpp; the primitive is asked about the 44 bytes only.
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
    attachment_hash,      // not the listed SHA-256
    // W4.4, verify_folder only, after every attachment:
    timestamp_file,     // timestamp.tst is listed and can't be read, is too
                        // large or isn't exactly one TimeStampToken
    timestamp_mismatch, // its imprint isn't SHA-256 or isn't the result's hash
    timestamp_invalid   // it doesn't verify under the caller's CA: the
                        // signature, the signer or its chain at the token's time
};

// The word as both verifiers print it; "unknown" for a value outside the enum.
std::string_view to_string(VerifyWord word) noexcept;

// Every word, `verified` first and then the failures in the checks' order:
// what a test holds the shared vectors and the Python verifier's set to.
const std::vector<std::string>& verify_words();

// What a verified folder's timestamp is (W4.4).
enum class TimestampState {
    none,      // no timestamp.tst in the folder: not timestamped
    unchecked, // one is there, its form and imprint hold, and the caller gave
               // no CA to verify it under
    checked    // it verifies under the caller's CA
};

// What a verifier is given to check a timestamp with: the PEM certificates a
// token must chain to, from the caller (`--tsa-ca`), never from the folder.
struct TimestampTrust {
    std::optional<std::string> ca_pem; // nullopt = none given
    const Rfc3161* primitive = &openssl_rfc3161();
};

struct Verification {
    VerifyWord word = VerifyWord::result_unreadable;
    // Both set with `verified` only.
    std::string bundle_sha256;
    std::string key_id;
    // With `verified` only, from verify_folder: each name of the folder that
    // isn't result.json, signature.json, timestamp.tst or a listed
    // attachment (W4.6's manifest.json), in the order given. A note, never a
    // failure.
    std::vector<std::string> notes;
    // With `verified` only, from verify_folder (W4.4): the folder's timestamp,
    // and with `checked` and `unchecked` the token's own time (genTime,
    // seconds since 1970 UTC; with `unchecked` nobody vouches for it).
    TimestampState timestamp = TimestampState::none;
    std::int64_t timestamp_time = 0;
};

// The third field of a verifier's `verified` line: the token's time as
// YYYY-MM-DDTHH:MM:SSZ when it was checked, else "none" or "unchecked".
std::string timestamp_field(const Verification& verdict);

// Thrown by Signer::verify and verify_folder when a check couldn't be made at
// all: the result's schema couldn't be loaded, or the validator itself failed
// (rp::ResultValidation::not_checked). Never a word: a failure of the verifier
// is never a verdict. `rpworker signer verify` answers it with exit 1.
class VerifierFailure : public std::runtime_error {
public:
    VerifierFailure();
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
    // Throws VerifierFailure when the schema check couldn't be made.
    static Verification verify(std::string_view result, std::string_view signature,
                               const PublicKey& key);

    // The same over a run folder, as `rpworker signer verify` runs it:
    // result.json through `read` (result_unreadable unless it is read), the
    // checks above with signature.json (signature_file when it isn't read),
    // then each listed attachment in the result's order: attachment_missing
    // (not read), attachment_size (larger than listed, so not read, or
    // shorter), attachment_hash. `files` are the folder's names: a file is
    // asked of `read` only when its name is among them byte for byte (so
    // ITEMS.CSV isn't items.csv, whatever the file system would open), and
    // the others are the notes. What `read` or the primitive throws is let
    // through, and a schema check that couldn't be made is a VerifierFailure:
    // a failure of the verifier is never a verdict.
    //
    // Then, W4.4, the timestamp, when `files` has timestamp.tst (byte for
    // byte): timestamp_file unless it is read whole within
    // kMaxTimestampFileBytes and is exactly one TimeStampToken;
    // timestamp_mismatch unless its imprint is SHA-256 and the result's own
    // hash, the bytes the signature signs; then, when `tsa` carries a CA,
    // timestamp_invalid unless the token verifies under it at the token's own
    // time (Rfc3161::verify_token). Without a CA the token is `unchecked`,
    // without a token the folder is `none`: both are `verified`.
    // timestamp.tst is never a note.
    static Verification verify_folder(const FileReader& read,
                                      const std::vector<std::string>& files,
                                      const PublicKey& key, const TimestampTrust& tsa = {});
};

} // namespace rp
