#include <rp/signer.hpp>

#include <rp/base64.hpp>
#include <rp/canonical_json.hpp>
#include <rp/cert_export.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/result_schema.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <span>
#include <utility>

// Held to 100% line coverage (worker/tools/coverage_gate.py): every line here
// is one a test runs, the rule for a public key file (pem_body) among them.
// The calls into OpenSSL whose failures no test can provoke are in
// ed25519.cpp, behind rp::Ed25519.

namespace rp {

namespace {

using nlohmann::json;

// Ed25519's PKCS#8 header (RFC 8410): version 0, the algorithm 1.3.101.112,
// and an OCTET STRING holding an OCTET STRING of 32 bytes, the seed.
constexpr std::array<unsigned char, 16> kPkcs8Prefix = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30,
                                                        0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                                                        0x04, 0x22, 0x04, 0x20};
constexpr std::size_t kPkcs8Bytes = kPkcs8Prefix.size() + kEd25519SeedBytes;

constexpr std::size_t kSha256HexChars = 64;

// Overwrites the bytes when it goes out of scope, on every path.
class Wipe {
public:
    explicit Wipe(std::vector<unsigned char>& bytes) noexcept : bytes_(bytes) {}
    ~Wipe() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }
    Wipe(const Wipe&) = delete;
    Wipe& operator=(const Wipe&) = delete;

private:
    std::vector<unsigned char>& bytes_;
};

std::string to_hex(std::span<const unsigned char> bytes)
{
    constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (const unsigned char byte : bytes) {
        hex += kHex[byte >> 4];
        hex += kHex[byte & 0x0f];
    }
    return hex;
}

std::string_view as_text(const std::vector<unsigned char>& bytes) noexcept
{
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// Lower case only, signature.v1.json's rule: not rp::is_sha256_hex (rp/cert_pin.hpp),
// which takes either case.
bool is_lower_sha256_hex(std::string_view text) noexcept
{
    return text.size() == kSha256HexChars &&
           std::all_of(text.begin(), text.end(),
                       [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

// The document `bytes` is the canonical-json-v1 form of, or nullopt: nested
// too deep, not JSON (whatever the parser calls it: a syntax error, bytes that
// aren't UTF-8, a number it can't hold), a value the canonical form refuses (a
// float, an integer past 2^53 - 1, a key that isn't ASCII), or a document whose
// canonical form is other bytes (a BOM, another key order, a key twice, white
// space, a trailing newline). One answer for all of it, so that the two
// verifiers' parsers can't differ on the word.
std::optional<json> parse_canonical(std::string_view bytes)
{
    std::optional<json> document;
    if (json_nesting_depth(bytes) > kMaxJsonNesting) {
        return document;
    }
    try {
        document = json::parse(bytes);
        if (canonical_json(*document) != bytes) {
            document.reset();
        }
    } catch (const json::exception&) {
        document.reset();
    } catch (const CanonicalJsonError&) {
        document.reset();
    }
    return document;
}

// The string at `key` of `object`, or empty when there is none.
std::string string_at(const json& object, const char* key)
{
    const auto member = object.find(key);
    if (member == object.end() || !member->is_string()) {
        return {};
    }
    return member->get<std::string>();
}

// What a signature file says, once it is one.
struct SignatureFile {
    std::string bundle_sha256;
    std::string key_id;
    Ed25519Signature signature{};
};

// signature.json's rules, the ones shared/schemas/signature.v1.json states:
// its own canonical form; an object of exactly the five keys; `format` and
// `algorithm` the two fixed words; bundle_sha256 and key_id 64 lower-case hex;
// `signature` strict Base64 (padded, no unused bit set, not URL-safe) of
// exactly 64 bytes.
std::optional<SignatureFile> parse_signature_file(std::string_view bytes)
{
    const std::optional<json> document = parse_canonical(bytes);
    if (!document || !document->is_object() || document->size() != 5) {
        return std::nullopt;
    }
    SignatureFile file;
    file.bundle_sha256 = string_at(*document, "bundle_sha256");
    file.key_id = string_at(*document, "key_id");
    const std::optional<std::vector<unsigned char>> signature =
        base64_decode(string_at(*document, "signature"));
    if (string_at(*document, "format") != kSignatureFormat ||
        string_at(*document, "algorithm") != kSignatureAlgorithm ||
        !is_lower_sha256_hex(file.bundle_sha256) || !is_lower_sha256_hex(file.key_id) ||
        !signature || signature->size() != file.signature.size()) {
        return std::nullopt;
    }
    std::copy(signature->begin(), signature->end(), file.signature.begin());
    return file;
}

// One file the result lists.
struct Listed {
    std::string name;
    std::string sha256;
    std::uintmax_t size_bytes = 0;
};

// The attachments of a document the schema took: none when it lists none.
std::vector<Listed> listed_attachments(const json& document)
{
    std::vector<Listed> listed;
    const json& attachments = document.at("attachments");
    if (attachments.is_array()) {
        for (const json& one : attachments) {
            listed.push_back({one.at("name").get<std::string>(),
                              one.at("sha256").get<std::string>(),
                              one.at("size_bytes").get<std::uintmax_t>()});
        }
    }
    return listed;
}

bool lists(const std::vector<Listed>& listed, std::string_view name)
{
    return std::any_of(listed.begin(), listed.end(),
                       [name](const Listed& one) { return one.name == name; });
}

bool lists_a_name_twice(const std::vector<Listed>& listed)
{
    for (std::size_t i = 0; i < listed.size(); ++i) {
        for (std::size_t j = i + 1; j < listed.size(); ++j) {
            if (listed[i].name == listed[j].name) {
                return true;
            }
        }
    }
    return false;
}

bool says_captured(const json& document)
{
    const json& screenshot = document.at("screenshot");
    return screenshot.is_object() && screenshot.at("state") == "captured";
}

Verification failed(VerifyWord word)
{
    Verification out;
    out.word = word;
    return out;
}

// The checks of a result's bytes and a signature file's bytes (null: not
// read), in their order; `listed` gets the result's attachments once the
// result is known to be one.
Verification check(std::string_view result, const std::string* signature_bytes,
                   const PublicKey& key, std::vector<Listed>& listed)
{
    const std::optional<json> document = parse_canonical(result);
    if (!document) {
        return failed(VerifyWord::result_not_canonical);
    }
    const ResultValidation validation = validate_result(*document);
    // "Not valid" from a validator that couldn't check says nothing of the
    // result: no word for it.
    if (validation.not_checked) {
        throw VerifierFailure();
    }
    if (!validation.valid) {
        return failed(VerifyWord::result_schema);
    }
    listed = listed_attachments(*document);
    if (lists_a_name_twice(listed)) {
        return failed(VerifyWord::attachment_twice);
    }
    if (says_captured(*document) && !lists(listed, kScreenshotName)) {
        return failed(VerifyWord::screenshot_missing);
    }
    const std::optional<SignatureFile> signature =
        signature_bytes != nullptr ? parse_signature_file(*signature_bytes) : std::nullopt;
    if (!signature) {
        return failed(VerifyWord::signature_file);
    }
    const std::array<unsigned char, 32> digest = sha256_bytes(result);
    if (signature->bundle_sha256 != to_hex(digest)) {
        return failed(VerifyWord::hash_mismatch);
    }
    if (signature->key_id != key.key_id()) {
        return failed(VerifyWord::wrong_key);
    }
    if (!key.primitive().verify(key.der(), digest, signature->signature)) {
        return failed(VerifyWord::signature_invalid);
    }
    Verification out;
    out.word = VerifyWord::verified;
    out.bundle_sha256 = signature->bundle_sha256;
    out.key_id = signature->key_id;
    return out;
}

// The word for one listed attachment as `read` finds it; `verified` when it is
// the file the result lists.
VerifyWord check_attachment(const FileReader& read, const Listed& attachment)
{
    // One larger than listed isn't read at all.
    const FileRead file = read(attachment.name, attachment.size_bytes);
    if (file.state == FileState::unreadable) {
        return VerifyWord::attachment_missing;
    }
    if (file.state == FileState::too_large || file.bytes.size() != attachment.size_bytes) {
        return VerifyWord::attachment_size;
    }
    if (sha256_hex(file.bytes) != attachment.sha256) {
        return VerifyWord::attachment_hash;
    }
    return VerifyWord::verified;
}

struct WordText {
    VerifyWord word;
    std::string_view text;
};

// The one table of the words, in the checks' order after `verified`.
constexpr std::array<WordText, 16> kWords = {{
    {VerifyWord::verified, "verified"},
    {VerifyWord::result_unreadable, "result_unreadable"},
    {VerifyWord::result_not_canonical, "result_not_canonical"},
    {VerifyWord::result_schema, "result_schema"},
    {VerifyWord::attachment_twice, "attachment_twice"},
    {VerifyWord::screenshot_missing, "screenshot_missing"},
    {VerifyWord::signature_file, "signature_file"},
    {VerifyWord::hash_mismatch, "hash_mismatch"},
    {VerifyWord::wrong_key, "wrong_key"},
    {VerifyWord::signature_invalid, "signature_invalid"},
    {VerifyWord::attachment_missing, "attachment_missing"},
    {VerifyWord::attachment_size, "attachment_size"},
    {VerifyWord::attachment_hash, "attachment_hash"},
    {VerifyWord::timestamp_file, "timestamp_file"},
    {VerifyWord::timestamp_mismatch, "timestamp_mismatch"},
    {VerifyWord::timestamp_invalid, "timestamp_invalid"},
}};

} // namespace

// --- the signing key ---------------------------------------------------------

struct SigningKey::Impl {
    const Ed25519* primitive = nullptr;
    std::unique_ptr<Ed25519Key> key;
    std::vector<unsigned char> public_der;
    std::string public_pem;
    std::string key_id;
    std::vector<std::string> secret_shapes;

    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    ~Impl()
    {
        for (std::string& shape : secret_shapes) {
            secure_wipe(shape);
        }
    }
};

namespace {

std::optional<SigningKey> parse_signing_key(std::string_view text, const Ed25519& primitive)
{
    std::optional<std::vector<unsigned char>> der = base64_decode(text);
    if (!der) {
        return std::nullopt;
    }
    const Wipe wipe(*der);
    // No ASN.1 reader: the length and the sixteen bytes are the whole rule, so
    // a key with anything after it, or of another algorithm, is refused here.
    if (der->size() != kPkcs8Bytes ||
        !std::equal(kPkcs8Prefix.begin(), kPkcs8Prefix.end(), der->begin())) {
        return std::nullopt;
    }
    const std::span<const unsigned char, kEd25519SeedBytes> seed(
        der->data() + kPkcs8Prefix.size(), kEd25519SeedBytes);
    auto impl = std::make_unique<SigningKey::Impl>();
    impl->primitive = &primitive;
    impl->key = primitive.make_key(seed);
    if (!impl->key) {
        return std::nullopt;
    }
    impl->public_der = impl->key->public_key_der();
    impl->public_pem = primitive.public_key_pem(impl->public_der);
    if (impl->public_der.size() != kEd25519PublicDerBytes || impl->public_pem.empty()) {
        return std::nullopt;
    }
    impl->key_id = sha256_hex(as_text(impl->public_der));
    // Each made at its final size and moved in: no copy is left behind.
    impl->secret_shapes.reserve(2);
    impl->secret_shapes.push_back(base64_encode(seed));
    impl->secret_shapes.push_back(to_hex(seed));
    return SigningKey(std::move(impl));
}

std::optional<SignedResult> sign_canonical(std::string_view canonical, const SigningKey& key)
{
    if (!parse_canonical(canonical)) {
        return std::nullopt;
    }
    const SigningKey::Impl& impl = key.impl();
    const std::array<unsigned char, 32> digest = sha256_bytes(canonical);
    const std::optional<Ed25519Signature> signature = impl.key->sign(digest);
    // The self-check: a signature the key's own public half refuses is never
    // handed out.
    if (!signature || !impl.primitive->verify(impl.public_der, digest, *signature)) {
        return std::nullopt;
    }
    SignedResult out;
    out.bundle_sha256 = to_hex(digest);
    out.key_id = impl.key_id;
    out.signature_file = canonical_json(json{{"algorithm", kSignatureAlgorithm},
                                             {"bundle_sha256", out.bundle_sha256},
                                             {"format", kSignatureFormat},
                                             {"key_id", out.key_id},
                                             {"signature", base64_encode(*signature)}});
    return out;
}

constexpr std::string_view kPemBegin = "-----BEGIN PUBLIC KEY-----";
constexpr std::string_view kPemEnd = "-----END PUBLIC KEY-----";

bool is_space(char c) noexcept
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool is_base64_char(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=';
}

// Takes one line end, LF or CRLF, off the front of `text`; false when it
// doesn't start with one (a CR alone is none).
bool take_line_end(std::string_view& text) noexcept
{
    if (text.starts_with("\r\n")) {
        text.remove_prefix(2);
        return true;
    }
    if (text.starts_with('\n')) {
        text.remove_prefix(1);
        return true;
    }
    return false;
}

// The one rule for a public key file (the W4.3 review; the rows of
// shared/testdata/signing-v1/key-files.json, which verify_bundle.py holds
// too). The body lines of `pem` joined, or nullopt unless `pem` is, in this
// order: optional white space (space, tab, CR, LF); the line
// "-----BEGIN PUBLIC KEY-----"; one or more lines of one or more Base64
// characters each; the line "-----END PUBLIC KEY-----"; optional white space.
// Inside the block a line ends with LF or CRLF and with nothing else, so no
// header line, no blank line, no space and no text beside the armour. Whether
// the body is Base64 of a key is the caller's to say.
std::optional<std::string> pem_body(std::string_view pem)
{
    while (!pem.empty() && is_space(pem.front())) {
        pem.remove_prefix(1);
    }
    while (!pem.empty() && is_space(pem.back())) {
        pem.remove_suffix(1);
    }
    if (!pem.starts_with(kPemBegin)) {
        return std::nullopt;
    }
    pem.remove_prefix(kPemBegin.size());
    std::string body;
    // Each turn takes a line end and then the END line, which must be all
    // that is left, or one body line.
    for (;;) {
        if (!take_line_end(pem)) {
            return std::nullopt;
        }
        if (pem == kPemEnd) {
            break;
        }
        std::size_t length = 0;
        while (length < pem.size() && is_base64_char(pem[length])) {
            ++length;
        }
        if (length == 0) {
            return std::nullopt;
        }
        body.append(pem.substr(0, length));
        pem.remove_prefix(length);
    }
    if (body.empty()) {
        return std::nullopt;
    }
    return body;
}

// The 44 bytes of the key the file `pem` holds, or nullopt. No PEM reader of
// the library: it skips lines before the block, stops after it, takes header
// lines and DER with bytes after the key, and hands back a key it has
// re-encoded. The bytes in the file are the key's own 44 or the file is no
// key; the primitive only says whether those bytes are an Ed25519 key.
std::optional<std::vector<unsigned char>> public_der_of(std::string_view pem,
                                                        const Ed25519& primitive)
{
    const std::optional<std::string> body = pem_body(pem);
    std::optional<std::vector<unsigned char>> der =
        body ? base64_decode(*body) : std::nullopt;
    if (!der || der->size() != kEd25519PublicDerBytes || !primitive.is_public_key(*der)) {
        der.reset();
    }
    return der;
}

} // namespace

std::string signing_key_text(std::span<const unsigned char, kEd25519SeedBytes> seed)
{
    std::array<unsigned char, kPkcs8Bytes> der{};
    std::copy(kPkcs8Prefix.begin(), kPkcs8Prefix.end(), der.begin());
    std::copy(seed.begin(), seed.end(), der.begin() + kPkcs8Prefix.size());
    std::string text = base64_encode(der);
    secure_wipe(der);
    return text;
}

std::optional<SigningKey> SigningKey::from_base64(std::string_view text,
                                                  const Ed25519& primitive) noexcept
{
    // One return after the handler: a function that returns from both the
    // block and its handler has a closing line no run reaches.
    std::optional<SigningKey> key;
    try {
        key = parse_signing_key(text, primitive);
    } catch (...) {
        key.reset();
    }
    return key;
}

SigningKey::SigningKey(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
SigningKey::~SigningKey() = default;
SigningKey::SigningKey(SigningKey&&) noexcept = default;
SigningKey& SigningKey::operator=(SigningKey&&) noexcept = default;

const std::string& SigningKey::public_key_pem() const noexcept
{
    return impl_->public_pem;
}

const std::string& SigningKey::key_id() const noexcept
{
    return impl_->key_id;
}

const std::vector<std::string>& SigningKey::secret_shapes() const noexcept
{
    return impl_->secret_shapes;
}

const SigningKey::Impl& SigningKey::impl() const noexcept
{
    return *impl_;
}

// --- a verifier's key --------------------------------------------------------

PublicKey::PublicKey(std::vector<unsigned char> der, std::string key_id,
                     const Ed25519& primitive) noexcept
    : der_(std::move(der)), key_id_(std::move(key_id)), primitive_(&primitive)
{
}

std::optional<PublicKey> PublicKey::from_pem(std::string_view pem,
                                             const Ed25519& primitive) noexcept
{
    std::optional<PublicKey> key;
    try {
        std::optional<std::vector<unsigned char>> der = public_der_of(pem, primitive);
        if (der) {
            std::string key_id = sha256_hex(as_text(*der));
            key = PublicKey(std::move(*der), std::move(key_id), primitive);
        }
    } catch (...) {
        key.reset();
    }
    return key;
}

const std::string& PublicKey::key_id() const noexcept
{
    return key_id_;
}

const std::vector<unsigned char>& PublicKey::der() const noexcept
{
    return der_;
}

const Ed25519& PublicKey::primitive() const noexcept
{
    return *primitive_;
}

// --- the words ---------------------------------------------------------------

VerifierFailure::VerifierFailure()
    : std::runtime_error("the result couldn't be checked against its schema")
{
}

std::string_view to_string(VerifyWord word) noexcept
{
    for (const WordText& one : kWords) {
        if (one.word == word) {
            return one.text;
        }
    }
    return "unknown";
}

const std::vector<std::string>& verify_words()
{
    static const std::vector<std::string> words = [] {
        std::vector<std::string> out;
        for (const WordText& one : kWords) {
            out.emplace_back(one.text);
        }
        return out;
    }();
    return words;
}

// --- the Signer --------------------------------------------------------------

std::optional<SignedResult> Signer::sign(std::string_view canonical,
                                         const SigningKey& key) noexcept
{
    std::optional<SignedResult> made;
    try {
        made = sign_canonical(canonical, key);
    } catch (...) {
        made.reset();
    }
    return made;
}

Verification Signer::verify(std::string_view result, std::string_view signature,
                            const PublicKey& key)
{
    const std::string signature_bytes(signature);
    std::vector<Listed> listed;
    return check(result, &signature_bytes, key, listed);
}

std::string timestamp_field(const Verification& verdict)
{
    if (verdict.timestamp == TimestampState::checked) {
        return timestamp_time_text(verdict.timestamp_time);
    }
    return verdict.timestamp == TimestampState::unchecked ? "unchecked" : "none";
}

Verification Signer::verify_folder(const FileReader& reader,
                                   const std::vector<std::string>& files, const PublicKey& key,
                                   const TimestampTrust& tsa)
{
    // A file is there under its own name, byte for byte, or it isn't there: a
    // name the folder doesn't list isn't asked for. A file system that ignores
    // case would open ITEMS.CSV for items.csv, and one that doesn't has no
    // such file; this way both give one word.
    const FileReader read = [&reader, &files](std::string_view name,
                                              std::uintmax_t limit) -> FileRead {
        if (std::find(files.begin(), files.end(), name) == files.end()) {
            return {};
        }
        return reader(name, limit);
    };
    const FileRead result = read(kResultFileName, kMaxResultFileBytes);
    if (result.state != FileState::read) {
        return failed(VerifyWord::result_unreadable);
    }
    const FileRead signature = read(kSignatureFileName, kMaxSignatureFileBytes);
    std::vector<Listed> listed;
    Verification verdict =
        check(result.bytes, signature.state == FileState::read ? &signature.bytes : nullptr, key,
              listed);
    if (verdict.word != VerifyWord::verified) {
        return verdict;
    }
    for (const Listed& attachment : listed) {
        const VerifyWord word = check_attachment(read, attachment);
        if (word != VerifyWord::verified) {
            return failed(word);
        }
    }
    // W4.4: the timestamp last, evidence about a result that is known good
    // by now. Its form and its imprint are held whoever asks; whether it
    // verifies needs the caller's CA.
    if (std::find(files.begin(), files.end(), kTimestampFileName) != files.end()) {
        const FileRead token = read(kTimestampFileName, kMaxTimestampFileBytes);
        const std::optional<TimestampTokenInfo> info =
            token.state == FileState::read ? tsa.primitive->parse_token(token.bytes) : std::nullopt;
        if (!info) {
            return failed(VerifyWord::timestamp_file);
        }
        // The bytes the signature signs: the SHA-256 of result.json's bytes.
        if (!info->sha256 || !std::ranges::equal(info->imprint, sha256_bytes(result.bytes))) {
            return failed(VerifyWord::timestamp_mismatch);
        }
        if (tsa.ca_pem && !tsa.primitive->verify_token(token.bytes, *tsa.ca_pem)) {
            return failed(VerifyWord::timestamp_invalid);
        }
        verdict.timestamp = tsa.ca_pem ? TimestampState::checked : TimestampState::unchecked;
        verdict.timestamp_time = info->gen_time;
    }
    for (const std::string& name : files) {
        if (name != kResultFileName && name != kSignatureFileName && name != kTimestampFileName &&
            !lists(listed, name)) {
            verdict.notes.push_back(name);
        }
    }
    return verdict;
}

} // namespace rp
