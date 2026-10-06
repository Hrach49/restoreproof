// The Signer (W4.3, docs/decisions.md 2026-10-05, points 2 to 6): the key's
// parsing rules, the signature file, the checks of a run folder in their order
// and their words, and the shared vectors of shared/testdata/signing-v1/, which
// shared/tools/verify_bundle.py must answer with the same words. Every key
// here is one of RFC 8032's published test keys or made at test time.

#include <rp/signer.hpp>

#include "../src/file_read.hpp"
#include "../src/result_schema_detail.hpp"
#include "result_lab.hpp"
#include "schema_walk.hpp"
#include "signing_lab.hpp"
#include "test_certs.hpp"
#include "test_support.hpp"

#include <rp/base64.hpp>
#include <rp/canonical_json.hpp>
#include <rp/evidence_builder.hpp>
#include <rp/result_schema.hpp>
#include <rp/sha256.hpp>

#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

using nlohmann::json;
using nlohmann::ordered_json;
using rp::Ed25519Signature;
using rp::FileRead;
using rp::FileState;
using rp::PublicKey;
using rp::SignedResult;
using rp::Signer;
using rp::SigningKey;
using rp::Verification;
using rp::VerifyWord;
using rp::test::Ed25519Fault;
using rp::test::FakeEd25519;
using rp::test::MemoryFolder;
using rp::test::TempDir;

constexpr const char* kSharedResult = "testdata/result-v1/valid.json";
constexpr const char* kKeysFile = "testdata/signing-v1/keys.json";
constexpr const char* kBundleFile = "testdata/signing-v1/bundle.json";
constexpr const char* kCasesFile = "testdata/signing-v1/cases.json";
constexpr const char* kSignatureSchema = "schemas/signature.v1.json";

// As measured with OpenSSL when the entry was written (RFC 8032 test 1).
constexpr std::string_view kKey1Pem = "-----BEGIN PUBLIC KEY-----\n"
                                      "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
                                      "-----END PUBLIC KEY-----\n";
constexpr std::string_view kKey1Id =
    "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

// The folder's two made-up attachments: not the rows and lines of the result's
// run, only files with the hashes and sizes the result lists.
const std::string kItemsCsv = "index,type,name\n"
                              "0,\"mail\",\"a made-up row\"\n"
                              "1,\"sharepoint\",\"and a second one\"\n";
const std::string kSessionLog = "a made-up line of a restore session\n"
                                "and a second one\n";

std::span<const unsigned char> as_bytes(std::string_view text)
{
    return {reinterpret_cast<const unsigned char*>(text.data()), text.size()};
}

std::string base64_of(std::string_view bytes)
{
    return rp::base64_encode(as_bytes(bytes));
}

std::string to_text(const std::vector<unsigned char>& bytes)
{
    return {bytes.begin(), bytes.end()};
}

std::string upper(std::string text)
{
    for (char& c : text) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
    }
    return text;
}

// `text` with its one `from` replaced by `to`.
std::string replaced(const std::string& text, std::string_view from, std::string_view to)
{
    const std::size_t at = text.find(from);
    REQUIRE(at != std::string::npos);
    REQUIRE(text.find(from, at + 1) == std::string::npos);
    std::string out = text;
    out.replace(at, from.size(), to);
    return out;
}

// The shared result with the two made-up attachments in place of its own.
json bundle_document()
{
    json document = json::parse(rp::test::read_shared(kSharedResult));
    document["attachments"] = rp::to_json(std::vector<rp::Attachment>{
        {std::string{rp::kItemsCsvName}, rp::sha256_hex(kItemsCsv), kItemsCsv.size()},
        {std::string{rp::kSessionLogName}, rp::sha256_hex(kSessionLog), kSessionLog.size()}});
    return document;
}

std::string bundle_result()
{
    return rp::canonical_json(bundle_document());
}

// signature.json's text from its three values, as the Signer writes it.
std::string signature_text(std::string_view hash, std::string_view key_id,
                           std::string_view signature)
{
    return "{\"algorithm\":\"ed25519\",\"bundle_sha256\":\"" + std::string{hash} +
           "\",\"format\":\"restoreproof.signature.v1\",\"key_id\":\"" + std::string{key_id} +
           "\",\"signature\":\"" + std::string{signature} + "\"}";
}

SignedResult signed_with(const SigningKey& key, std::string_view canonical)
{
    const std::optional<SignedResult> out = Signer::sign(canonical, key);
    REQUIRE(out);
    return *out;
}

std::string signature_of(const SignedResult& made)
{
    return json::parse(made.signature_file).at("signature").get<std::string>();
}

// A signed folder: the bundle's four files.
MemoryFolder bundle_folder()
{
    const SigningKey key = rp::test::signing_key();
    const std::string result = bundle_result();
    MemoryFolder folder;
    folder.files = {{"items.csv", kItemsCsv},
                    {"result.json", result},
                    {"signature.json", signed_with(key, result).signature_file},
                    {"veeam-session.log", kSessionLog}};
    return folder;
}

PublicKey key1()
{
    return rp::test::public_key_of(rp::test::signing_key());
}

PublicKey key2()
{
    return rp::test::public_key_of(rp::test::signing_key(rp::test::signing_key2_base64()));
}

VerifyWord word_of(const MemoryFolder& folder)
{
    return Signer::verify_folder(folder.reader(), folder.names(), key1()).word;
}

// The folder with its result replaced by `result` and signed again: only the
// result's own checks can refuse it.
MemoryFolder resigned(const std::string& result)
{
    MemoryFolder folder = bundle_folder();
    folder.files["result.json"] = result;
    folder.files["signature.json"] = signed_with(rp::test::signing_key(), result).signature_file;
    return folder;
}

// An RSA key as RP_SIGNING_KEY_BASE64 would carry it: Base64 of its PKCS#8 DER.
std::string rsa_pkcs8_base64()
{
    const rp::test::KeyPtr key = rp::test::shared_rsa2048_key();
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(i2d_PKCS8PrivateKey_bio(bio.get(), key.get(), nullptr, nullptr, 0, nullptr,
                                    nullptr) == 1);
    return base64_of(rp::test::bio_to_string(bio.get()));
}

// --- the shared vectors, as the code makes them --------------------------------

std::string file_text(const ordered_json& document)
{
    return document.dump(2) + "\n";
}

ordered_json keys_json()
{
    ordered_json keys = ordered_json::array();
    for (const auto& [name, seed] :
         {std::pair{rp::test::kSigningKey1Name, rp::test::kSigningSeed1Hex},
          std::pair{rp::test::kSigningKey2Name, rp::test::kSigningSeed2Hex}}) {
        const std::string base64 = rp::test::pkcs8_base64(seed);
        const SigningKey key = rp::test::signing_key(base64);
        keys.push_back({{"name", name},
                        {"seed_hex", seed},
                        {"private_pkcs8_base64", base64},
                        {"public_key_pem", key.public_key_pem()},
                        {"key_id", key.key_id()}});
    }
    return {{"description",
             "Two fixed Ed25519 key pairs for the signing vectors (W4.3, docs/decisions.md "
             "2026-10-05, point 6): RFC 8032 section 7.1's tests 1 and 2. They are published "
             "test keys, known to everyone, and must never sign anything real. `seed_hex` is the "
             "RFC's 32-byte SECRET KEY; `private_pkcs8_base64` is the key as the Worker's "
             "RP_SIGNING_KEY_BASE64 carries it (standard Base64 of the 48-byte PKCS#8 DER: the "
             "16 bytes 302e020100300506032b657004220420, then the seed); `public_key_pem` is the "
             "SubjectPublicKeyInfo PEM a verifier is given (LF line ends); `key_id` is the "
             "SHA-256 of that key's SubjectPublicKeyInfo DER, 64 lower-case hex. bundle.json "
             "and cases.json name a key by its `name`."},
            {"keys", keys}};
}

ordered_json bundle_json()
{
    const SigningKey key = rp::test::signing_key();
    const std::string result = bundle_result();
    const SignedResult made = signed_with(key, result);
    return {{"description",
             "One signed run folder as texts (W4.3, docs/decisions.md 2026-10-05, point 6). "
             "`files` maps each file's name to its content; a file's bytes are the UTF-8 of "
             "that string, exactly, with no byte added (no trailing newline, no BOM). "
             "result.json is shared/testdata/result-v1/valid.json with its `attachments` "
             "replaced by the two made-up files here, items.csv and veeam-session.log, whose "
             "SHA-256 and size it lists; signature.json is the Worker's signature of "
             "result.json's bytes with the key `key` of keys.json. With that key's "
             "`public_key_pem` both verifiers answer `verified <bundle_sha256> key <key_id>`. "
             "Written by the Worker's hidden test `rptests \"[.write_shared_signing]\"`; a "
             "Worker test holds the file to what the code makes, byte for byte."},
            {"key", rp::test::kSigningKey1Name},
            {"bundle_sha256", made.bundle_sha256},
            {"key_id", made.key_id},
            {"files",
             {{"items.csv", kItemsCsv},
              {"result.json", result},
              {"signature.json", made.signature_file},
              {"veeam-session.log", kSessionLog}}}};
}

ordered_json as_text(const std::string& content)
{
    return {{"text", content}};
}

ordered_json as_base64(const std::string& content)
{
    return {{"base64", base64_of(content)}};
}

// L, the order of Ed25519's group, little-endian:
// 2^252 + 27742317777372353535851937790883648493.
constexpr std::string_view kGroupOrderHex =
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

// The signature with S + L in place of S: the same number modulo L.
std::vector<unsigned char> with_s_plus_l(std::vector<unsigned char> signature)
{
    const std::vector<unsigned char> order = rp::test::bytes_from_hex(kGroupOrderHex);
    REQUIRE(signature.size() == 64);
    unsigned carry = 0;
    for (std::size_t i = 0; i < 32; ++i) {
        const unsigned sum = signature[32 + i] + order[i] + carry;
        signature[32 + i] = static_cast<unsigned char>(sum & 0xff);
        carry = sum >> 8;
    }
    REQUIRE(carry == 0); // S + L fits 32 bytes
    return signature;
}

ordered_json cases_json()
{
    const SigningKey first = rp::test::signing_key();
    const SigningKey second = rp::test::signing_key(rp::test::signing_key2_base64());
    const std::string result = bundle_result();
    const SignedResult made = signed_with(first, result);
    const SignedResult others = signed_with(second, result);
    const std::string signature = signature_of(made);
    const std::optional<std::vector<unsigned char>> raw = rp::base64_decode(signature);
    REQUIRE(raw);
    const std::string& hash = made.bundle_sha256;
    const std::string& key_id = made.key_id;

    ordered_json cases = ordered_json::array();
    using Files = std::vector<std::pair<std::string, ordered_json>>;
    const auto add = [&cases](std::string_view name, std::string_view expect, const Files& files,
                              std::string_view key = rp::test::kSigningKey1Name) {
        ordered_json changed = ordered_json::object();
        for (const auto& [file, content] : files) {
            changed[file] = content;
        }
        cases.push_back(
            {{"name", name}, {"expect", expect}, {"public_key", key}, {"files", changed}});
    };
    const auto result_case = [&add](std::string_view name, std::string_view expect,
                                    const ordered_json& content) {
        add(name, expect, {{"result.json", content}});
    };
    const auto signature_case = [&add](std::string_view name, std::string_view expect,
                                       const ordered_json& content) {
        add(name, expect, {{"signature.json", content}});
    };
    // The result with one value changed, canonical and valid still.
    const auto changed_result = [](const char* pointer, const json& value) {
        json document = bundle_document();
        document.at(json::json_pointer(pointer)) = value;
        return rp::canonical_json(document);
    };

    // result_unreadable
    result_case("result-removed", "result_unreadable", nullptr);

    // result_not_canonical
    const std::string last_key = ",\"worker_version\":\"0.0.0\"}";
    REQUIRE(result.ends_with(last_key));
    result_case("result-keys-reordered", "result_not_canonical",
                as_text("{\"worker_version\":\"0.0.0\"," +
                        result.substr(1, result.size() - 1 - last_key.size()) + "}"));
    result_case("result-trailing-newline", "result_not_canonical", as_text(result + "\n"));
    result_case("result-duplicate-key", "result_not_canonical",
                as_text("{\"worker_version\":\"9.9.9\"," + result.substr(1)));
    result_case("result-bom", "result_not_canonical", as_base64("\xEF\xBB\xBF" + result));
    const std::string number = "\"index\":0,\"ms\":123000,";
    result_case("result-float-1.0", "result_not_canonical",
                as_text(replaced(result, number, "\"index\":0,\"ms\":123000.0,")));
    result_case("result-nan", "result_not_canonical",
                as_text(replaced(result, number, "\"index\":0,\"ms\":NaN,")));
    result_case("result-1e400", "result_not_canonical",
                as_text(replaced(result, number, "\"index\":0,\"ms\":1e400,")));
    result_case("result-escaped-lone-surrogate", "result_not_canonical",
                as_text(replaced(result, last_key, ",\"worker_version\":\"\\ud800\"}")));
    result_case("result-5000-digit-integer", "result_not_canonical",
                as_text(replaced(result, number,
                                 "\"index\":0,\"ms\":" + std::string(5000, '1') + ",")));
    result_case("result-33-levels", "result_not_canonical",
                as_text(std::string(33, '[') + std::string(33, ']')));
    result_case("result-not-utf8", "result_not_canonical",
                as_base64(replaced(result, last_key, ",\"worker_version\":\"\xff\"}")));
    result_case("result-not-json", "result_not_canonical", as_text("this is not JSON"));

    // result_schema, and the two things the schema can't say
    result_case("result-unknown-status", "result_schema",
                as_text(changed_result("/status/status", "maybe")));
    json twice = bundle_document();
    twice["attachments"][1] = twice["attachments"][0];
    result_case("result-attachment-listed-twice", "attachment_twice",
                as_text(rp::canonical_json(twice)));
    result_case("result-captured-without-screenshot", "screenshot_missing",
                as_text(changed_result("/screenshot", json{{"state", "captured"}})));

    // signature_file
    signature_case("signature-removed", "signature_file", nullptr);
    signature_case("signature-not-json", "signature_file", as_text("this is not JSON"));
    signature_case("signature-keys-reordered", "signature_file",
                   as_text("{\"signature\":\"" + signature +
                           "\",\"algorithm\":\"ed25519\",\"bundle_sha256\":\"" + hash +
                           "\",\"format\":\"restoreproof.signature.v1\",\"key_id\":\"" + key_id +
                           "\"}"));
    const std::string file = signature_text(hash, key_id, signature);
    REQUIRE(file == made.signature_file);
    signature_case("signature-sixth-key", "signature_file",
                   as_text(file.substr(0, file.size() - 1) + ",\"tsa_token\":null}"));
    REQUIRE(upper(hash) != hash);
    REQUIRE(upper(key_id) != key_id);
    signature_case("signature-bundle-sha256-upper-case", "signature_file",
                   as_text(signature_text(upper(hash), key_id, signature)));
    signature_case("signature-key-id-upper-case", "signature_file",
                   as_text(signature_text(hash, upper(key_id), signature)));
    signature_case("signature-63-bytes", "signature_file",
                   as_text(signature_text(
                       hash, key_id,
                       rp::base64_encode(std::span<const unsigned char>(*raw).first(63)))));
    std::string url_safe = signature;
    std::replace(url_safe.begin(), url_safe.end(), '+', '-');
    std::replace(url_safe.begin(), url_safe.end(), '/', '_');
    REQUIRE(url_safe != signature);
    signature_case("signature-url-safe-base64", "signature_file",
                   as_text(signature_text(hash, key_id, url_safe)));
    signature_case("signature-without-padding", "signature_file",
                   as_text(signature_text(hash, key_id, signature.substr(0, 86))));
    // The character before the padding carries two bits of the last byte and
    // four that must be zero: the next letter of the alphabet sets one.
    std::string pad_bit = signature;
    REQUIRE(std::string_view{"AQgw"}.find(pad_bit[85]) != std::string_view::npos);
    ++pad_bit[85];
    signature_case("signature-non-zero-pad-bit", "signature_file",
                   as_text(signature_text(hash, key_id, pad_bit)));

    // hash_mismatch: the file stays canonical and valid, and isn't what was signed
    const std::string item_hash =
        bundle_document().at("expected").at("items").at(0).at("sha256").get<std::string>();
    std::string other_hash = item_hash;
    other_hash[0] = other_hash[0] == '0' ? '1' : '0';
    result_case("result-expected-item-hash-one-digit", "hash_mismatch",
                as_text(changed_result("/expected/items/0/sha256", other_hash)));
    const std::string forged = changed_result("/check/items/0/ms", 123001);
    result_case("result-check-item-one-digit", "hash_mismatch", as_text(forged));

    // wrong_key
    signature_case("signature-of-the-second-key", "wrong_key", as_text(others.signature_file));
    add("untouched-the-second-key-given", "wrong_key", {}, rp::test::kSigningKey2Name);

    // signature_invalid
    std::vector<unsigned char> one_bit = *raw;
    one_bit[0] ^= 0x01;
    signature_case("signature-one-bit-changed", "signature_invalid",
                   as_text(signature_text(hash, key_id, rp::base64_encode(one_bit))));
    signature_case("signature-s-plus-l", "signature_invalid",
                   as_text(signature_text(hash, key_id,
                                          rp::base64_encode(with_s_plus_l(*raw)))));
    signature_case("signature-of-the-second-key-under-the-first-key-id", "signature_invalid",
                   as_text(signature_text(hash, key_id, signature_of(others))));
    add("forgery-result-changed-hash-computed-again", "signature_invalid",
        {{"result.json", as_text(forged)},
         {"signature.json", as_text(signature_text(rp::sha256_hex(forged), key_id, signature))}});

    // the attachments
    add("attachment-removed", "attachment_missing", {{"veeam-session.log", nullptr}});
    add("attachment-cut-short", "attachment_size",
        {{"veeam-session.log", as_text(kSessionLog.substr(0, kSessionLog.size() - 1))}});
    add("attachment-one-byte-changed", "attachment_hash",
        {{"items.csv", as_text(replaced(kItemsCsv, "a made-up row", "a made-up roW"))}});

    add("untouched", "verified", {});

    return {{"description",
             "Run folders both verifiers must answer alike (W4.3, docs/decisions.md 2026-10-05, "
             "points 5 and 6): the Worker's `rpworker signer verify` (rp::Signer::verify_folder) "
             "and shared/tools/verify_bundle.py. For each case: write every file of `bundle`'s "
             "`files` into a new empty folder (a file's bytes are the UTF-8 of its string, "
             "nothing added), then apply the case's `files`, which maps a file name to null "
             "(remove the file), to {\"text\": s} (the file's bytes become the UTF-8 of s) or to "
             "{\"base64\": b} (they become the bytes b encodes in standard Base64: for bytes "
             "that aren't UTF-8 or start with a BOM); an empty `files` leaves the folder "
             "untouched. Then verify the folder with the `public_key_pem` of the key of `keys` "
             "that `public_key` names. `expect` is the one word of the answer: `verified` "
             "(the line is `verified <bundle_sha256> key <key_id>` with bundle.json's values), "
             "or the word after `not verified: `. The first failing check gives the word, in "
             "this order: result_unreadable, result_not_canonical, result_schema, "
             "attachment_twice, screenshot_missing, signature_file, hash_mismatch, wrong_key, "
             "signature_invalid, then per listed attachment attachment_missing, "
             "attachment_size, attachment_hash. A replaced file is kept exactly as given: "
             "bytes that aren't canonical JSON are the point. The check item holds no hash, so "
             "result-check-item-one-digit changes one digit of an item's `ms`. Written by the "
             "Worker's hidden test `rptests \"[.write_shared_signing]\"`; a Worker test holds "
             "the file to what the code makes, byte for byte."},
            {"bundle", "bundle.json"},
            {"keys", "keys.json"},
            {"cases", cases}};
}

void write_shared(const char* relative, const std::string& text)
{
    std::ofstream file(std::filesystem::path{RP_SHARED_DIR} / relative,
                       std::ios::binary | std::ios::trunc);
    file << text;
    file.close();
    REQUIRE(file);
}

json key_named(const json& keys, const std::string& name)
{
    json found;
    for (const json& key : keys.at("keys")) {
        if (key.at("name") == name) {
            found = key;
        }
    }
    REQUIRE(found.is_object());
    return found;
}

} // namespace

// --- the words -----------------------------------------------------------------

TEST_CASE("the verifier's words are the entry's thirteen, in the checks' order", "[signer]")
{
    const std::vector<std::string> words = {
        "verified",          "result_unreadable",  "result_not_canonical", "result_schema",
        "attachment_twice",  "screenshot_missing", "signature_file",       "hash_mismatch",
        "wrong_key",         "signature_invalid",  "attachment_missing",   "attachment_size",
        "attachment_hash"};
    CHECK(rp::verify_words() == words);
    for (std::size_t i = 0; i < words.size(); ++i) {
        CAPTURE(words[i]);
        CHECK(rp::to_string(static_cast<VerifyWord>(i)) == words[i]);
    }
    CHECK(rp::to_string(VerifyWord::verified) == "verified");
    CHECK(rp::to_string(VerifyWord::attachment_hash) == "attachment_hash");
    CHECK(rp::to_string(static_cast<VerifyWord>(13)) == "unknown");
    CHECK(rp::to_string(static_cast<VerifyWord>(-1)) == "unknown");
    // A verdict nobody set is never `verified`.
    CHECK(Verification{}.word == VerifyWord::result_unreadable);
}

// --- the key -------------------------------------------------------------------

TEST_CASE("SigningKey::from_base64 takes the body line of OpenSSL's PEM", "[signer][key]")
{
    const std::optional<SigningKey> key = SigningKey::from_base64(rp::test::kSigningKey1Base64);
    REQUIRE(key);
    CHECK(key->public_key_pem() == kKey1Pem);
    CHECK(key->key_id() == kKey1Id);
    CHECK(rp::test::pkcs8_base64(rp::test::kSigningSeed1Hex) == rp::test::kSigningKey1Base64);
}

TEST_CASE("a signing key's secret shapes are its seed in Base64 and in hex", "[signer][key]")
{
    const SigningKey key = rp::test::signing_key();
    const std::vector<unsigned char> seed = rp::test::bytes_from_hex(rp::test::kSigningSeed1Hex);
    CHECK(key.secret_shapes() ==
          std::vector<std::string>{rp::base64_encode(seed),
                                   std::string{rp::test::kSigningSeed1Hex}});
    CHECK(key.secret_shapes().at(0) == "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
}

TEST_CASE("SigningKey::from_base64 refuses everything but 48 bytes of Ed25519 PKCS#8",
          "[signer][key]")
{
    const std::string good{rp::test::kSigningKey1Base64};
    const std::string prefix{rp::test::kPkcs8PrefixHex};
    const std::string seed{rp::test::kSigningSeed1Hex};
    const auto base64_of_hex = [](const std::string& hex) {
        return rp::base64_encode(rp::test::bytes_from_hex(hex));
    };
    REQUIRE(SigningKey::from_base64(base64_of_hex(prefix + seed)));

    SECTION("nothing")
    {
        CHECK_FALSE(SigningKey::from_base64(""));
    }
    SECTION("Base64 that isn't strict")
    {
        std::string url_safe = good;
        std::replace(url_safe.begin(), url_safe.end(), '/', '_');
        REQUIRE(url_safe != good);
        CHECK_FALSE(SigningKey::from_base64(url_safe));
        CHECK_FALSE(SigningKey::from_base64(good + "\n"));
        CHECK_FALSE(SigningKey::from_base64(" " + good));
        CHECK_FALSE(SigningKey::from_base64(good.substr(0, 32) + "\n" + good.substr(32)));
        CHECK_FALSE(SigningKey::from_base64(good.substr(0, 63)));
        CHECK_FALSE(SigningKey::from_base64("not a key!"));
    }
    SECTION("47 bytes")
    {
        CHECK_FALSE(SigningKey::from_base64(base64_of_hex(prefix + seed.substr(0, 62))));
    }
    SECTION("49 bytes: a byte after the key")
    {
        CHECK_FALSE(SigningKey::from_base64(base64_of_hex(prefix + seed + "00")));
    }
    SECTION("the bare seed, in Base64 and in hex")
    {
        CHECK_FALSE(SigningKey::from_base64(base64_of_hex(seed)));
        CHECK_FALSE(SigningKey::from_base64(seed));
    }
    SECTION("another prefix: each of the sixteen bytes")
    {
        const std::size_t byte = GENERATE(range(std::size_t{0}, std::size_t{16}));
        CAPTURE(byte);
        std::string other = prefix;
        other[2 * byte + 1] = other[2 * byte + 1] == '0' ? '1' : '0';
        CHECK_FALSE(SigningKey::from_base64(base64_of_hex(other + seed)));
    }
    SECTION("X25519's and Ed448's algorithm in the same 48 bytes")
    {
        CHECK_FALSE(
            SigningKey::from_base64(base64_of_hex("302e020100300506032b656e04220420" + seed)));
        CHECK_FALSE(
            SigningKey::from_base64(base64_of_hex("302e020100300506032b657104220420" + seed)));
    }
    SECTION("an RSA key")
    {
        CHECK_FALSE(SigningKey::from_base64(rsa_pkcs8_base64()));
    }
    SECTION("the PEM itself")
    {
        CHECK_FALSE(SigningKey::from_base64("-----BEGIN PRIVATE KEY-----\n" + good +
                                            "\n-----END PRIVATE KEY-----\n"));
    }
}

TEST_CASE("SigningKey::from_base64 is nothing when the primitive fails at any call",
          "[signer][key]")
{
    const Ed25519Fault fault =
        GENERATE(Ed25519Fault::make_key_null, Ed25519Fault::make_key_throws,
                 Ed25519Fault::der_empty, Ed25519Fault::der_short, Ed25519Fault::der_throws,
                 Ed25519Fault::pem_empty, Ed25519Fault::pem_throws);
    CAPTURE(static_cast<int>(fault));
    const FakeEd25519 fake(fault);
    CHECK_FALSE(SigningKey::from_base64(rp::test::kSigningKey1Base64, fake));
    // The fake itself is no reason.
    const FakeEd25519 sound;
    CHECK(SigningKey::from_base64(rp::test::kSigningKey1Base64, sound));
}

TEST_CASE("a signing key can be moved, never copied", "[signer][key]")
{
    static_assert(!std::is_copy_constructible_v<SigningKey>);
    static_assert(!std::is_copy_assignable_v<SigningKey>);
    static_assert(std::is_nothrow_move_constructible_v<SigningKey>);
    static_assert(std::is_nothrow_move_assignable_v<SigningKey>);

    SigningKey first = rp::test::signing_key();
    SigningKey moved(std::move(first));
    CHECK(moved.key_id() == kKey1Id);
    SigningKey other = rp::test::signing_key(rp::test::signing_key2_base64());
    REQUIRE(other.key_id() != kKey1Id);
    other = std::move(moved);
    CHECK(other.key_id() == kKey1Id);
    CHECK(Signer::sign("{}", other));
}

TEST_CASE("PublicKey::from_pem takes the PEM a signing key gives", "[signer][key]")
{
    const std::optional<PublicKey> key = PublicKey::from_pem(kKey1Pem);
    REQUIRE(key);
    CHECK(key->key_id() == kKey1Id);
    CHECK(key->der().size() == rp::kEd25519PublicDerBytes);
    CHECK(rp::sha256_hex(to_text(key->der())) == kKey1Id);
    CHECK(&key->primitive() == &rp::openssl_ed25519());
    CHECK(key2().key_id() != kKey1Id);
}

// shared/testdata/signing-v1/key-files.json: the one rule for a public key
// file, row by row. verify_bundle.py runs the same rows
// (cloud/tests/test_verify_bundle.py), so the two readers take the same files.
TEST_CASE("PublicKey::from_pem takes and refuses every shared key file as the file says",
          "[signer][key][vectors]")
{
    const json file = json::parse(rp::test::read_shared("testdata/signing-v1/key-files.json"));
    const json& rows = file.at("key_files");
    REQUIRE(rows.size() == 46);
    const std::string key1_id = file.at("accepted_key_id").get<std::string>();
    const std::string identity_id = file.at("identity_key_id").get<std::string>();
    CHECK(key1_id == kKey1Id);
    std::set<std::string> names;
    int accepted = 0;

    for (const json& row : rows) {
        const std::string name = row.at("name").get<std::string>();
        CAPTURE(name);
        names.insert(name);
        // Exactly one of the two carriers.
        REQUIRE(row.contains("text") != row.contains("base64"));
        std::string bytes;
        if (row.contains("text")) {
            bytes = row.at("text").get<std::string>();
        } else {
            const std::optional<std::vector<unsigned char>> decoded =
                rp::base64_decode(row.at("base64").get<std::string>());
            REQUIRE(decoded);
            bytes.assign(decoded->begin(), decoded->end());
        }

        const std::optional<PublicKey> key = PublicKey::from_pem(bytes);
        CHECK(key.has_value() == row.at("accepted").get<bool>());
        if (row.at("accepted").get<bool>()) {
            ++accepted;
        }
        if (key) {
            // The key the file holds, by the bytes it holds: nothing normalised.
            CHECK(key->key_id() ==
                  (name == "small-order-identity-key" ? identity_id : key1_id));
            CHECK(key->der().size() == rp::kEd25519PublicDerBytes);
        }
    }
    CHECK(names.size() == rows.size());
    CHECK(accepted == 11);
    CHECK(file.at("description").get<std::string>().find("C5.5") != std::string::npos);
}

// PR #158 review, finding 15: the rule for the file's text is the Signer's own
// (strict, held to 100%), not the primitive's. A primitive that takes
// everything changes only the two rows whose 44 bytes aren't Ed25519's.
TEST_CASE("PublicKey::from_pem holds the key file's rule itself, whatever the primitive says",
          "[signer][key][vectors]")
{
    const json file = json::parse(rp::test::read_shared("testdata/signing-v1/key-files.json"));
    const FakeEd25519 permissive(Ed25519Fault::is_key_any);
    const std::set<std::string> primitive_only = {"bit-string-unused-bits-1", "x25519-public-key"};
    int refused = 0;
    int taken = 0;

    for (const json& row : file.at("key_files")) {
        const std::string name = row.at("name").get<std::string>();
        CAPTURE(name);
        std::string bytes;
        if (row.contains("text")) {
            bytes = row.at("text").get<std::string>();
        } else {
            const std::optional<std::vector<unsigned char>> decoded =
                rp::base64_decode(row.at("base64").get<std::string>());
            REQUIRE(decoded);
            bytes.assign(decoded->begin(), decoded->end());
        }
        const bool expected =
            row.at("accepted").get<bool>() || primitive_only.contains(name);

        const std::optional<PublicKey> key = PublicKey::from_pem(bytes, permissive);

        CHECK(key.has_value() == expected);
        ++(expected ? taken : refused);
        if (key) {
            // The file's own 44 bytes.
            CHECK(key->der().size() == rp::kEd25519PublicDerBytes);
        }
    }
    CHECK(refused == 33);
    CHECK(taken == 13);
}

TEST_CASE("PublicKey::from_pem refuses what isn't an Ed25519 public key", "[signer][key]")
{
    CHECK_FALSE(PublicKey::from_pem(""));
    CHECK_FALSE(PublicKey::from_pem("not a key"));
    CHECK_FALSE(PublicKey::from_pem(rp::test::kSigningKey1Base64));
    const rp::test::KeyPtr rsa = rp::test::shared_rsa2048_key();
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    REQUIRE(PEM_write_bio_PUBKEY(bio.get(), rsa.get()) == 1);
    CHECK_FALSE(PublicKey::from_pem(rp::test::bio_to_string(bio.get())));

    const FakeEd25519 no_key(Ed25519Fault::is_key_false);
    CHECK_FALSE(PublicKey::from_pem(kKey1Pem, no_key));
    const FakeEd25519 throwing(Ed25519Fault::is_key_throws);
    CHECK_FALSE(PublicKey::from_pem(kKey1Pem, throwing));
    const FakeEd25519 sound;
    const std::optional<PublicKey> key = PublicKey::from_pem(kKey1Pem, sound);
    REQUIRE(key);
    CHECK(&key->primitive() == &sound);
}

// --- sign ------------------------------------------------------------------------

TEST_CASE("sign gives the signature file's five keys over the bytes' SHA-256", "[signer][sign]")
{
    const SigningKey key = rp::test::signing_key();
    const std::string result = bundle_result();

    const std::optional<SignedResult> made = Signer::sign(result, key);
    REQUIRE(made);
    CHECK(made->bundle_sha256 == rp::sha256_hex(result));
    CHECK(made->key_id == kKey1Id);

    // The text is exactly this, and its own canonical form.
    const std::string signature = signature_of(*made);
    CHECK(made->signature_file == signature_text(made->bundle_sha256, kKey1Id, signature));
    CHECK(made->signature_file == rp::canonical_json(json::parse(made->signature_file)));
    CHECK(made->signature_file.size() == 322);
    CHECK(made->signature_file.size() < rp::kMaxSignatureFileBytes);

    // The signature is over the digest's 32 raw bytes, not its hex.
    REQUIRE(signature.size() == 88);
    const std::optional<std::vector<unsigned char>> raw = rp::base64_decode(signature);
    REQUIRE(raw);
    REQUIRE(raw->size() == rp::kEd25519SignatureBytes);
    const std::span<const unsigned char, rp::kEd25519SignatureBytes> bytes(raw->data(), 64);
    const PublicKey pub = rp::test::public_key_of(key);
    CHECK(rp::openssl_ed25519().verify(pub.der(), rp::sha256_bytes(result), bytes));
    CHECK_FALSE(rp::openssl_ed25519().verify(pub.der(), as_bytes(made->bundle_sha256), bytes));
    CHECK_FALSE(rp::openssl_ed25519().verify(pub.der(), as_bytes(result), bytes));

    // Ed25519 draws nothing at random: the same bytes, the same file.
    CHECK(Signer::sign(result, key)->signature_file == made->signature_file);
}

TEST_CASE("a signed result verifies under its key, and under no other", "[signer][sign]")
{
    const SigningKey key = rp::test::signing_key();
    const std::string result = bundle_result();
    const SignedResult made = signed_with(key, result);

    const Verification verdict = Signer::verify(result, made.signature_file, key1());
    CHECK(verdict.word == VerifyWord::verified);
    CHECK(verdict.bundle_sha256 == made.bundle_sha256);
    CHECK(verdict.key_id == made.key_id);
    CHECK(verdict.notes.empty());

    const Verification other = Signer::verify(result, made.signature_file, key2());
    CHECK(other.word == VerifyWord::wrong_key);
    CHECK(other.bundle_sha256.empty());
    CHECK(other.key_id.empty());
}

// Q4.1's second bullet, as the entry amends it: a re-ordered file is refused,
// and what holds instead is that one document has one canonical text.
TEST_CASE("a document built in two key orders has one canonical text and one hash",
          "[signer][sign]")
{
    const SigningKey key = rp::test::signing_key();
    const json first = json::parse(R"({"a":1,"b":{"c":[1,2],"d":"x"}})");
    const json second = json::parse(R"({ "b": {"d": "x", "c": [1, 2]}, "a": 1 })");
    json built;
    built["b"]["d"] = "x";
    built["b"]["c"] = {1, 2};
    built["a"] = 1;

    const std::string text = rp::canonical_json(first);
    CHECK(rp::canonical_json(second) == text);
    CHECK(rp::canonical_json(built) == text);
    const SignedResult made = signed_with(key, text);
    CHECK(signed_with(key, rp::canonical_json(second)).signature_file == made.signature_file);
    CHECK(made.bundle_sha256 == rp::sha256_hex(text));
}

TEST_CASE("sign refuses text that isn't its own canonical form", "[signer][sign]")
{
    const SigningKey key = rp::test::signing_key();
    const std::string result = bundle_result();
    REQUIRE(Signer::sign(result, key));

    const std::string text = GENERATE_COPY(
        std::string{},
        std::string{"this is not JSON"},
        std::string{R"({"b":1,"a":2})"},
        std::string{R"({"a":2, "b":1})"},
        std::string{"{\"a\":2}\n"},
        std::string{" {\"a\":2}"},
        std::string{R"({"a":1,"a":2})"},
        std::string{R"({"a":1.0})"},
        std::string{R"({"a":-0})"},
        std::string{R"({"a":1e2})"},
        std::string{R"({"a":NaN})"},
        std::string{R"({"a":9007199254740992})"},
        std::string{"{\"a\":" + std::string(5000, '1') + "}"},
        std::string{R"({"a":"\u0041"})"},
        std::string{R"({"a":"\ud800"})"},
        std::string{"{\"\xC3\xA4\":1}"},
        std::string{"{\"a\":\"\xff\"}"},
        std::string{"\xEF\xBB\xBF{\"a\":2}"},
        std::string{R"({"a":2}{"a":2})"},
        std::string(33, '[') + std::string(33, ']'),
        result + "\n",
        result.substr(0, result.size() - 1));
    CAPTURE(text.substr(0, 60));
    CHECK_FALSE(Signer::sign(text, key));
}

TEST_CASE("sign counts nesting outside strings, and takes 32 levels", "[signer][sign]")
{
    const SigningKey key = rp::test::signing_key();
    CHECK(Signer::sign(std::string(32, '[') + std::string(32, ']'), key));
    CHECK_FALSE(Signer::sign(std::string(33, '[') + std::string(33, ']'), key));
    // Sixteen objects in sixteen arrays.
    std::string mixed;
    for (int i = 0; i < 16; ++i) {
        mixed += "[{\"a\":";
    }
    mixed += "1";
    for (int i = 0; i < 16; ++i) {
        mixed += "}]";
    }
    CHECK(Signer::sign(mixed, key));
    CHECK_FALSE(Signer::sign("[" + mixed + "]", key));
    // Brackets inside a string open nothing, an escaped quote doesn't end it,
    // and an escaped backslash doesn't escape the quote after it.
    CHECK(Signer::sign("\"" + std::string(40, '[') + "\"", key));
    CHECK(Signer::sign("\"\\\"" + std::string(40, '{') + "\"", key));
    CHECK(Signer::sign("[\"\\\\\"," + std::string(31, '[') + std::string(31, ']') + "]", key));
    CHECK_FALSE(
        Signer::sign("[\"\\\\\"," + std::string(32, '[') + std::string(32, ']') + "]", key));
    // Closed again is closed: many arrays, one level at a time.
    std::string wide = "[";
    for (int i = 0; i < 40; ++i) {
        wide += i == 0 ? "[]" : ",[]";
    }
    CHECK(Signer::sign(wide + "]", key));
}

TEST_CASE("sign is nothing when the primitive fails: no signature, a throw, a signature that "
          "doesn't verify",
          "[signer][sign]")
{
    const Ed25519Fault fault =
        GENERATE(Ed25519Fault::sign_none, Ed25519Fault::sign_throws, Ed25519Fault::sign_other,
                 Ed25519Fault::check_false, Ed25519Fault::check_throws);
    CAPTURE(static_cast<int>(fault));
    const FakeEd25519 fake;
    const SigningKey key = rp::test::signing_key(rp::test::kSigningKey1Base64, fake);
    const std::string result = bundle_result();
    REQUIRE(Signer::sign(result, key));

    fake.fault = fault;
    CHECK_FALSE(Signer::sign(result, key));

    // And signs again once the primitive does.
    fake.fault = Ed25519Fault::none;
    CHECK(Signer::sign(result, key));
}

// --- the signature file ----------------------------------------------------------

TEST_CASE("a Worker-made signature file is valid against shared/schemas/signature.v1.json",
          "[signer][schema]")
{
    const json schema = json::parse(rp::test::read_shared(kSignatureSchema));
    CHECK(rp::test::problems_of(schema) == std::vector<std::string>{});
    CHECK(schema.at("required") ==
          json{"algorithm", "bundle_sha256", "format", "key_id", "signature"});
    CHECK(schema.at("properties").size() == 5);
    CHECK(schema.at("additionalProperties") == false);
    CHECK(schema.at("properties").at("format").at("const") == std::string{rp::kSignatureFormat});
    CHECK(schema.at("properties").at("algorithm").at("const") ==
          std::string{rp::kSignatureAlgorithm});

    nlohmann::json_schema::json_validator validator;
    validator.set_root_schema(schema);
    for (const std::string& key : {std::string{rp::test::kSigningKey1Base64},
                                   rp::test::signing_key2_base64()}) {
        const SignedResult made = signed_with(rp::test::signing_key(key), bundle_result());
        CHECK_NOTHROW(validator.validate(json::parse(made.signature_file)));
    }
}

// The Worker checks the signature file's rules in code and Python against the
// schema: every fault here that is still canonical JSON must be one to both.
TEST_CASE("the signature file's rules in code are the schema's", "[signer][schema]")
{
    const std::string result = bundle_result();
    const SignedResult made = signed_with(rp::test::signing_key(), result);
    const std::string hash = made.bundle_sha256;
    const std::string id = made.key_id;
    const std::string signature = signature_of(made);
    const std::optional<std::vector<unsigned char>> raw = rp::base64_decode(signature);
    REQUIRE(raw);
    std::vector<unsigned char> longer = *raw;
    longer.push_back(0);
    std::string pad_bit = signature;
    ++pad_bit[85];
    std::string url_safe = signature;
    std::replace(url_safe.begin(), url_safe.end(), '+', '-');
    std::replace(url_safe.begin(), url_safe.end(), '/', '_');
    json good = json::parse(made.signature_file);
    const auto with = [&good](const char* key, const json& value) {
        json changed = good;
        changed[key] = value;
        return rp::canonical_json(changed);
    };
    const auto without = [&good](const char* key) {
        json changed = good;
        changed.erase(key);
        return rp::canonical_json(changed);
    };
    json renamed = good;
    renamed.erase("key_id");
    renamed["key_ID"] = id;

    const std::string text = GENERATE_COPY(
        with("algorithm", "Ed25519"),
        with("algorithm", "ed448"),
        with("algorithm", nullptr),
        with("format", "restoreproof.signature.v2"),
        with("format", "restoreproof.result.v1"),
        with("format", 1),
        with("bundle_sha256", upper(hash)),
        with("bundle_sha256", hash.substr(0, 63)),
        with("bundle_sha256", hash + "0"),
        with("bundle_sha256", "g" + hash.substr(1)),
        with("bundle_sha256", ""),
        with("bundle_sha256", nullptr),
        with("key_id", upper(id)),
        with("key_id", id.substr(1)),
        with("key_id", id + "\n"),
        with("key_id", json::array({id})),
        with("signature", ""),
        with("signature", signature.substr(0, 86)),
        with("signature", signature.substr(0, 87)),
        with("signature", signature + "="),
        with("signature", signature.substr(0, 84)),
        with("signature", rp::base64_encode(std::span<const unsigned char>(*raw).first(63))),
        with("signature", rp::base64_encode(longer)),
        with("signature", pad_bit),
        with("signature", url_safe),
        with("signature", " " + signature.substr(1)),
        with("signature", rp::test::hex_from_bytes(*raw)),
        with("signature", nullptr),
        with("tsa_token", nullptr),
        with("signature_2", signature),
        without("algorithm"),
        without("bundle_sha256"),
        without("format"),
        without("key_id"),
        without("signature"),
        rp::canonical_json(renamed),
        std::string{"{}"},
        std::string{"[]"},
        std::string{"null"},
        std::string{"\"" + signature + "\""},
        rp::canonical_json(json::array({good})));
    CAPTURE(text);

    nlohmann::json_schema::json_validator validator;
    validator.set_root_schema(json::parse(rp::test::read_shared(kSignatureSchema)));
    CHECK_THROWS(validator.validate(json::parse(text)));
    CHECK(Signer::verify(result, text, key1()).word == VerifyWord::signature_file);
    // The untouched file is neither's reason.
    CHECK_NOTHROW(validator.validate(good));
    CHECK(Signer::verify(result, made.signature_file, key1()).word == VerifyWord::verified);
}

TEST_CASE("a signature file that isn't its own canonical form is signature_file",
          "[signer][verify]")
{
    const std::string result = bundle_result();
    const SignedResult made = signed_with(rp::test::signing_key(), result);
    const std::string& file = made.signature_file;

    const std::string text = GENERATE_COPY(
        std::string{}, std::string{"this is not JSON"}, file + "\n", " " + file,
        "\xEF\xBB\xBF" + file, file.substr(0, file.size() - 1),
        replaced(file, "\"algorithm\":\"ed25519\",", "\"algorithm\":\"ed25519\", "),
        replaced(file, "{\"algorithm\":\"ed25519\",",
                 "{\"algorithm\":\"ed448\",\"algorithm\":\"ed25519\","),
        std::string(33, '[') + file + std::string(33, ']'));
    CAPTURE(text.substr(0, 60));
    CHECK(Signer::verify(result, text, key1()).word == VerifyWord::signature_file);
}

// --- the folder's checks -----------------------------------------------------------

TEST_CASE("an untouched signed folder is verified, with its hash and its key's ID",
          "[signer][verify]")
{
    const MemoryFolder folder = bundle_folder();
    const Verification verdict = Signer::verify_folder(folder.reader(), folder.names(), key1());
    CHECK(verdict.word == VerifyWord::verified);
    CHECK(verdict.bundle_sha256 == rp::sha256_hex(folder.files.at("result.json")));
    CHECK(verdict.key_id == kKey1Id);
    CHECK(verdict.notes.empty());

    // What was read, and under which limits: an attachment at most its listed size.
    const std::vector<std::pair<std::string, std::uintmax_t>> asked = {
        {"result.json", rp::kMaxResultFileBytes},
        {"signature.json", rp::kMaxSignatureFileBytes},
        {"items.csv", kItemsCsv.size()},
        {"veeam-session.log", kSessionLog.size()}};
    CHECK(*folder.asked == asked);
}

TEST_CASE("a file the result doesn't list is a note, never a failure", "[signer][verify]")
{
    MemoryFolder folder = bundle_folder();
    folder.files["manifest.json"] = "{}";
    folder.files["timestamp.tsr"] = "token";
    folder.files["Items.csv"] = "another file to a verifier";

    const Verification verdict = Signer::verify_folder(folder.reader(), folder.names(), key1());
    CHECK(verdict.word == VerifyWord::verified);
    CHECK(verdict.notes ==
          std::vector<std::string>{"Items.csv", "manifest.json", "timestamp.tsr"});
    // The notes are of the names given, in their order; none is read.
    const Verification given = Signer::verify_folder(
        folder.reader(),
        {"zz", "result.json", "aa", "signature.json", "items.csv", "veeam-session.log"}, key1());
    CHECK(given.notes == std::vector<std::string>{"zz", "aa"});
    for (const auto& [name, limit] : *folder.asked) {
        CHECK(name != "manifest.json");
        CHECK(name != "zz");
    }
    // A folder that isn't verified has no notes.
    folder.files.erase("items.csv");
    const Verification failed = Signer::verify_folder(folder.reader(), folder.names(), key1());
    CHECK(failed.word == VerifyWord::attachment_missing);
    CHECK(failed.notes.empty());
    CHECK(failed.bundle_sha256.empty());
    CHECK(failed.key_id.empty());
}

TEST_CASE("result_unreadable is only: not there, not read, too large", "[signer][verify]")
{
    MemoryFolder folder = bundle_folder();
    SECTION("not there")
    {
        folder.files.erase("result.json");
        CHECK(word_of(folder) == VerifyWord::result_unreadable);
        // Nothing is read then: a name the folder doesn't list isn't asked for.
        CHECK(folder.asked->empty());
    }
    SECTION("too large: never parsed, though it is a result")
    {
        const rp::FileReader inner = folder.reader();
        const rp::FileReader small = [inner](std::string_view name, std::uintmax_t limit) {
            return inner(name, name == "result.json" ? std::uintmax_t{100} : limit);
        };
        CHECK(Signer::verify_folder(small, folder.names(), key1()).word ==
              VerifyWord::result_unreadable);
    }
    SECTION("empty is read, and not canonical")
    {
        folder.files["result.json"] = "";
        CHECK(word_of(folder) == VerifyWord::result_not_canonical);
    }
}

TEST_CASE("a signature file that isn't read is signature_file", "[signer][verify]")
{
    MemoryFolder folder = bundle_folder();
    SECTION("not there")
    {
        folder.files.erase("signature.json");
    }
    SECTION("too large")
    {
        folder.files["signature.json"] += std::string(rp::kMaxSignatureFileBytes, ' ');
    }
    CHECK(word_of(folder) == VerifyWord::signature_file);
}

TEST_CASE("the result's own checks come before the signature's, whatever the signature says",
          "[signer][verify]")
{
    MemoryFolder folder = bundle_folder();
    folder.files.erase("signature.json");

    SECTION("not canonical")
    {
        folder.files["result.json"] += "\n";
        CHECK(word_of(folder) == VerifyWord::result_not_canonical);
    }
    SECTION("canonical, not a result")
    {
        const std::string text = GENERATE(std::string{"{}"}, std::string{"[]"},
                                          std::string{"null"}, std::string{"1"},
                                          std::string(32, '[') + std::string(32, ']'));
        folder.files["result.json"] = text;
        CHECK(word_of(folder) == VerifyWord::result_schema);
    }
    SECTION("a name listed twice")
    {
        json document = bundle_document();
        document["attachments"][0] = document["attachments"][1];
        folder.files["result.json"] = rp::canonical_json(document);
        CHECK(word_of(folder) == VerifyWord::attachment_twice);
    }
    SECTION("captured, and no screenshot.png listed")
    {
        json document = bundle_document();
        document["screenshot"] = {{"state", "captured"}};
        folder.files["result.json"] = rp::canonical_json(document);
        CHECK(word_of(folder) == VerifyWord::screenshot_missing);
    }
    SECTION("twice comes before the screenshot")
    {
        json document = bundle_document();
        document["attachments"][0] = document["attachments"][1];
        document["screenshot"] = {{"state", "captured"}};
        folder.files["result.json"] = rp::canonical_json(document);
        CHECK(word_of(folder) == VerifyWord::attachment_twice);
    }
    SECTION("a sound result: then the signature file")
    {
        CHECK(word_of(folder) == VerifyWord::signature_file);
    }
}

TEST_CASE("after the signature file: the hash, then the key, then the signature",
          "[signer][verify]")
{
    const SigningKey first = rp::test::signing_key();
    const SigningKey second = rp::test::signing_key(rp::test::signing_key2_base64());
    MemoryFolder folder = bundle_folder();
    const std::string result = folder.files.at("result.json");
    const SignedResult made = signed_with(first, result);
    const SignedResult others = signed_with(second, result);
    const std::string other_result = rp::canonical_json(json{{"a", 1}});
    const SignedResult of_other = signed_with(second, other_result);

    SECTION("another result's hash, another key and its signature: hash_mismatch")
    {
        folder.files["signature.json"] = of_other.signature_file;
        CHECK(word_of(folder) == VerifyWord::hash_mismatch);
    }
    SECTION("this result's hash, another key and its signature: wrong_key")
    {
        folder.files["signature.json"] = others.signature_file;
        CHECK(word_of(folder) == VerifyWord::wrong_key);
        // Under that key it is verified: the caller's key decides.
        CHECK(Signer::verify_folder(folder.reader(), folder.names(), key2()).word ==
              VerifyWord::verified);
    }
    SECTION("this result's hash, this key's ID, another key's signature: signature_invalid")
    {
        folder.files["signature.json"] =
            signature_text(made.bundle_sha256, made.key_id, signature_of(others));
        CHECK(word_of(folder) == VerifyWord::signature_invalid);
    }
    SECTION("this key's signature of another result under this result's hash")
    {
        folder.files["signature.json"] = signature_text(
            made.bundle_sha256, made.key_id, signature_of(signed_with(first, other_result)));
        CHECK(word_of(folder) == VerifyWord::signature_invalid);
    }
    SECTION("the signature comes before the attachments")
    {
        folder.files.erase("items.csv");
        folder.files["signature.json"] =
            signature_text(made.bundle_sha256, made.key_id, signature_of(others));
        CHECK(word_of(folder) == VerifyWord::signature_invalid);
    }
}

TEST_CASE("each listed attachment: there, its size, its hash, in the result's order",
          "[signer][verify]")
{
    MemoryFolder folder = bundle_folder();

    SECTION("not there")
    {
        folder.files.erase("veeam-session.log");
        CHECK(word_of(folder) == VerifyWord::attachment_missing);
    }
    SECTION("shorter")
    {
        folder.files["veeam-session.log"].pop_back();
        CHECK(word_of(folder) == VerifyWord::attachment_size);
    }
    SECTION("empty")
    {
        folder.files["items.csv"].clear();
        CHECK(word_of(folder) == VerifyWord::attachment_size);
    }
    SECTION("longer: not read at all")
    {
        folder.files["items.csv"] += "x";
        CHECK(word_of(folder) == VerifyWord::attachment_size);
    }
    SECTION("the same size, one byte changed")
    {
        folder.files["items.csv"][0] ^= 0x01;
        CHECK(word_of(folder) == VerifyWord::attachment_hash);
    }
    SECTION("the first listed attachment's fault is the word")
    {
        folder.files["items.csv"][0] ^= 0x01;
        folder.files.erase("veeam-session.log");
        CHECK(word_of(folder) == VerifyWord::attachment_hash);
    }
    SECTION("a file listed with another's hash")
    {
        std::swap(folder.files["items.csv"], folder.files["veeam-session.log"]);
        CHECK(word_of(folder) == VerifyWord::attachment_size);
    }
}

TEST_CASE("a captured screenshot is one more listed attachment", "[signer][verify]")
{
    const std::string png = std::string("\x89PNG\r\n\x1a\n", 8) + std::string(40, '\0');
    json document = bundle_document();
    document["attachments"] = rp::to_json(std::vector<rp::Attachment>{
        {"items.csv", rp::sha256_hex(kItemsCsv), kItemsCsv.size()},
        {"screenshot.png", rp::sha256_hex(png), png.size()},
        {"veeam-session.log", rp::sha256_hex(kSessionLog), kSessionLog.size()}});
    document["screenshot"] = {{"state", "captured"}};
    MemoryFolder folder = resigned(rp::canonical_json(document));
    folder.files["screenshot.png"] = png;
    CHECK(word_of(folder) == VerifyWord::verified);

    folder.files["screenshot.png"][20] = 'x';
    CHECK(word_of(folder) == VerifyWord::attachment_hash);
    folder.files.erase("screenshot.png");
    CHECK(word_of(folder) == VerifyWord::attachment_missing);
}

TEST_CASE("a result with no run folder's files lists none, and none is read", "[signer][verify]")
{
    json document = bundle_document();
    document["attachments"] = nullptr;
    document["screenshot"] = nullptr;
    REQUIRE(rp::validate_result(document).valid);
    MemoryFolder folder = resigned(rp::canonical_json(document));
    folder.files.erase("items.csv");

    const Verification verdict = Signer::verify_folder(folder.reader(), folder.names(), key1());
    CHECK(verdict.word == VerifyWord::verified);
    CHECK(folder.asked->size() == 2);
    CHECK(verdict.notes == std::vector<std::string>{"veeam-session.log"});
}

TEST_CASE("verify_folder lets a reader's or the primitive's failure through: never a verdict",
          "[signer][verify]")
{
    const MemoryFolder folder = bundle_folder();
    const rp::FileReader broken = [](std::string_view, std::uintmax_t) -> FileRead {
        throw std::runtime_error("the disk went away");
    };
    CHECK_THROWS_AS(Signer::verify_folder(broken, folder.names(), key1()), std::runtime_error);

    const FakeEd25519 fake;
    const PublicKey key = rp::test::public_key_of(rp::test::signing_key(), fake);
    REQUIRE(Signer::verify_folder(folder.reader(), folder.names(), key).word ==
            VerifyWord::verified);
    fake.fault = Ed25519Fault::check_throws;
    CHECK_THROWS_AS(Signer::verify_folder(folder.reader(), folder.names(), key),
                    std::runtime_error);
    // The primitive's "no" is the word.
    fake.fault = Ed25519Fault::check_false;
    CHECK(Signer::verify_folder(folder.reader(), folder.names(), key).word ==
          VerifyWord::signature_invalid);
}

// A file system that ignores case (NTFS, by default) opens ITEMS.CSV when
// items.csv is asked for; one that doesn't has no such file. The folder's own
// list of names decides, so the word is the same on both, and no file is
// "verified" and "not listed in the result" at once.
TEST_CASE("a file is there only under its own name, byte for byte, whatever the reader opens",
          "[signer][verify]")
{
    // The reader finds all four files, as NTFS would under any case of a name.
    const MemoryFolder folder = bundle_folder();
    const auto verdict_for = [&folder](const std::vector<std::string>& names) {
        return Signer::verify_folder(folder.reader(), names, key1());
    };
    REQUIRE(verdict_for({"items.csv", "result.json", "signature.json", "veeam-session.log"})
                .word == VerifyWord::verified);
    folder.asked->clear();

    SECTION("the result")
    {
        const Verification verdict =
            verdict_for({"RESULT.JSON", "items.csv", "signature.json", "veeam-session.log"});
        CHECK(verdict.word == VerifyWord::result_unreadable);
        CHECK(verdict.notes.empty());
    }
    SECTION("the signature file")
    {
        CHECK(verdict_for({"Signature.json", "items.csv", "result.json", "veeam-session.log"})
                  .word == VerifyWord::signature_file);
    }
    SECTION("an attachment")
    {
        const Verification verdict =
            verdict_for({"ITEMS.CSV", "result.json", "signature.json", "veeam-session.log"});
        CHECK(verdict.word == VerifyWord::attachment_missing);
        CHECK(verdict.notes.empty());
        // And it wasn't read to find that out.
        for (const auto& [name, limit] : *folder.asked) {
            CHECK(name != "items.csv");
        }
    }
    SECTION("the second attachment")
    {
        CHECK(verdict_for({"items.csv", "result.json", "signature.json", "veeam-session.LOG"})
                  .word == VerifyWord::attachment_missing);
    }
    SECTION("no names at all: nothing is there")
    {
        CHECK(verdict_for({}).word == VerifyWord::result_unreadable);
        CHECK(folder.asked->empty());
    }
}

// rp::validate_result answers "not valid" when it couldn't check at all (the
// schema not loaded, no memory). That is no fact about the folder.
TEST_CASE("a result that couldn't be checked against its schema is the verifier's failure, "
          "never a word",
          "[signer][verify]")
{
    const MemoryFolder folder = bundle_folder();
    const std::string result = folder.files.at("result.json");
    const std::string signature = folder.files.at("signature.json");
    struct Unavailable {
        Unavailable() { rp::detail::set_result_validator_unavailable(true); }
        ~Unavailable() { rp::detail::set_result_validator_unavailable(false); }
    };
    {
        const Unavailable unavailable;
        CHECK_THROWS_AS(Signer::verify(result, signature, key1()), rp::VerifierFailure);
        CHECK_THROWS_AS(Signer::verify_folder(folder.reader(), folder.names(), key1()),
                        rp::VerifierFailure);
        // What is refused before the schema is asked still has its word.
        CHECK(Signer::verify(result + "\n", signature, key1()).word ==
              VerifyWord::result_not_canonical);
        CHECK(word_of(MemoryFolder{}) == VerifyWord::result_unreadable);
        // Signing asks no schema.
        CHECK(Signer::sign(result, rp::test::signing_key()));
    }
    CHECK(word_of(folder) == VerifyWord::verified);
    CHECK(std::string{rp::VerifierFailure().what()} ==
          "the result couldn't be checked against its schema");
}

// --- the shared vectors --------------------------------------------------------------

TEST_CASE("keys.json is RFC 8032's tests 1 and 2 as the code derives them", "[signer][vectors]")
{
    const std::string file = rp::test::read_shared(kKeysFile);
    // After a deliberate change: rptests "[.write_shared_signing]".
    REQUIRE(file == file_text(keys_json()));
    const json keys = json::parse(file).at("keys");
    REQUIRE(keys.size() == 2);
    CHECK(keys.at(0).at("name") == "rfc8032-test-1");
    CHECK(keys.at(0).at("seed_hex") == std::string{rp::test::kSigningSeed1Hex});
    CHECK(keys.at(0).at("private_pkcs8_base64") == std::string{rp::test::kSigningKey1Base64});
    CHECK(keys.at(0).at("public_key_pem") == std::string{kKey1Pem});
    CHECK(keys.at(0).at("key_id") == std::string{kKey1Id});
    CHECK(keys.at(1).at("name") == "rfc8032-test-2");
    CHECK(keys.at(1).at("seed_hex") == std::string{rp::test::kSigningSeed2Hex});
    // The same seeds as the primitive's vectors.
    const json tests = json::parse(rp::test::read_shared("testdata/signing-v1/ed25519.json"));
    CHECK(tests.at("tests").at(0).at("seed_hex") == keys.at(0).at("seed_hex"));
    CHECK(tests.at("tests").at(1).at("seed_hex") == keys.at(1).at("seed_hex"));
}

TEST_CASE("bundle.json is the signed folder the code makes, byte for byte", "[signer][vectors]")
{
    const std::string file = rp::test::read_shared(kBundleFile);
    // After a deliberate change to the result: rptests "[.write_shared_result]",
    // then rptests "[.write_shared_signing]".
    REQUIRE(file == file_text(bundle_json()));

    const json bundle = json::parse(file);
    const json& files = bundle.at("files");
    REQUIRE(files.size() == 4);
    const std::string result = files.at("result.json").get<std::string>();
    const json document = json::parse(result);
    CHECK(result == rp::canonical_json(document));
    CHECK(rp::validate_result(document).valid);
    CHECK(bundle.at("bundle_sha256") == rp::sha256_hex(result));
    CHECK(bundle.at("key_id") == std::string{kKey1Id});
    CHECK(bundle.at("key") == "rfc8032-test-1");
    // The result is the shared one but for what it lists.
    json shared = json::parse(rp::test::read_shared(kSharedResult));
    REQUIRE(shared.at("attachments") != document.at("attachments"));
    shared["attachments"] = document.at("attachments");
    CHECK(shared == document);
    for (const json& attachment : document.at("attachments")) {
        const std::string content =
            files.at(attachment.at("name").get<std::string>()).get<std::string>();
        CHECK(attachment.at("sha256") == rp::sha256_hex(content));
        CHECK(attachment.at("size_bytes") == content.size());
    }
    // The URL-safe case needs a character the two alphabets differ in.
    const std::string signature = json::parse(files.at("signature.json").get<std::string>())
                                      .at("signature")
                                      .get<std::string>();
    CHECK(signature.find_first_of("+/") != std::string::npos);

    MemoryFolder folder;
    for (const auto& [name, content] : files.items()) {
        folder.files[name] = content.get<std::string>();
    }
    const Verification verdict = Signer::verify_folder(folder.reader(), folder.names(), key1());
    CHECK(verdict.word == VerifyWord::verified);
    CHECK(bundle.at("bundle_sha256") == verdict.bundle_sha256);
    CHECK(bundle.at("key_id") == verdict.key_id);
}

TEST_CASE("cases.json is what the code makes, byte for byte", "[signer][vectors]")
{
    // After a deliberate change: rptests "[.write_shared_signing]".
    REQUIRE(rp::test::read_shared(kCasesFile) == file_text(cases_json()));
}

TEST_CASE("the shared cases expect every word, each failure at least once", "[signer][vectors]")
{
    const json cases = json::parse(rp::test::read_shared(kCasesFile)).at("cases");
    CHECK(cases.size() == 38);
    std::set<std::string> expected;
    std::set<std::string> names;
    std::map<std::string, int> count;
    for (const json& one : cases) {
        expected.insert(one.at("expect").get<std::string>());
        names.insert(one.at("name").get<std::string>());
        ++count[one.at("expect").get<std::string>()];
    }
    const std::vector<std::string>& words = rp::verify_words();
    CHECK(expected == std::set<std::string>(words.begin(), words.end()));
    CHECK(names.size() == cases.size());
    // The entry's list (point 6), and the second key given to the untouched folder.
    CHECK(count == std::map<std::string, int>{{"result_unreadable", 1},
                                              {"result_not_canonical", 12},
                                              {"result_schema", 1},
                                              {"attachment_twice", 1},
                                              {"screenshot_missing", 1},
                                              {"signature_file", 10},
                                              {"hash_mismatch", 2},
                                              {"wrong_key", 2},
                                              {"signature_invalid", 4},
                                              {"attachment_missing", 1},
                                              {"attachment_size", 1},
                                              {"attachment_hash", 1},
                                              {"verified", 1}});
    // Failures first, the untouched folder last.
    CHECK(cases.back().at("expect") == "verified");
    CHECK(cases.back().at("files").empty());
}

// Each case in a folder of its own on disk, through the real reader: what
// `rpworker signer verify` does, and what verify_bundle.py must answer alike.
TEST_CASE("the folder verifier answers every shared case with its word", "[signer][vectors]")
{
    const json keys = json::parse(rp::test::read_shared(kKeysFile));
    const json bundle = json::parse(rp::test::read_shared(kBundleFile));
    const json cases = json::parse(rp::test::read_shared(kCasesFile)).at("cases");
    REQUIRE_FALSE(cases.empty());

    for (const json& one : cases) {
        const std::string name = one.at("name").get<std::string>();
        CAPTURE(name);
        const TempDir dir;
        for (const auto& [file, content] : bundle.at("files").items()) {
            dir.write(file, content.get<std::string>());
        }
        for (const auto& [file, change] : one.at("files").items()) {
            if (change.is_null()) {
                REQUIRE(std::filesystem::remove(dir.path() / file));
            } else if (change.contains("text")) {
                dir.write(file, change.at("text").get<std::string>());
            } else {
                const std::optional<std::vector<unsigned char>> bytes =
                    rp::base64_decode(change.at("base64").get<std::string>());
                REQUIRE(bytes);
                dir.write(file, to_text(*bytes));
            }
        }
        const std::optional<PublicKey> key = PublicKey::from_pem(
            key_named(keys, one.at("public_key").get<std::string>())
                .at("public_key_pem")
                .get<std::string>());
        REQUIRE(key);
        const std::optional<std::vector<std::string>> names = rp::list_folder(dir.path());
        REQUIRE(names);

        const Verification verdict =
            Signer::verify_folder(rp::folder_reader(dir.path()), *names, *key);
        CHECK(rp::to_string(verdict.word) == one.at("expect").get<std::string>());
        if (verdict.word == VerifyWord::verified) {
            CHECK(bundle.at("bundle_sha256") == verdict.bundle_sha256);
            CHECK(bundle.at("key_id") == verdict.key_id);
            CHECK(verdict.notes.empty());
        }
    }
}

// Hidden: run by name only, after a deliberate change to the result
// (shared/testdata/result-v1/valid.json first) or to the signing rules, to
// write the shared signing documents again; the Cloud's test reads them.
TEST_CASE("write shared/testdata/signing-v1/ from what the code makes", "[.write_shared_signing]")
{
    const ordered_json bundle = bundle_json();
    const std::string signature =
        json::parse(bundle.at("files").at("signature.json").get<std::string>())
            .at("signature")
            .get<std::string>();
    // The URL-safe case needs one: change a made-up attachment's text until
    // the signature has it.
    REQUIRE(signature.find_first_of("+/") != std::string::npos);
    // All three texts first: a throw while one is made leaves the set as it was.
    const std::string keys_text = file_text(keys_json());
    const std::string bundle_text = file_text(bundle);
    const std::string cases_text = file_text(cases_json());
    write_shared(kKeysFile, keys_text);
    write_shared(kBundleFile, bundle_text);
    write_shared(kCasesFile, cases_text);
}
