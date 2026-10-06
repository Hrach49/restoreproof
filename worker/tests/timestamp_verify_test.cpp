// The folder verifier and the timestamp (W4.4, docs/decisions.md 2026-10-06
// W4.4, point 5): timestamp.tst checked after the attachments, three words,
// and what a verified folder says of its timestamp. The cases are
// shared/testdata/timestamp-v1/, which verify_bundle.py answers alike
// (cloud/tests/test_verify_bundle.py); their tokens come from the test-only
// TSA of tsa_lab.hpp, whose keys are published there and are no secret.

#include "../src/file_read.hpp"
#include "result_lab.hpp"
#include "signing_lab.hpp"
#include "test_support.hpp"
#include "tsa_lab.hpp"

#include <rp/base64.hpp>
#include <rp/rfc3161.hpp>
#include <rp/signer.hpp>

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using nlohmann::json;
using nlohmann::ordered_json;
using rp::PublicKey;
using rp::Signer;
using rp::TimestampState;
using rp::TimestampTrust;
using rp::Verification;
using rp::VerifyWord;
using rp::test::FakeRfc3161;
using rp::test::MemoryFolder;
using rp::test::Rfc3161Fault;
using rp::test::TempDir;
using rp::test::TestTsa;

constexpr const char* kSigningKeys = "testdata/signing-v1/keys.json";
constexpr const char* kBundle = "testdata/signing-v1/bundle.json";
constexpr const char* kKeysFile = "testdata/timestamp-v1/keys.json";
constexpr const char* kCasesFile = "testdata/timestamp-v1/cases.json";
const std::string kStampedAt = "2026-10-06T12:00:00Z";

json bundle()
{
    return json::parse(rp::test::read_shared(kBundle));
}

std::array<unsigned char, 32> bundle_digest()
{
    const std::vector<unsigned char> bytes =
        rp::test::bytes_from_hex(bundle().at("bundle_sha256").get<std::string>());
    std::array<unsigned char, 32> digest{};
    std::copy(bytes.begin(), bytes.end(), digest.begin());
    return digest;
}

PublicKey key1()
{
    return rp::test::public_key_of(rp::test::signing_key());
}

// The signed folder of signing-v1, in memory.
MemoryFolder signed_folder()
{
    MemoryFolder folder;
    const json signed_bundle = bundle();
    for (const auto& [name, content] : signed_bundle.at("files").items()) {
        folder.files[name] = content.get<std::string>();
    }
    return folder;
}

const TestTsa& tsa()
{
    static const TestTsa one;
    return one;
}

TimestampTrust trust(std::string ca_pem, const rp::Rfc3161& primitive = rp::openssl_rfc3161())
{
    return {std::move(ca_pem), &primitive};
}

std::string base64_of(const std::string& bytes)
{
    return rp::base64_encode(std::vector<unsigned char>(bytes.begin(), bytes.end()));
}

std::string flipped(std::string bytes, std::size_t at)
{
    bytes[at] = static_cast<char>(bytes[at] ^ 0x01);
    return bytes;
}

std::string file_text(const ordered_json& document)
{
    return document.dump(2) + "\n";
}

void write_shared(const char* relative, const std::string& text)
{
    const std::filesystem::path path = std::filesystem::path{RP_SHARED_DIR} / relative;
    std::filesystem::create_directories(path.parent_path());
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << text;
    file.close();
    REQUIRE(file);
}

} // namespace

// --- Failure paths, over a folder in memory -----------------------------------

TEST_CASE("a timestamp.tst that isn't one token is timestamp_file, with or without a CA",
          "[signer][timestamp]")
{
    const std::string good = tsa().token(bundle_digest());
    const std::string response = tsa().respond(rp::openssl_rfc3161().request(bundle_digest(), 1));
    const std::string content =
        GENERATE_COPY(std::string{}, std::string{"not a token"}, good + std::string(1, '\0'),
                      good.substr(0, good.size() - 1), response,
                      std::string(rp::kMaxTimestampFileBytes + 1, '\x30'));
    const bool with_ca = GENERATE(true, false);
    MemoryFolder folder = signed_folder();
    folder.files["timestamp.tst"] = content;

    const Verification verdict = Signer::verify_folder(
        folder.reader(), folder.names(), key1(),
        with_ca ? trust(tsa().root_pem()) : TimestampTrust{});

    CHECK(verdict.word == VerifyWord::timestamp_file);
    CHECK(verdict.bundle_sha256.empty());
    CHECK(verdict.timestamp == TimestampState::none);
}

TEST_CASE("a token that is listed and can't be read is timestamp_file", "[signer][timestamp]")
{
    MemoryFolder folder = signed_folder();
    std::vector<std::string> names = folder.names();
    names.push_back("timestamp.tst"); // listed, and the reader has no such file

    CHECK(Signer::verify_folder(folder.reader(), names, key1(), trust(tsa().root_pem())).word ==
          VerifyWord::timestamp_file);
    // Read with the token's own limit.
    CHECK(folder.asked->back() ==
          std::pair<std::string, std::uintmax_t>{"timestamp.tst", rp::kMaxTimestampFileBytes});
}

TEST_CASE("a token over another hash is timestamp_mismatch, with or without a CA",
          "[signer][timestamp]")
{
    const bool with_ca = GENERATE(true, false);
    MemoryFolder folder = signed_folder();
    SECTION("another digest")
    {
        folder.files["timestamp.tst"] = tsa().token(rp::test::kDigestAbc);
    }
    SECTION("a SHA-512 imprint")
    {
        folder.files["timestamp.tst"] = rp::test::sha512_token(tsa());
    }

    CHECK(Signer::verify_folder(folder.reader(), folder.names(), key1(),
                                with_ca ? trust(tsa().root_pem()) : TimestampTrust{})
              .word == VerifyWord::timestamp_mismatch);
}

TEST_CASE("a token that doesn't verify under the caller's CA is timestamp_invalid",
          "[signer][timestamp]")
{
    MemoryFolder folder = signed_folder();
    const std::string good = tsa().token(bundle_digest());
    std::string ca = tsa().root_pem();
    SECTION("another root")
    {
        folder.files["timestamp.tst"] = good;
        ca = TestTsa("another test root (not a secret)").root_pem();
    }
    SECTION("one bit of the signature flipped")
    {
        folder.files["timestamp.tst"] = flipped(good, good.size() - 5);
    }
    SECTION("stamped before its certificates were valid")
    {
        TestTsa early(tsa().root_pem(), tsa().tsa_cert_pem_text(), tsa().tsa_key_pem_text());
        early.time = rp::test::kTestTsaNotBefore - 86400;
        folder.files["timestamp.tst"] = early.token(bundle_digest());
    }
    SECTION("no certificate in the token")
    {
        folder.files["timestamp.tst"] = rp::test::token_without_certificate(tsa(), bundle_digest());
    }
    SECTION("a CA file that holds no certificate")
    {
        folder.files["timestamp.tst"] = good;
        ca = "not a certificate";
    }

    const Verification verdict =
        Signer::verify_folder(folder.reader(), folder.names(), key1(), trust(ca));

    CHECK(verdict.word == VerifyWord::timestamp_invalid);
    CHECK(verdict.bundle_sha256.empty());
}

TEST_CASE("the timestamp is checked last: an earlier failure is the word, and the token isn't "
          "even read",
          "[signer][timestamp]")
{
    MemoryFolder folder = signed_folder();
    folder.files["timestamp.tst"] = "not a token";
    VerifyWord expected = VerifyWord::verified;
    SECTION("an attachment changed")
    {
        folder.files["items.csv"].back() = 'X';
        expected = VerifyWord::attachment_hash;
    }
    SECTION("an attachment gone")
    {
        folder.files.erase("veeam-session.log");
        expected = VerifyWord::attachment_missing;
    }
    SECTION("the signature file gone")
    {
        folder.files.erase("signature.json");
        expected = VerifyWord::signature_file;
    }
    SECTION("another key")
    {
        expected = VerifyWord::wrong_key;
    }
    const PublicKey key =
        expected == VerifyWord::wrong_key
            ? rp::test::public_key_of(rp::test::signing_key(rp::test::signing_key2_base64()))
            : key1();

    CHECK(Signer::verify_folder(folder.reader(), folder.names(), key, trust(tsa().root_pem()))
              .word == expected);

    for (const auto& [name, limit] : *folder.asked) {
        CHECK(name != "timestamp.tst");
    }
}

TEST_CASE("the primitive's answers are the verifier's words, and what it throws is let through",
          "[signer][timestamp]")
{
    MemoryFolder folder = signed_folder();
    folder.files["timestamp.tst"] = tsa().token(bundle_digest());
    FakeRfc3161 primitive;
    const TimestampTrust with = trust(tsa().root_pem(), primitive);
    const auto word = [&] {
        return Signer::verify_folder(folder.reader(), folder.names(), key1(), with).word;
    };

    CHECK(word() == VerifyWord::verified);
    primitive.fault = Rfc3161Fault::token_none;
    CHECK(word() == VerifyWord::timestamp_file);
    primitive.fault = Rfc3161Fault::verify_false;
    CHECK(word() == VerifyWord::timestamp_invalid);
    // A failure of the verifier is never a verdict.
    primitive.fault = Rfc3161Fault::token_throws;
    CHECK_THROWS_AS(word(), std::runtime_error);
    primitive.fault = Rfc3161Fault::verify_throws;
    CHECK_THROWS_AS(word(), std::runtime_error);
}

// --- What a verified folder says of its timestamp ---------------------------------

TEST_CASE("no timestamp.tst: verified, timestamp none, with or without a CA",
          "[signer][timestamp]")
{
    const bool with_ca = GENERATE(true, false);
    MemoryFolder folder = signed_folder();
    SECTION("no such file") {}
    SECTION("another case of the name is another file: a note, and no timestamp")
    {
        folder.files["TIMESTAMP.TST"] = "not a token";
    }

    const Verification verdict = Signer::verify_folder(
        folder.reader(), folder.names(), key1(),
        with_ca ? trust(tsa().root_pem()) : TimestampTrust{});

    CHECK(verdict.word == VerifyWord::verified);
    CHECK(verdict.timestamp == TimestampState::none);
    CHECK(verdict.timestamp_time == 0);
    CHECK(rp::timestamp_field(verdict) == "none");
    CHECK(verdict.notes == (folder.files.contains("TIMESTAMP.TST")
                                ? std::vector<std::string>{"TIMESTAMP.TST"}
                                : std::vector<std::string>{}));
}

TEST_CASE("a good token under the caller's CA: verified, with the token's time, and no note",
          "[signer][timestamp]")
{
    MemoryFolder folder = signed_folder();
    folder.files["timestamp.tst"] = tsa().token(bundle_digest());
    std::string ca = tsa().root_pem();
    SECTION("the root") {}
    SECTION("the TSA's own certificate")
    {
        ca = tsa().tsa_cert_pem_text();
    }
    SECTION("another root beside it")
    {
        ca = TestTsa("another test root (not a secret)").root_pem() + tsa().root_pem();
    }

    const Verification verdict =
        Signer::verify_folder(folder.reader(), folder.names(), key1(), trust(ca));

    CHECK(verdict.word == VerifyWord::verified);
    CHECK(bundle().at("bundle_sha256") == verdict.bundle_sha256);
    CHECK(verdict.timestamp == TimestampState::checked);
    CHECK(verdict.timestamp_time == rp::test::kTestTsaTime);
    CHECK(rp::timestamp_field(verdict) == kStampedAt);
    CHECK(verdict.notes.empty());
}

TEST_CASE("a good token and no CA: verified, timestamp unchecked, and the primitive never asked "
          "to verify",
          "[signer][timestamp]")
{
    MemoryFolder folder = signed_folder();
    folder.files["timestamp.tst"] = tsa().token(bundle_digest());
    FakeRfc3161 primitive(Rfc3161Fault::verify_throws);

    const Verification verdict =
        Signer::verify_folder(folder.reader(), folder.names(), key1(), {std::nullopt, &primitive});

    CHECK(verdict.word == VerifyWord::verified);
    CHECK(verdict.timestamp == TimestampState::unchecked);
    CHECK(verdict.timestamp_time == rp::test::kTestTsaTime);
    CHECK(rp::timestamp_field(verdict) == "unchecked");
    CHECK(verdict.notes.empty());
}

TEST_CASE("the words are the documented sixteen, the timestamp's three last", "[signer][timestamp]")
{
    CHECK(rp::verify_words() ==
          std::vector<std::string>{"verified", "result_unreadable", "result_not_canonical",
                                   "result_schema", "attachment_twice", "screenshot_missing",
                                   "signature_file", "hash_mismatch", "wrong_key",
                                   "signature_invalid", "attachment_missing", "attachment_size",
                                   "attachment_hash", "timestamp_file", "timestamp_mismatch",
                                   "timestamp_invalid"});
    CHECK(rp::to_string(VerifyWord::timestamp_file) == "timestamp_file");
    CHECK(rp::to_string(VerifyWord::timestamp_mismatch) == "timestamp_mismatch");
    CHECK(rp::to_string(VerifyWord::timestamp_invalid) == "timestamp_invalid");
}

// --- The shared vectors -------------------------------------------------------------

namespace {

// keys.json: the published test TSA. Its tokens are in cases.json.
ordered_json keys_json(const TestTsa& one, const TestTsa& other)
{
    return {{"description",
             "The test-only timestamp authority of shared/testdata/timestamp-v1/ (W4.4): a root, "
             "a TSA certificate under it with its private key, and a second root that issued "
             "nothing here. Made for these vectors, published on purpose and never a secret; "
             "nothing but a test trusts them. Written once by the Worker's hidden test `rptests "
             "\"[.write_shared_timestamp]\"`. A token is signed with ECDSA, so writing the files "
             "again gives other bytes: the files are verified, never compared with a new run."},
            {"root_pem", one.root_pem()},
            {"tsa_certificate_pem", one.tsa_cert_pem_text()},
            {"tsa_private_key_pem", one.tsa_key_pem_text()},
            {"other_root_pem", other.root_pem()}};
}

ordered_json a_case(const char* name, const char* expect, const char* tsa_ca,
                    ordered_json files, const char* timestamp = nullptr)
{
    ordered_json one = {{"name", name}, {"expect", expect}};
    if (timestamp != nullptr) {
        one["timestamp"] = timestamp;
    }
    one["public_key"] = std::string{rp::test::kSigningKey1Name};
    one["tsa_ca"] = tsa_ca == nullptr ? ordered_json(nullptr) : ordered_json(tsa_ca);
    one["files"] = std::move(files);
    return one;
}

ordered_json token_file(const std::string& bytes)
{
    return {{"timestamp.tst", {{"base64", base64_of(bytes)}}}};
}

ordered_json cases_json(const TestTsa& one)
{
    const std::array<unsigned char, 32> digest = bundle_digest();
    const std::string good = one.token(digest);
    const std::string response = one.respond(rp::openssl_rfc3161().request(digest, 1));
    TestTsa early(one.root_pem(), one.tsa_cert_pem_text(), one.tsa_key_pem_text());
    early.time = rp::test::kTestTsaNotBefore - 86400;
    // The TSTInfo's serial number (4404): changing it changes the bytes the
    // signer's messageDigest covers, and nothing a verifier compares first.
    const std::size_t serial = good.find(std::string("\x02\x02\x11\x34", 4));
    REQUIRE(serial != std::string::npos);
    std::string csv = bundle().at("files").at("items.csv").get<std::string>();
    csv.back() = 'X';
    ordered_json bad_attachment = token_file("not a token");
    bad_attachment["items.csv"] = {{"text", csv}};

    ordered_json cases = ordered_json::array();
    // Failures first.
    cases.push_back(a_case("token-empty", "timestamp_file", "root",
                           {{"timestamp.tst", {{"text", ""}}}}));
    cases.push_back(a_case("token-is-text", "timestamp_file", "root",
                           {{"timestamp.tst", {{"text", "not a token\n"}}}}));
    cases.push_back(a_case("token-is-the-whole-response", "timestamp_file", "root",
                           token_file(response)));
    cases.push_back(a_case("token-with-a-byte-after-it", "timestamp_file", "root",
                           token_file(good + std::string(1, '\0'))));
    cases.push_back(a_case("token-cut-short", "timestamp_file", "root",
                           token_file(good.substr(0, good.size() - 1))));
    cases.push_back(a_case("token-over-64-kib", "timestamp_file", "root",
                           token_file(std::string(rp::kMaxTimestampFileBytes + 1, '\x30'))));
    cases.push_back(a_case("token-is-text-and-no-ca", "timestamp_file", nullptr,
                           {{"timestamp.tst", {{"text", "not a token\n"}}}}));
    cases.push_back(a_case("token-over-another-hash", "timestamp_mismatch", "root",
                           token_file(one.token(rp::test::kDigestAbc))));
    cases.push_back(a_case("token-over-another-hash-and-no-ca", "timestamp_mismatch", nullptr,
                           token_file(one.token(rp::test::kDigestAbc))));
    cases.push_back(a_case("token-with-a-sha512-imprint", "timestamp_mismatch", "root",
                           token_file(rp::test::sha512_token(one))));
    cases.push_back(a_case("token-under-another-root", "timestamp_invalid", "other_root",
                           token_file(good)));
    cases.push_back(a_case("token-signature-bit-flipped", "timestamp_invalid", "root",
                           token_file(flipped(good, good.size() - 5))));
    cases.push_back(a_case("token-serial-changed", "timestamp_invalid", "root",
                           token_file(flipped(good, serial + 3))));
    cases.push_back(a_case("token-stamped-before-its-certificates", "timestamp_invalid", "root",
                           token_file(early.token(digest))));
    cases.push_back(a_case("token-without-its-certificate", "timestamp_invalid", "root",
                           token_file(rp::test::token_without_certificate(one, digest))));
    // The timestamp is checked last.
    cases.push_back(a_case("attachment-changed-beside-a-bad-token", "attachment_hash", "root",
                           bad_attachment));
    // Verified, and what the line's third field is.
    cases.push_back(a_case("no-token", "verified", "root", ordered_json::object(), "none"));
    cases.push_back(a_case("no-token-and-no-ca", "verified", nullptr, ordered_json::object(),
                           "none"));
    cases.push_back(a_case("token-under-another-name", "verified", "root",
                           {{"TIMESTAMP.TST", {{"base64", base64_of(good)}}}}, "none"));
    cases.push_back(a_case("token-and-no-ca", "verified", nullptr, token_file(good), "unchecked"));
    cases.push_back(a_case("token-under-the-tsa-certificate", "verified", "tsa_certificate",
                           token_file(good), kStampedAt.c_str()));
    cases.push_back(a_case("token-under-both-roots", "verified", "both_roots", token_file(good),
                           kStampedAt.c_str()));
    cases.push_back(a_case("token", "verified", "root", token_file(good), kStampedAt.c_str()));

    return {{"description",
             "Run folders with a timestamp (W4.4): each case is signing-v1's signed folder "
             "(`bundle`), with `files` added, replaced ({\"text\"} or {\"base64\"}) or removed "
             "(null), the public key `public_key` of signing-v1/keys.json, and as the TSA's CA "
             "the PEM `tsa_ca` names in timestamp-v1/keys.json (`root`, `other_root`, "
             "`tsa_certificate`, or `both_roots`: the other root and then the root), or none "
             "(null). `expect` is the word both verifiers answer; with `verified`, `timestamp` "
             "is the third field of their line, `verified <bundle_sha256> key <key_id> "
             "timestamp <timestamp>`. The tokens are the test-only TSA's and stamp " +
                 kStampedAt +
                 "; a chain is checked at the token's own time, so they never expire. Written "
                 "once by the Worker's hidden test `rptests \"[.write_shared_timestamp]\"`; "
                 "ECDSA makes every run's tokens different, so the file is verified by both "
                 "builds and never regenerated in a test."},
            {"bundle", "../signing-v1/bundle.json"},
            {"signing_keys", "../signing-v1/keys.json"},
            {"keys", "keys.json"},
            {"cases", cases}};
}

std::string ca_named(const json& keys, const json& name)
{
    const std::string which = name.get<std::string>();
    if (which == "both_roots") {
        return keys.at("other_root_pem").get<std::string>() + keys.at("root_pem").get<std::string>();
    }
    return keys.at(which == "tsa_certificate" ? "tsa_certificate_pem" : which + "_pem")
        .get<std::string>();
}

} // namespace

TEST_CASE("the shared timestamp cases expect each of the three words and each third field",
          "[signer][timestamp][vectors]")
{
    const json cases = json::parse(rp::test::read_shared(kCasesFile)).at("cases");
    CHECK(cases.size() == 23);
    std::map<std::string, int> count;
    std::set<std::string> names;
    std::set<std::string> fields;
    for (const json& one : cases) {
        ++count[one.at("expect").get<std::string>()];
        names.insert(one.at("name").get<std::string>());
        CHECK(one.contains("timestamp") == (one.at("expect") == "verified"));
        if (one.contains("timestamp")) {
            fields.insert(one.at("timestamp").get<std::string>());
        }
    }
    CHECK(names.size() == cases.size());
    CHECK(count == std::map<std::string, int>{{"timestamp_file", 7},
                                              {"timestamp_mismatch", 3},
                                              {"timestamp_invalid", 5},
                                              {"attachment_hash", 1},
                                              {"verified", 7}});
    CHECK(fields == std::set<std::string>{"none", "unchecked", kStampedAt});
    // Failures first, the stamped folder last.
    CHECK(cases.front().at("expect") == "timestamp_file");
    CHECK(cases.back().at("name") == "token");
}

TEST_CASE("the published test TSA's keys are what the cases' tokens were made with",
          "[signer][timestamp][vectors]")
{
    const json keys = json::parse(rp::test::read_shared(kKeysFile));
    const rp::Rfc3161& ts = rp::openssl_rfc3161();
    CHECK(ts.certificates_in(keys.at("root_pem").get<std::string>()) == 1);
    CHECK(ts.certificates_in(keys.at("tsa_certificate_pem").get<std::string>()) == 1);
    CHECK(ts.certificates_in(keys.at("other_root_pem").get<std::string>()) == 1);
    // The published key still stamps: a new token verifies under the published root.
    const TestTsa published(keys.at("root_pem").get<std::string>(),
                            keys.at("tsa_certificate_pem").get<std::string>(),
                            keys.at("tsa_private_key_pem").get<std::string>());
    CHECK(ts.verify_token(published.token(bundle_digest()),
                          keys.at("root_pem").get<std::string>()));
    CHECK_FALSE(ts.verify_token(published.token(bundle_digest()),
                                keys.at("other_root_pem").get<std::string>()));
}

// Each case in a folder of its own on disk, through the real reader: what
// `rpworker signer verify --tsa-ca` does, and what verify_bundle.py must
// answer alike.
TEST_CASE("the folder verifier answers every shared timestamp case with its word and field",
          "[signer][timestamp][vectors]")
{
    const json signing_keys = json::parse(rp::test::read_shared(kSigningKeys));
    const json keys = json::parse(rp::test::read_shared(kKeysFile));
    const json signed_bundle = bundle();
    const json cases = json::parse(rp::test::read_shared(kCasesFile)).at("cases");
    REQUIRE_FALSE(cases.empty());

    for (const json& one : cases) {
        const std::string name = one.at("name").get<std::string>();
        CAPTURE(name);
        const TempDir dir;
        for (const auto& [file, content] : signed_bundle.at("files").items()) {
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
                dir.write(file, std::string(bytes->begin(), bytes->end()));
            }
        }
        std::string public_pem;
        for (const json& key : signing_keys.at("keys")) {
            if (key.at("name") == one.at("public_key")) {
                public_pem = key.at("public_key_pem").get<std::string>();
            }
        }
        const std::optional<PublicKey> key = PublicKey::from_pem(public_pem);
        REQUIRE(key);
        const std::optional<std::vector<std::string>> names = rp::list_folder(dir.path());
        REQUIRE(names);
        TimestampTrust with;
        if (!one.at("tsa_ca").is_null()) {
            with.ca_pem = ca_named(keys, one.at("tsa_ca"));
        }

        const Verification verdict =
            Signer::verify_folder(rp::folder_reader(dir.path()), *names, *key, with);

        CHECK(rp::to_string(verdict.word) == one.at("expect").get<std::string>());
        if (verdict.word == VerifyWord::verified) {
            CHECK(signed_bundle.at("bundle_sha256") == verdict.bundle_sha256);
            CHECK(rp::timestamp_field(verdict) == one.at("timestamp").get<std::string>());
        }
    }
}

// Hidden: run by name only, once, or after a deliberate change to the token's
// rules or to signing-v1's bundle (its hash is what the tokens stamp). The
// Cloud's test reads the two files.
TEST_CASE("write shared/testdata/timestamp-v1/ with a new test TSA", "[.write_shared_timestamp]")
{
    const TestTsa one("RestoreProof test TSA root (timestamp-v1, not a secret)");
    const TestTsa other("RestoreProof other test TSA root (timestamp-v1, not a secret)");
    // Both texts first: a throw while one is made leaves the pair as it was.
    const std::string keys_text = file_text(keys_json(one, other));
    const std::string cases_text = file_text(cases_json(one));
    write_shared(kKeysFile, keys_text);
    write_shared(kCasesFile, cases_text);
}
