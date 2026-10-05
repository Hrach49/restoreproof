// `rpworker signer public-key` and `rpworker signer verify` (W4.3,
// docs/decisions.md 2026-10-05, point 4). Every folder here is a temp folder
// made from shared/testdata/signing-v1/; the only keys are RFC 8032's
// published test keys.

#include <rp/base64.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>
#include <rp/signer.hpp>
#include <rp/signer_command.hpp>

#include "result_lab.hpp"
#include "signing_lab.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using nlohmann::json;
using rp::test::TempDir;
using Args = std::vector<std::string_view>;

namespace {

const std::string kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] | "
    "rpworker veeam list [--config <path>] [--record <dir>] | "
    "rpworker graph list [--hash] [--config <path>] [--record <dir>] | "
    "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
    "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] "
    "[--record <dir>] | "
    "rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
    "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] "
    "[--record <dir>] [--json <file> | --evidence <dir>] | "
    "rpworker signer public-key | rpworker signer verify <folder> --public-key <pem file>\n";

constexpr const char* kKeysFile = "testdata/signing-v1/keys.json";
constexpr const char* kBundleFile = "testdata/signing-v1/bundle.json";
constexpr const char* kCasesFile = "testdata/signing-v1/cases.json";

// RFC 8032 tests 1 and 2, as shared/testdata/signing-v1/keys.json has them.
const std::string kKey1Pem = "-----BEGIN PUBLIC KEY-----\n"
                             "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
                             "-----END PUBLIC KEY-----\n";
const std::string kKey1Id = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";
const std::string kKey2Pem = "-----BEGIN PUBLIC KEY-----\n"
                             "MCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=\n"
                             "-----END PUBLIC KEY-----\n";
const std::string kKey2Id = "deb2ded39dc26fce0e6085b6fc34bf6b5941913bbfe2ea614113cff9e004c170";

const std::string kKeyNotSet = "config error: RP_SIGNING_KEY_BASE64 is not set\n";
const std::string kKeyNotAKey = "config error: RP_SIGNING_KEY_BASE64 is not an Ed25519 private key "
                                "(Base64 of PKCS#8 DER)\n";

std::string utf8(const std::filesystem::path& path)
{
    return rp::test::narrow(path.wstring());
}

// What one run of the command gave.
struct Ran {
    int code = -1;
    std::string out;
    std::string err;
    int secrets_asked = 0;
};

// `rpworker signer <args>` with the signing key variable holding `key`.
Ran run(const Args& args, std::optional<std::string> key = std::nullopt)
{
    Ran ran;
    rp::SignerCommandEnv env;
    env.load_secrets = [&ran, key] {
        ++ran.secrets_asked;
        rp::Secrets secrets;
        // The other secrets are none of this command's business.
        secrets.veeam_password = "a Veeam password";
        secrets.signing_key_base64 = key;
        return secrets;
    };
    std::ostringstream out;
    std::ostringstream err;
    ran.code = rp::run_signer_command(args, out, err, env);
    ran.out = out.str();
    ran.err = err.str();
    return ran;
}

// The signed folder of shared/testdata/signing-v1/bundle.json, on disk.
void write_bundle(const TempDir& dir)
{
    const json bundle = json::parse(rp::test::read_shared(kBundleFile));
    for (const auto& [file, content] : bundle.at("files").items()) {
        dir.write(file, content.get<std::string>());
    }
}

std::string bundle_sha256()
{
    return json::parse(rp::test::read_shared(kBundleFile)).at("bundle_sha256").get<std::string>();
}

std::string verified_line(const std::string& key_id = kKey1Id)
{
    return "verified " + bundle_sha256() + " key " + key_id + "\n";
}

std::string pem_of(const json& keys, const std::string& name)
{
    std::string pem;
    for (const json& key : keys.at("keys")) {
        if (key.at("name") == name) {
            pem = key.at("public_key_pem").get<std::string>();
        }
    }
    REQUIRE_FALSE(pem.empty());
    return pem;
}

} // namespace

// --- the arguments -------------------------------------------------------------------

TEST_CASE("signer: a command line it doesn't understand is usage, 64, and nothing is read",
          "[signer_command]")
{
    const Args args = GENERATE(
        Args{},
        Args{""},
        Args{"sign"},
        Args{"new-key"},
        Args{"Public-Key"},
        Args{"public-key", "extra"},
        Args{"public-key", "--public-key", "key.pem"},
        Args{"verify"},
        Args{"Verify", "folder", "--public-key", "key.pem"},
        Args{"verify", "folder"},
        Args{"verify", "--public-key", "key.pem"},
        Args{"verify", "folder", "--public-key"},
        Args{"verify", "folder", "key.pem"},
        Args{"verify", "folder", "other", "--public-key", "key.pem"},
        Args{"verify", "folder", "--public-key", "key.pem", "other"},
        Args{"verify", "folder", "--public-key", "key.pem", "--public-key", "key.pem"},
        Args{"verify", "", "--public-key", "key.pem"},
        Args{"verify", "folder", "--public-key", ""},
        Args{"verify", "folder", "--Public-Key", "key.pem"},
        Args{"verify", "folder", "--config", "config.json", "--public-key", "key.pem"});
    CAPTURE(args);

    const Ran ran = run(args, std::string{rp::test::kSigningKey1Base64});
    CHECK(ran.code == 64);
    CHECK(ran.out.empty());
    CHECK(ran.err == kUsage);
    CHECK(ran.secrets_asked == 0);
}

// --- signer public-key ---------------------------------------------------------------

TEST_CASE("signer public-key: no key in the variable is a config error, 1", "[signer_command]")
{
    const std::optional<std::string> value = GENERATE(std::optional<std::string>{},
                                                      std::optional<std::string>{""});
    const Ran ran = run({"public-key"}, value);
    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == kKeyNotSet);
    CHECK(ran.secrets_asked == 1);
}

TEST_CASE("signer public-key: a value that isn't an Ed25519 private key is a config error, 1, "
          "and is never shown",
          "[signer_command]")
{
    const std::string seed1{rp::test::kSigningSeed1Hex};
    const std::string value = GENERATE_COPY(
        std::string{"not Base64 at all!"},
        // 47 and 49 bytes.
        rp::base64_encode(rp::test::bytes_from_hex(std::string{rp::test::kPkcs8PrefixHex} +
                                                   seed1.substr(2))),
        rp::base64_encode(rp::test::bytes_from_hex(std::string{rp::test::kPkcs8PrefixHex} +
                                                   seed1 + "00")),
        // X25519's header.
        rp::base64_encode(
            rp::test::bytes_from_hex("302e020100300506032b656e04220420" + seed1)),
        // The seed alone, and the PEM OpenSSL writes instead of its body line.
        rp::base64_encode(rp::test::bytes_from_hex(seed1)),
        "-----BEGIN PRIVATE KEY-----\n" + std::string{rp::test::kSigningKey1Base64} +
            "\n-----END PRIVATE KEY-----\n",
        std::string{rp::test::kSigningKey1Base64} + "\n");
    CAPTURE(value);

    const Ran ran = run({"public-key"}, value);
    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == kKeyNotAKey);
}

TEST_CASE("signer public-key: secrets that can't be read are a config error, 1",
          "[signer_command]")
{
    rp::SignerCommandEnv env;
    env.load_secrets = []() -> rp::Secrets {
        throw rp::ConfigError("RP_SIGNING_KEY_BASE64",
                              "RP_SIGNING_KEY_BASE64 is not valid Unicode");
    };
    std::ostringstream out;
    std::ostringstream err;
    const Args args{"public-key"};
    CHECK(rp::run_signer_command(args, out, err, env) == 1);
    CHECK(out.str().empty());
    CHECK(err.str() == "config error: RP_SIGNING_KEY_BASE64 is not valid Unicode\n");
}

TEST_CASE("signer public-key: any other failure is let out, for run_cli to report",
          "[signer_command]")
{
    rp::SignerCommandEnv env;
    env.load_secrets = []() -> rp::Secrets { throw std::runtime_error("holds a secret"); };
    std::ostringstream out;
    std::ostringstream err;
    const Args args{"public-key"};
    CHECK_THROWS_AS(rp::run_signer_command(args, out, err, env), std::runtime_error);
    CHECK(out.str().empty());
    CHECK(err.str().empty());
}

TEST_CASE("signer public-key prints the public key's PEM alone on stdout and its key ID on "
          "stderr, never the private key",
          "[signer_command]")
{
    SECTION("RFC 8032 test 1")
    {
        const Ran ran = run({"public-key"}, std::string{rp::test::kSigningKey1Base64});
        CHECK(ran.code == 0);
        // stdout is a key file as it is: `signer public-key > worker.pub.pem`.
        CHECK(ran.out == kKey1Pem);
        CHECK(ran.err == "key " + kKey1Id + "\n");
        CHECK(ran.secrets_asked == 1);

        // Neither the variable's text nor the seed in another shape.
        CHECK_THAT(ran.out, !ContainsSubstring(std::string{rp::test::kSigningKey1Base64}));
        const rp::SigningKey key = rp::test::signing_key();
        REQUIRE(key.secret_shapes().size() == 2);
        for (const std::string& shape : key.secret_shapes()) {
            CHECK_THAT(ran.out, !ContainsSubstring(shape));
        }
        CHECK_THAT(ran.out, !ContainsSubstring("PRIVATE"));
        CHECK_THAT(ran.err, !ContainsSubstring(std::string{rp::test::kSigningKey1Base64}));
        for (const std::string& shape : key.secret_shapes()) {
            CHECK_THAT(ran.err, !ContainsSubstring(shape));
        }

        // What it prints is the key a verifier takes: the whole of stdout, as
        // a file, given to `signer verify` on the shared bundle.
        const std::optional<rp::PublicKey> pub = rp::PublicKey::from_pem(ran.out);
        REQUIRE(pub);
        CHECK(pub->key_id() == kKey1Id);
        const TempDir keys;
        const std::string file = utf8(keys.write("exported.pem", ran.out));
        const TempDir dir;
        write_bundle(dir);
        const Ran verified = run({"verify", utf8(dir.path()), "--public-key", file});
        CHECK(verified.code == 0);
        CHECK(verified.out == verified_line());
        CHECK(verified.err.empty());
        // And as a console redirect writes it, with CRLF line ends.
        std::string crlf;
        for (const char c : ran.out) {
            crlf += c == '\n' ? std::string{"\r\n"} : std::string{c};
        }
        const std::string crlf_file = utf8(keys.write("exported-crlf.pem", crlf));
        CHECK(run({"verify", utf8(dir.path()), "--public-key", crlf_file}).out == verified_line());
    }
    SECTION("RFC 8032 test 2")
    {
        const Ran ran = run({"public-key"}, rp::test::signing_key2_base64());
        CHECK(ran.code == 0);
        CHECK(ran.out == kKey2Pem);
        CHECK(ran.err == "key " + kKey2Id + "\n");
    }
}

TEST_CASE("signer public-key: an answer that didn't reach stdout isn't one", "[signer_command]")
{
    rp::SignerCommandEnv env;
    env.load_secrets = [] {
        rp::Secrets secrets;
        secrets.signing_key_base64 = std::string{rp::test::kSigningKey1Base64};
        return secrets;
    };
    std::ostringstream out;
    out.setstate(std::ios::failbit);
    std::ostringstream err;
    const Args args{"public-key"};
    CHECK(rp::run_signer_command(args, out, err, env) == 1);
    // No `key <key_id>` line for a key that wasn't printed.
    CHECK(err.str() == "signer error: the answer couldn't be written\n");
}

TEST_CASE("the real signer environment reads the secrets from the process environment",
          "[signer_command]")
{
    const rp::test::ScopedEnv scoped(rp::kEnvSigningKeyBase64,
                                     std::string{rp::test::kSigningKey1Base64});
    const rp::SignerCommandEnv env = rp::default_signer_command_env();
    REQUIRE(env.load_secrets);
    CHECK(env.load_secrets().signing_key_base64 == std::string{rp::test::kSigningKey1Base64});
}

// --- signer verify: no answer could be made, exit 1 ----------------------------------

TEST_CASE("signer verify: a key file that can't be read or isn't a public key is exit 1",
          "[signer_command]")
{
    const TempDir dir;
    write_bundle(dir);
    const TempDir keys;
    const std::string folder = utf8(dir.path());

    SECTION("a path that isn't UTF-8")
    {
        const Ran ran = run({"verify", folder, "--public-key", "key\xff.pem"});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: the --public-key path is not valid UTF-8\n");
    }
    SECTION("no such file")
    {
        const std::string file = utf8(keys.path() / "no-such-key.pem");
        const Ran ran = run({"verify", folder, "--public-key", file});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: --public-key " + file + ": the file can't be read\n");
    }
    SECTION("a folder")
    {
        const std::string file = utf8(keys.path());
        const Ran ran = run({"verify", folder, "--public-key", file});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: --public-key " + file + ": the file can't be read\n");
    }
    SECTION("one byte over the limit, though a key with white space after it")
    {
        const std::string padded =
            kKey1Pem + std::string(rp::kMaxPublicKeyFileBytes + 1 - kKey1Pem.size(), '\n');
        const std::string file = utf8(keys.write("key.pem", padded));
        const Ran ran = run({"verify", folder, "--public-key", file});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: --public-key " + file + ": the file can't be read\n");
    }
    SECTION("not a public key in PEM")
    {
        const std::string content = GENERATE_COPY(
            std::string{},
            std::string{"hello\n"},
            // The private key's PEM, and the variable's own line.
            "-----BEGIN PRIVATE KEY-----\n" + std::string{rp::test::kSigningKey1Base64} +
                "\n-----END PRIVATE KEY-----\n",
            std::string{rp::test::kSigningKey1Base64},
            // Two keys, and the key with a line after it (what `signer
            // public-key` printed to stdout before the W4.3 review).
            kKey1Pem + kKey2Pem,
            kKey1Pem + "key " + kKey1Id + "\n",
            // The body cut by one group.
            std::string{"-----BEGIN PUBLIC KEY-----\n"
                        "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcH\n"
                        "-----END PUBLIC KEY-----\n"});
        CAPTURE(content);
        const std::string file = utf8(keys.write("key.pem", content));
        const Ran ran = run({"verify", folder, "--public-key", file});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err ==
              "signer error: --public-key " + file + ": not an Ed25519 public key in PEM\n");
    }
}

TEST_CASE("signer verify: a folder that can't be opened is exit 1", "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));

    SECTION("a path that isn't UTF-8")
    {
        const Ran ran = run({"verify", "runs\xff", "--public-key", key});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: the folder's path is not valid UTF-8\n");
    }
    SECTION("no such folder")
    {
        const std::string folder = utf8(keys.path() / "no-such-run");
        const Ran ran = run({"verify", folder, "--public-key", key});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: " + folder + ": the folder can't be opened\n");
    }
    SECTION("a file")
    {
        const Ran ran = run({"verify", key, "--public-key", key});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: " + key + ": the folder can't be opened\n");
    }
    SECTION("the key file is looked at first")
    {
        const std::string folder = utf8(keys.path() / "no-such-run");
        const std::string file = utf8(keys.path() / "no-such-key.pem");
        const Ran ran = run({"verify", folder, "--public-key", file});
        CHECK(ran.code == 1);
        CHECK(ran.err == "signer error: --public-key " + file + ": the file can't be read\n");
    }
}

// --- signer verify: the answers ------------------------------------------------------

TEST_CASE("signer verify: anything wrong inside the folder is a word and exit 5",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    const std::string folder = utf8(dir.path());

    SECTION("an empty folder")
    {
        const Ran ran = run({"verify", folder, "--public-key", key});
        CHECK(ran.code == 5);
        CHECK(ran.out == "not verified: result_unreadable\n");
        CHECK(ran.err.empty());
    }
    SECTION("no signature.json")
    {
        write_bundle(dir);
        REQUIRE(std::filesystem::remove(dir.path() / "signature.json"));
        const Ran ran = run({"verify", folder, "--public-key", key});
        CHECK(ran.code == 5);
        CHECK(ran.out == "not verified: signature_file\n");
        CHECK(ran.err.empty());
    }
    SECTION("another key's file: no note is printed without `verified`")
    {
        write_bundle(dir);
        dir.write("manifest.json", "{}");
        const std::string key2 = utf8(keys.write("key2.pem", kKey2Pem));
        const Ran ran = run({"verify", folder, "--public-key", key2});
        CHECK(ran.code == 5);
        CHECK(ran.out == "not verified: wrong_key\n");
        CHECK(ran.err.empty());
    }
    SECTION("an answer that didn't reach stdout isn't one")
    {
        std::ostringstream out;
        out.setstate(std::ios::failbit);
        std::ostringstream err;
        const Args args{"verify", folder, "--public-key", key};
        CHECK(rp::run_signer_command(args, out, err, rp::SignerCommandEnv{}) == 1);
        CHECK(err.str() == "signer error: the answer couldn't be written\n");
    }
}

TEST_CASE("signer verify: the signed folder is `verified <bundle_sha256> key <key_id>`, exit 0, "
          "with no secret and no config",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    const std::string folder = utf8(dir.path());

    SECTION("the folder, then the key")
    {
        const Ran ran = run({"verify", folder, "--public-key", key});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.out == "verified 572bf1f9f884217782d8b6c13db88f16257eafa5fea5b707d53aac0252fa81bf "
                         "key 06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9\n");
        CHECK(ran.err.empty());
        CHECK(ran.secrets_asked == 0);
    }
    SECTION("the key, then the folder")
    {
        const Ran ran = run({"verify", "--public-key", key, folder});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.err.empty());
    }
    SECTION("an environment with no secrets at all")
    {
        std::ostringstream out;
        std::ostringstream err;
        const Args args{"verify", folder, "--public-key", key};
        CHECK(rp::run_signer_command(args, out, err, rp::SignerCommandEnv{}) == 0);
        CHECK(out.str() == verified_line());
    }
    SECTION("a key file of exactly the limit, the key and white space")
    {
        const std::string padded =
            kKey1Pem + std::string(rp::kMaxPublicKeyFileBytes - kKey1Pem.size(), '\n');
        const std::string file = utf8(keys.write("padded.pem", padded));
        const Ran ran = run({"verify", folder, "--public-key", file});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
    }
    SECTION("the key `signer public-key` printed: its whole stdout as the key file")
    {
        const Ran printed = run({"public-key"}, std::string{rp::test::kSigningKey1Base64});
        REQUIRE(printed.code == 0);
        const std::string file = utf8(keys.write("printed.pem", printed.out));
        const Ran ran = run({"verify", folder, "--public-key", file});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.err.empty());
        CHECK(printed.err == "key " + kKey1Id + "\n");
    }
    SECTION("an answer that didn't reach stdout isn't one")
    {
        std::ostringstream out;
        out.setstate(std::ios::failbit);
        std::ostringstream err;
        const Args args{"verify", folder, "--public-key", key};
        CHECK(rp::run_signer_command(args, out, err, rp::SignerCommandEnv{}) == 1);
        CHECK(err.str() == "signer error: the answer couldn't be written\n");
    }
}

TEST_CASE("signer verify: a file the result doesn't list is a note on stderr, never a failure",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    dir.write("manifest.json", "{}");
    dir.write("token.tsr", "a token");
    std::filesystem::create_directory(dir.path() / "sub");
    // Outside ASCII: e acute, the euro sign, an emoji (two UTF-16 units), and DEL.
    dir.write(std::filesystem::path(rp::test::widen("\xc3\xa9.txt")), "x");
    dir.write(std::filesystem::path(rp::test::widen("\xe2\x82\xac.txt")), "x");
    dir.write(std::filesystem::path(rp::test::widen("\xf0\x9f\x98\x80.txt")), "x");
    dir.write(std::filesystem::path(rp::test::widen("a\x7f"
                                                    "b.txt")),
              "x");

    const Ran ran = run({"verify", utf8(dir.path()), "--public-key", key});
    CHECK(ran.code == 0);
    // The line on stdout is the same with or without them.
    CHECK(ran.out == verified_line());
    CHECK(ran.err == "note: not listed in the result: a\\x7fb.txt\n"
                     "note: not listed in the result: manifest.json\n"
                     "note: not listed in the result: sub\n"
                     "note: not listed in the result: token.tsr\n"
                     "note: not listed in the result: \\xe9.txt\n"
                     "note: not listed in the result: \\u20ac.txt\n"
                     "note: not listed in the result: \\U0001f600.txt\n");
}

// A name NTFS takes and UTF-16 doesn't: still a note, and the line is the one
// verify_bundle.py prints for the same folder (a lone surrogate as \udXXX).
TEST_CASE("signer verify: an unlisted file whose name isn't valid UTF-16 is a note, the folder "
          "still verified",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    const std::wstring low_alone = {L'x', wchar_t{0xDC80}, L'y'};

    SECTION("one such file")
    {
        if (!rp::test::create_empty_file(dir.path() / low_alone)) {
            SKIP("this file system refuses a file name that isn't valid UTF-16");
        }
        const Ran ran = run({"verify", utf8(dir.path()), "--public-key", key});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.err == "note: not listed in the result: x\\udc80y\n");
    }
    SECTION("a high surrogate with no low one after it, at the end and before a letter")
    {
        const std::wstring high_last = {L'a', wchar_t{0xD800}};
        const std::wstring high_then_letter = {wchar_t{0xD83D}, L'b'};
        const std::wstring low_then_high = {wchar_t{0xDE00}, wchar_t{0xD83D}};
        const std::wstring pair_then_high = {wchar_t{0xD83D}, wchar_t{0xDE00}, wchar_t{0xD83D}};
        for (const std::wstring& name :
             {low_alone, high_last, high_then_letter, low_then_high, pair_then_high}) {
            if (!rp::test::create_empty_file(dir.path() / name)) {
                SKIP("this file system refuses a file name that isn't valid UTF-16");
            }
        }
        const Ran ran = run({"verify", utf8(dir.path()), "--public-key", key});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.err == "note: not listed in the result: a\\ud800\n"
                         "note: not listed in the result: x\\udc80y\n"
                         "note: not listed in the result: \\ud83db\n"
                         "note: not listed in the result: \\ude00\\ud83d\n"
                         "note: not listed in the result: \\U0001f600\\ud83d\n");
    }
    SECTION("through run_cli: no unexpected failure")
    {
        if (!rp::test::create_empty_file(dir.path() / low_alone)) {
            SKIP("this file system refuses a file name that isn't valid UTF-16");
        }
        std::ostringstream out;
        std::ostringstream err;
        const std::string folder = utf8(dir.path());
        const Args args{"signer", "verify", folder, "--public-key", key};
        CHECK(rp::run_cli(args, out, err) == 0);
        CHECK(out.str() == verified_line());
        CHECK(err.str() == "note: not listed in the result: x\\udc80y\n");
    }
}

// shared/testdata/signing-v1/key-files.json through the command: a file the
// rule takes gets a verdict line, one it refuses the one error line and exit 1.
TEST_CASE("signer verify takes and refuses the shared key files as PublicKey::from_pem does",
          "[signer_command][vectors]")
{
    const json rows =
        json::parse(rp::test::read_shared("testdata/signing-v1/key-files.json")).at("key_files");
    REQUIRE(rows.size() == 46);
    const TempDir keys;
    const TempDir dir;
    write_bundle(dir);
    const std::string folder = utf8(dir.path());
    int accepted = 0;
    int refused = 0;

    for (const json& row : rows) {
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
        const std::string file = utf8(keys.write(name + ".pem", bytes));

        const Ran ran = run({"verify", folder, "--public-key", file});
        if (!row.at("accepted").get<bool>()) {
            ++refused;
            CHECK(ran.code == 1);
            CHECK(ran.out.empty());
            CHECK(ran.err ==
                  "signer error: --public-key " + file + ": not an Ed25519 public key in PEM\n");
        } else if (name == "small-order-identity-key") {
            // A key, and not the one that signed: a verdict, as for any other key.
            ++accepted;
            CHECK(ran.code == 5);
            CHECK(ran.out == "not verified: wrong_key\n");
            CHECK(ran.err.empty());
        } else {
            ++accepted;
            CHECK(ran.code == 0);
            CHECK(ran.out == verified_line());
            CHECK(ran.err.empty());
        }
    }
    CHECK(accepted == 11);
    CHECK(refused == 35);
}

// Each case of the shared vectors in a folder of its own, through the command:
// the stdout line and the exit code are what verify_bundle.py's line and its
// own exit code (0 or 1) must agree with.
TEST_CASE("signer verify answers every shared case with its line and exit code",
          "[signer_command][vectors]")
{
    const json keys = json::parse(rp::test::read_shared(kKeysFile));
    const json cases = json::parse(rp::test::read_shared(kCasesFile)).at("cases");
    REQUIRE(cases.size() == 38);
    const TempDir key_files;
    int verified = 0;

    for (const json& one : cases) {
        const std::string name = one.at("name").get<std::string>();
        CAPTURE(name);
        const TempDir dir;
        write_bundle(dir);
        for (const auto& [file, change] : one.at("files").items()) {
            if (change.is_null()) {
                REQUIRE(std::filesystem::remove(dir.path() / file));
            } else if (change.contains("text")) {
                dir.write(file, change.at("text").get<std::string>());
            } else {
                const std::optional<std::vector<unsigned char>> bytes =
                    rp::base64_decode(change.at("base64").get<std::string>());
                REQUIRE(bytes);
                dir.write(file, std::string{bytes->begin(), bytes->end()});
            }
        }
        const std::string key_name = one.at("public_key").get<std::string>();
        const std::string key =
            utf8(key_files.write(key_name + ".pem", pem_of(keys, key_name)));
        const std::string expect = one.at("expect").get<std::string>();

        const Ran ran = run({"verify", utf8(dir.path()), "--public-key", key});
        CHECK(ran.err.empty());
        if (expect == "verified") {
            ++verified;
            CHECK(ran.code == 0);
            CHECK(ran.out == verified_line());
        } else {
            CHECK(ran.code == 5);
            CHECK(ran.out == "not verified: " + expect + "\n");
        }
    }
    CHECK(verified == 1);
}

// --- through run_cli -----------------------------------------------------------------

TEST_CASE("rpworker signer runs both commands", "[signer_command][cli]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    const std::string folder = utf8(dir.path());
    std::ostringstream out;
    std::ostringstream err;

    SECTION("signer verify")
    {
        const Args args{"signer", "verify", folder, "--public-key", key};
        CHECK(rp::run_cli(args, out, err) == 0);
        CHECK(out.str() == verified_line());
        CHECK(err.str().empty());
    }
    SECTION("signer verify, not verified: exit 5")
    {
        dir.write("items.csv", "another file");
        const Args args{"signer", "verify", folder, "--public-key", key};
        CHECK(rp::run_cli(args, out, err) == rp::exit_code::restore);
        CHECK(out.str() == "not verified: attachment_size\n");
        CHECK(err.str().empty());
    }
    SECTION("signer public-key, the variable set")
    {
        const rp::test::ScopedEnv scoped(rp::kEnvSigningKeyBase64,
                                         std::string{rp::test::kSigningKey1Base64});
        const Args args{"signer", "public-key"};
        CHECK(rp::run_cli(args, out, err) == 0);
        CHECK(out.str() == kKey1Pem);
        CHECK(err.str() == "key " + kKey1Id + "\n");
    }
    SECTION("signer public-key, the variable unset")
    {
        const rp::test::ScopedEnv scoped(rp::kEnvSigningKeyBase64, std::optional<std::string>{});
        const Args args{"signer", "public-key"};
        CHECK(rp::run_cli(args, out, err) == 1);
        CHECK(out.str().empty());
        CHECK(err.str() == kKeyNotSet);
    }
    SECTION("a stream that throws is run_cli's unexpected failure, never a verdict")
    {
        rp::test::FailingStreamBuf failing;
        std::ostream lost(&failing);
        lost.exceptions(std::ios::badbit);
        const Args args{"signer", "verify", folder, "--public-key", key};
        CHECK(rp::run_cli(args, lost, err) == 1);
        CHECK(err.str() == "error: unexpected failure\n");
    }
}
