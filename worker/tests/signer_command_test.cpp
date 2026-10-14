// `rpworker signer public-key` and `rpworker signer verify` (W4.3,
// docs/decisions.md 2026-10-05, point 4). Every folder here is a temp folder
// made from shared/testdata/signing-v1/; the only keys are RFC 8032's
// published test keys.

#include <rp/base64.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>
#include <rp/vault.hpp>
#include <rp/signer.hpp>
#include <rp/signer_command.hpp>

#include "../src/file_read.hpp"
#include "../src/result_schema_detail.hpp"
#include "deep_folder.hpp"
#include "result_lab.hpp"
#include "signing_lab.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
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

// The usage line is rp::kCliUsage; cli_test.cpp holds its text.
const std::string kUsage{rp::kCliUsage};

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

const std::string kKeyNotSet = "config error: signing_key_base64 is not in the vault\n";
const std::string kKeyNotAKey = "config error: signing_key_base64 is not an Ed25519 private key "
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
    int default_vault_asked = 0;
    std::filesystem::path vault_read;
};

// `rpworker signer <args>` with the vault's signing_key_base64 holding `key`.
Ran run(const Args& args, std::optional<std::string> key = std::nullopt)
{
    Ran ran;
    rp::SignerCommandEnv env;
    env.default_vault_path = [&ran] {
        ++ran.default_vault_asked;
        return std::filesystem::path{"C:\\default\\vault.bin"};
    };
    env.load_secrets = [&ran, key](const std::filesystem::path& vault) {
        ++ran.secrets_asked;
        ran.vault_read = vault;
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
    return "verified " + bundle_sha256() + " key " + key_id + " timestamp none\n";
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

TEST_CASE("signer public-key: a vault that can't be used is a config error, 1",
          "[signer_command]")
{
    rp::SignerCommandEnv env;
    env.default_vault_path = [] { return std::filesystem::path{"C:\\default\\vault.bin"}; };
    env.load_secrets = [](const std::filesystem::path&) -> rp::Secrets {
        throw rp::VaultError("C:\\default\\vault.bin: vault file not found");
    };
    std::ostringstream out;
    std::ostringstream err;
    const Args args{"public-key"};
    CHECK(rp::run_signer_command(args, out, err, env) == 1);
    CHECK(out.str().empty());
    CHECK(err.str() == "config error: C:\\default\\vault.bin: vault file not found\n");
}

TEST_CASE("signer public-key reads the vault --vault names, else the default one (W4.5)",
          "[signer_command]")
{
    SECTION("--vault")
    {
        const Ran ran = run({"public-key", "--vault", "C:\\x\\v.bin"},
                            std::string{rp::test::kSigningKey1Base64});
        CHECK(ran.code == 0);
        CHECK(ran.out == kKey1Pem);
        CHECK(ran.vault_read == std::filesystem::path{"C:\\x\\v.bin"});
        CHECK(ran.default_vault_asked == 0);
    }
    SECTION("the default")
    {
        const Ran ran = run({"public-key"}, std::string{rp::test::kSigningKey1Base64});
        CHECK(ran.code == 0);
        CHECK(ran.default_vault_asked == 1);
        CHECK(ran.vault_read == std::filesystem::path{"C:\\default\\vault.bin"});
    }
    SECTION("a --vault path that isn't UTF-8")
    {
        const Ran ran = run({"public-key", "--vault", "\xFF.bin"},
                            std::string{rp::test::kSigningKey1Base64});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "config error: the --vault path is not valid UTF-8\n");
        CHECK(ran.secrets_asked == 0);
    }
}

TEST_CASE("signer public-key: any other failure is let out, for run_cli to report",
          "[signer_command]")
{
    rp::SignerCommandEnv env;
    env.default_vault_path = [] { return std::filesystem::path{"C:\\default\\vault.bin"}; };
    env.load_secrets = [](const std::filesystem::path&) -> rp::Secrets {
        throw std::runtime_error("holds a secret");
    };
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
        CHECK(verified.err == "note: not timestamped\n");
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
    env.default_vault_path = [] { return std::filesystem::path{"C:\\default\\vault.bin"}; };
    env.load_secrets = [](const std::filesystem::path&) {
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

TEST_CASE("the real signer environment reads the secrets from the vault", "[signer_command]")
{
    const rp::SignerCommandEnv env = rp::default_signer_command_env();
    REQUIRE(env.load_secrets);
    REQUIRE(env.default_vault_path);
    CHECK(env.default_vault_path() == rp::default_vault_path());
    const TempDir dir;
    const std::filesystem::path vault = dir.path() / "vault.bin";
    rp::Secrets secrets;
    secrets.signing_key_base64 = std::string{rp::test::kSigningKey1Base64};
    rp::write_vault(vault, secrets);
    CHECK(env.load_secrets(vault).signing_key_base64 == std::string{rp::test::kSigningKey1Base64});
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
        CHECK(ran.out == "verified 16452f9610ee5345ef5f4319c194241a1f6d24a938c0ee686f0a683d8130d3f6 "
                         "key 06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9 timestamp none\n");
        CHECK(ran.err == "note: not timestamped\n");
        CHECK(ran.secrets_asked == 0);
    }
    SECTION("the key, then the folder")
    {
        const Ran ran = run({"verify", "--public-key", key, folder});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.err == "note: not timestamped\n");
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
        CHECK(ran.err == "note: not timestamped\n");
        CHECK(printed.err == "key " + kKey1Id + "\n");
    }
    SECTION("an answer that didn't reach stdout isn't one")
    {
        std::ostringstream out;
        out.setstate(std::ios::failbit);
        std::ostringstream err;
        const Args args{"verify", folder, "--public-key", key};
        CHECK(rp::run_signer_command(args, out, err, rp::SignerCommandEnv{}) == 1);
        CHECK(err.str() == "note: not timestamped\n" "signer error: the answer couldn't be written\n");
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
                     "note: not listed in the result: \\U0001f600.txt\n" "note: not timestamped\n");
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
        CHECK(ran.err == "note: not listed in the result: x\\udc80y\n" "note: not timestamped\n");
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
                         "note: not listed in the result: \\U0001f600\\ud83d\n" "note: not timestamped\n");
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
        CHECK(err.str() == "note: not listed in the result: x\\udc80y\n" "note: not timestamped\n");
    }
}

// --- signer verify: the folder as the disk has it ------------------------------------

// rpworker.exe has no long-path manifest, so a file whose full path is past
// 260 characters didn't open: an intact folder got `attachment_missing`,
// `signature_file` or `result_unreadable`, by how long its path was, where
// verify_bundle.py said `verified`.
TEST_CASE("signer verify: a signed folder whose files are past MAX_PATH is verified like any "
          "other",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    const rp::test::DeepFolder deep(dir);
    const json bundle = json::parse(rp::test::read_shared(kBundleFile));
    for (const auto& [file, content] : bundle.at("files").items()) {
        deep.write(file, content.get<std::string>());
    }
    const std::string folder = utf8(deep.path());
    // Every one of the four, the shortest name included.
    REQUIRE(folder.size() + std::string{"\\items.csv"}.size() > 260);

    SECTION("untouched")
    {
        const Ran ran = run({"verify", folder, "--public-key", key});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.err == "note: not timestamped\n");
    }
    SECTION("with forward slashes")
    {
        std::string slashed = folder;
        std::replace(slashed.begin(), slashed.end(), '\\', '/');
        const Ran ran = run({"verify", slashed, "--public-key", key});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
    }
    SECTION("a file that isn't listed is still a note")
    {
        deep.write("manifest.json", "{}");
        const Ran ran = run({"verify", folder, "--public-key", key});
        CHECK(ran.code == 0);
        CHECK(ran.out == verified_line());
        CHECK(ran.err == "note: not listed in the result: manifest.json\n" "note: not timestamped\n");
    }
    SECTION("what is wrong inside it has its own word")
    {
        deep.remove("veeam-session.log");
        const Ran missing = run({"verify", folder, "--public-key", key});
        CHECK(missing.code == 5);
        CHECK(missing.out == "not verified: attachment_missing\n");
        deep.write("items.csv", "another file");
        const Ran size = run({"verify", folder, "--public-key", key});
        CHECK(size.code == 5);
        CHECK(size.out == "not verified: attachment_size\n");
    }
}

// What the caller named and nothing else: Windows drops blanks and dots at the
// end of a path, so ` ` or `...` would be the folder above, and `run ` the
// folder `run`. The Worker names the folder as a file inside it would, where
// they stay.
TEST_CASE("signer verify: a folder name of blanks or dots, or with a space after it, is no "
          "folder: never the one above or beside it",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    // A signed folder, and one inside it: whichever a wrong reading of the
    // name would open, it would verify.
    const TempDir dir;
    write_bundle(dir);
    std::filesystem::create_directory(dir.path() / "run");
    const json bundle = json::parse(rp::test::read_shared(kBundleFile));
    for (const auto& [file, content] : bundle.at("files").items()) {
        dir.write(std::filesystem::path{"run"} / file, content.get<std::string>());
    }
    const std::string top = utf8(dir.path());
    REQUIRE(run({"verify", top + "\\run", "--public-key", key}).out == verified_line());

    const std::string folder = GENERATE_COPY(top + "\\ ", top + "\\...", top + "\\. ",
                                             top + "\\.. ", top + "\\run\\ ", top + "\\run\\...",
                                             top + " ", top + "\\run ", top + "/run ");
    CAPTURE(folder);
    const Ran ran = run({"verify", folder, "--public-key", key});
    CHECK(ran.code == 1);
    CHECK(ran.out.empty());
    CHECK(ran.err == "signer error: " + folder + ": the folder can't be opened\n");
}

// MSVC gives a folder a size, 4096 on NTFS once it holds a few names, which
// was asked against the listed size before anything was opened: such a folder
// was `attachment_size` here and `attachment_missing` in verify_bundle.py.
TEST_CASE("signer verify: a listed attachment that is a folder is attachment_missing, whatever "
          "the folder holds",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    REQUIRE(std::filesystem::remove(dir.path() / "items.csv"));
    std::filesystem::create_directory(dir.path() / "items.csv");
    const int files = GENERATE(0, 1, 5, 40);
    CAPTURE(files);
    for (int i = 0; i < files; ++i) {
        dir.write(std::filesystem::path{"items.csv"} /
                      ("a-file-with-a-name-long-enough-" + std::to_string(i) + ".txt"),
                  "x");
    }

    const Ran ran = run({"verify", utf8(dir.path()), "--public-key", key});
    CHECK(ran.code == 5);
    CHECK(ran.out == "not verified: attachment_missing\n");
    CHECK(ran.err.empty());
}

// NTFS opens ITEMS.CSV for items.csv; a file system that tells the two apart
// has no items.csv. The folder's own list of names decides, so the answer is
// the same on both (and verify_bundle.py's), and no file is verified and
// "not listed in the result" in one answer.
TEST_CASE("signer verify: a file under another case of its name is not that file",
          "[signer_command]")
{
    struct Row {
        const char* name;
        const char* stored_as;
        const char* word;
    };
    const Row row = GENERATE(values<Row>({
        {"items.csv", "ITEMS.CSV", "attachment_missing"},
        {"veeam-session.log", "Veeam-Session.log", "attachment_missing"},
        {"result.json", "RESULT.JSON", "result_unreadable"},
        {"signature.json", "Signature.json", "signature_file"},
    }));
    CAPTURE(row.name);
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    std::filesystem::rename(dir.path() / row.name, dir.path() / row.stored_as);
    const std::optional<std::vector<std::string>> names = rp::list_folder(dir.path());
    REQUIRE(names);
    REQUIRE(std::find(names->begin(), names->end(), row.stored_as) != names->end());
    REQUIRE(std::find(names->begin(), names->end(), row.name) == names->end());

    const Ran ran = run({"verify", utf8(dir.path()), "--public-key", key});
    CHECK(ran.code == 5);
    CHECK(ran.out == std::string{"not verified: "} + row.word + "\n");
    CHECK(ran.err.empty());
}

// The embedded validator can fail to load (no memory): rp::validate_result
// then says "not valid" for any document, which is no fact about the folder.
TEST_CASE("signer verify: a result that couldn't be checked against its schema is exit 1, never "
          "a word",
          "[signer_command]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    const std::string folder = utf8(dir.path());
    struct Unavailable {
        Unavailable() { rp::detail::set_result_validator_unavailable(true); }
        ~Unavailable() { rp::detail::set_result_validator_unavailable(false); }
    };

    SECTION("the signed folder: no verdict")
    {
        Ran ran;
        {
            const Unavailable unavailable;
            ran = run({"verify", folder, "--public-key", key});
        }
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: the result couldn't be checked against its schema\n");
        // With the validator back, the same folder is verified.
        CHECK(run({"verify", folder, "--public-key", key}).out == verified_line());
    }
    SECTION("through run_cli")
    {
        std::ostringstream out;
        std::ostringstream err;
        const Args args{"signer", "verify", folder, "--public-key", key};
        int code = -1;
        {
            const Unavailable unavailable;
            code = rp::run_cli(args, out, err);
        }
        CHECK(code == 1);
        CHECK(out.str().empty());
        CHECK(err.str() == "signer error: the result couldn't be checked against its schema\n");
    }
    SECTION("a folder refused before the schema is asked still has its word")
    {
        REQUIRE(std::filesystem::remove(dir.path() / "result.json"));
        Ran ran;
        {
            const Unavailable unavailable;
            ran = run({"verify", folder, "--public-key", key});
        }
        CHECK(ran.code == 5);
        CHECK(ran.out == "not verified: result_unreadable\n");
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
            CHECK(ran.err == "note: not timestamped\n");
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
        CHECK(ran.err == (expect == "verified" ? "note: not timestamped\n" : ""));
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
        CHECK(err.str() == "note: not timestamped\n");
    }
    SECTION("signer verify, not verified: exit 5")
    {
        dir.write("items.csv", "another file");
        const Args args{"signer", "verify", folder, "--public-key", key};
        CHECK(rp::run_cli(args, out, err) == rp::exit_code::restore);
        CHECK(out.str() == "not verified: attachment_size\n");
        CHECK(err.str().empty());
    }
    SECTION("signer public-key, the key in a vault (W4.5)")
    {
        const TempDir vaults;
        const std::filesystem::path vault = vaults.path() / "vault.bin";
        rp::Secrets secrets;
        secrets.signing_key_base64 = std::string{rp::test::kSigningKey1Base64};
        rp::write_vault(vault, secrets);
        const std::string vault_arg = utf8(vault);
        const Args args{"signer", "public-key", "--vault", vault_arg};
        CHECK(rp::run_cli(args, out, err) == 0);
        CHECK(out.str() == kKey1Pem);
        CHECK(err.str() == "key " + kKey1Id + "\n");
    }
    SECTION("signer public-key, a vault without the key")
    {
        const TempDir vaults;
        const std::filesystem::path vault = vaults.path() / "vault.bin";
        rp::write_vault(vault, rp::Secrets{});
        const std::string vault_arg = utf8(vault);
        const Args args{"signer", "public-key", "--vault", vault_arg};
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
        CHECK(err.str() == "note: not timestamped\n" "error: unexpected failure\n");
    }
}

// --- W4.4: --tsa-ca and the line's third field ---------------------------------------

namespace {

constexpr const char* kTimestampKeys = "testdata/timestamp-v1/keys.json";
constexpr const char* kTimestampCases = "testdata/timestamp-v1/cases.json";

// The PEM a timestamp case's `tsa_ca` names in timestamp-v1/keys.json.
std::string tsa_ca_named(const json& keys, const std::string& which)
{
    if (which == "both_roots") {
        return keys.at("other_root_pem").get<std::string>() + keys.at("root_pem").get<std::string>();
    }
    return keys.at(which == "tsa_certificate" ? "tsa_certificate_pem" : which + "_pem")
        .get<std::string>();
}

} // namespace

TEST_CASE("signer verify: --tsa-ca without a value, empty or given twice is usage",
          "[signer_command][timestamp]")
{
    const Args args = GENERATE(
        Args{"verify", "folder", "--public-key", "key.pem", "--tsa-ca"},
        Args{"verify", "folder", "--public-key", "key.pem", "--tsa-ca", ""},
        Args{"verify", "folder", "--public-key", "key.pem", "--tsa-ca", "a.pem", "--tsa-ca",
             "b.pem"},
        Args{"verify", "--tsa-ca", "a.pem", "--public-key", "key.pem"},
        Args{"verify", "folder", "--tsa-ca", "a.pem"});

    const Ran ran = run(args);

    CHECK(ran.code == 64);
    CHECK(ran.out.empty());
    CHECK(ran.err == kUsage);
}

TEST_CASE("signer verify: a --tsa-ca file that can't be read or holds no certificate is exit 1, "
          "never a verdict",
          "[signer_command][timestamp]")
{
    const TempDir keys;
    const std::string key = utf8(keys.write("key.pem", kKey1Pem));
    const TempDir dir;
    write_bundle(dir);
    const std::string folder = utf8(dir.path());

    SECTION("not there")
    {
        const std::string ca = utf8(keys.path() / "no-such-ca.pem");
        const Ran ran = run({"verify", folder, "--public-key", key, "--tsa-ca", ca});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: --tsa-ca " + ca + ": the file can't be read\n");
    }
    SECTION("a folder")
    {
        const std::string ca = utf8(keys.path());
        const Ran ran = run({"verify", folder, "--public-key", key, "--tsa-ca", ca});
        CHECK(ran.code == 1);
        CHECK(ran.err == "signer error: --tsa-ca " + ca + ": the file can't be read\n");
    }
    SECTION("too large")
    {
        const std::string ca =
            utf8(keys.write("big.pem", std::string(rp::kMaxPublicKeyFileBytes + 1, 'A')));
        const Ran ran = run({"verify", folder, "--public-key", key, "--tsa-ca", ca});
        CHECK(ran.code == 1);
        CHECK(ran.err == "signer error: --tsa-ca " + ca + ": the file can't be read\n");
    }
    SECTION("no certificate in it")
    {
        const std::string content = GENERATE(std::string{}, std::string{"not a certificate\n"},
                                             kKey1Pem);
        const std::string ca = utf8(keys.write("ca.pem", content));
        const Ran ran = run({"verify", folder, "--public-key", key, "--tsa-ca", ca});
        CHECK(ran.code == 1);
        CHECK(ran.out.empty());
        CHECK(ran.err == "signer error: --tsa-ca " + ca + ": no certificate in PEM\n");
    }
    SECTION("not valid UTF-8")
    {
        const Ran ran = run({"verify", folder, "--public-key", key, "--tsa-ca", "\xff.pem"});
        CHECK(ran.code == 1);
        CHECK(ran.err == "signer error: the --tsa-ca path is not valid UTF-8\n");
    }
}

TEST_CASE("signer verify answers every shared timestamp case with its line, its note and its "
          "exit code",
          "[signer_command][timestamp][vectors]")
{
    const json signing_keys = json::parse(rp::test::read_shared(kKeysFile));
    const json keys = json::parse(rp::test::read_shared(kTimestampKeys));
    const json cases = json::parse(rp::test::read_shared(kTimestampCases)).at("cases");
    REQUIRE(cases.size() == 23);
    const TempDir key_files;
    const std::string key = utf8(key_files.write("key.pem", pem_of(signing_keys, "rfc8032-test-1")));

    for (const json& one : cases) {
        const std::string name = one.at("name").get<std::string>();
        CAPTURE(name);
        const TempDir dir;
        write_bundle(dir);
        for (const auto& [file, change] : one.at("files").items()) {
            if (change.contains("text")) {
                dir.write(file, change.at("text").get<std::string>());
            } else {
                const std::optional<std::vector<unsigned char>> bytes =
                    rp::base64_decode(change.at("base64").get<std::string>());
                REQUIRE(bytes);
                dir.write(file, std::string{bytes->begin(), bytes->end()});
            }
        }
        const std::string folder = utf8(dir.path());
        Args args{"verify", folder, "--public-key", key};
        std::string ca;
        if (!one.at("tsa_ca").is_null()) {
            const std::string which = one.at("tsa_ca").get<std::string>();
            ca = utf8(key_files.write(which + ".pem", tsa_ca_named(keys, which)));
            args.push_back("--tsa-ca");
            args.push_back(ca);
        }
        const std::string expect = one.at("expect").get<std::string>();

        const Ran ran = run(args);

        if (expect != "verified") {
            CHECK(ran.code == 5);
            CHECK(ran.out == "not verified: " + expect + "\n");
            CHECK(ran.err.empty());
            continue;
        }
        const std::string field = one.at("timestamp").get<std::string>();
        CHECK(ran.code == 0);
        CHECK(ran.out == "verified " + bundle_sha256() + " key " + kKey1Id + " timestamp " +
                             field + "\n");
        const std::string other_name =
            one.at("files").contains("TIMESTAMP.TST")
                ? std::string{"note: not listed in the result: TIMESTAMP.TST\n"}
                : std::string{};
        if (field == "none") {
            CHECK(ran.err == other_name + "note: not timestamped\n");
        } else if (field == "unchecked") {
            CHECK(ran.err == "note: timestamp.tst was not checked: no --tsa-ca\n");
        } else {
            CHECK(ran.err.empty());
        }
    }
}
