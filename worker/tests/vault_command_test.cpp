// W4.5: `rpworker vault set|remove|list|test|grant` (rp/vault_command.hpp)
// on vault files under a temp folder, through the real DPAPI. The value of
// `set` comes from a fake reader; the real one (stdin) is run by the exe
// tests.

#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/secrets.hpp>
#include <rp/vault.hpp>
#include <rp/vault_command.hpp>

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using Args = std::vector<std::string_view>;
using Catch::Matchers::ContainsSubstring;

namespace {

const std::string kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] [--vault <file>] | "
    "rpworker vault set|remove <name> [--vault <file>] | rpworker vault list|test [--vault <file>] | "
    "rpworker vault grant <account> [--vault <file>] | "
    "rpworker veeam list [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker graph list [--hash] [--config <path>] [--vault <file>] [--record <dir>] | rpworker graph certificate [--vault <file>] | "
    "rpworker client check --profile-file <file> [--vault <file>] [--record <dir>] | "
    "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] | "
    "rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] [--json <file> | --evidence <dir> [--outbox <root>]] | "
    "rpworker outbox flush [--config <path>] [--vault <file>] [--outbox <root>] [--record <dir>] | "
    "rpworker outbox list [--outbox <root>] | "
    "rpworker cloud register [--config <path>] [--vault <file>] [--name <worker name>] "
    "[--record <dir>] | "
    "rpworker signer public-key [--vault <file>] | rpworker signer new-key [--vault <file>] [--replace] | "
    "rpworker signer verify <folder> --public-key <pem file> [--tsa-ca <pem file>] | "
    "rpworker service install [--config <path>] | rpworker service uninstall|start|stop | "
    "rpworker service run [--config <path>]\n";

const std::string kNames = "veeam_username, veeam_password, graph_cert_pfx_base64, "
                           "graph_cert_password, signing_key_base64, cloud_install_token, "
                           "cloud_api_token";

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

struct Run {
    int code;
    std::string out;
    std::string err;
};

struct Lab {
    rp::test::TempDir dir;
    std::filesystem::path file = dir.path() / "vault.bin";
    std::string arg = utf8(file);
    // What the reader answers for `set`.
    rp::SecretValue next{rp::SecretValue::State::ok, "value-5c1d"};
    std::vector<std::string> prompts_for;
    int default_path_calls = 0;
    std::function<std::filesystem::path()> default_path = [this] { return file; };

    rp::VaultCommandEnv env()
    {
        rp::VaultCommandEnv env;
        env.default_vault_path = [this] {
            ++default_path_calls;
            return default_path();
        };
        env.read_secret = [this](std::string_view name) {
            prompts_for.emplace_back(name);
            return next;
        };
        return env;
    }

    // `args` as given: no --vault unless the test adds it.
    Run run_raw(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        const int code = rp::run_vault_command(args, out, err, env());
        return {code, out.str(), err.str()};
    }

    // `args`, then --vault <the temp file>.
    Run run(Args args)
    {
        args.push_back("--vault");
        args.push_back(arg);
        return run_raw(args);
    }
};

std::string five_masked(std::string_view user, std::string_view password, std::string_view pfx,
                        std::string_view pfx_password, std::string_view key,
                        std::string_view install = "(not set)", std::string_view api = "(not set)")
{
    return "veeam_username            " + std::string{user} + "\n" +
           "veeam_password            " + std::string{password} + "\n" +
           "graph_cert_pfx_base64     " + std::string{pfx} + "\n" +
           "graph_cert_password       " + std::string{pfx_password} + "\n" +
           "signing_key_base64        " + std::string{key} + "\n" +
           "cloud_install_token       " + std::string{install} + "\n" +
           "cloud_api_token           " + std::string{api} + "\n";
}

} // namespace

TEST_CASE("rpworker vault prints usage and exits 64 for a command line it doesn't take",
          "[vault_command]")
{
    const Args args = GENERATE(
        Args{}, Args{""}, Args{"Set", "veeam_username"}, Args{"set"}, Args{"set", "--vault", "x"},
        Args{"set", "--veeam_username"}, Args{"remove"}, Args{"grant"},
        Args{"grant", "--vault", "x"}, Args{"list", "extra"}, Args{"test", "veeam_username"},
        Args{"list", "--vault"}, Args{"list", "--vault", ""}, Args{"test", "--vault", "a", "--vault", "b"},
        Args{"set", "veeam_username", "a-value"}, Args{"set", "veeam_username", "--VAULT", "x"},
        Args{"show"}, Args{"list", "--config", "x"});
    CAPTURE(args);
    Lab lab;

    const Run run = lab.run_raw(args);
    REQUIRE(run.code == 64);
    REQUIRE(run.out.empty());
    REQUIRE(run.err == kUsage);
    REQUIRE(lab.default_path_calls == 0);
    REQUIRE(lab.prompts_for.empty());
}

TEST_CASE("rpworker vault set and remove take one of the seven names, never echoing another",
          "[vault_command]")
{
    const std::string_view subcommand = GENERATE("set", "remove");
    const std::string name = GENERATE(std::string{"VEEAM_USERNAME"}, std::string{"RP_VEEAM_PASSWORD"},
                                      std::string{"api_token"}, std::string{"SENTINEL-name\n"},
                                      std::string{"signing_private_key"});
    CAPTURE(subcommand, name);
    Lab lab;

    const Run run = lab.run({subcommand, name});
    REQUIRE(run.code == 64);
    REQUIRE(run.out.empty());
    REQUIRE(run.err == "usage error: the name must be one of " + kNames + "\n");
    REQUIRE_THAT(run.err, !ContainsSubstring("SENTINEL"));
    REQUIRE(lab.prompts_for.empty());
    REQUIRE_FALSE(std::filesystem::exists(lab.file));
}

TEST_CASE("rpworker vault set stores the value under its name, making the vault, and list and "
          "test show the name",
          "[vault_command]")
{
    Lab lab;

    const Run set = lab.run({"set", "veeam_password"});
    REQUIRE(set.err.empty());
    REQUIRE(set.out == "set veeam_password in " + lab.arg + "\n");
    REQUIRE(set.code == 0);
    REQUIRE(lab.prompts_for == std::vector<std::string>{"veeam_password"});
    REQUIRE(rp::read_vault(lab.file).veeam_password == "value-5c1d");
    REQUIRE_FALSE(rp::read_vault(lab.file).veeam_username.has_value());

    const Run list = lab.run({"list"});
    REQUIRE(list.code == 0);
    REQUIRE(list.err.empty());
    REQUIRE(list.out == "veeam_password\n");

    const Run test = lab.run({"test"});
    REQUIRE(test.code == 0);
    REQUIRE(test.err.empty());
    REQUIRE(test.out == "vault " + lab.arg + ": ok\n" +
                            five_masked("(not set)", "**** (set)", "(not set)", "(not set)",
                                        "(not set)"));
    REQUIRE_THAT(set.out + list.out + test.out, !ContainsSubstring("5c1d"));
}

TEST_CASE("rpworker vault set adds to a vault that is there and replaces a value", "[vault_command]")
{
    Lab lab;
    rp::Secrets before;
    before.veeam_username = "user-5c1d";
    before.signing_key_base64 = "key-5c1d";
    rp::write_vault(lab.file, before);

    lab.next.value = "pfx-5c1d";
    REQUIRE(lab.run({"set", "graph_cert_pfx_base64"}).code == 0);
    lab.next.value = "new-key-5c1d";
    REQUIRE(lab.run({"set", "signing_key_base64"}).code == 0);

    const rp::Secrets after = rp::read_vault(lab.file);
    CHECK(after.veeam_username == "user-5c1d");
    CHECK(after.graph_cert_pfx_base64 == "pfx-5c1d");
    CHECK(after.signing_key_base64 == "new-key-5c1d");
    CHECK(lab.run({"list"}).out == "veeam_username\ngraph_cert_pfx_base64\nsigning_key_base64\n");
}

TEST_CASE("rpworker vault set refuses a value it can't store, before the vault is touched",
          "[vault_command]")
{
    using State = rp::SecretValue::State;
    const auto [state, line] = GENERATE(table<State, std::string>({
        {State::empty, "vault error: the value is empty\n"},
        {State::too_long, "vault error: the value is longer than 65536 bytes\n"},
        {State::not_unicode, "vault error: the value isn't valid Unicode\n"},
        {State::not_utf8, "vault error: the value isn't valid UTF-8\n"},
        {State::failed, "vault error: the value couldn't be read\n"},
    }));
    CAPTURE(line);
    Lab lab;
    lab.next = {state, "SENTINEL-value"};

    const Run run = lab.run({"set", "veeam_password"});
    REQUIRE(run.code == 1);
    REQUIRE(run.out.empty());
    REQUIRE(run.err == line);
    REQUIRE_FALSE(std::filesystem::exists(lab.file));
}

TEST_CASE("rpworker vault remove takes a name out, and says when it wasn't there", "[vault_command]")
{
    Lab lab;
    rp::Secrets before;
    before.veeam_username = "user-5c1d";
    before.veeam_password = "pw-5c1d";
    rp::write_vault(lab.file, before);

    const Run removed = lab.run({"remove", "veeam_password"});
    REQUIRE(removed.code == 0);
    REQUIRE(removed.err.empty());
    REQUIRE(removed.out == "removed veeam_password from " + lab.arg + "\n");
    REQUIRE_FALSE(rp::read_vault(lab.file).veeam_password.has_value());
    REQUIRE(rp::read_vault(lab.file).veeam_username == "user-5c1d");

    const Run again = lab.run({"remove", "veeam_password"});
    REQUIRE(again.code == 0);
    REQUIRE(again.err.empty());
    REQUIRE(again.out == "veeam_password was not in " + lab.arg + "; nothing changed\n");
    REQUIRE(lab.prompts_for.empty());
}

TEST_CASE("rpworker vault list prints nothing for an empty vault", "[vault_command]")
{
    Lab lab;
    rp::write_vault(lab.file, rp::Secrets{});
    const Run run = lab.run({"list"});
    REQUIRE(run.code == 0);
    REQUIRE(run.out.empty());
    REQUIRE(run.err.empty());
}

TEST_CASE("rpworker vault test prints the five names masked, in config check's layout",
          "[vault_command]")
{
    Lab lab;
    rp::write_vault(lab.file, rp::Secrets{"u-5c1d", "p-5c1d", "pfx-5c1d", "pp-5c1d", "k-5c1d"});
    const Run run = lab.run({"test"});
    REQUIRE(run.code == 0);
    REQUIRE(run.err.empty());
    REQUIRE(run.out == "vault " + lab.arg + ": ok\n" +
                           five_masked("**** (set)", "**** (set)", "**** (set)", "**** (set)",
                                       "**** (set)"));
    REQUIRE_THAT(run.out, !ContainsSubstring("5c1d"));
}

TEST_CASE("rpworker vault grant adds a Read entry and names the account as a cell",
          "[vault_command]")
{
    Lab lab;
    rp::write_vault(lab.file, rp::Secrets{});
    const Run run = lab.run({"grant", "NT AUTHORITY\\LOCAL SERVICE"});
    REQUIRE(run.code == 0);
    REQUIRE(run.err.empty());
    REQUIRE(run.out == "granted read on " + lab.arg + " to NT AUTHORITY\\LOCAL SERVICE\n");

    const Run unknown = lab.run({"grant", "no\tsuch\x01" "account-5c1d"});
    REQUIRE(unknown.code == 1);
    REQUIRE(unknown.out.empty());
    REQUIRE(unknown.err == "vault error: " + lab.arg +
                               ": the account no such account-5c1d isn't known on this machine\n");
}

TEST_CASE("rpworker vault reports a vault it can't use as a vault error, 1", "[vault_command]")
{
    Lab lab;
    SECTION("not found: list, test, remove and grant")
    {
        const Args args =
            GENERATE(Args{"list"}, Args{"test"}, Args{"remove", "veeam_password"},
                     Args{"grant", "NT AUTHORITY\\LOCAL SERVICE"});
        CAPTURE(args);
        const Run run = lab.run(args);
        REQUIRE(run.code == 1);
        REQUIRE(run.out.empty());
        REQUIRE(run.err == "vault error: " + lab.arg + ": vault file not found\n");
    }
    SECTION("not a vault: set reads before it writes, and writes nothing")
    {
        std::ofstream(lab.file, std::ios::binary) << "not a blob";
        const Run run = lab.run({"set", "veeam_password"});
        REQUIRE(run.code == 1);
        REQUIRE(run.out.empty());
        REQUIRE(run.err == "vault error: " + lab.arg +
                               ": the vault can't be decrypted on this machine by this account "
                               "(error 0x00000057)\n");
        std::ifstream in(lab.file, std::ios::binary);
        const std::string bytes{std::istreambuf_iterator<char>(in), {}};
        REQUIRE(bytes == "not a blob");
    }
    SECTION("a folder as the vault")
    {
        std::filesystem::create_directory(lab.file);
        const Run run = lab.run({"list"});
        REQUIRE(run.code == 1);
        REQUIRE(run.err == "vault error: " + lab.arg + ": the vault file can't be read\n");
    }
}

TEST_CASE("rpworker vault takes --vault as a path and refuses one that isn't UTF-8",
          "[vault_command]")
{
    Lab lab;
    const Run run = lab.run_raw({"list", "--vault", "\xFF.bin"});
    REQUIRE(run.code == 1);
    REQUIRE(run.out.empty());
    REQUIRE(run.err == "vault error: the --vault path is not valid UTF-8\n");
    REQUIRE(lab.default_path_calls == 0);
}

TEST_CASE("rpworker vault reads the default vault without --vault, and reports a default it "
          "can't find",
          "[vault_command]")
{
    Lab lab;
    rp::write_vault(lab.file, rp::Secrets{});
    SECTION("the default")
    {
        const Run run = lab.run_raw({"list"});
        REQUIRE(run.code == 0);
        REQUIRE(lab.default_path_calls == 1);
    }
    SECTION("a default that can't be found")
    {
        lab.default_path = []() -> std::filesystem::path {
            throw rp::ConfigError("", "cannot find the ProgramData folder");
        };
        const Run run = lab.run_raw({"test"});
        REQUIRE(run.code == 1);
        REQUIRE(run.out.empty());
        REQUIRE(run.err == "vault error: cannot find the ProgramData folder\n");
    }
    SECTION("any other failure is let out, for run_cli to report")
    {
        lab.default_path = []() -> std::filesystem::path {
            throw std::runtime_error("SENTINEL-5c1d");
        };
        std::ostringstream out;
        std::ostringstream err;
        const Args args{"list"};
        REQUIRE_THROWS_AS(rp::run_vault_command(args, out, err, lab.env()), std::runtime_error);
        REQUIRE(out.str().empty());
        REQUIRE(err.str().empty());
    }
}

TEST_CASE("rpworker vault's real environment reads ProgramData and the console or stdin",
          "[vault_command]")
{
    const rp::VaultCommandEnv env = rp::default_vault_command_env();
    REQUIRE(env.default_vault_path() == rp::default_vault_path());
    REQUIRE(env.read_secret);
}

TEST_CASE("rpworker vault runs through run_cli", "[vault_command][cli]")
{
    Lab lab;
    rp::write_vault(lab.file, rp::Secrets{"u", "p", std::nullopt, std::nullopt, std::nullopt});
    std::ostringstream out;
    std::ostringstream err;
    const Args args{"vault", "list", "--vault", lab.arg};
    REQUIRE(rp::run_cli(args, out, err) == 0);
    REQUIRE(out.str() == "veeam_username\nveeam_password\n");
    REQUIRE(err.str().empty());
}
