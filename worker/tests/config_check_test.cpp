#include <rp/config.hpp>
#include <rp/config_check.hpp>
#include <rp/secrets.hpp>
#include <rp/timestamper.hpp>
#include <rp/vault.hpp>

#include "test_certs.hpp"
#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using Args = std::vector<std::string_view>;

namespace {

const std::string kUsage =
    "usage: rpworker --version | rpworker config check [--config <path>] [--vault <file>] | "
    "rpworker vault set|remove <name> [--vault <file>] | rpworker vault list|test [--vault <file>] | "
    "rpworker vault grant <account> [--vault <file>] | "
    "rpworker veeam list [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker graph list [--hash] [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker client check --profile-file <file> [--vault <file>] [--record <dir>] | "
    "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] | "
    "rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] "
    "[--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] "
    "[--record <dir>] [--profile-file <file>] [--json <file> | --evidence <dir> [--outbox <root>]] | "
    "rpworker outbox flush [--config <path>] [--outbox <root>] [--record <dir>] | "
    "rpworker outbox list [--outbox <root>] | "
    "rpworker signer public-key [--vault <file>] | "
    "rpworker signer verify <folder> --public-key <pem file> [--tsa-ca <pem file>] | "
    "rpworker service install [--config <path>] | rpworker service uninstall|start|stop | "
    "rpworker service run [--config <path>]\n";

// Every key set; sample_od left out to show its default.
const std::string kConfigJson = R"({
    "cloud_url": "https://cloud.example.invalid",
    "veeam_url": "https://veeam.example.invalid:4443",
    "veeam_org_name": "example.onmicrosoft.com",
    "graph_tenant_id": "00000000-0000-0000-0000-000000000001",
    "graph_client_id": "00000000-0000-0000-0000-000000000002",
    "test_mailbox": "restoretest@example.onmicrosoft.com",
    "test_site_id": "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002",
    "test_library_id": "b!library-id",
    "test_onedrive_drive_id": "b!drive-id",
    "test_onedrive_folder_id": "folder-id",
    "poll_interval_s": 60,
    "heartbeat_interval_s": 120,
    "sample_mail": 0,
    "sample_sp": 7,
    "log_level": "warn"
})";

std::string utf8(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// The masks `config check` prints for each of the seven secrets.
struct SecretMasks {
    std::string_view user;
    std::string_view password;
    std::string_view pfx;
    std::string_view pfx_password;
    std::string_view signing_key = "(not set)";
    std::string_view install_token = "(not set)";
    std::string_view api_token = "(not set)";
};

constexpr SecretMasks kNoSecrets{"(not set)", "(not set)", "(not set)", "(not set)"};

// The settings of a successful check of kConfigJson at `path`, with, when
// `ca_file` and `cert_sha256` are set, veeam_ca_file and veeam_cert_sha256
// added. `screenshots` is screenshots_enabled's line: the default, as
// kConfigJson doesn't set it.
std::string expected_settings(const std::filesystem::path& path, std::string_view ca_file = "(not set)",
                              std::string_view cert_sha256 = "(not set)",
                              std::string_view screenshots = "false",
                              std::string_view tsa_url = "(not set)",
                              std::string_view tsa_ca_file = "(not set)",
                              std::string_view cloud_ca_file = "(not set)",
                              std::string_view jobs_file = "(not set)")
{
    return "config file: " + utf8(path) + "\n" +
           "cloud_url                 https://cloud.example.invalid\n"
           "veeam_url                 https://veeam.example.invalid:4443\n"
           "veeam_org_name            example.onmicrosoft.com\n"
           "graph_tenant_id           00000000-0000-0000-0000-000000000001\n"
           "graph_client_id           00000000-0000-0000-0000-000000000002\n"
           "test_mailbox              restoretest@example.onmicrosoft.com\n"
           "test_site_id              example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002\n"
           "test_library_id           b!library-id\n"
           "test_onedrive_drive_id    b!drive-id\n"
           "test_onedrive_folder_id   folder-id\n"
           "poll_interval_s           60\n"
           "heartbeat_interval_s      120\n"
           "sample_mail               0\n"
           "sample_sp                 7\n"
           "sample_od                 5\n"
           "log_level                 warn\n"
           "veeam_ca_file             " +
           std::string{ca_file} + "\n" + "veeam_cert_sha256         " + std::string{cert_sha256} +
           "\n" + "tsa_url                   " + std::string{tsa_url} + "\n" +
           "tsa_ca_file               " + std::string{tsa_ca_file} + "\n" +
           "cloud_ca_file             " + std::string{cloud_ca_file} + "\n" +
           "jobs_file                 " + std::string{jobs_file} + "\n" +
           "screenshots_enabled       " + std::string{screenshots} + "\n";
}

// The secrets' part, for the vault at `vault` (W4.5).
std::string expected_secrets(const std::filesystem::path& vault, const SecretMasks& secrets)
{
    return "secrets (vault " + utf8(vault) + "; values are never shown):\n" +
           "veeam_username            " + std::string{secrets.user} + "\n" +
           "veeam_password            " + std::string{secrets.password} + "\n" +
           "graph_cert_pfx_base64     " + std::string{secrets.pfx} + "\n" +
           "graph_cert_password       " + std::string{secrets.pfx_password} + "\n" +
           "signing_key_base64        " + std::string{secrets.signing_key} + "\n" +
           "cloud_install_token       " + std::string{secrets.install_token} + "\n" +
           "cloud_api_token           " + std::string{secrets.api_token} + "\n";
}

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

using DefaultPath = std::function<std::filesystem::path()>;

// A temp folder with a vault in it (the five fields given), the default
// vault of every run, and counts of what was asked.
struct Lab {
    rp::test::TempDir dir;
    std::filesystem::path vault = dir.path() / "vault.bin";
    int default_config_calls = 0;
    int default_vault_calls = 0;
    int load_calls = 0;
    DefaultPath default_config = [] { return std::filesystem::path("unused.json"); };
    DefaultPath default_vault = [this] { return vault; };
    std::function<rp::Secrets(const std::filesystem::path&)> load = rp::read_vault;

    Lab()
    {
        rp::write_vault(vault, rp::Secrets{});
    }

    rp::ConfigCheckEnv env()
    {
        rp::ConfigCheckEnv env;
        env.default_config_path = [this] {
            ++default_config_calls;
            return default_config();
        };
        env.default_vault_path = [this] {
            ++default_vault_calls;
            return default_vault();
        };
        env.load_secrets = [this](const std::filesystem::path& file) {
            ++load_calls;
            return load(file);
        };
        return env;
    }

    Run run(const Args& args)
    {
        std::ostringstream out;
        std::ostringstream err;
        const int exit_code = rp::run_config_command(args, out, err, env());
        return {exit_code, out.str(), err.str()};
    }
};

} // namespace

TEST_CASE("rpworker config prints usage and exits 64 for arguments it doesn't understand",
          "[config_check]")
{
    const Args args = GENERATE(
        Args{},
        Args{""},
        Args{"Check"},
        Args{"show"},
        Args{"--config", "x.json", "check"},
        Args{"check", "--config"},
        Args{"check", "x.json"},
        Args{"check", "--config", "x.json", "extra"},
        Args{"check", "--config", "x.json", "--config", "y.json"},
        Args{"check", "--CONFIG", "x.json"},
        Args{"check", "check"},
        Args{"check", "--vault"},
        Args{"check", "--vault", "v.bin", "--vault", "w.bin"});
    CAPTURE(args);
    Lab lab;

    const Run result = lab.run(args);
    REQUIRE(result.exit_code == 64);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == kUsage);
    // Usage errors never look up ProgramData.
    REQUIRE(lab.default_config_calls == 0);
    REQUIRE(lab.default_vault_calls == 0);
}

TEST_CASE("rpworker config check exits 1 with the error when the config doesn't load",
          "[config_check]")
{
    Lab lab;
    const std::filesystem::path missing = lab.dir.path() / "missing.json";
    const std::string missing_arg = utf8(missing);

    const Run result = lab.run(Args{"check", "--config", missing_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + missing_arg + ": cannot read config file\n");
    // The vault isn't read for a config that doesn't load.
    REQUIRE(lab.load_calls == 0);
    REQUIRE(lab.default_vault_calls == 0);
}

TEST_CASE("rpworker config check reports an invalid config without its values", "[config_check]")
{
    Lab lab;
    const auto path = lab.dir.write("config.json", R"({"cloud_url": "http://SENTINEL-2a9f"})");
    const std::string path_arg = utf8(path);

    const Run result = lab.run(Args{"check", "--config", path_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err ==
            "config error: " + path_arg +
                ": config key \"cloud_url\" must be an https:// URL with no user name, password, "
                "query or fragment\n");
}

TEST_CASE("rpworker config check prints every setting and the vault's names, masked",
          "[config_check]")
{
    Lab lab;
    const auto path = lab.dir.write("config.json", kConfigJson);
    const std::string path_arg = utf8(path);
    rp::write_vault(lab.vault, rp::Secrets{"user-0c41", "password-0c41"});

    const Run result = lab.run(Args{"check", "--config", path_arg});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path) +
                              expected_secrets(lab.vault, {"**** (set)", "**** (set)", "(not set)",
                                                           "(not set)"}));
    REQUIRE(result.exit_code == 0);
    REQUIRE(lab.default_config_calls == 0);
    REQUIRE(lab.default_vault_calls == 1);
    REQUIRE(lab.load_calls == 1);
}

// W4.10 point 5: a config without the eight client keys (the service's, which
// takes the client from each job) prints (not set) for each.
TEST_CASE("rpworker config check prints (not set) for each of the eight client keys a config "
          "doesn't have",
          "[config_check][client_profile]")
{
    Lab lab;
    nlohmann::json doc = nlohmann::json::parse(kConfigJson);
    for (const char* key : {"veeam_org_name", "graph_tenant_id", "graph_client_id", "test_mailbox",
                            "test_site_id", "test_library_id", "test_onedrive_drive_id",
                            "test_onedrive_folder_id"}) {
        doc.erase(key);
    }
    const auto path = lab.dir.write("config.json", doc.dump(2));

    const Run result = lab.run(Args{"check", "--config", utf8(path)});
    REQUIRE(result.err.empty());
    REQUIRE(result.exit_code == 0);
    const std::string expected = "config file: " + utf8(path) + "\n" +
                                 "cloud_url                 https://cloud.example.invalid\n"
                                 "veeam_url                 https://veeam.example.invalid:4443\n"
                                 "veeam_org_name            (not set)\n"
                                 "graph_tenant_id           (not set)\n"
                                 "graph_client_id           (not set)\n"
                                 "test_mailbox              (not set)\n"
                                 "test_site_id              (not set)\n"
                                 "test_library_id           (not set)\n"
                                 "test_onedrive_drive_id    (not set)\n"
                                 "test_onedrive_folder_id   (not set)\n"
                                 "poll_interval_s           60\n";
    REQUIRE_THAT(result.out, Catch::Matchers::StartsWith(expected));
    REQUIRE_THAT(result.out, ContainsSubstring(expected_secrets(lab.vault, kNoSecrets)));
    // A config with some of them is refused as any invalid config is.
    doc["test_mailbox"] = "restoretest@example.onmicrosoft.com";
    const auto partial = lab.dir.write("partial.json", doc.dump(2));
    const Run refused = lab.run(Args{"check", "--config", utf8(partial)});
    REQUIRE(refused.exit_code == 1);
    REQUIRE(refused.out.empty());
    REQUIRE(refused.err ==
            "config error: " + utf8(partial) +
                ": config key \"veeam_org_name\" is missing: the eight client keys (veeam_org_name, "
                "graph_tenant_id, graph_client_id, test_mailbox, test_site_id, test_library_id, "
                "test_onedrive_drive_id, test_onedrive_folder_id) are set together or not at all\n");
}

TEST_CASE("rpworker config check reads the default path without --config", "[config_check]")
{
    Lab lab;
    const auto path = lab.dir.write("config.json", kConfigJson);
    lab.default_config = [path] { return path; };
    // Not a PFX, nor even Base64: config check stays offline and never opens
    // the certificate, it only says whether the name is in the vault.
    rp::write_vault(lab.vault, rp::Secrets{std::nullopt, std::nullopt, "pfx-0c41",
                                           "pfx-password-0c41", "key-0c41"});

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path) +
                              expected_secrets(lab.vault, {"(not set)", "(not set)", "**** (set)",
                                                           "**** (set)", "**** (set)"}));
    REQUIRE(result.exit_code == 0);
    REQUIRE(lab.default_config_calls == 1);
}

TEST_CASE("rpworker config check reads the vault --vault names, and reports one it can't use "
          "after the settings (W4.5)",
          "[config_check]")
{
    Lab lab;
    const auto path = lab.dir.write("config.json", kConfigJson);
    const std::string path_arg = utf8(path);
    SECTION("--vault")
    {
        const std::filesystem::path other = lab.dir.path() / "other.bin";
        rp::write_vault(other, rp::Secrets{std::nullopt, "p-0c41"});
        const std::string vault_arg = utf8(other);
        const Run result = lab.run(Args{"check", "--vault", vault_arg, "--config", path_arg});
        REQUIRE(result.err.empty());
        REQUIRE(result.out == expected_settings(path) +
                                  expected_secrets(other, {"(not set)", "**** (set)", "(not set)",
                                                           "(not set)"}));
        REQUIRE(result.exit_code == 0);
        REQUIRE(lab.default_vault_calls == 0);
    }
    SECTION("a --vault path that isn't UTF-8")
    {
        const Run result = lab.run(Args{"check", "--config", path_arg, "--vault", "\xFF.bin"});
        REQUIRE(result.exit_code == 1);
        REQUIRE(result.out == expected_settings(path));
        REQUIRE(result.err == "config error: the --vault path is not valid UTF-8\n");
        REQUIRE(lab.load_calls == 0);
    }
    SECTION("a vault that isn't there: the settings, then the vault's message")
    {
        const std::filesystem::path missing = lab.dir.path() / "missing.bin";
        const std::string vault_arg = utf8(missing);
        const Run result = lab.run(Args{"check", "--config", path_arg, "--vault", vault_arg});
        REQUIRE(result.exit_code == 1);
        REQUIRE(result.out == expected_settings(path));
        REQUIRE(result.err == "config error: " + vault_arg + ": vault file not found\n");
    }
    SECTION("a default vault that can't be found")
    {
        lab.default_vault = []() -> std::filesystem::path {
            throw rp::ConfigError("", "cannot find the ProgramData folder");
        };
        const Run result = lab.run(Args{"check", "--config", path_arg});
        REQUIRE(result.exit_code == 1);
        REQUIRE(result.out == expected_settings(path));
        REQUIRE(result.err == "config error: cannot find the ProgramData folder\n");
    }
    SECTION("any other failure reading the vault, without its message")
    {
        lab.load = [](const std::filesystem::path&) -> rp::Secrets {
            throw std::runtime_error("SENTINEL-d51f");
        };
        const Run result = lab.run(Args{"check", "--config", path_arg});
        REQUIRE(result.exit_code == 1);
        REQUIRE(result.out == expected_settings(path));
        REQUIRE(result.err == "config error: unexpected failure\n");
    }
}

TEST_CASE("rpworker config check never prints a secret's value", "[config_check]")
{
    Lab lab;
    const auto path = lab.dir.write("config.json", kConfigJson);
    lab.default_config = [path] { return path; };
    rp::write_vault(lab.vault, rp::Secrets{"SENTINEL-USER-91e7", "SENTINEL-PASSWORD-91e7",
                                           "SENTINEL-PFX-91e7", "SENTINEL-PFX-PASSWORD-91e7",
                                           "SENTINEL-KEY-91e7"});

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.exit_code == 0);
    const std::string all = result.out + result.err;
    REQUIRE_THAT(all, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(all, !ContainsSubstring("91e7"));
    REQUIRE_THAT(all, ContainsSubstring("veeam_username            **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("veeam_password            **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("graph_cert_pfx_base64     **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("graph_cert_password       **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("signing_key_base64        **** (set)\n"));
}

TEST_CASE("rpworker config check never prints a password in a URL", "[config_check]")
{
    Lab lab;
    std::string text = kConfigJson;
    const std::string url = "https://cloud.example.invalid";
    text.replace(text.find(url), url.size(), "https://user:SENTINEL-3b8d@cloud.example.invalid");
    const auto path = lab.dir.write("config.json", text);
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.exit_code == 1);
    REQUIRE_THAT(result.out + result.err, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(result.err, ContainsSubstring("\"cloud_url\""));
}

TEST_CASE("rpworker config check --config reads a UTF-8 path outside the ANSI code page",
          "[config_check]")
{
    Lab lab;
    // Cyrillic letters: not in cp1252, the ANSI code page of a Western machine.
    const auto path =
        lab.dir.write(std::filesystem::path(u8"тест.json"), kConfigJson);
    const std::string path_arg = utf8(path);

    const Run result = lab.run(Args{"check", "--config", path_arg});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path) + expected_secrets(lab.vault, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reports a veeam_ca_file it can't read", "[config_check]")
{
    Lab lab;
    std::string text = kConfigJson;
    const std::string ca_arg = utf8(lab.dir.path() / "missing.pem");
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() + ",");
    const std::string path_arg = utf8(lab.dir.write("config.json", text));

    const Run result = lab.run(Args{"check", "--config", path_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + path_arg +
                              ": config key \"veeam_ca_file\" names a file that can't be read\n");
}

TEST_CASE("rpworker config check prints veeam_ca_file, outside the ANSI code page too",
          "[config_check]")
{
    Lab lab;
    const std::filesystem::path name =
        GENERATE(std::filesystem::path("veeam-ca.pem"),
                 std::filesystem::path(u8"тест-ca.pem"));
    const std::string ca_arg = utf8(lab.dir.write(name, "-----BEGIN CERTIFICATE-----\n"));
    CAPTURE(ca_arg);
    std::string text = kConfigJson;
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() + ",");
    const auto path = lab.dir.write("config.json", text);
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path, ca_arg) + expected_secrets(lab.vault, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check prints veeam_cert_sha256 after veeam_ca_file", "[config_check]")
{
    Lab lab;
    const rp::test::Cert cert =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const std::string ca_arg = utf8(lab.dir.write("veeam-rest.pem", cert.pem().cert));
    const std::string sha256 = rp::test::cert_sha256_hex(cert);
    std::string text = kConfigJson;
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() +
                       ", \"veeam_cert_sha256\": \"" + sha256 + "\",");
    const auto path = lab.dir.write("config.json", text);
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.err.empty());
    REQUIRE(result.out ==
            expected_settings(path, ca_arg, sha256) + expected_secrets(lab.vault, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reports a screenshots_enabled that isn't true or false",
          "[config_check]")
{
    Lab lab;
    std::string text = kConfigJson;
    text.insert(1, R"("screenshots_enabled": "true",)");
    const std::string path_arg = utf8(lab.dir.write("config.json", text));

    const Run result = lab.run(Args{"check", "--config", path_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + path_arg +
                              ": config key \"screenshots_enabled\" must be true or false\n");
}

TEST_CASE("rpworker config check prints the TSA's URL and CA file when they are set",
          "[config_check][tsa]")
{
    Lab lab;
    const std::string ca = utf8(lab.dir.write("tsa-ca.pem", "-----BEGIN CERTIFICATE-----\n"));
    nlohmann::json doc = nlohmann::json::parse(kConfigJson);
    doc["tsa_url"] = "http://tsa.example.invalid/stamp";
    doc["tsa_ca_file"] = ca;
    const auto path = lab.dir.write("config.json", doc.dump());
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path, "(not set)", "(not set)", "false",
                                            "http://tsa.example.invalid/stamp", ca) +
                              expected_secrets(lab.vault, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check prints the Cloud's CA file when it is set",
          "[config_check][outbox]")
{
    Lab lab;
    const std::string ca =
        utf8(lab.dir.write("cloud-ca.pem", std::string{rp::default_tsa_ca_pem()}));
    nlohmann::json doc = nlohmann::json::parse(kConfigJson);
    doc["cloud_ca_file"] = ca;
    const auto path = lab.dir.write("config.json", doc.dump());
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path, "(not set)", "(not set)", "false", "(not set)",
                                            "(not set)", ca) +
                              expected_secrets(lab.vault, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

// W4.8: the stub job source. Its file needn't be there for the check.
TEST_CASE("rpworker config check prints the jobs file when it is set, there or not",
          "[config_check][jobs]")
{
    Lab lab;
    const std::string jobs = utf8(lab.dir.path() / "no-such-jobs.json");
    nlohmann::json doc = nlohmann::json::parse(kConfigJson);
    doc["jobs_file"] = jobs;
    const auto path = lab.dir.write("config.json", doc.dump());
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path, "(not set)", "(not set)", "false", "(not set)",
                                            "(not set)", "(not set)", jobs) +
                              expected_secrets(lab.vault, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check refuses a jobs_file that isn't an absolute path",
          "[config_check][jobs]")
{
    Lab lab;
    nlohmann::json doc = nlohmann::json::parse(kConfigJson);
    doc["jobs_file"] = "jobs.json";
    const auto path = lab.dir.write("config.json", doc.dump());
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    CHECK(result.out.empty());
    CHECK(result.err == "config error: " + utf8(path) +
                            ": config key \"jobs_file\" must be an absolute path, such as "
                            "C:\\ProgramData\\RestoreProof\\jobs.json\n");
    CHECK(result.exit_code == 1);
}

TEST_CASE("rpworker config check prints screenshots_enabled as true or false", "[config_check]")
{
    Lab lab;
    const std::string value = GENERATE("true", "false");
    CAPTURE(value);
    std::string text = kConfigJson;
    text.insert(1, "\"screenshots_enabled\": " + value + ",");
    const auto path = lab.dir.write("config.json", text);
    lab.default_config = [path] { return path; };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_settings(path, "(not set)", "(not set)", value) +
                              expected_secrets(lab.vault, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reports a veeam_ca_file that doesn't hold the pinned "
          "certificate",
          "[config_check]")
{
    Lab lab;
    const rp::test::Cert held =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const rp::test::Cert other =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const std::string ca_arg = utf8(lab.dir.write("veeam-rest.pem", held.pem().cert));
    std::string text = kConfigJson;
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() +
                       ", \"veeam_cert_sha256\": \"" + rp::test::cert_sha256_hex(other) + "\",");
    const std::string path_arg = utf8(lab.dir.write("config.json", text));

    const Run result = lab.run(Args{"check", "--config", path_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + path_arg +
                              ": config key \"veeam_cert_sha256\": veeam_ca_file holds no "
                              "certificate whose SHA-256 is veeam_cert_sha256\n");
}

TEST_CASE("rpworker config check reports an empty --config path as unreadable", "[config_check]")
{
    Lab lab;
    const Run result = lab.run(Args{"check", "--config", ""});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: : cannot read config file\n");
    REQUIRE(lab.default_config_calls == 0);
}

TEST_CASE("rpworker config check reports a --config path that isn't UTF-8", "[config_check]")
{
    const std::string path_arg = GENERATE(std::string("\xFF.json"), std::string("a\xC3.json"),
                                          std::string("\xED\xA0\x80.json"));
    CAPTURE(path_arg);
    Lab lab;

    const Run result = lab.run(Args{"check", "--config", path_arg});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: the --config path is not valid UTF-8\n");
}

TEST_CASE("rpworker config check --config never looks up the default path", "[config_check]")
{
    Lab lab;
    const std::string path_arg = utf8(lab.dir.write("config.json", kConfigJson));

    REQUIRE(lab.run(Args{"check", "--config", path_arg}).exit_code == 0);
    REQUIRE(lab.default_config_calls == 0);
}

TEST_CASE("rpworker config check reports a default path it can't find", "[config_check]")
{
    Lab lab;
    lab.default_config = []() -> std::filesystem::path {
        throw rp::ConfigError("", "cannot find the ProgramData folder");
    };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: cannot find the ProgramData folder\n");
}

TEST_CASE("rpworker config check reports any other failure without its message",
          "[config_check]")
{
    Lab lab;
    lab.default_config = []() -> std::filesystem::path {
        throw std::runtime_error("SENTINEL-d51f");
    };

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: unexpected failure\n");
}

TEST_CASE("rpworker config check prints no secret on any error path", "[config_check]")
{
    std::string with_password_key = kConfigJson;
    with_password_key.insert(1, R"("veeam_password": "SENTINEL-FILE-7a64",)");
    std::string with_userinfo = kConfigJson;
    const std::string url = "https://veeam.example.invalid:4443";
    with_userinfo.replace(with_userinfo.find(url), url.size(),
                          "https://admin:SENTINEL-FILE-7a64@veeam.example.invalid:4443");
    std::string with_key_name = kConfigJson;
    with_key_name.insert(1, R"("SENTINEL-FILE-7a64\n": 1,)");

    const std::string text = GENERATE_COPY(
        std::string(R"({"cloud_url": "SENTINEL-FILE-7a64)"),
        std::string(R"({"cloud_url": SENTINEL-FILE-7a64)"),
        std::string(R"({"sample_mail": 1e400})"),
        with_password_key,
        with_userinfo,
        with_key_name);
    CAPTURE(text);
    Lab lab;
    const auto path = lab.dir.write("config.json", text);
    lab.default_config = [path] { return path; };
    rp::write_vault(lab.vault, rp::Secrets{"SENTINEL-ENV-USER-7a64", "SENTINEL-ENV-PASSWORD-7a64",
                                           "SENTINEL-ENV-PFX-7a64", "SENTINEL-ENV-PFXPW-7a64",
                                           "SENTINEL-ENV-KEY-7a64"});

    const Run result = lab.run(Args{"check"});
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE_THAT(result.err, ContainsSubstring("config error: "));
    REQUIRE_THAT(result.out + result.err, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(result.out + result.err, !ContainsSubstring("7a64"));
}

TEST_CASE("the real config check environment reads ProgramData and the vault", "[config_check]")
{
    const rp::ConfigCheckEnv env = rp::default_config_check_env();
    REQUIRE(env.default_config_path() == rp::default_config_path());
    REQUIRE(env.default_vault_path() == rp::default_vault_path());
    Lab lab;
    rp::write_vault(lab.vault, rp::Secrets{"u-0c41"});
    REQUIRE(env.load_secrets(lab.vault).veeam_username == "u-0c41");
}
