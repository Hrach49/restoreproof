#include <rp/config.hpp>
#include <rp/config_check.hpp>
#include <rp/secrets.hpp>

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

const std::string kUsage = "usage: rpworker --version | rpworker config check [--config <path>] | "
                           "rpworker veeam list [--config <path>] [--record <dir>] | "
                           "rpworker graph list [--hash] [--config <path>] [--record <dir>] | "
                           "rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
                           "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] "
                           "[--config <path>] [--record <dir>] | "
                           "rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] "
                           "[--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] "
                           "[--config <path>] [--record <dir>] [--json <file> | --evidence <dir>] | "
                           "rpworker signer public-key | "
                           "rpworker signer verify <folder> --public-key <pem file>\n";

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

// The masks `config check` prints for each secret variable.
struct SecretMasks {
    std::string_view user;
    std::string_view password;
    std::string_view pfx;
    std::string_view pfx_password;
    std::string_view signing_key = "(not set)";
};

constexpr SecretMasks kNoSecrets{"(not set)", "(not set)", "(not set)", "(not set)"};

// The output of a successful check of kConfigJson at `path`, with the five
// secret lines given and, when `ca_file` and `cert_sha256` are set,
// veeam_ca_file and veeam_cert_sha256 added. `screenshots` is
// screenshots_enabled's line: the default, as kConfigJson doesn't set it.
std::string expected_output(const std::filesystem::path& path, const SecretMasks& secrets,
                            std::string_view ca_file = "(not set)",
                            std::string_view cert_sha256 = "(not set)",
                            std::string_view screenshots = "false")
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
           std::string{ca_file} + "\n" +
           "veeam_cert_sha256         " + std::string{cert_sha256} + "\n" +
           "screenshots_enabled       " + std::string{screenshots} + "\n" +
           "secrets (environment variables; values are never shown):\n"
           "RP_VEEAM_USERNAME         " +
           std::string{secrets.user} + "\n" + "RP_VEEAM_PASSWORD         " +
           std::string{secrets.password} + "\n" + "RP_GRAPH_CERT_PFX_BASE64  " +
           std::string{secrets.pfx} + "\n" + "RP_GRAPH_CERT_PASSWORD    " +
           std::string{secrets.pfx_password} + "\n" + "RP_SIGNING_KEY_BASE64     " +
           std::string{secrets.signing_key} + "\n";
}

struct Run {
    int exit_code;
    std::string out;
    std::string err;
};

using DefaultPath = std::function<std::filesystem::path()>;

Run run(const Args& args, const DefaultPath& default_path)
{
    std::ostringstream out;
    std::ostringstream err;
    const int exit_code = rp::run_config_command(args, out, err, default_path);
    return {exit_code, out.str(), err.str()};
}

Run run(const Args& args, const std::filesystem::path& default_path)
{
    return run(args, DefaultPath{[default_path] { return default_path; }});
}

// A default path that counts how often run_config_command asks for it.
struct PathSpy {
    int calls = 0;

    DefaultPath provider()
    {
        return [this] {
            ++calls;
            return std::filesystem::path("unused.json");
        };
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
        Args{"check", "check"});
    CAPTURE(args);
    PathSpy spy;

    const Run result = run(args, spy.provider());
    REQUIRE(result.exit_code == 64);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == kUsage);
    // Usage errors never look up ProgramData.
    REQUIRE(spy.calls == 0);
}

TEST_CASE("rpworker config check exits 1 with the error when the config doesn't load",
          "[config_check]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path missing = dir.path() / "missing.json";
    const std::string missing_arg = utf8(missing);

    PathSpy spy;
    const Run result = run(Args{"check", "--config", missing_arg}, spy.provider());
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + missing_arg + ": cannot read config file\n");
}

TEST_CASE("rpworker config check reports an invalid config without its values", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", R"({"cloud_url": "http://SENTINEL-2a9f"})");
    const std::string path_arg = utf8(path);

    PathSpy spy;
    const Run result = run(Args{"check", "--config", path_arg}, spy.provider());
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err ==
            "config error: " + path_arg +
                ": config key \"cloud_url\" must be an https:// URL with no user name, password, "
                "query or fragment\n");
}

TEST_CASE("rpworker config check prints every setting and masks the secrets", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const std::string path_arg = utf8(path);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, "user-0c41");
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, "password-0c41");
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, std::nullopt);
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, std::nullopt);
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, std::nullopt);

    PathSpy spy;
    const Run result = run(Args{"check", "--config", path_arg}, spy.provider());
    REQUIRE(result.err.empty());
    REQUIRE(result.out ==
            expected_output(path, {"**** (set)", "**** (set)", "(not set)", "(not set)"}));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reads the default path without --config", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    // Not a PFX, nor even Base64: config check stays offline and never opens
    // the certificate, it only says whether the variable is set.
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, "pfx-0c41");
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, "pfx-password-0c41");
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, "key-0c41");

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.err.empty());
    REQUIRE(result.out ==
            expected_output(
                path, {"(not set)", "(not set)", "**** (set)", "**** (set)", "**** (set)"}));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check never prints a secret's value", "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, "SENTINEL-USER-91e7");
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, "SENTINEL-PASSWORD-91e7");
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, "SENTINEL-PFX-91e7");
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, "SENTINEL-PFX-PASSWORD-91e7");
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, "SENTINEL-KEY-91e7");

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.exit_code == 0);
    const std::string all = result.out + result.err;
    REQUIRE_THAT(all, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(all, !ContainsSubstring("91e7"));
    REQUIRE_THAT(all, ContainsSubstring("RP_VEEAM_USERNAME         **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("RP_VEEAM_PASSWORD         **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("RP_GRAPH_CERT_PFX_BASE64  **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("RP_GRAPH_CERT_PASSWORD    **** (set)\n"));
    REQUIRE_THAT(all, ContainsSubstring("RP_SIGNING_KEY_BASE64     **** (set)\n"));
}

TEST_CASE("rpworker config check never prints a password in a URL", "[config_check]")
{
    const rp::test::TempDir dir;
    std::string text = kConfigJson;
    const std::string url = "https://cloud.example.invalid";
    text.replace(text.find(url), url.size(), "https://user:SENTINEL-3b8d@cloud.example.invalid");
    const auto path = dir.write("config.json", text);

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.exit_code == 1);
    REQUIRE_THAT(result.out + result.err, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(result.err, ContainsSubstring("\"cloud_url\""));
}

TEST_CASE("rpworker config check --config reads a UTF-8 path outside the ANSI code page",
          "[config_check]")
{
    const rp::test::TempDir dir;
    // Cyrillic letters: not in cp1252, the ANSI code page of a Western machine.
    const auto path =
        dir.write(std::filesystem::path(u8"\u0442\u0435\u0441\u0442.json"), kConfigJson);
    const std::string path_arg = utf8(path);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, std::nullopt);
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, std::nullopt);
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, std::nullopt);

    PathSpy spy;
    const Run result = run(Args{"check", "--config", path_arg}, spy.provider());
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_output(path, kNoSecrets));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reports a veeam_ca_file it can't read", "[config_check]")
{
    const rp::test::TempDir dir;
    std::string text = kConfigJson;
    const std::string ca_arg = utf8(dir.path() / "missing.pem");
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() + ",");
    const std::string path_arg = utf8(dir.write("config.json", text));

    PathSpy spy;
    const Run result = run(Args{"check", "--config", path_arg}, spy.provider());
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + path_arg +
                              ": config key \"veeam_ca_file\" names a file that can't be read\n");
}

TEST_CASE("rpworker config check prints veeam_ca_file, outside the ANSI code page too",
          "[config_check]")
{
    const rp::test::TempDir dir;
    const std::filesystem::path name =
        GENERATE(std::filesystem::path("veeam-ca.pem"),
                 std::filesystem::path(u8"тест-ca.pem"));
    const std::string ca_arg = utf8(dir.write(name, "-----BEGIN CERTIFICATE-----\n"));
    CAPTURE(ca_arg);
    std::string text = kConfigJson;
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() + ",");
    const auto path = dir.write("config.json", text);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, std::nullopt);
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, std::nullopt);
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, std::nullopt);

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_output(path, kNoSecrets, ca_arg));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check prints veeam_cert_sha256 after veeam_ca_file", "[config_check]")
{
    const rp::test::TempDir dir;
    const rp::test::Cert cert =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const std::string ca_arg = utf8(dir.write("veeam-rest.pem", cert.pem().cert));
    const std::string sha256 = rp::test::cert_sha256_hex(cert);
    std::string text = kConfigJson;
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() +
                       ", \"veeam_cert_sha256\": \"" + sha256 + "\",");
    const auto path = dir.write("config.json", text);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, std::nullopt);
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, std::nullopt);
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, std::nullopt);

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.err.empty());
    REQUIRE(result.out ==
            expected_output(path, kNoSecrets, ca_arg, sha256));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reports a screenshots_enabled that isn't true or false",
          "[config_check]")
{
    const rp::test::TempDir dir;
    std::string text = kConfigJson;
    text.insert(1, R"("screenshots_enabled": "true",)");
    const std::string path_arg = utf8(dir.write("config.json", text));

    PathSpy spy;
    const Run result = run(Args{"check", "--config", path_arg}, spy.provider());
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + path_arg +
                              ": config key \"screenshots_enabled\" must be true or false\n");
}

TEST_CASE("rpworker config check prints screenshots_enabled as true or false", "[config_check]")
{
    const rp::test::TempDir dir;
    const std::string value = GENERATE("true", "false");
    CAPTURE(value);
    std::string text = kConfigJson;
    text.insert(1, "\"screenshots_enabled\": " + value + ",");
    const auto path = dir.write("config.json", text);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, std::nullopt);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, std::nullopt);
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, std::nullopt);
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, std::nullopt);
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, std::nullopt);

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.err.empty());
    REQUIRE(result.out == expected_output(path, kNoSecrets, "(not set)", "(not set)", value));
    REQUIRE(result.exit_code == 0);
}

TEST_CASE("rpworker config check reports a veeam_ca_file that doesn't hold the pinned "
          "certificate",
          "[config_check]")
{
    const rp::test::TempDir dir;
    const rp::test::Cert held =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const rp::test::Cert other =
        rp::test::make_cert("Veeam Software", rp::test::Role::veeam_default);
    const std::string ca_arg = utf8(dir.write("veeam-rest.pem", held.pem().cert));
    std::string text = kConfigJson;
    text.insert(1, "\"veeam_ca_file\": " + nlohmann::json(ca_arg).dump() +
                       ", \"veeam_cert_sha256\": \"" + rp::test::cert_sha256_hex(other) + "\",");
    const std::string path_arg = utf8(dir.write("config.json", text));

    PathSpy spy;
    const Run result = run(Args{"check", "--config", path_arg}, spy.provider());
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: " + path_arg +
                              ": config key \"veeam_cert_sha256\": veeam_ca_file holds no "
                              "certificate whose SHA-256 is veeam_cert_sha256\n");
}

TEST_CASE("rpworker config check reports an empty --config path as unreadable", "[config_check]")
{
    PathSpy spy;
    const Run result = run(Args{"check", "--config", ""}, spy.provider());
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: : cannot read config file\n");
    REQUIRE(spy.calls == 0);
}

TEST_CASE("rpworker config check reports a --config path that isn't UTF-8", "[config_check]")
{
    const std::string path_arg = GENERATE(std::string("\xFF.json"), std::string("a\xC3.json"),
                                          std::string("\xED\xA0\x80.json"));
    CAPTURE(path_arg);

    PathSpy spy;
    const Run result = run(Args{"check", "--config", path_arg}, spy.provider());
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: the --config path is not valid UTF-8\n");
}

TEST_CASE("rpworker config check --config never looks up the default path", "[config_check]")
{
    const rp::test::TempDir dir;
    const std::string path_arg = utf8(dir.write("config.json", kConfigJson));
    PathSpy spy;

    REQUIRE(run(Args{"check", "--config", path_arg}, spy.provider()).exit_code == 0);
    REQUIRE(spy.calls == 0);
}

TEST_CASE("rpworker config check reports a default path it can't find", "[config_check]")
{
    const DefaultPath fails = []() -> std::filesystem::path {
        throw rp::ConfigError("", "cannot find the ProgramData folder");
    };

    const Run result = run(Args{"check"}, fails);
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: cannot find the ProgramData folder\n");
}

TEST_CASE("rpworker config check reports any other failure without its message",
          "[config_check]")
{
    const DefaultPath fails = []() -> std::filesystem::path {
        throw std::runtime_error("SENTINEL-d51f");
    };

    const Run result = run(Args{"check"}, fails);
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err == "config error: unexpected failure\n");
}

TEST_CASE("rpworker config check reports a secret variable that isn't valid Unicode",
          "[config_check]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword,
                                       std::wstring{L"SENTINEL-8e15"} + L'\xDC00');

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE(result.err ==
            "config error: environment variable RP_VEEAM_PASSWORD is not valid Unicode\n");
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
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", text);
    const rp::test::ScopedEnv user(rp::kEnvVeeamUsername, "SENTINEL-ENV-USER-7a64");
    const rp::test::ScopedEnv password(rp::kEnvVeeamPassword, "SENTINEL-ENV-PASSWORD-7a64");
    const rp::test::ScopedEnv pfx(rp::kEnvGraphCertPfxBase64, "SENTINEL-ENV-PFX-7a64");
    const rp::test::ScopedEnv pfx_password(rp::kEnvGraphCertPassword, "SENTINEL-ENV-PFXPW-7a64");
    const rp::test::ScopedEnv signing_key(rp::kEnvSigningKeyBase64, "SENTINEL-ENV-KEY-7a64");

    const Run result = run(Args{"check"}, path);
    REQUIRE(result.exit_code == 1);
    REQUIRE(result.out.empty());
    REQUIRE_THAT(result.err, ContainsSubstring("config error: "));
    REQUIRE_THAT(result.out + result.err, !ContainsSubstring("SENTINEL"));
    REQUIRE_THAT(result.out + result.err, !ContainsSubstring("7a64"));
}
