#include <rp/cli.hpp>
#include <rp/secrets.hpp>
#include <rp/vault.hpp>
#include <rp/version.hpp>

#include "test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using Args = std::vector<std::string_view>;

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
    "[--record <dir>] | rpworker cloud revoke [--config <path>] [--vault <file>] [--record <dir>] | "
    "rpworker signer public-key [--vault <file>] | rpworker signer new-key [--vault <file>] [--replace] | "
    "rpworker signer verify <folder> --public-key <pem file> [--tsa-ca <pem file>] | "
    "rpworker service install [--config <path>] | rpworker service uninstall|start|stop | "
    "rpworker service run [--config <path>] | "
    "rpworker doctor [--config <path>] [--vault <file>] [--client <profile file>]... "
    "[--json <file>] [--record <dir>]\n";

const std::string kConfigJson = R"({
    "cloud_url": "https://cloud.example.invalid",
    "veeam_url": "https://veeam.example.invalid",
    "veeam_org_name": "example.onmicrosoft.com",
    "graph_tenant_id": "00000000-0000-0000-0000-000000000001",
    "graph_client_id": "00000000-0000-0000-0000-000000000002",
    "test_mailbox": "restoretest@example.onmicrosoft.com",
    "test_site_id": "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002",
    "test_library_id": "b!library",
    "test_onedrive_drive_id": "b!drive",
    "test_onedrive_folder_id": "folder"
})";

} // namespace

TEST_CASE("rpworker prints usage to stderr and exits 64 for a command line it doesn't know", "[cli]")
{
    const Args args = GENERATE(
        Args{},
        Args{"--no-such-option"},
        Args{""},
        Args{"-v"},
        Args{"version"},
        Args{"--VERSION"},
        Args{"--version", "extra"},
        Args{"extra", "--version"},
        Args{"--version", "--version"},
        Args{"config"},
        Args{"Config", "check"},
        Args{"--version", "config", "check"},
        Args{"config", "check", "--config"},
        Args{"veeam"},
        Args{"Veeam", "list"},
        Args{"veeam", "lst"},
        Args{"veeam", "list", "--config"},
        // W3.6: `test` takes restore's options and --json (a file, never empty),
        // never --seed; `restore` takes neither.
        Args{"Test"},
        Args{"test", "--seed", "1"},
        Args{"test", "--json"},
        Args{"test", "--json", ""},
        Args{"test", "--json", "a.json", "--json", "b.json"},
        Args{"restore", "--json", "a.json"},
        // W4.2: --evidence (a folder, never empty) or --json, not both;
        // `restore` takes neither.
        Args{"test", "--evidence"},
        Args{"test", "--evidence", ""},
        Args{"test", "--evidence", "runs", "--json", "a.json"},
        Args{"restore", "--evidence", "runs"},
        Args{"restore", "--seed", "1"},
        // W4.3: `signer public-key` alone, or `signer verify` with a folder
        // and a key file.
        Args{"signer"},
        Args{"Signer", "public-key"},
        Args{"signer", "public-key", "extra"},
        Args{"signer", "verify"},
        Args{"signer", "verify", "folder"},
        Args{"signer", "rotate"},
        // W4.5: `signer public-key` takes --vault <file> and nothing else;
        // `vault` needs a subcommand, `set`/`remove` a name, `grant` an
        // account; `config check` takes --vault <file>.
        Args{"signer", "public-key", "--vault"},
        Args{"signer", "public-key", "--vault", ""},
        Args{"signer", "public-key", "extra"},
        Args{"vault"},
        Args{"Vault", "list"},
        Args{"vault", "set"},
        Args{"vault", "grant"},
        Args{"vault", "list", "--vault"},
        Args{"config", "check", "--vault"},
        Args{"config", "check", "--vault", "a", "--vault", "b"},
        Args{"veeam", "list", "--vault"},
        Args{"graph", "list", "--vault"},
        Args{"restore", "--vault"},
        Args{"test", "--vault"},
        // W4.7: `service` takes one of five subcommands, --config (a path,
        // never empty, once) for `install` and `run` alone, and no other word.
        // Only command lines the command refuses before any call are here:
        // run_cli asks the machine's real Service Control Manager.
        Args{"service"},
        Args{"Service", "start"},
        Args{"service", "restart"},
        Args{"service", "status"},
        Args{"service", "start", "extra"},
        Args{"service", "stop", "--force"},
        Args{"service", "uninstall", "--config", "C:\\config.json"},
        Args{"service", "install", "--config"},
        Args{"service", "install", "--config", ""},
        Args{"service", "install", "--config", "C:\\a.json", "--config", "C:\\b.json"},
        Args{"service", "install", "--vault", "C:\\vault.bin"},
        Args{"service", "run", "extra"},
        Args{"service", "run", "--config"});
    CAPTURE(args);

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 64);
    REQUIRE(out.str().empty());
    REQUIRE(err.str() == kUsage);
}

TEST_CASE("rpworker's exit codes are fixed: 0 ok, 1 config, 2 auth, 3 transient, 4 Veeam, 64 usage",
          "[cli]")
{
    STATIC_REQUIRE(rp::exit_code::ok == 0);
    STATIC_REQUIRE(rp::exit_code::config == 1);
    STATIC_REQUIRE(rp::exit_code::auth == 2);
    STATIC_REQUIRE(rp::exit_code::transient == 3);
    STATIC_REQUIRE(rp::exit_code::service == 4);
    STATIC_REQUIRE(rp::exit_code::usage == 64);
    REQUIRE(rp::kCliUsage == kUsage);
}

TEST_CASE("rpworker --version prints the project version to stdout and exits 0", "[cli]")
{
    const Args args{"--version"};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 0);
    REQUIRE(out.str() == std::string{rp::version()} + "\n");
    REQUIRE(err.str().empty());
}

TEST_CASE("rpworker service reaches the service's commands", "[cli][service_command]")
{
    // The one `service` command line run_cli is given here that the command
    // takes: `run` with a --config path that isn't UTF-8, refused before the
    // dispatcher is called. run_cli's environment is the real one, so nothing
    // that asks the machine's Service Control Manager for anything is run
    // through it; `rpworker.exe service run` itself is an exe test.
    const Args args{"service", "run", "--config", "C:\\\xff\\config.json"};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 1);
    REQUIRE(out.str().empty());
    REQUIRE(err.str() == "service error: the --config path is not valid UTF-8\n");
}

TEST_CASE("rpworker reports an exception a command doesn't handle as exit 1, never a crash",
          "[cli]")
{
    // Escaping wmain, it would end in abort(), whose exit code on Windows is
    // 3: exit_code::transient, "try again later".
    rp::test::FailingStreamBuf failing;
    std::ostream out(&failing);
    out.exceptions(std::ios::badbit);
    std::ostringstream err;

    const Args args{"--version"};

    SECTION("run_cli")
    {
        REQUIRE(rp::run_cli(args, out, err) == 1);
        // Its message may not be safe to show.
        REQUIRE(err.str() == "error: unexpected failure\n");
    }
    SECTION("run_main")
    {
        const std::vector<const wchar_t*> argv{L"rpworker.exe", L"--version"};
        REQUIRE(rp::run_main(argv, out, err) == 1);
        REQUIRE(err.str() == "error: unexpected failure\n");
    }
    SECTION("with stderr failing too, the exit code still says so")
    {
        REQUIRE(rp::run_cli(args, out, out) == 1);
    }
}

TEST_CASE("rpworker config check --config <file> checks that file", "[cli]")
{
    const rp::test::TempDir dir;
    const auto path = dir.write("config.json", kConfigJson);
    const std::string path_arg = rp::test::narrow(path.wstring());
    // W4.5: a vault of its own, so the check never reads ProgramData's.
    const std::filesystem::path vault = dir.path() / "vault.bin";
    rp::write_vault(vault, rp::Secrets{});
    const std::string vault_arg = rp::test::narrow(vault.wstring());
    const Args args{"config", "check", "--config", path_arg, "--vault", vault_arg};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 0);
    REQUIRE(err.str().empty());
    REQUIRE(out.str().starts_with("config file: " + path_arg + "\n"));
    REQUIRE(out.str().ends_with("secrets (vault " + vault_arg + "; values are never shown):\n"
                                "veeam_username            (not set)\n"
                                "veeam_password            (not set)\n"
                                "graph_cert_pfx_base64     (not set)\n"
                                "graph_cert_password       (not set)\n"
                                "signing_key_base64        (not set)\n"
                                "cloud_install_token       (not set)\n"
                                "cloud_api_token           (not set)\n"));
}

TEST_CASE("rpworker's main() skips the program name and runs the rest", "[cli]")
{
    const std::vector<const wchar_t*> argv{L"rpworker.exe", L"--version"};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_main(argv, out, err) == 0);
    REQUIRE(out.str() == std::string{rp::version()} + "\n");
    REQUIRE(err.str().empty());
}

TEST_CASE("rpworker's main() prints usage for an empty command line or argument", "[cli]")
{
    const std::vector<const wchar_t*> argv =
        GENERATE(std::vector<const wchar_t*>{}, std::vector<const wchar_t*>{L"rpworker.exe"},
                 std::vector<const wchar_t*>{L"rpworker.exe", L""});
    CAPTURE(argv.size());

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_main(argv, out, err) == 64);
    REQUIRE(out.str().empty());
    REQUIRE(err.str() == kUsage);
}

TEST_CASE("rpworker's main() passes a path outside the ANSI code page on as UTF-8", "[cli]")
{
    const rp::test::TempDir dir;
    // Cyrillic letters: not in cp1252, so on a Western machine a narrow argv
    // would turn them into '?'.
    const auto path =
        dir.write(std::filesystem::path(L"\u0442\u0435\u0441\u0442.json"), kConfigJson);
    const std::wstring wide_path = path.wstring();
    const std::filesystem::path vault = dir.path() / "vault.bin";
    rp::write_vault(vault, rp::Secrets{});
    const std::wstring wide_vault = vault.wstring();
    const std::vector<const wchar_t*> argv{L"rpworker.exe", L"config", L"check", L"--config",
                                           wide_path.c_str(), L"--vault", wide_vault.c_str()};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_main(argv, out, err) == 0);
    REQUIRE(err.str().empty());
    REQUIRE(out.str().starts_with("config file: " + rp::test::narrow(wide_path) + "\n"));
}

TEST_CASE("rpworker's main() rejects an argument that isn't valid Unicode", "[cli]")
{
    // An unpaired surrogate, which no UTF-8 string can hold. The program name
    // is never converted, so it doesn't matter there.
    const std::wstring bad = std::wstring{L"x"} + L'\xD800' + L".json";
    // Generated values outlive each run of the test case, so they hold strings,
    // not pointers into `bad`.
    const std::vector<std::wstring> args = GENERATE_COPY(
        std::vector<std::wstring>{L"rpworker.exe", bad},
        std::vector<std::wstring>{L"rpworker.exe", L"config", L"check", L"--config", bad});
    std::vector<const wchar_t*> argv;
    for (const std::wstring& arg : args) {
        argv.push_back(arg.c_str());
    }
    CAPTURE(argv.size());

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_main(argv, out, err) == 64);
    REQUIRE(out.str().empty());
    REQUIRE(err.str() == kUsage);
}

TEST_CASE("rpworker's main() ignores a program name that isn't valid Unicode", "[cli]")
{
    const std::wstring program = std::wstring{L"rp"} + L'\xDC00' + L".exe";
    const std::vector<const wchar_t*> argv{program.c_str(), L"--version"};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_main(argv, out, err) == 0);
    REQUIRE(out.str() == std::string{rp::version()} + "\n");
}
