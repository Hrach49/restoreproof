#include <rp/cli.hpp>
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

const std::string kUsage = "usage: rpworker --version | rpworker config check [--config <path>] | "
                           "rpworker veeam list [--config <path>]\n";

const std::string kConfigJson = R"({
    "cloud_url": "https://cloud.example.invalid",
    "veeam_url": "https://veeam.example.invalid",
    "veeam_org_name": "example.onmicrosoft.com",
    "graph_tenant_id": "tenant",
    "graph_client_id": "client",
    "test_mailbox": "restoretest@example.onmicrosoft.com",
    "test_site_id": "site",
    "test_library_id": "library",
    "test_onedrive_drive_id": "drive",
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
        Args{"veeam", "list", "--config"});
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
    STATIC_REQUIRE(rp::exit_code::veeam == 4);
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
    const Args args{"config", "check", "--config", path_arg};

    std::ostringstream out;
    std::ostringstream err;
    REQUIRE(rp::run_cli(args, out, err) == 0);
    REQUIRE(err.str().empty());
    REQUIRE(out.str().starts_with("config file: " + path_arg + "\n"));
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
    const std::vector<const wchar_t*> argv{L"rpworker.exe", L"config", L"check", L"--config",
                                           wide_path.c_str()};

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
