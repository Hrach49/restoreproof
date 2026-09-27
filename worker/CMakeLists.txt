cmake_minimum_required(VERSION 3.25)

project(restoreproof_worker VERSION 0.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Catch2 3 CONFIG REQUIRED)
find_package(cpr CONFIG REQUIRED)
# Test-only: the local HTTP(S) server the HTTP client tests talk to.
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)

enable_testing()

# rpcore: static library holding all Worker logic. rpworker (the exe) and
# rptests both link it; coverage is measured on its sources (src/, include/).
add_library(rpcore STATIC
    src/cert_pin.cpp
    src/cli.cpp
    src/command_config.cpp
    src/config.cpp
    src/config_check.cpp
    src/connector.cpp
    src/connector_registry.cpp
    src/http_client.cpp
    src/redact.cpp
    src/retry_policy.cpp
    src/secrets.cpp
    src/utf16.cpp
    src/veeam_client.cpp
    src/veeam_command.cpp
    src/version.cpp
)
target_include_directories(rpcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(rpcore PUBLIC RP_VERSION="${PROJECT_VERSION}")
# PUBLIC: JSON values and loggers will appear in rpcore's headers.
# PRIVATE: cpr and OpenSSL stay behind rpcore's own interfaces (HTTP client,
# signer), so callers don't see their headers.
target_link_libraries(rpcore
    PUBLIC nlohmann_json::nlohmann_json spdlog::spdlog
    PRIVATE cpr::cpr OpenSSL::Crypto
)
# C4062 (an enumerator not handled in a switch that has no default) is an
# error in rpcore, so a value added to an enum such as HttpMethod can't fall
# through to another value's behaviour unnoticed.
target_compile_options(rpcore PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/we4062>)
# program_data_dir() calls SHGetKnownFolderPath (shell32) and CoTaskMemFree (ole32);
# public_key_pin() reads the CA file with CryptQueryObject (crypt32), as curl does.
target_link_libraries(rpcore PRIVATE shell32 ole32 crypt32)

# rpworker: the Worker exe. main() lives in app/ and only hands argv to
# rp::run_cli; all parsing is in rpcore, where rptests can reach it
# (docs/decisions.md).
add_executable(rpworker
    app/main.cpp
)
target_link_libraries(rpworker PRIVATE rpcore)

add_executable(rptests
    tests/cert_pin_test.cpp
    tests/cli_test.cpp
    tests/config_check_test.cpp
    tests/config_test.cpp
    tests/connector_registry_test.cpp
    tests/connector_test.cpp
    tests/deps_test.cpp
    tests/http_client_test.cpp
    tests/http_client_tls_test.cpp
    tests/redact_test.cpp
    tests/retry_policy_test.cpp
    tests/secrets_test.cpp
    tests/smoke.cpp
    tests/veeam_client_live_test.cpp
    tests/veeam_client_test.cpp
    tests/veeam_command_test.cpp
    tests/version_test.cpp
)
# deps_test.cpp uses cpr and OpenSSL directly, so it links them itself.
target_link_libraries(rptests PRIVATE rpcore cpr::cpr OpenSSL::Crypto Catch2::Catch2WithMain)
# httplib is test-only: the HTTP client tests run a server on 127.0.0.1.
# http_client_test.cpp also reads rpcore's internal src/http_client_detail.hpp.
target_link_libraries(rptests PRIVATE httplib::httplib)
# The source scan in http_client_test.cpp looks for code that turns TLS
# verification off anywhere in the Worker.
target_compile_definitions(rptests PRIVATE RP_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
# config_test.cpp parses the shipped example, so it can't drift from the rules.
target_compile_definitions(rptests PRIVATE RP_CONFIG_EXAMPLE="${CMAKE_CURRENT_SOURCE_DIR}/config.example.json")
# Recorded service responses (tests/fixtures/<service>/), served by FakeHttpClient.
target_compile_definitions(rptests PRIVATE RP_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")

include(Catch)
catch_discover_tests(rptests)

# rpworker's main() can't be linked into rptests, so ctest runs the exe.
# run_exe_test.cmake checks the exit code and both streams exactly; ctest's own
# PASS_REGULAR_EXPRESSION and WILL_FAIL would ignore the exit code. ARGS takes
# any number of arguments; they reach the script as one list. UNSET_ENV names
# environment variables the script removes before running the exe.
set(RP_RUN_EXE_TEST ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_exe_test.cmake)
function(rp_add_exe_test name)
    cmake_parse_arguments(PARSE_ARGV 1 T "" "EXIT_CODE;STDOUT;STDERR" "ARGS;UNSET_ENV")
    add_test(NAME "${name}" COMMAND ${CMAKE_COMMAND}
        "-DEXE=$<TARGET_FILE:rpworker>" "-DARGS=${T_ARGS}" "-DUNSET_ENV=${T_UNSET_ENV}"
        "-DEXIT_CODE=${T_EXIT_CODE}" "-DSTDOUT=${T_STDOUT}" "-DSTDERR=${T_STDERR}"
        -P ${RP_RUN_EXE_TEST})
endfunction()

rp_add_exe_test("rpworker --version prints the project version"
    ARGS --version EXIT_CODE 0 STDOUT ${PROJECT_VERSION} STDERR "")
set(RP_USAGE "usage: rpworker --version | rpworker config check [--config <path>] | rpworker veeam list [--config <path>]")
rp_add_exe_test("rpworker rejects unknown arguments"
    ARGS --no-such-option EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker config without a subcommand prints usage"
    ARGS config EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
# Relative to the test's working directory, the build tree, where no config is.
rp_add_exe_test("rpworker config check reports a missing config file"
    ARGS config check --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
# Cyrillic letters aren't in cp1252: on a Western machine a narrow argv would turn them
# into '?' before the path reached rpcore.
rp_add_exe_test("rpworker config check keeps a --config path outside the ANSI code page"
    ARGS config check --config "тест-no-such-config.json" EXIT_CODE 1 STDOUT ""
    STDERR "config error: тест-no-such-config.json: cannot read config file")

# veeam list stops before any request in each of these, so none reaches the
# network. config.example.json is valid, so the last two get as far as the
# secrets. ctest sets both variables and run_exe_test removes the ones named
# in UNSET_ENV, which also shows that UNSET_ENV works.
rp_add_exe_test("rpworker veeam without a subcommand prints usage"
    ARGS veeam EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker veeam rejects an unknown subcommand"
    ARGS veeam lst EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker veeam list reports a missing config file"
    ARGS veeam list --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker veeam list needs RP_VEEAM_USERNAME"
    ARGS veeam list --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    UNSET_ENV RP_VEEAM_USERNAME RP_VEEAM_PASSWORD
    EXIT_CODE 1 STDOUT "" STDERR "config error: RP_VEEAM_USERNAME is not set")
rp_add_exe_test("rpworker veeam list needs RP_VEEAM_PASSWORD"
    ARGS veeam list --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    UNSET_ENV RP_VEEAM_PASSWORD
    EXIT_CODE 1 STDOUT "" STDERR "config error: RP_VEEAM_PASSWORD is not set")
set_tests_properties(
    "rpworker veeam list needs RP_VEEAM_USERNAME"
    "rpworker veeam list needs RP_VEEAM_PASSWORD"
    PROPERTIES ENVIRONMENT "RP_VEEAM_USERNAME=set-by-ctest;RP_VEEAM_PASSWORD=set-by-ctest")

# The checker itself must fail on a wrong exit code or wrong output, or the two
# tests above would prove nothing.
rp_add_exe_test("run_exe_test fails on a wrong exit code"
    ARGS --version EXIT_CODE 1 STDOUT ${PROJECT_VERSION} STDERR "")
rp_add_exe_test("run_exe_test fails on wrong stdout"
    ARGS --version EXIT_CODE 0 STDOUT "${PROJECT_VERSION}x" STDERR "")
rp_add_exe_test("run_exe_test fails on unexpected stderr"
    ARGS --version EXIT_CODE 0 STDOUT ${PROJECT_VERSION} STDERR "usage: rpworker --version")
set_tests_properties(
    "run_exe_test fails on a wrong exit code"
    "run_exe_test fails on wrong stdout"
    "run_exe_test fails on unexpected stderr"
    PROPERTIES WILL_FAIL TRUE)
