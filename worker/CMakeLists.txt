cmake_minimum_required(VERSION 3.25)

project(restoreproof_worker VERSION 0.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Catch2 3 CONFIG REQUIRED)
find_package(cpr CONFIG REQUIRED)
# Test-only: the local HTTP(S) server the HTTP client tests talk to.
find_package(httplib CONFIG REQUIRED)
# office-v1 (W3.2) opens restored docx/xlsx packages; zlib is its only codec.
find_package(libzip CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
# Test-only, directly: office_v1_test.cpp deflates the packages it builds.
find_package(ZLIB REQUIRED)

enable_testing()

# rpcore: static library holding all Worker logic. rpworker (the exe) and
# rptests both link it; coverage is measured on its sources (src/, include/).
add_library(rpcore STATIC
    src/base64.cpp
    src/canary_manifest.cpp
    src/cert_export.cpp
    src/cert_pin.cpp
    src/checker.cpp
    src/cleaner.cpp
    src/cli.cpp
    src/client_assertion.cpp
    src/command_config.cpp
    src/config.cpp
    src/config_check.cpp
    src/connector.cpp
    src/connector_registry.cpp
    src/expected_set.cpp
    src/graph_client.cpp
    src/graph_command.cpp
    src/graph_download.cpp
    src/graph_errors.cpp
    src/graph_ids.cpp
    src/graph_paging.cpp
    src/graph_targets.cpp
    src/http_client.cpp
    src/name_key.cpp
    src/office_v1.cpp
    src/recording_http_client.cpp
    src/redact.cpp
    src/restore_command.cpp
    src/retry_policy.cpp
    src/run_lock.cpp
    src/run_status.cpp
    src/sample_rng.cpp
    src/sample_selector.cpp
    src/secrets.cpp
    src/sha256.cpp
    src/target_guard.cpp
    src/target_guard_graph.cpp
    src/target_guard_veeam.cpp
    src/text_table.cpp
    src/text_v1.cpp
    src/utf16.cpp
    src/veeam_browse.cpp
    src/veeam_candidates.cpp
    src/veeam_client.cpp
    src/veeam_command.cpp
    src/veeam_explore.cpp
    src/veeam_m365_connector.cpp
    src/veeam_restore.cpp
    src/veeam_time.cpp
    src/version.cpp
)
target_include_directories(rpcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(rpcore PUBLIC RP_VERSION="${PROJECT_VERSION}")
# PUBLIC: JSON values and loggers will appear in rpcore's headers.
# PRIVATE: cpr, OpenSSL and libzip stay behind rpcore's own interfaces (HTTP
# client, signer, office-v1), so callers don't see their headers.
target_link_libraries(rpcore
    PUBLIC nlohmann_json::nlohmann_json spdlog::spdlog
    PRIVATE cpr::cpr OpenSSL::Crypto libzip::zip
)
# C4062 (an enumerator not handled in a switch that has no default) is an
# error in rpcore, so a value added to an enum such as HttpMethod can't fall
# through to another value's behaviour unnoticed.
target_compile_options(rpcore PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/we4062>)
# program_data_dir() calls SHGetKnownFolderPath (shell32) and CoTaskMemFree (ole32);
# public_key_pin() reads the CA file with CryptQueryObject (crypt32), as curl does.
# The restore credential's export (W2.5, cert_export.cpp) also reads the store
# and exports a PFX (crypt32) and makes its password (bcrypt). The tests'
# network guard (Q2.1, http_client.cpp) opens the sockets it allows (ws2_32).
target_link_libraries(rpcore PRIVATE shell32 ole32 crypt32 bcrypt ws2_32)

# rpworker: the Worker exe. main() lives in app/ and only hands argv to
# rp::run_cli; all parsing is in rpcore, where rptests can reach it
# (docs/decisions.md).
add_executable(rpworker
    app/main.cpp
)
target_link_libraries(rpworker PRIVATE rpcore)

add_executable(rptests
    tests/base64_test.cpp
    tests/canary_manifest_test.cpp
    tests/cert_export_test.cpp
    tests/cert_pin_test.cpp
    tests/checker_test.cpp
    tests/cleaner_live_test.cpp
    tests/cleaner_test.cpp
    tests/client_assertion_test.cpp
    tests/cli_test.cpp
    tests/command_config_test.cpp
    tests/config_check_test.cpp
    tests/config_test.cpp
    tests/connector_registry_test.cpp
    tests/connector_test.cpp
    tests/deps_test.cpp
    tests/expected_set_test.cpp
    tests/graph_client_live_test.cpp
    tests/graph_client_test.cpp
    tests/graph_command_live_test.cpp
    tests/graph_command_test.cpp
    tests/graph_download_test.cpp
    tests/graph_errors_test.cpp
    tests/graph_ids_test.cpp
    tests/graph_paging_test.cpp
    tests/graph_write_rule_test.cpp
    tests/graph_targets_live_test.cpp
    tests/graph_targets_test.cpp
    tests/http_client_test.cpp
    tests/http_client_tls_test.cpp
    tests/live_seed_test.cpp
    tests/name_key_test.cpp
    tests/office_v1_test.cpp
    tests/recording_http_client_test.cpp
    tests/redact_test.cpp
    tests/restore_command_test.cpp
    tests/restore_replay_test.cpp
    tests/retry_policy_test.cpp
    tests/run_lock_test.cpp
    tests/run_status_test.cpp
    tests/sample_rng_test.cpp
    tests/sample_selector_live_test.cpp
    tests/sample_selector_test.cpp
    tests/secrets_test.cpp
    tests/sha256_test.cpp
    tests/smoke.cpp
    tests/target_guard_test.cpp
    tests/target_guard_veeam_test.cpp
    tests/test_main.cpp
    tests/text_table_test.cpp
    tests/text_util_test.cpp
    tests/text_v1_test.cpp
    tests/veeam_browse_test.cpp
    tests/veeam_client_live_test.cpp
    tests/veeam_client_test.cpp
    tests/veeam_command_test.cpp
    tests/veeam_m365_candidates_test.cpp
    tests/veeam_m365_connector_test.cpp
    tests/veeam_m365_restore_guard_test.cpp
    tests/veeam_m365_restore_live_test.cpp
    tests/veeam_m365_restore_test.cpp
    tests/veeam_restore_test.cpp
    tests/version_test.cpp
)
# deps_test.cpp uses cpr and OpenSSL directly, so it links them itself.
# tests/test_main.cpp is rptests' main: Catch2's, inside the network guard (Q2.1).
target_link_libraries(rptests PRIVATE rpcore cpr::cpr OpenSSL::Crypto Catch2::Catch2)
# restore_command_test.cpp's Catch2 tables outgrow an object file's 65,279
# sections.
target_compile_options(rptests PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/bigobj>)
# cert_export_test.cpp deletes the CNG key file it makes (ncrypt).
target_link_libraries(rptests PRIVATE ncrypt)
# httplib is test-only: the HTTP client tests run a server on 127.0.0.1.
# http_client_test.cpp also reads rpcore's internal src/http_client_detail.hpp.
target_link_libraries(rptests PRIVATE httplib::httplib)
# deps_test.cpp writes and reads a package with libzip; office_v1_test.cpp
# deflates the packages it builds byte by byte (zlib).
target_link_libraries(rptests PRIVATE libzip::zip ZLIB::ZLIB)
# The source scan in http_client_test.cpp looks for code that turns TLS
# verification off anywhere in the Worker.
target_compile_definitions(rptests PRIVATE RP_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
# config_test.cpp parses the shipped example, so it can't drift from the rules.
target_compile_definitions(rptests PRIVATE RP_CONFIG_EXAMPLE="${CMAKE_CURRENT_SOURCE_DIR}/config.example.json")
# Recorded service responses (tests/fixtures/<service>/), served by FakeHttpClient.
target_compile_definitions(rptests PRIVATE RP_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
# The test vectors shared with the lab and the Cloud (shared/testdata/), e.g. text-v1.
target_compile_definitions(rptests PRIVATE RP_SHARED_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../shared")

include(Catch)
catch_discover_tests(rptests)

# rpworker's main() can't be linked into rptests, so ctest runs the exe.
# run_exe_test.cmake checks the exit code and both streams exactly; ctest's own
# PASS_REGULAR_EXPRESSION and WILL_FAIL would ignore the exit code. ARGS takes
# any number of arguments; they reach the script as one list. UNSET_ENV names
# environment variables the script removes before running the exe. Each test
# carries the label `exe`: the coverage run (tools/run_coverage.ps1) runs
# rptests.exe once itself and only these through ctest (`ctest -L exe`).
set(RP_RUN_EXE_TEST ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_exe_test.cmake)
function(rp_add_exe_test name)
    cmake_parse_arguments(PARSE_ARGV 1 T "" "EXIT_CODE;STDOUT;STDERR" "ARGS;UNSET_ENV")
    add_test(NAME "${name}" COMMAND ${CMAKE_COMMAND}
        "-DEXE=$<TARGET_FILE:rpworker>" "-DARGS=${T_ARGS}" "-DUNSET_ENV=${T_UNSET_ENV}"
        "-DEXIT_CODE=${T_EXIT_CODE}" "-DSTDOUT=${T_STDOUT}" "-DSTDERR=${T_STDERR}"
        -P ${RP_RUN_EXE_TEST})
    set_tests_properties("${name}" PROPERTIES LABELS exe)
endfunction()

rp_add_exe_test("rpworker --version prints the project version"
    ARGS --version EXIT_CODE 0 STDOUT ${PROJECT_VERSION} STDERR "")
set(RP_USAGE "usage: rpworker --version | rpworker config check [--config <path>] | rpworker veeam list [--config <path>] [--record <dir>] | rpworker graph list [--hash] [--config <path>] [--record <dir>] | rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--record <dir>]")
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
# --record (Q2.1) refuses a folder that isn't empty (this source folder) after
# the secrets and before any request.
rp_add_exe_test("rpworker veeam list --record needs a folder"
    ARGS veeam list --record EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker veeam list --record refuses a folder that isn't empty"
    ARGS veeam list --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    --record ${CMAKE_CURRENT_SOURCE_DIR}
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: ${CMAKE_CURRENT_SOURCE_DIR}: the --record folder is not empty")
set_tests_properties(
    "rpworker veeam list needs RP_VEEAM_USERNAME"
    "rpworker veeam list needs RP_VEEAM_PASSWORD"
    "rpworker veeam list --record refuses a folder that isn't empty"
    PROPERTIES ENVIRONMENT "RP_VEEAM_USERNAME=set-by-ctest;RP_VEEAM_PASSWORD=set-by-ctest")

# graph list stops before any request in each of these too: the certificate is
# loaded before the first one. ctest sets both variables; the last test removes
# them.
rp_add_exe_test("rpworker graph without a subcommand prints usage"
    ARGS graph EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker graph list rejects an unknown flag"
    ARGS graph list --hashes EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker graph list reports a missing config file"
    ARGS graph list --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker graph list needs RP_GRAPH_CERT_PFX_BASE64"
    ARGS graph list --hash --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    UNSET_ENV RP_GRAPH_CERT_PFX_BASE64 RP_GRAPH_CERT_PASSWORD
    EXIT_CODE 1 STDOUT "" STDERR "config error: RP_GRAPH_CERT_PFX_BASE64 is not set")
set_tests_properties(
    "rpworker graph list needs RP_GRAPH_CERT_PFX_BASE64"
    PROPERTIES ENVIRONMENT "RP_GRAPH_CERT_PFX_BASE64=set-by-ctest;RP_GRAPH_CERT_PASSWORD=set-by-ctest")

# restore stops before any request in each of these too: the arguments, the
# config, the Veeam secrets and the Graph certificate (opened and checked) come
# first. ctest sets the variables, the first three of the last four tests
# remove them, and the last one's PFX isn't Base64.
rp_add_exe_test("rpworker restore rejects an unknown flag"
    ARGS restore --mails 1 EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker restore rejects a sample size above 100"
    ARGS restore --mail 101 EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker restore reports a missing config file"
    ARGS restore --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker restore needs RP_VEEAM_USERNAME"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    UNSET_ENV RP_VEEAM_USERNAME RP_VEEAM_PASSWORD
    EXIT_CODE 1 STDOUT "" STDERR "config error: RP_VEEAM_USERNAME is not set")
rp_add_exe_test("rpworker restore needs RP_VEEAM_PASSWORD"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    UNSET_ENV RP_VEEAM_PASSWORD
    EXIT_CODE 1 STDOUT "" STDERR "config error: RP_VEEAM_PASSWORD is not set")
rp_add_exe_test("rpworker restore needs RP_GRAPH_CERT_PFX_BASE64"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    UNSET_ENV RP_GRAPH_CERT_PFX_BASE64 RP_GRAPH_CERT_PASSWORD
    EXIT_CODE 1 STDOUT "" STDERR "config error: RP_GRAPH_CERT_PFX_BASE64 is not set")
rp_add_exe_test("rpworker restore opens the Graph certificate before any request"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: RP_GRAPH_CERT_PFX_BASE64 is not valid Base64 (one line of A-Z, a-z, 0-9, + and /, padded with =)")
set_tests_properties(
    "rpworker restore needs RP_VEEAM_USERNAME"
    "rpworker restore needs RP_VEEAM_PASSWORD"
    "rpworker restore needs RP_GRAPH_CERT_PFX_BASE64"
    "rpworker restore opens the Graph certificate before any request"
    PROPERTIES ENVIRONMENT
    "RP_VEEAM_USERNAME=set-by-ctest;RP_VEEAM_PASSWORD=set-by-ctest;RP_GRAPH_CERT_PFX_BASE64=set-by-ctest;RP_GRAPH_CERT_PASSWORD=set-by-ctest")

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
