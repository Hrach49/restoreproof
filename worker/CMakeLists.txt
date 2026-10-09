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
# The result is validated against its embedded schema before it is written (W4.1).
find_package(nlohmann_json_schema_validator CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
# Test-only, directly: office_v1_test.cpp deflates the packages it builds.
find_package(ZLIB REQUIRED)

enable_testing()

# W4.9: the fixture secret scan (tools/fixture_secret_scan.py) runs as a ctest
# test when a Python is found; the gate's own tools need none at build time.
find_package(Python3 COMPONENTS Interpreter)
if(NOT Python3_Interpreter_FOUND)
    message(WARNING "No Python 3 found: the ctest test 'fixture secret scan' (W4.9) is not registered")
endif()

# rpcore: static library holding all Worker logic. rpworker (the exe) and
# rptests both link it; coverage is measured on its sources (src/, include/).
add_library(rpcore STATIC
    src/atomic_file.cpp
    src/base64.cpp
    src/canary_manifest.cpp
    src/canonical_json.cpp
    src/cert_export.cpp
    src/cert_pin.cpp
    src/checker.cpp
    src/cleaner.cpp
    src/cli.cpp
    src/client_assertion.cpp
    src/client_command.cpp
    src/client_profile.cpp
    src/command_config.cpp
    src/config.cpp
    src/config_check.cpp
    src/console_input.cpp
    src/connector.cpp
    src/connector_registry.cpp
    src/ed25519.cpp
    src/evidence_builder.cpp
    src/expected_set.cpp
    src/file_read.cpp
    src/folder_ops.cpp
    src/graph_client.cpp
    src/graph_command.cpp
    src/graph_download.cpp
    src/graph_errors.cpp
    src/graph_ids.cpp
    src/graph_paging.cpp
    src/graph_targets.cpp
    src/heartbeat.cpp
    src/http_client.cpp
    src/job_rules.cpp
    src/name_key.cpp
    src/office_v1.cpp
    src/outbox.cpp
    src/outbox_command.cpp
    src/recording_http_client.cpp
    src/redact.cpp
    src/restore_command.cpp
    src/result_builder.cpp
    src/result_schema.cpp
    src/retry_policy.cpp
    src/rfc3161.cpp
    src/run_folder_tail.cpp
    src/run_lock.cpp
    src/run_pipeline.cpp
    src/run_status.cpp
    src/sample_rng.cpp
    src/sample_selector.cpp
    src/scm.cpp
    src/secrets.cpp
    src/service.cpp
    src/service_command.cpp
    src/service_errors.cpp
    src/service_jobs.cpp
    src/service_recovery.cpp
    src/service_log.cpp
    src/service_log_stream.cpp
    src/service_loop.cpp
    src/worker_body.cpp
    src/sha256.cpp
    src/signer.cpp
    src/signer_command.cpp
    src/step_timer.cpp
    src/stop_signal.cpp
    src/target_guard.cpp
    src/target_guard_graph.cpp
    src/target_guard_veeam.cpp
    src/test_command.cpp
    src/text_table.cpp
    src/timestamper.cpp
    src/uploader.cpp
    src/text_v1.cpp
    src/utf16.cpp
    src/vault.cpp
    src/vault_command.cpp
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
# PRIVATE: cpr, OpenSSL, libzip and the schema validator stay behind rpcore's
# own interfaces (HTTP client, signer, office-v1, validate_result), so callers
# don't see their headers.
target_link_libraries(rpcore
    PUBLIC nlohmann_json::nlohmann_json spdlog::spdlog
    PRIVATE cpr::cpr OpenSSL::Crypto libzip::zip nlohmann_json_schema_validator::validator
)
# The result's schema (W4.1): shared/schemas/result.v1.json is the only copy,
# embedded as a byte array the build generates, so the Worker never reads a
# schema from disk. An edit to the file rebuilds; result_schema_test.cpp
# compares the embedded bytes with the file.
set(RP_RESULT_SCHEMA ${CMAKE_CURRENT_SOURCE_DIR}/../shared/schemas/result.v1.json)
set(RP_RESULT_SCHEMA_CPP ${CMAKE_CURRENT_BINARY_DIR}/generated/result_schema_bytes.cpp)
add_custom_command(
    OUTPUT ${RP_RESULT_SCHEMA_CPP}
    COMMAND ${CMAKE_COMMAND}
        -DINPUT=${RP_RESULT_SCHEMA} -DOUTPUT=${RP_RESULT_SCHEMA_CPP} -DSYMBOL=kResultSchema
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bytes.cmake
    DEPENDS ${RP_RESULT_SCHEMA} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bytes.cmake
    COMMENT "Embedding shared/schemas/result.v1.json"
    VERBATIM)
target_sources(rpcore PRIVATE ${RP_RESULT_SCHEMA_CPP})
# The default TSA's root (W4.4): shared/tsa/tsa-ca.pem is the only copy,
# embedded the same way, so a token of the default TSA is checked against a
# root the Worker carries, never one from disk or the Windows store. A test
# compares the embedded bytes with the file.
set(RP_TSA_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../shared/tsa/tsa-ca.pem)
set(RP_TSA_ROOT_CPP ${CMAKE_CURRENT_BINARY_DIR}/generated/tsa_root_bytes.cpp)
add_custom_command(
    OUTPUT ${RP_TSA_ROOT_CPP}
    COMMAND ${CMAKE_COMMAND}
        -DINPUT=${RP_TSA_ROOT} -DOUTPUT=${RP_TSA_ROOT_CPP} -DSYMBOL=kTsaRoot
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bytes.cmake
    DEPENDS ${RP_TSA_ROOT} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bytes.cmake
    COMMENT "Embedding shared/tsa/tsa-ca.pem"
    VERBATIM)
target_sources(rpcore PRIVATE ${RP_TSA_ROOT_CPP})
# C4062 (an enumerator not handled in a switch that has no default) is an
# error in rpcore, so a value added to an enum such as HttpMethod can't fall
# through to another value's behaviour unnoticed.
target_compile_options(rpcore PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/we4062>)
# program_data_dir() calls SHGetKnownFolderPath (shell32) and CoTaskMemFree (ole32);
# public_key_pin() reads the CA file with CryptQueryObject (crypt32), as curl does.
# The restore credential's export (W2.5, cert_export.cpp) also reads the store
# and exports a PFX (crypt32) and makes its password (bcrypt). The tests'
# network guard (Q2.1, http_client.cpp) opens the sockets it allows (ws2_32).
# The vault (W4.5, vault.cpp) encrypts with DPAPI (crypt32) and sets the
# file's ACL (advapi32).
target_link_libraries(rpcore PRIVATE shell32 ole32 crypt32 bcrypt ws2_32 advapi32)

# rpworker: the Worker exe. main() lives in app/ and only hands argv to
# rp::run_cli; all parsing is in rpcore, where rptests can reach it
# (docs/decisions.md).
add_executable(rpworker
    app/main.cpp
)
target_link_libraries(rpworker PRIVATE rpcore)

add_executable(rptests
    tests/atomic_file_test.cpp
    tests/base64_test.cpp
    tests/canary_manifest_test.cpp
    tests/canonical_json_test.cpp
    tests/cert_export_test.cpp
    tests/cert_pin_test.cpp
    tests/checker_test.cpp
    tests/cleaner_live_test.cpp
    tests/cleaner_test.cpp
    tests/client_assertion_test.cpp
    tests/cli_test.cpp
    tests/client_command_live_test.cpp
    tests/client_command_test.cpp
    tests/client_profile_test.cpp
    tests/command_config_test.cpp
    tests/config_check_test.cpp
    tests/config_test.cpp
    tests/connector_registry_test.cpp
    tests/connector_test.cpp
    tests/deps_test.cpp
    tests/ed25519_test.cpp
    tests/evidence_builder_test.cpp
    tests/expected_set_test.cpp
    tests/file_read_test.cpp
    tests/folder_ops_test.cpp
    tests/graph_client_live_test.cpp
    tests/graph_client_test.cpp
    tests/graph_command_live_test.cpp
    tests/graph_command_test.cpp
    tests/graph_download_test.cpp
    tests/graph_errors_test.cpp
    tests/graph_ids_test.cpp
    tests/graph_paging_test.cpp
    tests/graph_write_rule_test.cpp
    tests/heartbeat_test.cpp
    tests/graph_targets_live_test.cpp
    tests/graph_targets_test.cpp
    tests/http_client_test.cpp
    tests/http_client_tls_test.cpp
    tests/live_seed_test.cpp
    tests/name_key_test.cpp
    tests/office_v1_test.cpp
    tests/outbox_command_test.cpp
    tests/outbox_test.cpp
    tests/recording_http_client_test.cpp
    tests/redact_test.cpp
    tests/restore_command_test.cpp
    tests/restore_replay_test.cpp
    tests/result_builder_test.cpp
    tests/result_schema_test.cpp
    tests/retry_policy_test.cpp
    tests/rfc3161_test.cpp
    tests/run_lock_test.cpp
    tests/run_status_test.cpp
    tests/sample_rng_test.cpp
    tests/sample_selector_live_test.cpp
    tests/sample_selector_test.cpp
    tests/scm_test.cpp
    tests/secret_audit_test.cpp
    tests/secrets_test.cpp
    tests/service_command_test.cpp
    tests/service_errors_test.cpp
    tests/service_jobs_test.cpp
    tests/service_recovery_test.cpp
    tests/service_log_test.cpp
    tests/service_log_stream_test.cpp
    tests/service_loop_test.cpp
    tests/worker_body_test.cpp
    tests/service_test.cpp
    tests/sha256_test.cpp
    tests/signer_command_test.cpp
    tests/signer_test.cpp
    tests/smoke.cpp
    tests/step_timer_test.cpp
    tests/stop_signal_test.cpp
    tests/target_guard_test.cpp
    tests/target_guard_veeam_test.cpp
    tests/test_command_test.cpp
    tests/test_main.cpp
    tests/text_table_test.cpp
    tests/timestamp_verify_test.cpp
    tests/timestamper_test.cpp
    tests/uploader_test.cpp
    tests/text_util_test.cpp
    tests/text_v1_test.cpp
    tests/vault_command_test.cpp
    tests/vault_test.cpp
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
# restore_command_test.cpp's and test_command_test.cpp's Catch2 tables outgrow an object file's 65,279
# sections.
target_compile_options(rptests PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/bigobj>)
# cert_export_test.cpp deletes the CNG key file it makes (ncrypt);
# vault_test.cpp makes DPAPI blobs of its own (crypt32) and reads ACLs (advapi32).
target_link_libraries(rptests PRIVATE ncrypt crypt32 advapi32)
# httplib is test-only: the HTTP client tests run a server on 127.0.0.1.
# http_client_test.cpp also reads rpcore's internal src/http_client_detail.hpp.
target_link_libraries(rptests PRIVATE httplib::httplib)
# deps_test.cpp writes and reads a package with libzip; office_v1_test.cpp
# deflates the packages it builds byte by byte (zlib).
target_link_libraries(rptests PRIVATE libzip::zip ZLIB::ZLIB)
# deps_test.cpp validates a document with the schema validator directly.
target_link_libraries(rptests PRIVATE nlohmann_json_schema_validator::validator)
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
# environment variables the script removes before running the exe. STDIN names
# a file whose bytes are the exe's stdin (W4.5: what `vault set` reads). Each
# test carries the label `exe`: the coverage run (tools/run_coverage.ps1) runs
# rptests.exe once itself and only these through ctest (`ctest -L exe`).
set(RP_RUN_EXE_TEST ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_exe_test.cmake)
function(rp_add_exe_test name)
    cmake_parse_arguments(PARSE_ARGV 1 T "" "EXIT_CODE;STDOUT;STDERR;STDIN" "ARGS;UNSET_ENV")
    add_test(NAME "${name}" COMMAND ${CMAKE_COMMAND}
        "-DEXE=$<TARGET_FILE:rpworker>" "-DARGS=${T_ARGS}" "-DUNSET_ENV=${T_UNSET_ENV}"
        "-DSTDIN=${T_STDIN}"
        "-DEXIT_CODE=${T_EXIT_CODE}" "-DSTDOUT=${T_STDOUT}" "-DSTDERR=${T_STDERR}"
        -P ${RP_RUN_EXE_TEST})
    set_tests_properties("${name}" PROPERTIES LABELS exe)
endfunction()

rp_add_exe_test("rpworker --version prints the project version"
    ARGS --version EXIT_CODE 0 STDOUT ${PROJECT_VERSION} STDERR "")
set(RP_USAGE "usage: rpworker --version | rpworker config check [--config <path>] [--vault <file>] | rpworker vault set|remove <name> [--vault <file>] | rpworker vault list|test [--vault <file>] | rpworker vault grant <account> [--vault <file>] | rpworker veeam list [--config <path>] [--vault <file>] [--record <dir>] | rpworker graph list [--hash] [--config <path>] [--vault <file>] [--record <dir>] | rpworker client check --profile-file <file> [--vault <file>] [--record <dir>] | rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] [--record <dir>] [--profile-file <file>] | rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--vault <file>] [--record <dir>] [--profile-file <file>] [--json <file> | --evidence <dir> [--outbox <root>]] | rpworker outbox flush [--config <path>] [--outbox <root>] [--record <dir>] | rpworker outbox list [--outbox <root>] | rpworker signer public-key [--vault <file>] | rpworker signer verify <folder> --public-key <pem file> [--tsa-ca <pem file>] | rpworker service install [--config <path>] | rpworker service uninstall|start|stop | rpworker service run [--config <path>]")
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

# W4.8: a config whose jobs_file isn't an absolute path, made under the build
# tree from the example config. The service's working directory is System32,
# so a relative path would name a file that depends on where the process is.
set(RP_EXE_CONFIGS ${CMAKE_CURRENT_BINARY_DIR}/config-exe-test)
file(MAKE_DIRECTORY ${RP_EXE_CONFIGS})
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json RP_EXAMPLE_CONFIG)
string(REPLACE "\"screenshots_enabled\": false" "\"screenshots_enabled\": false,\n    \"jobs_file\": \"jobs.json\""
    RP_RELATIVE_JOBS_CONFIG "${RP_EXAMPLE_CONFIG}")
file(WRITE ${RP_EXE_CONFIGS}/relative-jobs.json "${RP_RELATIVE_JOBS_CONFIG}")
rp_add_exe_test("rpworker config check refuses a jobs_file that isn't an absolute path"
    ARGS config check --config ${RP_EXE_CONFIGS}/relative-jobs.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: ${RP_EXE_CONFIGS}/relative-jobs.json: config key \"jobs_file\" must be an absolute path, such as C:\\ProgramData\\RestoreProof\\jobs.json")

# The vault (W4.5): the exe tests use vault files of their own under the build
# tree, never %ProgramData%'s, each filled by `rpworker vault set` with the
# value piped in from a file (STDIN; a CRLF line end, stripped) and listed back
# by `vault list`. The four vaults are setup tests of the fixture `exe-vault`,
# ordered on each file by DEPENDS, and every test that reads one requires the
# fixture. The values are "set-by-ctest": not Base64, not a key.
set(RP_EXE_VAULTS ${CMAKE_CURRENT_BINARY_DIR}/vault-exe-test)
file(MAKE_DIRECTORY ${RP_EXE_VAULTS})
file(WRITE ${RP_EXE_VAULTS}/value.txt "set-by-ctest\r\n")
file(WRITE ${RP_EXE_VAULTS}/empty.txt "")
set(RP_VAULT_USER ${RP_EXE_VAULTS}/user.bin)       # veeam_username
set(RP_VAULT_TWO ${RP_EXE_VAULTS}/two.bin)         # veeam_username, veeam_password
set(RP_VAULT_FULL ${RP_EXE_VAULTS}/full.bin)       # those, graph_cert_pfx_base64, signing_key_base64
set(RP_VAULT_EMPTY ${RP_EXE_VAULTS}/empty.bin)     # nothing
set(RP_VAULT_MISSING ${RP_EXE_VAULTS}/no-such-vault.bin)
function(rp_add_vault_setup name vault secret)
    cmake_parse_arguments(PARSE_ARGV 3 T "" "AFTER" "")
    rp_add_exe_test("${name}"
        ARGS vault set ${secret} --vault ${vault} STDIN ${RP_EXE_VAULTS}/value.txt
        EXIT_CODE 0 STDOUT "set ${secret} in ${vault}" STDERR "")
    set_tests_properties("${name}" PROPERTIES FIXTURES_SETUP exe-vault)
    if(T_AFTER)
        set_tests_properties("${name}" PROPERTIES DEPENDS "${T_AFTER}")
    endif()
endfunction()
rp_add_vault_setup("rpworker vault set stores veeam_username from stdin" ${RP_VAULT_USER} veeam_username)
rp_add_vault_setup("rpworker vault set stores veeam_username (two)" ${RP_VAULT_TWO} veeam_username)
rp_add_vault_setup("rpworker vault set stores veeam_password (two)" ${RP_VAULT_TWO} veeam_password
    AFTER "rpworker vault set stores veeam_username (two)")
rp_add_vault_setup("rpworker vault set stores veeam_username (full)" ${RP_VAULT_FULL} veeam_username)
rp_add_vault_setup("rpworker vault set stores veeam_password (full)" ${RP_VAULT_FULL} veeam_password
    AFTER "rpworker vault set stores veeam_username (full)")
rp_add_vault_setup("rpworker vault set stores graph_cert_pfx_base64 (full)" ${RP_VAULT_FULL} graph_cert_pfx_base64
    AFTER "rpworker vault set stores veeam_password (full)")
rp_add_vault_setup("rpworker vault set stores signing_key_base64 (full)" ${RP_VAULT_FULL} signing_key_base64
    AFTER "rpworker vault set stores graph_cert_pfx_base64 (full)")
rp_add_vault_setup("rpworker vault set stores veeam_username (empty)" ${RP_VAULT_EMPTY} veeam_username)
rp_add_exe_test("rpworker vault remove takes veeam_username out (empty)"
    ARGS vault remove veeam_username --vault ${RP_VAULT_EMPTY}
    EXIT_CODE 0 STDOUT "removed veeam_username from ${RP_VAULT_EMPTY}" STDERR "")
set_tests_properties("rpworker vault remove takes veeam_username out (empty)" PROPERTIES
    FIXTURES_SETUP exe-vault DEPENDS "rpworker vault set stores veeam_username (empty)")
# What the vault commands say.
rp_add_exe_test("rpworker vault without a subcommand prints usage"
    ARGS vault EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker vault set needs a name"
    ARGS vault set --vault ${RP_VAULT_MISSING} EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker vault set takes one of the five names"
    ARGS vault set RP_VEEAM_USERNAME --vault ${RP_VAULT_MISSING} EXIT_CODE 64 STDOUT ""
    STDERR "usage error: the name must be one of veeam_username, veeam_password, graph_cert_pfx_base64, graph_cert_password, signing_key_base64")
rp_add_exe_test("rpworker vault set refuses an empty value from stdin"
    ARGS vault set veeam_password --vault ${RP_VAULT_MISSING} STDIN ${RP_EXE_VAULTS}/empty.txt
    EXIT_CODE 1 STDOUT "" STDERR "vault error: the value is empty")
rp_add_exe_test("rpworker vault list reports a vault that isn't there"
    ARGS vault list --vault ${RP_VAULT_MISSING} EXIT_CODE 1 STDOUT ""
    STDERR "vault error: ${RP_VAULT_MISSING}: vault file not found")
rp_add_exe_test("rpworker vault list prints the names in the vault"
    ARGS vault list --vault ${RP_VAULT_USER} EXIT_CODE 0 STDOUT "veeam_username" STDERR "")
rp_add_exe_test("rpworker vault list prints nothing for an empty vault"
    ARGS vault list --vault ${RP_VAULT_EMPTY} EXIT_CODE 0 STDOUT "" STDERR "")
rp_add_exe_test("rpworker vault remove says when a name wasn't there"
    ARGS vault remove graph_cert_password --vault ${RP_VAULT_USER} EXIT_CODE 0
    STDOUT "graph_cert_password was not in ${RP_VAULT_USER}; nothing changed" STDERR "")
rp_add_exe_test("rpworker vault grant refuses an account this machine doesn't know"
    ARGS vault grant "NT SERVICE\\NoSuchService-w45" --vault ${RP_VAULT_USER} EXIT_CODE 1 STDOUT ""
    STDERR "vault error: ${RP_VAULT_USER}: the account NT SERVICE\\NoSuchService-w45 isn't known on this machine")
set_tests_properties(
    "rpworker vault list prints the names in the vault"
    "rpworker vault list prints nothing for an empty vault"
    "rpworker vault remove says when a name wasn't there"
    "rpworker vault grant refuses an account this machine doesn't know"
    PROPERTIES FIXTURES_REQUIRED exe-vault)

# veeam list stops before any request in each of these, so none reaches the
# network. config.example.json is valid, so the vault ones get as far as the
# secrets.
rp_add_exe_test("rpworker veeam without a subcommand prints usage"
    ARGS veeam EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker veeam rejects an unknown subcommand"
    ARGS veeam lst EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker veeam list reports a missing config file"
    ARGS veeam list --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker veeam list reports a vault that isn't there"
    ARGS veeam list --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_MISSING}
    EXIT_CODE 1 STDOUT "" STDERR "config error: ${RP_VAULT_MISSING}: vault file not found")
rp_add_exe_test("rpworker veeam list needs veeam_username"
    ARGS veeam list --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_EMPTY}
    EXIT_CODE 1 STDOUT "" STDERR "config error: veeam_username is not in the vault")
rp_add_exe_test("rpworker veeam list needs veeam_password"
    ARGS veeam list --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_USER}
    EXIT_CODE 1 STDOUT "" STDERR "config error: veeam_password is not in the vault")
# --record (Q2.1) refuses a folder that isn't empty (this source folder) after
# the secrets and before any request.
rp_add_exe_test("rpworker veeam list --record needs a folder"
    ARGS veeam list --record EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker veeam list --record refuses a folder that isn't empty"
    ARGS veeam list --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_TWO}
    --record ${CMAKE_CURRENT_SOURCE_DIR}
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: ${CMAKE_CURRENT_SOURCE_DIR}: the --record folder is not empty")
set_tests_properties(
    "rpworker veeam list needs veeam_username"
    "rpworker veeam list needs veeam_password"
    "rpworker veeam list --record refuses a folder that isn't empty"
    PROPERTIES FIXTURES_REQUIRED exe-vault)

# graph list stops before any request in each of these too: the certificate is
# loaded before the first one.
rp_add_exe_test("rpworker graph without a subcommand prints usage"
    ARGS graph EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker graph list rejects an unknown flag"
    ARGS graph list --hashes EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker graph list reports a missing config file"
    ARGS graph list --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker graph list needs graph_cert_pfx_base64"
    ARGS graph list --hash --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_TWO}
    EXIT_CODE 1 STDOUT "" STDERR "config error: graph_cert_pfx_base64 is not in the vault")
set_tests_properties(
    "rpworker graph list needs graph_cert_pfx_base64"
    PROPERTIES FIXTURES_REQUIRED exe-vault)

# client check (W4.10) stops before any request in each of these: the
# arguments, the profile file, then the vault come first.
rp_add_exe_test("rpworker client without a subcommand prints usage"
    ARGS client EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker client check needs --profile-file"
    ARGS client check EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker client check rejects --config"
    ARGS client check --profile-file p.json --config c.json EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker client check reports a profile file that isn't there"
    ARGS client check --profile-file no-such-profile.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: --profile-file no-such-profile.json: can't be read")
rp_add_exe_test("rpworker client check refuses a profile that names another mailbox, naming the key"
    ARGS client check --profile-file ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/client-profile/alice-mailbox.json
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: --profile-file ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/client-profile/alice-mailbox.json: key \"test_mailbox\" must be restoretest@<domain>: restores only ever go to the restoretest mailbox")
rp_add_exe_test("rpworker client check refuses a profile missing a key, naming it"
    ARGS client check --profile-file ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/client-profile/missing-site.json
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: --profile-file ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/client-profile/missing-site.json: key \"test_site_id\" is missing (required)")
rp_add_exe_test("rpworker client check needs graph_cert_pfx_base64, after the profile"
    ARGS client check --profile-file ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/client-profile/valid.json --vault ${RP_VAULT_TWO}
    EXIT_CODE 1 STDOUT "" STDERR "config error: graph_cert_pfx_base64 is not in the vault")
set_tests_properties(
    "rpworker client check needs graph_cert_pfx_base64, after the profile"
    PROPERTIES FIXTURES_REQUIRED exe-vault)

# restore stops before any request in each of these too: the arguments, the
# config, the vault, the Veeam secrets and the Graph certificate (opened and
# checked) come first.
rp_add_exe_test("rpworker restore rejects an unknown flag"
    ARGS restore --mails 1 EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker restore rejects a sample size above 100"
    ARGS restore --mail 101 EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker restore reports a missing config file"
    ARGS restore --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker restore needs veeam_username"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_EMPTY}
    EXIT_CODE 1 STDOUT "" STDERR "config error: veeam_username is not in the vault")
rp_add_exe_test("rpworker restore needs veeam_password"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_USER}
    EXIT_CODE 1 STDOUT "" STDERR "config error: veeam_password is not in the vault")
rp_add_exe_test("rpworker restore needs graph_cert_pfx_base64"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_TWO}
    EXIT_CODE 1 STDOUT "" STDERR "config error: graph_cert_pfx_base64 is not in the vault")
rp_add_exe_test("rpworker restore opens the Graph certificate before any request"
    ARGS restore --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_FULL}
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: graph_cert_pfx_base64 is not valid Base64 (one line of A-Z, a-z, 0-9, + and /, padded with =)")
set_tests_properties(
    "rpworker restore needs veeam_username"
    "rpworker restore needs veeam_password"
    "rpworker restore needs graph_cert_pfx_base64"
    "rpworker restore opens the Graph certificate before any request"
    PROPERTIES FIXTURES_REQUIRED exe-vault)

# test (W3.6) runs restore's pipeline, so it stops at the same places before any
# request; its --json path is checked once the config is read and before the
# vault, so its refusals need no vault (a vault that isn't there shows that). A
# non-UTF-8 --json path can't come through wmain, and an empty one can't come
# through a CMake list (rptests covers both).
rp_add_exe_test("rpworker test rejects an unknown flag"
    ARGS test --seed 1 EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker test rejects a sample size above 100"
    ARGS test --mail 101 EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker test --json needs a file"
    ARGS test --json EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker test reports a missing config file"
    ARGS test --config no-such-config.json EXIT_CODE 1 STDOUT ""
    STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker test --json refuses a file that already exists"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_MISSING}
    --json ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: --json ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json: the file already exists")
rp_add_exe_test("rpworker test --json refuses a folder that doesn't exist"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_MISSING}
    --json ${CMAKE_CURRENT_SOURCE_DIR}/no-such-folder/run.json
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: --json ${CMAKE_CURRENT_SOURCE_DIR}/no-such-folder/run.json: the folder doesn't exist")
rp_add_exe_test("rpworker test --json refuses a name that holds a colon"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_MISSING}
    --json ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json:x
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: --json ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json:x: not a file name")
# W4.2: --evidence takes a runs root, never with --json; a --run-id that can't
# name the run's folder is refused once the config is read, before the vault.
rp_add_exe_test("rpworker test --evidence needs a folder"
    ARGS test --evidence EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker test takes --json or --evidence, not both"
    ARGS test --json run.json --evidence runs EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker test --evidence refuses a run ID that can't name a folder"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_MISSING}
    --evidence ${CMAKE_CURRENT_BINARY_DIR}/no-such-runs --run-id rp:1
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: --evidence: the run ID can't name a folder")
rp_add_exe_test("rpworker test needs veeam_username"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_EMPTY}
    EXIT_CODE 1 STDOUT "" STDERR "config error: veeam_username is not in the vault")
rp_add_exe_test("rpworker test needs veeam_password"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_USER}
    EXIT_CODE 1 STDOUT "" STDERR "config error: veeam_password is not in the vault")
rp_add_exe_test("rpworker test needs graph_cert_pfx_base64"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_TWO}
    EXIT_CODE 1 STDOUT "" STDERR "config error: graph_cert_pfx_base64 is not in the vault")
rp_add_exe_test("rpworker test opens the Graph certificate before any request"
    ARGS test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.example.json --vault ${RP_VAULT_FULL}
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: graph_cert_pfx_base64 is not valid Base64 (one line of A-Z, a-z, 0-9, + and /, padded with =)")
set_tests_properties(
    "rpworker test needs veeam_username"
    "rpworker test needs veeam_password"
    "rpworker test needs graph_cert_pfx_base64"
    "rpworker test opens the Graph certificate before any request"
    PROPERTIES FIXTURES_REQUIRED exe-vault)

# signer (W4.3) reads no config. public-key stops at the vault's signing key:
# a vault without one, then one holding something that is no key. verify needs
# a key file before it looks at the folder: RFC 8032 test 1's public key
# (shared/testdata/signing-v1/keys.json), written into the build tree, beside a
# run folder with nothing in it.
set(RP_SIGNER_TEST_KEY ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/rfc8032-test-1.pub.pem)
file(WRITE ${RP_SIGNER_TEST_KEY}
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n")
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/empty-run)
rp_add_exe_test("rpworker signer without a subcommand prints usage"
    ARGS signer EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker signer rejects an unknown subcommand"
    ARGS signer new-key EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker signer verify needs a folder and a key file"
    ARGS signer verify ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/empty-run
    EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker signer verify --public-key needs a file"
    ARGS signer verify ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/empty-run --public-key
    EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker signer public-key needs signing_key_base64"
    ARGS signer public-key --vault ${RP_VAULT_EMPTY}
    EXIT_CODE 1 STDOUT "" STDERR "config error: signing_key_base64 is not in the vault")
rp_add_exe_test("rpworker signer public-key refuses a value that is no key"
    ARGS signer public-key --vault ${RP_VAULT_FULL}
    EXIT_CODE 1 STDOUT ""
    STDERR "config error: signing_key_base64 is not an Ed25519 private key (Base64 of PKCS#8 DER)")
rp_add_exe_test("rpworker signer public-key reports a vault that isn't there"
    ARGS signer public-key --vault ${RP_VAULT_MISSING}
    EXIT_CODE 1 STDOUT "" STDERR "config error: ${RP_VAULT_MISSING}: vault file not found")
set_tests_properties(
    "rpworker signer public-key needs signing_key_base64"
    "rpworker signer public-key refuses a value that is no key"
    PROPERTIES FIXTURES_REQUIRED exe-vault)
rp_add_exe_test("rpworker signer verify reports a key file that can't be read"
    ARGS signer verify ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/empty-run
    --public-key no-such-key.pem
    EXIT_CODE 1 STDOUT ""
    STDERR "signer error: --public-key no-such-key.pem: the file can't be read")
rp_add_exe_test("rpworker signer verify reports a folder that can't be opened"
    ARGS signer verify ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/no-such-run
    --public-key ${RP_SIGNER_TEST_KEY}
    EXIT_CODE 1 STDOUT ""
    STDERR "signer error: ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/no-such-run: the folder can't be opened")
# Exit 5: the folder was read and isn't a signed run folder.
rp_add_exe_test("rpworker signer verify answers a folder with no result in it with a word"
    ARGS signer verify ${CMAKE_CURRENT_BINARY_DIR}/signer-exe-test/empty-run
    --public-key ${RP_SIGNER_TEST_KEY}
    EXIT_CODE 5 STDOUT "not verified: result_unreadable" STDERR "")

# outbox (W4.6): `list` reads no config and no vault; an empty root, and one
# that isn't there, hold nothing. `flush` reads the config for cloud_url and,
# with nothing queued, asks no one.
set(RP_OUTBOX_EXE ${CMAKE_CURRENT_BINARY_DIR}/outbox-exe-test)
file(REMOVE_RECURSE ${RP_OUTBOX_EXE})
file(MAKE_DIRECTORY ${RP_OUTBOX_EXE}/empty-root)
file(WRITE ${RP_OUTBOX_EXE}/config.json [=[{
    "cloud_url": "https://cloud.example.invalid",
    "veeam_url": "https://veeam.example.invalid:4443",
    "veeam_org_name": "example.onmicrosoft.com",
    "graph_tenant_id": "00000000-0000-0000-0000-000000000001",
    "graph_client_id": "00000000-0000-0000-0000-000000000002",
    "test_mailbox": "restoretest@example.onmicrosoft.com",
    "test_site_id": "example.sharepoint.com,00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002",
    "test_library_id": "b!library-id",
    "test_onedrive_drive_id": "b!drive-id",
    "test_onedrive_folder_id": "folder-id"
}]=])
rp_add_exe_test("rpworker outbox without a subcommand prints usage"
    ARGS outbox EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker outbox rejects an unknown subcommand"
    ARGS outbox send EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker outbox list rejects a word too many"
    ARGS outbox list ${RP_OUTBOX_EXE}/empty-root EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker outbox list --outbox needs a root"
    ARGS outbox list --outbox EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker outbox flush rejects --vault"
    ARGS outbox flush --vault ${RP_VAULT_MISSING} EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker test --outbox needs --evidence"
    ARGS test --outbox ${RP_OUTBOX_EXE}/empty-root EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker outbox list on an empty root"
    ARGS outbox list --outbox ${RP_OUTBOX_EXE}/empty-root
    EXIT_CODE 0 STDOUT "0 queued, 0 sent" STDERR "")
rp_add_exe_test("rpworker outbox list on a root that isn't there"
    ARGS outbox list --outbox ${RP_OUTBOX_EXE}/no-such-root
    EXIT_CODE 0 STDOUT "0 queued, 0 sent" STDERR "")
rp_add_exe_test("rpworker outbox flush reports a missing config file"
    ARGS outbox flush --config no-such-config.json --outbox ${RP_OUTBOX_EXE}/empty-root
    EXIT_CODE 1 STDOUT "" STDERR "config error: no-such-config.json: cannot read config file")
rp_add_exe_test("rpworker outbox flush with nothing queued"
    ARGS outbox flush --config ${RP_OUTBOX_EXE}/config.json --outbox ${RP_OUTBOX_EXE}/empty-root
    EXIT_CODE 0 STDOUT "0 queued, 0 sent" STDERR "")

# `rpworker service` (W4.7). No test here names install, uninstall, start or
# stop: with valid arguments they would act on this machine's real service.
# Only the usage line, which comes before any call, and `service run`, which
# the Service Control Manager refuses in a process it didn't start (1063):
# that run is also what brings src/scm.cpp's dispatcher call into the
# coverage report.
rp_add_exe_test("rpworker service without a subcommand prints usage"
    ARGS service EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker service rejects an unknown subcommand"
    ARGS service status EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker service run rejects a word too many"
    ARGS service run now EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker service run --config needs a path"
    ARGS service run --config EXIT_CODE 64 STDOUT "" STDERR "${RP_USAGE}")
rp_add_exe_test("rpworker service run is what the Service Control Manager starts"
    ARGS service run EXIT_CODE 1 STDOUT ""
    STDERR "service error: service run is what the Service Control Manager starts; use rpworker service start")

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

# W4.9: the committed fixture, vector and evidence trees hold no secret shape
# (a JWT, a Bearer token, a PEM private key block, a private key's or a PFX's
# Base64 opening, a keyed secret with a value) but what
# tools/fixture_secret_scan_allowlist.json names by file, shape and value.
# The same scan runs in CI without a Worker build (.github/workflows/worker.yml,
# job fixture-scan). Label `scan`: the coverage run leaves it out.
if(Python3_Interpreter_FOUND)
    add_test(NAME "fixture secret scan" COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/fixture_secret_scan.py
        --root ${CMAKE_CURRENT_SOURCE_DIR}/..)
    set_tests_properties("fixture secret scan" PROPERTIES LABELS scan)
endif()
