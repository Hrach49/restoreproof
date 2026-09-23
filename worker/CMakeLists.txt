cmake_minimum_required(VERSION 3.25)

project(restoreproof_worker VERSION 0.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Catch2 3 CONFIG REQUIRED)
find_package(cpr CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)

enable_testing()

# rpcore: static library holding all Worker logic. rpworker (the exe) and
# rptests both link it; coverage is measured on its sources (src/, include/).
add_library(rpcore STATIC
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

add_executable(rptests
    tests/deps_test.cpp
    tests/smoke.cpp
    tests/version_test.cpp
)
# deps_test.cpp uses cpr and OpenSSL directly, so it links them itself.
target_link_libraries(rptests PRIVATE rpcore cpr::cpr OpenSSL::Crypto Catch2::Catch2WithMain)

include(Catch)
catch_discover_tests(rptests)
