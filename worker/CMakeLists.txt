cmake_minimum_required(VERSION 3.25)

project(restoreproof_worker VERSION 0.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Catch2 3 CONFIG REQUIRED)

enable_testing()

# rpcore: static library holding all Worker logic. rpworker (the exe) and
# rptests both link it; coverage is measured on its sources (src/, include/).
add_library(rpcore STATIC
    src/version.cpp
)
target_include_directories(rpcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(rpcore PUBLIC RP_VERSION="${PROJECT_VERSION}")

add_executable(rptests
    tests/smoke.cpp
    tests/version_test.cpp
)
target_link_libraries(rptests PRIVATE rpcore Catch2::Catch2WithMain)

include(Catch)
catch_discover_tests(rptests)
