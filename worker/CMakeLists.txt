cmake_minimum_required(VERSION 3.25)

project(restoreproof_worker VERSION 0.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Catch2 3 CONFIG REQUIRED)

enable_testing()

add_executable(rptests tests/smoke.cpp)
target_link_libraries(rptests PRIVATE Catch2::Catch2WithMain)

include(Catch)
catch_discover_tests(rptests)
