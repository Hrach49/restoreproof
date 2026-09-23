# Runs an executable and checks its exit code, stdout and stderr exactly.
# ctest's PASS_REGULAR_EXPRESSION ignores the exit code and WILL_FAIL accepts
# any non-zero one, a crash included, so tests of rpworker.exe go through here.
#
#   cmake -DEXE=<path> [-DARGS=<arg>] -DEXIT_CODE=<n> -DSTDOUT=<line> -DSTDERR=<line>
#         -P run_exe_test.cmake
#
# STDOUT and STDERR each name the one line the stream must hold, newline
# included; an empty value means the stream must be empty. CRLF counts as LF.
# ARGS is a CMake list; pass one argument unless you escape the semicolons.

cmake_minimum_required(VERSION 3.25)

foreach(var IN ITEMS EXE EXIT_CODE STDOUT STDERR)
    if(NOT DEFINED ${var})
        message(FATAL_ERROR "run_exe_test.cmake: -D${var}=... is required")
    endif()
endforeach()

execute_process(
    COMMAND "${EXE}" ${ARGS}
    RESULT_VARIABLE actual_exit
    OUTPUT_VARIABLE actual_stdout
    ERROR_VARIABLE actual_stderr
)
string(REPLACE "\r\n" "\n" actual_stdout "${actual_stdout}")
string(REPLACE "\r\n" "\n" actual_stderr "${actual_stderr}")

set(failures "")
if(NOT "${actual_exit}" STREQUAL "${EXIT_CODE}")
    string(APPEND failures "\n  exit code: got '${actual_exit}', expected '${EXIT_CODE}'")
endif()
foreach(stream IN ITEMS STDOUT STDERR)
    string(TOLOWER "${stream}" name)
    if("${${stream}}" STREQUAL "")
        set(expected "")
    else()
        set(expected "${${stream}}\n")
    endif()
    if(NOT "${actual_${name}}" STREQUAL "${expected}")
        string(APPEND failures "\n  ${name}: got '${actual_${name}}', expected '${expected}'")
    endif()
endforeach()

if(failures)
    message(FATAL_ERROR "${EXE} ${ARGS}:${failures}")
endif()
