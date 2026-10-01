# Runs the Worker's tests under OpenCppCoverage and writes
# build/coverage/coverage.xml (Cobertura), the file tools/coverage_gate.py reads.
# CI and docs/testing.md both run this script, so the two can't drift.
#
#   cmake --preset coverage; cmake --build --preset coverage
#   pwsh tools/run_coverage.ps1
#
# Two OpenCppCoverage runs, merged (docs/decisions.md, 2026-10-01 "Worker
# coverage in one process"):
#  1. rptests.exe once, every Catch2 test case in one process. ctest would
#     start one process per test case, and OpenCppCoverage reads rptests' PDB
#     and sets its breakpoints again for each: most of an hour for a thousand
#     test cases.
#  2. the tests of rpworker.exe (ctest label `exe`), which --cover_children
#     follows through tests/run_exe_test.cmake into each rpworker.exe run,
#     added to the first run's data through --input_coverage.
# --modules keeps OpenCppCoverage from reading the PDBs of the vcpkg DLLs;
# --sources limits the report to rpcore (src/, include/) and rpworker's main()
# (app/), so tests, Catch2 and the STL don't count.
#
# Exits with the first failing run's exit code, so a failing test fails the
# step, and with 1 if a tool or the build is missing.

$ErrorActionPreference = 'Stop'

$worker = Split-Path -Parent $PSScriptRoot
$build = Join-Path $worker 'build\coverage'
$rptests = Join-Path $build 'rptests.exe'
$rpworker = Join-Path $build 'rpworker.exe'
$partial = Join-Path $build 'rptests.cov'
$report = Join-Path $build 'coverage.xml'

foreach ($exe in $rptests, $rpworker) {
    if (-not (Test-Path $exe)) {
        Write-Error "$exe not found: build the coverage preset first"
    }
}
foreach ($tool in 'OpenCppCoverage', 'ctest') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "$tool is not on PATH"
    }
}

# A report or partial result of an earlier run must never stand in for this one's.
Remove-Item $partial, $report -Force -ErrorAction SilentlyContinue

$sources = @(
    '--sources', (Join-Path $worker 'src'),
    '--sources', (Join-Path $worker 'include'),
    '--sources', (Join-Path $worker 'app')
)

# The build folder is the working directory ctest gives each test case.
OpenCppCoverage --quiet --modules $rptests @sources `
    --working_dir $build `
    --export_type "binary:$partial" `
    -- $rptests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Push-Location $worker
try {
    OpenCppCoverage --quiet --cover_children --modules $rpworker @sources `
        --input_coverage $partial `
        --export_type "cobertura:$report" `
        -- ctest --preset coverage -L exe
    $code = $LASTEXITCODE
}
finally {
    Pop-Location
}
if ($code -ne 0) { exit $code }

if (-not (Test-Path $report)) {
    Write-Error "$report was not written"
}
