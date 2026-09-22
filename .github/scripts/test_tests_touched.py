"""Tests for the "No test, no merge" guard (L0.5).

Run with: python -m pytest .github/scripts
"""

import subprocess
import sys
from pathlib import Path

import pytest

from tests_touched import MESSAGE, parse_paths, violations

SCRIPT = Path(__file__).with_name("tests_touched.py")


# Each row: (changed paths, expected offending source paths).
# An empty expectation means the PR is allowed to merge.
# Failure paths first.
CASES = [
    # --- blocked: source changed, no test changed ---
    (["worker/src/veeam_client.cpp"], ["worker/src/veeam_client.cpp"]),
    (["cloud/app/results.py"], ["cloud/app/results.py"]),
    (
        ["worker/src/a.cpp", "cloud/app/b.py", "docs/decisions.md"],
        ["worker/src/a.cpp", "cloud/app/b.py"],
    ),
    # A deleted source file is still a change to source.
    # (git diff --name-only lists deleted paths like any other.)
    (["worker/src/removed.cpp"], ["worker/src/removed.cpp"]),
    # Renames: the workflow runs git diff with --no-renames, so a move shows
    # up as the old path (deleted) plus the new path (added).
    (["worker/src/old.cpp", "worker/src/new.cpp"], ["worker/src/old.cpp", "worker/src/new.cpp"]),
    # Moving code out of worker/src/ still touches worker/src/.
    (["worker/src/moved.cpp", "worker/tools/moved.cpp"], ["worker/src/moved.cpp"]),
    # Look-alike test directories do not count as tests.
    (["worker/src/a.cpp", "worker/tests_old/x.cpp"], ["worker/src/a.cpp"]),
    (["worker/src/a.cpp", "worker/testsuite/x.cpp"], ["worker/src/a.cpp"]),
    (["cloud/app/a.py", "cloud/tests.py"], ["cloud/app/a.py"]),
    (["cloud/app/a.py", "testsfoo/x.py"], ["cloud/app/a.py"]),
    (["cloud/app/a.py", "docs/tests/x.md"], ["cloud/app/a.py"]),
    # The guard's own tests are not product tests.
    (["cloud/app/a.py", ".github/scripts/test_tests_touched.py"], ["cloud/app/a.py"]),
    # Windows-style separators and a leading ./ are normalised.
    (["worker\\src\\a.cpp"], ["worker/src/a.cpp"]),
    (["./cloud/app/a.py"], ["cloud/app/a.py"]),
    (["worker\\src\\a.cpp", "worker\\tests_old\\a.cpp"], ["worker/src/a.cpp"]),
    # Deeply nested source.
    (["cloud/app/repo/results_repo.py"], ["cloud/app/repo/results_repo.py"]),
    # --- allowed ---
    ([], []),
    (["docs/decisions.md"], []),
    (["README.md", ".github/workflows/worker.yml"], []),
    (["worker/src/a.cpp", "worker/tests/a_test.cpp"], []),
    (["cloud/app/a.py", "cloud/tests/test_a.py"], []),
    (["worker/src/a.cpp", "tests/e2e/scenarios.md"], []),
    # Any of the three test roots satisfies any source change.
    (["worker/src/a.cpp", "cloud/app/b.py", "cloud/tests/test_b.py"], []),
    # Deleting or adding a test file still counts as touching tests.
    (["worker/src/a.cpp", "worker/tests/fixtures/veeam/list.json"], []),
    (["worker\\src\\a.cpp", "worker\\tests\\a_test.cpp"], []),
    # Look-alike source directories are not source.
    (["worker/srcfoo/x.cpp"], []),
    (["worker/src.cpp"], []),
    (["cloud/application/x.py"], []),
    (["cloud/app.py"], []),
    (["cloud/apps/x.py"], []),
    (["other/worker/src/x.cpp"], []),
    # A bare directory name without a file below it is not a change under it.
    (["worker/src"], []),
    # Tests only.
    (["worker/tests/a_test.cpp"], []),
    # Other worker/cloud files (build config, lockfiles) do not need tests.
    (["worker/CMakeLists.txt", "cloud/pyproject.toml", "cloud/uv.lock"], []),
]


@pytest.mark.parametrize(("changed", "expected"), CASES)
def test_violations(changed, expected):
    assert violations(changed) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        ("\n\n", []),
        ("a\nb\n", ["a", "b"]),
        ("a\r\nb\r\n", ["a", "b"]),
        # git diff -z output: NUL-separated, trailing NUL.
        ("a\0b c\0", ["a", "b c"]),
        ("  a  \n", ["a"]),
    ],
)
def test_parse_paths(raw, expected):
    assert parse_paths(raw) == expected


def run_script(stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_blocks_source_change_without_test():
    result = run_script("worker/src/a.cpp\0docs/x.md\0")
    assert result.returncode == 1
    assert MESSAGE == "No test, no merge"
    assert MESSAGE in result.stdout
    assert "worker/src/a.cpp" in result.stdout
    assert "docs/x.md" not in result.stdout


def test_cli_allows_source_change_with_test():
    result = run_script("worker/src/a.cpp\nworker/tests/a_test.cpp\n")
    assert result.returncode == 0
    assert MESSAGE not in result.stdout


def test_cli_allows_empty_diff():
    result = run_script("")
    assert result.returncode == 0
