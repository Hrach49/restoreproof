"""Tests for the "No test, no merge" guard (L0.5).

Run with: python -m pytest .github/scripts
"""

import subprocess
import sys
from pathlib import Path

import pytest

from tests_touched import MESSAGE, parse_changes, violations

SCRIPT = Path(__file__).with_name("tests_touched.py")


def changes(items):
    """Rows list plain paths (status M) or (status, path) pairs."""
    return [i if isinstance(i, tuple) else ("M", i) for i in items]


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
    # Headers are rpcore source too (header-only or inline logic).
    (["worker/include/rp/target_guard.hpp"], ["worker/include/rp/target_guard.hpp"]),
    (["worker\\include\\rp\\a.hpp"], ["worker/include/rp/a.hpp"]),
    # A deleted source file is still a change to source.
    ([("D", "worker/src/removed.cpp")], ["worker/src/removed.cpp"]),
    # Renames: the workflow runs git diff with --no-renames, so a move shows
    # up as the old path (deleted) plus the new path (added).
    (
        [("D", "worker/src/old.cpp"), ("A", "worker/src/new.cpp")],
        ["worker/src/old.cpp", "worker/src/new.cpp"],
    ),
    # Moving code out of worker/src/ still touches worker/src/.
    ([("D", "worker/src/moved.cpp"), ("A", "worker/tools/moved.cpp")], ["worker/src/moved.cpp"]),
    # Each side needs its own tests: a Cloud test does not cover Worker code
    # and the other way round.
    (["worker/src/a.cpp", "cloud/tests/test_b.py"], ["worker/src/a.cpp"]),
    (["cloud/app/a.py", "worker/tests/a_test.cpp"], ["cloud/app/a.py"]),
    (
        ["worker/src/a.cpp", "cloud/app/b.py", "cloud/tests/test_b.py"],
        ["worker/src/a.cpp"],
    ),
    # Deleting tests alone does not count as writing one.
    ([("M", "cloud/app/auth.py"), ("D", "cloud/tests/test_auth.py")], ["cloud/app/auth.py"]),
    ([("M", "worker/src/a.cpp"), ("D", "worker/tests/a_test.cpp")], ["worker/src/a.cpp"]),
    # Only test code counts: fixtures, docs and the manual e2e list do not.
    (["worker/src/a.cpp", "worker/tests/fixtures/veeam/list.json"], ["worker/src/a.cpp"]),
    (["cloud/app/a.py", "cloud/tests/fixtures/bundle.json"], ["cloud/app/a.py"]),
    (["cloud/app/results.py", "tests/e2e/scenarios.md"], ["cloud/app/results.py"]),
    (["worker/src/a.cpp", "tests/e2e/scenarios.md"], ["worker/src/a.cpp"]),
    (["worker/src/a.cpp", "worker/tests/README.md"], ["worker/src/a.cpp"]),
    # Look-alike test directories do not count as tests.
    (["worker/src/a.cpp", "worker/tests_old/x.cpp"], ["worker/src/a.cpp"]),
    (["worker/src/a.cpp", "worker/testsuite/x.cpp"], ["worker/src/a.cpp"]),
    (["cloud/app/a.py", "cloud/tests.py"], ["cloud/app/a.py"]),
    (["cloud/app/a.py", "testsfoo/x.py"], ["cloud/app/a.py"]),
    (["cloud/app/a.py", "docs/tests/x.py"], ["cloud/app/a.py"]),
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
    (["worker/include/rp/a.hpp", "worker/tests/a_test.cpp"], []),
    (["worker/src/a.cpp", "worker/tests/support/fake_http_client.hpp"], []),
    (["cloud/app/a.py", "cloud/tests/test_a.py"], []),
    (["cloud/app/a.py", "cloud/tests/conftest.py"], []),
    (
        ["worker/src/a.cpp", "cloud/app/b.py", "worker/tests/a_test.cpp", "cloud/tests/test_b.py"],
        [],
    ),
    # Adding a test file counts; so does a fixture next to a real test change.
    ([("M", "worker/src/a.cpp"), ("A", "worker/tests/a_test.cpp")], []),
    (
        [
            "worker/src/a.cpp",
            ("A", "worker/tests/fixtures/veeam/list.json"),
            "worker/tests/a_test.cpp",
        ],
        [],
    ),
    # A test deleted alongside another test change is fine.
    (
        [("M", "cloud/app/a.py"), ("D", "cloud/tests/test_old.py"), ("A", "cloud/tests/test_a.py")],
        [],
    ),
    (["worker\\src\\a.cpp", "worker\\tests\\a_test.cpp"], []),
    # Look-alike source directories are not source.
    (["worker/srcfoo/x.cpp"], []),
    (["worker/src.cpp"], []),
    (["worker/includes/x.hpp"], []),
    (["cloud/application/x.py"], []),
    (["cloud/app.py"], []),
    (["cloud/apps/x.py"], []),
    (["other/worker/src/x.cpp"], []),
    # A bare directory name without a file below it is not a change under it.
    (["worker/src"], []),
    # Tests only.
    (["worker/tests/a_test.cpp"], []),
    ([("D", "worker/tests/a_test.cpp")], []),
    # Other worker/cloud files (build config, lockfiles) do not need tests.
    (["worker/CMakeLists.txt", "cloud/pyproject.toml", "cloud/uv.lock"], []),
]


@pytest.mark.parametrize(("changed", "expected"), CASES)
def test_violations(changed, expected):
    assert violations(changes(changed)) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        ("\n\n", []),
        # git diff --name-status: status, tab, path per line.
        ("M\ta\nD\tb\n", [("M", "a"), ("D", "b")]),
        ("A\ta\r\nM\tb\r\n", [("A", "a"), ("M", "b")]),
        # git diff --name-status -z: status and path are separate NUL fields.
        ("M\0a\0D\0b c\0", [("M", "a"), ("D", "b c")]),
        ("T\0a\0", [("T", "a")]),
    ],
)
def test_parse_changes(raw, expected):
    assert parse_changes(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        # A path without a status: the caller forgot --name-status.
        "worker/src/a.cpp\n",
        "worker/src/a.cpp\0",
        # A status without a path.
        "M\0",
        # Renames and copies have two paths; the workflow passes --no-renames.
        "R100\0old.cpp\0new.cpp\0",
        "R100\told.cpp\tnew.cpp\n",
        "X\ta\n",
    ],
)
def test_parse_changes_rejects_unexpected_input(raw):
    with pytest.raises(ValueError):
        parse_changes(raw)


def run_script(stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_blocks_source_change_without_test():
    result = run_script("M\0worker/src/a.cpp\0M\0docs/x.md\0")
    assert result.returncode == 1
    assert MESSAGE == "No test, no merge"
    assert MESSAGE in result.stdout
    assert "worker/src/a.cpp" in result.stdout
    assert "docs/x.md" not in result.stdout
    assert "worker/tests/" in result.stdout


def test_cli_allows_source_change_with_test():
    result = run_script("M\tworker/src/a.cpp\nA\tworker/tests/a_test.cpp\n")
    assert result.returncode == 0
    assert MESSAGE not in result.stdout


def test_cli_allows_empty_diff():
    result = run_script("")
    assert result.returncode == 0


def test_cli_rejects_input_without_status():
    # Plain --name-only output must not be read as "no source changed".
    result = run_script("worker/src/a.cpp\n")
    assert result.returncode == 2
    assert "--name-status" in result.stderr
