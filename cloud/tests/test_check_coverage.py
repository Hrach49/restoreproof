"""Tests for tools/check_coverage.py, the per-path 100% coverage gate.

CLAUDE.md requires 100% line and branch coverage on app/auth, app/results.py,
app/repo, since C5.9 app/cadence.py, since C5.11 app/contract.py and since
C6.4 app/report. pytest-cov only has a global threshold, so this script reads
coverage's JSON report and enforces the per-path floor.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools import check_coverage


def summary(statements=10, covered=10, branches=4, covered_branches=4):
    return {
        "summary": {
            "num_statements": statements,
            "covered_lines": covered,
            "num_branches": branches,
            "covered_branches": covered_branches,
        }
    }


FULL = summary()


def make_tree(root: Path, files):
    for rel in files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")


def write_report(root: Path, files, branch=True):
    report = {"meta": {"branch_coverage": branch}, "files": files}
    path = root / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def run(root: Path, report_path: Path, *extra):
    return check_coverage.main([str(report_path), "--root", str(root), *extra])


# ---- failure paths -------------------------------------------------------


@pytest.mark.parametrize(
    "case, on_disk, report_files",
    [
        (
            "results.py at 99% branch",
            ["app/results.py"],
            {"app/results.py": summary(branches=100, covered_branches=99)},
        ),
        (
            "results.py missing one line",
            ["app/results.py"],
            {"app/results.py": summary(statements=10, covered=9)},
        ),
        (
            "auth module with a partial branch",
            ["app/auth/__init__.py", "app/auth/tokens.py"],
            {
                "app/auth/__init__.py": FULL,
                "app/auth/tokens.py": summary(branches=2, covered_branches=1),
            },
        ),
        (
            "nested repo module under 100%",
            ["app/repo/sub/msp.py"],
            {"app/repo/sub/msp.py": summary(statements=5, covered=4)},
        ),
        (
            "repo file on disk but absent from the report",
            ["app/repo/msp.py", "app/repo/client.py"],
            {"app/repo/msp.py": FULL},
        ),
        (
            "results.py on disk but absent from the report",
            ["app/results.py"],
            {},
        ),
    ],
)
def test_fails_when_a_guarded_file_is_not_fully_covered(
    tmp_path, capsys, case, on_disk, report_files
):
    make_tree(tmp_path, on_disk)
    report = write_report(tmp_path, report_files)

    assert run(tmp_path, report) == 1, case
    assert "FAIL" in capsys.readouterr().out


def test_fails_when_report_has_no_branch_data(tmp_path, capsys):
    make_tree(tmp_path, ["app/results.py"])
    report = write_report(tmp_path, {"app/results.py": FULL}, branch=False)

    assert run(tmp_path, report) == 1
    assert "--cov-branch" in capsys.readouterr().out


def test_fails_when_report_file_is_missing(tmp_path, capsys):
    assert run(tmp_path, tmp_path / "nope.json") == 2
    assert "not found" in capsys.readouterr().err


def test_fails_when_report_is_not_json(tmp_path, capsys):
    bad = tmp_path / "coverage.json"
    bad.write_text("not json", encoding="utf-8")

    assert run(tmp_path, bad) == 2
    assert "not valid coverage JSON" in capsys.readouterr().err


# ---- skip and pass paths -------------------------------------------------


@pytest.mark.parametrize("guarded", ["app/auth", "app/results.py", "app/repo", "app/cadence.py", "app/contract.py", "app/report"])
def test_missing_guarded_path_is_skipped_not_failed(tmp_path, capsys, guarded):
    report = write_report(tmp_path, {})

    assert run(tmp_path, report) == 0
    out = capsys.readouterr().out
    assert f"SKIP | `{guarded}`" in out
    assert "does not exist yet" in out


@pytest.mark.parametrize(
    "case, on_disk, report_files",
    [
        (
            "all guarded paths at 100%",
            ["app/auth/__init__.py", "app/results.py", "app/repo/msp.py"],
            {
                "app/auth/__init__.py": FULL,
                "app/results.py": FULL,
                "app/repo/msp.py": FULL,
            },
        ),
        (
            "Windows-style report keys",
            ["app/repo/msp.py"],
            {"app\\repo\\msp.py": FULL},
        ),
        (
            "empty module has nothing to cover",
            ["app/auth/__init__.py"],
            {"app/auth/__init__.py": summary(0, 0, 0, 0)},
        ),
        (
            "unguarded file below 100% is ignored",
            ["app/results.py", "app/other.py", "app/results_extra.py"],
            {
                "app/results.py": FULL,
                "app/other.py": summary(statements=10, covered=5),
                "app/results_extra.py": summary(statements=10, covered=5),
            },
        ),
        (
            "non-Python files in a guarded dir are ignored",
            ["app/repo/msp.py", "app/repo/README.txt"],
            {"app/repo/msp.py": FULL},
        ),
    ],
)
def test_passes_when_guarded_files_are_fully_covered(
    tmp_path, capsys, case, on_disk, report_files
):
    make_tree(tmp_path, on_disk)
    report = write_report(tmp_path, report_files)

    assert run(tmp_path, report) == 0, case
    assert "FAIL" not in capsys.readouterr().out


def test_appends_markdown_table_to_summary_file(tmp_path):
    make_tree(tmp_path, ["app/results.py"])
    report = write_report(
        tmp_path, {"app/results.py": summary(branches=4, covered_branches=3)}
    )
    summary_file = tmp_path / "summary.md"
    summary_file.write_text("existing\n", encoding="utf-8")

    assert run(tmp_path, report, "--summary", str(summary_file)) == 1
    text = summary_file.read_text(encoding="utf-8")
    assert text.startswith("existing\n")
    assert "| Status | Path |" in text
    assert "FAIL | `app/results.py`" in text
    assert "3/4" in text


def test_default_root_is_current_directory(tmp_path, monkeypatch):
    make_tree(tmp_path, ["app/results.py"])
    report = write_report(tmp_path, {"app/results.py": FULL})
    monkeypatch.chdir(tmp_path)

    assert check_coverage.main([str(report)]) == 0


def test_runs_as_a_script(tmp_path):
    make_tree(tmp_path, ["app/results.py"])
    report = write_report(tmp_path, {"app/results.py": summary(covered=9)})
    script = Path(check_coverage.__file__)

    result = subprocess.run(
        [sys.executable, str(script), str(report), "--root", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "FAIL | `app/results.py`" in result.stdout
