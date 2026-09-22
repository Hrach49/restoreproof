"""Enforce 100% line and branch coverage on the security-critical Cloud paths.

pytest-cov only supports one global threshold (--cov-fail-under). CLAUDE.md
also requires 100% branch coverage on app/auth, app/results.py and app/repo, so
this script reads coverage's JSON report and checks those paths file by file.

Usage (from cloud/):
    uv run pytest --cov=app --cov-branch --cov-report=json:coverage.json
    uv run python tools/check_coverage.py coverage.json [--summary FILE]

Every .py file that exists on disk under a guarded path must appear in the
report with all statements and all branches covered. A guarded path that does
not exist yet is skipped with a message, not failed.

Exit codes: 0 = all guarded files fully covered (or skipped), 1 = a guarded
file is below 100% or unmeasured, 2 = report missing or unreadable.
Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

GUARDED = ("app/auth", "app/results.py", "app/repo")


@dataclass
class Row:
    status: str  # OK, FAIL or SKIP
    path: str
    lines: str = "-"
    branches: str = "-"
    note: str = ""


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def _guarded_files(root: Path, guarded: str) -> list[str] | None:
    """Return the .py files on disk for a guarded path, or None if it's absent."""
    target = root / guarded
    if target.is_file():
        return [guarded]
    if target.is_dir():
        return sorted(
            _norm(str(p.relative_to(root))) for p in target.rglob("*.py")
        )
    return None


def _check_file(path: str, files: dict) -> Row:
    entry = files.get(path)
    if entry is None:
        return Row("FAIL", path, note="not in coverage report (never measured)")
    s = entry["summary"]
    lines = f"{s['covered_lines']}/{s['num_statements']}"
    branches = f"{s['covered_branches']}/{s['num_branches']}"
    ok = (
        s["covered_lines"] == s["num_statements"]
        and s["covered_branches"] == s["num_branches"]
    )
    return Row("OK" if ok else "FAIL", path, lines, branches,
               "" if ok else "below 100%")


def evaluate(report: dict, root: Path, guarded=GUARDED) -> list[Row]:
    if not report.get("meta", {}).get("branch_coverage"):
        return [Row("FAIL", "(report)",
                    note="no branch data; run pytest with --cov-branch")]
    files = {_norm(k): v for k, v in report.get("files", {}).items()}
    rows: list[Row] = []
    for g in guarded:
        on_disk = _guarded_files(root, g)
        if on_disk is None:
            rows.append(Row("SKIP", g, note="does not exist yet"))
            continue
        rows.extend(_check_file(p, files) for p in on_disk)
    return rows


def to_markdown(rows: list[Row]) -> str:
    out = [
        "",
        "### Guarded paths (100% line + branch required)",
        "",
        "| Status | Path | Lines | Branches | Note |",
        "|---|---|---|---|---|",
    ]
    out += [
        f"| {r.status} | `{r.path}` | {r.lines} | {r.branches} | {r.note} |"
        for r in rows
    ]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", help="coverage JSON report")
    parser.add_argument("--root", default=".", help="cloud/ directory")
    parser.add_argument("--summary", help="append the markdown table here")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"coverage report not found: {report_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print(f"{report_path} is not valid coverage JSON", file=sys.stderr)
        return 2

    rows = evaluate(report, Path(args.root))
    table = to_markdown(rows)
    print(table, end="")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(table)
    return 1 if any(r.status == "FAIL" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
