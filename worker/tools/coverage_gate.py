"""Coverage gate for the Worker (rpcore), reading OpenCppCoverage Cobertura XML.

Usage:
    python coverage_gate.py coverage.xml [--min-line 80] [--summary FILE]

Rules (CLAUDE.md, "Coverage floors"):
  * total line coverage over the reported rpcore sources >= --min-line (80%);
  * vault, signer and target_guard need 100% *branch* coverage. OpenCppCoverage
    only measures lines (its Cobertura branch-rate is always 0), so this gate
    enforces 100% *line* coverage on those files as the closest proxy.
    TODO: real branch coverage needs a different tool, e.g. clang-cl with
    -fprofile-instr-generate -fcoverage-mapping + llvm-cov, or MSVC
    Microsoft.CodeCoverage (Enterprise). Files that don't exist yet are skipped
    with a note.

Exit codes: 0 pass, 1 below a threshold, 2 unusable report.
Stdlib only, so CI needs nothing beyond Python.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import PureWindowsPath
from typing import Iterable, TextIO

STRICT_NAMES = ("vault", "signer", "target_guard")
BRANCH_NOTE = (
    "Branch coverage is not measured: OpenCppCoverage reports line coverage only. "
    "`vault`, `signer` and `target_guard` are held to 100% **line** coverage as a proxy "
    "for the required 100% branch coverage."
)


class ReportError(Exception):
    pass


def load_lines(path: str) -> dict[str, dict[int, bool]]:
    """Return {filename: {line_number: covered}}, merged across packages/classes."""
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        raise ReportError(f"coverage report not found: {path}")
    except ET.ParseError as exc:
        raise ReportError(f"coverage report is not valid XML: {exc}")

    files: dict[str, dict[int, bool]] = {}
    for cls in root.iter("class"):
        name = cls.get("filename", "").replace("\\", "/")
        lines = files.setdefault(name, {})
        for line in cls.iter("line"):
            number = int(line.get("number", "0"))
            hit = int(line.get("hits", "0")) > 0
            lines[number] = lines.get(number, False) or hit
    files = {name: lines for name, lines in files.items() if lines}
    if not files:
        raise ReportError(
            "report contains no source lines; check the OpenCppCoverage --sources filter"
        )
    return files


def strict_name(filename: str) -> str | None:
    stem = PureWindowsPath(filename).stem
    return stem if stem in STRICT_NAMES else None


def pct(hit: int, total: int) -> float:
    return 100.0 * hit / total if total else 100.0


def evaluate(files: dict[str, dict[int, bool]], min_line: float):
    rows = []
    failures = []
    total_hit = total_lines = 0
    present = set()
    for name in sorted(files):
        lines = files[name]
        hit, total = sum(lines.values()), len(lines)
        total_hit += hit
        total_lines += total
        strict = strict_name(name)
        status = ""
        if strict:
            present.add(strict)
            status = "PASS" if hit == total else "FAIL"
            if hit != total:
                failures.append(f"{name}: {pct(hit, total):.1f}% lines, needs 100% (strict file)")
        rows.append((name, hit, total, status))
    overall = pct(total_hit, total_lines)
    if overall < min_line:
        failures.append(f"rpcore total: {overall:.1f}% lines, needs {min_line:g}%")
    return rows, (total_hit, total_lines, overall), present, failures


def render_summary(rows, totals, present, failures, min_line) -> str:
    total_hit, total_lines, overall = totals
    verdict = "PASS" if not failures else "FAIL"
    out = [
        f"## Worker coverage (rpcore): {verdict}",
        "",
        f"**Total line coverage: {overall:.1f}%** ({total_hit}/{total_lines}), floor {min_line:g}%.",
        "",
        "| File | Lines covered | Line % | Strict (100%) |",
        "|---|---|---|---|",
    ]
    for name, hit, total, status in rows:
        out.append(f"| `{name}` | {hit}/{total} | {pct(hit, total):.1f}% | {status or '-'} |")
    out.append("")
    for name in STRICT_NAMES:
        if name not in present:
            out.append(f"- `{name}`: not present yet, strict check skipped.")
    out += ["", f"> {BRANCH_NOTE}", ""]
    if failures:
        out.append("### Failures")
        out += [f"- {f}" for f in failures]
        out.append("")
    return "\n".join(out)


def main(argv: Iterable[str] | None = None, out: TextIO = sys.stdout) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report")
    parser.add_argument("--min-line", type=float, default=80.0)
    parser.add_argument("--summary", help="append a markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        files = load_lines(args.report)
    except ReportError as exc:
        print(f"coverage gate: ERROR: {exc}", file=out)
        return 2

    rows, totals, present, failures = evaluate(files, args.min_line)
    summary = render_summary(rows, totals, present, failures, args.min_line)
    print(summary, file=out)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
