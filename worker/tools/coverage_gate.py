"""Coverage gate for the Worker (rpcore), reading OpenCppCoverage Cobertura XML.

Usage (from worker/):
    python tools/coverage_gate.py coverage.xml [--root .] [--min-line 80] [--summary FILE]

Rules (CLAUDE.md, "Coverage floors"):
  * every .cpp under src/, include/ and app/ on disk (relative to --root) must
    be in the report. OpenCppCoverage only sees code a test runs: rpcore
    (src/, include/) through rptests.exe, where the linker drops an object no
    test references, and rpworker's main() (app/) through ctest's runs of
    rpworker.exe. An untested file would otherwise just be missing. Headers may
    be absent: a header of declarations has no executable lines;
  * total line coverage over the reported sources >= --min-line (80%);
  * vault, signer, target_guard, run_status (the status decision table,
    W3.3: the Worker's counterpart of the Cloud's app/results.py) and cleaner
    (W3.4: the only Worker code that deletes in the tenant) and timestamper
    (W4.4: it decides which RFC 3161 token is written) and outbox (W4.6: it
    decides what is queued, sent, kept and pruned) and service (W4.7: the
    service's state machine, its subcommands and its log, which decide when a
    process holding a run is ended, whether a SECURITY line is written and
    whether a line is redacted) and client_profile and strict_json (W4.10:
    src/client_profile.cpp and src/strict_json.hpp hold what the strict
    src/service_jobs.cpp and src/service_recovery.cpp decided before it: whether
    a job's or a record's client is a profile, and that a document with a key
    twice or nested too deep is never read) need 100%
    *branch* coverage. OpenCppCoverage only measures lines (its Cobertura
    branch-rate is always 0), so this gate enforces 100% *line* coverage on
    those files as the closest proxy.
    TODO: real branch coverage needs a different tool, e.g. clang-cl with
    -fprofile-instr-generate -fcoverage-mapping + llvm-cov, or MSVC
    Microsoft.CodeCoverage (Enterprise). A file is strict when any part of its
    path is a strict name or starts with one plus "_" (src/signer/ed25519.cpp,
    src/vault_dpapi.cpp, src/service_log.cpp). The calls into Windows under a
    strict file live in files of other names (src/scm.cpp and
    src/stop_signal.cpp under the service) and count toward the total only.
    Names with no file yet are skipped with a note.

Exit codes: 0 pass, 1 below a threshold, 2 unusable report.
Stdlib only, so CI needs nothing beyond Python.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Iterable, TextIO

STRICT_NAMES = (
    "vault",
    "signer",
    "target_guard",
    "run_status",
    "cleaner",
    "timestamper",
    "outbox",
    "service",
    "client_profile",
    "strict_json",
    "client_check",
    # W5.1: the Cloud's answers and the registration (cloud_api, cloud_command).
    "cloud",
    # W7.2: rpworker doctor's judgement and its command (doctor, doctor_command).
    "doctor",
)
SOURCE_DIRS = ("src", "include", "app")
SOURCE_EXTS = (".cpp", ".cc", ".cxx", ".c")
HEADER_EXTS = (".h", ".hpp", ".hh", ".hxx", ".ipp", ".inl")
BRANCH_NOTE = (
    "Branch coverage is not measured: OpenCppCoverage reports line coverage only. "
    "`vault`, `signer`, `target_guard`, `run_status`, `cleaner`, `timestamper`, `outbox`, `service`, "
    "`client_profile`, `strict_json`, `client_check`, `cloud` and `doctor` are held "
    "to 100% **line** "
    "coverage as a proxy for the required 100% branch coverage."
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
            try:
                number = int(line.get("number", "0"))
                hit = int(line.get("hits", "0")) > 0
            except ValueError:
                raise ReportError(f"bad line data in {name}: {line.attrib}")
            lines[number] = lines.get(number, False) or hit
    files = {name: lines for name, lines in files.items() if lines}
    if not files:
        raise ReportError(
            "report contains no source lines; check the OpenCppCoverage --sources filter"
        )
    return files


def files_on_disk(root: Path) -> list[str]:
    """C++ files under root's SOURCE_DIRS, as posix paths relative to root."""
    found = []
    for folder in SOURCE_DIRS:
        for path in (root / folder).rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_EXTS + HEADER_EXTS:
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


def key_by_disk(files: dict[str, dict[int, bool]], disk: list[str]) -> dict[str, dict[int, bool]]:
    """Rename report entries to their path on disk, merging entries that meet.

    OpenCppCoverage writes full paths, so a report name matches a file on disk
    when it ends with that file's relative path. Windows paths ignore case.
    """
    by_lower = {rel.lower(): rel for rel in disk}
    keyed: dict[str, dict[int, bool]] = {}
    for name, lines in files.items():
        parts = name.lower().split("/")
        suffixes = ("/".join(parts[i:]) for i in range(len(parts)))
        key = next((by_lower[s] for s in suffixes if s in by_lower), name)
        merged = keyed.setdefault(key, {})
        for number, hit in lines.items():
            merged[number] = merged.get(number, False) or hit
    return keyed


def strict_name(filename: str) -> str | None:
    path = PurePosixPath(filename.replace("\\", "/").lower())
    for part in (*path.parent.parts, path.stem):
        for name in STRICT_NAMES:
            if part == name or part.startswith(name + "_"):
                return name
    return None


def pct(hit: int, total: int) -> float:
    return 100.0 * hit / total if total else 100.0


def evaluate(files: dict[str, dict[int, bool]], min_line: float, disk: Iterable[str] = ()):
    """Rows are (name, hit, total, status); total is None for a file missing from the report."""
    disk = list(disk)
    files = key_by_disk(files, disk)
    missing = [rel for rel in disk if rel.lower().endswith(SOURCE_EXTS) and rel not in files]
    rows = []
    failures = []
    total_hit = total_lines = 0
    present = {strict_name(name) for name in (*files, *disk)} - {None}
    for name in sorted({*files, *missing}):
        strict = strict_name(name)
        if name not in files:
            failures.append(
                f"{name}: not in coverage report; no test links it into rptests"
                + (" (strict file)" if strict else "")
            )
            rows.append((name, 0, None, "FAIL" if strict else ""))
            continue
        lines = files[name]
        hit, total = sum(lines.values()), len(lines)
        total_hit += hit
        total_lines += total
        status = ""
        if strict:
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
        if total is None:
            out.append(f"| `{name}` | not in report | - | {status or '-'} |")
        else:
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
    parser.add_argument("--root", default=".", help="the worker/ folder holding src/ and include/")
    parser.add_argument("--min-line", type=float, default=80.0)
    parser.add_argument("--summary", help="append a markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        files = load_lines(args.report)
        root = Path(args.root)
        if not (root / "src").is_dir():
            raise ReportError(f"no src/ folder under --root {root.resolve()}")
    except ReportError as exc:
        print(f"coverage gate: ERROR: {exc}", file=out)
        return 2

    rows, totals, present, failures = evaluate(files, args.min_line, files_on_disk(root))
    summary = render_summary(rows, totals, present, failures, args.min_line)
    print(summary, file=out)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
