"""The "No test, no merge" guard (L0.5).

Reads a pull request's changes on stdin, as printed by
`git diff --name-status --no-renames [-z]`, and exits 1 with
"No test, no merge" if a side's source changed without a test change on the
same side:

    worker/src/, worker/include/  need a change to test code under worker/tests/
    cloud/app/                    needs a change to test code under cloud/tests/

Test code means C++ files under worker/tests/ and .py files under cloud/tests/.
Fixtures, docs and tests/e2e/scenarios.md don't count, and neither does a
deleted test: removing a test is not writing one.

Exit codes: 0 allowed, 1 blocked, 2 unreadable input.
Stdlib only, so it runs on any runner Python without installing anything.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from typing import NamedTuple

MESSAGE = "No test, no merge"


class Side(NamedTuple):
    source_dirs: tuple[str, ...]
    test_dir: str
    test_suffixes: tuple[str, ...]


SIDES = (
    Side(("worker/src/", "worker/include/"), "worker/tests/", (".cpp", ".hpp", ".h")),
    Side(("cloud/app/",), "cloud/tests/", (".py",)),
)

# Single-path statuses from `git diff --name-status --no-renames`.
STATUSES = frozenset("AMDT")


def normalise(path: str) -> str:
    """Use forward slashes and drop a leading './'."""
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _is_test_code(side: Side, path: str) -> bool:
    return path.startswith(side.test_dir) and path.endswith(side.test_suffixes)


def violations(changes: Iterable[tuple[str, str]]) -> list[str]:
    """Return the source paths that break the rule, or [] if the PR may merge.

    `changes` holds (status, path) pairs. Each dir ends in "/", so
    "worker/srcfoo/x" and "cloud/app.py" never count as source. Deleted source
    files count as source changes (a move out of worker/src/ is a delete plus
    an add, since the caller passes --no-renames).
    """
    pairs = [(status, normalise(path)) for status, path in changes]
    pairs = [(status, path) for status, path in pairs if path]
    offending = []
    for side in SIDES:
        tested = any(
            status != "D" and _is_test_code(side, path) for status, path in pairs
        )
        if not tested:
            offending += [path for _, path in pairs if path.startswith(side.source_dirs)]
    order = {path: i for i, (_, path) in enumerate(pairs)}
    return sorted(offending, key=order.__getitem__)


def parse_changes(raw: str) -> list[tuple[str, str]]:
    """Parse `git diff --name-status` output, with or without -z.

    Raises ValueError on anything else, e.g. plain --name-only output or a
    rename (two paths), so bad input can't pass as "nothing changed".
    """
    if "\0" in raw:
        fields = raw.split("\0")
        if fields and fields[-1] == "":
            fields.pop()
        if len(fields) % 2:
            raise ValueError("odd number of NUL-separated fields")
        rows = [(fields[i], fields[i + 1]) for i in range(0, len(fields), 2)]
    else:
        rows = []
        for line in re.split(r"\r?\n", raw):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) != 2:
                raise ValueError(f"expected 'STATUS<tab>PATH', got {line!r}")
            rows.append((parts[0], parts[1]))
    for status, path in rows:
        if status not in STATUSES or not path.strip():
            raise ValueError(f"unexpected change {status!r} {path!r}")
    return rows


def main() -> int:
    try:
        changes = parse_changes(sys.stdin.read())
    except ValueError as exc:
        print(
            f"tests_touched: ERROR: {exc}. "
            "Pipe in `git diff --name-status --no-renames -z BASE...HEAD`.",
            file=sys.stderr,
        )
        return 2
    offending = violations(changes)
    if not offending:
        print("OK: every source change comes with a test change on the same side.")
        return 0
    print(MESSAGE)
    for side in SIDES:
        paths = [p for p in offending if p.startswith(side.source_dirs)]
        if not paths:
            continue
        print(
            f"These paths changed under {' or '.join(side.source_dirs)}, but no test code "
            f"under {side.test_dir} was added or changed:"
        )
        for path in paths:
            print(f"  {path}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
