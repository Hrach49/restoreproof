"""The "No test, no merge" guard (L0.5).

Reads the paths changed by a pull request on stdin (newline- or
NUL-separated, as printed by `git diff --name-only [-z]`) and exits 1 with
"No test, no merge" if any path under worker/src/ or cloud/app/ changed but
nothing under worker/tests/, cloud/tests/ or tests/ did.

Stdlib only, so it runs on any runner Python without installing anything.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable

MESSAGE = "No test, no merge"

SOURCE_DIRS = ("worker/src/", "cloud/app/")
TEST_DIRS = ("worker/tests/", "cloud/tests/", "tests/")


def normalise(path: str) -> str:
    """Use forward slashes and drop a leading './'."""
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _under(path: str, dirs: tuple[str, ...]) -> bool:
    # Each dir ends in "/", so "worker/srcfoo/x" and "cloud/app.py" never match.
    return path.startswith(dirs)


def violations(changed: Iterable[str]) -> list[str]:
    """Return the source paths that break the rule, or [] if the PR may merge.

    The rule: if any changed path is under a source dir, at least one changed
    path must be under a test dir. Deleted and renamed files count as changes
    (the caller lists both sides of a rename).
    """
    paths = [normalise(p) for p in changed]
    paths = [p for p in paths if p]
    if any(_under(p, TEST_DIRS) for p in paths):
        return []
    return [p for p in paths if _under(p, SOURCE_DIRS)]


def parse_paths(raw: str) -> list[str]:
    """Split git diff output on NUL or newlines, dropping blanks."""
    return [p.strip() for p in re.split(r"[\0\r\n]+", raw) if p.strip()]


def main() -> int:
    offending = violations(parse_paths(sys.stdin.read()))
    if not offending:
        print("OK: no source change without a test change.")
        return 0
    print(MESSAGE)
    print(
        "These paths changed under "
        + " or ".join(SOURCE_DIRS)
        + " but nothing changed under "
        + ", ".join(TEST_DIRS)
        + ":"
    )
    for path in offending:
        print(f"  {path}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
