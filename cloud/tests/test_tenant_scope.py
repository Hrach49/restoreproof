"""C5.3: every database statement lives in app/repo/, and every repo method is
scoped to one MSP (docs/decisions.md 2026-10-10, "C5.3 and C5.4", points 2
and 3).

Two checks, both plain pytest so CI's test step runs them:

- The lint: outside app/repo/ (and app/migrations/, which runs on every MSP's
  rows by design) no file may build or run a statement. Text patterns, not an
  AST: the names to catch are tokens. Shown to work by planting `select(` in a
  router (the build notes record it).
- The AST walk: every public function or method under app/repo/ takes
  `msp_id: UUID` first, but for the three the decision names.

A repo method that forgets `msp_id` in a `where` is tests/test_repo_isolation.py's
to catch, not these.
"""

from __future__ import annotations

import ast
import contextlib
import re
import shutil
import sys
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent / "app"
REPO_DIR = APP_DIR / "repo"

# Where a statement may be built or run.
ALLOWED_DIRS = (REPO_DIR, APP_DIR / "migrations")

STATEMENT_NAMES = ("select", "update", "delete", "insert")
SESSION_CALLS = ("execute", "get", "get_one", "add", "add_all", "delete", "merge", "scalar", "scalars", "stream")

FORBIDDEN = (
    # A bare constructor call: not after a `.` (a dict's .update) or a word character.
    re.compile(r"(?<![\w.])(?:" + "|".join(STATEMENT_NAMES) + r")\("),
    # The same, qualified.
    re.compile(r"\b(?:sqlalchemy|sa)\.(?:" + "|".join(STATEMENT_NAMES) + r")\("),
    # Running one, or adding a row.
    re.compile(r"\bsession\.(?:" + "|".join(SESSION_CALLS) + r")\b"),
    # Importing a constructor.
    re.compile(r"^\s*from sqlalchemy[\w.]*\s+import\b.*\b(?:" + "|".join(STATEMENT_NAMES) + r")\b"),
)

# The five methods that take no msp_id: the three reads that happen before any
# MSP is known (C6.1: the login's address), the one that makes an MSP, and the
# scheduler's one read across every MSP (C5.9: the sweep and the dispatcher go
# MSP by MSP from it).
WITHOUT_MSP_ID = {
    ("lookup.py", "Lookup", "find_worker_by_token_hash"),
    ("lookup.py", "Lookup", "find_install_token_by_hash"),
    ("lookup.py", "Lookup", "find_user_by_email"),
    ("msps.py", "MspRepo", "create"),
    ("msps.py", "MspRepo", "list"),
}

# The one public function under app/repo/ that is no method: it words an
# IntegrityError (C5.10) and runs no statement, so it has no MSP to be scoped to.
MODULE_FUNCTIONS = {("errors.py", None, "constraint_refusal")}


# C5.10: the CLI lives beside app/ and is held like a router.
MANAGE = APP_DIR.parent / "manage.py"


def app_files() -> list[Path]:
    files = [path for path in APP_DIR.rglob("*.py") if "__pycache__" not in path.parts]
    if MANAGE.is_file():
        files.append(MANAGE)
    return sorted(files)


def outside_repo(path: Path) -> bool:
    return not any(path.is_relative_to(allowed) for allowed in ALLOWED_DIRS)


def offending_lines(text: str) -> list[tuple[int, str]]:
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        code = line.split("#", 1)[0]
        if any(pattern.search(code) for pattern in FORBIDDEN):
            found.append((number, line.strip()))
    return found


# --- The lint ------------------------------------------------------------------


def test_the_lint_looks_at_the_whole_app_but_the_repo_and_the_migrations():
    files = app_files()
    held = [path for path in files if outside_repo(path)]

    assert APP_DIR / "main.py" in held
    assert APP_DIR / "db.py" in held
    assert APP_DIR / "routers" / "workers.py" in held
    assert APP_DIR / "onboarding.py" in held
    assert APP_DIR / "scheduler.py" in held
    assert APP_DIR / "cadence.py" in held
    assert MANAGE in held
    assert not [path for path in held if path.is_relative_to(REPO_DIR)]
    assert not [path for path in held if path.is_relative_to(APP_DIR / "migrations")]
    assert len(held) >= 12


@pytest.mark.parametrize("path", [p for p in app_files() if outside_repo(p)], ids=lambda p: str(p.relative_to(APP_DIR.parent)))
def test_no_statement_is_built_or_run_outside_the_repo(path: Path):
    offending = offending_lines(path.read_text(encoding="utf-8"))

    assert offending == [], f"{path.relative_to(APP_DIR)}: a statement outside app/repo/"


@pytest.mark.parametrize(
    ("line", "refused"),
    [
        ("rows = await session.execute(select(Client))", True),
        ("stmt = select(Client).where(Client.msp_id == msp_id)", True),
        ("stmt = update(Client).values(name=name)", True),
        ("stmt = delete(Client)", True),
        ("stmt = insert(Client)", True),
        ("stmt = sqlalchemy.select(Client)", True),
        ("stmt = sa.update(Client)", True),
        ("session.add(row)", True),
        ("session.add_all(rows)", True),
        ("row = await session.get(Client, client_id)", True),
        ("row = await session.scalar(stmt)", True),
        ("rows = await session.scalars(stmt)", True),
        ("await session.delete(row)", True),
        ("from sqlalchemy import select", True),
        ("from sqlalchemy import Uuid, select, text", True),
        ("from sqlalchemy.sql import update", True),
        ("values.update(changes)", False),
        ("env.update({'a': 1})", False),
        ("headers = self.select(name)", False),
        ("from sqlalchemy import Text, Uuid, text", False),
        ("await connection.execute(text('SELECT 1'))", False),
        ("x = selected(1)", False),
        ("# select(Client) in a comment", False),
        ("async with request.app.state.session_factory() as session:", False),
    ],
)
def test_the_patterns_refuse_a_statement_and_let_a_dict_s_update_through(line: str, refused: bool):
    assert bool(offending_lines(line)) is refused, line


def test_the_lint_is_not_vacuous_the_repo_itself_selects():
    """If the patterns matched nothing, every file would pass: the repo's own
    statements must match them."""
    repo_files = sorted(path for path in REPO_DIR.rglob("*.py") if path.name != "__init__.py" and "__pycache__" not in path.parts)
    matched = {path.name for path in repo_files if offending_lines(path.read_text(encoding="utf-8"))}

    assert repo_files
    assert "clients.py" in matched
    assert "lookup.py" in matched
    assert len(matched) >= 11


# --- The AST walk: msp_id first ---------------------------------------------------


def _annotation_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.rsplit(".", 1)[-1]
    return None


def public_functions(path: Path) -> list[tuple[str | None, str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """(class name or None, function name, node) for every public def in the file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                found.append((None, node.name, node))
        elif isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and not member.name.startswith("_"):
                    found.append((node.name, member.name, member))
    return found


def all_repo_functions() -> list[tuple[str, str | None, str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    found = []
    # rglob: a sub-package of the repo is under the rule too (the C5.3/C5.4
    # review's finding 5).
    for path in sorted(REPO_DIR.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for class_name, name, node in public_functions(path):
            found.append((path.name, class_name, name, node))
    return found


def first_parameter(node: ast.FunctionDef | ast.AsyncFunctionDef, in_class: bool) -> ast.arg | None:
    params = list(node.args.posonlyargs) + list(node.args.args)
    if in_class:
        params = params[1:]  # self
    return params[0] if params else None


def test_every_public_repo_function_is_a_method_of_a_class_but_the_one_that_words_an_error():
    functions = all_repo_functions()

    assert functions
    assert {(f[0], f[1], f[2]) for f in functions if f[1] is None} == MODULE_FUNCTIONS
    for file_name, _class_name, name, node in functions:
        if (file_name, None, name) in MODULE_FUNCTIONS:
            assert [arg.arg for arg in node.args.args] == ["error"]


def test_every_public_repo_method_takes_msp_id_first_but_the_three_named():
    without = set()
    for file_name, class_name, name, node in all_repo_functions():
        if (file_name, class_name, name) in MODULE_FUNCTIONS:
            continue
        first = first_parameter(node, in_class=class_name is not None)
        if first is None or first.arg != "msp_id":
            without.add((file_name, class_name, name))
            continue
        assert _annotation_name(first.annotation) == "UUID", (file_name, class_name, name)

    assert without == WITHOUT_MSP_ID


def test_the_three_named_exist_and_take_no_msp_id_anywhere():
    """The allowance is exact: the three exist, and none of them has an msp_id
    parameter at all (an MSP is not known when they run)."""
    seen = set()
    for file_name, class_name, name, node in all_repo_functions():
        key = (file_name, class_name, name)
        if key in WITHOUT_MSP_ID:
            seen.add(key)
            names = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
            assert "msp_id" not in names, key

    assert seen == WITHOUT_MSP_ID


# --- Finding 5 of the C5.3/C5.4 review: a sub-package escapes nothing -----------------------


@contextlib.contextmanager
def planted_subpackage():
    """`app/repo/sub/x.py`: a repo class whose method takes no msp_id, under a
    sub-package. Both walks must find it; removed whatever happens."""
    folder = REPO_DIR / "sub"
    folder.mkdir()
    try:
        (folder / "__init__.py").write_text("", encoding="utf-8")
        (folder / "x.py").write_text(
            "from sqlalchemy import select\n"
            "from app.models import Client\n"
            "from app.repo.base import Repo\n\n\n"
            "class PlantedRepo(Repo):\n"
            "    async def leak(self, client_id):\n"
            "        return await self._one(select(Client).where(Client.id == client_id))\n",
            encoding="utf-8",
        )
        yield folder
    finally:
        for name in ("x.py", "__init__.py"):
            (folder / name).unlink(missing_ok=True)
        shutil.rmtree(folder / "__pycache__", ignore_errors=True)
        folder.rmdir()


def test_the_ast_walk_reaches_a_sub_package_of_the_repo():
    with planted_subpackage():
        found = {(file_name, class_name, name) for file_name, class_name, name, _ in all_repo_functions()}

        assert ("x.py", "PlantedRepo", "leak") in found
        without = {
            (file_name, class_name, name)
            for file_name, class_name, name, node in all_repo_functions()
            if (file_name, class_name, name) not in MODULE_FUNCTIONS
            and ((first := first_parameter(node, in_class=class_name is not None)) is None or first.arg != "msp_id")
        }
        assert ("x.py", "PlantedRepo", "leak") in without
        assert without - {("x.py", "PlantedRepo", "leak")} == WITHOUT_MSP_ID


def test_the_isolation_test_s_module_scan_reaches_a_sub_package_of_the_repo():
    from tests.test_repo_isolation import every_repo_method

    with planted_subpackage():
        try:
            names = {(cls.__name__, method) for cls, method in every_repo_method()}
        finally:
            for module in [m for m in sys.modules if m.startswith("app.repo.sub")]:
                del sys.modules[module]

    assert ("PlantedRepo", "leak") in names


def test_there_is_no_sub_package_under_the_repo_today():
    assert [path for path in REPO_DIR.rglob("*.py") if path.parent != REPO_DIR] == []
