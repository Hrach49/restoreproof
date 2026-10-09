"""C5.2: the one initial migration.

On an empty database `alembic upgrade head`, `downgrade -1` and `upgrade head`
again leave no error and the expected tables, and the models' metadata and the
migrated database agree.
"""

import os
import secrets
import subprocess
import sys

import asyncpg
import pytest
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import CheckConstraint
from sqlalchemy.engine import make_url

from app.models import Base
from tests.conftest import CLOUD_DIR, alembic, alembic_config, asyncpg_dsn

TABLES = {
    "msp",
    "user",
    "client",
    "worker",
    "connector",
    "test_plan",
    "test_run",
    "test_item",
    "report",
    "audit_log",
    "install_token",
}

PUBLIC_CONSTRAINTS = (
    "SELECT conname FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
    "WHERE n.nspname = 'public' AND c.conrelid::regclass::text <> 'alembic_version'"
)


@pytest.fixture
async def empty_database(test_database_url):
    """A database of this test's own, made empty and dropped again.

    Upgrading and downgrading the session's database would take the other
    tests' tables away.
    """
    name = f"{make_url(test_database_url).database}_{secrets.token_hex(4)}"
    admin = await asyncpg.connect(asyncpg_dsn(test_database_url), timeout=5)
    await admin.execute(f'CREATE DATABASE "{name}"')
    try:
        yield make_url(test_database_url).set(database=name).render_as_string(hide_password=False)
    finally:
        await admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
        await admin.close()


async def column(database_url: str, query: str) -> list:
    connection = await asyncpg.connect(asyncpg_dsn(database_url), timeout=5)
    try:
        return [row[0] for row in await connection.fetch(query)]
    finally:
        await connection.close()


async def tables(database_url: str) -> set[str]:
    return set(
        await column(database_url, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )


async def version(database_url: str) -> list[str]:
    return await column(database_url, "SELECT version_num FROM alembic_version")


def bare_environment() -> dict[str, str]:
    """What a process needs to start, and no setting of ours."""
    keep = {"PATH", "SYSTEMROOT", "PATHEXT", "TEMP", "TMP", "HOME", "USERPROFILE"}
    return {name: value for name, value in os.environ.items() if name.upper() in keep}


def alembic_cli(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=CLOUD_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_there_is_one_migration_and_it_is_the_initial_one():
    script = ScriptDirectory.from_config(alembic_config("postgresql+asyncpg://unused/unused"))

    revisions = [(revision.revision, revision.down_revision) for revision in script.walk_revisions()]
    assert script.get_heads() == ["0001"]
    assert revisions == [("0001", None)]


def test_the_models_name_the_eleven_tables():
    assert set(Base.metadata.tables) == TABLES


async def test_upgrade_downgrade_once_and_upgrade_again(empty_database):
    assert await tables(empty_database) == set()

    await alembic(empty_database, "upgrade", "head")
    assert await tables(empty_database) == TABLES | {"alembic_version"}
    assert await version(empty_database) == ["0001"]

    await alembic(empty_database, "downgrade", "-1")
    assert await tables(empty_database) == {"alembic_version"}
    assert await version(empty_database) == []
    assert await column(empty_database, PUBLIC_CONSTRAINTS) == []

    await alembic(empty_database, "upgrade", "head")
    assert await tables(empty_database) == TABLES | {"alembic_version"}
    assert await version(empty_database) == ["0001"]


async def test_the_models_and_the_migrated_database_agree(empty_database):
    """`alembic check`: an autogenerate run that must find nothing to do."""
    await alembic(empty_database, "upgrade", "head")

    await alembic(empty_database, "check")


async def test_alembic_check_would_see_a_difference(empty_database):
    """The check above is not vacuous: a table the models lack is a difference."""
    await alembic(empty_database, "upgrade", "head")
    connection = await asyncpg.connect(asyncpg_dsn(empty_database), timeout=5)
    await connection.execute("CREATE TABLE stray (id integer PRIMARY KEY)")
    await connection.close()

    with pytest.raises(CommandError, match="New upgrade operations detected"):
        await alembic(empty_database, "check")


async def test_the_check_constraints_are_the_models(migrated_database):
    """Autogenerate doesn't compare CHECK constraints, so their names are
    compared here; tests/test_models.py shows each one refusing a row."""
    in_models = {
        constraint.name
        for table in Base.metadata.tables.values()
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    in_database = set(await column(migrated_database, PUBLIC_CONSTRAINTS + " AND c.contype = 'c'"))

    assert in_models == in_database
    assert len(in_models) >= 12


async def test_every_constraint_and_index_has_the_convention_s_name(migrated_database):
    constraints = await column(migrated_database, PUBLIC_CONSTRAINTS)
    indexes = await column(
        migrated_database,
        "SELECT indexname FROM pg_indexes "
        "WHERE schemaname = 'public' AND tablename <> 'alembic_version'",
    )

    assert constraints
    assert all(name.startswith(("pk_", "fk_", "uq_", "ck_")) for name in constraints)
    assert all(name.startswith(("pk_", "uq_", "ix_")) for name in indexes)
    assert {"ix_test_run_msp_id_client_id_created_at", "ix_test_item_msp_id_run_id"} <= set(indexes)


async def test_the_command_line_migrates_from_database_url_alone(empty_database):
    """What the api container runs: `alembic upgrade head` with DATABASE_URL and
    no other setting (a migration needs no S3 key)."""
    env = bare_environment()
    env["DATABASE_URL"] = empty_database

    for args in (("upgrade", "head"), ("downgrade", "-1"), ("upgrade", "head"), ("check",)):
        done = alembic_cli(env, *args)
        assert done.returncode == 0, done.stderr[-2000:]

    assert await tables(empty_database) == TABLES | {"alembic_version"}


def test_the_command_line_without_database_url_names_it():
    done = alembic_cli(bare_environment(), "upgrade", "head")

    assert done.returncode != 0
    assert "settings error: DATABASE_URL is missing" in done.stderr


async def test_offline_mode_is_refused(empty_database):
    with pytest.raises(CommandError, match="offline mode"):
        await alembic(empty_database, "upgrade", "head", sql=True)

    assert await tables(empty_database) == set()


def test_alembic_ini_holds_no_database_url():
    text = (CLOUD_DIR / "alembic.ini").read_text(encoding="utf-8")

    assert "sqlalchemy.url" not in text
    assert "postgresql" not in text
