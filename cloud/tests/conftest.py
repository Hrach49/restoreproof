"""Shared fixtures: the settings a test app runs on and the test database.

The database tests run on a real PostgreSQL 16 and nothing else
(docs/decisions.md 2026-10-10, C5.1 and C5.2, point 2). They never skip: a
database that can't be reached fails them. `-m "not db"` deselects them.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
from collections.abc import AsyncIterator
from pathlib import Path

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.settings import Settings, load_settings

CLOUD_DIR = Path(__file__).resolve().parent.parent

# The Compose stack's test database (cloud/docker-compose.yml). Local only.
DEFAULT_TEST_DATABASE_URL = (
    "postgresql+asyncpg://restoreproof:local-only-postgres@127.0.0.1:55432/restoreproof_test"
)

HOW_TO_START = (
    "set TEST_DATABASE_URL, or run `docker compose up -d --wait postgres` from cloud/ "
    '(docs/testing.md, "Cloud")'
)


def checked_test_database_url(environ: dict[str, str] | os._Environ) -> str:
    """The tests' database URL, refused unless its database says it is a test one.

    The session empties this database, so it is never taken from DATABASE_URL
    and its name must end in `_test`.
    """
    url = environ.get("TEST_DATABASE_URL") or DEFAULT_TEST_DATABASE_URL
    try:
        parsed = make_url(url)
    except Exception:
        raise ValueError("TEST_DATABASE_URL is not a database URL") from None
    if parsed.drivername != "postgresql+asyncpg":
        raise ValueError("TEST_DATABASE_URL must start postgresql+asyncpg://")
    if not (parsed.database or "").endswith("_test"):
        raise ValueError(
            "TEST_DATABASE_URL must name a database ending in _test: the tests empty it"
        )
    return url


def asyncpg_dsn(url: str) -> str:
    """The same database for asyncpg's own connect (no SQLAlchemy driver name)."""
    return make_url(url).set(drivername="postgresql").render_as_string(hide_password=False)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "test_database_url" in getattr(item, "fixturenames", ()):
            item.add_marker(pytest.mark.db)


@pytest.fixture(scope="session")
async def test_database_url() -> str:
    """The test database's URL, once it has answered."""
    try:
        url = checked_test_database_url(os.environ)
    except ValueError as error:
        pytest.fail(str(error), pytrace=False)
    try:
        connection = await asyncpg.connect(asyncpg_dsn(url), timeout=5)
    except Exception as error:  # noqa: BLE001 - any failure to connect is the same answer
        pytest.fail(
            f"the test database can't be reached ({type(error).__name__}): {HOW_TO_START}",
            pytrace=False,
        )
    await connection.close()
    return url


def alembic_config(database_url: str) -> Config:
    """alembic.ini with the database given by the caller, not the environment."""
    config = Config(str(CLOUD_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(CLOUD_DIR / "app" / "migrations"))
    config.attributes["database_url"] = database_url
    return config


async def alembic(database_url: str, name: str, *args, **kwargs) -> None:
    """Run one alembic command as the command line does.

    env.py starts an event loop of its own, so the command runs in a thread.
    """
    await asyncio.to_thread(getattr(command, name), alembic_config(database_url), *args, **kwargs)


@pytest.fixture(scope="session")
async def migrated_database(test_database_url: str) -> str:
    """The test database, emptied and then built by `alembic upgrade head`, once.

    Every test runs on what the migration made, never on `metadata.create_all`.
    """
    connection = await asyncpg.connect(asyncpg_dsn(test_database_url), timeout=5)
    try:
        await connection.execute("DROP SCHEMA public CASCADE")
        await connection.execute("CREATE SCHEMA public")
    finally:
        await connection.close()
    await alembic(test_database_url, "upgrade", "head")
    return test_database_url


@pytest.fixture(scope="session")
async def test_engine(migrated_database: str):
    engine = create_async_engine(
        migrated_database,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"server_settings": {"timezone": "UTC"}},
    )
    yield engine
    await engine.dispose()


@pytest.fixture
async def session(test_engine, test_database_url):
    """A session inside one transaction that is rolled back when the test ends.

    The code under test may commit: the session joins the outer transaction
    with savepoints.
    """
    async with test_engine.connect() as connection:
        outer = await connection.begin()
        async with AsyncSession(
            bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
        ) as session:
            yield session
        await outer.rollback()


def make_settings(**changes: str) -> Settings:
    """Settings for an app under test; every address is a closed loopback port."""
    env = {
        "DATABASE_URL": "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none",
        "S3_ENDPOINT": "http://127.0.0.1:1",
        "S3_ACCESS_KEY": "test-access-key",
        "S3_SECRET_KEY": "test-secret-key",
        "S3_BUCKET": "test-bucket",
        "SECRET_KEY": "test-secret-key-" + "0" * 32,
    }
    env.update(changes)
    return load_settings(env)


def session_override(session: AsyncSession):
    """What a test puts in place of `get_session`: the same generator over the
    test's own session, with a savepoint where the real one has the
    transaction (the test's is already open), so a test sees what a refused
    request rolled back and keeps what a 201 committed."""

    async def dependency() -> AsyncIterator[AsyncSession]:
        async with session.begin_nested():
            yield session

    return dependency


@contextlib.asynccontextmanager
async def own_database_context(test_database_url: str):
    """A migrated database of a test's own, dropped again. The admin
    connection is closed whatever CREATE DATABASE does (the C5.5/C5.6
    review's finding 9)."""
    name = f"{make_url(test_database_url).database}_{secrets.token_hex(4)}"
    url = make_url(test_database_url).set(database=name).render_as_string(hide_password=False)
    admin = await asyncpg.connect(asyncpg_dsn(test_database_url), timeout=5)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        try:
            await alembic(url, "upgrade", "head")
            yield url
        finally:
            await admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
    finally:
        await admin.close()


@pytest.fixture
async def own_database(test_database_url: str):
    """A migrated database of this test's own: for a test whose rows must be
    committed, so a second connection can see them (two requests at once, a
    commit seen at the response's start). The session fixture's rows never
    are."""
    async with own_database_context(test_database_url) as url:
        yield url
