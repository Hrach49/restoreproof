"""Shared fixtures: the settings a test app runs on and the test database.

The database tests run on a real PostgreSQL 16 and nothing else
(docs/decisions.md 2026-10-10, C5.1 and C5.2, point 2). They never skip: a
database that can't be reached fails them. `-m "not db"` deselects them.
"""

from __future__ import annotations

import os

import asyncpg
import pytest
from sqlalchemy.engine import make_url

from app.settings import Settings, load_settings

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
