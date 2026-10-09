"""Alembic's environment (C5.2): asynchronous, online only.

The database comes from the caller (`config.attributes["database_url"]`, which
the tests set) or from DATABASE_URL alone: a migration needs no S3 key, so it
doesn't load the app's other settings. alembic.ini holds no URL.
"""

from __future__ import annotations

import asyncio

from alembic import context
from alembic.util import CommandError
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.models import Base
from app.settings import database_url_from_environment

config = context.config
target_metadata = Base.metadata


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run_online() -> None:
    url = config.attributes.get("database_url") or database_url_from_environment()
    engine = create_async_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    raise CommandError("offline mode (--sql) isn't supported: migrations run on a database")

asyncio.run(_run_online())
