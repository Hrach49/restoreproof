"""The database engine and its sessions (C5.1).

Asynchronous SQLAlchemy on asyncpg. The engine never echoes and hides the
parameters of a failed statement, so no row's content reaches a log line, and
every session is in UTC.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import Request

from app.settings import Settings

CONNECT_TIMEOUT_S = 5


def make_engine(settings: Settings) -> AsyncEngine:
    """The app's engine. Making it connects to nothing."""
    return create_async_engine(
        settings.database_url.get_secret_value(),
        echo=False,
        hide_parameters=True,
        pool_pre_ping=True,
        connect_args={"timeout": CONNECT_TIMEOUT_S, "server_settings": {"timezone": "UTC"}},
    )


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request, closed when it ends."""
    async with request.app.state.session_factory() as session:
        yield session


async def check_database(engine: AsyncEngine) -> None:
    """Raise unless the database answers a statement."""
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
