"""The database engine and its sessions (C5.1; the transaction per request C5.5).

Asynchronous SQLAlchemy on asyncpg. The engine never echoes and hides the
parameters of a failed statement, so no row's content reaches a log line, and
every session is in UTC.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import Request

from app.settings import Settings

CONNECT_TIMEOUT_S = 5


def make_engine_for_url(url: str) -> AsyncEngine:
    """An engine for `url` with the app's settings: no echo, the parameters
    of a failed statement hidden, every session in UTC. The CLI and the
    scheduler (C5.10, C5.9) make theirs from `DATABASE_URL` alone through
    here; making it connects to nothing."""
    return create_async_engine(
        url,
        echo=False,
        hide_parameters=True,
        pool_pre_ping=True,
        connect_args={"timeout": CONNECT_TIMEOUT_S, "server_settings": {"timezone": "UTC"}},
    )


def make_engine(settings: Settings) -> AsyncEngine:
    """The app's engine. Making it connects to nothing."""
    return make_engine_for_url(settings.database_url.get_secret_value())


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session and one transaction per request (C5.5,
    docs/decisions.md 2026-10-10, "C5.5 and C5.6", point 5).

    Committed when the route returns, rolled back when it raises (an
    HTTPException included: FastAPI throws it into this generator). The repos
    flush and never commit; a route calls neither commit nor rollback. A route
    takes it as `SessionDep`, never as a bare `Depends(get_session)`: FastAPI
    0.143 gives a yield dependency the scope `request` by default, whose exit
    runs after the response is sent, and the commit must run before (the
    C5.5/C5.6 review's finding 1), which `scope="function"` does.
    """
    async with request.app.state.session_factory() as session:
        async with session.begin():
            yield session


SessionDep = Annotated[AsyncSession, Depends(get_session, scope="function")]


async def check_database(engine: AsyncEngine) -> None:
    """Raise unless the database answers a statement."""
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
