"""C5.1: the app factory, its routers and its engine."""

import importlib
import io

import asyncpg
import httpx
import pytest
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import app
from app import health
from fastapi import params
from sqlalchemy.ext.asyncio import create_async_engine

from app.db import SessionDep, get_session, make_engine, make_session_factory
from app.main import ROUTERS, create_app
from app.settings import SettingsError
from tests.conftest import asyncpg_dsn, checked_test_database_url, make_settings

ROUTER_NAMES = ("workers", "jobs", "results", "heartbeat", "admin", "ui")


def make_app():
    return create_app(make_settings(), log_stream=io.StringIO())


async def get(application, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
        return await client.get(path)


def test_the_six_routers_are_modules_with_a_router_each():
    assert tuple(name for name, _ in ROUTERS) == ROUTER_NAMES
    for name, router in ROUTERS:
        module = importlib.import_module(f"app.routers.{name}")
        assert module.router is router
        assert isinstance(router, APIRouter)


def test_every_route_is_under_v1_but_healthz():
    """FastAPI keeps an included router as one entry: the factory's own routes
    are held by their paths, the included routers by which they are."""
    routes = make_app().routes

    own = [route.path for route in routes if hasattr(route, "path")]
    included = [route.original_router for route in routes if not hasattr(route, "path")]
    assert own and all(path.startswith("/v1/") for path in own)
    assert included == [health.router, *(router for _, router in ROUTERS)]
    assert [route.path for route in health.router.routes] == ["/healthz"]


@pytest.mark.parametrize("name", ROUTER_NAMES)
async def test_a_route_added_to_a_router_is_served_under_v1_and_nowhere_else(name):
    """C5.5 to C5.11 add routes to a router and no wiring."""
    router = dict(ROUTERS)[name]
    before = list(router.routes)

    async def answer():
        return {"router": name}

    router.add_api_route(f"/{name}/wiring-probe", answer, methods=["GET"])
    try:
        application = make_app()
        served = await get(application, f"/v1/{name}/wiring-probe")
        outside = await get(application, f"/{name}/wiring-probe")
    finally:
        # The probe alone: the router is the module's own, and its routes stay.
        router.routes[:] = before

    assert (served.status_code, served.json()) == (200, {"router": name})
    assert outside.status_code == 404
    assert router.routes == before


async def test_the_openapi_document_is_under_v1_and_leaves_healthz_out():
    application = make_app()

    document = await get(application, "/v1/openapi.json")

    assert document.status_code == 200
    assert document.json()["info"] == {"title": "RestoreProof Cloud", "version": app.__version__}
    assert "/healthz" not in document.json().get("paths", {})
    assert (await get(application, "/openapi.json")).status_code == 404
    assert (await get(application, "/docs")).status_code == 404
    assert (await get(application, "/redoc")).status_code == 404
    assert (await get(application, "/docs/oauth2-redirect")).status_code == 404


async def test_an_unknown_path_is_404_with_a_request_id():
    response = await get(make_app(), "/v1/nothing-here")

    assert response.status_code == 404
    assert response.headers["x-request-id"]


def test_without_settings_the_factory_reads_the_environment(monkeypatch):
    for name in ("DATABASE_URL", "S3_ENDPOINT", "S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_BUCKET"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("SECRET_KEY", "")

    with pytest.raises(SettingsError, match="settings error: DATABASE_URL is missing"):
        create_app()


def test_with_a_whole_environment_the_factory_makes_the_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none")
    monkeypatch.setenv("S3_ENDPOINT", "http://127.0.0.1:1")
    monkeypatch.setenv("S3_ACCESS_KEY", "a")
    monkeypatch.setenv("S3_SECRET_KEY", "b")
    monkeypatch.setenv("S3_BUCKET", "from-the-environment")
    monkeypatch.setenv("SECRET_KEY", "k" * 32)
    monkeypatch.setenv("LOG_LEVEL", "error")

    application = create_app()

    assert application.state.settings.s3_bucket == "from-the-environment"
    assert application.state.storage.bucket == "from-the-environment"


async def test_the_lifespan_disposes_the_engine():
    application = make_app()
    disposed = []

    class Engine:
        async def dispose(self) -> None:
            disposed.append(True)

    application.state.engine = Engine()

    async with application.router.lifespan_context(application):
        assert disposed == []

    assert disposed == [True]


def test_the_engine_hides_parameters_and_never_echoes():
    engine = make_engine(make_settings())

    assert engine.sync_engine.hide_parameters is True
    assert engine.sync_engine.echo is False
    assert engine.dialect.driver == "asyncpg"
    assert engine.url.database == "none"


async def test_the_engine_s_sessions_are_in_utc(test_database_url):
    engine = make_engine(make_settings(DATABASE_URL=test_database_url))
    try:
        async with engine.connect() as connection:
            zone = (await connection.execute(text("SHOW TimeZone"))).scalar_one()
    finally:
        await engine.dispose()

    assert zone == "UTC"


async def test_get_session_hands_out_a_session_of_the_app_s_factory_and_closes_it():
    application = make_app()

    class Request:
        app = application

    sessions = get_session(Request())
    session = await anext(sessions)

    assert session.bind is application.state.engine
    assert session.sync_session.expire_on_commit is False
    with pytest.raises(StopAsyncIteration):
        await anext(sessions)
    await application.state.engine.dispose()


def test_the_session_factory_is_bound_to_its_engine():
    engine = make_engine(make_settings())

    assert make_session_factory(engine).kw["bind"] is engine


@pytest.mark.parametrize(
    ("url", "problem"),
    [
        ("postgresql+asyncpg://u:p@127.0.0.1:55432/restoreproof", "ending in _test"),
        ("postgresql+asyncpg://u:p@127.0.0.1:55432/", "ending in _test"),
        ("postgresql+asyncpg://u:p@127.0.0.1:55432/restoreproof_test_copy", "ending in _test"),
        ("postgresql://u:p@127.0.0.1:55432/restoreproof_test", "postgresql\\+asyncpg://"),
        ("sqlite+aiosqlite:///restoreproof_test", "postgresql\\+asyncpg://"),
        ("not a url", "not a database URL"),
    ],
)
def test_the_tests_refuse_a_database_that_does_not_say_it_is_a_test_one(url, problem):
    with pytest.raises(ValueError, match=problem) as raised:
        checked_test_database_url({"TEST_DATABASE_URL": url})

    assert "u:p" not in str(raised.value)


def test_the_tests_database_is_never_taken_from_database_url():
    url = checked_test_database_url({"DATABASE_URL": "postgresql+asyncpg://u:p@prod/live"})

    assert url.endswith("@127.0.0.1:55432/restoreproof_test")


async def test_get_session_commits_before_the_response_starts_and_rolls_back_when_the_route_raises(own_database):
    """C5.5 point 5, held as the review's finding 1 asked: the row a route wrote
    is committed when the response's first ASGI message leaves, seen from a
    second connection inside `send`; a route that raises leaves no row. On a
    database of its own, so nothing is committed into the shared one."""
    engine = create_async_engine(own_database, connect_args={"server_settings": {"timezone": "UTC"}})
    application = make_app()
    application.state.session_factory = make_session_factory(engine)
    router = APIRouter()

    @router.get("/session-probe/{outcome}")
    async def probe(outcome: str, session: SessionDep):
        await session.execute(text("INSERT INTO msp (name) VALUES (:name)"), {"name": f"probe-{outcome}"})
        if outcome == "raise":
            raise HTTPException(status_code=400, detail="no")
        return {"ok": True}

    application.include_router(router, prefix="/v1")
    reader = await asyncpg.connect(asyncpg_dsn(own_database), timeout=5)
    seen_at_start: dict[str, int] = {}

    async def observing(scope, receive, send):
        async def observe(message):
            if message["type"] == "http.response.start":
                seen_at_start[scope["path"]] = await reader.fetchval(
                    "SELECT count(*) FROM msp WHERE name LIKE 'probe-%'"
                )
            await send(message)

        await application(scope, receive, observe)

    try:
        transport = httpx.ASGITransport(app=observing)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            returned = await client.get("/v1/session-probe/return")
            raised = await client.get("/v1/session-probe/raise")
        names = [row["name"] for row in await reader.fetch("SELECT name FROM msp ORDER BY name")]
    finally:
        await reader.close()
        await engine.dispose()

    assert (returned.status_code, raised.status_code) == (200, 400)
    assert seen_at_start == {"/v1/session-probe/return": 1, "/v1/session-probe/raise": 1}
    assert names == ["probe-return"]


def test_the_session_dependency_exits_before_the_response_by_its_scope():
    """FastAPI 0.143 gives a yield dependency the scope `request` by default,
    whose exit runs after the response is sent; the alias says `function`."""
    (depends,) = [m for m in SessionDep.__metadata__ if isinstance(m, params.Depends)]

    assert depends.dependency is get_session
    assert depends.scope == "function"


def test_the_session_factory_is_bound_to_its_engine():
    engine = make_engine(make_settings())

    assert make_session_factory(engine).kw["bind"] is engine


@pytest.mark.parametrize(
    ("url", "problem"),
    [
        ("postgresql+asyncpg://u:p@127.0.0.1:55432/restoreproof", "ending in _test"),
        ("postgresql+asyncpg://u:p@127.0.0.1:55432/", "ending in _test"),
        ("postgresql+asyncpg://u:p@127.0.0.1:55432/restoreproof_test_copy", "ending in _test"),
        ("postgresql://u:p@127.0.0.1:55432/restoreproof_test", "postgresql\\+asyncpg://"),
        ("sqlite+aiosqlite:///restoreproof_test", "postgresql\\+asyncpg://"),
        ("not a url", "not a database URL"),
    ],
)
def test_the_tests_refuse_a_database_that_does_not_say_it_is_a_test_one(url, problem):
    with pytest.raises(ValueError, match=problem) as raised:
        checked_test_database_url({"TEST_DATABASE_URL": url})

    assert "u:p" not in str(raised.value)


def test_the_tests_database_is_never_taken_from_database_url():
    url = checked_test_database_url({"DATABASE_URL": "postgresql+asyncpg://u:p@prod/live"})

    assert url.endswith("@127.0.0.1:55432/restoreproof_test")


async def test_get_session_commits_when_the_route_returns_and_rolls_back_when_it_raises(test_engine, test_database_url):
    """C5.5, point 5: the dependency owns the request's transaction. A row a
    route wrote is there after a 200 and not after a 400, seen from another
    connection; the repos never commit, so nothing else could have."""
    application = make_app()
    application.state.session_factory = make_session_factory(test_engine)
    router = APIRouter()

    @router.get("/session-probe/{outcome}")
    async def probe(outcome: str, session: AsyncSession = Depends(get_session)):
        await session.execute(text("INSERT INTO msp (name) VALUES (:name)"), {"name": f"probe-{outcome}"})
        if outcome == "raise":
            raise HTTPException(status_code=400, detail="no")
        return {"ok": True}

    application.include_router(router, prefix="/v1")
    reader = await asyncpg.connect(asyncpg_dsn(test_database_url), timeout=5)
    try:
        returned = await get(application, "/v1/session-probe/return")
        raised = await get(application, "/v1/session-probe/raise")
        names = await reader.fetch("SELECT name FROM msp WHERE name LIKE 'probe-%'")
        await reader.execute("DELETE FROM msp WHERE name LIKE 'probe-%'")
    finally:
        await reader.close()

    assert (returned.status_code, raised.status_code) == (200, 400)
    assert [row["name"] for row in names] == ["probe-return"]


async def test_an_own_database_that_cannot_be_made_closes_the_admin_connection(monkeypatch):
    """The review's finding 9: a failing CREATE DATABASE must not leak the
    connection that tried it."""
    from tests import conftest

    class FakeConnection:
        closed = False

        async def execute(self, statement):
            if statement.startswith("CREATE DATABASE"):
                raise RuntimeError("permission denied to create database")

        async def close(self):
            self.closed = True

    fake = FakeConnection()

    async def connect(_dsn, timeout):
        return fake

    monkeypatch.setattr(conftest.asyncpg, "connect", connect)
    with pytest.raises(RuntimeError, match="create database"):
        async with conftest.own_database_context("postgresql+asyncpg://u:p@127.0.0.1:1/x_test"):
            pass  # pragma: no cover - never reached

    assert fake.closed is True
