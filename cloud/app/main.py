"""The Cloud's app factory (C5.1).

Run as `uvicorn app.main:create_app --factory`. The settings are loaded first,
so a missing variable ends the process before it listens.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TextIO

from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles

import app as package
from app import health, ui
from app.auth.login_limiter import LoginLimiter
from app.contract import API_VERSION, ApiVersionMiddleware, BodyCapMiddleware
from app.db import make_engine, make_session_factory
from app.logging import RequestLogMiddleware, configure_logging
from app.results import tsa_ca_pem
from app.routers import admin, heartbeat, jobs, results, version, workers
from app.routers import ui as pages
from app.settings import Settings, load_settings
from app.storage import Storage

# The contract's number is the path's (C5.11; app/contract.py).
API_PREFIX = f"/v{API_VERSION}"

# The pages (C6.1; docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", point
# 1) are served at the root and never in the OpenAPI document.
ROOT_ROUTERS = ("ui",)

# Every API route lives in one of these. C5.5 to C5.11 add routes to a router;
# the wiring is here and doesn't change.
ROUTERS: tuple[tuple[str, APIRouter], ...] = (
    ("workers", workers.router),
    ("jobs", jobs.router),
    ("results", results.router),
    ("heartbeat", heartbeat.router),
    ("admin", admin.router),
    ("ui", pages.router),
    ("version", version.router),
)

# The one route that bounds its own body (96 MiB, on the bytes; C5.7): every
# other request is held to app/contract.py's cap. A test holds this set equal
# to the document's multipart operations.
LARGE_BODY_PATHS = frozenset({f"{API_PREFIX}/results"})


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    yield
    await application.state.engine.dispose()


def create_app(settings: Settings | None = None, *, log_stream: TextIO | None = None) -> FastAPI:
    """Make the app. Connects to nothing: the engine and the S3 client are lazy."""
    settings = load_settings() if settings is None else settings
    configure_logging(settings.log_level, stream=log_stream)

    application = FastAPI(
        title="RestoreProof Cloud",
        version=package.__version__,
        openapi_url=f"{API_PREFIX}/openapi.json",
        docs_url=f"{API_PREFIX}/docs",
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=None,
        lifespan=_lifespan,
    )
    application.state.settings = settings
    application.state.engine = make_engine(settings)
    application.state.session_factory = make_session_factory(application.state.engine)
    application.state.storage = Storage.from_settings(settings)
    # C5.7: the one root a bundle's timestamp is held to, from the image; a
    # test hands the route the shared vectors' test root here.
    application.state.tsa_ca_pem = tsa_ca_pem()
    # C6.1: the login's limiter, in this process's memory on the monotonic clock.
    application.state.login_limiter = LoginLimiter(time.monotonic)
    # C6.6: one report render at a time per process ("Generate now"; a render
    # is CPU seconds in a thread).
    application.state.render_slot = asyncio.Semaphore(1)

    # The last added is outermost: the API header stamps every answer, the
    # log middleware's own 500 included; the cap's 413 is logged as a request.
    application.add_middleware(BodyCapMiddleware, large_body_paths=LARGE_BODY_PATHS)
    application.add_middleware(RequestLogMiddleware)
    application.add_middleware(ApiVersionMiddleware)
    application.include_router(health.router)
    for name, router in ROUTERS:
        if name in ROOT_ROUTERS:
            application.include_router(router, include_in_schema=False)
        else:
            application.include_router(router, prefix=API_PREFIX)
    application.mount(ui.STATIC_PATH, StaticFiles(directory=ui.STATIC_DIR), name="static")
    return application
