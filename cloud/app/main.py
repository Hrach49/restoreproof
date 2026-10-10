"""The Cloud's app factory (C5.1).

Run as `uvicorn app.main:create_app --factory`. The settings are loaded first,
so a missing variable ends the process before it listens.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TextIO

from fastapi import APIRouter, FastAPI

import app as package
from app import health
from app.db import make_engine, make_session_factory
from app.logging import RequestLogMiddleware, configure_logging
from app.results import tsa_ca_pem
from app.routers import admin, heartbeat, jobs, results, ui, workers
from app.settings import Settings, load_settings
from app.storage import Storage

API_PREFIX = "/v1"

# Every API route lives in one of these. C5.5 to C5.11 add routes to a router;
# the wiring is here and doesn't change.
ROUTERS: tuple[tuple[str, APIRouter], ...] = (
    ("workers", workers.router),
    ("jobs", jobs.router),
    ("results", results.router),
    ("heartbeat", heartbeat.router),
    ("admin", admin.router),
    ("ui", ui.router),
)


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

    application.add_middleware(RequestLogMiddleware)
    application.include_router(health.router)
    for _name, router in ROUTERS:
        application.include_router(router, prefix=API_PREFIX)
    return application
