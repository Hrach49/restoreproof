"""GET /healthz: whether the database and the bucket answer (C5.1).

A probe for Compose and a load balancer, the one route outside /v1 and not in
the OpenAPI document. 200 only when both are ok, 503 otherwise, always both
keys. Nothing of an exception reaches the body, and the log gets its type only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.db import check_database

# Per check. Both run side by side, so this is also the route's own limit.
CHECK_TIMEOUT_S = 2.0

router = APIRouter()
log = structlog.get_logger("app.health")

Verdict = Literal["ok", "error"]


async def _verdict(name: str, check: Callable[[], Awaitable[None]]) -> Verdict:
    try:
        await asyncio.wait_for(check(), timeout=CHECK_TIMEOUT_S)
    except Exception as error:  # noqa: BLE001 - any failure of a check is "error"
        log.warning("health check failed", check=name, exc_type=type(error).__name__)
        return "error"
    return "ok"


@router.get("/healthz", include_in_schema=False)
async def healthz(request: Request) -> JSONResponse:
    state = request.app.state
    db, s3 = await asyncio.gather(
        _verdict("db", lambda: check_database(state.engine)),
        _verdict("s3", lambda: asyncio.to_thread(state.storage.check)),
    )
    return JSONResponse(
        {"db": db, "s3": s3},
        status_code=200 if db == s3 == "ok" else 503,
        headers={"Cache-Control": "no-store"},
    )
