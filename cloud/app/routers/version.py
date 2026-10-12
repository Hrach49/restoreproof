"""The version route, served under /v1.

`GET /version` (C5.11; docs/decisions.md 2026-10-12, point 2): the contract's
number and the Cloud's version, a closed body, no token (it must answer before
a Worker has one: W7.2's `rpworker doctor` checks `cloud_url` with it) and no
statement (the route takes neither a session nor the Worker; it says nothing
the anonymous OpenAPI document doesn't say in `info.version`).
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict

import app as package
from app.contract import API_VERSION

router = APIRouter()


class VersionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api: Literal[1]
    version: str


@router.get("/version", response_model=VersionBody)
async def version(response: Response) -> VersionBody:
    response.headers["Cache-Control"] = "no-store"
    return VersionBody(api=API_VERSION, version=package.__version__)
