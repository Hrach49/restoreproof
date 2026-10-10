"""The jobs routes, served under /v1.

`GET /jobs` (C5.6; docs/decisions.md 2026-10-10, "C5.5 and C5.6", point 4):
the Worker behind the bearer token gets its oldest queued runs, at most five,
as a `restoreproof.jobs.v1` document (shared/schemas/jobs.v1.json, which the
Worker's reader holds a document to), each run now `dispatched`. Every field
comes from a column the database already holds to the schema's rule: the
run's id as `run_id`, the client's id as `client_id`, the connector's profile
as `client`, the connector's type, the plan's three sizes, `latest`, and the
client's `screenshots_enabled`; `canary_cursor` is left out (the Worker
defaults it). `RunRepo.dispatch` answers each run with its plan, connector
and client in one joined select, so a poll is two statements after the
token's lookup, and one when nothing is queued. A Worker with nothing queued
gets an empty `jobs`. A revoked Worker is `current_worker`'s 401 before any
statement. The transaction is `get_session`'s, committed before the response
starts (`SessionDep`).
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependency import current_worker
from app.db import SessionDep
from app.models import Worker
from app.repo.runs import DISPATCH_LIMIT, Dispatched, RunRepo
from app.routers.errors import NOT_AUTHENTICATED

router = APIRouter()

JOBS_FORMAT = "restoreproof.jobs.v1"
RESTORE_POINT_LATEST = "latest"


class ConnectorRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str


class Job(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    client_id: str
    client: dict[str, Any]
    connector: ConnectorRef
    sample_mail: int
    sample_sp: int
    sample_od: int
    restore_point: str
    screenshots_enabled: bool


class JobsDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["restoreproof.jobs.v1"] = JOBS_FORMAT
    jobs: list[Job] = Field(max_length=DISPATCH_LIMIT)


def job_of(dispatched: Dispatched) -> Job:
    run, plan, connector, client = dispatched
    return Job(
        run_id=str(run.id),
        client_id=str(run.client_id),
        client=connector.config_json,
        connector=ConnectorRef(type=connector.type),
        sample_mail=plan.sample_mail,
        sample_sp=plan.sample_sp,
        sample_od=plan.sample_od,
        restore_point=RESTORE_POINT_LATEST,
        screenshots_enabled=client.screenshots_enabled,
    )


@router.get("/jobs", response_model=JobsDocument, responses={401: NOT_AUTHENTICATED})
async def jobs(worker: Annotated[Worker, Depends(current_worker)], session: SessionDep) -> JobsDocument:
    taken = await RunRepo(session).dispatch(worker.msp_id, worker.id, dt.datetime.now(dt.timezone.utc))
    return JobsDocument(jobs=[job_of(dispatched) for dispatched in taken])
