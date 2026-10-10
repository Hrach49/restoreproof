"""The jobs routes, served under /v1.

`GET /jobs` (C5.6; docs/decisions.md 2026-10-10, "C5.5 and C5.6", point 4):
the Worker behind the bearer token gets its oldest queued runs, at most five,
as a `restoreproof.jobs.v1` document (shared/schemas/jobs.v1.json, which the
Worker's reader holds a document to), each run now `dispatched`. Every field
comes from a column the database already holds to the schema's rule: the
run's id as `run_id`, the client's id as `client_id`, the connector's profile
as `client`, the connector's type, the plan's three sizes, `latest`, and the
client's `screenshots_enabled`; `canary_cursor` is left out (the Worker
defaults it). A Worker with nothing queued gets an empty `jobs`. A revoked
Worker is `current_worker`'s 401 before any statement.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependency import current_worker
from app.db import get_session
from app.models import Client, Connector, TestPlan, TestRun, Worker
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo

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
    jobs: list[Job] = Field(max_length=5)


def job_of(run: TestRun, plan: TestPlan, connector: Connector, client: Client) -> Job:
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


def _required(row: Any, what: str) -> Any:
    """By the keys of C5.3 a run's plan, connector and client exist in its
    MSP; a None here is the app's own fault, never an empty job."""
    if row is None:
        raise RuntimeError(f"a dispatched run has no {what}")
    return row


@router.get("/jobs", response_model=JobsDocument)
async def jobs(
    request: Request,
    worker: Worker = Depends(current_worker),
    session: AsyncSession = Depends(get_session),
) -> JobsDocument:
    msp_id: UUID = request.state.msp_id
    runs = await RunRepo(session).dispatch(msp_id, worker.id, dt.datetime.now(dt.timezone.utc))
    answer = []
    for run in runs:
        plan = _required(await PlanRepo(session).get(msp_id, run.plan_id), "plan")
        connector = _required(await ConnectorRepo(session).get(msp_id, run.connector_id), "connector")
        client = _required(await ClientRepo(session).get(msp_id, run.client_id), "client")
        answer.append(job_of(run, plan, connector, client))
    return JobsDocument(jobs=answer)
