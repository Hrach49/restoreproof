"""C5.9 and C5.10's by-hand Done-when, the rows the harness reads
(docs/decisions.md 2026-10-11, "C5.10 and C5.9", point 12; docs/testing.md
"The onboarding CLI and the scheduler"). The rows themselves are made by
`manage.py` in the api container; this script only reads the MSP's own rows
through the repos, and makes the Worker's key. Run from cloud/ with uv:

    uv run python ../docs/api/cloud-lab/c5.9-c5.10-harness/c59-c510-rows.py key
        the public half of an Ed25519 key made for the run (the base64 line of
        its key file); the private half is never kept (nothing is signed)
    uv run python ../docs/api/cloud-lab/c5.9-c5.10-harness/c59-c510-rows.py show <msp_id>
        the MSP's plans (PlanRepo.list), runs (RunRepo.list: state,
        scheduled_for, created_at), Workers (revoked_at) and audit rows

The database is the stack's (DATABASE_URL as docker-compose.yml gives it,
reached on 127.0.0.1:55432); every value in it is local only. Nothing of a
profile is printed: a plan is its ids, sizes and cadence.
"""

from __future__ import annotations

import asyncio
import base64
import sys
import uuid
from pathlib import Path

# docs/api/cloud-lab/c5.9-c5.10-harness -> the repository root, then cloud/ for the app.
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "cloud"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.db import make_engine_for_url, make_session_factory  # noqa: E402
from app.repo.audit import AuditRepo  # noqa: E402
from app.repo.plans import PlanRepo  # noqa: E402
from app.repo.runs import RunRepo  # noqa: E402
from app.repo.workers import WorkerRepo  # noqa: E402

STACK = "postgresql+asyncpg://restoreproof:local-only-postgres@127.0.0.1:55432/restoreproof"


def stamp(value) -> str:
    return "null" if value is None else value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


async def show(msp_id: uuid.UUID) -> None:
    engine = make_engine_for_url(STACK)
    try:
        async with make_session_factory(engine)() as session, session.begin():
            print("test_plan (PlanRepo.list):")
            for plan in await PlanRepo(session).list(msp_id):
                print(
                    f"  plan {plan.id} connector {plan.connector_id} sizes {plan.sample_mail}/{plan.sample_sp}/{plan.sample_od}"
                    f" cadence '{plan.cadence_cron}' enabled {plan.enabled} created_at {stamp(plan.created_at)}"
                )
            print("test_run (RunRepo.list, newest first):")
            for run in await RunRepo(session).list(msp_id):
                print(
                    f"  run {run.id} plan {run.plan_id} state {run.state} scheduled_for {stamp(run.scheduled_for)}"
                    f" created_at {stamp(run.created_at)} dispatched_at {stamp(run.dispatched_at)} attempt {run.attempt}"
                )
            print("worker (WorkerRepo.list):")
            for worker in await WorkerRepo(session).list(msp_id):
                print(f"  worker {worker.id} name '{worker.name}' version {worker.version} revoked_at {stamp(worker.revoked_at)}")
            print("audit_log:")
            for row in await AuditRepo(session).list(msp_id):
                print(f"  {stamp(row.at)} {row.action} {row.target}")
    finally:
        await engine.dispose()


def main(argv: list[str]) -> None:
    command = argv[0]
    if command == "key":
        der = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"public_key {base64.b64encode(der).decode('ascii')}")
    elif command == "show":
        asyncio.run(show(uuid.UUID(argv[1])))
    else:
        raise SystemExit(f"unknown command {command}")


if __name__ == "__main__":
    main(sys.argv[1:])
