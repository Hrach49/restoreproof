"""C5.7's live Done-when, the Cloud's rows (docs/decisions.md 2026-10-10, C5.7,
point 17; docs/testing.md "The upload"): what C5.10's manage.py will do, done
here through the repos against the Compose stack's own database. Run from
cloud/ with uv:

    uv run python ../docs/api/cloud-lab/c5.7-harness/c57-rows.py init <tenant_id>
        one MSP, one client of that tenant, one install token (printed once)
    uv run python ../docs/api/cloud-lab/c5.7-harness/c57-rows.py run <msp_id> <client_id> <worker_id> <profile.json>
        the connector on the lab's profile, a plan (10, 10, 10), one queued run
    uv run python ../docs/api/cloud-lab/c5.7-harness/c57-rows.py show <msp_id> <run_id>
        the run's row, its items and the MSP's audit rows, for the evidence

The database is the stack's (DATABASE_URL as docker-compose.yml gives it,
reached on 127.0.0.1:55432); every value in it is local only.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import sys
import uuid
from pathlib import Path

# docs/api/cloud-lab/c5.7-harness -> the repository root, then cloud/ for the app.
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "cloud"))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from app.auth.tokens import issue_install_token  # noqa: E402
from app.db import make_session_factory  # noqa: E402
from app.repo.audit import AuditRepo  # noqa: E402
from app.repo.clients import ClientRepo  # noqa: E402
from app.repo.connectors import ConnectorRepo  # noqa: E402
from app.repo.items import ItemRepo  # noqa: E402
from app.repo.msps import MspRepo  # noqa: E402
from app.repo.plans import PlanRepo  # noqa: E402
from app.repo.runs import RunRepo  # noqa: E402

STACK = "postgresql+asyncpg://restoreproof:local-only-postgres@127.0.0.1:55432/restoreproof"


async def main(argv: list[str]) -> None:
    engine = create_async_engine(STACK, connect_args={"server_settings": {"timezone": "UTC"}})
    try:
        async with make_session_factory(engine)() as session:
            async with session.begin():
                command = argv[0]
                if command == "init":
                    msp = await MspRepo(session).create(name="c5.7 done-when")
                    client = await ClientRepo(session).create(msp.id, name="RestoreProofLab", tenant_id=uuid.UUID(argv[1]))
                    token, row = await issue_install_token(
                        session, msp.id, dt.datetime.now(dt.timezone.utc), label="c5.7 done-when"
                    )
                    print(f"msp_id {msp.id}\nclient_id {client.id}\ninstall_token_id {row.id}\ninstall_token {token}")
                elif command == "run":
                    msp_id, client_id, worker_id = (uuid.UUID(value) for value in argv[1:4])
                    profile = json.loads(Path(argv[4]).read_text(encoding="utf-8"))
                    connector = await ConnectorRepo(session).create(msp_id, client_id, worker_id, profile)
                    plan = await PlanRepo(session).create(
                        msp_id, client_id, connector.id, sample_mail=10, sample_sp=10, sample_od=10, cadence_cron="0 2 * * *",
                        now=dt.datetime.now(dt.timezone.utc),  # C5.9: the plan's created_at
                    )
                    run = await RunRepo(session).create(
                        msp_id, plan_id=plan.id, client_id=client_id, connector_id=connector.id, worker_id=worker_id
                    )
                    print(f"connector_id {connector.id}\nplan_id {plan.id}\nrun_id {run.id}")
                elif command == "show":
                    msp_id, run_id = uuid.UUID(argv[1]), uuid.UUID(argv[2])
                    run = await RunRepo(session).get(msp_id, run_id)
                    columns = (
                        "state", "error_code", "error_message", "attempt", "dispatched_at", "started_at", "finished_at",
                        "total_ms", "restore_point_at", "bundle_key", "bundle_sha256", "signature_ok", "tsa_ok", "tsa_time",
                        "cleanup_ok",
                    )
                    print("test_run:")
                    for column in columns:
                        print(f"  {column}: {getattr(run, column)}")
                    items = await ItemRepo(session).list(msp_id, run_id)
                    print(f"test_item: {len(items)} row(s)")
                    for item in items:
                        print(
                            f"  {item.position:2} {item.type:10} {item.expected_kind:8} found {item.found} match {item.match}"
                            f" ms {item.ms} expected_sha256 {(item.expected_sha256 or '-')[:12]} reason {item.reason}"
                        )
                    print("audit_log:")
                    for row in await AuditRepo(session).list(msp_id):
                        print(f"  {row.action} {row.target}")
                else:
                    raise SystemExit(f"unknown command {command}")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
