"""C5.8's by-hand Done-when, the Cloud's rows (docs/decisions.md 2026-10-11, C5.8,
point 11; docs/testing.md "The heartbeat"): what C5.10's manage.py will do, done
here through the repos against the Compose stack's own database. Run from cloud/
with uv:

    uv run python ../docs/api/cloud-lab/c5.8-harness/c58-rows.py init
        one MSP, one install token (printed once)
    uv run python ../docs/api/cloud-lab/c5.8-harness/c58-rows.py show <msp_id>
        the MSP's Worker rows as C6.2's /workers page will read them
        (WorkerRepo.list), and the MSP's audit rows

The database is the stack's (DATABASE_URL as docker-compose.yml gives it,
reached on 127.0.0.1:55432); every value in it is local only.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import sys
import uuid
from pathlib import Path

# docs/api/cloud-lab/c5.8-harness -> the repository root, then cloud/ for the app.
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "cloud"))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from app.auth.tokens import issue_install_token  # noqa: E402
from app.db import make_session_factory  # noqa: E402
from app.repo.audit import AuditRepo  # noqa: E402
from app.repo.msps import MspRepo  # noqa: E402
from app.repo.workers import WorkerRepo  # noqa: E402

STACK = "postgresql+asyncpg://restoreproof:local-only-postgres@127.0.0.1:55432/restoreproof"
COLUMNS = ("name", "version", "last_seen_at", "last_error", "last_error_at", "outbox_depth", "uptime_s", "revoked_at")


async def main(argv: list[str]) -> None:
    engine = create_async_engine(STACK, connect_args={"server_settings": {"timezone": "UTC"}})
    try:
        async with make_session_factory(engine)() as session:
            async with session.begin():
                command = argv[0]
                if command == "init":
                    msp = await MspRepo(session).create(name="c5.8 done-when")
                    token, row = await issue_install_token(
                        session, msp.id, dt.datetime.now(dt.timezone.utc), label="c5.8 done-when"
                    )
                    print(f"msp_id {msp.id}\ninstall_token_id {row.id}\ninstall_token {token}")
                elif command == "show":
                    msp_id = uuid.UUID(argv[1])
                    print("worker (WorkerRepo.list, what /workers will read):")
                    for worker in await WorkerRepo(session).list(msp_id):
                        print("  " + ", ".join(f"{column} {getattr(worker, column)}" for column in COLUMNS))
                    print("audit_log:")
                    for row in await AuditRepo(session).list(msp_id):
                        print(f"  {row.at.isoformat()} {row.action} {row.target}")
                else:
                    raise SystemExit(f"unknown command {command}")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
