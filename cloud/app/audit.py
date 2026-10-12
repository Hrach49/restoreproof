"""The audit helper of the pages (C6.3; docs/decisions.md 2026-10-12, "C6.1,
C6.2 and C6.3", point 23): one place for the caller's address and one list of
the words a page writes. `record` writes `AuditRepo.write` in the route's own
transaction with the user it is given (the session's, or at a login the one
the address found) and `client_ip(request)`, the one reading of
`request.client.host` for every row a page writes (C5.12 edits it for a
proxy's header; the Worker's routes keep their own). A function, not a
middleware: it needs the session, the user and what the route decided.

`ACTIONS` is closed: `report.download` is C6.6's word and `settings.change`
C7.3's, added there. The CLI's words are app/onboarding.py's, the Worker's
the routes' own.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.repo.audit import AuditRepo

LOGIN_SUCCESS = "login.success"
LOGIN_FAILURE = "login.failure"
LOGIN_BLOCKED = "login.blocked"
LOGOUT = "logout"
BUNDLE_DOWNLOAD = "bundle.download"
WORKER_REVOKE = "worker.revoke"

ACTIONS = (LOGIN_SUCCESS, LOGIN_FAILURE, LOGIN_BLOCKED, LOGOUT, BUNDLE_DOWNLOAD, WORKER_REVOKE)


def client_ip(request: Request) -> str | None:
    """The caller's address as the server saw it; None when it has none."""
    return request.client.host if request.client is not None else None


async def record(session: AsyncSession, request: Request, msp_id: UUID, action: str, target: str, *, user_id: UUID | None) -> None:
    if action not in ACTIONS:
        raise ValueError("not an action a page writes")
    await AuditRepo(session).write(msp_id, action, target, user_id=user_id, ip=client_ip(request))
