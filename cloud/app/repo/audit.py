"""The audit log of an MSP: append-only, so no update and no delete."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from app.models import AuditLog
from app.repo.base import Repo


class AuditRepo(Repo):
    async def write(
        self, msp_id: UUID, action: str, target: str, *, user_id: UUID | None = None, ip: str | None = None
    ) -> AuditLog:
        return await self._add(AuditLog(msp_id=msp_id, action=action, target=target, user_id=user_id, ip=ip))

    async def list(self, msp_id: UUID) -> list[AuditLog]:
        return await self._all(
            select(AuditLog).where(AuditLog.msp_id == msp_id).order_by(AuditLog.at, AuditLog.id)
        )
