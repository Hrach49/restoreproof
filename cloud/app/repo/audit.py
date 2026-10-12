"""The audit log of an MSP: append-only, so no update and no delete. `page`
is the `/audit` page's read (C6.3; docs/decisions.md 2026-10-12, "C6.1, C6.2
and C6.3", points 16 and 24): newest first by `(at, id)`, from `since`, the
rows before the one `before` names (keyset), each with its user's address
when a user wrote it (the join on `(msp_id, user_id)`). One statement."""

from __future__ import annotations

import datetime as dt
from typing import NamedTuple
from uuid import UUID

from sqlalchemy import and_, select, true, tuple_

from app.models import AuditLog, User
from app.repo.base import Repo

PAGE_SIZE = 100


class AuditRow(NamedTuple):
    row: AuditLog
    email: str | None


class AuditRepo(Repo):
    async def write(
        self, msp_id: UUID, action: str, target: str, *, user_id: UUID | None = None, ip: str | None = None
    ) -> AuditLog:
        return await self._add(AuditLog(msp_id=msp_id, action=action, target=target, user_id=user_id, ip=ip))

    async def list(self, msp_id: UUID) -> list[AuditLog]:
        return await self._all(
            select(AuditLog).where(AuditLog.msp_id == msp_id).order_by(AuditLog.at, AuditLog.id)
        )

    async def page(self, msp_id: UUID, *, since: dt.datetime, before: UUID | None = None, limit: int = PAGE_SIZE) -> list[AuditRow]:
        if since.utcoffset() is None:
            raise ValueError("a time without a zone: give an aware UTC datetime")
        if not 1 <= limit <= PAGE_SIZE:
            raise ValueError(f"limit must be 1 to {PAGE_SIZE}")
        statement = (
            select(AuditLog, User.email)
            .outerjoin(User, and_(User.msp_id == AuditLog.msp_id, User.id == AuditLog.user_id))
            .where(AuditLog.msp_id == msp_id, AuditLog.at >= since)
        )
        if before is not None:
            anchor = (
                select(AuditLog.at.label("at"), AuditLog.id.label("id"))
                .where(AuditLog.msp_id == msp_id, AuditLog.id == before)
                .subquery("anchor")
            )
            statement = statement.join(anchor, true()).where(tuple_(AuditLog.at, AuditLog.id) < tuple_(anchor.c.at, anchor.c.id))
        rows = await self._rows(statement.order_by(AuditLog.at.desc(), AuditLog.id.desc()).limit(limit))
        return [AuditRow(row, email) for row, email in rows]
