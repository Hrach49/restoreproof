"""The monthly reports of an MSP's clients (C6.4 writes them)."""

from __future__ import annotations

import datetime as dt
from uuid import UUID

from sqlalchemy import select

from app.models import Report
from app.repo.base import Repo


class ReportRepo(Repo):
    async def create(
        self,
        msp_id: UUID,
        client_id: UUID,
        *,
        period_start: dt.date,
        period_end: dt.date,
        storage_key: str,
        sha256: str,
    ) -> Report:
        return await self._add(
            Report(
                msp_id=msp_id,
                client_id=client_id,
                period_start=period_start,
                period_end=period_end,
                storage_key=storage_key,
                sha256=sha256,
            )
        )

    async def get(self, msp_id: UUID, report_id: UUID) -> Report | None:
        return await self._one(select(Report).where(Report.msp_id == msp_id, Report.id == report_id))

    async def list(self, msp_id: UUID, *, client_id: UUID | None = None) -> list[Report]:
        statement = select(Report).where(Report.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(Report.client_id == client_id)
        return await self._all(statement.order_by(Report.period_start.desc(), Report.id))
