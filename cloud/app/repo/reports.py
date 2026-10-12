"""The monthly reports of an MSP's clients (C6.4 writes them; docs/decisions.md
2026-10-12, "C6.4", point 1): one row per generated PDF with its two hashes
(the content hash of the report rendered without it, the file hash of the
file), whether it is interim, its period as two dates and its key in the
bucket. The database holds one final report per client and period
(`uq_report_final_period`) and a key once (`uq_report_storage_key`); the
generator lets those refusals through as `constraint_refusal` words them."""

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
        content_sha256: str,
        file_sha256: str,
        interim: bool,
        generated_at: dt.datetime,
    ) -> Report:
        if generated_at.utcoffset() is None:
            raise ValueError("a time without a zone: give an aware UTC datetime")
        return await self._add(
            Report(
                msp_id=msp_id,
                client_id=client_id,
                period_start=period_start,
                period_end=period_end,
                storage_key=storage_key,
                content_sha256=content_sha256,
                file_sha256=file_sha256,
                interim=interim,
                generated_at=generated_at,
            )
        )

    async def get(self, msp_id: UUID, report_id: UUID) -> Report | None:
        return await self._one(select(Report).where(Report.msp_id == msp_id, Report.id == report_id))

    async def final(self, msp_id: UUID, client_id: UUID, period_start: dt.date) -> Report | None:
        """The client's final report of the period that begins `period_start`,
        if there is one (the generator asks before it renders; the index is
        the second line)."""
        return await self._one(
            select(Report).where(
                Report.msp_id == msp_id,
                Report.client_id == client_id,
                Report.period_start == period_start,
                Report.interim.is_(False),
            )
        )

    async def list(self, msp_id: UUID, *, client_id: UUID | None = None) -> list[Report]:
        statement = select(Report).where(Report.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(Report.client_id == client_id)
        return await self._all(statement.order_by(Report.period_start.desc(), Report.generated_at.desc(), Report.id))
