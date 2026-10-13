"""The monthly reports of an MSP's clients (C6.4 writes them; docs/decisions.md
2026-10-12, "C6.4", point 1): one row per generated PDF with its two hashes
(the content hash of the report rendered without it, the file hash of the
file), whether it is interim, its period as two dates and its key in the
bucket. The database holds one final report per client and period
(`uq_report_final_period`) and a key once (`uq_report_storage_key`); the
generator lets those refusals through as `constraint_refusal` words them."""

from __future__ import annotations

import datetime as dt
from typing import NamedTuple
from uuid import UUID

from sqlalchemy import and_, select, true, tuple_

from app.models import Client, Report
from app.repo.base import Repo

# C6.6: the reports pages' page, the history's size.
PAGE_SIZE = 50


class ReportRow(NamedTuple):
    """A report with its client's name (C6.6's `/reports`)."""

    report: Report
    client_name: str


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

    async def page(self, msp_id: UUID, *, client_id: UUID | None = None, before: UUID | None = None, limit: int = PAGE_SIZE) -> list[ReportRow]:
        """The MSP's reports (or one client's) newest period first, then
        newest generation, each with its client's name, at most `limit`: the
        rows before the report `before` names (keyset on `(period_start,
        generated_at, id)`; another MSP's report is no anchor and gives an
        empty page), or the newest when it is None (C6.6, docs/decisions.md
        2026-10-13, point 2). `limit` may be one more than a page: the row a
        caller asks for to know whether another page follows (the review's
        finding 11). One statement, joined on the key that starts with
        msp_id."""
        if not 1 <= limit <= PAGE_SIZE + 1:
            raise ValueError(f"limit must be 1 to {PAGE_SIZE + 1}")
        statement = (
            select(Report, Client.name)
            .join(Client, and_(Client.msp_id == Report.msp_id, Client.id == Report.client_id))
            .where(Report.msp_id == msp_id)
        )
        if client_id is not None:
            statement = statement.where(Report.client_id == client_id)
        if before is not None:
            anchor = (
                select(Report.period_start.label("period_start"), Report.generated_at.label("generated_at"), Report.id.label("id"))
                .where(Report.msp_id == msp_id, Report.id == before)
                .subquery("anchor")
            )
            statement = statement.join(anchor, true()).where(
                tuple_(Report.period_start, Report.generated_at, Report.id)
                < tuple_(anchor.c.period_start, anchor.c.generated_at, anchor.c.id)
            )
        rows = await self._rows(
            statement.order_by(Report.period_start.desc(), Report.generated_at.desc(), Report.id.desc()).limit(limit)
        )
        return [ReportRow(report, name) for report, name in rows]

    async def list(self, msp_id: UUID, *, client_id: UUID | None = None) -> list[Report]:
        statement = select(Report).where(Report.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(Report.client_id == client_id)
        return await self._all(statement.order_by(Report.period_start.desc(), Report.generated_at.desc(), Report.id))
