"""What a month's report says (C6.4; docs/decisions.md 2026-10-12, "C6.4",
points 4, 5 and 9): the period (one UTC calendar month), which runs are its
(`app/repo/runs.py`'s `period_filter`: a tested run by the time it ended, an
expired run by its creation, queued and dispatched never), the eight repo
reads with `msp_id` first, and the arithmetic every section prints. `gather`
reads; `build` decides, pure, from rows. Nothing here renders or writes.
"""

from __future__ import annotations

import calendar
import datetime as dt
import re
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Client, Connector, Msp, TestItem, TestPlan, TestRun, Worker
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.errors import RepoError
from app.repo.items import ItemRepo, TypeCount
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import TESTED_STATES, RunRepo
from app.repo.workers import WorkerRepo
from app.report.frameworks import CONTROLS, PENDING, Control

UTC = dt.timezone.utc
PERIOD_RULE = "not YYYY-MM"
NOT_BEGUN = "has not begun"
NO_RUN = "no run in the period"
NO_SUCH_CLIENT = "no such client"
NO_SUCH_MSP = "no such MSP"
_PERIOD = re.compile(r"^(\d{4})-(\d{2})$")

# The connector types the Cloud knows, worded for the Summary's "backup source".
BACKUP_SOURCES = {"veeam_m365": "Veeam Backup for Microsoft 365"}
UNKNOWN_SOURCE = "not recorded"

# The result word per state: the three verdicts as the pages print them, and
# an expired run as what it is (point 4).
RESULT_WORDS = {"pass": "pass", "fail": "fail", "error": "error", "expired": "did not run"}
DID_NOT_RUN = "did not run"


@dataclass(frozen=True)
class Period:
    """One UTC calendar month: its first and last day (inclusive dates), its
    name `YYYY-MM`, and the span `[start_at, end_at)` the reads take."""

    start: dt.date
    end: dt.date

    @property
    def name(self) -> str:
        return self.start.strftime("%Y-%m")

    @property
    def title(self) -> str:
        return self.start.strftime("%B %Y")

    @property
    def start_at(self) -> dt.datetime:
        return dt.datetime(self.start.year, self.start.month, 1, tzinfo=UTC)

    @property
    def end_at(self) -> dt.datetime:
        return dt.datetime(self.end.year, self.end.month, self.end.day, tzinfo=UTC) + dt.timedelta(days=1)


def month_of(day: dt.date) -> Period:
    last = calendar.monthrange(day.year, day.month)[1]
    return Period(dt.date(day.year, day.month, 1), dt.date(day.year, day.month, last))


def period_of(text: str) -> Period:
    """The month `YYYY-MM` names, or `period: not YYYY-MM` (never the text)."""
    found = _PERIOD.match(text)
    if found is None or not 1 <= int(found.group(2)) <= 12:
        raise RepoError("period", PERIOD_RULE)
    return month_of(dt.date(int(found.group(1)), int(found.group(2)), 1))


def previous_month(today: dt.date) -> Period:
    """The month before `today`'s: the CLI's default period."""
    return month_of(dt.date(today.year, today.month, 1) - dt.timedelta(days=1))


def interim_for(period: Period, now: dt.datetime) -> bool:
    """A report is interim while its period is not over: its last day is not
    before the generation day (UTC)."""
    return period.end >= now.astimezone(UTC).date()


@dataclass(frozen=True)
class RunLine:
    """One row of the Test log, and what the other sections read of a run."""

    run_id: UUID
    state: str
    result: str
    date: dt.datetime
    restore_point_at: dt.datetime | None
    mail: int
    sp: int
    od: int
    recovery_ms: int | None
    bundle_sha256: str | None
    tsa_ok: bool | None
    tsa_time: dt.datetime | None
    worker_id: UUID
    error_code: str | None
    error_message: str | None

    @property
    def short_id(self) -> str:
        return str(self.run_id)[:8]

    @property
    def tested(self) -> bool:
        return self.state in TESTED_STATES


@dataclass(frozen=True)
class FailedItem:
    type: str
    name: str
    found_word: str
    reason: str | None


@dataclass(frozen=True)
class Failure:
    line: RunLine
    items: list[FailedItem]
    retested_at: dt.datetime | None


@dataclass(frozen=True)
class WorkerLine:
    id: UUID
    name: str
    key_id: str


@dataclass(frozen=True)
class PlanSizes:
    mail: int
    sp: int
    od: int


@dataclass(frozen=True)
class ReportData:
    msp_name: str
    client_name: str
    period: Period
    interim: bool
    generated_at: dt.datetime
    backup_source: str
    runs: list[RunLine]
    tests: int
    passed: int
    failed: int
    errored: int
    did_not_run: int
    overall: str
    errors_line: str | None
    average_recovery_ms: int | None
    max_recovery_ms: int | None
    restore_points: list[dt.datetime]
    failures: list[Failure]
    plans: list[PlanSizes]
    workers: list[WorkerLine]
    controls: tuple[Control, ...]
    pending: str


def found_word(item: TestItem) -> str:
    """What the Failures section says of an item that did not match."""
    if item.found is False:
        return "missing"
    if item.found is True and item.match is False:
        return "mismatch"
    return "not checked"


def _tests_word(count: int) -> str:
    return "test" if count == 1 else "tests"


def overall_line(tests: int, passed: int, failed: int, errored: int) -> tuple[str, str | None]:
    """The Summary's one line, and the error line kept apart from it (point
    9: an error is never counted as a failure)."""
    errors = f"{errored} of {tests} {_tests_word(tests)} could not run (error)" if errored else None
    if tests == 0:
        return "No test ran in this period", errors
    if failed:
        return f"{failed} of {tests} {_tests_word(tests)} failed", errors
    if errored:
        return f"{passed} of {tests} {_tests_word(tests)} passed", errors
    return (f"All {tests} tests passed" if tests > 1 else "The 1 test passed"), errors


def build(
    msp: Msp,
    client: Client,
    period: Period,
    *,
    now: dt.datetime,
    connectors: list[Connector],
    plans: list[TestPlan],
    workers: list[Worker],
    runs: list[TestRun],
    counts: list[TypeCount],
    unmatched: list[TestItem],
) -> ReportData:
    """The report's data from the rows, pure."""
    by_type: dict[tuple[UUID, str], int] = {(c.run_id, c.type): c.count for c in counts}
    lines = [
        RunLine(
            run_id=run.id,
            state=run.state,
            result=RESULT_WORDS[run.state],
            date=run.finished_at or run.created_at,
            restore_point_at=run.restore_point_at,
            mail=by_type.get((run.id, "mail"), 0),
            sp=by_type.get((run.id, "sharepoint"), 0),
            od=by_type.get((run.id, "onedrive"), 0),
            recovery_ms=run.recovery_ms,
            bundle_sha256=run.bundle_sha256,
            tsa_ok=run.tsa_ok,
            tsa_time=run.tsa_time,
            worker_id=run.worker_id,
            error_code=run.error_code,
            error_message=run.error_message,
        )
        for run in runs
    ]
    tested = [line for line in lines if line.tested]
    passed = sum(1 for line in tested if line.state == "pass")
    failed = sum(1 for line in tested if line.state == "fail")
    errored = sum(1 for line in tested if line.state == "error")
    overall, errors = overall_line(len(tested), passed, failed, errored)
    recoveries = [line.recovery_ms for line in tested if line.recovery_ms is not None]
    failures = []
    for index, line in enumerate(lines):
        if line.state not in ("fail", "error"):
            continue
        items = [FailedItem(item.type, item.name, found_word(item), item.reason) for item in unmatched if item.run_id == line.run_id]
        retested = next((later.date for later in lines[index + 1 :] if later.state == "pass"), None)
        failures.append(Failure(line, items, retested))
    sources = []
    for connector in connectors:
        word = BACKUP_SOURCES.get(connector.type, UNKNOWN_SOURCE)
        if word not in sources:
            sources.append(word)
    run_workers = {line.worker_id for line in lines}
    return ReportData(
        msp_name=msp.name,
        client_name=client.name,
        period=period,
        interim=interim_for(period, now),
        generated_at=now,
        backup_source=", ".join(sources) if sources else UNKNOWN_SOURCE,
        runs=lines,
        tests=len(tested),
        passed=passed,
        failed=failed,
        errored=errored,
        did_not_run=sum(1 for line in lines if not line.tested),
        overall=overall,
        errors_line=errors,
        average_recovery_ms=sum(recoveries) // len(recoveries) if recoveries else None,
        max_recovery_ms=max(recoveries) if recoveries else None,
        restore_points=sorted({line.restore_point_at for line in tested if line.restore_point_at is not None}),
        failures=failures,
        plans=[PlanSizes(plan.sample_mail, plan.sample_sp, plan.sample_od) for plan in plans],
        workers=[WorkerLine(w.id, w.name, w.key_id) for w in workers if w.id in run_workers],
        controls=CONTROLS,
        pending=PENDING,
    )


async def gather(session: AsyncSession, msp_id: UUID, client_id: UUID, period: Period, *, now: dt.datetime) -> ReportData:
    """The month's data: eight reads, each with `msp_id` first, a fixed count
    whatever the rows (point 5); a refusal is a `RepoError` naming the key."""
    if period.start > now.astimezone(UTC).date():
        raise RepoError("period", NOT_BEGUN)
    msp = await MspRepo(session).get(msp_id)
    if msp is None:
        raise RepoError("msp_id", NO_SUCH_MSP)
    client = await ClientRepo(session).get(msp_id, client_id)
    if client is None:
        raise RepoError("client_id", NO_SUCH_CLIENT)
    connectors = await ConnectorRepo(session).list(msp_id, client_id=client_id)
    plans = await PlanRepo(session).list(msp_id, client_id=client_id)
    workers = await WorkerRepo(session).list(msp_id)
    runs = await RunRepo(session).period(msp_id, client_id, start=period.start_at, end=period.end_at)
    if not runs:
        raise RepoError("period", NO_RUN)
    counts = await ItemRepo(session).counts_by_type_in_period(msp_id, client_id, start=period.start_at, end=period.end_at)
    unmatched = await ItemRepo(session).unmatched_in_period(msp_id, client_id, start=period.start_at, end=period.end_at)
    return build(
        msp, client, period, now=now, connectors=connectors, plans=plans, workers=workers, runs=runs, counts=counts, unmatched=unmatched
    )
