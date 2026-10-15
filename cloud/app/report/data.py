"""What a month's report says (C6.4; docs/decisions.md 2026-10-12, "C6.4",
points 4, 5 and 9): the period (one UTC calendar month), which runs are its
(`app/repo/runs.py`'s `period_filter`: a tested run by the time it ended, an
expired run by its creation as one that did not run, a queued or dispatched
one by its creation as one with no result yet; a result the Cloud received
after its month had closed by the month it arrived in, counted on a line of
its own), the eight repo reads with `msp_id` first, and the arithmetic every section prints. `gather`
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
from app.report.frameworks import ABOUT, CONTROLS, NO_PASS, Control

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

# The result word per state: the three verdicts as the pages print them, an
# expired run as what it is (point 4), and a run still queued or handed out
# as one with no result when the report is made (the review's finding 2).
DID_NOT_RUN = "did not run"
NO_RESULT = "no result yet"
RESULT_WORDS = {
    "pass": "pass", "fail": "fail", "error": "error", "expired": DID_NOT_RUN, "queued": NO_RESULT, "dispatched": NO_RESULT,
}
# The runs whose restore ran: the ones a recovery time and a restore point
# are read from (an error is a test that could not run; the review's finding 5).
RAN_STATES = ("pass", "fail")
# C6.8 (docs/decisions.md 2026-10-15, points 1 to 4): the expected kinds as
# the Worker names them (`shared/schemas/result.v1.json`): a canary is
# `manifest` and only a canary; a random mail `fields`; a random file the
# backup gave no copy of `metadata`; one it gave a copy of `backup_content`.
CANARY = "manifest"
FIELDS = "fields"
METADATA = "metadata"
BACKUP_CONTENT = "backup_content"
# Compared by the SHA-256 of its content: what level 3 is claimed for.
CONTENT_KINDS = (CANARY, BACKUP_CONTENT)
# The client's own items, sampled at random: every kind but a canary's.
OWN_KINDS = (FIELDS, METADATA, BACKUP_CONTENT)
FILE_TYPES = ("sharepoint", "onedrive")
# C6.6 (docs/decisions.md 2026-10-13, point 3, and its build notes): the Test
# log, the Failures and the Integrity run list show the first this many runs
# of the month, in the month's order, and say how many more there were; the
# Summary's numbers count every run. A run is one log row and three to four
# lines of the Integrity table: 200 runs are about 23 pages, which the image
# renders twice in about 45 s on the dev laptop's Docker (500 took 112 s,
# past the Done-when's minute), so the entry's 500 became 200 in the build.
MAX_LOG_ROWS = 200
# The C6.6 review's findings 1 and 2: a month has no final report until this
# long after its last day, whoever asks (the job's hour on the 1st, the job's
# run at start, the CLI). `app/repo/runs.py`'s `RESULTS_CLOSE` is shorter, so
# every result that is the month's by that rule is committed before the
# month is read for its one final report.
FINAL_AFTER = dt.timedelta(hours=3)
NOT_CLOSED = f"not closed until {int(FINAL_AFTER.total_seconds() // 3600):02d}:00 UTC on the 1st"


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
    """The month `YYYY-MM` names, or `period: not YYYY-MM` (never the text);
    the year 0000 is no year of the calendar."""
    found = _PERIOD.match(text)
    if found is None or not 1 <= int(found.group(2)) <= 12 or int(found.group(1)) < dt.MINYEAR:
        raise RepoError("period", PERIOD_RULE)
    return month_of(dt.date(int(found.group(1)), int(found.group(2)), 1))


def previous_month(today: dt.date) -> Period:
    """The month before `today`'s: the CLI's default period."""
    return month_of(dt.date(today.year, today.month, 1) - dt.timedelta(days=1))


def closed_month(now: dt.datetime) -> Period:
    """The newest month that may have its final report at `now`: the job's
    period (before `FINAL_AFTER` on the 1st, the month before the last)."""
    return previous_month((now.astimezone(UTC) - FINAL_AFTER).date())


def closed(period: Period, now: dt.datetime) -> bool:
    """Whether the period's final report may be made at `now`."""
    return now >= period.end_at + FINAL_AFTER


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
    plan_id: UUID
    cleanup_ok: bool | None
    error_code: str | None
    error_message: str | None

    @property
    def short_id(self) -> str:
        return str(self.run_id)[:8]

    @property
    def tested(self) -> bool:
        return self.state in TESTED_STATES

    @property
    def ran(self) -> bool:
        return self.state in RAN_STATES

    @property
    def items(self) -> int:
        return self.mail + self.sp + self.od


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
    runs_left_out: int
    tests: int
    passed: int
    failed: int
    errored: int
    did_not_run: int
    no_result: int
    overall: str
    overall_class: str
    errors_line: str | None
    average_recovery_ms: int | None
    max_recovery_ms: int | None
    restore_points: list[dt.datetime]
    failures: list[Failure]
    failures_left_out: int
    plans: list[PlanSizes]
    ran: int
    # C6.8, over the tests that passed or failed: how many sampled a canary
    # and how many the client's own items, the client's own files tested and
    # how many of them were compared by content, which kinds were sampled,
    # and whether anything (and a file) was compared by the SHA-256 of its
    # content. Compared means found with `match` known: a missing item or
    # one nobody checked was not (the C6.8 code review's finding 1).
    canary_tests: int
    own_tests: int
    own_files: int
    content_files: int
    kinds: frozenset[str]
    content_compared: bool
    file_content_compared: bool
    late: int
    cleanup_incomplete: int
    workers: list[WorkerLine]
    controls: tuple[Control, ...]
    about: str
    no_pass: str


def found_word(item: TestItem) -> str:
    """What the Failures section says of an item that did not match. `match`
    decides first: an item the Worker could not check (its target unreadable)
    is stored as not found with `match` unknown, and that is "not checked",
    never "missing" (the review's finding 1)."""
    if item.match is not False:
        return "not checked"
    return "missing" if item.found is False else "mismatch"


def run_date(run: TestRun) -> dt.datetime:
    """When a run ended (a run that never did: when it was made), the date
    the report prints and the month's order: `app/repo/runs.py`'s `_run_time`
    on a row. A tested run of the month whose date is before the month is one
    whose result arrived after that month had closed (`period_time`)."""
    if run.state in TESTED_STATES:
        return run.finished_at or run.tsa_time or run.dispatched_at or run.created_at
    return run.created_at


def overall_class(tests: int, failed: int, errored: int) -> str:
    """The headline's colour: a month with no test is no pass (finding 8)."""
    if failed:
        return "fail"
    if errored:
        return "error"
    return "pass" if tests else "quiet"


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
    by_type: dict[tuple[UUID, str], int] = {}
    for c in counts:
        by_type[(c.run_id, c.type)] = by_type.get((c.run_id, c.type), 0) + c.count
    lines = [
        RunLine(
            run_id=run.id,
            state=run.state,
            result=RESULT_WORDS[run.state],
            date=run_date(run),
            restore_point_at=run.restore_point_at,
            mail=by_type.get((run.id, "mail"), 0),
            sp=by_type.get((run.id, "sharepoint"), 0),
            od=by_type.get((run.id, "onedrive"), 0),
            recovery_ms=run.recovery_ms,
            bundle_sha256=run.bundle_sha256,
            tsa_ok=run.tsa_ok,
            tsa_time=run.tsa_time,
            worker_id=run.worker_id,
            plan_id=run.plan_id,
            cleanup_ok=run.cleanup_ok,
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
    ran = [line for line in tested if line.ran]
    recoveries = [line.recovery_ms for line in ran if line.recovery_ms is not None]
    unmatched_of: dict[UUID, list[FailedItem]] = {}
    for item in unmatched:
        unmatched_of.setdefault(item.run_id, []).append(FailedItem(item.type, item.name, found_word(item), item.reason))
    # Newest first, so each plan's nearest later pass is known when its
    # failure is met: a pass of another plan sampled other things and is no
    # later test of this one (the review's finding 7).
    later_pass: dict[UUID, dt.datetime] = {}
    failures = []
    for line in reversed(lines):
        if line.state == "pass":
            later_pass[line.plan_id] = line.date
        elif line.state in ("fail", "error"):
            failures.append(Failure(line, unmatched_of.get(line.run_id, []), later_pass.get(line.plan_id)))
    failures.reverse()
    tested_plans = {line.plan_id for line in tested}
    # C6.8, point 1: what the tests that passed or failed compared; an error
    # is a test that could not run, and its items may never have been.
    ran_ids = {line.run_id for line in ran}
    ran_counts = [c for c in counts if c.run_id in ran_ids]
    own = [c for c in ran_counts if c.type in FILE_TYPES and c.expected_kind in (METADATA, BACKUP_CONTENT)]
    content = [c for c in ran_counts if c.expected_kind in CONTENT_KINDS and c.compared]
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
        runs=lines[:MAX_LOG_ROWS],
        runs_left_out=max(0, len(lines) - MAX_LOG_ROWS),
        tests=len(tested),
        passed=passed,
        failed=failed,
        errored=errored,
        did_not_run=sum(1 for line in lines if line.result == DID_NOT_RUN),
        no_result=sum(1 for line in lines if line.result == NO_RESULT),
        overall=overall,
        overall_class=overall_class(len(tested), failed, errored),
        errors_line=errors,
        average_recovery_ms=sum(recoveries) // len(recoveries) if recoveries else None,
        max_recovery_ms=max(recoveries) if recoveries else None,
        restore_points=sorted({line.restore_point_at for line in ran if line.restore_point_at is not None}),
        failures=failures[:MAX_LOG_ROWS],
        failures_left_out=max(0, len(failures) - MAX_LOG_ROWS),
        plans=[PlanSizes(plan.sample_mail, plan.sample_sp, plan.sample_od) for plan in plans if plan.id in tested_plans],
        ran=len(ran),
        canary_tests=len({c.run_id for c in ran_counts if c.expected_kind == CANARY}),
        own_tests=len({c.run_id for c in ran_counts if c.expected_kind in OWN_KINDS}),
        own_files=sum(c.count for c in own),
        content_files=sum(c.compared for c in own if c.expected_kind == BACKUP_CONTENT),
        kinds=frozenset(c.expected_kind for c in ran_counts),
        content_compared=bool(content),
        file_content_compared=any(c.type in FILE_TYPES for c in content),
        late=sum(1 for line in tested if line.date < period.start_at),
        cleanup_incomplete=sum(1 for line in tested if line.cleanup_ok is False),
        workers=[WorkerLine(w.id, w.name, w.key_id) for w in workers if w.id in run_workers],
        controls=CONTROLS,
        about=ABOUT,
        no_pass=NO_PASS,
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
