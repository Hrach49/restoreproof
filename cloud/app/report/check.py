"""The report checks (Q6.1; docs/decisions.md 2026-10-13, "Q6.1", points 1 to
5): what a test and `manage.py check-report` hold a stored report to. The
file: the object under the row's `storage_key`, read back whole, hashes to
`file_sha256`. The runs: every run the Summary counts (the month's rows as
`RunRepo.period` answers them, the report's own read, not the listed 200);
a tested run with `tsa_ok` true is *stamped* and its `timestamp.tst` is read
back from the bucket beside its `result.json` (whose SHA-256 is the row's
`bundle_sha256`), verified under the Cloud's TSA root with the verifier's own
words, its time the row's `tsa_time`, not before the second the test ended
and not more than `STAMP_BUDGET` after it; a tested run with no token is
*not stamped* and held to have none; an expired, queued or dispatched run
has *no bundle* and is only counted. A late result (received once the month
it ended in had closed, `is_late`, the arithmetic of `period_time` on a row)
is the period's by its arrival and counted. For a final report every result
was received before the report was generated; for an interim one that is
not held (`generated_at` is the clock read before the month is read).

`check_file` and `check_run` are pure and word one finding each;
`check_report` reads (two statements, then the bucket in a thread: the
report's object, and per run one list and at most two gets) and gathers.
A token that does not verify is refused at the upload, so a finding here
means the bucket or the row changed after the upload, the Cloud filed the
wrong object, or the Worker's clock disagrees with the TSA by more than the
Worker's own budget.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
from dataclasses import dataclass
from uuid import UUID

from botocore.exceptions import ClientError
from sqlalchemy.ext.asyncio import AsyncSession

from app import results as upload
from app.models import Report
from app.onboarding import Created
from app.repo.errors import RepoError
from app.repo.reports import ReportRepo
from app.repo.runs import RESULTS_CLOSE, TESTED_STATES, RunRepo
from app.report.data import Period, month_of, run_date
from app.storage import Storage

# The Worker's whole timestamp budget after a run's end: three attempts of
# ten seconds, a wait of thirty and one of sixty (worker/include/rp/
# timestamper.hpp: kTimestampAttempts, kTimestampTimeout,
# kTimestampFirstWait, kTimestampSecondWait; a test holds the sum). The steps
# between the end and the first request (the secret scan, the attachments'
# read-back, the signing) are milliseconds. No clock allowance beyond it.
STAMP_BUDGET = dt.timedelta(seconds=120)
RESULT_FILE = "result.json"
TIMESTAMP_FILE = "timestamp.tst"

NO_SUCH_REPORT = "no such report"
NO_OBJECT = "storage: no object"
FILE_DIFFERS = "file_sha256: differs"
BUNDLE_KEY_MISSING = "bundle_key: missing"
NO_BUNDLE_EXPECTED = "state: no bundle expected"
NOT_THE_RUNS = "period: not the run's"
RECEIVED_AFTER_REPORT = "received_after_report"
TSA_TIME_UNEXPECTED = "tsa_time: unexpected"
TOKEN_UNEXPECTED = f"storage: {TIMESTAMP_FILE} unexpected"
TSA_TIME_MISSING = "tsa_time: missing"
NO_RESULT_OBJECT = f"storage: no {RESULT_FILE}"
NO_TOKEN_OBJECT = f"storage: no {TIMESTAMP_FILE}"
BUNDLE_DIFFERS = "bundle_sha256: differs"
TSA_TIME_DIFFERS = "tsa_time: differs"
STAMP_BEFORE_END = "stamp_before_end"
STAMP_AFTER_BUDGET = "stamp_after_budget"


@dataclass(frozen=True)
class ReportCheck:
    """What `check_report` found: the counts, and the findings as `(run id
    or None for the file, word)` in the month's order, the file's first."""

    report_id: UUID
    final: bool
    file_ok: bool
    runs: int
    stamped: int
    not_stamped: int
    no_bundle: int
    late: int
    findings: tuple[tuple[UUID | None, str], ...]


def is_late(run) -> bool:
    """Whether a tested run's result arrived once the month it ended in had
    closed (`RESULTS_CLOSE` past that month's last day): then it is the
    month's it arrived in, `app/repo/runs.py`'s `period_time` on a row."""
    if run.state not in TESTED_STATES or run.received_at is None:
        return False
    return run.received_at >= month_of(run_date(run).date()).end_at + RESULTS_CLOSE


def check_file(report: Report, pdf: bytes | None) -> str | None:
    """The object under the row's key (None: not there) against `file_sha256`."""
    if pdf is None:
        return NO_OBJECT
    if hashlib.sha256(pdf).hexdigest() != report.file_sha256:
        return FILE_DIFFERS
    return None


def check_run(run, period: Period, *, names: list[str], objects: dict[str, bytes], tsa_ca: bytes, generated_at: dt.datetime, final: bool) -> str | None:
    """One run's finding, or None: `names` the files listed under its
    `bundle_key` and `objects` those read (`result.json` and `timestamp.tst`
    for a stamped run), both empty for a run with no bundle."""
    if run.state not in TESTED_STATES:
        if run.bundle_key is not None or run.tsa_ok is not None or run.tsa_time is not None:
            return NO_BUNDLE_EXPECTED
        return None
    if run.bundle_key is None:
        return BUNDLE_KEY_MISSING
    at = run.received_at if is_late(run) else run_date(run)
    if not period.start_at <= at < period.end_at:
        return NOT_THE_RUNS
    if final and run.received_at is not None and run.received_at >= generated_at:
        return RECEIVED_AFTER_REPORT
    if not run.tsa_ok:
        if run.tsa_time is not None:
            return TSA_TIME_UNEXPECTED
        if TIMESTAMP_FILE in names:
            return TOKEN_UNEXPECTED
        return None
    if run.tsa_time is None:
        return TSA_TIME_MISSING
    if RESULT_FILE not in names:
        return NO_RESULT_OBJECT
    if TIMESTAMP_FILE not in names:
        return NO_TOKEN_OBJECT
    digest = hashlib.sha256(objects[RESULT_FILE]).digest()
    if digest.hex() != run.bundle_sha256:
        return BUNDLE_DIFFERS
    vb = upload.verifier()
    word, time_text = vb.check_timestamp(objects[TIMESTAMP_FILE], digest, tsa_ca)
    if word != vb.VERIFIED:
        return word
    stamped = dt.datetime.strptime(time_text, upload.TIME_SECONDS).replace(tzinfo=dt.timezone.utc)
    if stamped != run.tsa_time:
        return TSA_TIME_DIFFERS
    if run.finished_at is not None:
        # The token's time is read in whole seconds; the end has milliseconds.
        if stamped < run.finished_at.replace(microsecond=0):
            return STAMP_BEFORE_END
        if stamped > run.finished_at + STAMP_BUDGET:
            return STAMP_AFTER_BUDGET
    return None


def _get(storage: Storage, key: str) -> bytes | None:
    try:
        return storage.get(key)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchKey":
            return None
        raise


async def check_report(session: AsyncSession, storage: Storage, msp_id: UUID, report_id: UUID, *, tsa_ca: bytes) -> ReportCheck:
    """The report's row and its month's runs (two statements, `msp_id`
    first), the objects read back, every finding worded; another MSP's
    report is `report_id: no such report` before anything is read."""
    report = await ReportRepo(session).get(msp_id, report_id)
    if report is None:
        raise RepoError("report_id", NO_SUCH_REPORT)
    period = Period(report.period_start, report.period_end)
    final = not report.interim
    findings: list[tuple[UUID | None, str]] = []
    pdf = await asyncio.to_thread(_get, storage, report.storage_key)
    file_word = check_file(report, pdf)
    if file_word is not None:
        findings.append((None, file_word))
    runs = await RunRepo(session).period(msp_id, report.client_id, start=period.start_at, end=period.end_at)
    stamped = not_stamped = no_bundle = late = 0
    for run in runs:
        names: list[str] = []
        objects: dict[str, bytes] = {}
        if run.state not in TESTED_STATES:
            no_bundle += 1
        else:
            late += is_late(run)
            if run.tsa_ok:
                stamped += 1
            else:
                not_stamped += 1
            if run.bundle_key is not None:
                names = await asyncio.to_thread(storage.list, run.bundle_key)
                for name in (RESULT_FILE, TIMESTAMP_FILE) if run.tsa_ok else ():
                    if name in names:
                        objects[name] = await asyncio.to_thread(storage.get, run.bundle_key + name)
        word = check_run(run, period, names=names, objects=objects, tsa_ca=tsa_ca, generated_at=report.generated_at, final=final)
        if word is not None:
            findings.append((run.id, word))
    return ReportCheck(
        report_id=report.id, final=final, file_ok=file_word is None, runs=len(runs), stamped=stamped, not_stamped=not_stamped,
        no_bundle=no_bundle, late=late, findings=tuple(findings),
    )


def created_of(found: ReportCheck) -> Created:
    """The CLI's lines for a check: the counts on stdout, one `<run id>:
    <word>` note per finding (`file: <word>` for the file) on stderr."""
    lines = (
        ("report_id", str(found.report_id)),
        ("final", "true" if found.final else "false"),
        ("file_sha256", "ok" if found.file_ok else "failed"),
        ("runs", str(found.runs)),
        ("stamped", str(found.stamped)),
        ("not_stamped", str(found.not_stamped)),
        ("no_bundle", str(found.no_bundle)),
        ("late", str(found.late)),
        ("findings", str(len(found.findings))),
    )
    notes = tuple(f"{'file' if run_id is None else run_id}: {word}" for run_id, word in found.findings)
    return Created(lines, notes)
