"""Q6.1 (docs/decisions.md 2026-10-13, "Q6.1"), the two Done-when tests by
name: the stored file hash equals the SHA-256 of the PDF downloaded through
the report's link, and for each run in the report the TSA token in the
bundle verifies and its time is within the period. The month is real: every
bundle goes through `POST /v1/results` with a token the test TSA made at a
chosen second (`tests/report_lab.py` `land`), the final report is made as
the job makes it and the interim one by "Generate now", and `check_report`
reads the objects back from the lab's bucket. Failure paths first: another
MSP's report, an object gone or changed, each planted fault on a run its
word, the budget held to the Worker's header.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import types
import uuid
from urllib.parse import urlsplit

import pytest
from sqlalchemy import event, text

from app.report import check as checks
from app.report.check import STAMP_BUDGET, ReportCheck, check_file, check_report, check_run, is_late
from app.report.data import Period, month_of
from app.report.generate import generate
from app.repo.errors import RepoError
from app.repo.runs import RESULTS_CLOSE, RunRepo
from app.schemas import shared_schemas_dir
from tests.report_lab import OCTOBER_START, SEPTEMBER, ReportLab, at, pdf_text
from tests.results_lab import UTC
from tests.test_reports_page import IP, TODAY, interim_key, rows_of
from tests.test_results import CLOSED_ATTACHMENTS, CLOSED_RESULT
from tests.tsa_lab import OTHER_ROOT_PEM, make_token

OCTOBER = month_of(OCTOBER_START.date())
# The job's clock on the 1st: the hour the final report is made (FINAL_AFTER).
FIRST = dt.datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC)
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
RUN_COLUMNS = (
    "id", "state", "bundle_key", "bundle_sha256", "tsa_ok", "tsa_time", "finished_at", "dispatched_at", "created_at", "received_at",
)


@pytest.fixture
async def lab(session, monkeypatch) -> ReportLab:
    lab = ReportLab(session, monkeypatch)
    await lab.fill()
    lab.time = TODAY
    return lab


async def september(lab: ReportLab) -> dict[str, uuid.UUID]:
    """The entry's point 6: a pass stamped three seconds after its end; a
    pass that ended at 23:59:58 on the last day and was stamped 42 seconds
    later, in October; a pass that ended on 31 August, was stamped five
    seconds later and arrived on 1 September at 03:05, after August had
    closed (late: September's); an error written afterwards with a token on
    the 20th; one with no token, handed out on the 15th; an expired, a
    queued and a dispatched run; and October's one pass."""
    passed = await lab.land(ended_at="2026-09-10T02:05:00.000Z", stamped_at=at(10, 2, 5, 3), received_at=at(10, 2, 6))
    edge = await lab.land(ended_at="2026-09-30T23:59:58.000Z", stamped_at=at(1, 0, 0, 40, month=10), received_at=at(1, 0, 1, month=10))
    late = await lab.land(ended_at="2026-08-31T23:50:00.000Z", stamped_at=at(31, 23, 50, 5, month=8), received_at=at(1, 3, 5))
    stamped_close = await lab.land(ended_at=None, stamped_at=at(20, 2, 5), received_at=at(20, 2, 6), base=CLOSED_RESULT, attachments=CLOSED_ATTACHMENTS)
    bare_close = await lab.land(
        ended_at=None, stamped_at=None, received_at=at(15, 2, 6), base=CLOSED_RESULT, attachments=CLOSED_ATTACHMENTS, dispatched_at=at(15, 2, 5),
    )
    expired = await lab.make_run(state="expired", created_at=at(12))
    queued = await lab.make_run(state="queued", created_at=at(16))
    dispatched = await lab.make_run(state="dispatched", created_at=at(17), dispatched_at=at(17, 2, 1))
    october = await lab.land(ended_at="2026-10-05T02:05:00.000Z", stamped_at=at(5, 2, 5, 2, month=10), received_at=at(5, 2, 6, month=10))
    return {
        "passed": passed, "edge": edge, "late": late, "stamped_close": stamped_close, "bare_close": bare_close, "expired": expired,
        "queued": queued, "dispatched": dispatched, "october": october,
    }


async def final_report(lab: ReportLab):
    """September's final report as the job makes it: `generate` with the
    job's arguments (tests/test_scheduler.py holds `tick_reports` to that
    call), the put under the month's key."""
    lab.expect_put(lab.final_key())
    created = await generate(lab.session, lab.storage, lab.msp_id, lab.client_id, SEPTEMBER, now=FIRST)
    return uuid.UUID(created.values["report_id"])


async def interim_report(lab: ReportLab):
    """October's interim report by the member's click."""
    lab.expect_put(interim_key(lab))
    clicked = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member, ip=IP, headers=SAME_ORIGIN)
    assert clicked.status_code == 303, clicked.text
    (row,) = [r for r in await rows_of(lab) if r.interim]
    return row.id


async def downloaded(lab: ReportLab, report_id: uuid.UUID, *, body: bytes | None = None) -> tuple[str, bytes]:
    """The report's link followed: `GET /reports/{id}/file`, the 302's URL,
    the object under the key that URL names, fetched as a browser would."""
    answer = await lab.get(f"/reports/{report_id}/file", lab.member, ip=IP, headers=SAME_ORIGIN)
    assert answer.status_code == 302, answer.text
    url = urlsplit(answer.headers["location"])
    prefix = f"/{lab.settings.s3_bucket}/"
    assert url.path.startswith(prefix)
    key = url.path[len(prefix):]
    lab.expect_get(key, body)
    return key, lab.storage.get(key)


async def month_runs(lab: ReportLab, period: Period) -> list:
    return await RunRepo(lab.session).period(lab.msp_id, lab.client_id, start=period.start_at, end=period.end_at)


async def expect_check(lab: ReportLab, report, period: Period, *, planted: dict[uuid.UUID, dict] | None = None) -> None:
    """The bucket calls `check_report` makes, in its order: the report's
    object, then each run of the month in the report's order."""
    lab.expect_get(report.storage_key)
    for run in await month_runs(lab, period):
        lab.expect_run_objects(run, **(planted or {}).get(run.id, {}))


async def report_row(lab: ReportLab, report_id: uuid.UUID):
    (row,) = [r for r in await rows_of(lab) if r.id == report_id]
    return row


def row_like(run, **changes) -> types.SimpleNamespace:
    """A copy of the columns the check reads, with planted changes, so the
    session's row is never dirtied."""
    return types.SimpleNamespace(**{**{name: getattr(run, name) for name in RUN_COLUMNS}, **changes})


def bundle_objects(lab: ReportLab, run) -> dict[str, bytes]:
    if run.bundle_key is None:
        return {}
    return {name: lab.objects[run.bundle_key + name] for name in ("result.json", "timestamp.tst") if run.bundle_key + name in lab.objects}


def names_of(lab: ReportLab, run) -> list[str]:
    if run.bundle_key is None:
        return []
    return sorted(key[len(run.bundle_key):] for key in lab.objects if key.startswith(run.bundle_key))


def judge(lab: ReportLab, run, period: Period = SEPTEMBER, *, names=None, objects=None, tsa_ca=None, generated_at=FIRST, final=True) -> str | None:
    return check_run(
        run, period, names=names_of(lab, run) if names is None else names, objects=bundle_objects(lab, run) if objects is None else objects,
        tsa_ca=lab.app.state.tsa_ca_pem if tsa_ca is None else tsa_ca, generated_at=generated_at, final=final,
    )


# --- The Done-when, by name ---------------------------------------------------------------------


async def test_the_stored_file_hash_equals_the_sha256_of_the_pdf_downloaded_through_the_report_s_link(lab):
    await september(lab)
    final = await final_report(lab)
    interim = await interim_report(lab)

    for report_id, period in ((final, SEPTEMBER), (interim, OCTOBER)):
        row = await report_row(lab, report_id)
        key, pdf = await downloaded(lab, report_id)
        await expect_check(lab, row, period)
        found = await check_report(lab.session, lab.storage, lab.msp_id, report_id, tsa_ca=lab.app.state.tsa_ca_pem)

        assert key == row.storage_key and pdf.startswith(b"%PDF-")
        assert hashlib.sha256(pdf).hexdigest() == row.file_sha256
        assert (found.file_ok, found.findings, found.final) == (True, (), period is SEPTEMBER)
    lab.stubber.assert_no_pending_responses()


async def test_for_each_run_in_the_report_the_tsa_token_in_the_bundle_verifies_and_its_time_is_within_the_period(lab):
    runs = await september(lab)
    final = await final_report(lab)
    row = await report_row(lab, final)
    await expect_check(lab, row, SEPTEMBER)

    found = await check_report(lab.session, lab.storage, lab.msp_id, final, tsa_ca=lab.app.state.tsa_ca_pem)

    assert found == ReportCheck(report_id=final, final=True, file_ok=True, runs=8, stamped=4, not_stamped=1, no_bundle=3, late=1, findings=())
    lab.stubber.assert_no_pending_responses()
    # The counts are the Summary's: the PDF says what the check counted.
    words = pdf_text(lab.bodies[0])
    assert re.search(r"T\s?ests run 5\b", words)
    for line in (
        "Scheduled tests that did not run: 1", "Scheduled tests with no result when this report was made: 2",
        "Tests that ended before this period and whose results arrived after that period had closed, counted here: 1",
    ):
        assert line in words, line
    # The late one is the one that ended in August and arrived after August closed; the edge one is September's by its end.
    by_id = {run.id: run for run in await month_runs(lab, SEPTEMBER)}
    assert [is_late(by_id[runs[name]]) for name in ("passed", "edge", "late", "stamped_close", "bare_close")] == [False, False, True, False, False]
    assert by_id[runs["edge"]].tsa_time == at(1, 0, 0, 40, month=10) and by_id[runs["edge"]].finished_at == at(30, 23, 59, 58)
    assert runs["october"] not in by_id


# --- Failure paths ------------------------------------------------------------------------------


async def test_another_msp_s_report_is_no_report_and_nothing_is_read_from_the_bucket(lab):
    await september(lab)
    final = await final_report(lab)

    with pytest.raises(RepoError, match="^report_id: no such report$"):
        await check_report(lab.session, lab.storage, lab.b_msp_id, final, tsa_ca=lab.app.state.tsa_ca_pem)
    with pytest.raises(RepoError, match="^report_id: no such report$"):
        await check_report(lab.session, lab.storage, lab.msp_id, uuid.uuid4(), tsa_ca=lab.app.state.tsa_ca_pem)
    lab.stubber.assert_no_pending_responses()


@pytest.mark.parametrize("fault", ["gone", "changed"])
async def test_a_report_whose_object_is_gone_or_changed_is_worded_and_the_link_still_302s(lab, fault):
    """The planted fault of the first Done-when: one byte of the stored
    object changed (or the object gone); the download still 302s (the route
    signs; it never reads), and the check says so."""
    await september(lab)
    final = await final_report(lab)
    row = await report_row(lab, final)
    pdf = lab.objects[row.storage_key]
    changed = pdf[:-1] + bytes([pdf[-1] ^ 1])
    if fault == "gone":
        answer = await lab.get(f"/reports/{final}/file", lab.member, ip=IP, headers=SAME_ORIGIN)
        lab.expect_missing(row.storage_key)
    else:
        answer, (_key, fetched) = None, await downloaded(lab, final, body=changed)
        assert hashlib.sha256(fetched).hexdigest() != row.file_sha256
        lab.expect_get(row.storage_key, changed)
    for run in await month_runs(lab, SEPTEMBER):
        lab.expect_run_objects(run)

    found = await check_report(lab.session, lab.storage, lab.msp_id, final, tsa_ca=lab.app.state.tsa_ca_pem)

    assert answer is None or answer.status_code == 302
    assert (found.file_ok, found.findings) == (False, ((None, "storage: no object" if fault == "gone" else "file_sha256: differs"),))
    assert found.runs == 8
    assert check_file(row, None) == "storage: no object" and check_file(row, changed) == "file_sha256: differs" and check_file(row, pdf) is None


async def test_a_token_of_another_time_under_a_run_s_key_is_found_through_the_bucket(lab):
    """The planted fault of the second Done-when, end to end: the token under
    the run's key replaced by one of the same digest made 121 s after the
    end, the row's `tsa_time` moved with it (moved alone it is `tsa_time:
    differs`, below); the check names the run."""
    runs = await september(lab)
    final = await final_report(lab)
    row = await report_row(lab, final)
    run = await RunRepo(lab.session).get(lab.msp_id, runs["passed"])
    digest = hashlib.sha256(lab.objects[run.bundle_key + "result.json"]).digest()
    moved = run.finished_at + STAMP_BUDGET + dt.timedelta(seconds=1)
    await lab.session.execute(text("UPDATE test_run SET tsa_time = :at WHERE id = :id"), {"at": moved, "id": run.id})
    await lab.session.refresh(run)  # the identity map's copy would still say the old time
    await expect_check(lab, row, SEPTEMBER, planted={run.id: {"objects": {"timestamp.tst": make_token(digest, moved)}}})

    found = await check_report(lab.session, lab.storage, lab.msp_id, final, tsa_ca=lab.app.state.tsa_ca_pem)

    assert found.findings == ((run.id, "stamp_after_budget"),)
    assert (found.file_ok, found.stamped) == (True, 4)
    lab.stubber.assert_no_pending_responses()


async def test_each_planted_fault_on_a_stamped_run_is_its_word_and_nothing_else_s(lab):
    """Point 4's faults, one by one, on the real rows and objects: the token
    after the budget, before the end's second, over another digest, under
    the other root; the row's time moved; the result of another run; the
    token or the result gone; the row's time missing."""
    runs = await september(lab)
    passed = await RunRepo(lab.session).get(lab.msp_id, runs["passed"])
    edge = await RunRepo(lab.session).get(lab.msp_id, runs["edge"])
    digest = hashlib.sha256(lab.objects[passed.bundle_key + "result.json"]).digest()
    end = passed.finished_at
    later, earlier = end + STAMP_BUDGET + dt.timedelta(seconds=1), end.replace(microsecond=0) - dt.timedelta(seconds=1)
    at_budget = end + STAMP_BUDGET
    token = lambda when: {"result.json": lab.objects[passed.bundle_key + "result.json"], "timestamp.tst": make_token(digest, when)}

    assert judge(lab, passed) is None and judge(lab, edge) is None
    assert judge(lab, row_like(passed, tsa_time=later), objects=token(later)) == "stamp_after_budget"
    assert judge(lab, row_like(passed, tsa_time=at_budget), objects=token(at_budget)) is None
    # The number itself, not the constant: a budget planted at a day let the lines above pass.
    literal = end + dt.timedelta(seconds=121)
    assert judge(lab, row_like(passed, tsa_time=literal), objects=token(literal)) == "stamp_after_budget"
    assert judge(lab, row_like(passed, tsa_time=earlier), objects=token(earlier)) == "stamp_before_end"
    assert judge(lab, row_like(passed, tsa_time=end.replace(microsecond=0)), objects=token(end.replace(microsecond=0))) is None
    assert judge(lab, passed, objects={**token(passed.tsa_time), "timestamp.tst": make_token(b"\0" * 32, passed.tsa_time)}) == "timestamp_mismatch"
    assert judge(lab, passed, tsa_ca=OTHER_ROOT_PEM) == "timestamp_invalid"
    assert judge(lab, passed, objects={**token(passed.tsa_time), "timestamp.tst": b"not a token"}) == "timestamp_file"
    assert judge(lab, row_like(passed, tsa_time=passed.tsa_time + dt.timedelta(seconds=1))) == "tsa_time: differs"
    assert judge(lab, passed, objects={**token(passed.tsa_time), "result.json": lab.objects[edge.bundle_key + "result.json"]}) == "bundle_sha256: differs"
    assert judge(lab, passed, names=["items.csv", "result.json", "signature.json", "veeam-session.log"]) == "storage: no timestamp.tst"
    assert judge(lab, passed, names=["items.csv", "signature.json", "timestamp.tst", "veeam-session.log"]) == "storage: no result.json"
    assert judge(lab, row_like(passed, tsa_time=None)) == "tsa_time: missing"
    assert judge(lab, row_like(passed, bundle_key=None)) == "bundle_key: missing"


async def test_a_result_written_afterwards_is_dated_by_its_stamp_and_has_no_budget(lab):
    """A run with no `finished_at` is dated by its token's time: the stamp is
    the only end there is, so no budget applies and only the period does."""
    runs = await september(lab)
    run = await RunRepo(lab.session).get(lab.msp_id, runs["stamped_close"])

    assert (run.finished_at, run.tsa_time) == (None, at(20, 2, 5))
    assert judge(lab, run) is None
    assert judge(lab, run, OCTOBER) == "period: not the run's"
    assert judge(lab, row_like(run, dispatched_at=at(1, month=10))) is None


async def test_a_run_not_stamped_must_have_no_token_and_no_time_and_a_run_without_a_bundle_only_counts(lab):
    runs = await september(lab)
    bare = await RunRepo(lab.session).get(lab.msp_id, runs["bare_close"])
    expired = await RunRepo(lab.session).get(lab.msp_id, runs["expired"])

    assert (bare.tsa_ok, bare.tsa_time, bare.bundle_key is not None) == (None, None, True)
    assert judge(lab, bare) is None
    assert judge(lab, bare, names=names_of(lab, bare) + ["timestamp.tst"]) == "storage: timestamp.tst unexpected"
    assert judge(lab, row_like(bare, tsa_time=at(15, 2, 7))) == "tsa_time: unexpected"
    assert judge(lab, row_like(bare, bundle_key=None)) == "bundle_key: missing"
    assert judge(lab, expired, names=[], objects={}) is None
    for planted in ({"bundle_key": "msp/x/runs/y/"}, {"tsa_ok": True}, {"tsa_time": at(12)}):
        assert judge(lab, row_like(expired, **planted), names=[], objects={}) == "state: no bundle expected", planted


async def test_a_late_result_is_the_period_s_by_its_arrival_and_a_run_of_another_month_is_worded(lab):
    runs = await september(lab)
    late = await RunRepo(lab.session).get(lab.msp_id, runs["late"])
    passed = await RunRepo(lab.session).get(lab.msp_id, runs["passed"])
    august = month_of(dt.date(2026, 8, 1))

    assert is_late(late) and not is_late(passed) and not is_late(row_like(late, received_at=None))
    assert late.received_at == august.end_at + RESULTS_CLOSE + dt.timedelta(hours=1, minutes=5)
    assert judge(lab, late) is None
    assert judge(lab, late, august) == "period: not the run's"
    assert judge(lab, passed, OCTOBER) == "period: not the run's"
    # Received a second before August closed: August's by its end, so not September's.
    assert judge(lab, row_like(late, received_at=august.end_at + RESULTS_CLOSE - dt.timedelta(seconds=1))) == "period: not the run's"


async def test_a_final_report_holds_every_result_received_before_it_and_an_interim_one_does_not(lab):
    """By the rules a final report is generated at 03:00 on the 1st or
    later and the month's results arrived before 02:00, so the word is for
    a final report made against them (a row made by hand, a clock moved)
    or a result moved afterwards: here a final report of September
    generated in September, before the pass arrived (received 02:06)."""
    runs = await september(lab)
    passed = await RunRepo(lab.session).get(lab.msp_id, runs["passed"])
    before = passed.received_at - dt.timedelta(minutes=6)

    assert passed.received_at == at(10, 2, 6)
    assert judge(lab, passed, generated_at=before, final=True) == "received_after_report"
    assert judge(lab, passed, generated_at=passed.received_at, final=True) == "received_after_report"
    assert judge(lab, passed, generated_at=before, final=False) is None
    assert judge(lab, row_like(passed, received_at=None), generated_at=before, final=True) is None
    assert judge(lab, passed, generated_at=FIRST, final=True) is None


async def test_a_stamped_run_whose_token_is_not_listed_is_found_through_the_bucket_and_nothing_is_read_for_it(lab):
    runs = await september(lab)
    final = await final_report(lab)
    row = await report_row(lab, final)
    run = await RunRepo(lab.session).get(lab.msp_id, runs["passed"])
    without = [name for name in names_of(lab, run) if name != "timestamp.tst"]
    await expect_check(lab, row, SEPTEMBER, planted={run.id: {"names": without}})

    found = await check_report(lab.session, lab.storage, lab.msp_id, final, tsa_ca=lab.app.state.tsa_ca_pem)

    assert found.findings == ((run.id, "storage: no timestamp.tst"),)
    lab.stubber.assert_no_pending_responses()


async def test_a_bucket_fault_other_than_a_missing_object_is_the_caller_s_not_a_finding(lab):
    """`storage: no object` is S3's NoSuchKey alone; any other answer of the
    bucket is raised as it is, since nothing of the report is known."""
    from botocore.exceptions import ClientError

    await september(lab)
    final = await final_report(lab)
    row = await report_row(lab, final)
    lab.stubber.add_client_error("get_object", service_error_code="InternalError", expected_params={"Bucket": lab.settings.s3_bucket, "Key": row.storage_key})

    with pytest.raises(ClientError, match="InternalError"):
        await check_report(lab.session, lab.storage, lab.msp_id, final, tsa_ca=lab.app.state.tsa_ca_pem)
    lab.stubber.assert_no_pending_responses()


def test_the_stamp_budget_is_the_worker_s_three_constants():
    """`STAMP_BUDGET` is the Worker's whole timestamp budget: the attempts
    times their timeout plus the two waits (worker/include/rp/timestamper.hpp)."""
    header = (shared_schemas_dir().parents[1] / "worker" / "include" / "rp" / "timestamper.hpp").read_text(encoding="utf-8")
    attempts = int(re.search(r"kTimestampAttempts = (\d+);", header).group(1))
    timeout, first, second = (int(re.search(rf"{name}\{{(\d+)\}}", header).group(1)) for name in ("kTimestampTimeout", "kTimestampFirstWait", "kTimestampSecondWait"))

    assert STAMP_BUDGET == dt.timedelta(milliseconds=attempts * timeout + first + second) == dt.timedelta(seconds=120)


async def test_the_check_is_two_statements_and_one_list_and_at_most_two_gets_per_run(lab, test_engine):
    await september(lab)
    final = await final_report(lab)
    row = await report_row(lab, final)
    await expect_check(lab, row, SEPTEMBER)
    seen: list[str] = []

    def listen(_conn, _cursor, statement, _params, _context, _executemany):
        seen.append(statement.split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", listen)
    try:
        found = await check_report(lab.session, lab.storage, lab.msp_id, final, tsa_ca=lab.app.state.tsa_ca_pem)
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", listen)

    assert seen == ["SELECT", "SELECT"]
    assert found.findings == ()
    # Every expected bucket call was made and no other (the Stubber refuses an unexpected one).
    lab.stubber.assert_no_pending_responses()


def test_the_words_are_the_module_s_own_and_the_verifier_s():
    assert checks.NO_SUCH_REPORT == "no such report"
    assert checks.STAMP_AFTER_BUDGET == "stamp_after_budget" and checks.STAMP_BEFORE_END == "stamp_before_end"
    assert checks.RESULT_FILE == "result.json" and checks.TIMESTAMP_FILE == "timestamp.tst"
