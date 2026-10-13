"""C6.4 (docs/decisions.md 2026-10-12, "C6.4"), the Done-when by name: a PDF
renders for a client with one failure and one error in the period and every
section is populated. Failure paths first (another MSP's client, a period
outside its rule, a month with no run, a second final report, a put that
fails, the banned phrases, a planted script, the secret scan), then the
month's membership, the two hashes, the interim report, the statement count,
the period arithmetic and the frameworks' rows.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import os
import re
import uuid

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import event, text

from app import ui
from app.report import frameworks, render
from app.report.data import Period, ReportData, found_word, gather, interim_for, overall_class, period_of, previous_month, run_date
from app.report.generate import ReportFailed, generate, storage_key
from app.report.render import PLACEHOLDER, Rendered, render_html, render_pdf, render_report
from app.repo.audit import AuditRepo
from app.repo.errors import RepoError
from app.repo.plans import PlanRepo
from app.repo.reports import ReportRepo
from tests.pages_lab import IP, UTC
from tests.report_lab import (
    OCTOBER_START, SEPTEMBER, SEPTEMBER_START, VECTOR_HASH, ReportLab, an_item, at, page_count, past_the_page, pdf_info, pdf_text,
    pdf_trailer_keys,
)
from tests.results_lab import NOW
from tests.test_contract import VECTOR

HEADINGS = ("Summary", "Test log", "Failures", "Method", "Integrity", "Framework mapping")
BANNED = ("fully recoverable", "guarantee", "certified", "accepted by insurers")
SCRIPT = "<script>alert(1)</script>"
ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"
HEX = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture
async def lab(session, monkeypatch) -> ReportLab:
    lab = ReportLab(session, monkeypatch)
    await lab.fill()
    return lab


async def make(lab: ReportLab, period: Period = SEPTEMBER, *, client_id=None, msp_id=None, now=None, user_id=None, ip=None):
    return await generate(
        lab.session, lab.storage, msp_id or lab.msp_id, client_id or lab.client_id, period,
        now=now or lab.time, user_id=user_id, ip=ip,
    )


async def report_rows(lab: ReportLab, msp_id=None):
    return await ReportRepo(lab.session).list(msp_id or lab.msp_id)


async def report_audit(lab: ReportLab, msp_id=None):
    return [(r.action, r.target, r.user_id, r.ip) for r in await AuditRepo(lab.session).list(msp_id or lab.msp_id) if r.action.startswith("report.")]


# --- The Done-when, by name ---------------------------------------------------------------------


async def test_a_pdf_renders_for_a_client_with_one_failure_and_one_error_in_the_period_and_every_section_is_populated(lab):
    runs = await lab.month()
    key = lab.final_key()
    lab.expect_put(key)
    generated_at = dt.datetime(2026, 10, 1, 3, 0, 7, tzinfo=UTC)

    created = await make(lab, now=generated_at)

    # The lines, the row, the object, the audit row.
    (row,) = await report_rows(lab)
    assert created.values == {
        "report_id": str(row.id), "period": "2026-09", "interim": "false", "storage_key": key,
        "content_sha256": row.content_sha256, "file_sha256": row.file_sha256,
    }
    assert (row.client_id, row.period_start, row.period_end, row.interim, row.generated_at) == (lab.client_id, dt.date(2026, 9, 1), dt.date(2026, 9, 30), False, generated_at)
    assert HEX.match(row.content_sha256) and HEX.match(row.file_sha256) and row.content_sha256 != row.file_sha256
    lab.stubber.assert_no_pending_responses()
    (pdf,) = lab.bodies
    assert pdf.startswith(b"%PDF-") and hashlib.sha256(pdf).hexdigest() == row.file_sha256
    assert await report_audit(lab) == [("report.create", f"report:{row.id}", None, None)]

    # The PDF is the render of the month's data: the same bytes again, so the
    # HTML below is the PDF's own.
    rendered = render_report(await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=generated_at))
    assert (rendered.content_sha256, rendered.file_sha256, rendered.pdf) == (row.content_sha256, row.file_sha256, pdf)
    html = rendered.html_2
    words = pdf_text(pdf)

    # Every section, in order, in the PDF's text.
    positions = [words.index(heading) for heading in HEADINGS]
    assert positions == sorted(positions)
    for needle in (
        "1 of 4 tests failed", "1 of 4 tests could not run (error)", "Scheduled tests that did not run: 1",
        "Scheduled tests with no result when this report was made: 2",
        "This report does not test full disaster recovery", "A later test of the same plan passed on 2026-09-25 02:20 UTC",
        "A file cannot contain its own hash", row.content_sha256, "it is not an assessment of the control",
        "On the dates listed, a sample of items was restored from the backup copy",
    ):
        assert needle in words, needle
    assert row.file_sha256 not in words and PLACEHOLDER not in words and "Interim" not in words
    assert page_count(pdf) >= 2

    short = {name: str(run_id)[:8] for name, run_id in runs.items()}
    # Summary
    for needle in (
        "<h1>Restore test report</h1>", "<dt>Client</dt><dd>contoso</dd>", "<dt>MSP</dt><dd>contract</dd>", "<dt>Period</dt><dd>September 2026 (2026-09)</dd>",
        "<p class=\"overall fail\">1 of 4 tests failed</p>", "<dt>Tests run</dt><dd>4</dd>", "<dt>Average recovery time</dt><dd>7:25</dd>",
        "<dt>Maximum recovery time</dt><dd>20:30</dd>", "<dt>Backup source</dt><dd>Veeam Backup for Microsoft 365</dd>",
        "<dt>Restore points covered</dt><dd>3, from 2026-09-09 23:00 UTC to 2026-09-29 22:00 UTC</dd>",
    ):
        assert needle in html, needle
    # Test log: one row per run, oldest first, with the counts and the short ids.
    log = html[html.index('<h2 id="test-log">'):html.index('<h2 id="failures">')]
    order = [log.index(f"<code>{short[name]}</code>") for name in ("failed", "expired", "queued", "dispatched", "errored", "later", "vector")]
    assert order == sorted(order) and log.count("<tr>") == 8  # the header's row and seven runs
    for needle in (
        "<td>2026-09-10 02:30 UTC</td><td>2026-09-09 23:00 UTC</td><td>1 / 1 / 1</td><td><span class=\"state fail\">fail</span></td><td>1:05</td>",
        "<td>2026-09-15 02:00 UTC</td><td>—</td><td>0 / 0 / 0</td><td><span class=\"state quiet\">did not run</span></td><td>—</td>",
        "<td>2026-09-16 02:00 UTC</td><td>—</td><td>0 / 0 / 0</td><td><span class=\"state quiet\">no result yet</span></td><td>—</td>",
        "<td>2026-09-17 02:00 UTC</td><td>—</td><td>0 / 0 / 0</td><td><span class=\"state quiet\">no result yet</span></td><td>—</td>",
        "<td>2026-09-20 02:05 UTC</td><td>—</td><td>0 / 0 / 0</td><td><span class=\"state error\">error</span></td><td>—</td>",
        "<td>2026-09-25 02:20 UTC</td><td>2026-09-24 23:00 UTC</td><td>1 / 0 / 0</td><td><span class=\"state pass\">pass</span></td><td>0:40</td>",
        "<td>2026-09-28 12:00 UTC</td><td>2026-09-29 22:00 UTC</td><td>0 / 1 / 1</td><td><span class=\"state pass\">pass</span></td><td>20:30</td>",
    ):
        assert needle in log, needle
    assert short["theirs"] not in html
    # Failures: the fail's items and reasons, the error's code, the re-test.
    failures = html[html.index('<h2 id="failures">'):html.index('<h2 id="method">')]
    for needle in (
        f"<h3>2026-09-10 02:30 UTC <span class=\"state fail\">fail</span> <code>{short['failed']}</code></h3>",
        "<td>mail</td><td>RP-CANARY-0003</td><td>missing</td><td>no restored copy found</td>",
        "<td>sharepoint</td><td>rp-canary-04.docx</td><td>mismatch</td><td>fields did not match: sha256</td>",
        f"<h3>2026-09-20 02:05 UTC <span class=\"state error\">error</span> <code>{short['errored']}</code></h3>",
        "<p>Error <code>veeam_unreachable</code>: the backup product did not answer</p>", "<p>No item was checked.</p>",
    ):
        assert needle in failures, needle
    assert "rp-canary-12.pdf" not in failures  # the fail's matched item
    assert failures.count("<p class=\"retest\">A later test of the same plan passed on 2026-09-25 02:20 UTC.</p>") == 2
    # Method
    method = html[html.index('<h2 id="method">'):html.index('<h2 id="integrity">')]
    for needle in (
        "up to 0 mails, 1 SharePoint file and 1 OneDrive file", "canary", "random", "<code>restoretest</code>", "<code>RestoreTarget</code>",
        "Verification levels covered: 1, 2, 3; level 4 partially (files opened and read via Microsoft Graph).",
    ):
        assert needle in method, needle
    # Integrity: the two hashes, the Worker, every run's bundle hash and TSA line.
    integrity = html[html.index('<h2 id="integrity">'):html.index('<h2 id="framework-mapping">')]
    for needle in (
        f"<dt>Content hash (SHA-256)</dt><dd><code>{row.content_sha256}</code></dd>", "<dt>File hash (SHA-256)</dt><dd>stored by the Cloud beside this report</dd>",
        f"<td>w1</td><td><code>{lab.worker_id}</code></td><td><code>{VECTOR['key_id']}</code></td>",
        f"<td><code>{runs['vector']}</code></td><td><code>{VECTOR_HASH}</code></td><td>timestamped 2026-09-28 12:00 UTC</td>",
        f"<td><code>{runs['failed']}</code></td><td><code>{'ab' * 32}</code></td><td>timestamped 2026-09-10 02:30 UTC</td>",
        f"<td><code>{runs['errored']}</code></td><td><code>{'cd' * 32}</code></td><td>not timestamped</td>",
        f"<td><code>{runs['expired']}</code></td><td>—</td><td>—</td>",
        f"<td><code>{runs['queued']}</code></td><td>—</td><td>—</td>",
        f"<td><code>{runs['dispatched']}</code></td><td>—</td><td>—</td>",
        "<dt>Generated</dt><dd>2026-10-01 03:00 UTC</dd>",
    ):
        assert needle in integrity, needle
    assert html.count("w2") == 0  # a Worker with no run in the month
    # Framework mapping: the four controls, their two sentences each (C6.7) and the sentence above the table.
    mapping = html[html.index('<h2 id="framework-mapping">'):]
    for control in frameworks.CONTROLS:
        for needle in (control.identifier, control.name, control.demonstrates, control.not_covered):
            assert needle.replace("'", "&#39;") in mapping, needle
    assert frameworks.ABOUT.replace("'", "&#39;") in mapping
    assert mapping.count("<td>—</td>") == 0 and mapping.count("<tr>") == 5
    assert "more tests of this period are not listed here" not in html


# --- Failure paths first ------------------------------------------------------------------------


async def test_another_msp_s_client_is_no_client_and_nothing_is_written_from_either_side(lab):
    await lab.month()
    before = (await lab.count("report"), await lab.count("audit_log"))

    for msp_id, client_id in ((lab.msp_id, lab.b_client_id), (lab.b_msp_id, lab.client_id)):
        with pytest.raises(RepoError, match="^client_id: no such client$"):
            await make(lab, msp_id=msp_id, client_id=client_id)

    assert (await lab.count("report"), await lab.count("audit_log")) == before
    assert lab.bodies == []


async def test_an_msp_nobody_has_is_no_msp_and_nothing_is_written(lab):
    await lab.month()
    before = (await lab.count("report"), await lab.count("audit_log"))

    with pytest.raises(RepoError, match="^msp_id: no such MSP$"):
        await make(lab, msp_id=uuid.uuid4())

    assert (await lab.count("report"), await lab.count("audit_log")) == before
    assert lab.bodies == []


@pytest.mark.parametrize("period_text", ["2026-9", "2026-09-01", "September 2026", "2026/09", "", "2026-13", "2026-00", "x", "0000-01"])
def test_a_period_outside_its_rule_is_refused_naming_the_key_alone(period_text):
    with pytest.raises(RepoError, match="^period: not YYYY-MM$") as raised:
        period_of(period_text)
    assert period_text not in str(raised.value) or period_text == ""


async def test_a_month_that_has_not_begun_and_a_month_with_no_run_are_refused_with_nothing_written(lab):
    await lab.month()
    before = (await lab.count("report"), await lab.count("audit_log"))

    with pytest.raises(RepoError, match="^period: has not begun$"):
        await make(lab, period_of("2027-01"), now=dt.datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC))
    with pytest.raises(RepoError, match="^period: no run in the period$"):
        await make(lab, period_of("2026-07"))

    assert (await lab.count("report"), await lab.count("audit_log")) == before
    assert lab.bodies == []


async def test_a_second_final_report_of_one_month_is_refused_before_rendering_and_nothing_is_put(lab, monkeypatch):
    """The read `ReportRepo.final` refuses it before the two passes; the
    partial unique index is the second line, for two generations at once
    (shown on the model in tests/test_models.py)."""
    await lab.month()
    lab.expect_put(lab.final_key())
    await make(lab)
    lab.stubber.assert_no_pending_responses()
    monkeypatch.setattr("app.report.generate.render_report", lambda data: pytest.fail("rendered a report the month already has"))

    with pytest.raises(RepoError, match="^period: already reported$"):
        await make(lab)

    assert len(await report_rows(lab)) == 1
    assert len(lab.bodies) == 1
    assert len(await report_audit(lab)) == 1
    # An interim report of the month is still taken after the final one.
    assert await ReportRepo(lab.session).final(lab.msp_id, lab.client_id, SEPTEMBER.start) is not None
    assert await ReportRepo(lab.session).final(lab.msp_id, lab.client_id, dt.date(2026, 8, 1)) is None
    assert await ReportRepo(lab.session).final(lab.b_msp_id, lab.client_id, SEPTEMBER.start) is None


async def test_a_month_that_has_its_final_report_is_refused_by_one_read_before_the_month_is_read(lab, test_engine, monkeypatch):
    """C6.6 (docs/decisions.md 2026-10-13, point 1; the C6.4 review's cut
    finding "ReportRepo.final after the eight reads"): the monthly job asks
    `generate` for every client of a month, so a month already reported costs
    one SELECT, not nine."""
    await lab.month()
    lab.expect_put(lab.final_key())
    await make(lab)
    monkeypatch.setattr("app.report.generate.render_report", lambda data: pytest.fail("rendered"))
    seen: list[str] = []

    def listen(_conn, _cursor, statement, _params, _context, _executemany):
        seen.append(statement.split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", listen)
    try:
        with pytest.raises(RepoError, match="^period: already reported$"):
            await make(lab)
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", listen)

    assert seen == ["SELECT"]


async def test_a_put_that_fails_is_worded_by_its_type_and_the_row_is_rolled_back_with_it(lab):
    await lab.month()
    lab.stubber.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)

    with pytest.raises(ReportFailed, match=r"^storage: put failed \(AccessDenied\)$") as raised:
        async with lab.session.begin_nested():
            await make(lab)

    assert isinstance(raised.value, RepoError) and isinstance(raised.value.__cause__, ClientError)
    assert await report_rows(lab) == []
    assert await report_audit(lab) == []


async def test_a_render_that_fails_is_worded_by_its_type_before_any_row_or_object(lab, monkeypatch):
    """The review's finding 11: a library that will not load is an OSError,
    which the CLI worded `database: unreachable`."""
    await lab.month()

    def broken(_data):
        raise OSError("cannot load library 'libpango-1.0-0' at /a/path")

    monkeypatch.setattr("app.report.generate.render_report", broken)

    with pytest.raises(ReportFailed) as raised:
        await make(lab)

    assert str(raised.value) == "report: not rendered (OSError)"
    assert await report_rows(lab) == [] and await report_audit(lab) == [] and lab.bodies == []


@pytest.mark.parametrize("phrase", BANNED)
async def test_the_banned_phrases_are_in_no_template_stylesheet_control_or_rendered_report(lab, phrase):
    await lab.month()
    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    rendered = render_report(data)
    texts = [
        (render.REPORT_DIR / "template.html").read_text(encoding="utf-8"),
        (render.REPORT_DIR / "report.css").read_text(encoding="utf-8"),
        (render.REPORT_DIR / "frameworks.py").read_text(encoding="utf-8"),
        rendered.html_1, rendered.html_2, pdf_text(rendered.pdf),
    ]

    for text_ in texts:
        assert phrase not in text_.lower()
    assert len(texts) == 6 and all(texts)


async def test_a_planted_script_is_escaped_in_both_passes(lab):
    runs = await lab.month()
    s = lab.session
    await s.execute(text("UPDATE client SET name = :n WHERE id = :id"), {"n": "contoso " + SCRIPT, "id": lab.client_id})
    await s.execute(text("UPDATE msp SET name = :n WHERE id = :id"), {"n": "msp " + SCRIPT, "id": lab.msp_id})
    await s.execute(text("UPDATE worker SET name = :n WHERE id = :id"), {"n": "w1 " + SCRIPT, "id": lab.worker_id})
    await s.execute(text("UPDATE test_item SET name = :n WHERE run_id = :id AND position = 0"), {"n": "item " + SCRIPT, "id": runs["failed"]})
    await s.execute(text("UPDATE test_run SET error_message = :n WHERE id = :id"), {"n": "message " + SCRIPT, "id": runs["errored"]})

    data = await gather(s, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    rendered = render_report(data)

    for html in (rendered.html_1, rendered.html_2):
        assert SCRIPT not in html
        assert html.count(ESCAPED) >= 5
    assert "alert(1)" in pdf_text(rendered.pdf)


async def test_no_secret_link_or_tenant_identifier_is_in_the_report(lab):
    await lab.month()
    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    rendered = render_report(data)
    words = pdf_text(rendered.pdf)

    for needle in ("Bearer", "BEGIN ", "X-Amz", "http", "?", VECTOR["tenant_id"], lab.settings.s3_bucket, "MCowBQYDK2VwAyEA"):
        assert needle not in rendered.html_1, needle
        assert needle not in rendered.html_2, needle
        assert needle not in words, needle
    assert lab.token not in rendered.html_2


# --- Membership (point 4) -----------------------------------------------------------------------


async def test_the_month_s_runs_are_the_tested_ones_by_their_end_and_the_others_by_creation(lab):
    runs = await lab.month()
    edge_in = await lab.tested("pass", finished_at=SEPTEMBER_START, recovery_ms=1000)
    edge_out = await lab.tested("pass", finished_at=OCTOBER_START, recovery_ms=1000)
    fallback = await lab.make_run(state="error", created_at=at(18), finished_at=None, error_code="interrupted")

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    ids = [line.run_id for line in data.runs]
    assert ids == [edge_in, runs["failed"], runs["expired"], runs["queued"], runs["dispatched"], fallback, runs["errored"], runs["later"], runs["vector"]]
    assert edge_out not in ids and runs["theirs"] not in ids
    assert [line.result for line in data.runs] == ["pass", "fail", "did not run", "no result yet", "no result yet", "error", "error", "pass", "pass"]
    assert (data.tests, data.passed, data.failed, data.errored, data.did_not_run, data.no_result) == (6, 3, 1, 2, 1, 2)
    assert data.overall == "1 of 6 tests failed"
    assert data.errors_line == "2 of 6 tests could not run (error)"
    fallback_line = next(line for line in data.runs if line.run_id == fallback)
    assert fallback_line.date == at(18)


async def test_a_month_of_passes_alone_says_so_and_a_fail_without_a_later_pass_says_so(lab):
    passed = await lab.tested("pass", finished_at=at(3), recovery_ms=3000)
    await lab.items(passed, [an_item(0)])
    failed = await lab.tested("fail", finished_at=at(28), recovery_ms=3000)
    await lab.items(failed, [an_item(0, found=False, match=False, reason="no restored copy found")])

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    rendered = render_report(data)

    (failure,) = data.failures
    assert failure.retested_at is None
    assert "No later test of the same plan passed in this period." in rendered.html_2
    assert "1 of 2 tests failed" in rendered.html_2
    assert data.errors_line is None
    # Passes alone.
    await lab.session.execute(text("UPDATE test_run SET state = 'pass' WHERE id = :id"), {"id": failed})
    alone = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    assert alone.overall == "All 2 tests passed"
    assert alone.failures == [] and alone.did_not_run == 0
    assert "No test failed or errored in this period." in render_html(alone, None)
    assert "Scheduled tests that did not run" not in render_html(alone, None)
    assert "Scheduled tests with no result" not in render_html(alone, None)


async def test_no_recovery_time_anywhere_gives_dashes_and_no_restore_point_says_none(lab):
    run = await lab.tested("pass", finished_at=at(3))
    await lab.items(run, [an_item(0)])

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    html = render_html(data, None)

    assert (data.average_recovery_ms, data.max_recovery_ms, data.restore_points) == (None, None, [])
    assert "Average recovery time</dt><dd>—</dd>" in html and "Maximum recovery time</dt><dd>—</dd>" in html
    assert "Restore points covered</dt><dd>none</dd>" in html


async def test_an_item_nobody_checked_is_said_so_and_the_counts_are_per_type(lab):
    run = await lab.tested("error", finished_at=at(3), error_code="graph_unreachable", error_message="the tenant did not answer")
    await lab.items(run, [an_item(0, found=None, match=None), an_item(1, type="onedrive", name="a.pdf", found=None, match=None), an_item(2, type="onedrive", name="b.pdf", found=None, match=None)])

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    (line,) = data.runs
    assert (line.mail, line.sp, line.od) == (1, 0, 2)
    (failure,) = data.failures
    assert [(item.type, item.name, item.found_word, item.reason) for item in failure.items] == [
        ("mail", "RP-CANARY-0000", "not checked", None), ("onedrive", "a.pdf", "not checked", None), ("onedrive", "b.pdf", "not checked", None),
    ]
    assert (failure.line.error_code, failure.line.error_message) == ("graph_unreachable", "the tenant did not answer")


# --- The two hashes (point 6) -------------------------------------------------------------------


async def test_the_content_hash_is_pass_one_s_bytes_and_the_file_hash_pass_two_s_and_the_passes_differ_by_the_hash_alone(lab):
    await lab.month()
    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    rendered = render_report(data)
    again = render_report(data)

    assert isinstance(rendered, Rendered)
    assert hashlib.sha256(render_pdf(rendered.html_1)).hexdigest() == rendered.content_sha256
    assert hashlib.sha256(rendered.pdf).hexdigest() == rendered.file_sha256
    assert rendered.html_1.count(PLACEHOLDER) == 1 and PLACEHOLDER not in rendered.html_2
    assert rendered.html_2 == rendered.html_1.replace(PLACEHOLDER, rendered.content_sha256)
    assert rendered.html_1 == render_html(data, None) and rendered.html_2 == render_html(data, rendered.content_sha256)
    words = pdf_text(rendered.pdf)
    assert rendered.content_sha256 in words and PLACEHOLDER not in words and rendered.file_sha256 not in words
    assert (again.content_sha256, again.file_sha256, again.pdf) == (rendered.content_sha256, rendered.file_sha256, rendered.pdf)


def test_the_pdf_carries_no_date_and_no_identifier_and_its_producer_is_the_library_s_version(monkeypatch):
    """Nothing in the file varies between two renders of one HTML by one
    WeasyPrint: no date, no `/ID`, and the fonts' time is pinned (fontTools'
    `SOURCE_DATE_EPOCH`) when nothing set it, left when something did. The
    Info dictionary is read through pypdf (it is in a compressed stream: the
    review's finding 14) and holds the title and the library's `/Producer`
    alone, so the bytes are one WeasyPrint version's, the one `uv.lock` pins."""
    html = "<!doctype html><html><head><meta charset='utf-8'><title>x</title></head><body><p>x <code>y</code> <b>z</b></p></body></html>"
    monkeypatch.delenv(render.SOURCE_DATE_EPOCH, raising=False)

    first = render_pdf(html)
    assert os.environ[render.SOURCE_DATE_EPOCH] == render.FONT_EPOCH
    monkeypatch.setenv(render.SOURCE_DATE_EPOCH, "1700000000")
    second = render_pdf(html)
    monkeypatch.setenv(render.SOURCE_DATE_EPOCH, render.FONT_EPOCH)
    third = render_pdf(html)

    assert first == third
    assert os.environ[render.SOURCE_DATE_EPOCH] == render.FONT_EPOCH
    assert second.startswith(b"%PDF-")
    import weasyprint

    assert pdf_info(first) == {"/Title": "x", "/Producer": f"WeasyPrint {weasyprint.__version__}"}
    assert "/ID" not in pdf_trailer_keys(first)
    # The reader does see a date when there is one: the same read, on a render that has it.
    dated = render_pdf(html.replace("<title>x</title>", "<title>x</title><meta name='dcterms.created' content='2026-10-01'>"))
    assert set(pdf_info(dated)) == {"/Title", "/Producer", "/CreationDate"}


# --- Interim reports ----------------------------------------------------------------------------


async def test_the_current_month_is_an_interim_report_under_a_key_with_its_time_and_two_of_them_are_two(lab):
    now = dt.datetime(2026, 9, 18, 14, 30, 9, tzinfo=UTC)
    await lab.month()
    keys = [f"msp/{lab.msp_id}/reports/{lab.client_id}/2026-09-interim-20260918T143009Z.pdf", f"msp/{lab.msp_id}/reports/{lab.client_id}/2026-09-interim-20260918T143010Z.pdf"]
    for key in keys:
        lab.expect_put(key)

    first = await make(lab, now=now)
    second = await make(lab, now=now + dt.timedelta(seconds=1))

    assert (first.values["interim"], first.values["storage_key"]) == ("true", keys[0])
    assert (second.values["interim"], second.values["storage_key"]) == ("true", keys[1])
    rows = await report_rows(lab)
    assert [(r.interim, r.storage_key) for r in rows] == [(True, keys[1]), (True, keys[0])]
    # One second apart in the same minute: the same text, so the same bytes
    # and hashes under two keys (the key is not in the PDF).
    assert len(lab.bodies) == 2 and lab.bodies[0] == lab.bodies[1]
    assert (rows[0].content_sha256, rows[0].file_sha256) == (rows[1].content_sha256, rows[1].file_sha256)
    lab.stubber.assert_no_pending_responses()
    words = pdf_text(lab.bodies[0])
    assert "Interim report" in words and "The period is not over" in words
    assert "2026-09-18 14:30 UTC" in words


async def test_a_second_interim_report_in_the_same_second_is_the_key_s_refusal(lab):
    now = dt.datetime(2026, 9, 18, 14, 30, 9, tzinfo=UTC)
    await lab.month()
    lab.expect_put(storage_key(lab.msp_id, lab.client_id, SEPTEMBER, True, now))
    await make(lab, now=now)

    with pytest.raises(RepoError, match="^storage_key: already used$"):
        async with lab.session.begin_nested():
            await make(lab, now=now)

    assert len(lab.bodies) == 1


@pytest.mark.parametrize(
    ("now", "interim"),
    [
        (dt.datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC), True),
        (dt.datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC), False),
        (dt.datetime(2026, 9, 1, 0, 0, 0, tzinfo=UTC), True),
    ],
)
def test_a_report_is_interim_until_the_day_after_its_period_ends(now, interim):
    assert interim_for(SEPTEMBER, now) is interim


async def test_a_final_report_after_an_interim_one_is_taken_and_the_audit_row_names_the_user_and_the_address(lab):
    await lab.month()
    interim_at = dt.datetime(2026, 9, 18, 14, 30, 9, tzinfo=UTC)
    lab.expect_put(storage_key(lab.msp_id, lab.client_id, SEPTEMBER, True, interim_at))
    lab.expect_put(lab.final_key())

    await make(lab, now=interim_at, user_id=lab.admin.id, ip=IP)
    final = await make(lab)

    assert final.values["interim"] == "false"
    rows = await report_rows(lab)
    assert [r.interim for r in rows] == [False, True]
    # Both rows share the transaction's now(), so the list has no order between them.
    assert sorted(await report_audit(lab), key=str) == sorted([("report.create", f"report:{rows[1].id}", lab.admin.id, IP), ("report.create", f"report:{rows[0].id}", None, None)], key=str)


# --- A fixed number of statements (point 5) -----------------------------------------------------


async def test_the_generator_runs_the_same_statements_for_three_runs_and_for_sixty(lab, test_engine):
    async def statements_of(month_runs: int) -> list[str]:
        for i in range(month_runs):
            run = await lab.tested("pass" if i % 3 else "fail", finished_at=at(1 + i % 28, 3, i), recovery_ms=1000 + i)
            await lab.items(run, [an_item(0, match=i % 3 != 0, found=i % 3 != 0, reason=None if i % 3 else "no restored copy found")])
        seen: list[str] = []

        def listen(_conn, _cursor, statement, _params, _context, _executemany):
            seen.append(statement.split()[0].upper())

        event.listen(test_engine.sync_engine, "before_cursor_execute", listen)
        try:
            data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
        finally:
            event.remove(test_engine.sync_engine, "before_cursor_execute", listen)
        assert data.tests == month_runs if month_runs == 3 else data.tests == 60
        return seen

    three = await statements_of(3)
    sixty = await statements_of(57)

    assert three == sixty
    assert three.count("SELECT") == 8 and set(three) == {"SELECT"}


async def test_generate_is_the_nine_reads_the_row_and_the_audit_row_then_the_put(lab, test_engine):
    await lab.month()
    lab.expect_put(lab.final_key())
    seen: list[str] = []
    order: list[str] = []

    def listen(_conn, _cursor, statement, _params, _context, _executemany):
        seen.append(statement.split()[0].upper())
        order.append("sql")

    lab.storage.client.meta.events.register("before-parameter-build.s3.PutObject", lambda **_kw: order.append("put"))
    event.listen(test_engine.sync_engine, "before_cursor_execute", listen)
    try:
        await make(lab)
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", listen)

    # The read for a final report the month has (first, C6.6), the eight reads of `gather`, the row, the audit row, then the put.
    assert seen == ["SELECT"] * 9 + ["INSERT", "INSERT"]
    assert order == ["sql"] * 11 + ["put"]


async def test_rendering_runs_in_a_thread_never_on_the_loop(lab, monkeypatch):
    await lab.month()
    lab.expect_put(lab.final_key())
    threads: list[bool] = []
    real = render.render_report

    def spy(data):
        threads.append(asyncio.get_event_loop_policy() is not None and _in_worker_thread())
        return real(data)

    monkeypatch.setattr("app.report.generate.render_report", spy)

    await make(lab)

    assert threads == [True]


def _in_worker_thread() -> bool:
    import threading

    return threading.current_thread() is not threading.main_thread()


# --- The period (point 4) -----------------------------------------------------------------------


def test_period_of_names_the_month_s_two_dates_and_its_span():
    period = period_of("2026-02")

    assert (period.start, period.end, period.name, period.title) == (dt.date(2026, 2, 1), dt.date(2026, 2, 28), "2026-02", "February 2026")
    assert (period.start_at, period.end_at) == (dt.datetime(2026, 2, 1, tzinfo=UTC), dt.datetime(2026, 3, 1, tzinfo=UTC))
    assert period_of("2028-02").end == dt.date(2028, 2, 29)
    assert period_of("2026-12").end_at == dt.datetime(2027, 1, 1, tzinfo=UTC)
    assert period_of("2026-09") == SEPTEMBER


@pytest.mark.parametrize(("today", "expected"), [(dt.date(2026, 10, 1), "2026-09"), (dt.date(2026, 1, 15), "2025-12"), (dt.date(2026, 3, 31), "2026-02")])
def test_the_previous_month_is_the_cli_s_default(today, expected):
    assert previous_month(today) == period_of(expected)


def test_the_storage_key_is_the_issue_s_for_a_final_report_and_carries_the_time_for_an_interim_one():
    msp_id, client_id = uuid.UUID("11111111-1111-4111-8111-111111111111"), uuid.UUID("22222222-2222-4222-8222-222222222222")
    now = dt.datetime(2026, 9, 18, 14, 30, 9, 123456, tzinfo=UTC)

    assert storage_key(msp_id, client_id, SEPTEMBER, False, now) == f"msp/{msp_id}/reports/{client_id}/2026-09.pdf"
    assert storage_key(msp_id, client_id, SEPTEMBER, True, now) == f"msp/{msp_id}/reports/{client_id}/2026-09-interim-20260918T143009Z.pdf"


# --- The frameworks (point 3) and the environment (point 7) -------------------------------------


def test_the_four_controls_are_named_by_their_own_words_and_each_has_its_two_sentences():
    """C6.7: the SOC 2 row by the criteria's own words (the issue's "recovery
    procedures tested" was a gloss); the sentences themselves are held
    verbatim by tests/test_report_wording.py."""
    assert [control.identifier for control in frameworks.CONTROLS] == [
        "ISO/IEC 27001:2022 A.8.13", "SOC 2 (2017 TSC) Availability A1.2 and A1.3", "HIPAA 45 CFR 164.308(a)(7)(ii)(D)", "DORA, Regulation (EU) 2022/2554, Article 12",
    ]
    assert all(control.name and control.demonstrates and control.not_covered for control in frameworks.CONTROLS)
    assert "Recovery procedures tested" not in [c.name for c in frameworks.CONTROLS]
    assert "A1.2: …" in frameworks.CONTROLS[1].name and "A1.3: the entity tests recovery plan procedures" in frameworks.CONTROLS[1].name
    assert "not an assessment of the control" in frameworks.ABOUT and "C6.7" not in frameworks.ABOUT


def test_the_report_s_environment_autoescapes_with_strict_undefined_and_the_pages_filters():
    env = render.environment()

    assert env.autoescape is True and env.undefined is ui.StrictUndefined
    assert env.from_string("{{ x }}").render(x="<b>") == "&lt;b&gt;"
    assert {"utc", "duration", "colour", "yes_no"} <= set(env.filters)
    assert env.list_templates(extensions=["html"]) == ["template.html"]
    with pytest.raises(Exception, match="undefined"):
        env.from_string("{{ nothing }}").render()


@pytest.mark.parametrize(
    ("counts", "overall", "errors"),
    [
        ((0, 0, 0, 0), "No test ran in this period", None),
        ((1, 1, 0, 0), "The 1 test passed", None),
        ((3, 3, 0, 0), "All 3 tests passed", None),
        ((4, 2, 1, 1), "1 of 4 tests failed", "1 of 4 tests could not run (error)"),
        ((1, 0, 1, 0), "1 of 1 test failed", None),
        ((3, 1, 0, 2), "1 of 3 tests passed", "2 of 3 tests could not run (error)"),
        ((1, 0, 0, 1), "0 of 1 test passed", "1 of 1 test could not run (error)"),
    ],
)
def test_the_overall_line_keeps_fail_and_error_apart(counts, overall, errors):
    from app.report.data import overall_line

    assert overall_line(*counts) == (overall, errors)


def test_the_backup_source_is_each_connector_type_once_and_not_recorded_without_one():
    """`build` by itself on plain rows: two connectors of one type give the
    word once; a type the Cloud doesn't know, or no connector, is 'not recorded'."""
    from types import SimpleNamespace

    from app.report.data import UNKNOWN_SOURCE, build

    now = dt.datetime(2026, 10, 1, tzinfo=UTC)
    msp, client = SimpleNamespace(name="m"), SimpleNamespace(name="c")
    expired = SimpleNamespace(
        id=uuid.uuid4(), state="expired", finished_at=None, created_at=at(15), restore_point_at=None, recovery_ms=None,
        bundle_sha256=None, tsa_ok=None, tsa_time=None, worker_id=uuid.uuid4(), error_code=None, error_message=None,
        plan_id=uuid.uuid4(), cleanup_ok=None, dispatched_at=at(15, 2, 1),
    )

    def made(connectors):
        return build(msp, client, SEPTEMBER, now=now, connectors=connectors, plans=[], workers=[], runs=[expired], counts=[], unmatched=[])

    assert made([SimpleNamespace(type="veeam_m365"), SimpleNamespace(type="veeam_m365")]).backup_source == "Veeam Backup for Microsoft 365"
    assert made([SimpleNamespace(type="veeam_m365"), SimpleNamespace(type="other_backup")]).backup_source == "Veeam Backup for Microsoft 365, not recorded"
    assert made([]).backup_source == UNKNOWN_SOURCE
    assert made([]).overall == "No test ran in this period" and made([]).did_not_run == 1


async def test_the_repo_refuses_a_naive_generation_time_before_any_row(lab):
    with pytest.raises(ValueError, match="without a zone"):
        await ReportRepo(lab.session).create(
            lab.msp_id, lab.client_id, period_start=SEPTEMBER.start, period_end=SEPTEMBER.end, storage_key="k",
            content_sha256="ab" * 32, file_sha256="cd" * 32, interim=False, generated_at=dt.datetime(2026, 10, 1),
        )
    assert await report_rows(lab) == []


def test_the_generator_s_clock_is_the_cloud_s_in_utc():
    from app.report import generate as generate_module

    stamp = generate_module.now()

    assert stamp.tzinfo is not None and stamp.utcoffset() == dt.timedelta(0)
    assert abs((dt.datetime.now(UTC) - stamp).total_seconds()) < 5


async def test_report_data_is_frozen_and_names_the_backup_source_from_the_connector_s_type(lab):
    await lab.month()

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    assert isinstance(data, ReportData)
    assert data.backup_source == "Veeam Backup for Microsoft 365"
    assert [(w.name, w.key_id) for w in data.workers] == [("w1", "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9")]
    assert [(p.mail, p.sp, p.od) for p in data.plans] == [(0, 1, 1)]
    with pytest.raises(Exception):
        data.tests = 0  # type: ignore[misc]


# --- The C6.4 review (docs/decisions.md 2026-10-13, "C6.4 code review") -------------------------


@pytest.mark.parametrize(
    ("found", "match", "word"),
    [
        (False, False, "missing"),
        (True, False, "mismatch"),
        (None, False, "mismatch"),
        # The Worker's check outcome `error` (its target could not be read) is
        # stored as not found with `match` unknown: never "missing".
        (False, None, "not checked"),
        (None, None, "not checked"),
        (True, None, "not checked"),
    ],
)
def test_an_item_the_worker_could_not_check_is_never_called_missing(found, match, word):
    """Finding 1."""
    assert found_word(an_item(0, found=found, match=match)) == word


async def test_a_fail_beside_an_unreadable_target_prints_missing_for_the_missing_item_alone(lab):
    """Finding 1, through the rows and the page."""
    run = await lab.tested("fail", finished_at=at(3), recovery_ms=1000)
    await lab.items(run, [
        an_item(0, name="gone", found=False, match=False, reason="no restored copy found"),
        an_item(1, type="onedrive", name="rp-canary-11.pdf", found=False, match=None, reason="the onedrive restore target couldn't be read (graph_permission)"),
    ])

    html = render_html(await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time), None)

    assert '<td>gone</td><td>missing</td>' in html
    assert '<td>rp-canary-11.pdf</td><td>not checked</td>' in html


async def test_a_month_whose_worker_was_off_is_reported_and_reads_as_no_month_of_passes(lab):
    """Finding 2: three passes, then the Worker goes off and the scheduler's
    runs stay queued. They are in the report as runs with no result, and a
    month of queued runs alone is still a report (it was `no run in the
    period`)."""
    for day in (1, 2, 3):
        await lab.tested("pass", finished_at=at(day), recovery_ms=1000)
    for day in range(4, 31):
        await lab.make_run(state="queued", created_at=at(day))

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    html = render_html(data, None)

    assert (data.tests, data.passed, data.did_not_run, data.no_result) == (3, 3, 0, 27)
    assert "All 3 tests passed" in html
    assert '<p class="overall quiet">Scheduled tests with no result when this report was made: 27</p>' in html
    assert html.count('<span class="state quiet">no result yet</span>') == 27

    await lab.session.execute(text("UPDATE test_run SET state = 'queued', finished_at = NULL WHERE client_id = :c"), {"c": lab.client_id})
    alone = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    assert (alone.tests, alone.no_result, alone.overall, alone.overall_class) == (0, 30, "No test ran in this period", "quiet")


async def test_a_run_handed_out_in_a_month_and_expired_after_its_report_is_in_that_month_s_report(lab):
    """Finding 2 (b): queued on the 30th, still dispatched when September's
    final report is made; whatever becomes of it, September said it had no
    result."""
    await lab.tested("pass", finished_at=at(29), recovery_ms=1000)
    late = await lab.make_run(state="dispatched", created_at=at(30, 20), dispatched_at=at(30, 20, 1))

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=dt.datetime(2026, 10, 1, 3, tzinfo=UTC))

    assert [(line.run_id, line.result, line.date) for line in data.runs if line.run_id == late] == [(late, "no result yet", at(30, 20))]
    assert data.no_result == 1


@pytest.mark.parametrize(
    ("columns", "expected"),
    [
        ({"finished_at": at(12, 2, 30), "tsa_time": at(12, 2, 31), "dispatched_at": at(12, 2, 1)}, at(12, 2, 30)),
        ({"finished_at": None, "tsa_time": at(12, 2, 31), "dispatched_at": at(12, 2, 1)}, at(12, 2, 31)),
        ({"finished_at": None, "tsa_time": None, "dispatched_at": at(12, 2, 1)}, at(12, 2, 1)),
        ({"finished_at": None, "tsa_time": None, "dispatched_at": None}, at(12, 2, 0)),
    ],
)
async def test_a_result_written_afterwards_is_dated_by_its_stamp_then_its_dispatch_never_its_queueing(lab, columns, expected):
    """Finding 3: the Worker's `interrupted`, `internal`, `job_invalid` and
    the like carry no `ended_at`."""
    run = await lab.make_run(state="error", created_at=at(12, 2, 0), error_code="interrupted", **columns)

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    (line,) = data.runs
    assert (line.run_id, line.date) == (run, expected)


async def test_a_pass_that_ended_before_an_interrupted_run_began_is_no_later_test_of_it(lab):
    """Finding 3's scenario: R1 queued 01:55 and passed 02:20; R2 queued
    02:00, handed out 02:21 and closed afterwards as `error interrupted`. By
    queue time the error stood above the pass and was 're-tested' by it."""
    passed = await lab.tested("pass", created_at=at(5, 1, 55), finished_at=at(5, 2, 20), recovery_ms=1000)
    interrupted = await lab.make_run(
        state="error", created_at=at(5, 2, 0), dispatched_at=at(5, 2, 21), tsa_time=at(5, 3, 40), error_code="interrupted", error_message="the run was interrupted",
    )

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    assert [line.run_id for line in data.runs] == [passed, interrupted]
    (failure,) = data.failures
    assert failure.line.date == at(5, 3, 40) and failure.retested_at is None


async def test_a_result_written_afterwards_is_the_month_s_it_was_stamped_in(lab):
    """Finding 3: queued on September's last minutes, closed in October."""
    run = await lab.make_run(state="error", created_at=at(30, 23, 58), dispatched_at=at(30, 23, 59), tsa_time=at(1, 0, 4, month=10), error_code="interrupted")
    await lab.tested("pass", finished_at=at(2), recovery_ms=1000)

    september = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    october = await gather(lab.session, lab.msp_id, lab.client_id, period_of("2026-10"), now=lab.time)

    assert run not in [line.run_id for line in september.runs]
    assert [line.run_id for line in october.runs] == [run]


def test_run_date_is_the_rule_of_the_statement_on_a_row():
    """`run_date` and `period_time` are one rule: every other state by its
    creation, whatever else the row holds."""
    from types import SimpleNamespace

    times = dict(finished_at=at(2), tsa_time=at(3), dispatched_at=at(4), created_at=at(1))

    for state in ("pass", "fail", "error"):
        assert run_date(SimpleNamespace(state=state, **times)) == at(2)
    for state in ("expired", "queued", "dispatched"):
        assert run_date(SimpleNamespace(state=state, **times)) == at(1)


async def test_an_error_whose_items_all_matched_does_not_say_no_item_was_checked(lab):
    """Finding 4: the Worker's `restore_contradiction`."""
    run = await lab.tested("error", finished_at=at(3), error_code="restore_contradiction", error_message="the evidence contradicts itself")
    await lab.items(run, [an_item(0), an_item(1, type="onedrive", name="a.pdf")])

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    html = render_html(data, None)

    (failure,) = data.failures
    assert failure.items == [] and failure.line.items == 2
    assert "<p>Every item that was checked matched.</p>" in html and "No item was checked." not in html


async def test_an_error_s_recovery_span_and_restore_point_are_no_part_of_the_summary(lab):
    """Finding 5: an error is a test that could not run."""
    await lab.tested("pass", finished_at=at(3), recovery_ms=2706000, restore_point_at=at(2, 23))
    await lab.tested("fail", finished_at=at(4), recovery_ms=1000000, restore_point_at=at(3, 23))
    await lab.tested("error", finished_at=at(5), recovery_ms=3600000, restore_point_at=at(4, 23), error_code="backup_transient")

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    html = render_html(data, None)

    assert (data.tests, data.ran) == (3, 2)
    assert (data.average_recovery_ms, data.max_recovery_ms) == (1853000, 2706000)
    assert data.restore_points == [at(2, 23), at(3, 23)]
    assert "<dt>Restore points covered</dt><dd>2, from 2026-09-02 23:00 UTC to 2026-09-03 23:00 UTC</dd>" in html
    assert "The recovery times and the restore points above are those of the tests that passed or failed." in html


async def test_a_month_in_which_nothing_ran_claims_no_restore_no_level_and_no_plan(lab):
    """Finding 6: the fixed sentences said 'restored and verified' and
    'levels covered' for a month of expired runs."""
    await lab.make_run(state="expired", created_at=at(15))
    await lab.tested("error", finished_at=at(16), error_code="veeam_unreachable")

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    html = render_html(data, None)

    assert (data.ran, data.files_sampled) == (0, False)
    assert "restored and verified" not in html and "Verification levels covered" not in html
    assert "<p>No test of this period reached the comparison, so no verification level was covered.</p>" in html
    assert "It records what each test listed here found for the items it sampled, on the dates shown." in html
    # The error run is the plan's, so the plan is named; an expired run alone names none.
    assert "Each test of the plan samples up to 0 mails, 1 SharePoint file and 1 OneDrive file" in html
    await lab.session.execute(text("UPDATE test_run SET state = 'expired' WHERE client_id = :c"), {"c": lab.client_id})
    none = render_html(await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time), None)
    assert "<p>No test of a plan has a result in this period.</p>" in none and "Each test of the plan" not in none


async def test_the_method_names_the_plans_that_were_tested_and_level_four_only_when_a_file_was_sampled(lab):
    """Finding 6: a plan made after the period, or with no run in it, is not
    the month's; a month of mails alone opened no file."""
    mails = (await PlanRepo(lab.session).create(
        lab.msp_id, lab.client_id, lab.inner.connector_id, sample_mail=100, sample_sp=0, sample_od=0, cadence_cron="0 4 * * *", now=NOW
    )).id
    run = await lab.tested("pass", finished_at=at(3), recovery_ms=1000, plan_id=mails, cleanup_ok=False)
    await lab.items(run, [an_item(0)])

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    html = render_html(data, None)

    assert [(p.mail, p.sp, p.od) for p in data.plans] == [(100, 0, 0)]
    assert "<p>Verification levels covered: 1, 2, 3.</p>" in html and "level 4" not in html
    assert "<p>In 1 test of this period the removal from the restore target did not complete.</p>" in html
    assert "by its sender's name when the backup lists one" in html and "unless it is an Office document, its size" in html
    # A file sampled by a test that ran: level 4 partially; two tests whose clean-up did not complete.
    files = await lab.tested("fail", finished_at=at(4), recovery_ms=1000, cleanup_ok=False)
    await lab.items(files, [an_item(0, type="sharepoint", name="a.docx", found=False, match=False)])
    both = render_html(await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time), None)
    assert "<p>Verification levels covered: 1, 2, 3; level 4 partially (files opened and read via Microsoft Graph).</p>" in both
    assert "<p>In 2 tests of this period the removal from the restore target did not complete.</p>" in both
    assert both.count("Each test of the plan samples up to") == 2


async def test_a_pass_of_another_plan_is_no_later_test_of_a_failure(lab):
    """Finding 7: a SharePoint plan fails on the 10th, a mail plan passes on
    the 11th; the failure's own plan passes on the 20th."""
    mails = (await PlanRepo(lab.session).create(
        lab.msp_id, lab.client_id, lab.inner.connector_id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 4 * * *", now=NOW
    )).id
    failed = await lab.tested("fail", finished_at=at(10), recovery_ms=1000)
    await lab.items(failed, [an_item(0, type="sharepoint", name="Budget 2026.xlsx", found=False, match=False)])
    await lab.tested("pass", finished_at=at(11), recovery_ms=1000, plan_id=mails)

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    assert [failure.retested_at for failure in data.failures] == [None]
    assert "No later test of the same plan passed in this period." in render_html(data, None)

    await lab.tested("pass", finished_at=at(20), recovery_ms=1000)
    await lab.tested("pass", finished_at=at(22), recovery_ms=1000)
    again = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    assert [failure.retested_at for failure in again.failures] == [at(20)]
    assert "A later test of the same plan passed on 2026-09-20 02:00 UTC." in render_html(again, None)


@pytest.mark.parametrize(
    ("counts", "colour"),
    [((0, 0, 0), "quiet"), ((3, 0, 0), "pass"), ((3, 1, 0), "fail"), ((3, 1, 1), "fail"), ((3, 0, 2), "error")],
)
def test_the_headline_of_a_month_without_a_test_is_not_in_the_pass_colour(counts, colour):
    """Finding 8."""
    assert overall_class(*counts) == colour


async def test_a_month_of_expired_runs_alone_has_a_quiet_headline(lab):
    """Finding 8, on the page."""
    await lab.make_run(state="expired", created_at=at(15))

    html = render_html(await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time), None)

    assert '<p class="overall quiet">No test ran in this period</p>' in html and 'class="overall pass"' not in html


async def test_no_text_of_the_report_is_laid_out_past_the_page(lab):
    """Finding 9: a run id whose groups all begin with a digit has no place a
    line may break, and the Runs table was wider than the paper; the same for
    a Worker's id, a hash and an item's name without a space."""
    import dataclasses

    await lab.month()
    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    solid = uuid.UUID("11111111-2222-4333-8444-555555555555")
    failures = [
        dataclasses.replace(failure, items=[dataclasses.replace(item, name="x" * 200, reason="y" * 200) for item in failure.items])
        for failure in data.failures
    ]
    wide = dataclasses.replace(
        data,
        runs=[dataclasses.replace(line, run_id=solid, bundle_sha256="1" * 64) for line in data.runs],
        workers=[dataclasses.replace(worker, id=solid, name="w" * 60, key_id="2" * 64) for worker in data.workers],
        failures=failures,
        client_name="c" * 120,
    )

    assert past_the_page(render_html(wide, "3" * 64)) == []
    assert past_the_page(render_html(data, None)) == []



# --- C6.6: the job's read of a month's clients (docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7", point 1) ---


async def test_clients_in_period_names_each_client_with_a_run_of_the_month_once_whatever_its_state(lab):
    """The second client's run of the month counts; a client whose only run
    is expired counts (its report says so); a client whose runs are all
    outside the month does not; another MSP's never; a naive time is refused."""
    from app.repo.runs import RunRepo
    from tests.test_pages import make_client

    await lab.month()
    third, third_connector, third_plan = await make_client(lab, "third")
    fourth, fourth_connector, fourth_plan = await make_client(lab, "fourth")
    await lab.make_run(state="expired", created_at=at(3), client_id=third.id, plan_id=third_plan.id, connector_id=third_connector.id)
    await lab.tested("pass", finished_at=at(3, month=10), client_id=fourth.id, plan_id=fourth_plan.id, connector_id=fourth_connector.id)
    repo = RunRepo(lab.session)

    september = await repo.clients_in_period(lab.msp_id, start=SEPTEMBER.start_at, end=SEPTEMBER.end_at)
    october = await repo.clients_in_period(lab.msp_id, start=OCTOBER_START, end=OCTOBER_START + dt.timedelta(days=31))

    assert sorted(september) == sorted([lab.client_id, lab.client2_id, third.id])
    assert sorted(october) == sorted([lab.client_id, fourth.id])
    assert await repo.clients_in_period(lab.b_msp_id, start=SEPTEMBER.start_at, end=SEPTEMBER.end_at) == []
    with pytest.raises(ValueError, match="without a zone"):
        await repo.clients_in_period(lab.msp_id, start=dt.datetime(2026, 9, 1), end=SEPTEMBER.end_at)


# --- C6.6: the cap on a month of thousands of runs (docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7", point 3) ---


def _plain_run(i: int, state: str) -> object:
    from types import SimpleNamespace

    finished = at(1 + i % 28, 3, i % 60, i // 60 % 60) if state in ("pass", "fail", "error") else None
    return SimpleNamespace(
        id=uuid.UUID(int=i + 1), state=state, finished_at=finished, created_at=at(1 + i % 28, 2, i % 60, i // 60 % 60), restore_point_at=at(1 + i % 28, 1),
        recovery_ms=1000 + i, bundle_sha256=None, tsa_ok=None, tsa_time=None, worker_id=uuid.UUID(int=99), error_code=None, error_message=None,
        plan_id=uuid.UUID(int=98), cleanup_ok=True, dispatched_at=None,
    )


@pytest.mark.parametrize(("total", "listed", "left"), [(200, 200, 0), (201, 200, 1), (1000, 200, 800)])
def test_build_lists_the_first_200_runs_and_failures_in_order_and_counts_every_run(total, listed, left):
    from types import SimpleNamespace

    from app.report.data import MAX_LOG_ROWS, build

    runs = [_plain_run(i, "fail") for i in range(total)]
    data = build(SimpleNamespace(name="m"), SimpleNamespace(name="c"), SEPTEMBER, now=dt.datetime(2026, 10, 1, tzinfo=UTC), connectors=[], plans=[], workers=[], runs=runs, counts=[], unmatched=[])

    assert MAX_LOG_ROWS == 200
    assert (len(data.runs), data.runs_left_out) == (listed, left)
    assert (len(data.failures), data.failures_left_out) == (listed, left)
    assert [line.run_id for line in data.runs] == [run.id for run in runs[:listed]]
    assert [failure.line.run_id for failure in data.failures] == [run.id for run in runs[:listed]]
    # The Summary counts every run.
    assert (data.tests, data.failed, data.ran) == (total, total, total)
    assert data.overall == f"{total} of {total} tests failed"
    assert data.max_recovery_ms == 1000 + total - 1 and len(data.restore_points) == 28


async def test_a_capped_month_says_how_many_runs_are_not_listed_in_both_passes_and_the_pdf(lab, monkeypatch):
    """The lab's September has seven runs; with the cap at five, two are left
    out of the log and the run list, and the Summary still counts four tests."""
    from app.report import data as report_data

    runs = await lab.month()
    monkeypatch.setattr(report_data, "MAX_LOG_ROWS", 5)

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    rendered = render_report(data)

    assert (len(data.runs), data.runs_left_out, data.tests, data.failures_left_out) == (5, 2, 4, 0)
    assert [line.run_id for line in data.runs][-1] == runs["errored"] and runs["vector"] not in [line.run_id for line in data.runs]
    for html in (rendered.html_1, rendered.html_2):
        assert html.count("2 more tests of this period are not listed here; the Cloud's pages hold every one.") == 2
        assert "<dt>Tests run</dt><dd>4</dd>" in html
        assert html.count(f"<code>{runs['vector']}</code>") == 0
    words = pdf_text(rendered.pdf)
    assert words.count("2 more tests of this period are not listed here") == 2 and "1 of 4 tests failed" in words
