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
from app.report.data import Period, ReportData, gather, interim_for, period_of, previous_month
from app.report.generate import generate, storage_key
from app.report.render import PLACEHOLDER, Rendered, render_html, render_pdf, render_report
from app.repo.audit import AuditRepo
from app.repo.errors import RepoError
from app.repo.reports import ReportRepo
from tests.pages_lab import IP, UTC
from tests.report_lab import OCTOBER_START, SEPTEMBER, SEPTEMBER_START, VECTOR_HASH, ReportLab, an_item, at, page_count, pdf_text
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
        "This report does not test full disaster recovery", "Re-tested and passed on 2026-09-25 02:20 UTC",
        "A file cannot contain its own hash", row.content_sha256, "not part of this report yet",
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
    order = [log.index(f"<code>{short[name]}</code>") for name in ("failed", "expired", "errored", "later", "vector")]
    assert order == sorted(order) and log.count("<tr>") == 6  # the header's row and five runs
    for needle in (
        "<td>2026-09-10 02:30 UTC</td><td>2026-09-09 23:00 UTC</td><td>1 / 1 / 1</td><td><span class=\"state fail\">fail</span></td><td>1:05</td>",
        "<td>2026-09-15 02:00 UTC</td><td>—</td><td>0 / 0 / 0</td><td><span class=\"state quiet\">did not run</span></td><td>—</td>",
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
    assert failures.count("<p class=\"retest\">Re-tested and passed on 2026-09-25 02:20 UTC.</p>") == 2
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
        "<dt>Generated</dt><dd>2026-10-01 03:00 UTC</dd>",
    ):
        assert needle in integrity, needle
    assert html.count("w2") == 0  # a Worker with no run in the month
    # Framework mapping: the four controls and the pending sentence.
    mapping = html[html.index('<h2 id="framework-mapping">'):]
    for needle in ("ISO/IEC 27001:2022 A.8.13", "SOC 2 Availability A1.2, A1.3", "HIPAA 45 CFR 164.308(a)(7)(ii)(D)", "DORA Regulation (EU) 2022/2554 Article 12", frameworks.PENDING):
        assert needle in mapping, needle
    assert mapping.count("<td>—</td>") == 8


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


@pytest.mark.parametrize("period_text", ["2026-9", "2026-09-01", "September 2026", "2026/09", "", "2026-13", "2026-00", "x"])
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


async def test_a_put_that_fails_raises_the_library_s_error_and_the_row_is_rolled_back_with_it(lab):
    await lab.month()
    lab.stubber.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)

    with pytest.raises(ClientError):
        async with lab.session.begin_nested():
            await make(lab)

    assert await report_rows(lab) == []
    assert await report_audit(lab) == []


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


async def test_the_month_s_runs_are_the_tested_ones_by_their_end_and_the_expired_ones_by_creation(lab):
    runs = await lab.month()
    edge_in = await lab.tested("pass", finished_at=SEPTEMBER_START, recovery_ms=1000)
    edge_out = await lab.tested("pass", finished_at=OCTOBER_START, recovery_ms=1000)
    fallback = await lab.make_run(state="error", created_at=at(18), finished_at=None, error_code="interrupted")

    data = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)

    ids = [line.run_id for line in data.runs]
    assert ids == [edge_in, runs["failed"], runs["expired"], fallback, runs["errored"], runs["later"], runs["vector"]]
    assert edge_out not in ids and runs["theirs"] not in ids
    assert [line.result for line in data.runs] == ["pass", "fail", "did not run", "error", "error", "pass", "pass"]
    assert (data.tests, data.passed, data.failed, data.errored, data.did_not_run) == (6, 3, 1, 2, 1)
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
    assert "No later test in this period passed." in rendered.html_2
    assert "1 of 2 tests failed" in rendered.html_2
    assert data.errors_line is None
    # Passes alone.
    await lab.session.execute(text("UPDATE test_run SET state = 'pass' WHERE id = :id"), {"id": failed})
    alone = await gather(lab.session, lab.msp_id, lab.client_id, SEPTEMBER, now=lab.time)
    assert alone.overall == "All 2 tests passed"
    assert alone.failures == [] and alone.did_not_run == 0
    assert "No test failed or errored in this period." in render_html(alone, None)
    assert "Scheduled tests that did not run" not in render_html(alone, None)


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


def test_the_pdf_carries_no_date_no_identifier_and_no_producer_of_its_own(monkeypatch):
    """WeasyPrint's defaults (shown in the entry's probe): nothing in the file
    varies between two renders of one HTML, and the fonts' time is pinned
    (fontTools' `SOURCE_DATE_EPOCH`) when nothing set it, left when something did."""
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
    for key in (b"/CreationDate", b"/ModDate", b"/ID", b"/Producer"):
        assert key not in first


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

    # The eight reads of `gather`, the read for a final report the month has, the row, the audit row, then the put.
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


def test_the_four_controls_are_named_and_their_two_columns_wait_for_c6_7():
    assert [control.identifier for control in frameworks.CONTROLS] == [
        "ISO/IEC 27001:2022 A.8.13", "SOC 2 Availability A1.2, A1.3", "HIPAA 45 CFR 164.308(a)(7)(ii)(D)", "DORA Regulation (EU) 2022/2554 Article 12",
    ]
    assert all(control.name for control in frameworks.CONTROLS)
    assert all(control.demonstrates is None and control.not_covered is None for control in frameworks.CONTROLS)
    assert "not part of this report yet" in frameworks.PENDING and "C6.7" in frameworks.PENDING


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
