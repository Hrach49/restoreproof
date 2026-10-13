"""C6.6 (docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7", point 2), the
Done-when by name: an interim report is downloadable from the dashboard
within a minute of clicking. Failure paths first (another MSP's client,
report and button; no session; another site; the cap; the client's row
held by another click; the slot; a client with nothing this month; a put and
a render that fail), then the list, the
download, the button, the nav entry, the planted script and the statement
counts; the repo's `page` read by itself.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import time
import uuid
from urllib.parse import urlsplit

import pytest
from sqlalchemy import event, text

from app import audit as words
from app.report import generate as report_generate
from app.report.data import month_of
from app.report.generate import storage_key
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.reports import PAGE_SIZE, ReportRepo, ReportRow
from app.routers.ui import reports as page
from app.routers.ui.reports import GENERATE_EVERY, RENDER_WAIT_S, capped, next_minute
from tests.report_lab import ReportLab, period_of
from tests.results_lab import NOW
from tests.test_pages import SCRIPT, ESCAPED

UTC = dt.timezone.utc
# The pages' clock: a day of October 2026, the month the lab's vector pass and
# its October run are in, whatever the real calendar says.
TODAY = dt.datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)
OCTOBER = month_of(TODAY.date())
IP = "10.2.2.2"


@pytest.fixture
async def lab(session, monkeypatch) -> ReportLab:
    lab = ReportLab(session, monkeypatch)
    await lab.fill()
    lab.time = TODAY
    return lab


def interim_key(lab: ReportLab, at: dt.datetime | None = None, client_id=None) -> str:
    return storage_key(lab.msp_id, client_id or lab.client_id, OCTOBER, True, at or lab.time)


async def a_report(lab: ReportLab, *, client_id=None, period="2026-09", interim=False, generated_at=NOW, msp_id=None) -> uuid.UUID:
    """A report row by hand (no object behind it): what the pages list."""
    month = period_of(period)
    stamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    key = f"msp/{msp_id or lab.msp_id}/reports/{client_id or lab.client_id}/{month.name}{'-interim-' + stamp if interim else ''}.pdf"
    row = await ReportRepo(lab.session).create(
        msp_id or lab.msp_id, client_id or lab.client_id, period_start=month.start, period_end=month.end, storage_key=key,
        content_sha256=uuid.uuid5(uuid.NAMESPACE_DNS, key).hex * 2, file_sha256=uuid.uuid5(uuid.NAMESPACE_URL, key).hex * 2,
        interim=interim, generated_at=generated_at,
    )
    return row.id


async def rows_of(lab: ReportLab, msp_id=None):
    return await ReportRepo(lab.session).list(msp_id or lab.msp_id)


async def report_audit(lab: ReportLab, msp_id=None):
    return [(r.action, r.target, r.user_id, r.ip) for r in await AuditRepo(lab.session).list(msp_id or lab.msp_id) if r.action.startswith("report.")]


def main_text(html: str) -> str:
    return html[html.index("<main>"):]


# --- The Done-when, by name ---------------------------------------------------------------------


async def test_an_interim_report_is_downloadable_from_the_dashboard_within_a_minute_of_clicking(lab):
    await lab.month()
    final = await a_report(lab)  # September's, so the list has an older row to stand under the new one
    key = interim_key(lab)
    lab.expect_put(key)

    clicked = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member, ip=IP, headers={"Sec-Fetch-Site": "same-origin"})
    listed = await lab.get(f"/clients/{lab.client_id}/reports", lab.member)
    (row,) = [r for r in await rows_of(lab) if r.id != final]
    download = await lab.get(f"/reports/{row.id}/file", lab.member, ip=IP, headers={"Sec-Fetch-Site": "same-origin"})

    assert (clicked.status_code, clicked.headers["location"]) == (303, f"/clients/{lab.client_id}/reports")
    assert listed.status_code == 200
    text_ = main_text(listed.text)
    # The new report's row stands above September's: the rows' own links, not words the page's help text has too.
    assert 0 < text_.index(f"/reports/{row.id}/file") < text_.index(f"/reports/{final}/file")
    assert "<td>interim</td>" in text_ and "<td>final</td>" in text_
    for needle in ("2026-10", "interim", "2026-10-13 10:00 UTC", row.content_sha256, row.file_sha256, f"/reports/{row.id}/file", "Generate now"):
        assert needle in text_, needle
    assert (row.interim, row.period_start, row.storage_key, row.generated_at) == (True, dt.date(2026, 10, 1), key, TODAY)
    assert download.status_code == 302 and download.headers["cache-control"] == "no-store"
    url = urlsplit(download.headers["location"])
    assert (url.netloc, url.path) == ("127.0.0.1:1", f"/{lab.settings.s3_bucket}/{key}")
    assert "X-Amz-Signature" in url.query and f"X-Amz-Expires=600" in url.query
    (pdf,) = lab.bodies
    assert pdf.startswith(b"%PDF-") and hashlib.sha256(pdf).hexdigest() == row.file_sha256
    lab.stubber.assert_no_pending_responses()
    assert sorted(await report_audit(lab)) == sorted([("report.create", f"report:{row.id}", lab.member.id, IP), ("report.download", f"report:{row.id}", lab.member.id, IP)])
    # "Within a minute" is not timed here: the render's seconds are the
    # machine's (the by-hand run on the stack times the click to the bytes),
    # and what bounds them is the cap on the rows (tests/test_report.py).
    # The page itself holds no link to the bucket.
    assert "X-Amz" not in listed.text and "127.0.0.1:1" not in listed.text


# --- Failure paths ------------------------------------------------------------------------------


async def test_another_msp_s_client_report_and_button_are_404_with_nothing_written(lab, monkeypatch):
    monkeypatch.setattr(report_generate, "render_report", lambda data: pytest.fail("rendered"))
    mine = await a_report(lab)
    theirs = await a_report(lab, client_id=lab.b_client_id, msp_id=lab.b_msp_id)
    before = await lab.written()

    answers = [
        await lab.get(f"/clients/{lab.client_id}/reports", lab.b_admin),
        await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.b_admin),
        await lab.get(f"/reports/{mine}/file", lab.b_admin),
        await lab.get(f"/clients/{lab.b_client_id}/reports", lab.member),
        await lab.post(f"/clients/{lab.b_client_id}/reports/generate", lab.admin),
        await lab.get(f"/reports/{theirs}/file", lab.admin),
    ]

    assert [a.status_code for a in answers] == [404] * 6
    assert await lab.written() == before
    assert "location" not in answers[2].headers and "location" not in answers[5].headers
    # Neither list shows the other's row.
    assert str(theirs) not in (await lab.get("/reports", lab.admin)).text
    assert str(mine) not in (await lab.get("/reports", lab.b_admin)).text


@pytest.mark.parametrize("path", ["/reports", "/clients/{client}/reports", "/reports/{report}/file"])
async def test_a_page_without_a_session_sends_the_browser_to_the_form_and_an_htmx_request_401(lab, path):
    report = await a_report(lab)
    path = path.format(client=lab.client_id, report=report)
    before = await lab.written()

    browser = await lab.get(path)
    htmx = await lab.get(path, headers={"HX-Request": "true"})
    posted = await lab.post(f"/clients/{lab.client_id}/reports/generate")

    assert (browser.status_code, browser.headers["location"]) == (303, "/login")
    assert (htmx.status_code, htmx.headers["hx-redirect"]) == (401, "/login")
    assert posted.status_code == 303
    assert await lab.written() == before


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
async def test_a_button_or_a_download_another_site_sent_the_browser_to_is_403_before_anything(lab, site, monkeypatch):
    monkeypatch.setattr(report_generate, "render_report", lambda data: pytest.fail("rendered"))
    report = await a_report(lab)
    before = await lab.written()

    clicked = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member, headers={"Sec-Fetch-Site": site})
    download = await lab.get(f"/reports/{report}/file", lab.member, headers={"Sec-Fetch-Site": site})

    assert (clicked.status_code, clicked.json()) == (403, {"detail": "cross-site request"})
    assert (download.status_code, download.json()) == (403, {"detail": "cross-site request"})
    assert "location" not in download.headers
    assert await lab.written() == before and len(await rows_of(lab)) == 1


async def test_a_second_click_inside_ten_minutes_is_429_with_the_line_and_no_render_and_at_ten_minutes_is_made(lab, monkeypatch):
    await lab.month()
    lab.expect_put(interim_key(lab))
    first = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.admin)
    assert first.status_code == 303

    lab.time = TODAY + dt.timedelta(minutes=9, seconds=59)
    with monkeypatch.context() as patch:
        patch.setattr(report_generate, "render_report", lambda data: pytest.fail("rendered under the cap"))
        refused = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.admin)

    assert refused.status_code == 429 and refused.headers["retry-after"] == "1"
    assert "An interim report of this month was made at 2026-10-13 10:00 UTC; the next can be made from 2026-10-13 10:10 UTC." in refused.text
    assert "Generate now" in refused.text and interim_key(lab, TODAY).split("/")[-1] not in refused.text
    assert len(await rows_of(lab)) == 1 and len(lab.bodies) == 1
    assert len(await report_audit(lab)) == 1

    lab.time = TODAY + dt.timedelta(minutes=10)
    lab.expect_put(interim_key(lab))
    made = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.admin)

    assert made.status_code == 303
    assert len(await rows_of(lab)) == 2
    assert GENERATE_EVERY == dt.timedelta(seconds=600)


async def test_the_refusal_names_no_time_and_no_wait_at_which_the_cap_still_refuses(lab):
    """Finding 12: a report made at 10:00:59 may be followed at 10:10:59. The
    line said "from 10:10 UTC" and the header 28 for 28.7 seconds left."""
    await lab.month()
    lab.time = TODAY + dt.timedelta(seconds=59)
    lab.expect_put(interim_key(lab))
    assert (await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.admin)).status_code == 303

    lab.time = TODAY + dt.timedelta(minutes=10, seconds=30, milliseconds=300)
    refused = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.admin)

    assert refused.status_code == 429 and refused.headers["retry-after"] == "29"
    assert "An interim report of this month was made at 2026-10-13 10:00 UTC; the next can be made from 2026-10-13 10:11 UTC." in refused.text

    # At the second the header named, the click is taken.
    lab.time = TODAY + dt.timedelta(minutes=10, seconds=59, milliseconds=300)
    lab.expect_put(interim_key(lab))
    assert (await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.admin)).status_code == 303


@pytest.mark.parametrize(
    ("given", "named"),
    [
        (dt.datetime(2026, 10, 13, 10, 10, 0, tzinfo=UTC), dt.datetime(2026, 10, 13, 10, 10, tzinfo=UTC)),
        (dt.datetime(2026, 10, 13, 10, 10, 0, 1, tzinfo=UTC), dt.datetime(2026, 10, 13, 10, 11, tzinfo=UTC)),
        (dt.datetime(2026, 10, 13, 10, 10, 59, tzinfo=UTC), dt.datetime(2026, 10, 13, 10, 11, tzinfo=UTC)),
        (dt.datetime(2026, 10, 13, 23, 59, 1, tzinfo=UTC), dt.datetime(2026, 10, 14, 0, 0, tzinfo=UTC)),
    ],
)
def test_next_minute_is_the_time_itself_or_the_whole_minute_after_it(given, named):
    assert next_minute(given) == named


async def test_a_click_while_a_report_is_being_made_waits_for_the_slot_and_is_then_429_with_no_row(lab, monkeypatch):
    await lab.month()
    monkeypatch.setattr(report_generate, "render_report", lambda data: pytest.fail("rendered without the slot"))
    monkeypatch.setattr(page, "RENDER_WAIT_S", 0.2)
    before = await lab.written()
    slot: asyncio.Semaphore = lab.app.state.render_slot
    await slot.acquire()
    try:
        started = time.monotonic()
        refused = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member)
        waited = time.monotonic() - started
    finally:
        slot.release()

    assert refused.status_code == 429 and refused.headers["retry-after"] == "60"
    assert "A report is being made; try again in a minute." in refused.text
    assert 0.2 <= waited < 5
    assert await rows_of(lab) == [] and await lab.written() == before
    assert RENDER_WAIT_S == 5


async def test_the_slot_is_free_again_after_a_report_is_made_and_after_each_refusal_and_never_over_released(lab, monkeypatch):
    """The route takes the slot once and gives it back once: after a report,
    a 409 and a 503 it is free, and it still holds one (a release too many
    would let two renders run)."""
    await lab.month()
    slot: asyncio.Semaphore = lab.app.state.render_slot

    lab.expect_put(interim_key(lab))
    made = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member)
    nothing = await lab.post(f"/clients/{lab.client2_id}/reports/generate", lab.member)
    lab.time = TODAY + GENERATE_EVERY
    lab.stubber.add_client_error("put_object", service_error_code="InternalError")
    failed = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member)

    assert [made.status_code, nothing.status_code, failed.status_code] == [303, 409, 503]
    assert not slot.locked() and slot._value == 1


async def test_a_click_while_another_request_holds_the_client_s_row_is_429_at_once_with_no_render_and_no_row(lab, monkeypatch):
    """Finding 6: two clicks at once both read the cap before either had a
    row. The client's row is taken first and kept to the commit, so the
    second is told at once that one is being made; with the row free again
    it reads the cap, and the first's report is there."""
    await lab.month()
    before = await lab.written()
    order: list[str] = []
    real_hold, real_page = ClientRepo.hold, ReportRepo.page

    async def held_by_another(self, msp_id, client_id):
        order.append("hold")
        return False

    async def page_(self, msp_id, **kwargs):
        order.append("page")
        return await real_page(self, msp_id, **kwargs)

    monkeypatch.setattr(ReportRepo, "page", page_)
    with monkeypatch.context() as patch:
        patch.setattr(ClientRepo, "hold", held_by_another)
        patch.setattr(report_generate, "render_report", lambda data: pytest.fail("rendered beside another click's report"))
        refused = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member)

    assert refused.status_code == 429 and refused.headers["retry-after"] == "60"
    assert "A report is being made; try again in a minute." in refused.text and "Generate now" in refused.text
    assert await rows_of(lab) == [] and await lab.written() == before
    assert order == ["hold", "page"]  # the hold before the cap's read; the one page is the refusal's own list
    assert not lab.app.state.render_slot.locked()

    # The real hold on a free row, then the cap's read under it.
    order.clear()
    monkeypatch.setattr(ClientRepo, "hold", lambda self, msp_id, client_id: _note(order, real_hold(self, msp_id, client_id)))
    lab.expect_put(interim_key(lab))
    made = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member)
    again = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member)

    assert (made.status_code, again.status_code) == (303, 429)
    assert order[:2] == ["hold", "page"] and "An interim report of this month was made at" in again.text
    assert len(await rows_of(lab)) == 1


def _note(order: list[str], answer):
    order.append("hold")
    return answer


async def test_hold_takes_the_client_s_row_until_the_transaction_ends_and_keeps_no_run_waiting(own_database):
    """`ClientRepo.hold` on two connections: the second is answered False at
    once (SKIP LOCKED), a run made for the client meanwhile is not kept
    waiting (FOR NO KEY UPDATE), and the row is free once the first has
    committed."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.db import make_session_factory
    from app.repo.runs import RunRepo
    from tests.test_repo_runs import Queue

    engine = create_async_engine(own_database, connect_args={"server_settings": {"timezone": "UTC"}})
    statements: list[str] = []
    event.listen(engine.sync_engine, "before_cursor_execute", lambda _c, _cur, statement, *_rest: statements.append(statement))
    try:
        factory = make_session_factory(engine)
        async with factory() as setup, setup.begin():
            q = await Queue.make(setup)
            msp_id, client_id, ids = q.msp.id, q.client.id, dict(plan_id=q.plan.id, client_id=q.client.id, connector_id=q.connector.id, worker_id=q.worker.id)
        async with factory() as first, first.begin():
            assert await ClientRepo(first).hold(msp_id, client_id) is True
            async with factory() as second, second.begin():
                started = time.monotonic()
                assert await ClientRepo(second).hold(msp_id, client_id) is False
                assert time.monotonic() - started < 2
                run = await asyncio.wait_for(RunRepo(second).create(msp_id, **ids), 5)
                assert run.client_id == client_id
        async with factory() as third, third.begin():
            assert await ClientRepo(third).hold(msp_id, client_id) is True
            assert await ClientRepo(third).hold(msp_id, uuid.uuid4()) is False
    finally:
        await engine.dispose()

    holds = [s for s in statements if "FOR " in s]
    assert len(holds) == 4 and all(s.rstrip().endswith("FOR NO KEY UPDATE SKIP LOCKED") for s in holds)


async def test_a_client_with_nothing_this_month_is_409_with_the_repo_s_words_and_no_row(lab):
    await lab.month()  # the second client's only run is September's
    before = await lab.written()

    refused = await lab.post(f"/clients/{lab.client2_id}/reports/generate", lab.member)

    assert refused.status_code == 409
    assert "period: no run in the period" in refused.text and "Generate now" in refused.text
    assert await rows_of(lab) == [] and await lab.written() == before
    lab.stubber.assert_no_pending_responses()


async def test_a_put_that_fails_is_503_with_the_type_and_nothing_of_the_report_is_committed(lab):
    await lab.month()
    before = await lab.written()
    lab.stubber.add_client_error("put_object", service_error_code="InternalError")

    refused = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.member)
    listed = await lab.get(f"/clients/{lab.client_id}/reports", lab.member)

    assert refused.status_code == 503
    assert "storage: put failed (ClientError)" in refused.text and "InternalError" not in refused.text
    assert await rows_of(lab) == [] and await lab.written() == before
    assert "No report yet." in listed.text
    assert "InternalError" not in lab.log and "report failed" in lab.log
    assert not lab.app.state.render_slot.locked()


async def test_a_render_that_fails_is_503_with_the_type_and_no_row(lab, monkeypatch):
    await lab.month()

    def broken(data):
        raise OSError("cannot load library 'gobject-2.0-0'")

    monkeypatch.setattr(report_generate, "render_report", broken)
    before = await lab.written()

    refused = await lab.post(f"/clients/{lab.client_id}/reports/generate", lab.admin)

    assert refused.status_code == 503
    assert "report: not rendered (OSError)" in refused.text and "gobject" not in refused.text
    assert await rows_of(lab) == [] and await lab.written() == before
    lab.stubber.assert_no_pending_responses()


@pytest.mark.parametrize("path", ["/clients/not-a-uuid/reports", "/reports/not-a-uuid/file"])
async def test_an_id_that_is_no_uuid_is_422(lab, path):
    assert (await lab.get(path, lab.member)).status_code == 422


# --- The lists ----------------------------------------------------------------------------------


async def test_the_lists_show_the_columns_newest_period_first_and_the_client_s_page_its_own_rows(lab):
    sep = await a_report(lab, generated_at=NOW)
    interim = await a_report(lab, interim=True, generated_at=NOW - dt.timedelta(days=12))
    aug = await a_report(lab, period="2026-08", generated_at=NOW - dt.timedelta(days=30))
    theirs = await a_report(lab, client_id=lab.client2_id, generated_at=NOW - dt.timedelta(hours=1))

    everything = main_text((await lab.get("/reports", lab.member)).text)
    own = main_text((await lab.get(f"/clients/{lab.client_id}/reports", lab.admin)).text)

    for needle in ("contoso", "fabrikam", f"/clients/{lab.client2_id}/reports", "2026-09", "2026-08", "interim", "final", f"/reports/{sep}/file", f"/reports/{theirs}/file", "Every client's monthly report"):
        assert needle in everything, needle
    assert [everything.index(f"/reports/{r}/file") for r in (sep, theirs, interim, aug)] == sorted(everything.index(f"/reports/{r}/file") for r in (sep, theirs, interim, aug))
    assert f"/reports/{theirs}/file" not in own and "fabrikam" not in own
    assert [own.index(f"/reports/{r}/file") for r in (sep, interim, aug)] == sorted(own.index(f"/reports/{r}/file") for r in (sep, interim, aug))
    for row in await rows_of(lab):
        if row.client_id == lab.client_id:
            assert row.content_sha256 in own and row.file_sha256 in own
    assert "Generate now" in own and "Generate now" not in everything
    assert "October 2026" in own


async def test_the_lists_page_by_fifty_with_and_without_htmx(lab):
    for n in range(PAGE_SIZE + 3):
        await a_report(lab, interim=True, generated_at=NOW - dt.timedelta(minutes=n))
    ids = [r.id for r in await ReportRepo(lab.session).list(lab.msp_id)]

    first = await lab.get(f"/clients/{lab.client_id}/reports", lab.member)
    rest = await lab.get(f"/clients/{lab.client_id}/reports?before={ids[PAGE_SIZE - 1]}", lab.member, headers={"HX-Request": "true"})
    whole = await lab.get(f"/reports?before={ids[PAGE_SIZE - 1]}", lab.member)

    assert first.text.count("/file\"") == PAGE_SIZE and f"?before={ids[PAGE_SIZE - 1]}" in first.text and "hx-get" in first.text
    assert rest.text.count("/file\"") == 3 and "<main>" not in rest.text and "more" not in rest.text
    assert whole.text.count("/file\"") == 3 and "<main>" in whole.text and "Reports" in whole.text
    assert all(str(i) in rest.text for i in ids[PAGE_SIZE:])


@pytest.mark.parametrize(("count", "more"), [(PAGE_SIZE - 1, False), (PAGE_SIZE, False), (PAGE_SIZE + 1, True)])
async def test_more_is_offered_only_when_a_row_follows_the_page(lab, count, more):
    """Finding 11: with exactly fifty reports the page offered "more", and
    the click put "No report yet." under fifty rows."""
    for n in range(count):
        await a_report(lab, interim=True, generated_at=NOW - dt.timedelta(minutes=n))
    ids = [r.id for r in await ReportRepo(lab.session).list(lab.msp_id)]

    for path in ("/reports", f"/clients/{lab.client_id}/reports"):
        first = await lab.get(path, lab.member)
        assert first.text.count("/file\"") == min(count, PAGE_SIZE)
        assert ("?before=" in first.text) is more and "No report yet." not in first.text
        if more:
            assert f"{path}?before={ids[PAGE_SIZE - 1]}" in first.text


async def test_a_continuation_with_no_row_says_nothing_and_an_empty_first_page_says_no_report_yet(lab):
    last = await a_report(lab)

    empty = await lab.get(f"/reports?before={last}", lab.member, headers={"HX-Request": "true"})
    theirs_first = await lab.get(f"/clients/{lab.client2_id}/reports", lab.member)

    assert empty.status_code == 200 and "No report yet." not in empty.text and "<tr" not in empty.text
    assert "No report yet." in theirs_first.text


async def test_the_nav_names_reports_for_both_roles_and_the_client_page_links_its_reports(lab):
    for user in (lab.member, lab.admin):
        for path in ("/clients", "/workers", "/reports"):
            assert 'href="/reports"' in (await lab.get(path, user)).text, (user.email, path)
    client_page = await lab.get(f"/clients/{lab.client_id}", lab.member)
    assert f'href="/clients/{lab.client_id}/reports"' in client_page.text


async def test_a_planted_script_in_a_client_s_name_is_escaped_on_the_new_pages(lab):
    await lab.session.execute(text("UPDATE client SET name = :n WHERE id = :id"), {"n": SCRIPT, "id": lab.client_id})
    await a_report(lab)
    await lab.session.execute(text("UPDATE msp SET name = :n WHERE id = :id"), {"n": "m " + SCRIPT, "id": lab.msp_id})

    pages = [await lab.get("/reports", lab.member), await lab.get(f"/clients/{lab.client_id}/reports", lab.member)]
    refused = await lab.post(f"/clients/{lab.client2_id}/reports/generate", lab.member)

    for answer in pages + [refused]:
        assert SCRIPT not in answer.text and ESCAPED in answer.text


async def test_either_role_downloads_and_the_row_names_the_user_and_the_address(lab):
    report = await a_report(lab)

    for user, ip in ((lab.member, "10.3.3.3"), (lab.admin, "10.4.4.4")):
        answer = await lab.get(f"/reports/{report}/file", user, ip=ip)
        assert answer.status_code == 302

    assert sorted(await report_audit(lab)) == sorted([("report.download", f"report:{report}", lab.member.id, "10.3.3.3"), ("report.download", f"report:{report}", lab.admin.id, "10.4.4.4")])
    assert words.REPORT_DOWNLOAD == "report.download" and words.REPORT_DOWNLOAD in words.ACTIONS


# --- A fixed number of statements -----------------------------------------------------------------


async def test_the_pages_run_the_same_statements_whatever_their_rows(lab, test_engine):
    async def count(method: str, path: str, user, **kwargs) -> list[str]:
        seen: list[str] = []

        def listen(conn, cursor, statement, parameters, context, executemany):
            word = statement.split()[0]
            if word in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                seen.append(word)

        event.listen(test_engine.sync_engine, "before_cursor_execute", listen)
        try:
            answer = await (lab.get(path, user, **kwargs) if method == "get" else lab.post(path, user, **kwargs))
            assert answer.status_code in (200, 302, 303), (path, answer.status_code, answer.text[:200])
        finally:
            event.remove(test_engine.sync_engine, "before_cursor_execute", listen)
        return seen

    one = await a_report(lab)
    few = [await count("get", "/reports", lab.member), await count("get", f"/clients/{lab.client_id}/reports", lab.member), await count("get", f"/reports/{one}/file", lab.member)]
    for n in range(30):
        await a_report(lab, interim=True, generated_at=NOW - dt.timedelta(minutes=n + 1))
    many = [await count("get", "/reports", lab.member), await count("get", f"/clients/{lab.client_id}/reports", lab.member), await count("get", f"/reports/{one}/file", lab.member)]

    assert few == many
    assert few[0] == ["SELECT"] * 3  # the user, the MSP, the page
    assert few[1] == ["SELECT"] * 4  # ... and the client
    assert few[2] == ["SELECT"] * 3 + ["INSERT"]  # the user, the MSP, the report, the audit row

    # The button: the user, the MSP, the client, its row's hold, the cap's read, the month's eight reads, the row and the audit row, for one run and for thirty.
    await lab.month()
    lab.expect_put(interim_key(lab))
    with_one = await count("post", f"/clients/{lab.client_id}/reports/generate", lab.member)
    for i in range(30):
        await lab.tested("pass", finished_at=dt.datetime(2026, 10, 2 + i % 10, 1, i, tzinfo=UTC), recovery_ms=1000)
    lab.time = TODAY + dt.timedelta(hours=1)
    lab.expect_put(interim_key(lab))
    with_thirty = await count("post", f"/clients/{lab.client_id}/reports/generate", lab.member)

    assert with_one == with_thirty == ["SELECT"] * 13 + ["INSERT"] * 2


# --- `capped`, pure ----------------------------------------------------------------------------


def test_capped_is_the_newest_interim_report_of_this_month_inside_the_interval():
    from types import SimpleNamespace

    def row(*, interim, period_start, generated_at):
        return ReportRow(SimpleNamespace(interim=interim, period_start=period_start, generated_at=generated_at), "c")

    start = dt.date(2026, 10, 1)
    at = dt.datetime(2026, 10, 13, 10, 0, tzinfo=UTC)
    fresh = row(interim=True, period_start=start, generated_at=at - dt.timedelta(minutes=3))

    assert capped([], start, at) is None
    assert capped([fresh], start, at) == at + dt.timedelta(minutes=7)
    assert capped([row(interim=True, period_start=start, generated_at=at - GENERATE_EVERY)], start, at) is None
    assert capped([row(interim=False, period_start=dt.date(2026, 9, 1), generated_at=at - dt.timedelta(minutes=3))], start, at) is None
    assert capped([row(interim=True, period_start=dt.date(2026, 9, 1), generated_at=at - dt.timedelta(minutes=3))], start, at) is None


# --- ReportRepo.page ----------------------------------------------------------------------------


async def test_page_is_newest_period_first_then_newest_generation_with_the_client_s_name_and_keysets_on_before(lab):
    ids = {
        "aug": await a_report(lab, period="2026-08"),
        "sep_interim_1": await a_report(lab, interim=True, generated_at=NOW - dt.timedelta(days=20)),
        "sep_interim_2": await a_report(lab, interim=True, generated_at=NOW - dt.timedelta(days=10)),
        "sep": await a_report(lab),
        "theirs": await a_report(lab, client_id=lab.client2_id),
        "b": await a_report(lab, client_id=lab.b_client_id, msp_id=lab.b_msp_id),
    }
    repo = ReportRepo(lab.session)

    rows = await repo.page(lab.msp_id)
    own = await repo.page(lab.msp_id, client_id=lab.client_id)
    after = await repo.page(lab.msp_id, before=ids["sep_interim_2"])
    two = await repo.page(lab.msp_id, limit=2)

    assert all(isinstance(row, ReportRow) for row in rows)
    assert {row.report.id for row in rows} == set(ids.values()) - {ids["b"]}
    # September's final and the second client's (generated at NOW too) are first, then the interim ones, then August.
    assert [row.report.id for row in rows[2:]] == [ids["sep_interim_2"], ids["sep_interim_1"], ids["aug"]]
    assert {row.report.id for row in rows[:2]} == {ids["sep"], ids["theirs"]}
    assert {row.client_name for row in rows} == {"contoso", "fabrikam"}
    assert [row.report.id for row in own] == [ids["sep"], ids["sep_interim_2"], ids["sep_interim_1"], ids["aug"]]
    assert [row.report.id for row in after] == [ids["sep_interim_1"], ids["aug"]]
    assert len(two) == 2 and PAGE_SIZE == 50
    assert await repo.page(lab.msp_id, before=ids["b"]) == []  # another MSP's anchor is no anchor
    # One more than a page is the row that says another page follows; no more.
    assert len(await repo.page(lab.msp_id, limit=PAGE_SIZE + 1)) == 5
    with pytest.raises(ValueError):
        await repo.page(lab.msp_id, limit=0)
    with pytest.raises(ValueError):
        await repo.page(lab.msp_id, limit=PAGE_SIZE + 2)
