"""C6.3 (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", points 23 to
25), the Done-when by name: downloading a bundle appears in /audit with user,
time and IP. The page is the admin's, newest first, the last 30 days by
default, paged by keyset, and nothing deletes a row; `AuditRepo.page` by
itself below.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid

import pytest
from sqlalchemy import text

from app import audit as words
from app.repo.audit import PAGE_SIZE, AuditRepo, AuditRow
from app.routers.ui.audit import DEFAULT_DAYS, MAX_DAYS
from tests.pages_lab import UTC, VECTOR_FILES, PagesLab


@pytest.fixture
async def lab(session, monkeypatch) -> PagesLab:
    lab = PagesLab(session, monkeypatch)
    await lab.fill()
    return lab


async def set_time(lab, row_id: uuid.UUID, at: dt.datetime) -> None:
    await lab.session.execute(text("UPDATE audit_log SET at = :at WHERE id = :id"), {"at": at, "id": row_id})


def rows_of(page_text: str) -> list[list[str]]:
    body = page_text.split("<tbody", 1)[1] if "<tbody" in page_text else page_text
    return [re.findall(r"<td>(.*?)</td>", row, re.S) for row in re.findall(r"<tr>(.*?)</tr>", body, re.S)]


# --- The Done-when, by name ---------------------------------------------------------------------


async def test_downloading_a_bundle_appears_in_audit_with_user_time_and_ip(lab):
    run_id = await lab.land_vector()
    lab.expect_list(run_id, VECTOR_FILES)
    download = await lab.get(f"/runs/{run_id}/files/items.csv", lab.member, ip="203.0.113.9")
    assert download.status_code == 302
    (row,) = [r for r in await AuditRepo(lab.session).list(lab.msp_id) if r.action == words.BUNDLE_DOWNLOAD]

    page = await lab.get("/audit", lab.admin)
    theirs = await lab.get("/audit", lab.b_admin)

    assert page.status_code == 200
    # The upload's own row shares this transaction's `now()` with the download's, so by action.
    (shown,) = [r for r in rows_of(page.text) if "bundle.download" in r[2]]
    assert shown == [row.at.strftime("%Y-%m-%d %H:%M:%S UTC"), "member@example.test", "<code>bundle.download</code>", f"run:{run_id} items.csv", "203.0.113.9"]
    assert "bundle.download" not in theirs.text and f"{run_id}" not in theirs.text


# --- Failure paths ------------------------------------------------------------------------------


async def test_a_member_is_403_and_no_session_303(lab):
    member = await lab.get("/audit", lab.member)
    nobody = await lab.get("/audit")

    assert (member.status_code, member.json()) == (403, {"detail": "admin only"})
    assert (nobody.status_code, nobody.headers["location"]) == (303, "/login")


@pytest.mark.parametrize("query", ["days=0", "days=3651", "days=x", "days=-1", "days=1.5", "before=x"])
async def test_a_span_or_a_cursor_outside_the_rule_is_422(lab, query):
    assert (await lab.get(f"/audit?{query}", lab.admin)).status_code == 422


# --- The page -----------------------------------------------------------------------------------


async def test_the_page_shows_the_last_30_days_newest_first_and_a_wider_span_on_request(lab):
    lab.time = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    at = lab.time
    repo = AuditRepo(lab.session)
    old = await repo.write(lab.msp_id, "msp.create", f"msp:{lab.msp_id}")
    await set_time(lab, old.id, at - dt.timedelta(days=31))
    edge = await repo.write(lab.msp_id, "client.create", "client:x", user_id=lab.admin.id, ip="10.0.0.1")
    await set_time(lab, edge.id, at - dt.timedelta(days=30))
    recent = await repo.write(lab.msp_id, "worker.register", "worker:y", ip="10.0.0.2")
    await set_time(lab, recent.id, at - dt.timedelta(hours=1))
    theirs = await repo.write(lab.b_msp_id, "plan.create", "plan:z")
    await set_time(lab, theirs.id, at)

    page = await lab.get("/audit", lab.admin)
    wider = await lab.get("/audit?days=90", lab.admin)

    assert [r[2:4] for r in rows_of(page.text)] == [["<code>worker.register</code>", "worker:y"], ["<code>client.create</code>", "client:x"]]
    assert [r[1] for r in rows_of(page.text)] == ["—", "admin@example.test"]
    assert [r[4] for r in rows_of(page.text)] == ["10.0.0.2", "10.0.0.1"]
    assert "plan:z" not in page.text and "msp.create" not in page.text
    assert f"The last {DEFAULT_DAYS} days" in page.text and DEFAULT_DAYS == 30 and MAX_DAYS == 3650
    assert [r[3] for r in rows_of(wider.text)] == ["worker:y", "client:x", f"msp:{lab.msp_id}"]
    assert "The last 90 days" in wider.text


async def test_the_page_pages_by_a_hundred_with_and_without_htmx(lab):
    lab.time = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    repo = AuditRepo(lab.session)
    ids = []
    for n in range(PAGE_SIZE + 2):
        row = await repo.write(lab.msp_id, "login.success", f"user:{n}", user_id=lab.member.id)
        await set_time(lab, row.id, lab.time - dt.timedelta(minutes=n))
        ids.append(row.id)

    first = await lab.get("/audit", lab.admin)
    before = re.search(r'href="/audit\?days=30&amp;before=([0-9a-f-]+)"', first.text).group(1)
    fragment = await lab.get(f"/audit?before={before}", lab.admin, headers={"HX-Request": "true"})
    whole = await lab.get(f"/audit?days=30&before={before}", lab.admin)

    assert len(rows_of(first.text)) == PAGE_SIZE and PAGE_SIZE == 100
    assert before == str(ids[PAGE_SIZE - 1])
    assert f'hx-get="/audit?days=30&amp;before={before}"' in first.text
    assert [r[3] for r in rows_of(fragment.text)] == [f"user:{PAGE_SIZE}", f"user:{PAGE_SIZE + 1}"] and "<html" not in fragment.text
    assert [r[3] for r in rows_of(whole.text)] == [f"user:{PAGE_SIZE}", f"user:{PAGE_SIZE + 1}"] and "<html" in whole.text
    assert "?before=" not in fragment.text


async def test_the_page_deletes_nothing_and_shows_the_cli_s_and_the_worker_s_rows(lab):
    repo = AuditRepo(lab.session)
    await repo.write(lab.msp_id, "msp.create", f"msp:{lab.msp_id}")
    await repo.write(lab.msp_id, "result.received", "run:r", ip="192.0.2.5")
    before = await lab.count("audit_log")

    page = await lab.get("/audit", lab.admin)

    assert await lab.count("audit_log") == before
    assert [r[1] for r in rows_of(page.text)] == ["—", "—"]
    assert "Nothing is ever deleted from this log." in page.text


async def test_every_word_a_page_writes_is_in_the_list(lab):
    run_id = await lab.land_vector()
    lab.expect_list(run_id, VECTOR_FILES)
    await lab.get(f"/runs/{run_id}/files/items.csv", lab.member)
    await lab.post(f"/workers/{lab.worker_id}/revoke", lab.admin)
    await lab.post("/logout", lab.member)

    written = {r.action for r in await AuditRepo(lab.session).list(lab.msp_id)} - {"result.received", "connector.create"}

    assert written == {words.BUNDLE_DOWNLOAD, words.WORKER_REVOKE, words.LOGOUT}
    assert written <= set(words.ACTIONS)


# --- AuditRepo.page -----------------------------------------------------------------------------


async def test_page_is_newest_first_from_since_with_the_user_s_address_and_keysets_on_before(lab):
    at = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    repo = AuditRepo(lab.session)
    rows = []
    for n in range(5):
        row = await repo.write(lab.msp_id, "x", f"t:{n}", user_id=lab.admin.id if n % 2 else None)
        await set_time(lab, row.id, at - dt.timedelta(hours=n))
        rows.append(row)
    same = await repo.write(lab.msp_id, "x", "t:same")
    await set_time(lab, same.id, at)
    theirs = await repo.write(lab.b_msp_id, "x", "t:theirs")
    await set_time(lab, theirs.id, at)

    newest = await repo.page(lab.msp_id, since=at - dt.timedelta(days=1))
    limited = await repo.page(lab.msp_id, since=at - dt.timedelta(days=1), limit=2)
    after = await repo.page(lab.msp_id, since=at - dt.timedelta(days=1), before=limited[-1].row.id, limit=2)
    narrow = await repo.page(lab.msp_id, since=at - dt.timedelta(hours=2))

    assert all(isinstance(r, AuditRow) for r in newest)
    assert [r.row.target for r in newest][:2] == sorted([rows[0].target, "t:same"], key=lambda t: {rows[0].target: rows[0].id, "t:same": same.id}[t], reverse=True)
    assert [r.row.target for r in newest][2:] == ["t:1", "t:2", "t:3", "t:4"]
    assert [r.email for r in newest][2:] == ["admin@example.test", None, "admin@example.test", None]
    assert len(limited) == 2 and [r.row.target for r in after] == [r.row.target for r in newest][2:4]
    assert [r.row.target for r in narrow] == [r.row.target for r in newest][:4]  # `since` is inclusive
    assert "t:theirs" not in [r.row.target for r in newest]
    assert await repo.page(lab.msp_id, since=at - dt.timedelta(days=1), before=theirs.id) == []
    assert await repo.page(lab.msp_id, since=at - dt.timedelta(days=1), before=uuid.uuid4()) == []
    with pytest.raises(ValueError, match="without a zone"):
        await repo.page(lab.msp_id, since=dt.datetime(2026, 1, 1))
    for limit in (0, PAGE_SIZE + 1):
        with pytest.raises(ValueError, match="limit must be 1 to 100"):
            await repo.page(lab.msp_id, since=at, limit=limit)
