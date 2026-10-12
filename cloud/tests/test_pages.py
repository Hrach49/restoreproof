"""C6.2 (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", points 15 to
22), the Done-when by name: the four pages render real data from the Sprint 5
runs (the Worker-written vector, posted as the Worker posts it) and a revoked
Worker gets 401 on its next poll. Failure paths first, then each cell against
rows made to order, the strip, the paging, the statement counts.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import event, text

from app import ui
from app.models import Worker
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.items import ItemRepo
from app.repo.plans import PlanRepo
from app.repo.runs import PAGE_SIZE, RunRepo
from app.repo.workers import WorkerRepo
from app.routers.ui.clients import STRIP_DAYS, NextRun, next_run, strip
from app.routers.ui.runs import LINK_SECONDS
from app.routers.ui.workers import LATE_AFTER, late
from tests.pages_lab import IP, UTC, VECTOR_FILES, PagesLab
from tests.test_contract import VECTOR, header_values, poll

PAGES = ("/clients", "/workers")
SCRIPT = "<script>alert(1)</script>"
ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"


@pytest.fixture
async def lab(session, monkeypatch) -> PagesLab:
    lab = PagesLab(session, monkeypatch)
    await lab.fill()
    return lab


def cell(text_: str, *needles: str) -> None:
    for needle in needles:
        assert needle in text_, needle


# --- The Done-when, by name ---------------------------------------------------------------------


async def test_the_four_pages_render_real_data_from_the_sprint_5_runs_and_a_revoked_worker_gets_401_on_its_next_poll(lab):
    run_id = await lab.land_vector()
    lab.expect_list(run_id, VECTOR_FILES)
    next_two = (lab.time + dt.timedelta(days=1)).replace(hour=2, minute=0, second=0) if lab.time.hour >= 2 else lab.time.replace(hour=2, minute=0, second=0)

    clients = await lab.get("/clients", lab.member)
    client = await lab.get(f"/clients/{lab.client_id}", lab.member)
    run = await lab.get(f"/runs/{run_id}", lab.member)
    workers = await lab.get("/workers", lab.member)

    for page in (clients, client, run, workers):
        assert page.status_code == 200, page.text
        assert header_values(page) == ["1"]
        cell(page.text, "contract", "member@example.test", 'href="/clients"', 'href="/workers"', 'action="/logout"')
        assert 'href="/audit"' not in page.text  # a member's frame
    # /clients: the client's row from the vector's run.
    cell(clients.text, f'href="/clients/{lab.client_id}">contoso<', "2026-09-28 12:00 UTC", 'class="state pass">pass<', "20:30", next_two.strftime("%Y-%m-%d %H:%M UTC"))
    # /clients/{id}: the history's one row, and the strip.
    cell(client.text, "<h1>contoso</h1>", f'href="/runs/{run_id}">2026-09-28 12:00 UTC<', "2026-09-29 22:00 UTC", '<td class="num">2</td>', "pass", "20:30", "manual")
    assert client.text.count('class="day') == STRIP_DAYS
    assert "<td>yes</td>\n    <td>yes</td>" in client.text  # cleanup ok, timestamped
    # /runs/{id}: the items, the files, the columns.
    cell(run.text, f"Run <code>{run_id}</code>", "rp-canary-01.pdf", "rp-canary-11.pdf", "41:00", "20:30", VECTOR["bundle_sha256"], "2026-09-29 22:00:45 UTC")
    for name in VECTOR_FILES:
        cell(run.text, f'href="/runs/{run_id}/files/{name}">{name}<')
    assert "<p>Bundle: " in run.text and "<p>Attachments: " in run.text
    assert "Error code" not in run.text
    # /workers: the two Workers, never seen, the member sees no Revoke.
    cell(workers.text, "<td>w1</td>", "<td>w2</td>", 'class="late">never<')
    assert "Revoke" not in workers.text
    lab.stubber.assert_no_pending_responses()

    # The admin's Revoke, then the Worker's next poll.
    admin_workers = await lab.get("/workers", lab.admin)
    revoked = await lab.post(f"/workers/{lab.worker_id}/revoke", lab.admin)
    after = await lab.get("/workers", lab.admin)
    polled = await poll(lab.inner)

    assert admin_workers.text.count("Revoke</button>") == 2
    assert (revoked.status_code, revoked.headers["location"]) == (303, "/workers")
    assert after.text.count("Revoke</button>") == 1 and "revoked " + lab.time.strftime("%Y-%m-%d %H:%M UTC") in after.text
    assert (polled.status_code, polled.json()) == (401, {"detail": "not authenticated"})
    row = await WorkerRepo(lab.session).get(lab.msp_id, lab.worker_id)
    assert row.revoked_at is not None
    rows = [(r.action, r.target, r.user_id, r.ip) for r in await AuditRepo(lab.session).list(lab.msp_id) if r.action == "worker.revoke"]
    assert rows == [("worker.revoke", f"worker:{lab.worker_id}", lab.admin.id, IP)]


# --- Failure paths first ------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/clients", "/clients/{client}", "/runs/{run}", "/runs/{run}/files/result.json", "/workers", "/audit"])
async def test_a_page_without_a_session_sends_the_browser_to_the_form_and_an_htmx_request_401(lab, path):
    run_id = await lab.make_run()
    path = path.format(client=lab.client_id, run=run_id)

    plain = await lab.get(path)
    fragment = await lab.get(path, headers={"HX-Request": "true"})

    assert (plain.status_code, plain.headers["location"]) == (303, "/login")
    assert (fragment.status_code, fragment.headers["hx-redirect"]) == (401, "/login")


async def test_another_msp_s_client_run_and_worker_are_404_and_never_listed(lab):
    b_run_id = lab.b_run_id
    revoke = await lab.post(f"/workers/{lab.b_worker_id}/revoke", lab.admin)
    clients = await lab.get("/clients", lab.admin)
    workers = await lab.get("/workers", lab.admin)

    assert (await lab.get(f"/clients/{lab.b_client_id}", lab.admin)).status_code == 404
    assert (await lab.get(f"/runs/{b_run_id}", lab.admin)).status_code == 404
    assert (await lab.get(f"/runs/{b_run_id}/files/result.json", lab.admin)).status_code == 404
    assert revoke.status_code == 404
    assert (await WorkerRepo(lab.session).get(lab.b_msp_id, lab.b_worker_id)).revoked_at is None
    assert "B client" not in clients.text and "b worker" not in workers.text and "Other MSP" not in clients.text
    assert (await lab.get(f"/clients/{uuid.uuid4()}", lab.admin)).status_code == 404
    assert (await lab.get(f"/runs/{uuid.uuid4()}", lab.admin)).status_code == 404
    assert (await lab.post(f"/workers/{uuid.uuid4()}/revoke", lab.admin)).status_code == 404
    # From the other side: B's admin sees nothing of A.
    theirs = await lab.get("/clients", lab.b_admin)
    assert "B client" in theirs.text and "contoso" not in theirs.text
    assert (await lab.get(f"/clients/{lab.client_id}", lab.b_admin)).status_code == 404


async def test_a_member_may_not_revoke(lab):
    response = await lab.post(f"/workers/{lab.worker_id}/revoke", lab.member)

    assert (response.status_code, response.json()) == (403, {"detail": "admin only"})
    assert (await WorkerRepo(lab.session).get(lab.msp_id, lab.worker_id)).revoked_at is None
    assert await lab.written() == 0


@pytest.mark.parametrize("path", ["/clients/not-a-uuid", "/clients/{client}?before=x", "/runs/nope", "/workers/nope/revoke"])
async def test_an_id_that_is_no_uuid_is_422(lab, path):
    path = path.format(client=lab.client_id)
    method = lab.post if path.endswith("/revoke") else lab.get

    assert (await method(path, lab.admin)).status_code == 422


async def test_a_revoke_from_another_site_is_403(lab):
    response = await lab.post(f"/workers/{lab.worker_id}/revoke", lab.admin, headers={"Sec-Fetch-Site": "cross-site"})

    assert response.status_code == 403
    assert (await WorkerRepo(lab.session).get(lab.msp_id, lab.worker_id)).revoked_at is None


async def test_a_worker_revoked_already_is_409_with_the_cli_s_words(lab):
    assert await WorkerRepo(lab.session).revoke(lab.msp_id, lab.worker_id, lab.time) == 1

    response = await lab.post(f"/workers/{lab.worker_id}/revoke", lab.admin)

    assert (response.status_code, response.text) == (409, "worker_id: no such Worker or already revoked")
    assert await lab.written() == 0


@pytest.mark.parametrize("name", ["a/b", "/result.json", ".hidden", "a" * 129, "sp ace", "ünïcode", "a%00b", "%2e%2e", "-x"])
async def test_a_file_name_outside_the_rule_is_404_without_a_list_or_a_row(lab, name):
    """A bare `..` never reaches the route: a browser (and httpx) folds it
    into the path before sending, so it is the run page's URL."""
    run_id = await lab.make_run(state="pass", bundle_key=f"msp/{lab.msp_id}/runs/x/")

    response = await lab.get(f"/runs/{run_id}/files/{name}", lab.member)

    assert response.status_code == 404, name
    assert await lab.written() == 0


async def test_a_file_the_bucket_does_not_list_and_a_run_without_a_bundle_are_404(lab):
    with_bundle = await lab.make_run(state="pass")
    await lab.session.execute(text("UPDATE test_run SET bundle_key = :key WHERE id = :id"), {"key": f"msp/{lab.msp_id}/runs/{with_bundle}/", "id": with_bundle})
    without = await lab.make_run(state="error", error_code="interrupted", error_message="the service was stopped")
    lab.expect_list(with_bundle, ["result.json", "signature.json"])

    listed = await lab.get(f"/runs/{with_bundle}/files/items.csv", lab.member)
    never = await lab.get(f"/runs/{without}/files/result.json", lab.member)
    page = await lab.get(f"/runs/{without}", lab.member)

    assert listed.status_code == 404 and never.status_code == 404
    assert "No bundle received." in page.text and "Error code" in page.text and "<code>interrupted</code>" in page.text and "the service was stopped" in page.text
    assert await lab.written() == 0
    lab.stubber.assert_no_pending_responses()


async def test_a_planted_script_is_escaped_on_every_page(lab):
    assert await ClientRepo(lab.session).update(lab.msp_id, lab.client_id, name=SCRIPT, screenshots_enabled=False) == 1
    await lab.session.execute(text("UPDATE worker SET name = :n, last_error = 'x' WHERE id = :id"), {"n": SCRIPT, "id": lab.worker_id})
    run_id = await lab.make_run(state="error", error_code="internal", error_message=SCRIPT)
    await ItemRepo(lab.session).create(lab.msp_id, run_id, position=0, type="mail", name=SCRIPT, expected_kind="fields", reason=SCRIPT)

    pages = [await lab.get(path, lab.admin) for path in ("/clients", f"/clients/{lab.client_id}", f"/runs/{run_id}", "/workers")]

    for page in pages:
        assert page.status_code == 200
        assert SCRIPT not in page.text and ESCAPED in page.text, page.request.url
    assert pages[2].text.count(ESCAPED) == 5  # the client's and the Worker's names, the message, the item's name and reason


# --- /clients -----------------------------------------------------------------------------------


async def make_client(lab, name: str, cron: str = "0 2 * * *", *, worker_id=None, enabled: bool = True):
    """A second client of the MSP on the first Worker (or as given), with one plan."""
    s = lab.session
    client = await ClientRepo(s).create(lab.msp_id, name=name, tenant_id=uuid.uuid4())
    from app.repo.connectors import ConnectorRepo
    from tests.test_repo_connectors import profile_for

    connector = await ConnectorRepo(s).create(lab.msp_id, client.id, worker_id or lab.worker_id, profile_for(client.tenant_id))
    plan = await PlanRepo(s).create(lab.msp_id, client.id, connector.id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron=cron, now=lab.time - dt.timedelta(days=1), enabled=enabled)
    return client, connector, plan


async def test_the_clients_page_shows_each_client_s_last_finished_run_and_next_run(lab):
    lab.time = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    at = lab.time
    quiet, _, _ = await make_client(lab, "Quiet")  # no run
    failed, failed_connector, failed_plan = await make_client(lab, "Failed", "30 */6 * * *")
    await lab.make_run(client_id=failed.id, connector_id=failed_connector.id, plan_id=failed_plan.id, state="pass", created_at=at - dt.timedelta(days=2), finished_at=at - dt.timedelta(days=2), recovery_ms=65_000)
    await lab.make_run(client_id=failed.id, connector_id=failed_connector.id, plan_id=failed_plan.id, state="fail", created_at=at - dt.timedelta(days=1), finished_at=at - dt.timedelta(hours=20), recovery_ms=3_600_000 + 65_000)
    await lab.make_run(client_id=failed.id, connector_id=failed_connector.id, plan_id=failed_plan.id, state="queued", created_at=at - dt.timedelta(hours=1))
    await lab.make_run(state="expired", created_at=at - dt.timedelta(days=3))
    await lab.make_run(state="error", created_at=at - dt.timedelta(days=4), finished_at=at - dt.timedelta(days=4))
    await lab.make_run(state="dispatched", created_at=at - dt.timedelta(minutes=5))
    disabled, _, _ = await make_client(lab, "Disabled", enabled=False)
    orphan_worker = await WorkerRepo(lab.session).create(lab.msp_id, "gone", public_key_pem="x", key_id="e" * 64, api_token_hash="f" * 64)
    assert await WorkerRepo(lab.session).revoke(lab.msp_id, orphan_worker.id, at) == 1
    orphan, _, _ = await make_client(lab, "Orphan", worker_id=orphan_worker.id)

    page = await lab.get("/clients", lab.member)

    rows = re.findall(r"<tr>(.*?)</tr>", page.text, re.S)[1:]  # the header's row is in thead
    by_name = {re.search(r">([^<]+)</a>", row).group(1): re.sub(r"\s+", " ", row) for row in rows}
    assert list(by_name) == sorted(by_name, key=str.lower) and set(by_name) == {"Disabled", "Failed", "Orphan", "Quiet", "contoso"}
    cell(by_name["Quiet"], "<td>—</td>", 'class="state none">none<', "<td class=\"num\">—</td>", "2026-10-13 02:00 UTC")
    cell(by_name["Failed"], (at - dt.timedelta(hours=20)).strftime("%Y-%m-%d %H:%M UTC"), 'class="state fail">fail<', "1:01:05", "queued since 2026-10-12 09:00 UTC")
    # The oldest pending run is the vector's own queued one (2020), not the one running now.
    cell(by_name["contoso"], "2026-10-09 10:00 UTC", 'class="state quiet">expired<', "queued since 2020-01-01 00:00 UTC")
    cell(by_name["Disabled"], 'class="state none">none<', "<td> none </td>")
    cell(by_name["Orphan"], '<span class="late">no Worker</span>')


def test_next_run_s_rules():
    at = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    client_id, other_id = uuid.uuid4(), uuid.uuid4()

    class Plan:
        def __init__(self, cid, cron):
            self.client_id, self.cadence_cron = cid, cron

    live, revoked = Worker(revoked_at=None), Worker(revoked_at=at)
    plans = [(Plan(client_id, "0 2 * * *"), live), (Plan(client_id, "0 12 * * *"), live), (Plan(other_id, "0 11 * * *"), live)]

    assert next_run(client_id, None, plans, at) == NextRun("next", dt.datetime(2026, 10, 12, 12, 0, tzinfo=UTC))
    assert next_run(client_id, None, [(Plan(client_id, "0 11 * * *"), revoked), *plans], at) == NextRun("next", dt.datetime(2026, 10, 12, 12, 0, tzinfo=UTC))
    assert next_run(client_id, None, [(Plan(client_id, "0 11 * * *"), revoked)], at) == NextRun("no_worker")
    assert next_run(client_id, None, [(Plan(other_id, "0 11 * * *"), revoked)], at) == NextRun("none")
    assert next_run(client_id, None, [], at) == NextRun("none")
    assert next_run(client_id, None, [(Plan(client_id, "not a cron"), live)], at) == NextRun("none")
    assert next_run(client_id, None, [(Plan(client_id, "not a cron"), live), (Plan(client_id, "0 2 31 2 *"), live), (Plan(client_id, "0 2 * * *"), live)], at) == NextRun("next", dt.datetime(2026, 10, 13, 2, 0, tzinfo=UTC))

    class Run:
        def __init__(self, state):
            self.state, self.created_at = state, at

    assert next_run(client_id, Run("queued"), plans, at) == NextRun("queued", at)
    assert next_run(client_id, Run("dispatched"), plans, at) == NextRun("running", at)


async def test_the_clients_page_runs_the_same_statements_whatever_its_rows(lab, test_engine):
    async def count(path: str, user) -> list[str]:
        seen: list[str] = []

        @event.listens_for(test_engine.sync_engine, "before_cursor_execute")
        def listen(conn, cursor, statement, parameters, context, executemany):
            word = statement.split()[0]
            if word in ("SELECT", "INSERT", "UPDATE", "DELETE"):  # not the override's savepoints
                seen.append(word)

        try:
            assert (await lab.get(path, user)).status_code == 200
        finally:
            event.remove(test_engine.sync_engine, "before_cursor_execute", listen)
        return seen

    one = await count("/clients", lab.member)
    for n in range(4):
        await make_client(lab, f"client {n}")
        await lab.make_run(state="pass")
    many = await count("/clients", lab.member)
    workers = await count("/workers", lab.member)
    client_page = await count(f"/clients/{lab.client_id}", lab.member)

    assert one == many == ["SELECT"] * 6  # the user, the MSP, the clients, the last runs, the pending runs, the plans
    assert workers == ["SELECT"] * 3
    assert client_page == ["SELECT"] * 5  # the user, the MSP, the client, the page, the strip


# --- /clients/{id} ------------------------------------------------------------------------------


async def test_the_history_shows_every_column_and_a_pending_run_s_dashes(lab):
    lab.time = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    at = lab.time
    passed = await lab.make_run(state="pass", created_at=at - dt.timedelta(days=1), finished_at=at - dt.timedelta(days=1), restore_point_at=at - dt.timedelta(days=1, hours=8), recovery_ms=1_000, cleanup_ok=True, tsa_ok=True, scheduled_for=at - dt.timedelta(days=1, hours=2))
    await ItemRepo(lab.session).create(lab.msp_id, passed, position=0, type="mail", name="a", expected_kind="fields")
    await ItemRepo(lab.session).create(lab.msp_id, passed, position=1, type="mail", name="b", expected_kind="fields")
    failed = await lab.make_run(state="fail", created_at=at - dt.timedelta(hours=2), finished_at=at - dt.timedelta(hours=2), cleanup_ok=False)
    queued = await lab.make_run(state="queued", created_at=at - dt.timedelta(hours=1), scheduled_for=at - dt.timedelta(hours=1))

    page = await lab.get(f"/clients/{lab.client_id}", lab.member)

    rows = {re.search(r'href="/runs/([^"]+)"', row).group(1): re.sub(r"\s+", " ", row) for row in re.findall(r"<tr>(.*?)</tr>", page.text, re.S)[1:]}
    assert list(rows) == [str(queued), str(failed), str(passed), str(lab.inner.run_id)]  # the vector's run, queued, began in 2020
    cell(rows[str(passed)], "2026-10-11 10:00 UTC", "2026-10-11 02:00 UTC", '<td class="num">2</td>', 'class="state pass">pass<', "0:01", "<td>yes</td> <td>yes</td>", "2026-10-11 08:00 UTC")
    cell(rows[str(failed)], '<td class="num">0</td>', 'class="state fail">fail<', '<td class="num">—</td>', "<td>no</td> <td>—</td>", "<td>manual</td>")
    cell(rows[str(queued)], '<td>—</td><td class="num">—</td>', 'class="state quiet">queued<', "2026-10-12 09:00 UTC")
    assert "more" not in page.text.split("</table>")[0].split('id="runs"')[1]


async def test_the_history_pages_by_fifty_with_and_without_htmx(lab):
    at = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    ids = [await lab.make_run(state="pass", created_at=at - dt.timedelta(minutes=i)) for i in range(PAGE_SIZE + 2)]

    first = await lab.get(f"/clients/{lab.client_id}", lab.member)
    before = re.search(r'href="/clients/[^?]+\?before=([0-9a-f-]+)"', first.text).group(1)
    second_page = await lab.get(f"/clients/{lab.client_id}?before={before}", lab.member)
    fragment = await lab.get(f"/clients/{lab.client_id}?before={before}", lab.member, headers={"HX-Request": "true"})

    assert first.text.count("<tr") == 1 + PAGE_SIZE + 1  # the header, fifty rows, the pager
    assert before == str(ids[PAGE_SIZE - 1])
    assert f'hx-get="/clients/{lab.client_id}?before={before}"' in first.text and 'hx-swap="outerHTML"' in first.text
    # The second page: the two runs left and the vector's own queued run, the oldest.
    assert second_page.text.count("<tr") == 1 + 3 and "?before=" not in second_page.text and "<html" in second_page.text
    assert fragment.text.count("<tr") == 3 and "<html" not in fragment.text and "?before=" not in fragment.text
    assert [str(i) for i in ids[PAGE_SIZE:]] + [str(lab.inner.run_id)] == re.findall(r'href="/runs/([^"]+)"', fragment.text)
    empty = await lab.get(f"/clients/{lab.client_id}?before={lab.inner.run_id}", lab.member, headers={"HX-Request": "true"})
    assert empty.text.count("<tr") == 1 and "No run yet." in empty.text


async def test_the_strip_has_ninety_cells_coloured_by_the_day_s_worst_test(lab):
    lab.time = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    at = lab.time
    await lab.make_run(state="pass", created_at=at - dt.timedelta(days=1))
    await lab.make_run(state="fail", created_at=at - dt.timedelta(days=1, hours=5))
    await lab.make_run(state="error", created_at=at - dt.timedelta(days=2))
    await lab.make_run(state="pass", created_at=at - dt.timedelta(days=2))
    await lab.make_run(state="pass", created_at=at - dt.timedelta(days=3))
    await lab.make_run(state="expired", created_at=at - dt.timedelta(days=4))
    await lab.make_run(state="queued", created_at=at)
    await lab.make_run(state="pass", created_at=at - dt.timedelta(days=STRIP_DAYS - 1))
    await lab.make_run(state="pass", created_at=at - dt.timedelta(days=STRIP_DAYS))  # outside

    page = await lab.get(f"/clients/{lab.client_id}", lab.member)

    cells = re.findall(r'<span class="day ?([a-z]*)" title="([^"]*)"', page.text)
    assert len(cells) == STRIP_DAYS
    by_day = {title.split(" ")[0]: (colour, title) for colour, title in cells}
    assert cells[0][1].startswith("2026-07-15") and cells[-1][1].startswith("2026-10-12")
    assert by_day["2026-10-11"] == ("fail", "2026-10-11 fail 1 pass 1")
    assert by_day["2026-10-10"] == ("error", "2026-10-10 error 1 pass 1")
    assert by_day["2026-10-09"] == ("pass", "2026-10-09 pass 1")
    assert by_day["2026-10-08"] == ("", "2026-10-08 expired 1")
    assert by_day["2026-10-12"] == ("", "2026-10-12 queued 1")
    assert by_day["2026-07-15"] == ("pass", "2026-07-15 pass 1")
    assert by_day["2026-07-16"] == ("", "2026-07-16")


def test_strip_is_pure_over_the_counts():
    from app.repo.runs import DayCount

    today = dt.date(2026, 10, 12)
    cells = strip([DayCount(today, "fail", 1), DayCount(today, "pass", 3), DayCount(dt.date(2026, 10, 11), "error", 2)], today)

    assert len(cells) == STRIP_DAYS
    assert cells[-1] == (today, "fail", {"fail": 1, "pass": 3})
    assert cells[-2] == (dt.date(2026, 10, 11), "error", {"error": 2})
    assert cells[0] == (dt.date(2026, 7, 15), None, {})


# --- /runs/{id} and the download ------------------------------------------------------------


async def test_the_download_writes_the_row_then_sends_the_browser_to_a_link_signed_for_ten_minutes(lab):
    run_id = await lab.land_vector()
    lab.expect_list(run_id, VECTOR_FILES)
    before = await lab.written()

    response = await lab.get(f"/runs/{run_id}/files/items.csv", lab.member, ip="10.1.1.1")

    assert response.status_code == 302
    assert response.headers["cache-control"] == "no-store"
    url = urlsplit(response.headers["location"])
    query = parse_qs(url.query)
    assert (url.scheme, url.netloc, url.path) == ("http", "127.0.0.1:1", f"/test-bucket/msp/{lab.msp_id}/runs/{run_id}/items.csv")
    assert query["X-Amz-Expires"] == [str(LINK_SECONDS)] and LINK_SECONDS == 600
    assert query["X-Amz-Signature"]
    rows = [(r.action, r.target, r.user_id, r.ip) for r in await AuditRepo(lab.session).list(lab.msp_id) if r.action == "bundle.download"]
    assert rows == [("bundle.download", f"run:{run_id} items.csv", lab.member.id, "10.1.1.1")]
    assert await lab.written() == before + 1
    lab.stubber.assert_no_pending_responses()
    # The page itself holds no link to the bucket.
    lab.expect_list(run_id, VECTOR_FILES)
    page = await lab.get(f"/runs/{run_id}", lab.member)
    assert "X-Amz" not in page.text and "127.0.0.1:1" not in page.text


async def test_the_run_page_groups_the_bundle_and_the_attachments_as_the_bucket_lists_them(lab):
    run_id = await lab.make_run(state="pass", bundle_key=f"msp/{lab.msp_id}/runs/{uuid.uuid4()}/")
    key = (await RunRepo(lab.session).get(lab.msp_id, run_id)).bundle_key
    lab.stubber.add_response(
        "list_objects_v2",
        {"Contents": [{"Key": key + n} for n in ("veeam-session.log", "result.json", "screenshot.png", "signature.json", "items.csv")]},
        expected_params={"Bucket": "test-bucket", "Prefix": key, "MaxKeys": 1000},
    )

    page = await lab.get(f"/runs/{run_id}", lab.member)

    bundle = re.search(r"<p>Bundle: (.*?)</p>", page.text).group(1)
    attachments = re.search(r"<p>Attachments: (.*?)</p>", page.text).group(1)
    assert re.findall(r">([^<]+)</a>", bundle) == ["result.json", "signature.json"]
    assert re.findall(r">([^<]+)</a>", attachments) == ["items.csv", "screenshot.png", "veeam-session.log"]


# --- /workers -----------------------------------------------------------------------------------


async def test_the_workers_page_shows_the_heartbeat_s_columns_and_red_past_24_hours(lab):
    lab.time = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    at = lab.time
    workers = WorkerRepo(lab.session)
    assert await workers.heartbeat(lab.msp_id, lab.worker_id, at=at - LATE_AFTER, version="1.2.3", last_error="job_invalid", last_error_at=at - dt.timedelta(hours=30), outbox_depth=4, uptime_s=3661) == 1
    assert await workers.heartbeat(lab.msp_id, lab.other_worker_id, at=at - LATE_AFTER - dt.timedelta(seconds=1), version="0.0.0", last_error=None, last_error_at=None, outbox_depth=0, uptime_s=59) == 1

    page = await lab.get("/workers", lab.admin)

    rows = {re.search(r"<td>([^<]+)</td>", row).group(1): re.sub(r"\s+", " ", row) for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page.text, re.S)[1:]}
    cell(rows["w1"], "<td>1.2.3</td>", "<td>2026-10-11 10:00 UTC</td>", "<code>job_invalid</code> at 2026-10-11 04:00 UTC", '<td class="num">4</td>', '<td class="num">1:01:01</td>', "Revoke</button>")
    assert 'class="late"' not in rows["w1"]
    cell(rows["w2"], "<td>0.0.0</td>", '<td class="late">2026-10-11 09:59 UTC</td>', "<td>—</td>", '<td class="num">0</td>', '<td class="num">0:59</td>')
    assert f'hx-confirm="Revoke w1? Its token stops working at its next request."' in page.text
    assert f'hx-post="/workers/{lab.worker_id}/revoke"' in page.text and f'action="/workers/{lab.worker_id}/revoke"' in page.text


def test_late_is_more_than_24_hours_or_never():
    at = dt.datetime(2026, 10, 12, 10, 0, tzinfo=UTC)

    assert late(None, at) is True
    assert late(at - LATE_AFTER, at) is False
    assert late(at - LATE_AFTER - dt.timedelta(seconds=1), at) is True
    assert LATE_AFTER == dt.timedelta(hours=24)


async def test_an_htmx_revoke_answers_the_row_alone(lab):
    response = await lab.post(f"/workers/{lab.worker_id}/revoke", lab.admin, headers={"HX-Request": "true"})

    assert response.status_code == 200
    assert response.text.lstrip().startswith(f'<tr id="worker-{lab.worker_id}">') and "<html" not in response.text
    assert "revoked " in response.text and "Revoke</button>" not in response.text


async def test_the_frame_names_the_msp_and_the_user_and_the_admin_s_audit_link(lab):
    member = await lab.get("/clients", lab.member)
    admin = await lab.get("/clients", lab.admin)

    assert '<span class="msp">contract</span>' in member.text and '<span class="user">member@example.test</span>' in member.text
    assert 'href="/audit"' not in member.text and 'href="/audit"' in admin.text
    assert (await lab.get("/", lab.member)).headers["location"] == "/clients"


def test_the_filters():
    assert ui.duration(None) == "—" and ui.duration(0) == "0:00" and ui.duration(61_500) == "1:01" and ui.duration(3_600_000) == "1:00:00"
    assert ui.utc(None) == "—" and ui.utc(dt.datetime(2026, 10, 12, 1, 2, 3, tzinfo=UTC)) == "2026-10-12 01:02 UTC"
    assert ui.utc(dt.datetime(2026, 10, 12, 3, 2, 3, tzinfo=dt.timezone(dt.timedelta(hours=2))), True) == "2026-10-12 01:02:03 UTC"
    assert ui.colour(None) == "none" and ui.colour("pass") == "pass" and ui.colour("expired") == "quiet" and ui.colour("made up") == "quiet"
    assert (ui.yes_no(None), ui.yes_no(True), ui.yes_no(False)) == ("—", "yes", "no")
