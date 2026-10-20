"""W7.3: `POST /v1/workers/self/revoke` (docs/decisions.md 2026-10-19, "W7.3
(#82) and W7.4 (#83)", point 5): the Worker revokes itself at uninstall. The
token's Worker gets `onboarding.revoke_worker`, the CLI's and the `/workers`
page's function: `revoked_at` set once and one `worker.revoke` audit row with
the Worker's address and no user; 204 with no body. No, another or a revoked
Worker's token is `current_worker`'s one 401 after the same work, before
anything is written; from the commit on the heartbeat, the poll and a second
revoke are that 401.

The app the factory makes with `get_session` overridden to the test's own
session; the Workers as tests/test_heartbeat.py makes them.
"""

from __future__ import annotations

import datetime as dt
import io
import uuid

import httpx
import pytest
from sqlalchemy import text

from app.auth.tokens import new_token, token_hash
from app.db import get_session
from app.main import create_app
from app.repo.audit import AuditRepo
from app.repo.msps import MspRepo
from app.repo.workers import WorkerRepo
from tests.conftest import make_settings, session_override

UTC = dt.timezone.utc
PATH = "/v1/workers/self/revoke"
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
T = dt.datetime(2026, 10, 19, 15, 0, 0, tzinfo=UTC)
REFUSED = {"detail": "not authenticated"}
NO_TOKEN = object()
HEARTBEAT = b'{"last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":0,"version":"0.1.1"}'


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


class Lab:
    """One MSP with two Workers, the first one's token in hand, one of them
    revoked already; a second MSP with one Worker; the log."""

    def __init__(self, session):
        self.session = session
        self.stream = io.StringIO()
        self.app = create_app(make_settings(), log_stream=self.stream)
        self.app.dependency_overrides[get_session] = session_override(session)

    async def fill(self) -> None:
        s = self.session
        self.msp_id = (await MspRepo(s).create(name="a")).id
        self.token = new_token()
        self.worker_id = (await WorkerRepo(s).create(
            self.msp_id, "w1", public_key_pem=PEM, key_id=a_hash("k1"), api_token_hash=token_hash(self.token),
            version="0.1.0",
        )).id
        self.other_token = new_token()
        self.other_worker_id = (await WorkerRepo(s).create(
            self.msp_id, "w2", public_key_pem=PEM, key_id=a_hash("k2"), api_token_hash=token_hash(self.other_token)
        )).id
        self.revoked_token = new_token()
        self.revoked_worker_id = (await WorkerRepo(s).create(
            self.msp_id, "gone", public_key_pem=PEM, key_id=a_hash("k3"), api_token_hash=token_hash(self.revoked_token)
        )).id
        assert await WorkerRepo(s).revoke(self.msp_id, self.revoked_worker_id, T - dt.timedelta(days=1)) == 1
        self.b_msp_id = (await MspRepo(s).create(name="b")).id
        self.b_token = new_token()
        self.b_worker_id = (await WorkerRepo(s).create(
            self.b_msp_id, "bw", public_key_pem=PEM, key_id=a_hash("bk"), api_token_hash=token_hash(self.b_token)
        )).id

    async def request(self, method: str, path: str, token=None, content: bytes = b"") -> httpx.Response:
        """`token` None is the Lab's own; NO_TOKEN sends no header."""
        headers = {}
        if token is not NO_TOKEN:
            headers["Authorization"] = f"Bearer {self.token if token is None else token}"
        if content:
            headers["Content-Type"] = "application/json"
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.request(method, path, headers=headers, content=content)

    async def revoke(self, token=None) -> httpx.Response:
        return await self.request("POST", PATH, token)

    async def revoked_at(self, worker_id=None, msp_id=None):
        worker = await WorkerRepo(self.session).get(msp_id or self.msp_id, worker_id or self.worker_id)
        await self.session.refresh(worker)
        return worker.revoked_at

    async def audit(self, msp_id=None) -> list[tuple]:
        return sorted(
            (row.action, row.target, row.user_id, row.ip) for row in await AuditRepo(self.session).list(msp_id or self.msp_id)
        )

    async def counts(self) -> dict[str, int]:
        return {
            name: await self.session.scalar(text(f"SELECT count(*) FROM {name}")) for name in ("worker", "audit_log")
        }

    @property
    def log(self) -> str:
        return self.stream.getvalue()


@pytest.fixture
async def lab(session):
    lab = Lab(session)
    await lab.fill()
    return lab


# --- Refusals, before anything is written ----------------------------------------------------


@pytest.mark.parametrize("token", [NO_TOKEN, "B" * 43, "not-a-token", ""])
async def test_no_or_another_token_is_the_one_401_and_nothing_is_written(lab, token):
    before = await lab.counts()
    audit_before = await lab.audit()

    response = await lab.revoke(token)

    assert response.status_code == 401
    assert response.json() == REFUSED
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["X-RestoreProof-API"] == "1"
    assert await lab.revoked_at() is None
    assert await lab.counts() == before and await lab.audit() == audit_before


async def test_a_revoked_worker_s_token_is_the_same_401_and_its_time_stays(lab):
    audit_before = await lab.audit()

    response = await lab.revoke(lab.revoked_token)

    assert (response.status_code, response.json()) == (401, REFUSED)
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert await lab.revoked_at(lab.revoked_worker_id) == T - dt.timedelta(days=1)
    assert await lab.audit() == audit_before


async def test_a_body_is_not_read_and_changes_nothing_of_the_answer(lab):
    response = await lab.request("POST", PATH, content=b'{"worker_id": "someone else"}')

    assert (response.status_code, response.content) == (204, b"")
    assert await lab.revoked_at() is not None


async def test_the_wrong_method_is_405_and_touches_nothing(lab):
    response = await lab.request("GET", PATH)

    assert response.status_code == 405
    assert await lab.revoked_at() is None


# --- The revoke ------------------------------------------------------------------------------


async def test_the_token_s_worker_is_revoked_once_with_one_audit_row(lab):
    before = await lab.counts()

    response = await lab.revoke()

    assert (response.status_code, response.content) == (204, b"")
    assert "content-type" not in response.headers
    assert response.headers["X-RestoreProof-API"] == "1"
    revoked_at = await lab.revoked_at()
    assert revoked_at is not None and revoked_at.tzinfo is not None
    assert abs(revoked_at - dt.datetime.now(UTC)) < dt.timedelta(minutes=5)
    # The other Workers, this MSP's and the other MSP's, are untouched.
    assert await lab.revoked_at(lab.other_worker_id) is None
    assert await lab.revoked_at(lab.b_worker_id, lab.b_msp_id) is None
    after = await lab.counts()
    assert after == {**before, "audit_log": before["audit_log"] + 1}
    rows = [row for row in await lab.audit() if row[0] == "worker.revoke" and row[1] == f"worker:{lab.worker_id}"]
    assert len(rows) == 1
    action, target, user_id, ip = rows[0]
    assert user_id is None and ip is not None
    assert await lab.audit(lab.b_msp_id) == []


async def test_a_revoke_that_lands_between_the_lookup_and_the_update_is_the_same_401(lab, monkeypatch):
    # The admin's Revoke on /workers (or a second uninstall) commits between
    # `current_worker`'s lookup and this request's UPDATE: the row the
    # dependency loaded was live, the UPDATE under `revoked_at IS NULL`
    # touches 0 rows. The heartbeat's rule for the same race: the one 401,
    # nothing written, never a 500. The 0 rows are made here on the repo
    # method, the one statement that decides it.
    before = await lab.counts()
    audit_before = await lab.audit()

    async def no_rows(self, msp_id, worker_id, at):
        return 0

    monkeypatch.setattr(WorkerRepo, "revoke", no_rows)
    response = await lab.revoke()

    assert response.status_code == 401
    assert response.json() == REFUSED
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["X-RestoreProof-API"] == "1"
    assert await lab.counts() == before and await lab.audit() == audit_before


async def test_from_the_commit_on_every_request_under_the_token_is_401(lab):
    assert (await lab.revoke()).status_code == 204
    audit_after = await lab.audit()

    second = await lab.revoke()
    heartbeat = await lab.request("POST", "/v1/heartbeat", content=HEARTBEAT)
    poll = await lab.request("GET", "/v1/jobs")

    assert [r.status_code for r in (second, heartbeat, poll)] == [401, 401, 401]
    assert all(r.json() == REFUSED for r in (second, heartbeat, poll))
    assert await lab.audit() == audit_after
    # The other Worker of the MSP still works.
    assert (await lab.request("GET", "/v1/jobs", lab.other_token)).status_code == 200


async def test_the_other_worker_s_token_revokes_the_other_worker_alone(lab):
    response = await lab.revoke(lab.other_token)

    assert response.status_code == 204
    assert await lab.revoked_at(lab.other_worker_id) is not None
    assert await lab.revoked_at() is None


# --- Nothing of the token in the log --------------------------------------------------------


async def test_nothing_of_the_token_reaches_a_log_line(lab):
    assert (await lab.revoke(new_token())).status_code == 401
    assert (await lab.revoke()).status_code == 204
    assert (await lab.revoke()).status_code == 401

    log = lab.log
    assert log.count('"event": "request"') == 3
    for secret in (lab.token, token_hash(lab.token), "Bearer", "authorization", "Authorization"):
        assert secret not in log
    assert '"status": 204' in log and '"status": 401' in log
