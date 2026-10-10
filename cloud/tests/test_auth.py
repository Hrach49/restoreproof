"""C5.4: `current_worker` (docs/decisions.md 2026-10-10, "C5.3 and C5.4",
point 5). Done when: a revoked token gets 401 and a valid one passes.

A probe route under /v1, added to the workers router for the test as
tests/test_app.py adds its wiring probe, guarded by Depends(current_worker),
on the app the factory makes, with get_session overridden to the test's own
session so the Worker rows the test made are the ones the dependency sees.
"""

from __future__ import annotations

import datetime as dt
import io

import httpx
import pytest
from fastapi import Depends, Request

from app.auth.dependency import current_worker
from app.auth.tokens import new_token, token_hash
from app.db import get_session
from app.main import create_app
from app.models import Worker
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.workers import WorkerRepo
from app.routers import workers
from tests.conftest import make_settings

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
PROBE = "/workers/auth-probe"

REFUSED_BODY = {"detail": "not authenticated"}


class Lab:
    """The app with the probe route, two Workers (one revoked) and the log."""

    def __init__(self, session):
        self.session = session
        self.stream = io.StringIO()
        self.before = list(workers.router.routes)

        async def probe(request: Request, worker: Worker = Depends(current_worker)):
            return {
                "worker_id": str(worker.id),
                "state_worker_id": str(request.state.worker.id),
                "msp_id": str(request.state.msp_id),
            }

        workers.router.add_api_route(PROBE, probe, methods=["GET"])
        self.app = create_app(make_settings(), log_stream=self.stream)
        self.app.dependency_overrides[get_session] = lambda: session

    @classmethod
    async def make(cls, session) -> "Lab":
        lab = cls(session)
        lab.msp = await MspRepo(session).create(name="a")
        lab.token = new_token()
        lab.worker = await WorkerRepo(session).create(
            lab.msp.id, name="live", public_key_pem=PEM, api_token_hash=token_hash(lab.token)
        )
        lab.revoked_token = new_token()
        lab.revoked = await WorkerRepo(session).create(
            lab.msp.id, name="revoked", public_key_pem=PEM, api_token_hash=token_hash(lab.revoked_token)
        )
        assert await WorkerRepo(session).revoke(lab.msp.id, lab.revoked.id, NOW) == 1
        return lab

    def close(self) -> None:
        workers.router.routes[:] = self.before

    async def get(self, headers: dict[str, str] | None = None) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.get(f"/v1{PROBE}", headers=headers or {})

    @property
    def log(self) -> str:
        return self.stream.getvalue()


@pytest.fixture
async def lab(session):
    lab = await Lab.make(session)
    try:
        yield lab
    finally:
        lab.close()


def refusals(lab: Lab) -> list[tuple[str, dict[str, str] | None]]:
    return [
        ("no header", None),
        ("Basic", {"Authorization": "Basic dXNlcjpwYXNz"}),
        ("two spaces", {"Authorization": f"Bearer  {lab.token}"}),
        ("a word after the token", {"Authorization": f"Bearer {lab.token} extra"}),
        ("another scheme's case", {"Authorization": f"bearer {lab.token}"}),
        ("an empty token", {"Authorization": "Bearer "}),
        ("an unknown token of the right shape", {"Authorization": f"Bearer {new_token()}"}),
        ("the hash in place of the token", {"Authorization": f"Bearer {token_hash(lab.token)}"}),
        ("a revoked Worker's token", {"Authorization": f"Bearer {lab.revoked_token}"}),
    ]


# --- The Done-when ------------------------------------------------------------------------


async def test_a_revoked_token_gets_401_and_a_valid_one_passes(lab):
    revoked = await lab.get({"Authorization": f"Bearer {lab.revoked_token}"})
    valid = await lab.get({"Authorization": f"Bearer {lab.token}"})

    assert (revoked.status_code, revoked.json()) == (401, REFUSED_BODY)
    assert revoked.headers["www-authenticate"] == "Bearer"
    assert valid.status_code == 200
    assert valid.json() == {
        "worker_id": str(lab.worker.id),
        "state_worker_id": str(lab.worker.id),
        "msp_id": str(lab.msp.id),
    }


# --- Every refusal is one and the same answer ----------------------------------------------


async def test_every_refusal_has_one_status_body_and_header(lab):
    answers = []
    for name, headers in refusals(lab):
        response = await lab.get(headers)
        answers.append((name, response.status_code, response.text, response.headers.get("www-authenticate")))

    assert len(answers) == 9
    assert {answer[1:] for answer in answers} == {(401, '{"detail":"not authenticated"}', "Bearer")}


async def test_every_refusal_and_the_success_do_the_same_work(lab, monkeypatch):
    """One hash, one lookup, one comparison, whatever the failure: nothing in
    the timing tells a caller a malformed header from an unknown token or a
    revoked Worker."""
    looked_up = []
    original = Lookup.find_worker_by_token_hash

    async def counting(self, token_hash_value):
        looked_up.append(token_hash_value)
        return await original(self, token_hash_value)

    monkeypatch.setattr(Lookup, "find_worker_by_token_hash", counting)

    for _name, headers in refusals(lab):
        await lab.get(headers)
    await lab.get({"Authorization": f"Bearer {lab.token}"})

    assert len(looked_up) == len(refusals(lab)) + 1
    assert all(len(value) == 64 for value in looked_up)
    assert looked_up[0] == token_hash("")  # no header: the empty token's hash is looked up
    assert looked_up[-1] == token_hash(lab.token)


async def test_a_revoked_worker_is_refused_whenever_revoked_at_is_set(lab):
    """The time doesn't matter: a revocation in the future is a revocation."""
    future_token = new_token()
    worker = await WorkerRepo(lab.session).create(
        lab.msp.id, name="later", public_key_pem=PEM, api_token_hash=token_hash(future_token)
    )
    await WorkerRepo(lab.session).revoke(lab.msp.id, worker.id, NOW + dt.timedelta(days=3650))

    response = await lab.get({"Authorization": f"Bearer {future_token}"})

    assert (response.status_code, response.json()) == (401, REFUSED_BODY)


async def test_the_worker_and_its_msp_are_on_the_request_state(lab):
    response = await lab.get({"Authorization": f"Bearer {lab.token}"})

    assert response.json()["msp_id"] == str(lab.msp.id)
    assert response.json()["state_worker_id"] == response.json()["worker_id"]


# --- The token never reaches a log line -----------------------------------------------------


async def test_neither_the_token_nor_its_hash_is_in_any_log_line(lab):
    failed = await lab.get({"Authorization": f"Bearer {lab.revoked_token}"})
    passed = await lab.get({"Authorization": f"Bearer {lab.token}"})
    malformed = await lab.get({"Authorization": f"Bearer  {lab.token}"})

    assert (failed.status_code, passed.status_code, malformed.status_code) == (401, 200, 401)
    log = lab.log
    assert log.count('"event": "request"') == 3
    for secret in (lab.token, lab.revoked_token, token_hash(lab.token), token_hash(lab.revoked_token)):
        assert secret not in log
    assert "Bearer" not in log
    assert "authorization" not in log.lower()


# --- The route depends on get_session ------------------------------------------------------------


async def test_the_dependency_takes_its_session_from_get_session(lab):
    """Without the override the app's engine (a closed port) would answer; the
    probe passes only because the dependency asked get_session."""
    lab.app.dependency_overrides.clear()

    response = await lab.get({"Authorization": f"Bearer {lab.token}"})

    assert response.status_code == 500
    assert response.json()["error"] == "internal"


async def test_the_probe_is_the_test_s_alone():
    assert PROBE not in [route.path for route in workers.router.routes]
