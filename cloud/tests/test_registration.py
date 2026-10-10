"""C5.5: `POST /v1/workers/register` (docs/decisions.md 2026-10-10, "C5.5 and
C5.6", point 3). Done when: the Worker's registration flow succeeds and the
token cannot be reused.

The app the factory makes, with `get_session` overridden to the test's own
session (tests/conftest.py, `session_override`, the same generator as the
real one over a savepoint), so what a refused request rolled back is seen.
The order of checks: the install token (401), the key (400), the key's unique
(409), then 201 with the API token once. A failed registration leaves the
token unused; the two races run on a database of their own.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import io
import json
import re
import uuid

import asyncpg
import httpx
import pytest
from fastapi import Depends
from sqlalchemy.ext.asyncio import create_async_engine

from app.auth.dependency import current_worker
from app.auth.tokens import issue_install_token, new_token, token_hash
from app.db import get_session, make_session_factory
from app.main import create_app
from app.models import Worker
from app.repo.audit import AuditRepo
from app.repo.install_tokens import InstallTokenRepo
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.workers import WorkerRepo
from app.routers import workers
from tests.conftest import asyncpg_dsn, make_settings, session_override
from tests.test_public_keys import ACCEPTED, REFUSED, pem_of
from tests.test_verify_bundle import KEY_FILES, file_bytes

UTC = dt.timezone.utc
PATH = "/v1/workers/register"
PROBE = "/workers/registration-probe"
TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_-]{43}$")

KEY = pem_of(ACCEPTED[0]["raw"])
KEY_ID = ACCEPTED[0]["key_id"]
# RFC 8032's test 2, another published key.
OTHER_KEY = pem_of("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")

NOT_AUTHENTICATED = {"detail": "not authenticated"}
KEY_REFUSED = {"detail": "public_key_pem: not an accepted Ed25519 public key"}
ALREADY_REGISTERED = {"detail": "public_key_pem: already registered"}


def body(**changes) -> dict:
    values = {"install_token": "", "public_key_pem": KEY, "worker_name": "veeam-vm", "version": "0.0.0"}
    return {**values, **changes}


class Lab:
    def __init__(self, session):
        self.session = session
        self.stream = io.StringIO()
        self.before = list(workers.router.routes)

        async def probe(worker: Worker = Depends(current_worker)):
            return {"worker_id": str(worker.id)}

        workers.router.add_api_route(PROBE, probe, methods=["GET"])
        self.app = create_app(make_settings(), log_stream=self.stream)
        self.app.dependency_overrides[get_session] = session_override(session)

    async def fill(self) -> None:
        # Ids as plain values: a refused request rolls its savepoint back, which
        # expires every row the session holds, and an expired attribute can't
        # be loaded outside the driver's greenlet.
        self.msp_id = (await MspRepo(self.session).create(name="a")).id
        self.now = dt.datetime.now(UTC)

    def close(self) -> None:
        workers.router.routes[:] = self.before

    async def issue(self, *, at: dt.datetime | None = None, msp_id=None) -> tuple[str, uuid.UUID]:
        """The token and its row's id."""
        token, row = await issue_install_token(
            self.session, msp_id or self.msp_id, at or self.now, label="the Veeam VM"
        )
        return token, row.id

    async def post(self, payload) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.post(PATH, json=payload)

    async def get(self, token: str) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.get(f"/v1{PROBE}", headers={"Authorization": f"Bearer {token}"})

    @property
    def log(self) -> str:
        return self.stream.getvalue()


@contextlib.asynccontextmanager
async def open_lab(session):
    lab = Lab(session)
    try:
        await lab.fill()
        yield lab
    finally:
        lab.close()


@pytest.fixture
async def lab(session):
    async with open_lab(session) as lab:
        yield lab


# --- The Done-when ------------------------------------------------------------------------


async def test_the_registration_flow_succeeds_and_the_token_cannot_be_reused(lab):
    install_token, row_id = await lab.issue()

    registered = await lab.post(body(install_token=install_token))
    again = await lab.post(body(install_token=install_token, public_key_pem=OTHER_KEY))

    assert registered.status_code == 201, registered.text
    answer = registered.json()
    assert sorted(answer) == ["api_token", "key_id", "worker_id"]
    assert TOKEN_SHAPE.fullmatch(answer["api_token"])
    assert answer["key_id"] == KEY_ID
    worker_id = uuid.UUID(answer["worker_id"])

    # The API token passes current_worker; the install token is used once.
    probe = await lab.get(answer["api_token"])
    assert (probe.status_code, probe.json()) == (200, {"worker_id": str(worker_id)})
    assert (again.status_code, again.json()) == (401, NOT_AUTHENTICATED)
    assert again.headers["www-authenticate"] == "Bearer"

    worker = await WorkerRepo(lab.session).get(lab.msp_id, worker_id)
    assert (worker.name, worker.version, worker.public_key_pem, worker.key_id) == ("veeam-vm", "0.0.0", KEY, KEY_ID)
    assert worker.api_token_hash == token_hash(answer["api_token"])
    assert worker.install_token_id == row_id
    assert worker.revoked_at is None
    used = await InstallTokenRepo(lab.session).get(lab.msp_id, row_id)
    assert used.used_at is not None
    # The token itself is nowhere in either row.
    assert answer["api_token"] not in json.dumps({k: str(v) for k, v in vars(worker).items()})


# --- The order of checks, one answer each ----------------------------------------------------


async def test_the_four_answers_in_their_order(lab):
    valid, _ = await lab.issue()
    used, _ = await lab.issue()
    assert (await lab.post(body(install_token=used))).status_code == 201

    # A bad token with a bad key is 401, never 400: nothing is said to a caller
    # without a valid token.
    unknown_bad_key = await lab.post(body(install_token=new_token(), public_key_pem="not a key"))
    used_registered_key = await lab.post(body(install_token=used, public_key_pem=KEY))
    valid_bad_key = await lab.post(body(install_token=valid, public_key_pem="not a key"))
    valid_registered_key = await lab.post(body(install_token=valid, public_key_pem=KEY))
    valid_other_key = await lab.post(body(install_token=valid, public_key_pem=OTHER_KEY))

    assert (unknown_bad_key.status_code, unknown_bad_key.json()) == (401, NOT_AUTHENTICATED)
    assert (used_registered_key.status_code, used_registered_key.json()) == (401, NOT_AUTHENTICATED)
    assert (valid_bad_key.status_code, valid_bad_key.json()) == (400, KEY_REFUSED)
    assert (valid_registered_key.status_code, valid_registered_key.json()) == (409, ALREADY_REGISTERED)
    assert valid_other_key.status_code == 201


async def test_an_unknown_a_used_and_an_expired_token_are_one_401(lab):
    used, _ = await lab.issue()
    assert (await lab.post(body(install_token=used))).status_code == 201
    expired, _ = await lab.issue(at=lab.now - dt.timedelta(days=7, seconds=1))
    tokens = [new_token(), used, expired, "short", "A" * 43, token_hash(used)]

    answers = []
    for token in tokens:
        response = await lab.post(body(install_token=token, public_key_pem=OTHER_KEY))
        answers.append((response.status_code, response.text, response.headers.get("www-authenticate")))

    assert set(answers) == {(401, '{"detail":"not authenticated"}', "Bearer")}
    assert len(await WorkerRepo(lab.session).list(lab.msp_id)) == 1


async def test_a_failed_registration_leaves_the_token_unused(lab):
    token, row_id = await lab.issue()
    other_token, _ = await lab.issue()
    assert (await lab.post(body(install_token=other_token))).status_code == 201  # KEY is now taken

    bad_key = await lab.post(body(install_token=token, public_key_pem="not a key"))
    assert (bad_key.status_code, bad_key.json()) == (400, KEY_REFUSED)
    assert (await InstallTokenRepo(lab.session).get(lab.msp_id, row_id)).used_at is None

    taken_key = await lab.post(body(install_token=token, public_key_pem=KEY))
    assert (taken_key.status_code, taken_key.json()) == (409, ALREADY_REGISTERED)
    assert (await InstallTokenRepo(lab.session).get(lab.msp_id, row_id)).used_at is None
    assert len(await WorkerRepo(lab.session).list(lab.msp_id)) == 1
    assert [r.action for r in await AuditRepo(lab.session).list(lab.msp_id)] == ["worker.register"]

    # The same token, the right key: the operator's second try.
    fixed = await lab.post(body(install_token=token, public_key_pem=OTHER_KEY))
    assert fixed.status_code == 201
    assert (await InstallTokenRepo(lab.session).get(lab.msp_id, row_id)).used_at is not None


@pytest.mark.parametrize("row", REFUSED, ids=lambda row: row["name"])
async def test_a_small_order_or_non_canonical_key_is_the_same_400(lab, row):
    token, row_id = await lab.issue()

    response = await lab.post(body(install_token=token, public_key_pem=pem_of(row["raw"])))

    assert (response.status_code, response.json()) == (400, KEY_REFUSED)
    assert (await InstallTokenRepo(lab.session).get(lab.msp_id, row_id)).used_at is None


@pytest.mark.parametrize(
    "name", [row["name"] for row in KEY_FILES if row["accepted"] and row["name"] != "small-order-identity-key"]
)
async def test_every_accepted_layout_is_stored_in_the_one_form(lab, name):
    row = next(row for row in KEY_FILES if row["name"] == name)
    token, _ = await lab.issue()

    response = await lab.post(body(install_token=token, public_key_pem=file_bytes(row).decode("utf-8")))

    assert response.status_code == 201, response.text
    worker = await WorkerRepo(lab.session).get(lab.msp_id, uuid.UUID(response.json()["worker_id"]))
    assert (worker.public_key_pem, worker.key_id) == (KEY, KEY_ID)


async def test_a_key_registered_in_another_msp_is_still_409(lab):
    other_id = (await MspRepo(lab.session).create(name="b")).id
    token_b, _ = await lab.issue(msp_id=other_id)
    token_a, _ = await lab.issue()
    assert (await lab.post(body(install_token=token_b))).status_code == 201

    response = await lab.post(body(install_token=token_a))

    assert (response.status_code, response.json()) == (409, ALREADY_REGISTERED)
    assert await WorkerRepo(lab.session).list(lab.msp_id) == []
    assert len(await WorkerRepo(lab.session).list(other_id)) == 1


# --- The body ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {k: v for k, v in body(install_token="x").items() if k != "version"},
        {**body(install_token="x"), "extra": 1},
        body(install_token=""),
        body(install_token="x" * 257),
        body(install_token="x", public_key_pem=""),
        body(install_token="x", public_key_pem="k" * 4097),
        body(install_token="x", worker_name=""),
        body(install_token="x", worker_name="a\nb"),
        body(install_token="x", worker_name="a\x7fb"),
        body(install_token="x", worker_name="n" * 129),
        body(install_token="x", version=""),
        body(install_token="x", version="é"),
        body(install_token="x", version="v" * 65),
        body(install_token="x", version="0.0.0\n"),
        body(install_token=123),
        "not an object",
    ],
    ids=lambda payload: json.dumps(payload)[:40],
)
async def test_a_body_that_is_not_the_model_is_422_before_any_lookup(lab, monkeypatch, payload):
    looked_up = []
    original = Lookup.find_install_token_by_hash

    async def counting(self, value):
        looked_up.append(value)
        return await original(self, value)

    monkeypatch.setattr(Lookup, "find_install_token_by_hash", counting)

    response = await lab.post(payload)

    assert response.status_code == 422
    assert looked_up == []
    assert await WorkerRepo(lab.session).list(lab.msp_id) == []


async def test_a_name_may_hold_any_printable_text_and_a_version_ascii_only(lab):
    token, _ = await lab.issue()

    response = await lab.post(body(install_token=token, worker_name="Veeam VM (Köln) #2", version="0.1.0-rc.1+win"))

    assert response.status_code == 201
    worker = await WorkerRepo(lab.session).get(lab.msp_id, uuid.UUID(response.json()["worker_id"]))
    assert (worker.name, worker.version) == ("Veeam VM (Köln) #2", "0.1.0-rc.1+win")


# --- The same work for every token ------------------------------------------------------------


async def test_every_answer_does_the_same_lookup_whatever_the_token_s_shape(lab, monkeypatch):
    looked_up = []
    original = Lookup.find_install_token_by_hash

    async def counting(self, value):
        looked_up.append(value)
        return await original(self, value)

    monkeypatch.setattr(Lookup, "find_install_token_by_hash", counting)
    valid, _ = await lab.issue()
    taken, _ = await lab.issue()

    for token, key in ((taken, KEY), ("short", OTHER_KEY), (new_token(), "bad"), (valid, "bad"), (valid, KEY), (valid, OTHER_KEY)):
        await lab.post(body(install_token=token, public_key_pem=key))

    assert len(looked_up) == 6
    assert all(len(value) == 64 for value in looked_up)
    assert looked_up[1] == token_hash("short")


# --- The audit row and the log ------------------------------------------------------------------


async def test_a_registration_writes_one_audit_row_with_the_caller_s_address(lab):
    token, _ = await lab.issue()

    response = await lab.post(body(install_token=token))

    rows = await AuditRepo(lab.session).list(lab.msp_id)
    assert len(rows) == 1
    row = rows[0]
    assert (row.action, row.target, row.user_id, row.ip) == (
        "worker.register", f"worker:{response.json()['worker_id']}", None, "127.0.0.1"
    )
    assert token not in (row.action + row.target)
    assert response.json()["api_token"] not in (row.action + row.target)


async def test_neither_token_nor_either_hash_reaches_a_log_line(lab):
    token, _ = await lab.issue()
    bad_key_token, _ = await lab.issue()

    created = await lab.post(body(install_token=token))
    refused = await lab.post(body(install_token=new_token()))
    bad_key = await lab.post(body(install_token=bad_key_token, public_key_pem="nope"))
    taken = await lab.post(body(install_token=bad_key_token, public_key_pem=KEY))

    assert (created.status_code, refused.status_code, bad_key.status_code, taken.status_code) == (201, 401, 400, 409)
    api_token = created.json()["api_token"]
    log = lab.log
    assert log.count('"event": "request"') == 4
    for secret in (token, bad_key_token, api_token, token_hash(token), token_hash(bad_key_token), token_hash(api_token)):
        assert secret not in log
    assert "Bearer" not in log
    assert "MCowBQYDK2Vw" not in log  # nothing of the body either


# --- The probe route is the test's alone ---------------------------------------------------------


def test_the_probe_is_the_test_s_alone():
    assert PROBE not in [route.path for route in workers.router.routes]


# --- Two requests at once, on a database of their own -----------------------------------------


async def racing_app(own_database: str):
    engine = create_async_engine(own_database, connect_args={"server_settings": {"timezone": "UTC"}})
    application = create_app(make_settings(), log_stream=io.StringIO())
    application.state.session_factory = make_session_factory(engine)
    return application, engine


async def issue_committed(own_database: str, now: dt.datetime, count: int) -> list[str]:
    engine = create_async_engine(own_database, connect_args={"server_settings": {"timezone": "UTC"}})
    tokens = []
    async with make_session_factory(engine)() as session:
        async with session.begin():
            msp = await MspRepo(session).create(name="race")
            for _ in range(count):
                token, _row = await issue_install_token(session, msp.id, now, label="race")
                tokens.append(token)
    await engine.dispose()
    return tokens


async def post_both(application, payloads) -> list[httpx.Response]:
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
        return list(await asyncio.gather(*(client.post(PATH, json=payload) for payload in payloads)))


async def count_rows(own_database: str, query: str) -> int:
    connection = await asyncpg.connect(asyncpg_dsn(own_database), timeout=5)
    try:
        return await connection.fetchval(query)
    finally:
        await connection.close()


async def test_one_token_sent_twice_at_once_registers_one_worker(own_database):
    (token,) = await issue_committed(own_database, dt.datetime.now(UTC), 1)
    application, engine = await racing_app(own_database)
    try:
        answers = await post_both(
            application, [body(install_token=token), body(install_token=token, public_key_pem=OTHER_KEY)]
        )
    finally:
        await engine.dispose()

    assert sorted(response.status_code for response in answers) == [201, 401]
    assert await count_rows(own_database, "SELECT count(*) FROM worker") == 1
    assert await count_rows(own_database, "SELECT count(*) FROM install_token WHERE used_at IS NOT NULL") == 1


async def test_one_key_sent_with_two_tokens_at_once_registers_one_worker_and_keeps_the_other_token(own_database):
    tokens = await issue_committed(own_database, dt.datetime.now(UTC), 2)
    application, engine = await racing_app(own_database)
    try:
        answers = await post_both(application, [body(install_token=token) for token in tokens])
    finally:
        await engine.dispose()

    assert sorted(response.status_code for response in answers) == [201, 409]
    assert await count_rows(own_database, "SELECT count(*) FROM worker") == 1
    assert await count_rows(own_database, "SELECT count(*) FROM install_token WHERE used_at IS NULL") == 1


async def test_another_refusal_of_the_database_is_not_dressed_as_a_409(lab, monkeypatch):
    """Only `uq_worker_key_id` is the 409; any other IntegrityError is the
    app's own 500, and the token stays unused by the rollback."""
    token, row_id = await lab.issue()
    taken_token, _ = await lab.issue()
    first = await lab.post(body(install_token=taken_token))
    assert first.status_code == 201
    api_token = first.json()["api_token"]
    monkeypatch.setattr("app.auth.registration.new_token", lambda: api_token)  # its hash is taken

    response = await lab.post(body(install_token=token, public_key_pem=OTHER_KEY))

    assert response.status_code == 500
    assert response.json()["error"] == "internal"
    assert (await InstallTokenRepo(lab.session).get(lab.msp_id, row_id)).used_at is None
    assert len(await WorkerRepo(lab.session).list(lab.msp_id)) == 1


async def test_the_worker_row_is_committed_before_the_201_leaves(own_database):
    """The review's finding 1: the Worker's immediate first poll with the new
    token must find the row, so the commit runs before the response starts."""
    (token,) = await issue_committed(own_database, dt.datetime.now(UTC), 1)
    application, engine = await racing_app(own_database)
    reader = await asyncpg.connect(asyncpg_dsn(own_database), timeout=5)
    seen = {}

    async def observing(scope, receive, send):
        async def observe(message):
            if message["type"] == "http.response.start":
                seen["workers"] = await reader.fetchval("SELECT count(*) FROM worker")
                seen["used"] = await reader.fetchval("SELECT count(*) FROM install_token WHERE used_at IS NOT NULL")
            await send(message)

        await application(scope, receive, observe)

    try:
        transport = httpx.ASGITransport(app=observing)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            response = await client.post(PATH, json=body(install_token=token))
    finally:
        await reader.close()
        await engine.dispose()

    assert response.status_code == 201
    assert seen == {"workers": 1, "used": 1}


def test_the_401_is_the_dependency_s_own():
    """The review's finding 7: one helper builds the 401 for both."""
    from app.auth import dependency, registration

    assert registration.not_authenticated is dependency.not_authenticated
    answer = dependency.not_authenticated()
    assert (answer.status_code, answer.detail, answer.headers) == (401, "not authenticated", {"WWW-Authenticate": "Bearer"})


@pytest.mark.parametrize(
    ("field", "value", "kind"),
    [
        ("worker_name", "n" * 129, "string_too_long"),
        ("worker_name", "a\x01b", "string_pattern_mismatch"),
        ("version", "v" * 65, "string_too_long"),
        ("version", "\u00e9", "string_pattern_mismatch"),
    ],
)
async def test_a_length_fault_is_reported_as_a_length_fault(lab, field, value, kind):
    """The review's finding 10: the pattern no longer repeats the length, so a
    string too long is `string_too_long`, not a pattern mismatch."""
    from app.routers.workers import RegisterBody

    response = await lab.post(body(install_token="x", **{field: value}))

    assert response.status_code == 422
    assert [error["type"] for error in response.json()["detail"]] == [kind]
    patterns = {name: [m.pattern for m in info.metadata if hasattr(m, "pattern")] for name, info in RegisterBody.model_fields.items()}
    assert patterns["worker_name"] == ["^[^\\x00-\\x1f\\x7f]+$"]
    assert patterns["version"] == ["^[ -~]+$"]
