"""C5.8: `POST /v1/heartbeat` (docs/decisions.md 2026-10-11, "C5.8"). Done
when: the dashboard column "last seen" (C6.2) updates every 15 minutes.

The app the factory makes with `get_session` overridden to the test's own
session; a Worker with an API token; the Worker's own recorded heartbeat
bodies (docs/api/veeam-lab/w4.11-3-service-run.txt lines 294 and 313) posted
byte for byte as `rp::send_heartbeat` posts them. C6.2's `/workers` page will
read `WorkerRepo.list`; the Done-when is that read after two heartbeats fifteen
minutes apart on the router's clock. The race runs on a database of its own.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import io
import json
import uuid

import httpx
import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.auth.dependency import current_worker
from app.auth.tokens import new_token, token_hash
from app.db import get_session, make_session_factory
from app.main import create_app
from app.models import Base
from app.repo.msps import MspRepo
from app.repo.workers import WorkerRepo
from app.routers import heartbeat as heartbeat_module
from app.routers import workers as workers_module
from tests.conftest import make_settings, session_override

UTC = dt.timezone.utc
PATH = "/v1/heartbeat"
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
T = dt.datetime(2026, 10, 11, 9, 0, 0, tzinfo=UTC)
FIFTEEN_MINUTES = dt.timedelta(seconds=900)  # heartbeat_interval_s's default
REFUSED = {"detail": "not authenticated"}

# The service's first heartbeat (88 bytes) and one after a job_invalid run
# (121 bytes), as the W4.11 stub Cloud printed them.
FIRST = b'{"last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":0,"version":"0.0.0"}'
AFTER_ERROR = (
    b'{"last_error":"job_invalid","last_error_at":"2026-10-09T20:27:38.206Z",'
    b'"outbox_depth":0,"uptime_s":152,"version":"0.0.0"}'
)
ERROR_AT = dt.datetime(2026, 10, 9, 20, 27, 38, 206000, tzinfo=UTC)
GOOD = json.loads(AFTER_ERROR)
NO_TOKEN = object()


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


def body_with(**changes) -> dict:
    body = dict(GOOD)
    for key, value in changes.items():
        if value is ...:
            del body[key]
        else:
            body[key] = value
    return body


class Lab:
    """One MSP with two Workers, the first one's token in hand; a second MSP
    with one Worker; the log."""

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
            version="0.0.0-registered",
        )).id
        self.other_token = new_token()
        self.other_worker_id = (await WorkerRepo(s).create(
            self.msp_id, "w2", public_key_pem=PEM, key_id=a_hash("k2"), api_token_hash=token_hash(self.other_token)
        )).id
        self.b_msp_id = (await MspRepo(s).create(name="b")).id
        self.b_token = new_token()
        self.b_worker_id = (await WorkerRepo(s).create(
            self.b_msp_id, "bw", public_key_pem=PEM, key_id=a_hash("bk"), api_token_hash=token_hash(self.b_token)
        )).id

    async def post(
        self, body, token=None, *, content_type: str = "application/json", method: str = "POST"
    ) -> httpx.Response:
        """`token` None is the Lab's own; NO_TOKEN sends no header."""
        headers = {"Content-Type": content_type}
        if token is not NO_TOKEN:
            headers["Authorization"] = f"Bearer {self.token if token is None else token}"
        content = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.request(method, PATH, headers=headers, content=content)

    async def row(self, worker_id=None, msp_id=None) -> tuple:
        """The six heartbeat columns as the database has them."""
        worker = await WorkerRepo(self.session).get(msp_id or self.msp_id, worker_id or self.worker_id)
        await self.session.refresh(worker)
        return (
            worker.last_seen_at, worker.version, worker.last_error, worker.last_error_at,
            worker.outbox_depth, worker.uptime_s,
        )

    async def counts(self) -> dict[str, int]:
        return {
            name: await self.session.scalar(text(f"SELECT count(*) FROM {name}"))
            for name in sorted(Base.metadata.tables)
        }

    @property
    def log(self) -> str:
        return self.stream.getvalue()


UNTOUCHED = (None, "0.0.0-registered", None, None, None, None)
NEVER = (None, None, None, None, None, None)


@pytest.fixture
async def lab(session):
    lab = Lab(session)
    await lab.fill()
    return lab


@pytest.fixture
def clock(monkeypatch):
    """The router's clock, set by the test."""
    times = {"now": T}
    monkeypatch.setattr(heartbeat_module, "now", lambda: times["now"])
    return times


# --- The Done-when ------------------------------------------------------------------------


async def test_the_dashboard_column_last_seen_updates_every_15_minutes(lab, clock):
    """C6.2's /workers page reads WorkerRepo.list; this is that read."""
    assert len(AFTER_ERROR) == 121 and len(FIRST) == 88

    response = await lab.post(AFTER_ERROR)

    assert (response.status_code, response.content) == (204, b"")
    rows = {w.name: w for w in await WorkerRepo(lab.session).list(lab.msp_id)}
    assert {name: w.last_seen_at for name, w in rows.items()} == {"w1": T, "w2": None}
    w1 = rows["w1"]
    assert (w1.version, w1.last_error, w1.last_error_at, w1.outbox_depth, w1.uptime_s) == (
        "0.0.0", "job_invalid", ERROR_AT, 0, 152,
    )
    assert (await lab.row(lab.b_worker_id, lab.b_msp_id))[0] is None

    # Fifteen minutes later the service has restarted: no error since its start.
    clock["now"] = T + FIFTEEN_MINUTES
    response = await lab.post(FIRST)

    assert (response.status_code, response.content) == (204, b"")
    # No expire: the UPDATE keeps the session's loaded rows in step (the review's finding 4).
    rows = {w.name: w for w in await WorkerRepo(lab.session).list(lab.msp_id)}
    assert {name: w.last_seen_at for name, w in rows.items()} == {"w1": T + FIFTEEN_MINUTES, "w2": None}
    w1 = rows["w1"]
    assert (w1.version, w1.last_error, w1.last_error_at, w1.outbox_depth, w1.uptime_s) == ("0.0.0", None, None, 0, 0)
    assert (await lab.row(lab.b_worker_id, lab.b_msp_id))[0] is None


# --- Who may send one: the one 401 --------------------------------------------------------


async def test_no_token_an_unknown_token_and_a_revoked_worker_are_one_401(lab, clock):
    before = await lab.counts()
    assert await WorkerRepo(lab.session).revoke(lab.msp_id, lab.other_worker_id, T) == 1

    without = await lab.post(AFTER_ERROR, NO_TOKEN)
    unknown = await lab.post(AFTER_ERROR, new_token())
    revoked = await lab.post(AFTER_ERROR, lab.other_token)

    for response in (without, unknown, revoked):
        assert (response.status_code, response.json()) == (401, REFUSED)
        assert response.headers["www-authenticate"] == "Bearer"
    assert await lab.row() == UNTOUCHED
    assert (await lab.row(lab.other_worker_id))[0] is None
    assert await lab.counts() == before


async def test_a_basic_header_is_the_same_401(lab):
    transport = httpx.ASGITransport(app=lab.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
        response = await client.post(
            PATH,
            headers={"Authorization": "Basic dXNlcjpwYXNz", "Content-Type": "application/json"},
            content=AFTER_ERROR,
        )

    assert (response.status_code, response.json()) == (401, REFUSED)
    assert await lab.row() == UNTOUCHED


async def test_a_worker_revoked_between_the_lookup_and_the_update_is_401_and_nothing_is_written(lab, clock):
    """The dependency answered the row; the revoke commits before the UPDATE,
    whose WHERE holds revoked_at IS NULL."""
    worker = await WorkerRepo(lab.session).get(lab.msp_id, lab.worker_id)
    lab.app.dependency_overrides[current_worker] = lambda: worker
    assert await WorkerRepo(lab.session).revoke(lab.msp_id, lab.worker_id, T) == 1
    before = await lab.counts()

    response = await lab.post(AFTER_ERROR, NO_TOKEN)

    assert (response.status_code, response.json()) == (401, REFUSED)
    assert response.headers["www-authenticate"] == "Bearer"
    assert await lab.row() == UNTOUCHED
    assert await lab.counts() == before


# --- The body: the Worker's five keys and nothing else -----------------------------------


BAD_BODIES = {
    "no version": body_with(version=...),
    "no last_error": body_with(last_error=...),
    "no last_error_at": body_with(last_error_at=...),
    "no outbox_depth": body_with(outbox_depth=...),
    "no uptime_s": body_with(uptime_s=...),
    "a sixth key": body_with(worker_id="w"),
    "an empty object": {},
    "an array": [GOOD],
    "a string": "heartbeat",
    "version empty": body_with(version=""),
    "version 65 characters": body_with(version="v" * 65),
    "version with a tab": body_with(version="0.0\t0"),
    "version non-ASCII": body_with(version="0.0.0é"),
    "version null": body_with(version=None),
    "last_error What()": body_with(last_error="What()"),
    "last_error with a space": body_with(last_error="job invalid"),
    "last_error 65 characters": body_with(last_error="e" * 65),
    "last_error empty": body_with(last_error=""),
    "last_error uppercase": body_with(last_error="Job_Invalid"),
    "last_error a number": body_with(last_error=4),
    "last_error without its time": body_with(last_error_at=None),
    "a time without its error": body_with(last_error=None),
    "time without milliseconds": body_with(last_error_at="2026-10-09T20:27:38Z"),
    "time with an offset": body_with(last_error_at="2026-10-09T20:27:38.206+00:00"),
    "time a date alone": body_with(last_error_at="2026-10-09"),
    "time 30th of February": body_with(last_error_at="2026-02-30T00:00:00.000Z"),
    "time hour 24": body_with(last_error_at="2026-10-09T24:00:00.000Z"),
    "time a number": body_with(last_error_at=1760000000),
    "time in other digits": body_with(last_error_at="\u0662\u0660\u0662\u0666-10-09T20:27:38.206Z"),
    "time with a line end": body_with(last_error_at="2026-10-09T20:27:38.206Z\n"),
    "outbox_depth -1": body_with(outbox_depth=-1),
    "outbox_depth 2^53": body_with(outbox_depth=2**53),
    "outbox_depth 1.0": body_with(outbox_depth=1.0),
    "outbox_depth '1'": body_with(outbox_depth="1"),
    "outbox_depth true": body_with(outbox_depth=True),
    "outbox_depth null": body_with(outbox_depth=None),
    "uptime_s -1": body_with(uptime_s=-1),
    "uptime_s 2^53": body_with(uptime_s=2**53),
    "uptime_s 1.0": body_with(uptime_s=1.0),
    "uptime_s '1'": body_with(uptime_s="1"),
    "uptime_s true": body_with(uptime_s=True),
    "uptime_s null": body_with(uptime_s=None),
}


@pytest.mark.parametrize("body", list(BAD_BODIES.values()), ids=list(BAD_BODIES))
async def test_a_body_outside_the_worker_s_five_keys_is_422_and_the_row_is_untouched(lab, clock, body):
    before = await lab.counts()

    response = await lab.post(body)

    assert response.status_code == 422, response.text
    assert await lab.row() == UNTOUCHED
    assert await lab.counts() == before


async def test_a_body_that_is_not_json_is_422(lab, clock):
    not_json = await lab.post(b"last_error=null", content_type="application/json")
    plain = await lab.post(AFTER_ERROR, content_type="text/plain")

    assert (not_json.status_code, plain.status_code) == (422, 422)
    assert await lab.row() == UNTOUCHED


# --- The token before the body (the C5.8 review's finding 1) ----------------------------------


# Past the parser's recursion depth (about a thousand), and under C5.11's 64 KiB
# body cap, which answers a longer body 413 before the route runs.
NESTED = b"[" * 30_000
HUGE_NUMBER = b'{"last_error":null,"last_error_at":null,"outbox_depth":' + b"9" * 5000 + b',"uptime_s":0,"version":"0.0.0"}'
UNREADABLE = {
    "not json": b"last_error=null",
    "nested past the parser's depth": NESTED,
    "a 5000-digit integer": HUGE_NUMBER,
    "not utf-8": b'{"version":"\xff"}',
    "empty": b"",
}


@pytest.mark.parametrize("content", list(UNREADABLE.values()), ids=list(UNREADABLE))
async def test_a_body_nothing_can_read_is_401_without_a_token_and_422_with_one(lab, clock, content):
    """Never FastAPI's own 400, which the contract doesn't name."""
    without = await lab.post(content, NO_TOKEN)
    unknown = await lab.post(content, new_token())
    known = await lab.post(content)

    for response in (without, unknown):
        assert (response.status_code, response.json()) == (401, REFUSED)
        assert response.headers["www-authenticate"] == "Bearer"
    assert known.status_code == 422, known.text
    assert isinstance(known.json()["detail"], list)
    assert await lab.row() == UNTOUCHED


async def test_another_content_type_is_401_without_a_token(lab, clock):
    response = await lab.post(AFTER_ERROR, NO_TOKEN, content_type="text/plain")

    assert (response.status_code, response.json()) == (401, REFUSED)


@pytest.mark.parametrize("content_type", ["application/json; charset=utf-8", "Application/JSON"])
async def test_the_media_type_is_read_in_any_case_and_with_a_parameter(lab, clock, content_type):
    assert (await lab.post(AFTER_ERROR, content_type=content_type)).status_code == 204


async def test_a_request_without_a_content_type_is_422(lab, clock):
    transport = httpx.ASGITransport(app=lab.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
        response = await client.post(PATH, headers={"Authorization": f"Bearer {lab.token}"}, content=AFTER_ERROR)

    assert response.status_code == 422
    assert await lab.row() == UNTOUCHED


async def test_the_body_of_a_request_without_a_token_is_never_read(lab, clock):
    pulled: list[int] = []

    async def chunks():
        for chunk in (AFTER_ERROR[:40], AFTER_ERROR[40:]):
            pulled.append(len(chunk))
            yield chunk

    transport = httpx.ASGITransport(app=lab.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
        response = await client.post(PATH, headers={"Content-Type": "application/json"}, content=chunks())

    assert (response.status_code, response.json()) == (401, REFUSED)
    assert pulled == []


# --- A key twice (finding 2) -------------------------------------------------------------------


TWICE = {
    "uptime_s twice": b'{"last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":0,"uptime_s":5,"version":"0.0.0"}',
    "version twice, the same": b'{"last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":0,"version":"0.0.0","version":"0.0.0"}',
    "last_error twice": b'{"last_error":"job_invalid","last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":0,"version":"0.0.0"}',
}


@pytest.mark.parametrize("content", list(TWICE.values()), ids=list(TWICE))
async def test_a_key_twice_is_422_and_the_row_is_untouched(lab, clock, content):
    response = await lab.post(content)

    assert response.status_code == 422, response.text
    assert await lab.row() == UNTOUCHED


async def test_the_largest_counts_the_body_may_carry_are_taken(lab, clock):
    response = await lab.post(body_with(outbox_depth=2**53 - 1, uptime_s=2**53 - 1))

    assert response.status_code == 204
    assert (await lab.row())[4:] == (2**53 - 1, 2**53 - 1)


async def test_the_route_is_post_only(lab):
    assert (await lab.post(AFTER_ERROR, method="GET")).status_code == 405
    assert (await lab.post(AFTER_ERROR, method="PUT")).status_code == 405


# --- What is written -------------------------------------------------------------------------


async def test_the_204_has_no_body_and_no_content_type(lab, clock):
    response = await lab.post(FIRST)

    assert response.status_code == 204
    assert response.content == b""
    assert "content-type" not in response.headers
    assert response.headers.get("content-length", "0") == "0"


async def test_version_is_replaced_and_a_null_clears_a_stored_error(lab, clock):
    assert (await lab.post(AFTER_ERROR)).status_code == 204
    assert await lab.row() == (T, "0.0.0", "job_invalid", ERROR_AT, 0, 152)

    later = body_with(version="0.1.0", last_error=None, last_error_at=None, outbox_depth=4, uptime_s=9)
    assert (await lab.post(later)).status_code == 204

    assert await lab.row() == (T, "0.1.0", None, None, 4, 9)


async def test_last_seen_at_is_the_cloud_s_clock_never_the_body_s_time(lab, clock):
    ahead = body_with(last_error_at="2027-10-09T20:27:38.206Z")

    assert (await lab.post(ahead)).status_code == 204

    row = await lab.row()
    assert row[0] == T
    assert row[3] == dt.datetime(2027, 10, 9, 20, 27, 38, 206000, tzinfo=UTC)


async def test_the_time_is_stored_to_the_millisecond_as_utc(lab, clock):
    assert (await lab.post(body_with(last_error_at="2026-10-09T23:59:59.999Z"))).status_code == 204

    assert (await lab.row())[3] == dt.datetime(2026, 10, 9, 23, 59, 59, 999000, tzinfo=UTC)


async def test_a_heartbeat_writes_the_worker_s_row_and_nothing_else(lab, clock):
    before = await lab.counts()

    assert (await lab.post(AFTER_ERROR)).status_code == 204

    assert await lab.counts() == before
    assert await lab.row(lab.other_worker_id) == NEVER
    assert await lab.row(lab.b_worker_id, lab.b_msp_id) == NEVER


async def test_a_heartbeat_is_two_statements(lab, clock, test_engine):
    """current_worker's lookup and the one UPDATE; nothing is read back."""
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        assert (await lab.post(AFTER_ERROR)).status_code == 204
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert [s for s in counted if s in ("SELECT", "UPDATE", "INSERT", "WITH")] == ["SELECT", "UPDATE"]


async def test_the_route_takes_the_worker_from_the_dependency_it_was_given(lab, clock):
    """Not from request.state, which only current_worker sets."""
    worker = await WorkerRepo(lab.session).get(lab.msp_id, lab.other_worker_id)
    lab.app.dependency_overrides[current_worker] = lambda: worker

    response = await lab.post(AFTER_ERROR, NO_TOKEN)

    assert response.status_code == 204
    assert (await lab.row(lab.other_worker_id))[0] == T
    assert await lab.row() == UNTOUCHED


# --- Nothing of the token or the body in the log --------------------------------------------


async def test_neither_the_token_nor_any_body_value_reaches_a_log_line(lab, clock):
    body = body_with(version="9.8.7-rc1", last_error="recovery_clean_incomplete", outbox_depth=7351, uptime_s=90001)

    assert (await lab.post(body)).status_code == 204
    assert (await lab.post(body, new_token())).status_code == 401
    assert (await lab.post(body_with(version=""))).status_code == 422

    log = lab.log
    assert log.count('"event": "request"') == 3
    for secret in (lab.token, token_hash(lab.token), "Bearer", "authorization", "Authorization"):
        assert secret not in log
    for value in ("9.8.7-rc1", "recovery_clean_incomplete", "2026-10-09T20:27:38.206Z", "7351", "90001", "job_invalid"):
        assert value not in log
    assert '"status": 204' in log and '"status": 401' in log and '"status": 422' in log


# --- Two heartbeats at once, on a database of their own ------------------------------------


async def test_two_heartbeats_at_once_both_land_and_the_row_is_one_of_them_whole(own_database):
    engine = create_async_engine(own_database, connect_args={"server_settings": {"timezone": "UTC"}})
    token = new_token()
    async with make_session_factory(engine)() as session:
        async with session.begin():
            msp = await MspRepo(session).create(name="race")
            worker = await WorkerRepo(session).create(
                msp.id, "w", public_key_pem=PEM, key_id=a_hash("race"), api_token_hash=token_hash(token)
            )
            msp_id, worker_id = msp.id, worker.id
    one = body_with(version="1.0.0", last_error=None, last_error_at=None, outbox_depth=1, uptime_s=10)
    two = body_with(
        version="2.0.0", last_error="not_read", last_error_at="2026-10-11T08:00:00.000Z", outbox_depth=2, uptime_s=20
    )
    application = create_app(make_settings(), log_stream=io.StringIO())
    application.state.session_factory = make_session_factory(engine)
    try:
        transport = httpx.ASGITransport(app=application)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            answers = await asyncio.gather(
                client.post(PATH, headers=headers, content=json.dumps(one).encode()),
                client.post(PATH, headers=headers, content=json.dumps(two).encode()),
            )
        async with make_session_factory(engine)() as session:
            row = await WorkerRepo(session).get(msp_id, worker_id)
            stored = (row.version, row.last_error, row.last_error_at, row.outbox_depth, row.uptime_s, row.last_seen_at)
    finally:
        await engine.dispose()

    assert [response.status_code for response in answers] == [204, 204]
    assert stored[:5] in (
        ("1.0.0", None, None, 1, 10),
        ("2.0.0", "not_read", dt.datetime(2026, 10, 11, 8, 0, tzinfo=UTC), 2, 20),
    )
    assert abs(dt.datetime.now(UTC) - stored[5]) < dt.timedelta(minutes=5)


# --- The model's own rules --------------------------------------------------------------------


def test_the_body_model_is_closed_and_names_the_five_keys():
    schema = heartbeat_module.HeartbeatBody.model_json_schema()

    assert schema["additionalProperties"] is False
    assert sorted(schema["required"]) == ["last_error", "last_error_at", "outbox_depth", "uptime_s", "version"]
    assert heartbeat_module.MAX_COUNT == 2**53 - 1


def test_last_error_at_is_parsed_once_into_the_worker_s_time_as_an_aware_utc_datetime():
    """Finding 8: the model holds the datetime; nothing parses the text again."""
    body = heartbeat_module.HeartbeatBody.model_validate(GOOD)
    first = heartbeat_module.HeartbeatBody.model_validate(json.loads(FIRST))

    assert body.last_error_at == ERROR_AT and body.last_error_at.tzinfo is UTC
    assert first.last_error_at is None
    assert not hasattr(body, "error_time")
    with pytest.raises(ValueError):
        heartbeat_module.HeartbeatBody.model_validate(body_with(last_error_at=ERROR_AT))


def test_the_version_rule_is_registration_s_own():
    """Finding 7: one type, so a version registration takes the heartbeat takes."""
    assert heartbeat_module.Version is workers_module.Version
    registered = workers_module.RegisterBody.model_json_schema()["properties"]["version"]
    assert heartbeat_module.HeartbeatBody.model_json_schema()["properties"]["version"] == registered
    assert registered == {"maxLength": 64, "minLength": 1, "pattern": "^[ -~]+$", "title": "Version", "type": "string"}
