"""C5.6: `GET /v1/jobs` (docs/decisions.md 2026-10-10, "C5.5 and C5.6",
point 4). Done when: two polls return the same job only if the first attempt
expired.

The app the factory makes with `get_session` overridden to the test's own
session; a Worker with an API token; the Worker's queued runs answered oldest
first, at most five, as a `restoreproof.jobs.v1` document the shared schema
validates, each run now `dispatched`. The race runs on a database of its own.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import io
import re
import uuid

import asyncpg
import httpx
import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.auth.dependency import current_worker
from app.auth.tokens import new_token, token_hash
from app.db import get_session, make_session_factory
from app.main import create_app
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import DISPATCH_LIMIT, RunRepo
from app.routers.jobs import JobsDocument
from app.repo.workers import WorkerRepo
from tests.conftest import asyncpg_dsn, make_settings, session_override
from tests.test_jobs_schema import VALIDATOR
from tests.test_repo_connectors import profile_for

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
PATH = "/v1/jobs"
FORMAT = "restoreproof.jobs.v1"
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
# The Worker's folder rule for a run_id (job_rules::is_folder_run_id): the
# schema's pattern, no ':', no '.' at the end, not a DOS device's name.
RUN_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
DOS_DEVICES = re.compile(r"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9]|LPT[0-9])(\..*)?$", re.IGNORECASE)
JOB_KEYS = [
    "client", "client_id", "connector", "restore_point", "run_id",
    "sample_mail", "sample_od", "sample_sp", "screenshots_enabled",
]


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


class Lab:
    """One MSP with a client on two Workers, each with a plan; the first
    Worker's API token in hand; a second MSP with one Worker and run."""

    def __init__(self, session):
        self.session = session
        self.stream = io.StringIO()
        self.app = create_app(make_settings(), log_stream=self.stream)
        self.app.dependency_overrides[get_session] = session_override(session)

    async def fill(self) -> None:
        s = self.session
        self.msp_id = (await MspRepo(s).create(name="a")).id
        client = await ClientRepo(s).create(self.msp_id, name="contoso", tenant_id=uuid.uuid4(), screenshots_enabled=True)
        self.client_id, self.tenant_id = client.id, client.tenant_id
        self.token = new_token()
        self.worker_id = (await WorkerRepo(s).create(
            self.msp_id, "w1", public_key_pem=PEM, key_id=a_hash("k1"), api_token_hash=token_hash(self.token)
        )).id
        self.other_token = new_token()
        self.other_worker_id = (await WorkerRepo(s).create(
            self.msp_id, "w2", public_key_pem=PEM, key_id=a_hash("k2"), api_token_hash=token_hash(self.other_token)
        )).id
        self.profile = profile_for(self.tenant_id)
        self.connector_id = (await ConnectorRepo(s).create(self.msp_id, self.client_id, self.worker_id, self.profile)).id
        self.other_connector_id = (await ConnectorRepo(s).create(
            self.msp_id, self.client_id, self.other_worker_id, self.profile
        )).id
        self.plan_id = (await PlanRepo(s).create(
            self.msp_id, self.client_id, self.connector_id, sample_mail=7, sample_sp=0, sample_od=2, cadence_cron="0 2 * * *", now=NOW
        )).id
        self.other_plan_id = (await PlanRepo(s).create(
            self.msp_id, self.client_id, self.other_connector_id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 3 * * *", now=NOW
        )).id
        # The other MSP: its own client, Worker, connector, plan and one run.
        self.b_msp_id = (await MspRepo(s).create(name="b")).id
        b_client = await ClientRepo(s).create(self.b_msp_id, name="b client", tenant_id=uuid.uuid4())
        self.b_token = new_token()
        b_worker = await WorkerRepo(s).create(
            self.b_msp_id, "bw", public_key_pem=PEM, key_id=a_hash("bk"), api_token_hash=token_hash(self.b_token)
        )
        b_connector = await ConnectorRepo(s).create(self.b_msp_id, b_client.id, b_worker.id, profile_for(b_client.tenant_id))
        b_plan = await PlanRepo(s).create(
            self.b_msp_id, b_client.id, b_connector.id, sample_mail=2, sample_sp=2, sample_od=2, cadence_cron="0 4 * * *", now=NOW
        )
        self.b_run_id = (await RunRepo(s).create(
            self.b_msp_id, plan_id=b_plan.id, client_id=b_client.id, connector_id=b_connector.id, worker_id=b_worker.id
        )).id
        self.clock = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

    async def run(self, *, other: bool = False) -> uuid.UUID:
        """A queued run for the first Worker (or the second), one minute
        younger than the last."""
        row = await RunRepo(self.session).create(
            self.msp_id,
            plan_id=self.other_plan_id if other else self.plan_id,
            client_id=self.client_id,
            connector_id=self.other_connector_id if other else self.connector_id,
            worker_id=self.other_worker_id if other else self.worker_id,
        )
        self.clock += dt.timedelta(minutes=1)
        await self.session.execute(
            text("UPDATE test_run SET created_at = :at WHERE id = :id"), {"at": self.clock, "id": row.id}
        )
        return row.id

    async def state_of(self, run_id: uuid.UUID, msp_id=None) -> tuple:
        row = await RunRepo(self.session).get(msp_id or self.msp_id, run_id)
        await self.session.refresh(row)
        return (row.state, row.attempt, row.dispatched_at)

    async def get(self, token: str | None = None, method: str = "GET") -> httpx.Response:
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.request(method, PATH, headers=headers)

    async def poll(self, token: str | None = None) -> list[str]:
        """The run_ids of a 200 answer, after the document is validated."""
        response = await self.get(self.token if token is None else token)
        assert response.status_code == 200, response.text
        document = response.json()
        assert VALIDATOR.is_valid(document), sorted(error.json_path for error in VALIDATOR.iter_errors(document))
        assert document["format"] == FORMAT
        return [job["run_id"] for job in document["jobs"]]

    @property
    def log(self) -> str:
        return self.stream.getvalue()


@pytest.fixture
async def lab(session):
    lab = Lab(session)
    await lab.fill()
    return lab


# --- The Done-when ------------------------------------------------------------------------


async def test_two_polls_return_the_same_job_only_if_the_first_attempt_expired(lab):
    first, second = await lab.run(), await lab.run()
    other = await lab.run(other=True)
    runs = RunRepo(lab.session)

    assert await lab.poll() == [str(first), str(second)]
    for run_id in (first, second):
        state, attempt, dispatched_at = await lab.state_of(run_id)
        assert (state, attempt) == ("dispatched", 1)
        assert abs(dt.datetime.now(UTC) - dispatched_at) < dt.timedelta(minutes=5)
    assert await lab.poll() == []
    assert await lab.poll(lab.other_token) == [str(other)]
    assert await lab.state_of(lab.b_run_id, lab.b_msp_id) == ("queued", 0, None)

    # Six hours on, the sweep puts both back (and the other Worker's one, the
    # sweep being the MSP's); the third poll answers them again.
    assert await runs.requeue_stale(lab.msp_id, dt.datetime.now(UTC) + dt.timedelta(hours=6)) == (3, 0)
    assert await lab.state_of(other) == ("queued", 1, (await lab.state_of(other))[2])
    assert await lab.poll() == [str(first), str(second)]
    assert (await lab.state_of(first))[:2] == ("dispatched", 2)
    assert await lab.poll() == []

    # After the third attempt the sweep expires them; a fourth poll answers nothing.
    assert await runs.requeue_stale(lab.msp_id, dt.datetime.now(UTC) + dt.timedelta(hours=12)) == (2, 0)
    assert await lab.poll() == [str(first), str(second)]
    assert await runs.requeue_stale(lab.msp_id, dt.datetime.now(UTC) + dt.timedelta(hours=18)) == (0, 2)
    assert await lab.poll() == []
    assert (await lab.state_of(first))[:2] == ("expired", 3)


# --- The document, field by field --------------------------------------------------------


async def test_each_job_carries_the_run_the_client_s_profile_the_connector_and_the_plan(lab):
    run_id = await lab.run()

    response = await lab.get(lab.token)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    document = response.json()
    assert sorted(document) == ["format", "jobs"]
    (job,) = document["jobs"]
    assert sorted(job) == JOB_KEYS  # no canary_cursor: the Worker defaults it
    assert job["run_id"] == str(run_id)
    assert job["client_id"] == str(lab.client_id)
    assert job["client"] == lab.profile
    assert job["client"]["graph_tenant_id"] == str(lab.tenant_id)
    assert job["connector"] == {"type": "veeam_m365"}
    assert (job["sample_mail"], job["sample_sp"], job["sample_od"]) == (7, 0, 2)
    assert job["restore_point"] == "latest"
    assert job["screenshots_enabled"] is True
    assert VALIDATOR.is_valid(document)


async def test_a_plan_opted_in_to_canaries_sends_its_cursor_and_a_plain_one_none(lab):
    """C6.8 (docs/decisions.md 2026-10-15, point 10): the job's `canary_cursor`
    is the plan's three columns, the key's presence the Worker's opt-in
    (W6.2); a plan without a cursor leaves the key out, never `null`, which
    the Worker's reader refuses."""
    opted = (await PlanRepo(lab.session).create(
        lab.msp_id, lab.client_id, lab.connector_id, sample_mail=2, sample_sp=2, sample_od=2, cadence_cron="0 5 * * *", now=NOW,
        canary_cursor=(0, 0, 0),
    )).id
    plain_run = await lab.run()
    opted_run = (await RunRepo(lab.session).create(
        lab.msp_id, plan_id=opted, client_id=lab.client_id, connector_id=lab.connector_id, worker_id=lab.worker_id
    )).id
    await lab.session.execute(text("UPDATE test_run SET created_at = :at WHERE id = :id"), {"at": lab.clock + dt.timedelta(minutes=1), "id": opted_run})
    await lab.session.execute(
        text("UPDATE test_plan SET canary_cursor_mail = 3, canary_cursor_sp = 1, canary_cursor_od = 999999 WHERE id = :id"), {"id": opted}
    )

    response = await lab.get(lab.token)

    document = response.json()
    assert VALIDATOR.is_valid(document), sorted(error.json_path for error in VALIDATOR.iter_errors(document))
    plain, with_canaries = document["jobs"]
    assert (plain["run_id"], with_canaries["run_id"]) == (str(plain_run), str(opted_run))
    assert sorted(plain) == JOB_KEYS and "canary_cursor" not in plain
    assert sorted(with_canaries) == sorted(JOB_KEYS + ["canary_cursor"])
    assert with_canaries["canary_cursor"] == [3, 1, 999999]


async def test_a_run_id_names_a_folder_on_the_worker(lab):
    run_id = str(await lab.run())
    (answered,) = await lab.poll()

    assert answered == run_id
    assert RUN_ID.fullmatch(answered)
    assert ":" not in answered and not answered.endswith(".") and answered not in (".", "..")
    assert not DOS_DEVICES.match(answered)
    assert len(answered) == 36


async def test_screenshots_enabled_is_the_client_s(lab):
    await lab.run()
    assert await ClientRepo(lab.session).update(lab.msp_id, lab.client_id, name="contoso", screenshots_enabled=False) == 1

    response = await lab.get(lab.token)

    assert response.json()["jobs"][0]["screenshots_enabled"] is False


async def test_at_most_five_oldest_first_and_the_rest_at_the_next_poll(lab):
    run_ids = [str(await lab.run()) for _ in range(7)]

    assert await lab.poll() == run_ids[:5]
    assert await lab.poll() == run_ids[5:]
    assert await lab.poll() == []


# --- Nothing to do, and who may ask --------------------------------------------------------


async def test_a_worker_with_nothing_queued_gets_an_empty_document(lab):
    response = await lab.get(lab.token)

    assert (response.status_code, response.json()) == (200, {"format": FORMAT, "jobs": []})
    assert VALIDATOR.is_valid(response.json())


async def test_a_worker_with_no_connector_gets_an_empty_document(lab):
    token = new_token()
    await WorkerRepo(lab.session).create(
        lab.msp_id, "bare", public_key_pem=PEM, key_id=a_hash("bare"), api_token_hash=token_hash(token)
    )

    assert await lab.poll(token) == []


async def test_a_revoked_worker_and_no_token_are_401_and_nothing_is_dispatched(lab):
    run_id = await lab.run()
    assert await WorkerRepo(lab.session).revoke(lab.msp_id, lab.worker_id, dt.datetime.now(UTC)) == 1

    revoked = await lab.get(lab.token)
    without = await lab.get(None)
    unknown = await lab.get(new_token())

    for response in (revoked, without, unknown):
        assert (response.status_code, response.json()) == (401, {"detail": "not authenticated"})
        assert response.headers["www-authenticate"] == "Bearer"
    assert await lab.state_of(run_id) == ("queued", 0, None)


async def test_another_worker_s_and_another_msp_s_runs_are_never_answered(lab):
    mine = await lab.run()
    other = await lab.run(other=True)

    assert await lab.poll() == [str(mine)]
    assert await lab.poll(lab.b_token) == [str(lab.b_run_id)]
    assert await lab.state_of(other) == ("queued", 0, None)
    assert await lab.poll(lab.other_token) == [str(other)]


async def test_the_route_is_get_only(lab):
    response = await lab.get(lab.token, method="POST")

    assert response.status_code == 405


async def test_the_token_reaches_no_log_line(lab):
    await lab.run()
    assert await lab.poll() != []

    assert lab.log.count('"event": "request"') == 1
    assert lab.token not in lab.log
    assert token_hash(lab.token) not in lab.log
    assert "Bearer" not in lab.log


# --- Two polls at once, on a database of their own -----------------------------------------


async def test_two_polls_at_once_share_no_run(own_database):
    engine = create_async_engine(own_database, connect_args={"server_settings": {"timezone": "UTC"}})
    token = new_token()
    async with make_session_factory(engine)() as session:
        async with session.begin():
            msp = await MspRepo(session).create(name="race")
            client = await ClientRepo(session).create(msp.id, name="c", tenant_id=uuid.uuid4())
            worker = await WorkerRepo(session).create(
                msp.id, "w", public_key_pem=PEM, key_id=a_hash("race"), api_token_hash=token_hash(token)
            )
            connector = await ConnectorRepo(session).create(msp.id, client.id, worker.id, profile_for(client.tenant_id))
            plan = await PlanRepo(session).create(
                msp.id, client.id, connector.id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 2 * * *", now=NOW
            )
            for _ in range(6):
                await RunRepo(session).create(
                    msp.id, plan_id=plan.id, client_id=client.id, connector_id=connector.id, worker_id=worker.id
                )
    application = create_app(make_settings(), log_stream=io.StringIO())
    application.state.session_factory = make_session_factory(engine)
    try:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            headers = {"Authorization": f"Bearer {token}"}
            answers = await asyncio.gather(client.get(PATH, headers=headers), client.get(PATH, headers=headers))
    finally:
        await engine.dispose()

    assert [response.status_code for response in answers] == [200, 200]
    taken = [[job["run_id"] for job in response.json()["jobs"]] for response in answers]
    # Two backends locking row by row may split 5/1, 4/2 or 3/3 (the review's
    # finding 4): what holds is disjoint, every run once, none over five.
    assert not set(taken[0]) & set(taken[1])
    assert sum(len(jobs) for jobs in taken) == 6
    assert max(len(jobs) for jobs in taken) <= 5
    connection = await asyncpg.connect(asyncpg_dsn(own_database), timeout=5)
    try:
        assert await connection.fetchval("SELECT count(*) FROM test_run WHERE state = 'dispatched'") == 6
        assert await connection.fetchval("SELECT count(*) FROM test_run WHERE attempt = 1") == 6
    finally:
        await connection.close()


# --- The route's statements and its inputs (the review's findings 5 and 6) -----------------


async def test_a_poll_is_three_statements_busy_and_two_idle(lab, test_engine):
    """current_worker's lookup, the dispatch, and one joined select for the
    runs' plan, connector and client; nothing per run."""
    for _ in range(5):
        await lab.run()
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        assert len(await lab.poll()) == 5
        busy = [s for s in counted if s in ("SELECT", "UPDATE", "WITH")]
        counted.clear()
        assert await lab.poll() == []
        idle = [s for s in counted if s in ("SELECT", "UPDATE", "WITH")]
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert busy == ["SELECT", "WITH", "SELECT"]
    assert idle == ["SELECT", "WITH"]


async def test_the_route_takes_the_msp_from_the_worker_it_was_given(lab):
    """The review's finding 6: not from request.state, which only
    current_worker sets; an override of the dependency still works."""
    run_id = await lab.run()
    worker = await WorkerRepo(lab.session).get(lab.msp_id, lab.worker_id)
    lab.app.dependency_overrides[current_worker] = lambda: worker

    response = await lab.get(None)

    assert response.status_code == 200
    assert [job["run_id"] for job in response.json()["jobs"]] == [str(run_id)]


def test_the_document_s_limit_is_the_repo_s_constant():
    (length,) = [m.max_length for m in JobsDocument.model_fields["jobs"].metadata if hasattr(m, "max_length")]

    assert length == DISPATCH_LIMIT == 5
