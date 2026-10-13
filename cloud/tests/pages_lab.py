"""The lab the page tests share (tests/test_pages.py, tests/test_audit_page.py;
C6.2 and C6.3): the C5.7 results lab (the app over the test's session, the
bucket on botocore's `Stubber`, the TSA root the vector's) filled with the
world the Worker-written vector names (tests/test_contract.py's
`fill_contract`), an admin and a member of that MSP, an admin of a second
MSP with a client, a Worker and a queued run of its own, a session cookie for
each, the session clock and the pages' clock on one time the test moves, the
login limiter on a still clock. `land_vector` posts the Worker's own bundle as
`POST /v1/results` takes it, so the pages render a real Worker run.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import httpx
from sqlalchemy import text

from app import onboarding, ui
from app.auth import sessions
from app.auth.login_limiter import LoginLimiter
from app.auth.sessions import SESSION_COOKIE, make_session
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.users import UserRepo
from app.repo.workers import WorkerRepo
from app.routers import results as results_route
from tests.conftest import make_settings
from tests.results_lab import NOW, Lab
from tests.test_contract import VECTOR, fill_contract, poll, vector_bytes
from tests.test_repo_connectors import profile_for
from tests.test_verify_bundle_timestamp import tsa_ca

UTC = dt.timezone.utc
SECRET = "test-secret-key-" + "0" * 32
IP = "127.0.0.1"
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
# The vector's file names, as the bucket lists them after `land_vector`.
VECTOR_FILES = sorted(VECTOR["files"])


class PagesLab:
    def __init__(self, session, monkeypatch):
        root = VECTOR["tsa_root"]
        self.inner = Lab(session, tsa_ca=tsa_ca(root)) if root is not None else Lab(session)
        self.session = session
        self.app = self.inner.app
        self.stubber = self.inner.stubber
        self.settings = make_settings(SESSION_COOKIE_SECURE="false")
        self.app.state.settings = self.settings
        self.app.state.login_limiter = LoginLimiter(lambda: 0.0)
        # After the rows' own `password_changed_at` (the database's clock).
        self.time = dt.datetime.now(UTC).replace(microsecond=0) + dt.timedelta(minutes=1)
        monkeypatch.setattr(sessions, "now", lambda: self.time)
        monkeypatch.setattr(ui, "now", lambda: self.time)
        monkeypatch.setattr(onboarding, "now", lambda: self.time)
        # The upload's clock: a minute after the vector's stamp, as a Worker
        # that reaches the Cloud uploads (a result received once its month
        # had closed is the month's it arrived in); a test moves it.
        self.received = dt.datetime.fromisoformat(VECTOR["tsa_time"].replace("Z", "+00:00")) + dt.timedelta(minutes=1)
        monkeypatch.setattr(results_route, "now", lambda: self.received)

    async def fill(self) -> None:
        s = self.session
        await fill_contract(self.inner)
        self.msp_id = self.inner.msp_id
        self.client_id = self.inner.client_id
        self.worker_id = self.inner.worker_id
        self.other_worker_id = self.inner.other_worker_id
        self.plan_id = self.inner.plan_id
        self.token = self.inner.token
        users = UserRepo(s)
        self.admin = await users.create(self.msp_id, email="admin@example.test", password_hash="x", role="admin")
        self.member = await users.create(self.msp_id, email="member@example.test", password_hash="x", role="member")
        # The other MSP: an admin, a client, a Worker, a connector, a plan and a queued run.
        self.b_msp_id = (await MspRepo(s).create(name="Other MSP")).id
        self.b_admin = await users.create(self.b_msp_id, email="b@example.test", password_hash="x", role="admin")
        self.b_client_id = (await ClientRepo(s).create(self.b_msp_id, name="B client", tenant_id=uuid.uuid4())).id
        self.b_worker_id = (await WorkerRepo(s).create(
            self.b_msp_id, "b worker", public_key_pem=PEM, key_id="b" * 64, api_token_hash="c" * 64
        )).id
        b_tenant = (await ClientRepo(s).get(self.b_msp_id, self.b_client_id)).tenant_id
        self.b_connector_id = (await ConnectorRepo(s).create(self.b_msp_id, self.b_client_id, self.b_worker_id, profile_for(b_tenant))).id
        self.b_plan_id = (await PlanRepo(s).create(
            self.b_msp_id, self.b_client_id, self.b_connector_id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 4 * * *", now=NOW
        )).id
        self.b_run_id = (await RunRepo(s).create(
            self.b_msp_id, plan_id=self.b_plan_id, client_id=self.b_client_id, connector_id=self.b_connector_id, worker_id=self.b_worker_id
        )).id
        # The connectors' own audit rows (ConnectorRepo writes one each): moved
        # to a day no page's default span reaches, so a test's rows are the
        # pages' own; `written()` counts from here.
        await s.execute(text("UPDATE audit_log SET at = '2020-01-01T00:00:00Z'"))
        self.baseline = await self.count("audit_log")
        # The users' passwords were "changed" long ago, so a test may put the
        # clock anywhere after 2020 and the cookies still hold.
        await s.execute(text('UPDATE "user" SET password_changed_at = \'2020-01-01T00:00:00Z\''))
        for user in (self.admin, self.member, self.b_admin):
            await s.refresh(user)  # the session's own copies, which `UserRepo.get` answers
        # The vector's run began long ago too, so a test's own runs are the
        # newest and today's strip cell is the test's alone.
        await s.execute(text("UPDATE test_run SET created_at = '2020-01-01T00:00:00Z' WHERE id = :id"), {"id": self.inner.run_id})

    # --- requests ------------------------------------------------------------------------------

    def cookie(self, user) -> str:
        return make_session(SECRET, user.id, user.msp_id, user.password_changed_at)

    def client(self, user=None, *, ip: str = IP) -> httpx.AsyncClient:
        cookies = {SESSION_COOKIE: self.cookie(user)} if user is not None else None
        transport = httpx.ASGITransport(app=self.app, client=(ip, 40000))
        return httpx.AsyncClient(transport=transport, base_url="http://cloud.test", cookies=cookies)

    async def get(self, path: str, user=None, *, headers: dict[str, str] | None = None, ip: str = IP) -> httpx.Response:
        async with self.client(user, ip=ip) as client:
            return await client.get(path, headers=headers or {})

    async def post(self, path: str, user=None, *, headers: dict[str, str] | None = None, ip: str = IP, data: Any = None) -> httpx.Response:
        async with self.client(user, ip=ip) as client:
            return await client.post(path, headers=headers or {}, data=data)

    # --- rows ----------------------------------------------------------------------------------

    async def land_vector(self) -> uuid.UUID:
        """The Worker's run dispatched by its own poll and its bundle posted
        as the Worker posts it: 202 `pass`."""
        polled = await poll(self.inner)
        assert polled.status_code == 200, polled.text
        parts = {p["name"]: vector_bytes(p["filename"]) for p in VECTOR["upload"]}
        self.inner.expect_puts(self.inner.run_id, parts)
        response = await self.inner.upload(parts)
        assert response.status_code == 202, response.text
        self.stubber.assert_no_pending_responses()
        return self.inner.run_id

    async def make_run(self, *, client_id=None, worker_id=None, plan_id=None, connector_id=None, state: str = "queued", created_at: dt.datetime | None = None, **columns) -> uuid.UUID:
        """A run of the MSP's client on its first Worker (or as given), with
        any column set by hand."""
        row = await RunRepo(self.session).create(
            self.msp_id,
            plan_id=plan_id or self.plan_id,
            client_id=client_id or self.client_id,
            connector_id=connector_id or self.inner.connector_id,
            worker_id=worker_id or self.worker_id,
        )
        values = {"state": state, **columns}
        if created_at is not None:
            values["created_at"] = created_at
        assignments = ", ".join(f"{name} = :{name}" for name in values)
        await self.session.execute(text(f"UPDATE test_run SET {assignments} WHERE id = :id"), {**values, "id": row.id})
        return row.id

    def expect_list(self, run_id: uuid.UUID, names: list[str], *, msp_id: uuid.UUID | None = None) -> None:
        prefix = f"msp/{msp_id or self.msp_id}/runs/{run_id}/"
        self.stubber.add_response(
            "list_objects_v2",
            {"Contents": [{"Key": prefix + name} for name in names]} if names else {},
            expected_params={"Bucket": self.settings.s3_bucket, "Prefix": prefix, "MaxKeys": 1000},
        )

    async def count(self, table: str) -> int:
        return (await self.session.execute(text(f'SELECT count(*) FROM "{table}"'))).scalar_one()

    async def written(self) -> int:
        """How many audit rows the pages wrote since the lab was filled."""
        return await self.count("audit_log") - self.baseline

    @property
    def log(self) -> str:
        return self.inner.log
