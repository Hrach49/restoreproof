"""C5.3's scope test: two MSPs, and no repo call with one's msp_id answers or
changes anything of the other's (docs/decisions.md 2026-10-10, "C5.3 and
C5.4", point 4).

MSP A and MSP B each get one user, client, worker, connector, plan, run with
two items, report, audit row and install token, all through the repos. Every
get and list, called with A's msp_id and B's ids, answers nothing of B's;
every update or delete called with A's msp_id on B's row answers 0 and leaves
the row as it was. A method added to a repo later must be added to the table
here: a test holds the table complete.
"""

from __future__ import annotations

import datetime as dt
import importlib
import inspect
import pkgutil
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

import pytest
from sqlalchemy import text
from sqlalchemy import inspect as sa_inspect

import app.repo
from app.repo.audit import AuditRepo
from app.repo.base import Repo
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.install_tokens import InstallTokenRepo
from app.repo.items import ItemRepo, ItemRow
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.reports import ReportRepo
from app.repo.runs import ReceivedRun, RunRepo
from app.repo.users import UserRepo
from app.repo.workers import WorkerRepo
from tests.test_repo_connectors import profile_for

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


RECEIVED = ReceivedRun(
    state="pass", error_code=None, error_message=None, started_at=NOW, finished_at=NOW, total_ms=1,
    restore_point_at=NOW, bundle_key="msp/x/runs/y/", bundle_sha256="ab" * 32, tsa_ok=None, tsa_time=None,
    cleanup_ok=True,
)


@dataclass
class World:
    """One MSP with one of everything, and a spare client, connector and plan
    that nothing points at, so a delete can be shown to work on one's own."""

    msp: Any
    user: Any
    client: Any
    worker: Any
    connector: Any
    plan: Any
    run: Any
    stale_run: Any = None
    items: list = field(default_factory=list)
    report: Any = None
    audit: Any = None
    token: Any = None
    spare_client: Any = None
    spare_worker: Any = None
    spare_connector: Any = None
    spare_plan: Any = None

    @property
    def ids(self) -> set[uuid.UUID]:
        rows = [self.msp, self.user, self.client, self.worker, self.connector, self.plan, self.run,
                self.stale_run, *self.items, self.report, self.audit, self.token, self.spare_client,
                self.spare_worker, self.spare_connector, self.spare_plan]
        return {row.id for row in rows}


async def make_world(session, name: str) -> World:
    msp = await MspRepo(session).create(name=name)
    user = await UserRepo(session).create(msp.id, email=f"{name}@example.test", password_hash="x", role="admin")
    client = await ClientRepo(session).create(msp.id, name=f"{name} client", tenant_id=uuid.uuid4())
    worker = await WorkerRepo(session).create(
        msp.id, f"{name} worker", public_key_pem=PEM, key_id=a_hash(f"{name} key"), api_token_hash=a_hash(f"{name} worker")
    )
    connector = await ConnectorRepo(session).create(
        msp.id, client.id, worker.id, profile_for(client.tenant_id), user_id=user.id
    )
    plan = await PlanRepo(session).create(
        msp.id, client.id, connector.id, sample_mail=5, sample_sp=3, sample_od=2, cadence_cron="0 2 * * *"
    )
    run = await RunRepo(session).create(
        msp.id, plan_id=plan.id, client_id=client.id, connector_id=connector.id, worker_id=worker.id
    )
    world = World(msp, user, client, worker, connector, plan, run)
    # A run dispatched at NOW, for the sweep to find (C5.6).
    world.stale_run = await RunRepo(session).create(
        msp.id, plan_id=plan.id, client_id=client.id, connector_id=connector.id, worker_id=worker.id
    )
    assert await RunRepo(session).set_state(msp.id, world.stale_run.id, "dispatched") == 1
    await session.execute(
        text("UPDATE test_run SET dispatched_at = :at, attempt = 1 WHERE id = :id"),
        {"at": NOW, "id": world.stale_run.id},
    )
    # One item by `create` and one by `create_many` (C5.7's one INSERT), so
    # both are among the rows every read and write below is held to.
    await ItemRepo(session).create(msp.id, run.id, position=0, type="mail", name=f"{name} item 1", expected_kind="manifest")
    many = ItemRow(
        position=1, type="mail", name=f"{name} item 2", expected_kind="manifest", expected_sha256=None,
        found_sha256=None, found=None, match=None, reason=None, ms=None,
    )
    assert await ItemRepo(session).create_many(msp.id, run.id, [many]) == 1
    world.items.extend(await ItemRepo(session).list(msp.id, run.id))
    assert [item.name for item in world.items] == [f"{name} item 1", f"{name} item 2"]
    world.report = await ReportRepo(session).create(
        msp.id, client.id, period_start=dt.date(2026, 9, 1), period_end=dt.date(2026, 9, 30),
        storage_key=f"{name}/2026-09.pdf", sha256="ab" * 32,
    )
    world.audit = await AuditRepo(session).write(msp.id, action="test.write", target=f"{name}:x", user_id=user.id, ip="10.0.0.1")
    world.token = await InstallTokenRepo(session).create(
        msp.id, token_hash=a_hash(f"{name} token"), expires_at=NOW + dt.timedelta(days=7), label=f"{name} token"
    )
    world.spare_client = await ClientRepo(session).create(msp.id, name=f"{name} spare", tenant_id=uuid.uuid4())
    # The spare connector is the client on a spare Worker, so the spare client
    # has nothing pointing at it and can be deleted.
    world.spare_worker = await WorkerRepo(session).create(
        msp.id, f"{name} spare worker", public_key_pem=PEM, key_id=a_hash(f"{name} spare key"), api_token_hash=a_hash(f"{name} spare worker")
    )
    world.spare_connector = await ConnectorRepo(session).create(
        msp.id, client.id, world.spare_worker.id, profile_for(client.tenant_id)
    )
    world.spare_plan = await PlanRepo(session).create(
        msp.id, client.id, connector.id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 3 * * *"
    )
    return world


@pytest.fixture
async def worlds(session) -> tuple[World, World]:
    return await make_world(session, "a"), await make_world(session, "b")


# --- The table -------------------------------------------------------------------

Args = Callable[[World], tuple]
Kwargs = Callable[[World], dict]


@dataclass(frozen=True)
class Read:
    repo: type
    method: str
    args: Args = lambda w: ()
    kwargs: Kwargs = lambda w: {}

    @property
    def id(self) -> str:
        return f"{self.repo.__name__}.{self.method}({self.args.__doc__ or ''}{self.kwargs.__doc__ or ''})"


def _args(doc: str, fn: Args) -> Args:
    fn.__doc__ = doc
    return fn


def _kwargs(doc: str, fn: Kwargs) -> Kwargs:
    fn.__doc__ = doc
    return fn


READS = [
    Read(MspRepo, "get"),
    Read(UserRepo, "get", _args("user", lambda w: (w.user.id,))),
    Read(UserRepo, "list"),
    Read(ClientRepo, "get", _args("client", lambda w: (w.client.id,))),
    Read(ClientRepo, "get_by_tenant", _args("tenant", lambda w: (w.client.tenant_id,))),
    Read(ClientRepo, "list"),
    Read(WorkerRepo, "get", _args("worker", lambda w: (w.worker.id,))),
    Read(WorkerRepo, "list"),
    Read(ConnectorRepo, "get", _args("connector", lambda w: (w.connector.id,))),
    Read(ConnectorRepo, "list"),
    Read(ConnectorRepo, "list", kwargs=_kwargs("client", lambda w: {"client_id": w.client.id})),
    Read(ConnectorRepo, "list", kwargs=_kwargs("worker", lambda w: {"worker_id": w.worker.id})),
    Read(PlanRepo, "get", _args("plan", lambda w: (w.plan.id,))),
    Read(PlanRepo, "list"),
    Read(PlanRepo, "list", kwargs=_kwargs("client", lambda w: {"client_id": w.client.id})),
    Read(RunRepo, "get", _args("run", lambda w: (w.run.id,))),
    Read(RunRepo, "list"),
    Read(RunRepo, "list", kwargs=_kwargs("client", lambda w: {"client_id": w.client.id})),
    Read(ItemRepo, "list", _args("run", lambda w: (w.run.id,))),
    Read(ReportRepo, "get", _args("report", lambda w: (w.report.id,))),
    Read(ReportRepo, "list"),
    Read(ReportRepo, "list", kwargs=_kwargs("client", lambda w: {"client_id": w.client.id})),
    Read(AuditRepo, "list"),
    Read(InstallTokenRepo, "get", _args("token", lambda w: (w.token.id,))),
    Read(InstallTokenRepo, "list"),
]


@dataclass(frozen=True)
class Write:
    repo: type
    method: str
    row: Callable[[World], Any]
    args: Args = lambda w: ()
    kwargs: Kwargs = lambda w: {}
    # A sweep names no row: with A's msp_id it may touch A's own rows, and the
    # other MSP's row must still be left as it was.
    sweep: bool = False

    @property
    def id(self) -> str:
        return f"{self.repo.__name__}.{self.method}"


WRITES = [
    Write(ClientRepo, "update", lambda w: w.client, lambda w: (w.client.id,), lambda w: {"name": "changed", "screenshots_enabled": True}),
    Write(ClientRepo, "delete", lambda w: w.spare_client, lambda w: (w.spare_client.id,)),
    Write(WorkerRepo, "revoke", lambda w: w.worker, lambda w: (w.worker.id, NOW)),
    # C5.8: with A's msp_id and B's Worker the heartbeat answers 0 and B's row stays.
    Write(WorkerRepo, "heartbeat", lambda w: w.worker, lambda w: (w.worker.id,), lambda w: {"at": NOW, "version": "0.0.0", "last_error": None, "last_error_at": None, "outbox_depth": 0, "uptime_s": 1}),
    Write(ConnectorRepo, "update", lambda w: w.connector, lambda w: (w.connector.id, w.connector.config_json)),
    Write(ConnectorRepo, "delete", lambda w: w.spare_connector, lambda w: (w.spare_connector.id,)),
    Write(PlanRepo, "set_enabled", lambda w: w.plan, lambda w: (w.plan.id, False)),
    Write(PlanRepo, "delete", lambda w: w.spare_plan, lambda w: (w.spare_plan.id,)),
    Write(RunRepo, "set_state", lambda w: w.run, lambda w: (w.run.id, "dispatched")),
    # C5.6: with A's msp_id and B's Worker the dispatch answers [] and B's run
    # stays queued; the sweep with A's msp_id leaves B's stale run dispatched.
    Write(RunRepo, "dispatch", lambda w: w.run, lambda w: (w.worker.id, NOW)),
    Write(RunRepo, "requeue_stale", lambda w: w.stale_run, lambda w: (NOW + dt.timedelta(hours=6),), sweep=True),
    # C5.7: with A's msp_id and B's dispatched run (B's Worker given, as the
    # route gives the token's Worker) the bundle isn't filed and B's row stays.
    Write(RunRepo, "receive", lambda w: w.stale_run, lambda w: (w.stale_run.id,), lambda w: {"worker_id": w.worker.id, "update": RECEIVED}),
    Write(InstallTokenRepo, "mark_used", lambda w: w.token, lambda w: (w.token.id, NOW)),
]

# Exercised by make_world: a create with A's msp_id and B's ids is refused by
# the database's keys (tests/test_models.py), which is not this file's to show.
CREATES = {
    (MspRepo, "create"),
    (UserRepo, "create"),
    (ClientRepo, "create"),
    (WorkerRepo, "create"),
    (ConnectorRepo, "create"),
    (PlanRepo, "create"),
    (RunRepo, "create"),
    (ItemRepo, "create"),
    (ItemRepo, "create_many"),
    (ReportRepo, "create"),
    (AuditRepo, "write"),
    (InstallTokenRepo, "create"),
}

LOOKUPS = {(Lookup, "find_worker_by_token_hash"), (Lookup, "find_install_token_by_hash")}


def every_repo_method() -> set[tuple[type, str]]:
    found = set()
    # walk_packages: a sub-package of the repo is in the table too (the
    # C5.3/C5.4 review's finding 5).
    for module_info in pkgutil.walk_packages(app.repo.__path__, prefix="app.repo."):
        module = importlib.import_module(module_info.name)
        for _name, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, Repo) and cls is not Repo and cls.__module__ == module.__name__:
                for method, _ in inspect.getmembers(cls, inspect.isfunction):
                    if not method.startswith("_"):
                        found.add((cls, method))
    return found


def test_the_table_names_every_repo_method():
    """A method added later must be added to READS, WRITES or CREATES."""
    in_table = {(r.repo, r.method) for r in READS} | {(w.repo, w.method) for w in WRITES} | CREATES | LOOKUPS

    assert every_repo_method() == in_table
    assert len(every_repo_method()) >= 40


def rows_touched(answer) -> int:
    """A write's answer as a count: an int, a list of rows (dispatch) or a
    pair of counts (requeue_stale)."""
    if isinstance(answer, int):
        return answer
    if isinstance(answer, tuple):
        return sum(answer)
    return len(answer)


def snapshot(row) -> dict:
    return {attr.key: getattr(row, attr.key) for attr in sa_inspect(row).mapper.column_attrs}


def msp_of(row) -> uuid.UUID:
    return getattr(row, "msp_id", None) or row.id


def rows_of(answer) -> list:
    if answer is None:
        return []
    return list(answer) if isinstance(answer, list) else [answer]


# --- Reads -------------------------------------------------------------------------


@pytest.mark.parametrize("read", READS, ids=[r.id for r in READS])
async def test_a_read_with_one_msp_s_id_answers_nothing_of_the_other(session, worlds, read: Read):
    a, b = worlds
    for mine, other in ((a, b), (b, a)):
        repo = read.repo(session)

        crossed = await getattr(repo, read.method)(mine.msp.id, *read.args(other), **read.kwargs(other))
        own = await getattr(repo, read.method)(mine.msp.id, *read.args(mine), **read.kwargs(mine))

        assert not [row for row in rows_of(crossed) if row.id in other.ids], read.id
        assert all(msp_of(row) == mine.msp.id for row in rows_of(crossed)), read.id
        assert rows_of(own), read.id
        assert all(msp_of(row) == mine.msp.id for row in rows_of(own)), read.id
        assert not [row for row in rows_of(own) if row.id in other.ids], read.id


async def test_a_get_of_the_other_msp_s_row_is_none_not_a_row(session, worlds):
    a, b = worlds
    gets = [r for r in READS if r.method.startswith("get") and r.repo is not MspRepo]

    assert len(gets) >= 8
    for read in gets:
        assert await getattr(read.repo(session), read.method)(a.msp.id, *read.args(b)) is None, read.id
        own = await getattr(read.repo(session), read.method)(a.msp.id, *read.args(a))
        assert own is not None and own.msp_id == a.msp.id, read.id


async def test_a_list_of_one_msp_is_the_whole_of_that_msp_s_rows(session, worlds):
    a, b = worlds

    assert {u.id for u in await UserRepo(session).list(a.msp.id)} == {a.user.id}
    assert {c.id for c in await ClientRepo(session).list(a.msp.id)} == {a.client.id, a.spare_client.id}
    assert {c.id for c in await ConnectorRepo(session).list(a.msp.id)} == {a.connector.id, a.spare_connector.id}
    assert {p.id for p in await PlanRepo(session).list(a.msp.id)} == {a.plan.id, a.spare_plan.id}
    assert {r.id for r in await RunRepo(session).list(a.msp.id)} == {a.run.id, a.stale_run.id}
    assert [i.id for i in await ItemRepo(session).list(a.msp.id, a.run.id)] == [i.id for i in a.items]
    assert [r.id for r in await ReportRepo(session).list(b.msp.id)] == [b.report.id]
    # The connector creates wrote audit rows of their own beside the one written by hand.
    assert {row.action for row in await AuditRepo(session).list(b.msp.id)} == {"test.write", "connector.create"}
    assert [t.id for t in await InstallTokenRepo(session).list(b.msp.id)] == [b.token.id]


# --- Writes --------------------------------------------------------------------------


@pytest.mark.parametrize("write", WRITES, ids=[w.id for w in WRITES])
async def test_a_write_with_one_msp_s_id_on_the_other_s_row_changes_nothing(session, worlds, write: Write):
    a, b = worlds
    for mine, other in ((a, b), (b, a)):
        row = write.row(other)
        await session.refresh(row)
        before = snapshot(row)

        touched = await getattr(write.repo(session), write.method)(mine.msp.id, *write.args(other), **write.kwargs(other))

        if not write.sweep:
            assert rows_touched(touched) == 0, write.id
        await session.refresh(row)
        assert snapshot(row) == before, write.id


@pytest.mark.parametrize("write", WRITES, ids=[w.id for w in WRITES])
async def test_the_same_write_with_the_row_s_own_msp_id_touches_one_row(session, worlds, write: Write):
    a, _ = worlds

    touched = await getattr(write.repo(session), write.method)(a.msp.id, *write.args(a), **write.kwargs(a))

    assert rows_touched(touched) == 1, write.id


async def test_a_write_on_a_row_that_does_not_exist_answers_zero(session, worlds):
    a, _ = worlds
    nothing = uuid.uuid4()

    assert await ClientRepo(session).update(a.msp.id, nothing, name="x", screenshots_enabled=False) == 0
    assert await ClientRepo(session).delete(a.msp.id, nothing) == 0
    assert await WorkerRepo(session).revoke(a.msp.id, nothing, NOW) == 0
    assert await ConnectorRepo(session).update(a.msp.id, nothing, a.connector.config_json) == 0
    assert await ConnectorRepo(session).delete(a.msp.id, nothing) == 0
    assert await PlanRepo(session).set_enabled(a.msp.id, nothing, True) == 0
    assert await PlanRepo(session).delete(a.msp.id, nothing) == 0
    assert await RunRepo(session).set_state(a.msp.id, nothing, "error") == 0
    assert await RunRepo(session).dispatch(a.msp.id, nothing, NOW) == []
    assert await RunRepo(session).requeue_stale(a.msp.id, NOW - dt.timedelta(days=1)) == (0, 0)
    assert await RunRepo(session).receive(a.msp.id, nothing, worker_id=a.worker.id, update=RECEIVED) == 0
    assert await InstallTokenRepo(session).mark_used(a.msp.id, nothing, NOW) == 0


async def test_the_writes_do_what_they_say_on_their_own_rows(session, worlds):
    a, _ = worlds
    clients, workers, plans, runs, tokens = (
        ClientRepo(session), WorkerRepo(session), PlanRepo(session), RunRepo(session), InstallTokenRepo(session)
    )

    assert await clients.update(a.msp.id, a.client.id, name="renamed", screenshots_enabled=True) == 1
    assert await workers.revoke(a.msp.id, a.worker.id, NOW) == 1
    assert await workers.revoke(a.msp.id, a.worker.id, NOW + dt.timedelta(days=1)) == 0  # once
    assert await plans.set_enabled(a.msp.id, a.plan.id, False) == 1
    assert await runs.set_state(a.msp.id, a.run.id, "dispatched") == 1
    assert await runs.receive(a.msp.id, a.stale_run.id, worker_id=a.worker.id, update=RECEIVED) == 1
    assert await runs.receive(a.msp.id, a.stale_run.id, worker_id=a.worker.id, update=RECEIVED) == 0  # once
    assert await tokens.mark_used(a.msp.id, a.token.id, NOW) == 1
    assert await tokens.mark_used(a.msp.id, a.token.id, NOW) == 0  # single use
    assert await clients.delete(a.msp.id, a.spare_client.id) == 1

    client = await clients.get(a.msp.id, a.client.id)
    assert (client.name, client.screenshots_enabled) == ("renamed", True)
    assert (await workers.get(a.msp.id, a.worker.id)).revoked_at == NOW
    assert (await plans.get(a.msp.id, a.plan.id)).enabled is False
    assert (await runs.get(a.msp.id, a.run.id)).state == "dispatched"
    assert (await runs.get(a.msp.id, a.stale_run.id)).state == "pass"
    assert (await tokens.get(a.msp.id, a.token.id)).used_at == NOW
    assert await clients.get(a.msp.id, a.spare_client.id) is None


# --- The two lookups before an MSP is known ------------------------------------------


async def test_the_lookups_find_a_row_by_its_hash_alone_and_the_row_carries_its_msp(session, worlds):
    a, b = worlds
    lookup = Lookup(session)

    worker = await lookup.find_worker_by_token_hash(b.worker.api_token_hash)
    token = await lookup.find_install_token_by_hash(a.token.token_hash)

    assert (worker.id, worker.msp_id) == (b.worker.id, b.msp.id)
    assert (token.id, token.msp_id) == (a.token.id, a.msp.id)
    assert await lookup.find_worker_by_token_hash(a_hash("nobody")) is None
    assert await lookup.find_install_token_by_hash(a_hash("nobody")) is None


# --- The repos never commit -------------------------------------------------------------


async def test_no_repo_commits(session, monkeypatch):
    """One transaction per request or command is the caller's."""
    committed = []

    async def commit():
        committed.append(True)

    monkeypatch.setattr(session, "commit", commit)

    await make_world(session, "c")

    assert committed == []
