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
# C6.4: the month the worlds' runs are in (their `created_at` is NOW's day or the day before).
MONTH_START = dt.datetime(2026, 10, 1, tzinfo=UTC)
MONTH_END = dt.datetime(2026, 11, 1, tzinfo=UTC)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


RECEIVED = ReceivedRun(
    state="pass", error_code=None, error_message=None, started_at=NOW, finished_at=NOW, total_ms=1, recovery_ms=1,
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
    done_run: Any = None
    failed_run: Any = None
    failed_item: Any = None
    items: list = field(default_factory=list)
    report: Any = None
    interim_report: Any = None
    audit: Any = None
    token: Any = None
    spare_client: Any = None
    spare_worker: Any = None
    spare_connector: Any = None
    spare_plan: Any = None

    @property
    def ids(self) -> set[uuid.UUID]:
        rows = [self.msp, self.user, self.client, self.worker, self.connector, self.plan, self.run,
                self.stale_run, self.done_run, self.failed_run, self.failed_item, *self.items, self.report, self.interim_report, self.audit,
                self.token, self.spare_client, self.spare_worker, self.spare_connector, self.spare_plan]
        return {row.id for row in rows}


async def make_world(session, name: str, *, clock: dt.datetime | None = None) -> World:
    """One of everything for one MSP. With `clock`, every audit row the world
    wrote takes that time (the finding-8 test moves the calendar)."""
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
        msp.id, client.id, connector.id, sample_mail=5, sample_sp=3, sample_od=2, cadence_cron="0 2 * * *", now=NOW
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
    # C6.2: a run that is over, for the pages' last-run read; the queued run
    # made a day before the rest, so a page before the stale run has it.
    world.done_run = await RunRepo(session).create(
        msp.id, plan_id=plan.id, client_id=client.id, connector_id=connector.id, worker_id=worker.id
    )
    assert await RunRepo(session).set_state(msp.id, world.done_run.id, "pass") == 1
    await session.execute(
        text("UPDATE test_run SET created_at = :at WHERE id = :id"), {"at": NOW - dt.timedelta(days=1), "id": run.id}
    )
    # C6.4: the two finished runs are in NOW's month on any calendar (their
    # times given, not the database's clock), and the failed one has an item
    # that didn't match, for the report's reads.
    await session.execute(
        text("UPDATE test_run SET created_at = :at, finished_at = :at WHERE id = :id"), {"at": NOW, "id": world.done_run.id}
    )
    world.failed_run = await RunRepo(session).create(
        msp.id, plan_id=plan.id, client_id=client.id, connector_id=connector.id, worker_id=worker.id
    )
    assert await RunRepo(session).set_state(msp.id, world.failed_run.id, "fail") == 1
    await session.execute(
        text("UPDATE test_run SET created_at = :at, finished_at = :at WHERE id = :id"),
        {"at": NOW + dt.timedelta(hours=1), "id": world.failed_run.id},
    )
    world.failed_item = await ItemRepo(session).create(
        msp.id, world.failed_run.id, position=0, type="mail", name=f"{name} missing", expected_kind="manifest",
        found=False, match=False, reason="no restored copy found",
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
        storage_key=f"{name}/2026-09.pdf", content_sha256="ab" * 32, file_sha256="cd" * 32, interim=False,
        generated_at=NOW,
    )
    # C6.6: an interim report a day older, so a page before the final one has a row of its own.
    world.interim_report = await ReportRepo(session).create(
        msp.id, client.id, period_start=dt.date(2026, 9, 1), period_end=dt.date(2026, 9, 30),
        storage_key=f"{name}/2026-09-interim.pdf", content_sha256="12" * 32, file_sha256="34" * 32, interim=True,
        generated_at=NOW - dt.timedelta(days=1),
    )
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
        msp.id, client.id, connector.id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 3 * * *", now=NOW
    )
    # Last, after every row the world makes: the spare connector's audit row
    # takes the database's now(), so moving the clock before it left one row
    # at the real time (the C6.4 review's finding 15).
    if clock is not None:
        await session.execute(text("UPDATE audit_log SET at = :at WHERE msp_id = :msp"), {"at": clock, "msp": msp.id})
    world.audit = await AuditRepo(session).write(msp.id, action="test.write", target=f"{name}:x", user_id=user.id, ip="10.0.0.1")
    # C6.3: the newest row by far, so a page before it has the connectors'
    # rows: 30 days after the MSP's newest row, on any day's calendar (the
    # C6.1-C6.3 review's finding 8: a fixed date was passed by the clock).
    await session.execute(
        text(
            "UPDATE audit_log SET at = (SELECT max(at) FROM audit_log WHERE msp_id = :msp AND id <> :id) + interval '30 days' "
            "WHERE id = :id"
        ),
        {"msp": msp.id, "id": world.audit.id},
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
    # C5.9: the scheduler's read of an MSP's enabled plans.
    Read(PlanRepo, "list", kwargs=_kwargs("enabled", lambda w: {"enabled": True})),
    Read(RunRepo, "get", _args("run", lambda w: (w.run.id,))),
    Read(RunRepo, "list"),
    Read(RunRepo, "list", kwargs=_kwargs("client", lambda w: {"client_id": w.client.id})),
    # C6.2: the pages' reads. The two per-client dicts are read as their rows.
    Read(RunRepo, "last_finished_per_client"),
    Read(RunRepo, "pending_per_client"),
    Read(RunRepo, "page", _args("client", lambda w: (w.client.id,))),
    Read(RunRepo, "page", _args("client, before", lambda w: (w.client.id,)), _kwargs("before", lambda w: {"before": w.stale_run.id})),
    Read(PlanRepo, "list_with_workers"),
    Read(PlanRepo, "list_with_workers", kwargs=_kwargs("enabled", lambda w: {"enabled": True})),
    # C6.3: the audit page's read.
    Read(AuditRepo, "page", kwargs=_kwargs("since", lambda w: {"since": NOW - dt.timedelta(days=365)})),
    Read(AuditRepo, "page", kwargs=_kwargs("since, before", lambda w: {"since": NOW - dt.timedelta(days=365), "before": w.audit.id})),
    Read(ItemRepo, "list", _args("run", lambda w: (w.run.id,))),
    # C6.4: the report's reads of a month (docs/decisions.md 2026-10-12, "C6.4", point 5).
    Read(RunRepo, "period", _args("client", lambda w: (w.client.id,)), _kwargs("month", lambda w: {"start": MONTH_START, "end": MONTH_END})),
    Read(ItemRepo, "unmatched_in_period", _args("client", lambda w: (w.client.id,)), _kwargs("month", lambda w: {"start": MONTH_START, "end": MONTH_END})),
    Read(ReportRepo, "get", _args("report", lambda w: (w.report.id,))),
    Read(ReportRepo, "final", _args("client, period", lambda w: (w.client.id, w.report.period_start))),
    Read(ReportRepo, "list"),
    Read(ReportRepo, "list", kwargs=_kwargs("client", lambda w: {"client_id": w.client.id})),
    # C6.6: the reports pages' read (docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7", point 2).
    Read(ReportRepo, "page"),
    Read(ReportRepo, "page", kwargs=_kwargs("client", lambda w: {"client_id": w.client.id})),
    Read(ReportRepo, "page", kwargs=_kwargs("before", lambda w: {"before": w.report.id})),
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
    Write(RunRepo, "receive", lambda w: w.stale_run, lambda w: (w.stale_run.id,), lambda w: {"worker_id": w.worker.id, "update": RECEIVED, "at": NOW}),
    Write(InstallTokenRepo, "mark_used", lambda w: w.token, lambda w: (w.token.id, NOW)),
    # C6.1: with A's msp_id and B's user the reset answers 0 and B's hash stays.
    Write(UserRepo, "set_password_hash", lambda w: w.user, lambda w: (w.user.id, "changed"), lambda w: {"changed_at": NOW}),
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
    (RunRepo, "create_scheduled"),
    (ItemRepo, "create"),
    (ItemRepo, "create_many"),
    (ReportRepo, "create"),
    (AuditRepo, "write"),
    (InstallTokenRepo, "create"),
}

LOOKUPS = {(Lookup, "find_worker_by_token_hash"), (Lookup, "find_install_token_by_hash"), (Lookup, "find_user_by_email")}

# C5.9: the one read across every MSP, the scheduler's; held below to answer
# both worlds' MSPs and nothing else of either.
CROSS_MSP = {(MspRepo, "list")}

# C6.2: a read that answers counts, not rows; held by its own test below.
# C6.4: the month's item counts per run and type, the same.
COUNTS = {(RunRepo, "daily_states"), (ItemRepo, "counts_by_type_in_period")}
# C6.6: a read that answers ids, not rows (the monthly job's clients); held by its own test below.
IDS = {(RunRepo, "clients_in_period")}
# The C6.6 review's finding 6: a row lock that answers whether it was taken; held by its own test below.
HOLDS = {(ClientRepo, "hold")}


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
    in_table = {(r.repo, r.method) for r in READS} | {(w.repo, w.method) for w in WRITES} | CREATES | LOOKUPS | CROSS_MSP | COUNTS | IDS | HOLDS

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
    """The rows a read answered: a row, a list of rows, a dict of rows by
    key, or a list of tuples of rows (a joined read) or of named tuples whose
    first field is the row (a row with its count or its user's address)."""
    if answer is None:
        return []
    if isinstance(answer, dict):
        return list(answer.values())
    if not isinstance(answer, list):
        return [answer]
    rows = []
    for entry in answer:
        if isinstance(entry, tuple):
            rows.extend(item for item in entry if hasattr(item, "msp_id") or hasattr(item, "retention_days"))
        else:
            rows.append(entry)
    return rows


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
    assert {r.id for r in await RunRepo(session).list(a.msp.id)} == {a.run.id, a.stale_run.id, a.done_run.id, a.failed_run.id}
    assert [i.id for i in await ItemRepo(session).list(a.msp.id, a.run.id)] == [i.id for i in a.items]
    assert [r.id for r in await ReportRepo(session).list(b.msp.id)] == [b.report.id, b.interim_report.id]
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
    assert await RunRepo(session).receive(a.msp.id, nothing, worker_id=a.worker.id, update=RECEIVED, at=NOW) == 0
    assert await InstallTokenRepo(session).mark_used(a.msp.id, nothing, NOW) == 0
    assert await UserRepo(session).set_password_hash(a.msp.id, nothing, "x", changed_at=NOW) == 0


async def test_set_password_hash_replaces_the_hash_and_marks_the_change_only_when_told(session, worlds):
    a, _ = worlds
    users = UserRepo(session)
    before = (await users.get(a.msp.id, a.user.id)).password_changed_at

    assert await users.set_password_hash(a.msp.id, a.user.id, "rehashed", changed_at=None) == 1
    await session.refresh(a.user)
    assert (a.user.password_hash, a.user.password_changed_at) == ("rehashed", before)
    assert await users.set_password_hash(a.msp.id, a.user.id, "reset", changed_at=NOW) == 1
    await session.refresh(a.user)
    assert (a.user.password_hash, a.user.password_changed_at) == ("reset", NOW)


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
    assert await runs.receive(a.msp.id, a.stale_run.id, worker_id=a.worker.id, update=RECEIVED, at=NOW) == 1
    assert await runs.receive(a.msp.id, a.stale_run.id, worker_id=a.worker.id, update=RECEIVED, at=NOW) == 0  # once
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
    # C6.1: the address in any case, trimmed; nobody for an unknown one.
    user = await lookup.find_user_by_email("  B@EXAMPLE.TEST ")
    assert (user.id, user.msp_id) == (b.user.id, b.msp.id)
    assert await lookup.find_user_by_email("nobody@example.test") is None
    assert await lookup.find_user_by_email("") is None


# --- The read that answers counts (C6.2) ---------------------------------------------------------


async def test_daily_states_with_one_msp_s_id_counts_nothing_of_the_other(session, worlds):
    a, b = worlds
    since = NOW - dt.timedelta(days=365)

    assert await RunRepo(session).daily_states(a.msp.id, b.client.id, since=since) == []
    own = await RunRepo(session).daily_states(a.msp.id, a.client.id, since=since)
    assert sum(count.count for count in own) == 4  # a.run queued, a.stale_run dispatched, a.done_run pass, a.failed_run fail


async def test_counts_by_type_in_period_with_one_msp_s_id_counts_nothing_of_the_other(session, worlds):
    """C6.4: of the world's runs in the month two have items: the failed one
    (one) and the queued one (two; a run with no result yet is the month's
    since the C6.4 review's finding 2)."""
    a, b = worlds

    assert await ItemRepo(session).counts_by_type_in_period(a.msp.id, b.client.id, start=MONTH_START, end=MONTH_END) == []
    own = await ItemRepo(session).counts_by_type_in_period(a.msp.id, a.client.id, start=MONTH_START, end=MONTH_END)
    assert sorted((str(count.run_id), count.type, count.expected_kind, count.count) for count in own) == sorted(
        [(str(a.run.id), "mail", "manifest", 2), (str(a.failed_run.id), "mail", "manifest", 1)]
    )


async def test_clients_in_period_with_one_msp_s_id_names_nothing_of_the_other(session, worlds):
    """C6.6: the month's clients of an MSP are its own client alone (every run
    of the world is in NOW's month), never the other's."""
    a, b = worlds

    own = await RunRepo(session).clients_in_period(a.msp.id, start=MONTH_START, end=MONTH_END)

    assert own == [a.client.id]
    assert b.client.id not in own
    assert await RunRepo(session).clients_in_period(b.msp.id, start=MONTH_START, end=MONTH_END) == [b.client.id]


# --- The audit reads on a moved calendar (the C6.1-C6.3 review's finding 8) ----------------


@pytest.mark.parametrize("clock", [dt.datetime(2026, 1, 1, tzinfo=UTC), dt.datetime(2027, 6, 1, tzinfo=UTC), dt.datetime(2040, 1, 1, tzinfo=UTC)])
async def test_the_audit_reads_hold_on_a_moved_clock(session, clock):
    """The hand-written audit row is placed after the MSP's newest row, not at
    a fixed date, so the keyset read before it answers the world's own rows
    whatever the calendar says: here with every other row at `clock`, past the
    fixed date the old world used (2026-11-09), and at a `clock` already
    behind the real one, which is what every later day is to the other two."""
    a = await make_world(session, "a", clock=clock)
    b = await make_world(session, "b", clock=clock)
    reads = [read for read in READS if read.repo is AuditRepo and read.method == "page"]

    assert len(reads) == 2
    for read in reads:
        own = rows_of(await AuditRepo(session).page(a.msp.id, *read.args(a), **read.kwargs(a)))
        crossed = rows_of(await AuditRepo(session).page(a.msp.id, *read.args(b), **read.kwargs(b)))
        assert own and all(row.msp_id == a.msp.id for row in own), read.id
        assert not [row for row in crossed if row.id in b.ids], read.id
    assert (await session.execute(text("SELECT max(at) FROM audit_log WHERE msp_id = :m AND id <> :i"), {"m": a.msp.id, "i": a.audit.id})).scalar_one() == clock
    await session.refresh(a.audit)
    assert a.audit.at == clock + dt.timedelta(days=30)


# --- The one read across MSPs (C5.9) ----------------------------------------------------------


async def test_msp_list_answers_both_msps_and_nothing_of_either_s_rows(session, worlds):
    a, b = worlds

    listed = await MspRepo(session).list()

    ids = {msp.id for msp in listed}
    assert {a.msp.id, b.msp.id} <= ids
    assert not ((a.ids | b.ids) - {a.msp.id, b.msp.id}) & ids
    assert all(type(msp).__name__ == "Msp" for msp in listed)


# --- The repos never commit -------------------------------------------------------------


async def test_no_repo_commits(session, monkeypatch):
    """One transaction per request or command is the caller's."""
    committed = []

    async def commit():
        committed.append(True)

    monkeypatch.setattr(session, "commit", commit)

    await make_world(session, "c")

    assert committed == []


async def test_hold_takes_a_client_of_its_own_msp_alone(session, worlds):
    """`ClientRepo.hold` with A's msp_id and B's client takes nothing, so one
    MSP's click never holds another's row."""
    a, b = worlds
    clients = ClientRepo(session)

    assert await clients.hold(a.msp.id, b.client.id) is False
    assert await clients.hold(b.msp.id, a.client.id) is False
    assert await clients.hold(a.msp.id, uuid.uuid4()) is False
    assert await clients.hold(a.msp.id, a.client.id) is True
    assert await clients.hold(b.msp.id, b.client.id) is True
