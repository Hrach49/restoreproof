"""C5.9 and C5.10 in the repo (docs/decisions.md 2026-10-11, "C5.10 and C5.9",
points 6 and 10): `PlanRepo.create` holds `cadence_cron` to five fields and to
at least monthly, as a `RepoError` naming the key and never the text;
`PlanRepo.list` takes `enabled`; `MspRepo.list` is the one read across every
MSP, the scheduler's.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from app.cadence import LESS_THAN_MONTHLY, NOT_A_CRON
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.errors import RepoError
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.workers import WorkerRepo
from tests.test_repo_connectors import profile_for

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 11, 12, 0, 30, tzinfo=UTC)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


class Lab:
    @classmethod
    async def make(cls, session, name="a") -> "Lab":
        lab = cls()
        lab.session = session
        lab.msp = await MspRepo(session).create(name=name)
        lab.client = await ClientRepo(session).create(lab.msp.id, name=f"{name} client", tenant_id=uuid.uuid4())
        lab.worker = await WorkerRepo(session).create(
            lab.msp.id, f"{name} worker", public_key_pem=PEM, key_id=a_hash(f"{name} key"), api_token_hash=a_hash(f"{name} token")
        )
        lab.connector = await ConnectorRepo(session).create(
            lab.msp.id, lab.client.id, lab.worker.id, profile_for(lab.client.tenant_id)
        )
        lab.plans = PlanRepo(session)
        return lab

    async def create(self, **changes):
        values = {"sample_mail": 5, "sample_sp": 3, "sample_od": 2, "cadence_cron": "0 2 * * *", "now": NOW}
        return await self.plans.create(self.msp.id, self.client.id, self.connector.id, **{**values, **changes})


# --- create: the cadence ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", NOT_A_CRON),
        ("nonsense", NOT_A_CRON),
        ("0 2 * *", NOT_A_CRON),
        ("0 2 * * * *", NOT_A_CRON),
        ("@daily", NOT_A_CRON),
        ("0 2 31 * *", LESS_THAN_MONTHLY),
        ("0 2 1 */2 *", LESS_THAN_MONTHLY),
        ("0 2 1 1 *", LESS_THAN_MONTHLY),
    ],
)
async def test_a_cadence_outside_the_rule_is_refused_without_its_text(session, text, reason):
    lab = await Lab.make(session)

    with pytest.raises(RepoError) as raised:
        await lab.create(cadence_cron=text)

    assert (raised.value.key, raised.value.reason) == ("cadence_cron", reason)
    assert text == "" or text not in str(raised.value)
    assert await lab.plans.list(lab.msp.id) == []


@pytest.mark.parametrize("text", ["0 2 * * *", "*/5 * * * *", "0 2 1 * *", "0 2 L * *", "0 2 * * 1"])
async def test_a_cadence_within_the_rule_is_stored_as_given(session, text):
    lab = await Lab.make(session)

    plan = await lab.create(cadence_cron=text)

    assert plan.cadence_cron == text
    assert plan.enabled is True
    await session.refresh(plan)
    assert plan.created_at is not None


async def test_the_cadence_is_checked_before_any_row_and_now_is_the_caller_s(session):
    lab = await Lab.make(session)

    with pytest.raises(TypeError):
        await lab.plans.create(
            lab.msp.id, lab.client.id, lab.connector.id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 2 * * *"
        )
    with pytest.raises(ValueError):
        await lab.create(now=dt.datetime(2026, 10, 11, 12, 0))


# --- list: enabled ----------------------------------------------------------------------------


async def test_list_takes_enabled(session):
    lab = await Lab.make(session)
    on = await lab.create()
    off = await lab.create(cadence_cron="0 3 * * *", enabled=False)

    assert [p.id for p in await lab.plans.list(lab.msp.id)] == sorted([on.id, off.id])
    assert [p.id for p in await lab.plans.list(lab.msp.id, enabled=True)] == [on.id]
    assert [p.id for p in await lab.plans.list(lab.msp.id, enabled=False)] == [off.id]
    assert [p.id for p in await lab.plans.list(lab.msp.id, client_id=lab.client.id, enabled=True)] == [on.id]
    assert await lab.plans.list(lab.msp.id, client_id=uuid.uuid4(), enabled=True) == []


# --- MspRepo.list: the scheduler's one read across MSPs ------------------------------------------


async def test_msp_list_answers_every_msp_by_name_then_id(session):
    b = await MspRepo(session).create(name="b")
    a = await MspRepo(session).create(name="a")
    a2 = await MspRepo(session).create(name="a")

    listed = await MspRepo(session).list()

    ids = [m.id for m in listed]
    assert set(ids) >= {a.id, a2.id, b.id}
    names = [m.name for m in listed]
    assert names == sorted(names)
    first_two = sorted([a.id, a2.id])
    assert [i for i in ids if i in first_two] == first_two
    assert ids.index(b.id) > max(ids.index(a.id), ids.index(a2.id))


# --- C6.2: each plan with its Worker (docs/decisions.md 2026-10-12, point 16) --------------------


async def test_list_with_workers_answers_each_plan_with_its_connector_s_worker(session):
    pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
    now = dt.datetime(2026, 10, 12, 12, tzinfo=dt.timezone.utc)
    msp = await MspRepo(session).create(name="a")
    client = await ClientRepo(session).create(msp.id, name="c", tenant_id=uuid.uuid4())
    workers = WorkerRepo(session)
    w1 = await workers.create(msp.id, "w1", public_key_pem=pem, key_id="1" * 64, api_token_hash="a" * 64)
    w2 = await workers.create(msp.id, "w2", public_key_pem=pem, key_id="2" * 64, api_token_hash="b" * 64)
    c1 = await ConnectorRepo(session).create(msp.id, client.id, w1.id, profile_for(client.tenant_id))
    c2 = await ConnectorRepo(session).create(msp.id, client.id, w2.id, profile_for(client.tenant_id))
    plans = PlanRepo(session)
    p1 = await plans.create(msp.id, client.id, c1.id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 2 * * *", now=now)
    p2 = await plans.create(msp.id, client.id, c2.id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 3 * * *", now=now, enabled=False)
    assert await workers.revoke(msp.id, w2.id, now) == 1
    other = await MspRepo(session).create(name="b")

    every = await plans.list_with_workers(msp.id)
    enabled = await plans.list_with_workers(msp.id, enabled=True)
    disabled = await plans.list_with_workers(msp.id, enabled=False)

    assert [(plan.id, worker.id) for plan, worker in every] == sorted([(p1.id, w1.id), (p2.id, w2.id)])
    assert [(plan.id, worker.id) for plan, worker in enabled] == [(p1.id, w1.id)]
    assert [(plan.id, worker.id, worker.revoked_at) for plan, worker in disabled] == [(p2.id, w2.id, now)]
    assert await plans.list_with_workers(other.id) == []
