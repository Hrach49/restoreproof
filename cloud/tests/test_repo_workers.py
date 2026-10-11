"""C5.5: what `WorkerRepo.create` stores and refuses (docs/decisions.md
2026-10-10, "C5.5 and C5.6", point 3): the key's id and the install token
that made the Worker, in the row the insert writes; the empty token's hash
refused (the C5.4 review's finding 2, its second half), with the constant
computed from the standard library so app.repo imports nothing of app.auth.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app.repo.errors import RepoError
from app.repo.install_tokens import InstallTokenRepo
from app.repo.msps import MspRepo
from app.repo.users import UserRepo
from app.repo.workers import EMPTY_TOKEN_HASH, WorkerRepo

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
KEY_ID = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"


@pytest.fixture
async def msp(session):
    return await MspRepo(session).create(name="a")


def test_the_empty_token_s_hash_is_the_standard_library_s():
    assert EMPTY_TOKEN_HASH == hashlib.sha256(b"").hexdigest()
    assert EMPTY_TOKEN_HASH == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


async def test_a_worker_is_stored_with_its_key_id_and_without_a_token(session, msp):
    worker = await WorkerRepo(session).create(
        msp.id, "lab", public_key_pem=PEM, key_id=KEY_ID, api_token_hash="1" * 64
    )
    await session.refresh(worker)

    assert (worker.msp_id, worker.name, worker.public_key_pem, worker.key_id) == (msp.id, "lab", PEM, KEY_ID)
    assert worker.api_token_hash == "1" * 64
    assert worker.install_token_id is None
    assert (worker.version, worker.last_seen_at, worker.last_error, worker.revoked_at) == (None, None, None, None)


async def test_a_worker_names_the_install_token_that_made_it(session, msp):
    token = await InstallTokenRepo(session).create(
        msp.id, token_hash="t" * 64, expires_at=NOW + dt.timedelta(days=7), label="lab"
    )

    worker = await WorkerRepo(session).create(
        msp.id, "lab", public_key_pem=PEM, key_id=KEY_ID, api_token_hash="1" * 64, install_token_id=token.id
    )

    assert (await WorkerRepo(session).get(msp.id, worker.id)).install_token_id == token.id


async def test_the_empty_token_s_hash_is_refused_before_any_statement(session, msp, monkeypatch):
    added = []
    monkeypatch.setattr(session, "add", lambda row: added.append(row))

    with pytest.raises(RepoError) as raised:
        await WorkerRepo(session).create(
            msp.id, "blank", public_key_pem=PEM, key_id=KEY_ID, api_token_hash=EMPTY_TOKEN_HASH
        )

    assert (raised.value.key, raised.value.reason) == ("api_token_hash", "the empty token's hash")
    assert str(raised.value) == "api_token_hash: the empty token's hash"
    assert added == []
    assert await WorkerRepo(session).list(msp.id) == []


async def test_a_key_id_twice_is_the_database_s_refusal_by_name(session, msp):
    other = await MspRepo(session).create(name="b")
    await WorkerRepo(session).create(msp.id, "first", public_key_pem=PEM, key_id=KEY_ID, api_token_hash="1" * 64)

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await WorkerRepo(session).create(
                other.id, "second", public_key_pem=PEM, key_id=KEY_ID, api_token_hash="2" * 64
            )
    assert '"uq_worker_key_id"' in str(raised.value.orig)


# --- The install token's new columns ---------------------------------------------------------


async def test_an_install_token_carries_its_label_and_maker(session, msp):
    user = await UserRepo(session).create(msp.id, email="admin@example.test", password_hash="x", role="admin")

    token = await InstallTokenRepo(session).create(
        msp.id, token_hash="t" * 64, expires_at=NOW + dt.timedelta(days=7), label="the Veeam VM", created_by=user.id
    )
    await session.refresh(token)

    assert (token.label, token.created_by) == ("the Veeam VM", user.id)
    assert token.created_at.utcoffset() == dt.timedelta(0)
    assert abs(dt.datetime.now(UTC) - token.created_at) < dt.timedelta(minutes=5)


async def test_an_install_token_from_the_cli_has_no_maker(session, msp):
    token = await InstallTokenRepo(session).create(
        msp.id, token_hash="t" * 64, expires_at=NOW + dt.timedelta(days=7), label="cli"
    )

    assert (await InstallTokenRepo(session).get(msp.id, token.id)).created_by is None


async def test_another_msp_s_user_cannot_be_the_maker(session, msp):
    other = await MspRepo(session).create(name="b")
    user = await UserRepo(session).create(other.id, email="b@example.test", password_hash="x", role="admin")

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await InstallTokenRepo(session).create(
                msp.id, token_hash="t" * 64, expires_at=NOW + dt.timedelta(days=7), label="x", created_by=user.id
            )
    assert '"fk_install_token_msp_id_created_by_user"' in str(raised.value.orig)
    assert uuid.UUID(str(user.id)) == user.id


# --- C5.8: the heartbeat ----------------------------------------------------------------------


AT = dt.datetime(2026, 10, 11, 9, 0, 0, tzinfo=UTC)
ERROR_AT = dt.datetime(2026, 10, 9, 20, 27, 38, 206000, tzinfo=UTC)
BEAT = {"version": "0.0.0", "last_error": "job_invalid", "last_error_at": ERROR_AT, "outbox_depth": 0, "uptime_s": 152}


@pytest.fixture
async def worker(session, msp):
    return await WorkerRepo(session).create(
        msp.id, "lab", public_key_pem=PEM, key_id=KEY_ID, api_token_hash="1" * 64, version="0.0.0-registered"
    )


async def heartbeat_of(session, msp_id, worker_id) -> tuple:
    row = await WorkerRepo(session).get(msp_id, worker_id)
    await session.refresh(row)
    return (row.last_seen_at, row.version, row.last_error, row.last_error_at, row.outbox_depth, row.uptime_s)


async def test_a_heartbeat_writes_the_six_columns_and_answers_one(session, msp, worker):
    assert await WorkerRepo(session).heartbeat(msp.id, worker.id, at=AT, **BEAT) == 1

    assert await heartbeat_of(session, msp.id, worker.id) == (AT, "0.0.0", "job_invalid", ERROR_AT, 0, 152)


async def test_a_later_heartbeat_replaces_every_column_null_included(session, msp, worker):
    await WorkerRepo(session).heartbeat(msp.id, worker.id, at=AT, **BEAT)
    later = AT + dt.timedelta(minutes=15)

    assert await WorkerRepo(session).heartbeat(
        msp.id, worker.id, at=later, version="0.0.1", last_error=None, last_error_at=None, outbox_depth=3, uptime_s=0
    ) == 1

    assert await heartbeat_of(session, msp.id, worker.id) == (later, "0.0.1", None, None, 3, 0)


async def test_a_heartbeat_for_another_msp_s_worker_another_id_or_a_revoked_worker_writes_nothing(session, msp, worker):
    other = await MspRepo(session).create(name="b")
    repo = WorkerRepo(session)

    assert await repo.heartbeat(other.id, worker.id, at=AT, **BEAT) == 0
    assert await repo.heartbeat(msp.id, uuid.uuid4(), at=AT, **BEAT) == 0
    assert await repo.revoke(msp.id, worker.id, NOW) == 1
    assert await repo.heartbeat(msp.id, worker.id, at=AT, **BEAT) == 0

    assert await heartbeat_of(session, msp.id, worker.id) == (None, "0.0.0-registered", None, None, None, None)


async def test_a_heartbeat_takes_the_largest_count_the_body_may_carry(session, msp, worker):
    assert await WorkerRepo(session).heartbeat(
        msp.id, worker.id, at=AT, version="0.0.0", last_error=None, last_error_at=None,
        outbox_depth=2**53 - 1, uptime_s=2**53 - 1,
    ) == 1

    assert (await heartbeat_of(session, msp.id, worker.id))[4:] == (2**53 - 1, 2**53 - 1)
