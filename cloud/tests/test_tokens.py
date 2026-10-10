"""C5.4: tokens (docs/decisions.md 2026-10-10, "C5.3 and C5.4", point 5).

A token is 32 random bytes in base64url without padding; the database holds
its SHA-256 alone. An install token expires seven days after it is issued and
is used once: the acceptance is one UPDATE whose conditions are in the
statement, so an unknown, a used and an expired token are refused alike.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import re

import pytest

from app.auth.tokens import (
    INSTALL_TOKEN_LIFETIME,
    TOKEN_BYTES,
    accept_install_token,
    issue_install_token,
    new_token,
    token_hash,
)
from app.models import InstallToken
from app.repo.install_tokens import InstallTokenRepo
from app.repo.msps import MspRepo
from app.repo.users import UserRepo

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
SEVEN_DAYS = dt.timedelta(days=7)
ONE_SECOND = dt.timedelta(seconds=1)

TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_-]{43}$")


# --- The token and its hash ----------------------------------------------------------


def test_a_token_is_32_random_bytes_in_base64url_without_padding():
    token = new_token()

    assert TOKEN_SHAPE.fullmatch(token), token
    assert "=" not in token
    assert len(base64.urlsafe_b64decode(token + "=")) == 32
    assert TOKEN_BYTES == 32


def test_two_tokens_are_never_equal():
    tokens = {new_token() for _ in range(200)}

    assert len(tokens) == 200


def test_the_hash_is_the_sha256_of_the_token_in_lower_case_hex():
    assert token_hash("abc") == hashlib.sha256(b"abc").hexdigest()
    assert token_hash("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert re.fullmatch(r"[0-9a-f]{64}", token_hash(new_token()))
    assert token_hash("") == hashlib.sha256(b"").hexdigest()


def test_the_lifetime_is_seven_days():
    assert INSTALL_TOKEN_LIFETIME == SEVEN_DAYS


# --- Install tokens ----------------------------------------------------------------------


@pytest.fixture
async def msp(session):
    return await MspRepo(session).create(name="a")


async def test_an_install_token_is_stored_as_its_hash_with_its_expiry(session, msp):
    token, row = await issue_install_token(session, msp.id, NOW, label="lab")

    assert TOKEN_SHAPE.fullmatch(token)
    assert isinstance(row, InstallToken)
    assert (row.msp_id, row.token_hash, row.expires_at, row.used_at) == (
        msp.id, token_hash(token), NOW + SEVEN_DAYS, None
    )
    assert (row.label, row.created_by) == ("lab", None)
    # The token itself is nowhere in the row.
    assert token not in {str(value) for value in vars(row).values()}
    assert (await InstallTokenRepo(session).get(msp.id, row.id)).token_hash == token_hash(token)


async def test_a_token_is_accepted_once_and_the_row_says_when(session, msp):
    token, row = await issue_install_token(session, msp.id, NOW, label="lab")
    when = NOW + dt.timedelta(days=3)

    accepted = await accept_install_token(session, token, when)
    again = await accept_install_token(session, token, when + ONE_SECOND)

    assert accepted is not None
    assert (accepted.id, accepted.msp_id) == (row.id, msp.id)
    await session.refresh(row)
    assert row.used_at == when
    assert again is None
    await session.refresh(row)
    assert row.used_at == when


async def test_expiry_is_at_exactly_seven_days(session, msp):
    token, row = await issue_install_token(session, msp.id, NOW, label="lab")

    assert await accept_install_token(session, token, NOW + SEVEN_DAYS) is None
    await session.refresh(row)
    assert row.used_at is None

    assert (await accept_install_token(session, token, NOW + SEVEN_DAYS - ONE_SECOND)).id == row.id


async def test_a_token_already_expired_when_asked_long_after_is_refused(session, msp):
    token, _ = await issue_install_token(session, msp.id, NOW, label="lab")

    assert await accept_install_token(session, token, NOW + dt.timedelta(days=30)) is None


@pytest.mark.parametrize("token", ["", "not-a-token", "A" * 43, "Bearer x"])
async def test_an_unknown_token_is_refused(session, msp, token):
    await issue_install_token(session, msp.id, NOW, label="lab")

    assert await accept_install_token(session, token, NOW) is None


async def test_two_msps_tokens_are_each_their_own(session):
    a = await MspRepo(session).create(name="a")
    b = await MspRepo(session).create(name="b")
    token_a, row_a = await issue_install_token(session, a.id, NOW, label="a")
    token_b, row_b = await issue_install_token(session, b.id, NOW, label="b")

    accepted = await accept_install_token(session, token_b, NOW)

    assert (accepted.id, accepted.msp_id) == (row_b.id, b.id)
    assert (await accept_install_token(session, token_a, NOW)).msp_id == a.id
    assert token_a != token_b


async def test_issuing_and_accepting_never_commit(session, msp, monkeypatch):
    committed = []

    async def commit():
        committed.append(True)

    monkeypatch.setattr(session, "commit", commit)
    token, _ = await issue_install_token(session, msp.id, NOW, label="lab")
    await accept_install_token(session, token, NOW)

    assert committed == []


async def test_an_install_token_names_its_maker_when_the_caller_gives_one(session, msp):
    user = await UserRepo(session).create(msp.id, email="admin@example.test", password_hash="x", role="admin")

    _token, row = await issue_install_token(session, msp.id, NOW, label="the Veeam VM", created_by=user.id)
    await session.refresh(row)

    assert (row.label, row.created_by) == ("the Veeam VM", user.id)
    assert row.created_at.utcoffset() == dt.timedelta(0)
