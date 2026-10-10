"""Tokens (C5.4).

`new_token()` is 32 random bytes in base64url without padding (43 characters);
`token_hash()` is its SHA-256 in hex, the only form the database holds. An
install token expires `INSTALL_TOKEN_LIFETIME` after it is issued and is used
once: `accept_install_token` finds the row by its hash, then marks it used in
one UPDATE whose conditions (`used_at IS NULL AND expires_at > now`) are in the
statement, so an unknown, a used and an expired token are refused alike, and
two accepts at once can't both win. Nothing here commits.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import secrets
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import InstallToken
from app.repo.install_tokens import InstallTokenRepo
from app.repo.lookup import Lookup

TOKEN_BYTES = 32
INSTALL_TOKEN_LIFETIME = dt.timedelta(days=7)


def new_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(TOKEN_BYTES)).rstrip(b"=").decode("ascii")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def issue_install_token(
    session: AsyncSession, msp_id: UUID, now: dt.datetime
) -> tuple[str, InstallToken]:
    """A new install token for the MSP: the token, to show once, and its row."""
    token = new_token()
    row = await InstallTokenRepo(session).create(
        msp_id, token_hash=token_hash(token), expires_at=now + INSTALL_TOKEN_LIFETIME
    )
    return token, row


async def accept_install_token(
    session: AsyncSession, token: str, now: dt.datetime
) -> InstallToken | None:
    """Use the token once; `None` for one that is unknown, used or expired."""
    row = await Lookup(session).find_install_token_by_hash(token_hash(token))
    if row is None:
        return None
    if await InstallTokenRepo(session).mark_used(row.msp_id, row.id, now) == 0:
        return None
    return row
