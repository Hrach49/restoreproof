"""Sessions and `current_user` (C6.1; docs/decisions.md 2026-10-12, "C6.1,
C6.2 and C6.3", points 4 and 5).

The session is one signed cookie, `rp_session`: itsdangerous's URL-safe
serializer under `SECRET_KEY` and the salt `restoreproof.session.v1` over
`{"u": <user_id>, "m": <msp_id>, "t": <issued, whole seconds>, "p": <the
password's stamp>}`, good for `SESSION_MAX_AGE_S` from `t` by the Cloud's
clock (`now()`, which a test moves). `SECRET_KEY` signs this and nothing else.
A cookie that is missing, unsigned, expired or of another shape is no
session, all alike.

`p` is `password_stamp(user.password_changed_at)` of the row the login
verified the password against: the session is of that password. `current_user`
reads the user's row every time (`UserRepo.get`, both ids from the cookie): a
user who is gone is no session, and a cookie whose stamp isn't the row's is no
session, so a reset, which moves `password_changed_at`, ends every session.
The two are compared for equality and never as times (the code review's
finding 2): `t` is the API host's clock in whole seconds and
`password_changed_at` the database's or the CLI host's in microseconds, so
"issued before" made a login in the second of a `create-user` a dead session
and let a reset from a clock behind the Cloud's leave sessions alive. No
session sends a browser to `/login` (303) and answers an htmx request 401
with `HX-Redirect`, since htmx follows no 303 across a swap. `current_admin`
is `current_user` and the role: a member is 403 (the route exists and is the
user's own MSP's). The cookie is not renewed while in use.

Guarded at 100% line and branch (tools/check_coverage.py).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Request, Response
from itsdangerous import BadData, URLSafeSerializer

from app.db import SessionDep
from app.models import User
from app.repo.users import UserRepo

SESSION_COOKIE = "rp_session"
SESSION_SALT = "restoreproof.session.v1"
SESSION_MAX_AGE_S = 12 * 60 * 60
LOGIN_PATH = "/login"
HX_REQUEST = "hx-request"
ADMIN = "admin"


def now() -> dt.datetime:
    """The Cloud's clock; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


@dataclass(frozen=True)
class Session:
    user_id: UUID
    msp_id: UUID
    issued_at: dt.datetime
    password_stamp: int


def _serializer(secret_key: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret_key, salt=SESSION_SALT)


EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def password_stamp(password_changed_at: dt.datetime) -> int:
    """The time as whole microseconds since 1970, the column's own precision:
    what a cookie carries of the password it was issued for."""
    return (password_changed_at - EPOCH) // dt.timedelta(microseconds=1)


def make_session(secret_key: str, user_id: UUID, msp_id: UUID, password_changed_at: dt.datetime) -> str:
    """The cookie's value for the user, issued now for the password of
    `password_changed_at` (the row the login read)."""
    issued = int(now().timestamp())
    payload = {"u": str(user_id), "m": str(msp_id), "t": issued, "p": password_stamp(password_changed_at)}
    return _serializer(secret_key).dumps(payload)


def read_session(secret_key: str, cookie: str | None) -> Session | None:
    """The session the cookie carries, or None for no cookie, a bad
    signature, another shape, or one older than `SESSION_MAX_AGE_S`."""
    if not cookie:
        return None
    try:
        payload = _serializer(secret_key).loads(cookie)
    except BadData:
        return None
    if not (isinstance(payload, dict) and set(payload) == {"u", "m", "t", "p"} and type(payload["t"]) is int and type(payload["p"]) is int):
        return None
    try:
        user_id, msp_id = UUID(payload["u"]), UUID(payload["m"])
    except (ValueError, TypeError, AttributeError):
        return None
    issued = dt.datetime.fromtimestamp(payload["t"], dt.timezone.utc)
    age = now() - issued
    if age < dt.timedelta(0) or age > dt.timedelta(seconds=SESSION_MAX_AGE_S):
        return None
    return Session(user_id, msp_id, issued, payload["p"])


def set_session_cookie(response: Response, value: str, *, secure: bool) -> None:
    response.set_cookie(
        SESSION_COOKIE, value, max_age=SESSION_MAX_AGE_S, path="/", httponly=True, samesite="lax", secure=secure
    )


def clear_session_cookie(response: Response, *, secure: bool) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax", secure=secure)


class NoSession(HTTPException):
    """No session: a browser is sent to the login page, an htmx request told
    to go there (401 with `HX-Redirect`)."""

    def __init__(self, request: Request) -> None:
        if request.headers.get(HX_REQUEST) == "true":
            super().__init__(status_code=401, detail="no session", headers={"HX-Redirect": LOGIN_PATH})
        else:
            super().__init__(status_code=303, detail="no session", headers={"Location": LOGIN_PATH})


async def session_user(request: Request, session: SessionDep) -> User | None:
    """The user behind the request's cookie, or None: the one read of the row
    (`UserRepo.get` with both ids from the cookie), the reset rule applied."""
    settings = request.app.state.settings
    found = read_session(settings.secret_key.get_secret_value(), request.cookies.get(SESSION_COOKIE))
    if found is None:
        return None
    user = await UserRepo(session).get(found.msp_id, found.user_id)
    if user is None or found.password_stamp != password_stamp(user.password_changed_at):
        return None
    return user


async def current_user(request: Request, user: Annotated[User | None, Depends(session_user)]) -> User:
    if user is None:
        raise NoSession(request)
    request.state.user = user
    return user


async def current_admin(user: Annotated[User, Depends(current_user)]) -> User:
    if user.role != ADMIN:
        raise HTTPException(status_code=403, detail="admin only")
    return user


CurrentUser = Annotated[User, Depends(current_user)]
CurrentAdmin = Annotated[User, Depends(current_admin)]
OptionalUser = Annotated[User | None, Depends(session_user)]
