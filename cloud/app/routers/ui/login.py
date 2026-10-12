"""`GET /login`, `POST /login`, `POST /logout`, `GET /` (C6.1;
docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", points 7 to 10).

`POST /login`: the limiter first (every post counts; the sixth in a minute
under the address or the caller's IP is 429 with `Retry-After` before any
password work, and one `login.blocked` row when the address is a user's);
then one lookup by address and one Argon2 verification, against the user's
hash or the unknown hash, so a known and an unknown address cost the same;
a wrong password is 401 with the form and one line and one `login.failure`
row; an unknown address the same answer with no row (no MSP) and one log
line with nothing of the form in it; the right password 303 to `/` with the
cookie and one `login.success` row. A refusal is returned, not raised, so its
row commits. Nothing of the form reaches a log line.

After the code review (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3
code review", findings 5 and 10). The two fields are read as optional and
held here, never by FastAPI, whose own 422 repeats the refused value in
`detail[].input` (a password pasted too long came back in clear): a field
that is missing, longer than its limit or no UTF-8 can hold (a multipart
form may name a charset that decodes to a lone surrogate) is 422 with the
login page and neither field in it, before the limiter and any work. An
address `check_email` refuses (a U+0000, which PostgreSQL takes in no text;
a space; no `@`) is no user's: no statement, the unknown hash, the same 401,
counted by the limiter like any other.
"""

from __future__ import annotations

import asyncio
from typing import Annotated

import structlog
from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import RedirectResponse

from app import audit, onboarding
from app.auth import passwords, sessions
from app.auth.sessions import CurrentUser, OptionalUser
from app.db import SessionDep
from app.models import User
from app.repo.errors import RepoError
from app.repo.lookup import Lookup
from app.repo.users import UserRepo
from app.ui import SameOrigin, render

router = APIRouter()
log = structlog.get_logger("app.login")

HOME = "/clients"
WRONG = "wrong email or password"
TOO_MANY = "too many attempts, try again in a minute"
# What a form field may be: the address up to a mailbox's limit, the password
# up to the hasher's rule; longer is the form's 422, never hashed.
MAX_EMAIL = 254


def _usable(field: str | None, limit: int) -> bool:
    """Whether the form gave the field, within its limit, as text UTF-8 holds."""
    if field is None or len(field) > limit:
        return False
    try:
        field.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


async def _user_of(lookup: Lookup, address: str) -> User | None:
    """The user of the address, or None without a statement for an address
    that can be nobody's (`create-user`'s own rule)."""
    try:
        onboarding.check_email(address)
    except RepoError:
        return None
    return await lookup.find_user_by_email(address)


def _secure(request: Request) -> bool:
    return request.app.state.settings.session_cookie_secure


def _login_page(status: int, message: str | None, email: str, headers: dict[str, str] | None = None) -> Response:
    return render("login.html", status_code=status, headers=headers, message=message, email=email)


@router.get("/login", response_class=Response)
async def login_form(user: OptionalUser) -> Response:
    if user is not None:
        return RedirectResponse(HOME, status_code=303)
    return _login_page(200, None, "")


@router.post("/login", response_class=Response)
async def login(
    request: Request,
    session: SessionDep,
    _same_origin: SameOrigin,
    email: Annotated[str | None, Form()] = None,
    password: Annotated[str | None, Form()] = None,
) -> Response:
    if not (_usable(email, MAX_EMAIL) and _usable(password, passwords.MAX_PASSWORD_CHARACTERS)):
        return _login_page(422, WRONG, "")
    address = email.strip()
    keys = [f"email:{address.lower()}"]
    ip = audit.client_ip(request)
    if ip is not None:
        keys.append(f"ip:{ip}")
    retry_after = request.app.state.login_limiter.attempt(keys)
    lookup = Lookup(session)
    if retry_after is not None:
        user = await _user_of(lookup, address)
        if user is not None:
            await audit.record(session, request, user.msp_id, audit.LOGIN_BLOCKED, f"user:{user.id}", user_id=user.id)
        return _login_page(429, TOO_MANY, address, headers={"Retry-After": str(retry_after)})
    user = await _user_of(lookup, address)
    stored = passwords.unknown_hash() if user is None else user.password_hash
    verified = await asyncio.to_thread(passwords.verify_password, stored, password)
    if user is None or not verified:
        if user is None:
            log.info("login refused")
        else:
            await audit.record(session, request, user.msp_id, audit.LOGIN_FAILURE, f"user:{user.id}", user_id=user.id)
        return _login_page(401, WRONG, address)
    if passwords.needs_rehash(stored):
        rehashed = await asyncio.to_thread(passwords.hash_password, password)
        await UserRepo(session).set_password_hash(user.msp_id, user.id, rehashed, changed_at=None)
    await audit.record(session, request, user.msp_id, audit.LOGIN_SUCCESS, f"user:{user.id}", user_id=user.id)
    response = RedirectResponse(HOME, status_code=303)
    secret = request.app.state.settings.secret_key.get_secret_value()
    sessions.set_session_cookie(response, sessions.make_session(secret, user.id, user.msp_id, user.password_changed_at), secure=_secure(request))
    return response


@router.post("/logout", response_class=Response)
async def logout(request: Request, session: SessionDep, _same_origin: SameOrigin, user: OptionalUser) -> Response:
    if user is not None:
        await audit.record(session, request, user.msp_id, audit.LOGOUT, f"user:{user.id}", user_id=user.id)
    response = RedirectResponse(sessions.LOGIN_PATH, status_code=303)
    sessions.clear_session_cookie(response, secure=_secure(request))
    return response


@router.get("/", response_class=Response)
async def home(_user: CurrentUser) -> Response:
    return RedirectResponse(HOME, status_code=303)
