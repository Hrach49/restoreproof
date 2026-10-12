"""What every page shares (C6.1, C6.2; docs/decisions.md 2026-10-12, "C6.1,
C6.2 and C6.3", points 11 and 26): the Jinja2 environment over
app/templates/ with autoescape on for every template and an undefined name a
fault, the filters the templates use (a time as UTC, a duration as m:ss, a
state's colour word), the htmx file's hash for the script tag's `integrity`,
`Layout` (the user and the MSP every page's frame names, two reads), and the
`Sec-Fetch-Site` rule for a page's POST (point 10).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.auth.sessions import CurrentUser
from app.db import SessionDep
from app.models import Msp, User
from app.repo.msps import MspRepo

APP_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"
STATIC_PATH = "/static"

# htmx 2.0.11, dist/htmx.min.js, vendored (point 11): a test holds the file
# to this and the script tag's `integrity` to the file.
HTMX_FILE = "htmx.min.js"
HTMX_VERSION = "2.0.11"
HTMX_SHA256 = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"

STATE_COLOURS = {"pass": "pass", "fail": "fail", "error": "error", "expired": "quiet", "queued": "quiet", "dispatched": "quiet"}
HX_REQUEST = "hx-request"

# A page's POST from another site is refused; `same-origin`, `none` and no
# header (curl, an old browser) pass, and SameSite=Lax keeps the cookie off a
# cross-site POST anyway. It doesn't keep it off a cross-site link, so the
# download, a GET that writes an audit row, is held the same way.
CROSS_SITE = ("cross-site", "same-site")


def now() -> dt.datetime:
    """The Cloud's clock for the pages; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


def utc(value: dt.datetime | None, seconds: bool = False) -> str:
    if value is None:
        return "—"
    layout = "%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M"
    return value.astimezone(dt.timezone.utc).strftime(layout) + " UTC"


def duration(ms: int | None) -> str:
    """A duration as m:ss (h:mm:ss past an hour), or a dash for none."""
    if ms is None:
        return "—"
    total = ms // 1000
    hours, rest = divmod(total, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    return f"{minutes}:{seconds:02d}"


def colour(state: str | None) -> str:
    return "none" if state is None else STATE_COLOURS.get(state, "quiet")


def yes_no(value: bool | None) -> str:
    if value is None:
        return "—"
    return "yes" if value else "no"


def make_environment(folder: Path) -> Environment:
    """A Jinja2 environment over `folder` with the pages' rules and filters:
    autoescape for every template, an undefined name a fault. The pages'
    environment and the report's (C6.4, `app/report/render.py`) are both made
    here, so a template of either escapes the same way."""
    env = Environment(loader=FileSystemLoader(folder), autoescape=True, undefined=StrictUndefined)
    env.filters.update({"utc": utc, "duration": duration, "colour": colour, "yes_no": yes_no})
    return env


@lru_cache(maxsize=1)
def environment() -> Environment:
    env = make_environment(TEMPLATES_DIR)
    env.globals.update({"static": STATIC_PATH, "htmx_integrity": htmx_integrity()})
    return env


@lru_cache(maxsize=1)
def htmx_integrity() -> str:
    """The `integrity` value of the vendored htmx: its SHA-384, as browsers take it."""
    digest = hashlib.sha384((STATIC_DIR / HTMX_FILE).read_bytes()).digest()
    return "sha384-" + base64.b64encode(digest).decode("ascii")


def render(name: str, status_code: int = 200, headers: dict[str, str] | None = None, **context: Any) -> HTMLResponse:
    text = environment().get_template(name).render(**context)
    return HTMLResponse(text, status_code=status_code, headers=headers)


@dataclass(frozen=True)
class Layout:
    """What every page's frame names: the user and their MSP."""

    user: User
    msp: Msp


async def layout(user: CurrentUser, session: SessionDep) -> Layout:
    msp = await MspRepo(session).get(user.msp_id)
    if msp is None:
        raise RuntimeError("a user without their MSP")
    return Layout(user, msp)


LayoutDep = Annotated[Layout, Depends(layout)]


def same_origin(request: Request) -> None:
    """Refuse a request whose `Sec-Fetch-Site` says another site sent it:
    every POST of the pages, and the one GET that writes (the download)."""
    if request.headers.get("sec-fetch-site", "").lower() in CROSS_SITE:
        raise HTTPException(status_code=403, detail="cross-site request")


SameOrigin = Annotated[None, Depends(same_origin)]
