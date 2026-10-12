"""C6.1 (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", points 1, 2, 4,
5, 7 to 11 and 14), the Done-when by name: wrong password five times is
blocked and each attempt is in the audit log. Through the app the factory
makes, `get_session` overridden to the test's session, the limiter on a clock
the test moves, the session clock moved through `app.auth.sessions.now`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import re
from http.cookies import SimpleCookie

import httpx
import pytest
from sqlalchemy import text

from app import audit as words
from app import ui
from app.auth import passwords, sessions
from app.auth.login_limiter import LoginLimiter
from app.auth.sessions import SESSION_COOKIE, SESSION_MAX_AGE_S, make_session, read_session
from app.db import get_session
from app.main import create_app
from app.repo.audit import AuditRepo
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.users import UserRepo
from app.routers.ui.login import HOME, TOO_MANY, WRONG
from tests.conftest import make_settings, session_override

UTC = dt.timezone.utc
PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "Sentinel-Wrong-Password-4f2a"
HASH = passwords.hash_password(PASSWORD)
SECRET = "test-secret-key-" + "0" * 32
IP = "127.0.0.1"
OTHER_IP = "10.0.0.7"
COOKIE_SHAPE = re.compile(r"^[A-Za-z0-9_.-]+$")


def cookie_of(response: httpx.Response) -> SimpleCookie:
    jar = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        jar.load(header)
    return jar


class Lab:
    def __init__(self, session, monkeypatch, **settings: str):
        self.session = session
        self.stream = io.StringIO()
        self.settings = make_settings(SESSION_COOKIE_SECURE="false", **settings)
        self.app = create_app(self.settings, log_stream=self.stream)
        self.app.dependency_overrides[get_session] = session_override(session)
        self.clock = 1000.0
        self.app.state.login_limiter = LoginLimiter(lambda: self.clock)
        # After the rows' own `password_changed_at` (the database's clock).
        self.time = dt.datetime.now(UTC).replace(microsecond=0) + dt.timedelta(minutes=1)
        monkeypatch.setattr(sessions, "now", lambda: self.time)

    async def fill(self) -> None:
        msps, users = MspRepo(self.session), UserRepo(self.session)
        self.msp = await msps.create(name="Contoso MSP")
        self.admin = await users.create(self.msp.id, email="Admin@Example.test", password_hash=HASH, role="admin")
        self.member = await users.create(self.msp.id, email="member@example.test", password_hash=HASH, role="member")
        self.other_msp = await msps.create(name="Other MSP")
        self.other = await users.create(self.other_msp.id, email="other@example.test", password_hash=HASH, role="admin")

    def client(self, *, ip: str = IP, cookies: dict[str, str] | None = None) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=self.app, client=(ip, 40000))
        return httpx.AsyncClient(transport=transport, base_url="http://cloud.test", cookies=cookies)

    async def login(self, email: str, password: str, *, ip: str = IP, headers: dict[str, str] | None = None) -> httpx.Response:
        async with self.client(ip=ip) as client:
            return await client.post("/login", data={"email": email, "password": password}, headers=headers or {})

    async def get(self, path: str, *, cookie: str | None = None, headers: dict[str, str] | None = None) -> httpx.Response:
        async with self.client(cookies={SESSION_COOKIE: cookie} if cookie else None) as client:
            return await client.get(path, headers=headers or {})

    async def post(self, path: str, *, cookie: str | None = None, headers: dict[str, str] | None = None, data=None) -> httpx.Response:
        async with self.client(cookies={SESSION_COOKIE: cookie} if cookie else None) as client:
            return await client.post(path, headers=headers or {}, data=data)

    def cookie_for(self, user) -> str:
        return make_session(SECRET, user.id, user.msp_id, user.password_changed_at)

    async def rows(self, msp_id=None) -> list[tuple[str, str, object, str | None]]:
        """The MSP's audit rows, sorted: every row of one test shares the
        transaction's `now()`, so the table's own order says nothing here."""
        rows = await AuditRepo(self.session).list(self.msp.id if msp_id is None else msp_id)
        return sorted((row.action, row.target, row.user_id, row.ip) for row in rows)

    async def row_count(self) -> int:
        return (await self.session.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()

    @property
    def log(self) -> str:
        return self.stream.getvalue()


@pytest.fixture
async def lab(session, monkeypatch) -> Lab:
    lab = Lab(session, monkeypatch)
    await lab.fill()
    return lab


# --- The Done-when, by name ------------------------------------------------------------------


async def test_wrong_password_five_times_is_blocked_and_each_attempt_is_in_the_audit_log(lab):
    wrong = [await lab.login("admin@example.test", WRONG_PASSWORD) for _ in range(5)]

    sixth = await lab.login("admin@example.test", WRONG_PASSWORD)
    right_but_blocked = await lab.login("admin@example.test", PASSWORD)

    assert [r.status_code for r in wrong] == [401] * 5
    assert all(WRONG in r.text for r in wrong)
    assert (sixth.status_code, sixth.headers["retry-after"]) == (429, "60")
    assert TOO_MANY in sixth.text
    assert right_but_blocked.status_code == 429 and SESSION_COOKIE not in right_but_blocked.headers.get("set-cookie", "")
    target = f"user:{lab.admin.id}"
    assert await lab.rows() == sorted([(words.LOGIN_FAILURE, target, lab.admin.id, IP)] * 5 + [(words.LOGIN_BLOCKED, target, lab.admin.id, IP)] * 2)

    lab.clock += 61
    allowed = await lab.login("admin@example.test", PASSWORD)

    assert (allowed.status_code, allowed.headers["location"]) == (303, HOME)
    assert (await lab.rows()).count((words.LOGIN_SUCCESS, target, lab.admin.id, IP)) == 1
    assert await lab.row_count() == 8


# --- Failure paths first ----------------------------------------------------------------------


async def test_an_unknown_address_is_answered_like_a_wrong_password_with_the_same_work_and_no_row(lab, monkeypatch):
    verified = []
    real = passwords.verify_password
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: verified.append(h) or real(h, p))
    unknown = await lab.login("nobody@example.test", PASSWORD)
    verified_unknown = list(verified)
    wrong = await lab.login("admin@example.test", WRONG_PASSWORD)

    assert (unknown.status_code, wrong.status_code) == (401, 401)
    assert unknown.text.replace("nobody", "admin") == wrong.text
    assert verified_unknown == [passwords.unknown_hash()]
    assert verified[1] == HASH
    assert await lab.row_count() == 1  # the wrong password's row alone
    assert '"event": "login refused"' in lab.log
    assert "nobody" not in lab.log


async def test_the_page_repeats_the_address_escaped_and_never_the_password(lab):
    response = await lab.login('<b onclick="x">bad</b>@example.test', WRONG_PASSWORD)

    assert response.status_code == 401
    assert "&lt;b onclick=&#34;x&#34;&gt;bad&lt;/b&gt;@example.test" in response.text
    assert "<b onclick" not in response.text
    assert WRONG_PASSWORD not in response.text


@pytest.mark.parametrize(
    "data",
    [
        {"email": "admin@example.test"},
        {"password": PASSWORD},
        {},
        {"email": "a" * 250 + "@example.test", "password": PASSWORD},
        {"email": "admin@example.test", "password": "x" * 1025},
    ],
    ids=["no password", "no email", "nothing", "address too long", "password too long"],
)
async def test_a_body_without_the_two_fields_is_422_before_any_work(lab, data, monkeypatch):
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: pytest.fail("verified"))
    async with lab.client() as client:
        response = await client.post("/login", data=data)

    assert response.status_code == 422
    assert await lab.row_count() == 0


async def test_the_form_s_422_is_the_login_page_and_repeats_nothing_of_the_form(lab):
    """The review's finding 10: FastAPI's own 422 repeats the value it
    refused in `detail[].input`, so a password pasted too long came back in
    clear. Every 422 of the form is the page, with neither field in it."""
    long_password = "Sentinel-Long-" + "x" * 1011
    long_address = "sentinel-" + "a" * 250 + "@example.test"
    async with lab.client() as client:
        answers = [
            await client.post("/login", data=data)
            for data in (
                {"email": "admin@example.test", "password": long_password},
                {"email": long_address, "password": PASSWORD},
                {"email": "admin@example.test"},
                {"password": PASSWORD},
            )
        ]

    for response in answers:
        assert response.status_code == 422
        assert response.headers["content-type"].startswith("text/html")
        assert 'name="password"' in response.text and WRONG in response.text
        for forbidden in ("Sentinel", "sentinel", PASSWORD, "admin@example.test", '"detail"'):
            assert forbidden not in response.text, forbidden
    assert await lab.row_count() == 0


@pytest.mark.parametrize("field", ["email", "password"])
async def test_a_field_no_utf_8_can_hold_is_the_form_s_422_and_never_a_500(lab, field, monkeypatch):
    """A multipart form may name its own charset: `+2AA-` in UTF-7 is a lone
    surrogate, which no page, statement or hash can take."""
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: pytest.fail("verified"))
    values = {"email": "admin@example.test", "password": PASSWORD, field: "+2AA-"}
    body = "".join(f'--b\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n' for name, value in values.items()) + "--b--\r\n"
    async with lab.client() as client:
        response = await client.post("/login", content=body.encode(), headers={"Content-Type": "multipart/form-data; boundary=b; charset=utf-7"})

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("text/html")
    assert await lab.row_count() == 0


@pytest.mark.parametrize("address", ["a\x00b@example.test", "admin@example.test\x00", "\x00", "admin@exam ple.test", "no-at-sign"])
async def test_an_address_outside_the_rule_is_nobody_s_and_is_answered_and_counted_like_one(lab, address, monkeypatch):
    """The review's finding 5: PostgreSQL takes no U+0000 in a text, so the
    lookup of such an address was a 500, and never a 429. An address
    `create-user` would refuse is no user's: the same answer and the same
    password work with no statement."""
    verified = []
    real = passwords.verify_password
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: verified.append(h) or real(h, p))

    answers = [await lab.login(address, PASSWORD) for _ in range(6)]

    assert [r.status_code for r in answers] == [401] * 5 + [429]
    assert all(WRONG in r.text for r in answers[:5]) and TOO_MANY in answers[5].text
    assert verified == [passwords.unknown_hash()] * 5
    assert await lab.row_count() == 0


@pytest.mark.parametrize(
    ("stored", "typed"),
    [
        ("\u0130lker@example.test", "\u0130lker@example.test"),
        ("\u039d\u0399\u039a\u039f\u03a3@example.gr", "\u039d\u0399\u039a\u039f\u03a3@example.gr"),
        ("J\u00d6RG@example.test", "j\u00f6rg@EXAMPLE.test"),
        ("stra\u00dfe@example.test", "stra\u00dfe@example.test"),
    ],
    ids=["dotted capital I", "final sigma", "umlaut in the other case", "sharp s"],
)
async def test_an_address_outside_ascii_logs_in_as_it_was_stored(lab, stored, typed):
    """The review's finding 11: the unique is on PostgreSQL's `lower(email)`,
    and Python's `str.lower()` maps these otherwise, so the user that
    `create-user` made was found by no login and no reset."""
    user = await UserRepo(lab.session).create(lab.msp.id, email=stored, password_hash=HASH, role="member")

    found = await Lookup(lab.session).find_user_by_email(f" {typed} ")
    response = await lab.login(typed, PASSWORD)

    assert found is not None and found.id == user.id
    assert response.status_code == 303
    assert await lab.rows() == [(words.LOGIN_SUCCESS, f"user:{user.id}", user.id, IP)]


async def test_a_json_body_is_422(lab):
    async with lab.client() as client:
        response = await client.post("/login", json={"email": "admin@example.test", "password": PASSWORD})

    assert response.status_code == 422


async def test_five_attempts_from_one_address_block_the_sixth_whatever_the_email(lab):
    for n in range(5):
        assert (await lab.login(f"user{n}@example.test", WRONG_PASSWORD)).status_code == 401

    blocked = await lab.login("admin@example.test", PASSWORD)
    elsewhere = await lab.login("admin@example.test", PASSWORD, ip=OTHER_IP)

    assert blocked.status_code == 429
    assert elsewhere.status_code == 303
    assert await lab.rows() == sorted([(words.LOGIN_BLOCKED, f"user:{lab.admin.id}", lab.admin.id, IP), (words.LOGIN_SUCCESS, f"user:{lab.admin.id}", lab.admin.id, OTHER_IP)])


async def test_five_attempts_on_one_email_from_anywhere_block_the_sixth_in_any_case(lab):
    for n in range(5):
        assert (await lab.login("Admin@Example.test", WRONG_PASSWORD, ip=f"10.0.0.{n}")).status_code == 401

    blocked = await lab.login("ADMIN@EXAMPLE.TEST ", PASSWORD, ip="10.0.0.9")
    another = await lab.login("member@example.test", PASSWORD, ip="10.0.0.9")

    assert blocked.status_code == 429
    assert another.status_code == 303


async def test_a_blocked_attempt_on_an_unknown_address_writes_no_row(lab):
    for _ in range(5):
        await lab.login("nobody@example.test", WRONG_PASSWORD)

    blocked = await lab.login("nobody@example.test", WRONG_PASSWORD)

    assert blocked.status_code == 429
    assert await lab.row_count() == 0


async def test_a_blocked_attempt_does_no_password_work(lab, monkeypatch):
    for _ in range(5):
        await lab.login("admin@example.test", WRONG_PASSWORD)
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: pytest.fail("verified while blocked"))

    assert (await lab.login("admin@example.test", PASSWORD)).status_code == 429


@pytest.mark.parametrize("site", ["cross-site", "same-site", "Cross-Site"])
async def test_a_post_from_another_site_is_403_before_anything(lab, site, monkeypatch):
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: pytest.fail("verified"))

    login = await lab.login("admin@example.test", PASSWORD, headers={"Sec-Fetch-Site": site})
    logout = await lab.post("/logout", cookie=lab.cookie_for(lab.admin), headers={"Sec-Fetch-Site": site})

    assert (login.status_code, logout.status_code) == (403, 403)
    assert await lab.row_count() == 0


@pytest.mark.parametrize("site", ["same-origin", "none", None])
async def test_a_post_from_this_site_or_without_the_header_passes(lab, site):
    headers = {} if site is None else {"Sec-Fetch-Site": site}

    assert (await lab.login("admin@example.test", PASSWORD, headers=headers)).status_code == 303


# --- The session -------------------------------------------------------------------------------


async def test_the_right_password_sets_the_cookie_with_its_flags_and_sends_the_browser_home(lab):
    response = await lab.login(" Admin@Example.test ", PASSWORD)

    assert (response.status_code, response.headers["location"]) == (303, HOME)
    morsel = cookie_of(response)[SESSION_COOKIE]
    assert COOKIE_SHAPE.match(morsel.value)
    assert morsel["httponly"] and morsel["samesite"].lower() == "lax" and morsel["path"] == "/"
    assert morsel["max-age"] == str(SESSION_MAX_AGE_S) and not morsel["secure"]
    found = read_session(SECRET, morsel.value)
    assert (found.user_id, found.msp_id, found.issued_at) == (lab.admin.id, lab.msp.id, lab.time)
    assert found.password_stamp == sessions.password_stamp(lab.admin.password_changed_at)
    assert await lab.rows() == [(words.LOGIN_SUCCESS, f"user:{lab.admin.id}", lab.admin.id, IP)]

    home = await lab.get("/", cookie=morsel.value)
    form = await lab.get("/login", cookie=morsel.value)
    assert (home.status_code, home.headers["location"]) == (303, HOME)
    assert (form.status_code, form.headers["location"]) == (303, HOME)


async def test_the_cookie_is_secure_unless_the_setting_says_otherwise(session, monkeypatch):
    lab = Lab(session, monkeypatch)
    lab.settings = make_settings()
    lab.app.state.settings = lab.settings
    await lab.fill()

    response = await lab.login("admin@example.test", PASSWORD)

    assert cookie_of(response)[SESSION_COOKIE]["secure"]


async def test_the_login_form_is_200_without_a_session_and_the_pages_send_the_browser_to_it(lab):
    form = await lab.get("/login")
    home = await lab.get("/")
    fragment = await lab.get("/", headers={"HX-Request": "true"})

    assert form.status_code == 200 and 'name="password"' in form.text and "Log in" in form.text
    assert (home.status_code, home.headers["location"]) == (303, "/login")
    assert (fragment.status_code, fragment.headers["hx-redirect"]) == (401, "/login")


def tampered(cookie: str) -> str:
    head, _, signature = cookie.rpartition(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    return f"{head}.{flipped}"


async def test_a_cookie_that_is_tampered_expired_of_another_shape_or_another_key_s_is_no_session(lab):
    good = lab.cookie_for(lab.admin)
    other_key = make_session("another-secret-key-" + "1" * 32, lab.admin.id, lab.msp.id, lab.admin.password_changed_at)
    stamp = sessions.password_stamp(lab.admin.password_changed_at)
    other_salt = sessions.URLSafeSerializer(SECRET, salt="other").dumps({"u": str(lab.admin.id), "m": str(lab.msp.id), "t": int(lab.time.timestamp()), "p": stamp})
    shapes = [
        sessions._serializer(SECRET).dumps(payload)
        for payload in (
            ["u", "m", "t", "p"],
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "p": stamp},
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "t": "123", "p": stamp},
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "t": 1.5, "p": stamp},
            {"u": "not-a-uuid", "m": str(lab.msp.id), "t": int(lab.time.timestamp()), "p": stamp},
            {"u": str(lab.admin.id), "m": 7, "t": int(lab.time.timestamp()), "p": stamp},
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "t": int(lab.time.timestamp()), "p": stamp, "x": 1},
            # The cookie of before the review: no stamp of the password.
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "t": int(lab.time.timestamp())},
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "t": int(lab.time.timestamp()), "p": str(stamp)},
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "t": int(lab.time.timestamp()), "p": float(stamp)},
            {"u": str(lab.admin.id), "m": str(lab.msp.id), "t": int(lab.time.timestamp()), "p": True},
        )
    ]
    before = lab.time
    lab.time = before + dt.timedelta(seconds=SESSION_MAX_AGE_S)
    at_the_edge = await lab.get("/", cookie=good)
    lab.time = before + dt.timedelta(seconds=SESSION_MAX_AGE_S + 1)
    expired = await lab.get("/", cookie=good)
    lab.time = before - dt.timedelta(seconds=1)
    from_the_future = await lab.get("/", cookie=good)
    lab.time = before

    assert (at_the_edge.status_code, at_the_edge.headers["location"]) == (303, HOME)
    for name, cookie in [("tampered", tampered(good)), ("other key", other_key), ("other salt", other_salt), ("empty", ""), ("garbage", "x.y.z"), *[(f"shape {n}", s) for n, s in enumerate(shapes)]]:
        response = await lab.get("/", cookie=cookie)
        assert (response.status_code, response.headers.get("location")) == (303, "/login"), name
    assert expired.headers["location"] == "/login" and from_the_future.headers["location"] == "/login"


async def test_a_cookie_of_a_user_who_is_gone_or_of_another_msp_s_id_is_no_session(lab):
    foreign = make_session(SECRET, lab.admin.id, lab.other_msp.id, lab.admin.password_changed_at)
    await lab.session.execute(text('DELETE FROM "user" WHERE id = :id'), {"id": lab.other.id})
    gone = lab.cookie_for(lab.other)

    assert (await lab.get("/", cookie=foreign)).headers["location"] == "/login"
    assert (await lab.get("/", cookie=gone)).headers["location"] == "/login"
    assert (await lab.get("/", cookie=lab.cookie_for(lab.admin))).headers["location"] == HOME


async def test_a_password_reset_ends_every_session_issued_before_it(lab):
    cookie = lab.cookie_for(lab.admin)
    assert (await lab.get("/", cookie=cookie)).headers["location"] == HOME

    assert await UserRepo(lab.session).set_password_hash(lab.msp.id, lab.admin.id, HASH, changed_at=lab.time + dt.timedelta(seconds=1)) == 1

    assert (await lab.get("/", cookie=cookie)).headers["location"] == "/login"
    lab.time += dt.timedelta(seconds=2)
    assert (await lab.get("/", cookie=lab.cookie_for(lab.admin))).headers["location"] == HOME


async def test_a_login_in_the_second_the_password_was_set_is_a_session(lab):
    """The review's finding 2 (a): the cookie's time is whole seconds and the
    row's has microseconds from another clock; no clock decides a session."""
    later_in_the_second = lab.time + dt.timedelta(microseconds=900_000)
    assert await UserRepo(lab.session).set_password_hash(lab.msp.id, lab.admin.id, HASH, changed_at=later_in_the_second) == 1

    response = await lab.login("admin@example.test", PASSWORD)
    cookie = cookie_of(response)[SESSION_COOKIE].value

    assert response.status_code == 303
    assert (await lab.get("/", cookie=cookie)).headers["location"] == HOME


@pytest.mark.parametrize("behind", [dt.timedelta(minutes=3), dt.timedelta(days=400), dt.timedelta(microseconds=1)])
async def test_a_reset_from_a_clock_behind_the_cloud_s_still_ends_every_session(lab, behind):
    """The review's finding 2 (b): `reset-password` runs wherever `DATABASE_URL`
    is, on that machine's clock."""
    cookie = lab.cookie_for(lab.admin)
    assert (await lab.get("/", cookie=cookie)).headers["location"] == HOME

    assert await UserRepo(lab.session).set_password_hash(lab.msp.id, lab.admin.id, HASH, changed_at=lab.time - behind) == 1
    await lab.session.refresh(lab.admin)

    assert (await lab.get("/", cookie=cookie)).headers["location"] == "/login"
    assert (await lab.get("/", cookie=lab.cookie_for(lab.admin))).headers["location"] == HOME


async def test_a_login_that_read_the_row_before_a_reset_is_no_session_after_it(lab):
    """A login in flight across a reset: its cookie carries the stamp of the
    row it verified against, whatever time it is signed at."""
    read_before = lab.admin.password_changed_at
    assert await UserRepo(lab.session).set_password_hash(lab.msp.id, lab.admin.id, HASH, changed_at=lab.time) == 1
    lab.time += dt.timedelta(seconds=30)

    late = make_session(SECRET, lab.admin.id, lab.msp.id, read_before)

    assert (await lab.get("/", cookie=late)).headers["location"] == "/login"


def test_the_password_s_stamp_is_its_time_in_whole_microseconds():
    at = dt.datetime(2026, 10, 12, 12, 0, 0, 250_001, tzinfo=UTC)

    assert sessions.password_stamp(at) == 1_791_806_400_250_001
    assert sessions.password_stamp(at.astimezone(dt.timezone(dt.timedelta(hours=2)))) == sessions.password_stamp(at)
    assert sessions.password_stamp(at + dt.timedelta(microseconds=1)) == sessions.password_stamp(at) + 1


async def test_a_rehash_at_login_replaces_the_hash_and_keeps_the_sessions(lab):
    older = passwords._hasher.__class__(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
    assert await UserRepo(lab.session).set_password_hash(lab.msp.id, lab.admin.id, older, changed_at=None) == 1
    earlier = lab.cookie_for(lab.admin)
    lab.time += dt.timedelta(seconds=5)

    response = await lab.login("admin@example.test", PASSWORD)

    assert response.status_code == 303
    await lab.session.refresh(lab.admin)
    assert lab.admin.password_hash != older and not passwords.needs_rehash(lab.admin.password_hash)
    assert passwords.verify_password(lab.admin.password_hash, PASSWORD)
    assert (await lab.get("/", cookie=earlier)).headers["location"] == HOME


async def test_logout_clears_the_cookie_writes_the_row_and_sends_the_browser_to_the_form(lab):
    cookie = lab.cookie_for(lab.member)

    with_session = await lab.post("/logout", cookie=cookie)
    without = await lab.post("/logout")

    assert (with_session.status_code, with_session.headers["location"]) == (303, "/login")
    morsel = cookie_of(with_session)[SESSION_COOKIE]
    assert morsel.value == "" and morsel["max-age"] == "0" and morsel["httponly"] and morsel["path"] == "/"
    assert (without.status_code, without.headers["location"]) == (303, "/login")
    assert await lab.rows() == [(words.LOGOUT, f"user:{lab.member.id}", lab.member.id, IP)]


async def test_get_logout_is_405(lab):
    assert (await lab.get("/logout", cookie=lab.cookie_for(lab.admin))).status_code == 405


# --- The log, the document, the static files --------------------------------------------------


async def test_nothing_of_a_login_reaches_a_log_line(lab):
    await lab.login("admin@example.test", WRONG_PASSWORD)
    right = await lab.login("admin@example.test", PASSWORD)
    await lab.login("nobody@example.test", PASSWORD)
    cookie = cookie_of(right)[SESSION_COOKIE].value
    await lab.get("/", cookie=cookie)
    await lab.post("/logout", cookie=cookie)
    for _ in range(5):
        await lab.login("admin@example.test", WRONG_PASSWORD)

    lines = [json.loads(line) for line in lab.log.splitlines()]
    assert {line["event"] for line in lines} == {"request", "login refused"}
    assert len([line for line in lines if line["event"] == "request"]) == 10
    for forbidden in ("example.test", "admin", WRONG_PASSWORD, PASSWORD, cookie, SESSION_COOKIE, "password=", "email="):
        assert forbidden not in lab.log, forbidden


async def test_the_pages_are_at_the_root_and_in_no_document(lab):
    document = lab.app.openapi()

    assert not [path for path in document["paths"] if not path.startswith("/v1/")]
    assert (await lab.get("/v1/login")).status_code == 404
    assert (await lab.get("/static/login")).status_code == 404


async def test_every_page_carries_the_api_header_and_is_under_the_body_cap(lab):
    response = await lab.get("/login")
    big = await lab.post("/login", headers={"Content-Length": "65537", "Content-Type": "application/x-www-form-urlencoded"})

    assert response.headers["x-restoreproof-api"] == "1"
    assert big.status_code == 413


async def test_the_static_files_are_served_and_htmx_is_the_vendored_file_held_to_its_hash(lab):
    css = await lab.get("/static/style.css")
    script = await lab.get("/static/htmx.min.js")
    form = await lab.get("/login")

    assert css.status_code == 200 and css.headers["content-type"].startswith("text/css")
    assert script.status_code == 200
    assert hashlib.sha256(script.content).hexdigest() == ui.HTMX_SHA256
    assert (ui.STATIC_DIR / ui.HTMX_FILE).read_bytes() == script.content
    assert f'src="/static/htmx.min.js" integrity="{ui.htmx_integrity()}"' in form.text
    assert ui.htmx_integrity() == "sha384-" + __import__("base64").b64encode(hashlib.sha384(script.content).digest()).decode()
    assert ui.HTMX_VERSION in script.text[:4000] or "htmx" in script.text[:200]
    assert sorted(p.name for p in ui.STATIC_DIR.iterdir()) == ["htmx.min.js", "style.css"]


def test_every_template_autoescapes():
    env = ui.environment()

    for name in env.list_templates():
        assert env.get_template(name).environment.autoescape is True, name
    assert env.autoescape is True
    assert env.from_string("{{ x }}").render(x="<b>") == "&lt;b&gt;"


def test_the_two_clocks_are_the_cloud_s_in_utc():
    """Every test above moves them; the real ones are aware UTC now."""
    for clock in (sessions.now, ui.now):
        stamp = clock()
        assert stamp.tzinfo is not None and stamp.utcoffset() == dt.timedelta(0)
        assert abs((dt.datetime.now(UTC) - stamp).total_seconds()) < 5


async def test_a_user_whose_msp_is_gone_is_the_app_s_failure(lab):
    """The keys forbid it; `layout` raises rather than render a frame with no name."""
    from app.ui import layout

    class Session:
        async def scalar(self, statement):
            return None

    with pytest.raises(RuntimeError, match="without their MSP"):
        await layout(lab.admin, Session())


def test_the_session_s_constants_and_the_salt():
    assert (SESSION_COOKIE, SESSION_MAX_AGE_S, sessions.SESSION_SALT) == ("rp_session", 43200, "restoreproof.session.v1")
    assert words.ACTIONS == ("login.success", "login.failure", "login.blocked", "logout", "bundle.download", "worker.revoke")


async def test_the_helper_refuses_a_word_outside_the_list(lab):
    class Request:
        client = None

    with pytest.raises(ValueError):
        await words.record(lab.session, Request(), lab.msp.id, "made.up", "x", user_id=None)
    assert words.client_ip(Request()) is None
