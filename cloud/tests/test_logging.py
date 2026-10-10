"""C5.1: one JSON line per request with its request ID; no line holds a token,
a password or a request body."""

import io
import json
import logging as stdlib_logging
import re

import httpx
import pytest
import structlog
from fastapi import FastAPI, Request

from app.logging import REDACTED, RequestLogMiddleware, configure_logging

SENTINEL = "Sentinel-Log-91bd"


class Lab:
    """A small app behind the middleware, its log lines in memory."""

    def __init__(self, level: str = "info"):
        self.stream = io.StringIO()
        configure_logging(level, stream=self.stream)
        self.app = FastAPI()
        self.app.add_middleware(RequestLogMiddleware)
        log = structlog.get_logger("lab")

        @self.app.get("/v1/plain")
        async def plain():
            log.info("inside the request", step=1)
            log.debug("a debug line")
            return {"ok": True}

        @self.app.post("/v1/echo")
        async def echo(request: Request):
            await request.body()
            return {"ok": True}

        @self.app.get("/v1/boom")
        async def boom():
            raise RuntimeError(f"the message quotes its input: {SENTINEL}")

        @self.app.get("/v1/keyed")
        async def keyed():
            log.info(
                "keyed",
                authorization=f"Bearer {SENTINEL}",
                password=SENTINEL,
                api_token=SENTINEL,
                S3_SECRET_KEY=SENTINEL,
                nested={"refresh_token": SENTINEL, "cookie": SENTINEL, "kept": "visible"},
                listed=[{"client_secret": SENTINEL}],
                token_count=3,
            )
            return {"ok": True}

        @self.app.get("/v1/stdlib")
        async def stdlib():
            stdlib_logging.getLogger("some.library").warning("from the %s", "library")
            try:
                raise ValueError(f"quoted {SENTINEL}")
            except ValueError:
                stdlib_logging.getLogger("some.library").exception("it failed")
            return {"ok": True}

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://cloud.test"
        )

    @property
    def text(self) -> str:
        return self.stream.getvalue()

    @property
    def lines(self) -> list[dict]:
        return [json.loads(line) for line in self.text.splitlines()]

    def request_line(self) -> dict:
        (line,) = [entry for entry in self.lines if entry["event"] == "request"]
        return line


@pytest.fixture
def lab():
    return Lab()


async def test_one_json_line_per_request_with_the_request_id(lab):
    async with lab.client() as client:
        response = await client.get("/v1/plain", headers={"X-Request-ID": "abc-123"})

    assert response.status_code == 200
    line = lab.request_line()
    assert line["request_id"] == "abc-123"
    assert line["method"] == "GET"
    assert line["path"] == "/v1/plain"
    assert line["status"] == 200
    assert line["level"] == "info"
    assert isinstance(line["duration_ms"], int) and line["duration_ms"] >= 0
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", line["ts"])
    assert set(line) == {
        "ts", "level", "event", "request_id", "method", "path", "status", "duration_ms",
    }  # fmt: skip


async def test_every_line_is_one_json_object(lab):
    async with lab.client() as client:
        await client.get("/v1/plain")
        await client.get("/v1/boom")
        await client.get("/v1/stdlib")

    for line in lab.text.splitlines():
        assert isinstance(json.loads(line), dict)


async def test_the_given_request_id_is_echoed(lab):
    async with lab.client() as client:
        response = await client.get("/v1/plain", headers={"X-Request-ID": "Run.7_a-Z"})

    assert response.headers["x-request-id"] == "Run.7_a-Z"


async def test_a_request_without_an_id_gets_one(lab):
    async with lab.client() as client:
        first = await client.get("/v1/plain")
        second = await client.get("/v1/plain")

    made = first.headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", made)
    assert second.headers["x-request-id"] != made
    assert {line["request_id"] for line in lab.lines if line["event"] == "request"} == {
        made,
        second.headers["x-request-id"],
    }


@pytest.mark.parametrize(
    "given",
    [
        "",
        "a" * 65,
        "has space",
        "semi;colon",
        'quote"d',
        "slash/ed",
        "tab\there",
        "caf\u00e9",
        f"{SENTINEL}{{}}",
    ],
)
async def test_a_request_id_outside_the_rule_is_replaced(lab, given):
    async with lab.client() as client:
        response = await client.get("/v1/plain", headers={"X-Request-ID": given.encode("latin-1")})

    made = response.headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", made)
    assert lab.request_line()["request_id"] == made


async def test_the_longest_id_the_rule_takes(lab):
    async with lab.client() as client:
        response = await client.get("/v1/plain", headers={"X-Request-ID": "a" * 64})

    assert response.headers["x-request-id"] == "a" * 64


async def test_two_request_id_headers_are_no_id(lab):
    async with lab.client() as client:
        response = await client.get(
            "/v1/plain", headers=[("X-Request-ID", "one"), ("X-Request-ID", "two")]
        )

    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-request-id"])


async def test_every_line_written_during_a_request_carries_its_id(lab):
    async with lab.client() as client:
        await client.get("/v1/plain", headers={"X-Request-ID": "one-id"})
        await client.get("/v1/stdlib", headers={"X-Request-ID": "other-id"})

    inside = [line for line in lab.lines if line["event"] == "inside the request"]
    assert [line["request_id"] for line in inside] == ["one-id"]
    assert inside[0]["step"] == 1
    library = [line for line in lab.lines if line["event"] == "from the library"]
    assert [line["request_id"] for line in library] == ["other-id"]
    assert library[0]["level"] == "warning"


async def test_a_line_outside_a_request_has_no_request_id(lab):
    async with lab.client() as client:
        await client.get("/v1/plain", headers={"X-Request-ID": "one-id"})
    structlog.get_logger("lab").info("after")

    (after,) = [line for line in lab.lines if line["event"] == "after"]
    assert "request_id" not in after


async def test_the_level_filters(lab):
    async with lab.client() as client:
        await client.get("/v1/plain")
    assert not [line for line in lab.lines if line["event"] == "a debug line"]

    debug = Lab("debug")
    async with debug.client() as client:
        await client.get("/v1/plain")
    assert [line for line in debug.lines if line["event"] == "a debug line"]

    errors_only = Lab("error")
    async with errors_only.client() as client:
        await client.get("/v1/plain")
    assert errors_only.lines == []


async def test_no_line_holds_a_header_a_query_string_or_a_body(lab):
    async with lab.client() as client:
        response = await client.post(
            f"/v1/echo?token={SENTINEL}&q=1",
            headers={"Authorization": f"Bearer {SENTINEL}", "Cookie": f"session={SENTINEL}"},
            json={"password": SENTINEL},
        )

    assert response.status_code == 200
    assert lab.request_line()["path"] == "/v1/echo"
    assert SENTINEL not in lab.text


async def test_an_unhandled_exception_is_logged_by_type_and_frames_never_by_message(lab):
    async with lab.client() as client:
        response = await client.get(
            f"/v1/boom?token={SENTINEL}", headers={"X-Request-ID": "boom-1"}
        )

    assert response.status_code == 500
    assert response.json() == {"error": "internal", "request_id": "boom-1"}
    assert response.headers["x-request-id"] == "boom-1"
    assert SENTINEL not in response.text
    assert SENTINEL not in lab.text

    (failure,) = [line for line in lab.lines if line["event"] == "unhandled exception"]
    assert failure["level"] == "error"
    assert failure["request_id"] == "boom-1"
    assert failure["exc_type"] == "RuntimeError"
    assert any(frame.endswith(" in boom") for frame in failure["stack"])
    assert all(re.fullmatch(r"[^:]+:\d+ in \S+", frame) for frame in failure["stack"])
    assert lab.request_line()["status"] == 500


async def test_a_library_s_exception_line_loses_its_message_too(lab):
    async with lab.client() as client:
        await client.get("/v1/stdlib")

    (failure,) = [line for line in lab.lines if line["event"] == "it failed"]
    assert failure["exc_type"] == "ValueError"
    assert failure["stack"]
    assert "exc_info" not in failure and "exception" not in failure
    assert SENTINEL not in lab.text


def test_an_exception_is_summarised_however_it_is_handed_over():
    lab = Lab()
    log = structlog.get_logger("lab")

    try:
        raise KeyError(SENTINEL)
    except KeyError as error:
        log.exception("the current one")
        log.error("a tuple", exc_info=(type(error), error, error.__traceback__))
    log.error("true with none current", exc_info=True)
    log.error("false", exc_info=False)

    current, as_tuple, none_current, false = lab.lines
    assert (current["exc_type"], as_tuple["exc_type"]) == ("KeyError", "KeyError")
    assert current["stack"] == as_tuple["stack"] != []
    for line in (none_current, false):
        assert "exc_type" not in line and "stack" not in line and "exc_info" not in line
    assert SENTINEL not in lab.text


async def test_a_value_under_a_secret_s_name_is_redacted(lab):
    async with lab.client() as client:
        await client.get("/v1/keyed")

    assert SENTINEL not in lab.text
    (line,) = [entry for entry in lab.lines if entry["event"] == "keyed"]
    assert line["authorization"] == REDACTED
    assert line["password"] == REDACTED
    assert line["api_token"] == REDACTED
    assert line["S3_SECRET_KEY"] == REDACTED
    assert line["nested"] == {"refresh_token": REDACTED, "cookie": REDACTED, "kept": "visible"}
    assert line["listed"] == [{"client_secret": REDACTED}]
    # A name that only starts like one is not a secret's name.
    assert line["token_count"] == 3


@pytest.mark.parametrize("level", ["debug", "info"])
def test_another_library_is_held_to_warnings_whatever_the_level(level):
    """An HTTP client logs each URL, query string included, at info."""
    lab = Lab(level)

    stdlib_logging.getLogger("httpx").info("HTTP Request: GET /x?token=%s", SENTINEL)
    stdlib_logging.getLogger("botocore.auth").debug("signature %s", SENTINEL)
    stdlib_logging.getLogger("botocore.auth").warning("a warning")

    assert [line["event"] for line in lab.lines] == ["a warning"]


def test_uvicorn_s_lines_take_our_form_and_its_access_log_is_off():
    uvicorn_error = stdlib_logging.getLogger("uvicorn.error")
    uvicorn_access = stdlib_logging.getLogger("uvicorn.access")
    theirs = stdlib_logging.StreamHandler(io.StringIO())
    for library in (uvicorn_error, uvicorn_access):
        library.addHandler(theirs)
        library.propagate = False

    lab = Lab()
    uvicorn_error.info("Started server process")
    uvicorn_access.info('127.0.0.1 - "GET /v1/x?token=%s HTTP/1.1" 200', SENTINEL)
    stdlib_logging.getLogger("alembic.runtime.migration").info("Running upgrade")

    assert [line["event"] for line in lab.lines] == ["Started server process", "Running upgrade"]
    assert theirs.stream.getvalue() == ""


async def test_a_response_that_failed_after_it_started_is_not_answered_twice():
    lab = Lab()

    async def half(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError(SENTINEL)

    app = RequestLogMiddleware(half)
    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "GET", "path": "/v1/half", "headers": [], "query_string": b""}
    await app(scope, receive, send)

    assert [message["type"] for message in sent] == ["http.response.start"]
    assert [line["event"] for line in lab.lines] == ["unhandled exception", "request"]
    assert lab.request_line()["status"] == 200
    assert SENTINEL not in lab.text


async def test_what_is_not_http_passes_through_untouched():
    lab = Lab()
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    await RequestLogMiddleware(inner)({"type": "lifespan"}, None, None)

    assert seen == ["lifespan"]
    assert lab.text == ""
