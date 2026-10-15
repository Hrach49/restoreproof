"""C5.11 (docs/decisions.md 2026-10-12, "C5.11"): the contract. Every
response carries `X-RestoreProof-API: 1` (point 1); `GET /v1/version` answers
the contract's number and the Cloud's version without a token or a statement
(point 2); every request body but the upload's is held to 64 KiB on the header
and on the bytes (point 5); and the Done-when by name, point 7: the run folder
the C++ Worker's service made from a job of the Cloud's shape
(shared/testdata/signing-v1/dispatched-run.json, written by
`rptests "[.write_shared_dispatched]"`) is posted byte for byte, under the
Worker's own part list, and lands as 202 `pass`. Nothing here re-signs.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import socket
import threading
import time
import uuid
from typing import Literal

import httpx
import pytest
import uvicorn
from fastapi import APIRouter, FastAPI, Request
from pydantic import ValidationError
from sqlalchemy import text
from starlette.responses import JSONResponse

import app as package
from app import contract, results
from app.contract import API_HEADER, API_VERSION, MAX_BODY_BYTES, ApiVersionMiddleware, BodyCapMiddleware
from app.main import API_PREFIX, LARGE_BODY_PATHS, ROUTERS, create_app
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.workers import WorkerRepo
from app.auth.tokens import new_token, token_hash
from app.db import get_session
from app.logging import RequestLogMiddleware
from app.routers.jobs import JOBS_FORMAT
from app.routers.version import VersionBody
from tests.conftest import make_settings, session_override
from tests.results_lab import NOW, Lab
from tests.test_jobs_schema import VALIDATOR as JOBS_VALIDATOR
from tests.test_heartbeat import UNTOUCHED as HEARTBEAT_UNTOUCHED
from tests.test_heartbeat import Lab as HeartbeatLab
from tests.test_results import rows_only
from tests.test_verify_bundle import KEYS, SCHEMAS_DIR, SIGNING_DIR, pem_file, public_key, run_main, vb
from tests.test_verify_bundle_timestamp import ca_file, tsa_ca

HEADER = API_HEADER.lower()
VALUE = str(API_VERSION)
TOO_LARGE = {"detail": results.BODY_TOO_LARGE}
REGISTER = f"{API_PREFIX}/workers/register"
VERSION = f"{API_PREFIX}/version"
SENTINEL = "ZQ-SENTINEL-BODY-VALUE"


def make_app(log_stream=None):
    return create_app(make_settings(), log_stream=log_stream or io.StringIO())


async def send(application, method: str, path: str, *, root_path: str = "", **request) -> httpx.Response:
    transport = httpx.ASGITransport(app=application, root_path=root_path)
    async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
        return await client.request(method, path, **request)


def header_values(response: httpx.Response) -> list[str]:
    return response.headers.get_list(HEADER)


# --- Point 1: the header on every response ----------------------------------------------------


@pytest.mark.parametrize(
    "method, path, sent, status",
    [
        ("GET", f"{API_PREFIX}/nothing-here", {}, 404),
        ("POST", VERSION, {}, 405),
        ("POST", REGISTER, {"json": {}}, 422),
        ("POST", REGISTER, {"headers": {"Content-Length": str(MAX_BODY_BYTES + 1), "Content-Type": "application/json"}, "content": b""}, 413),
        ("GET", f"{API_PREFIX}/openapi.json", {}, 200),
        ("GET", f"{API_PREFIX}/docs", {}, 200),
        ("GET", VERSION, {}, 200),
    ],
    ids=["404", "405", "422", "413", "openapi", "docs", "version"],
)
async def test_every_answer_carries_the_api_header_once(method, path, sent, status):
    response = await send(make_app(), method, path, **sent)

    assert response.status_code == status, response.text
    assert header_values(response) == [VALUE]


def app_over(session):
    """The app over the test's session, so `current_worker` has a database
    (its one lookup runs for every refusal) and finds no Worker."""
    application = make_app()
    application.dependency_overrides[get_session] = session_override(session)
    return application


async def test_the_one_401_carries_the_header(session):
    response = await send(app_over(session), "GET", f"{API_PREFIX}/jobs")

    assert (response.status_code, response.json()) == (401, {"detail": "not authenticated"})
    assert header_values(response) == [VALUE]


async def test_healthz_carries_the_header_on_a_503():
    """Both checks on closed ports: the probe outside /v1 is stamped too."""
    response = await send(make_app(), "GET", "/healthz")

    assert response.status_code == 503
    assert header_values(response) == [VALUE]


async def test_the_middleware_s_own_500_carries_the_header():
    router = APIRouter()

    @router.get("/version/boom")
    async def boom():
        raise RuntimeError("planted")

    version_router = dict(ROUTERS)["version"]
    before = list(version_router.routes)
    version_router.include_router(router)
    try:
        response = await send(make_app(), "GET", f"{API_PREFIX}/version/boom")
    finally:
        version_router.routes[:] = before

    assert response.status_code == 500
    assert response.json()["error"] == "internal"
    assert header_values(response) == [VALUE]


async def test_a_route_that_set_the_header_itself_is_stamped_once():
    async def own(_scope, _receive, send_):
        await send_({"type": "http.response.start", "status": 200, "headers": [(HEADER.encode(), b"7")]})
        await send_({"type": "http.response.body", "body": b""})

    response = await send(ApiVersionMiddleware(own), "GET", "/")

    assert header_values(response) == [VALUE]


async def test_a_non_http_scope_passes_through_untouched():
    seen = []

    async def inner(scope, _receive, _send):
        seen.append(scope["type"])

    await ApiVersionMiddleware(inner)({"type": "lifespan"}, None, None)

    assert seen == ["lifespan"]


def test_the_header_is_the_contract_s_number_and_the_path_s():
    assert API_HEADER == "X-RestoreProof-API"
    assert API_VERSION == 1
    assert API_PREFIX == f"/v{API_VERSION}"


def test_the_api_version_middleware_is_outermost_and_the_cap_inside_the_log():
    stack = [middleware.cls for middleware in make_app().user_middleware]

    assert stack[0] is ApiVersionMiddleware
    assert stack.index(BodyCapMiddleware) > stack.index(RequestLogMiddleware)


# --- Point 2: GET /v1/version ---------------------------------------------------------------


async def test_version_answers_the_two_keys_without_a_token_or_a_database():
    """The app's database is a closed port: a route that ran a statement
    would be a 500, so the 200 is also the proof of no statement."""
    application = make_app()

    plain = await send(application, "GET", VERSION)
    with_token = await send(application, "GET", VERSION, headers={"Authorization": "Bearer made-up"})
    basic = await send(application, "GET", VERSION, headers={"Authorization": "Basic x"})

    for response in (plain, with_token, basic):
        assert response.status_code == 200, response.text
        assert response.json() == {"api": API_VERSION, "version": package.__version__}
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["content-type"] == "application/json"


async def test_version_is_the_document_s_own_version():
    application = make_app()

    version = await send(application, "GET", VERSION)
    document = await send(application, "GET", f"{API_PREFIX}/openapi.json")

    assert version.json()["version"] == document.json()["info"]["version"] == package.__version__


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
async def test_version_takes_get_alone(method):
    response = await send(make_app(), method, VERSION)

    assert response.status_code == 405


def test_the_version_router_is_the_seventh():
    assert [name for name, _ in ROUTERS] == ["workers", "jobs", "results", "heartbeat", "admin", "ui", "version"]


# --- Point 5: the cap ------------------------------------------------------------------------


class Body:
    """A streamed body that counts what the app pulled."""

    def __init__(self, data: bytes, size: int = 1024):
        self.data = data
        self.size = size
        self.pulled = 0

    async def chunks(self):
        for at in range(0, len(self.data), self.size):
            self.pulled += len(self.data[at : at + self.size])
            yield self.data[at : at + self.size]


async def test_a_content_length_over_the_cap_is_413_with_nothing_pulled():
    body = Body(b"{" + b"x" * MAX_BODY_BYTES)
    stream = io.StringIO()

    response = await send(
        make_app(stream),
        "POST",
        REGISTER,
        headers={"Content-Length": str(MAX_BODY_BYTES + 1), "Content-Type": "application/json"},
        content=body.chunks(),
    )

    assert (response.status_code, response.json()) == (413, TOO_LARGE)
    assert response.headers["content-type"] == "application/json"
    assert header_values(response) == [VALUE]
    assert response.headers["x-request-id"]
    assert body.pulled == 0
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    (request_line,) = [line for line in lines if line["event"] == "request"]
    assert (request_line["status"], request_line["path"]) == (413, REGISTER)


async def test_a_body_of_exactly_the_cap_is_read_and_one_byte_more_is_413():
    at_cap = b'{"install_token": "' + b"x" * (MAX_BODY_BYTES - 21) + b'"}'
    assert len(at_cap) == MAX_BODY_BYTES
    over = at_cap + b" "
    application = make_app()

    taken = await send(application, "POST", REGISTER, content=at_cap, headers={"Content-Type": "application/json"})
    refused = await send(application, "POST", REGISTER, content=over, headers={"Content-Type": "application/json"})

    assert taken.status_code == 422, taken.text  # the model's refusal: the body was read whole
    assert (refused.status_code, refused.json()) == (413, TOO_LARGE)


async def test_a_streamed_body_without_a_length_is_413_at_the_cap_and_read_no_further():
    """No Content-Length (httpx sends it chunked): the bytes themselves are
    held, and the read ends at the first chunk over the cap."""
    body = Body(b'{"a":"' + SENTINEL.encode() + b"x" * (4 * MAX_BODY_BYTES) + b'"}', size=MAX_BODY_BYTES // 4)
    stream = io.StringIO()

    response = await send(make_app(stream), "POST", REGISTER, headers={"Content-Type": "application/json"}, content=body.chunks())

    assert (response.status_code, response.json()) == (413, TOO_LARGE)
    assert MAX_BODY_BYTES < body.pulled <= MAX_BODY_BYTES + MAX_BODY_BYTES // 4
    assert SENTINEL not in stream.getvalue()
    assert SENTINEL not in response.text


async def test_the_heartbeat_s_body_is_capped_too_and_the_token_still_comes_first(session):
    body = Body(b"{" + b"x" * (2 * MAX_BODY_BYTES))

    without_token = await send(
        app_over(session), "POST", f"{API_PREFIX}/heartbeat", headers={"Content-Type": "application/json"}, content=body.chunks()
    )
    declared = await send(
        app_over(session), "POST", f"{API_PREFIX}/heartbeat",
        headers={"Content-Type": "application/json", "Content-Length": str(MAX_BODY_BYTES + 1)}, content=body.chunks(),
    )

    # No token: the one 401 with nothing pulled (C5.8); the counter counts what
    # the app pulls, and the app pulled nothing. A declared over-cap length is
    # the header's 413 before anything, token or not: it tells nothing.
    assert (without_token.status_code, without_token.json()) == (401, {"detail": "not authenticated"})
    assert (declared.status_code, declared.json()) == (413, TOO_LARGE)
    assert body.pulled == 0


async def test_an_authenticated_heartbeat_whose_streamed_body_passes_the_cap_is_413_and_nothing_is_written(session):
    """The one read of a body inside a dependency (`heartbeat_body`'s
    `request.body()`, after the real `current_worker`): the counter's
    `BodyTooLarge` leaves it as the 413, never the route's 422 or a 500 (the
    C5.11 review's finding 8)."""
    lab = HeartbeatLab(session)
    await lab.fill()
    body = Body(b'{"version":"' + SENTINEL.encode() + b"x" * (4 * MAX_BODY_BYTES) + b'"}', size=MAX_BODY_BYTES // 4)

    response = await send(
        lab.app, "POST", f"{API_PREFIX}/heartbeat",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {lab.token}"}, content=body.chunks(),
    )

    assert (response.status_code, response.json()) == (413, TOO_LARGE)
    assert header_values(response) == [VALUE]
    assert MAX_BODY_BYTES < body.pulled <= MAX_BODY_BYTES + MAX_BODY_BYTES // 4
    assert await lab.row() == HEARTBEAT_UNTOUCHED
    assert SENTINEL not in lab.log


async def echo_length(request: Request):
    return JSONResponse({"length": len(await request.body())})


def capped_echo(**options) -> BodyCapMiddleware:
    """A FastAPI app of one echo route behind the cap (FastAPI's handler
    answers an HTTPException as `{"detail": ...}`, as the Cloud's does)."""
    inner = FastAPI()
    inner.add_api_route("/big", echo_length, methods=["POST"])
    inner.add_api_route("/small", echo_length, methods=["POST"])
    return BodyCapMiddleware(inner, **options)


async def call(application, headers: list[tuple[bytes, bytes]], body: bytes, path: str = "/small") -> tuple[int, bytes]:
    """One raw ASGI request, for a header httpx would never send."""
    scope = {"type": "http", "method": "POST", "path": path, "raw_path": path.encode(), "query_string": b"", "headers": headers, "scheme": "http", "server": ("test", 80), "client": ("test", 1)}
    messages = iter([{"type": "http.request", "body": body, "more_body": False}])
    sent = []

    async def receive():
        return next(messages)

    async def send_(message):
        sent.append(message)

    await application(scope, receive, send_)
    return sent[0]["status"], b"".join(m.get("body", b"") for m in sent[1:])


@pytest.mark.parametrize("length", [b"\xb2", b"abc", b"-1", b"", b"10 "], ids=["superscript two", "a word", "negative", "empty", "a space"])
async def test_a_content_length_that_is_not_ascii_digits_is_left_to_the_server(length):
    """Python's `isdigit` takes `²`; the cap takes ASCII digits alone and
    leaves anything else to the server, which refuses it before the app."""
    status, body = await call(capped_echo(cap=100), [(b"content-length", length)], b"x" * 10)

    assert (status, json.loads(body)) == (200, {"length": 10})


@pytest.mark.parametrize(
    "length, status",
    [
        (b"100", 200),
        (b"101", 413),
        (b"0" * 8, 200),
        (b"0" * 5000 + b"100", 200),
        (b"0" * 5000 + b"101", 413),
        (b"9" * 5000, 413),
    ],
    ids=["the cap", "one over", "zeros", "5000 zeros before the cap", "5000 zeros before one over", "5000 digits"],
)
async def test_a_content_length_of_any_number_of_digits_is_held_without_converting_it(length, status):
    """`int()` refuses a text past the interpreter's 4300 digits: a length of
    more digits than the cap's is over it as it stands, leading zeros aside
    (the C5.11 review's finding 6: a 500 before)."""
    answered, body = await call(capped_echo(cap=100), [(b"content-length", length)], b"x" * 10)

    assert answered == status
    assert json.loads(body) == ({"length": 10} if status == 200 else TOO_LARGE)


async def test_the_upload_s_path_is_left_to_its_own_cap(session):
    """A 90 MiB Content-Length to the upload is the route's business (401
    first without a token, as C5.7 holds); every other path is 413 before
    the app."""
    application = app_over(session)
    body = Body(b"x" * 10)

    upload = await send(
        application, "POST", f"{API_PREFIX}/results",
        headers={"Content-Length": str(90 * 1024 * 1024), "Content-Type": "multipart/form-data; boundary=x"}, content=body.chunks(),
    )
    register = await send(
        application, "POST", REGISTER,
        headers={"Content-Length": str(90 * 1024 * 1024), "Content-Type": "multipart/form-data; boundary=x"}, content=body.chunks(),
    )

    assert (upload.status_code, upload.json()) == (401, {"detail": "not authenticated"})
    assert (register.status_code, register.json()) == (413, TOO_LARGE)
    assert body.pulled == 0


async def test_the_upload_s_exemption_holds_behind_a_root_path(session):
    """`uvicorn --root-path /api` hands the app `/api/v1/results` as the path
    and `/api` as the root: the exemption is on the path the router matches
    (the C5.11 review's finding 2: the upload was 413 at 64 KiB before)."""
    application = app_over(session)
    body = Body(b"x" * 10)
    large = {"Content-Length": str(90 * 1024 * 1024), "Content-Type": "multipart/form-data; boundary=x"}

    version = await send(application, "GET", f"/api{VERSION}", root_path="/api")
    upload = await send(application, "POST", f"/api{API_PREFIX}/results", root_path="/api", headers=large, content=body.chunks())
    register = await send(application, "POST", f"/api{REGISTER}", root_path="/api", headers=large, content=body.chunks())

    assert version.status_code == 200, version.text
    assert (upload.status_code, upload.json()) == (401, {"detail": "not authenticated"})
    assert (register.status_code, register.json()) == (413, TOO_LARGE)
    assert body.pulled == 0


async def test_the_cap_middleware_alone_compares_the_path_without_the_root():
    capped = capped_echo(large_body_paths=frozenset({"/big"}), cap=100)
    data = b"x" * 200

    under_root = await send(capped, "POST", "/api/big", root_path="/api", content=data)
    # A path that only ends like the exempt one is not it.
    other = await send(capped, "POST", "/api/big", content=data)

    assert (under_root.status_code, under_root.json()) == (200, {"length": 200})
    assert other.status_code == 413


def test_the_exempt_paths_are_the_document_s_multipart_operations():
    application = make_app()
    (cap,) = [m for m in application.user_middleware if m.cls is BodyCapMiddleware]
    document = application.openapi()
    multipart = {
        path
        for path, operations in document["paths"].items()
        for operation in operations.values()
        if "multipart/form-data" in operation.get("requestBody", {}).get("content", {})
    }

    assert cap.kwargs["large_body_paths"] == frozenset(multipart) == frozenset({f"{API_PREFIX}/results"})
    assert MAX_BODY_BYTES == 64 * 1024


def test_the_document_s_cap_and_number_are_the_constants():
    """The 413's description and the version body's `const` are made from
    `MAX_BODY_BYTES` and `API_VERSION`, never typed a second time (the C5.11
    review's finding 14)."""
    document = make_app().openapi()
    described = {
        operation["responses"]["413"]["description"]
        for path, operations in document["paths"].items()
        for operation in operations.values()
        if "413" in operation["responses"] and path not in LARGE_BODY_PATHS
    }

    assert described == {
        f"The body is over the {MAX_BODY_BYTES // 1024} KiB cap every request but the upload has (`body: too large`)."
    }
    assert document["components"]["schemas"]["VersionBody"]["properties"]["api"]["const"] == API_VERSION
    assert VersionBody.model_fields["api"].annotation == Literal[API_VERSION]
    with pytest.raises(ValidationError):
        VersionBody(api=API_VERSION + 1, version="x")


async def test_the_cap_middleware_alone_passes_an_exempt_path_and_a_non_http_scope():
    capped = capped_echo(large_body_paths=frozenset({"/big"}), cap=100)
    data = b"x" * 200

    big = await send(capped, "POST", "/big", content=data)
    small_by_header = await send(capped, "POST", "/small", content=data)
    small_by_bytes = await send(capped, "POST", "/small", content=Body(data, size=50).chunks())
    seen = []

    async def record(scope, _receive, _send):
        seen.append(scope["type"])

    await BodyCapMiddleware(record)({"type": "lifespan"}, None, None)

    assert (big.status_code, big.json()) == (200, {"length": 200})
    assert (small_by_header.status_code, small_by_header.json()) == (413, TOO_LARGE)
    assert (small_by_bytes.status_code, small_by_bytes.json()) == (413, TOO_LARGE)
    assert seen == ["lifespan"]


async def test_a_message_that_is_no_body_passes_the_counter_uncounted():
    """`http.disconnect` has no body: the wrapper hands it on and counts nothing."""
    seen = []

    async def reads_once(_scope, receive, send_):
        seen.append((await receive())["type"])
        await send_({"type": "http.response.start", "status": 204, "headers": []})
        await send_({"type": "http.response.body", "body": b""})

    capped = BodyCapMiddleware(reads_once, cap=1)
    scope = {"type": "http", "method": "POST", "path": "/x", "headers": [], "query_string": b""}
    messages = iter([{"type": "http.disconnect"}])
    sent = []

    async def receive():
        return next(messages)

    async def send_(message):
        sent.append(message)

    await capped(scope, receive, send_)

    assert seen == ["http.disconnect"]
    assert sent[0]["status"] == 204


async def test_a_body_in_several_messages_is_counted_whole():
    """The ASGI body may come as many `http.request` messages: the sum is held."""
    capped = capped_echo(cap=100)

    within = await send(capped, "POST", "/small", content=Body(b"x" * 100, size=30).chunks())
    over = await send(capped, "POST", "/small", content=Body(b"x" * 101, size=30).chunks())

    assert (within.status_code, within.json()) == (200, {"length": 100})
    assert (over.status_code, over.json()) == (413, TOO_LARGE)


# --- Point 5 through a real server: the framing h11 does -------------------------------------


@pytest.fixture
def port():
    application = make_app()
    server = uvicorn.Server(uvicorn.Config(application, host="127.0.0.1", port=0, log_config=None, lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "uvicorn didn't start on loopback"
    try:
        yield server.servers[0].sockets[0].getsockname()[1]
    finally:
        server.should_exit = True
        thread.join(10)


def exchange(port: int, head: list[str], body: bytes) -> tuple[int, dict[str, str], bytes]:
    lines = [f"POST {REGISTER} HTTP/1.1", "Host: 127.0.0.1", "Content-Type: application/json", "Connection: close", *head]
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        try:
            connection.sendall("\r\n".join(lines).encode("ascii") + b"\r\n\r\n" + body)
        except OSError:
            pass
        answer = b""
        while True:
            try:
                chunk = connection.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            answer += chunk
    head_text, _, rest = answer.partition(b"\r\n\r\n")
    status_line, *header_lines = head_text.decode("latin-1").split("\r\n")
    headers = {name.lower(): value for name, _, value in (line.partition(": ") for line in header_lines)}
    return int(status_line.split()[1]), headers, rest


def chunked(data: bytes, size: int = 1024) -> bytes:
    pieces = [data[at : at + size] for at in range(0, len(data), size)]
    return b"".join(b"%x\r\n%s\r\n" % (len(piece), piece) for piece in pieces) + b"0\r\n\r\n"


def test_a_chunked_body_over_the_cap_beside_a_small_content_length_is_413_through_uvicorn(port):
    """The body is only just over the cap: the server answers at the first
    byte over and closes, and whatever it has not read by then resets the
    connection, which can cut the answer's body off before this side reads it
    (the C5.11 review's finding 1: 192 KiB left unread failed one run in seven)."""
    body = b"{" + b"x" * (MAX_BODY_BYTES + 2048)

    status, headers, answer = exchange(port, ["Content-Length: 10", "Transfer-Encoding: chunked"], chunked(body))

    assert status == 413
    assert json.loads(answer) == TOO_LARGE
    assert headers[HEADER] == VALUE


def test_a_plain_body_within_the_cap_reaches_the_route_through_uvicorn(port):
    body = b"{}"

    status, headers, answer = exchange(port, [f"Content-Length: {len(body)}"], body)

    assert status == 422  # the model's: the cap let it through
    assert headers[HEADER] == VALUE


# --- Point 7: the Done-when ------------------------------------------------------------------

VECTOR_FILE = SIGNING_DIR / "dispatched-run.json"


class _Vector(dict):
    """The vector, read at first use so the rest of this file runs before the
    Worker has written it (and the Done-when then fails, never skips)."""

    def _load(self):
        if not self:
            self.update(json.loads(VECTOR_FILE.read_bytes().decode("utf-8")))

    def __getitem__(self, key):
        self._load()
        return super().__getitem__(key)

    def __contains__(self, key):
        self._load()
        return super().__contains__(key)

    def keys(self):
        self._load()
        return super().keys()


class _Result(dict):
    def __getitem__(self, key):
        if not self:
            self.update(json.loads(VECTOR["files"]["result.json"]))
        return super().__getitem__(key)


VECTOR = _Vector()
RESULT = _Result()


def vector_bytes(name: str) -> bytes:
    value = VECTOR["files"][name]
    return value.encode("utf-8") if isinstance(value, str) else base64.b64decode(value["base64"], validate=True)


def worker_parts() -> list[tuple[str, tuple[str, bytes, str]]]:
    """httpx's `files` built from the Worker's own part list: each part's
    name, file name and content type as `rp::checked_parts` built them."""
    return [(p["name"], (p["filename"], vector_bytes(p["filename"]), p["content_type"])) for p in VECTOR["upload"]]


def write_vector(folder):
    folder.mkdir()
    for name in VECTOR["files"]:
        (folder / name).write_bytes(vector_bytes(name))
    return folder


def test_the_vector_is_a_run_of_a_job_of_the_cloud_s_shape():
    run_id, client_id = VECTOR["run_id"], VECTOR["client_id"]
    assert str(uuid.UUID(run_id)) == run_id and str(uuid.UUID(client_id)) == client_id
    assert run_id != client_id
    assert RESULT["run_id"] == run_id == VECTOR["job"]["run_id"]
    assert RESULT["client"]["client_id"] == client_id == VECTOR["job"]["client_id"]
    assert RESULT["client"]["scope"] == "same_tenant"
    assert RESULT["status"]["status"] == "pass"
    assert str(uuid.UUID(RESULT["client"]["tenant_id"])) == VECTOR["tenant_id"]
    # The job is a document the Worker's reader takes; that it is the one
    # `GET /v1/jobs` writes is the poll's test, below.
    JOBS_VALIDATOR.validate({"format": JOBS_FORMAT, "jobs": [VECTOR["job"]]})
    assert RESULT["worker_version"] == VECTOR["worker_version"]
    # The Worker's own part list: the three fixed parts, then the listed attachments.
    names = [part["name"] for part in VECTOR["upload"]]
    attachments = [entry["name"] for entry in RESULT["attachments"]]
    expected = ["result", "signature"] + (["timestamp"] if "timestamp.tst" in VECTOR["files"] else []) + attachments
    assert names == expected
    assert all(part["filename"] in VECTOR["files"] for part in VECTOR["upload"])
    assert [p["content_type"] for p in VECTOR["upload"][:2]] == ["application/json", "application/json"]
    assert all(p["content_type"] == "application/octet-stream" for p in VECTOR["upload"][2:])
    assert sorted(VECTOR["files"]) == sorted(p["filename"] for p in VECTOR["upload"])


def test_the_vector_s_hash_and_key_are_the_files_own():
    assert hashlib.sha256(vector_bytes("result.json")).hexdigest() == VECTOR["bundle_sha256"]
    assert KEYS[VECTOR["key"]]["key_id"] == VECTOR["key_id"]
    assert vb.canonical_fault(vector_bytes("result.json")) is None


def test_the_script_verifies_the_vector_as_it_is(tmp_path, capsys):
    folder = write_vector(tmp_path / "run")
    argv = [folder, "--public-key", pem_file(tmp_path, VECTOR["key"]), "--schemas", SCHEMAS_DIR]
    if VECTOR["tsa_root"] is not None:
        argv += ["--tsa-ca", ca_file(tmp_path, VECTOR["tsa_root"])]

    code, out, err = run_main(capsys, *argv)

    stamp = VECTOR["tsa_time"] if VECTOR["tsa_root"] is not None else "none"
    assert (code, out) == (0, f"verified {VECTOR['bundle_sha256']} key {VECTOR['key_id']} timestamp {stamp}\n")
    assert err == ("" if VECTOR["tsa_root"] is not None else "note: not timestamped\n")
    verdict = vb.verify_folder(folder, public_key(VECTOR["key"]), vb.load_schemas(SCHEMAS_DIR))
    assert (verdict.word, verdict.bundle_sha256, verdict.key_id) == ("verified", VECTOR["bundle_sha256"], VECTOR["key_id"])


async def fill_contract(lab: Lab) -> None:
    """The world the vector names, queued: the connector holds the vector's
    job's profile and the plan its three sizes, so the poll of these rows
    writes the job the Worker ran (the C5.11 review's finding 3). The client
    row and the run row carry the vector's ids, given by UPDATE before any row
    points at them (the repos take no id for a test's sake)."""
    s = lab.session
    job = VECTOR["job"]
    tenant = uuid.UUID(VECTOR["tenant_id"])
    lab.msp_id = (await MspRepo(s).create(name="contract")).id
    made = await ClientRepo(s).create(lab.msp_id, name="contoso", tenant_id=tenant)
    lab.client_id = uuid.UUID(VECTOR["client_id"])
    await s.execute(text("UPDATE client SET id = :new WHERE id = :old"), {"new": lab.client_id, "old": made.id})
    lab.token = new_token()
    lab.worker_id = (await WorkerRepo(s).create(
        lab.msp_id, "w1", public_key_pem=KEYS[VECTOR["key"]]["public_key_pem"],
        key_id=KEYS[VECTOR["key"]]["key_id"], api_token_hash=token_hash(lab.token),
    )).id
    lab.other_token = new_token()
    lab.other_worker_id = (await WorkerRepo(s).create(
        lab.msp_id, "w2", public_key_pem=KEYS["rfc8032-test-2"]["public_key_pem"],
        key_id=KEYS["rfc8032-test-2"]["key_id"], api_token_hash=token_hash(lab.other_token),
    )).id
    lab.connector_id = (await ConnectorRepo(s).create(lab.msp_id, lab.client_id, lab.worker_id, job["client"])).id
    lab.plan_id = (await PlanRepo(s).create(
        lab.msp_id, lab.client_id, lab.connector_id, sample_mail=job["sample_mail"], sample_sp=job["sample_sp"],
        sample_od=job["sample_od"], cadence_cron="0 2 * * *", now=NOW,
    )).id
    run = await RunRepo(s).create(
        lab.msp_id, plan_id=lab.plan_id, client_id=lab.client_id, connector_id=lab.connector_id, worker_id=lab.worker_id
    )
    lab.run_id = uuid.UUID(VECTOR["run_id"])
    await s.execute(text("UPDATE test_run SET id = :new WHERE id = :old"), {"new": lab.run_id, "old": run.id})


async def poll(lab: Lab) -> httpx.Response:
    return await send(lab.app, "GET", f"{API_PREFIX}/jobs", headers={"Authorization": f"Bearer {lab.token}"})


@pytest.fixture
async def lab(session):
    """The run queued, then dispatched by the Worker's own poll: `polled` is
    what `GET /v1/jobs` answered."""
    root = VECTOR["tsa_root"]
    lab = Lab(session, tsa_ca=tsa_ca(root)) if root is not None else Lab(session)
    await fill_contract(lab)
    lab.polled = await poll(lab)
    return lab


async def test_the_cloud_s_poll_writes_the_job_the_worker_ran(lab):
    """The vector's `job` is the file the Worker's service read; the rows that
    hold the vector's run answer the poll with that job, key for key, so a
    change to what `job_of` writes fails here until the Worker has run the
    new job and written the vector again."""
    assert lab.polled.status_code == 200, lab.polled.text
    assert lab.polled.json() == {"format": JOBS_FORMAT, "jobs": [VECTOR["job"]]}
    assert header_values(lab.polled) == [VALUE]
    row = await lab.run_row(lab.run_id)
    assert (row.state, row.attempt, row.dispatched_at is not None) == ("dispatched", 1, True)
    assert (await poll(lab)).json() == {"format": JOBS_FORMAT, "jobs": []}


async def test_the_contract_test_passes_against_a_fixture_generated_by_the_cpp_worker(lab):
    parts = {p["name"]: vector_bytes(p["filename"]) for p in VECTOR["upload"]}
    key = lab.expect_puts(lab.run_id, parts)
    before = await lab.counts()

    response = await lab.post(None, lab.token, files=worker_parts())

    assert response.status_code == 202, response.text
    assert response.json() == {"run_id": VECTOR["run_id"], "state": "pass"}
    assert header_values(response) == [VALUE]
    row = await lab.run_row(lab.run_id)
    assert (row.state, row.error_code, row.signature_ok, row.cleanup_ok) == ("pass", None, True, True)
    assert row.bundle_sha256 == VECTOR["bundle_sha256"] == hashlib.sha256(parts["result"]).hexdigest()
    assert row.bundle_key == key == f"msp/{lab.msp_id}/runs/{VECTOR['run_id']}/"
    if VECTOR["tsa_root"] is not None:
        assert row.tsa_ok is True
        assert row.tsa_time.strftime("%Y-%m-%dT%H:%M:%SZ") == VECTOR["tsa_time"]
    else:
        assert (row.tsa_ok, row.tsa_time) == (None, None)
    items = await lab.items(lab.run_id)
    expected = RESULT["expected"]["items"]
    assert [(i.position, i.type) for i in items] == [(e["index"], e["kind"]) for e in expected]
    assert all((i.found, i.match) == (True, True) for i in items)
    # C6.8 step 1: a run without canaries (W6.2), its files checked against
    # the backup's own copy (W6.3), stored with the kind and the hash.
    assert [(i.expected_kind, i.expected_sha256) for i in items] == [(e["expected_kind"], e.get("sha256")) for e in expected]
    assert {i.expected_kind for i in items} == {"backup_content"} and "manifest_sha256" not in RESULT["sample"]
    assert await lab.wrote(before) == [("result.received", f"run:{VECTOR['run_id']}")]
    assert rows_only(await lab.counts()) == {
        **rows_only(before), "test_item": before["test_item"] + len(expected), "audit_log": before["audit_log"] + 1
    }
    lab.stubber.assert_no_pending_responses()

    # The same request again: 202 with the stored state, nothing written, no put.
    before = await lab.counts()
    again = await lab.post(None, lab.token, files=worker_parts())
    assert (again.status_code, again.json()) == (202, {"run_id": VECTOR["run_id"], "state": "pass"})
    assert await lab.counts() == before
    lab.stubber.assert_no_pending_responses()


async def test_the_vector_under_the_other_worker_s_token_is_wrong_key(lab):
    """The key is the token's Worker's, never the body's."""
    before = await lab.counts()

    response = await lab.post(None, lab.other_token, files=worker_parts())

    assert (response.status_code, response.json()) == (400, {"detail": "wrong_key"})
    assert await lab.wrote(before) == [("result.rejected", f"worker:{lab.other_worker_id} wrong_key")]
    lab.stubber.assert_no_pending_responses()


async def test_the_vector_s_run_must_be_the_cloud_s(lab):
    """The vector names a run the Cloud never dispatched: 404, as every other
    shared vector is (tests/test_results_vectors.py)."""
    await lab.session.execute(text("DELETE FROM test_run WHERE id = :id"), {"id": lab.run_id})
    before = await lab.counts()

    response = await lab.post(None, lab.token, files=worker_parts())

    assert (response.status_code, response.json()) == (404, {"detail": results.NO_SUCH_RUN})
    assert await lab.wrote(before) == [("result.rejected", f"worker:{lab.worker_id} {results.NO_SUCH_RUN}")]
