"""C5.7's request limits through a real HTTP server (the C5.7 code review,
finding 1; docs/decisions.md 2026-10-11): uvicorn and h11 on loopback in front
of the route's own `_parts`, since `httpx.ASGITransport` neither frames a body
nor enforces a length, and the fault was in what the server hands over.

h11 frames a request that has both `Content-Length` and `Transfer-Encoding:
chunked` by its chunks and leaves the length header in the scope: a cap held
on the header alone lets a body of any size through.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from app import results
from app.routers.results import _parts

CAP = 4096
HEAD = b'--x\r\nContent-Disposition: form-data; name="items.csv"; filename="items.csv"\r\n\r\n'
TAIL = b"\r\n--x--\r\n"


async def parts_of(request):
    parts = await _parts(request)
    if isinstance(parts, results.Refused):
        return JSONResponse({"word": parts.word}, status_code=parts.status)
    return JSONResponse({name: len(data) for name, data in parts.items()})


@pytest.fixture
def port(monkeypatch):
    monkeypatch.setattr(results, "MAX_UPLOAD_BYTES", CAP)
    application = Starlette(routes=[Route("/", parts_of, methods=["POST"])])
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


def exchange(port: int, head: list[str], body: bytes) -> tuple[int, bytes]:
    """One request written whole to the socket; the answer's status and body."""
    lines = ["POST / HTTP/1.1", "Host: 127.0.0.1", "Content-Type: multipart/form-data; boundary=x", "Connection: close", *head]
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        try:
            connection.sendall("\r\n".join(lines).encode("ascii") + b"\r\n\r\n" + body)
        except OSError:
            pass  # the server answered and closed before the body was all sent
        answer = b""
        while True:
            try:
                chunk = connection.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            answer += chunk
    status_line, _, rest = answer.partition(b"\r\n")
    return int(status_line.split()[1]), rest.partition(b"\r\n\r\n")[2]


def chunked(data: bytes, size: int = 1024) -> bytes:
    pieces = [data[at : at + size] for at in range(0, len(data), size)]
    return b"".join(b"%x\r\n%s\r\n" % (len(piece), piece) for piece in pieces) + b"0\r\n\r\n"


def test_a_chunked_body_over_the_cap_beside_a_small_content_length_is_413(port):
    body = HEAD + b"z" * (16 * CAP) + TAIL

    status, answer = exchange(port, ["Content-Length: 10", "Transfer-Encoding: chunked"], chunked(body))

    assert (status, answer) == (413, b'{"word":"body: too large"}')


def test_a_chunked_body_within_the_cap_beside_a_content_length_is_read(port):
    body = HEAD + b"z" * 100 + TAIL

    status, answer = exchange(port, ["Content-Length: 10", "Transfer-Encoding: chunked"], chunked(body))

    assert (status, answer) == (200, b'{"items.csv":100}')


def test_a_chunked_body_alone_is_411_and_a_body_of_its_length_is_read(port):
    body = HEAD + b"z" * 100 + TAIL

    without = exchange(port, ["Transfer-Encoding: chunked"], chunked(body))
    plain = exchange(port, [f"Content-Length: {len(body)}"], body)

    assert without == (411, b'{"word":"body: no Content-Length"}')
    assert plain == (200, b'{"items.csv":100}')
