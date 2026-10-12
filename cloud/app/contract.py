"""The contract every response and request is held to (C5.11;
docs/decisions.md 2026-10-12, points 1 and 5).

`ApiVersionMiddleware` puts `X-RestoreProof-API: 1` on every response the
app sends, the outermost middleware, so a route's answer, FastAPI's 404, 405
and 422, the log middleware's own 500, /healthz and the OpenAPI document all
carry it: the one fact a Worker pointed at a wrong host or a proxy's error
page cannot otherwise tell from a 202. The value is the contract's number,
the `1` of `/v1`, not the Cloud's version (that is `GET /v1/version`'s).

`BodyCapMiddleware` holds every request body but the upload's to
`MAX_BODY_BYTES`, on the header before the app is called and on the bytes as
the app pulls them (a server that frames a body by its chunks hands over more
than `Content-Length` said: the C5.7 review's finding 1). The first byte over
the cap ends the read in `BodyTooLarge`, an `HTTPException` FastAPI re-raises
as it is (anything else it would turn into its own 400 while reading a body
parameter) and starlette answers as 413. The header check reads no byte and
the counter counts only what the app pulls, so a request without a token is
still the one 401 with nothing of its body read (C5.8). The upload's path
(`large_body_paths`) is left to the route's own cap; the path compared is the
one the router matches, without the server's `root_path` (uvicorn puts
`--root-path` in front of `scope["path"]`), so the exemption holds behind a
prefix too (the C5.11 review's finding 2).

Guarded at 100% line and branch (tools/check_coverage.py).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException
from starlette._utils import get_route_path
from starlette.responses import JSONResponse

from app.results import BODY_TOO_LARGE

API_VERSION = 1
API_HEADER = "X-RestoreProof-API"
# A hundred times the largest honest body (a registration is about 4.5 KB by
# its model's lengths, a heartbeat about 300 bytes).
MAX_BODY_BYTES = 64 * 1024

_HEADER_NAME = API_HEADER.lower().encode("latin-1")
_HEADER = (_HEADER_NAME, str(API_VERSION).encode("ascii"))

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class ApiVersionMiddleware:
    """Pure ASGI: the header on every `http.response.start`, once."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_stamped(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = [pair for pair in message.get("headers", []) if pair[0].lower() != _HEADER_NAME]
                headers.append(_HEADER)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_stamped)


class BodyTooLarge(HTTPException):
    """The bytes passed the cap: FastAPI re-raises an HTTPException raised
    while it reads a body, and starlette answers it as the 413."""

    def __init__(self) -> None:
        super().__init__(status_code=413, detail=BODY_TOO_LARGE)


class BodyCapMiddleware:
    """Pure ASGI: 413 on a `Content-Length` over the cap before the app runs,
    and `BodyTooLarge` from `receive` at the first byte over it; the paths in
    `large_body_paths` are left to their own cap."""

    def __init__(self, app: Any, *, large_body_paths: frozenset[str] = frozenset(), cap: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.large_body_paths = large_body_paths
        self.cap = cap

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or get_route_path(scope) in self.large_body_paths:
            await self.app(scope, receive, send)
            return
        if _declared_over(scope, self.cap):
            await JSONResponse({"detail": BODY_TOO_LARGE}, status_code=413)(scope, receive, send)
            return
        taken = 0

        async def counted() -> dict[str, Any]:
            nonlocal taken
            message = await receive()
            if message["type"] == "http.request":
                taken += len(message.get("body", b""))
                if taken > self.cap:
                    raise BodyTooLarge()
            return message

        await self.app(scope, counted, send)


def _declared_over(scope: Scope, cap: int) -> bool:
    """`Content-Length` of ASCII digits over the cap; anything else is the
    server's to refuse or the bytes' to show. A number of more digits than the
    cap's is over it by its length and is never converted: `int()` refuses a
    text past the interpreter's digit limit (the C5.11 review's finding 6)."""
    for name, value in scope["headers"]:
        if name == b"content-length":
            text = value.decode("latin-1")
            if not (text.isascii() and text.isdigit()):
                return False
            digits = text.lstrip("0")
            return len(digits) > len(str(cap)) or int(digits or "0") > cap
    return False
