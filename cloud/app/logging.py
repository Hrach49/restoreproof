"""Structured JSON logging with a request ID per request (C5.1).

One JSON object per line. The rule: no line holds a token, a password or a
request body. By construction: the request line has the path and never the
query string, no header and no body; an exception is logged as its type and its
stack's frames, never its message (a validation error's message quotes its
input). And as a second line, a value under a key named like a secret is
replaced.
"""

from __future__ import annotations

import logging
import re
import sys
import time
import traceback
import uuid
from pathlib import PurePath
from typing import Any, TextIO

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
from structlog.typing import EventDict

REDACTED = "[REDACTED]"

REQUEST_ID_HEADER = b"x-request-id"
# A caller's ID is logged on every line of the request and echoed, so it is
# held to a short, plain form; anything else is replaced by one made here.
_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")

_SECRET_ANYWHERE = ("secret", "password")
_SECRET_ENDINGS = ("token", "authorization", "cookie", "api_key", "access_key", "private_key")

_OWN_LOGGERS = ("app", "uvicorn", "alembic")

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def _is_secret_name(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(word in lowered for word in _SECRET_ANYWHERE) or lowered.endswith(_SECRET_ENDINGS)


def _redacted(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: REDACTED if isinstance(key, str) and _is_secret_name(key) else _redacted(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redacted(item) for item in value]
    return value


def redact_secret_names(_logger: Any, _method: str, event_dict: EventDict) -> EventDict:
    return _redacted(event_dict)


def exception_summary(_logger: Any, _method: str, event_dict: EventDict) -> EventDict:
    """Replace `exc_info` by the exception's type and frames, without its message."""
    exc_info = event_dict.pop("exc_info", None)
    if not exc_info:
        return event_dict
    if isinstance(exc_info, BaseException):
        error: BaseException | None = exc_info
    elif isinstance(exc_info, tuple):
        error = exc_info[1]
    else:
        error = sys.exc_info()[1]
    if error is not None:
        event_dict["exc_type"] = type(error).__name__
        event_dict["stack"] = [
            f"{PurePath(frame.filename).name}:{frame.lineno} in {frame.name}"
            for frame in traceback.extract_tb(error.__traceback__)
        ]
    return event_dict


def configure_logging(level: str = "info", stream: TextIO | None = None) -> None:
    """Send structlog's and the standard library's log lines to `stream` as JSON."""
    out = sys.stdout if stream is None else stream
    shared = [
        merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
    ]
    last = [exception_summary, redact_secret_names, structlog.processors.JSONRenderer()]
    structlog.configure(
        processors=[*shared, *last],
        wrapper_class=structlog.make_filtering_bound_logger(_LEVELS[level]),
        logger_factory=structlog.PrintLoggerFactory(file=out),
        cache_logger_on_first_use=False,
    )
    # What libraries log (uvicorn, alembic, SQLAlchemy) takes the same form.
    handler = logging.StreamHandler(out)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared,
            processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, *last],
        )
    )
    # LOG_LEVEL is for our own lines and the two programs we run. Every other
    # library is held to warnings and up, whatever the level: an HTTP client
    # logs each URL with its query string at info, and botocore its signed
    # requests at debug.
    logging.basicConfig(handlers=[handler], level=logging.WARNING, force=True)
    for name in _OWN_LOGGERS:
        logging.getLogger(name).setLevel(_LEVELS[level])
    # uvicorn installs handlers of its own before it calls the app factory:
    # its lines go through ours instead, and its access log, which prints the
    # query string, is off (the request line above replaces it).
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        library = logging.getLogger(name)
        library.handlers.clear()
        library.propagate = True
    logging.getLogger("uvicorn.access").disabled = True


def _request_id(scope: dict) -> str:
    given = [value for name, value in scope["headers"] if name == REQUEST_ID_HEADER]
    if len(given) == 1:
        text = given[0].decode("latin-1")
        if _REQUEST_ID.fullmatch(text):
            return text
    return uuid.uuid4().hex


class RequestLogMiddleware:
    """Pure ASGI: binds the request ID, echoes it, and writes the request line."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.log = structlog.get_logger("app.request")

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _request_id(scope)
        clear_contextvars()
        bind_contextvars(request_id=request_id)
        started = time.perf_counter()
        status: int | None = None

        async def send_with_id(message: dict) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = [pair for pair in message.get("headers", []) if pair[0] != REQUEST_ID_HEADER]
                headers.append((REQUEST_ID_HEADER, request_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception as error:  # noqa: BLE001 - the one place an unhandled error ends
            self.log.error("unhandled exception", exc_info=error)
            if status is None:
                body = b'{"error":"internal","request_id":"' + request_id.encode("ascii") + b'"}'
                await send_with_id(
                    {
                        "type": "http.response.start",
                        "status": 500,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
        finally:
            self.log.info(
                "request",
                method=scope["method"],
                path=scope["path"],
                status=status,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
            clear_contextvars()
