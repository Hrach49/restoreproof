"""A small scripted Transport for tests: replays queued responses (or asks a handler) and records requests."""

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from seeder.http import HttpResponse


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    follow_redirects: bool = True

    def json(self) -> Any:
        assert self.body is not None
        return json.loads(self.body.decode("utf-8"))


# A queued item is a response to return or an exception to raise.
Scripted = HttpResponse | Exception


class FakeTransport:
    def __init__(
        self,
        responses: list[Scripted] | None = None,
        handler: Callable[[RecordedRequest], Scripted] | None = None,
    ) -> None:
        self._queue = list(responses or [])
        self._handler = handler
        self.requests: list[RecordedRequest] = []

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
        *,
        follow_redirects: bool = True,
    ) -> HttpResponse:
        req = RecordedRequest(method, url, dict(headers), body, follow_redirects)
        self.requests.append(req)
        if self._handler is not None:
            result = self._handler(req)
        else:
            assert self._queue, f"unexpected request {method} {url}"
            result = self._queue.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def json_response(status: int, obj: Any, headers: Mapping[str, str] | None = None) -> HttpResponse:
    all_headers = {"content-type": "application/json"}
    all_headers.update(headers or {})
    return HttpResponse(status, json.dumps(obj).encode("utf-8"), all_headers)


def graph_error(status: int, code: str = "", message: str = "", headers: Mapping[str, str] | None = None) -> HttpResponse:
    return json_response(status, {"error": {"code": code, "message": message}}, headers)
