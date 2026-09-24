"""The HTTP seam. Graph code talks to a Transport; tests inject a fake one."""

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol


class TransportError(Exception):
    """The request never got an HTTP response (DNS, connect, timeout, TLS)."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes = b""
    # Header names are lower-case.
    headers: Mapping[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class Transport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> HttpResponse:
        """Send one request. Follows redirects. Raises TransportError when no response came."""
        ...
