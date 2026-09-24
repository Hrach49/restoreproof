"""The real Transport: requests over HTTPS. Never logs anything."""

from typing import Mapping

import requests

from seeder.http import HttpResponse, TransportError


class RequestsTransport:
    """Follows redirects. A file download answers with a 302 to a pre-authenticated URL on
    another host; requests drops the Authorization header on a cross-host redirect, so the
    Graph token never reaches that host."""

    def __init__(self, session: requests.Session | None = None, timeout: float = 60) -> None:
        self.session = session if session is not None else requests.Session()
        self.timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> HttpResponse:
        try:
            r = self.session.request(
                method,
                url,
                headers=dict(headers),
                data=body,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            # Only the method, URL and exception text: requests' messages carry no headers.
            # "from None" so the traceback doesn't drag in exc.request (which holds the headers).
            detail = str(exc)[:300]
            raise TransportError(f"{method} {url}: {type(exc).__name__}: {detail}") from None
        return HttpResponse(
            status=r.status_code,
            body=r.content,
            headers={k.lower(): v for k, v in r.headers.items()},
        )
