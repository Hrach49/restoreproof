"""The real Transport: requests over HTTPS. Never logs anything."""

import re
from typing import Mapping

import requests

from seeder.http import HttpResponse, TransportError

# A query string inside error text: "?" and everything up to whitespace, a quote or a paren.
_QUERY = re.compile(r"\?[^\s'\"()<>]+")
# Belt and braces for a query that slipped past _QUERY (e.g. an encoded "%3F").
_TEMPAUTH = re.compile(r"(?i)tempauth[\W_]*[^\s'\"()<>]*")


class RequestsTransport:
    """Follows redirects unless asked not to. A file download answers with a 302 to a pre-authenticated URL on
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
        *,
        follow_redirects: bool = True,
    ) -> HttpResponse:
        try:
            r = self.session.request(
                method,
                url,
                headers=dict(headers),
                data=body,
                timeout=self.timeout,
                allow_redirects=follow_redirects,
            )
        except requests.RequestException as exc:
            # Only the method, URL and exception text: requests' messages carry no headers, but
            # they do carry URLs, and a download's redirect URL holds a tempauth credential in
            # its query, so every query string goes. Redact before cutting, so a cut can't
            # split a secret out of the pattern's reach.
            # "from None" so the traceback doesn't drag in exc.request (which holds the headers).
            detail = _redact_queries(str(exc))[:300]
            raise TransportError(f"{method} {_strip_query(url)}: {type(exc).__name__}: {detail}") from None
        return HttpResponse(
            status=r.status_code,
            body=r.content,
            headers={k.lower(): v for k, v in r.headers.items()},
        )


def _strip_query(url: str) -> str:
    base, sep, _ = url.partition("?")
    return f"{base}?[redacted]" if sep else base


def _redact_queries(text: str) -> str:
    text = _QUERY.sub("?[redacted]", text)
    return _TEMPAUTH.sub("tempauth=[redacted]", text)
