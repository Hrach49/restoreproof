import pytest
import requests

from seeder.http import TransportError
from seeder.transport import RequestsTransport

SENTINEL = "sentinel-token-DO-NOT-LEAK"


class FakeResponse:
    def __init__(self, status_code: int, content: bytes, headers: dict[str, str]) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = requests.structures.CaseInsensitiveDict(headers)


class FakeSession:
    def __init__(self, result: FakeResponse | Exception) -> None:
        self._result = result
        self.calls: list[tuple[tuple, dict]] = []

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


@pytest.mark.parametrize(
    "exc",
    [
        requests.ConnectionError("connection refused"),
        requests.Timeout("read timed out"),
        requests.exceptions.SSLError("certificate verify failed"),
        requests.TooManyRedirects("too many redirects"),
    ],
)
def test_requests_exceptions_become_transport_errors_without_headers(exc, capsys):
    transport = RequestsTransport(session=FakeSession(exc))
    with pytest.raises(TransportError) as info:
        transport.request(
            "GET",
            "https://graph.microsoft.com/v1.0/me?x=1",
            {"Authorization": f"Bearer {SENTINEL}"},
        )
    for text in (str(info.value), repr(info.value), capsys.readouterr().out):
        assert SENTINEL not in text
        assert "Authorization" not in text
    assert "GET https://graph.microsoft.com/v1.0/me" in str(info.value)
    assert info.value.__cause__ is None


def test_passes_method_url_headers_body_timeout_and_follows_redirects():
    session = FakeSession(FakeResponse(201, b'{"id": "1"}', {"Content-Type": "application/json", "ETag": "x"}))
    transport = RequestsTransport(session=session, timeout=17)

    resp = transport.request(
        "PUT",
        "https://graph.microsoft.com/v1.0/drives/d/items/root:/a.txt:/content",
        {"Content-Type": "application/octet-stream"},
        b"\x00\x01data",
    )

    (args, kwargs), = session.calls
    assert args == ("PUT", "https://graph.microsoft.com/v1.0/drives/d/items/root:/a.txt:/content")
    assert kwargs == {
        "headers": {"Content-Type": "application/octet-stream"},
        "data": b"\x00\x01data",
        "timeout": 17,
        "allow_redirects": True,
    }
    assert resp.status == 201
    assert resp.body == b'{"id": "1"}'
    assert resp.json() == {"id": "1"}
    assert dict(resp.headers) == {"content-type": "application/json", "etag": "x"}


def test_error_statuses_are_returned_not_raised():
    transport = RequestsTransport(session=FakeSession(FakeResponse(503, b"busy", {"Retry-After": "3"})))
    resp = transport.request("GET", "https://graph.microsoft.com/v1.0/me", {})
    assert (resp.status, resp.body, resp.headers["retry-after"]) == (503, b"busy", "3")


def test_default_timeout_is_60_and_default_session_is_requests():
    transport = RequestsTransport()
    assert transport.timeout == 60
    assert isinstance(transport.session, requests.Session)
