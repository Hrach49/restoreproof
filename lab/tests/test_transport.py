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


SECRET = "SECRET123"
QUERY = f"UniqueId=abc&tempauth={SECRET}&ApiVersion=2.0"
DOWNLOAD = "https://contoso.sharepoint.com/sites/rt/_layouts/15/download.aspx"


@pytest.mark.parametrize(
    "exc_type",
    [requests.ConnectionError, requests.Timeout, requests.exceptions.SSLError, requests.TooManyRedirects],
)
@pytest.mark.parametrize(
    "detail",
    [
        # requests' own form: a pool message with the bare path and query of the redirected URL.
        "HTTPSConnectionPool(host='contoso.sharepoint.com', port=443): Max retries exceeded with url: "
        f"/sites/rt/_layouts/15/download.aspx?{QUERY} (Caused by NewConnectionError('refused'))",
        f"Exceeded 30 redirects: {DOWNLOAD}?{QUERY}",
        f"'{DOWNLOAD}?{QUERY.replace('&', '&amp;')}'",
        f"url: /sites/rt/_layouts/15/download.aspx?{QUERY}",
        # A long prefix pushes the query across the 300-char cut.
        "x" * 250 + f" url: /download.aspx?{QUERY}",
        # No "?" at all, but the credential's name is still there.
        f"bad url /download.aspx%3F{QUERY}",
        f"Tempauth: {SECRET}",
    ],
)
def test_transport_errors_never_carry_url_query_strings(exc_type, detail):
    transport = RequestsTransport(session=FakeSession(exc_type(detail)))
    with pytest.raises(TransportError) as info:
        transport.request("GET", f"{DOWNLOAD}?{QUERY}", {})
    text = str(info.value)
    assert SECRET not in text
    assert "ApiVersion" not in text
    assert text.startswith(f"GET {DOWNLOAD}?[redacted]: {exc_type.__name__}: ")
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


def test_transport_error_keeps_host_and_path_of_urls_in_the_detail():
    detail = f"Max retries exceeded with url: /sites/rt/download.aspx?{QUERY} (Caused by X)"
    transport = RequestsTransport(session=FakeSession(requests.ConnectionError(detail)))
    with pytest.raises(TransportError) as info:
        transport.request("GET", "https://graph.microsoft.com/v1.0/me/messages?$filter=subject eq 'x'", {})
    assert str(info.value) == (
        "GET https://graph.microsoft.com/v1.0/me/messages?[redacted]: ConnectionError: "
        "Max retries exceeded with url: /sites/rt/download.aspx?[redacted] (Caused by X)"
    )


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


def test_can_leave_a_redirect_unfollowed():
    session = FakeSession(FakeResponse(302, b"", {"Location": "https://t.sharepoint.com/x"}))
    transport = RequestsTransport(session=session)
    resp = transport.request("GET", "https://graph.microsoft.com/v1.0/drives/d/items/i/content", {}, follow_redirects=False)
    (_, kwargs), = session.calls
    assert kwargs["allow_redirects"] is False
    assert resp.status == 302
    assert resp.headers["location"] == "https://t.sharepoint.com/x"


def test_error_statuses_are_returned_not_raised():
    transport = RequestsTransport(session=FakeSession(FakeResponse(503, b"busy", {"Retry-After": "3"})))
    resp = transport.request("GET", "https://graph.microsoft.com/v1.0/me", {})
    assert (resp.status, resp.body, resp.headers["retry-after"]) == (503, b"busy", "3")


def test_default_timeout_is_60_and_default_session_is_requests():
    transport = RequestsTransport()
    assert transport.timeout == 60
    assert isinstance(transport.session, requests.Session)


def test_the_fake_transport_records_follow_redirects():
    from seeder.http import HttpResponse
    from tests.fake_transport import FakeTransport

    fake = FakeTransport([HttpResponse(200), HttpResponse(302)])
    fake.request("GET", "https://a/", {})
    fake.request("GET", "https://b/", {}, follow_redirects=False)
    assert [r.follow_redirects for r in fake.requests] == [True, False]
