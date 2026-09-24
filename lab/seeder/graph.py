"""A small Microsoft Graph client (delegated, one signed-in account) and the few calls the seeder needs."""

import json
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlencode

from seeder.http import HttpResponse, Transport, TransportError

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

RETRY_STATUSES = frozenset({429, 502, 503, 504})
_MAX_DETAIL = 300
_NOT_RETRIED = "the outcome is unknown, so it was not retried"

# Kept literal in query strings, as in Graph's documented URLs ("$filter=subject eq 'x'",
# "$select=a,b", "@microsoft.graph.conflictBehavior=fail"); all are legal in a query.
_QUERY_SAFE = "$,'@"


def seg(value: str) -> str:
    """Quote one path segment (an id or a file name).

    Like quote(value, safe="") except "!" stays literal: drive ids look like "b!XQgI...", and
    Graph writes them unencoded in its own URLs. "!" is a legal path character (RFC 3986
    sub-delim) and Graph accepts it either way, so leaving it keeps our URLs matching Graph's.
    """
    return quote(value, safe="!")


class GraphError(Exception):
    """A Graph call failed. The message never contains the token or any header."""

    def __init__(self, message: str, *, status: int | None, method: str, path: str) -> None:
        super().__init__(message)
        self.status = status
        self.method = method
        self.path = path


class GraphForbidden(GraphError):
    """HTTP 403: usually the wrong account is signed in, or consent is missing."""


class GraphOutcomeUnknown(GraphError):
    """A call that is not safe to repeat got no answer, or a 502/503/504: Graph may have done it."""


class GraphClient:
    def __init__(
        self,
        transport: Transport,
        token_provider: Callable[[], str],
        account: str,
        *,
        base_url: str = GRAPH_BASE,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 4,
    ) -> None:
        self._transport = transport
        self._token_provider = token_provider
        self.account = account
        self._base_url = base_url.rstrip("/")
        self._sleep = sleep
        self._max_attempts = max_attempts

    def __repr__(self) -> str:
        return f"GraphClient(account={self.account!r})"

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        json_body: Any = None,
        owner: str | None = None,
        idempotent: bool = True,
    ) -> HttpResponse:
        """idempotent=False (sendMail, a fail-on-conflict upload): after no response or a
        502/503/504 Graph may have done it, so raise GraphOutcomeUnknown instead of sending it
        again. 429 is still retried: Graph rejected the request without doing it."""
        url = self._base_url + path
        if params:
            url += "?" + urlencode(params, safe=_QUERY_SAFE, quote_via=quote)
        all_headers = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            all_headers["Content-Type"] = "application/json"

        token = ""
        for attempt in range(1, self._max_attempts + 1):
            token = self._token_provider()
            all_headers["Authorization"] = f"Bearer {token}"
            try:
                resp = self._transport.request(method, url, all_headers, body)
            except TransportError as exc:
                if not idempotent:
                    msg = f"{method} {path} as {self.account}: no response ({exc}); {_NOT_RETRIED}"
                    raise GraphOutcomeUnknown(_scrub(msg, token), status=None, method=method, path=path) from None
                if attempt == self._max_attempts:
                    msg = f"{method} {path} failed after {attempt} attempts: {exc}"
                    raise GraphError(_scrub(msg, token), status=None, method=method, path=path) from None
                self._sleep(2**attempt)
                continue
            if 200 <= resp.status < 300:
                return resp
            retry = resp.status in RETRY_STATUSES and (idempotent or resp.status == 429)
            if retry and attempt < self._max_attempts:
                self._sleep(_retry_delay(resp, attempt))
                continue
            raise self._error(resp, method, path, owner, attempt, token, idempotent)
        raise AssertionError("unreachable")  # pragma: no cover

    def _error(
        self,
        resp: HttpResponse,
        method: str,
        path: str,
        owner: str | None,
        attempts: int,
        token: str,
        idempotent: bool = True,
    ) -> GraphError:
        where = f"{method} {path} as {self.account}"
        detail = _graph_detail(resp)
        cls = GraphError
        if not idempotent and resp.status in RETRY_STATUSES - {429}:
            cls = GraphOutcomeUnknown
            msg = f"{where}: HTTP {resp.status}{detail}; {_NOT_RETRIED}"
        elif resp.status == 403:
            cls = GraphForbidden
            if owner and owner.lower() != self.account.lower():
                hint = (
                    f"this step needs {owner} to be signed in (delegated Graph calls only reach "
                    "the signed-in user's own mailbox and OneDrive)."
                )
            else:
                hint = (
                    "check the app's delegated permissions and admin consent (lab/README.md), "
                    f"and that {self.account} can access this location."
                )
            msg = f"Graph refused {where} (HTTP 403){detail}; {hint}"
        elif resp.status == 401:
            msg = f"{where}: the sign-in expired or was rejected (HTTP 401){detail}. Sign in again."
        elif resp.status == 404:
            msg = f"{where}: not found (HTTP 404){detail}"
        elif resp.status in RETRY_STATUSES:
            msg = f"{where} failed after {attempts} attempts: HTTP {resp.status}{detail}"
        else:
            msg = f"{where} failed: HTTP {resp.status}{detail}"
        return cls(_scrub(msg, token), status=resp.status, method=method, path=path)

    def get_json(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        owner: str | None = None,
    ) -> Any:
        return self.request("GET", path, params=params, headers=headers, owner=owner).json()

    def get_bytes(self, path: str, owner: str | None = None) -> bytes:
        return self.request("GET", path, owner=owner).body

    def post_json(
        self, path: str, payload: Any, owner: str | None = None, *, idempotent: bool = True
    ) -> HttpResponse:
        return self.request("POST", path, json_body=payload, owner=owner, idempotent=idempotent)

    def put_bytes(
        self,
        path: str,
        data: bytes,
        *,
        params: Mapping[str, str] | None = None,
        owner: str | None = None,
        idempotent: bool = True,
    ) -> Any:
        resp = self.request(
            "PUT",
            path,
            params=params,
            headers={"Content-Type": "application/octet-stream"},
            body=data,
            owner=owner,
            idempotent=idempotent,
        )
        return resp.json()


def _retry_delay(resp: HttpResponse, attempt: int) -> float:
    value = resp.headers.get("retry-after", "").strip()
    if value.isdigit():
        return int(value)
    return 2**attempt  # 2, 4, 8 s; an HTTP-date Retry-After also lands here


def _graph_detail(resp: HttpResponse) -> str:
    """Graph's own error code and message (never secrets), or "" if the body isn't Graph JSON."""
    try:
        error = resp.json()["error"]
        parts = [str(error.get("code") or ""), str(error.get("message") or "")]
    except (ValueError, KeyError, TypeError, AttributeError):
        return ""
    text = ": ".join(p for p in parts if p)
    if not text:
        return ""
    if len(text) > _MAX_DETAIL:
        text = text[: _MAX_DETAIL - 3] + "..."
    return f" [{text}]"


def _scrub(message: str, token: str) -> str:
    # Belt and braces: nothing we build includes the token, but a server or transport
    # message could echo it.
    return message.replace(token, "[redacted]") if token else message


# ---- the calls the seeder uses --------------------------------------------------------

# Every message read asks for the plain-text body and ids that survive a folder move.
MAIL_PREFER = 'outlook.body-content-type="text", IdType="ImmutableId"'
MESSAGE_FIELDS = (
    "id,subject,from,toRecipients,sentDateTime,receivedDateTime,internetMessageId,parentFolderId,body"
)


def _none_on_404(call: Callable[[], Any]) -> Any:
    try:
        return call()
    except GraphError as exc:
        if exc.status == 404:
            return None
        raise


def find_messages_by_subject(
    g: GraphClient, subject: str, owner: str, *, exclude_folder_id: str | None = None
) -> list[dict]:
    """Messages in any folder of the signed-in mailbox with exactly this subject, except those
    directly in exclude_folder_id. No $orderby: Graph rejects it combined with this $filter.
    The folder is left out here, not in the $filter: Graph often rejects that as inefficient."""
    literal = subject.replace("'", "''")
    params = {"$filter": f"subject eq '{literal}'", "$select": MESSAGE_FIELDS, "$top": "50"}
    data = g.get_json("/me/messages", params=params, headers={"Prefer": MAIL_PREFER}, owner=owner)
    messages = list(data.get("value", []))
    if exclude_folder_id is None:
        return messages
    return [m for m in messages if m.get("parentFolderId") != exclude_folder_id]


def get_deleted_items_id(g: GraphClient, owner: str) -> str:
    """The id of the signed-in mailbox's Deleted Items folder, in the same ImmutableId form as a
    message's parentFolderId (hence the Prefer header)."""
    data = g.get_json(
        "/me/mailFolders/deleteditems", params={"$select": "id"}, headers={"Prefer": MAIL_PREFER}, owner=owner
    )
    return data["id"]


def get_message(g: GraphClient, message_id: str, owner: str) -> dict | None:
    return _none_on_404(
        lambda: g.get_json(
            f"/me/messages/{seg(message_id)}",
            params={"$select": MESSAGE_FIELDS},
            headers={"Prefer": MAIL_PREFER},
            owner=owner,
        )
    )


def get_mail_folder_name(g: GraphClient, folder_id: str, owner: str) -> str:
    data = g.get_json(
        f"/me/mailFolders/{seg(folder_id)}",
        params={"$select": "displayName"},
        headers={"Prefer": MAIL_PREFER},
        owner=owner,
    )
    return data["displayName"]


def send_mail(
    g: GraphClient, *, subject: str, body_text: str, to_address: str, owner: str | None = None
) -> None:
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "text", "content": body_text},
            "toRecipients": [{"emailAddress": {"address": to_address}}],
        },
        "saveToSentItems": True,
    }
    # Not idempotent: a second POST after an unknown outcome could deliver the mail twice.
    try:
        resp = g.post_json("/me/sendMail", payload, owner=owner, idempotent=False)
    except GraphOutcomeUnknown as exc:
        raise GraphOutcomeUnknown(
            f"{exc}. {subject} may have been sent. Wait a few minutes, then run seed again: "
            "it finds the mails already delivered, and those are not sent twice.",
            status=exc.status,
            method=exc.method,
            path=exc.path,
        ) from None
    if resp.status != 202:
        raise GraphError(
            f"POST /me/sendMail as {g.account}: expected HTTP 202, got {resp.status}",
            status=resp.status,
            method="POST",
            path="/me/sendMail",
        )


def _item_path(drive_id: str, folder_id: str, name: str) -> str:
    return f"/drives/{seg(drive_id)}/items/{seg(folder_id)}:/{seg(name)}:"


def get_item_by_path(g: GraphClient, drive_id: str, folder_id: str, name: str, owner: str) -> dict | None:
    return _none_on_404(lambda: g.get_json(_item_path(drive_id, folder_id, name), owner=owner))


def get_item(g: GraphClient, drive_id: str, item_id: str, owner: str) -> dict | None:
    return _none_on_404(lambda: g.get_json(f"/drives/{seg(drive_id)}/items/{seg(item_id)}", owner=owner))


def upload_file(
    g: GraphClient, drive_id: str, folder_id: str, name: str, data: bytes, *, replace: bool, owner: str
) -> dict:
    """Simple upload (fine below 250 MB). Returns the driveItem JSON."""
    path = _item_path(drive_id, folder_id, name) + "/content"
    params = {"@microsoft.graph.conflictBehavior": "replace" if replace else "fail"}
    # Replacing is idempotent. Failing on a conflict is not: a retry after an upload that
    # did happen gets 409, and the 409 message below would wrongly point at --force.
    try:
        return g.put_bytes(path, data, params=params, owner=owner, idempotent=replace)
    except GraphOutcomeUnknown as exc:
        raise GraphOutcomeUnknown(
            f"{exc}. {name} may have been uploaded; run seed again: it finds the files already "
            "uploaded, and those are not uploaded twice.",
            status=exc.status,
            method=exc.method,
            path=exc.path,
        ) from None
    except GraphError as exc:
        if exc.status != 409:
            raise
        raise GraphError(
            f"{name} already exists in drive {drive_id}, folder {folder_id}; "
            "re-run with --force to replace it.",
            status=409,
            method="PUT",
            path=path,
        ) from None


def download_item(g: GraphClient, drive_id: str, item_id: str, owner: str) -> bytes:
    """Graph answers with a 302 to a pre-authenticated URL; the transport follows it."""
    return g.get_bytes(f"/drives/{seg(drive_id)}/items/{seg(item_id)}/content", owner=owner)
