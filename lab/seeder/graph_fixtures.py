"""`python -m seeder record-graph-fixtures` (W2.1): record the Worker's Graph fixtures live.

Signs in as the RestoreProof Worker app the way the Worker's GraphClient does: its own client
assertion (a JWT, PS256, header `x5t#S256` = base64url SHA-256 of the certificate), posted to
Entra's v2.0 token endpoint. Then it records the answers the Worker's tests replay from
worker/tests/fixtures/graph/: the token reply, the Entra errors for a bad signature, an unknown
certificate, app or tenant and a skewed clock, and the Graph replies for the test mailbox,
three things the app may not read, a bad or missing token and an unknown user.

W2.2 adds the states of the three restore targets (`--state empty|one-item|paged`): the
restoretest inbox, the RestoreTarget library and alice's OneDrive /RestoreTarget folder, read
the way the Worker's TargetReader reads them. Each state needs the targets to be in that state
(empty; one mail and one file in each; two mails); a reply that shows otherwise is UNEXPECTED
and nothing is written. The token reply is written only in the `auth` state. A `/content`
redirect is recorded, never followed, with its download credential scrubbed.

Only reads: one POST per token request, GET for everything else. Nothing is written unless
every reply came back with the status its file name promises and the content its state needs,
and none of them holds anything that looks like a token, an assertion, a download credential or
the PFX password. The access token in the token reply is replaced by a fake unsigned JWT.
Nothing secret is ever printed.
"""

import base64
import datetime as dt
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urlencode, urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from seeder import REPO_DIR, tenant
from seeder.auth import AuthError
from seeder.graph import MAIL_PREFER
from seeder.http import HttpResponse, Transport
from seeder.worker_app import CREDENTIAL_TARGET, SETUP_SCRIPT, CredentialError, load_pfx

DEFAULT_OUT_DIR = REPO_DIR / "worker" / "tests" / "fixtures" / "graph"
LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_LIFETIME = 300  # seconds, as the Worker's
SKEW = 3600  # the expired and future assertions are this far off
# {"typ":"JWT","alg":"none"}.{"scrubbed":true}. with no signature: parses, verifies nothing.
FAKE_ACCESS_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0."
# A token Graph can't read. Its first segment is short enough not to look like a real JWT.
MALFORMED_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ4IjoxfQ.AAAA"
# The response headers a fixture keeps, spelled as Graph and Entra send them.
KEPT_HEADERS = {
    name.lower(): name
    for name in (
        "Content-Type",
        "WWW-Authenticate",
        "Retry-After",
        "Location",
        "request-id",
        "client-request-id",
        "x-ms-request-id",
    )
}
# A JWT (or any long base64url run starting like one), even without its dots.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{37,}")
# What a scrubbed secret reads as in a fixture.
SCRUB_MARK = "SCRUBBED"
# The query keys of a SharePoint download link whose values are kept (case-insensitive). Every
# other value (tempauth, its encoded forms, anything new) becomes SCRUB_MARK.
DOWNLOAD_QUERY_KEPT = frozenset({"uniqueid", "translate", "apiversion"})
# A driveItem's pre-authenticated download link: dropped from bodies.
DOWNLOAD_URL_KEY = "@microsoft.graph.downloadUrl"
_TEMPAUTH_VALUE = re.compile(r"(?i)(tempauth(?:=|%3D))[^&\s\"]+")
# A tempauth whose value is anything but SCRUB_MARK: as a query value, encoded, or a JSON key.
_UNSCRUBBED_TEMPAUTH = re.compile(rf'(?i)tempauth(?:=|%3D|"\s*:\s*")(?!{SCRUB_MARK}(?:[&\s"]|$))')
_DOWNLOAD_QUERY = re.compile(r"(?i)download\.aspx\?([^\s\"'<>]*)")


class FixtureError(Exception):
    """A reply holds something that must not be committed; nothing was written."""


def _clock() -> float:
    return time.time()


def _new_key() -> rsa.RSAPrivateKey:
    """A key Entra has never seen, for the bad-signature case."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ---- the client assertion ------------------------------------------------------------------


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def token_url(tenant_id: str) -> str:
    return f"{LOGIN}/{tenant_id}/oauth2/v2.0/token"


def client_assertion(
    key: rsa.RSAPrivateKey,
    x5t_s256: str,
    *,
    client_id: str,
    tenant_id: str,
    now: int,
    lifetime: int = ASSERTION_LIFETIME,
) -> str:
    """A signed client assertion: PS256 (SHA-256, MGF1-SHA-256, salt 32), a fresh jti."""
    header = {"alg": "PS256", "typ": "JWT", "x5t#S256": x5t_s256}
    claims = {
        "aud": token_url(tenant_id),
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "iat": now,
        "exp": now + lifetime,
    }
    signing_input = ".".join(b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims))
    signature = key.sign(
        signing_input.encode("ascii"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return f"{signing_input}.{b64url(signature)}"


# ---- the fixture file ----------------------------------------------------------------------


def kept_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """The headers worth keeping, in the order they came, with their usual spelling."""
    return {KEPT_HEADERS[name.lower()]: value for name, value in headers.items() if name.lower() in KEPT_HEADERS}


def _body(response: HttpResponse) -> Any:
    if not response.body:
        return None
    text = response.body.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def fixture_text(source: str, request: str, response: HttpResponse) -> str:
    """The fixture as written: indented JSON, UTF-8 as is, a final newline."""
    record = {
        "source": source,
        "request": request,
        "status": response.status,
        "headers": kept_headers(response.headers),
        "body": _body(response),
    }
    return json.dumps(record, indent=2, ensure_ascii=False) + "\n"


def check_safe(name: str, text: str, secrets: list[str]) -> None:
    """Raises FixtureError if the text holds a JWT, an assertion or a known secret. The message
    says which kind, never the text itself. A tempauth is checked before the JWT rule, so an
    unscrubbed "tempauth=v1.eyJ…" is reported as what it is."""
    if _UNSCRUBBED_TEMPAUTH.search(text):
        raise FixtureError(f"{name}: refused to write it: it holds a tempauth download credential")
    for match in _DOWNLOAD_QUERY.finditer(text):
        for pair in match.group(1).split("&"):
            key, _, value = pair.partition("=")
            if key.lower() not in DOWNLOAD_QUERY_KEPT and value != SCRUB_MARK:
                raise FixtureError(f"{name}: refused to write it: a download URL holds an unknown query value")
    if _JWT.search(text):
        raise FixtureError(f"{name}: refused to write it: it holds what looks like a JWT")
    if "client_assertion" in text:
        raise FixtureError(f"{name}: refused to write it: it mentions client_assertion")
    if any(secret and secret in text for secret in secrets):
        raise FixtureError(f"{name}: refused to write it: it holds the password, the token or an assertion")


def _scrubbed_location(url: str) -> str:
    """A download link with its scheme, host and path, and only the allowed query values."""
    parts = urlsplit(url)
    query = "&".join(
        pair if key.lower() in DOWNLOAD_QUERY_KEPT and sep else f"{key}={SCRUB_MARK}"
        for pair in parts.query.split("&")
        if pair
        for key, sep, _ in [pair.partition("=")]
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _scrubbed_value(value: Any) -> Any:
    """Every download link key dropped, every tempauth value in a string masked, recursively."""
    if isinstance(value, dict):
        return {k: _scrubbed_value(v) for k, v in value.items() if k != DOWNLOAD_URL_KEY}
    if isinstance(value, list):
        return [_scrubbed_value(v) for v in value]
    if isinstance(value, str):
        return _TEMPAUTH_VALUE.sub(lambda m: m.group(1) + SCRUB_MARK, value)
    return value


def _scrubbed(response: HttpResponse) -> HttpResponse:
    """The reply as a fixture may keep it: a token reply's access token replaced by
    FAKE_ACCESS_TOKEN, a Location's query cut to the allowed values, download links dropped
    from the body and tempauth values masked. A reply with none of these is returned as is."""
    headers = dict(response.headers)
    if "location" in headers:
        headers["location"] = _scrubbed_location(headers["location"])
    body = _body(response)
    new_body = _scrubbed_value(body)
    if isinstance(new_body, dict) and "access_token" in new_body:
        new_body["access_token"] = FAKE_ACCESS_TOKEN
    if new_body == body and headers == dict(response.headers):
        return response
    if isinstance(new_body, str):
        data = new_body.encode("utf-8")
    else:
        data = b"" if new_body is None else json.dumps(new_body, ensure_ascii=False).encode("utf-8")
    return HttpResponse(response.status, data, headers)


def _error_code(response: HttpResponse) -> str:
    """What the output shows of a reply: Entra's error and AADSTS code, or Graph's error code."""
    body = _body(response)
    if not isinstance(body, dict):
        return ""
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("code") or "")
    if isinstance(error, str):
        codes = body.get("error_codes")
        first = codes[0] if isinstance(codes, list) and codes else None
        return f"{error} AADSTS{first}" if first is not None else error
    return ""


# ---- what is recorded ----------------------------------------------------------------------


STATES = ("auth", "empty", "one-item", "paged")
# A check returns what is wrong with a reply (its status already right), or None.
Check = Callable[[HttpResponse], "str | None"]


@dataclass(frozen=True)
class Entry:
    file_name: str
    expected: int  # the status the file name promises
    what: str  # the source line after "live <date>: "
    request: str  # method and path as written into the fixture; random parts hidden
    state: str = "auth"
    headers: tuple[tuple[str, str], ...] = ()  # sent besides Authorization (Prefer only)
    follow_redirects: bool = True
    check: Check | None = field(default=None, compare=False)
    # Facts about the reply printed after the verdict (what the Worker must adapt to).
    facts: Callable[[HttpResponse], str] | None = field(default=None, compare=False)


def _messages(upn: str, query: str = "$top=1&$select=id") -> str:
    return f"/users/{upn}/mailFolders/inbox/messages?{query}"


NOBODY_SHOWN = f"nobody-…@{tenant.TENANT_DOMAIN}"

# ---- the restore targets, read as the Worker's TargetReader reads them (W2.2) --------------

RESTORE_TARGET = "RestoreTarget"
# With the body, so one call lists and hashes a page (review of W2.2: no GET per mail).
MAIL_SELECT = "$select=id,subject,from,receivedDateTime,internetMessageId,body"
DRIVE_SELECT = "$select=id,name,driveType,webUrl,sharePointIds"
FOLDER_SELECT = "$select=id,name,folder,parentReference"
CHILDREN_QUERY = "$select=id,name,size,file,folder&$top=200"
PREFER = (("Prefer", MAIL_PREFER),)
# An ID from a reply may go in a URL path only if it is made of these (Exchange IDs end in "=").
_SAFE_ID = re.compile(r"[A-Za-z0-9!_=-]{1,512}")
_ITEM_ID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
# In the request lines: the IDs a reply gave, or random ones.
ITEM_ID_SHOWN = "<item id>"


def _mail_list(top: int) -> str:
    return _messages(tenant.RESTORETEST_UPN, f"{MAIL_SELECT}&$top={top}")


def _drive(drive_id: str) -> str:
    return f"/drives/{drive_id}?{DRIVE_SELECT}"


def _folder(item_id: str) -> str:
    return f"/drives/{tenant.ONEDRIVE_DRIVE_ID}/items/{item_id}?{FOLDER_SELECT}"


def _library_children() -> str:
    return f"/drives/{tenant.RESTORE_TARGET_DRIVE_ID}/root/children?{CHILDREN_QUERY}"


def _folder_children() -> str:
    return f"/drives/{tenant.ONEDRIVE_DRIVE_ID}/items/{tenant.ONEDRIVE_TARGET_FOLDER_ID}/children?{CHILDREN_QUERY}"


def _content(drive_id: str, item_id: str) -> str:
    return f"/drives/{drive_id}/items/{item_id}/content"


def _random_item_id() -> str:
    """The shape of a OneDrive for Business item ID: "01" and 32 base32 letters."""
    return "01" + "".join(secrets.choice(_ITEM_ID_CHARS) for _ in range(32))


def _random_drive_id() -> str:
    """The RestoreTarget drive ID with its last 16 bytes (the list GUID) random: a drive of the
    same site that doesn't exist, rather than a string Graph refuses to parse."""
    raw = tenant.RESTORE_TARGET_DRIVE_ID.removeprefix("b!")
    data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    return "b!" + b64url(data[:-16] + os.urandom(16))


def _json_object(response: HttpResponse) -> dict:
    body = _body(response)
    return body if isinstance(body, dict) else {}


def _last_segment(url: str) -> str:
    return unquote(urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1])


def _items(n: int, *, next_link: bool = False, files: bool = False) -> Check:
    """The reply lists exactly n items, with (or without) an @odata.nextLink on Graph v1.0, and,
    with files=True, each of them a file."""

    def check(response: HttpResponse) -> str | None:
        body = _json_object(response)
        value = body.get("value")
        if not isinstance(value, list):
            return 'no "value" array'
        if len(value) != n:
            return f"expected {n} item(s), got {len(value)}"
        link = body.get("@odata.nextLink")
        if next_link and not (isinstance(link, str) and link.startswith(f"{GRAPH}/")):
            return f"expected an @odata.nextLink on {GRAPH}/"
        if not next_link and link is not None:
            return "expected no @odata.nextLink"
        if files and not all(isinstance(item, dict) and isinstance(item.get("file"), dict) for item in value):
            return "the item is not a file"
        return None

    return check


def _named(body: dict) -> str | None:
    name = body.get("name")
    return None if name == RESTORE_TARGET else f"name is {name!r}, not {RESTORE_TARGET!r}"


def _restore_target_library(response: HttpResponse) -> str | None:
    """The RestoreTarget library: its display name, its URL name and its site IDs."""
    body = _json_object(response)
    web_url = body.get("webUrl")
    ids = body.get("sharePointIds")
    if problem := _named(body):
        return problem
    if not (isinstance(web_url, str) and _last_segment(web_url).lower() == RESTORE_TARGET.lower()):
        return f"webUrl does not end /{RESTORE_TARGET}"
    if not (isinstance(ids, dict) and ids.get("siteId") and ids.get("webId")):
        return "no sharePointIds.siteId and .webId"
    return None


def _restore_target_folder(response: HttpResponse) -> str | None:
    """alice's /RestoreTarget: its name, a folder, in her OneDrive."""
    body = _json_object(response)
    parent = body.get("parentReference")
    drive_id = parent.get("driveId") if isinstance(parent, dict) else None
    if problem := _named(body):
        return problem
    if not isinstance(body.get("folder"), dict):
        return "not a folder"
    if drive_id != tenant.ONEDRIVE_DRIVE_ID:
        return "parentReference.driveId is not alice's OneDrive"
    return None


def _graph_error(code: str) -> Check:
    def check(response: HttpResponse) -> str | None:
        actual = _error_code(response)
        return None if actual == code else f"error code {actual!r}, not {code!r}"

    return check


def _has_location(response: HttpResponse) -> str | None:
    return None if response.headers.get("location") else "no Location header"


def _text_bodies(response: HttpResponse) -> str | None:
    """Every message listed has its body as text (the Worker hashes it with text-v1)."""
    value = _json_object(response).get("value")
    for message in value if isinstance(value, list) else []:
        body = message.get("body") if isinstance(message, dict) else None
        content_type = body.get("contentType") if isinstance(body, dict) else None
        if not (
            isinstance(content_type, str) and content_type.lower() == "text" and isinstance(body.get("content"), str)
        ):
            return f"body.contentType is {content_type!r}, not text"
    return None


def _mail(n: int, *, next_link: bool = False) -> Check:
    """_items(n, next_link=...), and every body as text."""
    items = _items(n, next_link=next_link)
    return lambda response: items(response) or _text_bodies(response)


def _library_facts(response: HttpResponse) -> str:
    body = _json_object(response)
    web_url = body.get("webUrl")
    segment = _last_segment(web_url) if isinstance(web_url, str) else "(absent)"
    ids = "present" if isinstance(body.get("sharePointIds"), dict) else "absent"
    return f"webUrl last segment={segment}  sharePointIds={ids}"


def _folder_facts(response: HttpResponse) -> str:
    parent = _json_object(response).get("parentReference")
    parent = parent if isinstance(parent, dict) else {}
    path = parent.get("path") if isinstance(parent.get("path"), str) else "(absent)"
    parent_id = "present" if parent.get("id") else "absent"
    return f"parentReference.path={path}  parentReference.id={parent_id}"


def _get_line(path: str) -> str:
    return f"GET /v1.0{path}"


def _target_plan(state: str) -> list[Entry]:
    rt, od = tenant.RESTORE_TARGET_DRIVE_ID, tenant.ONEDRIVE_DRIVE_ID
    target_folder = tenant.ONEDRIVE_TARGET_FOLDER_ID

    def entry(name: str, status: int, what: str, path: str, **kwargs: Any) -> Entry:
        return Entry(name, status, what, path if path.startswith("GET ") else _get_line(path), state, **kwargs)

    if state == "empty":
        return [
            entry(
                "mail-list-200-empty.json", 200, "GET the restoretest inbox as the Worker lists it, empty",
                _mail_list(100), headers=PREFER, check=_mail(0),
            ),
            entry(
                "restoretarget-drive-200.json", 200, "GET the RestoreTarget library's drive, as the Worker's guard reads it",
                _drive(rt), check=_restore_target_library, facts=_library_facts,
            ),
            entry(
                "restoretarget-children-200-empty.json", 200, "GET the RestoreTarget library's root children, empty",
                _library_children(), check=_items(0),
            ),
            entry(
                "onedrive-folder-200.json", 200, "GET alice's OneDrive /RestoreTarget folder, as the Worker's guard reads it",
                _folder(target_folder), check=_restore_target_folder, facts=_folder_facts,
            ),
            entry(
                "onedrive-children-200-empty.json", 200, "GET the children of alice's /RestoreTarget, empty",
                _folder_children(), check=_items(0),
            ),
            entry(
                "onedrive-folder-404-itemnotfound.json", 404, "GET an item ID of no item in alice's OneDrive",
                _folder("<random item ID>"), check=_graph_error("itemNotFound"),
            ),
            entry(
                "drive-404-itemnotfound.json", 404, "GET a drive ID of no drive (the RestoreTarget drive's list GUID random)",
                _drive("<random drive ID>"), check=_graph_error("itemNotFound"),
            ),
        ]
    if state == "one-item":
        return [
            entry(
                "mail-list-200-one-item.json", 200,
                "GET the restoretest inbox as the Worker lists it, one mail, its body as text",
                _mail_list(100), headers=PREFER, check=_mail(1),
            ),
            entry(
                "restoretarget-children-200-one-item.json", 200, "GET the RestoreTarget library's root children, one file",
                _library_children(), check=_items(1, files=True),
            ),
            entry(
                "restoretarget-content-302.json", 302, "GET that file's content, redirect not followed, Location scrubbed",
                _content(rt, ITEM_ID_SHOWN), follow_redirects=False, check=_has_location,
            ),
            entry(
                "onedrive-children-200-one-item.json", 200, "GET the children of alice's /RestoreTarget, one file",
                _folder_children(), check=_items(1, files=True),
            ),
            entry(
                "onedrive-content-302.json", 302, "GET that file's content, redirect not followed, Location scrubbed",
                _content(od, ITEM_ID_SHOWN), follow_redirects=False, check=_has_location,
            ),
        ]
    return [
        entry(
            "mail-list-200-page1.json", 200, "GET the restoretest inbox with $top=1, two mails: page 1",
            _mail_list(1), headers=PREFER, check=_mail(1, next_link=True),
        ),
        entry(
            "mail-list-200-page2.json", 200, "GET page 1's @odata.nextLink: page 2",
            "GET <@odata.nextLink of mail-list-200-page1.json>", headers=PREFER, check=_mail(1),
        ),
    ]


def plan(tenant_id: str, state: str = "auth") -> list[Entry]:
    """Every fixture of `state`, in the order recorded. In `auth` the first is the token the
    Graph calls use; the other states sign in the same way but don't write the token."""
    if state not in STATES:
        raise ValueError(f"unknown state {state!r}; one of {', '.join(STATES)}")
    if state != "auth":
        return _target_plan(state)
    token = f"POST /{tenant_id}/oauth2/v2.0/token"
    return [
        Entry("token-200.json", 200, "token request, PS256 header ['x5t#S256']", token),
        Entry("token-bad-signature-401.json", 401, "assertion signed by a key Entra doesn't know", token),
        Entry("token-unknown-thumbprint-401.json", 401, "x5t#S256 of no uploaded certificate", token),
        Entry("token-unknown-app-400.json", 400, "client ID of no app", token),
        Entry("token-unknown-tenant-400.json", 400, "tenant ID of no tenant", "POST /<random GUID>/oauth2/v2.0/token"),
        Entry("token-expired-assertion-401.json", 401, "assertion expired an hour ago (clock skew)", token),
        Entry("token-future-assertion-401.json", 401, "assertion valid only from an hour ahead (clock skew)", token),
        Entry(
            "messages-200.json",
            200,
            "GET restoretest inbox messages ($top=1, $select=id)",
            f"GET /v1.0{_messages(tenant.RESTORETEST_UPN)}",
        ),
        Entry(
            "messages-403-exchange.json",
            403,
            "GET alice's inbox messages (outside the Exchange RBAC scope)",
            f"GET /v1.0{_messages(tenant.ALICE_UPN)}",
        ),
        Entry(
            "site-403-accessdenied.json",
            403,
            "GET the tenant root site (no Sites.Selected grant)",
            f"GET /v1.0/sites/{tenant.SHAREPOINT_HOST}",
        ),
        Entry("users-403-requestdenied.json", 403, "GET /users (no directory role)", "GET /v1.0/users?$top=1&$select=id"),
        Entry(
            "api-invalid-token-401.json",
            401,
            "GET with a malformed bearer token",
            f"GET /v1.0{_messages(tenant.RESTORETEST_UPN, '$top=1')}",
        ),
        Entry(
            "api-no-token-401.json",
            401,
            "GET without Authorization",
            f"GET /v1.0{_messages(tenant.RESTORETEST_UPN, '$top=1')}",
        ),
        Entry(
            "messages-404-unknown-user.json",
            404,
            "GET the mailbox of a user who doesn't exist",
            f"GET /v1.0{_messages(NOBODY_SHOWN, '$top=1')}",
        ),
    ]


class _Recorder:
    """Sends the requests of plan(), in order. Keeps every assertion and the token, so the
    safety check can look for them."""

    def __init__(
        self,
        transport: Transport,
        client_id: str,
        tenant_id: str,
        key: rsa.RSAPrivateKey,
        x5t_s256: str,
        now: int,
        other_key: rsa.RSAPrivateKey,
    ) -> None:
        self._transport = transport
        self._client_id = client_id
        self._tenant_id = tenant_id
        self._key = key
        self._x5t = x5t_s256
        self._now = now
        self._other_key = other_key
        self.secrets: list[str] = []
        self._token = ""

    def _post(self, *, key=None, x5t=None, client_id=None, tenant_id=None, now=None) -> HttpResponse:
        client_id = client_id or self._client_id
        tenant_id = tenant_id or self._tenant_id
        assertion = client_assertion(
            key or self._key,
            x5t or self._x5t,
            client_id=client_id,
            tenant_id=tenant_id,
            now=self._now if now is None else now,
        )
        self.secrets.append(assertion)
        form = {
            "client_id": client_id,
            "scope": GRAPH_SCOPE,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion,
            "grant_type": "client_credentials",
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self._transport.request("POST", token_url(tenant_id), headers, urlencode(form).encode("ascii"))

    def _get(
        self,
        path_or_url: str,
        authorization: str | None = "token",
        headers: tuple[tuple[str, str], ...] = (),
        follow_redirects: bool = True,
    ) -> HttpResponse:
        """GET a Graph path, or an absolute URL on Graph v1.0 (an @odata.nextLink); anything else
        absolute is refused before it is sent, so the token never leaves Graph."""
        if path_or_url.startswith("/") and not path_or_url.startswith("//"):
            url = f"{GRAPH}{path_or_url}"
        elif path_or_url.startswith(f"{GRAPH}/"):
            url = path_or_url
        else:
            raise FixtureError(f"refused to send a request that is not on {GRAPH}/")
        sent: dict[str, str] = {}
        for name, value in headers:
            if name.lower() == "authorization":
                raise ValueError("an extra header may not be Authorization: the recorder sets the token itself")
            sent[name] = value
        if authorization == "token":
            sent["Authorization"] = f"Bearer {self._token}"
        elif authorization is not None:
            sent["Authorization"] = authorization
        return self._transport.request("GET", url, sent, follow_redirects=follow_redirects)

    def sign_in(self) -> HttpResponse:
        response = self._post()
        body = _body(response)
        if response.status != 200:
            detail = _error_code(response) or "no error code"
            raise AuthError(f"The Worker app's token request failed: HTTP {response.status} {detail}.")
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise AuthError("The Worker app's token reply held no access token.")
        self._token = token
        self.secrets.append(token)
        return response

    def send(self, entry: Entry, replies: Mapping[str, HttpResponse]) -> HttpResponse:
        """Sends the request of `entry`. A request that needs an ID or a link from an earlier
        reply reads it from `replies` (file name -> reply)."""
        if entry.state == "auth":
            return self._send_auth(entry.file_name)
        rt, od = tenant.RESTORE_TARGET_DRIVE_ID, tenant.ONEDRIVE_DRIVE_ID

        def get(path: str) -> HttpResponse:
            return self._get(path, headers=entry.headers, follow_redirects=entry.follow_redirects)

        def first_id(source: str) -> str:
            return _first_id(entry.file_name, source, replies)

        senders: dict[str, Callable[[], HttpResponse]] = {
            "mail-list-200-empty.json": lambda: get(_mail_list(100)),
            "restoretarget-drive-200.json": lambda: get(_drive(rt)),
            "restoretarget-children-200-empty.json": lambda: get(_library_children()),
            "onedrive-folder-200.json": lambda: get(_folder(tenant.ONEDRIVE_TARGET_FOLDER_ID)),
            "onedrive-children-200-empty.json": lambda: get(_folder_children()),
            "onedrive-folder-404-itemnotfound.json": lambda: get(_folder(_random_item_id())),
            "drive-404-itemnotfound.json": lambda: get(_drive(_random_drive_id())),
            "mail-list-200-one-item.json": lambda: get(_mail_list(100)),
            "restoretarget-children-200-one-item.json": lambda: get(_library_children()),
            "restoretarget-content-302.json": lambda: get(_content(rt, first_id("restoretarget-children-200-one-item.json"))),
            "onedrive-children-200-one-item.json": lambda: get(_folder_children()),
            "onedrive-content-302.json": lambda: get(_content(od, first_id("onedrive-children-200-one-item.json"))),
            "mail-list-200-page1.json": lambda: get(_mail_list(1)),
            "mail-list-200-page2.json": lambda: get(_next_link(entry.file_name, "mail-list-200-page1.json", replies)),
        }
        return senders[entry.file_name]()

    def _send_auth(self, file_name: str) -> HttpResponse:
        nobody = f"nobody-{uuid.uuid4().hex[:8]}@{tenant.TENANT_DOMAIN}"
        senders: dict[str, Callable[[], HttpResponse]] = {
            "token-bad-signature-401.json": lambda: self._post(key=self._other_key),
            "token-unknown-thumbprint-401.json": lambda: self._post(x5t=b64url(b"\x01" * 32)),
            "token-unknown-app-400.json": lambda: self._post(client_id=str(uuid.uuid4())),
            "token-unknown-tenant-400.json": lambda: self._post(tenant_id=str(uuid.uuid4())),
            "token-expired-assertion-401.json": lambda: self._post(now=self._now - SKEW),
            "token-future-assertion-401.json": lambda: self._post(now=self._now + SKEW),
            "messages-200.json": lambda: self._get(_messages(tenant.RESTORETEST_UPN)),
            "messages-403-exchange.json": lambda: self._get(_messages(tenant.ALICE_UPN)),
            "site-403-accessdenied.json": lambda: self._get(f"/sites/{tenant.SHAREPOINT_HOST}"),
            "users-403-requestdenied.json": lambda: self._get("/users?$top=1&$select=id"),
            "api-invalid-token-401.json": lambda: self._get(
                _messages(tenant.RESTORETEST_UPN, "$top=1"), f"Bearer {MALFORMED_TOKEN}"
            ),
            "api-no-token-401.json": lambda: self._get(_messages(tenant.RESTORETEST_UPN, "$top=1"), None),
            "messages-404-unknown-user.json": lambda: self._get(_messages(nobody, "$top=1")),
        }
        return senders[file_name]()


def _first_id(file_name: str, source: str, replies: Mapping[str, HttpResponse]) -> str:
    """The ID of the first item listed in the reply `source`, if it may go in a URL path."""
    value = _json_object(replies[source]).get("value") if source in replies else None
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        raise FixtureError(f"{file_name}: needs an item from {source}, which had none")
    item_id = value[0].get("id")
    if not isinstance(item_id, str) or not _SAFE_ID.fullmatch(item_id):
        raise FixtureError(f"{file_name}: the ID from {source} can't go in a URL")
    return item_id


def _next_link(file_name: str, source: str, replies: Mapping[str, HttpResponse]) -> str:
    """The @odata.nextLink of the reply `source`. _get sends it only if it is on Graph v1.0."""
    link = _json_object(replies[source]).get("@odata.nextLink") if source in replies else None
    if not isinstance(link, str) or not link:
        raise FixtureError(f"{file_name}: needs a nextLink from {source}, which had none")
    return link


def _signing_key(pfx_path: Path, password: str) -> tuple[rsa.RSAPrivateKey, str]:
    certificate = load_pfx(pfx_path, password)
    key = serialization.load_pem_private_key(certificate.private_key_pem.encode("ascii"), None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CredentialError(f"{pfx_path} holds no RSA key; PS256 needs one. Re-create it with {SETUP_SCRIPT}.")
    cert = x509.load_pem_x509_certificate(certificate.certificate_pem.encode("ascii"))
    return key, b64url(cert.fingerprint(hashes.SHA256()))


def run_record(
    *,
    client_id: str,
    tenant_id: str,
    pfx_path: Path,
    read_password: Callable[[str], str | None],
    transport: Transport,
    out_dir: Path,
    out: Callable[[str], None] = print,
    clock: Callable[[], float] | None = None,
    other_key: rsa.RSAPrivateKey | None = None,
    state: str = "auth",
) -> int:
    """Records the fixtures of `state` (STATES). 0: every fixture written. 1: a reply had another
    status than its file name says, or not the content its state needs; nothing written.
    Credential and sign-in problems raise CredentialError/AuthError, a reply holding a secret,
    a request that needs what an earlier reply didn't give, or a link off Graph v1.0
    FixtureError, a lost connection TransportError; nothing is written then either. Prints one
    line per reply as it comes."""
    entries = plan(tenant_id, state)
    password = read_password(CREDENTIAL_TARGET)
    if not password:
        raise CredentialError(
            f"Credential Manager has no generic credential '{CREDENTIAL_TARGET}'. "
            f"{SETUP_SCRIPT} creates it together with the certificate."
        )
    key, x5t_s256 = _signing_key(pfx_path, password)
    now = (clock or _clock)()
    day = dt.datetime.fromtimestamp(now, tz=dt.timezone.utc).strftime("%Y-%m-%d")
    recorder = _Recorder(transport, client_id, tenant_id, key, x5t_s256, int(now), other_key or _new_key())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    key_lines = [line for line in key_pem.splitlines() if line and not line.startswith("-----")]

    token_reply = recorder.sign_in()  # every state; written only as auth's token-200.json
    replies: dict[str, HttpResponse] = {}
    texts: dict[str, str] = {}
    unexpected = 0
    for entry in entries:
        response = token_reply if entry.file_name == "token-200.json" else recorder.send(entry, replies)
        replies[entry.file_name] = response
        text = fixture_text(f"live {day}: {entry.what}", entry.request, _scrubbed(response))
        check_safe(entry.file_name, text, [password, *recorder.secrets, *key_lines])
        texts[entry.file_name] = text
        if response.status != entry.expected:
            problem: str | None = f"expected {entry.expected}"
        else:
            problem = entry.check(response) if entry.check else None
        unexpected += problem is not None
        line = f"{entry.file_name:<42}  {response.status}  {_error_code(response) or '-'}  "
        line += "ok" if problem is None else f"UNEXPECTED ({problem})"
        if entry.facts:
            line += "  " + entry.facts(response)
        out(line)

    if unexpected:
        out(f"nothing written: {unexpected} repl{'y was' if unexpected == 1 else 'ies were'} not as expected")
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in texts.items():
        with open(out_dir / name, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    out(f"wrote {len(texts)} fixtures to {out_dir}")
    return 0
