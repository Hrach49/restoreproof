"""record-graph-fixtures (W2.1): the Worker's recorded Graph and Entra responses, scrubbed.

Everything here runs against a fake Entra and a fake Graph behind the Transport seam. The fake
Entra checks each client assertion the way the real one does (PS256 signature by the app's
certificate, x5t#S256, audience, issuer, lifetime), so these tests also prove the recorder
builds assertions Entra would accept.
"""

import base64
import datetime as dt
import json
import re
import uuid
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from seeder import REPO_DIR, cli, graph_fixtures, tenant
from seeder.auth import AuthError
from seeder.graph import MAIL_PREFER
from seeder.graph_fixtures import (
    DEFAULT_OUT_DIR,
    FAKE_ACCESS_TOKEN,
    STATES,
    FixtureError,
    client_assertion,
    fixture_text,
    kept_headers,
    plan,
    run_record,
)
from seeder.http import HttpResponse, TransportError
from seeder.worker_app import CREDENTIAL_TARGET, CredentialError
from tests.fake_graph import make_app_token
from tests.fake_transport import FakeTransport, RecordedRequest, json_response

CLIENT_ID = "11111111-2222-3333-4444-555555555555"
PASSWORD_SENTINEL = "pfx-password-SENTINEL-DO-NOT-LEAK"
TOKEN_SENTINEL = "token-signature-SENTINEL-DO-NOT-LEAK-" + "x" * 40
NOW = dt.datetime(2026, 9, 28, 12, 0, 0, tzinfo=dt.timezone.utc).timestamp()
LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com/v1.0"

AUTH_FILES = {
    "token-200.json": 200,
    "token-bad-signature-401.json": 401,
    "token-unknown-thumbprint-401.json": 401,
    "token-unknown-app-400.json": 400,
    "token-unknown-tenant-400.json": 400,
    "token-expired-assertion-401.json": 401,
    "token-future-assertion-401.json": 401,
    "messages-200.json": 200,
    "messages-403-exchange.json": 403,
    "site-403-accessdenied.json": 403,
    "users-403-requestdenied.json": 403,
    "api-invalid-token-401.json": 401,
    "api-no-token-401.json": 401,
    "messages-404-unknown-user.json": 404,
}
# Per state, in the order recorded.
EXPECTED_FILES = {
    "auth": AUTH_FILES,
    "empty": {
        "mail-list-200-empty.json": 200,
        "restoretarget-drive-200.json": 200,
        "restoretarget-children-200-empty.json": 200,
        "onedrive-folder-200.json": 200,
        "onedrive-children-200-empty.json": 200,
        "onedrive-folder-404-itemnotfound.json": 404,
        "drive-404-itemnotfound.json": 404,
    },
    "one-item": {
        "mail-list-200-one-item.json": 200,
        "restoretarget-children-200-one-item.json": 200,
        "restoretarget-content-302.json": 302,
        "onedrive-children-200-one-item.json": 200,
        "onedrive-content-302.json": 302,
    },
    "paged": {
        "mail-list-200-page1.json": 200,
        "mail-list-200-page2.json": 200,
    },
}
RT = tenant.RESTORE_TARGET_DRIVE_ID
OD = tenant.ONEDRIVE_DRIVE_ID
FOLDER = tenant.ONEDRIVE_TARGET_FOLDER_ID
UPN = tenant.RESTORETEST_UPN
MAIL_SELECT = "$select=id,subject,from,receivedDateTime,internetMessageId,body"
CHILD_SELECT = "$select=id,name,size,file,folder&$top=200"
TEMPAUTH_SENTINEL = "v1.eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
CONTENT_LOCATION = (
    "https://restoreprooflab.sharepoint.com/sites/RestoreTest/_layouts/15/download.aspx"
    f"?UniqueId=u&tempauth={TEMPAUTH_SENTINEL}&Extra=secret&ApiVersion=2.0"
)


def a_message(n: int) -> dict:
    return {
        "id": f"AAMkAG{n}xyz_-A=",
        "subject": f"subject {n}",
        "from": {"emailAddress": {"name": "a", "address": "a@x.example"}},
        "receivedDateTime": "2026-09-28T10:00:00Z",
        "internetMessageId": f"<m{n}@x.example>",
    }


def a_file(n: int) -> dict:
    return {
        "@microsoft.graph.downloadUrl": CONTENT_LOCATION,
        "id": f"01FILE{n}ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "name": f"file{n}.txt",
        "size": 12,
        "file": {"mimeType": "text/plain"},
    }


# ---- fixtures ------------------------------------------------------------------------------


def _self_signed(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RestoreProof Worker (test)")])
    start = dt.datetime(2026, 9, 27, tzinfo=dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


@pytest.fixture(scope="module")
def key_and_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, _self_signed(key)


@pytest.fixture(scope="module")
def other_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def pfx(tmp_path, key_and_cert) -> Path:
    key, cert = key_and_cert
    data = pkcs12.serialize_key_and_certificates(
        b"rp-worker", key, cert, None, serialization.BestAvailableEncryption(PASSWORD_SENTINEL.encode())
    )
    path = tmp_path / "worker-graph.pfx"
    path.write_bytes(data)
    return path


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def entra_error(status: int, error: str, code: int, text: str) -> HttpResponse:
    return json_response(
        status,
        {
            "error": error,
            "error_description": f"AADSTS{code}: {text}. Trace ID: t Correlation ID: c",
            "error_codes": [code],
            "trace_id": "t",
        },
        {"x-ms-request-id": "req-login", "set-cookie": "fpc=secret-cookie", "cache-control": "no-store"},
    )


def graph_error(status: int, code: str, message: str, extra: dict | None = None) -> HttpResponse:
    return json_response(
        status,
        {"error": {"code": code, "message": message}},
        {"request-id": "req-graph", "client-request-id": "req-graph", "strict-transport-security": "max-age=1", **(extra or {})},
    )


class FakeCloud:
    """Entra's token endpoint and the few Graph URLs the recorder reads, checking what arrives."""

    def __init__(self, cert, *, token: str | None = None, overrides: dict | None = None) -> None:
        self.cert = cert
        self.x5t256 = b64url(cert.fingerprint(hashes.SHA256()))
        self.token = token or make_app_token(CLIENT_ID, signature=TOKEN_SENTINEL)
        self.overrides = overrides or {}  # path (no query) -> response, for Graph
        self.inbox: list[dict] = []  # the restoretest inbox, as Graph lists it
        self.rt_children: list[dict] = []  # the RestoreTarget library's root
        self.od_children: list[dict] = []  # alice's /RestoreTarget
        self.drive_reply = {
            "@odata.context": "ctx",
            "id": RT,
            "driveType": "documentLibrary",
            "name": "RestoreTarget",
            "webUrl": "https://restoreprooflab.sharepoint.com/sites/RestoreTest/RestoreTarget",
            "sharePointIds": {"listId": tenant.RESTORE_TARGET_LIST_ID, "siteId": "s", "webId": "w"},
        }
        self.folder_reply = {
            "@odata.context": "ctx",
            "id": FOLDER,
            "name": "RestoreTarget",
            "parentReference": {"driveType": "business", "driveId": OD, "id": "01ROOT", "path": "/drive/root:"},
            "folder": {"childCount": 0},
        }
        self.body_content_type = "text"
        self.assertions: list[tuple[dict, dict]] = []
        self.problems: list[str] = []  # never assert on the handler's thread; collect instead
        self.transport = FakeTransport(handler=self.handle)

    @property
    def requests(self) -> list[RecordedRequest]:
        return self.transport.requests

    def handle(self, req: RecordedRequest) -> HttpResponse:
        if req.url.startswith(LOGIN):
            return self.token_endpoint(req)
        if req.url.startswith(GRAPH):
            return self.graph(req)
        self.problems.append(f"unexpected host: {req.method} {req.url}")
        return json_response(599, {})

    def token_endpoint(self, req: RecordedRequest) -> HttpResponse:
        if req.method != "POST":
            self.problems.append(f"token endpoint got {req.method}")
        form = {k: v[0] for k, v in parse_qs((req.body or b"").decode()).items()}
        if req.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            self.problems.append("token POST is not form-encoded")
        if form.get("grant_type") != "client_credentials" or form.get("scope") != "https://graph.microsoft.com/.default":
            self.problems.append(f"bad form: {sorted(form)}")
        if form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
            self.problems.append("bad client_assertion_type")
        head_b64, claims_b64, sig_b64 = form["client_assertion"].split(".")
        header, claims = json.loads(unb64url(head_b64)), json.loads(unb64url(claims_b64))
        self.assertions.append((header, claims))
        tenant_id = urlsplit(req.url).path.split("/")[1]
        if req.url != f"{LOGIN}/{tenant_id}/oauth2/v2.0/token" or claims.get("aud") != req.url:
            self.problems.append(f"aud {claims.get('aud')} vs {req.url}")
        if not (claims.get("iss") == claims.get("sub") == form.get("client_id")):
            self.problems.append("iss/sub/client_id differ")
        if header != {"alg": "PS256", "typ": "JWT", "x5t#S256": header.get("x5t#S256")}:
            self.problems.append(f"header {header}")
        if claims.get("exp", 0) - claims.get("nbf", 0) != 300 or claims.get("iat") != claims.get("nbf"):
            self.problems.append("lifetime is not 300 s from nbf = iat")
        if tenant_id != tenant.TENANT_ID:
            return entra_error(400, "invalid_request", 90002, f"Tenant '{tenant_id}' not found")
        if form.get("client_id") != CLIENT_ID:
            return entra_error(400, "unauthorized_client", 700016, "Application was not found in the directory")
        if header.get("x5t#S256") != self.x5t256:
            return entra_error(401, "invalid_client", 700027, "The certificate is not registered on application")
        try:
            self.cert.public_key().verify(
                unb64url(sig_b64),
                f"{head_b64}.{claims_b64}".encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return entra_error(401, "invalid_client", 700027, "Key was found, but use of the key to verify the signature failed")
        if not (claims["nbf"] - 300 <= NOW <= claims["exp"] + 300):
            return entra_error(401, "invalid_client", 700024, "Client assertion is not within its valid time range")
        return json_response(
            200,
            {"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": self.token},
            {"x-ms-request-id": "req-login", "set-cookie": "fpc=secret-cookie"},
        )

    def graph(self, req: RecordedRequest) -> HttpResponse:
        if req.method != "GET":
            self.problems.append(f"Graph got {req.method}")
        auth = req.headers.get("Authorization")
        path = urlsplit(req.url).path.removeprefix("/v1.0")
        if auth is None:
            return graph_error(401, "InvalidAuthenticationToken", "Access token is empty.", {"www-authenticate": 'Bearer realm=""'})
        if auth != f"Bearer {self.token}":
            return graph_error(401, "InvalidAuthenticationToken", "NoAppIdInToken", {"www-authenticate": 'Bearer realm=""'})
        if path in self.overrides:
            return self.overrides[path]
        query = {unquote(k): v[0] for k, v in parse_qs(urlsplit(req.url).query).items()}
        if path == f"/users/{tenant.RESTORETEST_UPN}/mailFolders/inbox/messages":
            top, skip = int(query.get("$top", "10")), int(query.get("$skip", "0"))
            value = self.inbox[skip : skip + top]
            if "body" in query.get("$select", "").split(","):
                body = {"contentType": self.body_content_type, "content": "hello\r\n"}
                value = [dict(m, body=body) if isinstance(m, dict) else m for m in value]
            page: dict = {"@odata.context": "ctx", "value": value}
            if skip + top < len(self.inbox):
                # As Graph does: the request's $select again, encoded.
                select = query.get("$select", "").replace(",", "%2c")
                page["@odata.nextLink"] = (
                    f"{GRAPH}/users/{UPN}/mailFolders/inbox/messages"
                    f"?%24select={select}&%24top={top}&%24skip={skip + top}"
                )
            return json_response(200, page, {"request-id": "req-graph"})
        if path == f"/drives/{RT}":
            return json_response(200, self.drive_reply, {"request-id": "req-graph"})
        if path == f"/drives/{RT}/root/children":
            return json_response(200, {"@odata.context": "ctx", "value": self.rt_children}, {"request-id": "req-graph"})
        if path == f"/drives/{OD}/items/{FOLDER}":
            return json_response(200, self.folder_reply, {"request-id": "req-graph"})
        if path == f"/drives/{OD}/items/{FOLDER}/children":
            return json_response(200, {"@odata.context": "ctx", "value": self.od_children}, {"request-id": "req-graph"})
        if re.fullmatch(r"/drives/[^/]+/items/[^/]+/content", path):
            return HttpResponse(302, b"", {"location": CONTENT_LOCATION, "request-id": "req-graph"})
        if re.fullmatch(r"/drives/[^/]+(/items/[^/]+)?", path):
            return graph_error(404, "itemNotFound", "The resource could not be found.")
        if path == f"/users/{tenant.ALICE_UPN}/mailFolders/inbox/messages":
            return graph_error(403, "ErrorAccessDenied", "Access is denied. Check credentials and try again.")
        if path == f"/sites/{tenant.SHAREPOINT_HOST}":
            return graph_error(403, "accessDenied", "Access denied")
        if path == "/users":
            return graph_error(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
        if re.fullmatch(rf"/users/nobody-[0-9a-f]{{8}}@{re.escape(tenant.TENANT_DOMAIN)}/mailFolders/inbox/messages", path):
            return graph_error(404, "ErrorInvalidUser", "The requested user is invalid.")
        self.problems.append(f"unexpected Graph path {path}")
        return graph_error(400, "BadRequest", "unexpected")


def password_store(value: str | None = PASSWORD_SENTINEL):
    reads: list[str] = []

    def read(target: str) -> str | None:
        reads.append(target)
        return value

    read.reads = reads  # type: ignore[attr-defined]
    return read


def record(pfx_path, out_dir, cloud, *, other_key, read_password=None, transport=None, state="auth", lines=None):
    lines = [] if lines is None else lines
    code = run_record(
        client_id=CLIENT_ID,
        tenant_id=tenant.TENANT_ID,
        pfx_path=pfx_path,
        read_password=read_password or password_store(),
        transport=transport or cloud.transport,
        out_dir=out_dir,
        out=lines.append,
        clock=lambda: NOW,
        other_key=other_key,
        state=state,
    )
    return code, lines


def written(out_dir: Path) -> dict[str, dict]:
    return {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(out_dir.glob("*.json"))}


# ---- failure paths -------------------------------------------------------------------------


def test_missing_credential_manager_entry_is_a_credential_error(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    with pytest.raises(CredentialError, match=re.escape(CREDENTIAL_TARGET)):
        record(pfx, tmp_path / "out", cloud, other_key=other_key, read_password=password_store(None))
    assert cloud.requests == []
    assert not (tmp_path / "out").exists()


def test_wrong_pfx_password_is_a_credential_error_that_never_names_the_password(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    with pytest.raises(CredentialError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key, read_password=password_store("wrong-SENTINEL"))
    assert "wrong-SENTINEL" not in str(info.value)
    assert cloud.requests == []


def test_a_failed_sign_in_is_an_auth_error_and_nothing_reaches_graph(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    cloud.x5t256 = "not-the-uploaded-certificate"
    with pytest.raises(AuthError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key)
    assert "401" in str(info.value) and "invalid_client" in str(info.value) and "700027" in str(info.value)
    assert not any(r.url.startswith(GRAPH) for r in cloud.requests)
    assert not (tmp_path / "out").exists()


def test_a_token_reply_without_a_token_is_an_auth_error(pfx, tmp_path, key_and_cert, other_key):
    reply = json_response(200, {"token_type": "Bearer", "expires_in": 3599})
    transport = FakeTransport(handler=lambda req: reply)
    with pytest.raises(AuthError, match="no access token"):
        record(pfx, tmp_path / "out", FakeCloud(key_and_cert[1]), other_key=other_key, transport=transport)
    assert len(transport.requests) == 1


def test_a_status_other_than_the_recorded_one_writes_nothing_and_exits_1(pfx, tmp_path, key_and_cert, other_key):
    # alice's mailbox suddenly readable: the 403 fixture would silently become a 200.
    ok = json_response(200, {"value": []}, {"request-id": "r"})
    cloud = FakeCloud(key_and_cert[1], overrides={f"/users/{tenant.ALICE_UPN}/mailFolders/inbox/messages": ok})
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key)
    assert code == 1
    assert not (tmp_path / "out").exists()
    assert any("messages-403-exchange.json" in line and "UNEXPECTED" in line and "200" in line for line in lines)
    assert lines[-1].startswith("nothing written")


def test_an_existing_fixture_is_left_alone_when_nothing_is_written(pfx, tmp_path, key_and_cert, other_key):
    out = tmp_path / "out"
    out.mkdir()
    (out / "messages-200.json").write_text("old", encoding="utf-8")
    cloud = FakeCloud(key_and_cert[1], overrides={"/users": json_response(200, {"value": []})})
    code, _ = record(pfx, out, cloud, other_key=other_key)
    assert code == 1
    assert (out / "messages-200.json").read_text(encoding="utf-8") == "old"


@pytest.mark.parametrize(
    "leak",
    [
        pytest.param("eyJ" + "A" * 37 + ".eyJzdWIiOiJ4In0.sig", id="a JWT"),
        pytest.param("eyJ" + "b" * 60, id="a long JWT-looking segment"),
        pytest.param("see client_assertion=abc", id="client_assertion"),
        pytest.param(PASSWORD_SENTINEL, id="the PFX password"),
    ],
)
def test_refuses_to_write_anything_that_looks_like_a_secret(pfx, tmp_path, key_and_cert, other_key, leak):
    body = {"error": {"code": "ErrorAccessDenied", "message": f"denied {leak}"}}
    override = json_response(403, body, {"request-id": "r"})
    cloud = FakeCloud(key_and_cert[1], overrides={f"/users/{tenant.ALICE_UPN}/mailFolders/inbox/messages": override})
    with pytest.raises(FixtureError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key)
    assert "messages-403-exchange.json" in str(info.value)
    assert leak not in str(info.value)
    assert not (tmp_path / "out").exists()


def test_the_real_access_token_echoed_anywhere_is_refused(pfx, tmp_path, key_and_cert, other_key):
    token = "opaque-token-SENTINEL-not-jwt-shaped"
    cloud = FakeCloud(key_and_cert[1], token=token)
    cloud.overrides["/users"] = graph_error(403, "Authorization_RequestDenied", f"token {token}")
    with pytest.raises(FixtureError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key)
    assert token not in str(info.value)


def test_a_real_jwt_in_a_header_is_refused(pfx, tmp_path, key_and_cert, other_key):
    jwt = "eyJ" + "Q" * 50 + ".eyJ4IjoxfQ.sig"
    override = json_response(200, {"value": []}, {"www-authenticate": f"Bearer {jwt}"})
    cloud = FakeCloud(key_and_cert[1], overrides={f"/users/{tenant.RESTORETEST_UPN}/mailFolders/inbox/messages": override})
    with pytest.raises(FixtureError):
        record(pfx, tmp_path / "out", cloud, other_key=other_key)


def test_a_transport_error_propagates_and_nothing_is_written(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])

    def handler(req):
        if "/sites/" in req.url:
            return TransportError("GET https://graph.microsoft.com/v1.0/sites/x: ConnectionError")
        return cloud.handle(req)

    with pytest.raises(TransportError):
        record(pfx, tmp_path / "out", cloud, other_key=other_key, transport=FakeTransport(handler=handler))
    assert not (tmp_path / "out").exists()


# ---- download links (W2.2) -----------------------------------------------------------------

FAKE_TEMPAUTH = "v1.eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DOWNLOAD_LOCATION = (
    "https://restoreprooflab.sharepoint.com/sites/RestoreTest/_layouts/15/download.aspx"
    f"?UniqueId=u&tempauth={FAKE_TEMPAUTH}&Extra=secret&ApiVersion=2.0"
)


def test_scrub_keeps_only_the_allowed_query_values_of_a_location():
    reply = HttpResponse(302, b"", {"location": DOWNLOAD_LOCATION + "&translate=false&TEMPAUTH%3D=x&bare"})
    scrubbed = graph_fixtures._scrubbed(reply)
    assert scrubbed.headers["location"] == (
        "https://restoreprooflab.sharepoint.com/sites/RestoreTest/_layouts/15/download.aspx"
        "?UniqueId=u&tempauth=SCRUBBED&Extra=SCRUBBED&ApiVersion=2.0&translate=false&TEMPAUTH%3D=SCRUBBED&bare=SCRUBBED"
    )
    assert scrubbed.status == 302


def test_scrub_drops_a_fragment_of_a_location():
    reply = HttpResponse(302, b"", {"location": "https://t.sharepoint.com/x?UniqueId=u#tempauth-ish"})
    assert graph_fixtures._scrubbed(reply).headers["location"] == "https://t.sharepoint.com/x?UniqueId=u"


def test_scrub_drops_download_urls_and_masks_tempauth_in_body_strings():
    body = {
        "value": [
            {
                "id": "1",
                "name": "a.txt",
                "@microsoft.graph.downloadUrl": DOWNLOAD_LOCATION,
                "nested": {"@microsoft.graph.downloadUrl": "x", "note": f"see ?tempauth={FAKE_TEMPAUTH}&b=1"},
            }
        ],
        "other": f"TempAuth%3D{FAKE_TEMPAUTH} end",
    }
    scrubbed = graph_fixtures._scrubbed(json_response(200, body))
    assert scrubbed.json() == {
        "value": [{"id": "1", "name": "a.txt", "nested": {"note": "see ?tempauth=SCRUBBED&b=1"}}],
        "other": "TempAuth%3DSCRUBBED end",
    }


def test_scrub_leaves_a_reply_without_links_as_it_was():
    reply = json_response(200, {"value": [{"id": "1", "size": 3}]}, {"request-id": "r"})
    assert graph_fixtures._scrubbed(reply) == reply


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(f'"Location": "{DOWNLOAD_LOCATION}"', id="header"),
        pytest.param('{"note": "download.aspx?UniqueId=u&tempauth=abc123"}', id="json"),
        pytest.param(f"tempauth={FAKE_TEMPAUTH}", id="v1.eyJ"),
        pytest.param("x?TEMPAUTH%3Dabc", id="encoded"),
        pytest.param('{"tempauth": "abc"}', id="json key"),
    ],
)
def test_check_safe_refuses_an_unscrubbed_tempauth(text):
    with pytest.raises(FixtureError) as info:
        graph_fixtures.check_safe("f.json", text, secrets=[])
    assert str(info.value) == "f.json: refused to write it: it holds a tempauth download credential"


@pytest.mark.parametrize(
    "query",
    ["UniqueId=u&Extra=secret", "sig=abc&ApiVersion=2.0", "UniqueId=u&token"],
)
def test_check_safe_refuses_an_unknown_download_query_value(query):
    text = f'"Location": "https://t.sharepoint.com/_layouts/15/download.aspx?{query}"'
    with pytest.raises(FixtureError) as info:
        graph_fixtures.check_safe("f.json", text, secrets=[])
    assert str(info.value) == "f.json: refused to write it: a download URL holds an unknown query value"


@pytest.mark.parametrize(
    "text",
    [
        "https://restoreprooflab.sharepoint.com/sites/RestoreTest/_layouts/15/download.aspx"
        "?UniqueId=SCRUBBED&Translate=false&tempauth=SCRUBBED&ApiVersion=2.0",
        '{"Location": "https://t-my.sharepoint.com/_layouts/15/download.aspx?uniqueid=u&tempauth=SCRUBBED"}',
        '{"tempauth": "SCRUBBED"}',
    ],
)
def test_check_safe_accepts_a_scrubbed_download_link(text):
    graph_fixtures.check_safe("f.json", text, secrets=[])


def test_a_scrubbed_location_passes_check_safe():
    text = fixture_text("live x: y", "GET /v1.0/z", graph_fixtures._scrubbed(HttpResponse(302, b"", {"location": DOWNLOAD_LOCATION})))
    graph_fixtures.check_safe("f.json", text, secrets=[])
    assert FAKE_TEMPAUTH not in text and "secret" not in text


# ---- the restore-target states (W2.2) ------------------------------------------------------


def a_cloud(key_and_cert, state: str) -> "FakeCloud":
    """A fake tenant whose restore targets are in `state`."""
    cloud = FakeCloud(key_and_cert[1])
    if state in ("one-item", "paged"):
        cloud.inbox = [a_message(1)] if state == "one-item" else [a_message(1), a_message(2)]
        cloud.rt_children = [a_file(1)]
        cloud.od_children = [a_file(2)]
    return cloud


def graph_requests(cloud: "FakeCloud") -> list[RecordedRequest]:
    return [r for r in cloud.requests if r.url.startswith(GRAPH)]


def test_plan_refuses_an_unknown_state():
    with pytest.raises(ValueError, match="unknown state 'full'"):
        plan(tenant.TENANT_ID, "full")


def test_auth_state_is_unchanged():
    assert STATES == ("auth", "empty", "one-item", "paged")
    assert plan(tenant.TENANT_ID) == plan(tenant.TENANT_ID, "auth")
    assert [e.file_name for e in plan(tenant.TENANT_ID)] == list(AUTH_FILES)
    assert all(e.state == "auth" and e.headers == () and e.follow_redirects for e in plan(tenant.TENANT_ID))


def test_every_w2_2_entry_names_its_state():
    for state in STATES:
        assert {e.state for e in plan(tenant.TENANT_ID, state)} == {state}


def test_empty_state_with_an_item_writes_nothing(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "empty")
    cloud.inbox = [a_message(1)]
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="empty")
    assert code == 1
    assert not (tmp_path / "out").exists()
    assert re.fullmatch(r"mail-list-200-empty\.json +200  -  UNEXPECTED \(expected 0 item\(s\), got 1\)", lines[0])
    assert lines[-1] == "nothing written: 1 reply was not as expected"


@pytest.mark.parametrize(
    "edit, problem",
    [
        (lambda c: c.drive_reply.update(name="RestoreTest"), "restoretarget-drive-200.json"),
        (lambda c: c.drive_reply.update(webUrl="https://t.sharepoint.com/sites/RestoreTest/RestoreTest"), "restoretarget-drive-200.json"),
        (lambda c: c.drive_reply.pop("webUrl"), "restoretarget-drive-200.json"),
        (lambda c: c.drive_reply.pop("sharePointIds"), "restoretarget-drive-200.json"),
        (lambda c: c.drive_reply["sharePointIds"].pop("webId"), "restoretarget-drive-200.json"),
        (lambda c: c.folder_reply.update(name="RestoreTest"), "onedrive-folder-200.json"),
        (lambda c: c.folder_reply.pop("folder"), "onedrive-folder-200.json"),
        (lambda c: c.folder_reply["parentReference"].update(driveId="b!other"), "onedrive-folder-200.json"),
        (lambda c: c.folder_reply.pop("parentReference"), "onedrive-folder-200.json"),
        (lambda c: c.rt_children.append(a_file(1)), "restoretarget-children-200-empty.json"),
        (lambda c: c.od_children.append(a_file(1)), "onedrive-children-200-empty.json"),
    ],
    ids=[
        "drive name",
        "drive url",
        "drive no url",
        "drive sharePointIds",
        "drive webId",
        "folder name",
        "folder facet",
        "folder drive",
        "folder parent",
        "library item",
        "folder item",
    ],
)
def test_empty_state_refuses_a_target_that_isnt_as_expected(pfx, tmp_path, key_and_cert, other_key, edit, problem):
    cloud = a_cloud(key_and_cert, "empty")
    edit(cloud)
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="empty")
    assert code == 1
    assert not (tmp_path / "out").exists()
    bad = [line for line in lines if "UNEXPECTED" in line]
    assert len(bad) == 1 and bad[0].startswith(problem), lines


def test_a_not_found_case_with_another_error_code_is_unexpected(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "empty")
    real = cloud.graph

    def graph(req):  # the random drive ID answered with another code
        path = urlsplit(req.url).path.removeprefix("/v1.0")
        if re.fullmatch(r"/drives/[^/]+", path) and path != f"/drives/{RT}":
            return graph_error(404, "ErrorItemNotFound", "gone")
        return real(req)

    cloud.graph = graph
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="empty")
    assert code == 1
    assert any(
        line.startswith("drive-404-itemnotfound.json") and "UNEXPECTED (error code 'ErrorItemNotFound', not 'itemNotFound')" in line
        for line in lines
    ), lines


def test_one_item_state_with_no_item_writes_nothing(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "empty")
    lines: list[str] = []
    with pytest.raises(FixtureError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item", lines=lines)
    assert str(info.value) == (
        "restoretarget-content-302.json: needs an item from restoretarget-children-200-one-item.json, which had none"
    )
    assert "UNEXPECTED (expected 1 item(s), got 0)" in lines[0]
    assert not (tmp_path / "out").exists()


def test_one_item_state_refuses_a_body_that_isnt_text(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")
    cloud.body_content_type = "html"
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    assert code == 1
    assert any(
        line.startswith("mail-list-200-one-item.json") and "UNEXPECTED (body.contentType is 'html', not text)" in line
        for line in lines
    ), lines


# Review of W2.2: the listing carries each body, so the paged pages are checked too.
def test_paged_state_refuses_a_body_that_isnt_text(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "paged")
    cloud.body_content_type = "html"
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="paged")
    assert code == 1
    assert any(
        line.startswith("mail-list-200-page1.json") and "UNEXPECTED (body.contentType is 'html', not text)" in line
        for line in lines
    ), lines


def test_one_item_state_refuses_a_folder_where_a_file_should_be(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")
    cloud.rt_children = [{"id": "01FOLDER", "name": "f", "size": 0, "folder": {"childCount": 0}}]
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    assert code == 1
    assert any(
        line.startswith("restoretarget-children-200-one-item.json") and "UNEXPECTED (the item is not a file)" in line
        for line in lines
    )


def test_a_content_reply_without_location_is_unexpected(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")
    cloud.overrides[f"/drives/{RT}/items/{a_file(1)['id']}/content"] = HttpResponse(302, b"", {"request-id": "r"})
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    assert code == 1
    assert any(line.startswith("restoretarget-content-302.json") and "UNEXPECTED (no Location header)" in line for line in lines)


@pytest.mark.parametrize("bad_id", ["../../users/alice", "a?b", "a b", "", 7])
def test_an_id_that_cant_go_in_a_url_is_refused(pfx, tmp_path, key_and_cert, other_key, bad_id):
    cloud = a_cloud(key_and_cert, "one-item")
    cloud.rt_children[0]["id"] = bad_id
    with pytest.raises(FixtureError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    assert str(info.value) == (
        "restoretarget-content-302.json: the ID from restoretarget-children-200-one-item.json can't go in a URL"
    )
    assert len(graph_requests(cloud)) == 2


def test_paged_state_without_a_next_link_writes_nothing(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")  # one mail only: no second page
    lines: list[str] = []
    with pytest.raises(FixtureError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key, state="paged", lines=lines)
    assert str(info.value) == "mail-list-200-page2.json: needs a nextLink from mail-list-200-page1.json, which had none"
    assert "UNEXPECTED (expected an @odata.nextLink on https://graph.microsoft.com/v1.0/)" in lines[0]
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/v1.0/users/x/messages?$skip=1",
        "https://graph.microsoft.com/beta/users/x/messages?$skip=1",
        "http://graph.microsoft.com/v1.0/users/x/messages?$skip=1",
        "https://graph.microsoft.com/v1.0.evil.example/x",
    ],
)
def test_a_next_link_off_graph_v1_is_refused(pfx, tmp_path, key_and_cert, other_key, link):
    cloud = a_cloud(key_and_cert, "paged")
    page = {"value": [a_message(1)], "@odata.nextLink": link}
    cloud.overrides[f"/users/{UPN}/mailFolders/inbox/messages"] = json_response(200, page)
    with pytest.raises(FixtureError) as info:
        record(pfx, tmp_path / "out", cloud, other_key=other_key, state="paged")
    assert str(info.value) == "refused to send a request that is not on https://graph.microsoft.com/v1.0/"
    assert len(graph_requests(cloud)) == 1
    assert all(r.url.startswith((GRAPH + "/", LOGIN + "/")) for r in cloud.requests)
    assert not (tmp_path / "out").exists()


def test_get_refuses_an_authorization_in_extra_headers(key_and_cert, other_key):
    transport = FakeTransport([])
    recorder = graph_fixtures._Recorder(transport, CLIENT_ID, tenant.TENANT_ID, key_and_cert[0], "x5t", int(NOW), other_key)
    for name in ("Authorization", "authorization"):
        with pytest.raises(ValueError, match="Authorization"):
            recorder._get("/users", headers=((name, "Bearer x"),))
    assert transport.requests == []


def test_content_is_requested_without_following_redirects(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")
    code, _ = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    assert code == 0, cloud.problems
    for req in graph_requests(cloud):
        assert req.follow_redirects is (not req.url.endswith("/content")), req.url
    assert sum(req.url.endswith("/content") for req in cloud.requests) == 2
    assert not any("sharepoint.com" in req.url for req in cloud.requests)


@pytest.mark.parametrize("state", ["empty", "one-item", "paged"])
def test_prefer_is_sent_on_mail_requests_only(pfx, tmp_path, key_and_cert, other_key, state):
    cloud = a_cloud(key_and_cert, state)
    code, _ = record(pfx, tmp_path / "out", cloud, other_key=other_key, state=state)
    assert code == 0, cloud.problems
    for req in graph_requests(cloud):
        is_mail = f"/users/{UPN}/" in req.url
        assert req.headers.get("Prefer") == (MAIL_PREFER if is_mail else None), req.url
        assert req.headers["Authorization"] == f"Bearer {cloud.token}"


def test_the_not_found_cases_use_random_ids_of_the_right_shape(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "empty")
    record(pfx, tmp_path / "out", cloud, other_key=other_key, state="empty")
    paths = [urlsplit(r.url).path for r in graph_requests(cloud)]
    folder = [p for p in paths if p.startswith(f"/v1.0/drives/{OD}/items/") and FOLDER not in p]
    assert len(folder) == 1 and re.fullmatch(r"/v1\.0/drives/[^/]+/items/01[A-Z2-7]{32}", folder[0])
    other = [p.removeprefix("/v1.0/drives/") for p in paths if re.fullmatch(r"/v1\.0/drives/[^/]+", p) and p != f"/v1.0/drives/{RT}"]
    assert len(other) == 1 and other[0].startswith("b!") and other[0] != RT
    raw, rt_raw = unb64url(other[0][2:]), unb64url(RT[2:])
    assert len(raw) == len(rt_raw) and raw[:-16] == rt_raw[:-16] and raw[-16:] != rt_raw[-16:]


@pytest.mark.parametrize("state", STATES)
def test_records_every_fixture_of_each_state(pfx, tmp_path, key_and_cert, other_key, state):
    cloud = a_cloud(key_and_cert, state)
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state=state)
    assert code == 0, (lines, cloud.problems)
    assert cloud.problems == []
    files = written(tmp_path / "out")
    assert list(files) == sorted(EXPECTED_FILES[state])
    assert [line.split()[0] for line in lines[:-1]] == list(EXPECTED_FILES[state])
    for name, rec in files.items():
        assert list(rec) == ["source", "request", "status", "headers", "body"], name
        assert rec["source"].startswith("live 2026-09-28: "), name
        assert rec["status"] == EXPECTED_FILES[state][name], name
        assert re.search(rf"-{rec['status']}(-|\.json$)", name), name
    requests = {e.file_name: e.request for e in plan(tenant.TENANT_ID, state)}
    assert {name: rec["request"] for name, rec in files.items()} == requests
    assert lines[-1] == f"wrote {len(EXPECTED_FILES[state])} fixtures to {tmp_path / 'out'}"


def test_the_request_lines_of_the_w2_2_states():
    requests = {e.file_name: e.request for s in STATES[1:] for e in plan(tenant.TENANT_ID, s)}
    mail = f"GET /v1.0/users/{UPN}/mailFolders/inbox/messages?{MAIL_SELECT}"
    assert requests == {
        "mail-list-200-empty.json": f"{mail}&$top=100",
        "restoretarget-drive-200.json": f"GET /v1.0/drives/{RT}?$select=id,name,driveType,webUrl,sharePointIds",
        "restoretarget-children-200-empty.json": f"GET /v1.0/drives/{RT}/root/children?{CHILD_SELECT}",
        "onedrive-folder-200.json": f"GET /v1.0/drives/{OD}/items/{FOLDER}?$select=id,name,folder,parentReference",
        "onedrive-children-200-empty.json": f"GET /v1.0/drives/{OD}/items/{FOLDER}/children?{CHILD_SELECT}",
        "onedrive-folder-404-itemnotfound.json": (
            f"GET /v1.0/drives/{OD}/items/<random item ID>?$select=id,name,folder,parentReference"
        ),
        "drive-404-itemnotfound.json": "GET /v1.0/drives/<random drive ID>?$select=id,name,driveType,webUrl,sharePointIds",
        "mail-list-200-one-item.json": f"{mail}&$top=100",
        "restoretarget-children-200-one-item.json": f"GET /v1.0/drives/{RT}/root/children?{CHILD_SELECT}",
        "restoretarget-content-302.json": f"GET /v1.0/drives/{RT}/items/<item id>/content",
        "onedrive-children-200-one-item.json": f"GET /v1.0/drives/{OD}/items/{FOLDER}/children?{CHILD_SELECT}",
        "onedrive-content-302.json": f"GET /v1.0/drives/{OD}/items/<item id>/content",
        "mail-list-200-page1.json": f"{mail}&$top=1",
        "mail-list-200-page2.json": "GET <@odata.nextLink of mail-list-200-page1.json>",
    }


def test_the_dependent_requests_use_the_ids_and_link_from_the_replies(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")
    record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    urls = [r.url for r in graph_requests(cloud)]
    assert not any("/messages/" in url for url in urls)
    assert f"{GRAPH}/drives/{RT}/items/{a_file(1)['id']}/content" in urls
    assert f"{GRAPH}/drives/{OD}/items/{a_file(2)['id']}/content" in urls
    paged = a_cloud(key_and_cert, "paged")
    record(pfx, tmp_path / "out2", paged, other_key=other_key, state="paged")
    second = graph_requests(paged)[1]
    select = MAIL_SELECT.removeprefix("$select=").replace(",", "%2c")
    assert second.url == f"{GRAPH}/users/{UPN}/mailFolders/inbox/messages?%24select={select}&%24top=1&%24skip=1"


def test_the_folder_and_drive_lines_print_the_facts_the_worker_needs(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "empty")
    _, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="empty")
    folder = next(line for line in lines if line.startswith("onedrive-folder-200.json"))
    assert folder.endswith("ok  parentReference.path=/drive/root:  parentReference.id=present")
    drive = next(line for line in lines if line.startswith("restoretarget-drive-200.json"))
    assert drive.endswith("ok  webUrl last segment=RestoreTarget  sharePointIds=present")
    del cloud.folder_reply["parentReference"]["path"], cloud.folder_reply["parentReference"]["id"]
    _, lines = record(pfx, tmp_path / "out2", cloud, other_key=other_key, state="empty")
    folder = next(line for line in lines if line.startswith("onedrive-folder-200.json"))
    assert folder.endswith("ok  parentReference.path=(absent)  parentReference.id=absent")


def test_a_tempauth_in_a_location_is_scrubbed_before_writing(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")
    code, _ = record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    assert code == 0
    files = written(tmp_path / "out")
    for name in ("restoretarget-content-302.json", "onedrive-content-302.json"):
        assert files[name]["headers"]["Location"] == (
            "https://restoreprooflab.sharepoint.com/sites/RestoreTest/_layouts/15/download.aspx"
            "?UniqueId=u&tempauth=SCRUBBED&Extra=SCRUBBED&ApiVersion=2.0"
        )
    everything = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "out").iterdir())
    assert TEMPAUTH_SENTINEL not in everything and "secret" not in everything


def test_a_download_url_in_a_body_is_dropped(pfx, tmp_path, key_and_cert, other_key):
    cloud = a_cloud(key_and_cert, "one-item")
    record(pfx, tmp_path / "out", cloud, other_key=other_key, state="one-item")
    files = written(tmp_path / "out")
    for name in ("restoretarget-children-200-one-item.json", "onedrive-children-200-one-item.json"):
        (item,) = files[name]["body"]["value"]
        assert "@microsoft.graph.downloadUrl" not in item
        assert item["file"] == {"mimeType": "text/plain"}


def test_the_w2_2_states_only_read_and_send_no_token_off_graph(pfx, tmp_path, key_and_cert, other_key):
    for state in STATES[1:]:
        cloud = a_cloud(key_and_cert, state)
        record(pfx, tmp_path / state, cloud, other_key=other_key, state=state)
        assert len([r for r in cloud.requests if r.method == "POST"]) == 1  # the sign-in only
        assert all(r.method == "GET" for r in graph_requests(cloud))
        assert all(r.url.startswith((GRAPH + "/", LOGIN + "/")) for r in cloud.requests)


def test_the_cli_passes_the_state(monkeypatch, pfx, tmp_path, key_and_cert, other_key, capsys):
    cloud = a_cloud(key_and_cert, "empty")
    monkeypatch.setattr(cli, "read_generic_credential", password_store())
    monkeypatch.setattr(cli, "RequestsTransport", lambda: cloud.transport)
    monkeypatch.setattr(graph_fixtures, "_clock", lambda: NOW)
    out = tmp_path / "out"
    args = ["record-graph-fixtures", "--state", "empty", "--client-id", CLIENT_ID, "--pfx", str(pfx), "--out", str(out)]
    assert cli.main(args) == 0, capsys.readouterr().err
    assert list(written(out)) == sorted(EXPECTED_FILES["empty"])
    assert cli.main(["record-graph-fixtures", "--state", "full"]) == 2


# ---- the assertions ------------------------------------------------------------------------


def test_every_assertion_is_ps256_with_x5t_s256_and_a_fresh_jti(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    code, _ = record(pfx, tmp_path / "out", cloud, other_key=other_key)
    assert code == 0
    assert cloud.problems == []
    assert len(cloud.assertions) == 7
    assert all(h["alg"] == "PS256" and h["typ"] == "JWT" and set(h) == {"alg", "typ", "x5t#S256"} for h, _ in cloud.assertions)
    jtis = [c["jti"] for _, c in cloud.assertions]
    assert len(set(jtis)) == len(jtis)
    assert all(uuid.UUID(j).version == 4 for j in jtis)


def test_client_assertion_claims(key_and_cert):
    key, cert = key_and_cert
    x5t = b64url(cert.fingerprint(hashes.SHA256()))
    text = client_assertion(key, x5t, client_id=CLIENT_ID, tenant_id=tenant.TENANT_ID, now=1_800_000_000)
    head, claims, sig = text.split(".")
    assert json.loads(unb64url(head)) == {"alg": "PS256", "typ": "JWT", "x5t#S256": x5t}
    body = json.loads(unb64url(claims))
    assert body["aud"] == f"{LOGIN}/{tenant.TENANT_ID}/oauth2/v2.0/token"
    assert body["iss"] == body["sub"] == CLIENT_ID
    assert body["nbf"] == body["iat"] == 1_800_000_000
    assert body["exp"] == 1_800_000_300
    cert.public_key().verify(
        unb64url(sig),
        f"{head}.{claims}".encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def test_the_error_cases_vary_one_thing_each(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    record(pfx, tmp_path / "out", cloud, other_key=other_key)
    nbfs = [c["nbf"] for _, c in cloud.assertions]
    # token, bad signature, unknown thumbprint, unknown app, unknown tenant, expired, future
    assert nbfs == [int(NOW)] * 5 + [int(NOW) - 3600, int(NOW) + 3600]
    assert cloud.assertions[2][0]["x5t#S256"] == b64url(b"\x01" * 32)
    assert cloud.assertions[3][1]["iss"] != CLIENT_ID
    assert cloud.assertions[4][1]["aud"] != f"{LOGIN}/{tenant.TENANT_ID}/oauth2/v2.0/token"


# ---- what is written -----------------------------------------------------------------------


def test_records_every_fixture_under_its_name_with_the_expected_status(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    code, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key)
    assert code == 0
    files = written(tmp_path / "out")
    assert {name: rec["status"] for name, rec in files.items()} == AUTH_FILES
    for name, rec in files.items():
        assert list(rec) == ["source", "request", "status", "headers", "body"], name
        assert rec["source"].startswith("live 2026-09-28: "), name
        assert re.search(rf"-{rec['status']}(-|\.json$)", name), name
    assert lines[-1] == f"wrote {len(AUTH_FILES)} fixtures to {tmp_path / 'out'}"


def test_the_token_is_replaced_by_the_fake_unsigned_jwt(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    record(pfx, tmp_path / "out", cloud, other_key=other_key)
    body = written(tmp_path / "out")["token-200.json"]["body"]
    assert body["access_token"] == FAKE_ACCESS_TOKEN
    assert body["token_type"] == "Bearer" and body["expires_in"] == 3599
    assert FAKE_ACCESS_TOKEN.endswith(".") and FAKE_ACCESS_TOKEN.count(".") == 2  # alg none, no signature
    everything = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "out").iterdir())
    assert TOKEN_SENTINEL not in everything
    assert "client_assertion" not in everything
    assert "secret-cookie" not in everything


def test_request_lines_hide_the_random_parts(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    record(pfx, tmp_path / "out", cloud, other_key=other_key)
    files = written(tmp_path / "out")
    assert files["token-200.json"]["request"] == f"POST /{tenant.TENANT_ID}/oauth2/v2.0/token"
    assert files["token-unknown-tenant-400.json"]["request"] == "POST /<random GUID>/oauth2/v2.0/token"
    assert files["messages-404-unknown-user.json"]["request"] == (
        f"GET /v1.0/users/nobody-…@{tenant.TENANT_DOMAIN}/mailFolders/inbox/messages?$top=1"
    )
    assert files["messages-200.json"]["request"] == (
        f"GET /v1.0/users/{tenant.RESTORETEST_UPN}/mailFolders/inbox/messages?$top=1&$select=id"
    )


def test_only_the_kept_headers_survive_with_their_usual_spelling():
    headers = {
        "content-type": "application/json",
        "strict-transport-security": "x",
        "set-cookie": "fpc=1",
        "request-id": "a",
        "client-request-id": "b",
        "www-authenticate": 'Bearer realm=""',
        "x-ms-request-id": "c",
        "retry-after": "5",
        "location": "https://example.invalid/",
        "x-ms-ags-diagnostic": "{}",
    }
    assert kept_headers(headers) == {
        "Content-Type": "application/json",
        "request-id": "a",
        "client-request-id": "b",
        "WWW-Authenticate": 'Bearer realm=""',
        "x-ms-request-id": "c",
        "Retry-After": "5",
        "Location": "https://example.invalid/",
    }


def test_a_body_that_is_not_json_is_kept_as_text_and_an_empty_one_as_null():
    text = fixture_text("live x: y", "GET /v1.0/z", HttpResponse(503, b"<html>busy</html>", {"content-type": "text/html"}))
    assert json.loads(text)["body"] == "<html>busy</html>"
    assert json.loads(fixture_text("live x: y", "GET /v1.0/z", HttpResponse(204, b"", {})))["body"] is None


def test_fixture_text_is_indented_utf8_with_a_final_newline():
    text = fixture_text("live x: y", "GET /v1.0/users/nobody-…@x", HttpResponse(404, b'{"a": 1}', {}))
    assert text.endswith("}\n")
    assert "nobody-…" in text
    assert '\n  "status": 404,' in text


def test_the_graph_calls_only_read_and_tokens_go_only_to_login(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    record(pfx, tmp_path / "out", cloud, other_key=other_key)
    for req in cloud.requests:
        if req.method == "POST":
            assert req.url.startswith(f"{LOGIN}/") and req.url.endswith("/oauth2/v2.0/token")
            assert "Authorization" not in req.headers
        else:
            assert req.method == "GET" and req.url.startswith(f"{GRAPH}/")


def test_no_output_line_holds_a_secret(pfx, tmp_path, key_and_cert, other_key):
    cloud = FakeCloud(key_and_cert[1])
    _, lines = record(pfx, tmp_path / "out", cloud, other_key=other_key)
    text = "\n".join(lines)
    assert PASSWORD_SENTINEL not in text and TOKEN_SENTINEL not in text and "eyJ" not in text
    assert any(line.startswith("token-bad-signature-401.json") and "700027" in line for line in lines)
    assert any(line.startswith("messages-403-exchange.json") and "ErrorAccessDenied" in line for line in lines)


STAND_IN = "hand-written: stand-in"


@pytest.mark.parametrize("state", STATES)
def test_the_plan_of_each_state_names_the_expected_files(state):
    assert {e.file_name: e.expected for e in plan(tenant.TENANT_ID, state)} == EXPECTED_FILES[state]


@pytest.mark.parametrize(
    "state, entry",
    [(s, e) for s in STATES for e in plan(tenant.TENANT_ID, s)],
    ids=[f"{s}:{e.file_name}" for s in STATES for e in plan(tenant.TENANT_ID, s)],
)
def test_the_plan_matches_the_committed_fixtures(state, entry):
    """The file names, statuses and request lines agree with worker/tests/fixtures/graph/,
    so a re-recording replaces those files rather than adding new ones. A hand-written
    stand-in, committed until its state is recorded, is skipped; a missing file fails."""
    committed = DEFAULT_OUT_DIR
    if not committed.is_dir():
        pytest.skip("worker/tests/fixtures/graph/ not present")
    path = committed / entry.file_name
    assert path.is_file(), f"planned fixture {entry.file_name} is not committed in {committed}"
    rec = json.loads(path.read_text(encoding="utf-8"))
    if rec["source"].startswith(STAND_IN):
        pytest.skip(f"{entry.file_name}: stand-in until the {state} state is recorded")
    assert rec["status"] == entry.expected, entry.file_name
    assert rec["request"] == entry.request, entry.file_name
    assert rec["source"].split(": ", 1)[1] == entry.what, entry.file_name


_README_ROW = re.compile(r"^\| `([^`]+\.json)` \| ([^|]*?) \|")


def readme_rows(text: str) -> list[tuple[str, str]]:
    """(file, Source column) of every row of the README's "Files" table."""
    return [(m.group(1), m.group(2)) for line in text.splitlines() if (m := _README_ROW.match(line))]


def test_readme_rows_parse():
    text = "| Fixture | Source | For |\n|---|---|---|\n| `a.json` | live: x `y` | z |\n| `b.json` | hand-written: stand-in q | r |\nno"
    assert readme_rows(text) == [("a.json", "live: x `y`"), ("b.json", "hand-written: stand-in q")]


def test_the_fixture_readme_lists_every_file():
    if not DEFAULT_OUT_DIR.is_dir():
        pytest.skip("worker/tests/fixtures/graph/ not present")
    rows = readme_rows((DEFAULT_OUT_DIR / "README.md").read_text(encoding="utf-8"))
    names = [name for name, _ in rows]
    files = sorted(p.name for p in DEFAULT_OUT_DIR.glob("*.json"))
    assert sorted(set(names)) == sorted(names), "a file has more than one README row"
    assert [n for n in names if not (DEFAULT_OUT_DIR / n).is_file()] == [], "README rows naming no committed file"
    assert [f for f in files if f not in names] == [], "committed fixtures without a README row"
    for name, source in rows:
        rec = json.loads((DEFAULT_OUT_DIR / name).read_text(encoding="utf-8"))
        kind = rec["source"].split(" ", 1)[0].rstrip(":")
        assert source.split(" ", 1)[0].rstrip(":") == kind, f"{name}: README says {source!r}, the file {kind!r}"
        if rec["source"].startswith(STAND_IN):
            assert source.startswith(STAND_IN), f"{name} is a stand-in; its README row must say so"


def test_the_committed_live_fixtures_pass_the_scrub_check():
    if not DEFAULT_OUT_DIR.is_dir():
        pytest.skip("worker/tests/fixtures/graph/ not present")
    for path in DEFAULT_OUT_DIR.glob("*.json"):
        graph_fixtures.check_safe(path.name, path.read_text(encoding="utf-8"), secrets=[])


# ---- the command line ----------------------------------------------------------------------


def test_default_out_dir_is_the_worker_graph_fixtures():
    assert DEFAULT_OUT_DIR == REPO_DIR / "worker" / "tests" / "fixtures" / "graph"


def test_cli_records_into_out(monkeypatch, pfx, tmp_path, key_and_cert, other_key, capsys):
    cloud = FakeCloud(key_and_cert[1])
    read = password_store()
    monkeypatch.setattr(cli, "read_generic_credential", read)
    monkeypatch.setattr(cli, "RequestsTransport", lambda: cloud.transport)
    monkeypatch.setattr(graph_fixtures, "_new_key", lambda: other_key)
    monkeypatch.setattr(graph_fixtures, "_clock", lambda: NOW)
    out = tmp_path / "out"
    code = cli.main(["record-graph-fixtures", "--client-id", CLIENT_ID, "--pfx", str(pfx), "--out", str(out)])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert read.reads == [CREDENTIAL_TARGET]
    assert set(written(out)) == set(AUTH_FILES)
    assert PASSWORD_SENTINEL not in captured.out + captured.err
    assert TOKEN_SENTINEL not in captured.out + captured.err


def test_cli_refusal_is_one_line_exit_2(monkeypatch, pfx, tmp_path, key_and_cert, other_key, capsys):
    cloud = FakeCloud(key_and_cert[1])
    cloud.overrides["/users"] = graph_error(403, "Authorization_RequestDenied", "client_assertion here")
    monkeypatch.setattr(cli, "read_generic_credential", password_store())
    monkeypatch.setattr(cli, "RequestsTransport", lambda: cloud.transport)
    monkeypatch.setattr(graph_fixtures, "_new_key", lambda: other_key)
    monkeypatch.setattr(graph_fixtures, "_clock", lambda: NOW)
    code = cli.main(["record-graph-fixtures", "--client-id", CLIENT_ID, "--pfx", str(pfx), "--out", str(tmp_path / "o")])
    err = capsys.readouterr().err
    assert code == 2
    assert err.startswith("error: ") and len(err.strip().splitlines()) == 1
    assert "users-403-requestdenied.json" in err
    assert "Traceback" not in err


def test_cli_missing_credential_exits_2(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "read_generic_credential", lambda target: None)
    code = cli.main(["record-graph-fixtures", "--client-id", CLIENT_ID, "--pfx", str(tmp_path / "x.pfx")])
    assert code == 2
    assert CREDENTIAL_TARGET in capsys.readouterr().err
