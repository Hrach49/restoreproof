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
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from seeder import REPO_DIR, cli, graph_fixtures, tenant
from seeder.auth import AuthError
from seeder.graph_fixtures import (
    DEFAULT_OUT_DIR,
    FAKE_ACCESS_TOKEN,
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

EXPECTED_FILES = {
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
        if path == f"/users/{tenant.RESTORETEST_UPN}/mailFolders/inbox/messages":
            return json_response(200, {"@odata.context": "ctx", "value": []}, {"request-id": "req-graph"})
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


def record(pfx_path, out_dir, cloud, *, other_key, read_password=None, transport=None):
    lines: list[str] = []
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
    assert {name: rec["status"] for name, rec in files.items()} == EXPECTED_FILES
    for name, rec in files.items():
        assert list(rec) == ["source", "request", "status", "headers", "body"], name
        assert rec["source"].startswith("live 2026-09-28: "), name
        assert re.search(rf"-{rec['status']}(-|\.json$)", name), name
    assert lines[-1] == f"wrote {len(EXPECTED_FILES)} fixtures to {tmp_path / 'out'}"


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


def test_the_plan_matches_the_committed_fixtures():
    """The file names, statuses and request lines agree with worker/tests/fixtures/graph/,
    so a re-recording replaces those files rather than adding new ones."""
    committed = DEFAULT_OUT_DIR
    if not committed.is_dir():
        pytest.skip("worker/tests/fixtures/graph/ not present")
    entries = plan(tenant.TENANT_ID)
    assert {e.file_name: e.expected for e in entries} == EXPECTED_FILES
    for entry in entries:
        path = committed / entry.file_name
        assert path.is_file(), f"planned fixture {entry.file_name} is not committed in {committed}"
        rec = json.loads(path.read_text(encoding="utf-8"))
        assert rec["status"] == entry.expected, entry.file_name
        assert rec["request"] == entry.request, entry.file_name
        assert rec["source"].split(": ", 1)[1] == entry.what, entry.file_name


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
    assert set(written(out)) == set(EXPECTED_FILES)
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
