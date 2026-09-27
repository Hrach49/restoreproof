"""`python -m seeder check-worker-app` (L1.5): prove what the RestoreProof Worker app can reach.

Signs in as the Worker's own app registration with its certificate (client credentials, no
user), then sends one GET per probe and compares the HTTP status with the expected one: 200
where L1.5 granted access, 403 everywhere else. docs/security/graph-permissions.md says why
each probe is there. The check only reads.

The certificate's private key is in a PFX file outside the repo; its password is a generic
credential in Windows Credential Manager. Neither, nor the token, is ever printed.
"""

import base64
import binascii
import datetime as dt
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

import msal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from seeder import tenant
from seeder.auth import AuthError
from seeder.graph import GraphClient, GraphError
from seeder.http import Transport

CLIENT_ID_ENV = "RP_LAB_WORKER_CLIENT_ID"
CREDENTIAL_TARGET = "RestoreProof Lab - Worker Graph app PFX"
PFX_NAME = "worker-graph.pfx"
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]
SETUP_SCRIPT = "lab/entra/new-worker-app.ps1"
# The Entra application permissions (the token's "roles") L1.5 consents to, and nothing else.
# Mail access comes from Exchange RBAC for Applications, which is not in the token.
EXPECTED_ROLES = frozenset({"Sites.Selected", "Files.SelectedOperations.Selected"})

_ERROR_NOT_FOUND = 1168
_sleep = time.sleep


class CredentialError(AuthError):
    """The Worker app's certificate or its password is missing or unusable."""


# ---- the credential ------------------------------------------------------------------------


@dataclass(frozen=True)
class Certificate:
    private_key_pem: str = field(repr=False)
    certificate_pem: str = field(repr=False)
    thumbprint_sha1: str  # upper-case hex, as Windows and the Entra portal show it
    not_after: dt.datetime


def default_pfx_path(env: Mapping[str, str] = os.environ) -> Path:
    base = env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "RestoreProof" / "lab" / PFX_NAME


def load_pfx(path: Path, password: str) -> Certificate:
    """The key and certificate from the PFX. Messages name the file, never the password."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        raise CredentialError(
            f"No certificate file at {path}. Create it with {SETUP_SCRIPT} (lab/README.md)."
        ) from None
    try:
        key, cert, _ = pkcs12.load_key_and_certificates(data, password.encode("utf-8"))
    except (ValueError, TypeError):
        # "from None": cryptography's exception carries nothing secret, but no chances.
        raise CredentialError(
            f"{path} can't be opened with the password in Credential Manager ('{CREDENTIAL_TARGET}'). "
            f"The file and the password must come from the same {SETUP_SCRIPT} run."
        ) from None
    if key is None or cert is None:
        raise CredentialError(f"{path} holds no private key and certificate pair. Re-create it with {SETUP_SCRIPT}.")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    return Certificate(
        private_key_pem=key_pem,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        thumbprint_sha1=cert.fingerprint(hashes.SHA1()).hex().upper(),  # noqa: S303 - an identifier, as Entra shows it
        not_after=cert.not_valid_after_utc,
    )


def read_generic_credential(target: str) -> str | None:
    """The password of a generic credential in Windows Credential Manager, or None if there is none."""
    if sys.platform != "win32":
        raise CredentialError("Credential Manager is Windows only: run check-worker-app on the Windows lab machine.")
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    cred_read = advapi32.CredReadW
    cred_read.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
    cred_read.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    pointer = ctypes.POINTER(CREDENTIAL)()
    if not cred_read(target, 1, 0, ctypes.byref(pointer)):  # 1 = CRED_TYPE_GENERIC
        error = ctypes.get_last_error()
        if error == _ERROR_NOT_FOUND:
            return None
        raise CredentialError(f"Credential Manager could not read '{target}' (Windows error {error}).")
    try:
        cred = pointer.contents
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
    finally:
        advapi32.CredFree(pointer)
    # PowerShell's CredWriteW and cmdkey store the password as UTF-16LE.
    return blob.decode("utf-16-le")


def resolve_worker_client_id(cli_value: str | None, env: Mapping[str, str] = os.environ) -> str:
    """--client-id, then RP_LAB_WORKER_CLIENT_ID, then tenant.WORKER_CLIENT_ID."""
    for value in (cli_value, env.get(CLIENT_ID_ENV), tenant.WORKER_CLIENT_ID):
        if value and value.strip():
            return value.strip()
    raise AuthError(
        "No client ID for the RestoreProof Worker app. Pass --client-id or set "
        f"{CLIENT_ID_ENV} ({SETUP_SCRIPT} prints it)."
    )


# ---- sign-in -------------------------------------------------------------------------------


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


class AppSignIn:
    """Client-credentials sign-in with the certificate. MSAL caches the token in memory only."""

    def __init__(self, client_id: str, tenant_id: str, certificate: Certificate, *, app: Any = None,
                 secrets: list[str] | None = None) -> None:
        self._client_id = client_id
        self._tenant_id = tenant_id
        self._certificate = certificate
        self._app = app
        self._secrets = list(secrets or [])

    def __repr__(self) -> str:
        return f"AppSignIn(client_id={self._client_id!r})"

    @property
    def app(self) -> Any:
        if self._app is None:
            self._app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=f"https://login.microsoftonline.com/{self._tenant_id}",
                # A PEM key with its public certificate: MSAL signs with PS256 and the SHA-256 thumbprint.
                client_credential={
                    "private_key": self._certificate.private_key_pem,
                    "public_certificate": self._certificate.certificate_pem,
                },
            )
        return self._app

    def token(self) -> str:
        result = self.app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        if "error" in result:
            # Only error and error_description: a result may also hold a token.
            error = result.get("error") or "unknown_error"
            description = result.get("error_description") or ""
            message = f"Sign-in as the RestoreProof Worker app failed: {error}: {description}".rstrip(": ")
            raise AuthError(_redact(message, self._secrets + [str(result.get("access_token") or "")]))
        token = result.get("access_token")
        if not token:
            raise AuthError("Sign-in as the RestoreProof Worker app returned no access token.")
        self._secrets.append(token)
        return token


def token_roles(token: str) -> list[str] | None:
    """The "roles" claim of a JWT access token, sorted, or None if the token can't be read.
    Only the claim is read and shown; the signature is not checked (Graph checks it)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, binascii.Error):
        return None
    roles = payload.get("roles", []) if isinstance(payload, dict) else None
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        return None
    return sorted(roles)


# ---- the probes ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Probe:
    label: str
    path: str
    expected: int
    params: Mapping[str, str] | None = None


_ONE_ID = {"$top": "1", "$select": "id"}


def probes() -> list[Probe]:
    """Every GET the check sends. 200: what the Worker needs. 403: what it must not reach."""
    od, sp_site = tenant.ONEDRIVE_DRIVE_ID, tenant.SHAREPOINT_SITE_ID
    return [
        Probe("restoretest's mailbox: list messages", f"/users/{tenant.RESTORETEST_UPN}/messages", 200, _ONE_ID),
        Probe("RestoreTest site: the site", f"/sites/{sp_site}", 200),
        Probe("RestoreTarget library: the drive", f"/drives/{tenant.RESTORE_TARGET_DRIVE_ID}", 200),
        Probe("RestoreTarget library: files in its root", f"/drives/{tenant.RESTORE_TARGET_DRIVE_ID}/root/children", 200, _ONE_ID),
        Probe("alice's OneDrive: RestoreTarget folder", f"/drives/{od}/items/{tenant.ONEDRIVE_TARGET_FOLDER_ID}", 200),
        Probe("alice's OneDrive: files in RestoreTarget", f"/drives/{od}/items/{tenant.ONEDRIVE_TARGET_FOLDER_ID}/children", 200, _ONE_ID),
        Probe("alice's mailbox: list messages", f"/users/{tenant.ALICE_UPN}/messages", 403, _ONE_ID),
        Probe("tenant root site: the site", f"/sites/{tenant.SHAREPOINT_HOST}", 403),
        Probe("tenant root site: its libraries (/drives)", f"/sites/{tenant.SHAREPOINT_HOST}/drives", 403),
        Probe("alice's OneDrive: the site", f"/sites/{tenant.ONEDRIVE_HOST}:{tenant.ALICE_ONEDRIVE_SITE_PATH}", 403),
        Probe("alice's OneDrive: root", f"/drives/{od}/root", 403),
        Probe("alice's OneDrive: RestoreTest canary folder", f"/drives/{od}/items/{tenant.ONEDRIVE_FOLDER_ID}", 403),
        Probe("directory: list users", "/users", 403, _ONE_ID),
    ]


@dataclass(frozen=True)
class ProbeResult:
    probe: Probe
    actual: int | None  # None: no HTTP response

    @property
    def ok(self) -> bool:
        return self.actual == self.probe.expected


def run_probes(graph: GraphClient, items: list[Probe]) -> list[ProbeResult]:
    results = []
    for probe in items:
        try:
            actual: int | None = graph.request("GET", probe.path, params=probe.params).status
        except GraphError as exc:
            actual = exc.status  # the message is not shown: the status is the evidence
        results.append(ProbeResult(probe, actual))
    return results


# ---- the command ---------------------------------------------------------------------------


def run_check(
    *,
    client_id: str,
    tenant_id: str,
    pfx_path: Path,
    read_password: Callable[[str], str | None],
    transport: Transport,
    app: Any = None,
    out: Callable[[str], None] = print,
    sleep: Callable[[float], None] | None = None,
) -> int:
    """0: every probe and the token's roles as expected. 1: anything unexpected. Credential and
    sign-in problems raise CredentialError/AuthError (the CLI exits 2)."""
    password = read_password(CREDENTIAL_TARGET)
    if not password:
        raise CredentialError(
            f"Credential Manager has no generic credential '{CREDENTIAL_TARGET}'. "
            f"{SETUP_SCRIPT} creates it together with the certificate."
        )
    certificate = load_pfx(pfx_path, password)
    secrets = [password]
    signin = AppSignIn(client_id, tenant_id, certificate, app=app, secrets=secrets)
    token = signin.token()
    secrets.append(token)

    def say(line: str) -> None:
        out(_redact(line, secrets))

    say("RestoreProof Worker app check (L1.5): app-only Microsoft Graph, GET only")
    say(f"tenant ID    {tenant_id}")
    say(f"client ID    {client_id}")
    say(f"certificate  SHA-1 thumbprint {certificate.thumbprint_sha1}, expires {certificate.not_after:%Y-%m-%d}")

    roles = token_roles(token)
    roles_ok = roles is not None and set(roles) == EXPECTED_ROLES
    if roles is None:
        say("token roles  (the token can't be read)  UNEXPECTED")
    elif roles_ok:
        say(f"token roles  {', '.join(roles) or '(none)'}  ok")
    else:
        say(f"token roles  {', '.join(roles) or '(none)'}  UNEXPECTED: expected exactly {', '.join(sorted(EXPECTED_ROLES))}")
    say("")

    graph = GraphClient(transport, signin.token, "RestoreProof Worker (app-only)", sleep=sleep or _sleep)
    items = probes()
    results = run_probes(graph, items)
    say(f"{'result':<10}  {'expect':>6}  {'got':>6}  {'probe':<44}  request")
    for r in results:
        actual = "none" if r.actual is None else str(r.actual)
        verdict = "ok" if r.ok else "UNEXPECTED"
        say(f"{verdict:<10}  {r.probe.expected:>6}  {actual:>6}  {r.probe.label:<44}  GET {r.probe.path}")
    passed = sum(r.ok for r in results)
    unexpected = len(results) - passed + (0 if roles_ok else 1)
    summary = f"{passed}/{len(results)} probes as expected"
    say(summary if unexpected == 0 else f"{summary}; {unexpected} UNEXPECTED")
    return 0 if unexpected == 0 else 1
