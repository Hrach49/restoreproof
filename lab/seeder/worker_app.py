"""`python -m seeder check-worker-app` (L1.5): prove what the RestoreProof Worker app can reach.

Signs in as the Worker's own app registration with its certificate (client credentials, no
user), then sends one GET per probe and compares the HTTP status with the expected one: 200
where L1.5 granted access, 403 on what it didn't grant, and 404 where SharePoint hides items
around the one folder the app may read. It also asks for tokens for Exchange Online's and
SharePoint's own APIs, which must carry no roles, and signs in as alice (the seeder app,
delegated) to confirm her canary folder exists, so the app's 404 on it means "hidden", not
"gone". docs/security/graph-permissions.md says why each probe is there. The check only reads.

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
# The other APIs that reach mail or files if an admin consents a role on them (Exchange's
# full_access_as_app, SharePoint's Sites.Read.All). The Graph token doesn't show those roles.
OTHER_API_SCOPES = {
    "Exchange Online": ["https://outlook.office365.com/.default"],
    "SharePoint": [f"https://{tenant.SHAREPOINT_HOST}/.default"],
}
MSAL_TIMEOUT = 60  # seconds, like the Graph calls; MSAL's default waits forever
TARGET_FOLDER_NAME = "RestoreTarget"  # Veeam's OneDrive restore finds the folder by this name
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
            try:
                # The constructor already looks the tenant up over the network.
                self._app = msal.ConfidentialClientApplication(
                    self._client_id,
                    authority=f"https://login.microsoftonline.com/{self._tenant_id}",
                    # A PEM key with its public certificate: MSAL signs with PS256 and the SHA-256 thumbprint.
                    client_credential={
                        "private_key": self._certificate.private_key_pem,
                        "public_certificate": self._certificate.certificate_pem,
                    },
                    timeout=MSAL_TIMEOUT,
                )
            except Exception as exc:  # noqa: BLE001 - network, proxy or tenant errors: all "can't sign in"
                raise self._failed(exc) from None
        return self._app

    def _failed(self, exc: Exception) -> AuthError:
        message = f"Sign-in as the RestoreProof Worker app failed: {type(exc).__name__}: {exc}"
        return AuthError(_redact(message, self._secrets))

    def token(self, scopes: list[str] = GRAPH_SCOPES) -> str:
        app = self.app
        try:
            result = app.acquire_token_for_client(scopes=scopes)
        except Exception as exc:  # noqa: BLE001 - as above
            raise self._failed(exc) from None
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
    # For a listing: the one item (id, name) it must hold. The item missing or renamed, or
    # anything else listed, is unexpected.
    only_item: tuple[str, str] | None = None


_ONE_ID = {"$top": "1", "$select": "id"}


def probes() -> list[Probe]:
    """Every GET the check sends. 200: what the Worker needs, and the metadata SharePoint opens
    on the way to the granted OneDrive folder. 403: what it must not reach. 404: items SharePoint
    masks because the app may not see them (it answers "not found", not "forbidden")."""
    od, sp_site = tenant.ONEDRIVE_DRIVE_ID, tenant.SHAREPOINT_SITE_ID
    target, canary = tenant.ONEDRIVE_TARGET_FOLDER_ID, tenant.ONEDRIVE_FOLDER_ID
    return [
        Probe("restoretest's mailbox: list messages", f"/users/{tenant.RESTORETEST_UPN}/messages", 200, _ONE_ID),
        Probe("RestoreTest site: the site", f"/sites/{sp_site}", 200),
        Probe("RestoreTarget library: the drive", f"/drives/{tenant.RESTORE_TARGET_DRIVE_ID}", 200),
        Probe("RestoreTarget library: files in its root", f"/drives/{tenant.RESTORE_TARGET_DRIVE_ID}/root/children", 200, _ONE_ID),
        Probe("alice's OneDrive: RestoreTarget folder", f"/drives/{od}/items/{target}", 200),
        Probe("alice's OneDrive: files in RestoreTarget", f"/drives/{od}/items/{target}/children", 200, _ONE_ID),
        Probe("alice's OneDrive: the site (metadata)", f"/sites/{tenant.ONEDRIVE_HOST}:{tenant.ALICE_ONEDRIVE_SITE_PATH}", 200),
        Probe("alice's OneDrive: root folder (metadata)", f"/drives/{od}/root", 200),
        Probe(
            "alice's OneDrive: files in her root (only RestoreTarget)",
            f"/drives/{od}/root/children",
            200,
            {"$select": "id,name"},  # no $top: a page of one would hide anything else
            only_item=(target, TARGET_FOLDER_NAME),
        ),
        Probe("alice's mailbox: list messages", f"/users/{tenant.ALICE_UPN}/messages", 403, _ONE_ID),
        Probe("tenant root site: the site", f"/sites/{tenant.SHAREPOINT_HOST}", 403),
        Probe("tenant root site: its libraries (/drives)", f"/sites/{tenant.SHAREPOINT_HOST}/drives", 403),
        Probe("OneDrive host root site: the site", f"/sites/{tenant.ONEDRIVE_HOST}", 403),
        Probe("directory: list users", "/users", 403, _ONE_ID),
        Probe("alice's OneDrive: RestoreTest canary folder", f"/drives/{od}/items/{canary}", 404),
        Probe("alice's OneDrive: files in the RestoreTest canary folder", f"/drives/{od}/items/{canary}/children", 404, _ONE_ID),
    ]


@dataclass(frozen=True)
class ProbeResult:
    probe: Probe
    actual: int | None  # None: no HTTP response
    problem: str = ""  # what is wrong with a listing (probe.only_item)

    @property
    def ok(self) -> bool:
        return self.actual == self.probe.expected and not self.problem

    @property
    def note(self) -> str:
        return f"  ({self.problem})" if self.problem else ""


def run_probes(graph: GraphClient, items: list[Probe]) -> list[ProbeResult]:
    results = []
    for probe in items:
        problem = ""
        try:
            resp = graph.request("GET", probe.path, params=probe.params)
            actual: int | None = resp.status
            if probe.only_item is not None:
                problem = _listing_problem(resp, *probe.only_item)
        except GraphError as exc:
            actual = exc.status  # the message is not shown: the status is the evidence
        results.append(ProbeResult(probe, actual, problem))
    return results


def _listing_problem(resp: Any, item_id: str, name: str) -> str:
    """Empty when the listing holds exactly the item `item_id` named `name`, else what differs."""
    try:
        body = resp.json()
        items = [(item["id"], item.get("name")) for item in body["value"]]
    except (ValueError, KeyError, TypeError, AttributeError):
        return "listing can't be read"
    problems = []
    names = [n for i, n in items if i == item_id]
    if not names:
        problems.append(f"{name} not listed")
    elif names[0] != name:
        problems.append(f"{name} is named {names[0]!r}")
    others = sum(1 for i, _ in items if i != item_id) + (1 if body.get("@odata.nextLink") else 0)
    if others:
        problems.append(f"{others} other item{'s' if others != 1 else ''} listed")
    return "; ".join(problems)


def confirm_canary_folder(graph: GraphClient) -> tuple[bool, str]:
    """As alice: her RestoreTest canary folder exists and holds files. Without this, the app's
    404 on it could mean the folder is gone rather than hidden."""
    path = f"/drives/{tenant.ONEDRIVE_DRIVE_ID}/items/{tenant.ONEDRIVE_FOLDER_ID}"
    try:
        body = graph.request("GET", path, params={"$select": "id,name,folder"}).json()
    except GraphError as exc:
        return False, f"HTTP {exc.status if exc.status is not None else 'none'}"
    except ValueError:
        return False, "the answer can't be read"
    folder = body.get("folder") if isinstance(body, dict) else None
    children = folder.get("childCount") if isinstance(folder, dict) else None
    if not isinstance(children, int):
        return False, "not a folder"
    if children == 0:
        return False, "empty: run python -m seeder seed"
    return True, f"{body.get('name')}, {children} item{'s' if children != 1 else ''}"


# ---- the command ---------------------------------------------------------------------------


def run_check(
    *,
    client_id: str,
    tenant_id: str,
    pfx_path: Path,
    read_password: Callable[[str], str | None],
    transport: Transport,
    alice_token: Callable[[], str],
    app: Any = None,
    out: Callable[[str], None] = print,
    sleep: Callable[[float], None] | None = None,
) -> int:
    """0: every probe, every token's roles and the canary folder as expected. 1: anything
    unexpected. Credential and sign-in problems raise CredentialError/AuthError (the CLI exits 2).
    alice_token: alice's delegated Graph token (the seeder app), for one read of her canary folder."""
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
    other_tokens = {api: signin.token(scopes) for api, scopes in OTHER_API_SCOPES.items()}
    secrets.extend(other_tokens.values())

    def say(line: str) -> None:
        out(_redact(line, secrets))

    say("RestoreProof Worker app check (L1.5): app-only Microsoft Graph, GET only")
    say(f"tenant ID    {tenant_id}")
    say(f"client ID    {client_id}")
    say(f"certificate  SHA-1 thumbprint {certificate.thumbprint_sha1}, expires {certificate.not_after:%Y-%m-%d}")

    unexpected = 0
    checks = [("Microsoft Graph", token, EXPECTED_ROLES)]
    checks += [(api, api_token, frozenset()) for api, api_token in other_tokens.items()]
    for api, api_token, expected in checks:
        roles = token_roles(api_token)
        label = f"token roles, {api}"
        if roles is None:
            say(f"{label:<32}  (the token can't be read)  UNEXPECTED")
            unexpected += 1
        elif set(roles) == expected:
            say(f"{label:<32}  {', '.join(roles) or '(none)'}  ok")
        else:
            want = ", ".join(sorted(expected)) or "none"
            say(f"{label:<32}  {', '.join(roles) or '(none)'}  UNEXPECTED: expected exactly {want}")
            unexpected += 1

    alice = GraphClient(transport, alice_token, f"{tenant.ALICE_UPN} (seeder app)", sleep=sleep or _sleep)
    canary_ok, canary_note = confirm_canary_folder(alice)
    say(f"{'canary folder, read as alice':<32}  {canary_note}  {'ok' if canary_ok else 'UNEXPECTED'}")
    unexpected += 0 if canary_ok else 1
    say("")

    graph = GraphClient(transport, signin.token, "RestoreProof Worker (app-only)", sleep=sleep or _sleep)
    items = probes()
    results = run_probes(graph, items)
    say(f"{'result':<10}  {'expect':>6}  {'got':>6}  {'probe':<58}  request")
    for r in results:
        actual = "none" if r.actual is None else str(r.actual)
        verdict = "ok" if r.ok else "UNEXPECTED"
        say(f"{verdict:<10}  {r.probe.expected:>6}  {actual:>6}  {r.probe.label:<58}  GET {r.probe.path}{r.note}")
    passed = sum(r.ok for r in results)
    unexpected += len(results) - passed
    summary = f"{passed}/{len(results)} probes as expected"
    say(summary if unexpected == 0 else f"{summary}; {unexpected} UNEXPECTED")
    return 0 if unexpected == 0 else 1
