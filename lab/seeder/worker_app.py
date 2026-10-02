"""`python -m seeder check-worker-app` (L1.5, W3.4): prove what the RestoreProof Worker app can reach.

Signs in as the Worker's own app registration with its certificate (client credentials, no
user), then sends one request per probe and compares the HTTP status with the expected one:
200 where L1.5 granted read access, 403 on what it didn't grant, and 404 where SharePoint hides
items around the one folder the app may read. It also asks for tokens for Exchange Online's and
SharePoint's own APIs, which must carry no roles, and signs in as alice and the admin (the
seeder app, delegated) to confirm her canary folder and one canary file in each canary location
exist, so the app's 404 on them means "hidden", not "gone". docs/security/graph-permissions.md
says why each probe is there.

W3.4 added writes, in two kinds only. In each of the three restore targets it creates one item
named rp-probe-<uuid> and deletes it again (201, then 204): the Cleaner's grants work. And at one
canary file in the RestoreTest library and one in alice's /RestoreTest folder it sends a PATCH
with an empty body and an If-Match no item has, which must be refused (403 or 404) and could
change nothing even if it were let through (412). Nothing else is ever written, and nothing is
ever deleted outside a restore target.

The certificate's private key is in a PFX file outside the repo; its password is a generic
credential in Windows Credential Manager. Neither, nor the token, is ever printed.
"""

import base64
import binascii
import datetime as dt
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

import msal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from seeder import MANIFEST_PATH, tenant
from seeder.auth import AuthError
from seeder.catalog import CanaryFile, canary_files
from seeder.graph import GraphClient, GraphError, get_item_by_path, seg
from seeder.http import HttpResponse, Transport

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
# The Entra application permissions (the token's "roles") L1.5 and W3.4 consent to, and nothing
# else. Mail access comes from Exchange RBAC for Applications, which is not in the token.
EXPECTED_ROLES = frozenset({"Sites.Selected", "Files.SelectedOperations.Selected", "Lists.SelectedOperations.Selected"})

# ---- W3.4's write probes
PROBE_PREFIX = "rp-probe-"
PROBE_FILE_BODY = b"RestoreProof check-worker-app write probe (W3.4). Safe to delete.\n"
# The refusal probes' If-Match: no item has this ETag, so even a PATCH let through changes nothing.
NO_SUCH_ETAG = '"rp-probe-no-such-etag"'
# The Worker reads and deletes mail by ImmutableId (W3.4, point 3): the probe does the same.
IMMUTABLE_ID = 'IdType="ImmutableId"'
# A Graph item or message ID, as the Worker accepts one (letters, digits and "!-_=").
_ITEM_ID = re.compile(r"[A-Za-z0-9!_=-]{1,512}")

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
    # W3.4: the write probes' request. A create is not idempotent: after no answer it isn't sent again.
    method: str = "GET"
    headers: Mapping[str, str] | None = None
    json_body: Any = None
    body: bytes | None = None
    idempotent: bool = True
    # Other statuses that pass too: a refusal may be 403 or SharePoint's masking 404.
    also_ok: tuple[int, ...] = ()
    # W3.4: a delete's item, as the create's reply proved it (WriteTarget.delete_probe).
    item_id: str = ""

    @property
    def accepted(self) -> tuple[int, ...]:
        return (self.expected, *self.also_ok)

    @property
    def expect_text(self) -> str:
        return "/".join(str(status) for status in self.accepted)


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
        return self.actual in self.probe.accepted and not self.problem

    @property
    def note(self) -> str:
        return f"  ({self.problem})" if self.problem else ""


def _send(graph: GraphClient, probe: Probe) -> tuple[HttpResponse | None, int | None]:
    """The probe's request; its response (2xx only) and status. None: no HTTP response."""
    try:
        resp = graph.request(
            probe.method,
            probe.path,
            params=probe.params,
            headers=probe.headers,
            body=probe.body,
            json_body=probe.json_body,
            idempotent=probe.idempotent,
        )
    except GraphError as exc:
        return None, exc.status  # the message is not shown: the status is the evidence
    return resp, resp.status


def run_probes(graph: GraphClient, items: list[Probe]) -> list[ProbeResult]:
    results = []
    for probe in items:
        if probe.method != "GET":
            raise ValueError(f"run_probes sends GETs only, not {probe.method} {probe.path}")
        resp, actual = _send(graph, probe)
        problem = ""
        if resp is not None and probe.only_item is not None:
            problem = _listing_problem(resp, *probe.only_item)
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


# ---- W3.4: the write probes ------------------------------------------------------------------


@dataclass(frozen=True)
class WriteTarget:
    """A restore target the Cleaner deletes in: a file is created and deleted there, or a draft
    in the mailbox and then permanently deleted, as the Worker deletes restored mail."""

    label: str
    kind: str  # "file" | "mail"
    drive_id: str = ""
    folder_id: str = ""  # "root": the library's root folder
    mailbox: str = ""

    def create_probe(self, name: str) -> Probe:
        if self.kind == "mail":
            return Probe(
                f"{self.label}: create a draft",
                f"/users/{self.mailbox}/messages",
                201,
                method="POST",
                headers={"Prefer": IMMUTABLE_ID},
                json_body={"subject": name, "body": {"contentType": "text", "content": PROBE_FILE_BODY.decode()}},
                idempotent=False,
            )
        return Probe(
            f"{self.label}: create a file",
            f"/drives/{self.drive_id}/items/{self.folder_id}:/{seg(name)}.txt:/content",
            201,
            params={"@microsoft.graph.conflictBehavior": "fail"},
            method="PUT",
            headers={"Content-Type": "application/octet-stream"},
            body=PROBE_FILE_BODY,
            idempotent=False,
        )

    def delete_label(self) -> str:
        return f"{self.label}: {'permanently delete it' if self.kind == 'mail' else 'delete it'}"

    def delete_probe(self, resp: HttpResponse, name: str) -> tuple[Probe | None, str]:
        """The delete of what the create made, or None and why: an item not proven to be the
        probe's own, in this target, is never deleted."""
        try:
            item = resp.json()
        except ValueError:
            item = None
        if not isinstance(item, dict):
            return None, "the reply can't be read: nothing deleted"
        item_id = item.get("id")
        if not isinstance(item_id, str) or not _ITEM_ID.fullmatch(item_id) or item_id in _NEVER_DELETED:
            return None, "the reply has no item ID the check deletes: nothing deleted, check the target by hand"
        if self.kind == "mail":
            if item.get("subject") != name:
                return None, "the draft has another subject: nothing deleted, check the target by hand"
            path = f"/users/{self.mailbox}/messages/{seg(item_id)}/permanentDelete"
            delete = Probe(
                self.delete_label(), path, 204, method="POST", headers={"Prefer": IMMUTABLE_ID}, item_id=item_id
            )
            return delete, ""
        parent = item.get("parentReference")
        in_place = (
            item.get("name") == f"{name}.txt"
            and isinstance(parent, dict)
            and parent.get("driveId") == self.drive_id
            and (self.folder_id == "root" or parent.get("id") == self.folder_id)
        )
        if not in_place:
            return None, "the file is not where the check put it: nothing deleted, check the target by hand"
        etag = item.get("eTag")
        headers = {"If-Match": etag} if isinstance(etag, str) and etag else None
        path = f"/drives/{self.drive_id}/items/{seg(item_id)}"
        return Probe(self.delete_label(), path, 204, method="DELETE", headers=headers, item_id=item_id), ""


# The folders themselves and the canary folder: never a delete's target, whatever a reply says.
_NEVER_DELETED = frozenset({"root", tenant.ONEDRIVE_TARGET_FOLDER_ID, tenant.ONEDRIVE_FOLDER_ID})


def write_targets() -> list[WriteTarget]:
    """The three restore targets (CLAUDE.md, "Restore targets"), as lab/tenant.md names them."""
    return [
        WriteTarget("RestoreTarget library", "file", drive_id=tenant.RESTORE_TARGET_DRIVE_ID, folder_id="root"),
        WriteTarget(
            "alice's OneDrive: RestoreTarget folder",
            "file",
            drive_id=tenant.ONEDRIVE_DRIVE_ID,
            folder_id=tenant.ONEDRIVE_TARGET_FOLDER_ID,
        ),
        WriteTarget("restoretest's mailbox", "mail", mailbox=tenant.RESTORETEST_UPN),
    ]


def _canary_item_ids() -> frozenset[str]:
    """The canary files' drive item IDs from lab/seed-manifest.json (none if it can't be read):
    a delete never names one, whatever a create's reply said."""
    try:
        entries = json.loads(MANIFEST_PATH.read_bytes().decode("utf-8")).get("entries", [])
        return frozenset(e["drive_item_id"] for e in entries if isinstance(e, dict) and "drive_item_id" in e)
    except (OSError, ValueError, AttributeError, TypeError):
        return frozenset()


def _check_write(probe: Probe) -> None:
    """Belt and braces, apart from delete_probe's own checks: a create goes only into a restore
    target itself (the library's root, alice's /RestoreTarget folder, restoretest's messages); a
    delete names exactly the item delete_probe proved (probe.item_id), never a target folder or a
    canary file; and no write names a canary location."""
    sp, od, mailbox = tenant.RESTORE_TARGET_DRIVE_ID, tenant.ONEDRIVE_DRIVE_ID, tenant.RESTORETEST_UPN
    canary = (tenant.SHAREPOINT_DRIVE_ID, tenant.ONEDRIVE_FOLDER_ID, tenant.SHAREPOINT_LIST_ID)
    item = probe.item_id
    if not item:
        creates = (f"/drives/{sp}/items/root:/", f"/drives/{od}/items/{tenant.ONEDRIVE_TARGET_FOLDER_ID}:/")
        allowed = (
            probe.method == "PUT" and probe.path.startswith(creates) and probe.path.count(":/") == 2
        ) or (probe.method == "POST" and probe.path == f"/users/{mailbox}/messages")
    else:
        deletes = {f"/drives/{sp}/items/{seg(item)}", f"/drives/{od}/items/{seg(item)}"}
        allowed = (
            _ITEM_ID.fullmatch(item) is not None
            and item not in _NEVER_DELETED
            and item not in _canary_item_ids()
            and (
                (probe.method == "DELETE" and probe.path in deletes)
                or (probe.method == "POST" and probe.path == f"/users/{mailbox}/messages/{seg(item)}/permanentDelete")
            )
        )
    if not allowed or any(value in probe.path for value in canary):
        raise ValueError(f"refusing to send {probe.method} {probe.path}: not in a restore target")


def _new_probe_name() -> str:
    return f"{PROBE_PREFIX}{uuid.uuid4()}"


def run_write_probe(graph: GraphClient, target: WriteTarget, name: str | None = None) -> list[ProbeResult]:
    """Create, then delete, in one restore target: two rows. If the delete is interrupted (an
    exception other than a Graph error), it is sent once more on the way out, and only ever for
    an item delete_probe proved to be the probe's own, in this target."""
    name = name or _new_probe_name()
    create = target.create_probe(name)
    _check_write(create)
    resp, actual = _send(graph, create)
    delete, problem = None, ""
    if resp is not None and actual == create.expected:
        delete, problem = target.delete_probe(resp, name)
    elif actual is None or actual >= 500:
        where = "in Drafts, delete it by hand" if target.kind == "mail" else "the Worker's next clean removes it"
        problem = f"outcome unknown: {name} may have been created ({where})"
    results = [ProbeResult(create, actual, problem)]
    if delete is None:
        not_sent = Probe(target.delete_label(), "(not sent)", 204, method="DELETE" if target.kind == "file" else "POST")
        results.append(ProbeResult(not_sent, None, "nothing to delete"))
        return results
    _check_write(delete)
    answered = False
    try:
        _, actual = _send(graph, delete)
        answered = True
    finally:
        if not answered:
            try:
                graph.request(delete.method, delete.path, headers=delete.headers)
            except Exception:  # noqa: BLE001 - best effort on the way out; the first error goes on
                pass
    left = "" if actual == delete.expected else f"{name} may still be there"
    results.append(ProbeResult(delete, actual, left))
    return results


# ---- W3.4: the refusal probes at the canaries -------------------------------------------------


@dataclass(frozen=True)
class CanaryRefusal:
    label: str
    file: CanaryFile  # its uploader confirms it exists, so the app's 404 means "hidden"
    signed_in_as: str  # "admin" | "alice", for the confirmation row


def refusal_canaries() -> list[CanaryRefusal]:
    """One canary file in the RestoreTest library and one in alice's /RestoreTest folder."""
    files = canary_files()
    library = next(f for f in files if f.kind == "sharepoint_file")
    onedrive = next(f for f in files if f.kind == "onedrive_file")
    return [
        CanaryRefusal("RestoreTest library: change a canary file", library, "admin"),
        CanaryRefusal("alice's OneDrive: change a canary file in RestoreTest", onedrive, "alice"),
    ]


def confirm_canary_file(graph: GraphClient, canary: CanaryRefusal) -> tuple[str | None, str]:
    """As the file's uploader: its item ID, or None and why. Without it, a 404 to the app could
    mean the file is gone rather than hidden, so the refusal probe isn't sent."""
    f = canary.file
    try:
        item = get_item_by_path(graph, f.drive_id, f.folder_id, f.name, owner=f.uploader)
    except GraphError as exc:
        return None, f"HTTP {exc.status if exc.status is not None else 'none'}"
    except ValueError:
        return None, "the answer can't be read"
    if item is None:
        return None, f"{f.name} missing: run python -m seeder seed"
    if not isinstance(item, dict):
        return None, "the answer can't be read"
    parent, item_id = item.get("parentReference"), item.get("id")
    real_folder = f.folder_id == "root" or (isinstance(parent, dict) and parent.get("id") == f.folder_id)
    if (
        not isinstance(item.get("file"), dict)
        or not isinstance(parent, dict)
        or parent.get("driveId") != f.drive_id
        or not real_folder
        or not isinstance(item_id, str)
        or not _ITEM_ID.fullmatch(item_id)
        or item_id in _NEVER_DELETED
    ):
        return None, f"{f.name} is not a canary file where seed put it"
    return item_id, f.name


def refusal_probe(canary: CanaryRefusal, item_id: str | None) -> Probe:
    """PATCH {} with an If-Match no item has: refused is 403 (no write) or 404 (masked); 412
    means the app may write there; a 2xx means it wrote. The only request ever sent at a canary."""
    path = f"/drives/{canary.file.drive_id}/items/{seg(item_id)}" if item_id else "(not sent)"
    return Probe(canary.label, path, 403, method="PATCH", headers={"If-Match": NO_SUCH_ETAG}, json_body={}, also_ok=(404,))


def run_refusal_probe(graph: GraphClient, canary: CanaryRefusal, item_id: str | None) -> ProbeResult:
    probe = refusal_probe(canary, item_id)
    if item_id is None:
        return ProbeResult(probe, None, "not sent: the canary file's existence wasn't confirmed")
    if probe.method != "PATCH" or probe.json_body != {} or dict(probe.headers or {}) != {"If-Match": NO_SUCH_ETAG}:
        raise ValueError("a canary is only ever sent PATCH {} with If-Match " + NO_SUCH_ETAG)
    _, actual = _send(graph, probe)
    return ProbeResult(probe, actual)


# ---- the command ---------------------------------------------------------------------------


def run_check(
    *,
    client_id: str,
    tenant_id: str,
    pfx_path: Path,
    read_password: Callable[[str], str | None],
    transport: Transport,
    alice_token: Callable[[], str],
    admin_token: Callable[[], str],
    app: Any = None,
    out: Callable[[str], None] = print,
    sleep: Callable[[float], None] | None = None,
) -> int:
    """0: every probe, every token's roles and the canary folder as expected. 1: anything
    unexpected. Credential and sign-in problems raise CredentialError/AuthError (the CLI exits 2).
    alice_token: alice's delegated Graph token (the seeder app), for reads of her canary folder
    and one of its files. admin_token: the admin's, for one read of a canary file in the library."""
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

    say("RestoreProof Worker app check (L1.5, W3.4): app-only Microsoft Graph; writes only in the restore targets")
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
    owners = {"alice": alice}
    canary_ids: list[str | None] = []
    for canary in refusal_canaries():
        if canary.signed_in_as not in owners:
            owners[canary.signed_in_as] = GraphClient(
                transport, admin_token, f"{tenant.ADMIN_UPN} (seeder app)", sleep=sleep or _sleep
            )
        item_id, note = confirm_canary_file(owners[canary.signed_in_as], canary)
        where = "library" if canary.file.kind == "sharepoint_file" else "OneDrive"
        label = f"canary file, {where}, read as {canary.signed_in_as}"
        say(f"{label:<32}  {note}  {'ok' if item_id else 'UNEXPECTED'}")
        unexpected += 0 if item_id else 1
        canary_ids.append(item_id)
    say("")

    graph = GraphClient(transport, signin.token, "RestoreProof Worker (app-only)", sleep=sleep or _sleep)
    results = run_probes(graph, probes())
    for target in write_targets():
        results += run_write_probe(graph, target)
    for canary, item_id in zip(refusal_canaries(), canary_ids):
        results.append(run_refusal_probe(graph, canary, item_id))
    say(f"{'result':<10}  {'expect':>7}  {'got':>6}  {'probe':<58}  request")
    for r in results:
        actual = "none" if r.actual is None else str(r.actual)
        verdict = "ok" if r.ok else "UNEXPECTED"
        request = f"{r.probe.method} {r.probe.path}"
        say(f"{verdict:<10}  {r.probe.expect_text:>7}  {actual:>6}  {r.probe.label:<58}  {request}{r.note}")
    passed = sum(r.ok for r in results)
    unexpected += len(results) - passed
    summary = f"{passed}/{len(results)} probes as expected"
    say(summary if unexpected == 0 else f"{summary}; {unexpected} UNEXPECTED")
    return 0 if unexpected == 0 else 1
