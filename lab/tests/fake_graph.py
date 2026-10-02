"""An in-memory test tenant behind the http.Transport seam, plus a FakeSignIn.

Tokens are "token:<upn>"; the fake reads the signed-in account from the Authorization header,
so "/me" is always that account's own mailbox. Drives are reachable only by the account in
`drive_access` (403 otherwise), like delegated Graph.

App-only tokens (the RestoreProof Worker app, L1.5) are JWT-shaped, made by make_app_token. The
fake answers them from `app_grants`, the resources the app was granted, the way Graph answered
in the lab: 200 on a granted resource, 403 on any other one, and 404 on items a folder grant
masks. APP_GRANTS is what L1.5 and W3.4 grant.

App-only writes (W3.4's probes, in the restore targets only) follow the same grants: a file
uploaded into, or an item deleted in, a folder the app may write; a draft created in, or
permanently deleted from, a mailbox it may write. Without write: 403 where the app may read, 404
where a folder grant masks the item. A delete whose If-Match isn't the item's ETag is 412 wherever
the app may read the item, write or not: SharePoint checks the ETag before write permission (seen
live on 2026-10-02 for a PATCH at a canary file, build notes point 12; the fake assumes a DELETE
alike). There is no folder-create or PATCH route: check-worker-app sends neither (no write probe
can prove a refusal at a canary, docs/decisions.md 2026-10-02, W3.4 build notes, point 13).
"""

import base64
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping
from urllib.parse import parse_qs, unquote, urlsplit

from seeder import tenant
from seeder.graph import GRAPH_BASE
from seeder.http import HttpResponse
from tests.fake_transport import graph_error, json_response
from tests.office_fakes import sharepoint_rewrite

BASE_TIME = datetime(2026, 9, 25, 10, 0, 0, tzinfo=timezone.utc)
SHAREPOINT_ROOT_ID = "01SPROOTFOLDERREALID"

_ITEM_BY_PATH = re.compile(r"^/drives/([^/]+)/items/([^/:]+):/([^/:]+):(/content)?$")
_ITEM_BY_ID = re.compile(r"^/drives/([^/]+)/items/([^/:]+)(/content)?$")
_MESSAGE = re.compile(r"^/me/messages/([^/]+)$")
_FOLDER = re.compile(r"^/me/mailFolders/([^/]+)$")
_SUBJECT_FILTER = re.compile(r"^subject eq '(.*)'$")
_USER_MESSAGES = re.compile(r"^/users/([^/]+)/messages$")
_SITE = re.compile(r"^/sites/(.+?)(/drives)?$")
_DRIVE = re.compile(r"^/drives/([^/]+)(?:/(root|items/[^/]+)(/children)?)?$")
_APP_UPLOAD = re.compile(r"^/drives/([^/]+)/items/([^/:]+):/([^/:]+):/content$")
_APP_ITEM = re.compile(r"^/drives/([^/]+)/items/([^/:]+)$")
_APP_PERMANENT_DELETE = re.compile(r"^/users/([^/]+)/messages/([^/]+)/permanentDelete$")

# Grant keys: "mailbox:<upn lower>", "site:<site id>", "folder:<drive id>/<item id>", "directory";
# W3.4's writes: "mailbox-write:<upn lower>", "list-write:<drive id>" (a library's whole list),
# "folder-write:<drive id>/<item id>".
APP_GRANTS = frozenset(
    {
        f"mailbox:{tenant.RESTORETEST_UPN.lower()}",
        f"site:{tenant.SHAREPOINT_SITE_ID}",
        f"folder:{tenant.ONEDRIVE_DRIVE_ID}/{tenant.ONEDRIVE_TARGET_FOLDER_ID}",
        f"mailbox-write:{tenant.RESTORETEST_UPN.lower()}",
        f"list-write:{tenant.RESTORE_TARGET_DRIVE_ID}",
        f"folder-write:{tenant.ONEDRIVE_DRIVE_ID}/{tenant.ONEDRIVE_TARGET_FOLDER_ID}",
    }
)
WRITE_GRANTS = frozenset(g for g in APP_GRANTS if "-write:" in g)
# The drives of each site, as far as the fake knows.
SITE_DRIVES = {
    tenant.SHAREPOINT_SITE_ID: (tenant.RESTORE_TARGET_DRIVE_ID, tenant.SHAREPOINT_DRIVE_ID),
    f"{tenant.ONEDRIVE_HOST}:{tenant.ALICE_ONEDRIVE_SITE_PATH}": (tenant.ONEDRIVE_DRIVE_ID,),
    tenant.SHAREPOINT_HOST: ("b!FAKEROOTSITEDOCUMENTS",),
    tenant.ONEDRIVE_HOST: ("b!FAKEMYSITEHOSTDOCUMENTS",),
}
# What each drive's root folder holds (the rest are "01FAKECHILD").
DRIVE_ROOT_ITEMS = {
    tenant.ONEDRIVE_DRIVE_ID: (tenant.ONEDRIVE_TARGET_FOLDER_ID, tenant.ONEDRIVE_FOLDER_ID, "01FAKEALICEFILE"),
}
APP_ROLES = ("Sites.Selected", "Files.SelectedOperations.Selected", "Lists.SelectedOperations.Selected")
# The folders' names, as a listing shows them.
ITEM_NAMES = {tenant.ONEDRIVE_TARGET_FOLDER_ID: "RestoreTarget", tenant.ONEDRIVE_FOLDER_ID: "RestoreTest"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def make_app_token(client_id: str, roles=APP_ROLES, signature: str = "fake-signature") -> str:
    """An unsigned JWT-shaped app-only token, as Entra's client-credentials grant returns one."""
    header = _b64url(json.dumps({"typ": "JWT", "alg": "RS256"}).encode())
    payload = _b64url(json.dumps({"appid": client_id, "idtyp": "app", "roles": list(roles)}).encode())
    return f"{header}.{payload}.{signature}"


def _iso(moment: datetime, fraction: bool = False) -> str:
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    return text + (".1234567Z" if fraction else "Z")


@dataclass
class FakeDrive:
    drive_id: str
    kind: str  # "sharepoint" | "onedrive"
    folders: dict[str, str]  # address used in paths ("root" or real id) -> real folder id
    items: dict[str, dict] = field(default_factory=dict)  # item id -> {name, parent, data, modified}


class FakeTenant:
    def __init__(
        self,
        *,
        delivery_delay: int | None = 0,
        body_transform: Callable[[str], str] | None = None,
        rewrite_types: frozenset[str] | set[str] = frozenset(),
        drive_access: Mapping[str, str] | None = None,
        app_grants: frozenset[str] | set[str] = APP_GRANTS,
    ) -> None:
        """delivery_delay: number of message-list calls by the recipient before a sent mail
        shows up (None = never delivered). body_transform: what "Exchange" does to the body.
        rewrite_types: extensions whose bytes the SharePoint drive changes on upload."""
        self.delivery_delay = delivery_delay
        self.body_transform = body_transform or (lambda text: text)
        self.rewrite_types = set(rewrite_types)
        self.app_grants = set(app_grants)
        self.app_requests: list[tuple[str, str]] = []  # (method, path) of every app-only call
        # Every app-only write: (method, path, headers without Authorization, body).
        self.app_writes: list[tuple[str, str, dict[str, str], bytes | None]] = []
        self.app_items: dict[tuple[str, str], dict] = {}  # (drive, id) -> {name, parent, eTag}: app uploads
        self.app_drafts: dict[str, dict[str, dict]] = {}  # upn lower -> id -> draft
        self.item_names = dict(ITEM_NAMES)
        self.drive_access = dict(
            drive_access
            or {tenant.SHAREPOINT_DRIVE_ID: tenant.ADMIN_UPN, tenant.ONEDRIVE_DRIVE_ID: tenant.ALICE_UPN}
        )
        self.drives = {
            tenant.SHAREPOINT_DRIVE_ID: FakeDrive(
                tenant.SHAREPOINT_DRIVE_ID, "sharepoint", {"root": SHAREPOINT_ROOT_ID, SHAREPOINT_ROOT_ID: SHAREPOINT_ROOT_ID}
            ),
            tenant.ONEDRIVE_DRIVE_ID: FakeDrive(
                tenant.ONEDRIVE_DRIVE_ID, "onedrive", {tenant.ONEDRIVE_FOLDER_ID: tenant.ONEDRIVE_FOLDER_ID}
            ),
        }
        self.mailboxes: dict[str, list[dict]] = {}  # lower-case upn -> messages
        self.folders: dict[str, str] = {}  # folder id -> display name
        self.pending: list[dict] = []  # {"recipient", "message", "remaining"}
        self.sent: list[dict] = []  # sendMail payloads with the sender
        self.uploads: list[tuple[str, str, str]] = []  # (account, name, conflictBehavior)
        self.calls: Counter[str] = Counter()
        self.headers_seen: list[dict[str, str]] = []
        self._ticks = 0
        self._ids = 0

    # --- time and ids ----------------------------------------------------------------------

    def now(self) -> str:
        """The fake's current time, whole seconds (what seed's injected `now` returns)."""
        return _iso(BASE_TIME + timedelta(seconds=self._ticks))

    def _tick(self) -> datetime:
        self._ticks += 1
        return BASE_TIME + timedelta(seconds=self._ticks)

    def _next_id(self, prefix: str) -> str:
        self._ids += 1
        return f"{prefix}{self._ids:04d}"

    # --- test helpers ----------------------------------------------------------------------

    def folder_id(self, upn: str, name: str) -> str:
        folder_id = f"AAMkFolder-{upn.split('@')[0]}-{name.replace(' ', '')}"
        self.folders[folder_id] = name
        return folder_id

    def add_message(
        self, recipient: str, subject: str, body: str, *, sender: str = tenant.ADMIN_UPN, folder: str = "Inbox"
    ) -> dict:
        """Put a message straight into a mailbox (as if delivered earlier). folder="Deleted Items"
        puts it where a deleted message goes."""
        sent = self._tick()
        received = sent + timedelta(seconds=1)
        message = {
            "id": self._next_id(f"AAMkImmutable-{recipient.split('@')[0]}-"),
            "subject": subject,
            "from": {"emailAddress": {"address": sender}},
            "toRecipients": [{"emailAddress": {"address": recipient}}],
            "sentDateTime": _iso(sent),
            "receivedDateTime": _iso(received, fraction=True),
            "internetMessageId": f"<{self._next_id('fake-imid-')}@RestoreProofLab.onmicrosoft.com>",
            "parentFolderId": self.folder_id(recipient, folder),
            "body": {"contentType": "text", "content": body},
        }
        self.mailboxes.setdefault(recipient.lower(), []).append(message)
        return message

    def messages(self, upn: str, subject: str | None = None) -> list[dict]:
        box = self.mailboxes.get(upn.lower(), [])
        return [m for m in box if subject is None or m["subject"] == subject]

    def item(self, drive_id: str, name: str) -> tuple[str, dict] | None:
        for item_id, item in self.drives[drive_id].items.items():
            if item["name"] == name:
                return item_id, item
        return None

    def put_item(self, drive_id: str, name: str, data: bytes) -> str:
        """Put a file straight into a drive's canary folder."""
        drive = self.drives[drive_id]
        parent = SHAREPOINT_ROOT_ID if drive.kind == "sharepoint" else tenant.ONEDRIVE_FOLDER_ID
        found = self.item(drive_id, name)
        item_id = found[0] if found else self._next_id("01FAKEITEM")
        drive.items[item_id] = {"name": name, "parent": parent, "data": data, "modified": _iso(self._tick(), True)}
        return item_id

    # --- the Transport -----------------------------------------------------------------------

    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None = None) -> HttpResponse:
        self.headers_seen.append(dict(headers))
        auth = headers.get("Authorization", "")
        if auth.startswith("Bearer eyJ"):
            return self._app_request(method, url, headers, body)
        if not auth.startswith("Bearer token:"):
            return graph_error(401, "InvalidAuthenticationToken", "no token")
        account = auth[len("Bearer token:") :]
        assert url.startswith(GRAPH_BASE), url
        parts = urlsplit(url[len(GRAPH_BASE) :])
        path = unquote(parts.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}

        if path == "/me" and method == "GET":
            self.calls["me"] += 1
            return json_response(200, {"userPrincipalName": account})
        if path == "/me/sendMail" and method == "POST":
            return self._send_mail(account, json.loads(body or b"{}"))
        if path == "/me/messages" and method == "GET":
            return self._list_messages(account, query)
        if (m := _MESSAGE.match(path)) and method == "GET":
            self.calls["get_message"] += 1
            for message in self.messages(account):
                if message["id"] == m.group(1):
                    return json_response(200, message)
            return graph_error(404, "ErrorItemNotFound", "The specified object was not found in the store.")
        if path.lower() == "/me/mailfolders/deleteditems" and method == "GET":
            # The well-known name; the answer is the folder's real id, as Graph's is.
            self.calls["deleted_items"] += 1
            return json_response(200, {"id": self.folder_id(account, "Deleted Items"), "displayName": "Deleted Items"})
        if (m := _FOLDER.match(path)) and method == "GET":
            self.calls["get_folder"] += 1
            if m.group(1) not in self.folders:
                return graph_error(404, "ErrorItemNotFound", "folder not found")
            return json_response(200, {"id": m.group(1), "displayName": self.folders[m.group(1)]})
        if m := _ITEM_BY_PATH.match(path):
            return self._item_by_path(account, method, m.group(1), m.group(2), m.group(3), bool(m.group(4)), query, body)
        if (m := _ITEM_BY_ID.match(path)) and method == "GET":
            return self._item_by_id(account, m.group(1), m.group(2), bool(m.group(3)))
        return graph_error(400, "BadRequest", f"fake tenant has no route for {method} {path}")

    # --- app-only (the Worker app) ------------------------------------------------------------

    def _app_request(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> HttpResponse:
        assert url.startswith(GRAPH_BASE), url
        path = unquote(urlsplit(url[len(GRAPH_BASE) :]).path)
        self.app_requests.append((method, path))
        if method == "GET":
            answer = self._app_answer(path)
        else:
            kept = {k: v for k, v in headers.items() if k != "Authorization"}
            self.app_writes.append((method, path, kept, body))
            answer = self._app_write(method, path, headers, body)
        if answer is None:
            return graph_error(400, "BadRequest", f"fake tenant has no app-only route for {method} {path}")
        return answer

    # --- app-only writes (W3.4) ----------------------------------------------------------------

    def _app_access(self, drive_id: str, folder: str) -> str:
        """"write", "read", "masked" (a folder grant elsewhere in the drive) or "none"."""
        if f"list-write:{drive_id}" in self.app_grants or f"folder-write:{drive_id}/{folder}" in self.app_grants:
            return "write"
        site = next((s for s, drives in SITE_DRIVES.items() if drive_id in drives), None)
        if f"site:{site}" in self.app_grants or f"folder:{drive_id}/{folder}" in self.app_grants:
            return "read"
        if self._folder_grants(drive_id) or any(g.startswith(f"folder-write:{drive_id}/") for g in self.app_grants):
            return "masked"
        return "none"

    @staticmethod
    def _refused(access: str) -> HttpResponse:
        if access == "masked":
            return graph_error(404, "itemNotFound", "The resource could not be found.")
        return graph_error(403, "accessDenied", "Access denied")

    def _app_locate(self, drive_id: str, item_id: str) -> tuple[str, str, Callable[[], None]] | None:
        """(folder as an access key, eTag, remove) of an app upload or a seeded item."""
        if (drive_id, item_id) in self.app_items:
            item = self.app_items[(drive_id, item_id)]
            return item["parent"], item["eTag"], lambda: self.app_items.pop((drive_id, item_id))
        drive = self.drives.get(drive_id)
        if drive is not None and item_id in drive.items:
            parent = drive.items[item_id]["parent"]
            folder = "root" if parent == SHAREPOINT_ROOT_ID else parent
            return folder, f'"{{{item_id}}},1"', lambda: drive.items.pop(item_id)
        return None

    def _app_write(self, method: str, path: str, headers: Mapping[str, str], body: bytes | None) -> HttpResponse | None:
        mail_denied = graph_error(403, "ErrorAccessDenied", "Access is denied. Check credentials and try again.")
        if (m := _USER_MESSAGES.match(path)) and method == "POST":
            upn = m.group(1).lower()
            if f"mailbox-write:{upn}" not in self.app_grants:
                return mail_denied
            draft = json.loads(body or b"{}")
            draft_id = self._next_id("AAMkImmutableDraft-")
            self.app_drafts.setdefault(upn, {})[draft_id] = draft
            return json_response(201, {"id": draft_id, "subject": draft.get("subject"), "isDraft": True})
        if (m := _APP_PERMANENT_DELETE.match(path)) and method == "POST":
            upn, draft_id = m.group(1).lower(), m.group(2)
            if f"mailbox-write:{upn}" not in self.app_grants:
                return mail_denied
            if draft_id not in self.app_drafts.get(upn, {}):
                return graph_error(404, "ErrorItemNotFound", "The specified object was not found in the store.")
            del self.app_drafts[upn][draft_id]
            return HttpResponse(204)
        if (m := _APP_UPLOAD.match(path)) and method == "PUT":
            drive_id, folder, name = m.groups()
            access = self._app_access(drive_id, folder)
            if access != "write":
                return self._refused(access)
            if any(i["name"] == name and i["parent"] == folder for (d, _), i in self.app_items.items() if d == drive_id):
                return graph_error(409, "nameAlreadyExists", "The specified item name already exists.")
            item_id = self._next_id("01FAKEAPPITEM")
            etag = f'"{{{item_id}}},1"'
            self.app_items[(drive_id, item_id)] = {"name": name, "parent": folder, "eTag": etag, "data": body}
            parent_id = "01FAKERESTORETARGETROOT" if folder == "root" else folder
            item = {"id": item_id, "name": name, "eTag": etag, "file": {}, "parentReference": {"driveId": drive_id, "id": parent_id}}
            return json_response(201, item)
        if (m := _APP_ITEM.match(path)) and method == "DELETE":
            drive_id, item_id = m.groups()
            located = self._app_locate(drive_id, item_id)
            if located is None:
                return graph_error(404, "itemNotFound", "The resource could not be found.")
            folder, etag, remove = located
            access = self._app_access(drive_id, folder)
            if_match = headers.get("If-Match")
            if access in ("write", "read") and if_match is not None and if_match != etag:
                # Live (2026-10-02, a PATCH at a canary file): the ETag is checked before write permission.
                return graph_error(412, "resourceModified", "ETag does not match current item's value")
            if access != "write":
                return self._refused(access)
            remove()
            return HttpResponse(204)
        return None

    def _app_answer(self, path: str) -> HttpResponse | None:
        """What Graph answered the Worker app in the lab (docs/security/graph-permissions.md): 200
        on what is granted, 403 on anything else. A folder grant inside a site also opens that
        site's and drive root's metadata, lists only the granted folder at the root, and masks
        every other item as 404."""
        denied = graph_error(403, "accessDenied", "Access denied")
        if path == "/users":
            return json_response(200, {"value": [{"id": "u1"}]}) if "directory" in self.app_grants else denied
        if m := _USER_MESSAGES.match(path):
            granted = f"mailbox:{m.group(1).lower()}" in self.app_grants
            return json_response(200, {"value": [{"id": "AAMkFakeMessage"}]}) if granted else denied
        if m := _SITE.match(path):
            site = m.group(1)
            if site not in SITE_DRIVES:
                return None
            if f"site:{site}" in self.app_grants:
                body = {"value": [{"id": d} for d in SITE_DRIVES[site]]} if m.group(2) else {"id": site}
                return json_response(200, body)
            if not m.group(2) and any(self._folder_grants(d) for d in SITE_DRIVES[site]):
                return json_response(200, {"id": site})
            return denied
        if m := _DRIVE.match(path):
            drive_id, where, children = m.group(1), m.group(2), m.group(3)
            site = next((s for s, drives in SITE_DRIVES.items() if drive_id in drives), None)
            if site is None:
                return None
            item = where[len("items/") :] if where and where.startswith("items/") else None
            if f"site:{site}" in self.app_grants:
                if children:
                    return json_response(200, {"value": [{"id": i} for i in DRIVE_ROOT_ITEMS.get(drive_id, ("01FAKECHILD",))]})
                return json_response(200, {"id": item or where or drive_id})
            folders = self._folder_grants(drive_id)
            if not folders:
                return denied
            if item is not None:
                if item not in folders:
                    return graph_error(404, "itemNotFound", "The resource could not be found.")
                body = {"value": [{"id": "01FAKECHILD"}]} if children else {"id": item}
                return json_response(200, body)
            if where == "root":
                listed = [{"id": f, "name": self.item_names.get(f, f)} for f in sorted(folders)]
                body = {"value": listed} if children else {"id": "root"}
                return json_response(200, body)
            return denied
        return None

    def _folder_grants(self, drive_id: str) -> set[str]:
        prefix = f"folder:{drive_id}/"
        return {g[len(prefix) :] for g in self.app_grants if g.startswith(prefix)}

    # --- mail --------------------------------------------------------------------------------

    def _send_mail(self, account: str, payload: dict) -> HttpResponse:
        self.calls["send_mail"] += 1
        self.sent.append({"sender": account, **payload})
        msg = payload["message"]
        recipient = msg["toRecipients"][0]["emailAddress"]["address"]
        sent_at = self._tick()
        message = {
            "id": self._next_id(f"AAMkImmutable-{recipient.split('@')[0]}-"),
            "subject": msg["subject"],
            "from": {"emailAddress": {"address": account}},
            "toRecipients": msg["toRecipients"],
            "sentDateTime": _iso(sent_at),
            "receivedDateTime": None,  # set on delivery
            "internetMessageId": f"<{self._next_id('fake-imid-')}@RestoreProofLab.onmicrosoft.com>",
            "parentFolderId": self.folder_id(recipient, "Inbox"),
            "body": {"contentType": "text", "content": self.body_transform(msg["body"]["content"])},
        }
        if self.delivery_delay is not None:
            self.pending.append({"recipient": recipient.lower(), "message": message, "remaining": self.delivery_delay})
            self._deliver(recipient.lower(), count_call=False)
        return HttpResponse(202)

    def _deliver(self, upn: str, *, count_call: bool) -> None:
        for entry in list(self.pending):
            if entry["recipient"] != upn:
                continue
            if count_call:
                entry["remaining"] -= 1
            if entry["remaining"] <= 0:
                entry["message"]["receivedDateTime"] = _iso(self._tick(), fraction=True)
                self.mailboxes.setdefault(upn, []).append(entry["message"])
                self.pending.remove(entry)

    def _list_messages(self, account: str, query: dict[str, str]) -> HttpResponse:
        self.calls["list_messages"] += 1
        self._deliver(account.lower(), count_call=True)
        match = _SUBJECT_FILTER.match(query.get("$filter", ""))
        if not match:
            return graph_error(400, "BadRequest", "fake supports only $filter=subject eq '...'")
        subject = match.group(1).replace("''", "'")
        return json_response(200, {"value": self.messages(account, subject)})

    # --- files -------------------------------------------------------------------------------

    def _drive(self, account: str, drive_id: str) -> FakeDrive | HttpResponse:
        if drive_id not in self.drives:
            return graph_error(404, "itemNotFound", "drive not found")
        if self.drive_access.get(drive_id, "").lower() != account.lower():
            return graph_error(403, "accessDenied", "Access denied")
        return self.drives[drive_id]

    def _item_json(self, drive: FakeDrive, item_id: str) -> dict:
        item = drive.items[item_id]
        return {
            "id": item_id,
            "name": item["name"],
            "size": len(item["data"]),
            "file": {},
            "parentReference": {"driveId": drive.drive_id, "id": item["parent"]},
            "lastModifiedDateTime": item["modified"],
        }

    def _item_by_path(
        self, account, method, drive_id, folder, name, content, query, body
    ) -> HttpResponse:
        drive = self._drive(account, drive_id)
        if isinstance(drive, HttpResponse):
            return drive
        parent = drive.folders.get(folder)
        if parent is None:
            return graph_error(404, "itemNotFound", "folder not found")
        existing = next(
            (i for i, it in drive.items.items() if it["name"] == name and it["parent"] == parent), None
        )
        if method == "GET" and not content:
            self.calls["get_item_by_path"] += 1
            if existing is None:
                return graph_error(404, "itemNotFound", "The resource could not be found.")
            return json_response(200, self._item_json(drive, existing))
        if method == "PUT" and content:
            self.calls["upload"] += 1
            behavior = query.get("@microsoft.graph.conflictBehavior", "")
            self.uploads.append((account, name, behavior))
            if existing is not None and behavior == "fail":
                return graph_error(409, "nameAlreadyExists", "The specified item name already exists.")
            data = body or b""
            if drive.kind == "sharepoint" and name.rsplit(".", 1)[-1] in self.rewrite_types:
                data = sharepoint_rewrite(data)
            item_id = existing or self._next_id("01FAKEITEM")
            drive.items[item_id] = {"name": name, "parent": parent, "data": data, "modified": _iso(self._tick(), True)}
            return json_response(201 if existing is None else 200, self._item_json(drive, item_id))
        return graph_error(400, "BadRequest", "unsupported")

    def _item_by_id(self, account, drive_id, item_id, content) -> HttpResponse:
        drive = self._drive(account, drive_id)
        if isinstance(drive, HttpResponse):
            return drive
        if item_id in drive.folders.values() and item_id != SHAREPOINT_ROOT_ID and not content:
            count = sum(1 for item in drive.items.values() if item["parent"] == item_id)
            return json_response(200, {"id": item_id, "name": self.item_names.get(item_id, item_id), "folder": {"childCount": count}})
        if item_id not in drive.items:
            return graph_error(404, "itemNotFound", "The resource could not be found.")
        if content:
            self.calls["download"] += 1
            return HttpResponse(200, drive.items[item_id]["data"], {"content-type": "application/octet-stream"})
        self.calls["get_item"] += 1
        return json_response(200, self._item_json(drive, item_id))


class FakeSignIn:
    """Stands in for auth.SignIn: token_provider(upn, purpose) -> callable giving "token:<upn>".
    The first token for an account counts as an interactive sign-in."""

    def __init__(self, out: Callable[[str], None] | None = None) -> None:
        self.providers: list[tuple[str, str]] = []  # every token_provider call, in order
        self.interactive: list[tuple[str, str]] = []  # first token per account
        self._out = out

    def token_provider(self, upn: str, purpose: str) -> Callable[[], str]:
        self.providers.append((upn, purpose))

        def provide() -> str:
            if upn.lower() not in {u.lower() for u, _ in self.interactive}:
                self.interactive.append((upn, purpose))
                if self._out:
                    self._out(f"==> Sign in as {upn}  ({purpose})")
            return f"token:{upn}"

        return provide
