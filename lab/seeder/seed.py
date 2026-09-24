"""`python -m seeder seed`: put the 40 canary items in the test tenant and record them.

Delegated Graph only reaches the signed-in user's own mailbox and OneDrive, so the run signs in
three times (alice, bob, admin) and then reuses alice's and bob's cached sign-ins to read the
mails back. The manifest is written only once all 40 items were read back.
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from seeder import graph, tenant
from seeder.catalog import CanaryFile, CanaryMail, canary_files, canary_mails
from seeder.graph import GraphClient
from seeder.http import Transport
from seeder.manifest import build_manifest, file_entry, iso_utc, mail_entry, write_manifest
from seeder.normalize import NORMALIZATION_ID, normalize_body
from seeder.office import OFFICE_RULE, OfficeContentError, office_content_sha256

Out = Callable[[str], None]
STEPS = 5
BACKUP_REMINDER = (
    "Run the Veeam backup (L1.3) only after this seed: every canary item must be in the restore points."
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short(upn: str) -> str:
    return upn.split("@")[0]


def _range(items: list[CanaryMail]) -> str:
    return f"{items[0].subject}..{items[-1].subject[-4:]}"


def _file_range(files: list[CanaryFile]) -> str:
    return f"rp-canary-{files[0].number:02d}..{files[-1].number:02d}"


def first_difference(sent: str, got: str, width: int = 12) -> str:
    """Where two strings first differ, as short escaped excerpts."""
    index = next((i for i, (a, b) in enumerate(zip(sent, got)) if a != b), min(len(sent), len(got)))
    start = max(0, index - 4)
    return (
        f"first difference at character {index}: sent {sent[start:index + width]!r}, "
        f"read back {got[start:index + width]!r}"
    )


class _Seed:
    def __init__(self, *, signin, transport, canary_dir, force, sleep, now, out) -> None:
        self.signin = signin
        self.transport = transport
        self.canary_dir = Path(canary_dir)
        self.force = force
        self.sleep = sleep
        self.now = now
        self.out = out
        self.mails = list(canary_mails())
        self.files = list(canary_files())
        self.local: dict[str, bytes] = {}
        self.existing: dict[str, dict] = {}  # subject -> the one message already there
        # subject -> ids already in the mailbox before sending; --force reads back a copy not among them
        self.seen_ids: dict[str, set[str]] = {}
        self.deleted_items: dict[str, str] = {}  # upn -> id of that mailbox's Deleted Items folder
        self.to_send: list[CanaryMail] = []
        self.file_entries: dict[str, dict] = {}
        self.mail_entries: dict[str, dict] = {}
        self.stored_differs: list[str] = []
        self.content_differs: list[str] = []  # stored document content != canary/: stops the seed
        self.body_differs: list[str] = []
        self.not_inbox: list[str] = []
        self.uploaded = 0

    def client(self, upn: str, purpose: str) -> GraphClient:
        return GraphClient(self.transport, self.signin.token_provider(upn, purpose), upn, sleep=self.sleep)

    def step(self, number: int, upn: str, what: str) -> None:
        self.out("")
        self.out(f"Step {number}/{STEPS}: {upn} - {what}")

    def mails_for(self, upn: str) -> list[CanaryMail]:
        return [m for m in self.mails if m.recipient == upn]

    # --- local files --------------------------------------------------------------------

    def read_local_files(self) -> bool:
        missing = [f.name for f in self.files if not (self.canary_dir / f.name).is_file()]
        if missing:
            self.out(f"error: missing canary file(s) in {self.canary_dir}: {', '.join(missing)}")
            self.out("Run `uv run python -m seeder generate` first (the files are committed in lab/canary/).")
            return False
        self.local = {f.name: (self.canary_dir / f.name).read_bytes() for f in self.files}
        return True

    # --- mails ---------------------------------------------------------------------------

    def find(self, g: GraphClient, upn: str, subject: str) -> list[dict]:
        """Copies of this subject in upn's mailbox, ignoring Deleted Items: a copy the user
        deleted is gone as far as the seed is concerned."""
        if upn not in self.deleted_items:
            self.deleted_items[upn] = graph.get_deleted_items_id(g, owner=upn)
        return graph.find_messages_by_subject(g, subject, owner=upn, exclude_folder_id=self.deleted_items[upn])

    def check_mailbox(self, g: GraphClient, upn: str) -> bool:
        """Record which mails are already there; False if a subject is there more than once."""
        duplicates = []
        for mail in self.mails_for(upn):
            found = self.find(g, upn, mail.subject)
            self.seen_ids[mail.subject] = {m["id"] for m in found}
            if not found or self.force:
                self.to_send.append(mail)
                if found:
                    self.out(f"  {mail.subject}: {len(found)} already in mailbox, sending again (--force)")
            elif len(found) == 1:
                self.existing[mail.subject] = found[0]
                self.out(f"  {mail.subject}: already in mailbox, not sent")
            else:
                duplicates.append((mail.subject, len(found)))
        for subject, count in duplicates:
            self.out(
                f"error: {subject} is in {upn}'s mailbox {count} times. Delete the extra copies "
                "(keep one, or delete all; copies in Deleted Items don't count) and run seed again."
            )
        return not duplicates

    def send_missing(self, g: GraphClient) -> None:
        if not self.to_send:
            self.out("  every mail is already in its mailbox; nothing to send")
            return
        for mail in sorted(self.to_send, key=lambda m: m.number):
            graph.send_mail(
                g, subject=mail.subject, body_text=mail.body, to_address=mail.recipient, owner=tenant.ADMIN_UPN
            )
            self.out(f"  {mail.subject}: sent to {mail.recipient}")

    def _pick(self, subject: str, found: list[dict]) -> dict | None:
        if subject in self.existing:
            return self.existing[subject]
        # A copy that was not there before this run sent it. Ids, not timestamps: the PC's
        # clock and Exchange's need not agree.
        fresh = [m for m in found if m["id"] not in self.seen_ids.get(subject, set())]
        return max(fresh, key=lambda m: iso_utc(m["receivedDateTime"]), default=None)

    def poll_and_read(self, g: GraphClient, upn: str, deadline: float, clock: Callable[[], float], interval: float) -> list[str]:
        """Wait for this mailbox's mails, read them back; returns the subjects still missing."""
        pending = [m for m in self.mails_for(upn) if m.subject not in self.existing]
        found: dict[str, dict] = {s: msg for s, msg in self.existing.items() if s in {m.subject for m in self.mails_for(upn)}}
        while True:
            for mail in list(pending):
                msg = self._pick(mail.subject, self.find(g, upn, mail.subject))
                if msg is not None:
                    found[mail.subject] = msg
                    pending.remove(mail)
            if not pending or clock() >= deadline:
                break
            self.out(f"  waiting for {len(pending)} mail(s) in {upn}'s mailbox ...")
            self.sleep(interval)
        folders: dict[str, str] = {}
        for mail in self.mails_for(upn):
            if mail.subject in found:
                self.read_back(g, upn, mail, found[mail.subject], folders)
        return [m.subject for m in pending]

    def read_back(self, g: GraphClient, upn: str, mail: CanaryMail, msg: dict, folders: dict[str, str]) -> None:
        folder_id = msg["parentFolderId"]
        if folder_id not in folders:
            folders[folder_id] = graph.get_mail_folder_name(g, folder_id, owner=upn)
        folder = folders[folder_id]
        body = msg["body"]["content"]
        self.mail_entries[mail.subject] = mail_entry(
            mail,
            sender=msg["from"]["emailAddress"]["address"],
            folder=folder,
            sent_at=msg["sentDateTime"],
            received_at=msg["receivedDateTime"],
            internet_message_id=msg["internetMessageId"],
            graph_message_id=msg["id"],
            body_readback=body,
        )
        note = ""
        if body != mail.body:
            same = normalize_body(body) == normalize_body(mail.body)
            verdict = f"same after {NORMALIZATION_ID}" if same else f"differs after {NORMALIZATION_ID}"
            detail = first_difference(mail.body, body)
            if not same:
                detail = first_difference(normalize_body(mail.body), normalize_body(body)) + " (normalised)"
            line = f"{mail.subject}: read-back body differs from the sent body ({verdict}); {detail}"
            self.body_differs.append(line)
            note = f"; body differs ({verdict})"
        if folder != "Inbox":
            self.not_inbox.append(f"{mail.subject}: in folder {folder!r} of {upn}'s mailbox, not Inbox")
            note += f"; folder {folder!r}"
        self.out(f"  {mail.subject}: read back{note}")

    # --- files ---------------------------------------------------------------------------

    def seed_files(self, g: GraphClient, files: list[CanaryFile]) -> None:
        for file in files:
            owner = file.uploader
            local = self.local[file.name]
            existing = graph.get_item_by_path(g, file.drive_id, file.folder_id, file.name, owner=owner)
            skipped = existing is not None and not self.force
            if skipped:
                item = existing
                action = "already uploaded, not replaced"
            else:
                item = graph.upload_file(
                    g, file.drive_id, file.folder_id, file.name, local, replace=self.force, owner=owner
                )
                self.uploaded += 1
                action = "replaced" if existing is not None else "uploaded"
            stored = graph.download_item(g, file.drive_id, item["id"], owner=owner)
            line = f"  {file.name}: {action}"
            try:
                entry = file_entry(
                    file,
                    folder_id=item["parentReference"]["id"],
                    drive_item_id=item["id"],
                    last_modified_at=item["lastModifiedDateTime"],
                    local_bytes=local,
                    stored_bytes=stored,
                )
            except OfficeContentError as exc:
                self.content_differs.append(f"{file.name}: the stored file can't be read as .{file.file_type}: {exc}")
                self.out(line + f"; the stored file can't be read as .{file.file_type}: {exc}")
                continue
            self.file_entries[file.name] = entry
            office = entry["content_rule"] == OFFICE_RULE
            if office and entry["content_sha256"] != office_content_sha256(local, file.file_type):
                what = f"stored document content differs from canary/ ({OFFICE_RULE})"
                self.content_differs.append(
                    f"{file.name}: {what}"
                    + (": an old copy? Re-run with --force to replace it" if skipped else "")
                )
                self.out(line + f"; {what}")
                continue
            if stored != local and office:
                sizes = f"size {len(local)} -> {len(stored)} bytes, local -> stored"
                why = f"SharePoint/OneDrive rewrote the package; content unchanged ({OFFICE_RULE})"
                self.stored_differs.append(f"{file.name}: {sizes}; {why}")
                line += f"; stored bytes differ ({sizes}): {why}"
            elif stored != local:
                sizes = f"size {len(local)} -> {len(stored)} bytes, local -> stored"
                why = (
                    "either a SharePoint/OneDrive rewrite or a stale copy (use --force to replace)"
                    if skipped
                    else "SharePoint/OneDrive changed the file when it was stored"
                )
                self.stored_differs.append(f"{file.name}: {sizes}; {why}")
                line += f"; stored bytes differ ({sizes}): {why}"
            self.out(line)


def run_seed(
    *,
    signin: Any,
    transport: Transport,
    canary_dir: Path,
    manifest_path: Path,
    force: bool = False,
    mail_timeout: float = 600,
    poll_interval: float = 10,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], str] = utc_now,
    out: Out = print,
) -> int:
    """0 manifest written; 1 a problem the output explains (no manifest written).
    Graph and sign-in errors are raised (the CLI prints them)."""
    manifest_path = Path(manifest_path)
    s = _Seed(signin=signin, transport=transport, canary_dir=canary_dir, force=force, sleep=sleep, now=now, out=out)
    if not s.read_local_files():
        return 1
    if manifest_path.exists():
        out(f"note: {manifest_path} exists; it will be overwritten with the values read back in this run.")

    alice, bob, admin = tenant.ALICE_UPN, tenant.BOB_UPN, tenant.ADMIN_UPN
    alice_mails, bob_mails = s.mails_for(alice), s.mails_for(bob)
    sp_files = [f for f in s.files if f.kind == "sharepoint_file"]
    od_files = [f for f in s.files if f.kind == "onedrive_file"]

    what = (
        f"check her mailbox for {_range(alice_mails)}, upload {_file_range(od_files)} to her OneDrive"
    )
    s.step(1, alice, what)
    g = s.client(alice, what)
    if not s.check_mailbox(g, alice):
        return 1
    s.seed_files(g, od_files)

    what = f"check his mailbox for {_range(bob_mails)}"
    s.step(2, bob, what)
    if not s.check_mailbox(s.client(bob, what), bob):
        return 1

    what = f"send the missing mails, upload {_file_range(sp_files)} to the SharePoint RestoreTest library"
    s.step(3, admin, what)
    g = s.client(admin, what)
    s.send_missing(g)
    s.seed_files(g, sp_files)

    deadline = clock() + mail_timeout
    missing: dict[str, list[str]] = {}
    for number, upn, mails in ((4, alice, alice_mails), (5, bob, bob_mails)):
        what = f"read back {_range(mails)} from {_short(upn)}'s mailbox (signed in already; no new sign-in)"
        s.step(number, upn, what)
        still = s.poll_and_read(s.client(upn, what), upn, deadline, clock, poll_interval)
        if still:
            missing[upn] = still

    out("")
    if missing:
        for upn, subjects in missing.items():
            out(f"error: missing after {mail_timeout:g} s in {upn}'s mailbox: {', '.join(subjects)}")
        out("No manifest was written. Run seed again later: mails already delivered are not sent twice.")
        return 1

    if s.content_differs:
        out("error: the tenant holds different document content than lab/canary/:")
        for line in s.content_differs:
            out(f"  {line}")
        out("No manifest was written.")
        return 1

    entries = [s.mail_entries[m.subject] for m in s.mails] + [s.file_entries[f.name] for f in s.files]
    replaced = manifest_path.exists()
    write_manifest(manifest_path, build_manifest(entries, s.now()))

    _report(s, out)
    sent = len(s.to_send)
    out(
        f"Seeded: 20 mails ({sent} sent, {20 - sent} already there), 20 files ({s.uploaded} uploaded, "
        f"{20 - s.uploaded} already there); {len(s.stored_differs)} stored file(s) differ from canary/, "
        f"{len(s.body_differs)} mail body(ies) differ from what was sent, {len(s.not_inbox)} mail(s) outside Inbox."
    )
    out(f"Manifest written: {manifest_path}" + (" (the previous one was overwritten)" if replaced else ""))
    out("Next: uv run python -m seeder hash     (offline: canary/ and the manifest agree)")
    out("      uv run python -m seeder verify   (re-read the 40 items from the tenant)")
    out(BACKUP_REMINDER)
    return 0


def _report(s: _Seed, out: Out) -> None:
    for title, lines in (
        ("Stored bytes differ from the local file:", s.stored_differs),
        ("Mail bodies read back differ from what was sent:", s.body_differs),
        ("Mails not in Inbox:", s.not_inbox),
    ):
        if lines:
            out(title)
            for line in lines:
                out(f"  {line}")
