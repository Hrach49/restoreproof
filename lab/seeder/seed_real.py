"""`python -m seeder seed-real`: put real, non-canary files and mails in the tenant (L1.8).

The Worker's sampler takes half of each type from the canaries and half at random from real data
(W2.6). The lab had no real files, so the random SharePoint and OneDrive halves came up short
(docs/decisions.md 2026-10-03, W3.6 point 2). This puts a fixed set of small files in the root of
the RestoreTest site's default drive and of alice's OneDrive, and sends mails between alice and
bob. No manifest: the Worker reads a random item's expected values from Veeam.

It writes with the seeder app's delegated scopes, which reach far more than it needs
(`Sites.ReadWrite.All`), so it finds its places itself and refuses the restore targets and the
canary sources before any upload or send. It never replaces a file and never sends a mail whose
subject is already in alice's or bob's mailbox, so it can be run again.
"""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

from seeder import graph, tenant
from seeder.generate import GENERATORS, _xlsx
from seeder.graph import GraphClient, GraphError, seg
from seeder.http import Transport
from seeder.manifest import load_manifest

Out = Callable[[str], None]
STEPS = 6
FILE_TYPES = ("txt", "pdf", "png", "docx", "xlsx")
MAX_FILE_BYTES = 1024 * 1024  # all small: the Worker downloads each to compare its size
CANARY_PREFIX = "RP-CANARY-"  # the Worker's lister skips these, ASCII case-insensitive
FORBIDDEN_CHARS = "/\\:"
STOPPED = "Stopped: nothing was uploaded or sent."
COMMAND = "seed-real"  # what an unknown outcome tells the owner to run again
NEXT = (
    "Next: run the Veeam backup (RP-Lab-Full, or start it by hand), then the read-only "
    "[live][sample] dry run (lab/README.md, \"Real data for the random sample\")."
)

FileKind = Literal["sharepoint_file", "onedrive_file"]

# Never written to, by id (lab/tenant.md): the restore targets and the canary sources.
FORBIDDEN_DRIVES = {
    tenant.RESTORE_TARGET_DRIVE_ID.lower(): "RestoreTarget",
    tenant.SHAREPOINT_DRIVE_ID.lower(): "RestoreTest",
}
FORBIDDEN_FOLDERS = {
    tenant.ONEDRIVE_TARGET_FOLDER_ID.lower(): "RestoreTarget",
    tenant.ONEDRIVE_FOLDER_ID.lower(): "RestoreTest",
}
FORBIDDEN_DRIVE_NAMES = ("restoretarget", "restoretest")
MAIL_USERS = (tenant.ALICE_UPN, tenant.BOB_UPN)

SITE_DRIVE = "the RestoreTest site's default drive"
ALICE_DRIVE = "alice's OneDrive"


class RefusedError(Exception):
    """A write would have gone somewhere seed-real must never write."""


@dataclass(frozen=True)
class RealFile:
    number: int  # picks the PNG's colours and the xlsx's numbers; 31.. so none matches a canary
    name: str
    kind: FileKind
    sentence: str  # the text the file carries

    @property
    def file_type(self) -> str:
        return self.name.rsplit(".", 1)[-1] if "." in self.name else ""


@dataclass(frozen=True)
class RealMail:
    subject: str
    sentence: str
    sender: str
    recipient: str

    @property
    def body(self) -> str:
        """Plain text, CRLF line breaks, as the canary mails."""
        return f"Hi,\r\n\r\n{self.sentence}\r\n\r\nThanks"


def _sp(number: int, name: str, sentence: str) -> RealFile:
    return RealFile(number, name, "sharepoint_file", sentence)


def _od(number: int, name: str, sentence: str) -> RealFile:
    return RealFile(number, name, "onedrive_file", sentence)


def real_files() -> tuple[RealFile, ...]:
    """7 files per place: two each of txt, pdf and png, and one Office file (name check only)."""
    return (
        _sp(31, "team-meeting-notes.txt", "Notes from the Monday team meeting: the new rota starts in May."),
        _sp(32, "supplier-contacts.txt", "Supplier contacts for the office move, last checked in March."),
        _sp(33, "project-brief.pdf", "Project brief: replace the meeting room screens before summer."),
        _sp(34, "budget-summary.pdf", "Budget summary for the second quarter, figures in euro."),
        _sp(35, "office-floor-plan.png", "Office floor plan, first draft."),
        _sp(36, "brand-colours-draft.png", "Brand colours, second draft."),
        _sp(37, "room-bookings.xlsx", "Room bookings for the training week."),
        _od(38, "reading-list.txt", "Books to read this autumn, shortest first."),
        _od(39, "travel-notes.txt", "Travel notes: the hotel is a short walk from the station."),
        _od(40, "expense-report-march.pdf", "Expense report for March: two train tickets and one dinner."),
        _od(41, "course-certificate.pdf", "Certificate of completion for the spreadsheet basics course."),
        _od(42, "holiday-photo.png", "A holiday photo."),
        _od(43, "whiteboard-sketch.png", "A whiteboard sketch from the planning session."),
        _od(44, "weekly-status.docx", "Weekly status: the migration plan is ready for review."),
    )


def real_mails() -> tuple[RealMail, ...]:
    """6 from alice to bob and 6 from bob to alice. Each lands twice in the backup under one
    subject (Sent Items and Inbox), so 12 sends give the sampler 12 subjects."""
    alice, bob = tenant.ALICE_UPN, tenant.BOB_UPN
    to_bob = (
        ("Lunch on Friday", "Shall we try the new place on the corner at one?"),
        ("Notes from the supplier call", "They can deliver the chairs in the second week of May."),
        ("Draft agenda for the offsite", "I put the budget review first; move it if you like."),
        ("Printer on the second floor", "It jams on double-sided jobs again, I logged a ticket."),
        ("Holiday cover in August", "I am away from the 4th to the 15th, can you cover the desk?"),
        ("Parking passes for visitors", "Reception has ten passes left for next week."),
    )
    to_alice = (
        ("Quarterly numbers are in", "Sales are up a little on last quarter, details on Monday."),
        ("Laptop replacement request", "Mine will not charge any more, is there a spare one?"),
        ("Kitchen rota for next week", "You are on Tuesday and Thursday, I swapped with Sam."),
        ("Training session moved to Thursday", "Same room, same time, only the day changed."),
        ("Client visit on Tuesday", "They arrive at ten, I booked the big meeting room."),
        ("Updated phone list", "The new numbers for the support team are on the wiki."),
    )
    return tuple(RealMail(s, t, alice, bob) for s, t in to_bob) + tuple(RealMail(s, t, bob, alice) for s, t in to_alice)


def real_file_bytes(file: RealFile) -> bytes:
    """Deterministic, through the canary generators (standard library only, nothing compressed).
    A txt gets its own text and an xlsx its own sheet name: the canary footer and the canary
    sheet name would call them canaries."""
    if file.file_type == "txt":
        return f"{file.name}\n{file.sentence}\n".encode("utf-8")
    if file.file_type == "xlsx":
        return _xlsx(file, sheet_name="Sheet1")
    return GENERATORS[file.file_type](file)  # they read only name, sentence and number


# --- the plan's rules -------------------------------------------------------------------------

def name_key(text: str) -> str:
    """The Worker's same-name key (worker/src/name_key.hpp) for the printable ASCII the rules
    allow: upper case."""
    return text.upper()


def canary_names(manifest: dict) -> set[str]:
    """Every canary file name and mail subject in the manifest."""
    names = set()
    for entry in manifest.get("entries", []):
        for key in ("id", "name", "subject"):
            if isinstance(entry.get(key), str):
                names.add(entry[key])
    return names


def _printable_ascii(text: str) -> bool:
    return bool(text) and text == text.strip(" ") and all(" " <= c <= "~" for c in text)


def _name_problems(label: str, names: Iterable[str], canary: dict[str, str]) -> list[str]:
    problems = []
    seen: dict[str, str] = {}
    for name in names:
        if not _printable_ascii(name):
            problems.append(f"{label} {name!r} must be printable ASCII with no space at either end, and not empty")
        for ch in FORBIDDEN_CHARS:
            if ch in name:
                problems.append(f"{label} {name!r} contains {ch!r}")
        key = name_key(name)
        if key.startswith(CANARY_PREFIX):
            problems.append(f"{label} {name!r} starts with rp-canary- (in some case)")
        if key in canary:
            problems.append(f"{label} {name!r} has the name key of a canary ({canary[key]!r})")
        if key in seen:
            problems.append(f"{label}s {seen[key]!r} and {name!r} share one name key")
        seen.setdefault(key, name)
    return problems


def plan_problems(files: Iterable[RealFile], mails: Iterable[RealMail], canary: Iterable[str]) -> list[str]:
    """What breaks a rule (lab/README.md, "Real data for the random sample"); [] if nothing."""
    files, mails = list(files), list(mails)
    canary_keys = {name_key(n): n for n in canary}
    problems = []
    for kind, label in (("sharepoint_file", "SharePoint file"), ("onedrive_file", "OneDrive file")):
        problems += _name_problems(label, [f.name for f in files if f.kind == kind], canary_keys)
    problems += _name_problems("mail subject", [m.subject for m in mails], canary_keys)
    for file in files:
        if file.file_type not in FILE_TYPES:
            problems.append(f"file {file.name!r}: type {file.file_type!r} is not one of {', '.join(FILE_TYPES)}")
            continue
        size = len(real_file_bytes(file))
        if size > MAX_FILE_BYTES:
            problems.append(f"file {file.name!r} is {size} bytes, more than {MAX_FILE_BYTES}")
    users = {u.lower() for u in MAIL_USERS}
    for mail in mails:
        if mail.sender.lower() not in users:
            problems.append(f"mail {mail.subject!r} goes only from alice or bob, not {mail.sender}")
        if mail.recipient.lower() not in users:
            problems.append(f"mail {mail.subject!r} goes only to alice or bob, not {mail.recipient}")
        elif mail.recipient.lower() == mail.sender.lower():
            problems.append(f"mail {mail.subject!r} goes to its own sender")
    return problems


def send_refusal(mail: RealMail, upn: str) -> str | None:
    """Why upn may not send this mail, or None: only alice to bob or bob to alice, sent by its sender."""
    users = {u.lower() for u in MAIL_USERS}
    others = users - {upn.lower()}
    if upn.lower() in users and mail.sender.lower() == upn.lower() and mail.recipient.lower() in others:
        return None
    return (
        f"refused to send {mail.subject!r} from {mail.sender} to {mail.recipient}: "
        "seed-real sends only between alice and bob"
    )


# --- the places -------------------------------------------------------------------------------

@dataclass(frozen=True)
class Place:
    where: str
    drive_id: str
    root_id: str


def _drive_problem(where: str, drive: dict, expected: str | None) -> str | None:
    drive_id, name = str(drive.get("id", "")), str(drive.get("name", ""))
    if drive_id.lower() in FORBIDDEN_DRIVES:
        return f"refused: {where} is the {FORBIDDEN_DRIVES[drive_id.lower()]} library ({drive_id})"
    if name.lower() in FORBIDDEN_DRIVE_NAMES:
        return f"refused: {where} ({drive_id}) is named {name!r}, like a restore target or the canary library"
    if expected is not None and drive_id != expected:
        return f"refused: {where} ({drive_id}) is not alice's OneDrive as lab/tenant.md records it ({expected})"
    return None


def _root_problem(where: str, root: dict) -> str | None:
    root_id = str(root.get("id", ""))
    if root_id.lower() in FORBIDDEN_FOLDERS:
        return f"refused: {where} root is the {FORBIDDEN_FOLDERS[root_id.lower()]} folder ({root_id})"
    if "root" not in root:
        return f"refused: {where} root ({root_id}) is not a drive's root folder"
    return None


def find_place(
    g: GraphClient, where: str, drive_path: str, root_path: Callable[[str], str], *, owner: str,
    expected_drive: str | None = None,
) -> Place | str:
    """The drive and its root folder, read through Graph, or why seed-real refuses them."""
    drive = g.get_json(drive_path, params={"$select": "id,name,driveType"}, owner=owner)
    problem = _drive_problem(where, drive, expected_drive)
    if problem:
        return problem
    root = g.get_json(root_path(drive["id"]), params={"$select": "id,name,root"}, owner=owner)
    problem = _root_problem(where, root)
    if problem:
        return problem
    return Place(where, drive["id"], root["id"])


# --- the run ----------------------------------------------------------------------------------

class _SeedReal:
    def __init__(self, *, signin, transport, sleep, out) -> None:
        self.signin = signin
        self.transport = transport
        self.sleep = sleep
        self.out = out
        self.present: set[str] = set()  # subjects already in alice's or bob's mailbox
        self.counts = {"sharepoint_file": [0, 0], "onedrive_file": [0, 0], "mail": [0, 0]}  # [written, there]

    def client(self, upn: str, purpose: str) -> GraphClient:
        return GraphClient(self.transport, self.signin.token_provider(upn, purpose), upn, sleep=self.sleep)

    def step(self, number: int, upn: str, what: str) -> None:
        self.out("")
        self.out(f"Step {number}/{STEPS}: {upn} - {what}")

    def look_for_mails(self, g: GraphClient, upn: str, mails: list[RealMail]) -> None:
        """Note which subjects are in upn's mailbox, Deleted Items left out."""
        deleted = graph.get_deleted_items_id(g, owner=upn)
        found = [
            m.subject for m in mails
            if graph.find_messages_by_subject(g, m.subject, owner=upn, exclude_folder_id=deleted)
        ]
        self.present.update(found)
        self.out(f"  {len(found)} of {len(mails)} subject(s) already in {upn}'s mailbox")

    def upload(self, g: GraphClient, upn: str, place: Place, files: list[RealFile]) -> None:
        for file in files:
            counts = self.counts[file.kind]
            if graph.get_item_by_path(g, place.drive_id, place.root_id, file.name, owner=upn) is not None:
                counts[1] += 1
                self.out(f"  {file.name}: already there, not replaced")
                continue
            try:
                graph.upload_file(
                    g, place.drive_id, place.root_id, file.name, real_file_bytes(file),
                    replace=False, owner=upn, rerun=COMMAND,
                )
            except GraphError as exc:
                if exc.status != 409:
                    raise
                # A 409 for another reason (a lock, say) must not read as "already there".
                if graph.get_item_by_path(g, place.drive_id, place.root_id, file.name, owner=upn) is None:
                    raise GraphError(
                        f"{file.name}: Graph answered 409 Conflict, but no file of that name is in the root "
                        f"of {place.where}; nothing was replaced",
                        status=409,
                        method=exc.method,
                        path=exc.path,
                    ) from None
                counts[1] += 1
                self.out(f"  {file.name}: already there, not replaced")
                continue
            counts[0] += 1
            self.out(f"  {file.name}: uploaded")

    def send(self, g: GraphClient, upn: str, mails: list[RealMail]) -> None:
        for mail in mails:
            if mail.subject in self.present:
                self.counts["mail"][1] += 1
                self.out(f"  {mail.subject}: already in a mailbox, not sent")
                continue
            # Checked again here too, whatever the plan and the check before the writes said.
            refusal = send_refusal(mail, upn)
            if refusal:
                raise RefusedError(refusal)
            graph.send_mail(
                g, subject=mail.subject, body_text=mail.body, to_address=mail.recipient, owner=upn, rerun=COMMAND
            )
            self.counts["mail"][0] += 1
            self.out(f"  {mail.subject}: sent to {mail.recipient}")


def run_seed_real(
    *,
    signin: Any,
    transport: Transport,
    manifest_path: Path,
    files: Iterable[RealFile] | None = None,
    mails: Iterable[RealMail] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    out: Out = print,
) -> int:
    """0 done; 1 a rule or a place refused, which the output explains (nothing written).
    A missing or invalid manifest (ManifestError), a send refused (RefusedError), Graph and
    sign-in errors are raised (the CLI prints them, exit 2)."""
    files = list(real_files() if files is None else files)
    mails = list(real_mails() if mails is None else mails)
    canary = canary_names(load_manifest(manifest_path))
    problems = plan_problems(files, mails, canary)
    if problems:
        for problem in problems:
            out(f"error: {problem}")
        out(STOPPED)
        return 1

    alice, bob, admin = tenant.ALICE_UPN, tenant.BOB_UPN, tenant.ADMIN_UPN
    s = _SeedReal(signin=signin, transport=transport, sleep=sleep, out=out)
    sp_files = [f for f in files if f.kind == "sharepoint_file"]
    od_files = [f for f in files if f.kind == "onedrive_file"]
    from_alice = [m for m in mails if m.sender.lower() == alice.lower()]
    from_bob = [m for m in mails if m.sender.lower() == bob.lower()]

    what = f"find {SITE_DRIVE} and check it"
    s.step(1, admin, what)
    sp = find_place(
        s.client(admin, what), SITE_DRIVE, f"/sites/{seg(tenant.SHAREPOINT_SITE_ID)}/drive",
        lambda drive_id: f"/drives/{seg(drive_id)}/root", owner=admin,
    )
    if isinstance(sp, str):
        out(f"error: {sp}")
        out(STOPPED)
        return 1
    out(f"  drive {sp.drive_id}, root {sp.root_id}: ok")

    what = f"find her OneDrive root and check it, look for the {len(mails)} subjects in her mailbox"
    s.step(2, alice, what)
    g = s.client(alice, what)
    od = find_place(
        g, ALICE_DRIVE, "/me/drive", lambda _: "/me/drive/root", owner=alice, expected_drive=tenant.ONEDRIVE_DRIVE_ID
    )
    if isinstance(od, str):
        out(f"error: {od}")
        out(STOPPED)
        return 1
    out(f"  drive {od.drive_id}, root {od.root_id}: ok")
    s.look_for_mails(g, alice, mails)

    what = f"look for the {len(mails)} subjects in his mailbox"
    s.step(3, bob, what)
    s.look_for_mails(s.client(bob, what), bob, mails)

    # Every send checked again before the first write, so a refused one can't follow an upload.
    for mail in mails:
        refusal = send_refusal(mail, mail.sender)
        if refusal:
            raise RefusedError(f"{refusal}. {STOPPED}")

    what =f"upload {len(sp_files)} file(s) to the root of {SITE_DRIVE} (signed in already)"
    s.step(4, admin, what)
    s.upload(s.client(admin, what), admin, sp, sp_files)

    what = f"upload {len(od_files)} file(s) to her OneDrive root, send {len(from_alice)} mail(s) to bob (signed in already)"
    s.step(5, alice, what)
    g = s.client(alice, what)
    s.upload(g, alice, od, od_files)
    s.send(g, alice, from_alice)

    what = f"send {len(from_bob)} mail(s) to alice (signed in already)"
    s.step(6, bob, what)
    s.send(s.client(bob, what), bob, from_bob)

    c = s.counts
    out("")
    out(
        f"Seeded real data: SharePoint {c['sharepoint_file'][0]} uploaded, {c['sharepoint_file'][1]} already there; "
        f"OneDrive {c['onedrive_file'][0]} uploaded, {c['onedrive_file'][1]} already there; "
        f"mail {c['mail'][0]} sent, {c['mail'][1]} already there."
    )
    out("Mails are sent, not waited for: Exchange delivers them within minutes.")
    out(NEXT)
    return 0
