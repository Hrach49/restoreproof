"""Builds a complete, valid fake manifest plus a matching canary dir in a temp folder.

Uses made-up file bytes (never the committed lab/canary/ files) so these tests don't
depend on the generators.
"""

from pathlib import Path

from seeder.catalog import canary_files, canary_mails
from seeder.manifest import build_manifest, file_entry, mail_entry
from tests.office_fakes import office_zip, sharepoint_rewrite

SEEDED_AT = "2026-09-25T10:00:00Z"
# SharePoint rewrites Office files on upload, so the fake stores different bytes for these.
REWRITTEN_TYPES = {"docx", "xlsx"}


def fake_file_bytes(name: str) -> bytes:
    file_type = name.rsplit(".", 1)[-1]
    if file_type in REWRITTEN_TYPES:
        return office_zip(file_type, f"fake canary content of {name}")
    return f"fake canary content of {name}\n".encode("ascii")


def fake_stored_bytes(name: str, file_type: str, kind: str) -> bytes:
    local = fake_file_bytes(name)
    if kind == "sharepoint_file" and file_type in REWRITTEN_TYPES:
        return sharepoint_rewrite(local)
    return local


def make_canary_dir(root: Path) -> Path:
    canary = root / "canary"
    canary.mkdir(parents=True, exist_ok=True)
    for f in canary_files():
        (canary / f.name).write_bytes(fake_file_bytes(f.name))
    return canary


def make_entries() -> list[dict]:
    entries = []
    for m in canary_mails():
        entries.append(
            mail_entry(
                m,
                sender=m.sender,
                folder="Inbox",
                sent_at=f"2026-09-25T10:{m.number:02d}:00.1234567Z",
                received_at=f"2026-09-25T10:{m.number:02d}:05Z",
                internet_message_id=f"<fake-{m.number:04d}@RestoreProofLab.onmicrosoft.com>",
                graph_message_id=f"AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0Fake{m.number:04d}",
                body_readback=m.body,
            )
        )
    for f in canary_files():
        entries.append(
            file_entry(
                f,
                folder_id="01FAKEPARENTFOLDER" if f.folder_id == "root" else f.folder_id,
                drive_item_id=f"01FAKEITEM{f.number:02d}",
                last_modified_at="2026-09-25T10:30:00+00:00",
                local_bytes=fake_file_bytes(f.name),
                stored_bytes=fake_stored_bytes(f.name, f.file_type, f.kind),
            )
        )
    return entries


def make_manifest() -> dict:
    return build_manifest(make_entries(), SEEDED_AT)
