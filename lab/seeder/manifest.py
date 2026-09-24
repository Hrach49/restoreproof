"""lab/seed-manifest.json (seed-manifest.v1): builders, validation, reader and the `hash` check.

The JSON Schema is shared/schemas/seed-manifest.v1.json. validate_manifest adds the
cross-field rules the schema can't express (catalog order, hash consistency).
"""

import functools
import hashlib
import json
import os
import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from seeder import MANIFEST_SCHEMA_PATH, tenant
from seeder.catalog import CanaryFile, CanaryMail, canary_files, canary_mails
from seeder.normalize import NORMALIZATION_ID, body_sha256
from seeder.office import CONTENT_FOLDERS, OFFICE_RULE, OfficeContentError, office_content_sha256

SCHEMA_ID = "seed-manifest.v1"
ENTRY_COUNT = 40

RULES: dict[str, str] = {
    "mail_recipients": (
        "RP-CANARY-0001..0010 are in alice's mailbox, 0011..0020 in bob's; the admin sent all 20"
    ),
    "file_types": (
        "type cycles pdf, docx, xlsx, txt, png by file number: 01 pdf, 02 docx, 03 xlsx, "
        "04 txt, 05 png, 06 pdf, ... 20 png"
    ),
    "file_locations": (
        "rp-canary-01..10 are in the root of the SharePoint RestoreTest library, 11..20 in "
        "alice's OneDrive RestoreTest folder"
    ),
    "mail_body_hash": (
        "body_sha256 is SHA-256 of the body read back from the recipient's mailbox, normalised "
        "by body_normalization (text-v1, lab/README.md)"
    ),
    "file_hash": (
        "compare a restored file with content_sha256 by content_rule: bytes = SHA-256 of the "
        "whole file (equal to stored_sha256); office-v1 (docx, xlsx) = SHA-256 of the document's "
        "content parts, because SharePoint rewrites Office packages (lab/README.md)"
    ),
}

_KIND_DEFS = {
    "mail": "mail_entry",
    "sharepoint_file": "sharepoint_file_entry",
    "onedrive_file": "onedrive_file_entry",
}
_DATE_FIELDS = ("sent_at", "received_at", "last_modified_at")
_SECRET_WORDS = ("token", "password", "secret", "bearer")
_GRAPH_DATETIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})"
)


class ManifestError(Exception):
    """The manifest is missing, unreadable or invalid. `problems` lists each finding."""

    def __init__(self, problems: str | list[str]):
        self.problems = [problems] if isinstance(problems, str) else list(problems)
        super().__init__("\n".join(self.problems))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iso_utc(value: str) -> str:
    """Graph datetime -> "YYYY-MM-DDTHH:MM:SSZ" in UTC; fractional seconds are truncated."""
    match = _GRAPH_DATETIME.fullmatch(value)
    if not match:
        raise ValueError(f"not an ISO-8601 date-time with a time zone: {value!r}")
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    zone = match.group(7)
    if zone == "Z":
        tz = timezone.utc
    else:
        sign = 1 if zone[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
    moment = datetime(year, month, day, hour, minute, second, tzinfo=tz)  # ValueError if bad
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mail_entry(
    mail: CanaryMail,
    *,
    sender: str,
    folder: str,
    sent_at: str,
    received_at: str,
    internet_message_id: str,
    graph_message_id: str,
    body_readback: str,
) -> dict:
    return {
        "id": mail.subject,
        "kind": "mail",
        "subject": mail.subject,
        "sender": sender,
        "recipient": mail.recipient,
        "location": {"mailbox": mail.recipient, "folder": folder},
        "sent_at": iso_utc(sent_at),
        "received_at": iso_utc(received_at),
        "internet_message_id": internet_message_id,
        "graph_message_id": graph_message_id,
        "body_content_type": "text",
        "body_normalization": NORMALIZATION_ID,
        "body_sha256": body_sha256(body_readback),
        "sent_body_sha256": body_sha256(mail.body),
        "body_readback_exact": body_readback == mail.body,
    }


def file_entry(
    file: CanaryFile,
    *,
    folder_id: str,
    drive_item_id: str,
    last_modified_at: str,
    local_bytes: bytes,
    stored_bytes: bytes,
) -> dict:
    if file.kind == "sharepoint_file":
        location = {
            "site_id": tenant.SHAREPOINT_SITE_ID,
            "list_id": tenant.SHAREPOINT_LIST_ID,
            "drive_id": file.drive_id,
            "folder_id": folder_id,
            "folder_path": file.folder_path,
        }
    else:
        location = {
            "user": tenant.ALICE_UPN,
            "drive_id": file.drive_id,
            "folder_id": folder_id,
            "folder_path": file.folder_path,
        }
    local_sha, stored_sha = sha256_hex(local_bytes), sha256_hex(stored_bytes)
    if content_rule_for(file.file_type) == OFFICE_RULE:
        content_sha = office_content_sha256(stored_bytes, file.file_type)
    else:
        content_sha = stored_sha
    return {
        "id": file.name,
        "kind": file.kind,
        "name": file.name,
        "file_type": file.file_type,
        "location": location,
        "drive_item_id": drive_item_id,
        "uploaded_by": file.uploader,
        "last_modified_at": iso_utc(last_modified_at),
        "local_sha256": local_sha,
        "local_size": len(local_bytes),
        "stored_sha256": stored_sha,
        "stored_size": len(stored_bytes),
        "stored_matches_local": stored_sha == local_sha,
        "content_rule": content_rule_for(file.file_type),
        "content_sha256": content_sha,
    }


def content_rule_for(file_type: str) -> str:
    """office-v1 for the Office types SharePoint rewrites, bytes for everything else."""
    return OFFICE_RULE if file_type in CONTENT_FOLDERS else "bytes"


def build_manifest(entries: list[dict], seeded_at: str) -> dict:
    return {
        "schema": SCHEMA_ID,
        "tenant": tenant.TENANT_DOMAIN,
        "tenant_id": tenant.TENANT_ID,
        "seeded_at": iso_utc(seeded_at),
        "rules": dict(RULES),
        "entries": list(entries),
    }


# --- validation -----------------------------------------------------------------------

@functools.cache
def _schema() -> dict:
    return json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))


def find_secret_words(text: str) -> list[str]:
    """Secret-looking words (case-insensitive) in `text`; the manifest must have none."""
    lowered = text.lower()
    return [word for word in _SECRET_WORDS if word in lowered]


def _expected_ids_and_kinds() -> list[tuple[str, str]]:
    return [(m.subject, "mail") for m in canary_mails()] + [
        (f.name, f.kind) for f in canary_files()
    ]


def _entry_label(manifest: dict, path: list) -> str:
    if len(path) >= 2 and path[0] == "entries" and isinstance(path[1], int):
        entry = manifest["entries"][path[1]]
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            return f"entry {entry['id']}"
        return f"entries[{path[1]}]"
    return "manifest"


def _describe(error: ValidationError) -> str:
    field = ".".join(str(p) for p in error.absolute_path) or "(top level)"
    if error.validator in ("minItems", "maxItems") and isinstance(error.instance, list):
        return f"{field}: has {len(error.instance)} items, expected {error.validator_value}"
    if error.validator == "const":
        return f"{field}: expected {error.validator_value!r}, got {error.instance!r}"
    if error.validator == "enum":
        return f"{field}: expected one of {error.validator_value!r}, got {error.instance!r}"
    return f"{field}: {error.message}"


def _schema_problems(manifest: dict) -> list[str]:
    schema = _schema()
    problems = []
    for error in sorted(
        Draft202012Validator(schema).iter_errors(manifest), key=lambda e: [str(p) for p in e.absolute_path]
    ):
        path = list(error.absolute_path)
        label = _entry_label(manifest, path)
        if error.validator == "oneOf" and len(path) == 2 and path[0] == "entries":
            # Re-validate against the shape `kind` selects, for a message naming the field.
            entry = error.instance
            kind = entry.get("kind") if isinstance(entry, dict) else None
            if kind not in _KIND_DEFS:
                problems.append(
                    f"{label}: kind: expected one of {sorted(_KIND_DEFS)!r}, got {kind!r}"
                )
                continue
            sub = {"$defs": schema["$defs"], "$ref": f"#/$defs/{_KIND_DEFS[kind]}"}
            for sub_error in Draft202012Validator(sub).iter_errors(entry):
                problems.append(f"{label}: {_describe(sub_error)}")
            continue
        problems.append(f"{label}: {_describe(error)}")
    return problems


def _cross_field_problems(manifest: dict) -> list[str]:
    problems = []
    entries = manifest["entries"]
    seen: dict[str, int] = {}
    for index, entry in enumerate(entries):
        if entry["id"] in seen:
            problems.append(
                f"entry {entry['id']}: duplicate entry id (entries {seen[entry['id']]} and {index})"
            )
        seen.setdefault(entry["id"], index)

    for index, (entry, (want_id, want_kind)) in enumerate(zip(entries, _expected_ids_and_kinds())):
        if entry["id"] != want_id:
            problems.append(
                f"entries[{index}]: expected {want_id}, got {entry['id']} "
                "(order: mails RP-CANARY-0001..0020, then files rp-canary-01..20)"
            )
        elif entry["kind"] != want_kind:
            problems.append(
                f"entry {entry['id']}: kind expected {want_kind}, got {entry['kind']}"
            )

    try:
        iso_utc(manifest["seeded_at"])
    except ValueError:
        problems.append(f"manifest: seeded_at is not a real date: {manifest['seeded_at']!r}")

    for entry in entries:
        label = f"entry {entry['id']}"
        for field in _DATE_FIELDS:
            if field in entry:
                try:
                    iso_utc(entry[field])
                except ValueError:
                    problems.append(f"{label}: {field} is not a real date: {entry[field]!r}")
        if entry["kind"] == "mail":
            problems += _mail_problems(label, entry)
        else:
            problems += _file_problems(label, entry)
    return problems


def _mail_problems(label: str, entry: dict) -> list[str]:
    problems = []
    if entry["subject"] != entry["id"]:
        problems.append(f"{label}: subject expected {entry['id']}, got {entry['subject']}")
    if entry["location"]["mailbox"] != entry["recipient"]:
        problems.append(
            f"{label}: location.mailbox expected {entry['recipient']} (the recipient), "
            f"got {entry['location']['mailbox']}"
        )
    if entry["body_readback_exact"] and entry["body_sha256"] != entry["sent_body_sha256"]:
        problems.append(
            f"{label}: body_readback_exact is true but body_sha256 {entry['body_sha256']} "
            f"!= sent_body_sha256 {entry['sent_body_sha256']}"
        )
    return problems


def _file_problems(label: str, entry: dict) -> list[str]:
    problems = []
    if entry["name"] != entry["id"]:
        problems.append(f"{label}: name expected {entry['id']}, got {entry['name']}")
    extension = entry["name"].rsplit(".", 1)[-1]
    if entry["file_type"] != extension:
        problems.append(f"{label}: file_type expected {extension}, got {entry['file_type']}")
    same = entry["stored_sha256"] == entry["local_sha256"]
    if entry["stored_matches_local"] != same:
        problems.append(
            f"{label}: stored_matches_local expected {str(same).lower()} "
            f"(stored_sha256 {'==' if same else '!='} local_sha256), "
            f"got {str(entry['stored_matches_local']).lower()}"
        )
    rule = content_rule_for(entry["file_type"])
    if entry["content_rule"] != rule:
        problems.append(f"{label}: content_rule expected {rule} for .{entry['file_type']}, got {entry['content_rule']}")
    elif rule == "bytes" and entry["content_sha256"] != entry["stored_sha256"]:
        problems.append(
            f"{label}: content_sha256 expected stored_sha256 {entry['stored_sha256']} "
            f"(content_rule bytes), got {entry['content_sha256']}"
        )
    if same and entry["stored_size"] != entry["local_size"]:
        problems.append(
            f"{label}: stored_size {entry['stored_size']} != local_size {entry['local_size']} "
            "although the hashes are equal"
        )
    return problems


def validate_manifest(manifest: dict) -> None:
    """Raise ManifestError listing every problem: schema, catalog order, hash consistency."""
    if not isinstance(manifest, dict):
        raise ManifestError(f"manifest: expected a JSON object, got {type(manifest).__name__}")
    problems = _schema_problems(manifest)
    if not problems:
        problems = _cross_field_problems(manifest)
    words = find_secret_words(dumps_manifest(manifest))
    if words:
        problems.append(f"manifest: contains secret-looking word(s): {', '.join(words)}")
    if problems:
        raise ManifestError(problems)


# --- reading and writing ----------------------------------------------------------------

def dumps_manifest(manifest: dict) -> str:
    return json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def write_manifest(path: Path, manifest: dict) -> None:
    """Validate, then write UTF-8 with LF endings (via a temp file, so a failure leaves no half file)."""
    validate_manifest(manifest)
    path = Path(path)
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dumps_manifest(manifest))
    os.replace(temp, path)


def load_manifest(path: Path) -> dict:
    """Read the manifest JSON. Does not validate; call validate_manifest for that."""
    path = Path(path)
    if not path.is_file():
        raise ManifestError(
            f"{path} not found. Run `python -m seeder seed` to seed the tenant and write it."
        )
    try:
        data = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"{path} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: expected a JSON object, got {type(data).__name__}")
    return data


# --- the `hash` command -------------------------------------------------------------------

def _check_entry(entry: dict, canary_dir: Path, mails: dict[str, CanaryMail]) -> tuple[str, list[str]]:
    """(what was checked when OK, list of differences) for one entry."""
    if entry["kind"] == "mail":
        mail = mails[entry["id"]]
        problems = []
        want = body_sha256(mail.body)
        if entry["sent_body_sha256"] != want:
            problems.append(
                f"sent_body_sha256 differs: manifest {entry['sent_body_sha256']}, catalog body {want}"
            )
        if entry["subject"] != mail.subject:
            problems.append(f"subject differs: manifest {entry['subject']}, catalog {mail.subject}")
        if entry["recipient"] != mail.recipient:
            problems.append(
                f"recipient differs: manifest {entry['recipient']}, catalog {mail.recipient}"
            )
        return f"sent_body_sha256 {want}", problems

    path = Path(canary_dir) / entry["name"]
    if not path.is_file():
        return "", [f"missing: {path} does not exist"]
    data = path.read_bytes()
    actual = sha256_hex(data)
    problems = []
    if actual != entry["local_sha256"]:
        problems.append(
            f"local_sha256 differs: manifest {entry['local_sha256']}, file {actual}"
        )
    if len(data) != entry["local_size"]:
        problems.append(f"local_size differs: manifest {entry['local_size']}, file {len(data)}")
    if entry["content_rule"] != OFFICE_RULE:
        return f"local_sha256 {actual}", problems
    # SharePoint rewrites the package, not the content: the committed file's content parts
    # must hash to the content_sha256 recorded from the stored bytes.
    try:
        content = office_content_sha256(data, entry["file_type"])
    except OfficeContentError as exc:
        return "", problems + [f"content_sha256 ({OFFICE_RULE}) can't be computed: {exc}"]
    if content != entry["content_sha256"]:
        problems.append(
            f"content_sha256 ({OFFICE_RULE}) differs: manifest {entry['content_sha256']}, file {content}"
        )
    return f"local_sha256 {actual}, content_sha256 ({OFFICE_RULE}) {content}", problems


def _load_valid(manifest_path: Path) -> dict:
    manifest = load_manifest(manifest_path)
    validate_manifest(manifest)
    return manifest


def _results(manifest: dict, canary_dir: Path) -> list[tuple[str, str, list[str]]]:
    mails = {m.subject: m for m in canary_mails()}
    return [(e["id"], *_check_entry(e, canary_dir, mails)) for e in manifest["entries"]]


def check_hashes(manifest_path: Path, canary_dir: Path) -> list[str]:
    """Differences between the manifest and the catalog / canary files ("<id>: <problem>").

    Raises ManifestError if the manifest is missing, unreadable or invalid.
    """
    manifest = _load_valid(manifest_path)
    return [
        f"{entry_id}: {problem}"
        for entry_id, _, problems in _results(manifest, canary_dir)
        for problem in problems
    ]


def run_hash(manifest_path: Path, canary_dir: Path, out: Callable[[str], None] = print) -> int:
    """`python -m seeder hash`: 0 all reproduce, 1 any difference, 2 manifest missing/invalid."""
    try:
        manifest = _load_valid(manifest_path)
    except ManifestError as exc:
        out(f"error: {manifest_path}:")
        for problem in exc.problems:
            out(f"  {problem}")
        return 2

    results = _results(manifest, canary_dir)
    width = max(len(entry_id) for entry_id, _, _ in results)
    good = 0
    for entry_id, checked, problems in results:
        if problems:
            out(f"FAIL  {entry_id.ljust(width)}  {'; '.join(problems)}")
        else:
            good += 1
            out(f"ok    {entry_id.ljust(width)}  {checked}")
    total = len(results)
    if good == total:
        out(f"{good}/{total} entries reproduce the manifest hashes")
        return 0
    bad = total - good
    out(f"{good}/{total} entries reproduce the manifest hashes; {bad} {'differs' if bad == 1 else 'differ'}")
    return 1
