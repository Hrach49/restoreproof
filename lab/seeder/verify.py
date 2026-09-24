"""`python -m seeder verify`: re-read the 40 items by their Graph ids and compare with the manifest.

Each item is read as the account that owns it (delegated Graph): alice for mails 0001-0010 and
the OneDrive files, bob for mails 0011-0020, the admin for the SharePoint files.
"""

import time
from pathlib import Path
from typing import Any, Callable

from seeder import graph, tenant
from seeder.graph import GraphClient, GraphError
from seeder.http import Transport
from seeder.manifest import ManifestError, iso_utc, load_manifest, sha256_hex, validate_manifest
from seeder.normalize import body_sha256

Out = Callable[[str], None]
# (status, [differences]); status is "ok", "DIFF" or "MISSING".
Result = tuple[str, list[str]]


def _diff(field: str, manifest_value: Any, tenant_value: Any) -> str:
    return f"{field}: manifest {manifest_value}, tenant {tenant_value}"


def _safe_iso(value: Any) -> str:
    try:
        return iso_utc(value)
    except (TypeError, ValueError):
        return repr(value)


def check_mail(g: GraphClient, entry: dict) -> Result:
    owner = entry["recipient"]
    msg = graph.get_message(g, entry["graph_message_id"], owner=owner)
    if msg is None:
        return "MISSING", [f"message {entry['graph_message_id']} not found in {owner}'s mailbox"]
    sender = ((msg.get("from") or {}).get("emailAddress") or {}).get("address", "")
    checks = [
        ("subject", entry["subject"], msg.get("subject"), entry["subject"] == msg.get("subject")),
        ("sender", entry["sender"], sender, entry["sender"].lower() == sender.lower()),
        ("sent_at", entry["sent_at"], _safe_iso(msg.get("sentDateTime")), None),
        ("received_at", entry["received_at"], _safe_iso(msg.get("receivedDateTime")), None),
        ("internet_message_id", entry["internet_message_id"], msg.get("internetMessageId"), None),
        ("body_sha256", entry["body_sha256"], body_sha256(((msg.get("body") or {}).get("content")) or ""), None),
    ]
    diffs = [
        _diff(field, want, got)
        for field, want, got, same in checks
        if not (same if same is not None else want == got)
    ]
    return ("DIFF" if diffs else "ok"), diffs


def check_file(g: GraphClient, entry: dict) -> Result:
    owner = entry["uploaded_by"]
    drive_id = entry["location"]["drive_id"]
    item_id = entry["drive_item_id"]
    item = graph.get_item(g, drive_id, item_id, owner=owner)
    if item is None:
        return "MISSING", [f"drive item {item_id} not found"]
    try:
        data = graph.download_item(g, drive_id, item_id, owner=owner)
    except GraphError as exc:
        if exc.status == 404:
            return "MISSING", [f"drive item {item_id} has no content"]
        raise
    diffs = []
    if item.get("name") != entry["name"]:
        diffs.append(_diff("name", entry["name"], item.get("name")))
    if len(data) != entry["stored_size"]:
        diffs.append(_diff("size", entry["stored_size"], len(data)))
    actual = sha256_hex(data)
    if actual != entry["stored_sha256"]:
        diffs.append(_diff("stored_sha256", entry["stored_sha256"], actual))
    return ("DIFF" if diffs else "ok"), diffs


def run_verify(
    *,
    signin: Any,
    transport: Transport,
    manifest_path: Path,
    sleep: Callable[[float], None] = time.sleep,
    out: Out = print,
) -> int:
    """0 every entry matches, 1 any DIFF or MISSING, 2 the manifest is missing or invalid.
    Graph and sign-in errors are raised (the CLI prints them, exit 2)."""
    try:
        manifest = load_manifest(manifest_path)
        validate_manifest(manifest)
    except ManifestError as exc:
        out(f"error: {manifest_path}:")
        for problem in exc.problems:
            out(f"  {problem}")
        return 2

    entries = manifest["entries"]
    mails = [e for e in entries if e["kind"] == "mail"]
    groups = [
        (
            tenant.ALICE_UPN,
            "re-read her canary mails and the canary files in her OneDrive",
            [e for e in mails if e["recipient"].lower() == tenant.ALICE_UPN.lower()]
            + [e for e in entries if e["kind"] == "onedrive_file"],
        ),
        (
            tenant.BOB_UPN,
            "re-read his canary mails",
            [e for e in mails if e["recipient"].lower() == tenant.BOB_UPN.lower()],
        ),
        (
            tenant.ADMIN_UPN,
            "re-read the canary files in the SharePoint RestoreTest library",
            [e for e in entries if e["kind"] == "sharepoint_file"],
        ),
    ]

    results: dict[str, Result] = {}
    for number, (upn, purpose, group) in enumerate(groups, start=1):
        out(f"Step {number}/{len(groups)}: {upn} - {purpose}")
        g = GraphClient(transport, signin.token_provider(upn, purpose), upn, sleep=sleep)
        for entry in group:
            check = check_mail if entry["kind"] == "mail" else check_file
            results[entry["id"]] = check(g, entry)

    width = max(len(e["id"]) for e in entries)
    for entry in entries:
        status, diffs = results[entry["id"]]
        if status == "ok":
            out(f"ok      {entry['id']}")
        for diff in diffs:
            out(f"{status.ljust(7)} {entry['id'].ljust(width)}  {diff}")

    total = len(entries)
    good = sum(status == "ok" for status, _ in results.values())
    summary = f"{good}/{total} entries in the tenant match the manifest"
    if good == total:
        out(summary)
        return 0
    missing = sum(status == "MISSING" for status, _ in results.values())
    out(f"{summary}; {total - good - missing} differ, {missing} missing")
    return 1
