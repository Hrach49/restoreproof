"""W3.1 review, issue 3: which file types does SharePoint (and OneDrive) rewrite on upload?

Signs in as alice (delegated, the lab seeder app), makes a scratch folder in each restore
target (the RestoreTarget library's root and alice's OneDrive /RestoreTarget), uploads every
file in files/, reads each back at once and again after WAIT seconds, compares bytes and
Graph's size with what was uploaded, then deletes both scratch folders. Run from lab/:
    uv run python <this file>
"""
import hashlib
import io
import json
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from seeder import tenant
from seeder.auth import SignIn, resolve_client_id
from seeder.graph import GraphClient, seg
from seeder.transport import RequestsTransport

HERE = Path(__file__).parent
FILES = sorted((HERE / "files").iterdir())
WAIT = int(sys.argv[1]) if len(sys.argv) > 1 else 900
FOLDER = "rp-rewrite-check-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
# As the seeder: SharePoint as the admin (alice can't write the library), OneDrive as alice.
TARGETS = {
    "sharepoint": (tenant.RESTORE_TARGET_DRIVE_ID, "root", tenant.ADMIN_UPN),
    "onedrive": (tenant.ONEDRIVE_DRIVE_ID, tenant.ONEDRIVE_TARGET_FOLDER_ID, tenant.ALICE_UPN),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def changed_parts(before: bytes, after: bytes) -> list[str] | None:
    """For a zip package: the parts added, removed or changed; None if either isn't a zip."""
    try:
        a, b = zipfile.ZipFile(io.BytesIO(before)), zipfile.ZipFile(io.BytesIO(after))
    except zipfile.BadZipFile:
        return None
    pa = {n: sha(a.read(n)) for n in a.namelist()}
    pb = {n: sha(b.read(n)) for n in b.namelist()}
    return sorted(n for n in pa.keys() | pb.keys() if pa.get(n) != pb.get(n))


def main() -> None:
    signin = SignIn(resolve_client_id(None), tenant.TENANT_ID, mode="browser", out=print)
    transport = RequestsTransport()
    clients = {where: GraphClient(transport, signin.token_provider(upn, "the W3.1 rewrite check"), upn)
               for where, (_, _, upn) in TARGETS.items()}
    results: dict[str, dict] = {}
    folders: dict[str, tuple[str, str]] = {}
    try:
        for where, (drive, parent, UPN) in TARGETS.items():
            g = clients[where]
            folder = g.post_json(
                f"/drives/{seg(drive)}/items/{seg(parent)}/children",
                {"name": FOLDER, "folder": {}, "@microsoft.graph.conflictBehavior": "fail"},
                owner=UPN,
            ).json()
            folders[where] = (drive, folder["id"])
            print(f"{where}: made {FOLDER}")
            for path in FILES:
                data = path.read_bytes()
                item = g.put_bytes(
                    f"/drives/{seg(drive)}/items/{seg(folder['id'])}:/{seg(path.name)}:/content",
                    data, params={"@microsoft.graph.conflictBehavior": "fail"}, owner=UPN, idempotent=False,
                )
                results[f"{where}/{path.name}"] = {"uploaded": len(data), "uploaded_sha256": sha(data),
                                                   "item_id": item["id"], "drive": drive, "where": where, "reads": []}
        for label, delay in (("t0", 0), (f"t+{WAIT}s", WAIT)):
            if delay:
                print(f"waiting {delay} s for a later rewrite ...", flush=True)
                time.sleep(delay)
            for key, r in results.items():
                g, UPN = clients[r["where"]], TARGETS[r["where"]][2]
                meta = g.get_json(f"/drives/{seg(r['drive'])}/items/{seg(r['item_id'])}", owner=UPN)
                data = g.get_bytes(f"/drives/{seg(r['drive'])}/items/{seg(r['item_id'])}/content", owner=UPN)
                original = (HERE / "files" / key.split("/", 1)[1]).read_bytes()
                r["reads"].append({
                    "at": label, "graph_size": meta.get("size"), "downloaded": len(data),
                    "same_bytes": data == original, "changed_parts": changed_parts(original, data),
                })
            print(f"read back at {label}", flush=True)
    finally:
        for where, (drive, folder_id) in folders.items():
            g, UPN = clients[where], TARGETS[where][2]
            try:
                g.request("DELETE", f"/drives/{seg(drive)}/items/{seg(folder_id)}", owner=UPN)
                print(f"{where}: deleted {FOLDER}")
            except Exception as exc:  # report and go on: the other folder still goes
                print(f"{where}: could NOT delete {FOLDER}: {exc}")
        (HERE / "results.json").write_text(json.dumps(results, indent=2))

    print()
    print(f"{'file':38} {'up':>7} {'t0 graph/dl':>15} {'later graph/dl':>15}  rewritten (parts changed)")
    for key, r in results.items():
        cells = []
        for read in r["reads"]:
            cells.append(f"{read['graph_size']}/{read['downloaded']}")
        status = []
        for read in r["reads"]:
            if read["same_bytes"]:
                status.append(f"{read['at']}: no")
            else:
                parts = read["changed_parts"]
                status.append(f"{read['at']}: YES" + (f" ({', '.join(parts)})" if parts is not None else ""))
        print(f"{key:38} {r['uploaded']:>7} {cells[0]:>15} {cells[-1]:>15}  {'; '.join(status)}")


if __name__ == "__main__":
    main()
