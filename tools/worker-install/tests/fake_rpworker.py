"""A stand-in for rpworker.exe in the installer's tests (W7.1), grown from tools/tenant-setup's:
every command Install-RestoreProofWorker.ps1 and New-WorkerGraphCertificate.ps1 run, over a JSON
vault in the folder RP_FAKE_DIR names.

Every command line is appended to argv.log there (so a test can hold that no secret was ever an
argument), each `vault set` value is read from stdin and stored as the real Worker would store
it (one line, the newline dropped), and every other command's effect is a marker file. Flags in
that folder change the answers: `missing-vault` makes `vault list` answer as for a vault that
isn't there yet, `fail-<command words joined by ->` makes that command fail with one line and
the Worker's exit code, `register-401` makes `cloud register` answer as for a refused token,
`revoke-401` and `revoke-503` the same for `cloud revoke` (W7.3), `revoke-unwritable` as for a
revoke the vault couldn't record, `fail-vault-list` as for a vault this account can't read, `outbox-list.txt` is what
`outbox list` prints (its runs are in their backoff: "sent" by the next `outbox flush --now`,
"waiting" without it),
`register-503` as for a Cloud that wasn't reached, `cloud-holds-key` as for a Cloud that took
this Worker's key in a registration whose answer was lost (409 for that key, the key it held
kept in cloud-held-key.txt, 201 for any other). `config check` answers as the real one does
before the vault is made: the settings, then the vault's line and exit 1."""

import base64
import datetime
import json
import os
import sys
from pathlib import Path

VERSION = "0.1.0"
WORKER_ID = "65fd2c3e-9b1a-4e87-a0c3-1f2e3d4c5b6a"
KEY_ID = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"
THUMBPRINT = "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7"
FAKE_PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
# What `rpworker veeam list` prints for the lab (the Catch2 test's table, W7.1's column in).
VEEAM_LIST = (
    "  ORGANIZATION                     APP CERTIFICATE                           BACKUP TIME                   EX  SP  OD  TM  LONG-TERM  RESTORE POINT ID\n"
    f"  RestoreProofLab.onmicrosoft.com  {THUMBPRINT}  2026-09-25T19:37:15.2145203Z  x   x   x   -   no         c2f0f2e7-177f-48ac-992b-93a50cf702e371ac3d9c-eb29-42b6-a391-ae81fcc4681c\n"
    f"  RestoreProofLab.onmicrosoft.com  {THUMBPRINT}  2026-09-25T19:24:31.0936821Z  x   x   x   -   no         c2f0f2e7-177f-48ac-992b-93a50cf702e32fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7\n"
    "\n"
    "1 organisation(s), 2 restore point(s); * = veeam_org_name\n"
)
ALREADY_HAS_KEY = (
    "signer error: the vault already holds signing_key_base64; this Worker has its key (rpworker signer "
    "public-key prints it); --replace makes a new one, after which the Cloud must be told (manage.py "
    "revoke-worker, a new install token)"
)


def main() -> int:
    folder = Path(os.environ["RP_FAKE_DIR"])
    args = sys.argv[1:]
    with (folder / "argv.log").open("a", encoding="utf-8") as log:
        log.write(json.dumps(args) + "\n")
    vault_file = folder / "vault.json"
    vault = json.loads(vault_file.read_text(encoding="utf-8")) if vault_file.exists() else {}
    if "--vault" in args:
        i = args.index("--vault")
        (folder / "vault-arg.txt").write_text(args[i + 1], encoding="utf-8")
        args = args[:i] + args[i + 2:]

    def save():
        vault_file.write_text(json.dumps(vault), encoding="utf-8")

    def fails(*words: str) -> bool:
        return (folder / ("fail-" + "-".join(words))).exists()

    def mark(name: str):
        (folder / name).write_text("", encoding="ascii")

    if args == ["--version"]:
        if fails("version"):
            return 1
        print(VERSION)
        return 0
    if args[:2] == ["config", "check"] and len(args) == 4 and args[2] == "--config":
        # One rule of the real check, so a test can hold a rewrite: cloud_url is https://.
        try:
            document = json.loads(Path(args[3]).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            document = {}
        if fails("config", "check") or not str(document.get("cloud_url", "")).startswith("https://"):
            print("config error: cloud_url: must be an https:// URL", file=sys.stderr)
            return 1
        print(f"config file: {args[3]}")
        print(f"cloud_url: {document['cloud_url']}")
        if (folder / "missing-vault").exists() and not vault:
            print("config error: C:\\ProgramData\\RestoreProof\\vault.bin: vault file not found", file=sys.stderr)
            return 1
        print("secrets (vault C:\\ProgramData\\RestoreProof\\vault.bin; values are never shown):")
        return 0
    if args == ["vault", "list"]:
        if fails("vault", "list"):
            print("vault error: C:\\ProgramData\\RestoreProof\\vault.bin: the vault file can't be read", file=sys.stderr)
            return 1
        if (folder / "missing-vault").exists() and not vault:
            print("vault error: C:\\ProgramData\\RestoreProof\\vault.bin: vault file not found", file=sys.stderr)
            return 1
        for name in vault:
            print(name)
        return 0
    if len(args) == 3 and args[:2] == ["vault", "set"]:
        name = args[2]
        value = sys.stdin.buffer.read().decode("utf-8")
        if value.endswith("\r\n"):
            value = value[:-2]
        elif value.endswith("\n"):
            value = value[:-1]
        if fails("set", name):
            print(f"vault error: {name} couldn't be set", file=sys.stderr)
            return 1
        vault[name] = value
        save()
        print(f"set {name} in the vault")
        return 0
    if len(args) == 3 and args[:2] == ["vault", "remove"]:
        if args[2] in vault:
            del vault[args[2]]
            save()
            print(f"removed {args[2]} from the vault")
        else:
            print(f"{args[2]} was not in the vault; nothing changed")
        return 0
    if len(args) == 3 and args[:2] == ["vault", "grant"]:
        if fails("vault", "grant"):
            print(f"vault error: the account {args[2]} isn't known on this machine", file=sys.stderr)
            return 1
        (folder / "granted.log").open("a", encoding="utf-8").write(args[2] + "\n")
        print(f"granted read on the vault to {args[2]}")
        return 0
    if args[:2] == ["signer", "new-key"] and all(a == "--replace" for a in args[2:]):
        if fails("signer", "new-key"):
            print("signer error: no random bytes could be made", file=sys.stderr)
            return 1
        if vault.get("signing_key_base64") and "--replace" not in args:
            print(ALREADY_HAS_KEY, file=sys.stderr)
            return 1
        vault["signing_key_base64"] = "FAKE-SIGNING-KEY-" + os.urandom(8).hex()
        save()
        print("set signing_key_base64 in the vault", file=sys.stderr)
        sys.stdout.write(FAKE_PEM)
        print(f"key {KEY_ID}", file=sys.stderr)
        return 0
    if args == ["graph", "certificate"]:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        key, cert, _ = pkcs12.load_key_and_certificates(
            base64.b64decode(vault["graph_cert_pfx_base64"], validate=True), vault["graph_cert_password"].encode("ascii")
        )
        sys.stdout.write(cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
        thumb = cert.fingerprint(hashes.SHA1()).hex().upper()
        end = cert.not_valid_after_utc.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"thumbprint {thumb} (SHA-1), expires {end}", file=sys.stderr)
        return 0
    if args[:2] == ["veeam", "list"] and len(args) == 4 and args[2] == "--config":
        if fails("veeam", "list", "unreachable"):
            print("veeam error: Veeam POST /v8/token: unreachable", file=sys.stderr)
            return 3
        if fails("veeam", "list"):
            print("veeam error: Veeam POST /v8/token: HTTP 401: The server has rejected the client credentials.", file=sys.stderr)
            return 2
        table = folder / "veeam-list.txt"
        sys.stdout.write(table.read_text(encoding="utf-8") if table.exists() else VEEAM_LIST)
        return 0
    if args == ["service", "install"]:
        if fails("service", "install"):
            print("service error: access denied; run this from an elevated prompt (Administrators)", file=sys.stderr)
            return 1
        mark("service-installed")
        print('installed RestoreProof: "C:\\Program Files\\RestoreProof\\rpworker.exe" service run')
        print("account NT SERVICE\\RestoreProof, automatic start, restart after 60 s up to 3 times; not started: run rpworker service start")
        return 0
    if args == ["service", "uninstall"]:
        if (folder / "service-started").exists():
            print("service error: the service RestoreProof is running; stop it first (rpworker service stop)", file=sys.stderr)
            return 1
        if not (folder / "service-installed").exists():
            print("service error: the service RestoreProof is not installed", file=sys.stderr)
            return 1
        if fails("service", "uninstall"):
            print("service error: the service RestoreProof is marked for deletion; it goes when services.msc and any other tool that has it open are closed", file=sys.stderr)
            return 3
        (folder / "service-installed").unlink()
        print("uninstalled RestoreProof")
        return 0
    if args[:2] == ["outbox", "flush"]:
        if "cloud_api_token" not in vault:
            print("outbox error: cloud_api_token is not in the vault; nothing was sent (rpworker cloud register)", file=sys.stderr)
            return 1
        if fails("outbox", "flush"):
            print("kept fake-run-2: upload_unreachable; attempt 1, next at 2026-10-19T12:00:00Z")
            print("1 queued, 0 sent, 0 failed")
            return 3
        listing = folder / "outbox-list.txt"
        if listing.exists() and "--now" not in args:
            # The listing's runs are in their backoff (NEXT ahead), as the real flush keeps them.
            for run in [line.split()[0] for line in listing.read_text(encoding="utf-8").splitlines()[1:] if line and not line[0].isdigit()]:
                print(f"waiting {run}: next at 2026-10-19T12:40:10Z")
            print("1 queued, 0 sent, 0 failed")
            return 3
        if listing.exists():
            # --now: every queued run of the listing is sent, so the list after it is empty.
            for run in [line.split()[0] for line in listing.read_text(encoding="utf-8").splitlines()[1:] if line and not line[0].isdigit()]:
                print(f"sent {run}")
            listing.unlink()
            print("0 queued, 1 sent, 0 failed")
            return 0
        print("0 queued, 0 sent, 0 failed")
        return 0
    if args[:2] == ["outbox", "list"]:
        listing = folder / "outbox-list.txt"
        sys.stdout.write(listing.read_text(encoding="utf-8") if listing.exists() else "0 queued, 0 sent, 0 failed\n")
        return 0
    if args[:2] == ["cloud", "revoke"]:
        if "cloud_api_token" not in vault:
            print("config error: cloud_api_token is not in the vault; this Worker is not registered", file=sys.stderr)
            return 1
        if (folder / "revoke-503").exists():
            print("cloud revoke: the Cloud couldn't be reached (http_503); run it again, or revoke the Worker in the Cloud (manage.py revoke-worker)", file=sys.stderr)
            return 3
        if (folder / "revoke-unwritable").exists():
            mark("revoked")
            print("cloud revoke: the Cloud revoked this Worker, but the API token couldn't be removed from the vault (rpworker vault remove cloud_api_token)", file=sys.stderr)
            return 1
        if (folder / "revoke-401").exists():
            del vault["cloud_api_token"]
            save()
            print("cloud revoke: the Cloud doesn't know this token (revoked already, or never this Cloud's); it was removed from the vault", file=sys.stderr)
            return 2
        del vault["cloud_api_token"]
        save()
        mark("revoked")
        print(f"revoked worker {WORKER_ID}")
        return 0
    if args == ["service", "stop"]:
        if (folder / "service-started").exists():
            (folder / "service-started").unlink()
            mark("service-stopped-once")
            print("stopped RestoreProof in 0.4 s")
        else:
            print("RestoreProof is already stopped")
        return 0
    if args == ["service", "start"]:
        if fails("service", "start"):
            print("service error: the service RestoreProof stopped while starting (the config couldn't be loaded); see C:\\ProgramData\\RestoreProof\\logs\\worker.log", file=sys.stderr)
            return 1
        if (folder / "service-started").exists():
            print("RestoreProof is already running")
            return 0
        mark("service-started")
        if (folder / "service-stopped-once").exists():
            mark("started-after-stop")
        print("started RestoreProof")
        return 0
    if args[:2] == ["cloud", "register"] and (len(args) == 2 or (len(args) == 4 and args[2] == "--name")):
        if "cloud_api_token" in vault:
            print("cloud register: already registered (cloud_api_token is in the vault); nothing was done", file=sys.stderr)
            return 1
        if "cloud_install_token" not in vault:
            print("config error: cloud_install_token is not in the vault", file=sys.stderr)
            return 1
        if (folder / "register-401").exists():
            print("cloud register: the install token was refused (unknown, used or expired); make a new one (manage.py create-worker-token)", file=sys.stderr)
            return 2
        if (folder / "register-503").exists():
            print("cloud register: the Cloud couldn't be reached (http_503); run it again", file=sys.stderr)
            return 3
        if (folder / "cloud-holds-key").exists():
            held = folder / "cloud-held-key.txt"
            if not held.exists():
                held.write_text(vault.get("signing_key_base64", ""), encoding="utf-8")
            if held.read_text(encoding="utf-8") == vault.get("signing_key_base64", ""):
                print("cloud register: this Worker's key is already registered", file=sys.stderr)
                return 4
        (folder / "registered-name.txt").write_text(args[3] if len(args) == 4 else "", encoding="utf-8")
        vault["cloud_api_token"] = "FAKE-API-TOKEN-" + os.urandom(8).hex()
        del vault["cloud_install_token"]
        save()
        print(f"registered worker {WORKER_ID} key {KEY_ID}")
        return 0
    print("usage: fake rpworker", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
