"""A stand-in for rpworker.exe in the scripts' tests: `vault list`, `vault set <name>` and
`graph certificate`, over a JSON vault in the folder RP_FAKE_DIR names.

Every command line is appended to argv.log there (so a test can hold that no secret was ever an
argument), and each `vault set` value read from stdin is stored as the real Worker would store it
(one line, the newline dropped). Flags in that folder change the answers: `missing-vault` makes
`vault list` answer as for a vault that isn't there yet, `fail-set-<name>` makes that `vault set`
fail."""

import datetime
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12


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

    if args == ["vault", "list"]:
        if (folder / "missing-vault").exists():
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
        if (folder / f"fail-set-{name}").exists():
            print(f"vault error: {name} couldn't be set", file=sys.stderr)
            return 1
        vault[name] = value
        vault_file.write_text(json.dumps(vault), encoding="utf-8")
        print(f"set {name} in the vault")
        return 0
    if args == ["graph", "certificate"]:
        import base64

        key, cert, _ = pkcs12.load_key_and_certificates(
            base64.b64decode(vault["graph_cert_pfx_base64"], validate=True), vault["graph_cert_password"].encode("ascii")
        )
        sys.stdout.write(cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
        thumb = cert.fingerprint(hashes.SHA1()).hex().upper()
        end = cert.not_valid_after_utc.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"thumbprint {thumb} (SHA-1), expires {end}", file=sys.stderr)
        return 0
    print("usage: fake rpworker", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
