"""`python -m seeder {generate,hash,seed,verify}`."""

import argparse
import sys
from pathlib import Path

from seeder import CANARY_DIR, MANIFEST_PATH, tenant
from seeder.auth import MODES, AuthError, SignIn, resolve_client_id
from seeder.generate import run_generate
from seeder.graph import GraphError
from seeder.http import TransportError
from seeder.manifest import ManifestError, run_hash
from seeder.seed import run_seed
from seeder.transport import RequestsTransport
from seeder.verify import run_verify


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m seeder",
        description="Seed and check the RestoreProof canary set (L1.2). See lab/README.md.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="{generate,hash,seed,verify}")

    def paths(p: argparse.ArgumentParser, *, manifest: bool = True, canary: bool = True) -> None:
        if canary:
            p.add_argument("--canary-dir", type=Path, default=CANARY_DIR, help=f"default: {CANARY_DIR}")
        if manifest:
            p.add_argument("--manifest", type=Path, default=MANIFEST_PATH, help=f"default: {MANIFEST_PATH}")

    def signin(p: argparse.ArgumentParser) -> None:
        p.add_argument("--client-id", help="seeder app client ID (else RP_LAB_CLIENT_ID, else tenant.py)")
        p.add_argument("--auth", choices=MODES, default="browser", help="sign-in flow (default: browser)")

    paths(sub.add_parser("generate", help="write the 20 canary files (offline)"), manifest=False)
    paths(sub.add_parser("hash", help="check canary/ and the manifest agree (offline)"))
    seed = sub.add_parser("seed", help="put the 40 items in the tenant and write the manifest (live)")
    paths(seed)
    signin(seed)
    seed.add_argument("--force", action="store_true", help="send every mail again and replace every file")
    seed.add_argument(
        "--mail-timeout", type=float, default=600, metavar="SECONDS", help="wait for mail delivery (default: 600)"
    )
    verify = sub.add_parser("verify", help="re-read the 40 items and compare with the manifest (live)")
    paths(verify, canary=False)
    signin(verify)
    return parser


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _run(args: argparse.Namespace) -> int:
    if args.command == "generate":
        return run_generate(args.canary_dir)
    if args.command == "hash":
        return run_hash(args.manifest, args.canary_dir)
    client_id = resolve_client_id(args.client_id)
    signin = SignIn(client_id, tenant.TENANT_ID, mode=args.auth, out=print)
    transport = RequestsTransport()
    if args.command == "seed":
        return run_seed(
            signin=signin,
            transport=transport,
            canary_dir=args.canary_dir,
            manifest_path=args.manifest,
            force=args.force,
            mail_timeout=args.mail_timeout,
        )
    return run_verify(signin=signin, transport=transport, manifest_path=args.manifest)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # --help (0) or a usage error (2)
        return exc.code if isinstance(exc.code, int) else 2
    try:
        return _run(args)
    except (AuthError, GraphError, TransportError) as exc:
        _err(f"error: {exc}")
        return 2
    except ManifestError as exc:
        _err("error: " + "; ".join(exc.problems))
        return 2
    except KeyboardInterrupt:
        if args.command == "seed":
            _err("Interrupted; nothing was written: seed writes the manifest only at the very end.")
        else:
            _err("Interrupted.")
        return 130
