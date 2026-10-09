"""The fixture scan (W4.9, docs/decisions.md 2026-10-09): the committed data
trees searched for secret shapes.

Usage (from worker/, or anywhere with --root):
    python tools/fixture_secret_scan.py [--root <repo>] [--allowlist <file>] [--tree <path> ...]

CI has no lab secret and must never be given one, so this looks for the shapes
a secret takes, never a value: a JWT, a `Bearer` token, a PEM private key
block, the Base64 opening of a private key's DER (Ed25519, RSA and EC in
PKCS#8, RSA PKCS#1, EC SEC1) and of a PKCS#12 file, and a keyed secret
(`"password": "..."`, `access_token=...`) whose value isn't a placeholder
(`[REDACTED]`, `SCRUBBED`, `null`, empty, an ellipsis, or starting with `[`,
`<`, `$`, `(` or a backtick: a bracketed placeholder, a script's variable, call
or expression, Markdown's code). A
certificate or a signed token is public and no shape: `MII...` alone is
nothing, only the openings a private key or a PFX has.

Every file under each tree is read, whatever its name; UTF-8 where it is,
Latin-1 otherwise, so no byte is skipped. `.venv`, `__pycache__`, `build` and
`.git` folders are not entered, nor any symbolic link or junction.

The allowlist (fixture_secret_scan_allowlist.json beside this file) names, per
file, the shape it may hold, why, and either the exact `values` or the
`prefixes` of what is allowed; never a file-wide pass. An entry whose file is
gone or whose values match nothing is stale and fails the scan: a stale
allowance is a hole.

A finding names the file, the line and the shape, never the text.

Exit codes: 0 clean, 1 a finding or a stale entry, 2 the allowlist, a tree or
a file can't be read (never a pass over what wasn't read). Stdlib only, as the coverage gate is.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, TextIO

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parents[1]
DEFAULT_ALLOWLIST = HERE / "fixture_secret_scan_allowlist.json"
DEFAULT_TREES = [
    "worker/tests/fixtures",
    "shared/testdata",
    "docs/api",
    "tests/e2e",
    "lab/canary",
    "lab/seed-manifest.json",
    "lab/tenant.md",
]
SKIPPED_FOLDERS = frozenset({".venv", "__pycache__", "build", ".git"})

BASE64 = r"[A-Za-z0-9+/]"
# The keys rp::redact() masks in key=value and "key": "value" forms.
SECRET_KEYS = (
    "password",
    "client_secret",
    "client_assertion",
    "refresh_token",
    "access_token",
    "id_token",
    "tempauth",
    "applicationCertificate",
    "applicationCertificatePassword",
    "signing_key",
    "signing_key_base64",
    "signing_private_key",
    "pfx_base64",
    "pfx",
    "sig",
    "authorization",
)
_KEYS = "|".join(re.escape(k) for k in SECRET_KEYS)

# Shape name -> pattern. Group "value" is what the allowlist compares with;
# without one the whole match is.
SHAPES: dict[str, re.Pattern[str]] = {
    # eyJ not run into a preceding base64url character, then 37 or more
    # base64url characters and dots (the recorder's kMinJwtTail).
    "jwt": re.compile(r"(?<![A-Za-z0-9_-])(?P<value>eyJ[A-Za-z0-9_.\-]{37,})"),
    # A token of 20 or more; `name=value` after the scheme is an auth-param.
    "bearer": re.compile(
        r"\bBearer[ \t]+(?P<value>[A-Za-z0-9._~+/\-]{20,}={0,2})(?![A-Za-z0-9=])"
    ),
    # A BEGIN line whose label ends in PRIVATE KEY; the value is the block's
    # Base64 body (see pem_body).
    "pem_private_key": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    # The Base64 of each private key format's fixed opening bytes, which no
    # certificate or signed token has, then the rest of the Base64 run.
    "ed25519_pkcs8": re.compile(r"(?P<value>MC4CAQAwBQYDK2VwBCIEI" + BASE64 + r"{43})"),
    "rsa_pkcs8": re.compile(
        r"(?P<value>MII" + BASE64 + r"{2}[AQgw]IBADANBgkqhkiG9w0BAQEFAASC" + BASE64 + r"*)"
    ),
    "rsa_pkcs1": re.compile(r"(?P<value>MII" + BASE64 + r"{2}[AQgw]IBAAKCA" + BASE64 + r"*)"),
    "ec_pkcs8": re.compile(r"(?P<value>MIG" + BASE64 + r"AgEAMBMGByqGSM49" + BASE64 + r"*)"),
    "ec_sec1": re.compile(r"(?P<value>(?:MHcCAQEEI|MIGkAgEBBDA|MIHcAgEBBEIB)" + BASE64 + r"*)"),
    "pkcs12": re.compile(
        r"(?P<value>(?:MII" + BASE64 + r"{2}[AQgw]IBAzCC|MIM" + BASE64 + r"{4}CAQMwgg)"
        + BASE64 + r"*)"
    ),
    # "<key>": "<value>", its JSON-escaped form inside a string
    # (\"<key>\":\"<value>\") or <key>=<value> with a bare, "quoted" or
    # 'quoted' value; the key in any case, ending a longer name after a
    # separator as redact() takes it (veeam_password, db.password) but never
    # run into a letter or digit (xpassword) nor followed by one or '_'
    # (password_hash). A placeholder value is no secret (is_placeholder).
    "keyed_secret": re.compile(
        r"(?<![A-Za-z0-9])(?:" + _KEYS + r")(?![A-Za-z0-9_])"
        r"(?:\"\s*:\s*\"(?P<json>(?:[^\"\\]|\\.)*)\""
        r'|\\"\s*:\s*\\"(?P<esc>(?:[^\\"]|\\[^"])*?)\\"'
        r"|\s*=\s*(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'|(?P<form>[^&\s\"',]*)))",
        re.IGNORECASE,
    ),
}

PLACEHOLDERS = frozenset({"", "[REDACTED]", "SCRUBBED", "null"})


def is_placeholder(value: str) -> bool:
    if value in PLACEHOLDERS:
        return True
    # A bracketed placeholder ([REDACTED], <Base64 PFX>), a script's variable,
    # call or expression (`password = $pw`, `refresh_token = (Get-...)`,
    # `pfx = [Convert]::...`) or Markdown's backtick name where a value comes
    # from, not a value.
    if value[:1] in ("[", "<", "$", "(", "`"):
        return True
    return value.startswith("…") or value.startswith("...")


def pem_body(text: str, start: int) -> str:
    """The Base64 body of the PEM block whose BEGIN line starts at `start`,
    without white space and without the `\\n` and `\\r` a JSON string escapes
    them as; up to its END line, or to the end of the text."""
    header_end = text.index("-----", start + 5) + 5
    end = text.find("-----END", header_end)
    body = text[header_end : end if end >= 0 else len(text)]
    for escape in ("\\r\\n", "\\n", "\\r"):
        body = body.replace(escape, "")
    return "".join(body.split())


@dataclass(frozen=True)
class Shape:
    shape: str
    start: int
    value: str  # for the allowlist; never printed


def find_shapes(text: str) -> list[Shape]:
    found: list[Shape] = []
    for name, pattern in SHAPES.items():
        for match in pattern.finditer(text):
            if name == "pem_private_key":
                value = pem_body(text, match.start())
            elif name == "keyed_secret":
                value = next(v for v in (match.group("json"), match.group("esc"), match.group("dq"),
                                         match.group("sq"), match.group("form")) if v is not None)
                if is_placeholder(value):
                    continue
            else:
                value = match.group("value")
            found.append(Shape(name, match.start(), value))
    found.sort(key=lambda s: (s.start, s.shape))
    return found


class AllowlistError(Exception):
    pass


@dataclass
class Entry:
    path: str
    shape: str
    reason: str
    values: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    used: int = 0

    def allows(self, path: str, shape: str, value: str) -> bool:
        if path != self.path or shape != self.shape:
            return False
        if value in self.values:
            return True
        return any(value.startswith(prefix) for prefix in self.prefixes)


@dataclass
class Allowlist:
    entries: list[Entry] = field(default_factory=list)

    @classmethod
    def from_json(cls, document: object) -> "Allowlist":
        if not isinstance(document, dict) or set(document) != {"entries"}:
            raise AllowlistError("the allowlist is one object with the key \"entries\"")
        entries = document["entries"]
        if not isinstance(entries, list):
            raise AllowlistError("\"entries\" must be a list")
        out = cls()
        for n, raw in enumerate(entries, 1):
            out.entries.append(cls._entry(raw, n))
        return out

    @staticmethod
    def _entry(raw: object, n: int) -> Entry:
        where = f"entry {n}"
        if not isinstance(raw, dict):
            raise AllowlistError(f"{where}: not an object")
        allowed_keys = {"path", "shape", "reason", "values", "prefixes"}
        unknown = set(raw) - allowed_keys
        if unknown:
            raise AllowlistError(f"{where}: unknown key(s) {sorted(unknown)}")
        for key in ("path", "shape", "reason"):
            if not isinstance(raw.get(key), str) or not raw[key]:
                raise AllowlistError(f"{where}: \"{key}\" must be a non-empty string")
        if raw["shape"] not in SHAPES:
            raise AllowlistError(f"{where}: \"{raw['shape']}\" is not a shape")

        def strings(key: str) -> tuple[str, ...]:
            got = raw.get(key, [])
            if not isinstance(got, list) or not all(isinstance(v, str) and v for v in got):
                raise AllowlistError(f"{where}: \"{key}\" must be a list of non-empty strings")
            return tuple(got)

        values = strings("values")
        prefixes = strings("prefixes")
        if not values and not prefixes:
            raise AllowlistError(f"{where}: needs \"values\" or \"prefixes\"; never a file-wide pass")
        return Entry(raw["path"].replace("\\", "/"), raw["shape"], raw["reason"], values, prefixes)

    def allow(self, path: str, shape: str, value: str) -> bool:
        for entry in self.entries:
            if entry.allows(path, shape, value):
                entry.used += 1
                return True
        return False


def load_allowlist(file: Path) -> Allowlist:
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AllowlistError(f"{file}: can't be read: {exc.strerror}") from exc
    except ValueError as exc:
        raise AllowlistError(f"{file}: not JSON: {exc}") from exc
    return Allowlist.from_json(document)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    shape: str
    length: int

    def text(self) -> str:
        return f"{self.path}:{self.line}: {self.shape} ({self.length} characters)"


@dataclass(frozen=True)
class Stale:
    path: str
    shape: str
    why: str

    def text(self) -> str:
        return f"stale allowlist entry: {self.path}: {self.shape}: {self.why}"


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    stale: list[Stale] = field(default_factory=list)
    missing_trees: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)  # "<path>: <why>"
    files: int = 0
    allowed: int = 0

    def ok(self) -> bool:
        return (not self.findings and not self.stale and not self.missing_trees
                and not self.unreadable)


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def files_under(root: Path, tree: str) -> Iterable[Path] | None:
    """Every regular file under root/tree (or the file itself); None when
    nothing is there."""
    top = root / tree
    if top.is_file():
        return [top]
    if not top.is_dir():
        return None

    def walk(folder: Path) -> Iterable[Path]:
        for entry in sorted(folder.iterdir(), key=lambda p: p.name):
            # A link or a junction is never entered: it could point up the
            # tree, and what it points at is scanned where it is.
            if entry.is_symlink() or entry.is_junction():
                continue
            if entry.is_dir():
                if entry.name not in SKIPPED_FOLDERS:
                    yield from walk(entry)
            elif entry.is_file():
                yield entry

    return walk(top)


def relative_name(file: Path, root: Path) -> str:
    try:
        return file.relative_to(root).as_posix()
    except ValueError:
        return file.as_posix()


def scan_file(file: Path, root: Path, allowlist: Allowlist, result: Result) -> None:
    rel = relative_name(file, root)
    try:
        text = decode(file.read_bytes())
    except OSError as exc:
        result.unreadable.append(f"{rel}: {exc.strerror or exc}")
        return
    result.files += 1
    for shape in find_shapes(text):
        if allowlist.allow(rel, shape.shape, shape.value):
            result.allowed += 1
            continue
        line = text.count("\n", 0, shape.start) + 1
        result.findings.append(Finding(rel, line, shape.shape, len(shape.value)))


def scan_trees(root: Path, trees: list[str], allowlist: Allowlist) -> Result:
    result = Result()
    for tree in trees:
        files = files_under(root, tree)
        if files is None:
            result.missing_trees.append(tree)
            continue
        for file in files:
            scan_file(file, root, allowlist, result)
    for entry in allowlist.entries:
        if entry.used:
            continue
        why = "matches nothing" if (root / entry.path).is_file() else "no such file"
        result.stale.append(Stale(entry.path, entry.shape, why))
    return result


def main(argv: list[str] | None = None, out: TextIO = sys.stdout) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="the repository root")
    parser.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST))
    parser.add_argument("--tree", action="append", help="a path under --root; repeatable")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    trees = args.tree or DEFAULT_TREES
    try:
        allowlist = load_allowlist(Path(args.allowlist))
    except AllowlistError as exc:
        print(f"fixture secret scan: allowlist error: {exc}", file=out)
        return 2
    try:
        result = scan_trees(root, trees, allowlist)
    except OSError as exc:
        print(f"fixture secret scan: a tree can't be read: {exc}", file=out)
        return 2
    if result.missing_trees or result.unreadable:
        for tree in result.missing_trees:
            print(f"fixture secret scan: no such tree under {root}: {tree}", file=out)
        for file in result.unreadable:
            print(f"fixture secret scan: a file can't be read: {file}", file=out)
        return 2
    for finding in result.findings:
        print(finding.text(), file=out)
    for stale in result.stale:
        print(stale.text(), file=out)
    summary = (
        f"fixture secret scan: {result.files} file(s) in {len(trees)} tree(s), "
        f"{result.allowed} allowed match(es), {len(result.findings)} finding(s), "
        f"{len(result.stale)} stale allowlist entr{'y' if len(result.stale) == 1 else 'ies'}"
    )
    if result.ok():
        print(summary + "; no secret shape found", file=out)
        return 0
    print(summary, file=out)
    return 1


if __name__ == "__main__":
    sys.exit(main())
