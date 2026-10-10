"""The public key a Worker registers (C5.5; docs/decisions.md 2026-10-10,
"C5.5 and C5.6", point 2).

`read_key_file` is the key-file rule the two verifiers hold
(shared/testdata/signing-v1/key-files.json; `rp::PublicKey::from_pem` and
verify_bundle.py's `public_key_from_pem`): white space around, the two armour
lines, body lines of standard Base64 characters only ending in LF or CRLF, the
body joined strict Base64 of exactly the 44 bytes of an Ed25519
SubjectPublicKeyInfo as the library writes it. It answers those 44 bytes, the
key's DER, never a re-encoding.

`registered_key` then refuses what the verifiers take as a well-formed key and
the registering side alone can refuse: a non-canonical encoding (`y` at or
above 2^255 - 19, so one point has one `key_id`), a `y` that is no point of
the curve (RFC 8032 section 5.1.3's decompression finds no x; one mistyped
character of a pasted key is such a value about half the time, and nothing
could ever verify under it, so the operator hears at enrolment rather than at
the first bundle), and the eight small-order points, by a fixed list of their
encodings (Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs", 2020,
table 1), under which the library verifies a forged signature for any
message. What it answers is the one stored form: the
library's own three-line PEM of the DER and the key's id, the SHA-256 of the
DER in lower-case hex (signature.v1.json's `key_id`).

No library is asked anything: the rule is a comparison of bytes, the stored
form is the twelve-byte prefix, the key and Base64, and a test holds it equal
to the library's.

Strict (100% line and branch): this decides which keys a bundle can be
verified under.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

__all__ = ["DER_PREFIX", "RegisteredKey", "read_key_file", "registered_key"]

# What the library writes before the key's 32 bytes: SEQUENCE(42) of
# SEQUENCE(5) of the OID 1.3.101.112, then a BIT STRING(33) with no unused bits.
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
DER_BYTES = 44
KEY_BYTES = 32

_WHITE_SPACE = b" \t\r\n"
_BLOCK = re.compile(rb"-----BEGIN PUBLIC KEY-----\r?\n((?:[A-Za-z0-9+/=]+\r?\n)+)-----END PUBLIC KEY-----")

# The field's prime; a `y` at or above it is a non-canonical encoding.
_P = 2**255 - 19
_SIGN_BIT = 1 << 255
# The curve: -x^2 + y^2 = 1 + d x^2 y^2, d = -121665/121666 (RFC 8032, 5.1).
_D = (-121665 * pow(121666, _P - 2, _P)) % _P

# The fourteen encodings of the eight small-order points: the identity, the
# point of order 2, the two of order 4, the four of order 8, each canonical,
# and the six non-canonical forms the paper lists. Compared after the
# canonical rule, which refuses four of them on its own; the list holds all
# fourteen so that it is the paper's and not a derivation.
SMALL_ORDER = frozenset(
    bytes.fromhex(encoding)
    for encoding in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0100000000000000000000000000000000000000000000000000000000000080",
    )
)


@dataclass(frozen=True)
class RegisteredKey:
    """A key the Cloud registers: its DER, the one PEM text that is stored,
    and its id. Made by `registered_key` only."""

    der: bytes
    pem: str
    key_id: str


def _strict_base64(text: bytes) -> bytes | None:
    """The bytes `text` is the standard Base64 of, or None: padded, `=` only
    at the end, the unused bits zero, so no two texts decode to one value."""
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return data if base64.b64encode(data) == text else None


def read_key_file(pem: bytes) -> bytes | None:
    """The 44-byte SubjectPublicKeyInfo DER in the key file `pem`, or None
    unless `pem` is a public key file by the one rule both verifiers hold."""
    if type(pem) is not bytes:
        return None
    block = _BLOCK.fullmatch(pem.strip(_WHITE_SPACE))
    if block is None:
        return None
    der = _strict_base64(block.group(1).replace(b"\r", b"").replace(b"\n", b""))
    if der is None or len(der) != DER_BYTES or not der.startswith(DER_PREFIX):
        return None
    return der


def _is_canonical(raw: bytes) -> bool:
    """Whether the 32-byte encoding's `y` (the sign bit cleared) is below p."""
    return (int.from_bytes(raw, "little") & ~_SIGN_BIT) < _P


def _on_curve(raw: bytes) -> bool:
    """Whether some x makes (x, y) a point: RFC 8032 section 5.1.3's recovery
    of x from y, with its two candidates; no x is no point."""
    y = int.from_bytes(raw, "little") & ~_SIGN_BIT
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if x * x % _P != x2:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    return x * x % _P == x2


def registered_key(pem: str) -> RegisteredKey | None:
    """The key in the text `pem`, in its one stored form, or None: not a key
    file by the rule, a non-canonical encoding, or a small-order point."""
    try:
        der = read_key_file(pem.encode("utf-8"))
    except UnicodeEncodeError:  # a lone surrogate
        return None
    if der is None:
        return None
    raw = der[len(DER_PREFIX) :]
    if not _is_canonical(raw) or not _on_curve(raw) or raw in SMALL_ORDER:
        return None
    body = base64.b64encode(der).decode("ascii")
    return RegisteredKey(
        der=der,
        pem=f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n",
        key_id=hashlib.sha256(der).hexdigest(),
    )
