# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "asn1crypto>=1.5,<2",
#     "cryptography>=50,<51",
#     "jsonschema>=4.26,<5",
# ]
# ///
"""Checks a RestoreProof run folder against the Worker's public key.

    uv run verify_bundle.py <folder> --public-key <pem file> [--tsa-ca <pem file>]
                            [--schemas <dir>]

Exit 0 and `verified <bundle_sha256> key <key_id> timestamp <time | none |
unchecked>`, exit 1 and `not verified: <word>`, exit 2 for a usage error (an option given twice is
one), a folder, key or schema that can't be read, a missing package, a verdict
that couldn't be written to stdout, or anything unexpected (never a verdict).
An empty <folder>, --public-key or --schemas is such an error, never the
working folder; so is, on Windows, a folder name of blanks and dots only, which
Windows would read as the folder above it. The folder is resolved once, and
that one path is listed and read from; on Windows it is in the extended-length
form, so a file past 260 characters is read like any other. A file is there
only when the folder lists its name byte for byte: ITEMS.CSV is not items.csv,
whatever the file system would open.

One self-contained file (docs/decisions.md 2026-10-05, W4.3 point 5). It holds
the Python side of canonical-json-v1, the form `result.json` and
`signature.json` are written in:

    parse_strict(raw)      bytes -> value, refusing what isn't one plain JSON text
    canonical_json(value)  value -> the canonical bytes, refusing what has none
    canonical_fault(raw)   None when `raw` is its own canonical form, else why not
    is_canonical(raw)      the same as a bool

A refusal is a `Refusal` whose only content is a slug (`SLUGS`): never the
value or the key that was refused, and never a parser's own message.

The folder's checks, first failure wins, one word each (`WORDS`, in this order):

    result_unreadable     result.json isn't there, can't be read or is too large
    result_not_canonical  anything else that keeps its bytes from being the
                          canonical form of a document
    result_schema         not a restoreproof.result.v1
    attachment_twice      one name listed twice
    screenshot_missing    `captured`, and screenshot.png isn't listed
    signature_file        signature.json not there, not canonical, or not its
                          five keys and their shapes
    hash_mismatch         its bundle_sha256 isn't result.json's SHA-256
    wrong_key             its key_id isn't the given public key's
    signature_invalid     64 well-formed bytes Ed25519 refuses under that key
    attachment_missing    a listed file isn't there or can't be read
    attachment_size       not the listed size
    attachment_hash       not the listed SHA-256
    timestamp_file        timestamp.tst is there and can't be read, is over 64
                          KiB or isn't exactly one RFC 3161 TimeStampToken
    timestamp_mismatch    its imprint isn't SHA-256 or isn't result.json's hash
    timestamp_invalid     it doesn't verify under --tsa-ca: the signature, the
                          signer or its chain at the token's own time

The public key always comes from --public-key, never from the folder: the
signature file isn't itself signed, so the answer is only as good as that key.
A file in the folder that the result doesn't list is a `note:` line on stderr,
never a failure. The Worker's `rpworker signer verify` runs the same checks in
the same order with the same words; shared/testdata/signing-v1/ and
shared/testdata/timestamp-v1/ hold the two to one answer.

The timestamp (W4.4, docs/decisions.md 2026-10-06) is timestamp.tst, the bare
token of a timestamp authority over the SHA-256 of result.json's bytes, the
bytes the signature signs; `openssl ts -verify -data result.json -in
timestamp.tst -token_in -CAfile <root>` checks it too. It is the third field of
the `verified` line: the token's own time (UTC) when it verifies under the
certificates of --tsa-ca, which come from the caller like the key and never
from the folder; `none` when the folder has no timestamp.tst (still verified:
the run wasn't timestamped); `unchecked` when it has one and no --tsa-ca was
given. A token's certificates are held to the token's own time, not to today,
and revocation isn't checked. The signer must be among the token's
certificates, be named by its ESSCertID, carry a critical extended key usage of
timeStamping alone, and chain, each certificate issued by the next, to a
certificate of --tsa-ca.
"""

import argparse
import base64
import datetime
import hashlib
import json
import ntpath
import os
import re
import stat
import sys
from pathlib import Path
from typing import NamedTuple

try:
    from asn1crypto import cms, tsp
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError
except ImportError as missing:
    if __name__ != "__main__":
        raise
    # Run with plain `python` where the packages aren't installed. Left to
    # Python, the traceback's exit status is 1, which is "not verified".
    package = (missing.name or "?").partition(".")[0]
    sys.stderr.write(f"error: a package the script needs isn't installed ({package}); run it with `uv run`\n")
    sys.exit(2)  # EXIT_ERROR

__all__ = [
    "EXIT_ERROR",
    "EXIT_NOT_VERIFIED",
    "EXIT_VERIFIED",
    "MAX_NESTING",
    "MAX_RESULT_FILE_BYTES",
    "MAX_SAFE_INTEGER",
    "MAX_SIGNATURE_FILE_BYTES",
    "MAX_TIMESTAMP_FILE_BYTES",
    "NOT_CANONICAL",
    "READ",
    "SLUGS",
    "TIMESTAMP_FILE",
    "TIMESTAMP_NONE",
    "TIMESTAMP_UNCHECKED",
    "TOO_LARGE",
    "UNREADABLE",
    "VERIFIED",
    "WORDS",
    "PublicKey",
    "Refusal",
    "Schemas",
    "SetupError",
    "Verification",
    "canonical_fault",
    "canonical_json",
    "check_attachment",
    "check_timestamp",
    "default_schemas_dir",
    "is_canonical",
    "load_schemas",
    "main",
    "nesting_depth",
    "parse_strict",
    "public_key_from_pem",
    "verify",
    "verify_folder",
]

# --- canonical-json-v1 ---------------------------------------------------------

# More levels of arrays and objects than this, open at once, are refused before
# any parser sees the bytes. The Worker's verifier has the same limit.
MAX_NESTING = 32

# Integers are whole numbers within +-(2^53 - 1): what every JSON reader keeps.
MAX_SAFE_INTEGER = 2**53 - 1

# Every reason a Refusal can carry. The first three are the reasons
# shared/testdata/canonical-json-v1.json names.
SLUGS = frozenset(
    {
        "float",  # a number with a fraction or an exponent, 1e400 included
        "integer_out_of_range",  # outside +-(2^53 - 1), or too long for int()
        "non_ascii_key",  # an object key with a character past U+007F
        "duplicate_key",  # one object, one key twice
        "not_json",  # not one JSON text: a BOM, NaN, Infinity, a syntax error
        "invalid_utf8",  # bytes that aren't UTF-8, or a lone surrogate
        "too_deep",  # more than MAX_NESTING levels
    }
)

# canonical_fault's answer for bytes that parse and have a canonical form, which
# they are not (another key order, whitespace, a trailing newline, "-0", an
# escape the form doesn't use). Not a Refusal's slug.
NOT_CANONICAL = "not_canonical"


class Refusal(Exception):
    """Why a text or a value has no canonical form: `slug`, one of SLUGS.

    It holds nothing else. The refused value, its key and the parser's message
    (which can quote the input) are never kept, also not as a chained exception.
    """

    def __init__(self, slug: str) -> None:
        super().__init__(slug)
        self.slug = slug


def nesting_depth(raw: bytes, stop_after: int = MAX_NESTING) -> int:
    """The most arrays and objects open at once in `raw`, counted on the bytes
    and outside strings, without parsing. Stops at `stop_after` + 1."""
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte == 0x5B or byte == 0x7B:  # [ {
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > stop_after:
                    return deepest
        elif byte == 0x5D or byte == 0x7D:  # ] }
            depth -= 1
    return deepest


def _refuse_float(_text: str):
    raise Refusal("float")


def _refuse_constant(_name: str):
    # NaN, Infinity, -Infinity: words Python's parser takes and JSON doesn't have.
    raise Refusal("not_json")


def _parse_int(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        # More digits than int() converts (4300 by default).
        raise Refusal("integer_out_of_range") from None


def _object_without_duplicates(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate_key")
        result[key] = value
    return result


def parse_strict(raw: bytes):
    """The value of the JSON text in `raw`, or a Refusal.

    Refused: more than MAX_NESTING levels (`too_deep`, counted first), bytes
    that aren't strict UTF-8 (`invalid_utf8`), a BOM, NaN, Infinity, -Infinity
    or anything else that isn't one JSON text (`not_json`), a float however it
    is written (`float`), an integer int() can't hold (`integer_out_of_range`)
    and a key twice in one object (`duplicate_key`).

    Not refused here, since they are JSON: an integer past +-(2^53 - 1), a key
    that isn't ASCII and an escaped lone surrogate. canonical_json refuses those.
    """
    if type(raw) is not bytes:
        raise TypeError("parse_strict takes bytes")
    if nesting_depth(raw) > MAX_NESTING:
        raise Refusal("too_deep")
    # Decoded here: json.loads would take a BOM and UTF-16 from bytes.
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise Refusal("invalid_utf8") from None
    if text.startswith("\ufeff"):
        raise Refusal("not_json")
    try:
        return json.loads(
            text,
            parse_float=_refuse_float,
            parse_int=_parse_int,
            parse_constant=_refuse_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except Refusal:
        raise
    except RecursionError:
        raise Refusal("too_deep") from None
    except UnicodeError:
        raise Refusal("invalid_utf8") from None
    except ValueError:  # json.JSONDecodeError among them
        raise Refusal("not_json") from None


def _check_value(value) -> None:
    kind = type(value)
    if value is None or kind is bool:
        return
    if kind is int:  # by type: True is an int to isinstance
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise Refusal("integer_out_of_range")
        return
    if kind is float:
        raise Refusal("float")
    if kind is str:
        _check_string(value)
        return
    if kind is list:
        for item in value:
            _check_value(item)
        return
    if kind is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise Refusal("not_json")
            if not key.isascii():
                raise Refusal("non_ascii_key")
            _check_value(item)
        return
    # A tuple, bytes, a set, a subclass: json.dumps would rewrite it or fail.
    raise Refusal("not_json")


def _check_string(text: str) -> None:
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeError:  # a lone surrogate
        raise Refusal("invalid_utf8") from None


def canonical_json(value) -> bytes:
    """The canonical-json-v1 bytes of `value`, or a Refusal.

    Keys sorted, `,` and `:` only, no trailing newline, strings as UTF-8 with
    JSON's short escapes and lower-case \\u00xx for the other control
    characters: Python's one-line dump. Refused, never rewritten: an integer
    outside +-(2^53 - 1) (`integer_out_of_range`), a float (`float`), a key that
    isn't ASCII (`non_ascii_key`), a string with a lone surrogate
    (`invalid_utf8`), anything that isn't a plain JSON value (`not_json`) and a
    value nested deeper than Python follows (`too_deep`).
    """
    try:
        _check_value(value)
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return text.encode("utf-8", errors="strict")
    except Refusal:
        raise
    except RecursionError:
        raise Refusal("too_deep") from None
    except UnicodeError:
        raise Refusal("invalid_utf8") from None
    except (ValueError, TypeError):
        raise Refusal("not_json") from None


def canonical_fault(raw: bytes) -> str | None:
    """None when `raw` is the canonical form of the document it holds.

    Otherwise why not: the slug parse_strict or canonical_json refused it with,
    or NOT_CANONICAL when it has a canonical form and isn't it. A verifier maps
    every answer but None to its one word (`result_not_canonical`,
    `signature_file`); the slug is for a test and a person.
    """
    try:
        canonical = canonical_json(parse_strict(raw))
    except Refusal as refusal:
        return refusal.slug
    return None if canonical == raw else NOT_CANONICAL


def is_canonical(raw: bytes) -> bool:
    """Whether `raw` equals canonical_json(parse_strict(raw)); False for every
    refusal too."""
    return canonical_fault(raw) is None


# --- the run folder ------------------------------------------------------------

VERIFIED = "verified"

# Every word after `not verified: `, in the checks' order. With VERIFIED, the
# sixteen answers; the Worker's rp::verify_words() is the same list.
WORDS = (
    "result_unreadable",
    "result_not_canonical",
    "result_schema",
    "attachment_twice",
    "screenshot_missing",
    "signature_file",
    "hash_mismatch",
    "wrong_key",
    "signature_invalid",
    "attachment_missing",
    "attachment_size",
    "attachment_hash",
    "timestamp_file",
    "timestamp_mismatch",
    "timestamp_invalid",
)

RESULT_FILE = "result.json"
SIGNATURE_FILE = "signature.json"
TIMESTAMP_FILE = "timestamp.tst"
SCREENSHOT_FILE = "screenshot.png"
RESULT_SCHEMA_FILE = "result.v1.json"
SIGNATURE_SCHEMA_FILE = "signature.v1.json"

# A result.json or a signature.json larger than this isn't read: the Worker's
# kMaxResultFileBytes and kMaxSignatureFileBytes (rp/signer.hpp).
MAX_RESULT_FILE_BYTES = 16 * 1024 * 1024
MAX_SIGNATURE_FILE_BYTES = 4096
# A timestamp.tst larger than this isn't read: the Worker's
# kMaxTimestampFileBytes (rp/rfc3161.hpp). Real tokens are 4 to 8 KB.
MAX_TIMESTAMP_FILE_BYTES = 64 * 1024

# The third field of the `verified` line when it isn't a time.
TIMESTAMP_NONE = "none"
TIMESTAMP_UNCHECKED = "unchecked"

# The caller's own files. A PEM of one Ed25519 public key is 113 bytes.
_MAX_KEY_FILE_BYTES = 64 * 1024
_MAX_SCHEMA_FILE_BYTES = 16 * 1024 * 1024

# A public key file once the white space around it is gone: the BEGIN line,
# one or more lines of Base64 characters, the END line, each line but the last
# ended by LF or CRLF. Nothing else matches: no header line, no blank line, no
# space or tab, no lone CR, no text on an armour line.
_PEM_WHITE_SPACE = b" \t\r\n"
_PEM_BLOCK = re.compile(
    rb"-----BEGIN PUBLIC KEY-----\r?\n((?:[A-Za-z0-9+/=]+\r?\n)+)-----END PUBLIC KEY-----"
)
_PUBLIC_DER_BYTES = 44  # an Ed25519 key's SubjectPublicKeyInfo
# What the library writes before the key's 32 bytes: SEQUENCE(42) of
# SEQUENCE(5) of the OID 1.3.101.112, then a BIT STRING(33) with no unused bits.
_PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")

EXIT_VERIFIED = 0
EXIT_NOT_VERIFIED = 1
EXIT_ERROR = 2


class SetupError(Exception):
    """The verifier couldn't start: the folder, the key or a schema isn't what
    it must be. Exit 2, never a verdict. `str()` is the line after `error: `."""


class Verification(NamedTuple):
    """A verifier's answer: VERIFIED, or the first check that failed."""

    word: str
    bundle_sha256: str = ""  # with VERIFIED only
    key_id: str = ""  # with VERIFIED only
    # With VERIFIED only, from verify_folder: each name in the folder that isn't
    # result.json, signature.json, timestamp.tst or a listed attachment, sorted.
    notes: tuple[str, ...] = ()
    # With VERIFIED only, from verify_folder: the line's third field. The
    # token's time, YYYY-MM-DDTHH:MM:SSZ, when it verified under the caller's
    # CA; TIMESTAMP_UNCHECKED when there is a token and no CA was given;
    # TIMESTAMP_NONE when the folder has no timestamp.tst.
    timestamp: str = TIMESTAMP_NONE


class PublicKey:
    """The public key a verifier was given by its caller. Made by
    public_key_from_pem only."""

    def __init__(self, key: Ed25519PublicKey, der: bytes) -> None:
        self._key = key
        self.der = der  # SubjectPublicKeyInfo, 44 bytes
        self.key_id = hashlib.sha256(der).hexdigest()

    def accepts(self, signature: bytes, message: bytes) -> bool:
        """Whether `signature` is this key's Ed25519 signature of `message`."""
        try:
            self._key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


def _strict_base64(text: bytes) -> bytes | None:
    """The bytes `text` is the standard Base64 of, or None: padded, `=` only at
    the end, the unused bits zero, so no two texts decode to the same bytes."""
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError:  # binascii.Error among them
        return None
    return data if base64.b64encode(data) == text else None


def public_key_from_pem(pem: bytes) -> PublicKey | None:
    """The Ed25519 public key in the key file `pem`, or None.

    One rule, the Worker's PublicKey::from_pem's, held to it by
    shared/testdata/signing-v1/key-files.json and checked here before the
    library is asked anything: white space (space, tab, CR, LF) around; the
    line `-----BEGIN PUBLIC KEY-----`; one or more body lines of standard
    Base64 characters and nothing else; the line `-----END PUBLIC KEY-----`.
    Inside the block a line ends with LF or CRLF only. The body lines joined
    must be strict Base64 of exactly the 44 bytes of an Ed25519
    SubjectPublicKeyInfo as the library writes it (302a300506032b6570032100,
    then the key's 32 bytes). Those 44 bytes are the key's DER, never a
    re-encoding. No PEM or DER reader of the library is used: each takes more.
    """
    if type(pem) is not bytes:
        return None
    block = _PEM_BLOCK.fullmatch(pem.strip(_PEM_WHITE_SPACE))
    if block is None:
        return None
    der = _strict_base64(block.group(1).replace(b"\r", b"").replace(b"\n", b""))
    if der is None or len(der) != _PUBLIC_DER_BYTES or not der.startswith(_PUBLIC_DER_PREFIX):
        return None
    try:
        key = Ed25519PublicKey.from_public_bytes(der[len(_PUBLIC_DER_PREFIX) :])
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    return PublicKey(key, der)


# --- the timestamp (W4.4) --------------------------------------------------------

_DER = Encoding.DER
_UTC = datetime.timezone.utc

# How deep a chain from the token's signer to the caller's CA may be.
_MAX_CHAIN = 8

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
# ESSCertID (RFC 2634) names the signer by SHA-1; ESSCertIDv2 (RFC 5035) by the
# hash it says, SHA-256 unless it says another.
_ESS_HASHES = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}


class _Token(NamedTuple):
    """One TimeStampToken, read and not yet verified."""

    signed: object  # the CMS SignedData
    certificates: list  # the token's certificates, each read
    content: bytes  # the TSTInfo's DER, what the signer's messageDigest covers
    sha256: bool  # the imprint's algorithm is SHA-256
    imprint: bytes
    gen_time: object  # an aware datetime, fractions cut


def _parse_token(raw: bytes) -> _Token | None:
    """`raw` as exactly one TimeStampToken, or None: a CMS SignedData with one
    signer whose content is a TSTInfo of version 1, and no byte after it. A
    whole TimeStampResp is none. All of it is read here, its certificates
    included, as OpenSSL's reader does: bytes that are no token are
    timestamp_file whatever part of the token they are in, never
    timestamp_invalid further on."""
    try:
        outer = cms.ContentInfo.load(raw, strict=True)
        if outer["content_type"].native != "signed_data":
            return None
        signed = outer["content"]
        inner = signed["encap_content_info"]
        if inner["content_type"].native != "tst_info" or len(signed["signer_infos"]) != 1:
            return None
        content = bytes(inner["content"])
        info = tsp.TSTInfo.load(content, strict=True)
        if info["version"].native != "v1":
            return None
        imprint = info["message_imprint"]
        gen_time = info["gen_time"].native
        if gen_time.tzinfo is None:
            return None
        # Every field the checks go by, read once: asn1crypto reads a field
        # only when it is asked for. Not an algorithm's parameters, which
        # OpenSSL takes as they are.
        signer_info = signed["signer_infos"][0]
        for algorithm in [*signed["digest_algorithms"], signer_info["digest_algorithm"]]:
            algorithm["algorithm"].native  # noqa: B018
        signer_info["version"].native  # noqa: B018
        signer_info["sid"].chosen.native  # noqa: B018
        signer_info["signature_algorithm"]["algorithm"].native  # noqa: B018
        signer_info["signature"].native  # noqa: B018
        for attribute in signer_info["signed_attrs"]:
            attribute["type"].native  # noqa: B018
            for value in attribute["values"]:
                value.dump()
        for field in ("policy", "serial_number", "accuracy", "ordering", "nonce", "tsa", "extensions"):
            info[field].native  # noqa: B018
        certificates = [
            x509.load_der_x509_certificate(choice.chosen.dump())
            for choice in signed["certificates"]
            if choice.name == "certificate"
        ]
        return _Token(
            signed,
            certificates,
            content,
            imprint["hash_algorithm"]["algorithm"].native == "sha256",
            imprint["hashed_message"].native,
            gen_time.replace(microsecond=0),
        )
    except Exception:  # noqa: BLE001 - whatever a library makes of bytes that are no token
        return None


_PEM_BEGIN = re.compile(rb"-----BEGIN ([^\r\n]*?)-----")


def _ca_certificates(pem: bytes) -> list | None:
    """The certificates of a CA file's text, or None when it isn't one: every
    PEM block in it is a CERTIFICATE that reads as one, and there is at least
    one. A block of another label (a key, a CRL, the old X509 CERTIFICATE) or
    one that is cut off makes the whole text no CA file, as for the Worker;
    the library's own reader would skip it. Text outside the blocks is a
    comment."""
    labels = _PEM_BEGIN.findall(pem)
    if not labels or any(label != b"CERTIFICATE" for label in labels):
        return None
    try:
        certificates = x509.load_pem_x509_certificates(pem)
    except (ValueError, TypeError):
        return None
    return certificates if len(certificates) == len(labels) else None


def _is_timestamp_signer(certificate) -> bool:
    """Whether `certificate` may sign a timestamp, by OpenSSL's rule
    (X509_PURPOSE_TIMESTAMP_SIGN): an extended key usage that is critical and
    timeStamping alone; a key usage, when there is one, with digitalSignature
    or nonRepudiation (contentCommitment)."""
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return False
    if not usage.critical or list(usage.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        return False
    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return key_usage.digital_signature or key_usage.content_commitment


def _is_ca(certificate) -> bool:
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _der(certificate) -> bytes:
    return certificate.public_bytes(_DER)


def _chains(signer, others: list, anchors: list, at) -> bool:
    """Whether `signer` chains to one of `anchors`: each certificate valid at
    `at` and issued by the next, which is a CA, at most _MAX_CHAIN deep. A
    certificate that is itself one of the anchors ends the chain wherever it
    is met. `others` are the token's own certificates: they may stand between,
    never at the end."""
    trusted = {_der(anchor) for anchor in anchors}
    current = signer
    for _ in range(_MAX_CHAIN + 1):
        if not current.not_valid_before_utc <= at <= current.not_valid_after_utc:
            return False
        if _der(current) in trusted:
            return True
        issuer = None
        for candidate in [*anchors, *others]:
            try:
                current.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
                continue
            issuer = candidate
            break
        if issuer is None or not _is_ca(issuer):
            return False
        current = issuer
    return False


def _names_signer(attributes: dict, signer_der: bytes) -> bool:
    """Whether the token's ESSCertID names the signer: at least one of
    signingCertificate and signingCertificateV2 is among the signed attributes,
    and the first certificate ID of each that is there is the signer's hash."""
    found = False
    for name in ("signing_certificate", "signing_certificate_v2"):
        if name not in attributes:
            continue
        first = attributes[name]["certs"][0]
        algorithm = "sha1" if name == "signing_certificate" else first["hash_algorithm"]["algorithm"].native
        if algorithm not in _ESS_HASHES or _ESS_HASHES[algorithm](signer_der).digest() != first["cert_hash"].native:
            return False
        found = True
    return found


def _signature_holds(signer, signer_info, signed_bytes: bytes) -> bool:
    """Whether the signer's signature is over `signed_bytes`: RSA PKCS #1 v1.5
    for an RSA key and ECDSA for an EC one, with the signer's digest algorithm
    (SHA-256, SHA-384 or SHA-512). The signer info's own signature algorithm
    isn't signed and isn't read: OpenSSL goes by the key and the digest too."""
    hash_name = signer_info["digest_algorithm"]["algorithm"].native
    if hash_name not in _HASHES:
        return False
    signature = signer_info["signature"].native
    key = signer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed_bytes, padding.PKCS1v15(), _HASHES[hash_name]())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed_bytes, ec.ECDSA(_HASHES[hash_name]()))
        else:
            return False
    except InvalidSignature:
        return False
    return True


def _token_verifies(token: _Token, ca_pem: bytes) -> bool:
    """Whether the token's signature verifies and its signer chains to a
    certificate of `ca_pem`, at the token's own time. Anything the libraries
    refuse on the way is False, never an exception: a token that can't be
    checked is not a verified one."""
    try:
        anchors = _ca_certificates(ca_pem)
        if anchors is None:
            return False
        certificates = token.certificates
        signer_info = token.signed["signer_infos"][0]
        sid = signer_info["sid"]
        if sid.name != "issuer_and_serial_number":
            return False
        issuer = sid.chosen["issuer"].dump()
        serial = sid.chosen["serial_number"].native
        signers = [
            certificate
            for certificate in certificates
            if certificate.serial_number == serial and certificate.issuer.public_bytes() == issuer
        ]
        if len(signers) != 1:
            return False
        signer = signers[0]
        digest_name = signer_info["digest_algorithm"]["algorithm"].native
        # The SignedData's own list of digest algorithms isn't signed, and
        # OpenSSL still needs the signer's among them.
        listed = [algorithm["algorithm"].native for algorithm in token.signed["digest_algorithms"]]
        if digest_name not in listed or any(name not in _ESS_HASHES for name in listed):
            return False
        attributes = {}
        for attribute in signer_info["signed_attrs"]:
            if len(attribute["values"]) != 1 or attribute["type"].native in attributes:
                return False
            attributes[attribute["type"].native] = attribute["values"][0]
        if (
            digest_name not in _HASHES
            or attributes["content_type"].native != "tst_info"
            or attributes["message_digest"].native != hashlib.new(digest_name, token.content).digest()
            or not _names_signer(attributes, _der(signer))
            or not _is_timestamp_signer(signer)
        ):
            return False
        # What is signed is the attributes as a SET OF, not under their
        # context tag.
        signed_bytes = b"\x31" + signer_info["signed_attrs"].dump()[1:]
        if not _signature_holds(signer, signer_info, signed_bytes):
            return False
        others = [certificate for certificate in certificates if certificate is not signer]
        return _chains(signer, others, anchors, token.gen_time)
    except Exception:  # noqa: BLE001 - whatever a library makes of a token's bytes
        return False


def check_timestamp(raw: bytes, digest: bytes, ca_pem: bytes | None) -> tuple[str, str]:
    """The word for the token `raw` over `digest`, the SHA-256 of result.json's
    bytes, and with VERIFIED the line's third field: timestamp_file unless
    `raw` is exactly one TimeStampToken; timestamp_mismatch unless its imprint
    is SHA-256 and `digest`; then, with `ca_pem`, timestamp_invalid unless it
    verifies under those certificates at its own time, else its time; without
    `ca_pem`, TIMESTAMP_UNCHECKED."""
    token = _parse_token(raw)
    if token is None:
        return "timestamp_file", ""
    if not token.sha256 or token.imprint != digest:
        return "timestamp_mismatch", ""
    if ca_pem is None:
        return VERIFIED, TIMESTAMP_UNCHECKED
    if not _token_verifies(token, ca_pem):
        return "timestamp_invalid", ""
    return VERIFIED, token.gen_time.astimezone(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Schemas(NamedTuple):
    """The two schemas, each as a validator. Made by load_schemas."""

    result: Draft202012Validator
    signature: Draft202012Validator


def default_schemas_dir() -> Path:
    """`../schemas` beside this file."""
    return Path(__file__).resolve().parent.parent / "schemas"


# A reader's three answers (check_attachment, _read_file).
READ = "read"
UNREADABLE = "unreadable"  # not there, not a file, or it couldn't be read whole
TOO_LARGE = "too_large"  # more than the limit; not read
_READ, _UNREADABLE, _TOO_LARGE = READ, UNREADABLE, TOO_LARGE


def _read_file(path: Path, limit: int) -> tuple[str, bytes]:
    """One whole file of at most `limit` bytes, as the Worker's
    rp::read_whole_file."""
    try:
        status = os.stat(path)
        if not stat.S_ISREG(status.st_mode):
            return _UNREADABLE, b""
        if status.st_size > limit:
            return _TOO_LARGE, b""
        with open(path, "rb") as file:
            data = file.read(status.st_size + 1)
    except (OSError, ValueError):
        return _UNREADABLE, b""
    if len(data) != status.st_size:
        return _UNREADABLE, b""
    return _READ, data


def _is_empty(path) -> bool:
    """Whether `path` is the empty text. Path("") is ".", so this is asked
    before a Path is made of what the caller gave."""
    return len(os.fspath(path)) == 0


def _load_schema(folder: Path, name: str) -> Draft202012Validator:
    state, raw = _read_file(folder / name, _MAX_SCHEMA_FILE_BYTES)
    if state != _READ:
        raise SetupError(f"--schemas: {name} can't be read")
    try:
        schema = parse_strict(raw)
        if type(schema) is not dict:
            raise Refusal("not_json")
        Draft202012Validator.check_schema(schema)
    except (Refusal, SchemaError):
        raise SetupError(f"--schemas: {name} isn't a JSON Schema") from None
    return Draft202012Validator(schema)


def load_schemas(folder) -> Schemas:
    """result.v1.json and signature.v1.json of `folder`, or a SetupError: a
    schema that can't be found is never a skipped check. An empty `folder` is
    no folder (not the working one)."""
    if _is_empty(folder):
        raise SetupError("--schemas: the folder can't be opened")
    folder = Path(folder)
    return Schemas(_load_schema(folder, RESULT_SCHEMA_FILE), _load_schema(folder, SIGNATURE_SCHEMA_FILE))


def _failed(word: str) -> Verification:
    return Verification(word)


def _check(result: bytes, signature: bytes | None, key: PublicKey, schemas: Schemas) -> tuple[Verification, list]:
    """The checks of a result's bytes and a signature file's bytes (None: not
    read), in their order, and the result's attachments once it is known to be
    a result."""
    # The canonical form before the schema: Python's `integer` takes 1.0.
    if canonical_fault(result) is not None:
        return _failed("result_not_canonical"), []
    document = parse_strict(result)
    if not schemas.result.is_valid(document):
        return _failed("result_schema"), []
    listed = document["attachments"] or []
    names = [attachment["name"] for attachment in listed]
    # The two things the schema can't say.
    if len(set(names)) != len(names):
        return _failed("attachment_twice"), listed
    screenshot = document["screenshot"]
    if screenshot is not None and screenshot["state"] == "captured" and SCREENSHOT_FILE not in names:
        return _failed("screenshot_missing"), listed
    if signature is None or canonical_fault(signature) is not None:
        return _failed("signature_file"), listed
    signed = parse_strict(signature)
    if not schemas.signature.is_valid(signed):
        return _failed("signature_file"), listed
    digest = hashlib.sha256(result).digest()
    if signed["bundle_sha256"] != digest.hex():
        return _failed("hash_mismatch"), listed
    if signed["key_id"] != key.key_id:
        return _failed("wrong_key"), listed
    # The schema's pattern is strict Base64 of 64 bytes; the message is the 32
    # raw digest bytes, not their hex.
    if not key.accepts(base64.b64decode(signed["signature"], validate=True), digest):
        return _failed("signature_invalid"), listed
    return Verification(VERIFIED, signed["bundle_sha256"], signed["key_id"]), listed


def verify(result: bytes, signature: bytes | None, key: PublicKey, schemas: Schemas) -> Verification:
    """Checks a result's bytes and a signature file's bytes against the
    caller's key, first failure wins: result_not_canonical, result_schema,
    attachment_twice, screenshot_missing, signature_file, hash_mismatch,
    wrong_key, signature_invalid; else VERIFIED with the hash and the key's ID.
    The attachments aren't read."""
    return _check(result, signature, key, schemas)[0]


def check_attachment(read, attachment: dict) -> str:
    """The word for one listed attachment as `read(name, limit)` finds it;
    VERIFIED when it is the file the result lists. One larger than listed isn't
    read at all. `read` answers `(state, bytes)` with `state` one of READ,
    UNREADABLE (not there, not a file, not read whole) and TOO_LARGE (over
    `limit`, not read): the folder's reader here, the upload's parts in the
    Cloud (C5.7), which checks an attachment through this one function."""
    state, data = read(attachment["name"], attachment["size_bytes"])
    if state == _UNREADABLE:
        return "attachment_missing"
    if state == _TOO_LARGE or len(data) != attachment["size_bytes"]:
        return "attachment_size"
    if hashlib.sha256(data).hexdigest() != attachment["sha256"]:
        return "attachment_hash"
    return VERIFIED


_WINDOWS = os.name == "nt"


def _names_nothing(folder: str) -> bool:
    """Whether the last part of the Windows path `folder` is blanks and dots
    only, and neither `.` nor `..`. Windows drops such a part, so ` ` and `...`
    would be the working folder and `.. ` the one above it: a folder the caller
    never named. (`rpworker signer verify` opens none of them either.)"""
    last = re.split(r"[\\/]", ntpath.splitdrive(folder)[1])[-1]
    return last not in ("", ".", "..") and last.strip(" .") == ""


def _extended(folder: str) -> str:
    r"""The Windows path `folder`, absolute, in the extended-length form
    (\\?\C:\runs\one, \\?\UNC\server\share\one), which has no limit of 260
    characters: a file that is there opens however long the folder's path is,
    with or without the system's long-path setting. One that is already
    extended, or a device's, is left as it is."""
    full = ntpath.abspath(folder)
    if full.startswith(("\\\\?\\", "\\\\.\\")):
        return full
    if full.startswith("\\\\"):
        return "\\\\?\\UNC\\" + full[2:]
    return "\\\\?\\" + full


def _open_folder(folder) -> Path:
    """The one path the folder is listed and read through: `folder` resolved,
    which must be there and a folder. So a name the system lists and reads
    differently (on Windows, one ending in a space) can't give a listing of
    one place beside reads of another, which would end in a verdict. On
    Windows the path is the extended one (_extended), and a name Windows would
    drop altogether is no folder (_names_nothing)."""
    if _is_empty(folder):
        raise SetupError("the folder can't be opened")
    try:
        given = os.fsdecode(folder)
        if _WINDOWS:
            if _names_nothing(given):
                raise NotADirectoryError
            given = _extended(given)
        resolved = Path(given).resolve(strict=True)
        if not stat.S_ISDIR(os.stat(resolved).st_mode):
            raise NotADirectoryError
    except (OSError, ValueError, RuntimeError):
        raise SetupError("the folder can't be opened") from None
    return resolved


def verify_folder(folder, key: PublicKey, schemas: Schemas, tsa_ca: bytes | None = None) -> Verification:
    """The same over a run folder: result.json (result_unreadable unless it is
    read), the checks of `verify` with signature.json (signature_file when it
    isn't read), then each listed attachment in the result's order:
    attachment_missing, attachment_size, attachment_hash; then, when the folder
    has timestamp.tst, the timestamp (check_timestamp) with `tsa_ca`, the
    caller's PEM certificates or None. A file is there only when the folder's
    listing has its name, byte for byte; any other name isn't read. A
    SetupError when `folder` is empty or isn't a folder that can be resolved
    and listed."""
    folder = _open_folder(folder)
    try:
        names = sorted(os.listdir(folder))
    except (OSError, ValueError):
        raise SetupError("the folder can't be opened") from None
    there = frozenset(names)

    def read(name: str, limit: int) -> tuple[str, bytes]:
        # A file system that ignores case would open ITEMS.CSV for items.csv,
        # and one that doesn't has no such file: the listing decides, so both
        # give one word, the Worker's.
        if name not in there:
            return _UNREADABLE, b""
        return _read_file(folder / name, limit)

    state, result = read(RESULT_FILE, MAX_RESULT_FILE_BYTES)
    if state != _READ:
        return _failed("result_unreadable")
    state, signature = read(SIGNATURE_FILE, MAX_SIGNATURE_FILE_BYTES)
    verdict, listed = _check(result, signature if state == _READ else None, key, schemas)
    if verdict.word != VERIFIED:
        return verdict
    for attachment in listed:
        word = check_attachment(read, attachment)
        if word != VERIFIED:
            return _failed(word)
    # The timestamp last: evidence about a result that is known good by now.
    stamped = TIMESTAMP_NONE
    if TIMESTAMP_FILE in there:
        state, token = read(TIMESTAMP_FILE, MAX_TIMESTAMP_FILE_BYTES)
        if state != _READ:
            return _failed("timestamp_file")
        word, stamped = check_timestamp(token, hashlib.sha256(result).digest(), tsa_ca)
        if word != VERIFIED:
            return _failed(word)
    covered = {RESULT_FILE, SIGNATURE_FILE, TIMESTAMP_FILE} | {attachment["name"] for attachment in listed}
    return verdict._replace(notes=tuple(name for name in names if name not in covered), timestamp=stamped)


# --- the command ---------------------------------------------------------------


class _Once(argparse.Action):
    """An option's one value. Given again it is a usage error: argparse would
    keep the last, so a key or a schema folder a caller put first could be
    replaced by an argument passed on after it. (`rpworker signer verify`
    refuses a second --public-key too.)"""

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"argument {option_string}: given more than once")
        setattr(namespace, self.dest, values)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_bundle.py",
        description="Checks a RestoreProof run folder against the Worker's public key.",
        allow_abbrev=False,
    )
    parser.add_argument("folder", help="the run folder: result.json, signature.json and the attachments")
    parser.add_argument(
        "--public-key", required=True, action=_Once, metavar="<pem file>", help="the Worker's Ed25519 public key, PEM"
    )
    parser.add_argument(
        "--tsa-ca",
        action=_Once,
        metavar="<pem file>",
        help="the certificate(s) a timestamp must chain to, PEM; without it a timestamp isn't checked",
    )
    parser.add_argument(
        "--schemas", action=_Once, metavar="<dir>", help="the folder holding result.v1.json and signature.v1.json"
    )
    return parser


def _read_public_key(path: str) -> PublicKey:
    if _is_empty(path):
        raise SetupError("--public-key: the file can't be read")
    state, pem = _read_file(Path(path), _MAX_KEY_FILE_BYTES)
    if state != _READ:
        raise SetupError("--public-key: the file can't be read")
    key = public_key_from_pem(pem)
    if key is None:
        raise SetupError("--public-key: not an Ed25519 public key in PEM")
    return key


def _read_tsa_ca(path: str) -> bytes:
    """The caller's CA file: PEM whose every block is a certificate, at least
    one (_ca_certificates)."""
    if _is_empty(path):
        raise SetupError("--tsa-ca: the file can't be read")
    state, pem = _read_file(Path(path), _MAX_KEY_FILE_BYTES)
    if state != _READ:
        raise SetupError("--tsa-ca: the file can't be read")
    if _ca_certificates(pem) is None:
        raise SetupError("--tsa-ca: no certificate in PEM")
    return pem


def _printable(name: str) -> str:
    """A file's name for a line of output, as the Worker's `signer verify`
    writes it, byte for byte: printable ASCII but the backslash as it is,
    anything else by its code point in lower-case hex, \\xNN below U+0100,
    \\uNNNN below U+10000, \\UNNNNNNNN above. A surrogate without its pair (in a
    Windows name, or standing for a byte that isn't UTF-8 elsewhere) is a code
    point of its own, \\udXXX."""
    parts = []
    for char in name:
        point = ord(char)
        if 0x20 <= point <= 0x7E and char != "\\":
            parts.append(char)
        elif point < 0x100:
            parts.append(f"\\x{point:02x}")
        elif point < 0x10000:
            parts.append(f"\\u{point:04x}")
        else:
            parts.append(f"\\U{point:08x}")
    return "".join(parts)


def _run(argv: list[str] | None) -> int:
    args = _parser().parse_args(argv)
    try:
        schemas = load_schemas(args.schemas if args.schemas is not None else default_schemas_dir())
        key = _read_public_key(args.public_key)
        tsa_ca = _read_tsa_ca(args.tsa_ca) if args.tsa_ca is not None else None
        verdict = verify_folder(args.folder, key, schemas, tsa_ca)
    except SetupError as problem:
        print(f"error: {problem}", file=sys.stderr)
        return EXIT_ERROR
    if verdict.word != VERIFIED:
        print(f"not verified: {verdict.word}")
        return EXIT_NOT_VERIFIED
    try:
        for name in verdict.notes:
            print(f"note: not listed in the result: {_printable(name)}", file=sys.stderr)
        if verdict.timestamp == TIMESTAMP_NONE:
            print("note: not timestamped", file=sys.stderr)
        elif verdict.timestamp == TIMESTAMP_UNCHECKED:
            print(f"note: {TIMESTAMP_FILE} was not checked: no --tsa-ca", file=sys.stderr)
    except Exception:  # noqa: BLE001 - a lost stderr changes nothing
        pass
    print(f"verified {verdict.bundle_sha256} key {verdict.key_id} timestamp {verdict.timestamp}")
    return EXIT_VERIFIED


def main(argv: list[str] | None = None) -> int:
    """The exit code. Anything unexpected is 2, so a crash never reads as a
    verdict (0 or 1)."""
    try:
        code = _run(argv)
        sys.stdout.flush()  # a verdict that didn't reach stdout isn't one
        return code
    except SystemExit as stop:  # argparse: 2 for a usage error, 0 for --help
        return stop.code if type(stop.code) is int else EXIT_ERROR
    except BaseException as failure:  # noqa: BLE001 - by design, see above
        try:
            print(f"error: unexpected failure ({type(failure).__name__})", file=sys.stderr)
        except Exception:  # noqa: BLE001 - a lost stderr changes nothing
            pass
        return EXIT_ERROR


def _exit_code(code: int) -> int:
    """The process's exit code after `main` answered `code`: `code` itself once
    stdout holds nothing more. Text that still can't be written (the reader of
    a pipe has gone) would fail again in the interpreter's own flush at exit,
    which makes the exit status 120; stdout is pointed at the null device
    instead, so what is left goes nowhere, and the code is 2."""
    try:
        sys.stdout.flush()
        return code
    except Exception:  # noqa: BLE001 - whatever the stream raises
        pass
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except Exception:  # noqa: BLE001 - no descriptor to point elsewhere
        pass
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(_exit_code(main()))
