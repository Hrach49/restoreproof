"""The bundle's checks and its mapping to rows (C5.7; docs/decisions.md
2026-10-10, C5.7, points 1 and 4 to 12): everything `POST /v1/results` decides,
as pure functions over the request's parts, the token's Worker and the run.
The route (app/routers/results.py) reads the request and runs the statements;
nothing here touches the database or the bucket.

The verifier is the auditor's own file, shared/tools/verify_bundle.py, loaded
by path from beside shared/schemas (`verifier()`), so the Cloud is the Python
verifier and not a copy of it: `verify()` for the eight words of the result and
the signature, `check_attachment()` for the three of an attachment,
`check_timestamp()` for the three of the token, under the one root the image
carries (shared/tsa/tsa-ca.pem, `tsa_ca_pem()`). Every refusal is one fixed
word (`Refused`): the verifier's, or one of this module's own for the request
and the run, never a text of the body.

The order: the parts' names and sizes, the result (canonical form first, then
the schema), the signature under the token's Worker's key, each listed
attachment, a part the result doesn't list, the timestamp; only then the run
(this MSP's, this Worker's, handed out), the repeat, the client. A refusal
before the run is known tells a caller nothing about what runs exist.

Strict (100% line and branch): this decides what the Cloud files as evidence.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID

from app.models import Client, TestRun
from app.repo.items import ItemRow
from app.repo.runs import ReceivedRun
from app.schemas import shared_schemas_dir

__all__ = [
    "BODY_MALFORMED",
    "BODY_NOT_MULTIPART",
    "BODY_NO_LENGTH",
    "BODY_TOO_LARGE",
    "BUNDLE_CONFLICT",
    "CLIENT_MISMATCH",
    "FINISHED_STATES",
    "MAX_ATTACHMENT_BYTES",
    "MAX_FILE_PARTS",
    "MAX_UPLOAD_BYTES",
    "NOT_DISPATCHED",
    "NO_SUCH_RUN",
    "PART_TWICE",
    "PART_UNEXPECTED",
    "REQUEST_WORDS",
    "RESULT_PART",
    "RUN_WORDS",
    "SIGNATURE_PART",
    "TIMESTAMP_PART",
    "Refused",
    "Verified",
    "already_received",
    "bundle_key",
    "check_client",
    "check_run",
    "item_rows",
    "run_update",
    "size_refusal",
    "tsa_ca_pem",
    "verifier",
    "verify_upload",
]

# The parts' names (worker/src/outbox.cpp). Every other part is an attachment
# under the name the result lists.
RESULT_PART = "result"
SIGNATURE_PART = "signature"
TIMESTAMP_PART = "timestamp"
FIXED_PARTS = (RESULT_PART, SIGNATURE_PART, TIMESTAMP_PART)
FILE_NAMES = {RESULT_PART: "result.json", SIGNATURE_PART: "signature.json", TIMESTAMP_PART: "timestamp.tst"}
CONTENT_TYPES = {RESULT_PART: "application/json", SIGNATURE_PART: "application/json"}
OCTET_STREAM = "application/octet-stream"

# The request's limits (point 1). The three file limits are the verifiers'
# (rp/signer.hpp, rp/rfc3161.hpp, the script's MAX_*); an attachment's is
# C7.2's 25 MB; the whole is 16 MiB plus three attachments with room for the
# framing. Nothing else in the stack bounds a body.
MAX_UPLOAD_BYTES = 96 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_FILE_PARTS = 6  # result, signature, timestamp, three attachments

# The request's own words (400 unless said), beside the verifier's.
BODY_NOT_MULTIPART = "body: not multipart/form-data"  # 415
BODY_NO_LENGTH = "body: no Content-Length"  # 411
BODY_TOO_LARGE = "body: too large"  # 413
BODY_MALFORMED = "body: malformed"
PART_TWICE = "part_twice"
PART_UNEXPECTED = "part_unexpected"
REQUEST_WORDS = (BODY_NOT_MULTIPART, BODY_NO_LENGTH, BODY_TOO_LARGE, BODY_MALFORMED, PART_TWICE, PART_UNEXPECTED)

# The run's words (points 5, 9 and 13).
NO_SUCH_RUN = "run_id: no such run"  # 404: not a uuid, unknown, another MSP's, another Worker's
NOT_DISPATCHED = "run_id: not dispatched"  # 409
CLIENT_MISMATCH = "client_mismatch"  # 409
BUNDLE_CONFLICT = "bundle_conflict"  # 409
RUN_WORDS = (NO_SUCH_RUN, NOT_DISPATCHED, CLIENT_MISMATCH, BUNDLE_CONFLICT)

FINISHED_STATES = ("pass", "fail", "error")
SAME_TENANT = "same_tenant"

TIME_MILLISECONDS = "%Y-%m-%dT%H:%M:%S.%fZ"
TIME_SECONDS = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class Refused:
    """One refusal: its status and its word, and the run when it is known
    (then the audit row names the run, else the Worker)."""

    status: int
    word: str
    run_id: UUID | None = None


@dataclass(frozen=True)
class Verified:
    """A bundle that verified under the Worker's key: the parsed result and
    the bytes to store, the signature's hash, the token's time or None."""

    result: dict[str, Any]
    result_bytes: bytes
    signature_bytes: bytes
    timestamp_bytes: bytes | None
    bundle_sha256: str
    tsa_time: dt.datetime | None
    attachments: dict[str, bytes]  # in the result's order


# --- the verifier and the root, from beside shared/schemas ---------------------------------


@lru_cache(maxsize=None)
def verifier() -> ModuleType:
    """shared/tools/verify_bundle.py, loaded once by path, with its schemas
    from shared/schemas; a tree without it is this app's failure, never a
    skipped check."""
    path = shared_schemas_dir().parent / "tools" / "verify_bundle.py"
    if not path.is_file():
        raise FileNotFoundError("no shared/tools/verify_bundle.py beside shared/schemas")
    spec = importlib.util.spec_from_file_location("restoreproof_verify_bundle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SCHEMAS = module.load_schemas(shared_schemas_dir())
    return module


@lru_cache(maxsize=None)
def tsa_ca_pem() -> bytes:
    """shared/tsa/tsa-ca.pem, the one root a token is held to, read once."""
    path = shared_schemas_dir().parent / "tsa" / "tsa-ca.pem"
    if not path.is_file():
        raise FileNotFoundError("no shared/tsa/tsa-ca.pem beside shared/schemas")
    return path.read_bytes()


# --- the parts (point 1) --------------------------------------------------------------------


def size_refusal(name: str, size: int) -> Refused | None:
    """The refusal for a part of `size` bytes under `name` before it is read,
    or None: the result over 16 MiB is the verifier's `result_unreadable`,
    the signature over 4096 `signature_file`, the token over 64 KiB
    `timestamp_file`, any other part over the attachment cap 413."""
    vb = verifier()
    if name == RESULT_PART:
        return Refused(400, "result_unreadable") if size > vb.MAX_RESULT_FILE_BYTES else None
    if name == SIGNATURE_PART:
        return Refused(400, "signature_file") if size > vb.MAX_SIGNATURE_FILE_BYTES else None
    if name == TIMESTAMP_PART:
        return Refused(400, "timestamp_file") if size > vb.MAX_TIMESTAMP_FILE_BYTES else None
    return Refused(413, BODY_TOO_LARGE) if size > MAX_ATTACHMENT_BYTES else None


# --- the verification (points 4, 6, 7, 8) ----------------------------------------------------


def verify_upload(parts: Mapping[str, bytes], *, public_key_pem: str, key_id: str, tsa_ca: bytes) -> Verified | Refused:
    """The verifiers' checks over the parts, first failure wins, each a 400
    with the verifier's word; then a part the result doesn't list. The key is
    the token's Worker's stored PEM (its `key_id` is compared, never read from
    the body); the token is held to `tsa_ca`, and a missing one is "not
    timestamped"."""
    vb = verifier()
    key = vb.public_key_from_pem(public_key_pem.encode("ascii"))
    if key is None or key.key_id != key_id:
        # The stored form always reads (C5.5 stores the library's own text); a
        # row that doesn't is this app's failure, never a verdict.
        raise RuntimeError("the Worker's stored public key isn't one")
    result = parts.get(RESULT_PART)
    if result is None:
        return Refused(400, "result_unreadable")
    signature = parts.get(SIGNATURE_PART)
    verdict = vb.verify(result, signature, key, vb.SCHEMAS)
    if verdict.word != vb.VERIFIED:
        return Refused(400, verdict.word)
    document = vb.parse_strict(result)
    attachments: dict[str, bytes] = {}
    for attachment in document["attachments"] or []:
        if attachment["size_bytes"] > MAX_ATTACHMENT_BYTES:
            # Not a verifier's word: the bundle may be honest, and the Cloud
            # won't hold it.
            return Refused(413, BODY_TOO_LARGE)
        word = vb.check_attachment(_reader(parts), attachment)
        if word != vb.VERIFIED:
            return Refused(400, word)
        attachments[attachment["name"]] = parts[attachment["name"]]
    for name in parts:
        if name not in FIXED_PARTS and name not in attachments:
            return Refused(400, PART_UNEXPECTED)
    digest = hashlib.sha256(result).digest()
    token = parts.get(TIMESTAMP_PART)
    stamped: dt.datetime | None = None
    if token is not None:
        word, time_text = vb.check_timestamp(token, digest, tsa_ca)
        if word != vb.VERIFIED:
            return Refused(400, word)
        stamped = dt.datetime.strptime(time_text, TIME_SECONDS).replace(tzinfo=dt.timezone.utc)
    return Verified(
        result=document,
        result_bytes=result,
        signature_bytes=signature,
        timestamp_bytes=token,
        bundle_sha256=digest.hex(),
        tsa_time=stamped,
        attachments=attachments,
    )


def _reader(parts: Mapping[str, bytes]):
    """The verifier's reader over the parts: a part is read whole when it is
    there and not larger than the listed size (then `attachment_size`, as a
    file larger than listed isn't read)."""
    vb = verifier()

    def read(name: str, limit: int) -> tuple[str, bytes]:
        data = parts.get(name)
        if data is None:
            return vb.UNREADABLE, b""
        if len(data) > limit:
            return vb.TOO_LARGE, b""
        return vb.READ, data

    return read


# --- the run (points 5, 9, 13) ----------------------------------------------------------------


def check_run(result: Mapping[str, Any], run: TestRun | None, worker_id: UUID, bundle_sha256: str) -> Refused | None:
    """404 for a run that isn't this Worker's (`run` is None, or another
    Worker's); 409 for one never handed out; 409 `bundle_conflict` for one
    that holds another bundle; else None. `run` is the row `RunRepo.get`
    answered for the result's `run_id`, or None when that isn't a uuid."""
    if run is None or run.worker_id != worker_id:
        return Refused(404, NO_SUCH_RUN)
    if run.dispatched_at is None:
        return Refused(409, NOT_DISPATCHED, run.id)
    if run.state in FINISHED_STATES and run.bundle_sha256 != bundle_sha256:
        return Refused(409, BUNDLE_CONFLICT, run.id)
    return None


def already_received(run: TestRun, bundle_sha256: str) -> bool:
    """Whether the run already holds this very bundle (point 13): then 202
    with no change."""
    return run.state in FINISHED_STATES and run.bundle_sha256 == bundle_sha256


def run_uuid(result: Mapping[str, Any]) -> UUID | None:
    """The result's `run_id` as the run's uuid, or None when it is no uuid
    (a run the Cloud never dispatched)."""
    try:
        return uuid.UUID(result["run_id"])
    except ValueError:
        return None


def check_client(result: Mapping[str, Any], run: TestRun, client: Client) -> Refused | None:
    """The bundle's client is the run's (point 9): the job's `client_id`
    echoed, the profile's tenant, the organisation the backup product
    reported when the client check passed, and no verdict without that
    check; one word."""
    said = result["client"]
    if said["client_id"] != str(client.id):
        return Refused(409, CLIENT_MISMATCH, run.id)
    if _uuid_or_none(said["tenant_id"]) != client.tenant_id:
        return Refused(409, CLIENT_MISMATCH, run.id)
    if said["scope"] == SAME_TENANT:
        if _uuid_or_none(said["resolved"]["organization"]["tenant_id"]) != client.tenant_id:
            return Refused(409, CLIENT_MISMATCH, run.id)
    elif result["status"]["status"] != "error":
        return Refused(409, CLIENT_MISMATCH, run.id)
    return None


def _uuid_or_none(text: str) -> UUID | None:
    try:
        return uuid.UUID(text)
    except ValueError:
        return None


# --- the rows (points 10 to 12) -----------------------------------------------------------------


def bundle_key(msp_id: UUID, run_id: UUID) -> str:
    """Where the bundle's files go: the prefix, each file under its name."""
    return f"msp/{msp_id}/runs/{run_id}/"


def run_update(verified: Verified, key: str) -> ReceivedRun:
    """The run's columns from the result, by point 11's table."""
    result = verified.result
    status = result["status"]
    is_error = status["status"] == "error"
    span = result["timings"]["spans"]["total"]
    cleanup = result["cleanup"]
    return ReceivedRun(
        state=status["status"],
        error_code=status.get("error_code") if is_error else None,
        error_message=status["message"] if is_error else None,
        started_at=_time(result["started_at"], TIME_MILLISECONDS),
        finished_at=_time(result["ended_at"], TIME_MILLISECONDS),
        total_ms=_count(span.get("ms")) if span is not None else None,
        restore_point_at=_time(result["restore_point"]["backup_time"], TIME_SECONDS),
        bundle_key=key,
        bundle_sha256=verified.bundle_sha256,
        tsa_ok=True if verified.tsa_time is not None else None,
        tsa_time=verified.tsa_time,
        cleanup_ok=cleanup["cleanup_ok"] if cleanup is not None else None,
    )


def item_rows(result: Mapping[str, Any]) -> list[ItemRow]:
    """One row per expected item, joined to its check item by `index`
    (point 12's table); none when the run never sampled."""
    expected = result["expected"]
    if expected is None:
        return []
    check = result["check"]
    checked = {item["index"]: item for item in check["items"]} if check is not None else {}
    rows = []
    for item in expected["items"]:
        found = checked.get(item["index"])
        rows.append(
            ItemRow(
                position=item["index"],
                type=item["kind"],
                name=item["subject"] if item["kind"] == "mail" else item["name"],
                expected_kind=item["expected_kind"],
                expected_sha256=item.get("sha256"),
                found_sha256=None,
                found=found["found"] if found is not None else None,
                match=_match(found["outcome"]) if found is not None else None,
                reason=found.get("reason") if found is not None else None,
                ms=_count(found.get("ms")) if found is not None else None,
            )
        )
    return rows


def _match(outcome: str) -> bool | None:
    """`match` is true, `mismatch` and `missing` false, `error` not known."""
    if outcome == "match":
        return True
    if outcome == "error":
        return None
    return False


def _time(text: str | None, layout: str) -> dt.datetime | None:
    """A time of the result as aware UTC; null when null, and null for a text
    the pattern takes and the calendar refuses (the verifiers say verified)."""
    if text is None:
        return None
    try:
        return dt.datetime.strptime(text, layout).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _count(value: int | None) -> int | None:
    """A duration for a column that refuses a negative one: null for a clock
    that went back."""
    if value is None or value < 0:
        return None
    return value
