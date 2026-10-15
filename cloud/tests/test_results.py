"""C5.7: `POST /v1/results` (docs/decisions.md 2026-10-10, C5.7). Done when:
the tests pass and a real Worker bundle lands as pass in the DB.

"A real Worker bundle" without the Veeam VM is shared/testdata/signing-v1/
bundle.json: a run folder the Worker's own pipeline wrote, re-keyed to a run
the Cloud dispatched and re-signed with the same published key (point 17;
tests/results_lab.py). The app has `get_session` overridden to the test's
session, its bucket on botocore's `Stubber` and the shared vectors' test TSA
root. Failure paths first: the request's words, the run's, the client's; then
the Done-when, the mapping, the repeat and the race.
"""

from __future__ import annotations

import asyncio
import copy
import datetime as dt
import hashlib
import io
import json
import uuid

import asyncpg
import httpx
import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import create_async_engine

from app import results
from app.auth.tokens import new_token, token_hash
from app.db import make_session_factory
from app.main import create_app
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.workers import WorkerRepo
from app.routers import results as results_route
from app.storage import Storage, make_s3_client
from tests.conftest import asyncpg_dsn, make_settings
from tests.results_lab import (
    ATTACHMENTS,
    BUNDLE_RESULT,
    NOW,
    PATH,
    TENANT_ID,
    UTC,
    Lab,
    bundle,
    files_of,
)
from tests.test_repo_connectors import profile_for
from tests.test_verify_bundle import KEYS, vb
from tests.test_verify_bundle_closed import CLOSED
from tests.tsa_lab import OTHER_ROOT_PEM, STAMPED_AT

NOT_AUTHENTICATED = {"detail": "not authenticated"}
CLOSED_RESULT = json.loads(CLOSED["files"]["result.json"])
CLOSED_ATTACHMENTS = {name: CLOSED["files"][name].encode("utf-8") for name in ("items.csv", "veeam-session.log")}
SENTINEL = "Sentinel-Subject-7c4e1"


@pytest.fixture
async def lab(session):
    lab = Lab(session)
    await lab.fill()
    return lab


def refused_body(word: str) -> dict:
    return {"detail": word}


class Body:
    """A request body handed over chunk by chunk, counting the chunks the app
    asked for: what shows that a body was, or was not, read."""

    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks
        self.pulled = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.pulled += 1
            yield chunk


async def assert_refused(lab: Lab, response: httpx.Response, status: int, word: str, *, run_id=None, before: dict) -> None:
    """A refusal: its status and word, one audit row naming the Worker (or
    the run, once known) and the word, nothing else written, no put."""
    assert (response.status_code, response.json()) == (status, refused_body(word)), response.text
    who = f"worker:{lab.worker_id}" if run_id is None else f"run:{run_id}"
    assert await lab.wrote(before) == [("result.rejected", f"{who} {word}")]
    after = await lab.counts()
    assert {k: v for k, v in after.items() if k != "audit"} == {
        **{k: v for k, v in before.items() if k != "audit"}, "audit_log": before["audit_log"] + 1
    }
    lab.stubber.assert_no_pending_responses()


def rows_only(counts: dict) -> dict:
    return {k: v for k, v in counts.items() if k != "audit"}


# --- The Done-when -----------------------------------------------------------------------------


async def test_the_tests_pass_and_a_real_worker_bundle_lands_as_pass_in_the_db(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    key = lab.expect_puts(run_id, parts)
    before = await lab.counts()

    response = await lab.upload(parts)

    assert response.status_code == 202, response.text
    assert response.json() == {"run_id": str(run_id), "state": "pass"}
    row = await lab.run_row(run_id)
    assert row.state == "pass"
    assert (row.error_code, row.error_message) == (None, None)
    assert row.started_at == dt.datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)
    assert row.finished_at == dt.datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)
    assert row.total_ms == 4_182_000
    assert row.recovery_ms == 2_952_000  # C6.2: timings.spans.recovery.ms
    assert row.restore_point_at == dt.datetime(2026, 9, 29, 22, 0, 45, tzinfo=UTC)
    assert row.bundle_key == key == f"msp/{lab.msp_id}/runs/{run_id}/"
    assert row.bundle_sha256 == hashlib.sha256(parts["result"]).hexdigest()
    assert (row.signature_ok, row.tsa_ok, row.tsa_time, row.cleanup_ok) == (True, None, None, True)
    assert (row.dispatched_at, row.attempt) == (NOW, 1)
    items = await lab.items(run_id)
    assert [(i.position, i.type, i.name, i.expected_kind) for i in items] == [
        (0, "mail", "RP-CANARY-0001", "manifest"),
        (1, "mail", "real mail 01", "fields"),
        (2, "sharepoint", "rp-canary-02.docx", "manifest"),
        (3, "sharepoint", "report.pdf", "backup_content"),
        (4, "onedrive", "rp-canary-11.pdf", "manifest"),
        (5, "onedrive", "Übersicht.docx", "backup_content"),
    ]
    # W6.3: the two random files were checked against the backup's own copy.
    assert [i.expected_sha256 is not None for i in items] == [True, False, True, True, True, True]
    assert all((i.found, i.match, i.reason, i.found_sha256) == (True, True, None, None) for i in items)
    assert [i.ms for i in items] == [123_000, 123_000, 246_000, 246_000, 246_000, 246_000]
    assert await lab.wrote(before) == [("result.received", f"run:{run_id}")]
    after = await lab.counts()
    assert rows_only(after) == {**rows_only(before), "test_item": before["test_item"] + 6, "audit_log": before["audit_log"] + 1}
    lab.stubber.assert_no_pending_responses()

    # The same bundle again: 202 with the stored state, nothing written, no put.
    again = await lab.upload(parts)

    assert (again.status_code, again.json()) == (202, {"run_id": str(run_id), "state": "pass"})
    assert await lab.counts() == after
    assert await lab.wrote(after) == []


async def test_a_timestamped_worker_bundle_lands_with_the_token_s_time(lab):
    """The second Done-when: a token the test TSA made over the re-signed
    result's hash, held to `verified` before the route sees it."""
    run_id = await lab.run()
    parts = lab.bundle(run_id, stamped_at=STAMPED_AT)
    digest = hashlib.sha256(parts["result"]).digest()
    assert vb.check_timestamp(parts["timestamp"], digest, lab.app.state.tsa_ca_pem) == ("verified", "2026-10-06T12:00:00Z")
    key = lab.expect_puts(run_id, parts)

    response = await lab.upload(parts)

    assert response.status_code == 202, response.text
    row = await lab.run_row(run_id)
    assert (row.state, row.tsa_ok, row.tsa_time) == ("pass", True, STAMPED_AT)
    assert row.bundle_key == key
    lab.stubber.assert_no_pending_responses()


# --- The request's words (point 1) ----------------------------------------------------------


async def test_no_token_and_a_revoked_worker_are_401_before_the_body_is_parsed(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    before = await lab.counts()
    await WorkerRepo(lab.session).revoke(lab.msp_id, lab.other_worker_id, NOW)

    without = await lab.post(parts)
    revoked = await lab.post(parts, lab.other_token)
    garbage = await lab.post(None, lab.other_token, content=b"not even multipart", headers={"Content-Type": "text/plain"})
    unread = Body([b"x" * 1024] * 8)
    unpulled = await lab.post(None, None, content=unread, headers={"Content-Type": "multipart/form-data; boundary=x", "Content-Length": "8192"})

    for response in (without, revoked, garbage, unpulled):
        assert (response.status_code, response.json()) == (401, NOT_AUTHENTICATED)
        assert response.headers["WWW-Authenticate"] == "Bearer"
    assert unread.pulled == 0  # what "before the body is parsed" means: not one chunk was asked for
    assert await lab.counts() == before  # no audit row before authentication
    lab.stubber.assert_no_pending_responses()


async def test_a_body_that_is_not_multipart_is_415(lab):
    before = await lab.counts()

    response = await lab.upload(None, content=b'{"result": {}}', headers={"Content-Type": "application/json"})

    await assert_refused(lab, response, 415, results.BODY_NOT_MULTIPART, before=before)


async def test_a_body_without_a_content_length_is_411(lab):
    before = await lab.counts()

    async def chunks():
        yield b"--x\r\nContent-Disposition: form-data; name=\"result\"; filename=\"result.json\"\r\n\r\n{}\r\n--x--\r\n"

    response = await lab.upload(None, content=chunks(), headers={"Content-Type": "multipart/form-data; boundary=x"})

    await assert_refused(lab, response, 411, results.BODY_NO_LENGTH, before=before)


@pytest.mark.parametrize("length", [str(results.MAX_UPLOAD_BYTES + 1), "100000000000"])
async def test_a_content_length_over_the_cap_is_413_before_any_byte_is_read(lab, length):
    before = await lab.counts()
    body = Body([b"--x\r\nContent-Disposition: form-data; name=\"result\"; filename=\"result.json\"\r\n\r\n{}\r\n--x--\r\n"])

    response = await lab.upload(None, content=body, headers={"Content-Type": "multipart/form-data; boundary=x", "Content-Length": length})

    await assert_refused(lab, response, 413, results.BODY_TOO_LARGE, before=before)
    assert body.pulled == 0


def multipart_of(parts) -> tuple[bytes, str]:
    """The parts as one multipart body and its Content-Type, as httpx frames them."""
    request = httpx.Request("POST", "http://x", files=files_of(parts))
    request.read()
    return request.content, request.headers["Content-Type"]


async def test_a_body_over_the_cap_is_413_whatever_its_content_length_says_and_is_not_read_to_its_end(lab, monkeypatch):
    """The cap is held on the bytes that arrive, not on the header: a server
    that frames a body by its chunks (`Transfer-Encoding: chunked` beside a
    small Content-Length) hands the route more than the header said."""
    monkeypatch.setattr(results, "MAX_UPLOAD_BYTES", 4096)
    head = b"--x\r\nContent-Disposition: form-data; name=\"items.csv\"; filename=\"items.csv\"\r\n\r\n"
    body = Body([head] + [b"z" * 1024] * 64)
    before = await lab.counts()

    response = await lab.upload(None, content=body, headers={"Content-Type": "multipart/form-data; boundary=x", "Content-Length": "10"})

    await assert_refused(lab, response, 413, results.BODY_TOO_LARGE, before=before)
    assert body.pulled <= 6  # the head, four chunks to the cap, the one over it


async def test_a_body_of_exactly_the_cap_is_parsed_and_one_byte_more_is_413(lab, monkeypatch):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    content, content_type = multipart_of(parts)
    headers = {"Content-Type": content_type, "Content-Length": "10"}

    monkeypatch.setattr(results, "MAX_UPLOAD_BYTES", len(content) - 1)
    over = await lab.upload(None, content=Body([content]), headers=headers)
    monkeypatch.setattr(results, "MAX_UPLOAD_BYTES", len(content))
    lab.expect_puts(run_id, parts)
    at = await lab.upload(None, content=Body([content]), headers=headers)

    assert (over.status_code, over.json()) == (413, refused_body(results.BODY_TOO_LARGE))
    assert at.status_code == 202, at.text


@pytest.mark.parametrize("length", ["\u00b2", "1e3", "-1", "1 2", "0x10"])
async def test_a_content_length_that_is_no_number_is_411(lab, length):
    before = await lab.counts()

    response = await lab.upload(
        None, content=Body([b"x"]), headers={"Content-Type": "multipart/form-data; boundary=x", "Content-Length": length.encode("latin-1")}
    )

    await assert_refused(lab, response, 411, results.BODY_NO_LENGTH, before=before)


async def test_a_media_type_in_another_case_is_the_same_media_type(lab):
    """A media type is case-insensitive (RFC 9110): the body is parsed, never
    answered with a verifier's word for a form that was not read."""
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    content, content_type = multipart_of(parts)

    response = await lab.upload(None, content=content, headers={"Content-Type": content_type.replace("multipart/form-data", "Multipart/Form-Data")})

    assert response.status_code == 202, response.text


async def test_a_charset_no_name_decodes_under_is_400_malformed(lab):
    run_id = await lab.run()
    content, content_type = multipart_of(lab.bundle(run_id))
    before = await lab.counts()

    response = await lab.upload(None, content=content, headers={"Content-Type": content_type + "; charset=undefined"})

    await assert_refused(lab, response, 400, results.BODY_MALFORMED, before=before)


async def test_a_sender_that_goes_away_mid_body_is_malformed_never_an_unhandled_exception():
    from starlette.requests import Request

    from app.routers.results import _parts

    messages = [
        {"type": "http.request", "body": b"--x\r\nContent-Disposition: form-data; name=\"result\"; filename=\"r\"\r\n\r\n{", "more_body": True},
        {"type": "http.disconnect"},
    ]

    async def receive():
        return messages.pop(0)

    scope = {
        "type": "http", "method": "POST", "path": PATH, "query_string": b"",
        "headers": [(b"content-type", b"multipart/form-data; boundary=x"), (b"content-length", b"4096")],
    }

    assert await _parts(Request(scope, receive)) == results.Refused(400, results.BODY_MALFORMED)


async def test_the_form_s_spooled_files_are_closed_when_the_parts_are_read(lab, monkeypatch):
    from starlette.datastructures import UploadFile

    opened = []
    original = UploadFile.__init__

    def record(self, *args, **kwargs):
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(UploadFile, "__init__", record)
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    assert (await lab.upload({**parts, "signature": b"x" * 5000})).status_code == 400

    assert len(opened) == 8 and all(upload.file.closed for upload in opened)


async def test_the_bundle_is_verified_off_the_event_loop(lab, monkeypatch):
    """Verification is CPU work of up to seconds: on the loop it would hold
    every other request of every MSP."""
    import threading

    threads = []
    original = results.verify_upload

    def record(*args, **kwargs):
        threads.append(threading.get_ident())
        return original(*args, **kwargs)

    monkeypatch.setattr(results, "verify_upload", record)
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    assert len(threads) == 1 and threads[0] != threading.get_ident()


async def test_a_content_length_at_the_cap_is_read(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    body = httpx.Request("POST", "http://x", files=files_of(parts))
    body.read()

    response = await lab.upload(
        None, content=body.content,
        headers={"Content-Type": body.headers["Content-Type"], "Content-Length": str(results.MAX_UPLOAD_BYTES)},
    )

    # The server reads what the body holds; the header was within the cap.
    assert response.status_code == 202, response.text


@pytest.mark.parametrize(
    "case",
    ["bad boundary", "seventh file part", "a part without a file name", "no boundary"],
)
async def test_a_body_the_parser_refuses_is_400_malformed(lab, case):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    before = await lab.counts()
    request = {}
    if case == "bad boundary":
        request = {"content": b"--x\r\ngarbage", "headers": {"Content-Type": "multipart/form-data; boundary=y"}}
    elif case == "no boundary":
        request = {"content": b"--x\r\ngarbage", "headers": {"Content-Type": "multipart/form-data"}}
    elif case == "seventh file part":
        request = {"files": files_of(parts) + files_of([("screenshot.png", b"p"), ("extra", b"e"), ("more", b"m")])}
    else:
        request = {"files": files_of(parts), "data": {"note": "a field"}}

    response = await lab.upload(None, **request)

    await assert_refused(lab, response, 400, results.BODY_MALFORMED, before=before)


async def test_a_part_twice_is_400(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    before = await lab.counts()

    response = await lab.upload([*parts.items(), ("items.csv", parts["items.csv"])])

    await assert_refused(lab, response, 400, results.PART_TWICE, before=before)


@pytest.mark.parametrize(
    ("name", "limit", "status", "word"),
    [
        ("result", vb.MAX_RESULT_FILE_BYTES, 400, "result_unreadable"),
        ("signature", vb.MAX_SIGNATURE_FILE_BYTES, 400, "signature_file"),
        ("timestamp", vb.MAX_TIMESTAMP_FILE_BYTES, 400, "timestamp_file"),
        ("items.csv", results.MAX_ATTACHMENT_BYTES, 413, results.BODY_TOO_LARGE),
    ],
)
async def test_a_part_over_its_limit_is_refused_unread_and_one_at_it_is_read(lab, name, limit, status, word):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    before = await lab.counts()

    over = await lab.upload({**parts, name: b"x" * (limit + 1)})

    await assert_refused(lab, over, status, word, before=before)
    # At the limit the part is read and judged on its content (a verifier's
    # word, since x's are no file): never the size word.
    at = await lab.upload({**parts, name: b"x" * limit})
    assert at.status_code == 400 and at.json() != refused_body(results.BODY_TOO_LARGE)
    assert at.json()["detail"] in vb.WORDS


async def test_a_listed_attachment_over_the_cap_is_413(lab):
    run_id = await lab.run()
    big = b"z" * 64

    def patch(document):
        document["attachments"][0] = {"name": "items.csv", "sha256": hashlib.sha256(big).hexdigest(), "size_bytes": results.MAX_ATTACHMENT_BYTES + 1}

    parts = lab.bundle(run_id, patch=patch)
    before = await lab.counts()

    response = await lab.upload({**parts, "items.csv": big})

    await assert_refused(lab, response, 413, results.BODY_TOO_LARGE, before=before)


async def test_a_part_the_result_does_not_list_is_400(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    before = await lab.counts()

    response = await lab.upload({**parts, "manifest.json": b"{}"})

    await assert_refused(lab, response, 400, results.PART_UNEXPECTED, before=before)
    # A listed name in another case is not the listed part.
    before = await lab.counts()
    other_case = {k: v for k, v in parts.items() if k != "items.csv"} | {"ITEMS.CSV": parts["items.csv"]}
    response = await lab.upload(other_case)
    await assert_refused(lab, response, 400, "attachment_missing", before=before)


async def test_the_part_s_file_name_and_content_type_are_not_the_contract(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    files = [(name, ("whatever.bin", data, "text/plain")) for name, data in parts.items()]

    response = await lab.upload(None, files=files)

    assert response.status_code == 202, response.text


# --- The verifier's words through the route (point 4): the order and the key ------------------


async def test_the_key_is_the_token_s_worker_s_never_the_body_s(lab):
    """The second Worker's token with a bundle signed by the first key is
    `wrong_key`: the body's key_id names a registered key and still counts
    for nothing."""
    run_id = await lab.run(other=True)
    parts = lab.bundle(run_id)
    before = await lab.counts()

    response = await lab.upload(parts, lab.other_token)

    assert (response.status_code, response.json()) == (400, refused_body("wrong_key"))
    assert await lab.wrote(before) == [("result.rejected", f"worker:{lab.other_worker_id} wrong_key")]
    assert rows_only(await lab.counts()) == {**rows_only(before), "audit_log": before["audit_log"] + 1}


async def test_a_bundle_that_does_not_verify_names_no_run(lab):
    """Every 400 comes before the run is looked up: the same word whether the
    run exists, is another Worker's or is nothing."""
    mine = await lab.run()
    theirs = await lab.run(other=True)
    words = []
    for run_id in (mine, theirs, uuid.uuid4(), "not-a-uuid"):
        parts = lab.bundle(run_id)
        forged = {**parts, "signature": parts["signature"].replace(b'"algorithm":"ed25519"', b'"algorithm":"ed25518"')}
        words.append((await lab.upload(forged)).json()["detail"])
    assert words == ["signature_file"] * 4


async def test_no_string_of_the_result_reaches_a_response_or_a_log_line(lab):
    run_id = await lab.run()

    def patch(document):
        document["expected"]["items"][1]["subject"] = SENTINEL
        document["status"]["message"] = SENTINEL + " of the status"

    tampered = lab.bundle(run_id, patch=patch)
    tampered["result"] = tampered["result"].replace(b'"status":"pass"', b'"status":"pas"')  # not canonical? no: still canonical, the schema refuses
    refused = await lab.upload(tampered)
    taken = await lab.upload({**lab.bundle(run_id, patch=patch), "manifest.json": b"x"})

    assert refused.status_code == 400 and taken.status_code == 400
    for response in (refused, taken):
        assert SENTINEL not in response.text
    assert SENTINEL not in lab.log
    assert lab.token not in lab.log and token_hash(lab.token) not in lab.log
    assert lab.log.count('"event": "request"') == 2


# --- The run (point 5) --------------------------------------------------------------------------


@pytest.mark.parametrize("which", ["not a uuid", "unknown", "the other msp's", "the other worker's"])
async def test_a_run_that_is_not_this_worker_s_is_one_404(lab, which):
    run_id = {
        "not a uuid": "w46-done-when-2",
        "unknown": uuid.uuid4(),
        "the other msp's": lab.b_run_id,
        "the other worker's": await lab.run(other=True),
    }[which]
    parts = lab.bundle(run_id)
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 404, results.NO_SUCH_RUN, before=before)
    if which == "the other msp's":
        assert (await lab.run_row(lab.b_run_id, lab.b_msp_id)).state == "dispatched"


@pytest.mark.parametrize("spelling", ["upper", "no hyphens", "urn"])
async def test_a_run_id_that_is_not_the_text_the_cloud_dispatched_is_no_such_run(lab, spelling):
    """The job gave `str(test_run.id)`: the signed result names the run by
    that text or it names no run, so the stored evidence and the row agree
    byte for byte."""
    run_id = await lab.run()
    text_of = {"upper": str(run_id).upper(), "no hyphens": run_id.hex, "urn": f"urn:uuid:{run_id}"}[spelling]
    assert uuid.UUID(text_of) == run_id and text_of != str(run_id)
    parts = lab.bundle(text_of)
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 404, results.NO_SUCH_RUN, before=before)
    assert (await lab.run_row(run_id)).state == "dispatched"


async def test_a_run_never_handed_out_is_409(lab):
    run_id = await lab.run(state="queued", attempt=0)
    parts = lab.bundle(run_id)
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 409, results.NOT_DISPATCHED, run_id=run_id, before=before)
    assert (await lab.run_row(run_id)).state == "queued"


@pytest.mark.parametrize("state", ["dispatched", "queued", "expired"])
async def test_a_run_handed_out_takes_its_bundle_whatever_the_sweep_did_since(lab, state):
    """The W4.8 case: the service's `error interrupted` written at its next
    start lands on a run the sweep has requeued or expired meanwhile."""
    attempt = 3 if state == "expired" else 2
    run_id = await lab.run(state=state, attempt=attempt)
    parts = bundle(run_id, lab.client_id, base=CLOSED_RESULT, attachments=CLOSED_ATTACHMENTS)
    lab.expect_puts(run_id, parts)

    response = await lab.upload(parts)

    assert (response.status_code, response.json()) == (202, {"run_id": str(run_id), "state": "error"})
    row = await lab.run_row(run_id)
    assert (row.state, row.error_code, row.attempt, row.dispatched_at) == ("error", "interrupted", attempt, NOW)
    assert row.error_message.startswith("the run was interrupted before its result was written")
    assert row.started_at == dt.datetime(2026, 10, 8, 9, 0, 1, tzinfo=UTC)
    assert (row.finished_at, row.total_ms, row.cleanup_ok, row.tsa_ok) == (None, None, None, None)
    assert row.restore_point_at == dt.datetime(2026, 10, 7, 22, 0, 45, tzinfo=UTC)
    assert await lab.items(run_id) == []


# --- The client (point 9) -----------------------------------------------------------------------


def other_client_id(document):
    document["client"]["client_id"] = str(uuid.uuid4())


def null_client_id(document):
    document["client"]["client_id"] = None


def other_tenant(document):
    document["client"]["tenant_id"] = str(uuid.uuid4())


def tenant_no_guid(document):
    document["client"]["tenant_id"] = "contoso"


def other_organisation(document):
    document["client"]["resolved"]["organization"]["tenant_id"] = str(uuid.uuid4())


def organisation_no_guid(document):
    document["client"]["resolved"]["organization"]["tenant_id"] = "11111111-2222-3333-4444-55555555555"


def pass_without_the_check(document):
    document["client"]["scope"] = None
    document["client"]["resolved"] = None


@pytest.mark.parametrize(
    "patch",
    [other_client_id, null_client_id, other_tenant, tenant_no_guid, other_organisation, organisation_no_guid, pass_without_the_check],
    ids=lambda f: f.__name__,
)
async def test_a_bundle_whose_client_is_not_the_run_s_is_409(lab, patch):
    run_id = await lab.run()
    parts = lab.bundle(run_id, patch=patch)
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 409, results.CLIENT_MISMATCH, run_id=run_id, before=before)
    assert (await lab.run_row(run_id)).state == "dispatched"


async def test_the_tenant_in_the_other_case_is_the_same_tenant(lab):
    run_id = await lab.run()

    def upper(document):
        document["client"]["tenant_id"] = document["client"]["tenant_id"].upper()
        document["client"]["resolved"]["organization"]["tenant_id"] = str(TENANT_ID).upper()

    parts = lab.bundle(run_id, patch=upper)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202


async def test_an_error_without_the_client_check_is_filed_but_a_fail_is_not(lab):
    run_id = await lab.run()

    def fail_unchecked(document):
        pass_without_the_check(document)
        document["status"]["status"] = "fail"
    parts = lab.bundle(run_id, patch=fail_unchecked)

    assert (await lab.upload(parts)).json() == refused_body(results.CLIENT_MISMATCH)

    def error_unchecked(document):
        pass_without_the_check(document)
        document["status"]["status"] = "error"
        document["status"]["error_code"] = "client_mismatch"
    parts = lab.bundle(run_id, patch=error_unchecked)
    lab.expect_puts(run_id, parts)
    assert (await lab.upload(parts)).json() == {"run_id": str(run_id), "state": "error"}
    assert (await lab.run_row(run_id)).error_code == "client_mismatch"


def profile_unread(document):
    """What the Worker signs for a job whose client profile it couldn't read
    (worker/src/service_recovery.cpp, `close_plan`): the job's client_id beside
    the empty strings of a profile that was never known."""
    document["client"].update({"tenant_id": "", "veeam_org_name": "", "scope": None, "resolved": None})
    document["status"]["error_code"] = "job_invalid"
    document["status"]["message"] = "the job is invalid (client.veeam_org_name)"


async def test_the_worker_s_job_invalid_for_a_profile_it_could_not_read_is_filed(lab):
    run_id = await lab.run()
    parts = bundle(run_id, lab.client_id, base=CLOSED_RESULT, attachments=CLOSED_ATTACHMENTS, patch=profile_unread)
    lab.expect_puts(run_id, parts)

    response = await lab.upload(parts)

    assert (response.status_code, response.json()) == (202, {"run_id": str(run_id), "state": "error"}), response.text
    row = await lab.run_row(run_id)
    assert (row.state, row.error_code, row.error_message) == ("error", "job_invalid", "the job is invalid (client.veeam_org_name)")


@pytest.mark.parametrize("case", ["a pass", "another client", "a tenant that is said and wrong"])
async def test_an_unknown_tenant_excuses_nothing_else(lab, case):
    run_id = await lab.run()

    def patch(document):
        status = copy.deepcopy(document["status"])
        profile_unread(document)
        if case == "a pass":
            document["status"] = status
        elif case == "another client":
            document["client"]["client_id"] = str(uuid.uuid4())
        else:
            document["client"]["tenant_id"] = str(uuid.uuid4())

    if case == "a pass":
        parts = lab.bundle(run_id, patch=patch)
    else:
        parts = bundle(run_id, lab.client_id, base=CLOSED_RESULT, attachments=CLOSED_ATTACHMENTS, patch=patch)
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 409, results.CLIENT_MISMATCH, run_id=run_id, before=before)


# --- A result the tables can't hold --------------------------------------------------------------


def index_over_int4(document):
    document["expected"]["items"][5]["index"] = 2**31
    document["check"]["items"][5]["index"] = 2**31


def nul_in_a_subject(document):
    document["expected"]["items"][1]["subject"] = "real\x00mail"


def nul_in_a_file_name(document):
    document["expected"]["items"][3]["name"] = "report\x00.pdf"


def nul_in_the_status_message(document):
    document["status"] = copy.deepcopy(CLOSED_RESULT["status"])
    document["status"]["message"] = "the run\x00was interrupted"
    document["client"]["scope"] = None
    document["client"]["resolved"] = None


@pytest.mark.parametrize("patch", [index_over_int4, nul_in_a_subject, nul_in_a_file_name, nul_in_the_status_message], ids=lambda f: f.__name__)
async def test_a_verified_result_a_column_cannot_hold_is_a_worded_400_never_a_500(lab, patch):
    """The schema takes an index to 2^53-1 and any text; `test_item.position`
    is an int4 and PostgreSQL's text takes no U+0000. Refused with the
    Cloud's own word before the run is named, so the Worker isn't left
    retrying a 500 for good."""
    run_id = await lab.run()
    parts = lab.bundle(run_id, patch=patch)
    script = results.verifier()
    key = script.public_key_from_pem(KEYS["rfc8032-test-1"]["public_key_pem"].encode("ascii"))
    assert script.verify(parts["result"], parts["signature"], key, script.SCHEMAS).word == script.VERIFIED
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 400, results.RESULT_UNSTORABLE, before=before)
    assert (await lab.run_row(run_id)).state == "dispatched"


async def test_the_largest_index_the_column_holds_is_filed(lab):
    run_id = await lab.run()

    def patch(document):
        document["expected"]["items"][5]["index"] = 2**31 - 1
        document["check"]["items"][5]["index"] = 2**31 - 1
        # A pass's message is stored nowhere but in result.json: any text.
        document["status"]["message"] = "6 of 6\x00item(s) verified"

    parts = lab.bundle(run_id, patch=patch)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    assert [i.position for i in await lab.items(run_id)][-1] == 2**31 - 1


# --- The mapping (points 11 and 12) ------------------------------------------------------------


def a_fail(document):
    items = document["check"]["items"]
    items[1] = {"index": 1, "outcome": "mismatch", "found": True, "mismatches": ["subject"], "reason": "fields did not match: subject", "ms": 5}
    items[2] = {"index": 2, "outcome": "missing", "found": False, "reason": "no restored copy found"}
    items[3] = {"index": 3, "outcome": "error", "found": False, "reason": "the sharepoint restore target couldn't be read (graph_transient)", "error_code": "graph_transient"}
    items[4]["ms"] = -7
    document["check"]["counts"] = {"match": 3, "mismatch": 1, "missing": 1, "error": 1}
    document["status"] = {
        "status": "fail", "message": "3 of 6 item(s) verified; 2 failed; 1 unchecked", "restore_sent": True,
        "counts": {"items": 6, "verified": 3, "failed": 2, "unchecked": 1}, "verified": {"manifest": 2, "fields": 0, "metadata": 1, "backup_content": 0},
        "failed_items": [1, 2], "unchecked_items": [{"index": 3, "error_code": "graph_transient"}], "warnings": [],
    }
    document["timings"]["spans"]["total"] = {"note": "open"}
    document["ended_at"] = None
    document["cleanup"]["cleanup_ok"] = False


async def test_the_run_is_stamped_with_the_cloud_s_clock_when_its_bundle_is_filed_and_a_refusal_stamps_nothing(lab, monkeypatch):
    """The C6.6 review's finding 1: `received_at` is the Cloud's time, never a
    time of the bundle, and a report's month goes by it for a late result."""
    arrived = dt.datetime(2027, 1, 1, 3, 5, 0, 250000, tzinfo=dt.timezone.utc)
    monkeypatch.setattr(results_route, "now", lambda: arrived)
    run_id = await lab.run()
    assert (await lab.run_row(run_id)).received_at is None
    tampered = lab.bundle(run_id)
    tampered["result"] = tampered["result"].replace(b'"pass"', b'"fail"', 1)

    refused = await lab.upload(tampered)

    assert refused.status_code == 400 and (await lab.run_row(run_id)).received_at is None
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    assert (await lab.run_row(run_id)).received_at == arrived
    # The same bundle again changes nothing, its time included.
    monkeypatch.setattr(results_route, "now", lambda: arrived + dt.timedelta(days=1))
    assert (await lab.upload(parts)).status_code == 202
    assert (await lab.run_row(run_id)).received_at == arrived


def test_the_upload_s_clock_is_the_cloud_s_in_utc():
    before = dt.datetime.now(dt.timezone.utc)
    stamped = results_route.now()
    assert before <= stamped <= dt.datetime.now(dt.timezone.utc) and stamped.utcoffset() == dt.timedelta(0)


async def test_a_fail_s_items_and_columns(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id, patch=a_fail)
    lab.expect_puts(run_id, parts)

    response = await lab.upload(parts)

    assert response.json() == {"run_id": str(run_id), "state": "fail"}
    row = await lab.run_row(run_id)
    assert (row.state, row.error_code, row.error_message) == ("fail", None, None)
    assert (row.finished_at, row.total_ms, row.cleanup_ok) == (None, None, False)
    items = await lab.items(run_id)
    assert [(i.position, i.found, i.match, i.reason, i.ms) for i in items] == [
        (0, True, True, None, 123_000),
        (1, True, False, "fields did not match: subject", 5),
        (2, False, False, "no restored copy found", None),
        (3, False, None, "the sharepoint restore target couldn't be read (graph_transient)", None),
        (4, True, True, None, None),  # a clock that went back: not known
        (5, True, True, None, 246_000),
    ]


def a_content_fail(document):
    """C6.8 step 1: the two random files the backup gave a copy of
    (`backup_content`, one by `bytes`, one by `office-v1`) restored with other
    content: each a `sha256` mismatch, the run `fail` (W6.3 point 5)."""
    items = document["check"]["items"]
    for index in (3, 5):
        items[index] = {"index": index, "outcome": "mismatch", "found": True, "mismatches": ["sha256"], "reason": "fields did not match: sha256", "ms": 9}
    document["check"]["counts"] = {"match": 4, "mismatch": 2, "missing": 0, "error": 0}
    document["status"] = {
        "status": "fail", "message": "4 of 6 item(s) verified; 2 failed", "restore_sent": True,
        "counts": {"items": 6, "verified": 4, "failed": 2, "unchecked": 0}, "verified": {"manifest": 3, "fields": 1, "metadata": 0, "backup_content": 0},
        "failed_items": [3, 5], "unchecked_items": [], "warnings": [],
    }


async def test_a_backup_content_file_whose_restored_copy_differs_is_stored_as_a_mismatch_with_its_hash(lab):
    """C6.8 (docs/decisions.md 2026-10-15, step 1): the Cloud takes the
    fourth kind as it takes the other three: the row keeps the kind and the
    backup's hash, and a changed copy is `match` false with the Worker's
    reason, which the report's Failures section reads as "mismatch"."""
    run_id = await lab.run()
    parts = lab.bundle(run_id, patch=a_content_fail)
    lab.expect_puts(run_id, parts)

    response = await lab.upload(parts)

    assert response.json() == {"run_id": str(run_id), "state": "fail"}
    expected = {item["index"]: item for item in json.loads(parts["result"])["expected"]["items"]}
    items = await lab.items(run_id)
    assert [(i.position, i.expected_kind, i.expected_sha256, i.found, i.match, i.reason) for i in items if i.position in (3, 5)] == [
        (3, "backup_content", expected[3]["sha256"], True, False, "fields did not match: sha256"),
        (5, "backup_content", expected[5]["sha256"], True, False, "fields did not match: sha256"),
    ]
    assert [i.match for i in items] == [True, True, True, False, True, False]
    assert all(i.found_sha256 is None for i in items)


@pytest.mark.parametrize(
    ("span", "stored"),
    [
        (None, None),
        ({"note": "open"}, None),
        ({"note": "clock_backwards"}, None),
        ({"ms": 0}, 0),
        ({"ms": 61_000, "note": "stopped"}, 61_000),
        ({"ms": 2**53 - 1}, 2**53 - 1),
    ],
    ids=["null", "open", "clock backwards", "zero", "stopped", "largest"],
)
async def test_the_recovery_span_is_filed_as_the_total_is(lab, span, stored):
    """C6.2 (docs/decisions.md 2026-10-12, point 15): `timings.spans.recovery`
    goes into `test_run.recovery_ms`, null for a span without `ms`."""
    run_id = await lab.run()

    def patch(document):
        document["timings"]["spans"]["recovery"] = span

    parts = lab.bundle(run_id, patch=patch)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    row = await lab.run_row(run_id)
    assert (row.recovery_ms, row.total_ms) == (stored, 4_182_000)


async def test_a_run_that_sampled_but_was_not_checked_files_its_items_as_not_known(lab):
    run_id = await lab.run()

    def unchecked(document):
        document["check"] = None
        document["status"] = copy.deepcopy(CLOSED_RESULT["status"])
        document["status"]["error_code"] = "graph_transient"
        document["status"]["message"] = "the check could not run"
        document["client"]["scope"] = None
        document["client"]["resolved"] = None

    parts = lab.bundle(run_id, patch=unchecked)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).json() == {"run_id": str(run_id), "state": "error"}
    row = await lab.run_row(run_id)
    assert (row.error_code, row.error_message) == ("graph_transient", "the check could not run")
    items = await lab.items(run_id)
    assert len(items) == 6
    assert all((i.found, i.match, i.reason, i.ms) == (None, None, None, None) for i in items)
    assert [i.position for i in items] == [0, 1, 2, 3, 4, 5]


async def test_a_check_item_the_result_lacks_leaves_its_row_not_known(lab):
    run_id = await lab.run()

    def one_missing(document):
        del document["check"]["items"][2]

    parts = lab.bundle(run_id, patch=one_missing)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    items = await lab.items(run_id)
    assert [(i.position, i.found, i.match) for i in items][2] == (2, None, None)


async def test_a_date_the_pattern_takes_and_the_calendar_refuses_is_null_never_a_refusal(lab):
    run_id = await lab.run()

    def february_30(document):
        document["started_at"] = "2026-02-30T12:00:00.000Z"
        document["restore_point"]["backup_time"] = "2026-13-01T00:00:00Z"

    parts = lab.bundle(run_id, patch=february_30)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    row = await lab.run_row(run_id)
    assert (row.started_at, row.restore_point_at) == (None, None)
    assert row.finished_at == dt.datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)


async def test_the_stored_files_are_the_parts_bytes_under_the_run_s_prefix(lab):
    """What the Stubber was told to expect is the contract: key by key, byte
    for byte, with the content types (point 10)."""
    run_id = await lab.run()
    parts = lab.bundle(run_id, stamped_at=STAMPED_AT)
    key = lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202
    lab.stubber.assert_no_pending_responses()
    assert key.startswith("msp/") and key.endswith(f"/runs/{run_id}/")


# --- The repeat and the conflict (point 13) ----------------------------------------------------


async def test_another_bundle_for_a_run_that_holds_one_is_409_bundle_conflict(lab):
    run_id = await lab.run()
    first = lab.bundle(run_id)
    lab.expect_puts(run_id, first)
    assert (await lab.upload(first)).status_code == 202
    before = await lab.counts()

    def another(document):
        document["worker_version"] = "0.0.1"

    response = await lab.upload(lab.bundle(run_id, patch=another))

    await assert_refused(lab, response, 409, results.BUNDLE_CONFLICT, run_id=run_id, before=before)
    row = await lab.run_row(run_id)
    assert (row.state, row.bundle_sha256) == ("pass", hashlib.sha256(first["result"]).hexdigest())


async def test_a_repeat_is_verified_again_before_it_is_answered(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    assert (await lab.upload(parts)).status_code == 202
    before = await lab.counts()

    response = await lab.upload({**parts, "items.csv": parts["items.csv"] + b"x"})

    await assert_refused(lab, response, 400, "attachment_size", before=before)


# --- Statements, the commit and the race ---------------------------------------------------------


async def test_an_accepted_upload_is_six_statements_after_the_token_s_lookup_and_five_without_items(lab, test_engine):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    bare = await lab.run()
    bare_parts = bundle(bare, lab.client_id, base=CLOSED_RESULT, attachments=CLOSED_ATTACHMENTS)
    lab.expect_puts(bare, bare_parts)
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        assert (await lab.upload(parts)).status_code == 202
        with_items = [s for s in counted if s in ("SELECT", "UPDATE", "INSERT")]
        counted.clear()
        assert (await lab.upload(bare_parts)).status_code == 202
        without = [s for s in counted if s in ("SELECT", "UPDATE", "INSERT")]
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    # C6.8: the bundle has canaries, so one UPDATE more: the plan's cursor (0 rows: the lab's plan has none).
    assert with_items == ["SELECT", "SELECT", "SELECT", "UPDATE", "INSERT", "INSERT", "UPDATE"]
    assert without == ["SELECT", "SELECT", "SELECT", "UPDATE", "INSERT"]


async def committed_world(database_url: str):
    """An MSP, a client of the bundle's tenant, a Worker under test key 1 and
    one dispatched run, committed; the app on that database with its bucket
    stubbed."""
    engine = create_async_engine(database_url, connect_args={"server_settings": {"timezone": "UTC"}})
    token = new_token()
    async with make_session_factory(engine)() as session:
        async with session.begin():
            msp = await MspRepo(session).create(name="race")
            client = await ClientRepo(session).create(msp.id, name="c", tenant_id=TENANT_ID)
            worker = await WorkerRepo(session).create(
                msp.id, "w", public_key_pem=KEYS["rfc8032-test-1"]["public_key_pem"],
                key_id=KEYS["rfc8032-test-1"]["key_id"], api_token_hash=token_hash(token),
            )
            connector = await ConnectorRepo(session).create(msp.id, client.id, worker.id, profile_for(TENANT_ID))
            plan = await PlanRepo(session).create(
                msp.id, client.id, connector.id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 2 * * *", now=NOW
            )
            run = await RunRepo(session).create(
                msp.id, plan_id=plan.id, client_id=client.id, connector_id=connector.id, worker_id=worker.id
            )
            await session.execute(
                text("UPDATE test_run SET state = 'dispatched', dispatched_at = :at, attempt = 1 WHERE id = :id"),
                {"at": NOW, "id": run.id},
            )
    settings = make_settings()
    application = create_app(settings, log_stream=io.StringIO())
    application.state.session_factory = make_session_factory(engine)
    lab = Lab.__new__(Lab)
    lab.session, lab.stream, lab.settings, lab.app = None, io.StringIO(), settings, application
    s3 = make_s3_client(settings)
    from botocore.stub import Stubber
    lab.stubber = Stubber(s3)
    application.state.storage = Storage(s3, settings.s3_bucket)
    application.state.tsa_ca_pem = lab.app.state.tsa_ca_pem
    lab.stubber.activate()
    lab.msp_id, lab.client_id, lab.worker_id, lab.token = msp.id, client.id, worker.id, token
    return lab, engine, run.id


async def test_two_uploads_of_one_bundle_at_once_file_it_once(own_database):
    lab, engine, run_id = await committed_world(own_database)
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    try:
        transport = httpx.ASGITransport(app=lab.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            headers = {"Authorization": f"Bearer {lab.token}"}
            answers = await asyncio.gather(
                client.post(PATH, headers=headers, files=files_of(parts)),
                client.post(PATH, headers=headers, files=files_of(parts)),
            )
        reader = await asyncpg.connect(asyncpg_dsn(own_database), timeout=5)
        try:
            state = await reader.fetchval("SELECT state FROM test_run WHERE id = $1", run_id)
            items = await reader.fetchval("SELECT count(*) FROM test_item WHERE run_id = $1", run_id)
            received = await reader.fetchval("SELECT count(*) FROM audit_log WHERE action = 'result.received'")
        finally:
            await reader.close()
    finally:
        await engine.dispose()

    assert sorted(a.status_code for a in answers) == [202, 202]
    assert all(a.json() == {"run_id": str(run_id), "state": "pass"} for a in answers)
    assert (state, items, received) == ("pass", 6, 1)
    lab.stubber.assert_no_pending_responses()  # the puts ran once


async def test_the_rows_are_committed_before_the_202_leaves(own_database):
    """The Worker moves the folder to sent\\ on the 202: the row must be
    there for anyone who reads it right then (SessionDep's scope)."""
    lab, engine, run_id = await committed_world(own_database)
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    reader = await asyncpg.connect(asyncpg_dsn(own_database), timeout=5)
    seen = {}

    async def observing(scope, receive, send):
        async def observe(message):
            if message["type"] == "http.response.start":
                seen["state"] = await reader.fetchval("SELECT state FROM test_run WHERE id = $1", run_id)
                seen["items"] = await reader.fetchval("SELECT count(*) FROM test_item WHERE run_id = $1", run_id)
            await send(message)

        await lab.app(scope, receive, observe)

    try:
        transport = httpx.ASGITransport(app=observing)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            response = await client.post(PATH, headers={"Authorization": f"Bearer {lab.token}"}, files=files_of(parts))
    finally:
        await reader.close()
        await engine.dispose()

    assert response.status_code == 202
    assert seen == {"state": "pass", "items": 6}


async def test_a_put_that_fails_leaves_no_row_and_answers_500(lab):
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.stubber.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)
    before = await lab.counts()

    response = await lab.upload(parts)

    assert response.status_code == 500
    assert await lab.counts() == before
    assert (await lab.run_row(run_id)).state == "dispatched"


# --- C6.8: the canary cursor's advance (docs/decisions.md 2026-10-15, point 11) -------------------

# The re-signed bundle's rotation: mail 0 -> 1, SharePoint 1 -> 2, OneDrive 0 -> 1.
SENT, NEXT = (0, 1, 0), (1, 2, 1)


async def set_cursor(lab, cursor) -> None:
    mail, sp, od = cursor if cursor is not None else (None, None, None)
    await lab.session.execute(
        text("UPDATE test_plan SET canary_cursor_mail = :m, canary_cursor_sp = :s, canary_cursor_od = :o WHERE id = :id"),
        {"m": mail, "s": sp, "o": od, "id": lab.plan_id},
    )


async def cursor_now(lab):
    row = (await lab.session.execute(
        text("SELECT canary_cursor_mail, canary_cursor_sp, canary_cursor_od FROM test_plan WHERE id = :id"), {"id": lab.plan_id}
    )).one()
    return None if row[0] is None else tuple(row)


@pytest.mark.parametrize("patch", [None, a_content_fail], ids=["pass", "fail"])
async def test_a_result_with_canaries_moves_its_plan_s_cursor_to_the_worker_s_cursor_next(lab, patch):
    await set_cursor(lab, SENT)
    run_id = await lab.run()
    parts = lab.bundle(run_id, patch=patch)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202

    assert await cursor_now(lab) == NEXT
    # The same bundle again moves nothing (and writes nothing, the repeat's rule).
    assert (await lab.upload(parts)).status_code == 202
    assert await cursor_now(lab) == NEXT


@pytest.mark.parametrize("stored", [(5, 5, 5), NEXT, None], ids=["another cursor", "already moved", "no canaries"])
async def test_a_result_sent_with_another_cursor_moves_nothing_and_is_taken(lab, stored):
    """Two runs of one plan out with one cursor: the first result moves it,
    the second finds it moved; a plan opted out meanwhile stays out."""
    await set_cursor(lab, stored)
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)

    assert (await lab.upload(parts)).status_code == 202

    assert await cursor_now(lab) == stored


async def test_a_put_that_fails_rolls_the_cursor_back_with_the_run(lab):
    await set_cursor(lab, SENT)
    run_id = await lab.run()
    lab.stubber.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)

    assert (await lab.upload(lab.bundle(run_id))).status_code == 500

    assert await cursor_now(lab) == SENT


async def test_the_cursor_moves_after_the_objects_are_put(lab, monkeypatch):
    """The plan's row is locked from the advance to the commit: the advance
    comes after every put, so another upload of the plan never waits on this
    one's objects (the C6.8 code review's finding 5)."""
    await set_cursor(lab, SENT)
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    lab.expect_puts(run_id, parts)
    order: list[str] = []
    storage = lab.app.state.storage
    put = storage.put
    advance = PlanRepo.advance_canary_cursor

    def recorded_put(key, body, content_type):
        order.append("put")
        return put(key, body, content_type)

    async def recorded_advance(self, *args, **kwargs):
        order.append("advance")
        return await advance(self, *args, **kwargs)

    monkeypatch.setattr(storage, "put", recorded_put)
    monkeypatch.setattr(PlanRepo, "advance_canary_cursor", recorded_advance)

    assert (await lab.upload(parts)).status_code == 202

    assert order[-1] == "advance" and order.count("advance") == 1 and "put" in order
    assert await cursor_now(lab) == NEXT


def with_canaries(**changes) -> dict:
    document = copy.deepcopy(BUNDLE_RESULT)
    for key, value in changes.items():
        if key == "status":
            document["status"]["status"] = value
        else:
            kind, field = key.split("__")
            document["sample"][kind]["canary"][field] = value
    return document


def test_cursor_advance_reads_a_pass_or_a_fail_s_three_cursors():
    assert results.cursor_advance(with_canaries()) == (SENT, NEXT)
    assert results.cursor_advance(with_canaries(status="fail")) == (SENT, NEXT)
    assert results.cursor_advance(with_canaries(mail__cursor=999_999, onedrive__cursor_next=0)) == ((999_999, 1, 0), (1, 2, 0))


@pytest.mark.parametrize(
    "document",
    [
        with_canaries(status="error"),
        {**copy.deepcopy(BUNDLE_RESULT), "sample": None},
        CLOSED_RESULT,
        with_canaries(sharepoint__cursor_next=1_000_000),
        with_canaries(mail__cursor=2**53 - 1),
        with_canaries(onedrive__cursor=-1),
    ],
    ids=["error", "no sample", "a result written afterwards", "next over the rule", "sent over an integer column", "negative"],
)
def test_cursor_advance_is_none_for_what_must_not_move_a_cursor(document):
    """An error's canaries may never have been compared; a result without a
    rotation has none to hand on; a value outside the Worker's job rule can't
    be stored (the CHECK) or compared (an `integer` column), so the cursor is
    left as it is rather than the upload being a 500."""
    assert results.cursor_advance(document) is None


def test_cursor_advance_is_none_without_the_canary_objects():
    document = copy.deepcopy(BUNDLE_RESULT)
    del document["sample"]["manifest_sha256"]
    for kind in ("mail", "sharepoint", "onedrive"):
        del document["sample"][kind]["canary"]

    assert results.cursor_advance(document) is None


# --- The unit level of app/results.py ------------------------------------------------------------


def test_the_words_the_route_can_answer_are_the_verifier_s_and_the_request_s_and_the_run_s():
    assert set(results.REQUEST_WORDS) == {
        results.BODY_NOT_MULTIPART, results.BODY_NO_LENGTH, results.BODY_TOO_LARGE, results.BODY_MALFORMED,
        results.PART_TWICE, results.PART_UNEXPECTED, results.RESULT_UNSTORABLE,
    }
    assert set(results.RUN_WORDS) == {results.NO_SUCH_RUN, results.NOT_DISPATCHED, results.CLIENT_MISMATCH, results.BUNDLE_CONFLICT}
    assert not set(results.REQUEST_WORDS) & set(vb.WORDS)
    assert results.verifier().WORDS == vb.WORDS


def test_the_words_texts_are_the_contract():
    """The Worker and an operator read these texts (docs/verification.md "The
    Cloud receives a bundle"): a rename is a change of the API."""
    assert results.REQUEST_WORDS == (
        "body: not multipart/form-data", "body: no Content-Length", "body: too large", "body: malformed",
        "part_twice", "part_unexpected", "result_unstorable",
    )
    assert results.RUN_WORDS == ("run_id: no such run", "run_id: not dispatched", "client_mismatch", "bundle_conflict")


def test_every_run_state_either_takes_a_bundle_or_holds_one():
    """A state added to `RUN_STATES` lands in one list or the other, never in
    neither: `check_run` and `RunRepo.receive` between them cover every row."""
    import typing

    from app.models import RUN_STATES
    from app.repo.runs import RECEIVABLE_STATES
    from app.routers.results import Accepted

    assert set(results.FINISHED_STATES) | set(RECEIVABLE_STATES) == set(RUN_STATES)
    assert not set(results.FINISHED_STATES) & set(RECEIVABLE_STATES)
    assert results.FINISHED_STATES == ("pass", "fail", "error")
    assert typing.get_args(Accepted.model_fields["state"].annotation) == results.FINISHED_STATES


async def test_an_update_that_touched_nothing_on_a_run_that_still_takes_a_bundle_is_the_app_s_failure(lab, monkeypatch):
    """Only another upload's commit makes the UPDATE miss, and then the row
    read again says so (the two races in this file). A miss on a row that
    still takes a bundle is no state the Cloud knows: 500, nothing written."""
    calls = []

    async def touched_nothing(self, msp_id, run_id, *, worker_id, update, at):
        calls.append(run_id)
        return 0

    monkeypatch.setattr(RunRepo, "receive", touched_nothing)
    run_id = await lab.run()
    parts = lab.bundle(run_id)
    before = await lab.counts()

    response = await lab.upload(parts)

    assert response.status_code == 500
    assert calls == [run_id]  # asked once: nothing is tried twice
    assert await lab.counts() == before
    lab.stubber.assert_no_pending_responses()


def test_run_uuid_takes_the_canonical_text_alone():
    run_id = uuid.uuid4()
    assert results.run_uuid({"run_id": str(run_id)}) == run_id
    for text_of in (str(run_id).upper(), run_id.hex, f"urn:uuid:{run_id}", "{" + str(run_id) + "}", "x"):
        assert results.run_uuid({"run_id": text_of}) is None


def test_the_limits_are_the_verifiers_and_the_entry_s():
    assert results.MAX_UPLOAD_BYTES == 96 * 1024 * 1024
    assert results.MAX_ATTACHMENT_BYTES == 25 * 1024 * 1024
    assert results.MAX_FILE_PARTS == 6
    assert results.size_refusal("result", vb.MAX_RESULT_FILE_BYTES) is None
    assert results.size_refusal("screenshot.png", results.MAX_ATTACHMENT_BYTES) is None


def test_the_tsa_root_is_the_shared_file_and_the_verifier_is_the_shared_script():
    from app.schemas import shared_schemas_dir

    root = shared_schemas_dir().parent
    assert results.tsa_ca_pem() == (root / "tsa" / "tsa-ca.pem").read_bytes()
    assert b"-----BEGIN CERTIFICATE-----" in results.tsa_ca_pem()
    assert results.verifier().__file__ == str(root / "tools" / "verify_bundle.py")
    assert results.verifier() is results.verifier()


def test_a_tree_without_the_script_or_the_root_is_the_app_s_failure(tmp_path, monkeypatch):
    (tmp_path / "shared" / "schemas").mkdir(parents=True)
    monkeypatch.setattr(results, "shared_schemas_dir", lambda: tmp_path / "shared" / "schemas")
    results.verifier.cache_clear()
    results.tsa_ca_pem.cache_clear()
    try:
        with pytest.raises(FileNotFoundError, match="shared/tools/verify_bundle.py"):
            results.verifier()
        with pytest.raises(FileNotFoundError, match="shared/tsa/tsa-ca.pem"):
            results.tsa_ca_pem()
    finally:
        results.verifier.cache_clear()
        results.tsa_ca_pem.cache_clear()


def test_a_worker_row_whose_key_is_no_key_is_the_app_s_failure_never_a_verdict():
    parts = bundle(uuid.uuid4(), uuid.uuid4())
    with pytest.raises(RuntimeError):
        results.verify_upload(parts, public_key_pem="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n", key_id="a" * 64, tsa_ca=b"")
    with pytest.raises(RuntimeError):
        results.verify_upload(parts, public_key_pem=KEYS["rfc8032-test-1"]["public_key_pem"], key_id="a" * 64, tsa_ca=b"")


def test_a_token_is_held_to_the_root_the_route_was_given():
    parts = bundle(uuid.uuid4(), uuid.uuid4(), stamped_at=STAMPED_AT)
    key, key_id = KEYS["rfc8032-test-1"]["public_key_pem"], KEYS["rfc8032-test-1"]["key_id"]

    under_other = results.verify_upload(parts, public_key_pem=key, key_id=key_id, tsa_ca=OTHER_ROOT_PEM)
    verified = results.verify_upload(parts, public_key_pem=key, key_id=key_id, tsa_ca=results.tsa_ca_pem())

    assert under_other == results.Refused(400, "timestamp_invalid")
    assert verified == results.Refused(400, "timestamp_invalid")  # DigiCert's root, the image's: not the test TSA's


def test_item_rows_of_a_result_that_never_sampled_is_empty():
    assert results.item_rows(CLOSED_RESULT) == []
    assert results.item_rows({**BUNDLE_RESULT, "expected": None}) == []


def test_already_received_and_check_run_on_a_row():
    class Row:
        def __init__(self, **values):
            self.__dict__.update(values)

    worker = uuid.uuid4()
    run = Row(id=uuid.uuid4(), worker_id=worker, dispatched_at=NOW, state="pass", bundle_sha256="ab" * 32)

    assert results.already_received(run, "ab" * 32) is True
    assert results.already_received(run, "cd" * 32) is False
    assert results.check_run({}, run, worker, "ab" * 32) is None
    assert results.check_run({}, run, worker, "cd" * 32) == results.Refused(409, results.BUNDLE_CONFLICT, run.id)
    assert results.check_run({}, None, worker, "ab" * 32) == results.Refused(404, results.NO_SUCH_RUN)
    assert results.check_run({}, run, uuid.uuid4(), "ab" * 32) == results.Refused(404, results.NO_SUCH_RUN)
    never = Row(id=uuid.uuid4(), worker_id=worker, dispatched_at=None, state="queued", bundle_sha256=None)
    assert results.check_run({}, never, worker, "ab" * 32) == results.Refused(409, results.NOT_DISPATCHED, never.id)
    assert results.already_received(never, "ab" * 32) is False
    assert results.run_uuid({"run_id": "x"}) is None and results.run_uuid({"run_id": str(run.id)}) == run.id


async def test_two_different_bundles_for_one_run_at_once_file_one_and_refuse_the_other(own_database):
    """The race settled by the UPDATE's rowcount, the other way round: the
    loser reads the run again and finds another bundle there."""
    lab, engine, run_id = await committed_world(own_database)
    first = lab.bundle(run_id)

    def another(document):
        document["worker_version"] = "0.0.2"

    second = lab.bundle(run_id, patch=another)
    lab.stubber.add_response("put_object", {"ETag": '"x"'})
    lab.stubber.add_response("put_object", {"ETag": '"x"'})
    lab.stubber.add_response("put_object", {"ETag": '"x"'})
    lab.stubber.add_response("put_object", {"ETag": '"x"'})
    try:
        transport = httpx.ASGITransport(app=lab.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            headers = {"Authorization": f"Bearer {lab.token}"}
            answers = await asyncio.gather(
                client.post(PATH, headers=headers, files=files_of(first)),
                client.post(PATH, headers=headers, files=files_of(second)),
            )
        reader = await asyncpg.connect(asyncpg_dsn(own_database), timeout=5)
        try:
            stored = await reader.fetchval("SELECT bundle_sha256 FROM test_run WHERE id = $1", run_id)
            rejected = await reader.fetchval("SELECT count(*) FROM audit_log WHERE action = 'result.rejected'")
        finally:
            await reader.close()
    finally:
        await engine.dispose()

    assert sorted(a.status_code for a in answers) == [202, 409]
    assert [a.json() for a in answers if a.status_code == 409] == [{"detail": results.BUNDLE_CONFLICT}]
    winner = [p for p, a in zip((first, second), answers) if a.status_code == 202][0]
    assert stored == hashlib.sha256(winner["result"]).hexdigest()
    assert rejected == 1
    lab.stubber.assert_no_pending_responses()
