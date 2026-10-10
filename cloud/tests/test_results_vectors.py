"""C5.7: the shared vectors through `POST /v1/results` (docs/decisions.md
2026-10-10, C5.7, point 17): every case of shared/testdata/signing-v1/
cases.json and shared/testdata/timestamp-v1/cases.json, built as the folder
the Worker would upload and posted as the Worker posts it, under the Worker
registered with the case's key and the app's TSA root set to the case's.
Every failing case answers 400 with the case's own word, one audit row and
nothing stored; every verified case passes the whole verification and is then
404 `run_id: no such run`, since the vectors' run_id is no uuid (what the
Cloud can show for a folder it didn't dispatch). The 202 is
tests/test_results.py's, on the Worker-made bundle re-keyed to a run.
"""

from __future__ import annotations

import pytest

from app import results
from tests.results_lab import Lab
from tests.test_results import assert_refused, rows_only
from tests.test_verify_bundle import CASES_FILE as SIGNING_CASES
from tests.test_verify_bundle import write_folder
from tests.test_verify_bundle_closed import CLOSED
from tests.test_verify_bundle_timestamp import CASES_FILE as TIMESTAMP_CASES
from tests.test_verify_bundle_timestamp import tsa_ca
from tests.tsa_lab import ROOT_PEM

PART_OF = {"result.json": "result", "signature.json": "signature", "timestamp.tst": "timestamp"}

# Two cases differ from the verifiers by design (point 17): a token under
# another case of its name is a file the verifiers note and a part the upload
# refuses; a token with no CA given is unchecked to the script and checked
# under the root here.
DIFFERS = {"token-under-another-name": (400, results.PART_UNEXPECTED), "token-and-no-ca": (404, results.NO_SUCH_RUN)}


def parts_of(folder) -> dict[str, bytes]:
    """The folder as the Worker would post it: result.json as `result`,
    signature.json as `signature`, timestamp.tst as `timestamp`, every other
    file under its own name."""
    return {PART_OF.get(path.name, path.name): path.read_bytes() for path in sorted(folder.iterdir())}


def token_of(case) -> str:
    return "token" if case["public_key"] == "rfc8032-test-1" else "other_token"


@pytest.fixture
async def lab(session):
    lab = Lab(session)
    await lab.fill()
    return lab


async def post_case(lab: Lab, case, tmp_path):
    folder = write_folder(tmp_path / "run", case["files"])
    lab.app.state.tsa_ca_pem = tsa_ca(case.get("tsa_ca")) or ROOT_PEM
    before = await lab.counts()
    response = await lab.upload(parts_of(folder), getattr(lab, token_of(case)))
    return response, before


def expected(case) -> tuple[int, str]:
    if case["name"] in DIFFERS:
        return DIFFERS[case["name"]]
    return (404, results.NO_SUCH_RUN) if case["expect"] == "verified" else (400, case["expect"])


ALL_CASES = [*SIGNING_CASES["cases"], *TIMESTAMP_CASES["cases"]]


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda case: case["name"])
async def test_each_shared_case_gets_its_word_through_the_route(lab, case, tmp_path):
    response, before = await post_case(lab, case, tmp_path)

    status, word = expected(case)
    worker_id = lab.worker_id if case["public_key"] == "rfc8032-test-1" else lab.other_worker_id
    assert (response.status_code, response.json()) == (status, {"detail": word}), case["name"]
    assert await lab.wrote(before) == [("result.rejected", f"worker:{worker_id} {word}")]
    assert rows_only(await lab.counts()) == {**rows_only(before), "audit_log": before["audit_log"] + 1}
    lab.stubber.assert_no_pending_responses()


def test_the_cases_are_the_61_and_the_two_that_differ_are_named():
    assert len(ALL_CASES) == 38 + 23
    assert {case["name"] for case in ALL_CASES} >= set(DIFFERS)
    assert sum(1 for case in ALL_CASES if case["expect"] == "verified") == 8


async def test_the_closed_folder_verifies_and_is_then_the_run_s_404(lab):
    parts = {PART_OF.get(name, name): text.encode("utf-8") for name, text in CLOSED["files"].items()}
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 404, results.NO_SUCH_RUN, before=before)
    assert results.item_rows(results.verifier().parse_strict(parts["result"])) == []


async def test_a_verified_case_is_refused_for_the_run_only_after_the_whole_verification(lab, tmp_path):
    """The 404 comes after the fifteen words: the same folder under a key that
    isn't its signer's is `wrong_key`, never the run's word."""
    untouched = next(case for case in SIGNING_CASES["cases"] if case["name"] == "untouched")
    folder = write_folder(tmp_path / "run", untouched["files"])

    as_signer = await lab.upload(parts_of(folder), lab.token)
    as_other = await lab.upload(parts_of(folder), lab.other_token)

    assert as_signer.json() == {"detail": results.NO_SUCH_RUN}
    assert as_other.json() == {"detail": "wrong_key"}
