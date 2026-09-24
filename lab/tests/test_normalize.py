import hashlib
import json

import pytest

from seeder import REPO_DIR
from seeder.catalog import canary_mails
from seeder.normalize import NORMALIZATION_ID, body_sha256, normalize_body

VECTORS_PATH = REPO_DIR / "shared" / "testdata" / "body-normalization-text-v1.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
CASES = VECTORS["cases"]

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_vectors_file_names_this_normalisation():
    assert VECTORS["normalization"] == NORMALIZATION_ID == "text-v1"


def test_vectors_file_covers_every_required_case():
    names = {case["name"] for case in CASES}
    required = {
        "plain", "crlf", "lone-cr", "mixed-endings", "trailing-spaces", "trailing-tabs",
        "trailing-spaces-last-line", "trailing-newlines", "trailing-crlf-blank-lines",
        "leading-bom", "bom-not-at-start", "leading-whitespace", "nbsp-at-line-end",
        "non-ascii", "combining-sequence", "empty", "only-newlines",
        "catalog-rp-canary-0001-crlf", "catalog-rp-canary-0001-lf",
    }
    assert required <= names
    assert len(names) == len(CASES), "case names must be unique"


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_vector(case):
    assert normalize_body(case["input"]) == case["normalized"]
    assert hashlib.sha256(case["normalized"].encode("utf-8")).hexdigest() == case["sha256"]
    assert body_sha256(case["input"]) == case["sha256"]


def test_catalog_body_vectors_match_the_catalog_and_each_other():
    by_name = {c["name"]: c for c in CASES}
    crlf = by_name["catalog-rp-canary-0001-crlf"]
    lf = by_name["catalog-rp-canary-0001-lf"]
    assert crlf["input"] == canary_mails()[0].body
    assert lf["input"] == canary_mails()[0].body.replace("\r\n", "\n")
    assert crlf["sha256"] == lf["sha256"]


@pytest.mark.parametrize(
    ("name", "normalized"),
    [
        ("mixed-endings", "a\nb\nc\nd\n\ne"),
        ("trailing-crlf-blank-lines", "text"),
        ("leading-bom", "BOM at start"),
        ("bom-not-at-start", "text﻿ with BOM inside"),
        ("nbsp-at-line-end", "no-break space \nnext"),
        ("combining-sequence", "é is not composed to é"),
        ("only-newlines", ""),
    ],
)
def test_vector_normalized_values_are_hand_checked(name, normalized):
    assert {c["name"]: c for c in CASES}[name]["normalized"] == normalized


# Hand-derived: the expected hashes below come from literal bytes, not from the vectors
# file, so a wrong implementation can't confirm itself.
@pytest.mark.parametrize(
    ("text", "expected_bytes"),
    [
        ("a \r\nb\r\n\r\n", b"a\nb"),
        ("line1\rline2\r", b"line1\nline2"),
        ("x\t \t\ny  ", b"x\ny"),
        ("﻿hello\n\n\n", b"hello"),
        ("a﻿b", "a﻿b".encode("utf-8")),
        ("  indented", b"  indented"),
        ("nbsp \n", b"nbsp\xc2\xa0"),
        ("café 日本 \U0001F600", b"caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x98\x80"),
        ("é", b"e\xcc\x81"),  # combining acute accent stays decomposed (no NFC)
        ("\r\n\r\n", b""),
    ],
)
def test_hand_derived_hashes(text, expected_bytes):
    assert body_sha256(text) == hashlib.sha256(expected_bytes).hexdigest()


@pytest.mark.parametrize(
    ("text", "expected_hash"),
    [
        ("", EMPTY_SHA256),
        ("\n\n", EMPTY_SHA256),
        ("abc", ABC_SHA256),
        ("abc  \r\n", ABC_SHA256),
        ("﻿abc\t\r\n\r\n", ABC_SHA256),
    ],
)
def test_published_sha256_constants(text, expected_hash):
    assert body_sha256(text) == expected_hash


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a\r\nb", "a\nb"),
        ("a\rb", "a\nb"),
        ("a\r\r\nb", "a\n\nb"),
        ("a   \nb", "a\nb"),
        ("a\n\n\n", "a"),
        ("﻿﻿a", "﻿a"),  # only one leading BOM is dropped
        ("a  ", "a "),
        ("A b", "A b"),  # no case change
        ("日本 \n", "日本"),
    ],
)
def test_inline_normalisation(text, expected):
    assert normalize_body(text) == expected


def test_hash_is_lower_case_hex():
    value = body_sha256("RP")
    assert len(value) == 64 and value == value.lower()
