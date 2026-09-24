import hashlib
import io
import json
import zipfile

import pytest

from seeder import CANARY_DIR, REPO_DIR
from seeder.office import OFFICE_RULE, OfficeContentError, content_listing, office_content_sha256

VECTORS = REPO_DIR / "shared" / "testdata" / "office-content-v1"
CASES = json.loads((VECTORS / "cases.json").read_text(encoding="utf-8"))["cases"]


def _zip(parts: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


def _hand_hash(parts: dict[str, bytes]) -> str:
    lines = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(parts.items()))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


# --- failure paths ----------------------------------------------------------------------

def test_not_a_zip_is_an_error():
    with pytest.raises(OfficeContentError, match="not a ZIP"):
        office_content_sha256(b"%PDF-1.4 not a zip", "docx")


def test_no_content_parts_is_an_error():
    with pytest.raises(OfficeContentError, match="no word/ parts"):
        office_content_sha256(_zip({"docProps/core.xml": b"x", "word/_rels/document.xml.rels": b"r"}), "docx")


def test_type_without_a_rule_is_an_error():
    with pytest.raises(OfficeContentError, match="pdf"):
        office_content_sha256(_zip({"word/document.xml": b"x"}), "pdf")


def test_duplicate_part_names_are_an_error():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", b"a")
        with pytest.warns(UserWarning):
            z.writestr("word/document.xml", b"b")
    with pytest.raises(OfficeContentError, match="more than once"):
        office_content_sha256(buf.getvalue(), "docx")


def test_a_changed_content_part_changes_the_hash():
    a = _zip({"word/document.xml": b"<w:t>one</w:t>"})
    b = _zip({"word/document.xml": b"<w:t>two</w:t>"})
    assert office_content_sha256(a, "docx") != office_content_sha256(b, "docx")


def test_an_added_content_part_changes_the_hash():
    a = _zip({"xl/workbook.xml": b"w"})
    b = _zip({"xl/workbook.xml": b"w", "xl/media/image1.png": b"png"})
    assert office_content_sha256(a, "xlsx") != office_content_sha256(b, "xlsx")


# --- the rule -----------------------------------------------------------------------------

def test_hash_is_the_sha256_of_the_sorted_listing():
    parts = {
        "word/styles.xml": b"s",
        "word/document.xml": b"d",
        "word/media/image1.png": b"\x89PNG",
    }
    ignored = {
        "[Content_Types].xml": b"c",
        "_rels/.rels": b"r",
        "word/_rels/document.xml.rels": b"r2",
        "docProps/core.xml": b"p",
        "docProps/custom.xml": b"q",
        "customXml/item1.xml": b"x",
        "[trash]/0000.dat": b"t",
    }
    data = _zip({**ignored, **parts})
    assert office_content_sha256(data, "docx") == _hand_hash(parts)
    assert content_listing(data, "docx").splitlines() == [
        f"{hashlib.sha256(parts[n]).hexdigest()}  {n}" for n in sorted(parts)
    ]


def test_compression_does_not_change_the_hash():
    parts = {"xl/workbook.xml": b"w" * 500, "xl/worksheets/sheet1.xml": b"s" * 500}
    stored = _zip(parts)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in parts.items():
            z.writestr(n, d)
    assert office_content_sha256(stored, "xlsx") == office_content_sha256(buf.getvalue(), "xlsx")


def test_rule_name():
    assert OFFICE_RULE == "office-v1"


# --- the shared vectors: real SharePoint rewrites --------------------------------------

@pytest.mark.parametrize("case", CASES, ids=[c["file"] for c in CASES])
def test_shared_vectors(case):
    data = (VECTORS / case["file"]).read_bytes()
    assert office_content_sha256(data, case["file_type"]) == case["content_sha256"]


@pytest.mark.parametrize("stem, file_type", [("rp-canary-02", "docx"), ("rp-canary-03", "xlsx")])
def test_sharepoint_rewrite_keeps_the_content_hash(stem, file_type):
    local = (VECTORS / f"{stem}.local.{file_type}").read_bytes()
    stored = (VECTORS / f"{stem}.sharepoint.{file_type}").read_bytes()
    assert local != stored  # SharePoint really did rewrite the package
    assert office_content_sha256(local, file_type) == office_content_sha256(stored, file_type)


def test_vector_local_files_are_the_committed_canaries():
    for stem, ext in (("rp-canary-02", "docx"), ("rp-canary-03", "xlsx")):
        assert (VECTORS / f"{stem}.local.{ext}").read_bytes() == (CANARY_DIR / f"{stem}.{ext}").read_bytes()


def test_vectors_file_lists_every_vector_file():
    listed = {c["file"] for c in CASES}
    on_disk = {p.name for p in VECTORS.iterdir() if p.suffix in (".docx", ".xlsx")}
    assert listed == on_disk
