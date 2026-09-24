"""Tests for seeder.generate: the 20 canary files are deterministic, valid and committed."""

import hashlib
import io
import struct
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest

from seeder import CANARY_DIR
from seeder.catalog import canary_files
from seeder.generate import generate_all, generate_file, run_generate

FILES = canary_files()
BY_TYPE = {t: [f for f in FILES if f.file_type == t] for t in ("pdf", "docx", "xlsx", "txt", "png")}


def _ids(files):
    return [f.name for f in files]


# ---- failure paths first: anything that would make the expected set drift ----


@pytest.mark.parametrize("file", FILES, ids=_ids(FILES))
def test_generated_bytes_match_committed_file(file):
    committed = CANARY_DIR / file.name
    assert committed.is_file(), (
        f"{committed} is missing. The committed canary files are the expected set; "
        "regenerate them with `uv run python -m seeder generate` from lab/ only if that is intended."
    )
    assert generate_file(file) == committed.read_bytes(), (
        f"generate_file({file.name}) no longer produces the committed bytes in lab/canary/. "
        "If (and only if) this change is intentional, run `uv run python -m seeder generate` from lab/ "
        "and commit the new files: that changes the expected set, so it needs a new seed run and manifest."
    )


def test_generating_twice_gives_identical_bytes(tmp_path):
    first = generate_all(tmp_path / "a")
    second = generate_all(tmp_path / "b")
    assert [p.name for p in first] == [p.name for p in second] == _ids(FILES)
    for a, b in zip(first, second):
        assert a.read_bytes() == b.read_bytes(), a.name


def test_generate_all_creates_the_directory_and_returns_catalog_order(tmp_path):
    out = tmp_path / "nested" / "canary"
    paths = generate_all(out)
    assert paths == [out / f.name for f in FILES]
    assert sorted(p.name for p in out.iterdir()) == sorted(_ids(FILES))


def test_all_hashes_are_distinct():
    digests = {hashlib.sha256(generate_file(f)).hexdigest() for f in FILES}
    assert len(digests) == len(FILES)


# ---- catalog mapping table ----

MAPPING = [(n, ("pdf", "docx", "xlsx", "txt", "png")[(n - 1) % 5], "sharepoint_file" if n <= 10 else "onedrive_file")
           for n in range(1, 21)]


@pytest.mark.parametrize("number,file_type,kind", MAPPING)
def test_mapping(number, file_type, kind):
    file = FILES[number - 1]
    assert file.number == number
    assert file.file_type == file_type
    assert file.kind == kind
    assert file.name == f"rp-canary-{number:02d}.{file_type}"


def test_mapping_spot_checks():
    assert (FILES[0].file_type, FILES[0].kind) == ("pdf", "sharepoint_file")
    assert FILES[5].file_type == "pdf"
    assert (FILES[19].file_type, FILES[19].kind) == ("png", "onedrive_file")


# ---- format structure: nothing depends on clock, platform or zlib build ----


@pytest.mark.parametrize("file", BY_TYPE["docx"] + BY_TYPE["xlsx"], ids=_ids(BY_TYPE["docx"] + BY_TYPE["xlsx"]))
def test_zip_entries_are_stored_with_fixed_metadata(file):
    with zipfile.ZipFile(io.BytesIO(generate_file(file))) as z:
        infos = z.infolist()
        assert infos[0].filename == "[Content_Types].xml"
        for info in infos:
            assert info.compress_type == zipfile.ZIP_STORED, info.filename
            assert info.date_time == (1980, 1, 1, 0, 0, 0), info.filename
            assert info.create_system == 3, info.filename
            assert info.external_attr == 0o100644 << 16, info.filename
            assert info.flag_bits == 0, info.filename
            assert info.extra == b"", info.filename
            # Every part must be well-formed XML (Word/Excel refuse or repair otherwise).
            ElementTree.fromstring(z.read(info))
        assert z.testzip() is None


def _png_chunks(data: bytes) -> list[bytes]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, types = 8, []
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        types.append(data[pos + 4 : pos + 8])
        pos += 12 + length
    assert pos == len(data)
    return types


@pytest.mark.parametrize("file", BY_TYPE["png"], ids=_ids(BY_TYPE["png"]))
def test_png_has_only_ihdr_idat_iend(file):
    assert _png_chunks(generate_file(file)) == [b"IHDR", b"IDAT", b"IEND"]


@pytest.mark.parametrize("file", BY_TYPE["pdf"], ids=_ids(BY_TYPE["pdf"]))
def test_pdf_has_fixed_dates_and_no_id(file):
    data = generate_file(file)
    assert data.startswith(b"%PDF-1.4\n")
    assert data.endswith(b"%%EOF\n")
    assert b"/ID" not in data
    assert b"/CreationDate (D:20260101000000Z)" in data
    assert b"/ModDate (D:20260101000000Z)" in data
    assert b"/FlateDecode" not in data


@pytest.mark.parametrize("file", BY_TYPE["pdf"], ids=_ids(BY_TYPE["pdf"]))
def test_pdf_xref_offsets_are_exact(file):
    data = generate_file(file)
    startxref = int(data[data.rindex(b"startxref") :].split()[1])
    assert data[startxref:].startswith(b"xref\n")
    lines = data[startxref:].split(b"\n")
    first, count = map(int, lines[1].split())
    assert first == 0
    entries = data[startxref + len(lines[0]) + len(lines[1]) + 2 :][: 20 * count]
    for i in range(1, count):
        entry = entries[20 * i : 20 * (i + 1)]
        assert entry.endswith(b" n \n")
        offset = int(entry[:10])
        assert data[offset:].startswith(f"{i} 0 obj".encode()), i


# ---- every file opens with a real reader and carries its text ----


@pytest.mark.parametrize("file", BY_TYPE["pdf"], ids=_ids(BY_TYPE["pdf"]))
def test_pdf_opens_and_contains_sentence(file):
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(generate_file(file)), strict=True)
    assert len(reader.pages) == 1
    text = reader.pages[0].extract_text()
    assert file.sentence in text
    assert file.name in text


@pytest.mark.parametrize("file", BY_TYPE["docx"], ids=_ids(BY_TYPE["docx"]))
def test_docx_opens_and_contains_sentence(file):
    from docx import Document

    doc = Document(io.BytesIO(generate_file(file)))
    texts = [p.text for p in doc.paragraphs]
    assert texts[0] == file.name
    assert file.sentence in texts
    assert doc.core_properties.title == file.name
    assert doc.core_properties.author == "RestoreProof lab"


@pytest.mark.parametrize("file", BY_TYPE["xlsx"], ids=_ids(BY_TYPE["xlsx"]))
def test_xlsx_opens_and_contains_sentence(file):
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(generate_file(file)))
    ws = wb.worksheets[0]
    values = [c.value for row in ws.iter_rows() for c in row]
    assert file.name in values
    assert file.sentence in values
    numbers = [v for v in values if isinstance(v, (int, float))]
    assert numbers, "the sheet should carry a numeric table"


@pytest.mark.parametrize("file", BY_TYPE["txt"], ids=_ids(BY_TYPE["txt"]))
def test_txt_is_ascii_lf_and_contains_sentence(file):
    data = generate_file(file)
    text = data.decode("ascii")
    assert "\r" not in text
    assert text.endswith("\n")
    lines = text.splitlines()
    assert lines[0] == file.name
    assert lines[1] == file.sentence


@pytest.mark.parametrize("file", BY_TYPE["png"], ids=_ids(BY_TYPE["png"]))
def test_png_opens(file):
    from PIL import Image

    with Image.open(io.BytesIO(generate_file(file))) as img:
        img.load()
        assert img.size == (64, 64)
        assert img.mode == "RGB"


def test_pngs_differ_in_pixels():
    from PIL import Image

    pixels = set()
    for file in BY_TYPE["png"]:
        with Image.open(io.BytesIO(generate_file(file))) as img:
            pixels.add(img.tobytes())
    assert len(pixels) == len(BY_TYPE["png"])


# ---- the `generate` command ----


def test_run_generate_prints_one_line_per_file(tmp_path):
    lines: list[str] = []
    assert run_generate(tmp_path, out=lines.append) == 0
    assert len(lines) == 20
    for line, file in zip(lines, FILES):
        data = (tmp_path / file.name).read_bytes()
        assert file.name in line
        assert str(len(data)) in line
        assert hashlib.sha256(data).hexdigest() in line
