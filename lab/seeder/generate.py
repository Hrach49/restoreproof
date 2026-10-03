"""Generate the 20 canary files in lab/canary/.

Standard library only and no zlib compression anywhere, so the bytes are identical on every
run, platform and Python version: ZIP entries are stored, PNG pixel data sits in stored
deflate blocks, and every timestamp or platform-derived field is fixed. The committed
files are the expected set; changing a byte here needs a new seed run and manifest.
"""

import hashlib
import io
import struct
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from xml.sax.saxutils import escape

from seeder.catalog import CanaryFile, canary_files

AUTHOR = "RestoreProof lab"
PRODUCER = "RestoreProof lab seeder"
TXT_FOOTER = "RestoreProof canary file. Do not edit, move or delete it."
OOXML_DATE = "2026-01-01T00:00:00Z"
PDF_DATE = "D:20260101000000Z"
ZIP_DATE = (1980, 1, 1, 0, 0, 0)
ZIP_CREATE_SYSTEM = 3  # Unix
ZIP_EXTERNAL_ATTR = 0o100644 << 16  # regular file, rw-r--r--
PNG_SIZE = 64

XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


# ---- txt ----


def _txt(file: CanaryFile) -> bytes:
    return f"{file.name}\n{file.sentence}\n{TXT_FOOTER}\n".encode("ascii")


# ---- pdf ----


def _pdf_string(text: str) -> str:
    return "(" + text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


def _pdf(file: CanaryFile) -> bytes:
    content = (
        f"BT /F1 16 Tf 72 770 Td {_pdf_string(file.name)} Tj ET\n"
        f"BT /F1 10 Tf 72 740 Td {_pdf_string(file.sentence)} Tj ET\n"
    ).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"endstream",
        (
            f"<< /Title {_pdf_string(file.name)} /Producer {_pdf_string(PRODUCER)} "
            f"/CreationDate ({PDF_DATE}) /ModDate ({PDF_DATE}) >>"
        ).encode("ascii"),
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\n" % (len(objects) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


# ---- OOXML (docx, xlsx) ----


def _zip(parts: list[tuple[str, str]]) -> bytes:
    """A ZIP with stored entries whose every header field is fixed."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, text in parts:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = ZIP_CREATE_SYSTEM
            info.create_version = 20
            info.extract_version = 20
            # Must be non-zero: zipfile replaces 0 with its own default when writing.
            info.external_attr = ZIP_EXTERNAL_ATTR
            info.flag_bits = 0
            z.writestr(info, text.encode("utf-8"))
    return buf.getvalue()


def _content_types(overrides: list[tuple[str, str]]) -> str:
    items = "".join(f'<Override PartName="{p}" ContentType="{t}"/>' for p, t in overrides)
    return (
        XML_DECL
        + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + items
        + "</Types>"
    )


def _root_rels(main_part: str) -> str:
    return (
        XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        f'Target="{main_part}"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
        'Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" '
        'Target="docProps/app.xml"/>'
        "</Relationships>"
    )


def _core(title: str) -> str:
    return (
        XML_DECL
        + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{escape(title)}</dc:title>"
        f"<dc:creator>{AUTHOR}</dc:creator>"
        f"<cp:lastModifiedBy>{AUTHOR}</cp:lastModifiedBy>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{OOXML_DATE}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{OOXML_DATE}</dcterms:modified>'
        "</cp:coreProperties>"
    )


def _app() -> str:
    return (
        XML_DECL
        + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        f"<Application>{PRODUCER}</Application>"
        "</Properties>"
    )


CT_CORE = ("/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml")
CT_APP = ("/docProps/app.xml", "application/vnd.openxmlformats-officedocument.extended-properties+xml")


def _docx(file: CanaryFile) -> bytes:
    def para(text: str, bold: bool = False) -> str:
        props = "<w:rPr><w:b/></w:rPr>" if bold else ""
        return f'<w:p><w:r>{props}<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'

    document = (
        XML_DECL
        + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
        + para(file.name, bold=True)
        + para(file.sentence)
        + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
        'w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>'
        "</w:body></w:document>"
    )
    return _zip(
        [
            (
                "[Content_Types].xml",
                _content_types(
                    [
                        (
                            "/word/document.xml",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                        ),
                        CT_CORE,
                        CT_APP,
                    ]
                ),
            ),
            ("_rels/.rels", _root_rels("word/document.xml")),
            ("word/document.xml", document),
            ("docProps/core.xml", _core(file.name)),
            ("docProps/app.xml", _app()),
        ]
    )


def _xlsx(file: CanaryFile, sheet_name: str = "Canary") -> bytes:
    """`sheet_name` lets seed-real's files (L1.8) not call themselves canaries; the canary
    files keep "Canary", so their bytes and hashes stay the same."""
    def text_cell(ref: str, text: str) -> str:
        return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape(text)}</t></is></c>'

    def num_cell(ref: str, value: int) -> str:
        return f'<c r="{ref}"><v>{value}</v></c>'

    n = file.number
    rows = [
        [text_cell("A1", file.name)],
        [text_cell("A2", file.sentence)],
        [text_cell("A4", "row"), text_cell("B4", "value"), text_cell("C4", "square")],
    ]
    row_numbers = [1, 2, 4]
    for i in range(1, 6):
        r = 4 + i
        value = n * 100 + i
        rows.append([num_cell(f"A{r}", i), num_cell(f"B{r}", value), num_cell(f"C{r}", value * value)])
        row_numbers.append(r)
    sheet_data = "".join(f'<row r="{r}">{"".join(cells)}</row>' for r, cells in zip(row_numbers, rows))
    sheet = (
        XML_DECL
        + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<dimension ref="A1:C9"/>'
        f"<sheetData>{sheet_data}</sheetData>"
        "</worksheet>"
    )
    sheet_attr = escape(sheet_name, {'"': "&quot;"})
    workbook = (
        XML_DECL
        + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{sheet_attr}" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    workbook_rels = (
        XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        "</Relationships>"
    )
    styles = (
        XML_DECL
        + '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="1"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts>'
        '<fills count="2"><fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        "</styleSheet>"
    )
    main = "application/vnd.openxmlformats-officedocument.spreadsheetml"
    return _zip(
        [
            (
                "[Content_Types].xml",
                _content_types(
                    [
                        ("/xl/workbook.xml", f"{main}.sheet.main+xml"),
                        ("/xl/worksheets/sheet1.xml", f"{main}.worksheet+xml"),
                        ("/xl/styles.xml", f"{main}.styles+xml"),
                        CT_CORE,
                        CT_APP,
                    ]
                ),
            ),
            ("_rels/.rels", _root_rels("xl/workbook.xml")),
            ("xl/workbook.xml", workbook),
            ("xl/_rels/workbook.xml.rels", workbook_rels),
            ("xl/worksheets/sheet1.xml", sheet),
            ("xl/styles.xml", styles),
            ("docProps/core.xml", _core(file.name)),
            ("docProps/app.xml", _app()),
        ]
    )


# ---- png ----


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def _stored_zlib(raw: bytes) -> bytes:
    """zlib stream of stored (uncompressed) deflate blocks: no dependence on zlib's compressor."""
    out = bytearray(b"\x78\x01")
    blocks = [raw[i : i + 0xFFFF] for i in range(0, len(raw), 0xFFFF)] or [b""]
    for index, block in enumerate(blocks):
        final = 1 if index == len(blocks) - 1 else 0
        out += bytes([final]) + struct.pack("<HH", len(block), len(block) ^ 0xFFFF) + block
    out += struct.pack(">I", zlib.adler32(raw))
    return bytes(out)


def _png(file: CanaryFile) -> bytes:
    n = file.number
    raw = bytearray()
    for y in range(PNG_SIZE):
        raw.append(0)  # filter type None
        for x in range(PNG_SIZE):
            raw += bytes(((x * 4 + n * 13) & 255, (y * 4 + n * 29) & 255, (((x ^ y) * 4) + n * 47) & 255))
    ihdr = struct.pack(">IIBBBBB", PNG_SIZE, PNG_SIZE, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", _stored_zlib(bytes(raw)))
        + _png_chunk(b"IEND", b"")
    )


GENERATORS: dict[str, Callable[[CanaryFile], bytes]] = {
    "pdf": _pdf,
    "docx": _docx,
    "xlsx": _xlsx,
    "txt": _txt,
    "png": _png,
}


def generate_file(file: CanaryFile) -> bytes:
    return GENERATORS[file.file_type](file)


def generate_all(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for file in canary_files():
        path = out_dir / file.name
        path.write_bytes(generate_file(file))
        paths.append(path)
    return paths


def run_generate(out_dir: Path, out: Callable[[str], object] = print) -> int:
    """The `generate` command: write the files and print name, size and SHA-256 of each."""
    for path in generate_all(out_dir):
        data = path.read_bytes()
        out(f"{path.name}  {len(data):>6} bytes  sha256 {hashlib.sha256(data).hexdigest()}")
    return 0
