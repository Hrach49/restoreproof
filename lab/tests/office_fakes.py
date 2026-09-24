"""Small Office packages and a fake of what SharePoint does to them (tests only)."""

import io
import zipfile

CONTENT_PART = {"docx": "word/document.xml", "xlsx": "xl/workbook.xml"}


def _put(z: zipfile.ZipFile, name: str, data: bytes) -> None:
    # A fixed date: writestr(name, ...) stamps the current time, and these bytes must be
    # the same every time a test builds them.
    z.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), data, compress_type=z.compression)


def office_zip(file_type: str, text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        _put(z, "[Content_Types].xml", b"<Types/>")
        _put(z, "docProps/core.xml", b"<core/>")
        _put(z, CONTENT_PART[file_type], text.encode("utf-8"))
    return buf.getvalue()


def sharepoint_rewrite(data: bytes, round_: int = 1) -> bytes:
    """Like SharePoint: same content parts, new metadata parts and changed package parts."""
    src = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for info in src.infolist():
            name = info.filename
            if name.startswith(("customXml/", "[trash]/")) or name == "docProps/custom.xml":
                continue  # written again below
            part = src.read(info)
            if name == "[Content_Types].xml":
                part += b"<!-- customXml overrides -->"
            _put(z, info.filename, part)
        for n in range(1, round_ + 1):
            _put(z, f"customXml/item{n}.xml", b"<contentTypeSchema/>")
            _put(z, f"[trash]/{n:04d}.dat", b"old part")
        _put(z, "docProps/custom.xml", b"<ContentTypeId/>")
    return buf.getvalue()


def change_content(data: bytes, file_type: str) -> bytes:
    """The same package with the document content itself edited."""
    src = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for info in src.infolist():
            part = src.read(info)
            if info.filename == CONTENT_PART[file_type]:
                part += b"<edited/>"
            _put(z, info.filename, part)
    return buf.getvalue()
