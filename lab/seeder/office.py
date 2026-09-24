"""Content hash rule "office-v1" for docx and xlsx.

SharePoint rewrites Office files in a document library: it adds the library's content-type
metadata (customXml/, docProps/custom.xml), edits the relationship files and
[Content_Types].xml, and leaves [trash]/ parts from its own rewrites. It does so again some
time after the upload, without changing lastModifiedDateTime. The document content itself
(word/document.xml, xl/worksheets/*.xml, ...) is left byte for byte. So Office files are
compared on those parts only:

1. Open the file as a ZIP package.
2. Take every part whose name starts with the type's content folder ("word/" for docx,
   "xl/" for xlsx), except parts inside a "_rels/" folder.
3. Sort the part names by their UTF-8 bytes.
4. For each part write one line: lower-case hex SHA-256 of the uncompressed part bytes,
   two spaces, the part name, LF.
5. content_sha256 = lower-case hex SHA-256 of those lines (UTF-8).

Metadata (docProps/), package relationships and content types do not count. The C++
checker (W3.2) must implement the same rule; shared/testdata/office-content-v1/ holds
vectors, including real files SharePoint rewrote.
"""

import hashlib
import io
import zipfile

OFFICE_RULE = "office-v1"
CONTENT_FOLDERS = {"docx": "word/", "xlsx": "xl/"}


class OfficeContentError(ValueError):
    """The file can't be hashed by office-v1."""


def _content_parts(data: bytes, file_type: str) -> list[tuple[str, bytes]]:
    folder = CONTENT_FOLDERS.get(file_type)
    if folder is None:
        raise OfficeContentError(f"office-v1 has no rule for .{file_type} files")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise OfficeContentError(f"not a ZIP package, so not a valid .{file_type} file") from None
    names = [i.filename for i in z.infolist()]
    doubled = sorted({n for n in names if names.count(n) > 1})
    if doubled:
        raise OfficeContentError(f"part(s) stored more than once: {', '.join(doubled)}")
    chosen = sorted(
        (n for n in names if n.startswith(folder) and "_rels/" not in n and not n.endswith("/")),
        key=lambda n: n.encode("utf-8"),
    )
    if not chosen:
        raise OfficeContentError(f"no {folder} parts in this .{file_type} file")
    return [(n, z.read(n)) for n in chosen]


def content_listing(data: bytes, file_type: str) -> str:
    """The lines office-v1 hashes; useful to see which part differs."""
    return "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in _content_parts(data, file_type))


def office_content_sha256(data: bytes, file_type: str) -> str:
    return hashlib.sha256(content_listing(data, file_type).encode("utf-8")).hexdigest()
