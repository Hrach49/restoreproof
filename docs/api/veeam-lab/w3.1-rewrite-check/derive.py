"""Copy the real samples into files/ and derive the add-in and Visio variants by changing
only the main part's content type in [Content_Types].xml.

The other files were made first with LibreOffice 26.2 headless (`soffice --headless
--convert-to <ext>:<filter> --outdir files <source>`): doc, rtf, odt, docx, docm and pdf from
a small HTML page; xls, ods, xlsx and xlsm from a three-row CSV; ppt, odp, pptx and pptm
from LibreOffice's Blue_Curve.otp. LibreOffice can't write xlsb, so pkgs/issues.xlsb is
calamine's Excel-made test workbook (github.com/tafia/calamine, tests/issues.xlsb), and the
vsdx is the Visio-made template the `vsdx` PyPI package ships (vsdx/media/media.vsdx)."""
import re
import shutil
import zipfile
from pathlib import Path

here = Path(__file__).parent
files = here / "files"
shutil.copy(here / "pkgs" / "issues.xlsb", files / "rp-rw-sheet.xlsb")
with zipfile.ZipFile(next(here.glob("pkgs/whl/vsdx-*.whl"))) as w:
    (files / "rp-rw-drawing.vsdx").write_bytes(w.read("vsdx/media/media.vsdx"))


def derive(src: Path, dst: Path, old: str, new: str) -> None:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            data = zin.read(info)
            if info.filename == "[Content_Types].xml":
                text = data.decode("utf-8")
                assert old in text, (src, old)
                data = text.replace(old, new).encode("utf-8")
            zout.writestr(info, data)


derive(files / "rp-rw-sheet.xlsm", files / "rp-rw-sheet.xlam",
       "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
       "application/vnd.ms-excel.addin.macroEnabled.main+xml")
derive(files / "rp-rw-deck.pptm", files / "rp-rw-deck.ppam",
       "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
       "application/vnd.ms-powerpoint.addin.macroEnabled.main+xml")
vsdx = files / "rp-rw-drawing.vsdx"
for ext, kind in [("vsdm", "drawing.macroEnabled"), ("vssx", "stencil"), ("vstx", "template")]:
    derive(vsdx, files / f"rp-rw-drawing.{ext}", "application/vnd.ms-visio.drawing.main+xml",
           f"application/vnd.ms-visio.{kind}.main+xml")
# Controls: a canary docx the lab has seen rewritten, and a plain text file.
shutil.copy(Path(r"C:\restoreproof\lab\canary\rp-canary-02.docx"), files / "rp-rw-canary.docx")
(files / "rp-rw-plain.txt").write_bytes(b"RestoreProof rewrite check, 2026-10-01.\n")
for p in sorted(files.iterdir()):
    print(f"{p.name:24} {p.stat().st_size}")
