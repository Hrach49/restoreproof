"""The PDF (C6.4; docs/decisions.md 2026-10-12, "C6.4", points 6 and 7): one
template under `app/ui.py`'s rules (autoescape, `StrictUndefined`, the pages'
filters), rendered twice. Pass 1 prints `PLACEHOLDER` where the content hash
goes and its SHA-256 is the content hash; pass 2 prints that hash and its
SHA-256 is the file hash. WeasyPrint's defaults embed no date and no
identifier, so the same HTML is the same bytes by one WeasyPrint (the entry's
probe), and the hash cell is the one difference between the passes. The file
does name its producer, `WeasyPrint <version>`, and a font is subset as that
version does it, so the bytes and both hashes are one version's: the one
`uv.lock` pins (the C6.4 review's finding 14; a stored report is never
rendered again, so an upgrade changes no stored hash). WeasyPrint is
imported where it is called, so nothing else of the app needs its libraries
until a report is rendered.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment

from app import ui
from app.report.data import ReportData

REPORT_DIR = Path(__file__).resolve().parent
TEMPLATE = "template.html"
STYLESHEET = "report.css"
PLACEHOLDER = "computed after this report was rendered; see the note below"
# The time fontTools writes into a subset font when it has no HarfBuzz-Subset: 1970-01-01T00:00:00Z.
SOURCE_DATE_EPOCH = "SOURCE_DATE_EPOCH"
FONT_EPOCH = "0"


@lru_cache(maxsize=1)
def environment() -> Environment:
    return ui.make_environment(REPORT_DIR)


def render_html(data: ReportData, content_hash: str | None) -> str:
    """The report as HTML: pass 1 with `content_hash` None (the placeholder),
    pass 2 with the hash."""
    return environment().get_template(TEMPLATE).render(data=data, content_hash=PLACEHOLDER if content_hash is None else content_hash)


def render_pdf(html: str) -> bytes:
    """The one WeasyPrint call: A4 under `report.css`, the library's defaults
    otherwise (no `pdf_identifier`; the title and the library's own
    `/Producer` are the Info dictionary). CPU work of seconds: a
    caller runs it in a thread.

    Without HarfBuzz-Subset (this laptop's GTK runtime has none; the image
    has it) WeasyPrint subsets the embedded fonts with fontTools, which
    writes the current time into each font's `head` table, so two renders of
    one HTML differed by those bytes. fontTools takes that time from
    `SOURCE_DATE_EPOCH`, the reproducible-builds convention, so it is pinned
    here when nothing set it; HarfBuzz-Subset writes no time and ignores it.
    """
    from weasyprint import CSS, HTML

    os.environ.setdefault(SOURCE_DATE_EPOCH, FONT_EPOCH)
    return HTML(string=html, base_url=str(REPORT_DIR)).write_pdf(stylesheets=[CSS(filename=str(REPORT_DIR / STYLESHEET))])


@dataclass(frozen=True)
class Rendered:
    html_1: str
    content_sha256: str
    html_2: str
    pdf: bytes
    file_sha256: str


def render_report(data: ReportData) -> Rendered:
    """The two passes."""
    html_1 = render_html(data, None)
    content_sha256 = hashlib.sha256(render_pdf(html_1)).hexdigest()
    html_2 = render_html(data, content_sha256)
    pdf = render_pdf(html_2)
    return Rendered(html_1, content_sha256, html_2, pdf, hashlib.sha256(pdf).hexdigest())
