"""The monthly PDF report of a client (C6.4; docs/decisions.md 2026-10-12,
"C6.4"): `data.py` reads a month and decides what it says, `render.py` makes
the PDF in two passes (the content hash, then the file), `frameworks.py` names
the controls, `generate.py` files the row and the object. Guarded at 100% line
and branch (tools/check_coverage.py)."""
