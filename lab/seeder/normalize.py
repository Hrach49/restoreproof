"""Mail body normalisation "text-v1".

The C++ checker (W3.2) re-implements this; shared/testdata/body-normalization-text-v1.json
holds the vectors both must agree on. Any change here needs a new NORMALIZATION_ID.
"""

import hashlib

NORMALIZATION_ID = "text-v1"

_BOM = "﻿"


def normalize_body(text: str) -> str:
    """Normalise a Graph `body.content` read with `Prefer: outlook.body-content-type="text"`.

    Drops one leading BOM, turns CRLF and lone CR into LF, strips trailing spaces and tabs
    (only those two) from every line, and removes trailing LFs. Nothing else: no leading
    trim, no Unicode normalisation, no NBSP handling.
    """
    if text.startswith(_BOM):
        text = text[1:]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in text.split("\n")]
    return "\n".join(lines).rstrip("\n")


def body_sha256(text: str) -> str:
    """Lower-case hex SHA-256 of the normalised body, encoded as UTF-8 without a BOM."""
    return hashlib.sha256(normalize_body(text).encode("utf-8")).hexdigest()
