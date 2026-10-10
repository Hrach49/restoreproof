"""The shared schemas, read by path (C5.3; docs/decisions.md 2026-10-10, "C5.3
and C5.4", point 7).

`shared/schemas/` holds the only copies. The folder is found by walking up from
this file: `<repo>/shared/schemas` in the tree, `/srv/shared/schemas` in the
image, which the Dockerfile copies beside `app/`.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


def shared_schemas_dir(start: Path | None = None) -> Path:
    """The first `shared/schemas` above `start` (this file by default)."""
    here = (Path(__file__) if start is None else start).resolve()
    for folder in here.parents:
        candidate = folder / "shared" / "schemas"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("no shared/schemas folder above the app")


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    """One schema by its file name, read once."""
    path = shared_schemas_dir() / name
    if not path.is_file():
        raise FileNotFoundError(f"no such schema: {name}")
    return json.loads(path.read_bytes().decode("utf-8"))
