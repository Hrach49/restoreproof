"""Write the Cloud's OpenAPI document as docs/api/openapi-v1.json holds it
(C5.6; docs/decisions.md 2026-10-10, "C5.5 and C5.6", point 7).

Usage (from cloud/):
    uv run python tools/dump_openapi.py [path]

The default path is <repo>/docs/api/openapi-v1.json. tests/test_openapi.py
holds that file equal to what the app serves at /v1/openapi.json, so a route
change without a run of this tool fails the test step. The app is made with
placeholder settings of closed loopback ports (what the tests use); nothing
in app/settings.py gains a default by it, and nothing is connected to.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CLOUD_DIR = Path(__file__).resolve().parent.parent
DEFAULT_PATH = CLOUD_DIR.parent / "docs" / "api" / "openapi-v1.json"

# Every address a closed loopback port, every secret a visible placeholder.
PLACEHOLDER_ENVIRONMENT = {
    "DATABASE_URL": "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none",
    "S3_ENDPOINT": "http://127.0.0.1:1",
    "S3_ACCESS_KEY": "placeholder-access-key",
    "S3_SECRET_KEY": "placeholder-secret-key",
    "S3_BUCKET": "placeholder-bucket",
    "SECRET_KEY": "placeholder-secret-key-" + "0" * 32,
}


def openapi_text() -> str:
    """The document as the file holds it: sorted keys, two-space indentation, LF, a final newline."""
    sys.path.insert(0, str(CLOUD_DIR))
    from app.main import create_app  # noqa: PLC0415 - after the path is set
    from app.settings import load_settings  # noqa: PLC0415

    document = create_app(load_settings(PLACEHOLDER_ENVIRONMENT)).openapi()
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_PATH
    path.write_bytes(openapi_text().encode("utf-8"))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
