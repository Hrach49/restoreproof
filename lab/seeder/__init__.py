"""Seed and check the canary set (L1.2). Run from lab/: `uv run python -m seeder --help`."""

from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
CANARY_DIR = LAB_DIR / "canary"
MANIFEST_PATH = LAB_DIR / "seed-manifest.json"
REPO_DIR = LAB_DIR.parent
MANIFEST_SCHEMA_PATH = REPO_DIR / "shared" / "schemas" / "seed-manifest.v1.json"
