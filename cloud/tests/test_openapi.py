"""The committed OpenAPI document (C5.6; docs/decisions.md 2026-10-10, "C5.5
and C5.6", point 7): docs/api/openapi-v1.json is what the app serves at
/v1/openapi.json, byte for byte as tools/dump_openapi.py writes it, so a route
change without the regenerated file fails here. C5.11 adds the CI job's own
wording and the security scheme.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import httpx

from app.main import create_app
from tests.conftest import CLOUD_DIR, make_settings

DOCUMENT = CLOUD_DIR.parent / "docs" / "api" / "openapi-v1.json"
TOOL = CLOUD_DIR / "tools" / "dump_openapi.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("dump_openapi", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def served_document() -> dict:
    application = create_app(make_settings(), log_stream=io.StringIO())
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
        response = await client.get("/v1/openapi.json")
    assert response.status_code == 200
    return response.json()


async def test_the_committed_document_is_what_the_app_serves():
    assert DOCUMENT.is_file(), "run `uv run python tools/dump_openapi.py` from cloud/"
    committed = DOCUMENT.read_bytes()

    assert committed == load_tool().openapi_text().encode("utf-8"), (
        "docs/api/openapi-v1.json is stale: run `uv run python tools/dump_openapi.py` from cloud/"
    )
    assert json.loads(committed.decode("utf-8")) == await served_document()


def test_the_document_is_sorted_two_space_lf_with_a_final_newline():
    raw = DOCUMENT.read_bytes()

    assert b"\r" not in raw
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    document = json.loads(raw.decode("utf-8"))
    assert raw == (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def test_the_document_holds_the_two_routes_and_not_healthz():
    document = json.loads(DOCUMENT.read_bytes().decode("utf-8"))

    assert set(document["paths"]) == {"/v1/workers/register", "/v1/jobs"}
    assert "/healthz" not in document["paths"]
    register = document["paths"]["/v1/workers/register"]["post"]
    assert set(register["responses"]) == {"201", "422"}
    assert document["paths"]["/v1/jobs"]["get"]["responses"]["200"]
    body = document["components"]["schemas"]["RegisterBody"]
    assert body["additionalProperties"] is False
    assert sorted(body["required"]) == ["install_token", "public_key_pem", "version", "worker_name"]
    assert document["components"]["schemas"]["Registered"]["additionalProperties"] is False


def test_the_tool_writes_the_same_bytes_to_a_path_of_the_caller_s(tmp_path):
    target = tmp_path / "openapi.json"

    result = subprocess.run(
        [sys.executable, str(TOOL), str(target)], cwd=CLOUD_DIR, capture_output=True, text=True, timeout=120
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"wrote {target}"
    assert target.read_bytes() == DOCUMENT.read_bytes()


def test_the_tool_s_placeholders_are_closed_loopback_ports_and_visible_placeholders():
    env = load_tool().PLACEHOLDER_ENVIRONMENT

    assert "127.0.0.1:1" in env["DATABASE_URL"] and env["S3_ENDPOINT"] == "http://127.0.0.1:1"
    assert all("placeholder" in env[name] for name in ("S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_BUCKET", "SECRET_KEY"))
    assert Path(load_tool().DEFAULT_PATH) == DOCUMENT
