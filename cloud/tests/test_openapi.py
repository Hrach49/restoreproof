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
# The routes that take the Worker's bearer token (C5.11; W7.3 added the revoke).
SECURED = {("/v1/jobs", "get"), ("/v1/results", "post"), ("/v1/heartbeat", "post"), ("/v1/workers/self/revoke", "post")}


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


def test_the_document_holds_the_six_routes_and_not_healthz():
    document = json.loads(DOCUMENT.read_bytes().decode("utf-8"))

    assert set(document["paths"]) == {
        "/v1/workers/register", "/v1/jobs", "/v1/results", "/v1/heartbeat", "/v1/version", "/v1/workers/self/revoke",
    }
    assert "/healthz" not in document["paths"]
    register = document["paths"]["/v1/workers/register"]["post"]
    # The review's finding 3: every refusal the routes make is in the contract.
    # C5.11: the 413 of the body cap on the two routes that take a body.
    assert set(register["responses"]) == {"201", "400", "401", "409", "413", "422"}
    jobs = document["paths"]["/v1/jobs"]["get"]
    assert set(jobs["responses"]) == {"200", "401"}
    error = {"$ref": "#/components/schemas/ErrorBody"}
    for status in ("400", "401", "409"):
        assert register["responses"][status]["content"]["application/json"]["schema"] == error
    assert jobs["responses"]["401"]["content"]["application/json"]["schema"] == error
    assert jobs["responses"]["401"]["headers"]["WWW-Authenticate"]
    assert document["components"]["schemas"]["ErrorBody"]["required"] == ["detail"]
    body = document["components"]["schemas"]["RegisterBody"]
    assert body["additionalProperties"] is False
    assert sorted(body["required"]) == ["install_token", "public_key_pem", "version", "worker_name"]
    assert document["components"]["schemas"]["Registered"]["additionalProperties"] is False
    # C5.7: the upload, every refusal as ErrorBody, the multipart body by hand
    # (the route reads the form itself and declares no body model, so FastAPI
    # adds no 422).
    upload = document["paths"]["/v1/results"]["post"]
    assert set(upload["responses"]) == {"202", "400", "401", "404", "409", "411", "413", "415"}
    for status in ("400", "401", "404", "409", "411", "413", "415"):
        assert upload["responses"][status]["content"]["application/json"]["schema"] == error
    assert upload["responses"]["401"]["headers"]["WWW-Authenticate"]
    assert upload["responses"]["202"]["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/Accepted"}
    accepted = document["components"]["schemas"]["Accepted"]
    assert accepted["additionalProperties"] is False and sorted(accepted["required"]) == ["run_id", "state"]
    assert accepted["properties"]["state"]["enum"] == ["pass", "fail", "error"]
    parts = upload["requestBody"]["content"]["multipart/form-data"]["schema"]
    assert upload["requestBody"]["required"] is True
    assert parts["required"] == ["result", "signature"] and parts["additionalProperties"] is False
    assert set(parts["properties"]) == {"result", "signature", "timestamp", "items.csv", "veeam-session.log", "screenshot.png"}
    assert all(p == {"type": "string", "format": "binary", "description": p["description"]} for p in parts["properties"].values())
    # C5.8: the heartbeat, 204 without content, the 401 as ErrorBody, FastAPI's
    # 422 for the closed body of the Worker's five keys.
    beat = document["paths"]["/v1/heartbeat"]["post"]
    assert set(beat["responses"]) == {"204", "401", "413", "422"}
    for route in (register, beat):
        assert route["responses"]["413"]["content"]["application/json"]["schema"] == error
    assert "content" not in beat["responses"]["204"]
    assert beat["responses"]["401"]["content"]["application/json"]["schema"] == error
    assert beat["responses"]["401"]["headers"]["WWW-Authenticate"]
    assert beat["requestBody"]["required"] is True
    # The C5.8 review's finding 1: the route reads the body itself, after the
    # token, so the model's schema is written into the operation, not referred to.
    assert "HeartbeatBody" not in document["components"]["schemas"]
    assert beat["responses"]["422"]["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/HTTPValidationError"}
    body = beat["requestBody"]["content"]["application/json"]["schema"]
    assert body["title"] == "HeartbeatBody"
    assert body["additionalProperties"] is False
    assert sorted(body["required"]) == ["last_error", "last_error_at", "outbox_depth", "uptime_s", "version"]
    assert body["properties"]["version"]["pattern"] == "^[ -~]+$"
    assert {"type": "null"} in body["properties"]["last_error"]["anyOf"]
    assert {"type": "null"} in body["properties"]["last_error_at"]["anyOf"]
    for name in ("outbox_depth", "uptime_s"):
        assert (body["properties"][name]["type"], body["properties"][name]["minimum"], body["properties"][name]["maximum"]) == ("integer", 0, 2**53 - 1)
    # W7.3: the Worker's own revoke, 204 without content, no body, the 401 and
    # the cap's 413 as ErrorBody.
    revoke = document["paths"]["/v1/workers/self/revoke"]
    assert list(revoke) == ["post"]
    assert set(revoke["post"]["responses"]) == {"204", "401", "413"}
    assert "content" not in revoke["post"]["responses"]["204"]
    assert "requestBody" not in revoke["post"]
    for status in ("401", "413"):
        assert revoke["post"]["responses"][status]["content"]["application/json"]["schema"] == error
    assert revoke["post"]["responses"]["401"]["headers"]["WWW-Authenticate"]


# --- C5.11 (docs/decisions.md 2026-10-12, points 2 and 3) ------------------------------------


def test_the_version_route_is_in_the_document_with_its_200_alone():
    document = json.loads(DOCUMENT.read_bytes().decode("utf-8"))

    version = document["paths"]["/v1/version"]
    assert list(version) == ["get"]
    assert set(version["get"]["responses"]) == {"200"}
    assert "security" not in version["get"]
    assert version["get"]["responses"]["200"]["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/VersionBody"}
    body = document["components"]["schemas"]["VersionBody"]
    assert body["additionalProperties"] is False
    assert sorted(body["required"]) == ["api", "version"]
    assert body["properties"]["api"] == {"const": 1, "title": "Api", "type": "integer"}


def test_the_bearer_scheme_is_on_the_four_routes_that_take_the_token():
    document = json.loads(DOCUMENT.read_bytes().decode("utf-8"))

    scheme = document["components"]["securitySchemes"]
    assert list(scheme) == ["workerToken"]
    assert scheme["workerToken"]["type"] == "http" and scheme["workerToken"]["scheme"] == "bearer"
    assert "register" in scheme["workerToken"]["description"]
    secured = {
        (path, method) for path, operations in document["paths"].items() for method, operation in operations.items() if "security" in operation
    }
    assert secured == SECURED
    for path, method in secured:
        assert document["paths"][path][method]["security"] == [{"workerToken": []}]
    # Registration takes the install token in its body, never as a bearer.
    assert "security" not in document["paths"]["/v1/workers/register"]["post"]


def test_the_secured_operations_are_the_routes_that_depend_on_current_worker():
    """The document follows the code: a route that depends on `current_worker`
    is documented as taking the token, and one that doesn't isn't."""
    from fastapi.routing import APIRoute

    from app.auth.dependency import current_worker

    from app.main import API_PREFIX, ROUTERS

    application = create_app(make_settings(), log_stream=io.StringIO())

    def depends_on_current_worker(dependant) -> bool:
        return dependant.call is current_worker or any(depends_on_current_worker(d) for d in dependant.dependencies)

    # FastAPI keeps an included router as one entry of `app.routes`; the
    # routes are the routers' own, served under the prefix.
    by_code = {
        (API_PREFIX + route.path, method.lower())
        for _name, router in ROUTERS
        for route in router.routes
        if isinstance(route, APIRoute) and depends_on_current_worker(route.dependant)
        for method in route.methods
    }
    document = application.openapi()
    by_document = {
        (path, method) for path, operations in document["paths"].items() for method, operation in operations.items() if "security" in operation
    }

    assert by_code == by_document == SECURED


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
