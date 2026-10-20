"""W5.1 (#66): the Cloud's real answers, recorded once from the local stack
through its HTTPS front, as the Worker's test fixtures
(docs/decisions.md 2026-10-15, "W5.1 (#66)", point 10).

Run by hand, from the repository root, with the stack up (`docker compose up
-d --wait --build` in cloud/) and Caddy's root copied out:

    uv run --project cloud python docs/api/cloud-lab/w5.1-record/record_cloud.py \
        --ca %LOCALAPPDATA%\\RestoreProof\\lab\\cloud-ca.pem

It RE-MIGRATES the stack's database (downgrade base, upgrade head), makes an
MSP, the shared vector's client (its tenant and its id), registers the
vector's test key (RFC 8032 test key 1, never a secret), a connector holding
the vector's job's profile, a plan with the vector's sizes and its run with
the vector's id, then asks each route for each answer the Worker handles and
writes worker/tests/fixtures/cloud/<route>/<case>.json in the recorder's
format: the request line, the status, the kept headers spelled as the wire
had them, the body. Every token is replaced by SCRUBBED before anything is
written; no token is printed. The upload posts the vector's own bytes
without its timestamp part (the vector's token is the published test TSA's,
which the stack doesn't trust; a bundle without one is "not timestamped").
The 502 is Caddy's own, with the api stopped and started again. The
Worker's own revoke (W7.3) is asked last of what the token can do, and the
502s after it carry the token the Cloud no longer knows (they never reach
the app, so the answer is the same).
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[4]
CLOUD = ROOT / "cloud"
OUT = ROOT / "worker" / "tests" / "fixtures" / "cloud"
VECTOR = json.loads((ROOT / "shared" / "testdata" / "signing-v1" / "dispatched-run.json").read_text(encoding="utf-8"))
KEYS = {k["name"]: k for k in json.loads((ROOT / "shared" / "testdata" / "signing-v1" / "keys.json").read_text(encoding="utf-8"))["keys"]}
BASE = "https://localhost:8443"
SCRUBBED = "SCRUBBED"
# The recorder's kept headers (worker/src/recording_http_client.cpp).
KEPT = ("content-type", "retry-after", "www-authenticate", "x-restoreproof-api")
SOURCE = "docs/api/cloud-lab/w5.1-record/record_cloud.py against the Compose stack through Caddy"


def compose(*args: str, stdin: str | None = None) -> str:
    done = subprocess.run(
        ["docker", "compose", *args], cwd=CLOUD, input=stdin, capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        sys.exit(f"docker compose {args[0]} {args[1] if len(args) > 1 else ''} failed (exit {done.returncode})")
    return done.stdout


def manage(*args: str) -> dict[str, str]:
    out = compose("exec", "-T", "api", "python", "manage.py", *args)
    return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)


def sql(statement: str) -> str:
    return compose("exec", "-T", "postgres", "psql", "-U", "restoreproof", "-d", "restoreproof", "-tAc", statement).strip()


def scrub(value, tokens: set[str]):
    if isinstance(value, dict):
        return {k: (SCRUBBED if k.endswith("token") and isinstance(v, str) else scrub(v, tokens)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, tokens) for v in value]
    if isinstance(value, str) and value in tokens:
        return SCRUBBED
    return value


def write(route: str, case: str, request: str, response: httpx.Response, tokens: set[str]) -> None:
    headers = {name.decode(): value.decode() for name, value in response.headers.raw if name.decode().lower() in KEPT}
    text = response.text
    if not text:
        body = None
    else:
        try:
            body = scrub(json.loads(text), tokens)
        except ValueError:
            body = text
    for token in tokens:
        assert token not in json.dumps(body) and token not in json.dumps(headers), "a token reached a fixture"
    fixture = {"source": SOURCE, "request": request, "status": response.status_code, "headers": headers, "body": body}
    path = OUT / route / f"{case}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"{route}/{case}: {response.status_code}")


def vector_bytes(name: str) -> bytes:
    value = VECTOR["files"][name]
    return value.encode("utf-8") if isinstance(value, str) else base64.b64decode(value["base64"], validate=True)


def parts(*, tamper: bool = False) -> list:
    files = []
    for part in VECTOR["upload"]:
        if part["name"] == "timestamp":
            continue
        data = vector_bytes(part["filename"])
        if tamper and part["name"] == "result":
            data = data.replace(b'"pass"', b'"fail"', 1)
        files.append((part["name"], (part["filename"], data, part["content_type"])))
    return files


HEARTBEAT = {"last_error": None, "last_error_at": None, "outbox_depth": 0, "uptime_s": 60, "version": "0.0.0"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True, help="Caddy's root.crt, copied out of the proxy")
    ca = parser.parse_args().ca

    compose("exec", "-T", "api", "alembic", "downgrade", "base")
    compose("exec", "-T", "api", "alembic", "upgrade", "head")

    msp = manage("create-msp", "--name", "w51-record")["msp_id"]
    made = manage("create-client", "--msp-id", msp, "--name", "contoso", "--tenant-id", VECTOR["tenant_id"])["client_id"]
    client = VECTOR["client_id"]
    sql(f"UPDATE client SET id = '{client}' WHERE id = '{made}'")
    tokens: set[str] = set()

    def install_token() -> str:
        token = manage("create-worker-token", "--msp-id", msp, "--label", "w51-record")["install_token"]
        tokens.add(token)
        return token

    key = KEYS[VECTOR["key"]]
    first, second, unused = install_token(), install_token(), install_token()
    register = "POST /v1/workers/register"
    good = {"public_key_pem": key["public_key_pem"], "worker_name": "w51-record", "version": "0.0.0"}

    with httpx.Client(base_url=BASE, verify=ca, timeout=30) as http:
        write("register", "422-body", register, http.post("/v1/workers/register", json={"install_token": unused}), tokens)
        unknown = {**good, "install_token": "".join(["A"] * 43)}  # a token of the right shape that no row has
        write("register", "401", register, http.post("/v1/workers/register", json=unknown), tokens)
        bad_key = {**good, "install_token": unused, "public_key_pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"}
        write("register", "400", register, http.post("/v1/workers/register", json=bad_key), tokens)
        answer = http.post("/v1/workers/register", json={**good, "install_token": first})
        issued = answer.json()["api" + "_token"]
        tokens.add(issued)
        worker = answer.json()["worker_id"]
        write("register", "201", register, answer, tokens)
        write("register", "409", register, http.post("/v1/workers/register", json={**good, "install_token": second}), tokens)
        write("register", "401-used", register, http.post("/v1/workers/register", json={**good, "install_token": first}), tokens)

        profile = Path(CLOUD / "w51-profile.json")
        profile.write_text(json.dumps(VECTOR["job"]["client"]), encoding="utf-8")
        try:
            compose("cp", str(profile), "api:/tmp/w51-profile.json")
        finally:
            profile.unlink()
        connector = manage("create-connector", "--msp-id", msp, "--client-id", client, "--worker-id", worker,
                           "--profile-file", "/tmp/w51-profile.json")["connector_id"]
        job = VECTOR["job"]
        plan = manage("create-plan", "--msp-id", msp, "--client-id", client, "--connector-id", connector,
                      "--mail", str(job["sample_mail"]), "--sp", str(job["sample_sp"]), "--od", str(job["sample_od"]),
                      "--cron", "0 2 * * *", "--run-now")
        sql(f"UPDATE test_run SET id = '{VECTOR['run_id']}' WHERE id = '{plan['run_id']}'")

        bearer = {"Authorization": f"Bearer {issued}"}
        wrong_token = "B" * 43  # a token of the right shape that no Worker has
        wrong = {"Authorization": f"Bearer {wrong_token}"}
        results = "POST /v1/results"
        jobs = "GET /v1/jobs"
        write("results", "409-not-dispatched", results, http.post("/v1/results", headers=bearer, files=parts()), tokens)
        write("jobs", "200-one-job", jobs, http.get("/v1/jobs", headers=bearer), tokens)
        write("jobs", "200-none", jobs, http.get("/v1/jobs", headers=bearer), tokens)
        write("jobs", "401", jobs, http.get("/v1/jobs", headers=wrong), tokens)
        write("results", "401", results, http.post("/v1/results", headers=wrong, files=parts()), tokens)
        write("results", "400-signature", results, http.post("/v1/results", headers=bearer, files=parts(tamper=True)), tokens)
        write("results", "415", results, http.post("/v1/results", headers=bearer, json={}), tokens)
        write("results", "202", results, http.post("/v1/results", headers=bearer, files=parts()), tokens)
        write("results", "202-again", results, http.post("/v1/results", headers=bearer, files=parts()), tokens)

        canary = manage("create-plan", "--msp-id", msp, "--client-id", client, "--connector-id", connector,
                        "--mail", "0", "--sp", "1", "--od", "1", "--cron", "0 3 * * *", "--run-now", "--canaries")
        assert canary["canary_cursor"] == "0,0,0"
        write("jobs", "200-canary-cursor", jobs, http.get("/v1/jobs", headers=bearer), tokens)

        beat = "POST /v1/heartbeat"
        write("heartbeat", "204", beat, http.post("/v1/heartbeat", headers=bearer, json=HEARTBEAT), tokens)
        write("heartbeat", "401", beat, http.post("/v1/heartbeat", headers=wrong, json=HEARTBEAT), tokens)
        short = {k: v for k, v in HEARTBEAT.items() if k != "uptime_s"}
        write("heartbeat", "422", beat, http.post("/v1/heartbeat", headers=bearer, json=short), tokens)
        write("version", "200", "GET /v1/version", http.get("/v1/version"), tokens)

        # W7.3: the Worker's own revoke, last of what the registered token can
        # do: 204 once, then the same token is the 401 (the heartbeat's own).
        revoke = "POST /v1/workers/self/revoke"
        write("revoke", "401", revoke, http.post("/v1/workers/self/revoke", headers=wrong), tokens)
        write("revoke", "204", revoke, http.post("/v1/workers/self/revoke", headers=bearer), tokens)
        write("revoke", "401-revoked", revoke, http.post("/v1/workers/self/revoke", headers=bearer), tokens)

        compose("stop", "api")
        try:
            time.sleep(2)
            write("jobs", "502-proxy", jobs, http.get("/v1/jobs", headers=bearer), tokens)
            write("results", "502-proxy", results, http.post("/v1/results", headers=bearer, files=parts()), tokens)
        finally:
            compose("start", "api")


if __name__ == "__main__":
    main()
