"""The lab the C5.7 route tests share (tests/test_results.py,
tests/test_results_vectors.py): an MSP with a client of the shared bundle's
tenant and a Worker registered under RFC 8032's published test key 1, a
second Worker under test key 2, a second MSP; the app with `get_session`
overridden, the bucket on botocore's `Stubber`, the TSA root the vectors'
test root; and the bundle maker: the Worker-made run folder of
shared/testdata/signing-v1/bundle.json re-keyed to a run the Cloud dispatched
and re-signed with the same published key (docs/decisions.md 2026-10-10,
C5.7, point 17). The keys are published test keys, not secrets.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import uuid
from collections import Counter
from collections.abc import Callable
from typing import Any

import httpx
from botocore.stub import Stubber
from cryptography.hazmat.primitives import serialization
from sqlalchemy import text

from app.auth.tokens import new_token, token_hash
from app.db import get_session
from app.main import create_app
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.items import ItemRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.workers import WorkerRepo
from app.storage import Storage, make_s3_client
from tests.conftest import make_settings, session_override
from tests.test_repo_connectors import profile_for
from tests.test_verify_bundle import BUNDLE, KEYS, vb
from tests.tsa_lab import ROOT_PEM, make_token

UTC = dt.timezone.utc
PATH = "/v1/results"
NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
# The bundle's own client: its tenant, which the client row must carry.
BUNDLE_RESULT = json.loads(BUNDLE["files"]["result.json"])
TENANT_ID = uuid.UUID(BUNDLE_RESULT["client"]["tenant_id"])
ATTACHMENTS = {name: BUNDLE["files"][name].encode("utf-8") for name in ("items.csv", "veeam-session.log")}
FILE_NAMES = {"result": "result.json", "signature": "signature.json", "timestamp": "timestamp.tst"}
CONTENT_TYPES = {"result": "application/json", "signature": "application/json"}
Parts = dict[str, bytes]


def private_key(name: str = "rfc8032-test-1"):
    return serialization.load_der_private_key(base64.b64decode(KEYS[name]["private_pkcs8_base64"]), password=None)


def sign(document: dict[str, Any], key: str = "rfc8032-test-1") -> tuple[bytes, bytes]:
    """The result's canonical bytes and a signature.json of the Worker's five
    keys over their SHA-256, under the published key `key`."""
    result = vb.canonical_json(document)
    digest = hashlib.sha256(result).digest()
    signature = vb.canonical_json(
        {
            "algorithm": "ed25519",
            "bundle_sha256": digest.hex(),
            "format": "restoreproof.signature.v1",
            "key_id": KEYS[key]["key_id"],
            "signature": base64.b64encode(private_key(key).sign(digest)).decode("ascii"),
        }
    )
    return result, signature


def bundle(
    run_id: uuid.UUID | str,
    client_id: uuid.UUID | str | None,
    *,
    patch: Callable[[dict[str, Any]], None] | None = None,
    key: str = "rfc8032-test-1",
    stamped_at: dt.datetime | None = None,
    base: dict[str, Any] | None = None,
    attachments: dict[str, bytes] | None = None,
) -> Parts:
    """The Worker-made bundle as parts, its `run_id` and `client_id` the
    Cloud's, `patch` applied, re-signed; with a token over its hash at
    `stamped_at` when given."""
    document = json.loads(json.dumps(BUNDLE_RESULT if base is None else base))
    document["run_id"] = str(run_id)
    document["client"]["client_id"] = None if client_id is None else str(client_id)
    if patch is not None:
        patch(document)
    result, signature = sign(document, key)
    parts: Parts = {"result": result, "signature": signature}
    if stamped_at is not None:
        parts["timestamp"] = make_token(hashlib.sha256(result).digest(), stamped_at)
    parts.update(ATTACHMENTS if attachments is None else attachments)
    return parts


def files_of(parts: Parts | list[tuple[str, bytes]]) -> list[tuple[str, tuple[str, bytes, str]]]:
    """httpx's `files` for the parts, as the Worker sends them: each under its
    name, with its file name and content type (worker/src/outbox.cpp)."""
    items = list(parts.items()) if isinstance(parts, dict) else parts
    return [(name, (FILE_NAMES.get(name, name), data, CONTENT_TYPES.get(name, "application/octet-stream"))) for name, data in items]


class Lab:
    def __init__(self, session, *, tsa_ca: bytes = ROOT_PEM):
        self.session = session
        self.stream = io.StringIO()
        self.settings = make_settings()
        self.app = create_app(self.settings, log_stream=self.stream)
        self.app.dependency_overrides[get_session] = session_override(session)
        self.app.state.tsa_ca_pem = tsa_ca
        client = make_s3_client(self.settings)
        self.stubber = Stubber(client)
        self.app.state.storage = Storage(client, self.settings.s3_bucket)
        self.stubber.activate()

    async def fill(self) -> None:
        s = self.session
        self.msp_id = (await MspRepo(s).create(name="a")).id
        client = await ClientRepo(s).create(self.msp_id, name="contoso", tenant_id=TENANT_ID)
        self.client_id = client.id
        self.token = new_token()
        self.worker_id = (await WorkerRepo(s).create(
            self.msp_id, "w1", public_key_pem=KEYS["rfc8032-test-1"]["public_key_pem"],
            key_id=KEYS["rfc8032-test-1"]["key_id"], api_token_hash=token_hash(self.token),
        )).id
        self.other_token = new_token()
        self.other_worker_id = (await WorkerRepo(s).create(
            self.msp_id, "w2", public_key_pem=KEYS["rfc8032-test-2"]["public_key_pem"],
            key_id=KEYS["rfc8032-test-2"]["key_id"], api_token_hash=token_hash(self.other_token),
        )).id
        self.connector_id = (await ConnectorRepo(s).create(self.msp_id, self.client_id, self.worker_id, profile_for(TENANT_ID))).id
        self.other_connector_id = (await ConnectorRepo(s).create(
            self.msp_id, self.client_id, self.other_worker_id, profile_for(TENANT_ID)
        )).id
        self.plan_id = (await PlanRepo(s).create(
            self.msp_id, self.client_id, self.connector_id, sample_mail=3, sample_sp=2, sample_od=1, cadence_cron="0 2 * * *", now=NOW
        )).id
        self.other_plan_id = (await PlanRepo(s).create(
            self.msp_id, self.client_id, self.other_connector_id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 3 * * *", now=NOW
        )).id
        # The other MSP: its own client of the same tenant, Worker under the
        # same published key is impossible (the key's unique), so a made-up one.
        self.b_msp_id = (await MspRepo(s).create(name="b")).id
        b_client = await ClientRepo(s).create(self.b_msp_id, name="b client", tenant_id=TENANT_ID)
        b_worker = await WorkerRepo(s).create(
            self.b_msp_id, "bw", public_key_pem="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
            key_id="b" * 64, api_token_hash=token_hash(new_token()),
        )
        b_connector = await ConnectorRepo(s).create(self.b_msp_id, b_client.id, b_worker.id, profile_for(TENANT_ID))
        b_plan = await PlanRepo(s).create(
            self.b_msp_id, b_client.id, b_connector.id, sample_mail=2, sample_sp=2, sample_od=2, cadence_cron="0 4 * * *", now=NOW
        )
        self.b_run_id = (await RunRepo(s).create(
            self.b_msp_id, plan_id=b_plan.id, client_id=b_client.id, connector_id=b_connector.id, worker_id=b_worker.id
        )).id
        await self.session.execute(
            text("UPDATE test_run SET state = 'dispatched', dispatched_at = :at, attempt = 1 WHERE id = :id"),
            {"at": NOW, "id": self.b_run_id},
        )

    async def run(self, *, state: str = "dispatched", attempt: int = 1, other: bool = False) -> uuid.UUID:
        """A run of the first Worker (or the second) in `state`, handed out
        `attempt` times (0: never)."""
        row = await RunRepo(self.session).create(
            self.msp_id,
            plan_id=self.other_plan_id if other else self.plan_id,
            client_id=self.client_id,
            connector_id=self.other_connector_id if other else self.connector_id,
            worker_id=self.other_worker_id if other else self.worker_id,
        )
        await self.session.execute(
            text("UPDATE test_run SET state = :state, dispatched_at = :at, attempt = :attempt WHERE id = :id"),
            {"state": state, "at": None if attempt == 0 else NOW, "attempt": attempt, "id": row.id},
        )
        return row.id

    def bundle(self, run_id, **changes) -> Parts:
        return bundle(run_id, changes.pop("client_id", self.client_id), **changes)

    def expect_puts(self, run_id: uuid.UUID, parts: Parts, *, msp_id: uuid.UUID | None = None) -> str:
        """The puts an accepted upload makes, in order, each with its exact
        key, bytes and content type; answers the bundle's key."""
        key = f"msp/{msp_id or self.msp_id}/runs/{run_id}/"
        order = ["result", "signature"] + (["timestamp"] if "timestamp" in parts else [])
        order += [a["name"] for a in json.loads(parts["result"])["attachments"] or []]
        for name in order:
            self.stubber.add_response(
                "put_object",
                {"ETag": '"x"'},
                expected_params={
                    "Bucket": self.settings.s3_bucket,
                    "Key": key + FILE_NAMES.get(name, name),
                    "Body": parts[name],
                    "ContentType": CONTENT_TYPES.get(name, "application/octet-stream"),
                },
            )
        return key

    async def post(self, parts, token: str | None = None, **request) -> httpx.Response:
        headers = dict(request.pop("headers", {}))
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if parts is not None:
            request["files"] = files_of(parts)
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.post(PATH, headers=headers, **request)

    async def upload(self, parts, token: str | None = None, **request) -> httpx.Response:
        return await self.post(parts, self.token if token is None else token, **request)

    async def run_row(self, run_id, msp_id=None):
        return await RunRepo(self.session).get(msp_id or self.msp_id, run_id)

    async def items(self, run_id):
        return await ItemRepo(self.session).list(self.msp_id, run_id)

    async def audit(self, msp_id=None) -> list[tuple[str, str]]:
        return [(row.action, row.target) for row in await AuditRepo(self.session).list(msp_id or self.msp_id)]

    async def counts(self) -> dict[str, Any]:
        """Every table's row count and the audit rows as a multiset, to show a
        refusal wrote one audit row and nothing else. Rows of one transaction
        share `now()`, so the audit log has no "last row"; the difference of
        two multisets is what a request wrote."""
        tables = ("msp", "user", "client", "worker", "connector", "test_plan", "test_run", "test_item", "report", "audit_log", "install_token")
        counts: dict[str, Any] = {}
        for table in tables:
            counts[table] = (await self.session.execute(text(f'SELECT count(*) FROM "{table}"'))).scalar_one()
        counts["audit"] = Counter(await self.audit())
        return counts

    async def wrote(self, before: dict[str, Any]) -> list[tuple[str, str]]:
        """The audit rows written since `before`."""
        return sorted((Counter(await self.audit()) - before["audit"]).elements())

    @property
    def log(self) -> str:
        return self.stream.getvalue()
