"""The lab of the report tests (tests/test_report.py; C6.4, docs/decisions.md
2026-10-12, "C6.4"): the pages' lab (the vector's world, the bucket on
botocore's `Stubber`) with the runs of one month made to order, a second
client of the same MSP, the puts the generator makes recorded body by body
(the Stubber takes any body; a hook keeps what was sent), and the PDF's text
through pypdf.
"""

from __future__ import annotations

import datetime as dt
import io
import re
import uuid
from typing import Any

from botocore.response import StreamingBody
from botocore.stub import ANY
from pypdf import PdfReader
from sqlalchemy import text

from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.items import ItemRepo, ItemRow
from app.repo.plans import PlanRepo
from app.report.data import Period, period_of
from tests.pages_lab import UTC, PagesLab
from tests.results_lab import NOW, Parts
from tests.test_contract import VECTOR
from tests.test_repo_connectors import profile_for

SEPTEMBER = period_of("2026-09")
SEPTEMBER_START = dt.datetime(2026, 9, 1, tzinfo=UTC)
OCTOBER_START = dt.datetime(2026, 10, 1, tzinfo=UTC)
PDF_TYPE = "application/pdf"


def at(day: int, hour: int = 2, minute: int = 0, second: int = 0, month: int = 9) -> dt.datetime:
    return dt.datetime(2026, month, day, hour, minute, second, tzinfo=UTC)


def an_item(position: int, **changes) -> ItemRow:
    values = dict(
        position=position, type="mail", name=f"RP-CANARY-{position:04d}", expected_kind="manifest",
        expected_sha256=None, found_sha256=None, found=True, match=True, reason=None, ms=900,
    )
    return ItemRow(**{**values, **changes})


class ReportLab(PagesLab):
    async def fill(self) -> None:
        await super().fill()
        # A second client of the same MSP, on the second Worker with a plan of
        # its own (a run is under its plan's client): its runs are never in
        # the first's report.
        tenant2 = uuid.uuid4()
        self.client2_id = (await ClientRepo(self.session).create(self.msp_id, name="fabrikam", tenant_id=tenant2)).id
        self.connector2_id = (await ConnectorRepo(self.session).create(self.msp_id, self.client2_id, self.other_worker_id, profile_for(tenant2))).id
        self.plan2_id = (await PlanRepo(self.session).create(
            self.msp_id, self.client2_id, self.connector2_id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 5 * * *", now=NOW
        )).id
        self.bodies: list[bytes] = []
        # Every object put, by key (Q6.1: the check reads them back).
        self.objects: dict[str, bytes] = {}
        self.storage.client.meta.events.register("before-parameter-build.s3.PutObject", self._keep_body)

    @property
    def storage(self):
        return self.app.state.storage

    def _keep_body(self, params, **_kwargs) -> None:
        """The PDFs put, in order (the vector's own puts are not PDFs)."""
        if params.get("ContentType") == PDF_TYPE:
            self.bodies.append(params["Body"])
        self.objects[params["Key"]] = params["Body"]

    def expect_put(self, key: str) -> None:
        """One put under `key` of a PDF: the Stubber takes any body and the
        hook keeps the bytes sent."""
        self.stubber.add_response(
            "put_object",
            {"ETag": '"x"'},
            expected_params={"Bucket": self.settings.s3_bucket, "Key": key, "Body": ANY, "ContentType": PDF_TYPE},
        )

    def expect_get(self, key: str, body: bytes | None = None) -> None:
        """One `get_object` of `key` answered with `body` (the bytes put under
        it unless given: a planted fault answers other bytes)."""
        data = self.objects[key] if body is None else body
        self.stubber.add_response(
            "get_object", {"Body": StreamingBody(io.BytesIO(data), len(data))}, expected_params={"Bucket": self.settings.s3_bucket, "Key": key}
        )

    def expect_missing(self, key: str) -> None:
        """One `get_object` of `key` answered with S3's `NoSuchKey`."""
        self.stubber.add_client_error("get_object", service_error_code="NoSuchKey", expected_params={"Bucket": self.settings.s3_bucket, "Key": key})

    def expect_run_objects(self, run, *, names: list[str] | None = None, objects: dict[str, bytes] | None = None) -> None:
        """What the check reads of one run, in its order: the prefix listed
        (the bundle's files unless `names` is given), then, for a stamped run,
        `result.json` and `timestamp.tst` when listed, each the bytes put
        unless `objects` plants others."""
        if run.state not in ("pass", "fail", "error") or run.bundle_key is None:
            return
        prefix = run.bundle_key
        listed = sorted(k[len(prefix):] for k in self.objects if k.startswith(prefix)) if names is None else names
        self.stubber.add_response(
            "list_objects_v2",
            {"Contents": [{"Key": prefix + name} for name in listed]} if listed else {},
            expected_params={"Bucket": self.settings.s3_bucket, "Prefix": prefix, "MaxKeys": 1000},
        )
        if not run.tsa_ok:
            return
        for name in ("result.json", "timestamp.tst"):
            if name in listed:
                self.expect_get(prefix + name, (objects or {}).get(name))

    async def land(
        self,
        *,
        ended_at: str | None,
        stamped_at: dt.datetime | None,
        received_at: dt.datetime,
        base: dict[str, Any] | None = None,
        attachments: dict[str, bytes] | None = None,
        dispatched_at: dt.datetime | None = None,
    ) -> uuid.UUID:
        """A run of the first Worker dispatched (at `dispatched_at` when
        given) and its bundle posted as the Worker posts it, the result's
        `ended_at` as given (None: a result written afterwards, on `base`),
        a token of the test TSA at `stamped_at` (None: no token), the upload's
        clock at `received_at`: 202."""
        run_id = await self.inner.run()
        if dispatched_at is not None:
            await self.session.execute(text("UPDATE test_run SET dispatched_at = :at WHERE id = :id"), {"at": dispatched_at, "id": run_id})

        def patch(document: dict[str, Any]) -> None:
            # The pages' lab's client is the Worker vector's tenant, not the
            # re-signed bundle's: the result names the lab's.
            client = document["client"]
            if client.get("tenant_id"):
                client["tenant_id"] = VECTOR["tenant_id"]
            if client.get("resolved"):
                client["resolved"]["organization"]["tenant_id"] = VECTOR["tenant_id"]
            if ended_at is not None:
                ended = dt.datetime.strptime(ended_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                document["started_at"] = (ended - dt.timedelta(seconds=50)).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ended.microsecond // 1000:03d}Z"
                document["ended_at"] = ended_at

        parts: Parts = self.inner.bundle(run_id, patch=patch, stamped_at=stamped_at, base=base, attachments=attachments)
        self.inner.expect_puts(run_id, parts)
        self.received = received_at
        response = await self.inner.upload(parts)
        assert response.status_code == 202, response.text
        return run_id

    def final_key(self, period: Period = SEPTEMBER, client_id=None) -> str:
        return f"msp/{self.msp_id}/reports/{client_id or self.client_id}/{period.name}.pdf"

    async def items(self, run_id, rows: list[ItemRow]) -> None:
        await ItemRepo(self.session).create_many(self.msp_id, run_id, rows)

    async def tested(self, state: str, *, finished_at: dt.datetime, created_at: dt.datetime | None = None, **columns) -> uuid.UUID:
        """A run that is over, in `state`, ended at `finished_at` (begun a
        minute before unless `created_at` is given)."""
        return await self.make_run(
            state=state, created_at=created_at or finished_at - dt.timedelta(minutes=1),
            finished_at=finished_at, started_at=finished_at - dt.timedelta(seconds=50), **columns,
        )

    async def month(self) -> dict[str, uuid.UUID]:
        """The Done-when's September: the vector's pass (the 28th), a fail
        with a missing mail and a mismatched file (the 10th), an error with
        no item (the 20th), a later pass (the 25th), an expired run (the
        15th), a queued run (the 16th) and a dispatched one (the 17th), both
        with no result yet; and, never in the report, a pass of October, a
        pass of August's last second, and the second client's fail of the
        month."""
        vector = await self.land_vector()
        failed = await self.tested(
            "fail", finished_at=at(10, 2, 30), restore_point_at=at(9, 23), recovery_ms=65000, bundle_sha256="ab" * 32, tsa_ok=True, tsa_time=at(10, 2, 30, 5),
        )
        await self.items(failed, [
            an_item(0, name="RP-CANARY-0003", found=False, match=False, reason="no restored copy found"),
            an_item(1, type="sharepoint", name="rp-canary-04.docx", found=True, match=False, reason="fields did not match: sha256"),
            an_item(2, type="onedrive", name="rp-canary-12.pdf"),
        ])
        errored = await self.tested(
            "error", finished_at=at(20, 2, 5), error_code="veeam_unreachable", error_message="the backup product did not answer",
            bundle_sha256="cd" * 32, tsa_ok=None,
        )
        later = await self.tested(
            "pass", finished_at=at(25, 2, 20), restore_point_at=at(24, 23), recovery_ms=40000, bundle_sha256="ef" * 32, tsa_ok=True, tsa_time=at(25, 2, 20, 4),
        )
        await self.items(later, [an_item(0, name="RP-CANARY-0005")])
        expired = await self.make_run(state="expired", created_at=at(15))
        queued = await self.make_run(state="queued", created_at=at(16))
        dispatched = await self.make_run(state="dispatched", created_at=at(17), dispatched_at=at(17, 2, 1))
        await self.tested("pass", finished_at=at(1, 0, 0, 0, month=10), recovery_ms=1000)
        await self.tested("pass", finished_at=SEPTEMBER_START - dt.timedelta(seconds=1), recovery_ms=1000)
        theirs = await self.tested(
            "fail", finished_at=at(12), client_id=self.client2_id, plan_id=self.plan2_id, connector_id=self.connector2_id, worker_id=self.other_worker_id,
        )
        await self.items(theirs, [an_item(0, name="THEIRS", found=False, match=False, reason="no restored copy found")])
        return {
            "vector": vector, "failed": failed, "errored": errored, "later": later, "expired": expired, "queued": queued,
            "dispatched": dispatched, "theirs": theirs,
        }


def pdf_text(pdf: bytes) -> str:
    """The PDF's text as pypdf reads it, whitespace folded to single spaces."""
    reader = PdfReader(io.BytesIO(pdf))
    return re.sub(r"\s+", " ", " ".join(page.extract_text() for page in reader.pages))


def pdf_info(pdf: bytes) -> dict[str, str]:
    """The PDF's Info dictionary as pypdf reads it. WeasyPrint writes it into
    a compressed object stream, so a search of the raw bytes sees none of it
    (the C6.4 review's finding 14)."""
    return {str(key): str(value) for key, value in (PdfReader(io.BytesIO(pdf)).metadata or {}).items()}


def pdf_trailer_keys(pdf: bytes) -> set[str]:
    return {str(key) for key in PdfReader(io.BytesIO(pdf)).trailer}


def past_the_page(html: str) -> list[str]:
    """Every text of the laid-out report whose right edge is past its page's
    content box: what pypdf's text cannot see (the review's finding 9)."""
    from weasyprint import CSS, HTML

    from app.report import render

    document = HTML(string=html, base_url=str(render.REPORT_DIR)).render(stylesheets=[CSS(filename=str(render.REPORT_DIR / render.STYLESHEET))])
    found: list[str] = []
    boxes = 0
    for page in document.pages:
        box = page._page_box
        limit = box.margin_left + box.padding_left + box.width + 0.5
        for inner in box.descendants():
            if type(inner).__name__ == "TextBox":
                boxes += 1
                if inner.position_x + inner.width > limit:
                    found.append(inner.text)
    assert boxes > 50, boxes
    return found


def page_count(pdf: bytes) -> int:
    return len(PdfReader(io.BytesIO(pdf)).pages)


VECTOR_HASH = VECTOR["bundle_sha256"]
