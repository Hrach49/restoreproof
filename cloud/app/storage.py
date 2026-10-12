"""The S3 client (C5.1), the bundle's put and get (C5.7), and the pages' list
and pre-signed link (C6.2).

Any S3-compatible store: MinIO in the local stack. The check /healthz makes
has a client of its own: its short limits are a probe's, not an upload's. A
bundle's files go under `msp/<msp_id>/runs/<run_id>/<name>` through `put`,
one object per file (docs/decisions.md 2026-10-10, C5.7, point 10); `get`
reads one back whole; `list` names the objects under a prefix (the run page's
files). All three are synchronous, as boto3 is: a route runs them in a
thread, and an error is the library's own, never swallowed, so the route's
transaction rolls back.

`presigned_get_url` (C6.2, point 20) signs a GET of one object for a few
minutes with a third client made for `S3_PUBLIC_ENDPOINT`, the endpoint a
browser reaches: SigV4 signs the host, so a URL signed for the data endpoint
(`minio:9000` in the stack) doesn't open from a browser. Signing connects to
nothing.
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config

from app.settings import Settings

# One attempt under short limits: /healthz answers "error", it doesn't wait.
CHECK_CONNECT_TIMEOUT_S = 2
CHECK_READ_TIMEOUT_S = 2

# A run's objects are at most six (app/results.py MAX_FILE_PARTS); one call lists them.
LIST_MAX_KEYS = 1000


def make_s3_client(settings: Settings, *, for_check: bool = False, endpoint: str | None = None) -> Any:
    """A boto3 S3 client for the settings' endpoint (or `endpoint`). Making it
    connects to nothing.

    The data client keeps botocore's own limits and its standard retries;
    `for_check` gives the one /healthz asks through.
    """
    limits: dict[str, Any] = {"retries": {"mode": "standard"}}
    if for_check:
        limits = {
            "connect_timeout": CHECK_CONNECT_TIMEOUT_S,
            "read_timeout": CHECK_READ_TIMEOUT_S,
            "retries": {"total_max_attempts": 1, "mode": "standard"},
        }
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint if endpoint is None else endpoint,
        region_name=settings.s3_region,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key.get_secret_value(),
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            **limits,
        ),
    )


class Storage:
    def __init__(self, client: Any, bucket: str, check_client: Any | None = None, sign_client: Any | None = None) -> None:
        self.client = client
        self.bucket = bucket
        self.check_client = client if check_client is None else check_client
        self.sign_client = client if sign_client is None else sign_client

    @classmethod
    def from_settings(cls, settings: Settings) -> Storage:
        return cls(
            make_s3_client(settings),
            settings.s3_bucket,
            make_s3_client(settings, for_check=True),
            make_s3_client(settings, endpoint=settings.s3_public_endpoint or settings.s3_endpoint),
        )

    def check(self) -> None:
        """Raise unless the bucket can be listed.

        One call that proves the endpoint, the keys, the bucket and the right
        to list it. Synchronous, as boto3 is: call it from a thread.
        """
        self.check_client.list_objects_v2(Bucket=self.bucket, MaxKeys=1)

    def put(self, key: str, body: bytes, content_type: str) -> None:
        """Write `body` under `key`, replacing what was there."""
        self.client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType=content_type)

    def get(self, key: str) -> bytes:
        """The object under `key`, whole."""
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def list(self, prefix: str) -> list[str]:
        """The names (the key after `prefix`) of the objects under `prefix`,
        sorted; one call."""
        answer = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix, MaxKeys=LIST_MAX_KEYS)
        return sorted(entry["Key"][len(prefix):] for entry in answer.get("Contents", []))

    def presigned_get_url(self, key: str, *, expires_s: int) -> str:
        """A GET of `key` signed for `expires_s`, for the endpoint a browser reaches."""
        return self.sign_client.generate_presigned_url(
            "get_object", Params={"Bucket": self.bucket, "Key": key}, ExpiresIn=expires_s
        )
