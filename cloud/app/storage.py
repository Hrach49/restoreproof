"""The S3 client (C5.1).

Any S3-compatible store: MinIO in the local stack. Putting and getting an
object are C5.7's; this is the client and the check /healthz makes.
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config

from app.settings import Settings

# One attempt under short limits: /healthz answers "error", it doesn't wait.
CHECK_CONNECT_TIMEOUT_S = 2
CHECK_READ_TIMEOUT_S = 2


def make_s3_client(settings: Settings) -> Any:
    """A boto3 S3 client for the settings' endpoint. Making it connects to nothing."""
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        region_name=settings.s3_region,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key.get_secret_value(),
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=CHECK_CONNECT_TIMEOUT_S,
            read_timeout=CHECK_READ_TIMEOUT_S,
            retries={"total_max_attempts": 1, "mode": "standard"},
        ),
    )


class Storage:
    def __init__(self, client: Any, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    @classmethod
    def from_settings(cls, settings: Settings) -> Storage:
        return cls(make_s3_client(settings), settings.s3_bucket)

    def check(self) -> None:
        """Raise unless the bucket can be listed.

        One call that proves the endpoint, the keys, the bucket and the right
        to list it. Synchronous, as boto3 is: call it from a thread.
        """
        self.client.list_objects_v2(Bucket=self.bucket, MaxKeys=1)
