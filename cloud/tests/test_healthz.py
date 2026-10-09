"""C5.1: GET /healthz says whether the database and the bucket answer.

200 only when both are ok, 503 otherwise, always both keys, and nothing of an
exception's text in the body.
"""

import io
import json
import time

import httpx
import pytest
from botocore.stub import Stubber

import app.health
from app.main import create_app
from app.storage import Storage, make_s3_client
from tests.conftest import make_settings

SENTINEL = "Sentinel-Health-55c0"


class Lab:
    """The real app. By default its database and bucket are closed ports."""

    def __init__(self, **settings: str):
        self.log = io.StringIO()
        self.settings = make_settings(**settings)
        self.app = create_app(self.settings, log_stream=self.log)
        self.stubber: Stubber | None = None

    def stub_bucket(self) -> Stubber:
        """A real boto3 client whose answers are botocore's stubbed ones."""
        client = make_s3_client(self.settings)
        self.stubber = Stubber(client)
        self.app.state.storage = Storage(client, self.settings.s3_bucket)
        return self.stubber

    def bucket_answers(self) -> None:
        self.stub_bucket().add_response(
            "list_objects_v2",
            {"KeyCount": 0, "IsTruncated": False, "Name": "test-bucket"},
            expected_params={"Bucket": "test-bucket", "MaxKeys": 1},
        )
        self.stubber.activate()

    def bucket_refuses(self, code: str) -> None:
        self.stub_bucket().add_client_error(
            "list_objects_v2", service_error_code=code, service_message=SENTINEL, http_status_code=403
        )
        self.stubber.activate()

    async def get(self, path: str = "/healthz", **kwargs) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://cloud.test") as client:
            return await client.get(path, **kwargs)

    async def close(self) -> None:
        await self.app.state.engine.dispose()

    @property
    def lines(self) -> list[dict]:
        return [json.loads(line) for line in self.log.getvalue().splitlines()]

    def failures(self) -> list[dict]:
        return [line for line in self.lines if line["event"] == "health check failed"]


@pytest.fixture
async def lab(test_database_url):
    """Database: the real test Postgres. Bucket: a closed port until stubbed."""
    lab = Lab(DATABASE_URL=test_database_url)
    yield lab
    await lab.close()


@pytest.fixture
async def offline():
    """Both the database and the bucket are closed loopback ports."""
    lab = Lab()
    yield lab
    await lab.close()


async def test_both_ok_is_200(lab):
    lab.bucket_answers()

    response = await lab.get()

    assert response.status_code == 200
    assert response.json() == {"db": "ok", "s3": "ok"}
    assert response.headers["cache-control"] == "no-store"
    assert lab.failures() == []
    lab.stubber.assert_no_pending_responses()


async def test_the_bucket_down_is_503_with_the_database_still_ok(lab):
    response = await lab.get()

    assert response.status_code == 503
    assert response.json() == {"db": "ok", "s3": "error"}
    assert response.headers["cache-control"] == "no-store"


async def test_the_database_down_is_503_with_the_bucket_still_ok(offline):
    offline.bucket_answers()

    response = await offline.get()

    assert response.status_code == 503
    assert response.json() == {"db": "error", "s3": "ok"}


async def test_both_down_is_503_and_both_are_reported(offline):
    response = await offline.get()

    assert response.status_code == 503
    assert response.json() == {"db": "error", "s3": "error"}
    assert sorted(line["check"] for line in offline.failures()) == ["db", "s3"]


@pytest.mark.parametrize("code", ["AccessDenied", "NoSuchBucket", "InvalidAccessKeyId"])
async def test_a_bucket_that_refuses_the_listing_is_an_error(lab, code):
    lab.bucket_refuses(code)

    response = await lab.get()

    assert response.status_code == 503
    assert response.json() == {"db": "ok", "s3": "error"}


async def test_nothing_of_an_exception_s_text_reaches_the_body_or_the_log(lab):
    lab.bucket_refuses("AccessDenied")

    response = await lab.get(headers={"X-Request-ID": "health-1"})

    assert response.text == '{"db":"ok","s3":"error"}'
    assert SENTINEL not in response.text
    assert SENTINEL not in lab.log.getvalue()
    (failure,) = lab.failures()
    assert failure["check"] == "s3"
    # The exception's class and nothing else: botocore names it after the code.
    assert failure["exc_type"] in {"ClientError", "AccessDenied"}
    assert failure["level"] == "warning"
    assert failure["request_id"] == "health-1"
    assert set(failure) == {"ts", "level", "event", "request_id", "check", "exc_type"}


async def test_a_database_failure_is_logged_by_its_type_alone(offline):
    offline.bucket_answers()

    await offline.get()

    (failure,) = offline.failures()
    assert failure["check"] == "db"
    assert failure["exc_type"]
    assert "127.0.0.1" not in offline.log.getvalue()
    assert "nobody" not in offline.log.getvalue()


async def test_a_check_that_hangs_is_an_error_after_the_limit(lab, monkeypatch):
    monkeypatch.setattr(app.health, "CHECK_TIMEOUT_S", 0.05)

    class Hanging:
        def check(self) -> None:
            time.sleep(0.4)

    async def database(_engine) -> None:
        return None

    lab.app.state.storage = Hanging()
    monkeypatch.setattr(app.health, "check_database", database)
    started = time.perf_counter()

    response = await lab.get()

    assert time.perf_counter() - started < 0.35
    assert response.json() == {"db": "ok", "s3": "error"}
    (failure,) = lab.failures()
    assert failure["exc_type"] == "TimeoutError"


async def test_the_checks_run_side_by_side(lab, monkeypatch):
    """One being slow doesn't make the other wait for it."""
    monkeypatch.setattr(app.health, "CHECK_TIMEOUT_S", 0.3)
    order: list[str] = []

    class Slow:
        def check(self) -> None:
            time.sleep(0.15)
            order.append("s3")

    async def database(_engine) -> None:
        order.append("db")

    lab.app.state.storage = Slow()
    monkeypatch.setattr(app.health, "check_database", database)

    response = await lab.get()

    assert response.json() == {"db": "ok", "s3": "ok"}
    assert order == ["db", "s3"]


async def test_healthz_takes_part_in_request_logging(lab):
    lab.bucket_answers()

    response = await lab.get(headers={"X-Request-ID": "probe-7"})

    assert response.headers["x-request-id"] == "probe-7"
    (line,) = [entry for entry in lab.lines if entry["event"] == "request"]
    assert (line["path"], line["status"], line["request_id"]) == ("/healthz", 200, "probe-7")


def test_the_s3_client_is_path_style_sigv4_with_short_limits_and_no_retry():
    client = make_s3_client(make_settings(S3_REGION="eu-central-1"))

    config = client.meta.config
    assert client.meta.endpoint_url == "http://127.0.0.1:1"
    assert client.meta.region_name == "eu-central-1"
    assert config.signature_version == "s3v4"
    assert config.s3 == {"addressing_style": "path"}
    assert config.connect_timeout == 2
    assert config.read_timeout == 2
    assert config.retries == {"total_max_attempts": 1, "mode": "standard"}


def test_storage_from_settings_checks_the_settings_bucket():
    settings = make_settings(S3_BUCKET="another-bucket")
    storage = Storage.from_settings(settings)

    assert storage.bucket == "another-bucket"
    assert storage.client.meta.endpoint_url == settings.s3_endpoint
    assert storage.client.meta.service_model.service_name == "s3"
