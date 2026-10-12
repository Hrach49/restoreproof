"""C5.7: `Storage.put` and `get` (docs/decisions.md 2026-10-10, C5.7, point
10): one `put_object` with the exact key, bytes and content type, one
`get_object` read whole, each on botocore's `Stubber` and on a closed port.
No MinIO runs in the unit tests (the C5.1 rule): the real bucket is the by-hand
Done-when's.
"""

from __future__ import annotations

import io

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.response import StreamingBody
from botocore.stub import Stubber

from app.storage import Storage, make_s3_client
from tests.conftest import make_settings

KEY = "msp/11111111-1111-1111-1111-111111111111/runs/22222222-2222-2222-2222-222222222222/result.json"
BODY = b'{"format":"restoreproof.result.v1"}'


def stubbed() -> tuple[Storage, Stubber]:
    settings = make_settings()
    client = make_s3_client(settings)
    return Storage(client, settings.s3_bucket), Stubber(client)


def test_put_writes_the_bytes_under_the_key_with_the_content_type():
    storage, stubber = stubbed()
    stubber.add_response(
        "put_object",
        {"ETag": '"x"'},
        expected_params={"Bucket": "test-bucket", "Key": KEY, "Body": BODY, "ContentType": "application/json"},
    )

    with stubber:
        storage.put(KEY, BODY, "application/json")
        stubber.assert_no_pending_responses()


def test_get_reads_the_object_whole():
    storage, stubber = stubbed()
    stubber.add_response(
        "get_object",
        {"Body": StreamingBody(io.BytesIO(BODY), len(BODY)), "ContentLength": len(BODY)},
        expected_params={"Bucket": "test-bucket", "Key": KEY},
    )

    with stubber:
        assert storage.get(KEY) == BODY
        stubber.assert_no_pending_responses()


def test_a_put_the_bucket_refuses_raises_the_library_s_error():
    storage, stubber = stubbed()
    stubber.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)

    with stubber, pytest.raises(ClientError):
        storage.put(KEY, BODY, "application/octet-stream")


@pytest.mark.parametrize("call", ["put", "get"])
def test_a_bucket_on_a_closed_port_raises_and_answers_nothing(call):
    """The data client keeps botocore's own retries, so this takes a few
    seconds; the error is the library's, never swallowed."""
    settings = make_settings()
    storage = Storage(make_s3_client(settings), settings.s3_bucket)

    with pytest.raises(EndpointConnectionError):
        if call == "put":
            storage.put(KEY, BODY, "application/json")
        else:
            storage.get(KEY)


# --- C6.2: the run page's list and the download's link (docs/decisions.md 2026-10-12, points 19, 20)


PREFIX = KEY.rpartition("/")[0] + "/"


def test_list_answers_the_names_under_the_prefix_sorted_from_one_call():
    storage, stubber = stubbed()
    stubber.add_response(
        "list_objects_v2",
        {"Contents": [{"Key": PREFIX + "veeam-session.log"}, {"Key": PREFIX + "result.json"}, {"Key": PREFIX + "items.csv"}]},
        expected_params={"Bucket": "test-bucket", "Prefix": PREFIX, "MaxKeys": 1000},
    )
    stubber.add_response("list_objects_v2", {}, expected_params={"Bucket": "test-bucket", "Prefix": PREFIX, "MaxKeys": 1000})

    with stubber:
        assert storage.list(PREFIX) == ["items.csv", "result.json", "veeam-session.log"]
        assert storage.list(PREFIX) == []
        stubber.assert_no_pending_responses()


def test_a_list_the_bucket_refuses_raises_the_library_s_error():
    storage, stubber = stubbed()
    stubber.add_client_error("list_objects_v2", service_error_code="AccessDenied", http_status_code=403)

    with stubber, pytest.raises(ClientError):
        storage.list(PREFIX)


def test_the_link_is_signed_for_the_public_endpoint_for_the_given_seconds_and_holds_no_secret():
    from urllib.parse import parse_qs, urlsplit

    settings = make_settings(S3_PUBLIC_ENDPOINT="http://browser.test:9000")
    storage = Storage.from_settings(settings)

    url = storage.presigned_get_url(KEY, expires_s=600)

    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert (parts.scheme, parts.netloc, parts.path) == ("http", "browser.test:9000", f"/test-bucket/{KEY}")
    assert query["X-Amz-Expires"] == ["600"]
    assert query["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert query["X-Amz-Credential"][0].startswith("test-access-key/")
    assert query["X-Amz-Signature"][0]
    assert "test-secret-key" not in url
    assert storage.sign_client is not storage.client and storage.sign_client is not storage.check_client
    assert storage.client.meta.endpoint_url == "http://127.0.0.1:1"


def test_without_a_public_endpoint_the_link_is_signed_for_the_data_endpoint():
    storage = Storage.from_settings(make_settings())

    url = storage.presigned_get_url(KEY, expires_s=60)

    assert url.startswith(f"http://127.0.0.1:1/test-bucket/{KEY}?")
    assert "X-Amz-Expires=60" in url
    assert storage.sign_client.meta.endpoint_url == "http://127.0.0.1:1"


def test_a_storage_made_by_hand_signs_with_its_one_client():
    storage, _ = stubbed()

    assert storage.sign_client is storage.client
