import json

import pytest

from fake_transport import FakeTransport, graph_error, json_response
from seeder import graph
from seeder.graph import GRAPH_BASE, GraphClient, GraphError, GraphForbidden, MAIL_PREFER, MESSAGE_FIELDS
from seeder.http import HttpResponse, TransportError
from seeder.tenant import ALICE_UPN, BOB_UPN, ONEDRIVE_DRIVE_ID, SHAREPOINT_DRIVE_ID

SENTINEL = "sentinel-token-DO-NOT-LEAK"


def make_client(responses=None, *, handler=None, account=ALICE_UPN, token=SENTINEL, max_attempts=4):
    transport = FakeTransport(responses, handler=handler)
    sleeps: list[float] = []
    g = GraphClient(transport, lambda: token, account, sleep=sleeps.append, max_attempts=max_attempts)
    return g, transport, sleeps


def assert_no_leak(exc: BaseException, capsys) -> None:
    for text in (str(exc), repr(exc), capsys.readouterr().out, capsys.readouterr().err):
        assert SENTINEL not in text
        assert "Authorization" not in text
        assert "Bearer" not in text


# ---- failure paths -------------------------------------------------------------------


@pytest.mark.parametrize(
    "responses",
    [
        [graph_error(403, "ErrorAccessDenied", "Access is denied.")],
        [graph_error(500, "generalException", "boom")] ,
        [graph_error(503)] * 4,
        [TransportError("GET https://graph.microsoft.com/v1.0/me: ConnectionError")] * 4,
        [graph_error(409, "nameAlreadyExists", "exists")],
        [graph_error(401, "InvalidAuthenticationToken", "expired")],
        [HttpResponse(400, SENTINEL.encode())],  # even a body echoing the token is scrubbed
    ],
    ids=["403", "500", "503-exhausted", "transport-exhausted", "409", "401", "400-echo"],
)
def test_errors_never_contain_the_token(responses, capsys):
    g, _, _ = make_client(responses)
    with pytest.raises(GraphError) as info:
        g.request("GET", "/me/messages", params={"$top": "1"})
    assert_no_leak(info.value, capsys)


def test_403_with_other_owner_says_that_owner_must_sign_in():
    g, _, _ = make_client([graph_error(403, "ErrorAccessDenied", "Access is denied.")])
    with pytest.raises(GraphForbidden) as info:
        g.request("GET", "/me/messages", params={"$top": "1"}, owner=BOB_UPN)
    msg = str(info.value)
    assert ALICE_UPN in msg
    assert "GET /me/messages" in msg
    assert "$top" not in msg
    assert f"this step needs {BOB_UPN} to be signed in" in msg
    assert "own mailbox" in msg
    assert "ErrorAccessDenied" in msg and "Access is denied." in msg
    assert (info.value.status, info.value.method, info.value.path) == (403, "GET", "/me/messages")


@pytest.mark.parametrize("owner", [None, ALICE_UPN, ALICE_UPN.upper()])
def test_403_as_the_owner_points_at_consent(owner):
    g, _, _ = make_client([graph_error(403)])
    with pytest.raises(GraphForbidden) as info:
        g.request("PUT", "/drives/x/items/root:/a:/content", owner=owner)
    msg = str(info.value)
    assert ALICE_UPN in msg
    assert "PUT /drives/x/items/root:/a:/content" in msg
    assert "needs" not in msg
    assert "admin consent" in msg and "lab/README.md" in msg


def test_401_says_sign_in_expired_or_rejected():
    g, _, _ = make_client([graph_error(401, "InvalidAuthenticationToken", "Lifetime validation failed")])
    with pytest.raises(GraphError) as info:
        g.request("GET", "/me")
    assert not isinstance(info.value, GraphForbidden)
    assert info.value.status == 401
    assert "sign-in expired or was rejected" in str(info.value)
    assert "InvalidAuthenticationToken" in str(info.value)


def test_graph_error_text_is_truncated():
    g, _, _ = make_client([graph_error(400, "BadRequest", "x" * 2000)])
    with pytest.raises(GraphError) as info:
        g.request("GET", "/me")
    assert "x" * 300 not in str(info.value)
    assert len(str(info.value)) < 700


def test_non_json_error_body_still_gives_status():
    g, _, _ = make_client([HttpResponse(500, b"<html>oops</html>")])
    with pytest.raises(GraphError) as info:
        g.request("DELETE", "/me/messages/1")
    assert info.value.status == 500
    assert "HTTP 500" in str(info.value) and "DELETE /me/messages/1" in str(info.value)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 500])
def test_client_errors_are_not_retried(status):
    g, transport, sleeps = make_client([graph_error(status)])
    with pytest.raises(GraphError) as info:
        g.request("GET", "/me")
    assert info.value.status == status
    assert len(transport.requests) == 1
    assert sleeps == []


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_retryable_statuses_back_off_2_4_8_then_give_up(status):
    g, transport, sleeps = make_client([graph_error(status)] * 4)
    with pytest.raises(GraphError) as info:
        g.request("GET", "/me")
    assert info.value.status == status
    assert "4 attempts" in str(info.value)
    assert len(transport.requests) == 4
    assert sleeps == [2, 4, 8]


def test_transport_errors_are_retried_then_raised_as_graph_error():
    g, transport, sleeps = make_client([TransportError("GET x: ConnectionError: refused")] * 4)
    with pytest.raises(GraphError) as info:
        g.request("GET", "/me")
    assert info.value.status is None
    assert "ConnectionError" in str(info.value)
    assert len(transport.requests) == 4
    assert sleeps == [2, 4, 8]


def test_retry_after_seconds_is_honoured_and_bad_values_fall_back():
    g, transport, sleeps = make_client(
        [
            graph_error(429, headers={"retry-after": "7"}),
            graph_error(503, headers={"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}),
            graph_error(429, headers={"retry-after": "0"}),
            json_response(200, {"ok": True}),
        ]
    )
    assert g.get_json("/me") == {"ok": True}
    assert sleeps == [7, 4, 0]


def test_recovers_after_a_retry_and_fetches_a_fresh_token_each_attempt():
    tokens = iter(["t1", "t2"])
    transport = FakeTransport([graph_error(503), json_response(200, {"id": "me"})])
    sleeps: list[float] = []
    g = GraphClient(transport, lambda: next(tokens), ALICE_UPN, sleep=sleeps.append)
    assert g.get_json("/me") == {"id": "me"}
    assert [r.headers["Authorization"] for r in transport.requests] == ["Bearer t1", "Bearer t2"]
    assert sleeps == [2]


def test_max_attempts_is_configurable():
    g, transport, sleeps = make_client([graph_error(503)] * 2, max_attempts=2)
    with pytest.raises(GraphError):
        g.request("GET", "/me")
    assert len(transport.requests) == 2
    assert sleeps == [2]


# A call that is not idempotent (sendMail, a fail-on-conflict upload) is sent once when the
# outcome is unknown: no response, or a gateway error after Graph may have processed it.
UNKNOWN_OUTCOME = [
    TransportError("POST x: ReadTimeout: read timed out"),
    graph_error(502),
    graph_error(503),
    graph_error(504, "GatewayTimeout", "timed out"),
]
UNKNOWN_OUTCOME_IDS = ["transport", "502", "503", "504"]


@pytest.mark.parametrize("first", UNKNOWN_OUTCOME, ids=UNKNOWN_OUTCOME_IDS)
def test_non_idempotent_request_is_not_retried_after_an_unknown_outcome(first, capsys):
    g, transport, sleeps = make_client([first])
    with pytest.raises(graph.GraphOutcomeUnknown) as info:
        g.request("POST", "/me/x", json_body={}, idempotent=False)
    assert len(transport.requests) == 1
    assert sleeps == []
    msg = str(info.value)
    assert "POST /me/x" in msg and "outcome is unknown" in msg and "not retried" in msg
    assert "attempts" not in msg
    assert info.value.status == (None if isinstance(first, TransportError) else first.status)
    assert_no_leak(info.value, capsys)


def test_non_idempotent_request_still_retries_429():
    g, transport, sleeps = make_client(
        [graph_error(429, headers={"retry-after": "5"}), graph_error(429), HttpResponse(202)]
    )
    assert g.request("POST", "/me/x", json_body={}, idempotent=False).status == 202
    assert len(transport.requests) == 3
    assert sleeps == [5, 4]


def test_non_idempotent_request_gives_up_on_429_like_any_other_call():
    g, transport, _ = make_client([graph_error(429)] * 4)
    with pytest.raises(GraphError) as info:
        g.request("POST", "/me/x", json_body={}, idempotent=False)
    assert not isinstance(info.value, graph.GraphOutcomeUnknown)
    assert "4 attempts" in str(info.value)
    assert len(transport.requests) == 4


# ---- request building ----------------------------------------------------------------


def test_request_builds_url_headers_and_json_body():
    g, transport, _ = make_client([HttpResponse(204)])
    g.request("POST", "/me/x", params={"a": "b c"}, headers={"Prefer": "p"}, json_body={"k": "é"})
    (req,) = transport.requests
    assert req.url == f"{GRAPH_BASE}/me/x?a=b%20c"
    assert req.headers == {
        "Prefer": "p",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SENTINEL}",
    }
    assert req.json() == {"k": "é"}


def test_account_is_exposed():
    g, _, _ = make_client([], account=BOB_UPN)
    assert g.account == BOB_UPN


def test_repr_has_no_token():
    g, _, _ = make_client([])
    assert SENTINEL not in repr(g)


# ---- helpers -------------------------------------------------------------------------


def test_find_messages_by_subject_builds_the_exact_query():
    g, transport, _ = make_client([json_response(200, {"value": [{"id": "m1"}]})])
    assert graph.find_messages_by_subject(g, "RP-CANARY-0001", ALICE_UPN) == [{"id": "m1"}]
    (req,) = transport.requests
    assert req.method == "GET"
    assert req.url == (
        f"{GRAPH_BASE}/me/messages"
        "?$filter=subject%20eq%20'RP-CANARY-0001'"
        "&$select=id,subject,from,toRecipients,sentDateTime,receivedDateTime,internetMessageId,parentFolderId,body"
        "&$top=50"
    )
    assert req.headers["Prefer"] == MAIL_PREFER
    assert MAIL_PREFER == 'outlook.body-content-type="text", IdType="ImmutableId"'
    assert req.body is None


def test_find_messages_doubles_single_quotes_and_encodes_specials():
    g, transport, _ = make_client([json_response(200, {"value": []})])
    assert graph.find_messages_by_subject(g, "it's & #1", ALICE_UPN) == []
    assert "$filter=subject%20eq%20'it''s%20%26%20%231'&" in transport.requests[0].url


def test_find_messages_403_names_owner():
    g, _, _ = make_client([graph_error(403)])
    with pytest.raises(GraphForbidden, match=BOB_UPN):
        graph.find_messages_by_subject(g, "RP-CANARY-0011", BOB_UPN)


def test_send_mail_403_names_the_owner():
    g, _, _ = make_client([graph_error(403)])
    with pytest.raises(GraphForbidden, match=f"needs {BOB_UPN}"):
        graph.send_mail(g, subject="s", body_text="b", to_address=ALICE_UPN, owner=BOB_UPN)


def test_get_message_quotes_id_and_uses_prefer():
    g, transport, _ = make_client([json_response(200, {"id": "AAk/+="})])
    assert graph.get_message(g, "AAk/+=", ALICE_UPN) == {"id": "AAk/+="}
    (req,) = transport.requests
    assert req.url == f"{GRAPH_BASE}/me/messages/AAk%2F%2B%3D?$select={MESSAGE_FIELDS}"
    assert req.headers["Prefer"] == MAIL_PREFER


def test_get_message_404_is_none_but_other_errors_raise():
    g, _, _ = make_client([graph_error(404, "ErrorItemNotFound"), graph_error(400)])
    assert graph.get_message(g, "x", ALICE_UPN) is None
    with pytest.raises(GraphError):
        graph.get_message(g, "x", ALICE_UPN)


def test_get_mail_folder_name():
    g, transport, _ = make_client([json_response(200, {"id": "f", "displayName": "Inbox"})])
    assert graph.get_mail_folder_name(g, "AQ/=", ALICE_UPN) == "Inbox"
    (req,) = transport.requests
    assert req.url == f"{GRAPH_BASE}/me/mailFolders/AQ%2F%3D?$select=displayName"
    assert req.headers["Prefer"] == MAIL_PREFER


def test_send_mail_posts_the_exact_payload():
    g, transport, _ = make_client([HttpResponse(202)], account="admin@x")
    graph.send_mail(g, subject="RP-CANARY-0001", body_text="Hi\r\n\r\nFooter", to_address=ALICE_UPN)
    (req,) = transport.requests
    assert (req.method, req.url) == ("POST", f"{GRAPH_BASE}/me/sendMail")
    assert req.headers["Content-Type"] == "application/json"
    assert req.json() == {
        "message": {
            "subject": "RP-CANARY-0001",
            "body": {"contentType": "text", "content": "Hi\r\n\r\nFooter"},
            "toRecipients": [{"emailAddress": {"address": ALICE_UPN}}],
        },
        "saveToSentItems": True,
    }


def test_send_mail_other_success_status_is_an_error():
    g, _, _ = make_client([HttpResponse(200)])
    with pytest.raises(GraphError, match="202"):
        graph.send_mail(g, subject="s", body_text="b", to_address="t@x")


@pytest.mark.parametrize(
    "drive_id, encoded",
    [
        (SHAREPOINT_DRIVE_ID, SHAREPOINT_DRIVE_ID),  # "!" left as is, like Graph's own URLs
        ("a/b c", "a%2Fb%20c"),
    ],
)
def test_drive_paths_keep_bang_and_quote_the_rest(drive_id, encoded):
    g, transport, _ = make_client([json_response(200, {"id": "i"})])
    assert graph.get_item(g, drive_id, "01AB/C", ALICE_UPN) == {"id": "i"}
    assert transport.requests[0].url == f"{GRAPH_BASE}/drives/{encoded}/items/01AB%2FC"


def test_get_item_by_path():
    g, transport, _ = make_client([json_response(200, {"id": "i", "name": "rp canary.pdf"})])
    item = graph.get_item_by_path(g, ONEDRIVE_DRIVE_ID, "01ZK", "rp canary#1.pdf", ALICE_UPN)
    assert item == {"id": "i", "name": "rp canary.pdf"}
    (req,) = transport.requests
    assert req.method == "GET"
    assert req.url == f"{GRAPH_BASE}/drives/{ONEDRIVE_DRIVE_ID}/items/01ZK:/rp%20canary%231.pdf:"


@pytest.mark.parametrize("helper", ["get_item", "get_item_by_path"])
def test_item_404_is_none(helper):
    g, _, _ = make_client([graph_error(404, "itemNotFound")])
    fn = getattr(graph, helper)
    args = ("d", "i", ALICE_UPN) if helper == "get_item" else ("d", "root", "n", ALICE_UPN)
    assert fn(g, *args) is None


@pytest.mark.parametrize("replace, behavior", [(False, "fail"), (True, "replace")])
def test_upload_file(replace, behavior):
    item = {"id": "i", "name": "rp-canary-01.pdf", "size": 3, "parentReference": {"id": "p"}}
    g, transport, _ = make_client([json_response(201, item)])
    got = graph.upload_file(g, SHAREPOINT_DRIVE_ID, "root", "rp-canary-01.pdf", b"%PD", replace=replace, owner="a@x")
    assert got == item
    (req,) = transport.requests
    assert req.method == "PUT"
    assert req.url == (
        f"{GRAPH_BASE}/drives/{SHAREPOINT_DRIVE_ID}/items/root:/rp-canary-01.pdf:/content"
        f"?@microsoft.graph.conflictBehavior={behavior}"
    )
    assert req.headers["Content-Type"] == "application/octet-stream"
    assert req.body == b"%PD"


def test_upload_conflict_says_use_force(capsys):
    g, _, _ = make_client([graph_error(409, "nameAlreadyExists", "Name already exists")])
    with pytest.raises(GraphError) as info:
        graph.upload_file(g, "d", "root", "rp-canary-01.pdf", b"x", replace=False, owner=ALICE_UPN)
    assert info.value.status == 409
    msg = str(info.value)
    assert "rp-canary-01.pdf already exists" in msg
    assert "re-run with --force to replace" in msg
    assert_no_leak(info.value, capsys)


@pytest.mark.parametrize("first", UNKNOWN_OUTCOME, ids=UNKNOWN_OUTCOME_IDS)
def test_send_mail_is_sent_once_when_the_outcome_is_unknown(first, capsys):
    g, transport, sleeps = make_client([first, HttpResponse(202)], account="admin@x")
    with pytest.raises(graph.GraphOutcomeUnknown) as info:
        graph.send_mail(g, subject="RP-CANARY-0001", body_text="b", to_address=ALICE_UPN)
    assert len(transport.requests) == 1
    assert sleeps == []
    msg = str(info.value)
    assert "POST /me/sendMail as admin@x" in msg
    assert "RP-CANARY-0001 may have been sent" in msg
    assert "run seed again" in msg and "not sent twice" in msg
    assert (info.value.method, info.value.path) == ("POST", "/me/sendMail")
    assert_no_leak(info.value, capsys)


def test_send_mail_retries_429():
    g, transport, sleeps = make_client([graph_error(429, headers={"retry-after": "3"}), HttpResponse(202)])
    graph.send_mail(g, subject="s", body_text="b", to_address="t@x")
    assert len(transport.requests) == 2
    assert sleeps == [3]


@pytest.mark.parametrize("first", UNKNOWN_OUTCOME, ids=UNKNOWN_OUTCOME_IDS)
def test_upload_that_fails_on_conflict_is_sent_once_when_the_outcome_is_unknown(first, capsys):
    g, transport, sleeps = make_client([first, graph_error(409, "nameAlreadyExists")])
    with pytest.raises(graph.GraphOutcomeUnknown) as info:
        graph.upload_file(g, "d", "root", "rp-canary-01.pdf", b"x", replace=False, owner=ALICE_UPN)
    assert len(transport.requests) == 1
    assert sleeps == []
    msg = str(info.value)
    assert "rp-canary-01.pdf may have been uploaded" in msg
    assert "run seed again" in msg and "not uploaded twice" in msg
    assert "--force" not in msg
    assert_no_leak(info.value, capsys)


def test_upload_that_fails_on_conflict_retries_429():
    item = {"id": "i"}
    g, transport, sleeps = make_client([graph_error(429), json_response(201, item)])
    assert graph.upload_file(g, "d", "root", "n", b"x", replace=False, owner=ALICE_UPN) == item
    assert len(transport.requests) == 2
    assert sleeps == [2]


@pytest.mark.parametrize("first", UNKNOWN_OUTCOME, ids=UNKNOWN_OUTCOME_IDS)
def test_upload_that_replaces_is_retried(first):
    # conflictBehavior=replace: sending it twice leaves the same file, so it is retried.
    item = {"id": "i"}
    g, transport, sleeps = make_client([first, json_response(200, item)])
    assert graph.upload_file(g, "d", "root", "n", b"x", replace=True, owner=ALICE_UPN) == item
    assert len(transport.requests) == 2
    assert len(sleeps) == 1


def test_download_item_returns_bytes():
    g, transport, _ = make_client([HttpResponse(200, b"\x89PNG\x00")])
    assert graph.download_item(g, ONEDRIVE_DRIVE_ID, "01X", ALICE_UPN) == b"\x89PNG\x00"
    (req,) = transport.requests
    assert (req.method, req.url) == ("GET", f"{GRAPH_BASE}/drives/{ONEDRIVE_DRIVE_ID}/items/01X/content")


def test_post_json_and_put_bytes_primitives():
    g, transport, _ = make_client([HttpResponse(201, b"{}"), json_response(200, {"id": "x"})])
    assert g.post_json("/a", {"b": 1}).status == 201
    assert g.put_bytes("/c", b"z", params={"q": "1"}) == {"id": "x"}
    first, second = transport.requests
    assert json.loads(first.body) == {"b": 1}
    assert second.url == f"{GRAPH_BASE}/c?q=1"
    assert second.headers["Content-Type"] == "application/octet-stream"


def test_get_bytes_primitive():
    g, _, _ = make_client([HttpResponse(200, b"raw")])
    assert g.get_bytes("/x") == b"raw"
