# Graph and Entra fixtures

Recorded replies from Microsoft Entra's token endpoint and Microsoft Graph, served by
`FakeHttpClient` in the GraphClient tests (`worker/tests/graph_client_test.cpp`, W2.1 and
later). The live ones were recorded on 2026-09-28 against the lab tenant by
`uv run python -m seeder record-graph-fixtures` (`lab/README.md`), signed in as the
"RestoreProof Worker" app the way the Worker does: PS256, header `x5t#S256`. The rest are
hand-written, for replies the lab can't provoke; their `source` says so.

## Format

One JSON object per file, as in `../veeam/README.md`:

```json
{
  "source": "live 2026-09-28: token request, PS256 header ['x5t#S256']",
  "request": "POST /bcd6bd1a-ea42-489d-aa28-2c19a44ad146/oauth2/v2.0/token",
  "status": 200,
  "headers": { "Content-Type": "application/json; charset=utf-8", "x-ms-request-id": "..." },
  "body": { "...": "the recorded response body" }
}
```

- `source`: `live <date>: <what was sent>`, or `hand-written: <what it stands for and why>`.
- `request`: method and path (with query string) of the call. Documentation only: tests
  route by the URL they build themselves.
- `status`: the HTTP status.
- `headers`: only `Content-Type`, `WWW-Authenticate`, `Retry-After`, `Location`,
  `request-id`, `client-request-id` and `x-ms-request-id`, when the reply had them. The
  request IDs are what `GraphError::request_id()` reports.
- `body`: `null` means an empty body. A string is raw text. An object or array is JSON; the
  fake sends it compactly serialised.

No secret is kept. The token reply's `access_token` is a fake unsigned JWT
(`eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0.`); tests put their own token
in its place. No file holds a client assertion or anything JWT-shaped beyond that: the
recorder refuses to write one, and `lab/tests/test_graph_fixtures.py` checks every file here
the same way, hand-written ones included. Tenant and app IDs, UPNs, request and trace IDs are
real lab values.

## Files

| Fixture | Source | For |
|---|---|---|
| `token-200.json` | live: a token request | the token reply: `token_type` Bearer, `expires_in` 3599 |
| `token-bad-signature-401.json` | live: an assertion signed by a key Entra doesn't know | 401 `invalid_client` AADSTS700027 → `AuthError`, the certificate hint, not retried |
| `token-unknown-thumbprint-401.json` | live: an `x5t#S256` of no uploaded certificate | 401 `invalid_client` AADSTS700027 → `AuthError`, the certificate hint |
| `token-unknown-app-400.json` | live: a client ID of no app | 400 `unauthorized_client` AADSTS700016 → `AuthError`, "check graph_client_id and graph_tenant_id" |
| `token-unknown-tenant-400.json` | live: a tenant ID of no tenant | 400 `invalid_request` AADSTS90002 → `AuthError`, "check graph_tenant_id" |
| `token-expired-assertion-401.json` | live: an assertion that expired an hour ago | 401 `invalid_client` AADSTS700024 → `AuthError`, the clock hint |
| `token-future-assertion-401.json` | live: an assertion valid only from an hour ahead | 401 `invalid_client` AADSTS700024 → `AuthError`, the clock hint |
| `token-429-retry-after.json` | hand-written: Entra throttling, as documented (empty body, `Retry-After: 60`) | 429 → `TransientError`, retried after the Retry-After |
| `token-503-temporarily-unavailable.json` | hand-written: Entra's reply shape with the transient AADSTS90033 | 503 `temporarily_unavailable` → `TransientError`, retried |
| `token-500-html.json` | hand-written: a proxy's HTML error page | a 5xx that isn't JSON → `TransientError`; the body is never quoted |
| `token-302-redirect.json` | hand-written: a redirect from the token endpoint | 3xx → `GraphError`, nothing sent to its `Location` |
| `messages-200.json` | live: the restoretest inbox, `$top=1&$select=id` | a GET that works (`value: []`): `get()`, `get_json()`, the token's reuse and renewal |
| `messages-403-exchange.json` | live: alice's inbox, outside the Exchange RBAC scope | 403 `ErrorAccessDenied` → `PermissionError` naming the Mail grant; no innerError: the request ID comes from the headers |
| `messages-404-unknown-user.json` | live: the inbox of a user who doesn't exist | 404 `ErrorInvalidUser` → `NotFoundError` |
| `site-403-accessdenied.json` | live: the tenant root site, no Sites.Selected grant on it | 403 `accessDenied` → `PermissionError` naming the Sites grant; innerError: the request ID comes from the body |
| `users-403-requestdenied.json` | live: `GET /users`, no directory role | 403 `Authorization_RequestDenied` → `PermissionError` naming the grant |
| `api-invalid-token-401.json` | live: a GET with a malformed bearer token | 401 `InvalidAuthenticationToken` with WWW-Authenticate → one new token, then `AuthError` |
| `api-no-token-401.json` | live: a GET without Authorization | 401 `InvalidAuthenticationToken` with WWW-Authenticate → one new token, then `AuthError` |
| `api-insufficient-claims-401.json` | hand-written: a claims challenge (`error="insufficient_claims"` in WWW-Authenticate), as Conditional Access or continuous access evaluation sends it | 401 → `AuthError` at once, no new token |
| `messages-404-mailbox-not-enabled.json` | hand-written: `MailboxNotEnabledForRESTAPI`, what Graph says for a mailbox without an Exchange Online licence, inactive or on-premises | 404 → a plain `GraphError`, not `NotFoundError` |
| `messages-429-throttled.json` | hand-written: Graph throttling a mailbox (`ApplicationThrottled`, `Retry-After: 3`) | 429 → retried after the Retry-After, then `TransientError` |
| `messages-503-unavailable.json` | hand-written: Graph briefly unavailable (`serviceNotAvailable`, `Retry-After: 10`) | 503 → retried after the Retry-After, then `TransientError` |
| `onedrive-folder-403-accessdenied.json` | hand-written: a 403 on the OneDrive folder in the recorded `site-403-accessdenied.json` shape; SharePoint masks an ungranted item as 404 (L1.5), so the lab can't provoke one read-only | 403 `accessDenied` → `PermissionError` naming the OneDrive grant (W2.2) |
| `onedrive-folder-404-itemnotfound.json` | hand-written: stand-in until the empty state is recorded (W2.2): an item ID of no item in alice's OneDrive | 404 `itemNotFound` → `NotFoundError` (W2.2) |
| `restoretarget-content-302.json` | hand-written: stand-in until the one-item state is recorded (W2.2): a file's `/content` in the RestoreTarget library, redirect not followed, `Location` scrubbed | 302 → the download follows `Location` without the token (W2.2) |
| `onedrive-content-302.json` | hand-written: stand-in until the one-item state is recorded (W2.2): a file's `/content` in alice's `/RestoreTarget`, redirect not followed, `Location` scrubbed | 302 on the `-my` host → the download follows `Location` without the token (W2.2) |

Entra's refusals that the lab can't provoke (Conditional Access, a disabled app, the other
transient codes) are built in `graph_client_test.cpp` from `entra_error()`, in the recorded
shape, rather than kept as files.

Graph replies that only vary a recorded one (another status, Retry-After or WWW-Authenticate
value, a redirect, a body that isn't JSON, a page with `@odata.nextLink`) are built in the
test from `make_response()` or an edited fixture, rather than kept as files.
