# Veeam REST fixtures

Recorded responses from the Veeam Backup for Microsoft 365 REST API (v8), taken from the
W1.4, L1.6 and W2.4 lab evidence in `docs/api/veeam-lab/`. The evidence was already scrubbed
before it was committed. `FakeHttpClient` serves these files in the VeeamClient tests (W1.5
and later). The mapping and what each call does are in `docs/api/veeam-notes.md` §9.

## Format

One JSON object per file:

```json
{
  "source": "docs/api/veeam-lab/w1.4-auth-token.json",
  "request": "POST /v8/token",
  "status": 200,
  "headers": { "Content-Type": "application/json; charset=utf-8" },
  "body": { "...": "the recorded response body, unchanged" }
}
```

- `source`: the evidence file the response was copied from.
- `request`: method and path (with query string) of the recorded call. Documentation only,
  except in the five restore fixtures named below: there it is exactly `POST <path>` as sent,
  and the W2.7 guard tests take the path they check from it (the text after `POST `), with
  the restore kind, explore session and container read from its segments. Re-record them
  with that form, or every guard test built on them fails on the path.
- `status`: the HTTP status Veeam returned.
- `headers`: only `Content-Type` and `WWW-Authenticate`, when the response had them.
  `{}` when it had neither.
- `body`: `null` means an empty body. A string is raw text. An object or array is JSON;
  the fake sends it compactly serialised.
- `request_body` (only `restore-mail-200`, `restore-sp-200`, `restore-od-200`,
  `restore-mail-x5-200` and `restore-mail-r1-200`, W2.4's restore POSTs): the body the
  recorded POST sent, unchanged from the evidence's `request.body`, credentials `[REDACTED]`.
  Documentation for the fake; the target guard's tests (W2.7) and W2.5's check the exact
  body against it.

Tokens are `[REDACTED]`, as in the evidence. Tests substitute their own values where they
need a token. Organisation, restore point and session IDs, names and times are real lab
values and are kept as recorded: they exercise the composite-ID handling.

## Files

| Fixture | Source (`docs/api/veeam-lab/`) | For |
|---|---|---|
| `token-200.json` | `w1.4-auth-token.json` | login parses tokens and `expires_in` |
| `token-refresh-200.json` | `w1.4-auth-refresh.json` | refresh stores the new refresh token |
| `token-refresh-invalid-401.json` | `w1.4-auth-refresh-reuse-401.json` | refresh failure → password grant |
| `token-rejected-401.json` | `l1.6-admin-token-wrong-password-traced.json` | wrong credentials → `AuthError` |
| `token-rejected-500-empty.json` | `l1.6-admin-token-wrong-password.json` | empty 500 on `/v8/token` → `AuthError`, no retry |
| `api-invalid-token-401.json` | `w1.4-auth-pre-refresh-access.json` | 401 on an API call → re-login once, resend |
| `api-expired-token-401.json` | `w1.4-auth-expired-access-401.json` | 401 on an API call → re-login once, resend |
| `logout-204.json` | `w1.4-auth-logout.json` | logout |
| `health-200.json` | `w1.4-auth-health.json` | doctor |
| `organizations-200.json` | `w1.4-org-list.json` | `listOrganizations()` → `{id, name}` |
| `organization-200.json` | `w1.4-org-get-extended.json` | org details (msid, region, officeName) |
| `organization-404.json` | `w1.4-org-get-unknown-404.json` | `ResourceNotFound` → `NotFoundError` (a `VeeamError`) |
| `restore-points-200.json` | `w1.4-rp-list-org.json` | `listRestorePoints()` sorted newest first, raw `backupTime` kept |
| `restore-points-asc-200.json` | `w1.4-rp-list-asc.json` | sorting doesn't rely on server order |
| `restore-points-empty-200.json` | `w1.4-rp-list-empty.json` | no point → caller reports `error` |
| `restore-points-page1.json` | `w1.4-rp-list-limit1.json` | paging: the first full page of limit=1 |
| `restore-points-page2.json` | `w1.4-rp-list-limit1-offset1.json` | paging: the second page is full too, so the client asks for a third (the tests serve `restore-points-empty-200` there) |
| `restore-points-unknown-org-404.json` | `w1.4-rp-list-unknown-org.json` | `ResourceNotFound` for an unknown organisation → `NotFoundError` |
| `restore-point-400-format.json` | `w1.4-rp-get-bare-id.json` | 400 `ParameterValidationFailure` → `VeeamError` |
| `restore-points-bad-query-400.json` | `w1.4-rp-list-bad-from.json` | ProblemDetails body parses |
| `explore-201.json` | `w1.4-session-explore.json` | W2.x: explore |
| `explore-500-before-first.json` | `w1.4-session-explore-before.json` | W2.x: 500 with a message → `VeeamError`, not retried |
| `explore-500-not-utc.json` | `w1.4-session-explore-nooffset.json` | W2.x: 500 with a message → `VeeamError`, not retried |
| `session-working.json` | `w1.4-session-get.json` | W2.x polling |
| `session-stopped.json` | `w1.4-session-get-stopped.json` | W2.x polling; `endTime` without `Z` parses |
| `stop-204.json` | `w1.4-session-stop.json` | W2.x: stop the session |
| `statistics-409.json` | `w1.4-session-statistics-working-409.json` | W2.x: 409 = keep polling |
| `sessions-list.json` | `w1.4-sweep-list.json` | W2.x: the sweep picks only `Working` + own `initiatedBy` |
| `route-404-empty.json` | `w1.4-rp-guide-path-404.json` | a route that doesn't exist: empty 404 → `VeeamError` |
| `restore-mail-200.json` | `w2.4-mail-x1-restore.json` | W2.7/W2.5: mail `restoreTo`, one item; the guard accepts the path and body as sent |
| `restore-sp-200.json` | `w2.4-sp-x1-restore.json` | W2.7/W2.5: SharePoint `restoreTo`, one file |
| `restore-od-200.json` | `w2.4-od-x1-restore.json` | W2.7/W2.5: OneDrive `copyTo`, one file |
| `restore-mail-x5-200.json` | `w2.4-mail-x5-restore.json` | W2.7/W2.5: five items in one call; a duplicated item with the count unchanged |
| `restore-mail-r1-200.json` | `w2.4-mail-r1-restore.json` | W2.7: the body of the committed `10-restore.ps1` (W2.4 review) |

`rest-certificate.pem` is not a response: it is the lab's Veeam REST certificate (public, as
every TLS client sees it; no private key), exported on the Veeam server with
`ExportCertificatePem()`. `cert_pin_test.cpp` checks `rp::public_key_pin` against the two
hashes .NET computed for it there: SHA-256 `9FB19E0E…A213` and public-key pin
`jSOf+h9iDQY3dg41YdNXwUU7XTKxMeNbPlcqP1xhD0Q=`.
