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

### W2.5: the recorded restore runs (`restore_sample`)

Every call W2.4's `10-restore.ps1` made around the four restore POSTs above, one fixture per
step, so W2.5's tests can replay a whole run: `w24-<run>-<step>.json` from
`w2.4-<run>-<step>.json`, for the runs `mail-x5` (five mails, one call), `mail-x1`, `sp-x1` and
`od-x1` (one item each). The restore POST of each run is the `restore-*-200.json` above
(`mail-x5` → `restore-mail-x5-200`, `mail-x1` → `restore-mail-200`, `sp-x1` →
`restore-sp-200`, `od-x1` → `restore-od-200`). Each run's `request` is the path as recorded,
query included; the IDs in it are that run's own explore and restore sessions.

| Step | Request (per run) | Runs |
|---|---|---|
| `org` | `GET /v8/Organizations` (both org apps, thumbprint only) | all |
| `sweep-before` | `GET /v8/RestoreSessions?limit=200` (the preflight) | all |
| `explore` | `POST /v8/Organizations/{org}/explore` → 201, the explore session | all |
| `mailboxes` | `GET .../organization/mailboxes?limit=1000` | mail |
| `folder-inbox` | `GET .../mailboxes/{m}/folders?name=Inbox` | mail |
| `items` | `GET .../mailboxes/{m}/items?parentId={folder}&limit=1000` | mail |
| `item` | `GET .../mailboxes/{m}/items/{item}` (the re-read) | mail |
| `sites` | `GET .../Organization/Sites?parentId=root&limit=1000` | sp |
| `libraries` | `GET .../Organization/Sites/{site}/Libraries` | sp |
| `onedrives` | `GET .../Organization/OneDrives?limit=1000` | od |
| `folders-root` | `GET .../OneDrives/{od}/Folders?parentId=root` | od |
| `documents` | `GET .../{Sites/{site}\|OneDrives/{od}}/Documents?parentId={parent}&limit=1000` | sp, od |
| `document` | `GET .../Documents/{doc}` (the re-read) | sp, od |
| `sessions-after-post` | `GET /v8/RestoreSessions?startTimeFrom=...&orderBy=CreationTime&orderAsc=false&limit=50` (the duplicate check) | all |
| `session-working` | `GET /v8/RestoreSessions/{r}`, `state` `Working` | all |
| `session` | `GET /v8/RestoreSessions/{r}`, `state` `Stopped`, `result` `Success` | all |
| `statistics` | `GET /v8/RestoreSessions/{r}/Statistics` | all |
| `events` | `GET /v8/RestoreSessions/{r}/Events?limit=100` | all |

The script's paging (`limit=1000`) and its browse calls differ from W2.5's in places (no
`GET .../Sites/{site}` or `Folders?parentId=` below the root was recorded, and the SharePoint
document sat in the library root); tests route by path and serve these bodies where the shape
matches.

Failure sets from W1.0 (`w1.0-c-*`, a restore with the user's credentials that Veeam
accepted and then failed; see `docs/api/veeam-feasibility.md`), for the verdict and the
infrastructure classification:

| Fixture | Source (`docs/api/veeam-lab/`) | For |
|---|---|---|
| `w10-mail-user-session.json` | `w1.0-c-mail-user-session.json` | `Stopped`, `result` `Failed`, `0 items processed` |
| `w10-mail-user-statistics.json` | `w1.0-c-mail-user-statistics.json` | 0 restored; `errors[]` "Failed to open mailbox" → infrastructure |
| `w10-mail-user-events.json` | `w1.0-c-mail-user-events.json` | `Failed` events, "Failed to open mailbox" |
| `w10-sp-user-session.json` | `w1.0-c-sp-user-session.json` | `Stopped`, `Failed` |
| `w10-sp-user-statistics.json` | `w1.0-c-sp-user-statistics.json` | 0 restored; `errors[]` "Cannot connect to Microsoft 365" |
| `w10-sp-user-events.json` | `w1.0-c-sp-user-events.json` | `Failed` events, "Cannot connect to Microsoft 365" |
| `w10-od-user-session.json` | `w1.0-c-od-user-session.json` | `Stopped`, `Failed` |
| `w10-od-user-statistics.json` | `w1.0-c-od-user-statistics.json` | 0 restored, no `errors[]`: the reason is only in the events |
| `w10-od-user-events.json` | `w1.0-c-od-user-events.json` | `Failed` event, "Cannot connect to Microsoft 365" |
| `w10-mail-restore-400-no-folder.json` | `w1.0-c-mail-cert-restore-no-folder-400.json` | restore POST refused: 400 `ParameterValidationFailure` (no `folder`) → nothing started |
| `w10-mail-restore-400-no-casserver.json` | `w1.0-c-mail-user-restore-no-casserver-400.json` | restore POST refused: 400 `ParameterValidationFailure` (`CasServer`) |

The two `w10-mail-restore-400-*` fixtures also carry `request_body` (the refused POST's body,
credentials `[REDACTED]`), as documentation only: they are not restore bodies the guard should
accept (one has no `folder`, the other uses the user-credential fields).

### W2.6: the candidate lister (`list_candidates`)

`veeam_m365_candidates_test.cpp` replays the W2.4 explore sessions and containers above
(`w24-*-explore`, `-mailboxes`, `-sites`, `-libraries`, `-onedrives`, `-folders-root`) and three
W1.4 recordings the W2.4 runs didn't make:

| Fixture | Source (`docs/api/veeam-lab/`) | For |
|---|---|---|
| `w26-org-users.json` | `w1.4-org-users.json` | `GET /v8/Organizations/{org}/Users`: the six users, `name` the UPN a OneDrive's owner is found by |
| `w26-mail-folders.json` | `w1.4-mail-folders.json` | `GET .../mailboxes/{m}/folders` (no `parentId`): all 14 of alice's folders, flattened, for the folder-name uniqueness check |
| `w26-mail-folders-root.json` | `w1.4-mail-folders-root.json` | `GET .../mailboxes/{m}/folders?parentId=root`: the 13 top-level folders, their `type` and `category` |

No recording holds a real item (every mail and file in them is a canary), so the items the
tests list are synthetic: built in the test from a recorded entry (`w24-mail-x5-items`,
`w24-sp-x1-documents`, `w24-od-x1-documents`, `w24-od-x1-folders-root`) with the ID, name,
subject, class, time or size changed. None of them is saved here as if recorded.

`rest-certificate.pem` is not a response: it is the lab's Veeam REST certificate (public, as
every TLS client sees it; no private key), exported on the Veeam server with
`ExportCertificatePem()`. `cert_pin_test.cpp` checks `rp::public_key_pin` against the two
hashes .NET computed for it there: SHA-256 `9FB19E0E…A213` and public-key pin
`jSOf+h9iDQY3dg41YdNXwUU7XTKxMeNbPlcqP1xhD0Q=`.
