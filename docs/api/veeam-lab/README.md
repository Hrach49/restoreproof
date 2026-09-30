# Veeam REST evidence (L1.6, W1.0, W1.4, W2.4, W2.5)

Raw, scrubbed request/response pairs from the lab Veeam server (VB365 8.6, REST v8), recorded
on 2026-09-25/26: L1.6 and W1.0 for `docs/api/veeam-feasibility.md`, W1.4 for
`docs/api/veeam-notes.md` (made by the scripts in `docs/api/veeam-m365/`). W1.5 turns them into
`worker/tests/fixtures/veeam/` fixtures (the list is in `veeam-notes.md` §9). W2.4's restores,
recorded on 2026-09-28 by `docs/api/veeam-m365/10-restore.ps1`, are for
`docs/api/veeam-restore-flow.md`. W2.5's three files are the Worker's own live restore of
2026-09-30 (below); they are not in the call format.

## Format

One JSON file per call:

```jsonc
{
  "note": "who called what, and why",
  "captured_utc": "2026-09-26T14:24:04.014Z",
  "duration_ms": 1204,
  "request":  { "method": "POST", "path": "/v8/token", "body": { … } | "form=…" | null },
  "response": { "status": 200, "content_type": "…", "headers": { … }, "body": { … } | "text" | null }
}
```

`response.body` is `"<N bytes written to file>"` for downloads (MSG, PDF, DOCX); the files
themselves are not kept. `l1.6-operator-admin-sweep.json` and
`w1.0-b-operator-orphan-session-probe.json` are summaries of several calls.

## Scrubbing

Replaced with `"[REDACTED]"` before writing:

- the values of `access_token`, `refresh_token`, `id_token`, `password`, `userPassword`,
  `assertion`, `applicationCertificate`, `applicationCertificatePassword`, `client_secret`,
  `token`, `device_code`, in JSON and in form bodies;
- anything shaped like a JWT, and bearer values.

`Set-Cookie` and `Authorization` headers are dropped. W1.0's bearer rule also caught the
`WWW-Authenticate: Bearer error="invalid_token"` header (it reads `Bearer [REDACTED]"invalid_token"`
in `w1.0-a-restart-admin-access`); W1.4's rule only replaces token-length values, so the header
is intact in the `w1.4-auth-*` files. Every file was then checked against the
literal values of every secret used in the session (passwords, tokens, the certificate), and
for JWT and PFX patterns: no matches. Account names, object IDs and item names of the lab
tenant are not secret (`lab/tenant.md`) and are kept.

## Names

`<task>-<check>-<what>.json`: `l1.6-…` for the two accounts, `w1.0-a-…` refresh tokens,
`w1.0-b-…` operator scope, `w1.0-c-<mail|sp|od>-<cert|user|none>-…` admin restore bodies
(`-explore`, `-restore`, `-session`, `-statistics`, `-events`; `none` = no credentials,
refused with 400), `w1.0-d-…` export. Some
first attempts are kept under a suffix that names the outcome
(`-no-folder-400`, `-no-casserver-400`, `-antiforgery-500`, `-after-restart`).

Two operator grants show why a flag matters:

- `w1.0-a-operator-token` (14:20) was made without `disable_antiforgery_token`, and its
  refresh failed;
- `w1.0-a-operator-token-no-antiforgery` (14:24) is chain A, whose t0 refresh is
  `w1.0-a-operator-refresh-t0`.

The 48 h and 7-day refreshes will add `w1.0-a-operator-refresh-48h` and `-7d`.

W1.4 files are `w1.4-<area>-<what>.json`, with `<area>` one of `auth`, `org`, `rp` (restore
points), `session`, `mail`, `sp`, `od` and `sweep`. A suffix names an error case
(`-401`, `-404`, `-409`, `-400`, `-unknown`, `-bad-…`), and `w1.4-session-explore-<case>` is one
`dateTime` case of `veeam-notes.md` §4.2. They are written with `System.Text.Json`, so values
(timestamps especially) are byte-for-byte what Veeam sent. Before commit they were audited with
`docs/api/veeam-m365/audit-evidence.ps1` against every password and token value used, and for
JWT, bearer, PFX and PEM patterns: no hits. The W1.4 run left no explore session open
(`w1.4-sweep-list`).

## W2.4 restores

W2.4 files are `w2.4-<type>-<tag>-<what>.json`, one set per run of `10-restore.ps1`. `<type>` is
`mail`, `sp` or `od`; `<tag>` is `x1` (one item), `x5` (five items in one restore call) or `r1`
(one item, the committed script after the W2.4 review). The first four runs, from the restore
point of 2026-09-27T22:00:48Z, were made with an earlier revision of the script; `mail-r1`, from
the point of 2026-09-28T22:00:53Z, with the committed one. All `Success`:

| Run | Items | Source → target | Restore session |
|---|---|---|---|
| `mail-x1` | RP-CANARY-0011 | bob's Inbox → restoretest's Inbox | [`w2.4-mail-x1-session`](w2.4-mail-x1-session.json) |
| `sp-x1` | rp-canary-06.pdf | RestoreTest library → RestoreTarget library | [`w2.4-sp-x1-session`](w2.4-sp-x1-session.json) |
| `od-x1` | rp-canary-16.pdf | alice's `/RestoreTest` → alice's `/RestoreTarget` | [`w2.4-od-x1-session`](w2.4-od-x1-session.json) |
| `mail-x5` | RP-CANARY-0002 to 0006 | alice's Inbox → restoretest's Inbox | [`w2.4-mail-x5-session`](w2.4-mail-x5-session.json) |
| `mail-r1` | RP-CANARY-0011 | bob's Inbox → restoretest's Inbox | [`w2.4-mail-r1-session`](w2.4-mail-r1-session.json) |

`<what>`, in the order the script makes the calls:

| `<what>` | Call |
|---|---|
| `sweep-before` | `GET /v8/RestoreSessions?limit=200`: preflight, no rp-veeam session still `Working` |
| `org` | `GET /v8/Organizations`: the organisation app and certificate thumbprint used as restore credential |
| `explore` | `POST /v8/Organizations/{id}/explore` at the newest `backupTime` (`Vex`, `Vesp` or `Veod`) |
| `mailboxes`, `folder-inbox`, `items`, `item` | mail: the source mailbox, its Inbox, the Inbox's items, the first item re-read by ID |
| `sites`, `libraries`, `documents`, `document` | SharePoint: the RestoreTest site, its libraries, the canary library's documents, the first document re-read |
| `onedrives`, `folders-root`, `documents`, `document` | OneDrive: alice's OneDrive, its root folders, `/RestoreTest`'s documents, the first document re-read |
| `restore` | the restore POST (`.../items/restoreTo`, `.../Documents/restoreTo` or `.../Documents/copyTo`) and its `200 {sessionId}` |
| `sessions-after-post` | `GET /v8/RestoreSessions?startTimeFrom=…&orderBy=CreationTime&orderAsc=false&limit=50`: the duplicate check, exactly one new session each time |
| `session-working` | the restore session, first seen `Working` |
| `session` | the restore session, `Stopped`, with `result` and `details` |
| `statistics` | `GET /v8/RestoreSessions/{id}/Statistics` |
| `events` | `GET /v8/RestoreSessions/{id}/Events?limit=100`: one `Restore` event per item |

The script can also write `restore-<status>` (a restore POST that failed), `sessions-after-timeout`
(a later duplicate check after a POST without an answer) and `statistics-409` (statistics not
ready yet after `Stopped`); none of the four runs did.

The restore bodies carry the certificate and its one-time password; both read `"[REDACTED]"` in
the `restore` files. The script also scrubs the exported PFX's Base64. Before commit the 52 files
were audited with `audit-evidence.ps1 -Path ..\veeam-lab\w2.4-*.json` against rp-veeam's
password, every token and the one-time PFX passwords, and for JWT, bearer, PFX and PEM patterns:
no hits. Each run stops its explore session in its `finally` block.

## W2.5 live restore

The Worker's first live restore, 2026-09-30 07:35:12Z–07:37:39Z: `rptests.exe "[live][writes]"`
(`worker/tests/veeam_m365_restore_live_test.cpp`, `docs/testing.md`, "Live restore") restored 5
mails, 3 SharePoint files and 2 OneDrive files from the restore point of
2026-09-29T22:00:45.6603083Z through `restore_sample`, in three restore sessions, all `Success`
(`docs/api/veeam-restore-flow.md` §19). The Worker writes no per-call files, so these are not
in the call format above:

| File | What it is |
|---|---|
| [`w2.5-live-restore-result.json`](w2.5-live-restore-result.json) | the `RestoreResult` as JSON, written by the test through `RP_LIVE_EVIDENCE_FILE`: status, restore point, one entry per restore session and per item, the log |
| [`w2.5-live-console.txt`](w2.5-live-console.txt) | the test's console output, text |
| [`w2.5-live-graph-list-hash.txt`](w2.5-live-graph-list-hash.txt) | `rpworker graph list --hash` right after it, text: the 10 items in the three targets with their SHA-256 |

No credential reaches any of them (the `RestoreResult` holds none). Before commit the three
files were audited with `audit-evidence.ps1`: no hits.
