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

## W2.8 live restore (`rpworker restore`)

W2.8's "Done when", 2026-09-30 21:42:43Z–21:45:22Z: `rpworker restore --mail 5 --sp 5 --od 5`
(`docs/testing.md`, "Restore by hand", from an elevated PowerShell 7) chose run
`rp-20260930T214243Z-6138257d` (seed `59bd6f19`, canary cursor `0,0,0` -> `3,3,3`) on the restore
point of 2026-09-29T22:00:45.6603083Z: 3 canaries of each type and 2 random mails from real
data; the SharePoint and OneDrive random halves were short (no non-canary files in the lab), as
recorded in the header. It restored 11 of 11 items in four restore sessions, all `Success`, status
`succeeded`, exit 0, in 2:28. The read-back right after showed exactly these 11 items in the three
targets, so nothing else was there. Against `lab/seed-manifest.json`: the three canary mails'
`text-v1` hashes equal `body_sha256`; both PDFs and the OneDrive docx and xlsx equal
`stored_sha256` byte for byte; the SharePoint docx and xlsx differ in bytes, as SharePoint
rewrites Office files (their check is `office-v1`, W3.2). The OneDrive events' `source` names
the destination path (`…/Documents/RestoreTarget/…`), as W2.4 recorded
(`docs/api/veeam-restore-flow.md`).

| File | What it is |
|---|---|
| [`w2.8-live-restore.txt`](w2.8-live-restore.txt) | the command's output and exit code, as the console showed them |
| [`w2.8-live-graph-list-hash.txt`](w2.8-live-graph-list-hash.txt) | `rpworker graph list --hash` right after it: the 11 items with their SHA-256 |

Neither holds a credential: the command prints none. The copies stay in the targets until
removed by hand (W3.4).

## W3.2 live run (`rpworker restore` with the check)

W3.2's "Done when" for a live run, 2026-10-01, from an elevated Windows PowerShell with the lab
config (`%LOCALAPPDATA%\RestoreProof\lab\config.json`) and `--record`, on the restore point of
2026-09-30T22:00:43.4764524Z, canary cursor `0,0,0`:

- **Run 1** (`rp-20261001T172150Z-b029c118`, the targets empty before it): 3 canaries of each
  type and 2 random mails (the file random halves short, as in W2.8), 11 of 11 restored in four
  `Success` sessions, and the check read all 11 back: **11 match**, 0 mismatch, 0 missing, 0
  error, exit 0. The SharePoint docx and xlsx, which SharePoint rewrites, matched by
  `office-v1`; everything else by `text-v1` or `bytes`.
- **Run 2** (`rp-20261001T172434Z-999c6dea`): stopped while choosing the sample, before any
  restore: Veeam didn't answer a Stop of an explore session within 30 s, twice, and the command
  refused to go on (`restore error: ... couldn't be stopped ...; nothing was listed`, exit 4).
  The session read `Stopped` a few minutes later (`08-sweep-sessions.ps1 -WhatIf`: none
  Working).
- **Run 2b** (`rp-20261001T172815Z-6285c4a6`, the same canaries again, over run 1's copies):
  11 of 11 "restored" in four `Success` sessions. **Files**: all 6 `match`, and none counted as
  an earlier copy: a restore over a same-named file moves its `cTag` (the W3.2 decision's open
  check), the OneDrive pdf, docx and xlsx included, whose bytes didn't change. **Mails**: Veeam
  said each was "restored successfully", but the Inbox kept run 1's five copies with the same
  Graph IDs and no new one: Veeam leaves a mail that is already in the target as it is. The
  build then reported the five as `missing` (exit 5), which would have been a `fail` for an
  unclean target; fixed the same day (commit 6fd89e9): such an item is `error` `stale_target`.

| File | What it is |
|---|---|
| [`w3.2-live-1-graph-list-before.txt`](w3.2-live-1-graph-list-before.txt) | `rpworker graph list` before run 1: the three targets empty |
| [`w3.2-live-2-restore-run1.txt`](w3.2-live-2-restore-run1.txt) | run 1's output and exit code: the restore and the check, 11 match |
| [`w3.2-live-3-restore-run2-veeam-timeout.txt`](w3.2-live-3-restore-run2-veeam-timeout.txt) | run 2: Veeam's explore session Stop timing out, nothing restored |
| [`w3.2-live-4-graph-list-after-run1.txt`](w3.2-live-4-graph-list-after-run1.txt) | `rpworker graph list --hash` after run 1 (and run 2, which wrote nothing) |
| [`w3.2-live-5-restore-run2b.txt`](w3.2-live-5-restore-run2b.txt) | run 2b's output: 6 files match, 5 mails `missing` before the fix (stderr lines interleaved by the console) |
| [`w3.2-live-6-graph-list-after-run2b.txt`](w3.2-live-6-graph-list-after-run2b.txt) | `rpworker graph list --hash` after run 2b: the same five mail IDs; the SharePoint docx/xlsx bytes rewritten again |

Runs 1 and 2b's `--record` folders are replayed by `worker/tests/` (W3.2). None of these files
holds a credential. The 11 copies stay in the targets until removed by hand (W3.4).

## W4.12 spike: the restore credential under a service account

W4.12 (#135, `docs/decisions.md` 2026-10-07), 2026-10-06 23:06Z–23:24Z: the Worker's export of
Veeam's organisation app certificate from `LocalMachine\My`, tried from a Windows service as
LocalSystem and as a virtual account, then one mail restore as the virtual account through
`10-restore.ps1` and one through `rpworker restore`. Text files, as the console showed them;
each was checked against the session's secret values and for token, PFX and PEM shapes before
it was written (`w4.12-harness/spike-lib.ps1`, `Save-SpikeEvidence`): no hits. The commands
print no credential; the probes print lengths only.

| File | What it is |
|---|---|
| [`w4.12-1-probe-localsystem.txt`](w4.12-1-probe-localsystem.txt) | the probe as LocalSystem: `GET /v8/Organizations`, the certificate found by the reported thumbprint, the app ID checked, the key opened, exported in memory by .NET and by the Worker's exporter |
| [`w4.12-2-probe-virtual-account-denied.txt`](w4.12-2-probe-virtual-account-denied.txt) | the same as `NT SERVICE\RpSpikeProbe` with the key file's default ACL: the key can't be opened (`0x80090016`) |
| [`w4.12-3-probe-virtual-account-granted.txt`](w4.12-3-probe-virtual-account-granted.txt) | the same after one `icacls ... /grant "NT SERVICE\RpSpikeProbe:(R)"` on the key file: identical to LocalSystem's |
| [`w4.12-4-failure-cases.txt`](w4.12-4-failure-cases.txt) | as the virtual account, the Worker's exporter on a thumbprint no certificate has, a throwaway non-exportable certificate and a throwaway expired one: the three refusals `rpworker doctor` will name |
| [`w4.12-5-restore-script-virtual-account.txt`](w4.12-5-restore-script-virtual-account.txt) | `10-restore.ps1 -Type mail -Item RP-CANARY-0011` as the virtual account, the export in memory: `Success`, 22 s; nothing written under the key container folders or temp |
| [`w4.12-6-graph-list-hash-after-script.txt`](w4.12-6-graph-list-hash-after-script.txt) | `rpworker graph list --hash` right after: the one mail with the manifest's `body_sha256` |
| [`w4.12-7-cleanup-and-graph-list.txt`](w4.12-7-cleanup-and-graph-list.txt) | the live cleanup test emptying the targets, then `graph list`: 0 |
| [`w4.12-8-rpworker-restore-virtual-account.txt`](w4.12-8-rpworker-restore-virtual-account.txt) | the Done-when: `rpworker restore --mail 1 --sp 0 --od 0 --run-id w412-done-when-1` as the virtual account: 1 of 1, `status pass`, exit 0, cleaned after; two key files Veeam's own service wrote under `SystemKeys` noted |
| [`w4.12-9-graph-list-after-rpworker.txt`](w4.12-9-graph-list-after-rpworker.txt) | `rpworker graph list --hash` after it: 0 in all three targets |
| [`w4.12-10-teardown.txt`](w4.12-10-teardown.txt) | the service, the ACEs, the throwaway certificates and the spike folder taken away again, and what the machine holds after |
| [`w4.12-harness/`](w4.12-harness/) | how it was run: `RpSpikeHost.cs` (the temporary service that runs one command as its account, the secrets over a named pipe), `spike-lib.ps1` (the elevated shell's side: the service, the pipe, the evidence writer), `spike-probe.ps1`, `spike-failures.ps1`. Kept as text; not run by any test |

W4.5 (#48, `docs/decisions.md` 2026-10-07), 2026-10-07 00:58Z–01:05Z: the DPAPI vault. The lab's
vault filled from Credential Manager and the PFX file, one `rpworker test --evidence` run from
the vault alone, the W4.12 harness once more with the service account reading the vault (and
refused without its Read entry), a temporary non-administrator reading the file, and everything
taken away again. Text files, as the console showed them; each was checked against the four
secret values (the Veeam password, the PFX's Base64, its password, the signing key) and for
token, PFX, PEM and key shapes before it was written (`w4.5-harness/w45-service-run.ps1`,
`Save-W45Evidence`): no hits. No file holds a value, a blob or a key.

| File | What it is |
|---|---|
| [`w4.5-1-fill-vault.txt`](w4.5-1-fill-vault.txt) | `lab\entra\fill-worker-vault.ps1` from an elevated shell: five `set <name> in ...\vault.bin` lines, `vault list`, `vault test`, the file's ACL (`SYSTEM:(F)`, `Administrators:(F)`, `OWNER RIGHTS:(F)`, owner Administrators, 4272 bytes), `config check` reading the vault, and no `RP_*` variable in the shell |
| [`w4.5-2-test-evidence-from-the-vault.txt`](w4.5-2-test-evidence-from-the-vault.txt) | the Done-when: `rpworker test --mail 10 --sp 10 --od 10 --run-id w45-done-when-1 --evidence ...` as the current user, the vault the only source of secrets: 30 of 30, `status pass`, exit 0, signed and timestamped by DigiCert, `rpworker signer verify` with `--tsa-ca` `verified`, `graph list` 0 after |
| [`w4.5-3-service-account-reads-the-vault.txt`](w4.5-3-service-account-reads-the-vault.txt) | the W4.12 harness, the host serving 0 variables: `rpworker restore --mail 1 --sp 0 --od 0` as `NT SERVICE\RpSpikeProbe` after `rpworker vault grant` and the key file's ACE, 1 of 1, `status pass`, exit 0, cleaned after; then with the vault's entry taken away: `config error: ...\vault.bin: the vault file can't be read`, exit 1, before any Veeam call |
| [`w4.5-4-developer-grant-and-live-tests.txt`](w4.5-4-developer-grant-and-live-tests.txt) | the developer's own account, unelevated (a restricted token): `vault test` refused before `rpworker vault grant <account>`, `ok` after, and the read-only `[live]` tests run from the vault with no secret in the environment |
| [`w4.5-5-other-account.txt`](w4.5-5-other-account.txt) | the issue's manual test, under machine scope: a temporary local non-administrator reads the vault (`can't be read`), reads it once granted `Read` (`ok`: DPAPI decrypts for any account the ACL admits), can't write it (`couldn't be written`), and a vault it wrote in its own folder is refused to the administrator by the ownership rule; a copy on another machine not tried (one machine) |
| [`w4.5-6-teardown.txt`](w4.5-6-teardown.txt) | the service, its ACEs on the key file and the vault, the spike folder and the probe account taken away again; the lab's `vault.bin` stays, with its five names |
| [`w4.5-harness/`](w4.5-harness/) | `w45-service-run.ps1`: the W4.12 library reused with an empty pipe (the service gets no variable), the grant, the restore, the teardown and the evidence writer. Kept as text; not run by any test |
