# Veeam restore flow (W2.4)

How the Worker restores sampled items through the Veeam Backup for Microsoft 365 REST API into
the three restore targets, and how it reads the result. Written for W2.5 (`restore_sample` in
`VeeamM365Connector`), W2.7 (`TargetGuard`), W3.3 (`docs/verification.md`) and Q2.1 (the
fixtures). It covers the same ground as the guide's step 7, recorded against the live lab.

- **Server.** Veeam Backup for Microsoft 365 **8.6** (logs say 13.6.0.237), REST API **v8**,
  on the dev laptop (`docs/environment.md`).
- **Mode.** Admin mode, as `rp-veeam` (`docs/decisions.md` 2026-09-26). Operator mode is out
  of Stage 1.
- **Organisation.** `RestoreProofLab.onmicrosoft.com`, Veeam organisation ID
  `ff96d072-29e2-4cb4-a155-2590f5473176`.
- **Restore point.** `c2f0f2e7-…02e377858499-919b-4609-9b15-5b7fb33b5004`, `backupTime`
  `2026-09-27T22:00:48.1447833Z`: the nightly job's point, newer than the two W1.4 used.
- **Recorded.** 2026-09-28, 21:27–21:31 UTC, with an earlier, uncommitted revision of
  [`10-restore.ps1`](veeam-m365/10-restore.ps1) (§1, "Which revision"). Every exchange is saved,
  scrubbed, in [`veeam-lab/`](veeam-lab/README.md) as `w2.4-*.json` (52 files;
  `audit-evidence.ps1` found no secret in them).
- **Scope.** Four real restores into the restore targets: one mail, one SharePoint file, one
  OneDrive file, then five mails in one call. Read back through Graph with
  `rpworker graph list --hash`. The login, paging, IDs and browsing calls are in
  [`veeam-notes.md`](veeam-notes.md) and are linked, not repeated. The bodies first worked in
  W1.0 ([feasibility §2c](veeam-feasibility.md#c-exact-v8-restore-bodies)); this document is the
  sequence the Worker builds from.

Conventions as in `veeam-notes.md`: paths are relative to `https://<veeam-server>:4443`,
`{restoreSessionId}` etc. are placeholders, "→" gives the status seen, evidence names link into
`veeam-lab/`. Credential fields appear as field names only. Their values are in no file.

## 0. The sequence at a glance

```
POST /v8/token  grant_type=password                             (veeam-notes §1)
GET  /v8/RestoreSessions?limit=200                              preflight: none of ours Working (§2.1)
GET  /v8/Organizations                                          preflight: the org's app ID and thumbprint (§2.2)
GET  /v8/RestorePoints?organizationId={id}&limit=10000          newest backupTime, kept as the exact string (§3)
POST /v8/Organizations/{id}/explore  {dateTime, type}           → 201, explore session (§3)
GET  …browse the source container, match exactly, re-read…      (§4)
     build the body; TargetGuard on the exact text (§5, §6)
     export the credential into memory; TargetGuard again (§7)
POST …/items/restoreTo | …/Documents/restoreTo | …/Documents/copyTo   ONCE → 200 {sessionId} (§8)
GET  /v8/RestoreSessions?startTimeFrom=…&orderBy=CreationTime&orderAsc=false&limit=50   exactly one new session (§8)
GET  /v8/RestoreSessions/{sessionId}     every 5 s               until state == Stopped (§9)
GET  /v8/RestoreSessions/{sessionId}/Statistics                 counts; per-file items (§10)
GET  /v8/RestoreSessions/{sessionId}/Events?limit=100           one Restore event per item (§10)
POST /v8/RestoreSessions/{exploreSessionId}/Stop                → 204, in a finally, unless a restore from it may still run (§11)
POST /v8/token/logout                                           → 204
```

One explore session per item type, and one restore call per source container (a mailbox, a
site, a OneDrive) with all the sampled items from it (`docs/decisions.md` 2026-09-28, W2.4).
Then the Graph read-back decides `pass` or `fail` per item.

## 1. How it was recorded

[`10-restore.ps1`](veeam-m365/10-restore.ps1) is the only script in the collection that writes to
the tenant:

```
pwsh -File 10-restore.ps1 -Type mail|sp|od -Item <manifest id>[,<id>...] [-Tag x1] [-WhatIf] [-SaveEvidence]
```

- `-Item` takes 1 to 5 distinct ids from `lab/seed-manifest.json`, all of the kind `-Type`
  names. For mail, the source mailbox comes from the manifest entry (`location.mailbox`). For
  SharePoint and OneDrive, the source is the canary library or folder fixed in the script; the
  manifest entry gives the name, size or subject and received time to match.
- The three targets are constants in the script (`lab/tenant.md`, "Restore targets"). A
  hand-written guard checks the exact body before the POST (§6), until W2.7's `TargetGuard`
  replaces it.
- `-WhatIf` sends no restore POST, exports no certificate and saves no evidence. It still signs
  in, runs the preflight, opens an explore session, browses, builds the body, runs the guard
  and its self-test, stops the explore session, and exits 0 if the guard passed. A real run
  that loses its POST's answer at the same time could take that explore session for its restore
  (§8), so run it alone.
- `-SaveEvidence` refuses (exit 64) while evidence of the same type and `-Tag` exists, so a
  re-run never mixes its files with an earlier run's.
- It needs an elevated shell (the certificate export, §7), except with `-WhatIf`.
- Exit codes: 0 Veeam says restored (or `-WhatIf`: the guard passed); 1 the restore finished,
  not a success; 2 refused before any POST (guard, preflight, resolving an item), or a 4xx on the
  POST (nothing started); 3 no verdict (timeout, a POST without an answer, a duplicate check
  that doesn't confirm exactly the returned session, statistics or events unreadable or of an
  unexpected shape); 64 usage (also: not elevated without `-WhatIf`). Arguments bind by name
  only, and `-TimeoutMinutes` is 1 to 45; PowerShell's own parameter errors exit 1 before the
  script runs.

The four runs, back to back, all against the restore point above:

| Run | Items | Source | Explore session | Restore session | `result` | `details` | POST | `creationTime` → `endTime` |
|---|---|---|---|---|---|---|---|---|
| mail x1 | `RP-CANARY-0011` | bob, Inbox | `171ea3e1-…0d4a` | `b6fe35ef-9633-481d-9756-3496a717d8a9` | Success | 1 item processed (1 success) | 486 ms | 32 s |
| sp x1 | `rp-canary-06.pdf` | RestoreTest library | `9aa65291-…d76e` | `f7e9e6a8-62f3-4abd-a62c-84554981a6da` | Success | 1 item processed (1 success) | 464 ms | 46 s |
| od x1 | `rp-canary-16.pdf` | alice, `/RestoreTest` | `21ebe03d-…2e89` | `15c3f986-9569-4efb-955f-ea54ad46edb4` | Success | 1 item processed (1 success) | 294 ms | 34 s |
| mail x5 | `RP-CANARY-0002`…`0006` | alice, Inbox | `e64a4f87-…bc02` | `a9fb8fe0-caf9-49b3-9374-0ee3bea58b0f` | Success | 5 items processed (5 successes) | 228 ms | 81 s |
| mail r1 (2026-09-29, committed script, point `2026-09-28T22:00:53.2665624Z`) | `RP-CANARY-0011` | bob, Inbox | `0642691c-…88b0` | `b115035e-e66b-4908-9a2a-09acd31115aa` | Success | 1 item processed (1 success) | 159 ms | 22 s |

Evidence per run: `w2.4-<run>-sweep-before`, `-org`, `-explore`, the browse files (§4), `-restore`,
`-sessions-after-post`, `-session-working`, `-session`, `-statistics`, `-events`. For example
[`w2.4-mail-x5-restore`](veeam-lab/w2.4-mail-x5-restore.json),
[`w2.4-mail-x5-session`](veeam-lab/w2.4-mail-x5-session.json),
[`w2.4-mail-x5-events`](veeam-lab/w2.4-mail-x5-events.json). The console output isn't committed.

**Which revision.** The four runs were made with a revision of the script that was never
committed; the committed one is the result of the W2.4 review (`docs/decisions.md` 2026-09-29).
The recordings show it: the mail x1 run's Veeam log was complete (created 21:27:37.98Z, last
written 21:27:58Z) before that run's events call (21:28:04Z), so the committed log lookup would
have printed a line where that run printed none. The calls and bodies are the same. What
changed: the self-test (§6), the POST's status handling and the duplicate check (§8), what
happens on a timeout (§9), how file results are matched and what a malformed answer means
(§12), and the positional arguments and time-out range (above). The committed revision was
replayed offline against all four recordings, with the HTTP layer answering from the evidence
files (the same four verdicts, exit 0, and the failure paths of §8, §9 and §12), and run live
with `-WhatIf` on 2026-09-29 against the 2026-09-28T22:00:53Z point (guard passed, explore
session stopped, 204). Then it made one real restore, **mail r1** in the table above
(2026-09-29, 14:45–14:46 UTC, `w2.4-mail-r1-*.json`, 13 files; `audit-evidence.ps1`: 0 hits
over all 65 `w2.4-*` files). It printed "guard self-test: 12 mutations refused by the guard",
"duplicate check: 1 new session(s) of ours; exactly this one: True" and "VERDICT: Veeam says
restored", exit 0. `rpworker graph list --hash` then found `RP-CANARY-0011` in `restoretest`'s
Inbox with the manifest's `text-v1` `body_sha256` (`dfef80f3…7989`), and nothing in the other
two targets. The other console lines this document quotes from the runs are the earlier
revision's.

**Graph read-back** (`rpworker graph list --hash`, a config outside the repo with the
`lab/tenant.md` values, after `. .\lab\entra\set-worker-env.ps1`):

| | Before the runs | After |
|---|---|---|
| `restoretest` Inbox | 0 | 6: `RP-CANARY-0011`, `0002`–`0006` |
| RestoreTarget library | 0 | 1: `rp-canary-06.pdf`, 925 bytes |
| alice's `/RestoreTarget` | 0 | 1: `rp-canary-16.pdf`, 925 bytes |

All 8 SHA-256 values equal `lab/seed-manifest.json`: the mails' `text-v1` `body_sha256`, the
pdfs' `content_sha256` (rule `bytes`). W3.4's cleanup doesn't exist yet, so the owner removed
the 8 copies by hand. After that, `rpworker graph list` found 0 items in each of the three
targets (2026-09-28, about 21:38Z).

## 2. Preflight

### 2.1 None of our sessions still Working

`GET /v8/RestoreSessions?limit=200` → 200
([`w2.4-mail-x1-sweep-before`](veeam-lab/w2.4-mail-x1-sweep-before.json)). If any session with
`state == "Working"` and `initiatedBy` equal to our account is listed, the script refuses (exit 2)
and points to [`08-sweep-sessions.ps1`](veeam-m365/08-sweep-sessions.ps1). The duplicate check
(§8) relies on this: after the POST, a new session of ours can only be the one we started.

The Worker's planned first pipeline step (cleanup, veeam-notes §4.4) stops leftover sessions
instead of refusing. The caveat there still holds: run one test at a time per Veeam server.

### 2.2 The organisation's app

`GET /v8/Organizations` → 200 ([`w2.4-mail-x1-org`](veeam-lab/w2.4-mail-x1-org.json)). The script
picks the organisation by `id` and `name` and checks, in both `exchangeOnlineSettings` and
`sharePointOnlineSettings`:

```json
"applicationId": "1fd2609d-1242-43fe-94b5-d58688a90bd6",
"applicationCertificateThumbprint": "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7"
```

Both must equal the script's constants (`$VeeamAppId`, `$VeeamAppThumb`). The certificate it
exports (§7) is looked up by that same thumbprint, and the body's `applicationId` is that same
app ID. A mismatch refuses the run. This catches a Veeam organisation re-registered with another
app before a restore fails with it. `useApplicationOnlyAuth` is also `true` in both settings in
the evidence; the script doesn't check it.

## 3. Restore point and explore session

1. `GET /v8/RestorePoints?organizationId={id}&limit=10000`, sorted by `backupTime` newest first
   (not saved as W2.4 evidence; the shape is in veeam-notes §3).
2. `POST /v8/Organizations/{organizationId}/explore` → 201
   ([`w2.4-mail-x5-explore`](veeam-lab/w2.4-mail-x5-explore.json)):

   ```json
   {"dateTime":"2026-09-27T22:00:48.1447833Z","type":"Vex","showDeleted":false,"showAllVersions":false}
   ```

   `type` is `Vex` (mail), `Vesp` (SharePoint) or `Veod` (OneDrive). `dateTime` is the
   `backupTime` string **unchanged**, all 7 fractional digits and the `Z` (veeam-notes §4.2).
3. Record the explore session's `id` from the 201 before anything else can throw. The script
   adds it to the list its `finally` stops (§11) inside the call that opens it.

The session's `name` ("Exchange restore (Entire organization - 9/27/2026 10:00:48 PM)") embeds
the point in US format. Don't parse it. 215–533 ms per explore here.

## 4. Finding the items in the explore session

Every item is found the same way: list the **source** container with `limit=1000`, keep the
entries whose name is **exactly** (ordinal) the manifest's, require exactly one, then re-read it
by ID. The script refuses the run on zero or several matches (exit 2). For the Worker's status
they differ (§15): several matches, or a source container that can't be found or listed, is
`error`; zero matches for a canary the manifest dates before `backupTime` means the backup lacks
the item, which is `fail` with the item recorded as missing (a proposal for W3.3). Search is not
used (veeam-notes §5.4: listing is simpler for 10 canaries per
container).

All paths below start with `/v8/RestoreSessions/{exploreSessionId}/`. Mail is under lower-case
`organization/`, SharePoint and OneDrive under `Organization/` (veeam-notes §5).

### 4.1 Mail (`Vex`)

| Step | Call | Match | Evidence |
|---|---|---|---|
| Source mailbox | `GET organization/mailboxes?limit=1000` | `email` equal to the manifest's `location.mailbox`, ordinal ignoring case; exactly one. All items of one call must share it, and it must not be the target mailbox | [`w2.4-mail-x5-mailboxes`](veeam-lab/w2.4-mail-x5-mailboxes.json) |
| Source folder | `GET organization/mailboxes/{mailboxId}/folders?name=Inbox` | `name` ordinal `Inbox`; exactly one | [`w2.4-mail-x5-folder-inbox`](veeam-lab/w2.4-mail-x5-folder-inbox.json) |
| Items | `GET organization/mailboxes/{mailboxId}/items?parentId={folderId}&limit=1000` | `subject` ordinal equal to the manifest's; exactly one; `received` to the second equal to the manifest's `received_at` | [`w2.4-mail-x5-items`](veeam-lab/w2.4-mail-x5-items.json) (10 items) |
| Re-read | `GET organization/mailboxes/{mailboxId}/items/{itemId}` | `subject` unchanged | [`w2.4-mail-x5-item`](veeam-lab/w2.4-mail-x5-item.json) (the first item only) |

The body carries each item as `{"id": "<Veeam item id>"}` and nothing else.

### 4.2 SharePoint (`Vesp`)

| Step | Call | Match | Evidence |
|---|---|---|---|
| Site | `GET Organization/Sites?parentId=root&limit=1000` | `url` ordinal equal to the site URL | [`w2.4-sp-x1-sites`](veeam-lab/w2.4-sp-x1-sites.json) |
| Canary library | `GET Organization/Sites/{siteId}/Libraries` | `id` ends with the canary list ID `7eb0f08a-f57b-418c-8ca6-f2ab81297666`; exactly one | [`w2.4-sp-x1-libraries`](veeam-lab/w2.4-sp-x1-libraries.json) |
| Documents | `GET Organization/Sites/{siteId}/Documents?parentId={libraryId}&limit=1000` | `name` ordinal equal to the manifest's, `isFolder` false; exactly one | [`w2.4-sp-x1-documents`](veeam-lab/w2.4-sp-x1-documents.json) (10) |
| Re-read | `GET Organization/Sites/{siteId}/Documents/{documentId}` | `name` and `sizeBytes` equal to the manifest's `stored_size` | [`w2.4-sp-x1-document`](veeam-lab/w2.4-sp-x1-document.json) |

The re-read object goes into the body **whole, minus `_links` and `_actions`**.

The script's `Libraries` call has no `limit`, so it got the default 30
([`w2.4-sp-x1-libraries`](veeam-lab/w2.4-sp-x1-libraries.json) echoes `"limit": 30`). The lab
site has seven libraries, all within the default 30. W2.5 should pass `limit=1000` there too.

The names are in the tenant's language (veeam-notes §5.2): the site's default library is
`Dokumenty` (`url` `sites/RestoreTest/Shared Documents`), not `Documents`. The guard's forbidden
names (§6) are English, so they don't list it; the guard still accepts only `RestoreTarget`.

### 4.3 OneDrive (`Veod`)

| Step | Call | Match | Evidence |
|---|---|---|---|
| OneDrive | `GET Organization/OneDrives?limit=1000` | `url` ordinal equal to alice's OneDrive URL | [`w2.4-od-x1-onedrives`](veeam-lab/w2.4-od-x1-onedrives.json) |
| Canary folder | `GET Organization/OneDrives/{oneDriveId}/Folders?parentId=root` | `name` ordinal `RestoreTest`; exactly one | [`w2.4-od-x1-folders-root`](veeam-lab/w2.4-od-x1-folders-root.json) |
| Documents | `GET Organization/OneDrives/{oneDriveId}/Documents?parentId={folderId}&limit=1000` | as SharePoint | [`w2.4-od-x1-documents`](veeam-lab/w2.4-od-x1-documents.json) (10) |
| Re-read | `GET Organization/OneDrives/{oneDriveId}/Documents/{documentId}` | as SharePoint | [`w2.4-od-x1-document`](veeam-lab/w2.4-od-x1-document.json) |

The body's target `onedrive` is `{id, name, url}` taken from the OneDrives listing.

### 4.4 The restore targets are now in the backup

W1.4 saw neither the RestoreTarget library nor alice's `/RestoreTarget` in the backup
(veeam-notes §5.2, §5.3). Both were created on 2026-09-25, after W1.4's two points, so every
later point holds them; the first is 2026-09-27T11:23:13Z (listed on 2026-09-29, not explored).
The 2026-09-27T22:00:48Z point used here has both: the library `…ffec069d-65e4-4c3a-9da2-ac086cf9dafa` in
[`w2.4-sp-x1-libraries`](veeam-lab/w2.4-sp-x1-libraries.json), and the folder `RestoreTarget`
(created 2026-09-25T19:57:20Z) in [`w2.4-od-x1-folders-root`](veeam-lab/w2.4-od-x1-folders-root.json).
The script prints a note and goes on. It never takes a source from them.

The consequence: the nightly backup job backs up the targets too. A restore not cleaned up
before the next backup ends up in the next restore point. So sampling (W2.6) **never takes an
item from a target**, even if an item with the right name is there. Canaries come only from the
canary sources: the RestoreTest library by list ID, `/RestoreTest` by folder, the source
mailboxes' Inbox. The random sample comes from real data outside both the targets and the
canary locations (`docs/decisions.md` 2026-09-25).

## 5. The restore bodies

Keys in the order sent (the order of the W1.0 recordings). The exact key set is part of the
guard (§6). Credential values are shown as `…`.

### 5.1 Mail

`POST /v8/RestoreSessions/{exploreSessionId}/organization/mailboxes/{sourceMailboxId}/items/restoreTo`
([`w2.4-mail-x5-restore`](veeam-lab/w2.4-mail-x5-restore.json)):

```jsonc
{
  "mailbox": "restoretest@RestoreProofLab.onmicrosoft.com",
  "folder": "Inbox",
  "items": [ { "id": "<Veeam item id>" }, … ],          // 5 in the x5 run
  "changedItems": true,
  "deletedItems": true,
  "markRestoredAsUnread": false,
  "excludeDrafts": false,
  "excludeDeletedItems": false,
  "excludeInPlaceHoldItems": true,
  "excludeLitigationHoldItems": true,
  "officeRegion": "Worldwide",
  "officeOrganizationName": "RestoreProofLab.onmicrosoft.com",
  "applicationId": "1fd2609d-1242-43fe-94b5-d58688a90bd6",
  "applicationCertificate": "…",                        // Base64 PFX (§7)
  "applicationCertificatePassword": "…",
  "impersonationAccountName": "restoretest@RestoreProofLab.onmicrosoft.com"
}
```

- The path segment is lower-case `organization`. The mailbox in the path is the **source**
  mailbox's Veeam ID. The target is the `mailbox` address.
- The organisation field is `officeOrganizationName` (SharePoint and OneDrive use
  `organizationName`).
- `impersonationAccountName` is the target mailbox. It is required with a certificate (W1.0).
- `folder` is required in practice (W1.0: 400 "Missing mandatory parameters: Folder." without it).

### 5.2 SharePoint

`POST /v8/RestoreSessions/{exploreSessionId}/Organization/Sites/{siteId}/Documents/restoreTo`
([`w2.4-sp-x1-restore`](veeam-lab/w2.4-sp-x1-restore.json)):

```jsonc
{
  "documents": [ {                                       // the re-read object, minus _links and _actions
      "siteId": "fe08085d-…e689", "sizeBytes": 925, "version": "1.0", "versionId": 1,
      "id": "fe08085d-…e6897eb0f08a-f57b-418c-8ca6-f2ab812976665ac127fb-0646-464e-a89a-76e93e62feb8",
      "name": "rp-canary-06.pdf", "createdBy": "Hrachya Harutyunyan", "creationTime": "2026-09-24T22:14:47Z",
      "modifiedBy": "Hrachya Harutyunyan", "modificationTime": "2026-09-24T22:14:47Z", "isFolder": false } ],
  "siteURL": "https://restoreprooflab.sharepoint.com/sites/RestoreTest",
  "list": "RestoreTarget",                               // the target library's display name
  "sendSharedLinksNotification": false,
  "documentVersion": "Last",
  "documentLastVersionAction": "Merge",
  "officeRegion": "Worldwide",
  "organizationName": "RestoreProofLab.onmicrosoft.com",
  "applicationId": "1fd2609d-1242-43fe-94b5-d58688a90bd6",
  "applicationCertificate": "…",
  "applicationCertificatePassword": "…"
}
```

`siteURL` is written with that capitalisation (`URL`). `list` is a display name, not an ID.

### 5.3 OneDrive

`POST /v8/RestoreSessions/{exploreSessionId}/Organization/OneDrives/{sourceOneDriveId}/Documents/copyTo`
([`w2.4-od-x1-restore`](veeam-lab/w2.4-od-x1-restore.json)):

```jsonc
{
  "documents": [ {                                       // the re-read object, minus _links and _actions
      "oneDriveId": "6d600fc0-…c325", "sizeBytes": 925, "inheritedPermissions": true, "version": "1.0",
      "id": "14ad2a26-a9d6-4307-a1b0-7f15d8b7debb", "versionId": 1, "name": "rp-canary-16.pdf",
      "createdBy": "Alice Test", "creationTime": "2026-09-24T22:11:28Z", "modifiedBy": "Alice Test",
      "modificationTime": "2026-09-24T22:11:28Z", "isFolder": false } ],
  "onedrive": {
    "id": "6d600fc0-65f8-4811-ad18-096ec5b7e83498cfff1a-b404-4438-ae6e-6927a6ccc325",
    "name": "Alice Test",
    "url": "https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com"
  },
  "folder": "RestoreTarget",                             // a folder name in the target OneDrive's root
  "changedItems": true,
  "deletedItems": true,
  "documentVersion": "Last",
  "documentLastVersionAction": "Merge",
  "officeRegion": "Worldwide",
  "organizationName": "RestoreProofLab.onmicrosoft.com",
  "applicationId": "1fd2609d-1242-43fe-94b5-d58688a90bd6",
  "applicationCertificate": "…",
  "applicationCertificatePassword": "…"
}
```

OneDrive has no `restoreTo`; it is `copyTo` (feasibility §1).

## 6. The target guard

`Assert-RestoreTarget` in the script parses the **exact text** that will be sent and the exact
path. `JsonNode.Parse` accepts a duplicate key and throws only when that object is first read,
so the guard reads every object of the body once and refuses a duplicate key anywhere in it. It runs twice: on the draft, with placeholder
credentials, and again on the final text just before the POST. It checks:

- **The path.** The explore session ID is GUID-shaped and one this run opened. The container ID
  is one or more GUIDs. The path has no query, fragment or dot segment, and is exactly the
  restore-to-another-location call for the type (`…/items/restoreTo`, `…/Documents/restoreTo`,
  `…/Documents/copyTo`).
- **The key set.** Exactly the keys in §5, no more, no fewer.
- **Common values.** `officeRegion` is `Worldwide`. `applicationId` is Veeam's organisation app.
  The two credential fields are JSON strings.
- **Mail.** `mailbox` and `impersonationAccountName` are `restoretest@…`, `folder` is `Inbox`,
  `officeOrganizationName` is the lab organisation, the seven flags are JSON booleans, and each
  item is `{"id"}` alone with an ID from the resolved set.
- **SharePoint.** `siteURL` is the RestoreTest site. `list` is `RestoreTarget` and not one of the
  forbidden names (`RestoreTest`, `Documents`, `Shared Documents`). `organizationName` and the
  version options are fixed; `sendSharedLinksNotification` is false. Each document's `id` starts
  with the site ID plus the **canary** list ID (this script's rule: it restores canaries only;
  see "For W2.7"), its `siteId` is the site, its `id` and `name` are in the resolved set, and it
  isn't a folder.
- **OneDrive.** `onedrive` has exactly `id`, `name`, `url`; `url` is alice's OneDrive and `id`
  the OneDrive in this session. `folder` is `RestoreTarget` and not a forbidden name. Each
  document's `oneDriveId` is that OneDrive; `id` and `name` are resolved; not a folder.
- **The item set.** The IDs in the body are exactly the resolved set: none missing, none added,
  none twice.

**The self-test.** Before any credential is exported, the script mutates the real body and path
12 ways and runs the guard on each. A mutation counts only if the guard itself refused it (a
`GUARD:` message). If the guard accepts one, or a case fails anywhere else, the run stops
(exit 2).

The four recorded runs printed "guard self-test: 11 mutations refused", but with the earlier
revision (§1) one of the 11 never reached the guard. It built the array case with
`JsonArray.Add($string)`, which PowerShell binds to the generic `Add<T>`, and serialising that
node throws ("JsonSerializerOptions instance must specify a TypeInfoResolver"). The case's
catch-all counted that throw as a refusal. The guard did refuse arrays; the self-test didn't show
it. The committed revision builds the element with `JsonValue.Create`, adds a duplicate-key case,
and prints "12 mutations refused by the guard" (offline against the four recorded bodies, and
live with `-WhatIf`).

| # | Mutation | Mail | SharePoint | OneDrive |
|---|---|---|---|---|
| 1 | Wrong target container | `mailbox` = alice | `siteURL` = `/sites/Other` | `onedrive.url` = bob's |
| 2 | Canary location | `folder` = `Sent Items` | `list` = `RestoreTest` | `folder` = `RestoreTest` |
| 3 | Impersonation / case | `impersonationAccountName` = alice | `list` = `restoretarget` | `folder` = `restoretarget` |
| 4 | Extra key | `restoreToOriginalLocation: true` | same | same |
| 5 | Other app | `applicationId` = all-zero GUID | same | same |
| 6 | Look-alike name | `folder` = `In<U+00AD>box` | `list` = `Restore<U+00AD>Target` | `folder` = `Restore<U+00AD>Target` |
| 7 | Array instead of a string | `mailbox` = `["restoretest@…"]` | `siteURL` = `[…]` | `folder` = `[…]` |
| 8 | Duplicated item | the first item twice (same count with 2+ items) | same | same |
| 9 | Extra item | one more copy of the first | same | same |
| 10 | Duplicate key | the first key once more, with `"x"`, in the text | same | same |
| 11 | Original-location path | `…/restore` instead of `restoreTo`/`copyTo` | same | same |
| 12 | Dot-segment path | `…/restoreTo/../../restore` | same | same |

**The comparison pitfall.** PowerShell's `-ceq`, `-cne` and `-in` compare by culture, and
culture comparison ignores characters such as U+00AD (soft hyphen) and U+200B (zero-width
space). So `"Restore<U+00AD>Target" -ceq "RestoreTarget"` is **true**. A `[string]` cast of a
JSON array joins its elements, so `["restoretest@…"]` reads as the address. The first draft of
the guard had both holes (found in review). The script now compares with
`[string]::Equals(…, Ordinal)` and `Array.IndexOf`, requires JSON string kinds, and accepts only
printable ASCII in every checked value.

**For W2.7.** `std::string ==` is already ordinal. Keep the 12 mutations as `TargetGuard`
tests, the look-alike, array and duplicate-key cases included, check value kinds, not just
values, and let a test pass only on the guard's own refusal. The printable-ASCII rule works
because the three target names are ASCII by setup. *(Done in W2.7: `rp::veeam::check_restore_request` in
`worker/include/rp/target_guard_veeam.hpp`, tested in `worker/tests/target_guard_veeam_test.cpp`;
`docs/decisions.md` 2026-09-29, W2.7.)*

**When the guard runs.** The rule stays as CLAUDE.md and the 2026-09-22 decision put it:
`TargetGuard` is checked per item inside `RestoreSample`, before any Veeam call. `restore_sample`
receives its items and the configured targets in the `RestoreSpec`, so it resolves the targets
and checks every item's target (§16, check 1) before its first Veeam call. The body check of
this section is a second layer, not a replacement: it needs the browse results, so it runs after
browsing (read-only) and immediately before the restore POST, on the exact text (§16, check 2).

**Lab-only rules.** In the lab the source and the target share the site (RestoreTest) and the
OneDrive (alice's), so the script requires `onedrive.id` to equal the source OneDrive; W2.7
compares the target against the configured target, not against the source. And the canary
list-ID prefix on SharePoint document IDs holds because the script restores canaries only.
W2.6 also samples real data outside the canary locations, so W2.7 checks a document's `siteId`
and `id` against the sampled item, not against the canary list; a real-data item would
otherwise be refused as a guard violation on every run.

## 7. The restore credential

Owner decision (`docs/decisions.md` 2026-09-28, W2.4): the restore body carries **Veeam's own
organisation app** (`1fd2609d-1242-43fe-94b5-d58688a90bd6`, certificate `CN=RestoreProof Lab
Veeam`, thumbprint `AC3220B5…F783A7`, in `Cert:\LocalMachine\My`). Per run, `Get-RestoreCredential`:

1. checks the certificate has a private key and hasn't expired;
2. makes a one-time password from 32 random bytes;
3. exports the certificate to `%TEMP%\rp-w24-<guid>.pfx` (refusing a path inside the repo);
4. reads the file into memory as Base64 and deletes it in a `finally` (an undeletable file is an
   error that says so);
5. registers both values with the evidence scrubber. With `RP_LAB_SECRET_DIR` set, as in the
   documented run ([`veeam-m365/README.md`](veeam-m365/README.md)), the one-time password (not
   the PFX) also gets a DPAPI copy in that folder, outside the repo, for `audit-evidence.ps1`.
   The folder is deleted after the audit.

The certificate is exported only after the guard and its self-test passed. Its two values go
into the body, the guard runs again on the exact text, the POST goes out, and the fields are
cleared. The PFX is never stored. The evidence files hold `[REDACTED]` for
`applicationCertificate` and `applicationCertificatePassword`.

What stays open for the Worker (a spike before W4.5): a vault copy of this PFX, an export at run
time by the thumbprint Veeam reports (when the Worker runs on the Veeam server), or a dedicated
app with narrower permissions. Against a "narrow" app: Veeam's SharePoint restore demanded
`Group.ReadWrite.All` on the app (L1.4, [`manual-restore-reference.md`](../manual-restore-reference.md)).
The Worker's own app ("RestoreProof Worker") only reads, so it can't be this app.
`docs/decisions.md`'s "to be tested before the Worker stores any certificate" still holds.

## 8. One POST, and finding the session without resending

The restore POST is sent **once**, never retried automatically (veeam-notes §6). It answered
`200 {"sessionId": "<uuid>"}` in 228–486 ms in all four runs
([`w2.4-mail-x1-restore`](veeam-lab/w2.4-mail-x1-restore.json),
[`w2.4-sp-x1-restore`](veeam-lab/w2.4-sp-x1-restore.json),
[`w2.4-od-x1-restore`](veeam-lab/w2.4-od-x1-restore.json),
[`w2.4-mail-x5-restore`](veeam-lab/w2.4-mail-x5-restore.json)). That ID is a **new** restore
session, not the explore session. The 200 says nothing about the restore itself.

**The duplicate check** runs after every POST, so its query is proven on every run:

```
GET /v8/RestoreSessions?startTimeFrom={POST time − 60 s, to the second, Z}&orderBy=CreationTime&orderAsc=false&limit=50
```

It keeps a listed session only if all of these hold:

- `initiatedBy` is our account (Veeam lists the bare name, `rp-veeam`);
- `type` is this run's type (`Vex`, `Vesp`, `Veod`);
- `id` is GUID-shaped and **not** a session this run already knows: an explore session it
  opened (same `type`, listed too) or a restore session an earlier POST of the run returned or
  the check adopted;
- `creationTime` ≥ POST time − 5 s.

Every run found exactly one, the session the POST returned
([`w2.4-mail-x5-sessions-after-post`](veeam-lab/w2.4-mail-x5-sessions-after-post.json)). The
60 s window also listed the explore session (dropped by ID) and, in the first run, four earlier
`rp-veeam` sessions from the minute before, all `Stopped` (dropped by `creationTime`;
[`w2.4-mail-x1-sessions-after-post`](veeam-lab/w2.4-mail-x1-sessions-after-post.json)). In the
mail x5 run it also listed the previous od run's two `Veod` sessions, restore `15c3f986-…` and
explore `21ebe03d-…`, both `Stopped` (dropped by type and by `creationTime`;
[`w2.4-mail-x5-sessions-after-post`](veeam-lab/w2.4-mail-x5-sessions-after-post.json)).

The script sends one POST per run, but the Worker sends one per source container (§13), so
several of one type in a run. Excluding only the explore sessions would let a later POST that
got no answer adopt the session of an earlier one, and judge its items by the wrong session. So
every known session ID is excluded.

**With a session ID from the POST**, the check must list exactly that one new session. If it
lists another, none, or fails itself (a 5xx, a transport error), the script still polls the
returned session, so it isn't lost, but ends with no verdict (exit 3). The earlier revision
(§1) only printed the check's result, and a failing check aborted the run before the returned
session was polled or even printed.

The POST itself waits at most **60 s** for an answer (`-TimeoutSeconds 60`). No answer by then
counts as "no session ID" below. Any 2xx with a `sessionId` counts as the 200 does. The POST's
evidence is written only after the session ID is parsed, and a failed write is reported without
losing it.

**When the POST gives no session ID** (a transport error, a timeout, a 5xx, any other status
that is neither 2xx nor 4xx, or a 2xx without `sessionId`), the script doesn't resend. The
Worker tells one transport error apart: no connection or no TLS handshake means the request
never went out, so nothing started (`RestorePostOutcome::not_sent`, `connector::TransientError`,
the explore sessions closed) and no check runs. It runs the same check, and while it finds none, looks
up to 3 more times, 10 s apart. Exactly one candidate: it adopts it and polls it. Several
candidates: exit 3 at once. Still none after the last look: exit 3. Both are "no verdict, not
resent". A 4xx means nothing started: exit 2. None of these cases happened in W2.4.

The margins assume the Worker's clock and Veeam's agree within seconds (same machine in the
lab). The preflight (§2.1) makes "a new session of ours" unambiguous.

## 9. Waiting for the session

- Poll `GET /v8/RestoreSessions/{sessionId}` **every 5 s** until `state == "Stopped"`.
  While `Working`, `endTime` is `9999-12-31T23:59:59.9999999` with no `Z`
  ([`w2.4-mail-x5-session-working`](veeam-lab/w2.4-mail-x5-session-working.json)).
  `result` reads `Success` from the start and means nothing until `Stopped`.
- A 200 resets the failure count. **6 consecutive failures** (non-200 answers or transport
  errors) → no verdict (exit 3).
- A **404** → no verdict at once (the session is gone).
- **20 minutes** (`-TimeoutMinutes`, 1 to 45: the script signs in once and nothing refreshes the
  3600 s token) with the session still `Working` → no verdict.
- In all three cases the restore may still be running. The script then leaves the restore
  session **and the explore session it came from** alone (what Stop does to either while the
  restore runs is untested, §18), prints the explore session's ID, and says to wait until
  `GET /v8/RestoreSessions/{sessionId}` reads `Stopped` before running `08-sweep-sessions.ps1`.
  The earlier revision (§1) stopped the explore session in its `finally`, under the running
  restore. `08-sweep-sessions.ps1` can't tell a restore session from an explore session in the
  list (same `type`, same account), so it stops nothing while two of ours of one type are
  `Working`, unless given `-Force`.

The stopped session ([`w2.4-mail-x5-session`](veeam-lab/w2.4-mail-x5-session.json)), trimmed
(`organization`, `scopeName` and `_links` left out):

```json
{"id":"a9fb8fe0-caf9-49b3-9374-0ee3bea58b0f","name":"Exchange restore (Entire organization - 9/27/2026 10:00:48 PM)",
 "type":"Vex","creationTime":"2026-09-28T21:30:20.3324555Z","endTime":"2026-09-28T21:31:41.596799Z",
 "state":"Stopped","result":"Success","initiatedBy":"rp-veeam","details":"5 items processed (5 successes)",
 "clientHost":"[::ffff:127.0.0.1]","eTag":2}
```

## 10. Statistics, events and Veeam's log

### 10.1 Statistics

`GET /v8/RestoreSessions/{sessionId}/Statistics`. It answers 409 while `Working` (veeam-notes
§4.3); on a 409 the script asks again, up to 6 attempts in all, 5 s apart. In all four runs it
answered 200 at once after `Stopped`.

```jsonc
// Files: w2.4-sp-x1-statistics (w2.4-od-x1-statistics is the same shape)
{"totalItemsCount":1,"restoredItemsCount":1,"failedItemsCount":0,"skippedItemsCount":0,
 "items":[{"id":"5ac127fb-0646-464e-a89a-76e93e62feb8","itemRestoreDetailsType":"Item",
           "name":"rp-canary-06.pdf","itemType":"SharePointItem","status":"Success"}]}
// Mail: w2.4-mail-x5-statistics
{"totalItemsCount":5,"restoredItemsCount":5,"failedItemsCount":0,"skippedItemsCount":0,"items":[]}
```

- Mail `items[]` is **empty**, also with 5 items
  ([`w2.4-mail-x5-statistics`](veeam-lab/w2.4-mail-x5-statistics.json)).
- `items[].id` for SharePoint is the list item GUID at the end of the document ID
  ([`w2.4-sp-x1-statistics`](veeam-lab/w2.4-sp-x1-statistics.json)). For OneDrive it is the
  document ID itself ([`w2.4-od-x1-statistics`](veeam-lab/w2.4-od-x1-statistics.json)).
- `itemType` is `SharePointItem` for OneDrive files too.
- No `errors` field in these four. W1.0's failed mail restore had one (§12).

### 10.2 Events

`GET /v8/RestoreSessions/{sessionId}/Events?limit=100`. The list is "Restore session started"
(`type: None`), one `type: Restore` event per item, then "Restore session completed" (`None`).
An item event has `id`, `type`, `itemName`, `itemType`, `itemSizeBytes`, `source`, `target`,
`status`, `message`, `title`, `startTime`, `endTime`, `duration`, `order`, `organizationId`,
`backedUpOrganizationId` and `_links`, plus `userId` (mail, OneDrive) or `siteId` (SharePoint,
OneDrive). Trimmed:

```jsonc
// Mail, w2.4-mail-x5-events: order 1 of 5
{"itemName":"RP-CANARY-0003","itemType":"IPM.Note","itemSizeBytes":41111,
 "source":"Alice Test\\Inbox","target":"restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox",
 "type":"Restore","status":"Success","title":"Message successfully restored",
 "message":"Item RP-CANARY-0003 was restored successfully (type: IPM.Note; source: Alice Test\\Inbox; target: restoretest@RestoreProofLab.onmicrosoft.com\\<null>\\Inbox)",
 "order":1}
// SharePoint, w2.4-sp-x1-events
{"itemName":"rp-canary-06.pdf","itemType":"File","itemSizeBytes":925,
 "source":"/sites/RestoreTest/RestoreTest/rp-canary-06.pdf","target":"https://restoreprooflab.sharepoint.com/sites/RestoreTest",
 "type":"Restore","status":"Success","title":"Item is successfully restored.","duration":"00:00:05.0530196","order":1}
// OneDrive, w2.4-od-x1-events
{"itemName":"rp-canary-16.pdf","itemType":"File","itemSizeBytes":925,
 "source":"personal/alice_restoreprooflab_onmicrosoft_com/Documents/RestoreTarget/rp-canary-16.pdf",
 "target":"https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com",
 "type":"Restore","status":"Success","title":"Item is successfully restored.","order":1}
```

What to rely on and what not:

- **Order.** The 5 mails were sent as 0002, 0003, 0004, 0005, 0006. The events came as 0003,
  0004, 0005, 0002, 0006, and `order` follows the events, not the body
  ([`w2.4-mail-x5-events`](veeam-lab/w2.4-mail-x5-events.json)). Match events to items by
  `itemName`, never by position.
- **`itemName`** is the mail subject or the file name.
- **`title` varies** for the same outcome: "Message successfully restored" for four of the mails,
  "Folder successfully restored" for `RP-CANARY-0006` and for `RP-CANARY-0011`
  ([`w2.4-mail-x1-events`](veeam-lab/w2.4-mail-x1-events.json)). Use `type`, `status` and
  `itemName`. Keep `message` for the evidence bundle.
- **`source` of a `copyTo` event names the destination path** (`…/Documents/RestoreTarget/…`),
  as W1.0 found ([`w2.4-od-x1-events`](veeam-lab/w2.4-od-x1-events.json)).
- **A SharePoint event's `target` names only the site**, not the library
  ([`w2.4-sp-x1-events`](veeam-lab/w2.4-sp-x1-events.json)). A mail event's target is
  `<mailbox>\<null>\<folder>`.
- So events can't confirm the library or folder the file went to. The Graph read-back of the
  configured target does that.

### 10.3 Veeam's per-restore log

Veeam writes one log per restore session:

```
C:\ProgramData\Veeam\Backup365\Logs\RestoreREST\restore_<yyyy_MM_dd_HH_mm_ss>_<sessionId without dashes>_<organizationId without dashes>.log
restore_2026_09_28_23_28_38_f7e9e6a862f34abda62c84554981a6da_ff96d07229e24cb4a1552590f5473176.log   (sp x1)
```

- The session and organisation IDs have **no dashes**. Search for the ID with the dashes removed.
- The timestamp is the server's **local** time (UTC+2 here), and it isn't the session's
  `creationTime`: 6 s to 60 s after it in these runs (the name is to the second).
- The script lists the file after reading the statistics and events and prints its size. The
  earlier revision (§1) printed **0 bytes** for sp, od and mail x5 and no line for mail x1.
  Those readings don't show a late flush: each file was last written before its session's
  `endTime` (sp x1: last written 21:29:14Z, `endTime` 21:29:15.95Z), and the mail x1 file was
  complete before that run's events call (§1). A size read from a directory listing can lag for
  a file another process still holds open. The committed revision's real run (mail r1, §1)
  shows it: the script printed **0 bytes**, yet the file, looked at a minute later, held
  18,586 bytes last written at 14:46:26.128Z, 47 ms before the session's `endTime`
  (14:46:26.175Z), and before the script listed it. So the file is complete when the session
  stops, and the listed size is what lags. The Worker opens and reads the file after `Stopped`
  and never trusts a size from a directory listing.
- They are referenced, not committed. W1.0 found the AADSTS codes behind "Cannot connect to
  Microsoft 365" only there (feasibility §5.7).

## 11. Closing the explore session

The script's `finally` stops every explore session it opened: it reads the session and, if it is
still `Working`, sends `POST /v8/RestoreSessions/{exploreSessionId}/Stop` → **204** (all four
runs), then logs out → 204. The restore session stops by itself. The one exception: while a
restore made from it may still be running (the POST went out and its session wasn't seen
`Stopped`, §9), the explore session is left open and named.

An explore POST that fails once it may have gone out (a timeout, a dropped connection, a 5xx, a
2xx without an `id`) may still have opened a session: veeam-notes §4.4 saw a refused explore
left `Working` for 36 minutes. The Worker then runs the duplicate check's query and filter (§8)
from the explore POST's time, records every new session of ours of that type, and closes it with
the others, so the next run's preflight isn't blocked. A failed lookup is logged with the sweep
script (`08-sweep-sessions.ps1`).

After the stop, an explore session's `details` counts the restores made from it: the OneDrive
explore session `21ebe03d-…` reads `Stopped`, "1 item processed (1 success)" in
[`w2.4-mail-x5-sessions-after-post`](veeam-lab/w2.4-mail-x5-sessions-after-post.json). Read
results from the restore session's ID, never from the explore session.

## 12. Success, partial and failure

**Success** (all four runs): `state` `Stopped`, `result` `Success`, `details` "N items processed
(N successes)", `restoredItemsCount` N, one `Restore`/`Success` event per item, and for files one
`Success` entry per item in `Statistics.items[]`.

**Failure** (W1.0, user credentials refused by Microsoft 365 for MFA):

- OneDrive, the silent one: `result` `Failed`, `details` "0 items processed", statistics
  `totalItemsCount 1, restoredItemsCount 0, failedItemsCount 0`, no `errors`, empty `items[]`
  ([`w1.0-c-od-user-session`](veeam-lab/w1.0-c-od-user-session.json),
  [`w1.0-c-od-user-statistics`](veeam-lab/w1.0-c-od-user-statistics.json)). The events hold a
  `type: None`, `status: Failed` event, "Cannot connect to Microsoft 365. Failed to connect to
  https://restoreprooflab-my.sharepoint.com/personal/alice_…", then "Restore session failed". No
  event names the item ([`w1.0-c-od-user-events`](veeam-lab/w1.0-c-od-user-events.json)).
- SharePoint: `result` `Failed`, "0 items processed", but statistics `totalItemsCount 0` with an
  `errors` array: "Restore operation failed with error: Cannot connect to Microsoft 365. Failed
  to connect to https://restoreprooflab-admin.sharepoint.com/.."
  ([`w1.0-c-sp-user-statistics`](veeam-lab/w1.0-c-sp-user-statistics.json),
  [`w1.0-c-sp-user-events`](veeam-lab/w1.0-c-sp-user-events.json)).
- Mail: the same as SharePoint, "Restore operation failed with error: Failed to open mailbox:
  restoretest@…" ([`w1.0-c-mail-user-statistics`](veeam-lab/w1.0-c-mail-user-statistics.json),
  [`w1.0-c-mail-user-events`](veeam-lab/w1.0-c-mail-user-events.json)).

So a failure can report `totalItemsCount` 0 or 1, with or without `errors`. Only `result` and the
events were consistent.

These were infrastructure failures (sign-in), so `error`, not `fail`.

**Refused at the POST** (a 400, no session): "Missing mandatory parameters: Folder."
([`w1.0-c-mail-cert-restore-no-folder-400`](veeam-lab/w1.0-c-mail-cert-restore-no-folder-400.json)),
"… CasServer." ([`w1.0-c-mail-user-restore-no-casserver-400`](veeam-lab/w1.0-c-mail-user-restore-no-casserver-400.json)),
"… userName." without credentials.

**Partial** (`Warning`, or some items failed beside restored ones): **not seen yet**.

**The script's verdict "Veeam says restored"** needs all of:

1. `state == Stopped` and `result == Success`;
2. `Statistics.restoredItemsCount` equal to the number of items sent;
3. a `Restore` event with `status == Success` and `itemName` equal to each sent item's name
   (all types);
4. for SharePoint and OneDrive, a `Statistics.items[]` entry with `status == Success` whose `id`
   is the item's: for OneDrive the document ID, for SharePoint the list item GUID that ends the
   document ID (§10.1). The earlier revision (§1) matched this rule by name.

Events carry only a name, so no two items of one call may share one: the script refuses such a
call, and W2.5 splits same-named mails of one mailbox into separate calls. Separate calls don't
help files: `restoreTo` and `copyTo` drop the source path, so two `Document.docx` (from two
folders of one OneDrive, or from two sources) land on one target file, the second a new version
of the first (`documentLastVersionAction: Merge`), and the Graph read-back sees only the second.
So W2.5 refuses a sample with two SharePoint files, or two OneDrive files, of one name (ASCII
case-insensitive), before any Veeam request (the W2.5 review entry in `docs/decisions.md`); the
sampler (W2.6) must not pick two of one name. Two selectors that resolve to one backup item are
refused too, before any restore POST.

Every field the verdict reads (`result`, `restoredItemsCount`, `items`, the events' `results`)
must be there and of the expected JSON kind. Otherwise there is no verdict (exit 3), never
"NOT restored": a format change is not a failed restore.

Only then does the Graph read-back decide `pass` or `fail` per item. W1.7's contract
(`RestoreStatus::succeeded` in `rp/connector.hpp`) asks for 1 and 2. Rules 3 and 4 are a proposal
for W2.5: they tie the count to the items actually sent.

## 13. Several items in one call

Five mails in one call ([`w2.4-mail-x5-events`](veeam-lab/w2.4-mail-x5-events.json)) against one
([`w2.4-mail-x1-events`](veeam-lab/w2.4-mail-x1-events.json)):

| Run | Start → first item event | Items | Last item → "completed" | Total |
|---|---|---|---|---|
| mail x1 | 22 s | 0.06 s | 10 s | 32 s |
| sp x1 | 31 s | 5.05 s | 10 s | 46 s |
| od x1 | 23 s | 0.06 s | 10 s | 34 s |
| mail x5 | 71 s | 0.33 s for all 5 | 10 s | 81 s |

- The five items themselves took a third of a second. The longer run is all before the first
  item event. One run of each, so there is no rule to draw from 71 s vs 22 s. The Veeam log of
  that session (§10.3) may say where the time went. Not read.
- The last item always came 10 s before "Restore session completed".
- The 5 s poll adds up to 5 s to each wait.

Per-item results: for mail, only the events (`items[]` is empty). For files, `Statistics.items[]`
and the events. W1.7's `RestoreResult` carries only a total (`items_restored`); W3.3 needs to
know which items Veeam says failed, so W2.5 should add a per-item outcome.

Owner decision (`docs/decisions.md` 2026-09-28, W2.4): **one restore call per source container**
with all its sampled items. A sample with mails from alice and from bob is two calls, two restore
sessions (`RestoreResult.session_ids`). Two restore calls from one explore session were not tried.

## 14. Quirks

- **The targets are in the backup** since 2026-09-27 (§4.4): never sample from a target;
  canaries only from the canary sources, the random sample from real data outside the targets
  and the canary locations.
- **A restored mail keeps its `receivedDateTime`** (`2026-09-24T22:14:4xZ` here, the original's)
  and gets a **new Graph message ID** (it is a new message in another mailbox). L1.4 and W1.0
  showed it keeps its `internetMessageId`; W2.4 didn't read that field again. Match on
  `internetMessageId`, and empty the targets before each run (an old copy looks the same).
- **SharePoint rewrites docx and xlsx.** W2.4 restored pdfs only. W1.0 showed a restored docx has
  new bytes but the same `office-v1` hash (feasibility §2d), so compare Office files with
  `office-v1`, never whole-file SHA-256.
- **The explore session's `details`** count its restores after it stops (§11).
- **`clientHost`** reads `localhost:4443 (via: [::ffff:127.0.0.1])` for explore sessions and
  `[::ffff:127.0.0.1]` for restore sessions. Don't use it to tell them apart; use the IDs.
- **Event `title`** varies for the same outcome (§10.2).
- **Statistics `itemType`** is `SharePointItem` for OneDrive files.
- **The restoretest mailbox's `name`** in Veeam is "Restore⏎  Test"
  ([`w2.4-mail-x5-mailboxes`](veeam-lab/w2.4-mail-x5-mailboxes.json)). Match on `email`.
- **Session names** embed the point in US format, and the log file name uses local time. Parse
  neither.

## 15. Proposed Veeam result → status mapping (W2.5, W3.3)

For W2.5's `RestoreStatus` (`rp/connector.hpp`) and W3.3's table in `docs/verification.md`.
Infrastructure problems are `error`, never `fail` (CLAUDE.md). When unsure, `error`.

| What Veeam showed | Connector (W2.5) | Test status (W3.3) | Seen |
|---|---|---|---|
| Guard refusal | exception; no restore POST | `error` | self-test only (§6) |
| An item matches several entries in the explore session (ambiguous) | exception | `error` (the sample wasn't tested) | no |
| The source container can't be found or listed in the explore session | exception | `error` | no |
| A canary the manifest dates before `backupTime` has zero matches | the item recorded as missing | `fail`: the backup lacks the item (proposal; W3.3 settles it, §18) | no |
| Restore POST 4xx (validation, missing credentials) | exception; nothing started | `error` (our bug or config) | W1.0 400s |
| POST 401 or `ResourceAccessDenied` | `AuthError` | `error` | no |
| POST 5xx, timeout, transport error: the check (§8) finds exactly one session | continue with it | as the session decides | no |
| … finds none or several | exception, not resent | `error` | no |
| `Stopped`, `Success`, `restoredItemsCount` = N, every item's event (and file statistics entry) `Success` | `succeeded` | Graph decides `pass`/`fail` per item | all four runs |
| 0 restored in total, and an event message is infrastructure or auth ("Cannot connect to Microsoft 365", "Failed to open mailbox", "missing the required application permissions", AADSTS in Veeam's log) | exception (`AuthError` or `Error`), not a status | `error` | W1.0 user credentials |
| 0 restored in total otherwise, whatever `result` says (`Failed`; `Warning` or `Success` with 0) | `failed` | `fail` | no |
| `Warning`, or `Success` with 0 < `restoredItemsCount` < N, or some items `Failed` beside restored ones | `partial` | restored items → Graph; a failed item is `fail` when its message is about the item or the backup, `error` when it is infrastructure (proposal, see below) | no |
| Still `Working` after 20 min | exception; record the session ID; not resent | `error` | no |
| Session 404, or 6 polls in a row failing | exception | `error` | no |
| Statistics or events unreadable | exception | `error` | no |

How this fits W1.7's contract (`rp/connector.hpp`, `docs/decisions.md` 2026-09-27):

- **Kept.** The order `not_run`, `failed`, `succeeded`, `partial`, first fit wins: 0 restored in
  total is `failed` whatever `result` says, so `Success` or `Warning` with 0 is `failed`, never
  `partial`. "A failure to run at all … is an exception, never a status", and `failed` → `fail`.
- **How the infrastructure case fits.** A session that restored nothing because Microsoft 365
  refused the sign-in (W1.0) is a failure to run, not a failed restore. W2.5 raises it as an
  exception after reading the events, so it never reaches `failed`, and `failed` → `fail` stays
  true.
- **Changed, a proposal.** The contract's "`partial` → fail unless every item verifies" would
  report an infrastructure failure of some items as `fail`, which CLAUDE.md forbids. The
  proposal: a failed item whose message is infrastructure makes the run `error`. This needs a
  per-item outcome in `RestoreResult` (§13). W3.3 settles it and amends the contract's comment.
- **Changed, a proposal.** veeam-notes §5.4 says zero or several matches for a sampled item is
  `error`. The zero-match row above keeps that for everything except a canary the manifest dates
  before `backupTime`. W3.3 settles it.

The per-item conditions in the `succeeded` row are the proposal of §12.

## 16. Mapping the configured IDs to Veeam's names (owner decision 3; details for W2.5, W2.7)

Owner decision 3 (`docs/decisions.md` 2026-09-28, W2.4): the config keeps its Graph IDs, no new
keys. The Worker resolves them at run time through Graph with its own read-only app, then finds
the matching Veeam objects in the explore session.

| Config key | Graph call (Worker app) | Gives | Veeam body field |
|---|---|---|---|
| `test_mailbox` | none | the address | `mailbox`, `impersonationAccountName` |
| (fixed) | none | `Inbox` | `folder` (mail) |
| `test_site_id` | `GET /sites/{id}` → `webUrl` | `https://restoreprooflab.sharepoint.com/sites/RestoreTest` | `siteURL` |
| `test_library_id` | `GET /drives/{id}?$select=name,webUrl,sharePointIds` | `name` `RestoreTarget`; `sharePointIds.listId` `ffec069d-…`; `sharePointIds.siteUrl` | `list` |
| `test_onedrive_drive_id` | `GET /drives/{id}` → `webUrl` | the OneDrive's URL | match Veeam's `OneDrives` entry by `url`; send its `{id, name, url}` as `onedrive` |
| `test_onedrive_folder_id` | `GET /drives/{d}/items/{id}` | `name` `RestoreTarget` | `folder` (OneDrive) |

What the recorded Graph replies already show
([`restoretarget-drive-200`](../../worker/tests/fixtures/graph/restoretarget-drive-200.json),
[`onedrive-folder-200`](../../worker/tests/fixtures/graph/onedrive-folder-200.json)):

- the library drive's `name` is `RestoreTarget`, and its `sharePointIds.siteUrl` equals the
  `siteURL` sent, exactly;
- its `sharePointIds.listId` is the list ID at the end of Veeam's library ID;
- the folder's `parentReference.siteId` (`6d600fc0-…e834`) is the first GUID of Veeam's OneDrive
  `id`. That is a second check besides the URL.
- W2.7 review (2026-09-30): the folder GET with `sharepointIds` selected answers the OneDrive's
  `sharepointIds.siteUrl`, which equals Veeam's `onedrive.url` exactly, and `siteId` + `webId`,
  which run together are Veeam's OneDrive `id`. The guard's layer 2 requires both
  (`docs/decisions.md` 2026-09-30), so no drive-level read is needed.

Not tried in W2.4: whether the Worker app may read the OneDrive **drive** (its grant is on the
folder, `docs/security/graph-permissions.md`), and whether that drive's `webUrl` needs trimming
(a drive's `webUrl` usually ends in the library, such as `/Documents`) to equal Veeam's
personal-site URL. W2.5 checks both. If the drive can't be read, the folder's
`parentReference.siteId` is the fallback key.

`TargetGuard` makes two checks, and the first doesn't trust configuration. The 2026-09-22
decision rejected "trusting configuration: a typo in an MSP's config would be a data-loss
incident", and the 2026-09-24 config entry says "`TargetGuard` must resolve them and check they
are the `RestoreTest` library or folder" (`RestoreTarget` since 2026-09-25).

1. **The resolved targets are the dedicated restore targets**, before any Veeam call of
   `restore_sample`. A configured ID proves nothing by itself: the drive ID of a live library
   passes `parse_config`'s shape rules and resolves to a real name. This tenant's default
   library is `Dokumenty`, which no English forbidden-name list catches. So the resolved names
   must be the fixed target names, as `test_mailbox` must be `restoretest@<domain>`.
   W2.2's `TargetReader` already checks this when it reads the targets (`rp/graph_targets.hpp`,
   `kRestoreTargetName`, `WrongTargetError`; `docs/decisions.md` 2026-09-28, W2.2 and its
   review):
   - the library's drive `name` is exactly `RestoreTarget`, its `webUrl` ends in
     `RestoreTarget`, its `driveType` is `documentLibrary`, and its `sharePointIds` put it in the
     configured site;
   - the OneDrive folder's `name` is exactly `RestoreTarget`, it is a folder directly under the
     root of the configured drive, and that drive's `driveType` is `business`;
   - the mail target is `Inbox` of `restoretest@<domain>` (`parse_config`,
     `RestoreTargets::from_config`).
   W2.7 runs the same checks, or calls the same code, before a restore, and adds one:
   neither target is a canary location. *(As built in W2.7: the exact name `RestoreTarget` and
   the `webUrl` rule keep the canary library and folder out, both being `RestoreTest`; no list
   ID is compared with the canary library's, since the config carries no canary ID.)* A
   target that fails any of them is a guard violation (`error`). Onboarding a customer creates
   the two `RestoreTarget`s under that name.
2. **Veeam's body names exactly those targets** (§6), checked on the exact text immediately
   before the POST.

The fixed forbidden names (§6) stay as an extra check. They are not what keeps a live library
out.

*(W2.7: check 1 is `rp::TargetGuard::check_spec` in `worker/include/rp/target_guard.hpp`, on the
checks `TargetReader` shares from `rp/target_guard_graph.hpp`; check 2 is
`rp::veeam::check_restore_request`.)*

## 17. Fixtures for W2.5 and Q2.1 (`worker/tests/fixtures/veeam/`)

Take the `response` from each evidence file, as in veeam-notes §9. The restore bodies in the
`request` parts are the expected bodies for W2.5's tests (credentials `[REDACTED]`).

| Fixture | From | Tests |
|---|---|---|
| `restore-mail-200.json`, `restore-sp-200.json`, `restore-od-200.json` | `w2.4-mail-x1-restore`, `w2.4-sp-x1-restore`, `w2.4-od-x1-restore` | the POST path and exact body per type; `sessionId` parsed |
| `restore-mail-x5-200.json` | `w2.4-mail-x5-restore` | five items in one body, one call per container |
| `restore-session-working.json`, `restore-session-stopped.json` | `w2.4-*-session-working`, `w2.4-*-session` | polling; `endTime` without `Z`; `details` |
| `sessions-after-post.json` | `w2.4-mail-x1-sessions-after-post`, `w2.4-mail-x5-sessions-after-post` | the duplicate check keeps exactly one: drops the explore session by ID and older sessions by `creationTime` |
| `statistics-sp.json`, `statistics-od.json` | `w2.4-sp-x1-statistics`, `w2.4-od-x1-statistics` | per-file `items[]` by name |
| `statistics-mail-x5.json` | `w2.4-mail-x5-statistics` | empty `items[]`: per-item results from events |
| `statistics-409.json` | `w1.4-session-statistics-working-409` | 409 = wait |
| `events-mail-x5.json` | `w2.4-mail-x5-events` | out of order; match by `itemName`; varying `title` |
| `events-mail-x1.json` | `w2.4-mail-x1-events` | one item whose `title` is "Folder successfully restored": `type` and `status` decide, not `title` |
| `organizations-apps-200.json` | `w2.4-mail-x1-org` | the credential cross-check: `applicationId` and `applicationCertificateThumbprint` in both settings |
| `events-sp.json`, `events-od.json` | `w2.4-sp-x1-events`, `w2.4-od-x1-events` | site-only `target`; `copyTo` `source` is the destination |
| browse: `mail-items.json`, `sp-libraries.json`, `sp-documents.json`, `sp-document.json`, `od-folders-root.json`, `od-documents.json`, `od-document.json` | `w2.4-mail-x5-items`, `w2.4-sp-x1-libraries` (RestoreTarget present), `w2.4-sp-x1-documents`, `w2.4-sp-x1-document`, `w2.4-od-x1-folders-root` (`/RestoreTarget` present), `w2.4-od-x1-documents`, `w2.4-od-x1-document` | exact matching; never a target as source; `_links`/`_actions` removed |
| `restore-400-no-folder.json`, `restore-400-no-casserver.json` | `w1.0-c-mail-cert-restore-no-folder-400`, `w1.0-c-mail-user-restore-no-casserver-400` | 4xx → nothing started, `error` |
| `od-silent-failure-*.json` | `w1.0-c-od-user-session`, `-statistics`, `-events` | `Failed` with `failedItemsCount 0`: `failed`, classified `error` by the message |
| `mail-failure-*.json`, `sp-failure-*.json` | `w1.0-c-mail-user-*`, `w1.0-c-sp-user-*` (`-session`, `-statistics`, `-events`) | `errors[]` present, `totalItemsCount 0` |

Missing, to make by hand or record later: a `Warning` session and a partial restore (§18), a
5xx or timeout on the POST, a session 404 while polling.

## 18. Open points

- **The Worker's restore credential** (§7): a spike before W4.5. Vault copy, run-time export by
  thumbprint, or a dedicated app (which would need at least `Group.ReadWrite.All` for
  SharePoint).
- **Partial failure.** No `Warning` or mixed result was seen. Its statistics and events shape is
  unknown until one is recorded. §15's `partial` row is a proposal until then.
- **Stopping mid-restore.** Untested: Ctrl+C during the poll, and stopping the explore session or
  the restore session while the restore session is `Working`. The script leaves a restore that
  may still be running alone, and the explore session it came from too (§9);
  `08-sweep-sessions.ps1` stops nothing while one may be running. W2.5 needs to know whether Stop
  cancels a restore and what it reports.
- **A localised Inbox.** The source folder is found by `name=Inbox`, and the body's `folder` is
  `Inbox`. In a tenant in another language the Inbox may have another name. The folder object
  has `"category": "Inbox"` ([`w2.4-mail-x1-folder-inbox`](veeam-lab/w2.4-mail-x1-folder-inbox.json)),
  a better key for the source. What `"folder": "Inbox"` does in a localised target mailbox is
  unknown.
- **Veeam's log** (§10.3): each file was complete before its session's `endTime`; the 0-byte
  readings came from the directory listing's size, not from a late flush. Its contents weren't
  read in W2.4. If the Worker attaches it to the evidence bundle, it opens and reads it after
  `Stopped`, and scrubs it.
- **Clock agreement** for the duplicate check (§8) when the Worker and Veeam run on different
  machines.
- **Two restore calls from one explore session** (for mails from two mailboxes): not tried.
- **Cleanup.** The owner removed the 8 restored items by hand (§1), and the one from mail r1. W3.4 needs write
  permissions the Worker app doesn't have (`docs/security/graph-permissions.md`).
- **Canary missing from the restore point** (§4, §15): zero matches for a canary the manifest
  dates before `backupTime` is proposed as `fail`, not `error`. W3.3 settles it.
