# Veeam REST API feasibility (W1.0)

The spike that decides how the Worker talks to Veeam Backup for Microsoft 365 before any
`VeeamClient` code is written (guide, "Connector assumptions and the Sprint 1 gate"). Run on
2026-09-25/26 against the lab server (`docs/environment.md`): Veeam Backup for Microsoft 365
**8.6** (`Config.xml` `ProductVersion="8.6.0.237"`; "13.6.0.237" is the build number Veeam
writes in its logs, [KB4106](https://www.veeam.com/kb4106)), REST API **v8** on
`https://localhost:4443`, Community Edition, organisation `RestoreProofLab.onmicrosoft.com`
(modern app-only authentication), restore point `71ac3d9c…` (2026-09-25 19:37:15 UTC). The
two accounts come from L1.6 (`lab/tenant.md`, `docs/environment.md`). All calls were made
with PowerShell 7 and raw REST, not Bruno.

Every request and response is saved, scrubbed, in [`veeam-lab/`](veeam-lab/README.md); file
names are given as *evidence* below.

## Answer

**Default authentication mode: admin.** Operator mode is not supported in Stage 1.

| Lab check | Answer | Date (UTC) |
|---|---|---|
| a) Operator refresh-token lifetime | **Immediate refresh: yes.** 48 h and 7 days: **pending** (due 2026-09-28 15:06:36 and 2026-10-03 15:06:36). Already decided without them: **any restart of the Veeam REST service invalidates every token** (admin and operator), so operator mode can't run unattended through a reboot or a Veeam update whatever the lifetime is | 2026-09-26 |
| b) Operator restore scope | **SharePoint: yes**, `rp-canary-01.pdf` restored as `rpoperator` into `RestoreTarget`. **Mail and OneDrive: no**, the operator endpoints can only restore into the original mailbox / OneDrive, so `restoretest` and alice's `/RestoreTarget` can't be named (not attempted, by decision). **Outside the scope: refused** | 2026-09-26 |
| c) Exact v8 restore-to-another-location bodies | **Yes, recorded for all three.** With the app certificate: all three **restored** (1/1 each). With user credentials: all three **failed** on MFA (AADSTS50076). Results are **asynchronous** | 2026-09-26 |
| d) Export vs Graph | **Yes.** pdf: export bytes = Graph bytes = manifest. Mail: exported MSG body `text-v1` = Graph = manifest, `internetMessageId` equal. docx: `office-v1` of the export **and of a restored copy** = manifest `content_sha256` | 2026-09-26 |

Why admin, in one paragraph: the connector's job is to restore into the three restore
targets, and only the admin endpoints can name them (b). Operator sessions also end with every
REST service restart (a), need an interactive browser sign-in to start again (the tenant's
security defaults block the device-code flow), and need a multi-tenant Entra app. Admin mode signs in again unattended with a password
grant. The Sprint 1 gate's fallback (the PowerShell module) isn't triggered: admin mode passes
everything. The decision and its consequences are in `docs/decisions.md` (2026-09-26).

## 1. Capabilities the connector relies on

Documentation links are to Veeam's help center, pages for build 8.6.0.1102 (checked
2026-09-26); the REST reference is the v8 one. "Lab" is what this server did.

| Capability | Answer | Veeam documentation |
|---|---|---|
| REST API settings | Enabled by default here: port 4443, access-token lifetime 60 min (`AuthTokenLifeTime`), Swagger UI on, a self-signed certificate, "operator authentication only" off. Set in General Options → REST API or with `Set-VBORestAPISettings`. **Lab:** the default certificate is `CN=Veeam Software` with **no SAN and no extensions**, so no host name verifies (§5.1) | [REST API settings](https://helpcenter.veeam.com/docs/vbo365/guide/vbo_rest_api_settings.html), [Set-VBORestAPISettings](https://helpcenter.veeam.com/docs/vbo365/powershell/set-vborestapisettings.html) |
| Admin authentication | `POST /v8/token`, `grant_type=password`, form-encoded or JSON. Needs the **Veeam Backup Administrator** role ("in version 8, only the Veeam Backup Administrator role is available"; by default the local Administrators group has it). The role is set only in the console (Manage Users & Roles); no cmdlet or REST endpoint exists. **Lab:** a standard local user with the role and no admin group works, also after interactive and RDP logon are denied (§2 L1.6) | [Users and roles](https://helpcenter.veeam.com/docs/vbo365/guide/manage_users_roles.html), [REST authorization](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SectionOverview#section/Authorization-and-Security) |
| Operator authentication | `grant_type=operator`, `client_id=<oid>.<tid>`, `assertion=<Entra access token for api://<portal app>/access_as_user>`. Needs "restore operator authentication" (with its own certificate) and Restore Portal (an Entra app and a certificate) enabled, and a restore operator role | [Restore operator authentication](https://helpcenter.veeam.com/docs/vbo365/guide/vbo_authentication_settings_restore_operators.html), [Restore Portal settings](https://helpcenter.veeam.com/docs/vbo365/guide/vbo_restore_portal_settings.html), [Portal app permissions](https://helpcenter.veeam.com/docs/vbo365/guide/ssp_ad_application_permissions.html), [Operator roles](https://helpcenter.veeam.com/docs/vbo365/guide/ssp_new_operator_role.html), [Authorization for restore operators](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SectionOverview#section/Authorization-and-Security/Authorization-for-Restore-Operators) |
| Token refresh | `grant_type=refresh_token`. The docs give the access-token lifetime (60 min) but **no refresh-token lifetime**. **Lab:** refresh tokens rotate and are single-use; all tokens die with a REST service restart (§2 a) | [REST authorization](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SectionOverview#section/Authorization-and-Security) |
| Restore points | `GET /v8/RestorePoints` (filters `organizationId`, `from`, `to`, …); there is no `/v8/Organizations/{id}/RestorePoints` (the guide's path). Operators: `GET /v8/Organization/LoggedInUser/RestorePoints?rbacItem=<JSON>` | [RestorePoint](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/RestorePoint) |
| Explore (restore) sessions | Opened **by date and time**, not by restore point ID: `POST /v8/Organizations/{organizationId}/explore` (`Organization_Explore`) `{dateTime, type (Vex, Vesp, Veod or Vet), showDeleted, showAllVersions}` → 201 with the session. Operators use `POST /v8/Organization/OperatorExplore` with a `scope` | [Organization](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/Organization), [RestoreSession](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/RestoreSession) |
| Mail restore to another location | `POST …/organization/mailboxes/{mailboxId}/items/restoreTo`: target `mailbox` (address) and `folder` | [ExchangeItem_RestoreItemsToAction](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/ExchangeItem#operation/ExchangeItem_RestoreItemsToAction) |
| SharePoint restore to another location | `POST …/Organization/Sites/{siteId}/Documents/restoreTo`: target `siteURL` and `list` (the library's **display name**) | [SharePointDocument_RestoreDocumentsActionTo](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SharePointDocument#operation/SharePointDocument_RestoreDocumentsActionTo) |
| OneDrive restore to another location | There is no `restoreTo`; it is **`copyTo`**: `POST …/Organization/OneDrives/{oneDriveId}/Documents/copyTo`, target `onedrive` `{id, name, url}` and `folder` (a **name** in the target's root) | [OneDriveDocument_CopyToDocumentsAction](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/OneDriveDocument#operation/OneDriveDocument_CopyToDocumentsAction) |
| Restore credentials | Every admin restore-to-another-location body takes `applicationId` + `applicationCertificate` (Base64 PFX) + `applicationCertificatePassword`, or `userName` + `userPassword`, or `userCode` (a device code). **Lab:** they are **mandatory**: without them, 400 "Missing mandatory parameters: userName" (mail: "CasServer"). Only the certificate works unattended; user credentials fail on MFA, which Veeam doesn't support for REST | same pages; [MFA](https://helpcenter.veeam.com/docs/vbo365/guide/mfa.html) |
| Operator restores | `…/items/operatorRestore`, `…/Documents/operatorRestore`: **no target mailbox, site or OneDrive and no credentials**. Mail takes only a `folder`, SharePoint a `list` in the original site, OneDrive restores to the original (`RESTOperatorRestoreToOriginalOneDriveDocuments`). "Restore Portal … restores data to the original user mailbox or SharePoint site" | [Restore Portal considerations](https://helpcenter.veeam.com/docs/vbo365/guide/ssp_considerations.html), [SharePointDocument_OperatorRestore](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SharePointDocument#operation/SharePointDocument_OperatorRestore) |
| Item export | Mail: `…/items/{itemId}/save` (MSG) or `…/items/Save` (bulk); `exportToPst` needs Outlook on the server. SharePoint and OneDrive: `…/Documents/{documentId}/save` `{asZip}`; bulk `…/Documents/save` is always a ZIP. All return `application/octet-stream`. **Lab:** operators may export too | [ExchangeItem](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/ExchangeItem), [SharePointDocument](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SharePointDocument), [OneDriveDocument](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/OneDriveDocument) |
| Synchronous or asynchronous results | **Asynchronous.** v8 changelog: "All POST methods performing restore and copy operations return the `sessionId` property value instead of statistical information". Results via `GET /v8/RestoreSessions/{sessionId}` (`state`, `result`), `/Statistics` and `/Events` (§3) | [Changelog](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/SectionChangelog), [RestoreSession](https://helpcenter.veeam.com/references/vbo365/8/rest/tag/RestoreSession) |
| Community Edition | Up to 10 users, 1 TB SharePoint, 10 teams; "does not have limitations in terms of the product functionality"; "restore does not require licenses". The one exception found: "MFA is not supported in the Community Edition mode". **Lab:** REST, restore operators and Restore Portal all work on Community Edition (licence `Community`, 10 users, 4 used) | [Licensing](https://helpcenter.veeam.com/docs/vbo365/guide/vbo_licensing.html), [MFA](https://helpcenter.veeam.com/docs/vbo365/guide/mfa.html) |

## 2. The lab checks

### L1.6: both accounts (prerequisite)

- **`rp-veeam`** (admin mode), a standard local user in the Veeam Backup Administrator role:
  - password grant 200 (`l1.6-admin-token`), `GET /v8/RestorePoints` lists both points
    (`l1.6-admin-restore-points`), and `/Organizations`, `/RbacRoles`, `/Jobs` answer 200;
  - before the role, and with a wrong password, the grant gives the same answer, so the two
    can't be told apart: first an empty **500** (`l1.6-admin-token-no-role`,
    `-wrong-password`, `-unknown-user`), then, after a REST restart, **401** "The server has
    rejected the client credentials." (`…-traced`);
  - interactive logon denied (`LogonUser` type 2: error 1385), network logon allowed; the
    REST grant still works (`l1.6-admin-token-after-deny-logon`).
- **`rpoperator`** (operator mode):
  - `isOperator: true` (`l1.6-operator-info`), scope alice, bob, restoretest and the site
    (`l1.6-operator-effective-scope`);
  - it lists both restore points for alice and the site (`l1.6-operator-restore-points-alice`,
    `-site`; `rbacItem` is the **JSON** of a scope item);
  - administrative endpoints answer **401** (`l1.6-operator-admin-sweep`: `/RestorePoints`,
    `/Organizations`, `/Organizations/{id}/Users`, `/Jobs`, `/BackupRepositories`,
    `/RbacRoles`, `/Proxies`, `/Organizations/{id}/RbacRoles`); the admin explore answers 400
    "Exploring a specific organization or a job is not available for restore operators."
    `/v8/RestoreSessions` answers 200 with the operator's own sessions only.

### a) Operator refresh-token lifetime

How the operator token was obtained, and what it took:

1. The docs' **device-code flow is blocked by the tenant's security defaults**: AADSTS530035
   at the device login (2026-09-26 14:13:27 UTC). An interactive sign-in (authorization code +
   PKCE, MSAL, loopback redirect) for `api://<portal app>/access_as_user` works.
2. Veeam trades the assertion on-behalf-of, using the portal app and its certificate against the
   **`/common`** authority, so the portal app must be **multi-tenant**. Single-tenant gave
   AADSTS50194, which the API reports only as 401 "The server has rejected the client
   credentials." (the reason was in the REST trace log).
3. Without `disable_antiforgery_token=true` in the grant, the refresh fails with **500**
   `NotProvidedAntiforgeryTokenException` (`w1.0-a-operator-refresh-antiforgery-500`).

Results:

| Step | UTC | Result | Evidence |
|---|---|---|---|
| Operator grant (chain A) | 2026-09-26 14:24:04.014 | 200, `expires_in` 3600, `userName` `<oid>.<tid>` | `w1.0-a-operator-token-no-antiforgery` |
| Refresh immediately | 14:24:05.448 | **200**; the refresh token rotated | `w1.0-a-operator-refresh-t0` |
| The used refresh token again | 14:24:05.979 | **401**: single-use | `w1.0-a-operator-refresh-reuse-old` |
| REST service restart | 15:05:50 | pre-restart admin access token 401; admin and operator refresh tokens 401 "Refresh token is not valid" | `w1.0-a-restart-*` |
| Chain A after the restart | 15:06 | 401 "Refresh token is not valid" (chains A and B of 14:24 died in the restart) | `w1.0-a-operator-refresh-chainA-after-restart` |
| New chain A2: grant, then refresh | 15:06:35.497 / 15:06:36.547 | 200 / 200 | `w1.0-a-operator-token-chain-a2`, `…-refresh-t0-chain-a2` |
| New chain B2: grant only | 15:06:36.583 | 200 | `w1.0-a-operator-token-chain-b2` |
| **48 h: chain A2** | due **2026-09-28 15:06:36** | pending | `w1.0-a-operator-refresh-48h` |
| **7 days: chain B2** | due **2026-10-03 15:06:36** | pending | `w1.0-a-operator-refresh-7d` |

A2 and B2 are kept apart because rotation means a 48 h refresh would restart B's clock. The
tokens and the checker are outside the repo (`%LOCALAPPDATA%\RestoreProofLab\w1.0\`,
DPAPI); run `pwsh -File "$env:LOCALAPPDATA\RestoreProofLab\w1.0\refresh_check.ps1" -Chain A`
(or `-Chain B`) when due. It records the REST service's start time, because a reboot or a
Veeam update before then kills both chains and says nothing about lifetime.

### b) Operator restore scope

| Attempt (as `rpoperator`) | Result | Evidence |
|---|---|---|
| `OperatorExplore` Vesp, scope the RestoreTest site | 201 | `w1.0-b-operator-explore-sp` |
| `rp-canary-01.pdf` → `list: "RestoreTarget"` (the same site) | 200 `{sessionId}`; restored 1/1 in 45 s. Graph: in `RestoreTarget`, SHA-256 = manifest; the canary unchanged (same item ID, `lastModifiedDateTime`) | `w1.0-b-operator-sp-restore`, `-statistics`, `-events` |
| `RP-CANARY-0001` → `restoretest` | **Not possible**: `operatorRestore` has no mailbox field, only the original mailbox and a `folder`. Not sent (it could only restore into alice's mailbox) | schema `RESTOperatorRestoreOptions` (`ExchangeItem_OperatorRestore`) |
| `rp-canary-11.pdf` → alice `/RestoreTarget` | **Not possible**: `RESTOperatorRestoreToOriginalOneDriveDocuments`. Not sent | schema (`OneDriveDocument_OperatorRestore`) |
| Outside the scope: the admin's mailbox, the admin's OneDrive, the tenant root site | **Refused**: 500 "User rpoperator@… cannot manage selected object." | `w1.0-b-operator-explore-out-of-scope-*` |

Two side effects:

- **Orphaned sessions.** A refused out-of-scope explore still creates a restore session. The
  OneDrive one stayed `Working` for 36 minutes until the admin stopped it. The operator can't
  see or use it: its session list is filtered (`w1.0-b-operator-orphan-session-probe`).
- **One restore per operator session.** After one `operatorRestore` the explore session is
  `Stopped`, and the next call on it (a document save) got 500 "The session was forcibly
  closed." A new explore session works.

### c) Exact v8 restore bodies

Admin session opened with `POST /v8/Organizations/{organizationId}/explore`, a fresh
`rp-veeam` token per run, and targets asserted and checked empty through Graph before each
call. Bodies as sent (credentials shown as field names only; values are in no file):

```jsonc
// Mail: POST /v8/RestoreSessions/{id}/organization/mailboxes/{mailboxId}/items/restoreTo
{ "mailbox": "restoretest@RestoreProofLab.onmicrosoft.com", "folder": "Inbox",   // folder: required in practice
  "items": [{ "id": "<Veeam item id>" }],
  "changedItems": true, "deletedItems": true, "markRestoredAsUnread": false,
  "excludeDrafts": false, "excludeDeletedItems": false,
  "excludeInPlaceHoldItems": true, "excludeLitigationHoldItems": true,
  "officeRegion": "Worldwide", "officeOrganizationName": "RestoreProofLab.onmicrosoft.com",
  // certificate:
  "applicationId": "<Veeam org app id>", "applicationCertificate": "<Base64 PFX>",
  "applicationCertificatePassword": "…", "impersonationAccountName": "restoretest@…"
  // or user: "userName", "userPassword", "casServer": "outlook.office365.com" (required with a user)
}
// SharePoint: POST /v8/RestoreSessions/{id}/Organization/Sites/{siteId}/Documents/restoreTo
{ "documents": [ <the full RESTSharePointDocument from GET …/Documents> ],
  "siteURL": "https://restoreprooflab.sharepoint.com/sites/RestoreTest", "list": "RestoreTarget",
  "sendSharedLinksNotification": false, "documentVersion": "Last", "documentLastVersionAction": "Merge",
  "officeRegion": "Worldwide", "organizationName": "RestoreProofLab.onmicrosoft.com",
  "applicationId": "…", "applicationCertificate": "…", "applicationCertificatePassword": "…"   // or userName/userPassword
}
// OneDrive: POST /v8/RestoreSessions/{id}/Organization/OneDrives/{oneDriveId}/Documents/copyTo
{ "documents": [ <the full RESTOneDriveDocument> ],
  "onedrive": { "id": "<alice's OneDrive id in the session>", "name": "Alice Test",
                "url": "https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com" },
  "folder": "RestoreTarget", "changedItems": true, "deletedItems": true,
  "documentVersion": "Last", "documentLastVersionAction": "Merge",
  "officeRegion": "Worldwide", "organizationName": "RestoreProofLab.onmicrosoft.com",
  "applicationId": "…", "applicationCertificate": "…", "applicationCertificatePassword": "…"   // or userName/userPassword
}
```

Every call answered `200 {"sessionId": "<uuid>"}` within 0.5 s, whether the restore later
worked or not. The `sessionId` is a **new** restore session, not the explore session.

| | Certificate (`1fd2609d…`, Veeam's org app) | User (the global admin, security defaults = MFA) |
|---|---|---|
| Mail | **Restored** 1/1, 37 s: `restoretest` Inbox; Graph: sender, received time, `internetMessageId`, `text-v1` = manifest (`w1.0-c-mail-cert-*`) | **Failed**: "Failed to open mailbox: restoretest@…"; Veeam's restore log: AADSTS50076 for Exchange Online (`w1.0-c-mail-user-*`) |
| SharePoint | **Restored** 1/1, 42 s; Graph SHA-256 = manifest (`w1.0-c-sp-cert-*`) | **Failed**: "Cannot connect to Microsoft 365. Failed to connect to https://restoreprooflab-admin.sharepoint.com/"; AADSTS50076 for Graph (`w1.0-c-sp-user-*`) |
| OneDrive | **Restored** 1/1, 37 s, into alice `/RestoreTarget`; Graph SHA-256 = manifest (`w1.0-c-od-cert-*`) | **Failed**: "Cannot connect to Microsoft 365…" (`w1.0-c-od-user-*`) |

Validation errors met on the way (each a 400 `ParameterValidationFailure`, saved):

- mail without `folder`: "Missing mandatory parameters: Folder." (`w1.0-c-mail-cert-restore-no-folder-400`);
- mail with a user but no `casServer`: "Missing mandatory parameters: CasServer.";
- any type without credentials: "Missing mandatory parameters: userName." (mail: `CasServer`).

The schema marks none of these as required.

### d) Export vs Graph

| Item | Export (as `rpoperator`) | Graph | Manifest | Equal |
|---|---|---|---|---|
| `rp-canary-01.pdf` | `…/Documents/{id}/save {asZip:false}`: 925 bytes, SHA-256 `9c799236…a886` | the canary in the library: same | `content_sha256` same (`bytes`) | **yes** |
| `RP-CANARY-0001` | `…/items/{id}/save`: MSG, 72 704 bytes; body stream (`PR_BODY`, UTF-16) `text-v1` `4e1a9586…9bbe`; `internetMessageId` `<WA1P291MB0278BF62…>` | alice's message (`text` body, ImmutableId): same hash and ID | `body_sha256` same | **yes** |
| `rp-canary-02.docx` | 15 690 bytes = the bytes SharePoint stored (not the 3 263-byte original); `office-v1` `5540efd7…f30b` | — | `content_sha256` same (`office-v1`) | **yes** |
| `rp-canary-02.docx`, **restored** into `RestoreTarget` | — | 15 563 bytes: SharePoint **rewrote it again**, whole-file hash new; `office-v1` `5540efd7…f30b`; unchanged 16 minutes later | same | **yes** |

This closes the question left open in `lab/README.md`: a Veeam restore into the library
keeps the `office-v1` content hash. *W6.1 (2026-10-14) repeated the export in **admin mode**, for
SharePoint and for OneDrive, on 14 real files against their restored copies: 14 of 14 equal
(`veeam-notes.md` §12).* The MSG's sender property is an Exchange X.500 address,
not SMTP; match mail on `internetMessageId` (as L1.4 found).

## 3. How a restore's result is read

1. The restore POST returns `{sessionId}` at once. HTTP 200 says nothing about the restore.
2. Poll `GET /v8/RestoreSessions/{sessionId}`: `state` is `Working`, then **`Stopped`**. While
   it runs, `endTime` is `9999-12-31T23:59:59.9999999`, with no `Z` (`docs/api/veeam-notes.md` §4.1). `result` is `Success`, `Warning` or `Failed`;
   `details` reads like "1 item processed (1 success)". 30–45 s per item here.
3. `GET …/Statistics` answers **409 until the session stops**, then 200 with
   `totalItemsCount`, `restoredItemsCount`, `failedItemsCount`, `skippedItemsCount`, `errors`
   and `items[]` (per item: `id`, `name`, `status`).
4. `GET …/Events` lists "Restore session started", one `Restore` event per item
   (`Success`/`Failed`) and "Restore session completed" or "failed".

Traps seen:

- the OneDrive user-credential failure reported `totalItemsCount 1, restoredItemsCount 0,
  failedItemsCount 0` with **no `errors`**; only `result: Failed` and the events showed it;
- mail statistics have an **empty `items[]`** even on success;
- a `copyTo` event's `source` names the **destination** path.

So success means `result == Success` **and** `restoredItemsCount` equals the number of items
sent, and then the Graph read-back decides `pass`/`fail` (`docs/verification.md`, W3.3).

## 4. Default mode and the Sprint 1 gate

- **Admin mode is the default and the only mode built in Stage 1.**
  - It passes every check, runs unattended, and survives a Veeam restart by signing in again.
  - Its restores need restore credentials in the body. In practice that is an Entra
    application with a certificate, the one unattended option (§5.4).
- **Operator mode fails the checks that matter.**
  - It can't reach two of the three restore targets (b).
  - Its sessions die with every REST restart (a).
  - Starting one again needs an interactive browser sign-in, because the device-code flow is
    blocked where security defaults are on.
  - It needs a multi-tenant app with a certificate and one explore session per restore.
  
  It does pass the SharePoint restore, scope enforcement and export. So "never a Veeam
  administrator" can't be claimed for Stage 1.
- **Gate:** operator mode did not fail all four checks, and admin mode works, so the
  PowerShell-module fallback is not needed. It stays the documented answer for an MSP that
  refuses admin mode.

## 5. Findings for later tasks

1. **TLS (W1.3/W1.5).** The default REST certificate (`CN=Veeam Software`, no SAN, valid to
   2036) fails host-name verification for every name. curl: "CertGetNameString() failed to
   match connection hostname". So `veeam_ca_file` alone can't reach a default install. The
   spike pinned the leaf's SHA-256 instead. W1.5 decides between requiring the MSP to install a
   certificate with the server's DNS name (`Set-VBORestAPISettings -CertificateFilePath`) and a
   pinned-leaf option. Turning verification off stays out. *Settled in W1.5: `veeam_ca_file`
   plus `veeam_cert_sha256`, peer verification on, the key pinned, only the host-name check
   skipped (`docs/decisions.md` 2026-09-26, "Veeam TLS").*
2. **Status codes (W1.5).** Veeam uses **500** for client errors:
   - a refused login before a service restart;
   - the antiforgery refusal;
   - "cannot manage selected object";
   - "session was forcibly closed".
   
   Error bodies are `{"message", "errorCode"?}`. W1.3's retry policy retries 5xx, so
   `VeeamClient` must not treat a `/v8/token` 500 as transient, and should classify by body
   where it can. 401 "The server has rejected the client credentials." covers both wrong
   password and missing role.
3. **Tokens (W1.5, W4.5).** Access tokens last 60 min. Refresh tokens are single-use,
   rotating, and **invalidated by any REST service restart**, so `ensureToken()` must fall
   back to a fresh password grant on any refresh 401. Send `disable_antiforgery_token=true`
   with every grant. Always store the newest refresh token.
4. **Restore credentials (L1.5, W2.4, W4.5): open.** An admin restore needs an Entra app ID
   and its certificate (PFX, Base64) in the body. The lab used Veeam's own backup app, which
   holds broad application permissions. Whether the Worker gets that certificate or a
   dedicated restore app with narrower permissions is open. Either way the PFX is a vault
   secret, and the `RP_*` variables in `worker/include/rp/secrets.hpp` will change.
   *Still open after L1.5 (W2.4).* L1.5 made the Worker's own Graph app, "RestoreProof
   Worker" (`docs/security/graph-permissions.md`). It only reads (the three restore
   targets, and the rest of the RestoreTest site), so it can't be the app in Veeam's restore
   body, since Veeam writes the restored items. Its credential is already a certificate kept as a PFX plus password
   (`docs/decisions.md` 2026-09-27), the form this body takes.
   *After W2.4:* the lab restores with Veeam's own organisation app, its certificate exported
   per run and never stored; the Worker's restore credential stays open until a spike before
   W4.5 (`docs/decisions.md` 2026-09-28, W2.4).
5. **Addressing (W2.4, W2.7).**
   - Mail targets a mailbox **address** plus a folder **name**.
   - SharePoint targets a site URL plus a library **display name** (`RestoreTarget`).
   - OneDrive targets an `onedrive` object from the session (ID, name, URL) plus a folder
     **name** in its root.
   
   None takes the Graph drive or item IDs in `lab/tenant.md`, so `TargetGuard` must map the
   configured IDs to these names and check both. Veeam IDs are composites (site ID + web ID;
   library = site + list ID; restore point = repository ID + point ID).
6. **Sessions (W2.x).**
   - Explore by `dateTime` (the point's `backupTime`), not by ID.
   - Stop every explore session in a `finally`.
   - Sweep and stop any of our own sessions left `Working`: a refused explore can leave one.
7. **Diagnostics (W7.2).** Veeam writes one log per REST restore to
   `C:\ProgramData\Veeam\Backup365\Logs\RestoreREST\restore_<date>_<sessionId>_<orgId>.log`,
   with the underlying AADSTS codes. The REST API reports only "Cannot connect to Microsoft
   365". `rpworker doctor` should test one restore permission, not just listing.
8. **Veeam's user cache.** A new user wasn't visible to Veeam until
   `Get-VBOOrganizationUser -DataSource PreferLocalResynced` ran. Operator scope endpoints
   answered 404 "User with ID … not found" until then.
