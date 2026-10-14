# Veeam REST API notes (W1.4)

The call sequence the Worker uses against Veeam Backup for Microsoft 365, with real responses.
It is written for whoever builds `VeeamClient` (W1.5) and the restore flow (W2.4, W2.5):
each step gives the method and path, headers, body, a trimmed real response with a link to
the full evidence, the fields the Worker needs, and the errors seen.

- **Server.** Veeam Backup for Microsoft 365 **8.6** (logs say 13.6.0.237), REST API **v8**,
  Community Edition, on the dev laptop (`docs/environment.md`).
- **Organisation.** `RestoreProofLab.onmicrosoft.com`, Veeam organisation ID
  `ff96d072-29e2-4cb4-a155-2590f5473176`.
- **Restore points.** Full at 2026-09-25 19:24:31 UTC, incremental at 19:37:15 UTC.
- **Recorded.** 2026-09-26, as `rp-veeam` (admin mode, `docs/decisions.md` 2026-09-26).
- **How.** PowerShell 7 and raw REST (the collection is in [`veeam-m365/`](veeam-m365/README.md)).
  Every exchange is saved, scrubbed, in [`veeam-lab/`](veeam-lab/README.md) as `w1.4-*.json`.
- **Scope.** W1.4 is read-only: it logs in, lists, searches, and opens and stops explore
  sessions. It makes no restores. The restore bodies and their results come from W1.0
  ([`veeam-feasibility.md`](veeam-feasibility.md) §2c and §3), and this document links them
  instead of repeating them.

Conventions below:

- paths are relative to `https://<veeam-server>:4443` (the lab uses `https://localhost:4443`);
- `{restoreSessionId}` etc. are placeholders;
- "→" gives the status seen;
- evidence file names are links into `veeam-lab/`.

Response headers are the same on every call (`Cache-Control: no-store`, HSTS, `X-Frame-Options`,
...) and are left out of the excerpts. Responses are `application/json; charset=utf-8`, except
where noted.

## 0. The sequence at a glance

```
GET  /v8/Health                                             no token; is the REST service up
POST /v8/token  grant_type=password                         → access (60 min) + refresh token
GET  /v8/Organizations                                      → organisation id (match on name or msid)
GET  /v8/RestorePoints?organizationId={id}&limit=1000       → all points; sort by backupTime, take the newest (§3)
POST /v8/Organizations/{id}/explore  {dateTime: backupTime, type: Vex|Vesp|Veod}   → 201, session
     … browse or search inside the session (§5) → the items to restore
POST …/restoreTo | …/copyTo  (W1.0 bodies, feasibility §2c)  → 200 {sessionId}: a NEW restore session
GET  /v8/RestoreSessions/{sessionId}        (poll)          until state == Stopped; then result
GET  /v8/RestoreSessions/{sessionId}/Statistics, /Events   counts per item, messages
POST /v8/RestoreSessions/{exploreSessionId}/Stop            → 204, in a finally
POST /v8/token/logout                                       → 204
```

One explore session per item type (mail, SharePoint, OneDrive). Every call except `/v8/token`
and `/v8/Health` sends `Authorization: Bearer <access_token>`. Send `Accept: application/json`.
Bodies are JSON (`Content-Type: application/json`), except the token call, which takes either
encoding.

## 1. Login, refresh, logout

Script: [`01-auth.ps1`](veeam-m365/01-auth.ps1); expiry: [`09-token-expiry.ps1`](veeam-m365/09-token-expiry.ps1).

### 1.1 Health (no token)

`GET /v8/Health` → 200 ([`w1.4-auth-health`](veeam-lab/w1.4-auth-health.json)):

```json
{"status":"Healthy","entries":{"configurationDb":{"status":"Healthy"},"nats":{"status":"Healthy"}}}
```

Anonymous (the swagger marks `/v8/token`, `/v8/Health` and `/v8/RestorePortalSettings` as
`x-anonymous`). It is a cheap reachability probe for `rpworker doctor` (W7.2), and it tells
"Veeam is down" apart from "our credentials are wrong". It proves nothing about permissions.

### 1.2 Password grant

```
POST /v8/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=DESKTOP-P55CDUM%5Crp-veeam&password=[REDACTED]&disable_antiforgery_token=true
```

→ 200 ([`w1.4-auth-token`](veeam-lab/w1.4-auth-token.json)):

```json
{
  "access_token": "[REDACTED]",
  "refresh_token": "[REDACTED]",
  "token_type": "bearer",
  "expires_in": 3600,
  "userName": "DESKTOP-P55CDUM\\rp-veeam",
  ".issued": "2026-09-26T16:02:10.2493827Z",
  ".expires": "2026-09-26T17:02:10.2493827Z"
}
```

- The same body as JSON also works (`"disable_antiforgery_token": true`,
  [`w1.4-auth-token-json`](veeam-lab/w1.4-auth-token-json.json)). The Worker uses the form
  encoding.
- **Always send `disable_antiforgery_token=true`.** In W1.0 a grant without it succeeded,
  but its refresh failed with 500 "An antiforgery token is not specified."
  ([`w1.0-a-operator-refresh-antiforgery-500`](veeam-lab/w1.0-a-operator-refresh-antiforgery-500.json),
  an operator token; admin grants were always sent with the flag).
- `username` is `MACHINE\user` (or `DOMAIN\user`) of a Windows account in the Veeam Backup
  Administrator role.
- Both tokens are JWT-shaped (`eyJ…`, about 850 characters, seen at run time; the saved files
  hold `[REDACTED]`). Treat them as opaque: store them, never parse or log them.
- **The Worker needs** `access_token`, `refresh_token` and `expires_in`. Compute the expiry from
  the local clock at receipt; `.expires` is informative. `token_type` is lower-case `bearer`.
  Send it as `Bearer`.
- A refused login returns **401** `{"message":"The server has rejected the client
  credentials."}`, the same body for a wrong password and a missing role
  (`l1.6-admin-token-wrong-password-traced`, `-no-role-traced`). Before the REST service's
  restart, the same two cases and an unknown user gave an **empty 500** instead
  (`l1.6-admin-token-*`, feasibility §2 L1.6). All of them mean `AuthError` (§8).

### 1.3 Calling with the token; what a bad token looks like

| Case | Status | Body | `WWW-Authenticate` | Evidence |
|---|---|---|---|---|
| No `Authorization` header | 401 | empty | `Bearer` | [`w1.4-auth-no-token-401`](veeam-lab/w1.4-auth-no-token-401.json) |
| A value Veeam never issued | 401 | empty | `Bearer error="invalid_token"` | [`w1.4-auth-bad-token-401`](veeam-lab/w1.4-auth-bad-token-401.json) |
| The access token from before a refresh | 401 | empty | `Bearer error="invalid_token"` | [`w1.4-auth-pre-refresh-access`](veeam-lab/w1.4-auth-pre-refresh-access.json) |
| After logout | 401 | empty | `Bearer error="invalid_token"` | [`w1.4-auth-after-logout-access`](veeam-lab/w1.4-auth-after-logout-access.json) |
| After a REST service restart | 401 | empty | `Bearer error="invalid_token"` | [`w1.0-a-restart-admin-access`](veeam-lab/w1.0-a-restart-admin-access.json) (W1.0's scrubber masked the header there) |
| Past `.expires` | 401 | empty | `Bearer error="invalid_token", error_description="The token expired at '09/26/2026 17:01:43'"` | [`w1.4-auth-expired-access-401`](veeam-lab/w1.4-auth-expired-access-401.json) |

A 401 for a missing or bad token has an **empty body** (`Content-Length: 0`). A 401 with a JSON
`message` comes from `/v8/token`, and from API calls the account's **role** doesn't allow: an
operator token on the admin endpoints got 401 `{"message":"The server has rejected the client
credentials."}` (`l1.6-operator-admin-sweep`, a summary of several calls).

### 1.4 Refresh: rotating, single-use, and it revokes the old access token

```
POST /v8/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=[REDACTED]&disable_antiforgery_token=true
```

→ 200, the same shape as §1.2 ([`w1.4-auth-refresh`](veeam-lab/w1.4-auth-refresh.json)).
What the lab showed:

1. **The refresh token rotates.** Each refresh returns a new refresh token, and the used one is
   dead: sending it again → 401 `{"message":"Refresh token is not valid"}`
   ([`w1.4-auth-refresh-reuse-401`](veeam-lab/w1.4-auth-refresh-reuse-401.json)).
2. **A refresh revokes the previous access token at once**, well before its `.expires`
   ([`w1.4-auth-pre-refresh-access`](veeam-lab/w1.4-auth-pre-refresh-access.json)). A request
   still in flight with the old token can get 401. So `ensureToken()` must hand out the new
   token to every caller under the same lock that refreshes. A caller that gets a 401 with a
   token older than the current one just retries with the current one.
3. **Replaying a used refresh token does not kill the chain.** After the replay was refused,
   the newest refresh token still worked
   ([`w1.4-auth-refresh-after-reuse`](veeam-lab/w1.4-auth-refresh-after-reuse.json)). No
   "token family" revocation.
4. **Every REST service restart invalidates every token**, access and refresh, of every user
   (W1.0, `w1.0-a-restart-*`). The refresh then answers 401 "Refresh token is not valid".

The refresh-token lifetime is not documented. W1.0 is measuring it for operator tokens (48 h
and 7 days, issue #8). The Worker doesn't depend on it, because it signs in again with the
password whenever a refresh fails.

### 1.5 Expiry

A token granted at 16:01:43 UTC (`.expires` 17:01:43.5037956Z) was probed around its expiry
([`09-token-expiry.ps1`](veeam-m365/09-token-expiry.ps1)):

| When | Result |
|---|---|
| 17:01:15, 28 s before `.expires` | 200 |
| 17:02:16, 33 s after | 401 |
| 17:08, 6 min after | 401, `WWW-Authenticate: Bearer error="invalid_token", error_description="The token expired at '09/26/2026 17:01:43'"` ([`w1.4-auth-expired-access-401`](veeam-lab/w1.4-auth-expired-access-401.json)) |
| Then its refresh token (never used) | **200**, a new pair ([`w1.4-auth-refresh-after-expiry`](veeam-lab/w1.4-auth-refresh-after-expiry.json)) |

- **No clock-skew allowance.** The token died within a minute of `.expires` (ASP.NET's usual
  default is 5 minutes). So refresh *before* expiry, as W1.5's "within 60 s" rule does, and
  keep the local clock in sync with the Veeam server's. The Worker runs on the same machine
  in the lab, but maybe not at an MSP.
- **Only an expired token says why.** Expiry is the one 401 with an `error_description`; a
  revoked token (refresh, logout, restart) just says `invalid_token`. The client handles them
  the same way (§1.7), but the description is worth a debug log line, because it isn't secret.
- **An expired access token doesn't take its refresh token with it.** A Worker idle for more
  than an hour can still refresh (within the refresh token's own, undocumented lifetime).

### 1.6 Logout

`POST /v8/token/logout` with the bearer token, no body → **204**, empty
([`w1.4-auth-logout`](veeam-lab/w1.4-auth-logout.json)). Afterwards:

- that access token → 401 `invalid_token`
  ([`w1.4-auth-after-logout-access`](veeam-lab/w1.4-auth-after-logout-access.json));
- its refresh token → 401 "Refresh token is not valid"
  ([`w1.4-auth-after-logout-refresh`](veeam-lab/w1.4-auth-after-logout-refresh.json));
- **another token of the same user, from a separate grant, keeps working**
  ([`w1.4-auth-other-token-after-logout`](veeam-lab/w1.4-auth-other-token-after-logout.json)).
  Logout ends one chain, not the user's other sessions.

The Worker logs out at the end of each run, so tokens don't outlive the job.

### 1.7 The recipe for `VeeamClient` (W1.5)

```
login():        POST /v8/token grant_type=password (+ disable_antiforgery_token=true)
ensureToken():  under a mutex: if now >= received_at + expires_in - 60 s:
                   refresh (grant_type=refresh_token); Veeam refuses or garbles it → login();
                   Veeam unreachable (TransientError) → throw, no login()
                store the newest access AND refresh token; the old ones are dead
call(req):      send with the current token
                on 401 (empty body): if the token used is older than the current one → resend;
                   else login() once and resend (the REST service may have restarted);
                   a 401 after that login() → AuthError
logout():       refresh first if within 60 s of expiry (Veeam refuses an expired token);
                POST /v8/token/logout, one attempt, best effort, at the end of the run
```

Never resend `/v8/token` once it may have reached Veeam (a timeout, a dropped connection), and
never on a 5xx (see §8): a refused login is sometimes a 500, a resent password grant is another
logon, a resent refresh a used token. Only a request that never went out (no connection, no
handshake) is sent again. (W1.5 as built: `docs/decisions.md` 2026-09-26, "VeeamClient after
review".)

## 2. Organisation, users, sites; paging

Script: [`02-organizations.ps1`](veeam-m365/02-organizations.ps1).

### 2.1 Organisations

`GET /v8/Organizations` → 200 ([`w1.4-org-list`](veeam-lab/w1.4-org-list.json)),
`GET /v8/Organizations/{organizationId}` → 200 ([`w1.4-org-get`](veeam-lab/w1.4-org-get.json)).
With `?extendedView=true` the server asks the proxy and adds `isBackedup`, `firstBackuptime` and
`lastBackuptime` ([`w1.4-org-get-extended`](veeam-lab/w1.4-org-get-extended.json)):

```json
{
  "exchangeOnlineSettings": { "useApplicationOnlyAuth": true, "applicationId": "1fd2609d-1242-43fe-94b5-d58688a90bd6",
                              "applicationCertificateThumbprint": "AC3220B5…", "account": "HrachyaHarutyunyan@…", … },
  "sharePointOnlineSettings": { "useApplicationOnlyAuth": true, "officeOrganizationName": "RestoreProofLab.onmicrosoft.com", … },
  "isExchangeOnline": true, "isSharePointOnline": true, "type": "Office365", "region": "Worldwide",
  "id": "ff96d072-29e2-4cb4-a155-2590f5473176",
  "name": "RestoreProofLab.onmicrosoft.com", "officeName": "RestoreProofLab.onmicrosoft.com",
  "isBackedup": true,
  "firstBackuptime": "2026-09-25T19:24:31.0936821Z", "lastBackuptime": "2026-09-25T19:37:15.2145203Z",
  "msid": "bcd6bd1a-ea42-489d-aa28-2c19a44ad146",
  "backedUpOrganizationId": "RestoreProofLab.onmicrosoft.com:00000000-0000-0000-0000-000000000000:00000000-0000-0000-0000-000000000000"
}
```

- **The Worker needs** `id` (for every later call), `name` and `msid` (the Entra tenant ID, the
  safest key to match the configured tenant against), `region` (`officeRegion` in restore
  bodies) and `officeName` (`officeOrganizationName`/`organizationName`).
  `exchangeOnlineSettings.applicationId` is the Veeam org app whose certificate W1.0 used for
  restores (feasibility §5.4).
- `GET /v8/Organizations/{unknown uuid}` → 404 `ResourceNotFound`
  ([`w1.4-org-get-unknown-404`](veeam-lab/w1.4-org-get-unknown-404.json)). A malformed ID
  (`not-a-guid`) → the same 404 naming the **all-zero** GUID
  ([`w1.4-org-get-bad-id`](veeam-lab/w1.4-org-get-bad-id.json)): Veeam parses bad IDs as
  `Guid.Empty`, so validate IDs before calling.

### 2.2 Users and sites

`GET /v8/Organizations/{organizationId}/Users?limit=2&offset=0` → 200 ([`w1.4-org-users-page1`](veeam-lab/w1.4-org-users-page1.json); all six on one default page: [`w1.4-org-users`](veeam-lab/w1.4-org-users.json)):

```json
{"offset":0,"limit":2,"setId":"53c685d0-1be6-08df-0000-000000000000",
 "results":[{"id":"RestoreProofLab.onmicrosoft.com:00000000-…:00000000-…:533138fa-6982-4fd2-a8b1-593d3f655d32:00000000-…",
             "eTag":2,"displayName":"Hrachya Harutyunyan","name":"HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com",
             "type":"User","locationType":"Cloud","assignedLicenses":[…],"msid":"533138fa-6982-4fd2-a8b1-593d3f655d32"}, …],
 "_links":{"self":{…},"next":{"href":"/v8/Organizations/{id}/Users?setid=53c685d0-…&offset=2&limit=2"}}}
```

- The user `id` is a composite string (`<org name>:<guid>:<guid>:<Entra object id>:<guid>`),
  **not** a UUID. `msid` is the Entra object ID and `name` the UPN.
- Filter with `userName=<UPN>` ([`w1.4-org-users-by-name`](veeam-lab/w1.4-org-users-by-name.json))
  or `displayName=` (wildcards `*`, `?` per the swagger; not tried).
- The lab lists 6 users: the admin, alice, bob, restoretest, rpoperator and Exchange's
  `DiscoverySearchMailbox{…}`.

`GET /v8/Organizations/{organizationId}/Sites` → 200 ([`w1.4-org-sites`](veeam-lab/w1.4-org-sites.json)):

```json
{"id":"fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e689","eTag":1,
 "url":"https://restoreprooflab.sharepoint.com/sites/RestoreTest","name":"RestoreTest","isCloud":true,
 "isPersonal":false,"title":"RestoreTest","isAvailable":true,
 "msid":"fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-b3fe-cd091a09e689"}
```

- The site `id` is the site collection GUID and the web GUID **concatenated without a
  separator** (72 characters). `msid` is the same pair comma-separated. Graph's site ID is
  `<host>,<site guid>,<web guid>` (`lab/tenant.md`), so the three map onto each other.
- Personal (OneDrive) sites are left out unless `includePersonalSites=true`
  ([`w1.4-org-sites-personal`](veeam-lab/w1.4-org-sites-personal.json): 7 instead of 5).
  `filter=RestoreTest` matches on name ([`w1.4-org-sites-filter`](veeam-lab/w1.4-org-sites-filter.json)).
- Site names follow the tenant's language ("Witryna zespołu"). Match sites on `url`, never on
  `name`.

The Worker doesn't need `/Users` or `/Sites` for a test run: the explore session has its own
lists (§5). They are for `rpworker doctor` and for checking the configuration (does the
configured mailbox or site exist in the organisation Veeam backs up?).

### 2.3 Paging (every collection)

- `limit` (default **30**; the swagger gives a maximum of 10 000, not tried) and `offset` (default 0). Every page echoes `offset`
  and `limit`.
- `_links` has `self`, `next` while more remain, and `first`/`prev` after the first page
  ([`w1.4-org-users-page1`](veeam-lab/w1.4-org-users-page1.json),
  [`-page2`](veeam-lab/w1.4-org-users-page2.json)). An offset past the end → 200 with an empty
  `results` ([`w1.4-org-users-past-end`](veeam-lab/w1.4-org-users-past-end.json)).
- `setId` is a server-side cache of the result set for "the cloud" (Microsoft 365) calls.
  Organisation users and sites, and searches, return one. Restore points, sessions and
  in-session lists don't. Pass it back with the next `offset` to page through the same
  snapshot.
- **Rule for the Worker:** page with an explicit `limit` (such as 1000) until a page returns fewer
  than `limit` results. The default of 30 would silently truncate a mailbox folder or a library.

### 2.4 Veeam's user cache (`dataSource`)

`/Users` and `/Sites` take `dataSource`:

- `PreferLocal` (default): Veeam's cache if it is synchronised;
- `Production`: ask Microsoft 365 now;
- `PreferLocalResynced`: resynchronise the cache, then answer from it.

All three returned the same 6 users today
([`w1.4-org-users-preferlocal`](veeam-lab/w1.4-org-users-preferlocal.json), `-production`,
`-preferlocalresynced`). The first `PreferLocalResynced` call of the day took 3.5 s (console
output of the first run); the saved files are from a re-run, 10–30 ms each.

W1.0 saw a new tenant user stay invisible until the cache was resynced (feasibility §5.8:
`rpoperator` was created on 2026-09-26, and the scope endpoints answered 404 "User with ID …
not found" until `Get-VBOOrganizationUser -DataSource PreferLocalResynced`). W1.4 did not
create another user to repeat that; it would change the tenant.

**For the Worker:** the restore targets are fixed accounts, so this matters for a new target or
source account. A config check that can't find a configured user should retry once with
`dataSource=PreferLocalResynced` before reporting it missing.

## 3. Restore points

Script: [`03-restore-points.ps1`](veeam-m365/03-restore-points.ps1).

`GET /v8/RestorePoints?organizationId={organizationId}` → 200 ([`w1.4-rp-list-org`](veeam-lab/w1.4-rp-list-org.json)):

```json
{"offset":0,"limit":30,"results":[
  {"id":"c2f0f2e7-177f-48ac-992b-93a50cf702e371ac3d9c-eb29-42b6-a391-ae81fcc4681c",
   "isDeleted":false,"repositoryId":"c2f0f2e7-177f-48ac-992b-93a50cf702e3",
   "backupTime":"2026-09-25T19:37:15.2145203Z","jobId":"4cf03510-457c-401b-a1c6-e7e69be296e1",
   "retrievalId":"00000000-0000-0000-0000-000000000000","organizationId":"ff96d072-29e2-4cb4-a155-2590f5473176",
   "isExchange":true,"isSharePoint":true,"isOneDrive":true,"isTeams":false,
   "isLongTermCopy":false,"isCopy":false,"isRetrieved":false,"eTag":1,"objectsEtag":5},
  {"id":"c2f0f2e7-177f-48ac-992b-93a50cf702e32fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7", …
   "backupTime":"2026-09-25T19:24:31.0936821Z", …}]}
```

- **There is no `isModified`** (the guide's field). The fields are the ones above. `eTag` and
  `objectsEtag` are version counters, not a "changed" flag.
- **There is no `/v8/Organizations/{id}/RestorePoints`** (the guide's path): → 404 with an empty
  body, the route doesn't exist ([`w1.4-rp-guide-path-404`](veeam-lab/w1.4-rp-guide-path-404.json)).
  Filter the global list with `organizationId`.
- **The `id` is the repository ID and the point ID concatenated** (72 characters, no
  separator). `GET /v8/RestorePoints/{that id}` → 200 ([`w1.4-rp-get`](veeam-lab/w1.4-rp-get.json)).
  The bare point ID (what `Get-VBORestorePoint` shows) → **400** "Incorrect restore point ID
  format…" ([`w1.4-rp-get-bare-id`](veeam-lab/w1.4-rp-get-bare-id.json)). An unknown point in a
  known repository → 404 ([`w1.4-rp-get-unknown-404`](veeam-lab/w1.4-rp-get-unknown-404.json)).
  Keep the ID as an opaque string.
- **Order:** newest first by default ([`w1.4-rp-list`](veeam-lab/w1.4-rp-list.json)),
  `orderAsc=true` reverses it ([`w1.4-rp-list-asc`](veeam-lab/w1.4-rp-list-asc.json)).
- **`from`/`to`** filter on `backupTime`. Both are **inclusive**: `from` equal to the latest
  `backupTime` still returns it ([`w1.4-rp-list-from-exact`](veeam-lab/w1.4-rp-list-from-exact.json)).
  `from` between the two points returns only the later one, `to` there only the earlier one
  ([`-from`](veeam-lab/w1.4-rp-list-from.json), [`-to`](veeam-lab/w1.4-rp-list-to.json)). A
  window with none → 200 and empty `results` ([`-empty`](veeam-lab/w1.4-rp-list-empty.json)).
  A value that isn't a date → 400 in ASP.NET's `ProblemDetails` shape (`{"errors":{"from":[…]},
  "title":…,"status":400,"traceId":…}`), not Veeam's `{message, errorCode}`
  ([`-bad-from`](veeam-lab/w1.4-rp-list-bad-from.json)). An unknown `organizationId` → 404
  ([`-unknown-org`](veeam-lab/w1.4-rp-list-unknown-org.json)).
- Paging as in §2.3; no `setId` here.

**Picking "latest":** `GET /v8/RestorePoints?organizationId={id}&limit=1` returns the newest
([`w1.4-rp-list-limit1`](veeam-lab/w1.4-rp-list-limit1.json)). `VeeamClient::listRestorePoints`
should still fetch the whole list with a large `limit` and sort by `backupTime` descending
itself (W1.5's contract says "sorted newest first"). Also, keep only points with `isExchange` /
`isSharePoint` / `isOneDrive` true for the type being tested, and skip `isLongTermCopy`
(archive tier: restores from it need a retrieval job first).

**The Worker needs** `id`, `backupTime` (**as the exact string**, see §4.2), `organizationId`,
`jobId`, the three `is…` flags and `isDeleted`.

## 4. Restore (explore) sessions

Script: [`04-sessions.ps1`](veeam-m365/04-sessions.ps1).

### 4.1 Open

```
POST /v8/Organizations/{organizationId}/explore
Content-Type: application/json

{"dateTime":"2026-09-25T19:37:15.2145203Z","type":"Vex","showDeleted":false,"showAllVersions":false}
```

→ **201** ([`w1.4-session-explore`](veeam-lab/w1.4-session-explore.json)):

```json
{"id":"208fce8b-836d-4363-89b4-f457b46d1333",
 "name":"Exchange restore (Entire organization - 9/25/2026 7:37:15 PM)",
 "organization":"RestoreProofLab.onmicrosoft.com","type":"Vex",
 "creationTime":"2026-09-26T15:56:47.694074Z","endTime":"9999-12-31T23:59:59.9999999",
 "state":"Working","result":"Success","initiatedBy":"rp-veeam","scopeName":"",
 "clientHost":"localhost:4443 (via: [::ffff:127.0.0.1])","eTag":1}
```

- `type`: `Vex` (Exchange), `Vesp` (SharePoint), `Veod` (OneDrive), `Vet` (Teams). Anything
  else → 400 `ParameterValidationFailure`
  ([`w1.4-session-explore-bad-type-400`](veeam-lab/w1.4-session-explore-bad-type-400.json)).
- There is no restore-point ID in the body: the session is opened **by time** (§4.2). The
  optional `repositoryId` picks the repository when there are several; the lab has one.
- The Worker keeps `id`. `name` is a display string (US format, and the embedded time is the
  requested `dateTime`): don't parse it.
- **`endTime` while `Working` is `9999-12-31T23:59:59.9999999` with no `Z`.** The date parser
  must accept a timestamp without an offset, or ignore `endTime` until `state == Stopped`.
- `result` is already `Success` for a fresh session. It means nothing until `Stopped` (§7).
- About 150–300 ms here.

### 4.2 What `dateTime` does

| `dateTime` sent | Result | Evidence |
|---|---|---|
| The latest point's `backupTime`, exactly as listed (`…19:37:15.2145203Z`) | 201; alice's Inbox: the 10 canaries | [`w1.4-session-explore`](veeam-lab/w1.4-session-explore.json), [`w1.4-session-content-exact`](veeam-lab/w1.4-session-content-exact.json) |
| Truncated to the second (`2026-09-25T19:37:15Z`) | 201; the same 10 items, same item IDs | [`-second`](veeam-lab/w1.4-session-explore-second.json), [`w1.4-session-content-second`](veeam-lab/w1.4-session-content-second.json) |
| **Between** the two points (`19:30:00Z`) | 201; the same 10 items; session name shows 7:30:00 PM | [`-between`](veeam-lab/w1.4-session-explore-between.json), [`w1.4-session-content-between`](veeam-lab/w1.4-session-content-between.json) |
| **After** the latest point (now) | 201; the same 10 items | [`-after`](veeam-lab/w1.4-session-explore-after.json), [`w1.4-session-content-after`](veeam-lab/w1.4-session-content-after.json) |
| **Before** the first point (`19:00:00Z`) | **500** "The chosen restore point date precedes the date of the first available restore point (9/25/2026 7:24:31 PM)." | [`-before`](veeam-lab/w1.4-session-explore-before.json) |
| The same instant with an offset (`21:37:15+02:00`) | **500** "Date/time value must be based on Coordinated Universal Time (UTC)… based on: Local." | [`-local`](veeam-lab/w1.4-session-explore-local.json) |
| No offset (`2026-09-25T19:37:15`) | **500** "… based on: Unspecified." | [`-nooffset`](veeam-lab/w1.4-session-explore-nooffset.json) |
| UTC written as an offset (`…19:37:15.2145203+00:00`) | **500** "… based on: Local." (parsed and converted to server time) | [`-plus0`](veeam-lab/w1.4-session-explore-plus0.json) |
| Not a date (`"yesterday"`) | 400 `ParameterValidationFailure` | [`-bad-date-400`](veeam-lab/w1.4-session-explore-bad-date-400.json) |
| Missing | 400 "Missing mandatory parameters: DateTime." | [`-no-date`](veeam-lab/w1.4-session-explore-no-date.json) |

What this means:

- **The session shows the organisation as of `dateTime`**: the newest data backed up at or
  before it. Veeam's reference says the same for the job explore ("If you specify the point in
  time which exceeds the organization last backup time, the restore session will be created
  with backup data as of the latest restore point"; before the first backup, the job
  explore creates an empty session, while the organisation explore answers 500).
- The lab's incremental point has 0 changed items, so its content is identical to the full
  point's. **The content can't show which point a between-points session used**, and Veeam's
  logs don't name it either. We rely on the documented point-in-time rule.
- **Only a `Z` (UTC) timestamp is accepted.** Any offset, `+00:00` included, or none at all is a
  500, not a 400.
- Item IDs were identical in all four sessions: they don't depend on the session.
- **Rule for the Worker:** send the chosen point's `backupTime` string **unchanged**, all 7
  fractional digits and the `Z`. Don't round-trip it through a date type that drops digits:
  truncated to the second, `19:37:15Z` is *earlier* than the point (`19:37:15.2145203Z`), so by
  the point-in-time rule it could open the previous point. Record the `backupTime` sent in the
  result JSON as the tested point.

### 4.3 Read and list

- `GET /v8/RestoreSessions/{restoreSessionId}` → 200, the same shape as §4.1
  ([`w1.4-session-get`](veeam-lab/w1.4-session-get.json)). Unknown ID → 404 `ResourceNotFound`
  ([`w1.4-session-get-unknown-404`](veeam-lab/w1.4-session-get-unknown-404.json)).
- `GET /v8/RestoreSessions/{restoreSessionId}/organization` → `{"id":"ff96d072-…","name":
  "RestoreProofLab.onmicrosoft.com (9/25/2026 9:37:15 PM)","type":"Office365"}`
  ([`w1.4-session-organization`](veeam-lab/w1.4-session-organization.json)). The time in that
  name is the server's **local** time, while the session name shows UTC: one more reason not to
  parse names.
- `GET …/Events` of an explore session with no restore lists just "Restore session started"
  ([`w1.4-session-events-working`](veeam-lab/w1.4-session-events-working.json)).
- `GET …/Statistics` while `Working` → **409** `{"message":"Unable to provide statistics until
  the restore session completes."}` (no `errorCode`;
  [`w1.4-session-statistics-working-409`](veeam-lab/w1.4-session-statistics-working-409.json)).
  After the stop, an explore session with no restore → 404 "The restore session statistics are
  not available." ([`w1.4-session-statistics-stopped`](veeam-lab/w1.4-session-statistics-stopped.json)).
- `GET /v8/RestoreSessions?limit=…` lists every user's sessions, **newest `creationTime`
  first** ([`w1.4-session-list`](veeam-lab/w1.4-session-list.json)). It has filters
  `startTimeFrom`/`startTimeTo`/`endTimeFrom`/`endTimeTo`, `orderBy` (`CreationTime`,
  `EndTime`) and `orderAsc`, but **no filter on state or user**. `initiatedBy` is the **bare
  account name** (`rp-veeam`), without the machine or domain prefix used to sign in.

### 4.4 Stop, and sweep leftovers

`POST /v8/RestoreSessions/{restoreSessionId}/Stop`, no body → **204**
([`w1.4-session-stop`](veeam-lab/w1.4-session-stop.json)). Then:

- the session reads `state: Stopped`, `endTime` set, `details: "0 items processed"`
  ([`w1.4-session-get-stopped`](veeam-lab/w1.4-session-get-stopped.json));
- **stopping again → 204** too: Stop is idempotent
  ([`w1.4-session-stop-again`](veeam-lab/w1.4-session-stop-again.json)), so a `finally` can
  always call it;
- any browse call on it → **500** `{"message":"Restore session is stopped."}`
  ([`w1.4-session-browse-after-stop`](veeam-lab/w1.4-session-browse-after-stop.json)).
- **a Stop can hang once** (2026-09-30, W2.6's live dry run): the Stop of explore session
  e251a437-19d8-49ff-aaa3-b7171f3cbe53 timed out after the 30 s HTTP timeout with 0 bytes
  received, the session was still `Working` minutes later, and a second Stop (the sweep) returned
  204 at once; so the Worker, after a Stop that fails as transient (timeout, dropped connection, a
  transient 5xx), reads the session again and sends one more Stop only if it is still `Working`,
  at most 2 Stops per session, and never retries an auth error or a 4xx
  (`ExploreSessions::stop_if_working`, `worker/src/veeam_explore.cpp`).

**Sweep** ([`08-sweep-sessions.ps1`](veeam-m365/08-sweep-sessions.ps1)): list
`/v8/RestoreSessions?limit=200` ([`w1.4-sweep-list`](veeam-lab/w1.4-sweep-list.json)) and stop
each one with `state == "Working"` and `initiatedBy` equal to the Worker's account name. Leave
anyone else's alone: an MSP's engineer may be restoring in the console. Run it at the start of
every test run (the pipeline's first "cleanup" step) and at the end.

Why the sweep is needed:

- in W1.0 a refused explore (an operator's out-of-scope explore, feasibility §2b) left a session
  `Working` for 36 minutes;
- during W1.4 a script failed between the 201 and the point where it recorded the ID (a bug in
  the evidence writer, since fixed); the session stayed `Working` until the sweep stopped it
  (seen in the run's output, not saved as evidence).

**Caveat for W2.5:** the sweep can't tell a leftover from a session another run is using right
now under the same account. Either run one test at a time per Veeam server (the scheduler's
job), or stop only sessions whose `creationTime` is older than the longest a run can take.

The lesson for W2.5: record the session ID straight from the 201, before anything else can
throw.

## 5. Browsing and search inside a session

Scripts: [`05-mail.ps1`](veeam-m365/05-mail.ps1), [`06-sharepoint.ps1`](veeam-m365/06-sharepoint.ps1),
[`07-onedrive.ps1`](veeam-m365/07-onedrive.ps1). All paths below start with
`/v8/RestoreSessions/{restoreSessionId}/`. Note the case: mail is under `organization/…`,
SharePoint and OneDrive under `Organization/…`. The server ignores case, and its own `_links`
are all lower-case, but keep the swagger's spelling. Objects carry `_links` (such as `self`, `parent`,
`mailbox`, `children`) and, for restorable ones, `_actions` (the restore/save URIs they support).

### 5.1 Mail (`Vex`): mailboxes → folders → items

| Step | Call | Evidence |
|---|---|---|
| Mailboxes | `GET organization/mailboxes?limit=…` → `{id (uuid), name, email, isArchive, isPublic}` | [`w1.4-mail-mailboxes`](veeam-lab/w1.4-mail-mailboxes.json), [`-mailbox-get`](veeam-lab/w1.4-mail-mailbox-get.json) |
| Folders | `GET organization/mailboxes/{mailboxId}/folders?name=Inbox` (wildcards `*`, `?` per the swagger; not tried) or `?parentId=root` (top level) or `?parentId={folderId}` (subfolders). No `parentId`: every folder, flattened (14 vs 13 at root here) | [`w1.4-mail-folders-by-name`](veeam-lab/w1.4-mail-folders-by-name.json), [`-folders-root`](veeam-lab/w1.4-mail-folders-root.json), [`-folders`](veeam-lab/w1.4-mail-folders.json) |
| Items | `GET organization/mailboxes/{mailboxId}/items?parentId={folderId}&limit=…` (the folder's own `_links.items` uses `?folderId=`; `parentId` is the documented name). No `parentId`: the mailbox's items, all folders | [`w1.4-mail-items`](veeam-lab/w1.4-mail-items.json), [`-items-page`](veeam-lab/w1.4-mail-items-page.json), [`-items-no-parent`](veeam-lab/w1.4-mail-items-no-parent.json) |
| One item | `GET organization/mailboxes/{mailboxId}/items/{itemId}` | [`w1.4-mail-item-get`](veeam-lab/w1.4-mail-item-get.json) |

Mailbox and item (trimmed):

```json
{"id":"e00393b0-a896-4487-ad04-0e1be36468fb","name":"Alice Test","email":"alice@RestoreProofLab.onmicrosoft.com","isArchive":false,"isPublic":false}

{"mailboxId":"e00393b0-a896-4487-ad04-0e1be36468fb","attachments":[],"subject":"RP-CANARY-0001","itemClass":"IPM.Note",
 "id":"LgAAAEYAAAAWAAAAAAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQwAAAAAAACUONBHt75MQZNX3evuAgFOBwD9C8F5knDCTJ65_rDRErifAAAAAAEMAAD9C8F5knDCTJ65_rDRErifAAAAAFuMAAD9C8F5knDCTJ65_rDRErifAAAAADr_",
 "from":"Hrachya Harutyunyan","importance":"Normal","cc":"","bcc":"","to":"Alice Test",
 "sent":"2026-09-24T22:14:40Z","received":"2026-09-24T22:14:43.5020317Z","reminder":false}
```

- The mailbox `name` is the display name, and can contain a line break (`restoretest` is
  "Restore⏎Test", `lab/tenant.md`). Match mailboxes on `email`, case-insensitively.
- `from`/`to` are **display names**, not addresses. The item has no `internetMessageId`: to
  tie a Veeam item to the manifest, use the mailbox plus `subject`, then check `received`
  against the manifest. After the restore, the Graph read-back matches on `internetMessageId`
  (L1.4, W3.2).
- Folder `type` was `None` for the Inbox. Its `category` is `Inbox`.
- An item ID that doesn't decode → **400** "Item ID is not valid" (not 404;
  [`w1.4-mail-item-get-unknown`](veeam-lab/w1.4-mail-item-get-unknown.json)).

### 5.2 SharePoint (`Vesp`): sites → libraries → documents

| Step | Call | Evidence |
|---|---|---|
| Sites | `GET Organization/Sites?parentId=root&limit=…` (top-level sites, personal sites included here: alice's OneDrive shows up); `?parentId={siteId}` → subsites (none here) | [`w1.4-sp-sites-root`](veeam-lab/w1.4-sp-sites-root.json), [`-subsites`](veeam-lab/w1.4-sp-subsites.json) |
| One site | `GET Organization/Sites/{siteId}` → `{id, name, url}` | [`w1.4-sp-site-get`](veeam-lab/w1.4-sp-site-get.json) |
| Libraries | `GET Organization/Sites/{siteId}/Libraries` → `{id, name, url, description, creationTime, siteId}` | [`w1.4-sp-libraries`](veeam-lab/w1.4-sp-libraries.json), [`-library-get`](veeam-lab/w1.4-sp-library-get.json) |
| Documents | `GET Organization/Sites/{siteId}/Documents?parentId={libraryId or folderId}&limit=…` (`includeFolders=true` to list folders too). `parentId=root` → **400** "Root parentId is unsupported." No `parentId`: every document of the site, all libraries (12 here: the 10 canaries, `Home.aspx`, a OneNote notebook) | [`w1.4-sp-documents`](veeam-lab/w1.4-sp-documents.json), [`-documents-page`](veeam-lab/w1.4-sp-documents-page.json), [`-documents-root`](veeam-lab/w1.4-sp-documents-root.json), [`-documents-no-parent`](veeam-lab/w1.4-sp-documents-no-parent.json) |
| Folders | `GET Organization/Sites/{siteId}/Folders?parentId={libraryId}` (none in the canary library) | [`w1.4-sp-folders`](veeam-lab/w1.4-sp-folders.json) |
| One document | `GET Organization/Sites/{siteId}/Documents/{documentId}`; versions: `…/Versions` (empty: `showAllVersions` was false) | [`w1.4-sp-document-get`](veeam-lab/w1.4-sp-document-get.json), [`-document-versions`](veeam-lab/w1.4-sp-document-versions.json) |

Library and document (trimmed):

```json
{"id":"fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e6897eb0f08a-f57b-418c-8ca6-f2ab81297666",
 "name":"RestoreTest","url":"sites/RestoreTest/RestoreTest","description":"","creationTime":"0001-01-01T00:00:00Z",
 "siteId":"fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e689"}

{"siteId":"fe08085d-…e689","sizeBytes":925,"version":"1.0","versionId":1,
 "id":"fe08085d-eb70-42e8-95a6-470189bd98eb4ecaf399-cc0e-4d95-b3fe-cd091a09e6897eb0f08a-f57b-418c-8ca6-f2ab81297666c137e9be-2c7c-49b8-b09a-8ada92102e78",
 "name":"rp-canary-01.pdf","createdBy":"Hrachya Harutyunyan","creationTime":"2026-09-24T22:14:43Z",
 "modifiedBy":"Hrachya Harutyunyan","modificationTime":"2026-09-24T22:14:43Z","isFolder":false}
```

- Library names are the tenant's language ("Dokumenty", "Strony witryny"). Find the source
  library by the **list ID at the end of its `id`**, the 36 characters after the site ID
  (`7eb0f08a-…` = `lab/tenant.md`'s RestoreTest list ID), or by `url`. Don't use `name`.
- **The `RestoreTarget` library is not in the backup** (it doesn't appear in `Libraries`). A
  restore target doesn't have to be: the `restoreTo` body names the target site by URL and the
  library by display name (feasibility §2c). Only the *source* must be in the backup.
  *(W2.4, 2026-09-28: true of the two 2026-09-25 points only. The library was created later
  that day and is in the backup from the 2026-09-27T22:00:48Z point on; see
  [`veeam-restore-flow.md`](veeam-restore-flow.md) §4.4.)*
- The document `id` embeds site + web + list + item GUIDs. The last 36 characters are the
  SharePoint list item's unique ID, and that bare GUID is what the restore `Statistics`
  report as `items[].id` (`w1.0-c-sp-cert-statistics`).
- `creationTime` of a library read `0001-01-01T00:00:00Z` (not tracked).
- The W1.0 `restoreTo` body sends the **whole document object** from this list (minus
  `_links`). Build it from `GET …/Documents`, not from a search result (§5.4).

### 5.3 OneDrive (`Veod`): OneDrives → folders → documents

| Step | Call | Evidence |
|---|---|---|
| OneDrives | `GET Organization/OneDrives?limit=…` → `{id, name, url}` (only alice's OneDrive has data here) | [`w1.4-od-onedrives`](veeam-lab/w1.4-od-onedrives.json), [`-onedrive-get`](veeam-lab/w1.4-od-onedrive-get.json) |
| Folders | `GET Organization/OneDrives/{oneDriveId}/Folders?parentId=root` (top level; no `parentId` gives the same) or `?parentId={folderId}` | [`w1.4-od-folders-root`](veeam-lab/w1.4-od-folders-root.json), [`-folders`](veeam-lab/w1.4-od-folders.json), [`-folder-get`](veeam-lab/w1.4-od-folder-get.json) |
| Documents | `GET Organization/OneDrives/{oneDriveId}/Documents?parentId={folderId}&limit=…`; `?parentId=root&includeFolders=true` → the root's folders; no `parentId` → **every file, flattened** | [`w1.4-od-documents`](veeam-lab/w1.4-od-documents.json), [`-documents-page`](veeam-lab/w1.4-od-documents-page.json), [`-documents-root`](veeam-lab/w1.4-od-documents-root.json), [`-documents-no-parent`](veeam-lab/w1.4-od-documents-no-parent.json) |
| One document | `GET Organization/OneDrives/{oneDriveId}/Documents/{documentId}`; unknown → 404 "Document not found" | [`w1.4-od-document-get`](veeam-lab/w1.4-od-document-get.json), [`-document-get-unknown`](veeam-lab/w1.4-od-document-get-unknown.json) |

```json
{"id":"6d600fc0-65f8-4811-ad18-096ec5b7e83498cfff1a-b404-4438-ae6e-6927a6ccc325","name":"Alice Test",
 "url":"https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com"}

{"oneDriveId":"6d600fc0-…c325","sizeBytes":925,"inheritedPermissions":true,"version":"1.0",
 "id":"bab96008-6315-4110-89bc-75f4f3d587a4","versionId":1,"name":"rp-canary-11.pdf",
 "createdBy":"Alice Test","creationTime":"2026-09-24T22:11:23Z","modifiedBy":"Alice Test",
 "modificationTime":"2026-09-24T22:11:23Z","isFolder":false}
```

- The OneDrive `id` is two GUIDs concatenated (the personal site + web, like a site ID). Folder
  and document IDs are **plain GUIDs**, unlike SharePoint's composite ones.
- Match the OneDrive on `url` (the personal site URL built from the UPN), not on `name` (a
  display name, not unique). The `copyTo` body needs this object `{id, name, url}` as its
  target `onedrive` (feasibility §2c).
- **alice's `/RestoreTarget` folder is not in the backup either.** The `copyTo` body names the
  target folder by name only. *(W2.4, 2026-09-28: true of the two 2026-09-25 points only. The
  folder was created later that day and is in the backup from the 2026-09-27T22:00:48Z point
  on; see [`veeam-restore-flow.md`](veeam-restore-flow.md) §4.4.)*

### 5.4 Search (instead of listing)

Every search is a `POST` with the body `{"query": "<keyword>:<value>"}`, and pages like a list
(`limit`, `offset`, `setId`). The syntax is Veeam's "Item Search Parameters" (User Guide,
appendix A), which follows Outlook's `keyword:value`. Values with spaces go in double quotes.

| Scope | Call (under `/v8/RestoreSessions/{restoreSessionId}/`) | Query | Found | Time | Evidence |
|---|---|---|---|---|---|
| One mailbox | `POST organization/mailboxes/{mailboxId}/search` | `subject:RP-CANARY-0001` | 1 (alice's Inbox) | 0.2 s | [`w1.4-mail-search-mailbox`](veeam-lab/w1.4-mail-search-mailbox.json) |
| One mail folder | `POST organization/mailboxes/{mailboxId}/folders/{folderId}/search` | same | 1 | 0.06 s | [`w1.4-mail-search-folder`](veeam-lab/w1.4-mail-search-folder.json) |
| All mailboxes | `POST organization/mailboxes/search` | same | **2**: alice's Inbox **and the sender's Sent Items** | 1.4 s | [`w1.4-mail-search-all-mailboxes`](veeam-lab/w1.4-mail-search-all-mailboxes.json) |
| Organisation | `POST organization/searchExchange` | same | 2 (as above) | 1.3 s | [`w1.4-mail-search-exchange`](veeam-lab/w1.4-mail-search-exchange.json) |
| One site | `POST Organization/Sites/{siteId}/search` | `filename:rp-canary-01.pdf` | 1 | 5.2 s | [`w1.4-sp-search-site`](veeam-lab/w1.4-sp-search-site.json) |
| One library | `POST Organization/Sites/{siteId}/Libraries/{libraryId}/search` | same | 1 | 0.15 s | [`w1.4-sp-search-library`](veeam-lab/w1.4-sp-search-library.json) |
| All sites | `POST Organization/Sites/search` | same | 1 | 4.4 s | [`w1.4-sp-search-all-sites`](veeam-lab/w1.4-sp-search-all-sites.json) |
| Site, typed | `POST Organization/Sites/{siteId}/search?itemType=Items&containerType=Library` | same | 1 | 1.1 s | [`w1.4-sp-search-site-typed`](veeam-lab/w1.4-sp-search-site-typed.json) |
| One OneDrive | `POST Organization/OneDrives/{oneDriveId}/search` | `filename:rp-canary-11.pdf` | 1 | 4.1 s | [`w1.4-od-search-onedrive`](veeam-lab/w1.4-od-search-onedrive.json) |
| One OneDrive folder | `POST Organization/OneDrives/{oneDriveId}/Folders/{folderId}/search` | same | 1 | 0.17 s | [`w1.4-od-search-folder`](veeam-lab/w1.4-od-search-folder.json) |
| All OneDrives | `POST Organization/OneDrives/search` | same | 1 | 0.3 s | [`w1.4-od-search-all`](veeam-lab/w1.4-od-search-all.json) |

How the query behaves:

- **Prefix match on words, case-insensitive.** `subject:RP-CANARY-000` found 9 items (0001–0009,
  not 0010; [`w1.4-mail-search-prefix`](veeam-lab/w1.4-mail-search-prefix.json)).
  `filename:rp-canary-1` found 11–19, not 20 ([`w1.4-od-search-prefix`](veeam-lab/w1.4-od-search-prefix.json)).
  `filename:rp-canary-01` (no extension) found the pdf
  ([`w1.4-sp-search-no-extension`](veeam-lab/w1.4-sp-search-no-extension.json)).
  `subject:rp-canary-0001` found the upper-case subject
  ([`w1.4-mail-search-lowercase`](veeam-lab/w1.4-mail-search-lowercase.json)).
- Quoting (`subject:"RP-CANARY-0001"`, `filename:"rp-canary-01.pdf"`,
  [`w1.4-sp-search-quoted`](veeam-lab/w1.4-sp-search-quoted.json)) and no keyword at all (`RP-CANARY-0001`,
  `rp-canary-01.pdf`) gave the same single hit here
  ([`w1.4-mail-search-quoted`](veeam-lab/w1.4-mail-search-quoted.json),
  [`-bare`](veeam-lab/w1.4-mail-search-bare.json), [`w1.4-sp-search-bare`](veeam-lab/w1.4-sp-search-bare.json)).
- No match → 200 with empty `results` ([`w1.4-mail-search-none`](veeam-lab/w1.4-mail-search-none.json),
  [`w1.4-sp-search-none`](veeam-lab/w1.4-sp-search-none.json), [`w1.4-od-search-none`](veeam-lab/w1.4-od-search-none.json)).
  An empty query → 200, empty ([`w1.4-mail-search-empty`](veeam-lab/w1.4-mail-search-empty.json)). A syntax error (`subject:(RP-CANARY-0001`) → **500** "Syntax
  error: unexpected end of input, expected Right Parenthesis."
  ([`w1.4-mail-search-bad-query`](veeam-lab/w1.4-mail-search-bad-query.json)).
- OneDrive search takes `itemType=All|Folders|Documents`; SharePoint takes
  `itemType=All|Folders|Items` and `containerType=List|Library`.
- Mail search results carry `mailboxId`, and the folder only as `_links.parent` (a URL ending in
  the folder ID). An organisation-wide hit is told apart from the sender's Sent Items copy only
  by those two.
- **Search results are not the same objects as list results.** Their times have **no `Z`**
  (`"creationTime":"2026-09-24T22:14:43"` vs `"…:43Z"` from `GET …/Documents`).
- A search over a whole site or OneDrive took 4–5 s the first time and about 1 s after that. A
  search scoped to a library or folder took 0.15–0.2 s.

**Rule for the Worker (W2.5):**

1. Scope every search to the **source container**: alice's mailbox (better, its folder), the
   RestoreTest library, alice's `/RestoreTest` folder. Never search organisation-wide.
2. Treat a hit only as a candidate. Keep results whose `subject`/`name` is **exactly** equal
   (ordinal) to the manifest's, and expect exactly one; zero or several → `error` (the sample
   can't be located). This is not `fail`, because the backup wasn't tested. *(W2.4 proposes one
   exception for W3.3: zero matches for a canary the manifest dates before the point's
   `backupTime` is `fail`, the backup lacking it; `docs/api/veeam-restore-flow.md` §15.)*
3. Then re-read the item with `GET …/{id}` and send that object in the restore body.

For the 10+10+10+10 canaries, listing the container once (`limit=1000`) and matching locally
is simpler and faster than 10 searches. Search is for large real mailboxes (Stage 2 sampling).

### 5.5 ID formats

| Object | Example | Format |
|---|---|---|
| Organisation | `ff96d072-29e2-4cb4-a155-2590f5473176` | UUID |
| Organisation user | `RestoreProofLab.onmicrosoft.com:0000…:0000…:533138fa-…:0000…` | string, `:`-separated, embeds the Entra object ID |
| Organisation site | `fe08085d-…98eb4ecaf399-…e689` | site GUID + web GUID, concatenated (72 chars) |
| Restore point | `c2f0f2e7-…02e371ac3d9c-…681c` | repository ID + point ID, concatenated (72 chars) |
| Restore session | `208fce8b-836d-4363-89b4-f457b46d1333` | UUID |
| Mailbox (in a session) | `e00393b0-a896-4487-ad04-0e1be36468fb` | UUID, session-independent (same in W1.0 and W1.4 sessions) |
| Mail folder | `AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQwAAA` | base64url (Exchange entry ID) |
| Mail item | `LgAAAEYAAAAW…ADr_` (200 chars) | base64url; contains the folder's ID (`…AAAAAAQwAAA` for the Inbox) |
| SharePoint site (in a session) | same as the organisation site ID | 72 chars |
| SharePoint library | site ID + list GUID (108 chars) | the list GUID matches Graph's list ID |
| SharePoint document | library ID + item GUID (144 chars) | the item GUID is the list item's unique ID |
| OneDrive | `6d600fc0-…b7e834` + `98cfff1a-…c325` | two GUIDs, concatenated |
| OneDrive folder / document | `bab96008-6315-4110-89bc-75f4f3d587a4` | UUID |

Mail item IDs contain `-` and `_`, so URL-escape every ID placed in a path or query anyway.
None of these IDs is a Graph ID. The Graph read-back (W2.1, W3.x) finds restored items by path
and name, and mail by `internetMessageId`.

## 6. Restore to another location

Not repeated here: the three bodies, as sent and as they worked, are in
[feasibility §2c](veeam-feasibility.md#c-exact-v8-restore-bodies), with the evidence in
`w1.0-c-<mail|sp|od>-cert-*` (and the refused ones in `-none-*`, `-user-*` and `-no-folder-400`).
Summary of what each needs:

| | Endpoint (under the explore session) | Target fields | Required in practice |
|---|---|---|---|
| Mail | `POST organization/mailboxes/{mailboxId}/items/restoreTo` | `mailbox` (the target **address**), `folder` (a **name**, e.g. `Inbox`) | `folder` (else 400 "Missing mandatory parameters: Folder."); credentials; with a certificate also `impersonationAccountName` (the target mailbox); with a user, `casServer` (else 400) |
| SharePoint | `POST Organization/Sites/{siteId}/Documents/restoreTo` | `siteURL`, `list` (the library's **display name**) | `documents` = the full document objects; credentials |
| OneDrive | `POST Organization/OneDrives/{oneDriveId}/Documents/copyTo` | `onedrive` = `{id, name, url}` from §5.3, `folder` (a **name** in its root) | `documents` = the full document objects; credentials |

Credentials: `applicationId` + `applicationCertificate` (Base64 PFX) +
`applicationCertificatePassword` is the only kind that works unattended (feasibility §5.4).
With none, Veeam answers 400 "Missing mandatory parameters: userName." (mail: "CasServer."). Every restore call
answers **200 `{"sessionId": "<uuid>"}` within 0.5 s** whether or not the restore will succeed.
That ID is a **new** restore session, not the explore session.

`TargetGuard` (W2.7) must check these fields before the call: the mailbox address, the site URL
plus library name, and the OneDrive URL plus folder name, against the configured targets. Veeam
takes names, not the Graph IDs in the config (feasibility §5.5).

A restore POST must **not** be retried automatically (the W1.3 open point: it could run twice).
After a timeout or 5xx, look for the new session in `GET /v8/RestoreSessions` (newest first,
`initiatedBy`, `creationTime`) before deciding anything.

## 7. Waiting for the result

From W1.0's restores (feasibility §3; `w1.0-c-sp-cert-*` shown):

1. `POST …/restoreTo` → 200 `{"sessionId":"e09bc42d-…"}` ([`w1.0-c-sp-cert-restore`](veeam-lab/w1.0-c-sp-cert-restore.json)).
2. Poll `GET /v8/RestoreSessions/{sessionId}` every 5 s. `state` goes `Working` → **`Stopped`**
   (the only two values in the swagger's enum). Then `result` ∈ `Success`, `Warning`, `Failed`, and `details`
   reads "1 item processed (1 success)". It took 30–45 s per item here
   ([`w1.0-c-sp-cert-session`](veeam-lab/w1.0-c-sp-cert-session.json)):
   ```json
   {"id":"e09bc42d-…","name":"SharePoint restore (Entire organization - 9/25/2026 7:37:15 PM)","type":"Vesp",
    "creationTime":"2026-09-26T14:51:04.0961538Z","endTime":"2026-09-26T14:51:44.9135241Z",
    "state":"Stopped","result":"Success","initiatedBy":"rp-veeam","details":"1 item processed (1 success)","eTag":2}
   ```
3. Then `GET …/Statistics` (409 until `Stopped`, §4.3) ([`w1.0-c-sp-cert-statistics`](veeam-lab/w1.0-c-sp-cert-statistics.json)):
   ```json
   {"totalItemsCount":1,"restoredItemsCount":1,"failedItemsCount":0,"skippedItemsCount":0,
    "items":[{"id":"c137e9be-2c7c-49b8-b09a-8ada92102e78","itemRestoreDetailsType":"Item","name":"rp-canary-01.pdf",
              "itemType":"SharePointItem","status":"Success"}]}
   ```
   and `GET …/Events?limit=100` ("Restore session started", one `type: Restore` event per item
   with `status`, `source`, `target`, `message`, then "…completed" or "…failed";
   [`w1.0-c-sp-cert-events`](veeam-lab/w1.0-c-sp-cert-events.json)).

Traps (W1.0):

- A failed OneDrive restore reported `totalItemsCount 1, restoredItemsCount 0, failedItemsCount 0`,
  **no `errors`**, `details: "0 items processed"`. Only `result: Failed` and the events showed it
  ([`w1.0-c-od-user-statistics`](veeam-lab/w1.0-c-od-user-statistics.json),
  [`-session`](veeam-lab/w1.0-c-od-user-session.json)).
- Mail statistics have an **empty `items[]`** even on success
  ([`w1.0-c-mail-cert-statistics`](veeam-lab/w1.0-c-mail-cert-statistics.json)).
- A `copyTo` event's `source` names the **destination** path.
- `Statistics.items[].id` is the bare item GUID (the tail of the document ID in §5.5), not the
  document ID sent.

So "Veeam says restored" = `state == Stopped` **and** `result == Success` **and**
`restoredItemsCount` equals the number of items sent; only then does the Graph read-back decide
`pass` or `fail` (`docs/verification.md`, W3.3, to be written). Anything else means Veeam
reported a problem, and whether that is `fail` or `error` depends on the cause: W1.0's
user-credential failures were Microsoft 365 sign-in refusals (MFA), an infrastructure problem,
so `error` under CLAUDE.md's status rules. W3.3's decision table settles it; keep the
session's `result`, `details`, statistics and event messages in the result JSON for it. A
20-minute timeout with the session still `Working` → `error`; stop the explore session and
record the restore session ID.

## 8. Errors and what `VeeamClient` should map them to

Veeam's error body is `{"message": "…", "errorCode": "…"?}` (`RESTExceptionInfo`; `errorCode` ∈
`ResourceNotFound`, `ParameterValidationFailure`, `ResourceAccessDenied`, `OperationConflict`,
`Timeout`, `ProxyOffline`, …, often absent). Query-string binding errors use ASP.NET's
`ProblemDetails` instead. 401s on API calls have no body.

| Status | Body seen | When | Evidence | Map to |
|---|---|---|---|---|
| 401 | empty; `WWW-Authenticate: Bearer` | no token | `w1.4-auth-no-token-401` | `AuthError` (a bug: always send a token) |
| 401 | empty; `Bearer error="invalid_token"` (expired: plus `error_description="The token expired at …"`) | token expired, or revoked by a refresh, logout or REST restart; unknown token | `w1.4-auth-bad-token-401`, `-pre-refresh-access`, `-after-logout-access`, `w1.0-a-restart-admin-access` | sign in again once and resend (§1.7); then `AuthError` |
| 401 | `{"message":"The server has rejected the client credentials."}` | `/v8/token`: wrong password, unknown user, no Veeam role | `l1.6-admin-token-*-traced` | `AuthError` |
| 401 | `{"message":"The server has rejected the client credentials."}` | an API call the account's role doesn't allow (seen with an operator token) | `l1.6-operator-admin-sweep` | `AuthError` (don't re-login in a loop: the credentials are valid, the role isn't) |
| 401 | `{"message":"Refresh token is not valid"}` | `/v8/token` refresh: used, logged out, or killed by a restart | `w1.4-auth-refresh-reuse-401`, `-after-logout-refresh`, `w1.0-a-restart-*-refresh` | not an error: fall back to the password grant; `AuthError` only if that fails |
| 500 | **empty** | `/v8/token`: a refused login before the REST service's restart | `l1.6-admin-token-no-role`, `-wrong-password`, `-unknown-user` | `AuthError` (never retry `/v8/token` on 5xx; any 500 there is `AuthError`, a 502/503/504 `TransientError`) |
| 500 | `{"message":"An antiforgery token is not specified."}` | refresh without `disable_antiforgery_token` | `w1.0-a-operator-refresh-antiforgery-500` | a bug in the client; as built, `AuthError` like any 500 on `/v8/token` (a refresh falls back to the password first) |
| 400 | `{"message":"Missing mandatory parameters: …","errorCode":"ParameterValidationFailure"}` | restore without `folder`, credentials, `casServer`; explore without `dateTime` | `w1.0-c-mail-cert-restore-no-folder-400`, `w1.0-c-*-none-restore`, `w1.4-session-explore-no-date` | `VeeamError` |
| 400 | `ParameterValidationFailure`: "Error converting value …", "Incorrect restore point ID format…", "Item ID is not valid…", "Root parentId is unsupported." | bad enum/date/ID in a body or path | `w1.4-session-explore-bad-*-400`, `w1.4-rp-get-bare-id`, `w1.4-mail-item-get-unknown`, `w1.4-sp-documents-root` | `VeeamError` |
| 400 | ProblemDetails `{"errors":{"from":[…]},"status":400,…}` | bad query-string value | `w1.4-rp-list-bad-from` | `VeeamError` |
| 400 | "Exploring a specific organization or a job is not available for restore operators." | operator token on the admin explore | `l1.6-operator-admin-explore-refused` | `AuthError` (wrong account kind) |
| 404 | `{"message":"… does not exist …" / "Document not found (ID: …)","errorCode":"ResourceNotFound"}` | unknown organisation, restore point, session, document | `w1.4-org-get-unknown-404`, `w1.4-rp-get-unknown-404`, `w1.4-session-get-unknown-404`, `w1.4-od-document-get-unknown` | `VeeamError` (callers may treat "not found" specially, e.g. `NotFoundError : VeeamError`) |
| 404 | "The restore session statistics are not available." | Statistics of a stopped explore session with no restore | `w1.4-session-statistics-stopped` | `VeeamError` |
| 404 | empty | a route that doesn't exist | `w1.4-rp-guide-path-404` | `VeeamError` (a bug) |
| 409 | `{"message":"Unable to provide statistics until the restore session completes."}` | Statistics while `Working` | `w1.4-session-statistics-working-409` | not an error while polling: keep waiting |
| 500 | `{"message":"The chosen restore point date precedes the date of the first available restore point (…)."}` | explore before the first point | `w1.4-session-explore-before` | `VeeamError` (not transient) |
| 500 | `{"message":"Date/time value must be based on Coordinated Universal Time (UTC)…"}` | explore `dateTime` without `Z` | `w1.4-session-explore-local`, `-nooffset` | `VeeamError` (a bug) |
| 500 | `{"message":"Restore session is stopped."}` | browsing a stopped session | `w1.4-session-browse-after-stop` | `VeeamError` |
| 500 | `{"message":"Syntax error: …"}` | bad search query | `w1.4-mail-search-bad-query` | `VeeamError` |
| 500 | `{"message":"User … cannot manage selected object."}` | operator outside its scope | `w1.0-b-operator-explore-out-of-scope-*` | `AuthError` |
| 500 | `{"message":"The session was forcibly closed."}` | the next call on an operator session after its restore (feasibility §2b) | not saved | `VeeamError` |
| 5xx without a Veeam JSON body, connect/TLS-handshake errors, timeouts, dropped connections | — | service down or restarting | (W1.3 tests) | `TransientError` (as built, retried by `VeeamClient` itself: five attempts per GET; a token request only when it never went out) |

The problem: **W1.3's `HttpClient` retries every 5xx (five attempts in total, about 15 s of waiting).** Every 500 above is
deterministic, so each would cost about 15 s of retries and then surface as an `HttpError`
without the body. Proposal for W1.5 (to decide there, `docs/decisions.md`):

- let a request opt out of retry on status (keep retrying transport errors);
- have `VeeamClient` classify the 5xx itself:
  - `/v8/token` 5xx → `AuthError`;
  - a 500 whose body parses as `{"message": …}` → `VeeamError(message)`;
  - anything else 5xx (empty or non-JSON body, 502/503/504) → `TransientError`, retried;
- keep restore POSTs out of automatic retry altogether (§6).

The guide's "401/403 → AuthError" stands. No 403 was seen; Veeam uses 401 for an unauthorised
role (`l1.6-operator-admin-sweep`). `errorCode: ResourceAccessDenied` should map to `AuthError`
too.

## 9. Fixtures for W1.5 (`worker/tests/fixtures/veeam/`)

Take the `response` (status, headers that matter, body) from each evidence file. They are
already scrubbed; tokens are `[REDACTED]`, which is fine for a fake.

| Fixture | From | Tests |
|---|---|---|
| `token-200.json` | `w1.4-auth-token` | login parses tokens and `expires_in` |
| `token-refresh-200.json` | `w1.4-auth-refresh` | refresh stores the new refresh token |
| `token-refresh-invalid-401.json` | `w1.4-auth-refresh-reuse-401` | refresh failure → password grant |
| `token-rejected-401.json` | `l1.6-admin-token-wrong-password-traced` | wrong credentials → `AuthError` |
| `token-rejected-500-empty.json` | `l1.6-admin-token-wrong-password` | empty 500 on `/v8/token` → `AuthError`, no retry |
| `api-invalid-token-401.json`, `api-expired-token-401.json` | `w1.4-auth-pre-refresh-access`, `w1.4-auth-expired-access-401` | 401 on an API call → re-login once, resend |
| `logout-204.json` | `w1.4-auth-logout` | logout |
| `health-200.json` | `w1.4-auth-health` | doctor |
| `organizations-200.json` | `w1.4-org-list` | `listOrganizations()` → `{id, name}` |
| `organization-200.json` | `w1.4-org-get-extended` | org details (msid, region, officeName) |
| `organization-404.json` | `w1.4-org-get-unknown-404` | `ResourceNotFound` → `VeeamError` |
| `restore-points-200.json` | `w1.4-rp-list-org` | `listRestorePoints()` sorted newest first, raw `backupTime` kept |
| `restore-points-asc-200.json` | `w1.4-rp-list-asc` | sorting doesn't rely on server order |
| `restore-points-empty-200.json` | `w1.4-rp-list-empty` | no point → caller reports `error` |
| `restore-points-page1/2.json` | `w1.4-rp-list-limit1`, `-limit1-offset1` | paging stops when a page is short |
| `restore-point-400-format.json` | `w1.4-rp-get-bare-id` | 400 `ParameterValidationFailure` → `VeeamError` |
| `restore-points-bad-query-400.json` | `w1.4-rp-list-bad-from` | ProblemDetails body parses |
| `explore-201.json`, `explore-500-before-first.json`, `explore-500-not-utc.json` | `w1.4-session-explore`, `-before`, `-nooffset` | W2.x: explore; 500 with a message → `VeeamError`, not retried |
| `session-working.json`, `session-stopped.json`, `stop-204.json` | `w1.4-session-get`, `-get-stopped`, `-stop` | W2.x polling; `endTime` without `Z` parses |
| `statistics-409.json` | `w1.4-session-statistics-working-409` | W2.x: 409 = keep polling |
| `sessions-list.json` | `w1.4-sweep-list` | W2.x: the sweep picks only `Working` + own `initiatedBy` |
| mail/sp/od browse files | `w1.4-mail-*`, `w1.4-sp-*`, `w1.4-od-*` | W2.4/W2.5 navigation and exact-name matching |
| restore results | `w1.0-c-*-cert-*` (success), `w1.0-c-od-user-*` (the silent failure), `w1.0-c-mail-cert-statistics` (empty `items[]`) | W2.5: result decision table |

Session IDs, item IDs and names in these files are real lab values. Keep them: they exercise
the composite-ID handling.

## 10. Where the guide differs

| Guide (W1.4/W1.5) | Reality (v8, measured) |
|---|---|
| Bruno collection `docs/api/veeam-m365.bru` | PowerShell scripts in [`veeam-m365/`](veeam-m365/README.md) (`docs/decisions.md`, 2026-09-26) |
| `GET /Organizations/{id}/RestorePoints` | `GET /v8/RestorePoints?organizationId={id}`; the guide's path is 404 |
| `RestorePoint{id, backupTime, isModified}` | no `isModified`; `id` is repository ID + point ID |
| `POST /RestoreSessions` to explore | `POST /v8/Organizations/{id}/explore`, by `dateTime`, 201 |
| "the operator flow from W1.0" in the same collection | operator mode is out of Stage 1 (`docs/decisions.md` 2026-09-26); not repeated |
| W2.4: "record the operation id and how completion is signalled" | the restore returns a new restore-session ID; completion = `state: Stopped` (§7) |
| W1.5: "5xx → TransientError" | Veeam returns 500 for many deterministic client errors (§8) |

## 11. Open points

- **Which point a between-points session opens** (§4.2): can't be shown on this lab (identical
  content). If it matters, a later task can seed a change between two backups. The Worker
  sidesteps it by always sending an exact `backupTime`.
- **Retry classification of 5xx** (§8): decided in W1.5, as proposed there
  (`docs/decisions.md` 2026-09-26, "VeeamClient: status retries off per request"). A restore
  POST running twice after a timeout is still open for W2.x. *(W2.4, 2026-09-28: answered. The
  restore POST is sent at most once, with a duplicate check in `GET /v8/RestoreSessions`
  instead of a resend; see [`veeam-restore-flow.md`](veeam-restore-flow.md) §8. The Worker
  implements it in W2.5.)*
- **A new user and Veeam's cache** (§2.4): observed in W1.0, not re-tested (it needs a tenant
  change).

## 12. Document export (W6.1)

The spike W6.1 (#181, `docs/decisions.md` 2026-10-14) answered, on 2026-10-13 23:36–23:41 UTC,
whether Veeam's document export gives a real file's bytes straight from the backup **in admin
mode** (as `rp-veeam`, the account the Worker signs in as), for **SharePoint and for OneDrive**,
and whether those bytes compare with the copy a restore puts in the restore target. Until then
the export had been run once, as the operator account, for SharePoint only (feasibility §2 d).
Harness: `worker/tests/export_spike_live_test.cpp` through
[`w6.1-harness/w61-live.ps1`](veeam-lab/w6.1-harness/w61-live.ps1) (`docs/testing.md`, "The
export spike"); evidence [`w6.1-*`](veeam-lab/README.md#w61-spike-veeams-document-export-in-admin-mode).
Items: the lab's 14 real files of L1.8 (7 in the RestoreTest site's default library, 7 in alice's
OneDrive root), found through the connector's own `list_candidates` on the restore point of
2026-10-13T22:00:58.3211091Z; no canary, no mail.

### 12.1 The call

```
POST /v8/RestoreSessions/{restoreSessionId}/Organization/Sites/{siteId}/Documents/{documentId}/save
POST /v8/RestoreSessions/{restoreSessionId}/Organization/OneDrives/{oneDriveId}/Documents/{documentId}/save
Content-Type: application/json

{"asZip": false}
```

→ **200** `application/octet-stream`, `Content-Length` = the document's `sizeBytes` as listed,
`Content-Disposition: attachment; filename=<name>; filename*=UTF-8''<name>`, the body the file
(`w6.1-recording/export/001` to `016`: the 14 exports, the `asZip` one and the one beside the
restore, each as a digest, size and SHA-256). The document
IDs are the ones `GET …/Documents` lists (§5.2, §5.3), the same in every session. The request
names **no Microsoft 365 credential** (compare the restore bodies, feasibility §2 c), and Veeam
answers it from the repository: the source library's listing (ids, names, sizes, eTags,
modification times) and the OneDrive root's metadata, read through the Worker app before the
first export and after the last, were equal (`w6.1-results.json`, `notes.source_unchanged`), and
the restore targets were empty before and after the exports. **The export writes nothing in the
tenant.**

### 12.2 Admin mode, SharePoint and OneDrive: yes, both

| Site / OneDrive | Session | Files | Exports | Bytes = `sizeBytes` | Time per file |
|---|---|---|---|---|---|
| RestoreTest site, default library (`Vesp` session `4532c9c7…`) | 7 sites listed, 19 documents in the site | txt ×2, pdf ×2, png ×2, xlsx | **7 of 7** 200 octet-stream | yes, all 7 | 14.9 s the first, then 0.7–1.4 s |
| alice's OneDrive (`Veod` session `fc6176f5…`) | 2 OneDrives listed, 17 documents | txt ×2, pdf ×2, png ×2, docx | **7 of 7** 200 octet-stream | yes, all 7 | 0.5–0.9 s |

(`w6.1-2-export-spike.txt`, the `export …` lines; the second full run of the night, whose
evidence this is. The first full run, 23:31–23:35 UTC, gave the same 14 of 14 with 12.0 s, 9.5 s
and 8.4 s as its slow ones; its files were replaced by this run's, as the harness replaces
evidence only with a passing run's.)

### 12.3 The export against the restored copy: 14 of 14 equal

The same 14 were restored through `restore_sample` (the guarded path, two restore sessions,
both `Success`, 7 of 7 each: `4dc4c706…` SharePoint 23:38:05–23:39:18, `0b261e56…` OneDrive
23:39:22–23:39:54) and read back from the two file targets with the Worker's `TargetReader`
(`w6.1-2-export-spike.txt`, the table and the `hash …` lines) and, as a second tool, `rpworker
graph list --hash` (`w6.1-3-graph-list-hash-after.txt`):

| File | Export bytes | Restored bytes | Bytes equal | Content equal (rule) |
|---|---|---|---|---|
| 6 SharePoint txt, pdf, png | 84–12,420 | the same | **yes** | **yes** (SHA-256) |
| `room-bookings.xlsx` (SharePoint) | 19,995 | **22,594** | no: SharePoint rewrote the package on restore (as W1.0 saw for a docx) | **yes** (`office-v1` `a2d69a1b…` on both sides) |
| 6 OneDrive txt, pdf, png | 60–12,420 | the same | **yes** | **yes** (SHA-256) |
| `weekly-status.docx` (OneDrive) | 3,230 | 3,230 | **yes** | **yes** (`office-v1` `bcf2ef44…`; OneDrive rewrote nothing, as W3.1's check saw) |

Every SHA-256 `graph list --hash` printed equals the test's restored hash. So the export's bytes
are what a restore puts back, byte for byte for plain files, and by `office-v1` for Office files
(byte for byte too where SharePoint doesn't rewrite).

### 12.4 Limits and behaviour seen

- **`asZip: true`** answers a ZIP (598 bytes for the 899-byte pdf, `Content-Disposition`
  `project-brief.pdf.zip`) holding **one entry** named as the file, whose bytes equal the plain
  export's (`notes.as_zip`). Nothing is gained: send `false` and hash the body.
- **Time.** 0.5–1.5 s per file for these sizes, with one slow export per run of 9–15 s (the
  first of the run in both runs, and one more in the first run); the overlap export below took
  12.0 s. Budget 15 s or more per export, not the median. **Size:** the lab files are at most
  20 KB, so no large file was tried; the Worker's own read-back cap is 64 MiB
  (`rp::graph::kMaxDownloadBytes`), and an export above it would be the same cap's question.
- **The session after an export** stays `Working` and browsable: a document re-read and the
  session read after the seven exports (`notes.session_after_exports`). An export does not end
  an admin explore session (the operator's one-restore-per-session rule of feasibility §2 b was
  about restores).
- **An export beside a running restore.** Once two `Vesp` sessions of ours were `Working` (the
  connector's explore session `687c3d24…` and the restore `4dc4c706…` it had started), a third
  explore session `29efce0b…` was opened and `project-brief.pdf` exported from it: 200, the
  same SHA-256, 12.0 s; the restore went on to `Success` 7 of 7, and the OneDrive restore after
  it too (`notes.export_during_restore`, `notes.restore`). The export disturbed neither.
  Since the code review (`docs/decisions.md` 2026-10-14, "W6.1 code review") the test opens that
  third session as soon as the connector's explore session is listed, before the restore POST, so
  it is older than the connector's duplicate window (restore-flow §8: a `Working` `Vesp` session
  of ours created from 5 s before the POST is a second candidate and costs the restore its
  verdict, the connector's rule and not Veeam's; `notes.export_during_restore
  .session_c_before_duplicate_window` says whether it was), and it lists the sessions since the
  restore began, newest first, as `own_sessions` does, never the server's default order of a page
  of everything; the kept evidence is the run before that change.
- **A Stop that hangs**, once more: the connector's OneDrive explore session `58a1b0cc…` did
  not answer two Stops within 30 s each and was left `Working` by the connector (its rule: at
  most two Stops, `veeam_explore.cpp`); the same thing §4.4 recorded on 2026-09-30 and W3.2's
  live run met on 2026-10-01. It is Veeam's Stop, not the export: the hang came after the
  restores, on the session the connector had opened. `08-sweep-sessions.ps1 -WhatIf` some
  minutes later listed 200 sessions and **0 Working**: the session had stopped on its own, as
  on 2026-09-30.
- **What `office-v1` reads:** `docx` and `xlsx` only (`rp/office_v1.hpp`, `lab/seeder/office.py`,
  `CONTENT_FOLDERS`). A pptx, a doc, an xls, a ppt and the macro and template types are
  rewritten by SharePoint (`docs/verification.md`, "The rule for the Office files SharePoint
  rewrites") and have no content rule, so their export can't be compared with a restored copy
  until a rule exists; none is in the lab, and the spike added none (from the code, not a live
  check).

### 12.5 Verdict for W6.3: go, with these limits

The export works in admin mode for SharePoint and for OneDrive, and its bytes are the restored
copy's. W6.3 (`backup_content`, the real file's content expected from the backup before the
restore) can be built, under four conditions: (1) **Office files by `office-v1`, never by
bytes** (the export is the bytes SharePoint stored; the restore may rewrite them again); (2)
**`asZip` false**, always; (3) **pptx, legacy Office and the macro and template types stay
`metadata` by name** until a content rule exists for them; (4) **a time budget of at least 15 s
per export and the 64 MiB cap**, the export inside the connector's own explore session before
the restore POST (an export leaves the session usable, and runs beside a restore). The one
product seam the spike did not build is a `VeeamClient` method for an octet-stream POST, W6.3's
with its unit tests (`docs/decisions.md` 2026-10-14, W6.1, point 1).

**Built (W6.3, `docs/decisions.md` 2026-10-14, "W6.3 (#183) and W6.2 (#182)").** Under those four
limits: `VeeamClient::export_document` (one send, `Accept: */*` as the spike sent it, the answer's
type held to `application/octet-stream`), the connector's export step inside `restore_sample`
after every item is found and before the first restore request, 60 s per file and 15 minutes per
run, the 64 MiB cap; a file the export can't give is checked by name and size and named by the
`content_export` warning.
