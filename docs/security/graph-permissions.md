# Worker permissions: Microsoft Graph and Exchange Online

What the Worker's own app registration, **RestoreProof Worker**, may do in the tenant, and why
(L1.5, issue #13; W3.4, issue #39). The Worker uses it, app-only (no user), to read back what
Veeam restored into the three restore targets (CLAUDE.md, "Restore targets"), and since W3.4 to
delete those copies again (the Cleaner). The decisions behind this page are in
`docs/decisions.md`, 2026-09-27 (L1.5) and 2026-10-02 (W3.4, point 1). The lab's IDs are in
`lab/tenant.md` ("RestoreProof Worker app"), and the setup script is
`lab/entra/new-worker-app.ps1`, whose steps are in `lab/README.md`. The owner runs the script
and grants the admin consent; nothing in the repo changes the tenant on its own.

The rule is least privilege: nothing beyond what the L1.5 and W3.4 Done-whens and the reasons
below need. The app may write only in the three restore targets. The canary sources (the
`RestoreTest` library and alice's `/RestoreTest` folder) are never written, and in OneDrive not
even readable.

## What is granted

| # | Permission | Type | Granted in | Scope | Role | Why the Worker needs it |
|---|---|---|---|---|---|---|
| 1 | `Sites.Selected` | Microsoft Graph application permission, admin consent | Entra ID (consent) + SharePoint (`POST /sites/{site-id}/permissions`) | The RestoreTest site only | `read` | Read SharePoint items Veeam restored into the `RestoreTarget` library, which is in that site. The Done-when: "reads … the RestoreTest site". |
| 2 | `Files.SelectedOperations.Selected` | Microsoft Graph application permission, admin consent | Entra ID (consent) + OneDrive (`POST /drives/{drive-id}/items/{item-id}/permissions`) | alice's OneDrive `/RestoreTarget` folder only | `write` (W3.4; `read` until then) | Read OneDrive files Veeam restored into that folder, and delete them again (W3.4). |
| 3 | `Application Mail.ReadWrite` | Exchange Online RBAC for Applications role (**not** an Entra consent) | Exchange Online (`New-ManagementRoleAssignment -App … -CustomResourceScope`), assignment `RestoreProof Worker - Application Mail.ReadWrite - restoretest` | Management scope `RestoreProof Worker - restoretest mailbox`: `PrimarySmtpAddress -eq 'restoretest@…'` | read and write (W3.4; `Application Mail.Read` until then, whose assignment the script removes) | Read mail Veeam restored into the `restoretest` mailbox (the Done-when: "reads the test mailbox"), and permanently delete it again (W3.4). |
| 4 | `Lists.SelectedOperations.Selected` (W3.4) | Microsoft Graph application permission, admin consent | Entra ID (consent) + SharePoint (`POST /sites/{site-id}/lists/{list-id}/permissions`) | The `RestoreTarget` list (library) only, list ID in `lab/tenant.md` | `write` | Delete the files Veeam restored into the `RestoreTarget` library (W3.4). #1 stays `read`: listing the library relies on it. |

The access token therefore carries exactly three roles, `Files.SelectedOperations.Selected`,
`Lists.SelectedOperations.Selected` and `Sites.Selected`. Mail access isn't in the token:
Exchange checks its own role assignment on every call. `check-worker-app` fails if the token has
any other role.

A `*.Selected` consent alone gives no access. The app also needs a grant on the resource
itself, and it gets one on the RestoreTest site (read), on the RestoreTarget list (write) and on
the RestoreTarget folder (write), nowhere else
(Microsoft, [Overview of Selected permissions in OneDrive and SharePoint](https://learn.microsoft.com/en-us/graph/permissions-selected-overview)).
Microsoft documents there that a list, folder or file grant breaks inheritance on that resource,
that it applies whatever the path the item is reached by, and that `write` means "read and
modify the metadata and contents"; whether `write` also lets the app delete an item, and a
folder grant a child of the folder, `check-worker-app`'s write probes show (below).

**What the script checks before a write grant (W3.4).** A wrong ID in a grant call would make
something else writable, so `new-worker-app.ps1` reads the list (`$select=id,displayName,webUrl`)
and refuses unless its `displayName` is `RestoreTarget` and so is its address's last segment, and
reads the folder and refuses unless it is a folder named `RestoreTarget` directly under the root
of alice's drive. Only then does it POST (or PATCH) the `write` role. These mirror the Worker's
own `check_restore_library` and `check_restore_onedrive_folder`.

### Credential

A certificate, not a client secret:

- **The key is never sent.** The app signs a short-lived assertion with the private key, so
  nothing reusable crosses the wire. A secret is a password, sent with every token request.
- **Restores need a certificate anyway.** Veeam's restore-to-another-location body needs an
  Entra app ID and its certificate as a PFX (`docs/api/veeam-feasibility.md` §5.4). One kind
  of credential, stored one way, covers both.

In the lab it is a self-signed RSA 2048 certificate, valid for one year, subject
`CN=RestoreProof Worker (lab)`:

- **The private key** exists only in a PFX file outside the repo:
  `%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`.
- **The PFX password** is random and lives in Windows Credential Manager, as the generic
  credential `RestoreProof Lab - Worker Graph app PFX`.
- **The script never prints either one.** It deletes the certificate-store copy once the PFX
  is written, and uploads only the public certificate to the app.

Until the vault (W4.5), the Worker reads the same two values from environment variables,
`RP_GRAPH_CERT_PFX_BASE64` (the PFX as one line of Base64) and `RP_GRAPH_CERT_PASSWORD`,
which replaced `RP_GRAPH_CLIENT_SECRET` in W2.1; see `docs/worker-config.md`, "Microsoft Graph
app". It has no client secret.

### How the Worker signs in

Since W2.1 the Worker signs in itself, in C++ (`rp::graph::GraphClient` in
`worker/include/rp/graph_client.hpp`; decisions in `docs/decisions.md`, 2026-09-28):

- **The certificate is checked first.** Before any network call the Worker opens the PFX
  once (OpenSSL) and refuses one that is unusable: no MAC, wrong password, a legacy cipher, no
  key, a key that doesn't match, not RSA of at least 2048 bits, expired or not yet valid.
  After that it keeps only the key and certificate objects.
- **Each token request carries a new client assertion:** a JWT signed with the private key,
  PS256, with the certificate's `x5t#S256` in its header so Entra can find the key. Its
  audience is the tenant's token URL, its issuer and subject the Worker app's client ID; it is
  valid for 5 minutes and never reused. The request is the client-credentials grant with scope
  `https://graph.microsoft.com/.default`, so the token carries the three roles above and nothing
  else.
- **The token stays in memory** and goes only to URLs under
  `https://graph.microsoft.com/v1.0/`. Redirects are never followed with it.
- **What is left until the vault (W4.5):** the PFX and its password sit in environment
  variables, and the key lives in the Worker's memory while it runs.

The same sign-in, from Python, is how `python -m seeder record-graph-fixtures` records the
replies the Worker's tests replay (`lab/README.md`).

### What a refusal says

Graph's 403 doesn't say which permission is missing. So every Graph call the Worker makes
names the grant it relies on, and any 403 Graph explains (`ErrorAccessDenied` from Exchange,
`accessDenied` from SharePoint and OneDrive, `Authorization_RequestDenied` from the directory,
or another code) becomes a `PermissionError` whose message names it:

```text
Graph denied GET /v1.0/drives/b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6 (403 accessDenied): the Worker app relies on Sites.Selected read on the test site; see docs/security/graph-permissions.md
```

The mail calls are the exception. Since W3.2 every read of the test mailbox, the message
listing included, first runs the restore-target guard's mailbox check (`GET
/users/{test_mailbox}/mailFolders/inbox`), and a 403 there is the guard's refusal (a
`WrongTargetError`, exit 4), not a `PermissionError`: the Exchange scope covers the
`restoretest` mailbox alone, so a 403 may mean the address is another mailbox. Its message
still names the grant:

```text
Graph refused the Worker app the Inbox of the mailbox test_mailbox names (403): the app's Exchange scope covers the restoretest mailbox alone, so the address is another mailbox, or the grant "Exchange RBAC "Application Mail.ReadWrite" in a management scope covering the test mailbox" is missing: the Worker reads only the restoretest mailbox; nothing was listed
```

The path is shown without its query. A 403 without Graph's JSON error is no verdict on
the app's permissions (a TLS-inspecting proxy answers a blocked request with its own page), so
it is a plain `GraphError` that points at the network instead. Neither is a mailbox Graph
can't read (`MailboxNotEnabledForRESTAPI`, `MailboxNotSupportedForRESTAPI`), which is a
`GraphError` about the mailbox whatever its status. A 401 that persists after a fresh token names the grant
too, since Graph also answers 401 when the app has no role at all. The grant texts are
generic, so a customer never sees the lab's names:

| Grant (`rp::graph`) | Text in the message | Permission above |
|---|---|---|
| `kMailGrant` | `Exchange RBAC "Application Mail.ReadWrite" in a management scope covering the test mailbox` | #3 |
| `kSitesReadGrant` | `Sites.Selected read on the test site` | #1 |
| `kOneDriveGrant` | `Files.SelectedOperations.Selected write on the test OneDrive folder` | #2 |
| `kListWriteGrant` | `Lists.SelectedOperations.Selected write on the test library` | #4 |

The OneDrive grant came with W2.2, which reads the folder. W3.4 renamed `kMailReadGrant` to
`kMailGrant` and `kOneDriveReadGrant` to `kOneDriveGrant` with the texts above, and added
`kListWriteGrant`, which the Cleaner's deletes in the library name (`docs/decisions.md`
2026-10-02, point 3). A test checks that no grant text names a lab value. Whatever the grant, a refusal makes the run's status `error`, never `fail` (`docs/verification.md`).

How the OneDrive grant's (#2) refusal is verified differs from the other two: it can't be
provoked read-only. SharePoint answers 404 `itemNotFound`, not 403, for an item the app may not
read (the canary-folder probes below), so live, a missing or dropped grant shows up as a
`NotFoundError` on the folder, and `rp::graph::TargetReader` adds to its message that the
Worker app may lack `Files.SelectedOperations.Selected write on the test OneDrive folder`. The
`PermissionError` path for #2 is tested only from the hand-written fixture
`worker/tests/fixtures/graph/onedrive-folder-403-accessdenied.json`. Both give status `error`
(`docs/decisions.md` 2026-09-28, W2.2).

## What is deliberately not granted

| Left out | Why |
|---|---|
| `Mail.Read` (Entra application permission) | It covers every mailbox in the tenant. Exchange adds an RBAC grant to an Entra consent as a union, so with both in place the scope would mean nothing ([RBAC for Applications, FAQ](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)). The script removes this consent if it is ever added, and the checker fails on a `Mail.Read` role in the token. Application Access Policies, the older way to scope it, are replaced by RBAC for Applications. |
| `Files.Read.All`, `Files.ReadWrite.All` | They read every drive in the tenant through `/drives/{id}`, every other site's libraries and every user's OneDrive included. The Done-when's "403 on any other site" would fail. |
| `Sites.Read.All`, `Sites.ReadWrite.All`, `Sites.FullControl.All` | Every site in the tenant. |
| `Sites.Selected` on alice's OneDrive | It would open all of her OneDrive, her own files and the canary `/RestoreTest` folder included. The Worker needs one folder, so it gets one folder (#2). In a customer tenant this OneDrive belongs to a real person. |
| Any write role other than #2, #3 and #4: `Sites.Selected` `write` on the RestoreTest site, `write` on any other list or folder, `owner` or `fullcontrol` anywhere | `Sites.Selected` `write` would cover the whole RestoreTest site, the canary library included. The Cleaner needs to delete in the three restore targets only, so it gets write on exactly those (W3.4, `docs/decisions.md` 2026-10-02, point 1). `owner` and `fullcontrol` would let the app change grants, its own included. |
| `Mail.Send`, `Mail.ReadWrite` (Entra application permissions), calendars, contacts | Never needed. `Mail.ReadWrite` as an Entra consent covers every mailbox; the Cleaner's mail write is the RBAC role #3, scoped to `restoretest`. |
| `User.Read.All`, `Directory.Read.All` | The Worker addresses the mailbox by the UPN in `config.json` and the drive by ID. It never looks anyone up. The checker proves `/users` is 403. |
| Delegated permissions | The Worker runs unattended, as a service. |
| A client secret | See "Credential". |

## How it is verified

`python -m seeder check-worker-app` (run from `lab/`) signs in with the certificate and sends
one request per probe, then compares the HTTP status with the expected one. The expected
statuses are the ones Graph gave in the lab: 403 where nothing is granted, 404 for an item
hidden inside a site where the app holds a folder grant. It also takes a token for Exchange
Online's and SharePoint's own APIs: a role consented there (`full_access_as_app`,
`Sites.Read.All`) never shows in the Graph token, and all Graph probes would still pass. And it
signs in as alice (the seeder app, delegated; a browser opens, `--auth device` for a code) to
confirm her canary folder exists, since a deleted folder answers 404 too. Exit 0 means
everything was as expected; 1 means any probe, token or the canary folder was not; 2 means the
credential or a sign-in failed.

Since W3.4 it also writes, in the three restore targets only (`docs/decisions.md` 2026-10-02,
point 9, and the build notes' point 13):

- **Write probes, which must succeed.** In each restore target it creates one item named
  `rp-probe-<uuid>` and deletes it again: a small `.txt` file uploaded into the RestoreTarget
  library's root and into alice's `/RestoreTarget` folder (201), then `DELETE` with the
  `If-Match` ETag the upload returned (204); a draft in the `restoretest` mailbox (201), then
  `permanentDelete` (204), both with `Prefer: IdType="ImmutableId"` as the Worker sends it. A
  create is never sent twice (an unanswered one may have happened; the row says where the item
  may be). The delete is sent only for an item the create's reply proves to be the probe's own,
  in that target: its name, its drive and, in OneDrive, its folder. An interrupted delete is
  sent once more on the way out, and only there.
- **Nothing but GETs at a canary.** No write probe can prove a refusal there (below), so none is
  sent: no request of another method goes to the canary library, its list or alice's canary
  folder, and no request names a canary file. That the app can't write at a canary is proven
  read-only, from the grants, by `lab/entra/check-worker-grants.ps1`. alice's mailbox gets no
  write probe either: read and write share the RBAC scope, so the read probe's 403 is the proof.

| Probe | Request | Expected | What it proves |
|---|---|---|---|
| token roles, Microsoft Graph | the Graph token's `roles` claim | exactly `Files.SelectedOperations.Selected`, `Lists.SelectedOperations.Selected`, `Sites.Selected` | No Graph permission beyond #1, #2 and #4, in particular no `Mail.Read` |
| token roles, Exchange Online | a token for `https://outlook.office365.com` | no roles | No `full_access_as_app` or other Exchange application role (that would reach every mailbox over EWS) |
| token roles, SharePoint | a token for `https://restoreprooflab.sharepoint.com` | no roles | No SharePoint application role (`Sites.Read.All` there would reach every site over SharePoint REST) |
| canary folder, read as alice | `GET /drives/{alice's drive}/items/{RestoreTest}`, as alice | a folder with files | The folder the canary-folder probes expect 404 on exists, so their 404 means "hidden", not "gone" |
| restoretest's mailbox | `GET /users/restoretest@…/messages` | 200 | #3 reaches the test mailbox |
| RestoreTest site | `GET /sites/{RestoreTest site ID}` | 200 | #1 reaches the site |
| RestoreTarget library: the drive | `GET /drives/{RestoreTarget drive ID}` | 200 | #1 covers the SharePoint restore target |
| RestoreTarget library: files in its root | `GET /drives/{RestoreTarget drive ID}/root/children` | 200 | #1 lets it read the restored files |
| alice's OneDrive: RestoreTarget folder | `GET /drives/{alice's drive}/items/{RestoreTarget}` | 200 | #2 reaches the OneDrive restore target |
| alice's OneDrive: files in RestoreTarget | `GET …/items/{RestoreTarget}/children` | 200 | #2 lets it read the restored files |
| alice's OneDrive: the site (metadata) | `GET /sites/restoreprooflab-my.sharepoint.com:/personal/alice_…` | 200 | Seen in the lab: a grant on a folder opens the metadata of the site and drive around it (name, URL), not their content. The next two rows prove that |
| alice's OneDrive: root folder (metadata) | `GET /drives/{alice's drive}/root` | 200 | As above: the root folder item, not its content |
| alice's OneDrive: files in her root | `GET /drives/{alice's drive}/root/children` | 200, **listing only `RestoreTarget`, by that name** | SharePoint masks every item the app may not see: her other files and the canary folder aren't even listed. Any other item listed (or a next page) fails the probe, and so does `RestoreTarget` missing or renamed: Veeam's OneDrive restore finds the folder by name |
| alice's mailbox | `GET /users/alice@…/messages` | 403 | #3 is scoped to restoretest; no Entra `Mail.Read` |
| tenant root site: the site | `GET /sites/restoreprooflab.sharepoint.com` | 403 | #1 is on one site only (the Done-when's "403 on any other site") |
| tenant root site: its libraries | `GET /sites/restoreprooflab.sharepoint.com/drives` | 403 | No `Files.Read.All`-style access to other sites' drives |
| OneDrive host root site | `GET /sites/restoreprooflab-my.sharepoint.com` | 403 | A second site with no grant in it: closed too |
| directory: list users | `GET /users` | 403 | No directory permission |
| alice's OneDrive: RestoreTest canary folder | `GET /drives/{alice's drive}/items/{RestoreTest}` | 404 | The canary folder can't be read, let alone written. SharePoint answers "not found", not "forbidden", for an item the app may not see (seen in the lab) |
| alice's OneDrive: files in the canary folder | `GET …/items/{RestoreTest}/children` | 404 | Nor its files |
| RestoreTarget library: create a file / delete it | `PUT /drives/{RestoreTarget drive}/items/root:/rp-probe-<uuid>.txt:/content`, then `DELETE /drives/{RestoreTarget drive}/items/{id}` with `If-Match` | 201, then 204 | #4 lets the Cleaner delete in the library, a `DELETE` included |
| alice's OneDrive: RestoreTarget folder: create a file / delete it | `PUT …/items/{RestoreTarget}:/rp-probe-<uuid>.txt:/content`, then `DELETE …/items/{id}` with `If-Match` | 201, then 204 | #2 `write` lets the Cleaner delete a child of the folder |
| restoretest's mailbox: create a draft / permanently delete it | `POST /users/restoretest@…/messages`, then `POST …/messages/{id}/permanentDelete`, ImmutableId | 201, then 204 | #3 lets the Cleaner permanently delete mail, by the ImmutableId it lists |

The live run's output is the Done-when evidence: `docs/security/l1.5-worker-app-check.txt`
(L1.5) and, once the owner has run the W3.4 setup and the checks, `docs/security/w3.4-worker-app-check.txt`
and `docs/security/w3.4-worker-grants-check.txt` (the grant check's; each saved as it is
printed; neither holds a secret). The script also prints Exchange's own
view (`Test-ServicePrincipalAuthorization`): `InScope` True for restoretest and False for
alice, now for the role `Application Mail.ReadWrite`.

### How each refusal is verified

- **The canaries (#1 read on the site; #2 and #4 not on them): by the grants, read-only.**
  `lab/entra/check-worker-grants.ps1` lists the grants as the admin (`Sites.FullControl.All`,
  GETs only) and matches the Worker app by its client ID, never its name. It requires: on the
  RestoreTest site exactly one Worker app grant, `read`; on the canary library's list, its root
  folder and each of its 10 canary files no Worker app grant of its own and an inherited one
  only `read`; on alice's OneDrive site, its Documents list, her OneDrive root, her
  `/RestoreTest` folder and its 10 canary files no Worker app grant at all (her site found by
  its URL and checked to hold her drive, the list through the drive); on the RestoreTarget list
  and alice's `/RestoreTarget` folder exactly one Worker app grant of its own, `write`. A
  permission naming the app's ID anywhere counts as the app's (SharePoint's `siteUser` claim
  form included). The canary files come from `lab/seed-manifest.json`; a failed GET or a reply
  without a permission list is a problem, never a pass; another application's grant is printed
  as a note. In the selected-permissions model access comes only from an application grant on
  the resource or on a parent it inherits from (Microsoft,
  [Overview of Selected permissions](https://learn.microsoft.com/graph/permissions-selected-overview),
  "How access is calculated"), so no grant on a canary or any of its parents means no access
  through a grant. The proof has a second half: no tenant-wide role (`Sites.ReadWrite.All`,
  `Files.ReadWrite.All` and the like reach every canary with no grant listed), which
  `check-worker-app`'s token-roles rows check (only the three `*.Selected` roles in the Graph
  token, none for SharePoint or Exchange). The two runs together are the evidence. It also catches what
  a probe at a folder never could, a write grant on one canary file alone
  (`Files.SelectedOperations.Selected` allows one on a single driveItem). `new-worker-app.ps1`
  runs it at its end and stops on a problem. Rows in `lab/README.md`.
- **Why no write probe (live, 2026-10-02).** Two were tried and neither can tell a refusal from
  a permitted write that something else stopped. A `PATCH {}` with `If-Match:
  "rp-probe-no-such-etag"` on `rp-canary-01.pdf` got 412: where the app may read an item,
  SharePoint checks `If-Match` before write permission. A folder create with a name SharePoint
  never accepts (`rp-probe-invalid:name`) got 400 at both canary locations, alice's
  `/RestoreTest` folder included, which the same app gets 404 on for a plain GET (it can't even
  see it), and 400 in the two restore targets too: Graph validates the name before any
  permission check, so a 400 says nothing. Any probe whose request could pass the checks would
  risk a real write at a canary, so the check reads the grants instead
  (`docs/decisions.md` 2026-10-02, W3.4 build notes, points 12 and 13).
- **alice's canary folder, read side.** The read probes on it still expect 404 (masked), after
  alice's own sign-in confirms the folder exists.
- **Other mailboxes (#3 scoped).** No write is sent to alice's mailbox. Read and write share
  the RBAC scope, so the read probe's 403 on alice's mailbox, and `Test-ServicePrincipalAuthorization`'s
  `InScope` False, prove the write is refused there too.
- **Other sites and the directory.** Unchanged since L1.5: the 403 read probes.
- **In the Worker.** No Worker code ever sends a write at a canary: the Cleaner deletes only an
  item it listed in a restore target, behind the guard's own checks (`docs/decisions.md`
  2026-10-02, point 4). Its tests replay a hand-written 403: no write at a canary is ever sent,
  live or from the lab, to record one.

The tests (`lab/tests/test_worker_app.py`) run the same check against a fake tenant, failure
paths first:

- an unexpected 200 on a forbidden resource;
- a 403 on an allowed one;
- a write grant missing (the create fails, and no delete is sent), a delete refused, a created
  item the reply doesn't prove to be in its target (never deleted), a create with an unknown
  outcome (never sent again), and an interrupted delete (sent once more, in the target only);
- no request but a GET reaching a canary location or naming a canary file, and no folder
  create anywhere, with the grants as they are and with a write grant on the canary library or
  on alice's canary folder (which `check-worker-app` doesn't probe: the grant check reads them);
- an extra or missing role, and any role in the Exchange Online or SharePoint token;
- `RestoreTarget` renamed or missing from alice's root listing;
- the canary folder missing or empty, although the app still gets 404 on it;
- no response;
- a token failure, including MSAL raising (no network, unknown tenant);
- a missing or wrong credential.

`lab/tests/test_entra_script.py` runs parts of the setup script with stubs: removing a
consent on an API other than Graph, removing client secrets and other certificates, retrying
only replication lag, treating "already exists" as granted, and the two name checks refusing
the canary library, a renamed list, another list's address, the canary folder, a nested or
renamed folder and another drive. It also checks the script's text: the only `write` grants
are on the RestoreTarget list and folder, each behind its name check; the list grant uses only
`$RestoreTargetListId`; the only mail role is `Application Mail.ReadWrite`; and the canary
library and folder are never named. For `check-worker-grants.ps1` it runs the rules
(`Test-PermissionRule`) row by row, failure rows first (a Worker app write on the canary list,
a grant of its own or an inherited one other than `read` on a canary file, any Worker app entry
on alice's canary folder, the site grant `write`, missing or doubled, the app matched by its ID
with an empty name, the RestoreTarget `write` missing), then the whole script with
`Invoke-MgGraphRequest` stubbed: a failed GET, a next page, a manifest that can't be read or
lists fewer than 20 files (nothing read), another account, and the grants as set up; and it
checks the script's constants against `seeder/tenant.py`, that every Graph call is a `GET`, that
it asks for `Sites.FullControl.All` only and names no write verb, and that `new-worker-app.ps1`
runs it after the grants and stops on a problem.

A sentinel test greps every output for the PFX password, the token and the private key.

## Caveats

- **A management scope needs `Enable-OrganizationCustomization`.** New tenants start
  "dehydrated" and refuse `New-ManagementScope` until this one-time, tenant-wide, irreversible
  step. The script runs it when `Get-OrganizationConfig` reports `IsDehydrated`. The lab tenant
  ran it on 2026-09-27; a customer tenant may need it too (open item 3).
- **Exchange permission changes are cached for 30 minutes to 2 hours.** Until then the mail
  probes can still show the old state. `Test-ServicePrincipalAuthorization` skips the cache.
- **The RestoreTest site holds the canary library too.** `Sites.Selected` applies to the whole
  site, so #1 can also read the `RestoreTest` library (canaries `01…10`). That is read, never
  write, and the Worker never asks for it. The write grant #4 is on the RestoreTarget list
  alone. The OneDrive canaries aren't readable at all.
- **The folder and list grants break permission inheritance** on `/RestoreTarget` and on the
  RestoreTarget list, as any item- or list-level grant does. Files restored into them inherit
  the grant. Microsoft notes a service limit on unique permissions; two are far below it.
- **What `write` reaches.** `Application Mail.ReadWrite` lets the app change or delete any item
  in `restoretest`, a mailbox that exists only for restores. #4 covers every item in the
  RestoreTarget library, #2 every item in the `/RestoreTarget` folder and the folder itself;
  deleting that folder would drop the grant, and the Cleaner never deletes a folder. Neither
  grant reaches a sibling list or folder (W3.4, residual risks).
- **A deleted file is recoverable.** The Cleaner's file `DELETE` puts the item in the site's
  recycle bin for 93 days; a mail `permanentDelete` goes to Recoverable Items (Purges).
- **The OneDrive grant needs the admin to be a site collection admin of alice's OneDrive.**
  Even a global admin can't manage another user's OneDrive without that. `lab/README.md` says
  how to set it, and how to remove it afterwards.
- **Deleting and re-creating `/RestoreTarget`** gives it a new item ID and drops the grant.
  The Worker then gets 404 on the old ID (SharePoint's mask; a 403 where Graph says so),
  which it reports as `error`, not `fail` (`docs/verification.md`). Run the script again after updating the ID.

## Open items

1. **Write access for cleanup (W3.4). Closed on 2026-10-02:** `check-worker-app` 22/22 (list `write` allows a `DELETE`, folder `write` allows deleting a child, `permanentDelete` takes the ImmutableId) and `check-worker-grants.ps1` "canary grants: ok", both saved. Decided in
   `docs/decisions.md` 2026-10-02, "W3.4: cleaning the restore targets before and after each
   run", point 1: grants #2, #3 and #4 above, made by the owner with
   `lab/entra/new-worker-app.ps1` and the admin consent, to be proved by a re-run of
   `check-worker-app` (its token roles and write probes) and a run of the read-only grant check,
   `lab/entra/check-worker-grants.ps1`, saved as `docs/security/w3.4-worker-app-check.txt` and
   `docs/security/w3.4-worker-grants-check.txt` (the build notes' "Still open"). This item is
   closed once both are saved and pass. `Sites.Selected` `write` is never an option. If
   a probe fails live (whether list `write` allows a `DELETE`, whether folder `write` allows
   deleting a child), that entry is amended, not this table widened. Exchange caches role
   changes for 30 minutes to 2 hours: probe again after the delay before trusting a 403 on the
   mail probe.
2. **The Veeam restore app (W2.4).** Veeam's restore body carries an Entra app ID and its
   certificate. This app can't serve: it has no write access anywhere, and Veeam writes the
   restored items. Whether that is Veeam's own backup app, or a dedicated restore app with
   narrower permissions, is still open (`docs/api/veeam-feasibility.md` §5.4, and
   `docs/decisions.md` 2026-09-26). Either way its PFX is a vault secret like this one.
   W2.4 (`docs/decisions.md` 2026-09-28) restored in the lab with Veeam's own organisation
   app: its certificate exported per run from `Cert:\LocalMachine\My` into memory, the
   temporary PFX deleted at once, the PFX not stored. A dedicated app is still open, for a spike
   before W4.5. Against a narrow one: Veeam's SharePoint restore demanded
   `Group.ReadWrite.All` (application) on the app (L1.4, `docs/manual-restore-reference.md`).
3. **Customer tenants.** Onboarding an MSP's client repeats these steps per tenant: the
   `restoretest` scope, the site grant, the OneDrive folder grant and the site collection
   admin requirement. How the product guides or automates that is for the onboarding tasks.
4. **Certificate expiry.** The lab certificate expires one year after it was made (date in
   `lab/tenant.md`). To renew it, delete the PFX and run the script again: it makes a new
   certificate and replaces the old one on the app. Stage 1 has no renewal alert yet; the
   Worker only logs a warning once the certificate expires within 30 days (W2.1), and refuses
   an expired one.
5. **Reading alice's OneDrive drive (W2.5).** W2.4's mapping of config IDs to Veeam's names
   (`docs/decisions.md` 2026-09-28, W2.4, decision 3) reads
   `GET /drives/{test_onedrive_drive_id}` for the OneDrive's `webUrl`. This app's grant,
   `Files.SelectedOperations.Selected`, is on the `/RestoreTarget` folder only, so a
   drive-level read may answer 403. W2.5 must check it. If it is refused, the fallback is the
   folder's `parentReference.siteId` (the first GUID of Veeam's OneDrive `id`), read through the
   existing folder grant: no new permission (`docs/api/veeam-restore-flow.md` §16). Settled in
   W2.7's review (2026-09-30): the folder's own `sharepointIds` (`siteUrl`, `siteId`, `webId`)
   give Veeam's OneDrive URL and ID through the folder grant, so the Worker never reads the
   drive. The guard also reads the restoretest Inbox (`GET /users/{mailbox}/mailFolders/inbox`)
   through #3: a 403 there means the configured address isn't the scoped mailbox, and the guard
   refuses it.
