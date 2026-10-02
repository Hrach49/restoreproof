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
signs in as alice and as the admin (the seeder app, delegated; a browser opens for each,
`--auth device` for a code) to confirm her canary folder exists and that the two canary files
the refusal probes aim at exist, since a deleted item answers 404 too. Exit 0 means everything
was as expected; 1 means any probe, token, the canary folder or a canary file was not; 2 means
the credential or a sign-in failed.

Since W3.4 it also writes, in three kinds only (`docs/decisions.md` 2026-10-02, point 9, as
amended by the build notes' point on the live 412):

- **Write probes, which must succeed.** In each restore target it creates one item named
  `rp-probe-<uuid>` and deletes it again: a small `.txt` file uploaded into the RestoreTarget
  library's root and into alice's `/RestoreTarget` folder (201), then `DELETE` with the
  `If-Match` ETag the upload returned (204); a draft in the `restoretest` mailbox (201), then
  `permanentDelete` (204), both with `Prefer: IdType="ImmutableId"` as the Worker sends it. A
  create is never sent twice (an unanswered one may have happened; the row says where the item
  may be). The delete is sent only for an item the create's reply proves to be the probe's own,
  in that target: its name, its drive and, in OneDrive, its folder. An interrupted delete is
  sent once more on the way out, and only there.
- **Refusal probes, which must be refused and could create nothing anyway.** In the folder of
  one canary file in the RestoreTest library (its root) and of one in alice's `/RestoreTest`
  folder it sends `POST /drives/{drive}/items/{folder}/children` with the body
  `{"name": "rp-probe-invalid:name", "folder": {}, "@microsoft.graph.conflictBehavior": "fail"}`.
  `:` is invalid in a SharePoint or OneDrive name, so nothing can be created. 403 or 404 is
  refused (ok). 400 means the request passed the permission check and only the name stopped it,
  so the app may write there; any 2xx means it created something (the row says to remove it by
  hand); 409, 412 or anything else is not a refusal either: all fail the check. The request
  names the folder, never a canary file. The seeder's own sign-ins (the admin for the library,
  alice for her folder) confirm each canary file exists first, so a 404 means "hidden"; a file
  that can't be confirmed fails the check, and nothing is sent there. Nothing else is ever sent
  at a canary location. alice's mailbox gets no write probe: read and write share the RBAC
  scope, so the read probe's 403 is the proof.
- **Controls, which must get 400.** The same invalid-name create in the RestoreTarget library's
  root and in alice's `/RestoreTarget` folder, where the app may write: 400 shows what
  "allowed" looks like, so a canary's 403 is a refusal and not something SharePoint rejects for
  every caller. Anything but 400 fails the check (a 403 or 404: no write in the target; a 2xx:
  it created something, remove it by hand). It creates nothing.

| Probe | Request | Expected | What it proves |
|---|---|---|---|
| token roles, Microsoft Graph | the Graph token's `roles` claim | exactly `Files.SelectedOperations.Selected`, `Lists.SelectedOperations.Selected`, `Sites.Selected` | No Graph permission beyond #1, #2 and #4, in particular no `Mail.Read` |
| token roles, Exchange Online | a token for `https://outlook.office365.com` | no roles | No `full_access_as_app` or other Exchange application role (that would reach every mailbox over EWS) |
| token roles, SharePoint | a token for `https://restoreprooflab.sharepoint.com` | no roles | No SharePoint application role (`Sites.Read.All` there would reach every site over SharePoint REST) |
| canary folder, read as alice | `GET /drives/{alice's drive}/items/{RestoreTest}`, as alice | a folder with files | The folder the canary-folder probes expect 404 on exists, so their 404 means "hidden", not "gone" |
| canary file, library, read as admin | `GET /drives/{RestoreTest drive}/items/root:/rp-canary-01.pdf:`, as the admin | a file there | The library refusal probe's target exists |
| canary file, OneDrive, read as alice | `GET /drives/{alice's drive}/items/{RestoreTest}:/rp-canary-11.pdf:`, as alice | a file there | The OneDrive refusal probe's target exists, so its 404 means "hidden" |
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
| RestoreTarget library: invalid name (control) | `POST /drives/{RestoreTarget drive}/items/root/children`, body `{"name": "rp-probe-invalid:name", "folder": {}, "@microsoft.graph.conflictBehavior": "fail"}` | 400 | Where #4 lets the app write, the request passes the permission check and only the name stops it: what "allowed" looks like |
| alice's OneDrive: RestoreTarget folder: invalid name (control) | `POST /drives/{alice's drive}/items/{RestoreTarget}/children`, as above | 400 | The same under #2 |
| RestoreTest library: invalid name beside a canary | `POST /drives/{RestoreTest drive}/items/root/children` (the folder of rp-canary-01), as above | 403 or 404 | #4 is on the RestoreTarget list only: the app can't write in the canary library's root (a grant on one canary file alone isn't seen; see below) |
| alice's OneDrive: invalid name in RestoreTest | `POST /drives/{alice's drive}/items/{RestoreTest}/children` (the folder of rp-canary-11), as above | 403 or 404 (404 expected: the folder is masked; the old `PATCH` got 404 there live on 2026-10-02) | #2 is on the RestoreTarget folder only: the canary folder stays out of reach (a grant on one canary file alone isn't seen; see below) |

The live run's output is the Done-when evidence: `docs/security/l1.5-worker-app-check.txt`
(L1.5) and, once the owner has run the W3.4 setup and the check, `docs/security/w3.4-worker-app-check.txt`
(the output saved as it is printed; it holds no secret). The script also prints Exchange's own
view (`Test-ServicePrincipalAuthorization`): `InScope` True for restoretest and False for
alice, now for the role `Application Mail.ReadWrite`.

### How each refusal is verified

- **The canary library (#1 read, #4 not on it).** The invalid-name folder create in its root
  must get 403. The library is in the same site as the RestoreTarget list, so a list grant made
  on the wrong ID would show here as 400; the script's name check refuses that ID before the
  grant.
- **alice's canary folder (#2 not on it).** The same create in it must get 404 (masked) or 403;
  400 would mean a folder grant reaches it. The read probes on the folder still expect 404.
- **The controls.** The same create in the two file restore targets must get 400, so a 403 at a
  canary is a refusal, not a request SharePoint would reject anyway.
- **What the probe does not see: a grant on one canary file.** The create asks the canary
  file's folder, not the file. `Files.SelectedOperations.Selected` can also grant write on one
  driveItem alone; such a grant on `rp-canary-01.pdf` or `rp-canary-11.pdf` leaves the folder's
  answer 403 or 404, and the check passes (a test pins this). The probe catches a write grant on
  the canary library's list, on the site or on alice's canary folder; a grant on a single canary
  file shows only in a read-only listing of that file's permissions, like the owner's below.
  The old `PATCH` named the file, but its 412 couldn't tell either.
- **Why not a `PATCH` (live, 2026-10-02).** The first refusal probe was `PATCH {}` on the canary
  file with `If-Match: "rp-probe-no-such-etag"`. At `rp-canary-01.pdf` in the library it got
  412, not 403 or 404, and the check failed, as it should on an unknown answer. An owner-run,
  read-only listing of the grants (the admin, `Sites.FullControl.All`) showed the canary side
  right: the app has only `read` on the RestoreTest site (the grant named RestoreProof Worker),
  and no application grant at all on the canary library's list (`7eb0f08a-…`) or on
  `rp-canary-01.pdf` (inherited site groups only). The RestoreTarget list has unique
  permissions with one application `write` grant, but the listing printed that application's
  name empty, so it didn't show whose it is; the controls' 400 in the live re-run, or a listing
  that prints `grantedToV2.application.id`, will. So where the app may read an item SharePoint checks
  `If-Match` before write permission, and a 412 can't tell "refused" from "allowed but stopped by
  the ETag". alice's canary answered 404 (the app can't read that folder), which was right. The
  invalid-name folder create replaced it: it never names a canary file, can create nothing, and
  its control shows the 400 a permitted request gets. If a canary ever answers that create 400
  too (SharePoint checking the name before permission), the check fails, and telling a refusal
  apart would need yet another design, never a pass.
- **Other mailboxes (#3 scoped).** No write is sent to alice's mailbox. Read and write share
  the RBAC scope, so the read probe's 403 on alice's mailbox, and `Test-ServicePrincipalAuthorization`'s
  `InScope` False, prove the write is refused there too.
- **Other sites and the directory.** Unchanged since L1.5: the 403 read probes.
- **In the Worker.** No Worker code ever sends a write at a canary: the Cleaner deletes only an
  item it listed in a restore target, behind the guard's own checks (`docs/decisions.md`
  2026-10-02, point 4). Its tests replay a hand-written 403 taken from the Python probe's reply.

The tests (`lab/tests/test_worker_app.py`) run the same check against a fake tenant, failure
paths first:

- an unexpected 200 on a forbidden resource;
- a 403 on an allowed one;
- a write grant missing (the create fails, and no delete is sent), a delete refused, a created
  item the reply doesn't prove to be in its target (never deleted), a create with an unknown
  outcome (never sent again), and an interrupted delete (sent once more, in the target only);
- a 400, 409, 412, 500 or any 2xx on a canary's invalid-name create (a misgranted canary
  library shows as 400 from the fake tenant itself), a control answering 403, 404, 409, 500 or
  a 2xx, and a canary file missing or unreadable by its owner (an error, never a pass; nothing
  is sent there); the only request at a canary location is that exact `POST`, with no canary
  file's ID in any path; the fake tenant answers a wrong `If-Match` on a readable canary 412, as
  seen live; and the probe's limit: a write grant on one canary file alone leaves the check
  passing;
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
library and folder are never named.

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

1. **Write access for cleanup (W3.4). Closed.** Decided in `docs/decisions.md` 2026-10-02,
   "W3.4: cleaning the restore targets before and after each run", point 1: grants #2, #3 and
   #4 above, made by the owner with `lab/entra/new-worker-app.ps1` and the admin consent, and
   proved by `check-worker-app`'s write and refusal probes (evidence
   `docs/security/w3.4-worker-app-check.txt`). `Sites.Selected` `write` is never an option. If
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
