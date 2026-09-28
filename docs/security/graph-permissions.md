# Worker permissions: Microsoft Graph and Exchange Online

What the Worker's own app registration, **RestoreProof Worker**, may do in the tenant, and why
(L1.5, issue #13). The Worker uses it, app-only (no user), to read back what Veeam restored
into the three restore targets (CLAUDE.md, "Restore targets"). The decisions behind this page
are in `docs/decisions.md`, 2026-09-27. The lab's IDs are in `lab/tenant.md` ("RestoreProof
Worker app"), and the setup script is `lab/entra/new-worker-app.ps1`, whose steps are in
`lab/README.md`.

The rule is least privilege: nothing beyond what the L1.5 Done-when and the reasons below
need. The canary sources (the `RestoreTest` library and alice's `/RestoreTest` folder) are
never written, and in OneDrive not even readable.

## What is granted

| # | Permission | Type | Granted in | Scope | Role | Why the Worker needs it |
|---|---|---|---|---|---|---|
| 1 | `Sites.Selected` | Microsoft Graph application permission, admin consent | Entra ID (consent) + SharePoint (`POST /sites/{site-id}/permissions`) | The RestoreTest site only | `read` | Read SharePoint items Veeam restored into the `RestoreTarget` library, which is in that site. The Done-when: "reads … the RestoreTest site". |
| 2 | `Files.SelectedOperations.Selected` | Microsoft Graph application permission, admin consent | Entra ID (consent) + OneDrive (`POST /drives/{drive-id}/items/{item-id}/permissions`) | alice's OneDrive `/RestoreTarget` folder only | `read` | Read OneDrive files Veeam restored into that folder. |
| 3 | `Application Mail.Read` | Exchange Online RBAC for Applications role (**not** an Entra consent) | Exchange Online (`New-ManagementRoleAssignment -App … -CustomResourceScope`) | Management scope `RestoreProof Worker - restoretest mailbox`: `PrimarySmtpAddress -eq 'restoretest@…'` | read | Read mail Veeam restored into the `restoretest` mailbox. The Done-when: "reads the test mailbox". |

The access token therefore carries exactly two roles, `Files.SelectedOperations.Selected` and
`Sites.Selected`. Mail access isn't in the token: Exchange checks its own role assignment on
every call. `check-worker-app` fails if the token has any other role.

A `*.Selected` consent alone gives no access. The app also needs a grant on the resource
itself, and it gets one on the RestoreTest site and on the RestoreTarget folder, nowhere else
(Microsoft, [Overview of Selected permissions in OneDrive and SharePoint](https://learn.microsoft.com/en-us/graph/permissions-selected-overview)).

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
  `https://graph.microsoft.com/.default`, so the token carries the two roles above and nothing
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
Graph denied GET /v1.0/users/restoretest@contoso.onmicrosoft.com/mailFolders/inbox/messages (403 ErrorAccessDenied): the Worker app relies on Exchange RBAC "Application Mail.Read" in a management scope covering the test mailbox; see docs/security/graph-permissions.md
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
| `kMailReadGrant` | `Exchange RBAC "Application Mail.Read" in a management scope covering the test mailbox` | #3 |
| `kSitesReadGrant` | `Sites.Selected read on the test site` | #1 |
| `kOneDriveReadGrant` | `Files.SelectedOperations.Selected read on the test OneDrive folder` | #2 |

The OneDrive grant came with W2.2, which reads the folder; a test checks that no grant text
names a lab value. Whatever the grant, a refusal makes the run's status `error`, never `fail` (`docs/verification.md`).

How the OneDrive grant's (#2) refusal is verified differs from the other two: it can't be
provoked read-only. SharePoint answers 404 `itemNotFound`, not 403, for an item the app may not
read (the canary-folder probes below), so live, a missing or dropped grant shows up as a
`NotFoundError` on the folder, and `rp::graph::TargetReader` adds to its message that the
Worker app may lack `Files.SelectedOperations.Selected read on the test OneDrive folder`. The
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
| Any write role (`write`, `owner`, `fullcontrol`; `Application Mail.ReadWrite`) | L1.5 only reads. Cleanup's write needs are an open item (below). |
| `Mail.Send`, `Mail.ReadWrite`, calendars, contacts | Never needed. |
| `User.Read.All`, `Directory.Read.All` | The Worker addresses the mailbox by the UPN in `config.json` and the drive by ID. It never looks anyone up. The checker proves `/users` is 403. |
| Delegated permissions | The Worker runs unattended, as a service. |
| A client secret | See "Credential". |

## How it is verified

`python -m seeder check-worker-app` (run from `lab/`) signs in with the certificate and sends
one GET per probe, then compares the HTTP status with the expected one. It only reads. The
expected statuses are the ones Graph gave in the lab: 403 where nothing is granted, 404 for an
item hidden inside a site where the app holds a folder grant. It also takes a token for
Exchange Online's and SharePoint's own APIs: a role consented there (`full_access_as_app`,
`Sites.Read.All`) never shows in the Graph token, and all Graph probes would still pass. And it
signs in as alice (the seeder app, delegated; a browser opens, `--auth device` for a code) to
confirm her canary folder exists, since a deleted folder answers 404 too. Exit 0 means
everything was as expected; 1 means any probe, token or the canary folder was not; 2 means
the credential or a sign-in failed.

| Probe | Request | Expected | What it proves |
|---|---|---|---|
| token roles, Microsoft Graph | the Graph token's `roles` claim | exactly `Files.SelectedOperations.Selected`, `Sites.Selected` | No Graph permission beyond #1 and #2, in particular no `Mail.Read` |
| token roles, Exchange Online | a token for `https://outlook.office365.com` | no roles | No `full_access_as_app` or other Exchange application role (that would reach every mailbox over EWS) |
| token roles, SharePoint | a token for `https://restoreprooflab.sharepoint.com` | no roles | No SharePoint application role (`Sites.Read.All` there would reach every site over SharePoint REST) |
| canary folder, read as alice | `GET /drives/{alice's drive}/items/{RestoreTest}`, as alice | a folder with files | The folder the last two probes expect 404 on exists, so their 404 means "hidden", not "gone" |
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

The live run's output is the Done-when evidence: `docs/security/l1.5-worker-app-check.txt`.
The script also prints Exchange's own view (`Test-ServicePrincipalAuthorization`): `InScope`
True for restoretest and False for alice.

The tests (`lab/tests/test_worker_app.py`) run the same check against a fake tenant, failure
paths first:

- an unexpected 200 on a forbidden resource;
- a 403 on an allowed one;
- an extra or missing role, and any role in the Exchange Online or SharePoint token;
- `RestoreTarget` renamed or missing from alice's root listing;
- the canary folder missing or empty, although the app still gets 404 on it;
- no response;
- a token failure, including MSAL raising (no network, unknown tenant);
- a missing or wrong credential.

`lab/tests/test_entra_script.py` runs parts of the setup script with stubs: removing a
consent on an API other than Graph, removing client secrets and other certificates, retrying
only replication lag, and treating "already exists" as granted.

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
  write, and the Worker never asks for it. The OneDrive canaries aren't readable at all.
- **The folder grant breaks permission inheritance on `/RestoreTarget`**, as any item-level
  grant does. Files restored into it inherit the grant.
- **The OneDrive grant needs the admin to be a site collection admin of alice's OneDrive.**
  Even a global admin can't manage another user's OneDrive without that. `lab/README.md` says
  how to set it, and how to remove it afterwards.
- **Deleting and re-creating `/RestoreTarget`** gives it a new item ID and drops the grant.
  The Worker then gets 404 on the old ID (SharePoint's mask; a 403 where Graph says so),
  which it reports as `error`, not `fail` (`docs/verification.md`). Run the script again after updating the ID.

## Open items

1. **Write access for cleanup (W3.x).** The Cleaner deletes what a test restored, so it needs
   to write where L1.5 only reads. `Sites.Selected` with `write` must **not** be used: it
   covers the whole RestoreTest site, the canary library included. The proposal, to be
   tested in W3.x before anything is granted:
   - **SharePoint:** `Lists.SelectedOperations.Selected` with `write` on the RestoreTarget
     list only (list ID in `lab/tenant.md`), through
     `POST /sites/{site-id}/lists/{list-id}/permissions`. `Sites.Selected` `read` stays for
     the site.
   - **OneDrive:** the existing `/RestoreTarget` folder grant raised from `read` to `write`.
   - **Mail:** `Application Mail.ReadWrite` in place of `Application Mail.Read`, on the same
     restoretest scope (RBAC; no Entra consent).
   - **Negative checks:** `check-worker-app` would gain write probes that must fail on the
     canary library and folder (a create that returns 403), and a create-and-delete on each
     RestoreTarget.
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
   existing folder grant: no new permission (`docs/api/veeam-restore-flow.md` §16).
