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

Until the vault (W4.5), the Worker will take the same two values from environment variables,
`RP_GRAPH_CERT_PFX_BASE64` and `RP_GRAPH_CERT_PASSWORD`, which replace
`RP_GRAPH_CLIENT_SECRET` (`docs/worker-config.md`). The code change is W2.1's.

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
item hidden inside a site where the app holds a folder grant. Exit 0
means everything was as expected; 1 means any probe or the token's roles were not; 2 means
the credential or sign-in failed.

| Probe | Request | Expected | What it proves |
|---|---|---|---|
| token roles | the access token's `roles` claim | exactly `Files.SelectedOperations.Selected`, `Sites.Selected` | No Entra permission beyond #1 and #2, in particular no `Mail.Read` |
| restoretest's mailbox | `GET /users/restoretest@…/messages` | 200 | #3 reaches the test mailbox |
| RestoreTest site | `GET /sites/{RestoreTest site ID}` | 200 | #1 reaches the site |
| RestoreTarget library: the drive | `GET /drives/{RestoreTarget drive ID}` | 200 | #1 covers the SharePoint restore target |
| RestoreTarget library: files in its root | `GET /drives/{RestoreTarget drive ID}/root/children` | 200 | #1 lets it read the restored files |
| alice's OneDrive: RestoreTarget folder | `GET /drives/{alice's drive}/items/{RestoreTarget}` | 200 | #2 reaches the OneDrive restore target |
| alice's OneDrive: files in RestoreTarget | `GET …/items/{RestoreTarget}/children` | 200 | #2 lets it read the restored files |
| alice's OneDrive: the site (metadata) | `GET /sites/restoreprooflab-my.sharepoint.com:/personal/alice_…` | 200 | Seen in the lab: a grant on a folder opens the metadata of the site and drive around it (name, URL), not their content. The next two rows prove that |
| alice's OneDrive: root folder (metadata) | `GET /drives/{alice's drive}/root` | 200 | As above: the root folder item, not its content |
| alice's OneDrive: files in her root | `GET /drives/{alice's drive}/root/children` | 200, **listing only `RestoreTarget`** | SharePoint masks every item the app may not see: her other files and the canary folder aren't even listed. Any other item listed (or a next page) fails the probe |
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
- an extra or missing role;
- no response;
- a token failure;
- a missing or wrong credential.

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
  The Worker then gets 403, which it must report as `error`, not `fail`
  (`docs/verification.md`). Run the script again after updating the ID.

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
3. **Customer tenants.** Onboarding an MSP's client repeats these steps per tenant: the
   `restoretest` scope, the site grant, the OneDrive folder grant and the site collection
   admin requirement. How the product guides or automates that is for the onboarding tasks.
4. **Certificate expiry.** The lab certificate expires one year after it was made (date in
   `lab/tenant.md`). To renew it, delete the PFX and run the script again: it makes a new
   certificate and replaces the old one on the app. Stage 1 has no renewal alert yet.
