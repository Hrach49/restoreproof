# Test tenant

The Microsoft 365 tenant the lab backs up with Veeam and the Worker restores into (L1.1).
IDs only: passwords and secrets live in Windows Credential Manager (generic credentials
named "RestoreProof Lab - …"), never here.
Tenant choice and licences: `docs/decisions.md`, 2026-09-23.

## Tenant

| | |
|---|---|
| Tenant name | `RestoreProofLab.onmicrosoft.com` |
| Tenant ID | `bcd6bd1a-ea42-489d-aa28-2c19a44ad146` |
| SharePoint host | `restoreprooflab.sharepoint.com` |

## Users

All licensed (Microsoft 365 Business Standard trial), usage location PL.

| Role | User principal name |
|---|---|
| Global admin (the guide's "admin") | `HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com` |
| Test user, mail and OneDrive source | `alice@RestoreProofLab.onmicrosoft.com` |
| Test user, mail source | `bob@RestoreProofLab.onmicrosoft.com` |
| Mail restore target | `restoretest@RestoreProofLab.onmicrosoft.com` |
| Veeam restore operator (L1.6), **no licence** | `rpoperator@RestoreProofLab.onmicrosoft.com` |

`rpoperator` (object ID `5108276f-c9d8-4603-b742-e35c6fc3f4f7`, usage location PL) was created
on 2026-09-26 through Graph for W1.0's operator-mode checks. Operator mode was not adopted
(`docs/decisions.md`, 2026-09-26), so nothing in the product uses it. `restoretest`'s display
name contains a line break ("Restore⏎Test"); Veeam shows it that way too.

The Worker's own Veeam account, `rp-veeam`, is a local Windows account on the Veeam server,
not a tenant user: see `docs/environment.md`.

## Restore targets

Every restore goes to one of these (CLAUDE.md, "Restore targets"). The canary files are
**not** in them: `rp-canary-01…10` are in the `RestoreTest` library and `11…20` in alice's
`/RestoreTest` folder (see "Canary sources" below), so a restore never lands on top of a canary
and the Cleaner never deletes one (`docs/decisions.md`, 2026-09-25).

| Target | Value |
|---|---|
| Mail | `restoretest@RestoreProofLab.onmicrosoft.com` |
| SharePoint site URL | `https://restoreprooflab.sharepoint.com/sites/RestoreTest` |
| SharePoint site ID | `restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-b3fe-cd091a09e689` |
| RestoreTarget library, URL | `https://restoreprooflab.sharepoint.com/sites/RestoreTest/RestoreTarget` |
| RestoreTarget library, list ID | `ffec069d-65e4-4c3a-9da2-ac086cf9dafa` |
| RestoreTarget library, drive ID | `b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6` |
| alice's OneDrive, drive ID | `b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3` |
| alice's OneDrive `RestoreTarget` folder, item ID | `01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH` |
| alice's OneDrive as a site: host, path | `restoreprooflab-my.sharepoint.com`, `/personal/alice_restoreprooflab_onmicrosoft_com` (not a target; the Worker app sees only its metadata, and in it only the `RestoreTarget` folder) |

Both `RestoreTarget`s were created on 2026-09-25 (L1.4): the library by hand in the site (New >
Document library; the seeder app lacks `Sites.Manage.All`), the folder through Graph as alice.

## Canary sources

Where L1.2 seeded the canary files. Never a restore target; `lab/seed-manifest.json` has the
same IDs per item.

| Source | Value |
|---|---|
| RestoreTest library, list ID | `7eb0f08a-f57b-418c-8ca6-f2ab81297666` |
| RestoreTest library, drive ID | `b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omK8LB-e_WMQYym8quBKXZm` |
| alice's OneDrive `RestoreTest` folder, item ID | `01ZK75LGF7FPAIWTU5MFGIMX6YUFEV7ZC4` |

The site is a team site without a Microsoft 365 group (template `STS#3`): a group-connected
site would have claimed the mail alias `restoretest@`, which belongs to the mail target user.
The RestoreTest library was added through Graph (`POST /sites/{site-id}/lists`, template
`documentLibrary`); the site's default "Documents" library is not a restore target.

alice's OneDrive IDs were read as alice (`GET /me/drive`, `/me/drive/root:/RestoreTest`): a
global admin gets 403 on another user's OneDrive through delegated Graph unless made a site
collection admin of it. The Worker uses app-only permissions (L1.5), which this does not affect.

The Worker config keys `test_mailbox`, `test_site_id`, `test_library_id`,
`test_onedrive_drive_id` and `test_onedrive_folder_id` (`docs/worker-config.md`) take the
"Restore targets" values. `test_library_id` holds the RestoreTarget library's **drive ID**
(`b!…`), not its list ID, since Graph reads files by drive (W2.2, `docs/decisions.md`
2026-09-28). W1.0 found that the Veeam restore body takes none of these IDs
(`docs/api/veeam-feasibility.md` §5.5):

- the mail body names the mailbox address and a folder name;
- the SharePoint body names the site URL and the library's display name `RestoreTarget`;
- the OneDrive body names the user's OneDrive (an object from the Veeam session) and the
  folder name `RestoreTarget`.

W2.4 settled the mapping (`docs/decisions.md` 2026-09-28, W2.4): the Worker resolves the
names at run time through Graph with its read-only app (the site's `webUrl`, the library's
drive `name`, the OneDrive's `webUrl`, the folder's `name`; the mailbox is `test_mailbox`, the
folder `Inbox`) and finds Veeam's OneDrive object by that URL. W2.5 and W2.7 implement it (the
OneDrive drive read and its `webUrl` form are checked in W2.5; `docs/api/veeam-restore-flow.md`
§16). No new config keys. `docs/worker-config.md` says the restore credential has no variable
yet: it stays open until a spike before W4.5.

Both `RestoreTarget`s were made on 2026-09-25, so every later restore point holds them: the
first is 2026-09-27T11:23:13Z, and W2.4 saw them in the 2026-09-27T22:00:48Z point (W1.4 saw
the two earlier points without them). Anything left in a target at backup time is in
the next point, so the sampler (W2.6) never takes items from a target.

## RestoreProof Worker app (L1.5)

The Worker's own app registration: it reads back what Veeam restored, app-only. It can read
the three restore targets, the rest of the RestoreTest site (canary library included) and the
metadata of alice's OneDrive site and root folder, nothing else. What is granted, why, and how
it is checked:
`docs/security/graph-permissions.md`. Made on 2026-09-27 with `lab/entra/new-worker-app.ps1`
(steps in `lab/README.md`), which is safe to re-run. `lab/tests/test_catalog.py` checks the
client ID matches `WORKER_CLIENT_ID` in `lab/seeder/tenant.py`.

| | |
|---|---|
| RestoreProof Worker, application (client) ID | `737da5ef-baf2-4198-b009-e160d8ca77c9` |
| Service principal object ID | `f5a56ba3-1b8f-4d4c-8a0a-b2b579b7bd5f` |
| Sign-in audience | Single tenant (`AzureADMyOrg`) |
| Credential | Certificate (no client secret): self-signed RSA 2048, `CN=RestoreProof Worker (lab)`, SHA-1 thumbprint `B56D2BD39945BAB1484A53F6C78C059A369EDBB3`, created 2026-09-27, expires 2027-09-27. Private key only in `%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`; its password only in Credential Manager (`RestoreProof Lab - Worker Graph app PFX`) |
| Graph application permissions (admin consent) | `Sites.Selected`, `Files.SelectedOperations.Selected`; nothing else |
| SharePoint grants | `read` on the RestoreTest site; `read` on alice's OneDrive `RestoreTarget` folder |
| Exchange Online | Role assignment `RestoreProof Worker - Application Mail.Read - restoretest` (role `Application Mail.Read`), management scope `RestoreProof Worker - restoretest mailbox` (`PrimarySmtpAddress -eq 'restoretest@RestoreProofLab.onmicrosoft.com'`) |
| Live check | `python -m seeder check-worker-app`: 16/16 on 2026-09-27, `docs/security/l1.5-worker-app-check.txt` |

Setting it up changed the tenant in two other ways:

- `Enable-OrganizationCustomization` was run on 2026-09-27. Exchange needs it before a
  management scope can exist. It is tenant-wide and can't be undone.
- The global admin is a site collection admin of alice's OneDrive (admin center, "Create link
  to files"), which the folder grant needed. `lab/README.md` says how to remove it.

## Veeam Restore Portal app and operator role (W1.0 / L1.6)

Made on 2026-09-26 to test operator mode. Not used by the product (admin mode is the default,
`docs/decisions.md` 2026-09-26). They are kept, because the operator refresh-token checks run
until 2026-10-03. Delete the app and `rpoperator` after that, unless operator mode comes back.

| | |
|---|---|
| RestoreProof Lab Restore Portal, application (client) ID | `65558485-d895-4274-8d89-f18c954530ab` |
| Application object ID | `6862b27c-29d7-4d53-b1ed-9e4ec5b34ccf` |
| Service principal object ID | `f1ec13c2-fa48-4282-ba50-435ca55eb54d` |
| Sign-in audience | Multi-tenant (`AzureADMultipleOrgs`): Veeam's on-behalf-of call uses the `/common` authority and fails with AADSTS50194 on a single-tenant app |
| Exposed API | `api://65558485-d895-4274-8d89-f18c954530ab`, delegated scope `access_as_user` (v2 tokens) |
| Permissions | Delegated: Microsoft Graph `User.Read`, own `access_as_user`; tenant-wide admin consent |
| Redirect URIs | SPA `https://localhost:4443/` (the portal), public client `http://localhost` (MSAL sign-in; the device-code flow is blocked by security defaults) |
| Credential | Certificate `CN=RestoreProof Lab Restore Portal`, thumbprint `9E498EC6…` (in `docs/environment.md`) |
| Veeam restore operator role | `RestoreProof Lab Operators` (ID `45106dff-0f96-4095-b30c-bf4417b852bd`): operator `rpoperator`; objects alice, bob, restoretest and the RestoreTest site |

## Seeder app

The app registration the canary seeder (L1.2) signs in through. It is a public client with
delegated Microsoft Graph permissions only, and has no client secret or certificate. Setup
steps: `lab/README.md`. Record the ID in backticks, like the IDs above:
`lab/tests/test_catalog.py` checks that it matches `SEEDER_CLIENT_ID` in
`lab/seeder/tenant.py`.

| | |
|---|---|
| RestoreProof Lab Seeder, application (client) ID | `153b6fd7-36c1-41bf-9e90-238326ba2364` |

Created on 2026-09-25 with the Microsoft Graph PowerShell script in `lab/README.md`: single tenant,
redirect URI `http://localhost`, public client flows allowed, and tenant-wide admin consent for
the five delegated scopes.
