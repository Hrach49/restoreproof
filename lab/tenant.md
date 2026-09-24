# Test tenant

The Microsoft 365 tenant the lab backs up with Veeam and the Worker restores into (L1.1).
IDs only: passwords and secrets live in the password manager, never here.
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

## Restore targets

Every restore goes to one of these (CLAUDE.md, "Restore targets").

| Target | Value |
|---|---|
| Mail | `restoretest@RestoreProofLab.onmicrosoft.com` |
| SharePoint site URL | `https://restoreprooflab.sharepoint.com/sites/RestoreTest` |
| SharePoint site ID | `restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-b3fe-cd091a09e689` |
| RestoreTest library, list ID | `7eb0f08a-f57b-418c-8ca6-f2ab81297666` |
| RestoreTest library, drive ID | `b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omK8LB-e_WMQYym8quBKXZm` |
| alice's OneDrive, drive ID | `b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3` |
| alice's OneDrive `RestoreTest` folder, item ID | `01ZK75LGF7FPAIWTU5MFGIMX6YUFEV7ZC4` |

The site is a team site without a Microsoft 365 group (template `STS#3`): a group-connected
site would have claimed the mail alias `restoretest@`, which belongs to the mail target user.
The RestoreTest library was added through Graph (`POST /sites/{site-id}/lists`, template
`documentLibrary`); the site's default "Documents" library is not a restore target.

alice's OneDrive IDs were read as alice (`GET /me/drive`, `/me/drive/root:/RestoreTest`): a
global admin gets 403 on another user's OneDrive through delegated Graph unless made a site
collection admin of it. The Worker uses app-only permissions (L1.5), which this does not affect.

The Worker config keys `test_mailbox`, `test_site_id`, `test_library_id`,
`test_onedrive_drive_id` and `test_onedrive_folder_id` (`docs/worker-config.md`) take these
values. Open point: the library has both a list ID and a drive ID, and `test_library_id` does not
yet say which one it holds. Graph reads files by drive ID; what the Veeam restore body needs
is settled by W1.0/W2.4, and the config doc is updated then.
