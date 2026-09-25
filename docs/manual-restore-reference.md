# Manual restore reference (L1.4)

One mail, one SharePoint file and one OneDrive file, restored by hand from a Veeam Backup for
Microsoft 365 restore point into the restore targets, then read back through Microsoft Graph and
compared with `lab/seed-manifest.json`. This is the flow the Worker automates through the REST
API (W2.4, W2.5); every step below lists what the API has to do instead.

Done on 2026-09-25 against Veeam Backup for Microsoft 365 13.6.0.237 (`docs/environment.md`),
restore point `71ac3d9c-eb29-42b6-a391-ae81fcc4681c` (2026-09-25 19:37:15 UTC, the latest).

**Deviation from the guide.** The guide asks for the console wizards with a screenshot of every
dialog. The restores were run with Veeam's PowerShell cmdlets instead (the Explorer modules the
console itself uses), because the wizard needs the app certificate as a file and the cmdlets
make each parameter explicit. The console path is summarised at the end; the one dialog captured
is `docs/lab/l1.4-mail-connection-settings.png`.

## Result

| | Restored item | From | To | Veeam result | Graph read-back vs manifest |
|---|---|---|---|---|---|
| Mail | `RP-CANARY-0001` | alice, Inbox | `restoretest`, Inbox | 1 created, 0 failed, 18 s | sender, received time, `internetMessageId` and `text-v1` body hash all match |
| SharePoint | `rp-canary-01.pdf` | RestoreTest library | `RestoreTarget` library, root | no error, no warning, 22 s | SHA-256 matches (925 bytes) |
| OneDrive | `rp-canary-11.pdf` | alice, `/RestoreTest` | alice, `/RestoreTarget` | 1 restored, 0 failed, 22 s | SHA-256 matches (925 bytes) |

The originals were untouched: the RestoreTest library and alice's `/RestoreTest` still hold 10
files each, and `rp-canary-01.pdf` and `rp-canary-11.pdf` keep their manifest
`lastModifiedDateTime`.

## Common setup

- **PowerShell 7** (`pwsh`), run as administrator. Modules:
  `C:\Program Files\Veeam\Backup365\Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1`,
  and under `C:\Program Files\Veeam\Backup and Replication\Explorers\` the Exchange and
  SharePoint modules. The OneDrive cmdlets (`*-VEOD*`) come with the **SharePoint** module.
- **Restore point**: `Get-VBORestorePoint | Sort-Object BackupTime | Select-Object -Last 1`.
  Veeam reports `BackupTime` in UTC here; the console shows local time (21:37).
- **Authentication**: Veeam's own Entra app (`1fd2609d-…`) with its certificate. Every restore
  cmdlet takes `-ApplicationId`, `-ApplicationCertificatePath` and
  `-ApplicationCertificatePassword`: a **`.pfx` file**, not a thumbprint. The certificate was
  exported from `Cert:\LocalMachine\My` to a temporary `.pfx` with a random one-time password
  and deleted after the restores. No user signs in.
- **Never** `-Overwrite`, never "original location".

**API equivalent.** The Worker logs in to the Veeam REST API (`/v8/token`, W1.0 decides admin
or operator mode) and passes restore credentials in the restore request body. Whether that body
takes the app ID and certificate, a user, or nothing (Veeam using the organisation's saved app)
is one of W1.0's lab checks.

## 1. Mail

```powershell
$s     = Start-VBOExchangeItemRestoreSession -RestorePoint $rp
$mb    = Get-VEXDatabase -Session $s | ForEach-Object { Get-VEXMailbox -Database $_ } |
         Where-Object Email -eq 'alice@RestoreProofLab.onmicrosoft.com'
$inbox = Get-VEXFolder -Mailbox $mb | Where-Object Name -eq 'Inbox'
$item  = Get-VEXItem -Folder $inbox | Where-Object Subject -eq 'RP-CANARY-0001'
Restore-VEXItem -Item $item -TargetMailbox 'restoretest@RestoreProofLab.onmicrosoft.com' `
    -OrganizationName 'RestoreProofLab.onmicrosoft.com' -Region Worldwide `
    -ApplicationId $appId -ApplicationCertificatePath $pfx -ApplicationCertificatePassword $pw `
    -RestoreChangedItem -RestoreDeletedItem -Force
Stop-VBOExchangeItemRestoreSession -Session $s
```

- Without `-TargetMailbox` the cmdlet restores to the **original mailbox**.
- It refuses to run without at least one of `-RestoreChangedItem` / `-RestoreDeletedItem` (the
  wizard's "changed items" / "missing items" boxes), and without `-Region` (the wizard's
  "Default"; `Worldwide` here).
- No `-ToFolder`: Veeam put the mail in `restoretest`'s **Inbox**, the same folder name as the
  source, unread.
- **What appeared in the target**: one message in `restoretest`'s Inbox, sender
  `HrachyaHarutyunyan@…`, `receivedDateTime` `2026-09-24T22:14:43Z` (the original's, not the
  restore time), the original `internetMessageId`, body `text-v1` hash equal to the manifest.

**For the Worker.** A restored mail keeps its original received time and `internetMessageId`,
so the checker (W3.2) can match on `internetMessageId`, and the received-time tolerance was
not needed here. Because the restored copy looks like the original, `restoretest` must be empty
before a run (W3.4 cleans at the start), or an old copy would pass for a new restore.

## 2. SharePoint

```powershell
$s   = Start-VBOSharePointItemRestoreSession -RestorePoint $rp
$site = Get-VESPSite -Organization (Get-VESPOrganization -Session $s) | Where-Object Name -eq 'RestoreTest'
$lib = Get-VESPDocumentLibrary -Site $site | Where-Object Name -eq 'RestoreTest'
$doc = Get-VESPDocument -DocumentLibrary $lib | Where-Object Name -eq 'rp-canary-01.pdf'
Restore-VESPItem -Document $doc -SiteURL 'https://restoreprooflab.sharepoint.com/sites/RestoreTest' `
    -TargetList 'RestoreTarget' `
    -ApplicationId $appId -ApplicationCertificatePath $pfx -ApplicationCertificatePassword $pw `
    -RestoreChangedItems -RestoreDeletedItems
Stop-VBOSharePointItemRestoreSession -Session $s
```

- `-TargetList` is the target library's **display name**. Without it the cmdlet restores to the
  original list; without `-SiteURL`, to the original site.
- `-OrganizationName` is only for restoring into a *different* Microsoft 365 organisation.
  Passed with the same site, it fails: "Parameter can only be used for restoring to another
  location".
- **First attempt failed**: "The specified Microsoft Entra ID application is missing the
  required application permissions (Microsoft API: Microsoft Graph, permissions:
  Group.ReadWrite.All)". Veeam's app had its backup permissions only. `Group.ReadWrite.All`
  (application) was granted to it through Graph (app role assignment plus the app
  registration's `requiredResourceAccess`), after which the restore worked at once.
- **What appeared in the target**: `rp-canary-01.pdf` in the root of `RestoreTarget`, 925
  bytes, SHA-256 equal to the manifest, `createdDateTime` `2026-09-24T22:14:43Z` (the
  original's).

**For the Worker.** An MSP's Veeam app may also lack restore permissions; the Worker must map
this Veeam error to `error` (infrastructure), not `fail`, and `rpworker doctor` (W7.2) should
test a restore permission, not only listing. Restored files keep their original timestamps
too, so the same "target empty before the run" rule applies. Whether `office-v1` holds for a
restored docx/xlsx is still open for W1.0 (this was a pdf).

## 3. OneDrive

```powershell
$s   = Start-VEODRestoreSession -RestorePoint $rp
$u   = Get-VEODUser -Session $s | Where-Object Name -eq 'Alice Test'
$doc = Get-VEODDocument -User $u -Recurse | Where-Object Name -eq 'rp-canary-11.pdf'
Restore-VEODDocument -Document $doc -TargetUser 'Alice Test' -TargetFolder 'RestoreTarget' `
    -ApplicationId $appId -ApplicationCertificatePath $pfx -ApplicationCertificatePassword $pw `
    -RestoreChangedItems -RestoreDeletedItems
Stop-VEODRestoreSession -Session $s
```

- `-TargetUser` takes the **display name** (`Alice Test`). The UPN, in any case, fails with
  "User not found: alice@…", also after the permission fix.
- `-TargetFolder` is a folder name in the target user's OneDrive root. Veeam put the file
  directly into `/RestoreTarget`, without recreating the source path (`RestoreTest/…`).
- **What appeared in the target**: `rp-canary-11.pdf` in alice's `/RestoreTarget`, 925 bytes,
  SHA-256 equal to the manifest, `createdDateTime` `2026-09-24T22:11:23Z` (the original's).

**For the Worker.** Display names are not unique, so the REST body should identify the target
user by ID if the API allows it (W2.4); `TargetGuard` (W2.7) checks the target drive and folder
IDs whatever the request uses.

## The console path

Veeam console → Organizations → right-click the organisation → Explore → Exchange / SharePoint /
OneDrive → pick the restore point → select the item → Restore → *another location*. The
"Microsoft 365 connection settings" page (`docs/lab/l1.4-mail-connection-settings.png`) offers
*Modern authentication (certificate-based)* with the organisation's app ID filled in and asks
for the application certificate, as the cmdlets do.

## Cleanup

The three restored items are deleted from `restoretest`'s Inbox, the `RestoreTarget` library and
alice's `/RestoreTarget` after this document is written (step 5 of L1.4), leaving all three
targets empty.
