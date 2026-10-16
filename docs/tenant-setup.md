# Preparing a client's tenant (W7.0)

One script prepares a client's Microsoft 365 tenant for RestoreProof:
`tools/tenant-setup/Initialize-RestoreProofTenant.ps1`. It finds or makes the three restore
targets, sets up the "RestoreProof Worker" app with exactly the grants the Worker needs, checks
them, and prints the client's profile for `manage.py create-connector`. Run it again at any time:
it changes only what differs, and on a tenant that is already set up it prints `changes: 0`.

The grants and why each is needed: `docs/security/graph-permissions.md`. The decision behind the
script: `docs/decisions.md`, 2026-10-16, "W7.0 (#189)".

## Before you start

- **The tenant is in Veeam.** The MSP has added the client's organisation to Veeam Backup for
  Microsoft 365 (Veeam's own app) and a backup job backs it up. The script does nothing in Veeam.
- **The Worker has its Graph certificate.** Once per Worker, on the Worker's machine, from an
  elevated PowerShell 7:

  ```
  pwsh -NoProfile -File tools\tenant-setup\New-WorkerGraphCertificate.ps1 -Worker <path to rpworker.exe>
  ```

  It makes the certificate in memory and puts it straight into the Worker's vault; it is never
  shown or written to a file. A Worker uses the same certificate for all its clients. To give a
  client's tenant its public half (safe to send by email):

  ```
  rpworker graph certificate > worker-graph.pem
  ```

  To replace it (`-Replace`), stop the RestoreProof service first: the script refuses while it
  runs. Every client's app then needs the script below run again in its tenant.
- **The person who runs the script** signs in as a **Global Administrator** of the client's
  tenant (twice: once for Microsoft Graph, once for Exchange Online), with an account **of the
  client's tenant**: a partner's (GDAP) or guest account reaches its own organisation's Exchange,
  and the script stops before reading anything when either sign-in is to another tenant.
- **PowerShell 7.4 or later**, and two modules, installed once:

  ```
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
  ```

  (ExchangeOnlineManagement 3.7.2 or later. On a Veeam server, Veeam's own older copy is not enough.)
- **A SharePoint site for the RestoreTarget library.** Make one for RestoreProof alone (for
  example `https://<tenant>.sharepoint.com/sites/RestoreProof`, a team site without a Microsoft 365
  group): the Worker app gets read on the whole site, so anything else in it is readable too. The
  script refuses the tenant's root site and any OneDrive.
- **A user for the /RestoreTarget folder**, licensed with OneDrive and signed in to OneDrive once.
  An account kept for RestoreProof is best: the Worker app sees the names of this user's
  OneDrive site and root folder (not their content).

## Step 1: make the admin a site collection admin of that user's OneDrive

Even a Global Administrator can't make a folder in another user's OneDrive without this.

1. Open the Microsoft 365 admin center, **Users** > **Active users**.
2. Click the user's name.
3. On the **OneDrive** tab, under **Get access to files**, click **Create link to files**.

That makes you a site collection admin of the user's OneDrive. To remove it later: open the link,
**Settings** (gear) > **Site permissions** > **Advanced permissions settings** > **Site
Collection Administrators**, and remove yourself.

## Step 2: run the script

```
pwsh -NoProfile -File tools\tenant-setup\Initialize-RestoreProofTenant.ps1 `
    -TenantId <the client's tenant ID> `
    -SiteUrl https://<tenant>.sharepoint.com/sites/RestoreProof `
    -OneDriveUser <the user>@<domain> `
    -WorkerCertificateFile .\worker-graph.pem `
    -ProfileFile .\<client>-profile.json
```

On the Worker's machine, `-Worker <path to rpworker.exe>` reads the certificate from the vault
instead of `-WorkerCertificateFile` (from an elevated shell, since the vault is under
%ProgramData%). If the Worker can't give it, the script prints the Worker's own reason (for
example a vault it can't read from an unelevated shell); only a vault with no Graph certificate
yet needs `New-WorkerGraphCertificate.ps1`.

Optional: `-MailboxAddress` (default `restoretest@<the tenant's *.onmicrosoft.com domain>`; it
must be `restoretest@...`), `-VeeamOrgName` (default that same domain, the name Veeam gives the
organisation), `-WhatIf` (read everything, print the plan, change nothing), `-CheckOnly` (the
check alone).

**`Enable-OrganizationCustomization`.** A new tenant's Exchange can't hold the management scope
the mail role needs until this one-time step, which applies to the whole tenant and can't be
undone. The script runs it only with `-AllowOrganizationCustomization`; without the switch it
stops before changing anything and says so.

## What it prints

One line per step. `ok: ...` when nothing differed, `change: ...` for each change it made,
`note: ...` for something to know (another library the Worker app can read, another
application's grant), then:

- `grants: ok`, or `problem: ...` lines and `grants: <n> problem(s)` (exit 1). The check reads
  everything again: the app is single tenant with only the Worker's certificate and no secret,
  holds exactly the three permissions and no delegated grant or directory role; read on the site,
  write on the RestoreTarget list and the /RestoreTarget folder, nothing of its own on the site's
  other lists or on the user's OneDrive root or site; exactly the one Exchange role assignment,
  and Exchange's own answer that the app reaches `restoretest` and not your mailbox or the user's.
- `profile:` and the profile, written to `-ProfileFile` too.
- `changes: <n>`.

Exchange can take 30 minutes to 2 hours to apply the mail role everywhere. A read the check can't
make (an Exchange answer that failed, a permission list it couldn't read) is a `problem:` line,
never a pass. The user given as `-OneDriveUser` may be `restoretest` itself (a licensed user, as
in the lab); the check then notes it and does not test it as a mailbox the app must not reach.

**An app made again.** If the client deleted the app registration or its enterprise app, the
next run makes them again and moves the mail role to the new one: it removes the old role
assignment of RestoreProof's name and, when Exchange still points at the deleted service
principal, that pointer, then makes both again.

A new app takes a few seconds to reach all of Microsoft's servers: a read or grant that names it
and answers 400 or 404 is tried again, up to six times, ten seconds apart (`note: ... not ready
yet`).

A step that finds something it must not change stops with one line and changes nothing more: a
`restoretest` address that is a group or another mailbox's alias or that names more than one
recipient, a list called RestoreTarget that
is no document library, a file called RestoreTarget in the user's OneDrive, two apps called
"RestoreProof Worker", a OneDrive you can't open (step 1).

## Step 3: give the profile to the Cloud

The profile holds IDs only, no secret. Next is `docs/onboarding.md` step 4:

```
manage.py create-connector --msp-id <msp_id> --client-id <client_id> --worker-id <worker_id> --profile-file <client>-profile.json
```

## What the script never does

- It changes nothing but the app registration "RestoreProof Worker" and its service principal,
  the three SharePoint grants, the Exchange scope and role assignment named for RestoreProof (and
  the app's Exchange service principal pointer), and the three restore targets.
- It never grants Sites.Selected write, owner or full control, any `*.All` permission, Mail.Read,
  Mail.ReadWrite or full_access_as_app as an Entra consent, and never adds a client secret. Any of
  these found on the app is removed.
- It never deletes a target or anything in one (the Worker's Cleaner empties the targets).
- It never sees the Worker's private key, and prints, logs or writes no secret.
- It seeds no canary. Canaries stay an opt-in per plan (`manage.py create-plan --canaries`); a
  client tenant has none unless they are seeded separately.
- It changes nothing in Veeam, in licences, in sharing settings or in who is site collection admin.

## Undoing it

Delete the app registration "RestoreProof Worker" (Entra admin center, App registrations), the
RestoreTarget library and the /RestoreTarget folder once empty, and in Exchange Online PowerShell
`Remove-ManagementRoleAssignment 'RestoreProof Worker - Application Mail.ReadWrite - restoretest'`,
`Remove-ManagementScope 'RestoreProof Worker - restoretest mailbox'` and the shared mailbox
`restoretest` if the script made it. `Enable-OrganizationCustomization` can't be undone.
