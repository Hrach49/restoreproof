# Veeam REST call collection (W1.4)

PowerShell 7 scripts that make, step by step, the calls described in
[`../veeam-notes.md`](../veeam-notes.md), against the lab's Veeam Backup for Microsoft 365
REST API (v8). They replace the Bruno collection the guide asked for (`docs/decisions.md`,
2026-09-26). The responses they record are in [`../veeam-lab/`](../veeam-lab/README.md)
(`w1.4-*.json`).

| Script | Notes section | What it does |
|---|---|---|
| `VeeamLab.ps1` | — | Shared helper, dot-sourced by every script: pinned TLS, login/logout, scrubbing, `Save-Evidence`, explore/stop helpers |
| `01-auth.ps1` | §1 | Health, no/bad token, password grant (form and JSON), refresh, refresh reuse, logout |
| `02-organizations.ps1` | §2 | Organisations, users, sites, paging, `dataSource` |
| `03-restore-points.ps1` | §3 | Restore points: filters, order, paging, the ID format |
| `04-sessions.ps1` | §4 | Explore sessions: open, read, list, stop; what `dateTime` selects |
| `05-mail.ps1` | §5.1, §5.4 | Mailboxes → folders → items; the four mail searches |
| `06-sharepoint.ps1` | §5.2, §5.4 | Sites → libraries → documents; SharePoint searches |
| `07-onedrive.ps1` | §5.3, §5.4 | OneDrives → folders → documents; OneDrive searches |
| `08-sweep-sessions.ps1` | §4.4 | Lists sessions and stops rp-veeam's `Working` ones (`-WhatIf` only lists) |
| `09-token-expiry.ps1` | §1.5 | `-Start` grants a token; `-Probe` asks whether it is still accepted; `-Check` (after 60 min) records what the expired token and its refresh token answer |
| `audit-evidence.ps1` | — | Checks evidence files for secrets before a commit |

Everything here is **read-only** on the Microsoft 365 side. The scripts sign in, list, search,
and open and stop explore sessions; none restores anything. Every explore session a script
opens is stopped in its `finally` block, and `08-sweep-sessions.ps1` catches anything left
over.

## Before you run them

- **PowerShell 7** (`pwsh`). Windows PowerShell 5.1 can't compile the pinned TLS handler.
- **On the Veeam server itself.** The scripts call `https://localhost:4443` unless
  `RP_VEEAM_URL` says otherwise.
- **rp-veeam's password in Windows Credential Manager**, as a *generic* credential named
  `RestoreProof Lab - rp-veeam (local Veeam REST)`. It is already there on the dev laptop
  (`docs/environment.md`). To check it:
  1. Press **Start**, type `Credential Manager`, press **Enter**.
  2. Click **Windows Credentials**.
  3. Under **Generic Credentials**, look for **RestoreProof Lab - rp-veeam (local Veeam REST)**.
     Don't open or change it; the scripts only read it.
- **No secret ever goes into a script or a file in the repo.** The password is read at run
  time and, like every token, stays in the process's memory.

Optional environment variables (defaults in brackets):

| Variable | Meaning |
|---|---|
| `RP_VEEAM_URL` | REST base URL [`https://localhost:4443`] |
| `RP_VEEAM_PIN_SHA256` | SHA-256 of the Veeam REST server certificate [the lab's, `9FB19E0E…A213`] |
| `RP_VEEAM_USER` | the account that signs in [`DESKTOP-P55CDUM\rp-veeam`] |
| `RP_LAB_SECRET_DIR` | a folder where each secret the scripts see is also kept as a DPAPI file, for `audit-evidence.ps1` [unset: memory only] |

## TLS

Veeam's default REST certificate is `CN=Veeam Software` with no subject alternative name, so no
host name ever verifies against it (`docs/api/veeam-feasibility.md` §5.1). The helper doesn't
switch verification off. Instead it accepts exactly one certificate, the one whose SHA-256 is
pinned, and rejects every other. (It doesn't check the chain, the validity dates or the host
name: for a self-signed, SAN-less certificate the pin is the whole check. This is the
"pinned-leaf" option feasibility §5.1 leaves open for W1.5.) To read the pin of another server, take it from the server's
own certificate store, not from the network. On the Veeam server, in PowerShell 7 as
administrator:

1. Open the Veeam console, **☰ menu → General Options → REST API**, and note the certificate's
   thumbprint (SHA-1), or read it with `Get-VBORestAPISettings`.
2. Run, with the first characters of that thumbprint:
   ```powershell
   Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -like '895C6325*' |
       ForEach-Object { $_.Subject; $_.GetCertHashString('SHA256') }
   ```
   On the lab this prints `CN=Veeam Software, O=Veeam Software, OU=Veeam Software` and
   `9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213`.

## Running

From a PowerShell 7 prompt in the repo root:

```powershell
pwsh -File docs\api\veeam-m365\01-auth.ps1            # prints one line per call; saves nothing
pwsh -File docs\api\veeam-m365\05-mail.ps1
pwsh -File docs\api\veeam-m365\08-sweep-sessions.ps1 -WhatIf
```

Output is safe to paste: status codes, IDs, names and Veeam's error messages, never a token or
the password.

To **re-record evidence**, add `-SaveEvidence`. That (over)writes `docs\api\veeam-lab\w1.4-*.json`.
Keep the secrets in a throw-away folder so the audit can check the files against them, then
delete that folder:

```powershell
$env:RP_LAB_SECRET_DIR = "$env:TEMP\rp-lab-secrets"
foreach ($s in '01-auth','02-organizations','03-restore-points','04-sessions','05-mail','06-sharepoint','07-onedrive') {
    pwsh -File "docs\api\veeam-m365\$s.ps1" -SaveEvidence
}
pwsh -File docs\api\veeam-m365\08-sweep-sessions.ps1 -SaveEvidence   # also proves nothing is left Working
pwsh -File docs\api\veeam-m365\audit-evidence.ps1                   # must print "0 hit(s)"
Remove-Item -Recurse -Force $env:RP_LAB_SECRET_DIR; Remove-Item Env:RP_LAB_SECRET_DIR
```

The expiry check takes an hour:

```powershell
pwsh -File docs\api\veeam-m365\09-token-expiry.ps1 -Start -StateDir "$env:TEMP\rp-expiry"
# … after the printed expiry time (plus a few minutes) …
pwsh -File docs\api\veeam-m365\09-token-expiry.ps1 -Check -StateDir "$env:TEMP\rp-expiry" -SaveEvidence
```

`-Check` deletes the token files from `-StateDir` when it is done.

## Rules the scripts follow

- **Never restart Veeam's services** to "fix" a 401: a restart kills every token on the server,
  including other people's.
- **Stop what you open.** `New-ExploreSession` remembers each session ID the moment the 201
  arrives, and `Stop-OpenedSessions` in the `finally` stops them. Stop is idempotent (204
  twice).
- **Scrub before writing.** `Save-Evidence` replaces every known secret value, token-shaped
  JSON/form values, bearer values and JWTs. It refuses to write a file in which a known secret
  survived, and it drops `Set-Cookie` and `Authorization` headers.
- **Audit before committing** (`audit-evidence.ps1`), as W1.0 did.
