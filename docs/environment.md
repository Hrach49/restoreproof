# Development environment

Recorded for L0.2 on 2026-09-22. Update this file whenever a tool is upgraded.

## Laptop

| | |
|---|---|
| OS | Windows 10 Pro 10.0.19045 |
| CPU | Intel Core i7-7600U (2 cores / 4 threads) |
| RAM | 16 GB |
| Disk | 256 GB NVMe SSD |

## Toolchain

| Tool | Version | Notes |
|---|---|---|
| Visual Studio 2022 Community | 17.13.3 | Workload "Desktop development with C++" |
| MSVC | 14.43.34808 | |
| CMake | 3.30.5-msvc23 | Bundled with VS; on PATH only in the Developer PowerShell |
| Ninja | 1.12.1 | Bundled with VS |
| vcpkg | 2026-07-27 (tool) | Full clone at `C:\vcpkg`; `VCPKG_ROOT=C:\vcpkg` (user env). Port versions come from `builtin-baseline` in `worker/vcpkg.json` |
| Python | 3.12.9 | |
| uv | 0.12.17 | Installed with winget (`astral-sh.uv`); lives in `%LOCALAPPDATA%\Microsoft\WinGet\Links`, which is not on PATH in Git Bash or PowerShell here, so call it by full path or add that folder to PATH |
| Docker Desktop | 4.73.0 | WSL2 backend; Compose v5.1.3 |
| WSL | 2.7.14.0 | Capped by `%USERPROFILE%\.wslconfig`: `memory=4GB`, `processors=2` |
| Git | 2.53.0.windows.2 | |
| Bruno | 4.1.0 | Installed with winget (`Bruno.Bruno`) |
| OpenCppCoverage | 0.9.9.0 | Installed with winget (`OpenCppCoverage.OpenCppCoverage`); Worker line coverage (L0.5). CI pins the same release by SHA-256 |

## Terminal setup

The worker presets use Ninja + `cl`, so build from a VS 2022 Developer PowerShell. The dev shell overwrites `VCPKG_ROOT` with VS's bundled vcpkg; set it back after entering:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -HostArch amd64
$env:VCPKG_ROOT = 'C:\vcpkg'
```

L0.2 check (all succeed in that one terminal): `cmake --version`, `uv --version`, `docker ps`, `git --version`.

## Veeam host

Veeam Backup for Microsoft 365 (v8, Community Edition) is installed **directly on this
laptop**, not in a VM (decision of 2026-09-25, superseding the Hyper-V VM of 2026-09-22).
Windows 10 22H2 is a supported backup server OS. The laptop is below Veeam's stated minimum
(8 cores, 16 GB RAM), so expect slow backups; Veeam's services start with Windows and can be
stopped in `services.msc` during heavy C++ builds (scheduled backups then don't run). REST
API on port 4443. A spare PC or cloud VM remains the fallback. Installed in L1.3 on
2026-09-25:

| | |
|---|---|
| Veeam Backup for Microsoft 365 | 13.6.0.237: the "build in logs" number of product version **8.6** (`Config.xml` `ProductVersion="8.6.0.237"`; Veeam [KB4106](https://www.veeam.com/kb4106) lists both numbers; the help center documents 8.6.0.1102). The installer also put VBR 13.1.0.26072 and the Exchange/SharePoint Explorers 13.6.0.237 on the laptop. Licence: Community (10 users, 4 used) |
| REST API | Still **`v8`**: Swagger at `https://localhost:4443/swagger/index.html` reports `version: v8`, `/v8/...` answers, `/v13/...` is 404. Self-signed certificate `CN=Veeam Software` (thumbprint `895C6325…`, SHA-256 `9FB19E0E…A213`, valid to 2036) with **no SAN**: no host name verifies against it (`docs/api/veeam-feasibility.md` §5.1). Access tokens 60 min. Every restart of `Veeam.Archiver.REST.Service` invalidates all REST tokens |
| Services | `Veeam.Archiver.Service`, `Veeam.Archiver.Proxy`, `Veeam.Archiver.REST.Service` (automatic) |
| Organisation | `RestoreProofLab.onmicrosoft.com` (modern app-only authentication) |
| Veeam's Entra app | `RestoreProof Lab Veeam`, app ID `1fd2609d-1242-43fe-94b5-d58688a90bd6`, certificate `CN=RestoreProof Lab Veeam` (thumbprint `AC3220B5…`, LocalMachine\My, private key exportable, expires 2028-09-25). Its backup permissions lacked Microsoft Graph `Group.ReadWrite.All`, which SharePoint restores need; granted on 2026-09-25 (L1.4, `docs/manual-restore-reference.md`). This is Veeam's app, not the Worker's (L1.5) |
| Backup job | `RP-Lab-Full`: all users, all SharePoint sites and OneDrives |
| Restore points | Full `2fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7` at 2026-09-25 19:24:31 UTC (60.7 MB, 1495 items); incremental `71ac3d9c-eb29-42b6-a391-ae81fcc4681c` at 19:37:15 UTC (0 changed items). Job history: `docs/lab/l1.3-job-history.png` |

All 40 canaries are in the latest point (checked with Veeam's PowerShell explore cmdlets):
`RP-CANARY-0001…0010` in alice's mailbox, `0011…0020` in bob's, `rp-canary-01…10` in the
RestoreTest library, `rp-canary-11…20` in alice's OneDrive.

Veeam's PowerShell module is `C:\Program Files\Veeam\Backup365\Veeam.Archiver.PowerShell\`,
with the Explorer modules under `C:\Program Files\Veeam\Backup and Replication\Explorers\`.
It needs **PowerShell 7** (`pwsh`): under Windows PowerShell 5.1 it loads with a deprecation
warning, and opening a restore session fails on a missing `Microsoft.Bcl.TimeProvider`.
Relevant to the PowerShell fallback in the Sprint 1 gate.

### Veeam accounts and settings (L1.6, W1.0; 2026-09-26)

- **`DESKTOP-P55CDUM\rp-veeam`** is the Worker's admin-mode REST account
  (`docs/decisions.md`, 2026-09-26).
  - A standard local user (SID `S-1-5-21-3314352153-334213494-2992209376-1006`), in no local
    group. Password never expires; the user can't change it.
  - Veeam role **Veeam Backup Administrator**, given in the console (Manage Users & Roles →
    Users and Roles). No cmdlet or REST endpoint can set it.
  - Local security policy denies it **interactive and Remote Desktop logon**
    (`SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`). The REST password
    grant still works: Veeam uses a network logon.
  - The 32-character random password is in Windows Credential Manager on this laptop
    ("RestoreProof Lab - rp-veeam (local Veeam REST)"), never in the repo.
- **Restore operator authentication**: enabled, certificate `CN=RestoreProof Lab Veeam
  Operator Auth` (thumbprint `26F8C9B2…E21A`, LocalMachine\My, to 2028-09-26).
- **Restore Portal**: enabled for the Entra app `RestoreProof Lab Restore Portal`
  (`lab/tenant.md`), region Worldwide, portal URI `https://localhost:4443`, certificate
  `CN=RestoreProof Lab Restore Portal` (thumbprint `9E498EC6…42D0`, to 2028-09-26).
- **Restore operator role** `RestoreProof Lab Operators`: `rpoperator`, scoped to alice, bob,
  restoretest and the RestoreTest site. Operator mode is not used by the product; these stay
  until the refresh-token checks end (2026-10-03).
- **REST tracing** (`EnableTracing` on `<Rest>` in `C:\ProgramData\Veeam\Backup365\Config.xml`)
  was switched on for W1.0 and is off again. When on, `Logs\Veeam.Archiver.REST_*.log` gives
  the reason behind a bare 401/500, such as the AADSTS code. Each REST restore also writes
  `Logs\RestoreREST\restore_<date>_<sessionId>_<orgId>.log`, tracing or not.
- **Veeam's user cache.** A new tenant user reaches it with
  `Get-VBOOrganizationUser -Organization $org -DataSource PreferLocalResynced`.
