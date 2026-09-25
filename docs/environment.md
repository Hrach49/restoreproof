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
| Veeam Backup for Microsoft 365 | 13.6.0.237 (Veeam now numbers it like Backup & Replication; the installer also put VBR 13.1.0.26072 and the Exchange/SharePoint Explorers 13.6.0.237 on the laptop) |
| REST API | Still **`v8`**: Swagger at `https://localhost:4443/swagger/index.html` reports `version: v8`, `/v8/...` answers, `/v13/...` is 404. Self-signed certificate |
| Services | `Veeam.Archiver.Service`, `Veeam.Archiver.Proxy`, `Veeam.Archiver.REST.Service` (automatic) |
| Organisation | `RestoreProofLab.onmicrosoft.com` (modern app-only authentication) |
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
