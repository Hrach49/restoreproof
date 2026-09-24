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
API on port 4443. A spare PC or cloud VM remains the fallback. Installed in L1.3; version
and job details are recorded below once the install is done.
