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
| uv | 0.12.17 | Installed with winget (`astral-sh.uv`) |
| Docker Desktop | 4.73.0 | WSL2 backend; Compose v5.1.3 |
| WSL | 2.7.14.0 | Capped by `%USERPROFILE%\.wslconfig`: `memory=4GB`, `processors=2` |
| Git | 2.53.0.windows.2 | |
| Bruno | 4.1.0 | Installed with winget (`Bruno.Bruno`) |

## Terminal setup

The worker presets use Ninja + `cl`, so build from a VS 2022 Developer PowerShell. The dev shell overwrites `VCPKG_ROOT` with VS's bundled vcpkg; set it back after entering:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -HostArch amd64
$env:VCPKG_ROOT = 'C:\vcpkg'
```

L0.2 check (all succeed in that one terminal): `cmake --version`, `uv --version`, `docker ps`, `git --version`.

## Veeam host

A local Hyper-V VM on this laptop, sized **2 vCPU, 6 GB RAM, dynamically expanding disk**
rather than the plan's 4 vCPU / 8 GB / 100 GB, which a 2-core, 16 GB machine cannot spare
alongside VS and Docker. Do not run the VM and a C++ build at the same time. Built in L1.3;
a spare PC or cloud VM is the fallback if it proves too slow. See `docs/decisions.md`.
