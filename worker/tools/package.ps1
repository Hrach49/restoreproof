<#
.SYNOPSIS
    Builds the Worker's release package, RestoreProof-Worker-<version>.zip (W7.1,
    docs/decisions.md 2026-10-16 point 2).

.DESCRIPTION
    From worker/: configures and builds the `ci` preset (Release; the `dev` build is Debug with
    debug DLLs beside the exe), then zips rpworker.exe, every DLL from its build folder,
    tools/worker-install/Install-RestoreProofWorker.ps1, RestoreProofWorker.psm1 and
    WorkerMachine.psm1, a copy of tools/tenant-setup/New-WorkerGraphCertificate.ps1 (taken here;
    no second copy in git), config.example.json and docs/install-guide.md when it exists, as
    RestoreProof-Worker-<version>.zip under -Out, <version> from `rpworker --version`. A
    code-signing step goes before the zip when the owner has the certificate: signtool on the
    exe and the DLLs, Set-AuthenticodeSignature on the scripts.

    Run it from a VS 2022 Developer PowerShell (cmake, ninja and cl on PATH; VCPKG_ROOT set back
    to the real clone). -NoBuild zips what build\ci already holds.

.EXAMPLE
    pwsh -File tools\package.ps1
.EXAMPLE
    pwsh -File tools\package.ps1 -Out C:\packages -NoBuild
#>
#Requires -Version 7.4
[CmdletBinding()]
param(
    [string]$Out = '',
    [switch]$NoBuild
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$worker = Split-Path -Parent $PSScriptRoot
$repo = Split-Path -Parent $worker
$build = Join-Path $worker 'build\ci'
if (-not $Out) { $Out = Join-Path $worker 'build\package' }

if (-not $NoBuild) {
    Push-Location $worker
    try {
        & cmake --preset ci
        if ($LASTEXITCODE -ne 0) { throw "cmake --preset ci failed ($LASTEXITCODE)" }
        & cmake --build --preset ci --target rpworker
        if ($LASTEXITCODE -ne 0) { throw "cmake --build --preset ci failed ($LASTEXITCODE)" }
    } finally { Pop-Location }
}

$exe = Join-Path $build 'rpworker.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "no ${exe}: build the ci preset first" }
$version = (& $exe --version | Select-Object -First 1).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "rpworker --version printed '$version'" }

$staging = Join-Path ([IO.Path]::GetTempPath()) ("rp-package-" + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $staging
try {
    $files = @(
        $exe
        Get-ChildItem -LiteralPath $build -File -Filter '*.dll' | ForEach-Object FullName
        (Join-Path $repo 'tools\worker-install\Install-RestoreProofWorker.ps1')
        (Join-Path $repo 'tools\worker-install\RestoreProofWorker.psm1')
        (Join-Path $repo 'tools\worker-install\WorkerMachine.psm1')
        (Join-Path $repo 'tools\tenant-setup\New-WorkerGraphCertificate.ps1')
        (Join-Path $worker 'config.example.json')
    )
    $guide = Join-Path $repo 'docs\install-guide.md'
    if (Test-Path -LiteralPath $guide -PathType Leaf) { $files += $guide }
    foreach ($file in $files) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "missing: $file" }
        Copy-Item -LiteralPath $file -Destination $staging
    }
    $null = New-Item -ItemType Directory -Path $Out -Force
    $zip = Join-Path $Out "RestoreProof-Worker-$version.zip"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip -CompressionLevel Optimal
    $listing = Get-ChildItem -LiteralPath $staging -File | Sort-Object Name | ForEach-Object { "  $($_.Name)  $($_.Length) bytes  sha256 $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower())" }
    "package: $zip"
    "version: $version"
    "files:"
    $listing
    "sha256: $((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower())"
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}
