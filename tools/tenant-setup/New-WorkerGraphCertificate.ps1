<#
.SYNOPSIS
    Makes the Worker's Microsoft Graph certificate and puts it straight into the Worker's vault
    (W7.0, docs/decisions.md 2026-10-16, point 4). Once per Worker, on the Worker's machine.

.DESCRIPTION
    A Worker signs in to every client's tenant with one certificate: the vault holds one
    graph_cert_pfx_base64 and one graph_cert_password. This script makes that certificate:

      - an RSA 2048 key and a self-signed certificate, subject "CN=RestoreProof Worker", SHA-256,
        valid for two years, made in memory with .NET's CertificateRequest (no certificate store);
      - the PFX built with AES-256-CBC and SHA-256 (the ciphers the Worker reads) under a random
        password of 32 bytes;
      - each value given to `rpworker vault set <name>` on stdin, one process each, as
        lab\entra\fill-worker-vault.ps1 does: never on a command line, in an environment
        variable, in a file, in a transcript or on the screen. The byte arrays are cleared after.

    It refuses when the vault already holds graph_cert_pfx_base64 or graph_cert_password, unless
    -Replace: a new certificate strands every client app that holds the old one until
    Initialize-RestoreProofTenant.ps1 is run again in that client's tenant.

    It ends with `rpworker graph certificate`, which opens the new PFX from the vault as the
    Worker does and prints its thumbprint. The public half is what each client's tenant gets:
    `rpworker graph certificate > worker-graph.pem`, or Initialize-RestoreProofTenant.ps1 -Worker.

    Run it in PowerShell 7.4 or later, elevated when the vault is the default one under
    %ProgramData% (its ACL is SYSTEM, Administrators and its owner); -VaultPath names another.

.EXAMPLE
    pwsh -NoProfile -File tools\tenant-setup\New-WorkerGraphCertificate.ps1 -Worker 'C:\Program Files\RestoreProof\rpworker.exe'
#>
#Requires -Version 7.4
[CmdletBinding()]
param(
    # rpworker.exe; default: the dev build beside this repository.
    [string]$Worker = '',
    # Passed to rpworker as --vault <file>; default: the Worker's default vault.
    [string]$VaultPath = '',
    # Replace a certificate the vault already holds.
    [switch]$Replace,
    # The Worker's service, which must be stopped while a certificate is replaced (the tests name another).
    [string]$ServiceName = 'RestoreProof'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Subject = 'CN=RestoreProof Worker'
$KeyBits = 2048
$ValidYears = 2
$Iterations = 100000
$Names = @('graph_cert_pfx_base64', 'graph_cert_password')

# What a native command reads from a pipe: UTF-8, no BOM, whatever the console's code page.
$OutputEncoding = [Text.UTF8Encoding]::new($false)

if (-not $Worker) { $Worker = Join-Path $PSScriptRoot '..\..\worker\build\dev\rpworker.exe' }
if (-not (Test-Path -LiteralPath $Worker -PathType Leaf)) {
    throw "No Worker at $Worker. Pass -Worker with the path of rpworker.exe."
}
$Worker = (Resolve-Path -LiteralPath $Worker).ProviderPath
$vaultArgs = @()
if ($VaultPath) { $vaultArgs = @('--vault', $VaultPath) }

# The names the vault holds now. A vault that isn't there yet holds none (vault set makes it).
$listed = & $Worker vault list @vaultArgs 2>&1
$listCode = $LASTEXITCODE
$lines = @($listed | ForEach-Object { "$_" })
if ($listCode -ne 0 -and -not ($lines | Where-Object { $_ -match ': vault file not found$' })) {
    throw "rpworker vault list failed (exit $listCode): $($lines -join ' '). Nothing was made."
}
$held = @($Names | Where-Object { $listCode -eq 0 -and $lines -ccontains $_ })
if ($held.Count -gt 0 -and -not $Replace) {
    throw ("The vault already holds $($held -join ' and '): this Worker has its Graph certificate. " +
        'Nothing was made. To make a new one, run this again with -Replace; every client app that holds the ' +
        'old certificate then needs Initialize-RestoreProofTenant.ps1 run again in its tenant.')
}
# The two values are written one after the other: a running service could read the new PFX with
# the old password between them.
if ($held.Count -gt 0) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and "$($service.Status)" -ne 'Stopped') {
        throw "The $ServiceName service is $($service.Status): stop it first (rpworker service stop), then run this again. Nothing was made."
    }
}

Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$rsa = [Security.Cryptography.RSA]::Create($KeyBits)
$pfx = $null
$passwordBytes = [byte[]]::new(32)
$password = $null
$pfxBase64 = $null
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject, $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $now = [DateTimeOffset]::UtcNow
    $cert = $request.CreateSelfSigned($now.AddDays(-1), $now.AddYears($ValidYears))
    $thumbprint = $cert.Thumbprint

    [Security.Cryptography.RandomNumberGenerator]::Fill($passwordBytes)
    $password = [Convert]::ToBase64String($passwordBytes)
    $pbe = [Security.Cryptography.PbeParameters]::new(
        [Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc, [Security.Cryptography.HashAlgorithmName]::SHA256, $Iterations)

    # The certificate and the shrouded key, each in a bag encrypted with the password; a MAC over both.
    $certs = [Security.Cryptography.Pkcs.Pkcs12SafeContents]::new()
    $null = $certs.AddCertificate($cert)
    $keys = [Security.Cryptography.Pkcs.Pkcs12SafeContents]::new()
    $null = $keys.AddShroudedKey($rsa, $password, $pbe)
    $builder = [Security.Cryptography.Pkcs.Pkcs12Builder]::new()
    $builder.AddSafeContentsEncrypted($certs, $password, $pbe)
    $builder.AddSafeContentsUnencrypted($keys)
    $builder.SealWithMac($password, [Security.Cryptography.HashAlgorithmName]::SHA256, $Iterations)
    $pfx = $builder.Encode()
    $pfxBase64 = [Convert]::ToBase64String($pfx)
    $cert.Dispose()

    # The PFX first: a password alone opens nothing.
    $pfxBase64 | & $Worker vault set graph_cert_pfx_base64 @vaultArgs
    if ($LASTEXITCODE -ne 0) { throw "rpworker vault set graph_cert_pfx_base64 failed (exit $LASTEXITCODE); nothing was set" }
    $password | & $Worker vault set graph_cert_password @vaultArgs
    if ($LASTEXITCODE -ne 0) {
        # What the vault holds now: the new PFX, and the old certificate's password if it had one.
        $left = if ($held -ccontains 'graph_cert_password') { "with the old certificate's password, which doesn't open it" } else { 'without its password' }
        throw ("rpworker vault set graph_cert_password failed (exit $LASTEXITCODE): the vault now holds the new PFX " +
            "$left, so the Worker can't sign in to Graph. Run this again with -Replace.")
    }
}
finally {
    $rsa.Dispose()
    if ($pfx) { [Array]::Clear($pfx, 0, $pfx.Length) }
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    # .NET strings can't be wiped; drop the references so nothing here holds them.
    $password = $null; $pfxBase64 = $null; $builder = $null; $keys = $null
}

# The Worker opens it from the vault as it does to sign in; its thumbprint line is on stderr.
$check = & $Worker graph certificate @vaultArgs 2>&1
if ($LASTEXITCODE -ne 0) { throw "rpworker graph certificate failed (exit $LASTEXITCODE): $(@($check | ForEach-Object { "$_" }) -join ' ')" }
$line = @($check | Where-Object { "$_" -like 'thumbprint *' } | ForEach-Object { "$_" })
if ($line.Count -ne 1 -or $line[0] -notlike "thumbprint $thumbprint *") {
    throw "rpworker graph certificate does not show the new certificate ($thumbprint)"
}
Write-Host "made the Worker's Graph certificate: $($line[0])"
Write-Host 'Its public half for a client tenant: rpworker graph certificate > worker-graph.pem (or Initialize-RestoreProofTenant.ps1 -Worker).'
