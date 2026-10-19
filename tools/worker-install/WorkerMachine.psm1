<#
    What Install-RestoreProofWorker.ps1 reads of the machine it runs on (W7.1): whether the shell
    is elevated, the installed service, Veeam's REST service, the certificate veeam_url presents,
    a certificate's private key file; since W7.3 and W7.4 an exe's version, the run record, the
    Apps & features entry and the overwrite-then-delete of a file. Nothing here decides anything
    (RestoreProofWorker.psm1 does); what writes (the entry, the overwrite) is called by the scripts
    once a rule said to. The script takes this module by path (-MachineModule) so the
    tests give it tests/FakeMachine.psm1 instead; every function here has a fake of the same
    name and shape there. It imports nothing: Get-KeyFileCandidates comes from the rules module
    the script imported, found through the global scope (an Import-Module -Force from inside a
    module would unload the script's).
#>
Set-StrictMode -Version Latest

function Test-IsElevated {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-MachineFacts {
    [pscustomobject]@{
        PSVersion   = $PSVersionTable.PSVersion
        Is64Bit     = [Environment]::Is64BitOperatingSystem
        IsWindows   = $IsWindows
        MachineName = [Environment]::MachineName
    }
}

# The service `Name`, as Win32_Service reports it (PathName, State, StartName), or $null.
function Get-InstalledService([Parameter(Mandatory)][string]$Name) {
    $escaped = $Name -replace "'", "''"
    Get-CimInstance Win32_Service -Filter "Name='$escaped'" -ErrorAction SilentlyContinue | Select-Object -First 1
}

# Whether Veeam Backup for Microsoft 365's REST service is on this machine.
function Test-VeeamOnThisMachine {
    $null -ne (Get-Service 'Veeam.Archiver.REST.Service' -ErrorAction SilentlyContinue)
}

<#
.SYNOPSIS
    The certificate `Url`'s server presents, read in one TLS handshake that accepts whatever
    comes (nothing is sent after it), with what the installer's rule needs: whether that very
    certificate is in LocalMachine\My with its private key, whether it chains to the Windows
    store, and whether it names the URL's host. Throws when the host can't be reached.
#>
function Get-RemoteCertificate([Parameter(Mandatory)][string]$Url) {
    $uri = [Uri]$Url
    $port = if ($uri.IsDefaultPort) { 443 } else { $uri.Port }
    $leaf = $null
    $chainOk = $false
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.Connect($uri.Host, $port)
        $callback = [Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $certificate, $chain, $errors)
            $script:ProbeLeaf = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
            $script:ProbeChainOk = (($errors -band [Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -eq 0)
            $script:ProbeNameOk = (($errors -band [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -eq 0)
            $true
        }
        $ssl = [Net.Security.SslStream]::new($client.GetStream(), $false, $callback)
        try { $ssl.AuthenticateAsClient($uri.Host) } finally { $ssl.Dispose() }
        $leaf = $script:ProbeLeaf
        $chainOk = $script:ProbeChainOk
        $nameOk = $script:ProbeNameOk
    } finally { $client.Dispose() }
    if ($null -eq $leaf) { throw "no certificate from $Url" }
    $own = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $leaf.Thumbprint -and $_.HasPrivateKey })
    [pscustomobject]@{
        Subject             = $leaf.Subject
        Thumbprint          = $leaf.Thumbprint
        Sha256              = $leaf.GetCertHashString('SHA256')
        NotAfter            = $leaf.NotAfter.ToUniversalTime()
        Der                 = $leaf.RawData
        InLocalStoreWithKey = ($own.Count -eq 1)
        ChainsToStore       = $chainOk
        NamesHost           = $nameOk
    }
}

<#
.SYNOPSIS
    The private key file of the certificate with `Thumbprint` in LocalMachine\My, as
    Veeam's organisation app certificate has one (W4.12): $null when the certificate isn't
    there, has no private key, or its key file is under neither folder.
#>
function Get-CertificateKeyFile([Parameter(Mandatory)][string]$Thumbprint) {
    $certificates = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $Thumbprint -and $_.HasPrivateKey })
    if ($certificates.Count -ne 1) { return $null }
    $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificates[0])
    if ($null -eq $key) { return $null }
    $name = if ($key -is [Security.Cryptography.RSACng]) { $key.Key.UniqueName } else { $key.CspKeyContainerInfo.UniqueKeyContainerName }
    if (-not $name) { return $null }
    foreach ($candidate in (Get-KeyFileCandidates -UniqueName $name)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    $null
}


# --- W7.3 and W7.4 (decision 2026-10-19): the upgrade and the uninstall ------------------

<#
.SYNOPSIS
    What `Exe --version` prints, held to a version's shape; throws with the exe's first line
    when it isn't one or the exe can't be run.
#>
function Get-WorkerVersion([Parameter(Mandatory)][string]$Exe) {
    $lines = @(& $Exe --version 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -ne '' })
    $first = if ($lines.Count) { $lines[0].Trim() } else { '(no output)' }
    if ($LASTEXITCODE -ne 0 -or $first -notmatch '^\d+\.\d+\.\d+$') { throw "$Exe --version failed: $first" }
    $first
}

<#
.SYNOPSIS
    The run the service has taken, from state\running.json under `Root` (W4.8: written ahead of
    every step of a run, deleted after the run and its hold): $null when no record is there,
    else its run_id ('?' when the file can't be read as the record). Nothing else of it is read.
#>
function Get-RunRecord([Parameter(Mandatory)][string]$Root) {
    $path = Join-Path $Root 'state\running.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $id = if ($record.PSObject.Properties['run_id']) { [string]$record.run_id } else { '' }
        if ($id -notmatch '^[A-Za-z0-9._-]{1,128}$') { $id = '?' }
    } catch { $id = '?' }
    [pscustomobject]@{ RunId = $id }
}

# The pwsh running this, for the Apps entry's UninstallString.
function Get-PwshPath { (Get-Process -Id $PID).Path }

$script:UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

<#
.SYNOPSIS
    The Apps & features entry's values as a hashtable (name to value), or $null when there is
    none.
#>
function Get-UninstallEntry([Parameter(Mandatory)][string]$Name) {
    $key = Join-Path $script:UninstallKey $Name
    if (-not (Test-Path -LiteralPath $key)) { return $null }
    $item = Get-ItemProperty -LiteralPath $key
    $values = @{}
    foreach ($property in $item.PSObject.Properties) {
        if ($property.Name -in 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') { continue }
        $values[$property.Name] = $property.Value
    }
    $values
}

function Set-UninstallEntry([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Values) {
    $key = Join-Path $script:UninstallKey $Name
    if (-not (Test-Path -LiteralPath $key)) { $null = New-Item -Path $key -Force }
    foreach ($entry in $Values.GetEnumerator()) {
        $type = if ($entry.Value -is [int]) { 'DWord' } else { 'String' }
        $null = New-ItemProperty -LiteralPath $key -Name $entry.Key -Value $entry.Value -PropertyType $type -Force
    }
}

function Remove-UninstallEntry([Parameter(Mandatory)][string]$Name) {
    $key = Join-Path $script:UninstallKey $Name
    if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key -Recurse -Force }
}

<#
.SYNOPSIS
    The file's bytes overwritten once in place with random ones through one handle, flushed to
    the disk, then the file deleted (W7.3 point 6: it defeats an undelete tool; it guarantees no
    erasure on an SSD or inside a volume snapshot). -KeepFile leaves the overwritten file for a
    test to read. Throws when the file can't be opened (held by someone, or no right).
#>
function Remove-FileOverwritten([Parameter(Mandatory)][string]$Path, [switch]$KeepFile) {
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $length = $stream.Length
        $left = $length
        while ($left -gt 0) {
            $n = [int][Math]::Min(65536, $left)
            $chunk = [Security.Cryptography.RandomNumberGenerator]::GetBytes($n)
            $stream.Write($chunk, 0, $n)
            $left -= $n
        }
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    if (-not $KeepFile) { [IO.File]::Delete($Path) }
}

Export-ModuleMember -Function Test-IsElevated, Get-MachineFacts, Get-InstalledService, Test-VeeamOnThisMachine, Get-RemoteCertificate, Get-CertificateKeyFile, Get-WorkerVersion, Get-RunRecord, Get-PwshPath, Get-UninstallEntry, Set-UninstallEntry, Remove-UninstallEntry, Remove-FileOverwritten
