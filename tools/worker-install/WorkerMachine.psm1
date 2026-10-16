<#
    What Install-RestoreProofWorker.ps1 reads of the machine it runs on (W7.1): whether the shell
    is elevated, the installed service, Veeam's REST service, the certificate veeam_url presents,
    a certificate's private key file. Nothing here decides anything (RestoreProofWorker.psm1
    does) and nothing here writes. The script takes this module by path (-MachineModule) so the
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

Export-ModuleMember -Function Test-IsElevated, Get-MachineFacts, Get-InstalledService, Test-VeeamOnThisMachine, Get-RemoteCertificate, Get-CertificateKeyFile
