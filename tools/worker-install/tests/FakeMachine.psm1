<#
    A fake of WorkerMachine.psm1 for the installer's tests (W7.1): the same six functions,
    answering from the JSON state RP_FAKE_DIR\machine.json (tests/install_lab.py builds it) and
    logging each call to RP_FAKE_DIR\machine.log. Nothing here touches the real machine. It
    imports nothing: the rules module the script imported is found through the global scope (an
    Import-Module -Force from inside a module would unload the script's).
#>
Set-StrictMode -Version Latest

function Get-FakeState {
    $path = Join-Path $env:RP_FAKE_DIR 'machine.json'
    if (-not (Test-Path -LiteralPath $path)) { return @{} }
    Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable
}

function Write-FakeLog([string]$Line) {
    Add-Content -LiteralPath (Join-Path $env:RP_FAKE_DIR 'machine.log') -Value $Line -Encoding utf8
}

function Get-FakeValue([string]$Name, $Default) {
    $state = Get-FakeState
    if ($state.ContainsKey($Name)) { return $state[$Name] }
    $Default
}

function Test-IsElevated { Write-FakeLog 'Test-IsElevated'; [bool](Get-FakeValue 'elevated' $true) }

function Get-MachineFacts {
    Write-FakeLog 'Get-MachineFacts'
    [pscustomobject]@{
        PSVersion   = [version](Get-FakeValue 'psVersion' '7.4.0')
        Is64Bit     = [bool](Get-FakeValue 'is64Bit' $true)
        IsWindows   = [bool](Get-FakeValue 'isWindows' $true)
        MachineName = [string](Get-FakeValue 'machineName' 'FAKE-HOST')
    }
}

function Get-InstalledService([Parameter(Mandatory)][string]$Name) {
    Write-FakeLog "Get-InstalledService $Name"
    $service = Get-FakeValue 'installedService' $null
    if ($null -eq $service) { return $null }
    [pscustomobject]@{ Name = $Name; PathName = $service['pathName']; State = $service['state'] }
}

function Test-VeeamOnThisMachine { Write-FakeLog 'Test-VeeamOnThisMachine'; [bool](Get-FakeValue 'veeamHere' $true) }

function Get-RemoteCertificate([Parameter(Mandatory)][string]$Url) {
    Write-FakeLog "Get-RemoteCertificate $Url"
    $remote = Get-FakeValue 'remote' $null
    if ($null -eq $remote) { throw "fake: no TLS server at $Url" }
    $der = [Convert]::FromBase64String($remote['derBase64'])
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    [pscustomobject]@{
        Subject             = $certificate.Subject
        Thumbprint          = $certificate.Thumbprint
        Sha256              = $certificate.GetCertHashString('SHA256')
        NotAfter            = $certificate.NotAfter.ToUniversalTime()
        Der                 = $der
        InLocalStoreWithKey = [bool]$remote['inLocalStoreWithKey']
        ChainsToStore       = [bool]$remote['chainsToStore']
        NamesHost           = [bool]$remote['namesHost']
    }
}

function Get-CertificateKeyFile([Parameter(Mandatory)][string]$Thumbprint) {
    Write-FakeLog "Get-CertificateKeyFile $Thumbprint"
    $files = Get-FakeValue 'keyFiles' @{}
    if ($files.ContainsKey($Thumbprint)) { return [string]$files[$Thumbprint] }
    $null
}

Export-ModuleMember -Function Test-IsElevated, Get-MachineFacts, Get-InstalledService, Test-VeeamOnThisMachine, Get-RemoteCertificate, Get-CertificateKeyFile
