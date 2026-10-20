<#
    A fake of WorkerMachine.psm1 for the installer's tests (W7.1, W7.3, W7.4): the same functions,
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
    if (Get-FakeValue 'serviceQueryFails' $false) { throw 'fake: Invalid class' }
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


# --- W7.3 and W7.4 --------------------------------------------------------------------------

# The version written into the dummy exe's bytes by install_lab.py ("MZ fake worker <version>");
# `versionFails` in machine.json makes it fail.
function Get-WorkerVersion([Parameter(Mandatory)][string]$Exe) {
    Write-FakeLog "Get-WorkerVersion $Exe"
    if (Get-FakeValue 'versionFails' $false) { throw "$Exe --version failed: fake: no version" }
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "$Exe --version failed: not there" }
    $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Exe))
    $m = [regex]::Match($text, 'MZ fake worker (\d+\.\d+\.\d+)')
    if (-not $m.Success) { return '0.1.0' }
    $m.Groups[1].Value
}

# A run in progress for the first `runInProgressPolls` reads (counted down in machine.json),
# then none; `runInProgress` true means for ever. The fake Worker's `service stop` and `start`
# don't touch it: the countdown is the run ending by itself.
function Get-RunRecord([Parameter(Mandatory)][string]$Root) {
    Write-FakeLog "Get-RunRecord $Root"
    $state = Get-FakeState
    if ($state.ContainsKey('runInProgress') -and $state['runInProgress']) { return [pscustomobject]@{ RunId = 'fake-run-1' } }
    # The window of point 3 step 3: a run taken between the wait's read and the stop (the flag
    # record-after-stop makes every read after the fake Worker's `service stop` see one, until
    # its first `service start` after that stop (started-after-stop)).
    if ((Test-Path -LiteralPath (Join-Path $env:RP_FAKE_DIR 'record-after-stop')) -and (Test-Path -LiteralPath (Join-Path $env:RP_FAKE_DIR 'service-stopped-once')) -and -not (Test-Path -LiteralPath (Join-Path $env:RP_FAKE_DIR 'started-after-stop'))) {
        return [pscustomobject]@{ RunId = 'fake-run-2' }
    }
    # `runSequence`: one entry per read, taken from the front (a run id, or null for none), then none.
    if ($state.ContainsKey('runSequence') -and @($state['runSequence']).Count -gt 0) {
        $sequence = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in @($state['runSequence'])) { $sequence.Add($entry) }
        $id = $sequence[0]
        $sequence.RemoveAt(0)
        $state['runSequence'] = @($sequence)
        ($state | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath (Join-Path $env:RP_FAKE_DIR 'machine.json') -Encoding utf8
        if ($null -eq $id) { return $null }
        return [pscustomobject]@{ RunId = [string]$id }
    }
    if ($state.ContainsKey('runInProgressPolls') -and [int]$state['runInProgressPolls'] -gt 0) {
        $state['runInProgressPolls'] = [int]$state['runInProgressPolls'] - 1
        ($state | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath (Join-Path $env:RP_FAKE_DIR 'machine.json') -Encoding utf8
        return [pscustomobject]@{ RunId = 'fake-run-1' }
    }
    $null
}

function Get-PwshPath { 'C:\fake\pwsh\pwsh.exe' }

function Get-FakeEntryPath { Join-Path $env:RP_FAKE_DIR 'uninstall-entry.json' }

function Get-UninstallEntry([Parameter(Mandatory)][string]$Name) {
    Write-FakeLog "Get-UninstallEntry $Name"
    $path = Get-FakeEntryPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable
}

function Set-UninstallEntry([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Values) {
    Write-FakeLog "Set-UninstallEntry $Name"
    ($Values | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Get-FakeEntryPath) -Encoding utf8
}

function Remove-UninstallEntry([Parameter(Mandatory)][string]$Name) {
    Write-FakeLog "Remove-UninstallEntry $Name"
    Remove-Item -LiteralPath (Get-FakeEntryPath) -Force -ErrorAction SilentlyContinue
}

# Recorded, then deleted (the real overwrite is tested on its own, test_machine.py); a path
# named in `unremovable` throws as a held file does.
function Remove-FileOverwritten([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Within, [switch]$KeepFile) {
    Write-FakeLog "Remove-FileOverwritten $Path"
    $held = @(Get-FakeValue 'unremovable' @())
    if ($held -contains (Split-Path -Leaf $Path)) { throw "fake: $Path is held by another process" }
    Add-Content -LiteralPath (Join-Path $env:RP_FAKE_DIR 'overwritten.log') -Value $Path -Encoding utf8
    if (-not $KeepFile) { [IO.File]::Delete($Path) }
}

# Logged, as the real one starts the elevated window; `elevateRefused` throws as a refused UAC does.
function Start-ElevatedUninstall([Parameter(Mandatory)][string]$Script) {
    Write-FakeLog "Start-ElevatedUninstall $Script"
    if (Get-FakeValue 'elevateRefused' $false) { throw 'fake: The operation was canceled by the user.' }
}

Export-ModuleMember -Function Test-IsElevated, Get-MachineFacts, Get-InstalledService, Test-VeeamOnThisMachine, Get-RemoteCertificate, Get-CertificateKeyFile, Get-WorkerVersion, Get-RunRecord, Get-PwshPath, Get-UninstallEntry, Set-UninstallEntry, Remove-UninstallEntry, Remove-FileOverwritten, Start-ElevatedUninstall
