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

# The service `Name`, as Win32_Service reports it (PathName, State, StartName), or $null when
# there is none. A query that fails throws (never $null: a WMI fault read as "no service" made
# the uninstall destroy a running Worker's data, the W7.3 review's second pass).
function Get-InstalledService([Parameter(Mandatory)][string]$Name) {
    $escaped = $Name -replace "'", "''"
    Get-CimInstance Win32_Service -Filter "Name='$escaped'" -ErrorAction Stop | Select-Object -First 1
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

# What the overwrite needs of Windows that .NET doesn't give: a handle opened with the DELETE
# right beside read and write (so the file deleted is the file checked and written, through the
# same handle), the path that handle reached (GetFinalPathNameByHandleW: every junction and
# symbolic link on the way resolved), how many names the file has (nNumberOfLinks), and the
# delete itself (SetFileInformationByHandle, FileDispositionInfo).
if (-not ('RestoreProof.HandleFacts' -as [type])) {
    Add-Type -Namespace RestoreProof -Name HandleFacts -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct ByHandleInfo {
    public uint Attributes; public uint CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
    public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links;
    public uint IndexHigh; public uint IndexLow;
}
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
static extern uint GetFinalPathNameByHandleW(Microsoft.Win32.SafeHandles.SafeFileHandle handle, System.Text.StringBuilder path, uint length, uint flags);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out ByHandleInfo info);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool SetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, int infoClass, ref byte deleteFile, uint size);
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, System.IntPtr security, uint disposition, uint flags, System.IntPtr template);
static Microsoft.Win32.SafeHandles.SafeFileHandle Open(string path, uint access, uint share, uint flags) {
    var handle = CreateFileW(path, access, share, System.IntPtr.Zero, 3, flags, System.IntPtr.Zero);
    if (handle.IsInvalid) { throw new System.ComponentModel.Win32Exception(); }
    return handle;
}
// Read, write and delete, shared with nobody (a held file is refused here).
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenForOverwrite(string path) {
    return Open(path, 0x80000000u | 0x40000000u | 0x00010000u, 0, 0);
}
public static string FinalPath(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    var text = new System.Text.StringBuilder(32768);
    uint n = GetFinalPathNameByHandleW(handle, text, (uint)text.Capacity, 0);
    if (n == 0 || n >= text.Capacity) { throw new System.ComponentModel.Win32Exception(); }
    return text.ToString();
}
public static uint Links(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    ByHandleInfo info;
    if (!GetFileInformationByHandle(handle, out info)) { throw new System.ComponentModel.Win32Exception(); }
    return info.Links;
}
public static void MarkDeleted(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    byte yes = 1;
    if (!SetFileInformationByHandle(handle, 4, ref yes, 1)) { throw new System.ComponentModel.Win32Exception(); }
}
// A folder's final path: opened for no access (FILE_FLAG_BACKUP_SEMANTICS, sharing everything).
public static string FolderFinalPath(string path) {
    using (var handle = Open(path, 0, 7, 0x02000000)) { return FinalPath(handle); }
}
'@
}

<#
.SYNOPSIS
    The file's bytes overwritten once in place with random ones through one handle, flushed to
    the disk, then the file deleted through that same handle (W7.3 point 6: it defeats an
    undelete tool; it guarantees no erasure on an SSD or inside a volume snapshot). -KeepFile
    leaves the overwritten file for a test to read. Throws when the file can't be opened (held
    by someone, or no right).

    The service account can write under the run folders, and this runs elevated, so nothing is
    written or deleted that isn't the file at `Path` itself (the W7.3 review's second pass,
    CWE-59): the handle's final path must be `Within`'s final path joined with the rest of
    `Path` (no junction or symbolic link on the way, whatever was swapped in after the caller
    looked), and the file must have one name (a hard link to a file elsewhere is never
    written). Either refused throws before a byte is written, and the file is left.
#>
function Remove-FileOverwritten([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Within, [switch]$KeepFile) {
    $full = [IO.Path]::GetFullPath($Path)
    $base = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Within))
    if (-not $full.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw "not under $Within" }
    $expected = [RestoreProof.HandleFacts]::FolderFinalPath($base) + $full.Substring($base.Length)
    $handle = [RestoreProof.HandleFacts]::OpenForOverwrite($full)
    try {
        $reached = [RestoreProof.HandleFacts]::FinalPath($handle)
        if (-not [string]::Equals($reached, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'is reached through a junction or a symbolic link: not overwritten' }
        $links = [RestoreProof.HandleFacts]::Links($handle)
        if ($links -ne 1) { throw "has $links names (a hard link): not overwritten" }
        # The stream owns no handle of its own: the one checked is written, then deleted.
        $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::ReadWrite)
        $length = $stream.Length
        $left = $length
        while ($left -gt 0) {
            $n = [int][Math]::Min(65536, $left)
            $chunk = [Security.Cryptography.RandomNumberGenerator]::GetBytes($n)
            $stream.Write($chunk, 0, $n)
            $left -= $n
        }
        $stream.Flush($true)
        if (-not $KeepFile) { [RestoreProof.HandleFacts]::MarkDeleted($handle) }
    } finally { $handle.Dispose() }
}

<#
.SYNOPSIS
    The uninstall started again in an elevated window (Settings' Uninstall starts it as the user,
    UAC-filtered): the same pwsh, -NoExit so its lines can be read, -ExecutionPolicy Bypass.
    Throws when the elevation is refused.
#>
function Start-ElevatedUninstall([Parameter(Mandatory)][string]$Script) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$Script`"")
    $null = Start-Process -FilePath (Get-PwshPath) -Verb RunAs -ArgumentList $arguments
}

Export-ModuleMember -Function Test-IsElevated, Get-MachineFacts, Get-InstalledService, Test-VeeamOnThisMachine, Get-RemoteCertificate, Get-CertificateKeyFile, Get-WorkerVersion, Get-RunRecord, Get-PwshPath, Get-UninstallEntry, Set-UninstallEntry, Remove-UninstallEntry, Remove-FileOverwritten, Start-ElevatedUninstall
