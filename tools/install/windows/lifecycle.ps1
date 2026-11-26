. (Join-Path $PSScriptRoot 'launcher.ps1')

$ExaCopyOwnerFile = 'owner.marker'
$ExaCopyVersions = 'versions'
$ExaCopyOwnerLimit = 16384
$ExaCopyRootFiles = @($ExaCopyOwnerFile, 'release.manifest', 'release.sig', $ExaCopyVersions)
$ExaCopyVersionFiles = @($ExaCopyOwnerFile, 'exacopy.exe')

function Get-ExaCopyContext {
    param(
        [string] $Version, [string] $PublisherCert, [string] $PublisherSha256,
        [string] $Scope, [switch] $ResolveLatest
    )
    if (!$IsWindows) { throw 'These PowerShell entry points require Windows.' }
    if ($Scope -cne 'User') { throw 'Only explicitly non-elevated user scope is supported.' }
    if (!$ResolveLatest -or $Version) {
        Assert-ExaCopyTrustArguments $Version $PublisherCert $PublisherSha256
    }
    else {
        Assert-ExaCopyPublisherArguments $PublisherCert $PublisherSha256
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $owner = $identity.User
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Run the user-scope installer without elevation.'
        }
    }
    finally {
        $identity.Dispose()
    }
    $local = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
    $programs = Join-Path $local 'Programs'
    $root = Join-Path $programs 'ExaCopy'
    $certificatePath = Resolve-ExaCopyWindowsPath $PublisherCert
    if (Test-ExaCopyUnderPath $certificatePath $root) {
        throw 'The publisher trust anchor must lie outside the installation root.'
    }
    return [pscustomobject]@{
        Local = $local
        Programs = $programs
        Root = $root
        Owner = $owner
        Target = Get-ExaCopyTarget
        Version = $Version
        CertificatePath = $certificatePath
        PublisherSha256 = $PublisherSha256
    }
}

function Get-ExaCopyOwnerBytes {
    param($Context, [string] $ManifestHash)

    $unicode = [Text.UnicodeEncoding]::new($false, $false, $true)
    $path = [Convert]::ToBase64String($unicode.GetBytes($Context.Root))
    $text = "schema=exacopy-windows-owner-v1`nowner_sid=$($Context.Owner.Value)`nroot_utf16le=$path`nmanifest_sha256=$ManifestHash`n"
    $bytes = [Text.Encoding]::ASCII.GetBytes($text)
    if ($bytes.Length -gt $ExaCopyOwnerLimit) { throw 'Owner marker exceeds its byte limit.' }
    return ,$bytes
}

function Assert-ExaCopySameBytes {
    param([byte[]] $Expected, [byte[]] $Actual)
    if ($Expected.Length -ne $Actual.Length -or
        (Get-ExaCopySha256 $Expected) -cne (Get-ExaCopySha256 $Actual)) {
        throw 'Installer ownership or retained release evidence changed.'
    }
}

function Read-ExaCopyReleaseFiles {
    param([string] $Directory, $Context, [byte[]] $Certificate, [switch] $Historical)
    $manifest = Read-ExaCopyBoundedBytes (Join-Path $Directory 'release.manifest') $ExaCopyManifestLimit
    $signature = Read-ExaCopyBoundedBytes (Join-Path $Directory 'release.sig') $ExaCopySignatureLimit
    $verification = @{
        Manifest = $manifest
        Signature = $signature
        Certificate = $Certificate
        PublisherSha256 = $Context.PublisherSha256
        Version = $Context.Version
        Target = $Context.Target
        UnixNow = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        Historical = $Historical
    }
    $release = Confirm-ExaCopyRelease @verification
    return [pscustomobject]@{
        Release = $release
        Manifest = $manifest
        Signature = $signature
        ManifestHash = Get-ExaCopySha256 $manifest
    }
}

function Open-ExaCopyInstallation {
    param([string] $Root, $Context, [byte[]] $Certificate)
    Confirm-ExaCopyOwnerAcl $Root $Context.Owner -Root
    $ownerPath = Join-Path $Root $ExaCopyOwnerFile
    [void](Confirm-ExaCopyPath $ownerPath -File)
    $lease = [IO.FileStream]::new($ownerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $bin = Join-Path $Root 'bin'
        $hasLauncher = Confirm-ExaCopyPath $bin -AllowMissing
        $expectedEntries = if ($hasLauncher) { $ExaCopyRootFiles + 'bin' } else { $ExaCopyRootFiles }
        Assert-ExaCopyExactEntries $Root $expectedEntries
        $signed = Read-ExaCopyReleaseFiles $Root $Context $Certificate -Historical
        $expected = Get-ExaCopyOwnerBytes $Context $signed.ManifestHash
        Assert-ExaCopySameBytes $expected (Read-ExaCopyStreamBytes $lease $ExaCopyOwnerLimit)
        $versions = Join-Path $Root $ExaCopyVersions
        Confirm-ExaCopyOwnerAcl $versions $Context.Owner
        $installation = [pscustomobject]@{
            Lease = $lease; Signed = $signed; OwnerBytes = $expected; Versions = $versions
            HasLauncher = $hasLauncher
        }
        if ($hasLauncher) {
            $material = Get-ExaCopyLauncherMaterial $Context $installation $Certificate
            Confirm-ExaCopyLauncherDirectory $bin $material $Context.Owner
        }
        return $installation
    }
    catch {
        $lease.Dispose()
        throw
    }
}

function Get-ExaCopyOwnedVersion {
    param($Context, $Installation, [switch] $AllowIncomplete)

    $versionPath = Join-Path $Installation.Versions $Context.Version
    $present = Confirm-ExaCopyPath $versionPath -AllowMissing
    if (!$present) {
        Assert-ExaCopyExactEntries $Installation.Versions @()
        return $null
    }
    Assert-ExaCopyExactEntries $Installation.Versions @($Context.Version)
    Confirm-ExaCopyOwnerAcl $versionPath $Context.Owner
    $exe = Join-Path $versionPath 'exacopy.exe'
    $exePresent = Confirm-ExaCopyPath $exe -File -AllowMissing
    if ($exePresent) {
        Assert-ExaCopyExactEntries $versionPath $ExaCopyVersionFiles
    }
    elseif ($AllowIncomplete) {
        Assert-ExaCopyExactEntries $versionPath @($ExaCopyOwnerFile)
    }
    else {
        throw 'Version directory is incomplete. Inspect retained installer evidence.'
    }
    $ownerPath = Join-Path $versionPath $ExaCopyOwnerFile
    Assert-ExaCopySameBytes $Installation.OwnerBytes (Read-ExaCopyBoundedBytes $ownerPath $ExaCopyOwnerLimit)
    if ($exePresent) {
        Confirm-ExaCopyArtifact $exe $Installation.Signed.Release
    }
    return [pscustomobject]@{
        Path = $versionPath
        Executable = $exe
        OwnerPath = $ownerPath
        ExecutablePresent = $exePresent
    }
}

function Copy-ExaCopyArtifact {
    param([string] $Source, [string] $Destination, $Release)
    [void](Confirm-ExaCopyPath $Source -File)
    $from = [IO.FileStream]::new($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($from.Length -ne $Release.size) { throw 'Artifact length changed before staging.' }
        $target = [IO.FileStream]::new($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $from.CopyTo($target)
            if ($target.Length -ne $Release.size) { throw 'Staged artifact byte length changed.' }
            $target.Flush($true)
        }
        finally {
            $target.Dispose()
        }
    }
    finally {
        $from.Dispose()
    }
    Confirm-ExaCopyArtifact $Destination $Release
}

function Write-ExaCopyVersionStage {
    param([string] $Stage, [string] $Artifact, $Signed, [byte[]] $OwnerBytes, $Context)
    Confirm-ExaCopyOwnerAcl $Stage $Context.Owner
    Assert-ExaCopyExactEntries $Stage @()
    $ownerPath = Join-Path $Stage $ExaCopyOwnerFile
    Write-ExaCopyNewBytes $ownerPath $OwnerBytes
    Copy-ExaCopyArtifact $Artifact (Join-Path $Stage 'exacopy.exe') $Signed.Release
    Assert-ExaCopyExactEntries $Stage $ExaCopyVersionFiles
    Assert-ExaCopySameBytes $OwnerBytes (Read-ExaCopyBoundedBytes $ownerPath $ExaCopyOwnerLimit)
}

function Install-ExaCopySignedVersion {
    param([string] $OfflineBundle, $Context, [switch] $DryRun)
    $bundle = Resolve-ExaCopyWindowsPath $OfflineBundle
    if ((Test-ExaCopyUnderPath $Context.Root $bundle) -or (Test-ExaCopyUnderPath $bundle $Context.Root) -or
        (Test-ExaCopyUnderPath $Context.CertificatePath $bundle)) {
        throw 'The bundle, independently supplied certificate, and install root must be separate.'
    }
    [void](Confirm-ExaCopyPath $bundle)
    Assert-ExaCopyExactEntries $bundle $ExaCopyReleaseFiles
    $certificate = Read-ExaCopyBoundedBytes $Context.CertificatePath $ExaCopyCertLimit
    $signed = Read-ExaCopyReleaseFiles $bundle $Context $certificate
    Assert-ExaCopyWindowsFloor $signed.Release.min_os
    $artifact = Join-Path $bundle 'exacopy.exe'
    Confirm-ExaCopyArtifact $artifact $signed.Release

    Assert-ExaCopyContextAncestors $Context $Context.Local
    $hasPrograms = Confirm-ExaCopyPath $Context.Programs -AllowMissing
    $hasRoot = $false
    if ($hasPrograms) {
        Assert-ExaCopyContextAncestors $Context $Context.Programs
        $hasRoot = Confirm-ExaCopyPath $Context.Root -AllowMissing
    }
    $executable = Join-Path (Join-Path (Join-Path $Context.Root $ExaCopyVersions) $Context.Version) 'exacopy.exe'
    $result = [ordered]@{
        status = if ($DryRun) { 'would_install' } else { 'installed' }
        version = $Context.Version
        path = $executable
        launcher = Join-Path (Join-Path $Context.Root 'bin') 'exacopy.ps1'
    }

    if ($hasRoot) {
        $installation = Open-ExaCopyInstallation $Context.Root $Context $certificate
        try {
            if ($installation.Signed.ManifestHash -cne $signed.ManifestHash) {
                throw 'An existing installation only permits its same exact trusted release.'
            }
            $existing = Get-ExaCopyOwnedVersion $Context $installation
            if ($null -ne $existing) {
                if ($DryRun) {
                    if ($installation.HasLauncher) { $result.status = 'already_installed' }
                }
                else {
                    Publish-ExaCopyLauncher $Context $installation $certificate
                    if ($installation.HasLauncher) { $result.status = 'already_installed' }
                }
                return $result
            }
            if ($installation.HasLauncher) {
                throw 'A selection exists although the signed version is missing. Inspect installation evidence.'
            }
            if ($DryRun) { return $result }
            Assert-ExaCopyContextAncestors $Context $Context.Programs
            $stage = New-ExaCopyPrivateStage $installation.Versions $Context.Owner
            try {
                Write-ExaCopyVersionStage $stage $artifact $signed $installation.OwnerBytes $Context
                Assert-ExaCopyContextAncestors $Context $Context.Programs
                [void](Confirm-ExaCopyPath $installation.Versions)
                [IO.Directory]::Move($stage, (Join-Path $installation.Versions $Context.Version))
            }
            catch {
                throw "Version publication could not be confirmed. Inspect stage '$stage' and the selected version. $($_.Exception.Message)"
            }
            Publish-ExaCopyLauncher $Context $installation $certificate
            return $result
        }
        finally {
            $installation.Lease.Dispose()
        }
    }

    if ($DryRun) { return $result }
    if (!$hasPrograms) {
        Assert-ExaCopyContextAncestors $Context $Context.Local
        [void][IO.Directory]::CreateDirectory($Context.Programs)
    }
    Assert-ExaCopyContextAncestors $Context $Context.Programs
    $rootStage = New-ExaCopyPrivateStage $Context.Programs $Context.Owner
    try {
        Publish-ExaCopyNewInstallation $rootStage $artifact $signed $Context $certificate
    }
    catch {
        throw "Installation publication could not be confirmed. Inspect stage '$rootStage' and install root '$($Context.Root)'. $($_.Exception.Message)"
    }
    return $result
}

function Publish-ExaCopyNewInstallation {
    param([string] $RootStage, [string] $Artifact, $Signed, $Context, [byte[]] $Certificate)
    $ownerBytes = Get-ExaCopyOwnerBytes $Context $signed.ManifestHash
    Write-ExaCopyNewBytes (Join-Path $rootStage $ExaCopyOwnerFile) $ownerBytes
    Write-ExaCopyNewBytes (Join-Path $rootStage 'release.manifest') $signed.Manifest
    Write-ExaCopyNewBytes (Join-Path $rootStage 'release.sig') $signed.Signature
    $versionPath = Join-Path (Join-Path $rootStage $ExaCopyVersions) $Context.Version
    [void][IO.Directory]::CreateDirectory($versionPath)
    Write-ExaCopyVersionStage $versionPath $artifact $signed $ownerBytes $Context
    $checked = Open-ExaCopyInstallation $rootStage $Context $certificate
    try {
        Assert-ExaCopySameBytes $signed.Manifest $checked.Signed.Manifest
        [void](Get-ExaCopyOwnedVersion $Context $checked)
    }
    finally {
        $checked.Lease.Dispose()
    }
    Assert-ExaCopyContextAncestors $Context $Context.Programs
    [IO.Directory]::Move($rootStage, $Context.Root)
    $published = Open-ExaCopyInstallation $Context.Root $Context $certificate
    try { Publish-ExaCopyLauncher $Context $published $certificate }
    finally { $published.Lease.Dispose() }
}

function Assert-ExaCopyExecutableIdle {
    param([string] $Path)

    foreach ($process in [Diagnostics.Process]::GetProcessesByName('exacopy')) {
        try {
            if ($process.HasExited) { continue }
            $image = $process.MainModule.FileName
            if ([string]::IsNullOrEmpty($image)) { throw 'An active ExaCopy process could not be inspected.' }
            if ($Path.Equals($image, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Close the active ExaCopy process before uninstalling.'
            }
        }
        finally {
            $process.Dispose()
        }
    }
    # On Windows this probes existing incompatible file handles. The removal
    # still honors the native filesystem refusal if a handle appears later.
    $exclusive = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    $exclusive.Dispose()
}

function Uninstall-ExaCopySignedVersion {
    param($Context, [switch] $DryRun, [switch] $Quiesced)

    Assert-ExaCopyContextAncestors $Context $Context.Local
    $result = [ordered]@{ status = 'already_absent'; version = $Context.Version; path = $Context.Root }
    if (!(Confirm-ExaCopyPath $Context.Programs -AllowMissing)) { return $result }
    Assert-ExaCopyContextAncestors $Context $Context.Programs
    if (!(Confirm-ExaCopyPath $Context.Root -AllowMissing)) { return $result }

    $certificate = Read-ExaCopyBoundedBytes $Context.CertificatePath $ExaCopyCertLimit
    $installation = Open-ExaCopyInstallation $Context.Root $Context $certificate
    try {
        Assert-ExaCopyWindowsFloor $installation.Signed.Release.min_os
        $owned = Get-ExaCopyOwnedVersion $Context $installation -AllowIncomplete
        if ($installation.HasLauncher -and ($null -eq $owned -or !$owned.ExecutablePresent)) {
            throw 'A launcher selects a missing executable. Inspect installation evidence.'
        }
        if ($null -eq $owned) { return $result }
        $result.path = $owned.Path
        Assert-ExaCopyNoNamedStreams $owned.Path
        Assert-ExaCopyNoNamedStreams $owned.OwnerPath
        if ($owned.ExecutablePresent) {
            Assert-ExaCopyNoNamedStreams $owned.Executable
            Assert-ExaCopyExecutableIdle $owned.Executable
        }
        if ($DryRun) {
            Remove-ExaCopyLauncher $Context $installation $certificate -DryRun
            $result.status = 'would_uninstall'
            return $result
        }
        if (!$Quiesced) {
            throw 'Close installed ExaCopy processes and prevent new launches, then supply -Quiesced.'
        }
        Assert-ExaCopyContextAncestors $Context $Context.Programs
        Confirm-ExaCopyOwnerAcl $owned.Path $Context.Owner
        Remove-ExaCopyLauncher $Context $installation $certificate
        Assert-ExaCopyContextAncestors $Context $Context.Programs
        if ($owned.ExecutablePresent) {
            [void](Confirm-ExaCopyPath $owned.Executable -File)
            [IO.File]::Delete($owned.Executable)
            if (Get-ExaCopyNodeExists $owned.Executable) { throw 'Executable removal could not be confirmed.' }
        }
        Assert-ExaCopyExactEntries $owned.Path @($ExaCopyOwnerFile)
        Assert-ExaCopySameBytes $installation.OwnerBytes (Read-ExaCopyBoundedBytes $owned.OwnerPath $ExaCopyOwnerLimit)
        [IO.File]::Delete($owned.OwnerPath)
        [IO.Directory]::Delete($owned.Path, $false)
        $result.status = 'uninstalled'
        return $result
    }
    finally {
        $installation.Lease.Dispose()
    }
}
