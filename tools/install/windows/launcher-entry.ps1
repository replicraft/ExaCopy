# Fixed entry body included in the generated, owner-bound PowerShell shim.
$ancestry = $null
try {
    if (!$IsWindows) { throw 'This launcher requires Windows.' }
    $bin = Resolve-ExaCopyWindowsPath $PSScriptRoot
    $root = [IO.Directory]::GetParent($bin).FullName
    $local = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
    $programs = Join-Path $local 'Programs'
    $expectedRoot = Join-Path $programs 'ExaCopy'
    $unicode = [Text.UnicodeEncoding]::new($false, $false, $true)
    $rootLabel = [Convert]::ToBase64String($unicode.GetBytes($root))
    if ($bin -cne (Join-Path $root 'bin') -or $root -cne $expectedRoot -or $rootLabel -cne $ExaCopyLauncherRootLabel) {
        throw 'Launcher is outside its admitted installation root.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $owner = $identity.User
        if ($owner.Value -cne $ExaCopyLauncherSid) { throw 'Launcher belongs to another user.' }
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Run the user-scope launcher without elevation.'
        }
    }
    finally { $identity.Dispose() }
    $ancestry = Open-ExaCopyProductAncestry $local $owner
    Assert-ExaCopyInstallAncestors $programs $owner $ancestry
    Confirm-ExaCopyOwnerAcl $root $owner -Root
    Confirm-ExaCopyOwnerAcl $bin $owner -Root
    Assert-ExaCopyExactEntries $root @('owner.marker', 'release.manifest', 'release.sig', 'versions', 'bin')
    Assert-ExaCopyExactEntries $bin $ExaCopyLauncherNames
    $ownerPath = Join-Path $root 'owner.marker'
    [void](Confirm-ExaCopyPath $ownerPath -File)
    $lease = [IO.FileStream]::new($ownerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $rootOwner = Read-ExaCopyStreamBytes $lease 16384
        if ((Get-ExaCopySha256 $rootOwner) -cne $ExaCopyLauncherRootOwnerHash) {
            throw 'Installation owner marker changed.'
        }
        $selection = Get-ExaCopyLauncherSelection $ExaCopyLauncherVersion $ExaCopyLauncherManifestHash
        Assert-ExaCopyLauncherBytes $selection (Read-ExaCopyBoundedBytes (Join-Path $bin 'selected') $ExaCopyLauncherSelectionLimit)
        $self = Read-ExaCopyBoundedBytes (Join-Path $bin 'exacopy.ps1') $ExaCopyLauncherScriptLimit
        $expectedReceipt = Get-ExaCopyLauncherReceipt $ExaCopyLauncherRootOwnerHash $selection $self
        Assert-ExaCopyLauncherBytes $expectedReceipt (Read-ExaCopyBoundedBytes (Join-Path $bin 'owner.marker') $ExaCopyLauncherReceiptLimit)
        $manifest = Read-ExaCopyBoundedBytes (Join-Path $root 'release.manifest') $ExaCopyManifestLimit
        if ((Get-ExaCopySha256 $manifest) -cne $ExaCopyLauncherManifestHash) {
            throw 'Selected publisher manifest changed.'
        }
        $signature = Read-ExaCopyBoundedBytes (Join-Path $root 'release.sig') $ExaCopySignatureLimit
        $verification = @{
            Manifest = $manifest
            Signature = $signature
            Certificate = [Convert]::FromBase64String($ExaCopyLauncherCertificate)
            PublisherSha256 = $ExaCopyLauncherPublisherPin
            Version = $ExaCopyLauncherVersion
            Target = Get-ExaCopyTarget
            UnixNow = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            Historical = $true
        }
        $release = Confirm-ExaCopyRelease @verification
        Assert-ExaCopyWindowsFloor $release.min_os
        $versions = Join-Path $root 'versions'
        Confirm-ExaCopyOwnerAcl $versions $owner
        Assert-ExaCopyExactEntries $versions @($ExaCopyLauncherVersion)
        $version = Join-Path $versions $ExaCopyLauncherVersion
        Confirm-ExaCopyOwnerAcl $version $owner
        Assert-ExaCopyExactEntries $version @('owner.marker', 'exacopy.exe')
        Assert-ExaCopyLauncherBytes $rootOwner (Read-ExaCopyBoundedBytes (Join-Path $version 'owner.marker') 16384)
        $exe = Join-Path $version 'exacopy.exe'
        [void](Confirm-ExaCopyPath $exe -File)
        $artifact = [IO.FileStream]::new($exe, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            Confirm-ExaCopyArtifact $exe $release
            $PSNativeCommandArgumentPassing = 'Standard'
            $PSNativeCommandUseErrorActionPreference = $false
            Assert-ExaCopyInstallAncestors $programs $owner $ancestry
            & $exe @args
            $code = $LASTEXITCODE
        }
        finally { $artifact.Dispose() }
    }
    finally { $lease.Dispose() }
    exit $code
}
catch {
    [Console]::Error.WriteLine('ExaCopy launcher: ' + $_.Exception.Message)
    exit 1
}
finally {
    if ($null -ne $ancestry) { $ancestry.Dispose() }
}
