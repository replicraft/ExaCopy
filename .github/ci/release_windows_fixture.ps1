#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Archive,
    [Parameter(Mandatory)][string] $Index,
    [Parameter(Mandatory)][string] $Certificate,
    [Parameter(Mandatory)][string] $PublisherSha256,
    [Parameter(Mandatory)][string] $Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '../../tools/install/windows'
foreach ($file in @('paths', 'release', 'lifecycle', 'download', 'archive')) {
    . (Join-Path $root "$file.ps1")
}
function Test-ExaCopyPackagedLauncher {
    param([string] $Bundle, [string] $Target, $Signed)

    # Exercise the installer in a private root without changing the runner's
    # canonical user installation or weakening the public non-elevated guard.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $owner = $identity.User }
    finally { $identity.Dispose() }
    $local = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
    $fixture = New-ExaCopyPrivateStage $local $owner
    Write-Output "Disposable Windows launcher fixture: $fixture"
    $programs = Join-Path $fixture 'Programs'
    $installRoot = Join-Path $programs 'ExaCopy'
    $context = [pscustomobject]@{
        Local = $fixture
        Programs = $programs
        Root = $installRoot
        Owner = $owner
        Target = $Target
        Version = $Version
        CertificatePath = (Resolve-ExaCopyWindowsPath $Certificate)
        PublisherSha256 = $PublisherSha256
    }
    $incumbent = Join-Path $fixture 'unrelated.txt'
    [IO.File]::WriteAllText($incumbent, 'preserve a neighboring owner file')

    $installed = Install-ExaCopySignedVersion $Bundle $context
    $bin = Join-Path $installRoot 'bin'
    $expectedExecutable = Join-Path (Join-Path (Join-Path $installRoot 'versions') $Version) 'exacopy.exe'
    $expectedLauncher = Join-Path $bin 'exacopy.ps1'
    if ($installed.status -cne 'installed' -or $installed.path -cne $expectedExecutable -or
        $installed.launcher -cne $expectedLauncher -or ![IO.File]::Exists($expectedLauncher)) {
        throw 'The installer did not publish the exact packaged version and stable launcher.'
    }
    Assert-ExaCopyExactEntries $bin @('exacopy.ps1', 'selected', 'owner.marker')
    $selected = [Text.Encoding]::ASCII.GetString((Read-ExaCopyBoundedBytes (Join-Path $bin 'selected') 256))
    $expectedSelection = "schema=exacopy-windows-selection-v1`nversion=$Version`nmanifest_sha256=$($Signed.ManifestHash)`n"
    if ($selected -cne $expectedSelection) { throw 'The launcher does not select the exact signed package.' }
    Confirm-ExaCopyArtifact $expectedExecutable $Signed.Release
    $versionText = @(& $expectedExecutable --version)
    if ($LASTEXITCODE -ne 0 -or $versionText.Count -eq 0 -or $versionText[0] -cne "exacopy $Version") {
        throw 'The exact selected CLI did not report the expected version.'
    }

    $removed = Uninstall-ExaCopySignedVersion $context -Quiesced
    if ($removed.status -cne 'uninstalled' -or (Get-ExaCopyNodeExists $bin) -or
        (Get-ExaCopyNodeExists (Split-Path -Parent $expectedExecutable)) -or
        [IO.File]::ReadAllText($incumbent) -cne 'preserve a neighboring owner file') {
        throw 'The uninstall did not withdraw exactly the owned launcher and version.'
    }

    # The production uninstall retains the authenticated root. The runner
    # fixture owns this entire disposable case and clears only its known files.
    Assert-ExaCopyExactEntries $fixture @('Programs', 'unrelated.txt')
    Assert-ExaCopyExactEntries $programs @('ExaCopy')
    Assert-ExaCopyExactEntries $installRoot @('owner.marker', 'release.manifest', 'release.sig', 'versions')
    Assert-ExaCopyExactEntries (Join-Path $installRoot 'versions') @()
    foreach ($name in @('owner.marker', 'release.manifest', 'release.sig')) {
        [IO.File]::Delete((Join-Path $installRoot $name))
    }
    [IO.Directory]::Delete((Join-Path $installRoot 'versions'), $false)
    [IO.Directory]::Delete($installRoot, $false)
    [IO.Directory]::Delete($programs, $false)
    [IO.File]::Delete($incumbent)
    [IO.Directory]::Delete($fixture, $false)
}

$target = Get-ExaCopyTarget
Assert-ExaCopyTrustArguments $Version $Certificate $PublisherSha256
$name = "exacopy-cli-$target.zip"
if ([IO.Path]::GetFileName($Archive) -cne $name) { throw 'Unexpected fixture archive name.' }
$checksumBytes = Read-ExaCopyBoundedBytes $Index $ExaCopyReleaseChecksumsLimit
$digest = Get-ExaCopyReleaseAssetDigest $checksumBytes $name
$stage = [IO.Directory]::CreateTempSubdirectory('exacopy-release-fixture-')
$created = [Collections.Generic.List[string]]::new()
try {
    $inputFile = [IO.FileStream]::new($Archive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { Expand-ExaCopyReleaseArchive $inputFile $digest $stage.FullName $created }
    finally { $inputFile.Dispose() }
    Assert-ExaCopyExactEntries $stage.FullName $ExaCopyReleaseFiles
    $certificateBytes = Read-ExaCopyBoundedBytes $Certificate $ExaCopyCertLimit
    $context = @{ PublisherSha256 = $PublisherSha256; Version = $Version; Target = $target }
    $signed = Read-ExaCopyReleaseFiles $stage.FullName $context $certificateBytes
    Assert-ExaCopyWindowsFloor $signed.Release.min_os
    $executable = Join-Path $stage.FullName 'exacopy.exe'
    Confirm-ExaCopyArtifact $executable $signed.Release
    $helpText = & $executable --help
    if ($LASTEXITCODE -ne 0 -or ($helpText -join "`n") -notmatch 'Usage: exacopy') {
        throw 'The verified packaged CLI did not emit the expected help.'
    }
    Test-ExaCopyPackagedLauncher $stage.FullName $target $signed
    Write-Output 'The Windows installer verified the mixed index, installed the exact launcher selection and removed only its owned version.'
}
finally {
    foreach ($entry in $created) { [IO.File]::Delete((Join-Path $stage.FullName $entry)) }
    [IO.Directory]::Delete($stage.FullName, $false)
}
