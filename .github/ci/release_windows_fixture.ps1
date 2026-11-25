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
    Write-Output 'The Windows installer verified the exact packaged CLI using the combined release index.'
}
finally {
    foreach ($entry in $created) { [IO.File]::Delete((Join-Path $stage.FullName $entry)) }
    [IO.Directory]::Delete($stage.FullName, $false)
}
