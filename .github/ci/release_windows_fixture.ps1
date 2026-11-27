#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Archive,
    [Parameter(Mandatory)][string] $Index,
    [Parameter(Mandatory)][string] $Certificate,
    [Parameter(Mandatory)][string] $PublisherSha256,
    [Parameter(Mandatory)][string] $Version,
    [string] $NativeSignatureReport,
    [string] $SourceRoot,
    [string] $FixtureParent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([bool] $SourceRoot -ne [bool] $FixtureParent -or ($SourceRoot -and $NativeSignatureReport)) {
    throw 'A disposable testing source and parent must be paired and cannot select native signing.'
}
$root = if ($SourceRoot) { Join-Path $SourceRoot 'tools/install/windows' }
        else { Join-Path $PSScriptRoot '../../tools/install/windows' }
foreach ($file in @('paths', 'release', 'lifecycle', 'download', 'archive')) {
    . (Join-Path $root "$file.ps1")
}

function Get-FixtureRefusal {
    param([scriptblock] $Attempt)
    try { [void](& $Attempt) }
    catch { return $_.Exception.Message }
    throw 'Expected the installer fixture to refuse.'
}

function Invoke-FixtureWithdrawalFault {
    param($Context)

    $exactEntries = ${function:Assert-ExaCopyExactEntries}
    $programs = $Context.Programs
    # Local function scope restores the shipped helper on return, including on error.
    function Assert-ExaCopyExactEntries {
        param([string] $Directory, [string[]] $Names)
        & $exactEntries $Directory $Names
        if ([IO.Path]::GetDirectoryName($Directory) -ceq $programs -and
            [IO.Path]::GetFileName($Directory) -cmatch '\A[.]ExaCopy-version-retired-[0-9a-f]{32}\z' -and
            ($null -eq $Names -or $Names.Count -eq 0)) {
            throw 'Fixture stopped after removing the retired version marker.'
        }
    }

    Uninstall-ExaCopySignedVersion $Context -Quiesced
}

function Test-ExaCopyWithdrawalRetry {
    param([string] $Bundle, $Context, $Signed, [string] $Executable)

    $versionPath = [IO.Path]::GetDirectoryName($Executable)
    $versions = [IO.Path]::GetDirectoryName($versionPath)
    $bin = Join-Path $Context.Root 'bin'
    $lookalikeName = '.ExaCopy-version-retired-' + ('0' * 32)
    $lookalike = Join-Path $Context.Programs $lookalikeName
    [void][IO.Directory]::CreateDirectory($lookalike)
    $sentinel = Join-Path $lookalike 'unrelated.txt'
    [IO.File]::WriteAllText($sentinel, 'preserve a retirement-looking directory')
    if ((Install-ExaCopySignedVersion $Bundle $Context).status -cne 'installed') {
        throw 'Could not reinstall the exact package for the withdrawal control.'
    }

    $failure = Get-FixtureRefusal { Invoke-FixtureWithdrawalFault $Context }
    $retired = @([IO.Directory]::EnumerateDirectories($Context.Programs, '.ExaCopy-version-retired-*') |
        Where-Object { $_ -cne $lookalike })
    if ($retired.Count -ne 1) { throw "Expected one retired version directory. $failure" }
    $prefix = "Version withdrawal to '$($retired[0])' completed but cleanup could not be confirmed."
    if (!$failure.StartsWith($prefix, [StringComparison]::Ordinal) -or
        !$failure.EndsWith('Fixture stopped after removing the retired version marker.', [StringComparison]::Ordinal) -or
        (Get-ExaCopyNodeExists $bin)) {
        throw "The withdrawal fault did not retain exact retirement evidence. $failure"
    }
    Assert-ExaCopyExactEntries $versions @()
    Assert-ExaCopyExactEntries $retired[0] @()
    if ((Uninstall-ExaCopySignedVersion $Context -Quiesced).status -cne 'already_absent') {
        throw 'Uninstall retry did not recognize that the live version was withdrawn.'
    }

    # An old interrupted uninstall can leave an empty live path with no ownership proof.
    [void][IO.Directory]::CreateDirectory($versionPath)
    $installRefusal = Get-FixtureRefusal { Install-ExaCopySignedVersion $Bundle $Context }
    $removeRefusal = Get-FixtureRefusal { Uninstall-ExaCopySignedVersion $Context -Quiesced }
    if ($installRefusal -cnotlike 'Version directory is incomplete.*' -or
        $removeRefusal -cne 'Directory lacks one or more required entries.' -or (Get-ExaCopyNodeExists $bin)) {
        throw 'An unmarked live version was not refused at the ownership boundary.'
    }
    Assert-ExaCopyExactEntries $versionPath @()
    [IO.Directory]::Delete($versionPath, $false)

    if ((Install-ExaCopySignedVersion $Bundle $Context).status -cne 'installed') {
        throw 'Retirement evidence blocked reinstall of the exact package.'
    }
    Confirm-ExaCopyArtifact $Executable $Signed.Release
    if ((Uninstall-ExaCopySignedVersion $Context -Quiesced).status -cne 'uninstalled' -or
        (Get-ExaCopyNodeExists $bin) -or
        [IO.File]::ReadAllText($sentinel) -cne 'preserve a retirement-looking directory') {
        throw 'Normal cleanup did not preserve the unrelated sibling.'
    }
    Assert-ExaCopyExactEntries $versions @()
    Assert-ExaCopyExactEntries $Context.Programs @('ExaCopy', $lookalikeName, [IO.Path]::GetFileName($retired[0]))
    Assert-ExaCopyExactEntries $retired[0] @()
    Assert-ExaCopyExactEntries $lookalike @('unrelated.txt')
    [IO.Directory]::Delete($retired[0], $false)
    [IO.File]::Delete($sentinel)
    [IO.Directory]::Delete($lookalike, $false)
    Write-Output 'Windows verified withdrawal retry, legacy unmarked version refusal, and unrelated sibling preservation.'
}

function Test-ExaCopyPackagedLauncher {
    param([string] $Bundle, [string] $Target, $Signed)

    # Exercise the installer in a private root without changing the runner's
    # canonical user installation or weakening the public non-elevated guard.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $owner = $identity.User }
    finally { $identity.Dispose() }
    $local = if ($FixtureParent) { Resolve-ExaCopyWindowsPath $FixtureParent }
             else { Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) }
    if ($FixtureParent) {
        [void](Confirm-ExaCopyPath $local)
        $next = [IO.DirectoryInfo]::new($local)
        $depth = 0
        while ($null -ne $next) {
            $acl = [IO.FileSystemAclExtensions]::GetAccessControl($next)
            $sid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            Write-Output "Disposable parent depth=$depth owner_sid=$sid"
            $next = $next.Parent
            $depth++
        }
        Assert-ExaCopyInstallAncestors $local $owner
        Write-Output 'Disposable fixed NTFS fixture parent passed unchanged ancestry and ACL checks.'
    }
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
    if ($installed.status -cne 'installed') { throw 'The installer did not publish the package.' }
    $smokePassed = $false
    try {
        if ($installed.path -cne $expectedExecutable -or
            $installed.launcher -cne $expectedLauncher -or ![IO.File]::Exists($expectedLauncher)) {
            throw 'The installer did not publish the exact packaged version and stable launcher.'
        }
        Assert-ExaCopyExactEntries $bin @('exacopy.ps1', 'selected', 'owner.marker')
        $selected = [Text.Encoding]::ASCII.GetString((Read-ExaCopyBoundedBytes (Join-Path $bin 'selected') 256))
        $expectedSelection = "schema=exacopy-windows-selection-v1`nversion=$Version`nmanifest_sha256=$($Signed.ManifestHash)`n"
        if ($selected -cne $expectedSelection) { throw 'The launcher does not select the exact signed package.' }
        Confirm-ExaCopyArtifact $expectedExecutable $Signed.Release
        Write-Output "Verified installed executable SHA-256 $($Signed.Release.sha256)"
        if ($NativeSignatureReport) {
            & (Join-Path $PSScriptRoot 'release_windows_signature.ps1') `
                -Directory (Split-Path -Parent $expectedExecutable) -Report $NativeSignatureReport
        }
        $helpText = & $expectedExecutable --help
        if ($LASTEXITCODE -ne 0 -or ($helpText -join "`n") -notmatch 'Usage: exacopy') {
            throw 'The verified packaged CLI did not emit the expected help.'
        }
        $versionText = @(& $expectedExecutable --version)
        if ($LASTEXITCODE -ne 0 -or $versionText.Count -eq 0 -or $versionText[0] -cne "exacopy $Version") {
            throw 'The exact selected CLI did not report the expected version.'
        }
        $smokePassed = $true
    }
    finally {
        $removed = Uninstall-ExaCopySignedVersion $context -Quiesced
        if ($removed.status -cne 'uninstalled' -or (Get-ExaCopyNodeExists $bin) -or
            (Get-ExaCopyNodeExists (Split-Path -Parent $expectedExecutable)) -or
            [IO.File]::ReadAllText($incumbent) -cne 'preserve a neighboring owner file') {
            throw 'The uninstall did not withdraw exactly the owned launcher and version.'
        }

        if ($smokePassed -and !$SourceRoot) {
            Assert-ExaCopyExactEntries $programs @('ExaCopy')
            Test-ExaCopyWithdrawalRetry $Bundle $context $Signed $expectedExecutable
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
    Test-ExaCopyPackagedLauncher $stage.FullName $target $signed
    Write-Output 'Windows verified the archive, launcher selection, selected executable launch, and owned withdrawal.'
    Write-Output 'The public non-elevated PowerShell shim requires its canonical per-user root.'
}
finally {
    foreach ($entry in $created) { [IO.File]::Delete((Join-Path $stage.FullName $entry)) }
    [IO.Directory]::Delete($stage.FullName, $false)
}
