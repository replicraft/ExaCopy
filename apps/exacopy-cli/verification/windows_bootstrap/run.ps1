# Opt-in runner for a separately selected Windows bootstrap test image.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Image,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ImageSha256,
    [Parameter(Mandatory)][string] $ScratchParent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or ![Environment]::Is64BitProcess) { throw 'Requires 64-bit Windows PowerShell 7.' }

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
. (Join-Path $repo 'tools/install/windows/paths.ps1')
. (Join-Path $repo '.github/ci/windows-ntfs-custody.ps1')
. (Join-Path $repo '.github/ci/windows-ntfs-read-diff.ps1')
Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-custody.cs')
Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-read-diff-custody.cs')
Add-Type -Path (Join-Path $repo 'crates/platform/exacopy-platform/verification/windows_ntfs_publication/process.cs')

function Get-BootstrapIdentity {
    param([string] $VolumeGuid, [string] $Observation)

    if ($Observation -cnotmatch '\A[0-9A-F]{16}:[0-9A-F]{32}\z') { throw 'Malformed native identity.' }
    $serial, $highLow = $Observation.Split(':')
    # The custody helper formats native little-endian u64s high word first.
    # Reverse all 16 decoded bytes to recover FILE_ID_128.Identifier.
    $native = [Convert]::FromHexString($highLow)
    [Array]::Reverse($native)
    return "$VolumeGuid/$($serial.ToLowerInvariant())/$([Convert]::ToHexString($native).ToLowerInvariant())"
}

function New-BootstrapEmptyRecord {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner)

    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($Owner)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $Owner, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
    $stream = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path), [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $acl)
    try {
        $created = [ExaCopyQualification.ReadDiffCustody]::Observe($stream.SafeFileHandle, $false)
        if ($created.Links -ne 1 -or $stream.Length -ne 0) { throw 'Unexpected new fixture record state.' }
        return $created.FileId
    } finally {
        $stream.Dispose()
    }
}

function Confirm-BootstrapFixture {
    param($Roles, $Ancestors, [string] $RootId)

    Confirm-StageAncestorCustody $Ancestors
    foreach ($role in $Roles) {
        Assert-StageSameVolume $RootId $role.Id
        Assert-ReadDiffTreeSecurity $role.Path $Ancestors.Owner
        Assert-ExaCopyNoNamedStreams $role.Path -IncludeHidden
        $named = [ExaCopyQualification.ReadDiffCustody]::HoldNode($role.Path, $role.Directory, $false)
        try {
            foreach ($handle in @($role.Pin, $named)) {
                $node = [ExaCopyQualification.ReadDiffCustody]::Observe($handle, $role.Directory)
                Assert-StageSameIdentity $role.Id $node.FileId
                if (!$role.Directory -and $node.Links -ne 1) { throw 'A fixture record gained a hard link.' }
            }
        } finally {
            $named.Dispose()
        }
    }
    Assert-ExaCopyExactEntries $Roles[0].Path @([IO.Path]::GetFileName($Roles[1].Path))
    Assert-ExaCopyExactEntries $Roles[1].Path @('owner.cbor', 'journal')
    Assert-ExaCopyExactEntries $Roles[3].Path @('00000000000000000001.exajnl')
}

$Image = Resolve-ExaCopyWindowsPath $Image
$ScratchParent = Resolve-ExaCopyWindowsPath $ScratchParent
[void](Confirm-ExaCopyPath $Image -File)
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
try { $owner = $current.User } finally { $current.Dispose() }

$scratchAncestors = $null
$imageAncestors = $null
$imagePin = $null
$fixturePin = $null
$evidence = $null
$fixture = $null
$roles = [Collections.Generic.List[object]]::new()
$receipt = $null
$launchAttempted = $false
$fixtureComplete = $false
try {
    $scratchAncestors = New-StageAncestorCustody $ScratchParent $owner {}
    $imageAncestors = New-StageAncestorCustody ([IO.Path]::GetDirectoryName($Image)) $owner {}
    Assert-ReadDiffTreeSecurity $Image $owner
    Assert-ExaCopyNoNamedStreams $Image -IncludeHidden
    $imagePin = [IO.File]::Open($Image, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $imageId = [ExaCopyQualification.ReadDiffCustody]::Observe($imagePin.SafeFileHandle, $false)
    if ($imageId.Links -ne 1 -or $imagePin.Length -le 0 -or $imagePin.Length -gt 64MB) {
        throw 'Expected one bounded, single-link test executable.'
    }
    $observedHash = (Get-FileHash -InputStream $imagePin -Algorithm SHA256).Hash
    if ($observedHash -ine $ImageSha256) { throw 'The held test image has the wrong digest.' }
    $imageNamed = [ExaCopyQualification.ReadDiffCustody]::HoldNode($Image, $false, $false)
    try {
        $namedId = [ExaCopyQualification.ReadDiffCustody]::Observe($imageNamed, $false).FileId
        Assert-StageSameIdentity $imageId.FileId $namedId
    } finally {
        $imageNamed.Dispose()
    }

    $instance = [Guid]::NewGuid().ToString('N')
    $newEvidence = Join-Path $ScratchParent "exacopy-bootstrap-evidence-$instance"
    New-StagePrivateFixture $newEvidence $owner
    $evidence = $newEvidence
    $fixture = Join-Path $ScratchParent "exacopy-bootstrap-fixture-$instance"
    New-StagePrivateFixture $fixture $owner
    $fixturePin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($fixture)
    $rootId = [ExaCopyQualification.DirectoryCustody]::Observe($fixturePin)
    $volume = [ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($scratchAncestors.Held[0].Handle)
    $guid = $volume.Substring(11, 36).ToLowerInvariant()

    $job = Join-Path $fixture '.exacopy-018d45be-0000-7000-8000-000000000001'
    $journal = Join-Path $job 'journal'
    New-StagePrivateFixture $job $owner
    New-StagePrivateFixture $journal $owner
    $ownerPath = Join-Path $job 'owner.cbor'
    $segmentPath = Join-Path $journal '00000000000000000001.exajnl'
    $ownerId = New-BootstrapEmptyRecord $ownerPath $owner
    $segmentId = New-BootstrapEmptyRecord $segmentPath $owner
    # Storage role order is also the independently selected launcher order.
    foreach ($entry in @(
        @{ Path = $fixture; Directory = $true; Created = $rootId }
        @{ Path = $job; Directory = $true; Created = $null }
        @{ Path = $ownerPath; Directory = $false; Created = $ownerId }
        @{ Path = $journal; Directory = $true; Created = $null }
        @{ Path = $segmentPath; Directory = $false; Created = $segmentId }
    )) {
        $pin = [ExaCopyQualification.ReadDiffCustody]::HoldNode($entry.Path, $entry.Directory, $false)
        $role = [pscustomobject]@{ Path = $entry.Path; Directory = $entry.Directory; Pin = $pin; Id = $null }
        $roles.Add($role)
        $role.Id = [ExaCopyQualification.ReadDiffCustody]::Observe($pin, $role.Directory).FileId
        if ($null -ne $entry.Created) { Assert-StageSameIdentity $entry.Created $role.Id }
    }
    Confirm-BootstrapFixture $roles $scratchAncestors $rootId
    $fixtureComplete = $true
    Write-StageAclEvidence $fixture $owner 'before' $evidence

    $roleIds = ($roles | ForEach-Object { Get-BootstrapIdentity $guid $_.Id }) -join ';'
    [ordered]@{ image_sha256 = $observedHash.ToLowerInvariant(); fixture = $fixture; role_ids = $roleIds } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'selection.json')
    $stdout = Join-Path $evidence 'fixture.stdout'
    $stderr = Join-Path $evidence 'fixture.stderr'
    $selector = 'admits_only_the_selected_held_bootstrap_history'
    $launchAttempted = $true
    $receipt = [ExaCopyQualification.PublicationProcess]::Run($Image,
        @('--ignored', '--exact', $selector, '--show-output', '--test-threads=1'), $fixture,
        @("SystemRoot=$env:SystemRoot", "SystemDrive=$env:SystemDrive",
          "EXACOPY_WINDOWS_BOOTSTRAP_ROOT=$fixture", "EXACOPY_WINDOWS_BOOTSTRAP_ROLE_IDS=$roleIds"),
        $stdout, $stderr, 30000)
    $receipt | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $evidence 'process.json')
    if (!$receipt.Started -or !$receipt.Assigned -or !$receipt.JobListConfigured -or !$receipt.Resumed -or
        !$receipt.RootSignaled -or !$receipt.Drained -or $receipt.ActiveProcesses -ne 0 -or
        $receipt.TimedOut -or $receipt.OutputLimitExceeded -or $receipt.StdoutExtentUnconfirmed -or
        $receipt.StderrExtentUnconfirmed -or $receipt.Error -or $receipt.CleanupError -or $null -eq $receipt.ExitCode) {
        throw 'The owned fixture process did not produce a complete bounded receipt.'
    }
    $output = Get-Content -Raw -LiteralPath $stdout
    Assert-ReadDiffExactResult $selector $receipt.ExitCode $output
    $heads = [regex]::Matches($output, '(?m)^\{"extent":310,"historical_head":"[0-9a-f]{64}","sequence":1\}\r?$')
    if ($heads.Count -ne 1) { throw 'Expected one historical bootstrap boundary.' }
    Set-Content -LiteralPath (Join-Path $evidence 'historical-head.json') -Value $heads[0].Value
    Confirm-StageAncestorCustody $imageAncestors
} catch {
    if ($evidence -and (Get-ExaCopyNodeExists $evidence)) {
        Set-Content -LiteralPath (Join-Path $evidence 'runner-error.txt') -Value $_.ToString()
    }
    throw
} finally {
    try {
        if ($fixtureComplete -and (!$launchAttempted -or
            ($null -ne $receipt -and $receipt.Drained -and $receipt.ActiveProcesses -eq 0))) {
            Confirm-BootstrapFixture $roles $scratchAncestors $rootId
            # The tree and exact original identities were rechecked after drain.
            # Release redundant observations before using handle-bound disposal.
            foreach ($role in $roles) { $role.Pin.Dispose() }
            Remove-ReadDiffBuildChildren $fixture $rootId $owner -IncludeHidden
            Remove-HeldStageFixture $fixture $rootId $fixturePin $scratchAncestors $evidence
            $fixturePin.Dispose()
            if (Get-ExaCopyNodeExists $fixture) { throw 'The original fixture name remained after disposal.' }
            Set-Content -LiteralPath (Join-Path $evidence 'cleanup.txt') -Value 'original fixture removed'
        } elseif ($fixture) {
            Set-Content -LiteralPath (Join-Path $evidence 'cleanup.txt') -Value 'fixture retained after incomplete custody'
            Write-Warning "Retaining the fixture because setup or process custody was incomplete. $fixture"
        }
    } catch {
        if ($evidence -and (Get-ExaCopyNodeExists $evidence)) {
            Set-Content -LiteralPath (Join-Path $evidence 'cleanup-error.txt') -Value $_.ToString()
        }
        throw
    } finally {
        foreach ($role in $roles) { $role.Pin.Dispose() }
        if ($null -ne $fixturePin) { $fixturePin.Dispose() }
        if ($null -ne $imagePin) { $imagePin.Dispose() }
        if ($null -ne $imageAncestors) { Close-StageAncestorCustody $imageAncestors.Held }
        if ($null -ne $scratchAncestors) { Close-StageAncestorCustody $scratchAncestors.Held }
        if ($evidence) { Write-Host "Bootstrap fixture evidence retained at $evidence" }
    }
}
