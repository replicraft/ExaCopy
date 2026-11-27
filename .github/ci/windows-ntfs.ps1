[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Repository,

    [Parameter(Mandatory)]
    [string] $EvidenceDirectory,

    [Parameter(Mandatory)]
    [string] $LocalNtfsRoot,

    [string] $UncRoot,

    [string] $SecondNtfsRoot,

    [switch] $IncludeSymlink,

    [switch] $HostedReadDiff,

    [ValidateSet('Read', 'Stage', 'Diff')]
    [string] $Mode = 'Read'
)

$ErrorActionPreference = 'Stop'

function New-HostedReadDiffDirectory {
    param([string] $Path)
    # Windows os.mkdir uses exclusive creation with the inherited ACL.
    & python -B -c 'import os, sys; os.mkdir(sys.argv[1])' $Path
    if ($LASTEXITCODE -ne 0) { throw 'Exclusive Read/Diff directory creation was refused.' }
    Get-Item -LiteralPath $Path
}

if ($HostedReadDiff) {
    . (Join-Path $PSScriptRoot '../../tools/install/windows/paths.ps1')
    . (Join-Path $PSScriptRoot 'windows-ntfs-custody.ps1')
    . (Join-Path $PSScriptRoot 'windows-ntfs-read-diff.ps1')
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-ntfs-custody.cs')
    [void](Get-ReadDiffHostedSystemVolume $LocalNtfsRoot)
    $evidenceRoot = [IO.DirectoryInfo]::new($env:EXACOPY_READ_DIFF_EVIDENCE_ROOT)
    $candidate = [IO.DirectoryInfo]::new($EvidenceDirectory)
    if ($evidenceRoot.Parent.FullName -ine $env:USERPROFILE -or
        $evidenceRoot.Name -cnotmatch '^exacopy-windows-read-diff-evidence-[0-9a-f]{32}$' -or
        $candidate.FullName -cne $EvidenceDirectory -or $candidate.Parent.FullName -ine $evidenceRoot.FullName -or
        $candidate.Name -cnotmatch '^exacopy-windows-read-diff-native-[0-9a-f]{32}$') {
        throw 'Use a new per-run native evidence path under the admitted evidence root.'
    }
    [void](Confirm-ExaCopyPath $evidenceRoot.FullName)
    [void](Confirm-ExaCopyPath $env:GITHUB_OUTPUT -File)
    $evidenceIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $evidenceOwner = $evidenceIdentity.User
        $evidencePin = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($evidenceRoot.FullName)
        try {
            $actual = [ExaCopyQualification.DirectoryCustody]::Observe($evidencePin)
            Assert-StageSameIdentity $env:EXACOPY_READ_DIFF_EVIDENCE_ID $actual
            Assert-ReadDiffTreeSecurity $evidenceRoot.FullName $evidenceOwner
            $evidence = New-HostedReadDiffDirectory $EvidenceDirectory
            [void](Confirm-ExaCopyPath $evidence.FullName)
            Assert-ReadDiffTreeSecurity $evidence.FullName $evidenceOwner
            $artifactPath = $evidence.FullName.Replace([char]92, [char]47)
            Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8 -Value "evidence_path=$artifactPath"
        } finally {
            $evidencePin.Dispose()
        }
    } finally {
        $evidenceIdentity.Dispose()
    }
} else {
    $evidence = New-Item -ItemType Directory -Path $EvidenceDirectory
}
try {
    if ($HostedReadDiff -and ($Mode -eq 'Stage' -or $UncRoot -or $SecondNtfsRoot -or !$IncludeSymlink)) {
        throw 'Hosted Read/Diff requires its fixed NTFS inputs and the native reparse controls.'
    }
    if ($Mode -ne 'Read' -and ($UncRoot -or $SecondNtfsRoot)) {
        throw 'The selected lane requires only a fixed local NTFS root.'
    }
    $repo = (Resolve-Path -LiteralPath $Repository).Path
    $rootInfo = Get-Item -LiteralPath $LocalNtfsRoot
    if (-not $rootInfo.PSIsContainer -or $rootInfo.FullName -notmatch '^[A-Za-z]:\\') {
        throw 'Use a disposable plain directory with a local drive letter.'
    }
    # Reject redirected ancestors so DriveInfo describes the actual fixture volume.
    for ($ancestor = $rootInfo; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
        if ($ancestor.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
            throw "The fixture root traverses a reparse point at $($ancestor.FullName)."
        }
    }
    $drive = [IO.DriveInfo]::new($rootInfo.FullName.Substring(0, 3))
    if ($drive.DriveType -ne 'Fixed') {
        throw "Expected a local fixed drive. Found $($drive.DriveType) at $($drive.Name)."
    }
    if ($drive.DriveFormat -ne 'NTFS') {
        throw "Expected NTFS. Found $($drive.DriveFormat) at $($drive.Name)."
    }
} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $evidence.FullName 'preflight-failure.log')
    throw
}
$oldRoot = $env:EXACOPY_WINDOWS_NTFS_ROOT
$oldUnc = $env:EXACOPY_WINDOWS_UNC_ROOT
$oldSecond = $env:EXACOPY_WINDOWS_SECOND_NTFS_ROOT
$oldTarget = $env:CARGO_TARGET_DIR
$oldBuild = $env:CARGO_BUILD_BUILD_DIR
$oldCli = $env:EXACOPY_WINDOWS_QUALIFIED_CLI
$readDiffGuard = $null
$readDiffBuildPin = $null
$readDiffBuildIdentity = $null
$readDiffBuild = $null
$scratch = $null
$stageOwner = $null
$stageAncestors = $null
$stagePin = $null
$stageFixtureIdentity = $null
$stageAdmitted = $false

function Invoke-Lane {
    param([string] $Name, [string] $Program, [string[]] $Arguments, [switch] $QuietStdout)
    $out = Join-Path $evidence.FullName ($Name + '.stdout.log')
    $err = Join-Path $evidence.FullName ($Name + '.stderr.log')
    # All program arguments are fixed tokens with no spaces. Start-Process stores
    # Cargo's stderr without converting its ordinary status lines into errors.
    $launch = @{
        FilePath = $Program
        ArgumentList = $Arguments
        WorkingDirectory = $repo
        RedirectStandardOutput = $out
        RedirectStandardError = $err
        NoNewWindow = $true
        Wait = $true
        PassThru = $true
    }
    $process = Start-Process @launch
    Add-Content -LiteralPath (Join-Path $evidence.FullName 'lanes.tsv') -Value (@($Name, $process.ExitCode) -join [char]9)
    if (!$QuietStdout) { Get-Content -LiteralPath $out | Write-Host }
    Get-Content -LiteralPath $err | Write-Host
    return $process.ExitCode
}

function Run-TestLane {
    param([string] $Name, [int] $ExpectedTests, [string[]] $HarnessArgs, [string[]] $ExactNames)
    $cargoArgs = @('+1.100.0', 'test', '--locked')
    switch ($Mode) {
        'Read' {
            $cargoArgs += @('-p', 'exacopy-platform', '--test', 'windows_read', '--features', 'windows-read-fixture')
        }
        'Stage' {
            $cargoArgs += @('-p', 'exacopy-platform', '--lib', '--features', 'experimental-windows-copy')
        }
        'Diff' {
            $cargoArgs += @('-p', 'exacopy-cli', '--test', 'windows_diff', '--features', 'experimental-windows-diff')
        }
    }
    $cargoArgs += @('--target', 'x86_64-pc-windows-msvc', '--', '--nocapture', '--test-threads=1')
    $exitCode = Invoke-Lane -Name $Name -Program 'cargo' -Arguments ($cargoArgs + $HarnessArgs)
    $output = Get-Content -Raw -LiteralPath (Join-Path $evidence.FullName ($Name + '.stdout.log'))
    # Libtest succeeds when zero tests match. Require the expected number of passes.
    $result = "(?m)^test result: ok\. $ExpectedTests passed; 0 failed;"
    $missing = @()
    if ($ExactNames) {
        $result += ' 0 ignored;'
        foreach ($testName in $ExactNames) {
            $escaped = [regex]::Escape($testName)
            if ([regex]::Matches($output, "(?m)^test $escaped \.\.\. ok\r?$").Count -ne 1) {
                $missing += $testName
            }
        }
        if ($missing.Count -ne 0) {
            $missing | Set-Content -LiteralPath (Join-Path $evidence.FullName ($Name + '-missing-tests.txt'))
        }
    }
    if ($exitCode -ne 0 -or $output -notmatch $result -or $missing.Count -ne 0) {
        Add-Content -LiteralPath (Join-Path $evidence.FullName 'qualification-failures.txt') -Value $Name
        return 1
    }
    return 0
}

function Write-StageAclEvidence {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner, [string] $Phase)

    Confirm-ExaCopyOwnerAcl $Path $Owner -Root
    $acl = Get-Acl -LiteralPath $Path
    Assert-StagePlainAcl $acl
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $access = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    if ($access[0].InheritanceFlags -ne $inheritance -or
        $access[0].PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
        throw 'The private Stage owner rule does not apply to the root and both descendant kinds.'
    }
    [ordered]@{
        path = $Path
        owner_sid = $Owner.Value
        protected = $acl.AreAccessRulesProtected
        sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner, Access')
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName ("stage-acl-$Phase.json"))
}

function Test-StageSymlink {
    param([string] $Path)

    $log = Join-Path $evidence.FullName 'stage-symlink-capability.json'
    if (!$IncludeSymlink) {
        @{ status = 'not-requested' } | ConvertTo-Json | Set-Content -LiteralPath $log
        return $false
    }
    $target = Join-Path $Path 'symlink-capability-target'
    $alias = Join-Path $Path 'symlink-capability-link'
    [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
    try {
        try {
            $link = [IO.File]::CreateSymbolicLink($alias, $target)
        } catch {
            $failure = $_.Exception.GetBaseException()
            $nativeCode = $failure.HResult -band 0xffff
            $reason = switch ($nativeCode) {
                50 { 'operation-not-supported' }
                1314 { 'privilege-not-held' }
            }
            if ($failure -isnot [IO.IOException] -or ($failure.HResult -band 0xffff0000) -ne 0x80070000 -or !$reason) {
                throw
            }
            Write-Warning "Optional Stage symlink cases blocked ($reason)."
            [ordered]@{
                status = 'blocked'
                reason = $reason
                win32_error = $nativeCode
                message = $failure.Message
            } | ConvertTo-Json | Set-Content -LiteralPath $log
            return $false
        }
        if ($link.LinkTarget -cne $target -or !$link.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
            throw 'The optional capability probe did not observe the selected native symbolic link.'
        }
        [IO.File]::Delete($alias)
        @{ status = 'supported' } | ConvertTo-Json | Set-Content -LiteralPath $log
        return $true
    } finally {
        [IO.File]::Delete($target)
    }
}

try {
    $sourceStatus = Invoke-Lane -Name 'revision' -Program 'git' -Arguments @('rev-parse', 'HEAD')
    $revision = Get-Content -LiteralPath (Join-Path $evidence.FullName 'revision.stdout.log') -Raw
    if ($sourceStatus -ne 0 -or $revision -notmatch '^\s*[0-9a-f]{40}\s*$') {
        throw 'Could not identify the tested source revision.'
    }
    $sourceDiff = Invoke-Lane -Name 'candidate_diff' -Program 'git' -Arguments @('diff', '--no-ext-diff', 'HEAD', '--binary')
    $sourceFiles = Invoke-Lane -Name 'candidate_status' -Program 'git' -Arguments @('status', '--porcelain=v1', '--untracked-files=all')
    if ($sourceDiff -ne 0 -or $sourceFiles -ne 0) {
        throw 'Could not capture source evidence.'
    }
    $status = Get-Content -LiteralPath (Join-Path $evidence.FullName 'candidate_status.stdout.log') -Raw
    $diff = Get-Content -LiteralPath (Join-Path $evidence.FullName 'candidate_diff.stdout.log') -Raw
    if (-not [string]::IsNullOrWhiteSpace($status) -or -not [string]::IsNullOrWhiteSpace($diff)) {
        throw 'Qualification requires a clean Git checkout. The candidate diff and status have been retained.'
    }

    if ($env:GITHUB_ACTIONS -ceq 'true' -and $revision.Trim() -cne $env:GITHUB_SHA) {
        throw 'Qualification requires the selected GitHub source revision.'
    }

    if ($Mode -eq 'Stage') {
        . (Join-Path $repo 'tools/install/windows/paths.ps1')
        Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-custody.cs')
        . (Join-Path $repo '.github/ci/windows-ntfs-custody.ps1')
        . (Join-Path $repo '.github/ci/windows-ntfs-ancestor-diagnostic.ps1')
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $stageOwner = $identity.User
            $token = [ordered]@{
                scope = 'synthetic-owner-private-stage'
                user_sid = $stageOwner.Value
                administrator_enabled = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
                child_launch = 'inherits-runner-token'
            }
        } finally {
            $identity.Dispose()
        }
        $systemVolume = if ($token.administrator_enabled) {
            Get-StageHostedSystemVolume $rootInfo.FullName ([Environment]::GetEnvironmentVariables()) ([Environment]::SystemDirectory)
        }
        $token['ancestor_owner_profile'] = if ($systemVolume) { 'hosted-system-volume-owner-v1' } else { 'ordinary-owner-v1' }
        $token | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName 'stage-token.json')
        if ((Invoke-Lane -Name 'stage-token-groups-privileges' -Program 'whoami.exe' -Arguments @('/all')) -ne 0) {
            throw 'Could not record the native Stage caller token.'
        }
        $usesUserProfile = [string]::Equals($rootInfo.FullName, $env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase)
        $stageAncestors = New-StageAncestorCustody $rootInfo.FullName $stageOwner -HostedSystemVolume $systemVolume -BeforeAdmission {
            param($Held)
            Write-StageAncestorDiagnostic $Held $token $usesUserProfile (Join-Path $evidence.FullName 'stage-ancestor-admission.json')
        }
        $scratch = [IO.DirectoryInfo]::new((Join-Path $rootInfo.FullName ('exacopy-native-' + [Guid]::NewGuid().ToString('N'))))
        New-StagePrivateFixture $scratch.FullName $stageOwner
        $stagePin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($scratch.FullName)
        $stageFixtureIdentity = [ExaCopyQualification.DirectoryCustody]::Observe($stagePin)
        Confirm-StageAncestorCustody $stageAncestors
        Assert-StageSameVolume $stageAncestors.Held[0].Identity $stageFixtureIdentity
        Write-StageAclEvidence $scratch.FullName $stageOwner 'before'
        Confirm-StageNoResidue $scratch.FullName
        [ExaCopyQualification.DirectoryCustody]::ControlAncestorDeleteSharing($scratch.FullName)
        $stageAdmitted = $true
        [ordered]@{
            fixture = $stageFixtureIdentity
            ancestors = @($stageAncestors.Held | ForEach-Object { $_.Identity })
            authority = 'synthetic runner user, SYSTEM and local Administrators'
            ancestor_delete_open_control = 'sharing-violation'
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName 'stage-custody.json')
    } elseif ($HostedReadDiff) {
        Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-read-diff-custody.cs')
        $systemVolume = Get-ReadDiffHostedSystemVolume $rootInfo.FullName
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $stageOwner = $identity.User
            if (![Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)) {
                throw 'The hosted Read/Diff fixture requires its runner administrator token.'
            }
        } finally {
            $identity.Dispose()
        }
        $ancestorAdmission = @{
            HostedSystemVolume = $systemVolume
            BeforeAdmission = {
                param($Held)
                @($Held | ForEach-Object { @{ path = $_.Path; identity = $_.Identity } }) |
                    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName 'read-diff-ancestor-admission.json')
            }
        }
        $stageAncestors = New-StageAncestorCustody $rootInfo.FullName $stageOwner @ancestorAdmission
        $readDiffVolume = [ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($stageAncestors.Held[0].Handle)
        Assert-ReadDiffTreeSecurity $rootInfo.FullName $stageOwner
        $scratch = New-HostedReadDiffDirectory (Join-Path $rootInfo.FullName ('exacopy-read-diff-' + [Guid]::NewGuid().ToString('N')))
        $stagePin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($scratch.FullName)
        $stageFixtureIdentity = [ExaCopyQualification.DirectoryCustody]::Observe($stagePin)
        $readDiffGuard = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($scratch.FullName)
        Assert-StageSameIdentity $stageFixtureIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($readDiffGuard))
        Assert-StageSameVolume $stageAncestors.Held[0].Identity $stageFixtureIdentity
        Assert-ReadDiffTreeSecurity $scratch.FullName $stageOwner
        Confirm-StageNoResidue $scratch.FullName
        Confirm-StageAncestorCustody $stageAncestors
        $build = New-HostedReadDiffDirectory (Join-Path $scratch.FullName 'cargo-target')
        $readDiffBuild = $build.FullName
        $readDiffBuildPin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($readDiffBuild)
        $readDiffBuildIdentity = [ExaCopyQualification.DirectoryCustody]::Observe($readDiffBuildPin)
        Assert-StageSameVolume $stageFixtureIdentity $readDiffBuildIdentity
        Assert-ReadDiffTreeSecurity $readDiffBuild $stageOwner
        Assert-ExaCopyNoNamedStreams $readDiffBuild
        [ordered]@{
            physical_ntfs_root = $readDiffVolume
            fixture = $stageFixtureIdentity
            build = $readDiffBuildIdentity
            caller_sid = $stageOwner.Value
            fixture_owner_sid = (Get-Acl -LiteralPath $scratch.FullName).GetOwner(
                [Security.Principal.SecurityIdentifier]).Value
            authority = 'canonical hosted user, SYSTEM and local Administrators; inherited ACL'
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName 'read-diff-custody.json')
    } else {
        $scratch = New-Item -ItemType Directory -Path (Join-Path $rootInfo.FullName ('exacopy-native-' + [guid]::NewGuid()))
    }

    $env:EXACOPY_WINDOWS_NTFS_ROOT = $scratch.FullName
    if ($HostedReadDiff) {
        $env:CARGO_TARGET_DIR = $readDiffBuild
        $env:CARGO_BUILD_BUILD_DIR = $readDiffBuild
    } else {
        $env:CARGO_TARGET_DIR = Join-Path $repo 'target/windows-ntfs-qualification'
    }
    $env:EXACOPY_WINDOWS_UNC_ROOT = $UncRoot
    $env:EXACOPY_WINDOWS_SECOND_NTFS_ROOT = $SecondNtfsRoot

    $os = Get-CimInstance Win32_OperatingSystem
    $profile = [ordered]@{
        os = $os.Caption
        os_version = $os.Version
        os_build = $os.BuildNumber
        os_architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        runner_image = $env:ImageOS
        runner_image_version = $env:ImageVersion
        test_target = 'x86_64-pc-windows-msvc'
        qualification = $Mode
        exact_hosted_read_diff = [bool]$HostedReadDiff
        fixture_filesystem = $drive.DriveFormat
        fixture_drive_type = $drive.DriveType.ToString()
        fixture_drive = $drive.Name
        unc_requested = [bool]$UncRoot
        second_ntfs_requested = [bool]$SecondNtfsRoot
        symlink_requested = [bool]$IncludeSymlink
        lockfile_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repo 'Cargo.lock')).Hash
    }
    $profile | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName 'profile.json')
    if ($profile.os_architecture -ne 'X64') {
        throw 'The native fixture requires an x64 Windows kernel and MSVC tools.'
    }
    $preflight = Invoke-Lane -Name 'compiler' -Program 'rustc' -Arguments @('+1.100.0', '-vV')
    $compiler = Get-Content -Raw -LiteralPath (Join-Path $evidence.FullName 'compiler.stdout.log')
    if ($preflight -ne 0 -or $compiler -notmatch 'commit-hash: 0ef1bc386059596dada8fb65b50425aab2ea637a' -or
        $compiler -notmatch 'host: x86_64-pc-windows-msvc') {
        throw 'The installed native compiler must match the pinned official Rust build.'
    }

    try {
        $partition = Get-Partition -DriveLetter ($drive.Name[0])
        $partition | Get-Disk | Select-Object BusType, PartitionStyle | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $evidence.FullName 'volume-attachment.json')
    } catch {
        $_ | Out-String |
            Set-Content -LiteralPath (Join-Path $evidence.FullName 'volume-attachment-unavailable.log')
    }
    $filterStatus = Invoke-Lane -Name 'filters' -Program 'fltmc' -Arguments @('filters')
    if ($filterStatus -ne 0) {
        Add-Content -LiteralPath (Join-Path $evidence.FullName 'profile-notes.txt') -Value 'Filter inventory unavailable under the running account.'
    }

    if ($Mode -eq 'Stage') {
        $failures = Run-TestLane -Name 'stage_contract_controls' -ExpectedTests 3 `
            -HarnessArgs @('windows::stage::', '--skip', 'windows::stage::publication::')
        $failures += Run-TestLane -Name 'ordinary_ntfs_stage' -ExpectedTests 5 `
            -HarnessArgs @('--ignored', 'windows::stage::tests::', '--skip', 'stage_symlink_')
        $capture = 'windows::stage::capture::tests::'
        $cases = @(
            $capture + 'capture_syncs_exact_prefix_and_reads_two_independent_views'
            $capture + 'failed_prefix_barrier_retires_writer_and_preserves_bytes_for_inspection'
            $capture + 'prefix_postflush_extent_change_retires_writer_without_reset'
            $capture + 'retained_checks_exact_name_identity_extent_and_denies_writer_sharing'
            $capture + 'retained_refuses_unsupported_file_attributes'
        )
        $captureFailures = Run-TestLane -Name 'ordinary_ntfs_capture' -ExpectedTests 5 `
            -HarnessArgs @('--ignored', $capture, '--skip', 'capture_symlink_') -ExactNames $cases
        $failures += $captureFailures
        if ($captureFailures -eq 0) {
            $observed = Get-Content -Raw -LiteralPath (Join-Path $evidence.FullName 'ordinary_ntfs_capture.stderr.log')
            foreach ($marker in @('ntfs-capture prefix_observations=', 'ntfs-capture held_parent=', 'ntfs-inspection held_parent=')) {
                if (!$observed.Contains($marker)) {
                    throw "Missing native handle evidence '$marker'."
                }
            }
        }
        if (Test-StageSymlink $scratch.FullName) {
            $symlink = $capture + 'capture_symlink_cannot_select_the_referent_identity'
            $failures += Run-TestLane -Name 'capture_symlink' -ExpectedTests 1 `
                -HarnessArgs @('--ignored', '--exact', $symlink) -ExactNames @($symlink)
            $failures += Run-TestLane -Name 'stage_symlinks' -ExpectedTests 2 `
                -HarnessArgs @('--ignored', 'windows::stage::tests::stage_symlink_')
        }
    } elseif ($HostedReadDiff) {
        $failures = Invoke-ExactReadDiff $Mode $readDiffBuild $evidence.FullName $repo
        $checkedHead = Invoke-Lane -Name 'final_revision' -Program 'git' -Arguments @('rev-parse', 'HEAD')
        $checkedStatus = Invoke-Lane -Name 'final_status' -Program 'git' -Arguments @('status', '--porcelain=v1', '--untracked-files=all')
        $headOutput = Get-Content -Raw -LiteralPath (Join-Path $evidence.FullName 'final_revision.stdout.log')
        $statusOutput = Get-Content -Raw -LiteralPath (Join-Path $evidence.FullName 'final_status.stdout.log')
        if ($checkedHead -ne 0 -or $checkedStatus -ne 0 -or $headOutput.Trim() -cne $revision.Trim() -or
            ![string]::IsNullOrWhiteSpace($statusOutput) -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repo 'Cargo.lock')).Hash -cne $profile.lockfile_sha256) {
            throw 'The exact Read/Diff source or lockfile changed during qualification.'
        }
    } elseif ($Mode -eq 'Diff') {
        $failures = Run-TestLane -Name 'diff_path_refusal' -ExpectedTests 1 `
            -HarnessArgs @('ntfs_profile_refuses_unavailable_or_unadmitted_input')
        $failures += Run-TestLane -Name 'ordinary_ntfs_diff' -ExpectedTests 1 `
            -HarnessArgs @('--ignored', 'ordinary_ntfs_compares_and_preserves_regular_files')
        if ($IncludeSymlink) {
            $failures += Run-TestLane -Name 'diff_symlinks' -ExpectedTests 1 `
                -HarnessArgs @('--ignored', 'refuses_native_reparse_leaf_and_parent')
        }
    } else {
        $failures = Run-TestLane -Name 'parser' -ExpectedTests 4 -HarnessArgs @('directory_entries::')
        $failures += Run-TestLane -Name 'ordinary_ntfs' -ExpectedTests 11 -HarnessArgs @('--ignored', 'ordinary_ntfs_')
        if ($UncRoot) {
            $failures += Run-TestLane -Name 'unc_refusal' -ExpectedTests 1 -HarnessArgs @('--ignored', 'native_unc_handle_has_no_local_volume_guid_and_is_refused')
        }
        if ($SecondNtfsRoot) {
            $failures += Run-TestLane -Name 'cross_volume_junction' -ExpectedTests 1 -HarnessArgs @('--ignored', 'native_cross_volume_held_parent_junction_is_refused')
        }
        if ($IncludeSymlink) {
            $failures += Run-TestLane -Name 'file_and_directory_symlinks' -ExpectedTests 1 -HarnessArgs @('--ignored', 'refuses_reparse_leaf_and_parent')
        }
    }
    if ($failures -ne 0) {
        throw "$failures native lane(s) failed. Preserve stdout/stderr and inspect the failing positive control or test."
    }
} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $evidence.FullName 'qualification-failure.log')
    throw
} finally {
    $env:EXACOPY_WINDOWS_NTFS_ROOT = $oldRoot
    $env:EXACOPY_WINDOWS_UNC_ROOT = $oldUnc
    $env:EXACOPY_WINDOWS_SECOND_NTFS_ROOT = $oldSecond
    $env:CARGO_TARGET_DIR = $oldTarget
    if ($HostedReadDiff) {
        $env:CARGO_BUILD_BUILD_DIR = $oldBuild
        $env:EXACOPY_WINDOWS_QUALIFIED_CLI = $oldCli
    }
    try {
        if ($null -ne $scratch) {
            try {
                if ($Mode -eq 'Stage') {
                    if (!$stageAdmitted) {
                        throw 'Original NTFS fixture custody was not fully admitted.'
                    }
                    Remove-HeldStageFixture $scratch.FullName $stageFixtureIdentity $stagePin $stageAncestors
                    $stagePin.Dispose()
                } elseif ($HostedReadDiff) {
                    $cleanupCustody = @{
                        Fixture = $scratch.FullName; Build = $readDiffBuild; Pin = $stagePin
                        Guard = $readDiffGuard; Identity = $stageFixtureIdentity
                        BuildPin = $readDiffBuildPin; BuildIdentity = $readDiffBuildIdentity
                        Ancestors = $stageAncestors; Volume = $readDiffVolume
                    }
                    Remove-HeldReadDiffFixture @cleanupCustody
                } else {
                    # Existing manual Read/Diff compatibility.
                    [IO.Directory]::Delete($scratch.FullName, $false)
                }
                $stillPresent = if ($Mode -eq 'Stage' -or $HostedReadDiff) {
                    Get-ExaCopyNodeExists $scratch.FullName
                } else {
                    Test-Path -LiteralPath $scratch.FullName
                }
                if ($stillPresent) {
                    throw 'The fixture path is present after nonrecursive disposal.'
                }
                [ordered]@{ status = 'deleted'; path = $scratch.FullName; identity = $stageFixtureIdentity } |
                    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName 'fixture-cleanup.json')
            } catch {
                [ordered]@{
                    status = 'retained-or-unconfirmed'
                    path = $scratch.FullName
                    identity = $stageFixtureIdentity
                    message = $_.Exception.Message
                } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence.FullName 'fixture-cleanup.json')
                if ($Mode -eq 'Stage' -or $HostedReadDiff) { throw }
                Write-Warning "Synthetic scratch preserved at $($scratch.FullName): $_"
            }
        }
    } finally {
        if ($null -ne $readDiffBuildPin) { $readDiffBuildPin.Dispose() }
        if ($null -ne $readDiffGuard) { $readDiffGuard.Dispose() }
        if ($null -ne $stagePin) { $stagePin.Dispose() }
        if ($null -ne $stageAncestors) { Close-StageAncestorCustody $stageAncestors.Held }
    }
}
