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

    [ValidateSet('Read', 'Stage', 'Diff')]
    [string] $Mode = 'Read'
)

$ErrorActionPreference = 'Stop'
$evidence = New-Item -ItemType Directory -Path $EvidenceDirectory
try {
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
    $scratch = New-Item -ItemType Directory -Path (Join-Path $rootInfo.FullName ('exacopy-native-' + [guid]::NewGuid()))
} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $evidence.FullName 'preflight-failure.log')
    throw
}
$oldRoot = $env:EXACOPY_WINDOWS_NTFS_ROOT
$oldUnc = $env:EXACOPY_WINDOWS_UNC_ROOT
$oldSecond = $env:EXACOPY_WINDOWS_SECOND_NTFS_ROOT
$oldTarget = $env:CARGO_TARGET_DIR

function Invoke-Lane {
    param([string] $Name, [string] $Program, [string[]] $Arguments)
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
    Get-Content -LiteralPath $out | Write-Host
    Get-Content -LiteralPath $err | Write-Host
    return $process.ExitCode
}

function Run-TestLane {
    param([string] $Name, [int] $ExpectedTests, [string[]] $HarnessArgs)
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
    if ($exitCode -ne 0 -or $output -notmatch $result) {
        Add-Content -LiteralPath (Join-Path $evidence.FullName 'qualification-failures.txt') -Value $Name
        return 1
    }
    return 0
}

try {
    $env:EXACOPY_WINDOWS_NTFS_ROOT = $scratch.FullName
    $env:CARGO_TARGET_DIR = Join-Path $repo 'target/windows-ntfs-qualification'
    $env:EXACOPY_WINDOWS_UNC_ROOT = $UncRoot
    $env:EXACOPY_WINDOWS_SECOND_NTFS_ROOT = $SecondNtfsRoot

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
            -HarnessArgs @('windows::stage::')
        $failures += Run-TestLane -Name 'ordinary_ntfs_stage' -ExpectedTests 5 `
            -HarnessArgs @('--ignored', 'windows::stage::tests::', '--skip', 'stage_symlink_')
        if ($IncludeSymlink) {
            $failures += Run-TestLane -Name 'stage_symlinks' -ExpectedTests 2 `
                -HarnessArgs @('--ignored', 'windows::stage::tests::stage_symlink_')
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
    # Leave unexpected residue for diagnosis. A non-recursive removal cannot traverse a tag.
    try {
        [IO.Directory]::Delete($scratch.FullName, $false)
    } catch {
        Write-Warning "Synthetic scratch preserved at $($scratch.FullName): $_"
    }
}
