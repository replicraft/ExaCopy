# One canonical hosted provider. The app fixture keeps its original interface.
[CmdletBinding()]
param([switch] $AdmissionOnly, [switch] $SftpCapture)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($AdmissionOnly -and $SftpCapture) { throw 'Admission-only applies to the common volume and actor profile.' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$publication = Join-Path $repo 'crates/platform/exacopy-platform/verification/windows_ntfs_publication'
. (Join-Path $publication 'selection.ps1')
. (Join-Path $repo 'tools/install/windows/paths.ps1')
. (Join-Path $repo '.github/ci/windows-ntfs-custody.ps1')
. (Join-Path $repo '.github/ci/windows-ntfs-read-diff.ps1')
. (Join-Path $PSScriptRoot 'hosted_admission.ps1')
$identity = Confirm-HostedBootstrapJob $repo
Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-custody.cs')
Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-read-diff-custody.cs')
Add-Type -Path (Join-Path $publication 'process.cs')

function Read-BootstrapRetiredCapture {
    param([string] $Path, [int] $Length, [string] $Identity, [string] $Sha256)

    if ($Length -lt 0 -or $Length -gt [ExaCopyQualification.PublicationProcess]::StreamLimitBytes -or
        $Identity -cnotmatch '\A[0-9A-F]{16}:[0-9A-F]{32}\z' -or $Sha256 -cnotmatch '\A[0-9A-F]{64}\z') {
        throw 'The compiler sink lacks bounded retirement evidence.'
    }
    [void](Confirm-ExaCopyPath $Path -File)
    $held = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $seen = [ExaCopyQualification.ReadDiffCustody]::Observe($held.SafeFileHandle, $false)
        Assert-StageSameIdentity $Identity $seen.FileId
        if ($seen.Links -ne 1 -or $held.Length -ne $Length) { throw 'The compiler sink changed after retirement.' }
        $bytes = [byte[]]::new($Length)
        $held.ReadExactly($bytes, 0, $Length)
        if ($held.ReadByte() -ne -1 -or
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)) -cne $Sha256) {
            throw 'The compiler sink no longer matches its retired extent and digest.'
        }
        return ,$bytes
    } finally {
        $held.Dispose()
    }
}

function Assert-BootstrapProcess {
    param($Process)

    if ($null -eq $Process -or !$Process.Started -or !$Process.Assigned -or !$Process.JobListConfigured -or
        !$Process.Resumed -or !$Process.RootSignaled -or !$Process.Drained -or $Process.ActiveProcesses -ne 0 -or
        $Process.TimedOut -or $Process.OutputLimitExceeded -or $Process.StdoutExtentUnconfirmed -or
        $Process.StderrExtentUnconfirmed -or $Process.Error -or $Process.CleanupError -or
        $null -eq $Process.ExitCode -or $Process.ExitCode -ne 0) {
        throw 'The exact owned bootstrap process did not complete.'
    }
}

function Get-BootstrapExactTool {
    param([string] $Path, [string] $Volume)

    Confirm-PublicationVendorPath $Path -File
    Assert-ReadDiffTreeSecurity $Path $owner
    Assert-ExaCopyNoNamedStreams $Path -IncludeHidden
    $parents = [Collections.Generic.List[object]]::new()
    $held = $null
    try {
        for ($parent = [IO.Directory]::GetParent($Path); $null -ne $parent; $parent = $parent.Parent) {
            $pin = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($parent.FullName)
            $parents.Add(@{ Handle = $pin })
            Assert-StageSameVolume $Volume ([ExaCopyQualification.DirectoryCustody]::Observe($pin))
        }
        $held = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $seen = [ExaCopyQualification.ReadDiffCustody]::Observe($held.SafeFileHandle, $false)
        Assert-StageSameVolume $Volume $seen.FileId
        $record = Read-PublicationApplicationRecord $Path -HeldImage $held
        $record.native_identity = $seen.FileId
        $record.links = $seen.Links
        $tool = @{ Held = $held; Record = $record; Parents = $parents }
        Confirm-BootstrapToolName $tool
        return $tool
    } catch {
        if ($null -ne $held) { $held.Dispose() }
        Close-StageAncestorCustody $parents
        throw
    }
}

function Confirm-BootstrapToolName {
    param($Tool)

    $named = [ExaCopyQualification.ReadDiffCustody]::HoldNode($Tool.Record.path, $false, $false)
    try {
        Assert-StageSameIdentity $Tool.Record.native_identity ([ExaCopyQualification.ReadDiffCustody]::Observe($named, $false)).FileId
        Assert-StageSameIdentity $Tool.Record.native_identity ([ExaCopyQualification.ReadDiffCustody]::Observe($Tool.Held.SafeFileHandle, $false)).FileId
    } finally {
        $named.Dispose()
    }
}

$current = [Security.Principal.WindowsIdentity]::GetCurrent()
try { $owner = $current.User } finally { $current.Dispose() }
$system = New-StageAncestorCustody $env:USERPROFILE $owner -BeforeAdmission {} -HostedSystemVolume ($env:SystemDrive + '\')
$evidence = $evidencePin = $data = $fixturePin = $fixtureGuard = $buildPin = $buildGuard = $null
$cargo = $compiler = $shell = $binary = $runnerImage = $null
$fixture = $build = $work = $null
$drained = $true
$childAttempted = $false
$outerAdmitted = $false
$state = $identity
if ($SftpCapture) { $state.fixture_target = 'windows_sftp_capture' }
$state.status = 'failed'
$state.phase = 'data-volume-admission'
$state.cleanup = 'not-acquired'
try {
    # The published exception for the system root is scoped solely to build
    # tools and retained receipts. The native five-role tree is never there.
    [void][ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($system.Held[0].Handle)
    $name = Join-Path $env:USERPROFILE ('exacopy-bootstrap-hosted-evidence-' + [Guid]::NewGuid().ToString('N'))
    New-StagePrivateFixture $name $owner
    $evidencePin = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($name)
    $evidenceId = [ExaCopyQualification.DirectoryCustody]::Observe($evidencePin)
    Assert-StageSameVolume $system.Held[0].Identity $evidenceId
    Confirm-ExaCopyOwnerAcl $name $owner -Root
    Confirm-StageNoResidue $name
    $evidence = $name
    $data = Open-BootstrapHostedDataParent $repo $owner
    $state.data_volume = $data.VolumeGuidRoot
    $state.ancestors = @($data.Ancestors.Held | ForEach-Object Identity)
    if ($AdmissionOnly) {
        $state.status = 'eligible'
        return
    }

    $state.phase = 'owned-build'
    $fixture = Join-Path $data.Parent ('exacopy-bootstrap-hosted-' + [Guid]::NewGuid().ToString('N'))
    New-StagePrivateFixture $fixture $owner
    $state.cleanup = 'unconfirmed'
    $fixturePin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($fixture)
    $fixtureGuard = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($fixture)
    $fixtureId = [ExaCopyQualification.DirectoryCustody]::Observe($fixturePin)
    Assert-StageSameIdentity $fixtureId ([ExaCopyQualification.DirectoryCustody]::Observe($fixtureGuard))
    Assert-StageSameVolume $data.Ancestors.Held[0].Identity $fixtureId
    Confirm-ExaCopyOwnerAcl $fixture $owner -Root
    Confirm-StageNoResidue $fixture
    $state.fixture_identity = $fixtureId
    $state.fixture_path = $fixture

    $build = Join-Path $fixture 'build'
    New-StagePrivateFixture $build $owner
    $buildPin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($build)
    $buildGuard = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($build)
    $buildId = [ExaCopyQualification.DirectoryCustody]::Observe($buildPin)
    Assert-StageSameIdentity $buildId ([ExaCopyQualification.DirectoryCustody]::Observe($buildGuard))
    Assert-StageSameVolume $fixtureId $buildId
    Confirm-StageNoResidue $build
    $outerAdmitted = $true

    $rustupHome = Join-Path $env:USERPROFILE '.rustup'
    $cargoHome = Join-Path $env:USERPROFILE '.cargo'
    $compilerPath = Resolve-PublicationCompiler $rustupHome
    $cargoPath = Join-Path ([IO.Path]::GetDirectoryName($compilerPath)) 'cargo.exe'
    $cargo = Get-BootstrapExactTool $cargoPath $system.Held[0].Identity
    $compiler = Get-BootstrapExactTool $compilerPath $system.Held[0].Identity
    $state.cargo = $cargo.Record
    $state.rustc = $compiler.Record
    $base = @(foreach ($key in @('SystemRoot', 'SystemDrive', 'WINDIR', 'COMSPEC', 'USERPROFILE',
        'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'ProgramData', 'APPDATA', 'LOCALAPPDATA',
        'PROCESSOR_ARCHITECTURE', 'Path')) {
        $value = [Environment]::GetEnvironmentVariable($key)
        if ($value) { "$key=$value" }
    })
    $environment = $base + @("RUSTUP_HOME=$rustupHome", "CARGO_HOME=$cargoHome", "RUSTC=$compilerPath",
        "CARGO_TARGET_DIR=$build", "CARGO_BUILD_BUILD_DIR=$build", 'CARGO_TERM_COLOR=never',
        'CARGO_INCREMENTAL=0', 'CARGO_CACHE_RUSTC_INFO=0', "TMP=$build", "TEMP=$build")
    Assert-PreparedCargoConfiguration $repo $cargoHome $environment

    $stdout = Join-Path $evidence 'cargo.stdout'
    $stderr = Join-Path $evidence 'cargo.stderr'
    $drained = $false
    $prepared = if ($SftpCapture) {
        [ExaCopyQualification.PublicationProcess]::PrepareSftpCaptureBuild($cargoPath, $repo,
            $environment, $stdout, $stderr, 480000)
    } else {
        [ExaCopyQualification.PublicationProcess]::PrepareBootstrapBuild($cargoPath, $repo,
            $environment, $stdout, $stderr, 480000)
    }
    $process = $prepared.Process
    $drained = ($null -ne $process -and $process.RootSignaled -and $process.Drained -and
        $null -ne $process.ActiveProcesses -and $process.ActiveProcesses -eq 0)
    $prepared | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'cargo-process.json')
    Assert-BootstrapProcess $process
    if ($prepared.Disposition.ToString() -cne 'QuiescedAfterRootExit' -or $prepared.RootExitCodeBeforeRetirement -ne 0 -or
        !$prepared.StopRequested -or $prepared.StopSucceeded -ne $true -or $null -ne $prepared.StopNativeError -or
        !$prepared.StdoutEof -or !$prepared.StderrEof -or $prepared.StdoutSinkIdentity -ceq $prepared.StderrSinkIdentity -or
        $prepared.InvocationId -cnotmatch '\A[0-9a-f]{32}\z') {
        throw 'The owned bootstrap compiler did not deliver complete retirement.'
    }
    Confirm-BootstrapToolName $cargo
    Confirm-BootstrapToolName $compiler
    $messages = Read-BootstrapRetiredCapture $stdout $process.StdoutBytes $prepared.StdoutSinkIdentity $prepared.StdoutSinkSha256
    [void](Read-BootstrapRetiredCapture $stderr $process.StderrBytes $prepared.StderrSinkIdentity $prepared.StderrSinkSha256)
    $binaryPath = Select-BootstrapExecutable $messages $repo $build -SftpCapture:$SftpCapture
    $state.preparation_invocation_id = $prepared.InvocationId
    $state.phase = 'held-fixture'
    $binary = Get-BootstrapExactTool $binaryPath $data.Ancestors.Held[0].Identity
    if ($binary.Record.links -ne 1 -or $binary.Record.bytes -gt 64MB) { throw 'The selected bootstrap image has invalid bounds.' }
    $null = Assert-PreparedPublicationPe $binary.Held
    $state.executable = $binary.Record
    $shellPath = (Get-Process -Id $PID).Path
    if ($shellPath -cne (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')) {
        throw 'The running hosted PowerShell is outside its canonical program path.'
    }
    $shell = Get-BootstrapExactTool $shellPath $system.Held[0].Identity
    $state.powershell = $shell.Record
    $work = Join-Path $fixture 'work'
    New-StagePrivateFixture $work $owner
    Confirm-ExaCopyOwnerAcl $work $owner -Root
    Confirm-StageNoResidue $work
    Confirm-StageAncestorCustody $data.Ancestors
    Confirm-PublicationSource $repo $state.source

    $caseOut = Join-Path $evidence 'fixture-runner.stdout'
    $caseErr = Join-Path $evidence 'fixture-runner.stderr'
    $runner = Join-Path $PSScriptRoot 'run.ps1'
    $runnerImage = Get-BootstrapExactTool $runner $data.Ancestors.Held[0].Identity
    $state.runner_source = $runnerImage.Record
    $drained = $false
    $childAttempted = $true
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $runner, '-Image', $binaryPath,
        '-ImageSha256', $binary.Record.sha256, '-ScratchParent', $work)
    if ($SftpCapture) { $arguments += '-SftpCapture' }
    $case = [ExaCopyQualification.PublicationProcess]::RunBootstrapActor($shellPath,
        $arguments, $repo, ($base + @("TMP=$build", "TEMP=$build")), $caseOut, $caseErr, 90000)
    $drained = ($null -ne $case -and $case.RootSignaled -and $case.Drained -and
        $null -ne $case.ActiveProcesses -and $case.ActiveProcesses -eq 0)
    $case | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'fixture-runner.process.json')
    Assert-BootstrapProcess $case
    $state.actor_sid = $owner.Value

    $acquired = @([IO.Directory]::EnumerateFileSystemEntries($work) | Select-Object -First 2)
    if ($acquired.Count -ne 1 -or
        [IO.Path]::GetFileName($acquired[0]) -cnotmatch '\Aexacopy-bootstrap-evidence-[0-9a-f]{32}\z') {
        throw 'The bounded child fixture or its cleanup has an unexpected inventory.'
    }
    $caseEvidence = $acquired[0]
    [void](Confirm-ExaCopyPath $caseEvidence)
    Confirm-ExaCopyOwnerAcl $caseEvidence $owner -Root
    $casePin = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($caseEvidence)
    try {
        $outcomeName = if ($SftpCapture) { 'capture-boundary.json' } else { 'historical-head.json' }
        $caseNames = @('stage-acl-before.json', 'stage-acl-after.json', 'process.json', 'fixture.stdout',
            'fixture.stderr', 'selection.json', $outcomeName, 'cleanup.txt')
        Assert-ExaCopyExactEntries $caseEvidence $caseNames
        foreach ($name in $caseNames) {
            $inputPath = Join-Path $caseEvidence $name
            [void](Confirm-ExaCopyPath $inputPath -File)
            Assert-ReadDiffTreeSecurity $inputPath $owner
            Assert-ExaCopyNoNamedStreams $inputPath -IncludeHidden
            $inputFile = [IO.File]::Open($inputPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                $info = [ExaCopyQualification.ReadDiffCustody]::Observe($inputFile.SafeFileHandle, $false)
                Assert-StageSameVolume $buildId $info.FileId
                if ($info.Links -ne 1 -or $inputFile.Length -gt 1MB) { throw 'Invalid exact fixture receipt sink.' }
                $bytes = [byte[]]::new([int]$inputFile.Length)
                $inputFile.ReadExactly($bytes, 0, $bytes.Length)
                if ($inputFile.ReadByte() -ne -1) { throw 'The fixture receipt extent changed.' }
                Write-ExaCopyNewBytes (Join-Path $evidence ("fixture-" + $name)) $bytes
            } finally {
                $inputFile.Dispose()
            }
        }
        if ((Get-Content -LiteralPath (Join-Path $evidence 'fixture-cleanup.txt') -Raw).Trim() -cne 'original fixture removed') {
            throw 'The inner owned fixture was retained.'
        }
    } finally {
        $casePin.Dispose()
    }
    Confirm-PublicationSource $repo $state.source
    if ((Get-FileHash -LiteralPath (Join-Path $repo 'Cargo.lock') -Algorithm SHA256).Hash -cne $state.lock_sha256) {
        throw 'The bound lockfile changed.'
    }
    Confirm-BootstrapToolName $shell
    Confirm-BootstrapToolName $runnerImage
    Confirm-BootstrapToolName $binary
    $binary.Held.Position = 0
    if ((Get-FileHash -InputStream $binary.Held -Algorithm SHA256).Hash -cne $binary.Record.sha256) {
        throw 'The held bootstrap test image changed.'
    }
    $state.source_rechecked = $true
    $state.status = 'passed'
} catch {
    $state.error = $_.Exception.Message
} finally {
    foreach ($item in @($runnerImage, $binary, $shell, $compiler, $cargo)) {
        if ($null -ne $item) {
            $item.Held.Dispose()
            Close-StageAncestorCustody $item.Parents
        }
    }
    try {
        if ($outerAdmitted -and $drained -and (!$childAttempted -or $state.status -eq 'passed')) {
            Confirm-StageAncestorCustody $data.Ancestors
            Assert-StageSameIdentity $fixtureId ([ExaCopyQualification.DirectoryCustody]::Observe($fixturePin))
            Assert-StageSameIdentity $buildId ([ExaCopyQualification.DirectoryCustody]::Observe($buildPin))
            if ($work) {
                Confirm-ExaCopyOwnerAcl $work $owner -Root
                if (!$childAttempted) { Confirm-StageNoResidue $work }
                Assert-ExaCopyExactEntries $fixture @('build', 'work')
            } else {
                Assert-ExaCopyExactEntries $fixture @('build')
            }
            $buildGuard.Dispose()
            $buildPin.Dispose()
            Remove-ReadDiffBuildChildren $fixture $fixtureId $owner -IncludeHidden -AllowReadOnlyBuildFiles
            $fixtureGuard.Dispose()
            Remove-HeldStageFixture $fixture $fixtureId $fixturePin $data.Ancestors $evidence
            $fixturePin.Dispose()
            if (Get-ExaCopyNodeExists $fixture) { throw 'The outer bootstrap fixture was retained.' }
            $state.cleanup = 'deleted'
        }
    } catch {
        $state.status = 'failed'
        $state.cleanup_error = $_.Exception.Message
    } finally {
        if ($null -ne $buildGuard) { $buildGuard.Dispose() }
        if ($null -ne $buildPin) { $buildPin.Dispose() }
        if ($null -ne $fixtureGuard) { $fixtureGuard.Dispose() }
        if ($null -ne $fixturePin) { $fixturePin.Dispose() }
        if ($null -ne $data) { Close-StageAncestorCustody $data.Ancestors.Held }
        try {
            if ($evidence) {
                Confirm-StageAncestorCustody $system
                Assert-StageSameIdentity $evidenceId ([ExaCopyQualification.DirectoryCustody]::Observe($evidencePin))
                Confirm-ExaCopyOwnerAcl $evidence $owner -Root
                $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'result.json')
                if ($drained) {
                    [void](Confirm-ExaCopyPath $env:GITHUB_OUTPUT -File)
                    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8 -Value (
                        'evidence_path=' + $evidence.Replace([char]92, [char]47))
                }
            }
        } finally {
            if ($null -ne $evidencePin) { $evidencePin.Dispose() }
            Close-StageAncestorCustody $system.Held
        }
    }
}
if ($state.status -ne 'passed' -or $state.cleanup -ne 'deleted') {
    throw "Hosted bootstrap qualification failed in phase $($state.phase)."
}
