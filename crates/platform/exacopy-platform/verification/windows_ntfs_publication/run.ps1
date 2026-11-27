[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../../..'))
$qualification = 'windows-hosted-server2025-fixed-ntfs-publication-v1'
$selected = 'x86_64-pc-windows-msvc'
if (!$IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
    $env:RUNNER_ARCH -cne 'X64' -or $env:GITHUB_SERVER_URL -cne 'https://github.com' -or
    $env:GITHUB_EVENT_NAME -cnotin @('push', 'workflow_dispatch') -or
    $env:GITHUB_WORKFLOW_REF -cne 'replicraft/ExaCopy/.github/workflows/windows-ntfs-publication.yml@refs/heads/main' -or
    $env:GITHUB_WORKFLOW_SHA -cne $env:GITHUB_SHA -or
    $env:GITHUB_REPOSITORY -cne 'replicraft/ExaCopy' -or $env:GITHUB_REF -cne 'refs/heads/main' -or
    $env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z') {
    throw 'Run this fixture only from its canonical hosted Windows workflow.'
}

. (Join-Path $PSScriptRoot 'selection.ps1')
Confirm-PublicationSource $repo $env:GITHUB_SHA

. (Join-Path $repo 'tools/install/windows/paths.ps1')
. (Join-Path $repo '.github/ci/windows-ntfs-custody.ps1')
. (Join-Path $repo '.github/ci/windows-ntfs-read-diff.ps1')
Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-custody.cs')
Add-Type -Path (Join-Path $repo '.github/ci/windows-ntfs-read-diff-custody.cs')
Add-Type -Path (Join-Path $PSScriptRoot 'process.cs')

function New-PublicationEnvironment {
    param([hashtable] $Scope)
    $safe = @{}
    foreach ($name in @(
        'Path', 'PATHEXT', 'SystemRoot', 'WINDIR', 'COMSPEC', 'USERPROFILE', 'HOMEDRIVE',
        'HOMEPATH', 'USERNAME', 'APPDATA', 'LOCALAPPDATA', 'ProgramFiles', 'ProgramFiles(x86)',
        'ProgramW6432', 'CommonProgramFiles', 'NUMBER_OF_PROCESSORS', 'OS', 'PROCESSOR_ARCHITECTURE',
        'RUSTUP_HOME', 'CARGO_HOME', 'LIB', 'LIBPATH', 'INCLUDE', 'VCINSTALLDIR',
        'VCToolsInstallDir', 'WindowsSdkDir', 'WindowsSDKVersion', 'VSCMD_VER'
    )) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (![string]::IsNullOrEmpty($value)) { $safe[$name] = $value }
    }
    foreach ($name in $Scope.Keys) { $safe[$name] = $Scope[$name] }
    return [string[]]@($safe.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
}

function Get-PublicationLaunchFacts {
    param([string] $Name, [string] $Program, [string] $WorkingDirectory, [string[]] $Arguments,
        [string[]] $Environment)
    # Record only the known setup oracles and the exact failing setup call.
    # Environment values remain private, including those accepted by the allowlist.
    if ($Name -cnotin @('launch-pwsh', 'launch-python', 'apfs-source')) { return }
    $keys = @($Environment | ForEach-Object { $_.Split('=', 2)[0] } | Sort-Object -CaseSensitive)
    $units = 1
    foreach ($entry in $Environment) { $units += $entry.Length + 1 }
    [ordered]@{
        application = if ($Program.Length -le 260) { $Program }
        application_units = $Program.Length
        working_directory = if ($WorkingDirectory.Length -le 260) { $WorkingDirectory }
        working_directory_units = $WorkingDirectory.Length
        arguments = @($Arguments | Select-Object -First 4 | ForEach-Object {
            if ($_.Length -le 128) { $_ } else { $null }
        })
        argument_count = $Arguments.Count
        environment_keys = @($keys | Select-Object -First 64)
        environment_count = $Environment.Count
        environment_utf16_units = $units
    }
}

function Write-PublicationEvidenceDiagnostic {
    # Emit one bounded line from process-owned memory when the evidence path
    # cannot be handed to the uploader. Base64 prevents workflow commands
    # and line breaks in native error text from affecting the job log.
    $payload = [ordered]@{
        phase = $diagnostic.phase
        process_drained = $state.process_drained
        cleanup = $state.cleanup
        receipt = $diagnostic.receipt
    }
    if ($null -ne $diagnostic.launch) { $payload.launch = $diagnostic.launch }
    $serialized = $payload | ConvertTo-Json -Depth 4 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($serialized)
    $logged = [Math]::Min($bytes.Length, 4096)
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    $encoded = [Convert]::ToBase64String($bytes, 0, $logged)
    Write-Host "Windows publication diagnostic json_bytes=$($bytes.Length) logged_bytes=$logged sha256=$digest base64=$encoded"
}

function Invoke-PublicationChild {
    param([string] $Name, [string] $Program, [string[]] $Arguments, [int] $Timeout)
    $diagnostic.phase = $Name
    $diagnostic.receipt = $null
    $diagnostic.launch = Get-PublicationLaunchFacts $Name $Program $repo $Arguments $childEnvironment
    if ($null -ne $diagnostic.launch -and $state.tools.python.path -ceq $Program) {
        $diagnostic.launch.application_sha256 = $state.tools.python.sha256
        $diagnostic.launch.application_bytes = $state.tools.python.bytes
    }
    $state.process_drained = $false
    $stdout = Join-Path $evidence ($Name + '.stdout.log')
    $stderr = Join-Path $evidence ($Name + '.stderr.log')
    $record = Join-Path $evidence ($Name + '.process.json')
    $child = [ExaCopyQualification.PublicationProcess]::Run(
        $Program, $Arguments, $repo, $childEnvironment, $stdout, $stderr, $Timeout)
    $diagnostic.receipt = $child
    $child | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $record -Encoding utf8
    if ($null -ne $diagnostic.launch) {
        $diagnostic.launch | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Join-Path $evidence ($Name + '.launch.json')) -Encoding utf8
    }
    $state.process_drained = (!$child.Started -and !$child.CreationAttempted) -or
        ($child.Drained -and $child.RootSignaled -and $null -ne $child.ActiveProcesses -and
            $child.ActiveProcesses -eq 0)
    if (!$state.process_drained -or !$child.Started -or !$child.JobListConfigured -or
        !$child.Assigned -or !$child.Resumed -or
        $child.TimedOut -or $child.OutputLimitExceeded -or $child.StdoutExtentUnconfirmed -or
        $child.StderrExtentUnconfirmed -or $child.Error -or $child.CleanupError -or
        $null -eq $child.ExitCode) {
        throw "The owned process did not complete its qualification contract: $Name"
    }
    return $child.ExitCode
}

function Close-PublicationVendorCustody($Tool) {
    if ($null -ne $Tool.Image) { $Tool.Image.Dispose() }
    Close-StageAncestorCustody $Tool.Parents
}

function Confirm-PublicationVendorCustody($Tool) {
    Confirm-PublicationVendorPath $Tool.Path -File
    $named = [ExaCopyQualification.ReadDiffCustody]::HoldNode($Tool.Path, $false, $false)
    try {
        Assert-StageSameIdentity $Tool.Identity ([ExaCopyQualification.ReadDiffCustody]::Observe($named, $false).FileId)
        Assert-StageSameIdentity $Tool.Identity ([ExaCopyQualification.ReadDiffCustody]::Observe($Tool.Image.SafeFileHandle, $false).FileId)
    } finally {
        $named.Dispose()
    }
}

function New-PublicationVendorCustody([string] $Path, [string] $VolumeIdentity) {
    Confirm-PublicationVendorPath $Path -File
    $parents = [Collections.Generic.Stack[string]]::new()
    for ($parent = [IO.Directory]::GetParent($Path); $null -ne $parent; $parent = $parent.Parent) {
        $parents.Push($parent.FullName)
    }
    $tool = @{
        Path = $Path
        Parents = [Collections.Generic.List[object]]::new()
        Image = $null
        Identity = $null
        Record = $null
    }
    try {
        # These canonical vendor paths are anchored under OS program directories.
        # Hold their names without applying the fixture owner's ACL shape to them.
        foreach ($parent in $parents) {
            $handle = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($parent)
            $tool.Parents.Add(@{ Handle = $handle })
            Assert-StageSameVolume $VolumeIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($handle))
        }
        $named = [ExaCopyQualification.ReadDiffCustody]::HoldNode($Path, $false, $false)
        try {
            $tool.Identity = [ExaCopyQualification.ReadDiffCustody]::Observe($named, $false).FileId
            Assert-StageSameVolume $VolumeIdentity $tool.Identity
            $tool.Image = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            Confirm-PublicationVendorCustody $tool
            $signature = Get-AuthenticodeSignature -LiteralPath $Path
            $signer = if ($null -ne $signature.SignerCertificate) {
                $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            }
            Assert-PublicationVendorSignature ([string]$signature.Status) $signer
            $tool.Record = Read-PublicationApplicationRecord $Path -HeldImage $tool.Image
            $tool.Record['native_identity'] = $tool.Identity
            $tool.Record['signer'] = $signer
        } finally {
            $named.Dispose()
        }
        return $tool
    } catch {
        Close-PublicationVendorCustody $tool
        throw
    }
}

function Confirm-PublicationImage {
    $named = [ExaCopyQualification.ReadDiffCustody]::HoldNode($binary, $false, $false)
    try {
        Assert-StageSameIdentity $imageId ([ExaCopyQualification.ReadDiffCustody]::Observe($named, $false).FileId)
        Assert-StageSameIdentity $imageId ([ExaCopyQualification.ReadDiffCustody]::Observe($image.SafeFileHandle, $false).FileId)
        $image.Position = 0
        if ((Get-FileHash -Algorithm SHA256 -InputStream $image).Hash -cne $imageHash) {
            throw 'The held compiler image digest changed.'
        }
    } finally {
        $named.Dispose()
    }
}

function Invoke-PublicationCases {
    foreach ($item in @(@{ Name = 'inventory'; Flags = @() }, @{ Name = 'ignored'; Flags = @('--ignored') })) {
        Confirm-PublicationImage
        $inventoryArgs = @('--list', '--format', 'terse') + $item.Flags
        if ((Invoke-PublicationChild $item.Name $binary $inventoryArgs 30000) -ne 0) {
            throw 'The held image did not emit a test inventory.'
        }
        Confirm-PublicationImage
    }
    Assert-PublicationInventory (Get-Content -LiteralPath (Join-Path $evidence 'inventory.stdout.log')) `
        (Get-Content -LiteralPath (Join-Path $evidence 'ignored.stdout.log'))
    $cases = Get-PublicationCases
    foreach ($name in @($cases.Ordinary) + @($cases.Native)) {
        $label = 'case-' + $name.Replace('::', '-')
        $flags = @('--exact', $name, '--nocapture', '--test-threads=1')
        if ($name -cin $cases.Native) { $flags += '--ignored' }
        $case = [ordered]@{ selector = $name; ignored = $name -cin $cases.Native; status = 'fail' }
        $state.cases += $case
        try {
            Confirm-PublicationImage
            $exitCode = Invoke-PublicationChild $label $binary $flags 60000
            $output = Get-Content -Raw -LiteralPath (Join-Path $evidence ($label + '.stdout.log'))
            Assert-PublicationResult $name $exitCode $output
            $case.status = 'pass'
        } catch {
            $case.error = $_.Exception.Message
            if (!$state.process_drained) { throw }
        } finally {
            if ($state.process_drained) { Confirm-PublicationImage }
        }
    }
    if (@($state.cases | Where-Object status -ceq 'pass').Count -ne 7) {
        throw 'An exact publication selector failed. Inspect its owned stdout and stderr.'
    }
}

$windows = Get-CimInstance Win32_OperatingSystem
if ($windows.Caption -cnotmatch 'Windows Server 2025' -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne 'X64') {
    throw 'This profile requires Windows Server 2025 on x64.'
}
$root = [IO.DirectoryInfo]::new($env:USERPROFILE).FullName
if ($env:SystemDrive -cnotmatch '\A[A-Za-z]:\z') { throw 'Invalid hosted system-drive identity.' }
$system = $env:SystemDrive + '\'
$drive = [IO.DriveInfo]::new($system)
if ($env:SystemRoot -ine ($system + 'Windows') -or
    [Environment]::SystemDirectory -ine ($system + 'Windows\System32') -or
    !$root.StartsWith($system, [StringComparison]::OrdinalIgnoreCase) -or $root -ieq $system -or
    $drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') {
    throw 'The native fixture requires the hosted Windows fixed NTFS system volume.'
}
[void](Confirm-ExaCopyPath $env:GITHUB_OUTPUT -File)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$ancestors = $evidencePin = $fixturePin = $fixtureGuard = $buildPin = $image = $null
$compilerAncestors = $compilerImage = $null
$linkerTool = $null
$fixture = $evidence = $null
$fixtureCustodied = $false
$evidenceExported = $false
$diagnostic = @{ phase = 'fixture-admission'; receipt = $null; launch = $null }
$state = @{
    profile = $qualification; source_revision = $env:GITHUB_SHA; status = 'fail'; process_drained = $true
    target = $selected; windows = $windows.Caption; build_number = $windows.BuildNumber
    runner_image = $env:ImageVersion; cases = @(); cleanup = 'not-acquired'
}
try {
    $owner = $identity.User
    if (![Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The synthetic hosted fixture requires its runner administrator token.'
    }
    $ancestors = New-StageAncestorCustody $root $owner -HostedSystemVolume $system -BeforeAdmission { param($Held) }
    $volume = [ExaCopyQualification.ReadDiffCustody]::PhysicalNtfsRoot($ancestors.Held[0].Handle)
    Assert-ReadDiffTreeSecurity $root $owner
    $candidate = Join-Path $root ('exacopy-windows-publication-evidence-' + [Guid]::NewGuid().ToString('N'))
    New-StagePrivateFixture $candidate $owner
    $evidencePin = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($candidate)
    $evidenceId = [ExaCopyQualification.DirectoryCustody]::Observe($evidencePin)
    Assert-StageSameVolume $ancestors.Held[0].Identity $evidenceId
    Assert-ReadDiffTreeSecurity $candidate $owner
    Confirm-StageNoResidue $candidate
    Confirm-StageAncestorCustody $ancestors
    $evidence = $candidate

    $state.owner_sid = $owner.Value
    $state.administrator = $true
    $state.physical_ntfs_guid = $volume
    $state.evidence_identity = $evidenceId
    $state.ancestor_identities = @($ancestors.Held | ForEach-Object Identity)
    $state.lockfile_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repo 'Cargo.lock')).Hash
    $state.source_tree = @(& git -C $repo rev-parse --verify 'HEAD^{tree}')
    if ($LASTEXITCODE -ne 0 -or $state.source_tree.Count -ne 1 -or $state.source_tree[0] -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Could not record the source tree object.'
    }
    $state.source_tree = $state.source_tree[0]
    $fileHashes = [ordered]@{}
    foreach ($source in @(
        'crates/platform/exacopy-platform/src/windows/stage/publication/tests.rs',
        'crates/platform/exacopy-platform/src/windows/stage/publication/tests/profile.rs',
        'fixture.toml', 'run.ps1', 'selection.ps1', 'process.cs', 'test_runner.ps1', 'process-controls.ps1'
    )) {
        $sourcePath = if ($source.Contains('/')) { Join-Path $repo $source } else { Join-Path $PSScriptRoot $source }
        $fileHashes[$source] = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourcePath).Hash
    }
    $state.source_inputs = $fileHashes
    $fixture = Join-Path $root ('exacopy-windows-publication-fixture-' + [Guid]::NewGuid().ToString('N'))
    New-StagePrivateFixture $fixture $owner
    $state.cleanup = 'retained-or-unconfirmed'
    $fixturePin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($fixture)
    $fixtureId = [ExaCopyQualification.DirectoryCustody]::Observe($fixturePin)
    $state.fixture_identity = $fixtureId
    Assert-StageSameVolume $ancestors.Held[0].Identity $fixtureId
    Write-StageAclEvidence $fixture $owner 'before' $evidence
    Confirm-StageNoResidue $fixture
    Confirm-StageAncestorCustody $ancestors
    $fixtureCustodied = $true
    # The control first needs an authorized DELETE open without the deny-delete
    # guard. The original fixture pin and trusted ancestor holds remain live.
    try {
        [ExaCopyQualification.DirectoryCustody]::ControlAncestorDeleteSharing($fixture)
    } catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause -is [ComponentModel.Win32Exception]) {
            $state.fixture_sharing_win32_error = $cause.NativeErrorCode
        }
        throw
    }
    $fixtureGuard = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($fixture)
    Assert-StageSameIdentity $fixtureId ([ExaCopyQualification.DirectoryCustody]::Observe($fixtureGuard))
    Write-StageAclEvidence $fixture $owner 'guarded' $evidence
    Confirm-StageNoResidue $fixture
    Confirm-StageAncestorCustody $ancestors

    $build = Join-Path $fixture 'cargo-target'
    New-StagePrivateFixture $build $owner
    $buildPin = [ExaCopyQualification.DirectoryCustody]::HoldFixture($build)
    $buildId = [ExaCopyQualification.DirectoryCustody]::Observe($buildPin)
    $state.build_identity = $buildId
    Assert-StageSameVolume $fixtureId $buildId
    Assert-ReadDiffTreeSecurity $build $owner
    Confirm-StageNoResidue $build
    $rustupHome = [IO.Path]::Combine($root, '.rustup')
    [void](Confirm-ExaCopyPath $rustupHome -AllowMissing)
    $childEnvironment = New-PublicationEnvironment @{
        RUSTUP_HOME = $rustupHome
        CARGO_TARGET_DIR = $build; CARGO_BUILD_BUILD_DIR = $build; CARGO_TERM_COLOR = 'never'
        CARGO_INCREMENTAL = '0'; TEMP = $build; TMP = $build; RUNNER_TEMP = $build
        EXACOPY_WINDOWS_NTFS_ROOT = $fixture; EXPECTED_RUST_HOST = $selected
        RUST_BACKTRACE = '0'; PYTHONDONTWRITEBYTECODE = '1'; RUNNER_OS = 'Windows'; RUNNER_ARCH = 'X64'
        GIT_TERMINAL_PROMPT = '0'; GCM_INTERACTIVE = 'Never'
    }

    $state.tools = [ordered]@{}
    $state.tools.python = Resolve-PublicationApplication 'python.exe'
    $state.tools.bash = Resolve-PublicationApplication 'bash.exe'
    $state.tools.cargo = Resolve-PublicationApplication 'cargo.exe'
    $python = $state.tools.python.path
    $bash = $state.tools.bash.path
    $cargo = $state.tools.cargo.path
    $powershell = (Get-Process -Id $PID).Path
    $nativeControls = Join-Path $evidence 'native-process-controls'
    New-StagePrivateFixture $nativeControls $owner
    Assert-ReadDiffTreeSecurity $nativeControls $owner
    # Compare a known current host image and the selected Python under one
    # unchanged supervisor, working directory and environment before APFS I/O.
    if ((Invoke-PublicationChild 'launch-pwsh' $powershell @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', "Write-Output 'qualification-pwsh'") 30000) -ne 0 -or
        (Get-Content -Raw -LiteralPath (Join-Path $evidence 'launch-pwsh.stdout.log')).TrimEnd() -cne 'qualification-pwsh') {
        throw 'The known hosted PowerShell image did not complete the contained launch oracle.'
    }
    if ((Invoke-PublicationChild 'launch-python' $python @(
        '-B', '-c', 'print("qualification-python")') 30000) -ne 0 -or
        (Get-Content -Raw -LiteralPath (Join-Path $evidence 'launch-python.stdout.log')).TrimEnd() -cne 'qualification-python') {
        throw 'The selected Python image did not complete the contained launch oracle.'
    }
    foreach ($setup in @(
        @{ Name = 'apfs-source'; Program = $python; Args = @('-B', 'tools/apfs_source.py', '--fetch') },
        @{ Name = 'transport-source'; Program = $python; Args = @('-B', 'tools/transport_source.py', '--fetch') },
        @{ Name = 'rust-setup'; Program = $bash; Args = @('.github/ci/install.sh', 'rust') },
        @{ Name = 'locked-fetch'; Program = $cargo; Args = @('+1.100.0', 'fetch', '--locked', '--target', $selected) },
        @{ Name = 'controls'; Program = $powershell;
            Args = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', (Join-Path $PSScriptRoot 'test_runner.ps1')) },
        @{ Name = 'process-controls'; Program = $powershell;
            Args = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', (Join-Path $PSScriptRoot 'process-controls.ps1'),
                '-NativeOutputDirectory', $nativeControls, '-ObserveHostedJobProcesses') }
    )) {
        if ((Invoke-PublicationChild $setup.Name $setup.Program $setup.Args 240000) -ne 0) {
            throw "Pinned qualification setup failed: $($setup.Name)"
        }
    }
    Confirm-PublicationSource $repo $env:GITHUB_SHA
    $diagnostic.phase = 'rustc-admission'
    $diagnostic.receipt = $null
    $diagnostic.launch = $null
    $rustc = Resolve-PublicationCompiler $rustupHome
    $compilerAncestors = New-StageAncestorCustody ([IO.Path]::GetDirectoryName($rustc)) $owner `
        -HostedSystemVolume $system -BeforeAdmission { param($Held) }
    $namedCompiler = [ExaCopyQualification.ReadDiffCustody]::HoldNode($rustc, $false, $false)
    try {
        $compilerId = [ExaCopyQualification.ReadDiffCustody]::Observe($namedCompiler, $false).FileId
        Assert-StageSameVolume $ancestors.Held[0].Identity $compilerId
        $compilerImage = [IO.File]::Open($rustc, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        Assert-StageSameIdentity $compilerId ([ExaCopyQualification.ReadDiffCustody]::Observe($compilerImage.SafeFileHandle, $false).FileId)
        $state.tools.rustc = Read-PublicationApplicationRecord $rustc -HeldImage $compilerImage
        $state.tools.rustc['native_identity'] = $compilerId
    } finally {
        $namedCompiler.Dispose()
    }
    if ((Invoke-PublicationChild 'rustc' $rustc @('-vV') 30000) -ne 0) {
        throw 'The pinned Windows Rust compiler was unavailable.'
    }
    $compiler = Get-Content -Raw -LiteralPath (Join-Path $evidence 'rustc.stdout.log')
    if ($compiler -cnotmatch '(?m)^commit-hash: 0ef1bc386059596dada8fb65b50425aab2ea637a\r?$' -or
        $compiler -cnotmatch '(?m)^host: x86_64-pc-windows-msvc\r?$') {
        throw 'The compiler did not match the pinned native toolchain.'
    }

    $diagnostic.phase = 'msvc-admission'
    $diagnostic.receipt = $diagnostic.launch = $null
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $locator = $programFilesX86 + '\Microsoft Visual Studio\Installer\vswhere.exe'
    $systemIdentity = $ancestors.Held[0].Identity
    $locatorTool = New-PublicationVendorCustody $locator $systemIdentity
    try {
        $state.tools.vswhere = $locatorTool.Record
        if ((Invoke-PublicationChild 'msvc-locator' $locator @('-latest', '-products', '*', '-requires',
            'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath') 30000) -ne 0) {
            throw 'The hosted Visual Studio locator did not complete.'
        }
        Confirm-PublicationVendorCustody $locatorTool
    } finally {
        Close-PublicationVendorCustody $locatorTool
    }
    $visualStudioLines = Get-Content -LiteralPath (Join-Path $evidence 'msvc-locator.stdout.log')
    $visualStudio = Select-PublicationVisualStudio $visualStudioLines $programFiles $programFilesX86
    $devShell = $visualStudio + '\Common7\Tools\Launch-VsDevShell.ps1'
    $msvcScript = @'
$ErrorActionPreference = 'Stop'
& $env:EXACOPY_VS_DEV_SHELL -Arch amd64 -HostArch amd64 -SkipAutomaticLocation *> $null
[Console]::WriteLine((ConvertTo-Json -Compress -InputObject @{
    vc = $env:VCToolsInstallDir
    sdk = $env:WindowsSdkDir
    sdk_version = $env:WindowsSDKLibVersion
}))
'@
    $msvcVariables = @('LIB', 'LIBPATH', 'INCLUDE', 'VCINSTALLDIR', 'VCToolsInstallDir',
        'WindowsSdkDir', 'WindowsSDKVersion', 'VSCMD_VER')
    $publicationEnvironment = $childEnvironment
    $baseEnvironment = [string[]]@($publicationEnvironment | Where-Object { $_.Split('=', 2)[0] -notin $msvcVariables })
    $devShellTool = New-PublicationVendorCustody $devShell $systemIdentity
    try {
        $state.tools.vs_developer_shell = $devShellTool.Record
        $childEnvironment = $baseEnvironment + @(
            "EXACOPY_VS_DEV_SHELL=$devShell"
            ('ProgramData=' + [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
        )
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($msvcScript))
        if ((Invoke-PublicationChild 'msvc-environment' $powershell @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) 60000) -ne 0) {
            throw 'The hosted x64 Visual Studio developer environment did not initialize.'
        }
        Confirm-PublicationVendorCustody $devShellTool
    } finally {
        $childEnvironment = $baseEnvironment
        Close-PublicationVendorCustody $devShellTool
    }
    $msvcLines = Get-Content -LiteralPath (Join-Path $evidence 'msvc-environment.stdout.log')
    $msvc = Select-PublicationMsvc $msvcLines $visualStudio $programFilesX86
    $linker = $msvc.linker
    $linkerTool = New-PublicationVendorCustody $linker $systemIdentity
    $state.tools.linker = $linkerTool.Record

    Confirm-StageAncestorCustody $compilerAncestors
    $basePath = @($baseEnvironment | Where-Object { $_.StartsWith('Path=', [StringComparison]::OrdinalIgnoreCase) })
    if ($basePath.Count -ne 1) { throw 'The contained build requires one inherited PATH assignment.' }
    $childEnvironment = [string[]]@($baseEnvironment | Where-Object { $_.Split('=', 2)[0] -ine 'Path' })
    $childEnvironment += "RUSTC=$rustc"
    $childEnvironment += @(
        "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=$linker"
        ("PATH=" + $msvc.bin + ';' + $basePath[0].Substring(5))
        ('LIB=' + ($msvc.libraries -join ';'))
        ('VCINSTALLDIR=' + $visualStudio + '\VC\')
        ('VSINSTALLDIR=' + $visualStudio + '\')
        ('VCToolsInstallDir=' + $msvc.vc + '\')
        ('WindowsSdkDir=' + $msvc.sdk + '\')
        ('WindowsSDKVersion=' + $msvc.sdk_version + '\')
        'VSCMD_ARG_HOST_ARCH=x64'
        'VSCMD_ARG_TGT_ARCH=x64'
    )
    $arguments = @('+1.100.0', 'test', '--locked', '--offline', '--jobs', '2', '--target', $selected,
        '-p', 'exacopy-platform', '--lib', '--no-default-features', '--features', 'experimental-windows-copy', '--no-run',
        '--message-format=json')
    if ((Invoke-PublicationChild 'cargo-build' $cargo $arguments 480000) -ne 0) {
        throw 'The selected Windows platform library test image did not build.'
    }
    Confirm-PublicationVendorCustody $linkerTool
    Close-PublicationVendorCustody $linkerTool
    $linkerTool = $null
    $childEnvironment = $publicationEnvironment
    Confirm-StageAncestorCustody $compilerAncestors
    Assert-StageSameIdentity $compilerId ([ExaCopyQualification.ReadDiffCustody]::Observe($compilerImage.SafeFileHandle, $false).FileId)
    $compilerImage.Dispose()
    $compilerImage = $null
    Close-StageAncestorCustody $compilerAncestors.Held
    $compilerAncestors = $null
    $ownerPath = Join-Path $repo 'crates/platform/exacopy-platform'
    $manifestPath = Convert-ReadDiffExecutableSeparators ([IO.Path]::GetFullPath((Join-Path $ownerPath 'Cargo.toml')))
    $libraryPath = Convert-ReadDiffExecutableSeparators ([IO.Path]::GetFullPath((Join-Path $ownerPath 'src/lib.rs')))
    $reported = Select-PublicationExecutable (Get-Content -LiteralPath (Join-Path $evidence 'cargo-build.stdout.log')) `
        $manifestPath $libraryPath
    $binary = Resolve-ReadDiffExecutablePath $reported $build
    [void](Confirm-ExaCopyPath $binary -File)
    $image = [IO.File]::Open($binary, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $imageId = [ExaCopyQualification.ReadDiffCustody]::Observe($image.SafeFileHandle, $false).FileId
    Assert-StageSameVolume $fixtureId $imageId
    $imageHash = (Get-FileHash -Algorithm SHA256 -InputStream $image).Hash
    $state.executable = @{ path = $binary; native_identity = $imageId; sha256 = $imageHash }

    try {
        Invoke-PublicationCases
    } finally {
        Confirm-PublicationSource $repo $env:GITHUB_SHA
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repo 'Cargo.lock')).Hash -cne $state.lockfile_sha256) {
            throw 'The reviewed lockfile changed.'
        }
        $state.source_rechecked = $true
    }
    $state.status = 'pass'
} catch {
    $state.error = $_.Exception.Message
} finally {
    try {
        if ($null -ne $image) { $image.Dispose() }
        if ($null -ne $linkerTool) { Close-PublicationVendorCustody $linkerTool }
        if ($null -ne $compilerImage) { $compilerImage.Dispose() }
        if ($null -ne $compilerAncestors) { Close-StageAncestorCustody $compilerAncestors.Held }
        if ($fixtureCustodied -and $state.process_drained) {
            try {
                if ($null -ne $buildPin) {
                    Remove-HeldReadDiffFixture $fixture $build $fixturePin $fixtureGuard $fixtureId $buildPin $buildId $volume $ancestors `
                        -IncludeHiddenBuildEntries -AllowReadOnlyBuildFiles
                } else {
                    Confirm-StageNoResidue $fixture
                    if ($null -ne $fixtureGuard) { $fixtureGuard.Dispose() }
                    Remove-HeldStageFixture $fixture $fixtureId $fixturePin $ancestors $evidence
                    $fixturePin.Dispose()
                }
                if (Get-ExaCopyNodeExists $fixture) { throw 'The fixture name remains occupied after disposal.' }
                $state.cleanup = 'deleted'
            } catch {
                $state.cleanup_error = $_.Exception.Message
            }
        }
        if ($state.cleanup -ne 'deleted') { $state.status = 'fail' }
        if ($evidence) {
            Confirm-StageAncestorCustody $ancestors
            Assert-StageSameIdentity $evidenceId ([ExaCopyQualification.DirectoryCustody]::Observe($evidencePin))
            Assert-ReadDiffTreeSecurity $evidence $owner
            $namedEvidence = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($evidence)
            try {
                Assert-StageSameIdentity $evidenceId ([ExaCopyQualification.DirectoryCustody]::Observe($namedEvidence))
                $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding utf8
                if ($state.process_drained) {
                    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8 -Value (
                        'evidence_path=' + $evidence.Replace([char]92, [char]47))
                    $evidenceExported = $true
                } else {
                    Write-Warning 'Owned process drain is unconfirmed. The fixture and its evidence remain in place.'
                }
            } finally {
                $namedEvidence.Dispose()
            }
        }
    } finally {
        try {
            if ($null -ne $buildPin) { $buildPin.Dispose() }
            if ($null -ne $fixtureGuard) { $fixtureGuard.Dispose() }
            if ($null -ne $fixturePin) { $fixturePin.Dispose() }
            if ($null -ne $evidencePin) { $evidencePin.Dispose() }
            if ($null -ne $ancestors) { Close-StageAncestorCustody $ancestors.Held }
            $identity.Dispose()
        } finally {
            if (!$evidenceExported) { Write-PublicationEvidenceDiagnostic }
        }
    }
}
if ($state.status -cne 'pass') {
    throw ('Fixed NTFS publication qualification failed: ' + $state.error + ' ' + $state.cleanup_error)
}
