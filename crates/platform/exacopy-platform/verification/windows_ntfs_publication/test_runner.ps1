$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../../..'))
. (Join-Path $repo '.github/ci/windows-ntfs-read-diff.ps1')
. (Join-Path $PSScriptRoot 'selection.ps1')

function Require {
    param([bool] $Condition, [string] $Description)
    if (!$Condition) { throw $Description }
}

function Require-Refusal {
    param([scriptblock] $Check, [string] $Description)
    try { & $Check | Out-Null } catch { return }
    throw "A negative control was accepted: $Description"
}

# Use genuine ApplicationInfo instances with synthetic Windows paths so
# this exercises the same collection semantics on both portable and native hosts.
$currentPowerShell = (Get-Process -Id $PID).Path
$knownApplication = @(Get-Command -Name $currentPowerShell -CommandType Application -All)[0]
$bindingFlags = [Reflection.BindingFlags]'Instance,NonPublic'
$applicationType = [Management.Automation.ApplicationInfo]
$constructor = $applicationType.GetConstructors($bindingFlags)[0]
$commandContext = $applicationType.GetField('_context', $bindingFlags).GetValue($knownApplication)
function New-SyntheticApplication {
    param([string] $Path)
    $constructor.Invoke(@('python.exe', $Path, $commandContext))
}

function Test-PublicationToolSelection {
    $first = 'C:\hostedtoolcache\windows\Python\3.12.10\x64\python.exe'
    $second = 'C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps\python.exe'
    $firstApplication = New-SyntheticApplication $first
    $secondApplication = New-SyntheticApplication $second
    $simulatedCommands = @($firstApplication, $secondApplication)
    $checked = [Collections.Generic.List[string]]::new()
    $rejectFirst = $false
    function Get-Command {
        param([string] $Name, [string] $CommandType, [switch] $All, [string] $ErrorAction)
        Require ($Name -ceq 'python.exe' -and $CommandType -ceq 'Application' -and $All -and
            $ErrorAction -ceq 'Stop') 'Application discovery must request PATH precedence and exact executable type.'
        $simulatedCommands
    }
    function Resolve-ExaCopyWindowsPath { param([string] $Path) $Path }
    function Read-PublicationApplicationRecord {
        param([string] $Path)
        $checked.Add($Path)
        $attributes = if ($rejectFirst) { [IO.FileAttributes]::ReparsePoint } else { [IO.FileAttributes]::Normal }
        Assert-PublicationApplicationAttributes $attributes
        return @{ path = $Path }
    }
    function Bind-OriginalApplication { param([string] $Program) $Program }
    Require ((Bind-OriginalApplication $simulatedCommands.Source) -ceq "$first $second") (
        'The original member enumeration must reproduce the hosted joined-path failure.'
    )
    $selected = Resolve-PublicationApplication 'python.exe'
    Require ($selected.path -ceq $first -and $checked.Count -eq 1 -and $checked[0] -ceq $first) (
        'The first typed ApplicationInfo must be read as exactly one path.'
    )

    $checked.Clear()
    $rejectFirst = $true
    Require-Refusal { Resolve-PublicationApplication 'python.exe' } 'first PATH application is a reparse point'
    Require ($checked.Count -eq 1 -and $checked[0] -ceq $first) 'Refusal must never inspect the later PATH alias.'
    $checked.Clear()
    $rejectFirst = $false
    $emptySource = New-SyntheticApplication $first
    $emptySource | Add-Member -Force -NotePropertyName Source -NotePropertyValue ''
    foreach ($bad in @(
        [pscustomobject]@{ Source = $first }, $emptySource, (New-SyntheticApplication 'folder\python.exe'),
        (New-SyntheticApplication "$first $second"), (New-SyntheticApplication 'C:\folder\python.cmd'),
        (New-SyntheticApplication 'C:\folder\python.exe:alternate')
    )) {
        $simulatedCommands = @($bad, $secondApplication)
        Require-Refusal { Resolve-PublicationApplication 'python.exe' } 'first PATH result is not an exact available application'
    }
    $simulatedCommands = @()
    Require-Refusal { Resolve-PublicationApplication 'python.exe' } 'no PATH match'
    Require ($checked.Count -eq 0) 'Invalid candidates must be refused before file open.'
}
Test-PublicationToolSelection

foreach ($attributes in @(
    [IO.FileAttributes]::Directory, [IO.FileAttributes]::Device, [IO.FileAttributes]::Offline,
    [IO.FileAttributes]::ReparsePoint, 0x00040000, 0x00400000
)) {
    Require-Refusal { Assert-PublicationApplicationAttributes $attributes } 'nonregular or unavailable application attributes'
}

. (Join-Path $repo 'tools/install/windows/paths.ps1')
# Provider visibility must be opt-in and still inspect every selected stream.
function Test-PublicationHiddenStreamLookup {
    $synthetic = 'C:\fixture\cargo-target\synthetic-source\.git'
    $calls = [Collections.Generic.List[bool]]::new()
    $hidden = $false
    $namedStream = $false
    function Get-Item {
        param([string] $LiteralPath, [string] $Stream, [string] $ErrorAction, [switch] $Force)
        Require ($LiteralPath -ceq $synthetic -and $Stream -ceq '*' -and $ErrorAction -ceq 'Stop') (
            'The exact path and complete stream enumeration must be requested.'
        )
        $calls.Add($PSBoundParameters.ContainsKey('Force') -and $Force)
        if ($hidden -and !$Force) { throw 'hidden fixture entry is not visible by default' }
        [pscustomobject]@{ Stream = ':$DATA' }
        if ($namedStream) { [pscustomobject]@{ Stream = 'preserve:$DATA' } }
    }
    Assert-ExaCopyNoNamedStreams $synthetic
    $hidden = $true
    Require-Refusal { Assert-ExaCopyNoNamedStreams $synthetic } 'hidden visibility must stay opt-in'
    Assert-ExaCopyNoNamedStreams $synthetic -IncludeHidden
    $namedStream = $true
    Require-Refusal { Assert-ExaCopyNoNamedStreams $synthetic -IncludeHidden } 'a hidden entry with named data must be preserved'
    Require (($calls -join ',') -ceq 'False,False,True,True') 'Use Force only for explicitly admitted hidden metadata.'
}
Test-PublicationHiddenStreamLookup

$knownRecord = Read-PublicationApplicationRecord $currentPowerShell
$expected = (Get-FileHash -LiteralPath $currentPowerShell -Algorithm SHA256).Hash
Require ($knownRecord.path -ceq $currentPowerShell -and $knownRecord.bytes -gt 0 -and $knownRecord.sha256 -ceq $expected) (
    'The actual running PowerShell must produce the exact bounded application fingerprint.'
)

$selection = Get-PublicationCases
$manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'fixture.toml')
$manifestCases = @([regex]::Matches($manifest, '(?m)^selector = "([^"]+)"\r?$') |
    ForEach-Object { $_.Groups[1].Value })
Require (($manifestCases -join '.') -ceq ($selection.Native -join '.') -and
    $selection.Native.Count -eq 5 -and $selection.Ordinary.Count -eq 2) 'The runtime and owned profile cases diverged.'
Require (@($manifestCases | Sort-Object -Unique).Count -eq 5) 'The native cases must be independently named.'

$all = @(@($selection.Ordinary) + @($selection.Native) | ForEach-Object { "${_}: test" })
$ignored = @($selection.Native | ForEach-Object { "${_}: test" })
Assert-PublicationInventory $all $ignored
Require-Refusal { Assert-PublicationInventory ($all + $all[-1]) $ignored } 'duplicate inventory'
Require-Refusal { Assert-PublicationInventory $all ($ignored + $all[0]) } 'wrong ordinary ignore state'
Require-Refusal { Assert-PublicationInventory $all $ignored[0..3] } 'missing ignored selector'
$extra = 'windows::stage::publication::tests::unregistered: test'
Require-Refusal { Assert-PublicationInventory ($all + $extra) $ignored } 'extra ordinary selector'
Require-Refusal { Assert-PublicationInventory ($all + $extra) ($ignored + $extra) } 'extra ignored selector'
Assert-PublicationInventory ($all + 'windows::stage::tests::unrelated: test') $ignored

$name = $selection.Native[0]
$good = "running 1 test`r`ntest $name ... ok`r`ntest result: ok. 1 passed; 0 failed; 0 ignored;"
Assert-PublicationResult $name 0 $good
Require-Refusal { Assert-PublicationResult $name 0 ($good -replace ' \.\.\. ok', ' ... ignored') } 'ignored attendance'
Require-Refusal { Assert-PublicationResult $name 0 ($good -replace 'running 1', 'running 0') } 'zero attendance'
Require-Refusal { Assert-PublicationResult $name 0 ($good + "`n" + $good) } 'duplicate case records'
Require-Refusal { Assert-PublicationResult $name 87 $good } 'nonzero native status'
Require-Refusal { Assert-PublicationResult $name $null $good } 'missing process exit'

$path = 'D:\a\ExaCopy\crates\platform\exacopy-platform'
$image = 'C:\fixture\target\a/b.exe'
$event = @{
    reason = 'compiler-artifact'; executable = $image; fresh = $false
    profile = @{ test = $true }; features = @('experimental-windows-copy')
    manifest_path = "$path\Cargo.toml"; filenames = @($image)
    target = @{ name = 'exacopy_platform'; kind = @('lib'); crate_types = @('lib'); src_path = "$path\src/lib.rs" }
}
function Select-FakeImage {
    param([hashtable] $Event, [switch] $Duplicate)
    $records = @($Event | ConvertTo-Json -Compress -Depth 6)
    if ($Duplicate) { $records += $records[0] }
    Select-PublicationExecutable $records "$path\Cargo.toml" "$path\src\lib.rs"
}
Require ((Select-FakeImage $event) -ceq $image) 'One fresh library test image with mixed Cargo path separators must select.'
$bad = $event.Clone()
$bad.fresh = $true
Require-Refusal { Select-FakeImage $bad } 'fresh=false missing'
$bad = $event.Clone()
$bad.filenames = @('C:\foreign.exe')
Require-Refusal { Select-FakeImage $bad } 'executable absent from Cargo output names'
$bad = $event.Clone()
$bad.features = @('experimental-windows-copy', 'experimental-windows-read')
Require-Refusal { Select-FakeImage $bad } 'wider feature profile'
$bad = $event.Clone()
$bad.target = $event.target.Clone()
$bad.target.src_path = "$path\src\..\src\lib.rs"
Require-Refusal { Select-FakeImage $bad } 'noncanonical source path'
$bad = $event.Clone()
$bad.profile = @{ test = $false }
Require-Refusal { Select-FakeImage $bad } 'non-test library binary'
Require-Refusal { Select-FakeImage $event -Duplicate } 'ambiguous Cargo artifact'

$stage = Get-Content -Raw -LiteralPath (Join-Path $repo '.github/ci/windows-ntfs.ps1')
$ordinary = [regex]::Match($stage, "Run-TestLane -Name 'stage_contract_controls' -ExpectedTests (\d+)\s+\x60\r?\n\s*-HarnessArgs @\('([^']+)', '--skip', '([^']+)'\)")
Require $ordinary.Success 'Existing Stage ordinary selector must explicitly exclude the publication subtree.'
Require ($ordinary.Groups[1].Value -ceq '3') 'The existing Stage ordinary count must remain three.'
$stageNames = @(
    'windows::stage::tests::bounded_range_uses_the_model_guard_for_positive_lengths'
    'windows::stage::error::tests::non_file_handle_preserves_the_native_query_failure'
    'windows::stage::error::tests::confirmed_create_refusal_preserves_the_typed_observation_cause'
)
$names = @($stageNames) + @($selection.Ordinary)
$include = $ordinary.Groups[2].Value
$exclude = $ordinary.Groups[3].Value
Require (@($names | Where-Object { $_.Contains($include) }).Count -eq 5) 'The unbounded Stage selector control should see five.'
$filtered = @($names | Where-Object { $_.Contains($include) -and !$_.Contains($exclude) })
Require (($filtered -join '.') -ceq ($stageNames -join '.')) 'Stage must retain only its three existing ordinary controls.'
foreach ($preserved in @(
    "Run-TestLane -Name 'ordinary_ntfs_stage' -ExpectedTests 5",
    "Run-TestLane -Name 'ordinary_ntfs_capture' -ExpectedTests 5",
    "Run-TestLane -Name 'capture_symlink' -ExpectedTests 1",
    "Run-TestLane -Name 'stage_symlinks' -ExpectedTests 2"
)) {
    Require $stage.Contains($preserved) "The existing Stage native selector count changed: $preserved"
}

# The shared cleanup helper and its ACL writer must resolve when Stage is not run.
. (Join-Path $repo '.github/ci/windows-ntfs-custody.ps1')
$heldCleanup = Get-Command Remove-HeldStageFixture -CommandType Function
$aclWriter = Get-Command Write-StageAclEvidence -CommandType Function
Require ($heldCleanup.Parameters.ContainsKey('EvidencePath') -and
    $aclWriter.Parameters.ContainsKey('EvidencePath')) 'Held cleanup must have a callable ACL writer with explicit evidence custody.'

# Exercise the actual ordering and the pre-build cleanup branch without native I/O.
$runnerTokens = $runnerErrors = $null
$runnerAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'run.ps1'), [ref]$runnerTokens, [ref]$runnerErrors)
Require ($runnerErrors.Count -eq 0) 'The publication runner must parse.'
$fixtureCalls = $runnerAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Static -and $node.Arguments.Count -eq 1 -and
        $node.Arguments[0].Extent.Text -ceq '$fixture'
}, $true)
$probe = @($fixtureCalls | Where-Object { $_.Member.Value -ceq 'ControlAncestorDeleteSharing' })
$guard = @($fixtureCalls | Where-Object { $_.Member.Value -ceq 'HoldAncestor' })
Require ($probe.Count -eq 1 -and $guard.Count -eq 1 -and
    $probe[0].Extent.EndOffset -lt $guard[0].Extent.StartOffset) 'The two-sided DELETE probe must precede the persistent fixture guard.'
$build = @($runnerAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'New-StagePrivateFixture' -and
        $node.CommandElements[1].Extent.Text -ceq '$build'
}, $true))
Require ($build.Count -eq 1 -and $guard[0].Extent.EndOffset -lt $build[0].Extent.StartOffset) 'The persistent guard must precede build acquisition.'

$cleanup = @($runnerAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -ceq '$fixtureCustodied -and $state.process_drained'
}, $true))
Require ($cleanup.Count -eq 1) 'Fixture cleanup must require established custody and process drain.'
$cleanupScript = [scriptblock]::Create($cleanup[0].Extent.Text)
function Test-PreBuildCleanup {
    param([bool] $fixtureCustodied, [bool] $Drained, [bool] $Empty, [bool] $Deleted)
    $state = @{ cleanup = 'retained-or-unconfirmed'; process_drained = $Drained }
    $fixture = 'synthetic-fixture'
    $evidence = 'synthetic-evidence'
    $fixtureGuard = $null
    $buildPin = $null
    $fixturePin = [pscustomobject]@{ Closed = $false }
    $fixturePin | Add-Member ScriptMethod Dispose { $this.Closed = $true }
    $calls = [Collections.Generic.List[string]]::new()
    function Confirm-StageNoResidue {
        param([string] $Path)
        Require ($Path -ceq $fixture) 'Cleanup selected a different fixture.'
        if (!$Empty) { throw 'unexpected fixture residue' }
    }
    function Remove-HeldStageFixture {
        param($Path, $FixtureIdentity, $FixturePin, $Ancestors, $EvidencePath)
        Require ($Path -ceq $fixture -and $EvidencePath -ceq $evidence) 'Held cleanup selected the wrong custody or evidence.'
        $calls.Add('nonrecursive-held-cleanup')
    }
    function Get-ExaCopyNodeExists { return $false }
    & $cleanupScript
    Require (($state.cleanup -ceq 'deleted') -eq $Deleted) 'Unexpected cleanup result.'
    Require ($fixturePin.Closed -eq $Deleted -and $calls.Count -eq [int]$Deleted) 'Unexpected disposal effect.'
}
Test-PreBuildCleanup $true $true $true $true
Test-PreBuildCleanup $false $true $true $false
Test-PreBuildCleanup $true $false $true $false
Test-PreBuildCleanup $true $true $false $false

# Generate the actual grandchild launcher without starting a program.
$controlTokens = $controlErrors = $null
$controlAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'process-controls.ps1'), [ref]$controlTokens, [ref]$controlErrors)
Require ($controlErrors.Count -eq 0) 'The process-control script must parse.'
foreach ($functionName in @('Quote-Literal', 'Encode-Script', 'New-GrandchildLaunch')) {
    $definition = $controlAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName
    }, $false)
    Require ($null -ne $definition) 'The grandchild launcher must have its exact source.'
    . ([scriptblock]::Create($definition.Extent.Text))
}
$application = 'C:\Program Files\PowerShell\7\pwsh.exe'
$grandchild = New-GrandchildLaunch 'exit 0'
$noShell = $grandchild.IndexOf('$start.UseShellExecute = $false', [StringComparison]::Ordinal)
$noWindow = $grandchild.IndexOf('$start.CreateNoWindow = $true', [StringComparison]::Ordinal)
$effect = $grandchild.IndexOf('[Diagnostics.Process]::Start($start)', [StringComparison]::Ordinal)
Require ($noShell -ge 0 -and $noWindow -gt $noShell -and $effect -gt $noWindow) (
    'The nested launch must explicitly disable shell execution and console allocation before Process.Start.'
)

$source = [IO.Directory]::CreateTempSubdirectory('exacopy-publication-source-control-')
try {
    $work = $source.FullName
    $path = Join-Path $work 'tracked.txt'
    & git -C $work init --quiet
    Require ($LASTEXITCODE -eq 0) 'Could not initialize the owned source control.'
    Set-Content -LiteralPath $path -Value 'committed synthetic source'
    & git -C $work add -- tracked.txt
    Require ($LASTEXITCODE -eq 0) 'Could not index the owned source control.'
    & git -C $work -c user.name=Qualification -c user.email=fixture@example.invalid -c core.hooksPath=NUL commit --quiet -m Synthetic
    Require ($LASTEXITCODE -eq 0) 'Could not commit the owned source control.'
    $head = @(& git -C $work rev-parse --verify HEAD)
    Require ($LASTEXITCODE -eq 0 -and $head.Count -eq 1) 'Could not identify owned source control.'
    Confirm-PublicationSource $work $head[0]
    Require-Refusal { Confirm-PublicationSource $work ('0' * 40) } 'wrong exact source revision'
    Set-Content -LiteralPath $path -Value 'modified tracked source'
    Require-Refusal { Confirm-PublicationSource $work $head[0] } 'dirty tracked source'
    & git -C $work restore -- tracked.txt
    Require ($LASTEXITCODE -eq 0) 'Could not restore the owned source control.'
    & git -C $work config status.showUntrackedFiles no
    Require ($LASTEXITCODE -eq 0) 'Could not establish the untracked source control.'
    Set-Content -LiteralPath (Join-Path $work 'untracked.txt') -Value 'untracked synthetic source'
    Require-Refusal { Confirm-PublicationSource $work $head[0] } 'untracked source when config hides it'
} finally {
    # Native build custody performs the inode-checked subtree cleanup on
    # Windows. This host-only synthetic repository otherwise has no content
    # beyond the known text and Git-owned object files shown above.
    if (!$IsWindows) {
        $source.Delete($true)
        Require (!$source.Exists -and ![IO.Directory]::Exists($source.FullName)) 'Source control residue remains.'
    }
}

$parseErrors = $null
$tokens = $null
$runnerPath = Join-Path $PSScriptRoot 'run.ps1'
$runner = [Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref] $tokens, [ref] $parseErrors)
Require ($parseErrors.Count -eq 0) 'The exact runner source must parse.'
$fallback = $runner.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -ceq 'Write-PublicationEvidenceDiagnostic'
}, $false)
Require ($null -ne $fallback) 'The runner diagnostic must be defined.'
. ([scriptblock]::Create($fallback.Extent.Text))
$launchFacts = $runner.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -ceq 'Get-PublicationLaunchFacts'
}, $false)
Require ($null -ne $launchFacts) 'The bounded launch diagnostic must be defined.'
. ([scriptblock]::Create($launchFacts.Extent.Text))

$python = 'C:\Program Files\Hosted Python\python.exe'
$cwd = 'D:\a\ExaCopy\ExaCopy'
$argsForApfs = @('-B', 'tools/apfs_source.py', '--fetch')
$environment = @('Path=secret-value-that-must-not-be-retained', 'USERPROFILE=C:\fixture', 'TMP=C:\temp')
$launch = Get-PublicationLaunchFacts 'apfs-source' $python $cwd $argsForApfs $environment
Require ($launch.application -ceq $python -and $launch.working_directory -ceq $cwd -and
    ($launch.arguments -join [char]0) -ceq ($argsForApfs -join [char]0)) 'Keep the exact application, cwd and fixed arguments.'
Require ($launch.environment_count -eq 3 -and
    ($launch.environment_keys -join ',') -ceq 'Path,TMP,USERPROFILE' -and
    $launch.environment_utf16_units -eq (($environment -join [char]0).Length + 2)) 'Only record explicit environment metadata.'
$encodedLaunch = $launch | ConvertTo-Json -Depth 4 -Compress
Require (!$encodedLaunch.Contains('secret-value-that-must-not-be-retained') -and
    !$encodedLaunch.Contains('C:\\fixture')) 'Never retain environment values in a launch diagnostic.'
Require ($null -eq (Get-PublicationLaunchFacts 'other' $python $cwd @('other') $environment)) 'Unselected phases must not record raw arguments.'
$long = Get-PublicationLaunchFacts 'apfs-source' ('x' * 261) $cwd @('a' * 129) $environment
Require ($null -eq $long.application -and $long.application_units -eq 261 -and
    $null -eq $long.arguments[0]) 'Do not emit out-of-bound text.'
$sourceText = $runner.Extent.Text
$knownOffset = $sourceText.IndexOf("Invoke-PublicationChild 'launch-pwsh'", [StringComparison]::Ordinal)
$pythonOffset = $sourceText.IndexOf("Invoke-PublicationChild 'launch-python' `$python", [StringComparison]::Ordinal)
$apfsOffset = $sourceText.IndexOf("Name = 'apfs-source'; Program = `$python", [StringComparison]::Ordinal)
Require ($knownOffset -ge 0 -and $knownOffset -lt $pythonOffset -and $pythonOffset -lt $apfsOffset) (
    'The known image and the exact selected Python must pass the same containment path before APFS setup.'
)

$payload = [ordered]@{
    phase = 'process-controls'
    process_drained = $false
    cleanup = 'retained-or-unconfirmed'
    receipt = [ordered]@{ Started = $true; Drained = $false; NativeError = 5; Error = '' }
}
$state = @{ process_drained = $payload.process_drained; cleanup = $payload.cleanup }
$payload.launch = $launch
$diagnostic = @{ phase = $payload.phase; receipt = $payload.receipt; launch = $launch }
foreach ($errorText in @("synthetic failure`n::error::injected`r`n##[error]other", ('λ' * 5000))) {
    $payload.receipt.Error = $errorText
    $messages = @(Write-PublicationEvidenceDiagnostic 6>&1)
    Require ($messages.Count -eq 1) 'The fallback must write exactly one host line.'
    $line = [string] $messages[0]
    $frame = [regex]::Match($line,
        '\AWindows publication diagnostic json_bytes=(\d+) logged_bytes=(\d+) sha256=([0-9A-F]{64}) base64=([A-Za-z0-9+/]+={0,2})\z')
    Require ($frame.Success) 'Untrusted error text must remain inside a single encoded diagnostic.'
    $expected = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 4 -Compress))
    $actual = [Convert]::FromBase64String($frame.Groups[4].Value)
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expected))
    Require ([int] $frame.Groups[1].Value -eq $expected.Length -and $frame.Groups[3].Value -ceq $digest) (
        'The fallback must identify the exact full diagnostic payload.'
    )
    Require ([int] $frame.Groups[2].Value -eq $actual.Length -and $actual.Length -eq [Math]::Min(4096, $expected.Length) -and
        $line.Length -lt 5700) 'The fallback must obey the log byte limit.'
    Require ([Convert]::ToBase64String([byte[]] $expected[0..($actual.Length - 1)]) -ceq $frame.Groups[4].Value) (
        'The encoded bytes must match the exact serialized prefix.'
    )
}

# Run the production PowerShell branch with a managed stand-in for the native
# supervisor. Its private signature matches the reflection boundary.
$definition = $controlAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-ContainmentControl'
}, $false)
Require ($null -ne $definition) 'The observer refusal control must have its exact source.'
. ([scriptblock]::Create($definition.Extent.Text))

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;

namespace ExaCopyQualification
{
    public static class PublicationProcess
    {
        private static void Run(string program, string[] arguments, string directory, string[] environment,
            string stdout, string stderr, int timeout, bool observe, bool refuse)
        {
            if (program != "selected fixture.exe" ||
                arguments.Length != 5 || arguments[0] != "-NoLogo" || arguments[1] != "-NoProfile" ||
                arguments[2] != "-NonInteractive" || arguments[3] != "-EncodedCommand" ||
                Encoding.Unicode.GetString(Convert.FromBase64String(arguments[4])) != "exit 0" ||
                directory != Path.GetFullPath(directory) ||
                stdout != Path.Join(directory, "reflection-control.stdout.log") ||
                stderr != Path.Join(directory, "reflection-control.stderr.log") ||
                environment.Length != 2 || environment[0] != "A=first" || environment[1] != "B=second" ||
                timeout != 42 || !observe || !refuse)
                throw new InvalidOperationException("Incorrect observer reflection arguments.");
            // Stop before the control writes a receipt or performs native work.
            throw new InvalidOperationException("Reached the typed observer control.");
        }
    }
}
'@

function Require-ObserverBindingResult([string] $Expected) {
    try {
        [void](Invoke-ContainmentControl 'reflection-control' 'exit 0' 42 -RefuseObserver)
    } catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause.Message -ceq $Expected) { return }
        throw
    }
    throw 'The observer binding control did not reach its expected outcome.'
}

$directory = [psobject]::AsPSObject($PSScriptRoot)
$application = [psobject]::AsPSObject('selected fixture.exe')
$allowed = [psobject]::AsPSObject([string[]]@('A=first', 'B=second'))
Require-ObserverBindingResult 'Reached the typed observer control.'

$invalidObserverArguments = 'Observer refusal controls require the selected application, paths, and typed launch vectors.'
$application = [pscustomobject]@{ Path = 'selected fixture.exe' }
Require-ObserverBindingResult $invalidObserverArguments
$application = [psobject]::AsPSObject('selected fixture.exe')
$allowed = [object[]]@('A=first', 'B=second')
Require-ObserverBindingResult $invalidObserverArguments

# Exercise the exact hosted accounting oracle with both full and partial exit
# notifications. Process identity evidence is synthetic on a portable host.
$definition = $controlAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-HostedNestedJob'
}, $false)
Require ($null -ne $definition) 'The hosted process tree oracle must have its exact source.'
. ([scriptblock]::Create($definition.Extent.Text))

function New-NestedFixtureEvidence([bool] $Completed) {
    @{
        ProcessId = [uint32]10; TotalProcessesBeforeResume = 1; TotalProcesses = 4; LimitTerminations = 0
        FixtureObservation = @{
            root = @{ pid = [uint32]10; child_pid = [uint32]20 }
            child = @{ pid = [uint32]20; child_pid = [uint32]0 }
            same_child = $true
            finish = if ($Completed) { @{ pid = [uint32]20; child_pid = [uint32]0 } }
            finish_matches_child = $Completed
        }
        JobProcessEvents = @(
            @{ Kind = 'new-process'; ProcessId = [uint32]10; ParentProcessId = [uint32]1; SelectedImage = $true }
            @{ Kind = 'new-process'; ProcessId = [uint32]30; ParentProcessId = [uint32]10; Image = 'conhost.exe'; SystemConsoleHost = $true }
            @{ Kind = 'new-process'; ProcessId = [uint32]20; ParentProcessId = [uint32]10; SelectedImage = $true }
            @{ Kind = 'new-process'; ProcessId = [uint32]40; ParentProcessId = [uint32]20; Image = 'conhost.exe'; SystemConsoleHost = $true }
            @{ Kind = 'exit-process'; ProcessId = [uint32]10 }
        )
    }
}

$completedEvidence = New-NestedFixtureEvidence $true
$completedEvidence.JobProcessEvents += @(
    @{ Kind = 'exit-process'; ProcessId = [uint32]20 }
    @{ Kind = 'exit-process'; ProcessId = [uint32]30 }
    @{ Kind = 'exit-process'; ProcessId = [uint32]40 }
    @{ Kind = 'active-zero'; ProcessId = [uint32]0 }
)
Assert-HostedNestedJob $completedEvidence 1 $true
$timedEvidence = New-NestedFixtureEvidence $false
$timedEvidence.JobProcessEvents = $timedEvidence.JobProcessEvents[3, 1, 2, 0, 4]
Assert-HostedNestedJob $timedEvidence 1 $false
foreach ($case in @(
    @{ Name = 'unaccounted process'; Change = { param($e) $e.TotalProcesses = 5 } }
    @{ Name = 'missing creation evidence'; Change = { param($e) $e.JobProcessEvents = $e.JobProcessEvents[0..2] } }
    @{ Name = 'duplicate PID'; Change = { param($e) $e.JobProcessEvents[3].ProcessId = [uint32]30 } }
    @{ Name = 'both consoles under one parent'; Change = { param($e) $e.JobProcessEvents[3].ParentProcessId = [uint32]10 } }
    @{ Name = 'lookalike console basename'; Change = { param($e) $e.JobProcessEvents[3].SystemConsoleHost = $false } }
    @{ Name = 'wrong executable'; Change = { param($e) $e.JobProcessEvents[2].SelectedImage = $false } }
    @{ Name = 'unexpected root parent'; Change = { param($e) $e.JobProcessEvents[0].ParentProcessId = [uint32]2 } }
    @{ Name = 'mismatched marker'; Change = { param($e) $e.FixtureObservation.finish.pid = [uint32]30 } }
    @{ Name = 'missing completion marker'; Change = { param($e) $e.FixtureObservation.finish = $null } }
    @{ Name = 'unknown exit'; Change = { param($e) $e.JobProcessEvents[4].ProcessId = [uint32]50 } }
    @{ Name = 'truncated notifications'; Change = { param($e) $e.JobProcessEventsCapped = $true } }
)) {
    $evidence = New-NestedFixtureEvidence $true
    & $case.Change $evidence
    Require-Refusal { Assert-HostedNestedJob $evidence 1 $true } $case.Name
}

Write-Output 'Windows held publication selector, exact-source, Stage isolation, fallback diagnostics and observer binding controls passed.'
Write-Output 'Hosted nested console process tree controls passed.'
