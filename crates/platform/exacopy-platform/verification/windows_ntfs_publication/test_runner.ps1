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

function Test-PublicationCompilerSelection {
    $provisioned = 'C:\Users\fixture\.rustup'
    $expected = "$provisioned\toolchains\1.100.0-x86_64-pc-windows-msvc\bin\rustc.exe"
    $checks = [Collections.Generic.List[string]]::new()
    $refuseFile = $false
    $changePath = $false
    function Resolve-ExaCopyWindowsPath {
        param([string] $Path)
        if ($changePath) { return 'C:\different\rustc.exe' }
        return $Path
    }
    function Get-Command { throw 'Compiler selection consulted PATH.' }
    function Confirm-ExaCopyPath {
        param([string] $Path, [switch] $File)
        $checks.Add($Path)
        Require ($File -and $Path -ceq $expected) 'Compiler selection checked an unexpected filesystem path.'
        if ($refuseFile) { throw 'A filesystem component is a reparse point or device.' }
        return $true
    }

    Require ((Resolve-PublicationCompiler $provisioned) -ceq $expected -and $checks.Count -eq 1) (
        'The selected compiler must be the exact provisioned toolchain image.'
    )
    $refuseFile = $true
    $checks.Clear()
    Require-Refusal { Resolve-PublicationCompiler $provisioned } 'redirected compiler path'
    Require ($checks.Count -eq 1) 'A declined compiler image cannot trigger an alternate candidate.'
    $checks.Clear()
    $changePath = $true
    Require-Refusal { Resolve-PublicationCompiler $provisioned } 'noncanonical compiler path'
    Require ($checks.Count -eq 0) 'A changed canonical path must be refused before filesystem admission.'
}
Test-PublicationCompilerSelection

function Test-PublicationMsvcCatalogEnvironment {
    $validated = [Collections.Generic.List[string]]::new()
    $refuse = $false
    function Confirm-PublicationVendorPath {
        param([string] $Path)
        $validated.Add($Path)
        if ($refuse) { throw 'A filesystem component is a reparse point or device.' }
    }
    $commonData = 'C:\ProgramData'
    $settings = @(Get-PublicationMsvcCatalogEnvironment $commonData 'C:\')
    Require ($validated.Count -eq 1 -and $validated[0] -ceq $commonData -and $settings.Count -eq 2 -and
        $settings[0] -ceq "ProgramData=$commonData" -and $settings[1] -ceq "ALLUSERSPROFILE=$commonData") (
        'Only the aliases of the validated OS machine-data directory may be projected.'
    )
    foreach ($foreign in @('', 'ProgramData', 'C:\', 'D:\ProgramData')) {
        Require-Refusal { Get-PublicationMsvcCatalogEnvironment $foreign 'C:\' } 'invalid machine catalog root'
    }
    Require ($validated.Count -eq 1) 'Unrooted or foreign directories must be refused before path admission.'
    $refuse = $true
    Require-Refusal { Get-PublicationMsvcCatalogEnvironment $commonData 'C:\' } 'redirected machine catalog root'
}
Test-PublicationMsvcCatalogEnvironment

function Test-PublicationMsvcSelection {
    $programFiles = 'C:\Program Files'
    $x86 = 'C:\Program Files (x86)'
    $visualStudio = "$programFiles\Microsoft Visual Studio\2030\BuildTools"
    $vc = "$visualStudio\VC\Tools\MSVC\42.7.12345"
    $sdk = "$x86\Windows Kits\10"
    $facts = @{ vc = "$vc\"; sdk = "$sdk\"; sdk_version = '10.0.43210.0\' }
    $held = [Collections.Generic.List[string]]::new()
    $rejectLinker = $false
    function Resolve-ExaCopyWindowsPath { param([string] $Path) $Path }
    function Confirm-ExaCopyPath {
        param([string] $Path, [switch] $File)
        if ($File -and $rejectLinker) { throw 'A filesystem component is a reparse point or device.' }
        if ($File) { $held.Add($Path) }
        return $true
    }
    function Get-Command { throw 'MSVC selection must not search PATH.' }

    Require ((Select-PublicationVisualStudio @($visualStudio) $programFiles $x86) -ceq $visualStudio) (
        'The unique hosted Visual Studio instance must be selected.'
    )
    Require-Refusal { Select-PublicationVisualStudio @() $programFiles $x86 } 'empty Visual Studio catalog result'
    Require-Refusal { Select-PublicationVisualStudio @($visualStudio, $visualStudio) $programFiles $x86 } (
        'ambiguous Visual Studio output'
    )
    Require-Refusal { Select-PublicationVisualStudio @('C:\outside\Tools') $programFiles $x86 } (
        'Visual Studio outside the hosted program directories'
    )
    $encoded = ConvertTo-Json -Compress -InputObject $facts
    $msvc = Select-PublicationMsvc @($encoded) $visualStudio $x86
    $expectedLinker = "$vc\bin\Hostx64\x64\link.exe"
    $expectedLibraries = @("$vc\lib\x64", "$sdk\Lib\10.0.43210.0\ucrt\x64", "$sdk\Lib\10.0.43210.0\um\x64")
    Require ($msvc.linker -ceq $expectedLinker -and $held.Count -eq 1 -and $held[0] -ceq $expectedLinker -and
        ($msvc.libraries -join ';') -ceq ($expectedLibraries -join ';')) (
        'Linker and libraries must come from the observed x64 vendor toolset and SDK version.'
    )
    $rejectLinker = $true
    Require-Refusal { Select-PublicationMsvc @($encoded) $visualStudio $x86 } 'redirected native linker'
    $rejectLinker = $false
    foreach ($bad in @(
        @{ vc = 'C:\Program Files\Git\usr\bin'; sdk = $sdk; sdk_version = '10.0.43210.0' }
        @{ vc = $vc; sdk = 'C:\outside\Windows Kits\10'; sdk_version = '10.0.43210.0' }
        @{ vc = $vc; sdk = "$sdk;C:\foreign"; sdk_version = '10.0.43210.0' }
        @{ vc = $vc; sdk = $sdk; sdk_version = '..\foreign' }
    )) {
        $record = ConvertTo-Json -Compress -InputObject $bad
        Require-Refusal { Select-PublicationMsvc @($record) $visualStudio $x86 } 'invalid toolset or SDK evidence'
    }
    Require-Refusal { Select-PublicationMsvc @($encoded, $encoded) $visualStudio $x86 } 'ambiguous SDK evidence'
}
Test-PublicationMsvcSelection

Assert-PublicationVendorSignature 'Valid' 'Microsoft Corporation'
Require-Refusal { Assert-PublicationVendorSignature 'HashMismatch' 'Microsoft Corporation' } 'changed Microsoft-signed image'
Require-Refusal { Assert-PublicationVendorSignature 'Valid' 'Microsoft Corporation Tools' } 'lookalike vendor signer'
Require-Refusal { Assert-PublicationVendorSignature 'NotSigned' '' } 'unsigned vendor image'

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
$locatorArgs = @('-latest', '-products', '*', '-requires',
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath')
$catalogEnvironment = @('ProgramData=C:\fixture-catalog-root', 'ALLUSERSPROFILE=C:\fixture-catalog-root')
$locatorFacts = Get-PublicationLaunchFacts 'msvc-locator' $python $cwd $locatorArgs $catalogEnvironment
Require ($locatorFacts.argument_count -eq 7 -and
    ($locatorFacts.arguments -join [char]0) -ceq ($locatorArgs -join [char]0) -and
    ($locatorFacts.environment_keys -join ',') -ceq 'ALLUSERSPROFILE,ProgramData' -and
    !($locatorFacts | ConvertTo-Json -Compress).Contains('fixture-catalog-root')) (
    'Retain the exact bounded locator arguments and environment key names without their values.'
)
$long = Get-PublicationLaunchFacts 'apfs-source' ('x' * 261) $cwd @('a' * 129) $environment
Require ($null -eq $long.application -and $long.application_units -eq 261 -and
    $null -eq $long.arguments[0]) 'Do not emit out-of-bound text.'
$sourceText = $runner.Extent.Text
$observedBuild = "Invoke-PublicationChild 'cargo-build' " + '$cargo $arguments 480000 -ObserveBuildProcesses'
Require ($sourceText.Contains($observedBuild, [StringComparison]::Ordinal) -and
    [regex]::Matches($sourceText, '-ObserveBuildProcesses').Count -eq 1) (
    'Only the contained Cargo build gets post-root job process diagnostics.'
)
$compilerInstall = $sourceText.IndexOf('RUSTUP_HOME = $rustupHome', [StringComparison]::Ordinal)
$compilerResolution = $sourceText.IndexOf('$rustc = Resolve-PublicationCompiler $rustupHome', [StringComparison]::Ordinal)
$compilerProbe = $sourceText.IndexOf("'rustc' " + '$rustc' + " @('-vV')", [StringComparison]::Ordinal)
$compilerBinding = $sourceText.IndexOf('$childEnvironment += "RUSTC=$rustc"', [StringComparison]::Ordinal)
$compilerBuild = $sourceText.IndexOf("'cargo-build' " + '$cargo', [StringComparison]::Ordinal)
$msvcLocator = $sourceText.IndexOf("Invoke-PublicationChild 'msvc-locator'", [StringComparison]::Ordinal)
$msvcEnvironment = $sourceText.IndexOf("Invoke-PublicationChild 'msvc-environment'", [StringComparison]::Ordinal)
$linkerHold = $sourceText.IndexOf('New-PublicationVendorCustody $linker $systemIdentity', [StringComparison]::Ordinal)
$linkerBinding = $sourceText.IndexOf('"CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=$linker"', [StringComparison]::Ordinal)
$linkerRelease = $sourceText.IndexOf('Close-PublicationVendorCustody $linkerTool', [StringComparison]::Ordinal)
Require ($msvcLocator -ge 0 -and $msvcLocator -lt $msvcEnvironment -and $msvcEnvironment -lt $linkerHold -and
    $linkerHold -lt $linkerBinding -and $linkerBinding -lt $compilerBuild -and $compilerBuild -lt $linkerRelease) (
    'The contained build must consume the exact held linker selected from the hosted developer environment.'
)
$compilerRelease = $sourceText.IndexOf('$compilerImage.Dispose()', [StringComparison]::Ordinal)
Require ($compilerInstall -ge 0 -and $compilerInstall -lt $compilerResolution -and
    $compilerResolution -lt $compilerProbe -and $compilerProbe -lt $compilerBinding -and
    $compilerBinding -lt $compilerBuild -and $compilerBuild -lt $compilerRelease) (
    'The exact provisioned compiler must stay held through its direct probe and the bound Cargo build.'
)
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

# Prepared output controls are synthetic. They do not run a build or a PE image.
function Test-PreparedPublicationOutput {
    $manifest = 'D:\repo\crates\platform\exacopy-platform\Cargo.toml'
    $source = 'D:\repo\crates\platform\exacopy-platform\src\lib.rs'
    $build = 'C:\fixture\cargo-target'
    $image = "$build\x86_64-pc-windows-msvc\deps/exacopy_platform.exe"
    $imagePath = Convert-ReadDiffExecutableSeparators $image
    $ids = @('platform', 'core', 'model', 'endpoint', 'diff', 'uuid', 'windows-sys', 'windows-link')
    function Resolve-ReadDiffExecutablePath {
        param([string] $Reported, [string] $Build)
        $normalized = Convert-ReadDiffExecutableSeparators $Reported
        if ($Build -cne 'C:\fixture\cargo-target\x86_64-pc-windows-msvc' -or $normalized -cne $imagePath) {
            throw 'Unexpected prepared image path.'
        }
        $normalized
    }

    $events = @()
    foreach ($id in $ids) {
        $events += @{
            reason = 'compiler-artifact'; package_id = $id; fresh = $false; executable = $null
            target = @{ name = $id; kind = @('lib'); crate_types = @('lib') }
            profile = @{
                test = $false; opt_level = '0'; debuginfo = 2
                debug_assertions = $true; overflow_checks = $true
            }
        }
    }
    $events[0].executable = $image
    $events[0].target.name = 'exacopy_platform'
    $events[0].target.src_path = $source
    $events[0].profile.test = $true
    $events[0].features = @('experimental-windows-copy')
    $events[0].manifest_path = $manifest
    $events[0].filenames = @($image)
    $artifacts = @($events | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 8 })
    $finished = '{"reason":"build-finished","success":true}'
    $lines = $artifacts + $finished

    function Select-CapturedImage {
        param([string[]] $Lines)
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Lines -join "`r`n") + "`r`n")
        Select-PreparedPublicationExecutable $bytes $manifest $source $build $ids
    }
    Require ((Select-CapturedImage $lines) -ceq $imagePath) 'The complete closed compiler transcript must admit its selected name.'
    Require-Refusal { Select-CapturedImage $artifacts } 'missing terminal build record'
    Require-Refusal { Select-CapturedImage ($lines + $finished) } 'duplicate terminal build record'
    Require-Refusal { Select-CapturedImage ($lines + $artifacts[2]) } 'record after terminal marker'
    Require-Refusal { Select-CapturedImage ($artifacts + '{"reason":"build-finished","success":false}') } 'unsuccessful build record'
    Require-Refusal { Select-CapturedImage ($artifacts + '{"reason":"build-finished","success":"true"}') } 'non-Boolean build result'
    Require-Refusal { Select-CapturedImage ($artifacts + '{"reason":"build-finished","success":false,"success":true}') } 'duplicate JSON member'
    Require-Refusal { Select-CapturedImage ($artifacts + $artifacts[0] + $finished) } 'duplicate selected artifact'
    Require-Refusal { Select-CapturedImage ($artifacts[0..6] + $finished) } 'missing dependency artifact'
    Require-Refusal { Select-CapturedImage ($artifacts + '{"reason":"build-script-executed","package_id":"platform"}' + $finished) } 'extra producer record'
    $partial = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    Require-Refusal { Select-PreparedPublicationExecutable $partial $manifest $source $build $ids } 'missing final newline'
    $invalid = [byte[]]@(0xc0, 0x80, 0x0a)
    Require-Refusal { Select-PreparedPublicationExecutable $invalid $manifest $source $build $ids } 'invalid UTF-8'
    foreach ($field in @('fresh', 'features', 'manifest_path', 'executable', 'package_id', 'filenames')) {
        $mutant = $events[0].Clone()
        $mutant[$field] = switch ($field) {
            fresh { $true }
            features { ,@('other') }
            manifest_path { 'C:\foreign\Cargo.toml' }
            executable { 'C:\foreign\image.exe' }
            package_id { 'core' }
            filenames { ,@($image, $imagePath) }
        }
        $line = ConvertTo-Json -InputObject $mutant -Compress -Depth 8
        Require-Refusal { Select-CapturedImage (@($line) + $artifacts[1..7] + $finished) } "changed Cargo artifact $field"
    }
    $wrongProfile = $events[0].Clone()
    $wrongProfile.profile = $events[0].profile.Clone()
    $wrongProfile.profile.debuginfo = 0
    $line = ConvertTo-Json -InputObject $wrongProfile -Compress -Depth 8
    Require-Refusal { Select-CapturedImage (@($line) + $artifacts[1..7] + $finished) } 'changed test build profile'
}
Test-PreparedPublicationOutput

function Test-PreparedPublicationCompilerGraph {
    $repository = 'D:\repo'
    $platform = "$repository\crates\platform\exacopy-platform"
    $manifest = "$platform\Cargo.toml"
    $source = "$platform\src\lib.rs"
    $parts = @(
        @{ name = 'exacopy-platform'; dir = $platform; dev = @('exacopy-diff', 'exacopy-endpoint', 'windows-sys'); normal = @('exacopy-endpoint', 'exacopy-model', 'windows-sys') },
        @{ name = 'exacopy-core'; dir = "$repository\crates\foundation\exacopy-core"; normal = @('uuid') },
        @{ name = 'exacopy-model'; dir = "$repository\crates\foundation\exacopy-model"; normal = @('exacopy-core') },
        @{ name = 'exacopy-endpoint'; dir = "$repository\crates\interfaces\exacopy-endpoint"; normal = @('exacopy-core', 'exacopy-model') },
        @{ name = 'exacopy-diff'; dir = "$repository\crates\engines\exacopy-diff"; normal = @('exacopy-endpoint') },
        @{ name = 'uuid'; version = '1.29.3' },
        @{ name = 'windows-sys'; version = '0.61.2'; normal = @('windows-link') },
        @{ name = 'windows-link'; version = '0.2.1' }
    )
    $metadata = @{ version = 1; workspace_root = $repository; packages = @(); resolve = @{ root = 'exacopy-platform'; nodes = @() } }
    foreach ($part in $parts) {
        $package = @{
            id = $part.name; name = $part.name; version = '0.1.0'; source = $null
            manifest_path = "$($part.dir)\Cargo.toml"
            targets = @(@{ kind = @('lib'); crate_types = @('lib'); src_path = "$($part.dir)\src\lib.rs" })
        }
        if ($part.version) {
            $package.version = $part.version
            $package.source = 'registry+https://github.com/rust-lang/crates.io-index'
            $package.manifest_path = "C:\cargo\registry\$($part.name)\Cargo.toml"
        }
        $node = @{ id = $part.name; deps = @(); features = @() }
        if ($part.name -ceq 'exacopy-platform') { $node.features = @('experimental-windows-copy') }
        foreach ($dependency in @(@($part.normal) + @($part.dev) | Where-Object { $_ } | Sort-Object -Unique)) {
            $kinds = @()
            if ($dependency -cin $part.normal) { $kinds += @{ kind = $null } }
            if ($dependency -cin $part.dev) { $kinds += @{ kind = 'dev' } }
            $node.deps += @{ pkg = $dependency; dep_kinds = $kinds }
        }
        $metadata.packages += $package
        $metadata.resolve.nodes += $node
    }
    function Read-FixtureGraph {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $metadata -Depth 16 -Compress))
        Assert-PublicationCompilerGraph $bytes $manifest $source $repository
    }
    $ids = @(Read-FixtureGraph)
    Require ($ids.Count -eq 8 -and $ids[0] -ceq 'exacopy-platform') 'The finite compiler graph must return the selected package first.'
    $original = $metadata.packages[5].targets
    foreach ($kind in @('custom-build', 'proc-macro')) {
        $metadata.packages[5].targets = $original + @(@{ kind = @($kind); crate_types = @($kind) })
        Require-Refusal { Read-FixtureGraph } "unreviewed dependency $kind target"
    }
    $metadata.packages[5].targets = $original
    $metadata.resolve.nodes[5].deps = @(@{ pkg = 'windows-link'; dep_kinds = @(@{ kind = $null }) })
    Require-Refusal { Read-FixtureGraph } 'unreviewed selected compiler edge'
}
Test-PreparedPublicationCompilerGraph

function Test-PreparedPeFixture {
    $bytes = [byte[]]::new(1024)
    function Put16([int] $Offset, [uint16] $Value) { [BitConverter]::GetBytes($Value).CopyTo($bytes, $Offset) }
    function Put32([int] $Offset, [uint32] $Value) { [BitConverter]::GetBytes($Value).CopyTo($bytes, $Offset) }
    Put16 0 0x5A4D
    Put32 0x3C 0x80
    Put32 0x80 0x4550
    Put16 0x84 0x8664
    Put16 0x86 1
    Put16 0x94 112
    Put16 0x96 2
    Put16 0x98 0x20B
    Put32 0xA8 0x1000
    Put32 0xD0 0x2000
    Put32 0xD4 0x200
    Put32 0x110 0x100
    Put32 0x114 0x1000
    Put32 0x118 0x200
    Put32 0x11C 0x200
    Put32 0x12C 0x20000020

    function Check-FixturePe([byte[]] $Payload) {
        $stream = [IO.MemoryStream]::new($Payload, $false)
        try {
            $stream.Position = 3
            Assert-PreparedPublicationPe $stream
            Require ($stream.Position -eq 3 -and $stream.CanRead) 'PE inspection must preserve the held stream.'
        } finally { $stream.Dispose() }
    }
    Check-FixturePe $bytes
    foreach ($mutant in @(
        @{ offset = 0x84; word = 0x014C },
        @{ offset = 0x96; word = 0x2002 },
        @{ offset = 0x98; word = 0x010B },
        @{ offset = 0x94; word = 111 }
    )) {
        $changed = [byte[]]$bytes.Clone()
        [BitConverter]::GetBytes([uint16]$mutant.word).CopyTo($changed, $mutant.offset)
        Require-Refusal { Check-FixturePe $changed } 'unsupported PE role, architecture or extent'
    }
    Require-Refusal { Check-FixturePe $bytes[0..511] } 'short executable section'
}
Test-PreparedPeFixture

function Test-PreparedCargoConfig {
    $repository = $repo
    $cargoHome = [IO.Path]::Combine($repo, '.synthetic-cargo-home')
    $hasConfig = $false
    function Resolve-ExaCopyWindowsPath([string] $Path) { $Path }
    function Confirm-ExaCopyPath([string] $Path, [switch] $File, [switch] $AllowMissing) {
        if ($File) { return $hasConfig -and $Path -ceq [IO.Path]::Combine($cargoHome, 'config.toml') }
        return $Path -ceq $cargoHome
    }
    $environment = @("CARGO_HOME=$cargoHome")
    Assert-PreparedCargoConfiguration $repository $cargoHome $environment
    Require-Refusal { Assert-PreparedCargoConfiguration $repository $cargoHome ($environment + 'RUSTC_WRAPPER=unreviewed') } 'ambient compiler wrapper'
    Require-Refusal { Assert-PreparedCargoConfiguration $repository $cargoHome ($environment + 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER=unreviewed') } 'ambient target runner'
    Require-Refusal { Assert-PreparedCargoConfiguration $repository $cargoHome @('CARGO_HOME=elsewhere') } 'inspected Cargo home differs from child home'
    $hasConfig = $true
    Require-Refusal { Assert-PreparedCargoConfiguration $repository $cargoHome $environment } 'unreviewed Cargo home configuration'
}
Test-PreparedCargoConfig

$modeSwitch = @($runner.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq 'PrepareOwnedCompilerJob' })
Require ($modeSwitch.Count -eq 1 -and $modeSwitch[0].StaticType -eq [Management.Automation.SwitchParameter] -and
    $null -eq $modeSwitch[0].DefaultValue) 'Owned compiler preparation must be an explicit switch with its default off.'
$publicationWorkflow = Get-Content -Raw -LiteralPath (Join-Path $repo '.github/workflows/windows-ntfs-publication.yml')
Require ($publicationWorkflow -cmatch '(?m)^\s*\./crates/platform/exacopy-platform/verification/windows_ntfs_publication/run\.ps1\s*$' -and
    $publicationWorkflow -cnotmatch 'PrepareOwnedCompilerJob') 'The canonical workflow must retain the existing strict invocation.'

$profileDefinition = $runner.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Get-PublicationHostedProfile'
}, $false)
Require ($null -ne $profileDefinition) 'The runner must define hosted profile admission.'
. ([scriptblock]::Create($profileDefinition.Extent.Text))
$strictRef = 'replicraft/ExaCopy/.github/workflows/windows-ntfs-publication.yml@refs/heads/main'
$preparationRef = 'replicraft/ExaCopy/.github/workflows/windows-ntfs-publication-preparation.yml@refs/heads/main'
$strict = Get-PublicationHostedProfile $false $strictRef 'push'
Require ($strict.Profile -ceq 'windows-hosted-server2025-fixed-ntfs-publication-v1' -and
    $strict.Workflow -ceq '.github/workflows/windows-ntfs-publication.yml' -and
    $strict.Manifest -ceq 'crates/platform/exacopy-platform/verification/windows_ntfs_publication/fixture.toml') 'The strict profile must retain its existing manifest, workflow, and name.'
Require ((Get-PublicationHostedProfile $false $strictRef 'workflow_dispatch').Profile -ceq $strict.Profile) 'The strict workflow still accepts its original dispatch event.'
$preparation = Get-PublicationHostedProfile $true $preparationRef 'push'
Require ($preparation.Profile -ceq 'windows-hosted-server2025-fixed-ntfs-publication-owned-preparation-v2' -and
    $preparation.Workflow -ceq '.github/workflows/windows-ntfs-publication-preparation.yml' -and
    $preparation.Manifest -ceq 'crates/platform/exacopy-platform/verification/windows_ntfs_publication_preparation/fixture.toml') 'Preparation must have its own manifest, workflow, and profile.'
Require-Refusal { Get-PublicationHostedProfile $true $strictRef 'push' } 'strict workflow with preparation enabled'
Require-Refusal { Get-PublicationHostedProfile $false $preparationRef 'push' } 'preparation workflow with strict mode'
Require-Refusal { Get-PublicationHostedProfile $true $preparationRef 'workflow_dispatch' } 'manual preparation dispatch'
Require-Refusal { Get-PublicationHostedProfile $true ($preparationRef.Replace('heads/main', 'heads/other')) 'push' } 'preparation on another branch'
Require-Refusal { Get-PublicationHostedProfile $true ($preparationRef.Replace('replicraft/', 'other/')) 'push' } 'preparation from another owner'

$preparationWorkflow = Get-Content -Raw -LiteralPath (Join-Path $repo $preparation.Workflow)
$preparationCommand = '(?m)^          \./crates/platform/exacopy-platform/verification/windows_ntfs_publication/run\.ps1 -PrepareOwnedCompilerJob\r?$'
Require ([regex]::Matches($preparationWorkflow, $preparationCommand).Count -eq 1 -and
    $preparationWorkflow -cmatch '(?m)^  push:\r?$' -and
    $preparationWorkflow -cnotmatch '(?m)workflow_dispatch|workflow_call|pull_request' -and
    $preparationWorkflow -cmatch '(?m)^          name: windows-ntfs-publication-preparation-v2-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}\r?$') 'Preparation must have one fixed push invocation and a separate evidence artifact.'

$prepareDefinition = $runner.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Invoke-OwnedPublicationBuildPreparation'
}, $false)
$strictDefinition = $runner.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Invoke-PublicationChild'
}, $false)
Require ($null -ne $prepareDefinition -and $null -ne $strictDefinition -and
    $prepareDefinition.Extent.Text.Contains('::PreparePublicationBuild(') -and
    !$strictDefinition.Extent.Text.Contains('::PreparePublicationBuild(')) 'Owned compiler preparation must have a distinct native entry point.'
$casesDefinition = $runner.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Invoke-PublicationCases'
}, $false)
$recheckDefinition = $runner.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Confirm-PreparedPublicationSource'
}, $false)
Require ($null -ne $casesDefinition -and $null -ne $recheckDefinition -and
    $recheckDefinition.Extent.Text.Contains('Confirm-PublicationSource') -and
    $recheckDefinition.Extent.Text.Contains('Cargo.lock') -and
    $recheckDefinition.Extent.Text.Contains('lockfile_sha256')) 'Prepared selectors require the exact source and lock digest.'
$casesText = $casesDefinition.Extent.Text
$checkedAt = $casesText.IndexOf('Confirm-PreparedPublicationSource', [StringComparison]::Ordinal)
$selectorAt = $casesText.IndexOf('Invoke-PublicationChild', [StringComparison]::Ordinal)
Require ($checkedAt -ge 0 -and $selectorAt -gt $checkedAt) 'Prepared source and lock must be rechecked before the first selector.'
