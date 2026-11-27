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

$payload = [ordered]@{
    phase = 'process-controls'
    process_drained = $false
    cleanup = 'retained-or-unconfirmed'
    receipt = [ordered]@{ Started = $true; Drained = $false; NativeError = 5; Error = '' }
}
$state = @{ process_drained = $payload.process_drained; cleanup = $payload.cleanup }
$diagnostic = @{ phase = $payload.phase; receipt = $payload.receipt }
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

Write-Output 'Windows held publication selector, exact-source, Stage isolation and fallback diagnostic controls passed.'
