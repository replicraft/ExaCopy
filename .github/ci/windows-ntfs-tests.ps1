[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $LocalNtfsRoot,

    [Parameter(Mandatory)]
    [string] $EvidenceDirectory,

    [ValidateSet('Read', 'Stage')]
    [string] $Mode = 'Read'
)

$ErrorActionPreference = 'Stop'
$evidence = New-Item -ItemType Directory -Path $EvidenceDirectory
$fixture = New-Item -ItemType Directory -Path (Join-Path $evidence.FullName 'source-fixture')

function Invoke-FixtureGit {
    param([string[]] $Arguments)
    & git -C $fixture.FullName @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Git fixture setup failed: $Arguments"
    }
}

function Assert-SourceRefused {
    param([string] $Name, [string] $StatusLine, [string] $DiffLine)
    $logs = Join-Path $evidence.FullName $Name
    $failure = $null
    try {
        & (Join-Path $PSScriptRoot 'windows-ntfs.ps1') -Repository $fixture.FullName `
            -LocalNtfsRoot $LocalNtfsRoot -EvidenceDirectory $logs -Mode $Mode
    } catch {
        $failure = $_
    }
    if ($null -eq $failure -or $failure.Exception.Message -notmatch '^Qualification requires a clean Git checkout') {
        throw "Expected the dirty source refusal for $($Name): $failure"
    }
    $status = Get-Content -Raw -LiteralPath (Join-Path $logs 'candidate_status.stdout.log')
    $diff = Get-Content -Raw -LiteralPath (Join-Path $logs 'candidate_diff.stdout.log')
    if ($status -notmatch $StatusLine -or ($DiffLine -and $diff -notmatch $DiffLine)) {
        throw "The raw candidate evidence for $Name is missing the fixture change."
    }
    if (Test-Path -LiteralPath (Join-Path $logs 'compiler.stdout.log')) {
        throw "The dirty source control $Name reached the toolchain before refusal."
    }
}

try {
    Set-Content -LiteralPath (Join-Path $fixture.FullName 'tracked.txt') -Value 'committed content'
    Invoke-FixtureGit -Arguments @('init', '--quiet')
    Invoke-FixtureGit -Arguments @('add', '--', 'tracked.txt')
    Invoke-FixtureGit -Arguments @('-c', 'user.name=ExaCopy qualification fixture',
        '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'Initialize synthetic source')

    Set-Content -LiteralPath (Join-Path $fixture.FullName 'tracked.txt') -Value 'changed content'
    Assert-SourceRefused -Name 'modified-tracked-source' -StatusLine '(?m)^ M tracked\.txt\r?$' -DiffLine '(?m)^\+changed content\r?$'

    Invoke-FixtureGit -Arguments @('restore', '--', 'tracked.txt')
    Invoke-FixtureGit -Arguments @('config', 'status.showUntrackedFiles', 'no')
    Set-Content -LiteralPath (Join-Path $fixture.FullName 'config.toml') -Value '[build]'
    Assert-SourceRefused -Name 'untracked-source' -StatusLine '(?m)^\?\? config\.toml\r?$'
} finally {
    # Only synthetic files created by this test live here. Keep the run logs.
    [IO.Directory]::Delete($fixture.FullName, $true)
}
