#Requires -Version 7.4
[CmdletBinding()]
param([string] $Artifact)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.DirectoryInfo]::new($PSScriptRoot).Parent.Parent.Parent.FullName
$production = @('install.ps1', 'uninstall.ps1', 'tools/install/windows/paths.ps1',
    'tools/install/windows/release.ps1', 'tools/install/windows/lifecycle.ps1',
    'tools/install/windows/fixture-tools.ps1', 'tools/install/windows/Lifecycle.Tests.ps1')
foreach ($relative in $production) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $relative), [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw ("Parse error in ${relative}: " + $errors[0].Message) }
}
. (Join-Path $PSScriptRoot 'paths.ps1')
. (Join-Path $PSScriptRoot 'release.ps1')
. (Join-Path $PSScriptRoot 'lifecycle.ps1')

function Assert-Refuses {
    param([scriptblock] $Check, [string] $Message)
    try { [void](& $Check) }
    catch { return }
    throw $Message
}

. (Join-Path $PSScriptRoot 'fixture-tools.ps1')

$fixture = [IO.Directory]::CreateTempSubdirectory('exacopy-installer-fixture-')
$artifactPath = Join-Path $fixture.FullName 'exacopy.exe'
$extraPath = Join-Path $fixture.FullName 'unowned'
$now = [DateTimeOffset]::UtcNow
$publisher = $null
try {
    $publisher = New-FixturePublisher $now
    $rsa = $publisher.SigningKey
    $der = $publisher.Certificate

    $payload = New-ExecutableHeader 0x8664
    $digest = Get-ExaCopySha256 $payload
    $pin = Get-ExaCopySha256 $der
    $epoch = $now.ToUnixTimeSeconds()
    $manifest = New-FixtureManifest $pin $digest $epoch
    $arguments = @{
        Certificate = $der
        PublisherSha256 = $pin
        Version = '1.2.3'
        Target = 'x86_64-pc-windows-msvc'
        UnixNow = $epoch
    }
    $release = Test-FixtureManifest $manifest $rsa $arguments
    if ($release.size -ne 512 -or $release.sequence -ne 7) { throw 'Incorrect signed field projection.' }
    [IO.File]::WriteAllBytes($artifactPath, $payload)
    Confirm-ExaCopyArtifact $artifactPath $release
    Assert-ExaCopyExactEntries $fixture.FullName @('exacopy.exe')
    [IO.File]::WriteAllText($extraPath, 'exact incumbent fixture')
    Assert-Refuses { Assert-ExaCopyExactEntries $fixture.FullName @('exacopy.exe') } 'Unowned entry accepted.'
    if ([IO.File]::ReadAllText($extraPath) -cne 'exact incumbent fixture') { throw 'Unexpected fixture changed.' }
    Assert-Refuses { Read-ExaCopyBoundedBytes $artifactPath 511 } 'Oversized file admitted.'

    $wrong = $arguments.Clone()
    $wrong.PublisherSha256 = '0' * 64
    Assert-Refuses { Test-FixtureManifest $manifest $rsa $wrong } 'Wrong publisher pin admitted.'
    $wrong = $arguments.Clone()
    $wrong.Target = 'aarch64-pc-windows-msvc'
    Assert-Refuses { Test-FixtureManifest $manifest $rsa $wrong } 'Wrong native architecture admitted.'
    $wrong = $arguments.Clone()
    $wrong.Version = '1.2.4'
    Assert-Refuses { Test-FixtureManifest $manifest $rsa $wrong } 'Wrong release version admitted.'
    $wrong = $arguments.Clone()
    $wrong.UnixNow = $epoch + 300
    Assert-Refuses { Test-FixtureManifest $manifest $rsa $wrong } 'Expired release admitted.'
    $wrong.Historical = $true
    [void](Test-FixtureManifest $manifest $rsa $wrong)

    $malformed = @(
        'version=01.2.3', 'artifact=../exacopy.exe', 'artifact=CON.txt',
        'sequence=2147483648', 'size=268435457', 'min_os=10.0.20347', ('publisher_sha256=' + ('0' * 64))
    )
    $original = [Text.Encoding]::ASCII.GetString($manifest)
    foreach ($replacement in $malformed) {
        $key = $replacement.Split('=')[0]
        $changed = [Regex]::Replace($original, "(?m)^${key}=.*$", $replacement)
        if ($changed -ceq $original) { throw 'The malformed fixture was not modified.' }
        Assert-Refuses { Test-FixtureManifest ([Text.Encoding]::ASCII.GetBytes($changed)) $rsa $arguments } 'Invalid signed release admitted.'
    }
    $duplicate = $original.Replace("sequence=7`n", "sequence=7`nsequence=8`n")
    Assert-Refuses { Test-FixtureManifest ([Text.Encoding]::ASCII.GetBytes($duplicate)) $rsa $arguments } 'Duplicate signed field admitted.'
    Assert-Refuses { Test-FixtureManifest ([Text.Encoding]::ASCII.GetBytes($original.TrimEnd([char]10))) $rsa $arguments } 'Missing final LF admitted.'
    $badSignature = $arguments.Clone()
    $badSignature.Manifest = $manifest
    $badSignature.Signature = [byte[]]::new(384)
    Assert-Refuses { Confirm-ExaCopyRelease @badSignature } 'Invalid detached signature admitted.'
    Assert-Refuses { Assert-ExaCopyTrustArguments '1.2.3' '' $pin } 'Missing publisher certificate admitted.'

    $payload[511] = 42
    [IO.File]::WriteAllBytes($artifactPath, $payload)
    Assert-Refuses { Confirm-ExaCopyArtifact $artifactPath $release } 'Tampered artifact accepted.'
    [IO.File]::WriteAllBytes($artifactPath, (New-ExecutableHeader 0xaa64))
    Assert-Refuses { Confirm-ExaCopyArtifact $artifactPath $release } 'Wrong PE machine accepted.'
    foreach ($component in @('CON.txt', 'NUL', 'COM1.txt', 'lpt9', "COM`u{b9}.txt", 'name.', 'name ')) {
        Assert-Refuses { Assert-ExaCopyWindowsComponent $component } 'Ambiguous Windows component admitted.'
    }
    Assert-ExaCopyWindowsComponent 'record.release'
    if (Test-ExaCopyUnderPath 'C:\bundle-other\certificate' 'C:\bundle') { throw 'Path prefix confused with descendant.' }
    if (!(Test-ExaCopyUnderPath 'C:\Bundle\certificate' 'c:\bundle')) { throw 'Path case check failed.' }

    if ($IsWindows) {
        Assert-ExaCopyNoNamedStreams $fixture.FullName
        Assert-ExaCopyNoNamedStreams $artifactPath
        try {
            Set-Content -LiteralPath $artifactPath -Stream 'ExaCopy-UnownedFixture' -Value 'unowned bytes'
            Assert-Refuses { Assert-ExaCopyNoNamedStreams $artifactPath } 'Named file stream accepted.'
            if ((Get-Content -LiteralPath $artifactPath -Stream 'ExaCopy-UnownedFixture' -Raw).Trim() -cne 'unowned bytes') {
                throw 'The verifier changed a named stream.'
            }
        }
        finally {
            Remove-Item -LiteralPath $artifactPath -Stream 'ExaCopy-UnownedFixture' -ErrorAction SilentlyContinue
        }
    }

    if (![string]::IsNullOrEmpty($Artifact)) {
        if (!$IsWindows) { throw '-Artifact host-target verification requires Windows.' }
        $realPath = Resolve-ExaCopyWindowsPath $Artifact
        [void](Confirm-ExaCopyPath $realPath -File)
        $real = [IO.FileStream]::new($realPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $length = $real.Length
            if ($length -le 0 -or $length -gt $ExaCopyArtifactLimit) { throw 'Fixture artifact size is outside the profile.' }
            $realHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($real)).ToLowerInvariant()
        }
        finally { $real.Dispose() }
        $realArgs = $arguments.Clone()
        $realArgs.Target = Get-ExaCopyTarget
        $realManifest = New-FixtureManifest $pin $realHash $epoch $length $realArgs.Target
        $fixtureRelease = Test-FixtureManifest $realManifest $rsa $realArgs
        Confirm-ExaCopyArtifact $realPath $fixtureRelease
        Write-Output 'Exact native CLI artifact passed signed size, digest, and PE-header verification.'
    }
}
finally {
    if ($null -ne $publisher) { $publisher.SigningKey.Dispose() }
    [IO.File]::Delete($artifactPath)
    [IO.File]::Delete($extraPath)
    [IO.Directory]::Delete($fixture.FullName, $false)
}

if (!$IsWindows) {
    $hostExe = [Environment]::ProcessPath
    foreach ($entry in @('install.ps1', 'uninstall.ps1')) {
        $output = & $hostExe -NoProfile -NonInteractive -File (Join-Path $root $entry) -DryRun 2>&1
        if ($LASTEXITCODE -ne 1 -or "$output" -notlike '*require Windows*') {
            throw "Non-Windows platform guard failed for $entry."
        }
    }
}

Write-Output 'PowerShell syntax, signed release, PE header, path, and refusal fixtures passed.'
