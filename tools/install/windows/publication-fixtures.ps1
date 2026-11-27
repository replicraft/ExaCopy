#Requires -Version 7.4
# Injected installer observations and launcher failures. Directory moves use the host filesystem.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lifecycle.ps1')

function Resolve-ExaCopyWindowsPath { param($Path) $Path }
function Test-ExaCopyUnderPath { $false }
function Assert-ExaCopyExactEntries {}
function Read-ExaCopyBoundedBytes { ,([byte[]] @(7)) }
function Assert-ExaCopyWindowsFloor {}
function Confirm-ExaCopyArtifact {}
function Assert-ExaCopyContextAncestors {}
function Confirm-ExaCopyPath { param($Path, [switch]$AllowMissing) Test-Path -LiteralPath $Path }
function Read-ExaCopyReleaseFiles { $script:signed }
function Get-ExaCopyOwnerBytes { ,([byte[]] @(7)) }
function Get-ExaCopySha256 { param([byte[]] $Bytes) [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)) }
function Write-ExaCopyNewBytes { param($Path, [byte[]] $Bytes) [IO.File]::WriteAllBytes($Path, $Bytes) }
function New-ExaCopyPrivateStage {
    param($Parent)
    $script:stage = Join-Path $Parent 'private-stage'
    [void][IO.Directory]::CreateDirectory($script:stage)
    $script:stage
}
function Open-ExaCopyInstallation {
    param($Path)
    $manifest = if ($script:scenario -eq 'changed-root' -and $Path -eq $script:context.Root) {
        [pscustomobject] @{ Manifest = [byte[]] @(9); ManifestHash = $script:signed.ManifestHash }
    }
    else { $script:signed }
    return [pscustomobject] @{
        Lease = [IO.MemoryStream]::new()
        Signed = $manifest
        Versions = Join-Path $Path 'versions'
        OwnerBytes = [byte[]] @(7)
        HasLauncher = $false
    }
}
function Get-ExaCopyOwnedVersion {
    param($Context, $Installation)
    $exe = Join-Path (Join-Path $Installation.Versions $Context.Version) 'exacopy.exe'
    if (Test-Path -LiteralPath $exe) { return [pscustomobject] @{ Executable = $exe } }
    return $null
}
function Write-ExaCopyVersionStage {
    param($Path)
    if ($script:scenario -eq 'prepare-failure') { throw 'injected staging error' }
    if ($script:scenario -eq 'missing-version') { return }
    [IO.File]::WriteAllBytes((Join-Path $Path 'exacopy.exe'), [byte[]] @(99))
    if ($script:scenario -eq 'collision') {
        $incumbent = if ($script:repair) { Join-Path (Join-Path $script:context.Root 'versions') $script:context.Version } else { $script:context.Root }
        [void][IO.Directory]::CreateDirectory($incumbent)
        [IO.File]::WriteAllText((Join-Path $incumbent 'incumbent'), 'original')
    }
}
function Publish-ExaCopyLauncher {
    param($Context, $Installation)
    $script:launcherAttempts++
    if ($null -eq (Get-ExaCopyOwnedVersion $Context $Installation)) { throw 'expected version read-back failed' }
    if ($script:scenario -eq 'launcher-failure') { throw 'injected launcher error' }
}

function Test-Fault {
    param($Scenario, $Repair, $Expected, $StagePresent, $PublicPresent, $LauncherAttempts)
    $script:scenario = $Scenario
    $script:repair = $Repair
    $script:launcherAttempts = 0
    $local = Join-Path $Work "$Scenario-$Repair"
    $programs = Join-Path $local 'Programs'
    $script:context = [pscustomobject] @{
        Local = $local; Programs = $programs; Root = Join-Path $programs 'ExaCopy'
        CertificatePath = Join-Path $local 'certificate'; Version = '1.2.3'; Owner = $null
    }
    $bundle = Join-Path $local 'bundle'
    [void][IO.Directory]::CreateDirectory($bundle)
    [void][IO.Directory]::CreateDirectory($programs)
    $public = $script:context.Root
    if ($Repair) {
        $versions = Join-Path $public 'versions'
        [void][IO.Directory]::CreateDirectory($versions)
        $public = Join-Path $versions $script:context.Version
    }
    $result = $null
    $failure = $null
    try { $result = Install-ExaCopySignedVersion $bundle $script:context }
    catch { $failure = $_.Exception.Message }
    if ($Expected) {
        if ($failure -notlike $Expected) { throw "Unexpected ${Scenario} failure: '$failure'" }
    }
    elseif ($null -ne $failure -or $result.status -cne 'installed') {
        throw "Unexpected ${Scenario} success result: $result $failure"
    }
    if ($Expected) {
        $inspectionPaths = if ($StagePresent) {
            $script:stage
            if ($Scenario -eq 'collision') { $public }
        }
        else {
            $public
            Join-Path (Join-Path $script:context.Root 'bin') 'exacopy.ps1'
        }
        foreach ($path in $inspectionPaths) {
            if (!$failure.Contains("'" + $path + "'", [StringComparison]::Ordinal)) {
                throw "Missing inspection path '$path' after $Scenario (repair=$Repair)."
            }
        }
    }
    if ((Test-Path -LiteralPath $script:stage) -ne $StagePresent -or
        (Test-Path -LiteralPath $public) -ne $PublicPresent -or
        $script:launcherAttempts -ne $LauncherAttempts) {
        throw "Unexpected namespace or launcher count after $Scenario (repair=$Repair)"
    }
    if ($Scenario -eq 'collision') {
        if ([IO.File]::ReadAllText((Join-Path $public 'incumbent')) -cne 'original') {
            throw 'The incumbent changed.'
        }
    }
    "PASS $Scenario (repair=$Repair)"
}
$ExaCopyReleaseFiles = @()
$ExaCopyCertLimit = 4096
$signed = [pscustomobject] @{
    Manifest = [byte[]] @(1, 2, 3); Signature = [byte[]] @(4); ManifestHash = 'fixture'
    Release = [pscustomobject] @{ min_os = 0 }
}
$fixture = [IO.Directory]::CreateTempSubdirectory('exacopy-install-publication-')
$Work = $fixture.FullName
try {
    foreach ($repair in @($false, $true)) {
        Test-Fault 'prepare-failure' $repair '*preparation failed before publication*injected staging error*' $true $false 0
        Test-Fault 'collision' $repair '*rename outcome is uncertain*private-stage*' $true $true 0
        Test-Fault 'launcher-failure' $repair '*rename to*completed*injected launcher error*' $false $true 1
        Test-Fault 'success' $repair $null $false $true 1
    }
    Test-Fault 'missing-version' $false '*preparation failed before publication*absent from the install stage*' $true $false 0
    Test-Fault 'changed-root' $false '*rename to*completed*retained release evidence changed*' $false $true 0
}
finally {
    $fixture.Delete($true)
}
