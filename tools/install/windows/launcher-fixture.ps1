#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'paths.ps1')
. (Join-Path $PSScriptRoot 'release.ps1')
. (Join-Path $PSScriptRoot 'launcher.ps1')

function Assert-LauncherFixtureRefused {
    param([scriptblock] $Action, [string] $Expected)
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike $Expected) { throw }
        return
    }
    throw "Unexpected launch material acceptance: $Expected"
}

$certificate = [byte[]] @(0, 2, 4, 128, 255)
$context = [pscustomobject] @{
    Version = '1.2.3'
    Owner = [pscustomobject] @{ Value = 'S-1-5-21-4-6-8-10' }
    PublisherSha256 = Get-ExaCopySha256 $certificate
    Root = "C:\Users\O'Brien (fixture)\AppData\Local\Programs\ExaCopy"
}
$installation = [pscustomobject] @{
    Signed = [pscustomobject] @{ ManifestHash = ('b' * 64) }
    OwnerBytes = [Text.Encoding]::ASCII.GetBytes('synthetic root owner')
}

$one = Get-ExaCopyLauncherMaterial $context $installation $certificate
$two = Get-ExaCopyLauncherMaterial $context $installation $certificate
foreach ($field in @('Selection', 'Script', 'Receipt')) {
    Assert-ExaCopyLauncherBytes $one.$field $two.$field
}
$selection = [Text.Encoding]::ASCII.GetString($one.Selection)
$expected = "schema=exacopy-windows-selection-v1`nversion=1.2.3`nmanifest_sha256=$('b' * 64)`n"
if ($selection -cne $expected) { throw 'Selector differs from the frozen canonical format.' }

$generated = [Text.UTF8Encoding]::new($false, $true).GetString($one.Script)
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($generated, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw $errors[0] }
if (!$generated.Contains('& $exe @args') -or $generated.Contains($context.Root) -or
    $generated.Contains('Set-ExecutionPolicy') -or $generated.Contains('Invoke-Expression')) {
    throw 'Launcher argument forwarding or trusted-code composition changed.'
}
foreach ($file in @('paths.ps1', 'release.ps1', 'launcher-format.ps1', 'launcher-entry.ps1')) {
    $hash = Get-ExaCopySha256 ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $file)))
    if ($one.Inputs[$file] -cne $hash) { throw "Unbound launcher source input: $file" }
}

$changedSelection = [Text.Encoding]::ASCII.GetBytes($selection.Replace('1.2.3', '1.2.4'))
Assert-LauncherFixtureRefused {
    Assert-ExaCopyLauncherBytes $one.Selection $changedSelection
} '*ownership or selected release changed*'

$context.Version = '1.2.3; exit 0'
Assert-LauncherFixtureRefused {
    Get-ExaCopyLauncherMaterial $context $installation $certificate
} '*Invalid launcher release selection*'
$context.Version = '1.2.3'
Assert-LauncherFixtureRefused {
    Get-ExaCopyLauncherMaterial $context $installation ([byte[]] @(9))
} '*Invalid independently supplied launcher trust*'

foreach ($file in @('lifecycle.ps1', 'launcher.ps1', 'launcher-format.ps1', 'launcher-entry.ps1')) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw $errors[0] }
}
Write-Output ('Launcher material, UTF-8 script AST ({0} statements), selector, trust and conflict fixtures passed.' -f $ast.EndBlock.Statements.Count)
