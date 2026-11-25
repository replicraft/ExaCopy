#Requires -Version 7.4
[CmdletBinding()]
param(
    [string] $Version,
    [string] $PublisherCert,
    [string] $PublisherSha256,
    [string] $Scope = 'User',
    [switch] $NonInteractive,
    [switch] $DryRun,
    [switch] $Quiesced,
    [switch] $Purge,
    [switch] $Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    if ($Purge) { throw 'Purging profiles, credentials, or jobs is unsupported.' }
    . (Join-Path $PSScriptRoot 'tools/install/windows/paths.ps1')
    . (Join-Path $PSScriptRoot 'tools/install/windows/release.ps1')
    . (Join-Path $PSScriptRoot 'tools/install/windows/lifecycle.ps1')
    $context = Get-ExaCopyContext $Version $PublisherCert $PublisherSha256 $Scope
    $result = Uninstall-ExaCopySignedVersion $context -DryRun:$DryRun -Quiesced:$Quiesced
    if ($Json) { $result | ConvertTo-Json -Compress }
    else { Write-Output ('{0} {1} at {2}' -f $result.status, $result.version, $result.path) }
    exit 0
}
catch {
    [Console]::Error.WriteLine('ExaCopy uninstall: ' + $_.Exception.Message)
    exit 1
}
