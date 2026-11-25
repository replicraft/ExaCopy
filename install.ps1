#Requires -Version 7.4
[CmdletBinding()]
param(
    [string] $OfflineBundle,
    [string] $Version,
    [string] $PublisherCert,
    [string] $PublisherSha256,
    [string] $Scope = 'User',
    [switch] $CliOnly,
    [switch] $NonInteractive,
    [switch] $DryRun,
    [switch] $Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    . (Join-Path $PSScriptRoot 'tools/install/windows/paths.ps1')
    . (Join-Path $PSScriptRoot 'tools/install/windows/release.ps1')
    . (Join-Path $PSScriptRoot 'tools/install/windows/lifecycle.ps1')
    $context = Get-ExaCopyContext $Version $PublisherCert $PublisherSha256 $Scope
    $result = Install-ExaCopySignedVersion $OfflineBundle $context -DryRun:$DryRun
    if ($Json) { $result | ConvertTo-Json -Compress }
    else { Write-Output ('{0} {1} at {2}' -f $result.status, $result.version, $result.path) }
    exit 0
}
catch {
    [Console]::Error.WriteLine('ExaCopy install: ' + $_.Exception.Message)
    exit 1
}
