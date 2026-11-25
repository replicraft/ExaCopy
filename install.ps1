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
    [switch] $Json,
    [switch] $Latest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    . (Join-Path $PSScriptRoot 'tools/install/windows/paths.ps1')
    . (Join-Path $PSScriptRoot 'tools/install/windows/release.ps1')
    . (Join-Path $PSScriptRoot 'tools/install/windows/lifecycle.ps1')
    if ($PSBoundParameters.ContainsKey('OfflineBundle')) {
        if ($Latest) { throw '-Latest and -OfflineBundle are mutually exclusive.' }
        $context = Get-ExaCopyContext $Version $PublisherCert $PublisherSha256 $Scope
        $result = Install-ExaCopySignedVersion $OfflineBundle $context -DryRun:$DryRun
    }
    else {
        if ($PSBoundParameters.ContainsKey('Version') -and $Version -cnotmatch $ExaCopyVersionPattern) {
            throw 'Supply an exact release version in canonical N.N.N form.'
        }
        . (Join-Path $PSScriptRoot 'tools/install/windows/download.ps1')
        . (Join-Path $PSScriptRoot 'tools/install/windows/archive.ps1')
        . (Join-Path $PSScriptRoot 'tools/install/windows/online.ps1')
        $context = Get-ExaCopyContext $Version $PublisherCert $PublisherSha256 $Scope -ResolveLatest
        $result = Install-ExaCopyLatestVersion $context -DryRun:$DryRun
    }
    if ($Json) { $result | ConvertTo-Json -Compress }
    else { Write-Output ('{0} {1} at {2}' -f $result.status, $result.version, $result.path) }
    exit 0
}
catch {
    [Console]::Error.WriteLine('ExaCopy install: ' + $_.Exception.Message)
    exit 1
}
