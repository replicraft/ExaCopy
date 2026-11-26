#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Directory,
    [string] $Report = (Join-Path $Directory 'native-signature.txt')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$subject = $env:EXACOPY_WINDOWS_SIGNER_SUBJECT
if ([string]::IsNullOrWhiteSpace($subject)) {
    throw 'Production Windows verification requires EXACOPY_WINDOWS_SIGNER_SUBJECT.'
}
$binary = Join-Path $Directory 'exacopy.exe'
$signature = Get-AuthenticodeSignature -LiteralPath $binary
if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $signature.TimeStamperCertificate -or
    $signature.SignerCertificate.Subject -cne $subject) {
    throw 'The signed Windows CLI did not validate with the approved publisher and a trusted timestamp.'
}
$tool = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
& $tool verify /pa /all /v $binary 2>&1 |
    Set-Content -Encoding utf8 -LiteralPath $Report
if ($LASTEXITCODE -ne 0) {
    throw 'Windows SDK Signature verification failed.'
}
