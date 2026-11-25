# Closed private Windows launcher layout.
$ExaCopyLauncherNames = @('exacopy.ps1', 'selected', 'owner.marker')
$ExaCopyLauncherScriptLimit = 128KB
$ExaCopyLauncherSelectionLimit = 256
$ExaCopyLauncherReceiptLimit = 512

function Get-ExaCopyLauncherSelection {
    param([string] $Version, [string] $ManifestSha256)
    if ($Version -cnotmatch $ExaCopyVersionPattern -or $ManifestSha256 -cnotmatch $ExaCopyDigestPattern) {
        throw 'Invalid launcher release selection.'
    }
    $text = "schema=exacopy-windows-selection-v1`nversion=$Version`nmanifest_sha256=$ManifestSha256`n"
    return ,[Text.Encoding]::ASCII.GetBytes($text)
}

function Get-ExaCopyLauncherReceipt {
    param([string] $RootOwnerHash, [byte[]] $Selection, [byte[]] $Script)
    if ($RootOwnerHash -cnotmatch $ExaCopyDigestPattern) { throw 'Invalid launcher root ownership hash.' }
    $selectorHash = Get-ExaCopySha256 $Selection
    $scriptHash = Get-ExaCopySha256 $Script
    $text = "schema=exacopy-windows-launcher-v1`nroot_owner_sha256=$RootOwnerHash`nselection_sha256=$selectorHash`nscript_sha256=$scriptHash`n"
    return ,[Text.Encoding]::ASCII.GetBytes($text)
}

function Assert-ExaCopyLauncherBytes {
    param([byte[]] $Expected, [byte[]] $Actual)
    if ($Expected.Length -ne $Actual.Length -or (Get-ExaCopySha256 $Expected) -cne (Get-ExaCopySha256 $Actual)) {
        throw 'Launcher ownership or selected release changed.'
    }
}
