# Sourced by the installer and uninstaller from the trusted distribution.
$ExaCopyLauncherSources = $PSScriptRoot
. (Join-Path $PSScriptRoot 'launcher-format.ps1')

function Get-ExaCopyLauncherMaterial {
    param($Context, $Installation, [byte[]] $Certificate)

    $manifestHash = $Installation.Signed.ManifestHash
    $selection = Get-ExaCopyLauncherSelection $Context.Version $manifestHash
    $ownerHash = Get-ExaCopySha256 $Installation.OwnerBytes
    if ($Context.Owner.Value -cnotmatch '\AS-[0-9]+(?:-[0-9]+)+\z' -or
        $Context.PublisherSha256 -cnotmatch $ExaCopyDigestPattern -or
        $Certificate.Length -eq 0 -or $Certificate.Length -gt $ExaCopyCertLimit -or
        (Get-ExaCopySha256 $Certificate) -cne $Context.PublisherSha256) {
        throw 'Invalid independently supplied launcher trust.'
    }
    $unicode = [Text.UnicodeEncoding]::new($false, $false, $true)
    $rootLabel = [Convert]::ToBase64String($unicode.GetBytes($Context.Root))
    $launcherCertificate = [Convert]::ToBase64String($Certificate)
    # Interpolated values are fixed hexadecimal, numeric, SID or Base64 tokens.
    $preamble = @"
#Requires -Version 7.4
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$ExaCopyLauncherVersion = '$($Context.Version)'
`$ExaCopyLauncherManifestHash = '$manifestHash'
`$ExaCopyLauncherRootOwnerHash = '$ownerHash'
`$ExaCopyLauncherRootLabel = '$rootLabel'
`$ExaCopyLauncherSid = '$($Context.Owner.Value)'
`$ExaCopyLauncherPublisherPin = '$($Context.PublisherSha256)'
`$ExaCopyLauncherCertificate = '$launcherCertificate'
"@
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $fragments = [Collections.Generic.List[string]]::new()
    $fragments.Add($preamble)
    $inputs = [ordered]@{}
    foreach ($name in @('paths.ps1', 'release.ps1', 'launcher-format.ps1', 'launcher-entry.ps1')) {
        $bytes = Read-ExaCopyBoundedBytes (Join-Path $ExaCopyLauncherSources $name) $ExaCopyLauncherScriptLimit
        $inputs[$name] = Get-ExaCopySha256 $bytes
        $fragments.Add($utf8.GetString($bytes))
    }
    $scriptBytes = $utf8.GetBytes([string]::Join([char]10, $fragments))
    if ($scriptBytes.Length -gt $ExaCopyLauncherScriptLimit) {
        throw 'Launcher script exceeds its bound.'
    }
    return [pscustomobject]@{
        Selection = $selection
        Script = $scriptBytes
        Receipt = Get-ExaCopyLauncherReceipt $ownerHash $selection $scriptBytes
        Inputs = $inputs
    }
}

function Confirm-ExaCopyLauncherDirectory {
    param([string] $Path, $Material, $Owner, [switch] $ForRemoval)
    Confirm-ExaCopyOwnerAcl $Path $Owner -Root
    Assert-ExaCopyExactEntries $Path $ExaCopyLauncherNames
    $script = Join-Path $Path 'exacopy.ps1'
    $selector = Join-Path $Path 'selected'
    $receipt = Join-Path $Path 'owner.marker'
    Assert-ExaCopyLauncherBytes $Material.Script (Read-ExaCopyBoundedBytes $script $ExaCopyLauncherScriptLimit)
    Assert-ExaCopyLauncherBytes $Material.Selection (Read-ExaCopyBoundedBytes $selector $ExaCopyLauncherSelectionLimit)
    Assert-ExaCopyLauncherBytes $Material.Receipt (Read-ExaCopyBoundedBytes $receipt $ExaCopyLauncherReceiptLimit)
    if ($ForRemoval) {
        foreach ($entry in @($Path, $script, $selector, $receipt)) {
            Assert-ExaCopyNoNamedStreams $entry
        }
    }
}

function Publish-ExaCopyLauncher {
    param($Context, $Installation, [byte[]] $Certificate)
    $destination = Join-Path $Context.Root 'bin'
    if ($null -eq (Get-ExaCopyOwnedVersion $Context $Installation)) {
        throw 'The signed version is absent. Launcher publication refused.'
    }
    $material = Get-ExaCopyLauncherMaterial $Context $Installation $Certificate
    if (Confirm-ExaCopyPath $destination -AllowMissing) {
        Confirm-ExaCopyLauncherDirectory $destination $material $Context.Owner
        return
    }

    $stage = New-ExaCopyPrivateStage $Context.Programs $Context.Owner
    try {
        Write-ExaCopyNewBytes (Join-Path $stage 'exacopy.ps1') $material.Script
        Write-ExaCopyNewBytes (Join-Path $stage 'selected') $material.Selection
        Write-ExaCopyNewBytes (Join-Path $stage 'owner.marker') $material.Receipt
        Confirm-ExaCopyLauncherDirectory $stage $material $Context.Owner
        # Lifecycle holds the root owner lease, after completed version publication.
        if ($null -eq (Get-ExaCopyOwnedVersion $Context $Installation)) {
            throw 'The signed version is absent. Launcher publication refused.'
        }
        Assert-ExaCopyInstallAncestors $Context.Programs $Context.Owner
        Confirm-ExaCopyOwnerAcl $Context.Root $Context.Owner -Root
        [IO.Directory]::Move($stage, $destination)
        Confirm-ExaCopyLauncherDirectory $destination $material $Context.Owner
    }
    catch {
        throw "Launcher publication could not be confirmed. Inspect '$stage' and '$destination'. $($_.Exception.Message)"
    }
}

function Remove-ExaCopyLauncher {
    param($Context, $Installation, [byte[]] $Certificate, [switch] $DryRun)
    $destination = Join-Path $Context.Root 'bin'
    if (!(Confirm-ExaCopyPath $destination -AllowMissing)) { return }
    $material = Get-ExaCopyLauncherMaterial $Context $Installation $Certificate
    Confirm-ExaCopyLauncherDirectory $destination $material $Context.Owner -ForRemoval
    if ($DryRun) { return }

    Assert-ExaCopyInstallAncestors $Context.Programs $Context.Owner
    Confirm-ExaCopyOwnerAcl $Context.Root $Context.Owner -Root
    $retired = Join-Path $Context.Programs ('.ExaCopy-launcher-retired-' + [Guid]::NewGuid().ToString('N'))
    try {
        # Withdraw the whole selection at once. Partial cleanup cannot shadow a later launcher.
        [IO.Directory]::Move($destination, $retired)
        Confirm-ExaCopyLauncherDirectory $retired $material $Context.Owner -ForRemoval
        foreach ($name in $ExaCopyLauncherNames) {
            [IO.File]::Delete((Join-Path $retired $name))
        }
        [IO.Directory]::Delete($retired, $false)
    }
    catch {
        throw "Launcher withdrawal could not be confirmed. Inspect '$retired' and '$destination'. $($_.Exception.Message)"
    }
}
