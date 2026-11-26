$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-ntfs-custody.ps1')
. (Join-Path $PSScriptRoot 'windows-ntfs-ancestor-diagnostic.ps1')

function Assert-Refused {
    param([scriptblock] $Operation, [string] $Expected)
    try {
        & $Operation
    } catch {
        if ($_.Exception.Message -ne $Expected) { throw }
        return
    }
    throw "Expected custody refusal '$Expected'."
}

$original = '0000000000000123:00000000000000000000000000004567'
$sameVolumeReplacement = '0000000000000123:00000000000000000000000000004568'
$otherVolume = '0000000000000124:00000000000000000000000000004567'
Assert-StageSameIdentity $original $original
Assert-StageSameVolume $original $sameVolumeReplacement
$identityRefusal = 'The currently observed NTFS directory is not the held original.'
Assert-Refused { Assert-StageSameIdentity $original $sameVolumeReplacement } $identityRefusal
Assert-Refused { Assert-StageSameIdentity '' '' } $identityRefusal
$volumeRefusal = 'The selected NTFS directory is not on the held root volume.'
Assert-Refused { Assert-StageSameVolume $original $otherVolume } $volumeRefusal
Assert-Refused { Assert-StageSameVolume $original 'invalid' } $volumeRefusal

$script:checks = [Collections.Generic.List[string]]::new()
$script:syntheticFailure = ''
function Assert-ExaCopyExactEntries {
    param([string] $Directory, [string[]] $Names)
    if ($Directory -ne 'synthetic' -or $Names.Count -ne 0) { throw 'Expected a synthetic empty directory.' }
    $script:checks.Add('children')
    if ($script:syntheticFailure -eq 'children') { throw 'Contains an unexpected entry.' }
}
function Assert-ExaCopyNoNamedStreams {
    param([string] $Path)
    if ($Path -ne 'synthetic') { throw 'Expected a synthetic stream observation.' }
    $script:checks.Add('streams')
    if ($script:syntheticFailure -eq 'streams') { throw 'Contains a named stream.' }
}
function Assert-ObservationOrder {
    param([string] $Expected)
    if (($script:checks -join ',') -ne $Expected) { throw 'Unexpected residue checks.' }
    $script:checks.Clear()
}

Confirm-StageNoResidue 'synthetic'
Assert-ObservationOrder 'children,streams'
$script:syntheticFailure = 'children'
Assert-Refused { Confirm-StageNoResidue 'synthetic' } 'Contains an unexpected entry.'
Assert-ObservationOrder 'children'
$script:syntheticFailure = 'streams'
Assert-Refused { Confirm-StageNoResidue 'synthetic' } 'Contains a named stream.'
Assert-ObservationOrder 'children,streams'
Write-Output 'Synthetic custody selector controls passed.'

$user = 'S-1-5-21-1-2-3-1001'
$token = @{ user_sid = $user; administrator_enabled = $true }
$sample = @(
    @{ Depth = 0; OwnerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; RawAclStatus = 'plain'; SystemAccess = $true }
    @{ Depth = 1; OwnerSid = 'S-1-5-32-544'; RawAclStatus = 'unsupported' }
    @{ Depth = 2; OwnerSid = $user; RawAclStatus = 'plain'; AdministratorsAccess = $false }
)
$summary = Get-StageAncestorDiagnosticSummary $sample 3 $token $true
if ($summary.effective_current_sid -cne $user -or !$summary.administrator_enabled -or
    $summary.parent_selection -cne 'current-user-profile' -or
    $summary.ancestors[0].depth_from_volume_root -ne 0 -or $summary.ancestors[0].role -cne 'volume-root' -or
    $summary.ancestors[0].owner_category -cne 'trusted-installer-service' -or
    $summary.ancestors[0].existing_owner_policy_match -or
    !$summary.ancestors[0].system_directory_allow_ace_present -or
    $summary.ancestors[1].raw_acl_status -cne 'unsupported' -or
    $summary.ancestors[2].role -cne 'fixture-parent' -or $summary.ancestors[2].owner_category -cne 'current-user') {
    throw 'Unexpected synthetic Stage ancestor diagnosis.'
}
$deepSample = @(foreach ($depth in (Get-StageAncestorDiagnosticDepths 33)) {
    @{ Depth = $depth; OwnerSid = $user; RawAclStatus = 'plain' }
})
$deep = Get-StageAncestorDiagnosticSummary $deepSample 33 $token $false
if ($deep.ancestors.Count -ne 32 -or $deep.ancestors_omitted -ne 1 -or
    $deep.ancestors[-1].role -cne 'fixture-parent' -or
    $deep.ancestors[-1].depth_from_volume_root -ne 32 -or
    $deep.parent_selection -cne 'explicit-local-root') {
    throw 'Stage ancestor diagnostic exceeded its bound.'
}
Write-Output 'Synthetic Stage ancestor diagnostic controls passed.'
