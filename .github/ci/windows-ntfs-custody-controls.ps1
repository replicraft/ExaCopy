$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-ntfs-custody.ps1')

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
