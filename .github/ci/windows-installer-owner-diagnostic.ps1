# No input path or profile override. Report contains categories and no native names.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-HeldInstallerDirectory {
    param([string] $Path)
    $handle = [ExaCopyQualification.InstallerOwnerObservation]::Hold($Path)
    try {
        return [pscustomobject]@{
            Path = $Path
            Handle = $handle
            Identity = [ExaCopyQualification.InstallerOwnerObservation]::ObserveDirectory($handle)
            VolumePath = [ExaCopyQualification.InstallerOwnerObservation]::VolumePath($handle)
        }
    } catch {
        $handle.Dispose()
        throw
    }
}

function Assert-HeldInstallerIdentity {
    param($Entry)
    $fresh = Get-HeldInstallerDirectory $Entry.Path
    try {
        if ($fresh.Identity -cne $Entry.Identity -or $fresh.VolumePath -cne $Entry.VolumePath -or
            [ExaCopyQualification.InstallerOwnerObservation]::ObserveDirectory($Entry.Handle) -cne $Entry.Identity -or
            [ExaCopyQualification.InstallerOwnerObservation]::VolumePath($Entry.Handle) -cne $Entry.VolumePath) {
            throw 'Held directory observation changed.'
        }
    } finally {
        $fresh.Handle.Dispose()
    }
}

$ancestors = [Collections.Generic.List[object]]::new()
$aces = [Collections.Generic.List[object]]::new()
$report = [ordered]@{
    schema = 'exacopy.windows-installer-owner-diagnostic.v1'
    profile = 'current-user-known-localappdata-on-fixed-ntfs-windows-volume-c'
    status = 'blocked'
    product_check_scope = 'local-app-data-ancestor-chain'
    failure_phase = 'diagnostic-setup'
    product_ancestor_result = 'not-observed'
    first_refusal_depth_from_volume_root = $null
    first_refusal = $null
    administrator_enabled = $null
    ancestors = $ancestors
    competing_aces = $aces
    competing_aces_omitted = 0
    qualifies_installer_lifecycle = $false
}
$held = [Collections.Generic.List[object]]::new()
$identity = $null
$system = $null
try {
    . (Join-Path $PSScriptRoot '../../tools/install/windows/paths.ps1')
    . (Join-Path $PSScriptRoot 'windows-installer-owner-policy.ps1')
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-installer-owner-observation.cs')

    $report.failure_phase = 'selected-subject'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $owner = $identity.User
    $report.administrator_enabled = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    $report.failure_phase = 'known-folder'
    $local = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
    $profile = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile))
    $windows = Resolve-ExaCopyWindowsPath ([ExaCopyQualification.InstallerOwnerObservation]::SystemWindowsDirectory())
    if (![IO.Path]::GetPathRoot($local).Equals('C:\', [StringComparison]::OrdinalIgnoreCase) -or
        ![IO.Path]::GetPathRoot($windows).Equals('C:\', [StringComparison]::OrdinalIgnoreCase) -or
        ![IO.Path]::GetPathRoot($profile).Equals('C:\', [StringComparison]::OrdinalIgnoreCase) -or
        !$local.StartsWith($profile.TrimEnd([char]92) + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $profile -ieq 'C:\' -or $windows -ieq 'C:\') {
        throw 'Known folder is outside the selected system-volume profile.'
    }

    $report.failure_phase = 'ancestor-limit'
    $paths = Get-InstallerAncestorPaths $local
    $report.failure_phase = 'physical-ancestry'
    if ($paths.Count -lt 3) { throw 'Known folder ancestry is incomplete.' }
    foreach ($path in $paths) {
        $observation = Get-HeldInstallerDirectory $path
        $held.Add($observation)
        $volume = $held[0].VolumePath
        if ($volume -cnotmatch '\A\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\\z' -or
            !$observation.VolumePath.Equals($volume + $path.Substring(3), [StringComparison]::OrdinalIgnoreCase) -or
            $observation.Identity.Substring(0, 16) -cne $held[0].Identity.Substring(0, 16)) {
            throw 'Physical volume or normalized ancestry changed.'
        }
    }
    if (![ExaCopyQualification.InstallerOwnerObservation]::FixedNtfsVolume($held[0].Handle, $volume) -or
        !($held.Path -icontains $profile)) {
        throw 'The selected profile was outside the observed ancestry.'
    }
    $system = Get-HeldInstallerDirectory $windows
    if (!$system.VolumePath.Equals($volume + $windows.Substring(3), [StringComparison]::OrdinalIgnoreCase) -or
        $system.Identity.Substring(0, 16) -cne $held[0].Identity.Substring(0, 16)) {
        throw 'The OS Windows directory differs from the held volume.'
    }
    Assert-HeldInstallerIdentity $system

    $report.failure_phase = 'descriptor-observation'
    $competing = 0
    $productUnavailable = $false
    for ($depth = $held.Count - 1; $depth -ge 0; $depth--) {
        $entry = $held[$depth]
        $higher = $depth -lt $held.Count - 1
        Assert-HeldInstallerIdentity $entry
        $bytes = [ExaCopyQualification.InstallerOwnerObservation]::SecurityDescriptor($entry.Handle)
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetSecurityDescriptorBinaryForm($bytes, [Security.AccessControl.AccessControlSections]'Owner, Access')
        $rawStatus = Get-InstallerRawDaclStatus $bytes
        $nodeResult = 'accepted'
        try {
            Assert-ExaCopyParentAcl $entry.Path $owner -Ancestor:$higher
        } catch {
            $nodeResult = Get-InstallerOwnerFailure $_.Exception.Message
            if ($nodeResult -ceq 'product-observation-unavailable') { $productUnavailable = $true }
        }
        Assert-HeldInstallerIdentity $entry
        $again = [ExaCopyQualification.InstallerOwnerObservation]::SecurityDescriptor($entry.Handle)
        if (![Linq.Enumerable]::SequenceEqual[byte]($bytes, $again)) {
            throw 'Descriptor changed during observation.'
        }
        if ($report.first_refusal -eq $null -and $nodeResult -cne 'accepted') {
            $report.first_refusal = $nodeResult
            $report.first_refusal_depth_from_volume_root = $depth
        }
        $role = if (!$higher) { 'local-app-data' } elseif ($depth -eq 0) { 'volume-root' }
            elseif ($entry.Path -ieq $profile) { 'user-profile' } else { 'upper-ancestor' }
        $ownerClass = Get-InstallerOwnerClass ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) $owner.Value
        $ownerMatches = $ownerClass -in 'current-user', 'local-system', 'builtin-administrators'
        $count = Get-InstallerCompetingAces $acl $owner.Value $higher $depth $aces
        if (($nodeResult -ceq 'accepted' -and (!$ownerMatches -or $count -ne 0)) -or
            ($nodeResult -ceq 'competing-dacl-policy' -and (!$ownerMatches -or $count -eq 0)) -or
            ($nodeResult -ceq 'owner-policy' -and $ownerMatches)) {
            $report.failure_phase = 'descriptor-policy-disagreement'
            throw 'Held descriptor and named product decision disagree.'
        }
        $competing += $count
        $ancestors.Add([ordered]@{
            depth_from_volume_root = $depth
            role = $role
            owner_class = $ownerClass
            raw_dacl_status = $rawStatus
            product_node_result = $nodeResult
        })
    }
    $report.competing_aces_omitted = $competing - $aces.Count
    Assert-HeldInstallerIdentity $system
    foreach ($entry in $held) { Assert-HeldInstallerIdentity $entry }
    $report.product_ancestor_result = if ($productUnavailable) { 'unavailable' }
        elseif ($report.first_refusal) { 'refused' } else { 'accepted' }
    if ($report.competing_aces_omitted -gt 0) {
        $report.failure_phase = 'ace-limit'
    } elseif ($productUnavailable) {
        $report.failure_phase = 'product-observation'
    } else {
        $report.status = 'observed'
        $report.failure_phase = if ($report.first_refusal) { 'product-ancestor-policy' } else { $null }
    }
} catch {
    # Native errors can embed a private path, ACL or SID. Only emit the closed phase.
} finally {
    if ($null -ne $system) { $system.Handle.Dispose() }
    for ($index = $held.Count - 1; $index -ge 0; $index--) { $held[$index].Handle.Dispose() }
    if ($null -ne $identity) { $identity.Dispose() }
}
$report | ConvertTo-Json -Depth 6
