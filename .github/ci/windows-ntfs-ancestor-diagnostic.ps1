# Read-only Stage diagnostics. Only bounded SID and ACL classifications enter artifacts.

function Get-StageOwnerCategory {
    param([string] $Sid, [string] $EffectiveSid)
    if (!$Sid) { return 'unavailable' }
    if ($Sid -ceq $EffectiveSid) { return 'current-user' }
    switch -CaseSensitive ($Sid) {
        'S-1-5-18' { return 'local-system' }
        'S-1-5-32-544' { return 'builtin-administrators' }
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' {
            return 'trusted-installer-service'
        }
        default { return 'other' }
    }
}

function Get-StageAncestorDiagnosticDepths {
    param([int] $Count)

    $maximum = 32
    for ($depth = 0; $depth -lt [Math]::Min($Count, $maximum - 1); $depth++) {
        $depth
    }
    if ($Count -ge $maximum) { $Count - 1 }
}

function Get-StageAncestorDiagnosticSummary {
    param($Observations, [int] $AncestorCount, $Token, [bool] $UsesUserProfile)

    $ancestors = @(foreach ($observation in $Observations) {
        $depth = $observation.Depth
        $role = if ($depth -eq $AncestorCount - 1) { 'fixture-parent' }
            elseif ($depth -eq 0) { 'volume-root' }
            else { 'upper-ancestor' }
        $ownerCategory = Get-StageOwnerCategory $observation.OwnerSid $Token.user_sid
        [ordered]@{
            depth_from_volume_root = $depth
            role = $role
            owner_sid = $observation.OwnerSid
            owner_category = $ownerCategory
            existing_owner_policy_match = if ($ownerCategory -eq 'unavailable') { $null }
                else { $ownerCategory -in 'current-user', 'local-system', 'builtin-administrators' }
            raw_acl_status = $observation.RawAclStatus
            system_directory_allow_ace_present = $observation.SystemAccess
            administrators_directory_allow_ace_present = $observation.AdministratorsAccess
        }
    })
    return [ordered]@{
        schema = 1
        profile = 'synthetic-fixed-local-ntfs-stage'
        parent_selection = if ($UsesUserProfile) { 'current-user-profile' } else { 'explicit-local-root' }
        effective_current_sid = $Token.user_sid
        administrator_enabled = $Token.administrator_enabled
        ancestor_count = $AncestorCount
        ancestors_omitted = $AncestorCount - $Observations.Count
        ancestors = $ancestors
    }
}

function Write-StageAncestorDiagnostic {
    param($Held, $Token, [bool] $UsesUserProfile, [string] $OutputPath)

    # Include the selected parent even when the full ancestry exceeds the
    # diagnostic limit. The original guard still checks every ancestor.
    $observations = @(
        foreach ($depth in (Get-StageAncestorDiagnosticDepths $Held.Count)) {
            $record = [pscustomobject]@{
                Depth = $depth
                OwnerSid = $null
                RawAclStatus = 'unreadable'
                SystemAccess = $null
                AdministratorsAccess = $null
            }
            try {
                $acl = Get-Acl -LiteralPath $Held[$depth].Path -ErrorAction Stop
                $record.OwnerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
                $record.RawAclStatus = 'unsupported'
                Assert-StagePlainAcl $acl
                $record.RawAclStatus = 'plain'
                $access = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
                $allowed = @($access | Where-Object {
                    $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                    ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
                })
                $record.SystemAccess = 'S-1-5-18' -in $allowed.IdentityReference.Value
                $record.AdministratorsAccess = 'S-1-5-32-544' -in $allowed.IdentityReference.Value
            } catch {
                # Report only a stable classification. An exception may include paths.
            }
            $record
        }
    )
    Get-StageAncestorDiagnosticSummary $observations $Held.Count $Token $UsesUserProfile |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath
}
