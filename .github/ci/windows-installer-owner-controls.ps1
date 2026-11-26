Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../tools/install/windows/paths.ps1')
. (Join-Path $PSScriptRoot 'windows-installer-owner-policy.ps1')

function New-SyntheticRule {
    param([string] $Sid, [string] $Rights, [string] $Propagation = 'None', [string] $Kind = 'Allow')
    [pscustomobject]@{
        IdentityReference = [pscustomobject]@{ Value = $Sid }
        FileSystemRights = [Security.AccessControl.FileSystemRights]$Rights
        PropagationFlags = [Security.AccessControl.PropagationFlags]$Propagation
        AccessControlType = [Security.AccessControl.AccessControlType]$Kind
        InheritanceFlags = [Security.AccessControl.InheritanceFlags]::ContainerInherit
        IsInherited = $true
    }
}

$current = 'S-1-5-21-123-456-789-1001'
$foreign = 'S-1-5-21-555-666-777-1002'
$ownerClasses = @{
    $current = 'current-user'
    $foreign = 'other'
    'S-1-5-18' = 'local-system'
    'S-1-5-19' = 'local-service'
    'S-1-5-20' = 'network-service'
    'S-1-5-32-544' = 'builtin-administrators'
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = 'trusted-installer-service'
}
foreach ($case in $ownerClasses.GetEnumerator()) {
    if ((Get-InstallerOwnerClass $case.Key $current) -cne $case.Value) { throw 'Unexpected owner classification.' }
}
if ((Get-InstallerOwnerFailure 'C:\Users\private\unexpected') -cne 'product-observation-unavailable') {
    throw 'Unexpected exception detail classification.'
}

$acl = [pscustomobject]@{
    Rules = @(
        (New-SyntheticRule 'S-1-5-18' 'FullControl'),
        (New-SyntheticRule $foreign 'DeleteSubdirectoriesAndFiles' 'InheritOnly'),
        (New-SyntheticRule $foreign 'DeleteSubdirectoriesAndFiles' 'None' 'Deny'),
        (New-SyntheticRule $foreign 'CreateDirectories'),
        (New-SyntheticRule $foreign 'DeleteSubdirectoriesAndFiles')
    )
}
$acl | Add-Member ScriptMethod GetAccessRules { param($Explicit, $Inherited, $Type) $this.Rules }
$rows = [Collections.Generic.List[object]]::new()
if ((Get-InstallerCompetingAces $acl $current $true 0 $rows) -ne 1 -or $rows.Count -ne 1 -or
    $rows[0].normalized_file_system_mask -cne '0x00000040' -or $rows[0].trustee_class -cne 'other' -or
    !$rows[0].inherited -or !$rows[0].applies_to_this_directory -or $rows[0].propagation_flags -ne 0) {
    throw 'The higher ancestor DACL projection differs from the product predicate.'
}
$rows.Clear()
if ((Get-InstallerCompetingAces $acl $current $false 3 $rows) -ne 2 -or $rows.Count -ne 2) {
    throw 'The immediate parent DACL projection differs from the product predicate.'
}
$rows.Clear()
$acl.Rules = @($acl.Rules[-1]) * 35
if ((Get-InstallerCompetingAces $acl $current $true 0 $rows) -ne 35 -or $rows.Count -ne 32 -or
    (ConvertTo-Json -InputObject @($rows) -Depth 4) -match [regex]::Escape($foreign)) {
    throw 'Unbounded or unredacted diagnostic projection.'
}
$deep = [IO.Path]::GetTempPath()
foreach ($index in 1..33) { $deep = Join-Path $deep 'synthetic' }
$refused = $false
try {
    $null = Get-InstallerAncestorPaths $deep
} catch {
    if ($_.Exception.Message -cne 'Installer ancestor count exceeds observation bound.') { throw }
    $refused = $true
}
if (!$refused -or (Get-InstallerAncestorPaths ([IO.Path]::GetTempPath())).Count -gt 32) {
    throw 'Ancestor observation exceeded its bound.'
}
Write-Output 'Installer owner, product DACL policy, row-limit and redaction controls passed.'
