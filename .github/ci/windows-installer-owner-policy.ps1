# Bounded redacted projection of the unchanged installer predicates.
function Get-InstallerAncestorPaths {
    param([string] $Path)
    $paths = [Collections.Generic.Stack[string]]::new()
    for ($entry = [IO.DirectoryInfo]::new($Path); $null -ne $entry; $entry = $entry.Parent) {
        if ($paths.Count -ge 32) { throw 'Installer ancestor count exceeds observation bound.' }
        $paths.Push($entry.FullName)
    }
    return ,$paths
}

function Get-InstallerOwnerClass {
    param([string] $Sid, [string] $Current)
    if (!$Sid) { return 'unavailable' }
    if ($Sid -ceq $Current) { return 'current-user' }
    switch -CaseSensitive ($Sid) {
        'S-1-5-18' { 'local-system' }
        'S-1-5-19' { 'local-service' }
        'S-1-5-20' { 'network-service' }
        'S-1-5-32-544' { 'builtin-administrators' }
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' { 'trusted-installer-service' }
        default { 'other' }
    }
}

function Get-InstallerOwnerFailure {
    param([string] $Message)
    switch -CaseSensitive ($Message) {
        'An installation ancestor is outside trusted user or system ownership.' { 'owner-policy' }
        'An installation ancestor admits competing changes by another principal.' { 'competing-dacl-policy' }
        default { 'product-observation-unavailable' }
    }
}

function Get-InstallerCompetingAces {
    param($Acl, [string] $Current, [bool] $Ancestor, [int] $Depth, $Rows)
    $trusted = @($Current, 'S-1-5-18', 'S-1-5-32-544')
    $count = 0
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $single = [pscustomobject]@{ Rule = $rule }
        $single | Add-Member ScriptMethod GetAccessRules { param($Explicit, $Inherited, $Type) $this.Rule }
        try {
            Assert-ExaCopyParentDacl $single $trusted -Ancestor:$Ancestor
            continue
        } catch {
            if ((Get-InstallerOwnerFailure $_.Exception.Message) -cne 'competing-dacl-policy') { throw }
        }
        $count++
        if ($Rows.Count -ge 32) { continue }
        $Rows.Add([ordered]@{
            depth_from_volume_root = $Depth
            trustee_class = Get-InstallerOwnerClass $rule.IdentityReference.Value $Current
            normalized_file_system_mask = '0x{0:x8}' -f [int]$rule.FileSystemRights
            inherited = [bool]$rule.IsInherited
            inheritance_flags = [int]$rule.InheritanceFlags
            propagation_flags = [int]$rule.PropagationFlags
            applies_to_this_directory = $true
        })
    }
    return $count
}

function Get-InstallerRawDaclStatus {
    param([byte[]] $Bytes)
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Bytes, 0)
    if ($null -eq $raw.DiscretionaryAcl -or
        ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) {
        return 'absent-or-null'
    }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
            $ace.AceQualifier -notin @([Security.AccessControl.AceQualifier]::AccessAllowed,
                [Security.AccessControl.AceQualifier]::AccessDenied)) {
            return 'unsupported-form'
        }
    }
    return 'plain'
}
