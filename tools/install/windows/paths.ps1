function Resolve-ExaCopyWindowsPath {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'A required local filesystem path is missing.'
    }
    $location = Get-Location
    if ($location.Provider.Name -cne 'FileSystem') {
        throw 'Run the offline installer from a filesystem location.'
    }
    foreach ($component in ($Path -split '[\\/]')) {
        if ($component.Length -ne 0 -and $component -cnotmatch '\A[A-Za-z]:\z') {
            Assert-ExaCopyWindowsComponent $component
        }
    }
    $full = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path, $location.ProviderPath))
    if ($full -cnotmatch '\A[A-Za-z]:\\[^:\x00-\x1f]*\z') {
        throw 'Only normal absolute local drive paths are supported.'
    }
    foreach ($component in $full.Substring(3).Split([char]92)) {
        Assert-ExaCopyWindowsComponent $component
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') {
        throw 'The first Windows offline profile requires a local fixed NTFS volume.'
    }
    return $full
}

function Assert-ExaCopyWindowsComponent {
    param([string] $Component)
    if ($Component -in '.', '..') { return }
    if ($Component.EndsWith('.') -or $Component.EndsWith(' ') -or $Component -match '[<>:"|?*\x00-\x1f]' -or
        $Component -match '\A(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9\u00b9\u00b2\u00b3]) *(?:\.|\z)') {
        throw 'Ambiguous Windows pathname components or reserved device names are unsupported.'
    }
}

function Confirm-ExaCopyPath {
    param([string] $Path, [switch] $File, [switch] $AllowMissing)

    $ancestors = [Collections.Generic.List[string]]::new()
    $current = $Path
    while ($null -ne $current) {
        $ancestors.Add($current)
        $parent = [IO.Directory]::GetParent($current)
        $current = if ($null -eq $parent) { $null } else { $parent.FullName }
    }
    for ($i = $ancestors.Count - 1; $i -ge 0; $i--) {
        try {
            $attributes = [IO.File]::GetAttributes($ancestors[$i])
        }
        catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {
            if ($AllowMissing -and $i -eq 0) { return $false }
            throw
        }
        if (($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Device)) -ne 0) {
            throw 'A filesystem component is a reparse point or device.'
        }
        $directory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
        if ($directory -eq ($File -and $i -eq 0)) {
            throw 'A filesystem component has an unexpected type.'
        }
    }
    return $true
}

function Get-ExaCopyNodeExists {
    param([string] $Path)
    try {
        [void][IO.File]::GetAttributes($Path)
        return $true
    }
    catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {
        return $false
    }
}

function Assert-ExaCopyExactEntries {
    param([string] $Directory, [string[]] $Names)
    $missing = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Names) { [void]$missing.Add($name) }
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($Directory)) {
        if (!$missing.Remove([IO.Path]::GetFileName($entry))) {
            throw 'Directory contains an unexpected entry.'
        }
    }
    if ($missing.Count -ne 0) {
        throw 'Directory lacks one or more required entries.'
    }
}

function Read-ExaCopyBoundedBytes {
    param([string] $Path, [int] $Limit)
    [void](Confirm-ExaCopyPath $Path -File)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        return ,(Read-ExaCopyStreamBytes $stream $Limit)
    }
    finally {
        $stream.Dispose()
    }
}

function Read-ExaCopyStreamBytes {
    param([IO.FileStream] $Stream, [int] $Limit)
    $size = $Stream.Length
    if ($size -le 0 -or $size -gt $Limit) {
        throw 'A required installer file is empty or exceeds its byte limit.'
    }
    $bytes = [byte[]]::new([int]$size)
    $Stream.ReadExactly($bytes, 0, $bytes.Length)
    if ($Stream.ReadByte() -ne -1) {
        throw 'An installer input changed while being read.'
    }
    return ,$bytes
}

function Write-ExaCopyNewBytes {
    param([string] $Path, [byte[]] $Bytes)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Confirm-ExaCopyOwnerAcl {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner, [switch] $Root)
    [void](Confirm-ExaCopyPath $Path)
    $directory = [IO.DirectoryInfo]::new($Path)
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    $acl = [IO.FileSystemAclExtensions]::GetAccessControl($directory, $sections)
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $Owner.Value -or
        ($Root -and !$acl.AreAccessRulesProtected)) {
        throw 'Installation directory is not owned and protected by the current user.'
    }
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -cne $Owner.Value -or
        $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
            [Security.AccessControl.FileSystemRights]::FullControl -or
        ($rules[0].PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
        throw 'Installation directory lacks the expected owner-only ACL.'
    }
}

function New-ExaCopyPrivateStage {
    param([string] $Parent, [Security.Principal.SecurityIdentifier] $Owner)

    [void](Confirm-ExaCopyPath $Parent)
    $path = Join-Path $Parent ('.ExaCopy-install-' + [Guid]::NewGuid().ToString('N'))
    if (Get-ExaCopyNodeExists $path) {
        throw 'A generated staging name is occupied.'
    }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($Owner)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $Owner, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), $acl)
    Confirm-ExaCopyOwnerAcl $path $Owner -Root
    Assert-ExaCopyExactEntries $path @()
    return $path
}

function Assert-ExaCopyParentAcl {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner, [switch] $Ancestor)
    [void](Confirm-ExaCopyPath $Path)
    $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($Path))
    $trusted = @($Owner.Value, 'S-1-5-18', 'S-1-5-32-544')
    $ownershipChanges = [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    $changes = if ($Ancestor) {
        # Ordinary create-child access on a higher ancestor cannot replace an
        # existing child protected against both deletion and ACL changes.
        $ownershipChanges
    }
    else {
        $ownershipChanges -bor [Security.AccessControl.FileSystemRights]::Write
    }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw 'An installation ancestor is outside trusted user or system ownership.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Value -notin $trusted -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            ($rule.FileSystemRights -band $changes) -ne 0) {
            throw 'An installation ancestor admits competing changes by another principal.'
        }
    }
}

function Assert-ExaCopyInstallAncestors {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner)
    Assert-ExaCopyParentAcl $Path $Owner
    $parent = [IO.Directory]::GetParent($Path)
    while ($null -ne $parent) {
        Assert-ExaCopyParentAcl $parent.FullName $Owner -Ancestor
        $parent = $parent.Parent
    }
}

function Test-ExaCopyUnderPath {
    param([string] $Path, [string] $Parent)
    return $Path.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Parent.TrimEnd([char]92) + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ExaCopyNoNamedStreams {
    param([string] $Path)
    # Directory streams are also possible on NTFS. Deleting just the unnamed
    # installation record would otherwise silently remove their user data.
    foreach ($entry in (Get-Item -LiteralPath $Path -Stream '*' -ErrorAction Stop)) {
        if ($entry.Stream -cne ':$DATA') {
            throw 'An owned installation entry has a named NTFS stream. No removal is authorized.'
        }
    }
}
