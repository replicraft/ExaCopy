# Stage-only fixture authority. The trusted principals and prior-handle assumptions
# match the selected private test profile. Loading this file opens no handles.

function Get-StageHostedSystemVolume {
    param([string] $Parent, [System.Collections.IDictionary] $Environment, [string] $SystemDirectory)

    if ($Environment.GITHUB_ACTIONS -cne 'true' -or $Environment.RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $Environment.RUNNER_OS -cne 'Windows' -or $Environment.RUNNER_ARCH -cne 'X64' -or
        $Environment.GITHUB_SERVER_URL -cne 'https://github.com' -or $Environment.GITHUB_REPOSITORY -ine 'replicraft/ExaCopy' -or
        $Environment.GITHUB_EVENT_NAME -cne 'push' -or $Environment.GITHUB_REF -cne 'refs/heads/main' -or
        $Environment.GITHUB_WORKFLOW_REF -ine 'replicraft/ExaCopy/.github/workflows/windows-ntfs-qualification.yml@refs/heads/main' -or
        $Environment.GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$' -or
        $Environment.GITHUB_WORKFLOW_SHA -cne $Environment.GITHUB_SHA -or
        $Environment.SystemDrive -notmatch '^[A-Z]:$' -or $Parent -ine $Environment.USERPROFILE) {
        return
    }
    $root = $Environment.SystemDrive + '\'
    if ($Environment.SystemRoot -ieq ($root + 'Windows') -and
        $SystemDirectory -ieq ($root + 'Windows\System32') -and
        $Parent.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -and $Parent -ine $root) {
        return $root
    }
}

function Assert-StageSystemVolumeAcl {
    param($Acl, [string] $Owner)

    $trusted = @($Owner, 'S-1-5-18', 'S-1-5-32-544')
    $serviceOwner = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $observed = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($observed -notin $trusted -and $observed -cne $serviceOwner) {
        throw 'An installation ancestor is outside trusted user or system ownership.'
    }
    # This hosted test trusts the OS servicing owner only at the system-drive
    # root. The ordinary competing-change ACE policy still applies there.
    Assert-ExaCopyParentDacl $Acl $trusted -Ancestor
}

function New-StageAncestorCustody {
    param(
        [string] $Path,
        [Security.Principal.SecurityIdentifier] $Owner,
        [scriptblock] $BeforeAdmission,
        [string] $HostedSystemVolume
    )

    $names = [Collections.Generic.Stack[string]]::new()
    for ($ancestor = [IO.DirectoryInfo]::new($Path); $null -ne $ancestor; $ancestor = $ancestor.Parent) {
        $names.Push($ancestor.FullName)
    }

    $held = [Collections.Generic.List[object]]::new()
    try {
        foreach ($name in $names) {
            $handle = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($name)
            try {
                $held.Add([pscustomobject]@{
                    Path = $name
                    Handle = $handle
                    Identity = [ExaCopyQualification.DirectoryCustody]::Observe($handle)
                })
            } catch {
                $handle.Dispose()
                throw
            }
        }
        if ($HostedSystemVolume -and ($held.Count -lt 2 -or $held[0].Path -ine $HostedSystemVolume)) {
            throw 'The hosted Stage system volume is outside the held ancestry.'
        }
        $custody = [pscustomobject]@{ Parent = $Path; Owner = $Owner; Held = $held; HostedSystemVolume = $HostedSystemVolume }
        & $BeforeAdmission $held
        Confirm-StageAncestorCustody $custody
        return $custody
    } catch {
        Close-StageAncestorCustody $held
        throw
    }
}

function Close-StageAncestorCustody {
    param($Held)
    for ($index = $Held.Count - 1; $index -ge 0; $index--) {
        $Held[$index].Handle.Dispose()
    }
}

function Assert-StageSameIdentity {
    param([string] $Expected, [string] $Observed)
    if ([string]::IsNullOrEmpty($Expected) -or $Observed -cne $Expected) {
        throw 'The currently observed NTFS directory is not the held original.'
    }
}

function Assert-StageSameVolume {
    param([string] $Root, [string] $Observed)
    if ($Root.Length -ne 49 -or $Observed.Length -ne 49 -or
        $Root.Substring(0, 16) -cne $Observed.Substring(0, 16)) {
        throw 'The selected NTFS directory is not on the held root volume.'
    }
}

function Assert-StagePlainAcl {
    param([Security.AccessControl.DirectorySecurity] $Acl)

    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl -or
        ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) {
        throw 'A custody directory has no explicit discretionary ACL.'
    }
    $simpleRights = @([Security.AccessControl.AceQualifier]::AccessAllowed, [Security.AccessControl.AceQualifier]::AccessDenied)
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
            $ace.AceQualifier -notin $simpleRights) {
            throw 'A custody directory has an unsupported discretionary ACE.'
        }
    }
}

function Assert-StageAncestorOwnership {
    param($Custody)

    if (!$Custody.HostedSystemVolume) {
        Assert-ExaCopyInstallAncestors $Custody.Parent $Custody.Owner
        return
    }
    for ($index = $Custody.Held.Count - 1; $index -ge 0; $index--) {
        $path = $Custody.Held[$index].Path
        if ($index -eq 0 -and $Custody.HostedSystemVolume -and $path -ieq $Custody.HostedSystemVolume) {
            [void](Confirm-ExaCopyPath $path)
            $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($path))
            Assert-StageSystemVolumeAcl $acl $Custody.Owner.Value
        } else {
            Assert-ExaCopyParentAcl $path $Custody.Owner -Ancestor:($index -lt $Custody.Held.Count - 1)
        }
    }
}

function Confirm-StageAncestorCustody {
    param($Custody)

    Assert-StageAncestorOwnership $Custody
    foreach ($entry in $Custody.Held) {
        Assert-StageSameVolume $Custody.Held[0].Identity $entry.Identity
        Assert-StagePlainAcl (Get-Acl -LiteralPath $entry.Path)
        Assert-StageSameIdentity $entry.Identity ([ExaCopyQualification.DirectoryCustody]::Observe($entry.Handle))
        $named = [ExaCopyQualification.DirectoryCustody]::HoldAncestor($entry.Path)
        try {
            Assert-StageSameIdentity $entry.Identity ([ExaCopyQualification.DirectoryCustody]::Observe($named))
        } finally {
            $named.Dispose()
        }
    }
}

function New-StagePrivateFixture {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner)

    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($Owner)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $Owner, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    [ExaCopyQualification.DirectoryCustody]::CreateExclusiveFixture($Path, $acl.GetSecurityDescriptorBinaryForm())
}

function Confirm-StageNoResidue {
    param([string] $Path)

    Assert-ExaCopyExactEntries $Path @()
    Assert-ExaCopyNoNamedStreams $Path
}

function Remove-HeldStageFixture {
    param([string] $Path, [string] $FixtureIdentity, $FixturePin, $Ancestors)

    Confirm-StageAncestorCustody $Ancestors
    Assert-StageSameIdentity $FixtureIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($FixturePin))
    $selected = [ExaCopyQualification.DirectoryCustody]::OpenForDisposition($Path)
    try {
        Assert-StageSameIdentity $FixtureIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($selected))
        Write-StageAclEvidence $Path $Ancestors.Owner 'after'
        Confirm-StageNoResidue $Path
        Confirm-StageAncestorCustody $Ancestors
        Assert-StageSameIdentity $FixtureIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($FixturePin))
        Assert-StageSameIdentity $FixtureIdentity ([ExaCopyQualification.DirectoryCustody]::Observe($selected))
        [ExaCopyQualification.DirectoryCustody]::MarkForDeletion($selected)
    } finally {
        $selected.Dispose()
    }
}
