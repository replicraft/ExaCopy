#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'paths.ps1')

function Assert-Refused {
    param([scriptblock] $Attempt, [string] $Expected)
    try { & $Attempt }
    catch {
        if ($_.Exception.Message -notlike "*$Expected*") { throw }
        return
    }
    throw "Missing refusal: $Expected"
}

$trusted = @('S-1-5-21-7-8-9-1001', 'S-1-5-18', 'S-1-5-32-544')
$trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$system = [pscustomobject]@{}
$system | Add-Member ScriptMethod IsSystemVolumeRoot { return $true }
$other = [pscustomobject]@{}
$other | Add-Member ScriptMethod IsSystemVolumeRoot { return $false }
foreach ($owner in $trusted) { Assert-ExaCopyHeldAncestorOwner $owner $trusted }
Assert-ExaCopyHeldAncestorOwner $trustedInstaller $trusted -Ancestor -VolumeRoot -Ancestry $system
$reason = 'outside trusted user or system ownership'
Assert-Refused { Assert-ExaCopyHeldAncestorOwner $trustedInstaller $trusted -Ancestor -VolumeRoot } $reason
Assert-Refused { Assert-ExaCopyHeldAncestorOwner $trustedInstaller $trusted -Ancestor -VolumeRoot -Ancestry $other } $reason
Assert-Refused { Assert-ExaCopyHeldAncestorOwner $trustedInstaller $trusted -Ancestor -Ancestry $system } $reason
Assert-Refused { Assert-ExaCopyHeldAncestorOwner $trustedInstaller $trusted -VolumeRoot -Ancestry $system } $reason
foreach ($owner in @('S-1-5-19', 'S-1-5-20', 'S-1-1-0', 'S-1-5-21-7-8-9-1002')) {
    Assert-Refused { Assert-ExaCopyHeldAncestorOwner $owner $trusted -Ancestor -VolumeRoot -Ancestry $system } $reason
}

# Even on the verified system root the service is an outside DACL trustee.
$rule = [pscustomobject]@{
    AccessControlType = [Security.AccessControl.AccessControlType]::Allow
    IdentityReference = [pscustomobject]@{ Value = $trustedInstaller }
    PropagationFlags = [Security.AccessControl.PropagationFlags]::None
    FileSystemRights = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
}
$acl = [pscustomobject]@{ Rule = $rule }
$acl | Add-Member ScriptMethod GetAccessRules { param($Explicit, $Inherited, $TargetType) return $this.Rule }
Assert-Refused { Assert-ExaCopyParentDacl $acl $trusted -Ancestor } 'competing changes'
$acl.Rule.PropagationFlags = [Security.AccessControl.PropagationFlags]::InheritOnly
Assert-ExaCopyParentDacl $acl $trusted -Ancestor
Write-Output 'System-volume owner role and independent DACL controls passed.'

$genericRead = 0x80000000u
$genericWrite = 0x40000000u
$genericExecute = 0x20000000u
$genericAll = 0x10000000u
function Convert-FixtureMask {
    param([uint32] $Bits)
    return [BitConverter]::ToInt32([BitConverter]::GetBytes($Bits), 0)
}
$examples = @(
    @{ Mask = 0u; Expected = 0 },
    @{ Mask = $genericRead; Expected = 0x00120089 },
    @{ Mask = $genericWrite; Expected = 0x00120116 },
    @{ Mask = $genericExecute; Expected = 0x001200A0 },
    @{ Mask = $genericAll; Expected = 0x001F01FF },
    @{ Mask = ($genericRead -bor $genericExecute); Expected = 0x001200A9 },
    @{ Mask = ($genericRead -bor $genericWrite -bor $genericExecute -bor 0x40u); Expected = 0x001201FF },
    @{ Mask = ($genericRead -bor 0x00080000u); Expected = 0x001A0089 },
    @{ Mask = 0x00040002u; Expected = 0x00040002 }
)
foreach ($example in $examples) {
    $mapped = ConvertTo-ExaCopyDirectoryAccessMask (Convert-FixtureMask $example.Mask)
    if ($mapped -ne $example.Expected) { throw 'Directory generic access mapping differs from its expected rights.' }
}
foreach ($unsupported in @(0x200u, 0x01000000u, 0x02000000u, ($genericRead -bor 0x200u))) {
    Assert-Refused { ConvertTo-ExaCopyDirectoryAccessMask (Convert-FixtureMask $unsupported) } 'Unsupported specific directory rights'
}
$foreign = 'S-1-1-0'
$parentChanges = Get-ExaCopyParentChangeMask
$ancestorChanges = Get-ExaCopyParentChangeMask -Ancestor
foreach ($changes in @($parentChanges, $ancestorChanges)) {
    foreach ($readOnly in @($genericRead, $genericExecute, ($genericRead -bor $genericExecute))) {
        Assert-ExaCopyMappedAncestorGrant $foreign (Convert-FixtureMask $readOnly) $trusted $changes $true $false 0 1
    }
    Assert-Refused { Assert-ExaCopyMappedAncestorGrant $foreign (Convert-FixtureMask $genericWrite) $trusted $changes $true $false 4 2 } 'depth=4 ace=2 shape=common-allow generic=write'
    Assert-Refused { Assert-ExaCopyMappedAncestorGrant $trustedInstaller (Convert-FixtureMask $genericAll) $trusted $changes $true $false 0 3 } 'depth=0 ace=3 shape=common-allow generic=all'
    Assert-Refused { Assert-ExaCopyMappedAncestorGrant $foreign (Convert-FixtureMask ($genericRead -bor 0x40u)) $trusted $changes $true $false 0 3 } 'competing changes'
    Assert-Refused { Assert-ExaCopyMappedAncestorGrant $foreign (Convert-FixtureMask ($genericRead -bor 0x200u)) $trusted $changes $true $false 4 5 } 'depth=4 ace=5 shape=common-allow generic=read'
}
Assert-ExaCopyMappedAncestorGrant $foreign (Convert-FixtureMask $genericWrite) $trusted $ancestorChanges $true $true 2 0
Assert-Refused { Assert-ExaCopyMappedAncestorGrant $foreign (Convert-FixtureMask $genericWrite) $trusted $parentChanges $true $false 3 0 } 'competing changes'
Assert-ExaCopyMappedAncestorGrant $foreign (Convert-FixtureMask $genericAll) $trusted $parentChanges $false $false 4 0
Assert-ExaCopyMappedAncestorGrant $trusted[0] (Convert-FixtureMask $genericAll) $trusted $parentChanges $true $false 4 0
Assert-ExaCopyMappedAncestorGrant $foreign 2 $trusted $ancestorChanges $true $false 0 0
Assert-Refused { Assert-ExaCopyMappedAncestorGrant $foreign 2 $trusted $parentChanges $true $false 4 0 } 'competing changes'
Write-Output 'Directory generic mapping, effective inheritance and bounded refusal controls passed.'

if ($IsWindows) {
    if (!('ExaCopyInstaller.GenericMaskFixture' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace ExaCopyInstaller {
    public static class GenericMaskFixture {
        [StructLayout(LayoutKind.Sequential)]
        private struct Mapping { public uint Read, Write, Execute, All; }
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern void MapGenericMask(ref uint mask, in Mapping mapping);
        public static uint NativeMap(uint mask) {
            var mapping = new Mapping { Read = 0x00120089, Write = 0x00120116, Execute = 0x001200A0, All = 0x001F01FF };
            MapGenericMask(ref mask, in mapping);
            return mask;
        }
    }
}
'@
    }
    foreach ($generic in 0..15) {
        foreach ($specific in @(0u, 0x40u, 0x00080000u, 0x001F01FFu)) {
            $bits = ([uint32] $generic -shl 28) -bor $specific
            if ((ConvertTo-ExaCopyDirectoryAccessMask (Convert-FixtureMask $bits)) -ne
                [ExaCopyInstaller.GenericMaskFixture]::NativeMap($bits)) {
                throw 'Directory generic mapping differs from native MapGenericMask.'
            }
        }
    }
    Write-Output 'Native MapGenericMask agreed on 64 generic and specific directory mask combinations.'

    # Synthetic memory-only descriptors exercise the real held ACL parser.
    function New-FixtureHeldObservation {
        param($Ace, [Security.Principal.SecurityIdentifier] $Owner)
        $dacl = [Security.AccessControl.RawAcl]::new([Security.AccessControl.GenericAcl]::AclRevisionDS, 1)
        $dacl.InsertAce(0, $Ace)
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent, $Owner, $Owner, $null, $dacl)
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)
        return [pscustomobject]@{ Security = $bytes; IsSystemRoot = $false }
    }
    $syntheticOwner = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $syntheticOutside = [Security.Principal.SecurityIdentifier]::new($foreign)
    $flags = [Security.AccessControl.AceFlags]::None
    $allow = [Security.AccessControl.AceQualifier]::AccessAllowed
    $readMask = Convert-FixtureMask $genericRead
    $plain = [Security.AccessControl.CommonAce]::new($flags, $allow, $readMask, $syntheticOutside, $false, $null)
    $observed = New-FixtureHeldObservation $plain $syntheticOwner
    $rawHex = [Convert]::ToHexString($observed.Security)
    Assert-ExaCopyHeldAncestorAcl $null $observed $syntheticOwner -Depth 4
    if ([Convert]::ToHexString($observed.Security) -cne $rawHex) { throw 'Held ACL validation changed the descriptor bytes.' }
    $callback = [Security.AccessControl.CommonAce]::new($flags, $allow, $readMask, $syntheticOutside, $true, [byte[]]::new(4))
    $objectAce = [Security.AccessControl.ObjectAce]::new($flags, $allow, $readMask, $syntheticOutside,
        [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent, [Guid] 'B19201C9-5B14-45D0-9F40-36BBA551E514', [Guid]::Empty, $false, $null)
    $unknownType = [Enum]::ToObject([Security.AccessControl.AceType], [byte] 0x7F)
    $unknownAce = [Security.AccessControl.CustomAce]::new($unknownType, $flags, $null)
    foreach ($case in @(
        @{ Ace = $callback; Expected = 'shape=callback generic=read' },
        @{ Ace = $objectAce; Expected = 'shape=object generic=read' },
        @{ Ace = $unknownAce; Expected = 'shape=non-common generic=unknown' }
    )) {
        $observed = New-FixtureHeldObservation $case.Ace $syntheticOwner
        $rawHex = [Convert]::ToHexString($observed.Security)
        Assert-Refused { Assert-ExaCopyHeldAncestorAcl $null $observed $syntheticOwner -Depth 4 } "depth=4 ace=0 $($case.Expected)"
        if ([Convert]::ToHexString($observed.Security) -cne $rawHex) { throw 'Refusal changed descriptor bytes.' }
    }
    Write-Output 'In-memory held ACL controls accepted generic read and refused callback, object and unknown ACEs.'
}

# Compile the actual generated-launcher fragment on the portable lane. No
# native syscall is invoked here. Validate the native response layout sizes.
$tokens = $null
$errors = $null
$pathsFile = Join-Path $PSScriptRoot 'paths.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($pathsFile, [ref] $tokens, [ref] $errors)
if ($errors.Count -ne 0) { throw 'Installer path fragment does not parse.' }
$definition = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString -and
        $node.Value.StartsWith('using System;', [StringComparison]::Ordinal)
}, $true))
if ($definition.Count -ne 1) { throw 'Expected exactly one installer native helper definition.' }
if (!('ExaCopyInstaller.ProductAncestry' -as [type])) {
    Add-Type -TypeDefinition $definition[0].Value
}
foreach ($shape in @{ Identity = 24; StandardInfo = 24; AttributeTag = 8 }.GetEnumerator()) {
    $nativeLayout = [ExaCopyInstaller.ProductAncestry].GetNestedType($shape.Key, [Reflection.BindingFlags]::NonPublic)
    if ([Runtime.InteropServices.Marshal]::SizeOf([type] $nativeLayout) -ne $shape.Value) {
        throw "Unexpected native layout: $($shape.Key)"
    }
}
Write-Output 'Actual native helper compiles and its response layout sizes match the Win32 ABI.'

# On Windows also exercise the real held chain before the package fixture
# creates anything. The public installer retains its non-elevation gate.
if ($IsWindows) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $owner = $identity.User
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $administratorEnabled = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally { $identity.Dispose() }
    $local = Resolve-ExaCopyWindowsPath ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
    $ancestry = Open-ExaCopyProductAncestry $local $owner
    try {
        Assert-ExaCopyInstallAncestors $local $owner $ancestry
        $root = $ancestry.Inspect($local)[0]
        $rootSecurity = [Security.AccessControl.RawSecurityDescriptor]::new($root.Security, 0)
        $usedSystemRootRole = $rootSecurity.Owner.Value -ceq $trustedInstaller
        if ($usedSystemRootRole -and !$ancestry.IsSystemVolumeRoot()) {
            throw 'The held root owner exception lacks native system-volume proof.'
        }
        $other = Join-Path $local 'ExaCopy-unadmitted-fixture-parent'
        Assert-Refused { $ancestry.Inspect($other) } 'Invalid installer mutation parent'
        Write-Output "Native read-only ancestry admitted (administrator-enabled=$administratorEnabled, system-root-owner-role=$usedSystemRootRole)."
    }
    finally { $ancestry.Dispose() }
}
else {
    Write-Output 'Native held-ancestry smoke applies on Windows.'
}
