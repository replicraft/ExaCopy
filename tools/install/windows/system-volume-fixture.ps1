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
