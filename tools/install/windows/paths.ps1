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
    try {
        [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), $acl)
        Confirm-ExaCopyOwnerAcl $path $Owner -Root
        Assert-ExaCopyExactEntries $path @()
    }
    catch {
        throw "Private stage creation could not be confirmed. Inspect '$path'. $($_.Exception.Message)"
    }
    return $path
}

function Assert-ExaCopyParentDacl {
    param($Acl, [string[]] $Trusted, [switch] $Ancestor)
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
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Value -notin $trusted -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            ($rule.FileSystemRights -band $changes) -ne 0) {
            throw 'An installation ancestor admits competing changes by another principal.'
        }
    }
}

function Assert-ExaCopyParentAcl {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner, [switch] $Ancestor)
    [void](Confirm-ExaCopyPath $Path)
    $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($Path))
    $trusted = @($Owner.Value, 'S-1-5-18', 'S-1-5-32-544')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw 'An installation ancestor is outside trusted user or system ownership.'
    }
    Assert-ExaCopyParentDacl $acl $trusted -Ancestor:$Ancestor
}

function Assert-ExaCopyInstallAncestors {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Owner, $ProductAncestry)
    if ($null -ne $ProductAncestry) {
        $observations = $ProductAncestry.Inspect($Path)
        for ($i = 0; $i -lt $observations.Length; $i++) {
            Assert-ExaCopyHeldAncestorAcl $ProductAncestry $observations[$i] $Owner -Ancestor:($i -lt ($observations.Length - 1))
        }
        return
    }
    Assert-ExaCopyParentAcl $Path $Owner
    $parent = [IO.Directory]::GetParent($Path)
    while ($null -ne $parent) {
        Assert-ExaCopyParentAcl $parent.FullName $Owner -Ancestor
        $parent = $parent.Parent
    }
}

function Assert-ExaCopyContextAncestors {
    param($Context, [string] $Path)
    $scope = $Context.PSObject.Properties['ProductAncestry']
    $admission = if ($null -ne $scope) { $scope.Value } else { $null }
    Assert-ExaCopyInstallAncestors $Path $Context.Owner $admission
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

# Used only by the public product context and its generated launcher. The
# ordinary fixture/parent ACL helpers below do not infer this role from a path.
function Open-ExaCopyProductAncestry {
    param([string] $Local, [Security.Principal.SecurityIdentifier] $Owner)
    $thread = [Security.Principal.WindowsIdentity]::GetCurrent($true)
    if ($null -ne $thread) {
        $thread.Dispose()
        throw 'Installer ancestor admission cannot use an impersonated token.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($identity.User.Value -cne $Owner.Value) { throw 'Installer identity changed before ancestor admission.' }
    }
    finally { $identity.Dispose() }
    if (!('ExaCopyInstaller.ProductAncestry' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ExaCopyInstaller {
    public sealed class ProductAncestry : IDisposable {
        private const uint DirectoryAccess = 0x00020081; // READ_CONTROL, READ_ATTRIBUTES, LIST_DIRECTORY
        private const uint ShareReadWrite = 3; // No FILE_SHARE_DELETE, because LIST_DIRECTORY participates.
        private const uint OpenDirectory = 0x02200000; // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        private const uint Directory = 0x10;
        private const uint ReparseOrDevice = 0x440;
        private const uint Fixed = 3;
        private const uint DefaultKnownFolder = 0x400;
        private const int MaximumDepth = 64;
        private const int MaximumPath = 32768;
        private static readonly Guid LocalFolder = new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");
        private static readonly Guid ProfileFolder = new Guid("5E6C858F-0E22-4760-9AFE-EA3317B67173");
        private const StringComparison WindowsName = StringComparison.OrdinalIgnoreCase;

        [StructLayout(LayoutKind.Sequential)]
        private struct Identity {
            public ulong Volume, Low, High;
            public bool Matches(Identity other) => Volume == other.Volume && Low == other.Low && High == other.High;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTag { public uint Attributes, Tag; }
        [StructLayout(LayoutKind.Sequential)]
        private struct StandardInfo {
            public long AllocationSize, EndOfFile;
            public uint LinkCount;
            public byte DeletePending, IsDirectory;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint sharing, IntPtr security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        private static extern bool FileId(SafeFileHandle file, int kind, out Identity id, uint size);
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        private static extern bool FileTag(SafeFileHandle file, int kind, out AttributeTag tag, uint size);
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        private static extern bool FileStandard(SafeFileHandle file, int kind, out StandardInfo info, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder name, uint capacity, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint GetSystemWindowsDirectoryW(StringBuilder name, uint capacity);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint GetDriveTypeW(string root);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, IntPtr name, uint capacity,
            IntPtr serial, IntPtr maxComponent, IntPtr flags, StringBuilder fileSystem, uint fsCapacity);
        [DllImport("shell32.dll")]
        private static extern int SHGetKnownFolderPath(in Guid folder, uint flags, IntPtr token, out IntPtr name);
        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityInfo(SafeFileHandle file, uint type, uint fields, IntPtr owner,
            IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr value);

        public sealed class Observation {
            public byte[] Security { get; }
            public bool IsSystemRoot { get; }
            internal Observation(byte[] security, bool isSystemRoot) { Security = security; IsSystemRoot = isSystemRoot; }
        }
        private sealed class HeldDirectory : IDisposable {
            public readonly string PathName, PhysicalName;
            public readonly SafeFileHandle Handle;
            public readonly Identity Id;
            public HeldDirectory(string name) {
                PathName = name;
                Handle = CreateFileW(name, DirectoryAccess, ShareReadWrite, IntPtr.Zero, 3, OpenDirectory, IntPtr.Zero);
                try {
                    if (Handle.IsInvalid || !FileTag(Handle, 9, out var tag, 8) || !FileId(Handle, 18, out Id, 24) ||
                        !FileStandard(Handle, 1, out var standard, 24))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    if ((tag.Attributes & Directory) == 0 || (tag.Attributes & ReparseOrDevice) != 0 || tag.Tag != 0 ||
                        standard.IsDirectory != 1 || standard.DeletePending != 0 || Id.Volume == 0 || (Id.Low | Id.High) == 0)
                        throw new IOException("Installer ancestor is not an ordinary directory.");
                    var physical = new StringBuilder(MaximumPath);
                    PhysicalName = Complete(physical, GetFinalPathNameByHandleW(Handle, physical, MaximumPath, 1));
                }
                catch { Handle.Dispose(); throw; }
            }
            public bool Same(HeldDirectory other) => Id.Matches(other.Id) && PhysicalName.Equals(other.PhysicalName, WindowsName);
            public void Recheck() {
                using (var fresh = new HeldDirectory(PathName)) {
                    if (!Same(fresh)) throw new IOException("Installer ancestor name changed after admission.");
                }
            }
            public byte[] ReadSecurity() {
                var status = GetSecurityInfo(Handle, 1, 5, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var raw);
                try {
                    if (status != 0) throw new Win32Exception((int)status);
                    if (raw == IntPtr.Zero) throw new IOException("Installer ancestor security is unavailable.");
                    uint size = GetSecurityDescriptorLength(raw);
                    if (size < 20 || size > 65536) throw new IOException("Invalid installer ancestor security length.");
                    var bytes = new byte[size];
                    Marshal.Copy(raw, bytes, 0, bytes.Length);
                    return bytes;
                }
                finally { if (raw != IntPtr.Zero) LocalFree(raw); }
            }
            public void Dispose() => Handle.Dispose();
        }

        private readonly List<HeldDirectory> chain = new List<HeldDirectory>();
        private readonly string local, programs, volume;
        private HeldDirectory programsHandle, systemRoot;
        private string profile;
        private bool disposed;

        public ProductAncestry(string admittedLocal) {
            local = admittedLocal;
            programs = Path.Combine(local, "Programs");
            if (!KnownFolder(LocalFolder).Equals(local, WindowsName))
                throw new IOException("Installer root differs from the current user's native known folder.");
            string drive = Path.GetPathRoot(local) ?? throw new IOException("Installer ancestry has no drive root.");
            string[] parts = local.Substring(drive.Length).Split('\\');
            if (parts.Length < 1 || parts.Length > MaximumDepth || GetDriveTypeW(drive) != Fixed)
                throw new IOException("Installer ancestry is outside the bounded fixed drive profile.");
            try {
                var root = new HeldDirectory(drive);
                chain.Add(root);
                volume = VolumeRoot(root.PhysicalName);
                var fs = new StringBuilder(32);
                if (!root.PhysicalName.Equals(volume, WindowsName) ||
                    !GetVolumeInformationByHandleW(root.Handle, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, fs, 32) ||
                    fs.ToString() != "NTFS")
                    throw new IOException("Installer ancestry is outside a physical NTFS volume root.");
                string next = drive;
                foreach (string part in parts) {
                    if (part.Length == 0 || part == "." || part == "..") throw new IOException("Invalid installer ancestry component.");
                    next = Path.Combine(next, part);
                    chain.Add(OpenMember(next));
                }
                RecheckKnownFolder();
            }
            catch { Dispose(); throw; }
        }

        private void RecheckKnownFolder() {
            string current = KnownFolder(LocalFolder);
            if (!current.Equals(local, WindowsName)) throw new IOException("Installer known folder changed.");
            using (var known = new HeldDirectory(current)) {
                if (!chain[chain.Count - 1].Same(known)) throw new IOException("Installer known folder identity changed.");
            }
        }

        // Request this proof only for an otherwise refused owner at depth zero.
        public bool IsSystemVolumeRoot() {
            if (disposed) throw new ObjectDisposedException(nameof(ProductAncestry));
            string currentProfile = KnownFolder(ProfileFolder);
            var heldProfile = chain.Find(node => node.PathName.Equals(currentProfile, WindowsName));
            string defaultLocal = KnownFolder(LocalFolder, DefaultKnownFolder);
            if (!defaultLocal.Equals(local, WindowsName) || heldProfile == null ||
                currentProfile.Equals(local, WindowsName) || currentProfile.Equals(chain[0].PathName, WindowsName))
                return false;
            using (var profileDirectory = new HeldDirectory(currentProfile))
            using (var defaultDirectory = new HeldDirectory(defaultLocal)) {
                if (!heldProfile.Same(profileDirectory) || !chain[chain.Count - 1].Same(defaultDirectory)) return false;
            }
            var windows = new StringBuilder(MaximumPath);
            string directory = Complete(windows, GetSystemWindowsDirectoryW(windows, MaximumPath));
            string systemDrive = Path.GetPathRoot(directory);
            if (systemDrive == null || systemDrive.Length != 3 || directory.Length <= systemDrive.Length) return false;
            using (var system = new HeldDirectory(directory)) {
                if (system.Id.Volume != chain[0].Id.Volume ||
                    !system.PhysicalName.Equals(volume + directory.Substring(systemDrive.Length), WindowsName)) return false;
            }
            if (systemRoot == null) {
                var nativeRoot = new HeldDirectory(volume);
                if (!chain[0].Same(nativeRoot)) { nativeRoot.Dispose(); return false; }
                systemRoot = nativeRoot;
                profile = currentProfile;
            }
            chain[0].Recheck();
            systemRoot.Recheck();
            return profile.Equals(currentProfile, WindowsName) && chain[0].Same(systemRoot);
        }

        public Observation[] Inspect(string parent) {
            if (disposed) throw new ObjectDisposedException(nameof(ProductAncestry));
            RecheckKnownFolder();
            bool selectPrograms = parent.Equals(programs, WindowsName);
            if (!selectPrograms && !parent.Equals(local, WindowsName)) throw new IOException("Invalid installer mutation parent.");
            var result = new List<Observation>();
            for (int index = 0; index < chain.Count; index++) {
                var node = chain[index];
                node.Recheck();
                result.Add(new Observation(node.ReadSecurity(), index == 0));
            }
            if (selectPrograms) {
                if (programsHandle == null) programsHandle = OpenMember(programs);
                programsHandle.Recheck();
                result.Add(new Observation(programsHandle.ReadSecurity(), false));
            }
            return result.ToArray();
        }

        private HeldDirectory OpenMember(string name) {
            var opened = new HeldDirectory(name);
            if (opened.Id.Volume == chain[0].Id.Volume && opened.PhysicalName.Equals(volume + name.Substring(3), WindowsName))
                return opened;
            opened.Dispose();
            throw new IOException("Installer component is outside its held physical ancestry.");
        }
        private static string VolumeRoot(string full) {
            const string prefix = @"\\?\Volume{";
            int close = full.IndexOf('}');
            if (!full.StartsWith(prefix, WindowsName) || close != prefix.Length + 36 || close + 1 >= full.Length ||
                full[close + 1] != '\\' || !Guid.TryParseExact(full.Substring(prefix.Length, 36), "D", out _))
                throw new IOException("Installer filesystem does not expose a canonical GUID volume path.");
            return full.Substring(0, close + 2);
        }
        private static string Complete(StringBuilder name, uint used) {
            if (used == 0 || used >= name.Capacity) throw new IOException("Installer native path unavailable or exceeds its bound.");
            return name.ToString();
        }
        private static string KnownFolder(Guid folder, uint flags = 0) {
            int result = SHGetKnownFolderPath(in folder, flags, IntPtr.Zero, out var raw);
            try {
                if (result != 0) Marshal.ThrowExceptionForHR(result);
                string name = Marshal.PtrToStringUni(raw);
                if (String.IsNullOrEmpty(name) || name.Length >= MaximumPath) throw new IOException("Installer known folder unavailable.");
                return Path.TrimEndingDirectorySeparator(name);
            }
            finally { if (raw != IntPtr.Zero) Marshal.FreeCoTaskMem(raw); }
        }
        public void Dispose() {
            if (disposed) return;
            disposed = true;
            programsHandle?.Dispose();
            foreach (var node in chain) node.Dispose();
            systemRoot?.Dispose();
        }
    }
}
'@
    }
    return [ExaCopyInstaller.ProductAncestry]::new($Local)
}

function Assert-ExaCopyHeldAncestorAcl {
    param($Ancestry, $Observation, [Security.Principal.SecurityIdentifier] $Owner, [switch] $Ancestor)
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Observation.Security, 0)
    if ($null -eq $raw.Owner -or $null -eq $raw.DiscretionaryAcl -or
        ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) {
        throw 'Installer ancestor owner or effective ACL is unavailable.'
    }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
            $ace.AceType -notin @([Security.AccessControl.AceType]::AccessAllowed, [Security.AccessControl.AceType]::AccessDenied) -or
            ($ace.AccessMask -band -268435456) -ne 0) {
            throw 'Installer ancestor ACL has an unsupported rule representation.'
        }
    }
    $trusted = @($Owner.Value, 'S-1-5-18', 'S-1-5-32-544')
    Assert-ExaCopyHeldAncestorOwner $raw.Owner.Value $trusted -Ancestor:$Ancestor -VolumeRoot:$Observation.IsSystemRoot -Ancestry $Ancestry
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    $acl.SetSecurityDescriptorBinaryForm($Observation.Security, $sections)
    Assert-ExaCopyParentDacl $acl $trusted -Ancestor:$Ancestor
}

function Assert-ExaCopyHeldAncestorOwner {
    param([string] $Observed, [string[]] $Trusted, [switch] $Ancestor, [switch] $VolumeRoot, $Ancestry)
    if ($Observed -in $Trusted) { return }
    if ($Ancestor -and $VolumeRoot -and $Observed -ceq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -and
        $null -ne $Ancestry -and $Ancestry.IsSystemVolumeRoot()) { return }
    throw 'An installation ancestor is outside trusted user or system ownership.'
}
