using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ExaCopyQualification
{
    // Read-only, fixed local NTFS metadata for the installer diagnostic.
    public static class InstallerOwnerObservation
    {
        private const uint ListDirectory = 0x0001;
        private const uint ReadAttributes = 0x0080;
        private const uint ReadControl = 0x00020000;
        private const uint ShareReadWrite = 0x0003;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;
        private const uint BackupSemantics = 0x02000000;
        private const uint Directory = 0x0010;
        private const uint DriveFixed = 3;
        private const uint ForbiddenAttributes = 0x00000440; // reparse point or device
        private const uint VolumeNameGuid = 1;
        private const uint FileObject = 1;
        private const uint OwnerAndDacl = 0x00000005;
        private const int PathLimit = 32768;
        private const int DescriptorLimit = 65536;

        private enum FileInfoClass { Standard = 1, AttributeTag = 9, Identity = 18 }

        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTag
        {
            public uint Attributes;
            public uint Tag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Standard
        {
            public long Allocation;
            public long End;
            public uint Links;
            public byte DeletePending;
            public byte IsDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Identity
        {
            public ulong Volume;
            public ulong Low;
            public ulong High;
        }

        public static SafeFileHandle Hold(string path)
        {
            var handle = CreateFileW(path, ListDirectory | ReadAttributes | ReadControl, ShareReadWrite,
                IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }
            return handle;
        }

        public static string SystemWindowsDirectory()
        {
            var name = new StringBuilder(PathLimit);
            return CheckedPath(GetSystemWindowsDirectoryW(name, PathLimit), name);
        }

        public static string ObserveDirectory(SafeFileHandle handle)
        {
            Require(GetTag(handle, FileInfoClass.AttributeTag, out var tag, Size<AttributeTag>()));
            Require(GetStandard(handle, FileInfoClass.Standard, out var standard, Size<Standard>()));
            Require(GetIdentity(handle, FileInfoClass.Identity, out var identity, Size<Identity>()));
            if ((tag.Attributes & (Directory | ForbiddenAttributes)) != Directory || tag.Tag != 0 ||
                standard.IsDirectory != 1 || standard.DeletePending != 0 ||
                identity.Volume == 0 || (identity.Low == 0 && identity.High == 0))
                throw new IOException("Unsupported directory metadata.");
            return FormattableString.Invariant($"{identity.Volume:X16}:{identity.High:X16}{identity.Low:X16}");
        }

        public static string VolumePath(SafeFileHandle handle)
        {
            var name = new StringBuilder(PathLimit);
            return CheckedPath(GetFinalPathNameByHandleW(handle, name, PathLimit, VolumeNameGuid), name);
        }

        public static bool FixedNtfsVolume(SafeFileHandle root, string volumePath)
        {
            var fileSystem = new StringBuilder(32);
            Require(GetVolumeInformationByHandleW(root, IntPtr.Zero, 0, out _, out _, out _, fileSystem, 32));
            return GetDriveTypeW(volumePath) == DriveFixed &&
                string.Equals(fileSystem.ToString(), "NTFS", StringComparison.Ordinal);
        }

        public static byte[] SecurityDescriptor(SafeFileHandle handle)
        {
            var error = GetSecurityInfo(handle, FileObject, OwnerAndDacl, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, out var descriptor);
            try
            {
                if (error != 0)
                    throw new Win32Exception(checked((int)error));
                if (descriptor == IntPtr.Zero || !IsValidSecurityDescriptor(descriptor))
                    throw new IOException("Unsupported security descriptor.");
                var length = GetSecurityDescriptorLength(descriptor);
                if (length < 20 || length > DescriptorLimit)
                    throw new IOException("Unsupported security descriptor extent.");
                var bytes = new byte[checked((int)length)];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                return bytes;
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                    LocalFree(descriptor);
            }
        }

        private static uint Size<T>() where T : struct => checked((uint)Marshal.SizeOf<T>());

        private static string CheckedPath(uint size, StringBuilder name)
        {
            Require(size != 0);
            if (size >= PathLimit || size != name.Length)
                throw new IOException("Unsupported native path extent.");
            return name.ToString();
        }

        private static void Require(bool success)
        {
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint rights, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint GetSystemWindowsDirectoryW(StringBuilder path, uint capacity);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetTag(SafeFileHandle handle, FileInfoClass kind, out AttributeTag info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetStandard(SafeFileHandle handle, FileInfoClass kind, out Standard info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetIdentity(SafeFileHandle handle, FileInfoClass kind, out Identity info, uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, IntPtr volumeName, uint nameCapacity,
            out uint serial, out uint maximumComponent, out uint fileSystemFlags, StringBuilder fileSystem, uint fileSystemCapacity);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint GetDriveTypeW(string path);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint GetSecurityInfo(SafeFileHandle handle, uint kind, uint scope,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern bool IsValidSecurityDescriptor(IntPtr descriptor);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr LocalFree(IntPtr descriptor);
    }
}
