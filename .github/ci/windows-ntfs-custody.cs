using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ExaCopyQualification
{
    // Test-only fixed NTFS directory custody. Keep the admitted handles live.
    public static class DirectoryCustody
    {
        private const uint FileListDirectory = 0x0001;
        private const uint FileReadAttributes = 0x0080;
        private const uint Delete = 0x00010000;
        private const uint ShareReadWrite = 0x0003;
        private const uint ShareDelete = 0x0004;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;
        private const uint BackupSemantics = 0x02000000;
        private const uint ReparsePoint = 0x0400;
        private const uint Directory = 0x0010;
        private const uint FileTypeDisk = 1;
        private const int SharingViolation = 32;
        private const int MaxSecurityDescriptorBytes = 65536;

        public enum CleanupRole
        {
            FixtureRoot,
            BuildRoot,
            BuildEntry,
        }

        private enum FileInfoClass
        {
            Standard = 1,
            Disposition = 4,
            AttributeTag = 9,
            Identity = 18,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTagInfo
        {
            public uint Attributes;
            public uint Tag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StandardInfo
        {
            public long AllocationSize;
            public long EndOfFile;
            public uint LinkCount;
            public byte DeletePending;
            public byte IsDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IdInfo
        {
            public ulong VolumeSerial;
            public ulong IdLow;
            public ulong IdHigh;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DispositionInfo
        {
            // FILE_DISPOSITION_INFO.DeleteFile is a one-byte BOOLEAN.
            public byte DeleteFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public uint Length;
            public IntPtr Descriptor;
            public int InheritHandle;
        }

        public static void CreateExclusiveFixture(string path, byte[] descriptor)
        {
            if (descriptor == null || descriptor.Length == 0 || descriptor.Length > MaxSecurityDescriptorBytes)
                throw new ArgumentException("Expected a bounded self-relative directory descriptor.");
            var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
            try
            {
                var attributes = new SecurityAttributes
                {
                    Length = Size<SecurityAttributes>(),
                    Descriptor = pinned.AddrOfPinnedObject(),
                    InheritHandle = 0,
                };
                Require(CreateDirectoryW(path, ref attributes), "Exclusive private directory creation was refused.");
            }
            finally
            {
                pinned.Free();
            }
        }

        public static void ControlAncestorDeleteSharing(string fixturePath)
        {
            // An authorized DELETE open must be available on the controlled leaf.
            using (OpenForDisposition(fixturePath)) { }
            using (HoldAncestor(fixturePath))
            {
                try
                {
                    using (OpenForDisposition(fixturePath)) { }
                }
                catch (Win32Exception error) when (error.NativeErrorCode == SharingViolation)
                {
                    return;
                }
                throw new IOException("A held ancestor failed to exclude a competing DELETE open.");
            }
        }

        public static SafeFileHandle HoldAncestor(string path)
        {
            // Attribute-only access does not engage Win32 read share accounting.
            return Open(path, FileListDirectory | FileReadAttributes, ShareReadWrite);
        }

        public static SafeFileHandle HoldFixture(string path)
        {
            // Attribute access does not request read-data access. Allow the final
            // DELETE open while keeping the original object referenced.
            return Open(path, FileReadAttributes, ShareReadWrite | ShareDelete);
        }

        public static SafeFileHandle OpenForDisposition(string path)
        {
            return Open(path, FileReadAttributes | Delete, ShareReadWrite);
        }

        private static SafeFileHandle Open(string path, uint access, uint share)
        {
            var handle = CreateFileW(path, access, share, IntPtr.Zero, OpenExisting,
                BackupSemantics | OpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Could not open the held NTFS directory.");
            }
            try
            {
                Observe(handle);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static string Observe(SafeFileHandle handle)
        {
            if (GetFileType(handle) != FileTypeDisk)
                throw new IOException("The held NTFS directory does not have a disk handle.");
            Require(GetAttributeTag(handle, FileInfoClass.AttributeTag, out var tag,
                Size<AttributeTagInfo>()), "Could not observe directory attributes.");
            if ((tag.Attributes & (Directory | ReparsePoint)) != Directory || tag.Tag != 0)
                throw new IOException("The held object is a reparse point or is not a plain directory.");
            Require(GetStandard(handle, FileInfoClass.Standard, out var standard,
                Size<StandardInfo>()), "Could not observe directory state.");
            if (standard.IsDirectory != 1 || standard.DeletePending != 0)
                throw new IOException("The held directory is unavailable or pending deletion.");
            Require(GetIdentity(handle, FileInfoClass.Identity, out var identity,
                Size<IdInfo>()), "Could not observe directory identity.");
            if (identity.VolumeSerial == 0 || (identity.IdLow == 0 && identity.IdHigh == 0))
                throw new IOException("The held directory lacks an identifiable volume or file ID.");
            return FormattableString.Invariant(
                $"{identity.VolumeSerial:X16}:{identity.IdHigh:X16}{identity.IdLow:X16}");
        }

        public static void MarkForDeletion(SafeFileHandle handle, CleanupRole role)
        {
            var information = new DispositionInfo { DeleteFile = 1 };
            if (SetDisposition(handle, FileInfoClass.Disposition, ref information, Size<DispositionInfo>()))
                return;

            // Keep the disposition error even if the subsequent handle observation fails.
            var error = Marshal.GetLastWin32Error();
            uint? attributes = GetAttributeTag(handle, FileInfoClass.AttributeTag, out var tag,
                Size<AttributeTagInfo>()) ? tag.Attributes : (uint?)null;
            throw DispositionFailure(role, error, attributes);
        }

        private static Win32Exception DispositionFailure(CleanupRole role, int error, uint? attributes)
        {
            string kind = "unknown";
            string flags = "unavailable";
            if (attributes.HasValue)
            {
                kind = (attributes.Value & Directory) == Directory ? "directory" : "file";
                flags = FormattableString.Invariant($"0x{attributes.Value:X8}");
            }
            return new Win32Exception(error, FormattableString.Invariant(
                $"Native nonrecursive disposition was refused for {role} (type={kind}, win32={error}, attributes={flags})."));
        }

        private static uint Size<T>() where T : struct
        {
            return checked((uint)Marshal.SizeOf<T>());
        }

        private static void Require(bool success, string message)
        {
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error(), message);
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", ExactSpelling = true,
            CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", ExactSpelling = true,
            CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
            IntPtr security, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern uint GetFileType(SafeFileHandle handle);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetAttributeTag(SafeFileHandle handle, FileInfoClass kind,
            out AttributeTagInfo information, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetStandard(SafeFileHandle handle, FileInfoClass kind,
            out StandardInfo information, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetIdentity(SafeFileHandle handle, FileInfoClass kind,
            out IdInfo information, uint size);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", ExactSpelling = true, SetLastError = true)]
        private static extern bool SetDisposition(SafeFileHandle handle, FileInfoClass kind,
            ref DispositionInfo information, uint size);
    }
}
