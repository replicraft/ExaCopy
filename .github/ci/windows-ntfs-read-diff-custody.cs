using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ExaCopyQualification
{
    // Native facts for the hosted Read/Diff test runner's own build entries.
    public static class ReadDiffCustody
    {
        private const uint Directory = 0x0010;
        private const uint ReparseOrDevice = 0x0440;
        private const uint ReadAttributes = 0x0080;
        private const uint Delete = 0x00010000;
        private const uint ReadWriteShare = 0x0003;
        private const uint DeleteShare = 0x0004;
        private const uint OpenExisting = 3;
        private const uint BackupAndOpenReparse = 0x02200000;
        private const uint DiskHandle = 1;
        private const uint VolumeNameGuid = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct Attributes
        {
            public uint Flags;
            public uint Tag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Standard
        {
            public long Allocation;
            public long Extent;
            public uint Links;
            public byte Pending;
            public byte IsDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Identity
        {
            public ulong Volume;
            public ulong Low;
            public ulong High;
        }

        public sealed class Node
        {
            public string FileId { get; }
            public uint Links { get; }
            internal Node(string id, uint links)
            {
                FileId = id;
                Links = links;
            }
        }

        public static string PhysicalNtfsRoot(SafeFileHandle handle)
        {
            var path = new StringBuilder(80);
            uint length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, VolumeNameGuid);
            if (length == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot observe the held volume GUID root.");
            var name = path.ToString();
            if (length >= path.Capacity || name.Length != 49 ||
                !name.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase) ||
                !name.EndsWith(@"}\", StringComparison.Ordinal) ||
                !Guid.TryParseExact(name.Substring(11, 36), "D", out _))
                throw new IOException("The held drive handle is not the physical volume root.");
            var fileSystem = new StringBuilder(32);
            Require(GetVolumeInformationByHandleW(handle, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, fileSystem, 32), "Cannot observe the held volume filesystem.");
            if (fileSystem.ToString() != "NTFS")
                throw new IOException("The held physical volume is not NTFS.");
            return name;
        }

        public static SafeFileHandle HoldNode(string path, bool directory, bool delete)
        {
            var handle = CreateFileW(path, ReadAttributes | (delete ? Delete : 0),
                ReadWriteShare | (delete ? 0 : DeleteShare), IntPtr.Zero, OpenExisting,
                BackupAndOpenReparse, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Could not open the selected build entry.");
            }
            try
            {
                Observe(handle, directory);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static Node Observe(SafeFileHandle handle, bool directory)
        {
            if (GetFileType(handle) != DiskHandle)
                throw new IOException("The selected build entry is not a disk object.");
            Require(GetTag(handle, 9, out var tag, Size<Attributes>()),
                "Cannot observe build entry attributes.");
            Require(GetStandard(handle, 1, out var state, Size<Standard>()),
                "Cannot observe build entry state.");
            if ((tag.Flags & ReparseOrDevice) != 0 || tag.Tag != 0 ||
                ((tag.Flags & Directory) != 0) != directory || state.IsDirectory != (directory ? 1 : 0) ||
                state.Pending != 0 || state.Links == 0)
                throw new IOException("The selected build entry is a reparse, unavailable, or has a different type.");
            Require(GetIdentity(handle, 18, out var id, Size<Identity>()),
                "Cannot observe build entry identity.");
            if (id.Volume == 0 || (id.Low | id.High) == 0)
                throw new IOException("The selected build entry lacks native identity.");
            return new Node(FormattableString.Invariant($"{id.Volume:X16}:{id.High:X16}{id.Low:X16}"),
                state.Links);
        }

        private static uint Size<T>() where T : struct => checked((uint)Marshal.SizeOf<T>());

        private static void Require(bool success, string message)
        {
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error(), message);
        }

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern uint GetFileType(SafeFileHandle handle);

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder name,
            uint capacity, uint flags);

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, IntPtr volume,
            uint volumeCapacity, IntPtr serial, IntPtr maxComponent, IntPtr flags, StringBuilder fileSystem,
            uint fileSystemCapacity);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetTag(SafeFileHandle handle, int kind, out Attributes info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetStandard(SafeFileHandle handle, int kind, out Standard info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetIdentity(SafeFileHandle handle, int kind, out Identity info, uint size);
    }
}
