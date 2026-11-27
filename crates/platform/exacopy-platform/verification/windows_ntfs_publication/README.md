# Windows fixed NTFS publication qualification

The hosted profile selects Windows Server 2025 x64 and verifies custody of
the physical NTFS volume. Its private Cargo build tree can contain read-only
files. The hosted run at `379b30c` recorded Win32 error 5 during classic
disposition of a build file with attributes `0x21` (read-only and archive).

After the existing file ID, ownership, ACL, alternate stream, hard-link and
namespace checks, this profile selects `FileDispositionInfoEx` only when
the held regular build file has the read-only attribute. It requests
`FILE_DISPOSITION_DELETE | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE`
with the same DELETE-authorized handle. This Win32 information class uses
a four-byte flag buffer. Directory and writable-file cleanup use classic
disposition. A native refusal retains the failure result and stops cleanup.
The cleanup issues no attribute write or POSIX disposition. It verifies
absence after closing the selected handle and observation pin.

The documented extended operation is described in the [Windows
WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex)
and the [Win32 information class](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class).
Microsoft’s [C++ standard library implementation](https://github.com/microsoft/STL/blob/main/stl/src/filesystem.cpp)
dates support for the ignore-read-only flag to Windows 10 version 1809.
This fixture uses it only on the hosted Windows Server 2025 profile.
The portable controls cover selection, information class, flag values and
typed error reporting. Native execution of this cleanup remains a hosted
qualification requirement.

The selected handle retains its existing DELETE and read-attributes rights.
Exact local NTFS effectiveness with these rights is unqualified. Microsoft's
[SMB model](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4c26c8cb-5a8f-4339-a372-b315c4974131)
describes an additional write-attributes requirement. The hosted trial keeps
its existing access shape and retains a native refusal instead of requesting
wider rights or changing attributes after failure.

Hosted run `45953198194` at `8d0a5a5` reported `cleanup=deleted` and no
cleanup error for this owned build fixture with the unchanged access
rights. The nested process control still failed before publication cases.
This cleanup result does not qualify the NTFS publication adapter.

The hosted runner separately enables bounded process diagnostics to
investigate the nested-control process count. Observer errors are ancillary
to launch, accounting, timeout and drain decisions. Notifications and
PID-to-image-basename samples can be delayed, missing or stale; they grant
no process authority. The exact process-count assertion stays in place.
The added observer-refusal controls require native Windows execution.
