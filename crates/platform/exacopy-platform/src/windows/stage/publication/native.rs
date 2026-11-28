use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Wdk::Storage::FileSystem::{
	FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
	HANDLE, NTSTATUS, RtlNtStatusToDosError, STATUS_INVALID_DEVICE_REQUEST, STATUS_NOT_IMPLEMENTED,
	STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION, STATUS_SUCCESS,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_CASE_SENSITIVE_INFO, FILE_NAME_OPENED, FileCaseSensitiveInfo, GetDriveTypeW,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{WindowsPublicationError, WindowsPublicationOutcome};
use crate::windows::native::{local_ntfs_path, parse_volume_guid, query};
use crate::windows::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent};

// PUBLIC_OBJECT_BASIC_INFORMATION from the Windows SDK. The object manager has
// only one writable output of this size and the reserved fields stay opaque.
#[derive(Default)]
#[repr(C)]
struct ObjectBasic {
	attributes: u32,
	granted_access: u32,
	handle_count: u32,
	pointer_count: u32,
	reserved: [u32; 10],
}

pub(in crate::windows) fn require_access(
	parent: BorrowedHandle<'_>,
	required: u32,
) -> Result<(), WindowsPublicationError> {
	let mut info = ObjectBasic::default();
	let size = u32::try_from(size_of::<ObjectBasic>())
		.map_err(|_| WindowsPublicationError::DestinationAccess)?;
	let mut written = 0;
	// SAFETY: The borrowed handle is live. This synchronous object-manager query
	// receives a correctly sized initialized PUBLIC_OBJECT_BASIC_INFORMATION buffer.
	let status = unsafe {
		NtQueryObject(
			parent.as_raw_handle(),
			ObjectBasicInformation,
			(&raw mut info).cast(),
			size,
			&mut written,
		)
	};
	if status != STATUS_SUCCESS {
		return Err(WindowsPublicationError::DestinationAccessQuery(status));
	}
	if written != size || info.granted_access & required != required {
		return Err(WindowsPublicationError::DestinationAccess);
	}
	Ok(())
}

pub(super) fn require_fixed_ntfs(
	parent: BorrowedHandle<'_>,
) -> Result<(), WindowsPublicationError> {
	const MAX_PATH_UNITS: usize = 32_768;
	// GetDriveTypeW's fixed local media classification.
	const DRIVE_FIXED: u32 = 3;
	let mut path = [0_u16; MAX_PATH_UNITS];
	let count = local_ntfs_path(parent, FILE_NAME_OPENED, &mut path)
		.map_err(WindowsPublicationError::native)?;
	let (_, relative) =
		parse_volume_guid(&path[..count]).map_err(WindowsPublicationError::native)?;
	let root_end = count - relative.len();
	path[root_end] = 0;
	// SAFETY: The validated path prefix is a complete volume GUID root with
	// its trailing backslash and a terminating zero in the live buffer.
	if unsafe { GetDriveTypeW(path.as_ptr()) } != DRIVE_FIXED {
		return Err(WindowsPublicationError::UnsupportedVolume);
	}
	Ok(())
}

pub(in crate::windows) fn require_case_insensitive(
	parent: BorrowedHandle<'_>,
) -> Result<(), WindowsPublicationError> {
	let mut info = FILE_CASE_SENSITIVE_INFO::default();
	// SAFETY: The class matches the initialized, correctly sized output type.
	unsafe { query(parent, FileCaseSensitiveInfo, &mut info) }
		.map_err(WindowsPublicationError::native)?;
	if info.Flags != 0 {
		return Err(WindowsPublicationError::CaseSensitiveDestination);
	}
	Ok(())
}

// Leave room for native header padding in addition to the counted name and
// its terminator on both supported pointer widths.
const RENAME_NAME_CAPACITY: usize = MAX_WINDOWS_COMPONENT_UNITS + 3;

#[repr(C)]
struct RenameBuffer {
	replace_if_exists: u32,
	#[cfg(target_pointer_width = "64")]
	alignment_padding: u32,
	root: HANDLE,
	name_length: u32,
	name: [u16; RENAME_NAME_CAPACITY],
}

const _: () = {
	assert!(align_of::<RenameBuffer>() == align_of::<FILE_RENAME_INFORMATION>());
	assert!(
		offset_of!(RenameBuffer, replace_if_exists)
			== offset_of!(FILE_RENAME_INFORMATION, Anonymous)
	);
	assert!(offset_of!(RenameBuffer, root) == offset_of!(FILE_RENAME_INFORMATION, RootDirectory));
	assert!(
		offset_of!(RenameBuffer, name_length)
			== offset_of!(FILE_RENAME_INFORMATION, FileNameLength)
	);
	assert!(offset_of!(RenameBuffer, name) == offset_of!(FILE_RENAME_INFORMATION, FileName));
};

impl RenameBuffer {
	fn new(
		root: HANDLE,
		name: WindowsComponent<'_>,
	) -> Result<(Self, u32), WindowsPublicationError> {
		let units = name.as_units();
		let name_length = u32::try_from(size_of_val(units))
			.map_err(|_| WindowsPublicationError::InvalidRenameLength)?;
		// The name begins at FileName, and the WDK requires the total
		// allocation to cover sizeof(FILE_RENAME_INFORMATION) plus its bytes.
		let header_tail =
			size_of::<FILE_RENAME_INFORMATION>() - offset_of!(FILE_RENAME_INFORMATION, FileName);
		let bytes = offset_of!(Self, name)
			.checked_add(size_of_val(units))
			.and_then(|end| end.checked_add(header_tail))
			.filter(|&count| count <= size_of::<Self>())
			.and_then(|count| u32::try_from(count).ok())
			.ok_or(WindowsPublicationError::InvalidRenameLength)?;
		let mut buffer = Self {
			replace_if_exists: 0,
			#[cfg(target_pointer_width = "64")]
			alignment_padding: 0,
			root,
			name_length,
			name: [0; RENAME_NAME_CAPACITY],
		};
		buffer.name[..units.len()].copy_from_slice(units);
		Ok((buffer, bytes))
	}
}

pub(super) fn rename_no_replace(
	source: BorrowedHandle<'_>,
	root: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
) -> Result<(), WindowsPublicationOutcome> {
	let (buffer, bytes) = RenameBuffer::new(root.as_raw_handle(), name)
		.map_err(WindowsPublicationOutcome::Rejected)?;
	let mut io_status = IO_STATUS_BLOCK::default();
	// SAFETY: The DELETE-capable source pin was opened for synchronous I/O.
	// NtSetInformationFile completes synchronously, with both handles and both
	// buffers live. The initialized WDK layout uses the held directory, a
	// counted single UTF-16 component and the legacy no-replace setting.
	let status = unsafe {
		NtSetInformationFile(
			source.as_raw_handle(),
			&mut io_status,
			(&raw const buffer).cast(),
			bytes,
			FileRenameInformation,
		)
	};
	if status != STATUS_SUCCESS {
		return Err(classify(status));
	}
	Ok(())
}

fn classify(status: NTSTATUS) -> WindowsPublicationOutcome {
	// SAFETY: This conversion takes the status by value and has no pointers.
	let code = unsafe { RtlNtStatusToDosError(status) };
	let cause = io::Error::from_raw_os_error(i32::from_ne_bytes(code.to_ne_bytes()));
	match status {
		STATUS_OBJECT_NAME_COLLISION => WindowsPublicationOutcome::Conflict(cause),
		STATUS_NOT_SUPPORTED | STATUS_INVALID_DEVICE_REQUEST | STATUS_NOT_IMPLEMENTED => {
			WindowsPublicationOutcome::Unsupported(cause)
		}
		_ => WindowsPublicationOutcome::Uncertain(cause),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use windows_sys::Win32::Foundation::{
		ERROR_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_EXISTS,
		STATUS_PENDING,
	};

	#[test]
	fn rename_buffer_has_counted_units_and_zero_replacement() {
		let root: HANDLE = std::ptr::dangling_mut::<u8>().cast();
		for length in [1, MAX_WINDOWS_COMPONENT_UNITS] {
			let units = vec![u16::from(b'x'); length];
			let (buffer, bytes) =
				RenameBuffer::new(root, WindowsComponent::new(&units).unwrap()).unwrap();
			assert_eq!(buffer.replace_if_exists, 0);
			assert_eq!(buffer.root, root);
			assert_eq!(buffer.name_length as usize, length * size_of::<u16>());
			assert_eq!(&buffer.name[..length], &units);
			assert_eq!(buffer.name[length], 0);
			assert_eq!(
				bytes as usize,
				size_of::<FILE_RENAME_INFORMATION>() + length * size_of::<u16>(),
			);
			assert!(bytes as usize <= size_of::<RenameBuffer>());
		}
	}

	#[test]
	fn native_refusals_keep_unknown_effects_distinct() {
		assert!(matches!(
			classify(STATUS_NOT_SUPPORTED),
			WindowsPublicationOutcome::Unsupported(_)
		));
		assert!(matches!(
			classify(STATUS_OBJECT_NAME_COLLISION),
			WindowsPublicationOutcome::Conflict(_)
		));
		assert!(matches!(
			classify(STATUS_INVALID_PARAMETER),
			WindowsPublicationOutcome::Uncertain(error)
				if error.raw_os_error() == i32::try_from(ERROR_INVALID_PARAMETER).ok()
		));
		for status in [STATUS_OBJECT_NAME_EXISTS, STATUS_PENDING] {
			assert!(matches!(
				classify(status),
				WindowsPublicationOutcome::Uncertain(_)
			));
		}
	}
}
