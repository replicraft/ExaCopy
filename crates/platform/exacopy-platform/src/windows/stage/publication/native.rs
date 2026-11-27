use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Win32::Foundation::{
	ERROR_ALREADY_EXISTS, ERROR_CALL_NOT_IMPLEMENTED, ERROR_FILE_EXISTS, ERROR_INVALID_FUNCTION,
	ERROR_NOT_SUPPORTED, HANDLE, STATUS_SUCCESS,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_NAME_OPENED, FILE_RENAME_INFO, FileRenameInfo, GetDriveTypeW, SetFileInformationByHandle,
};

use super::{WindowsPublicationError, WindowsPublicationOutcome};
use crate::windows::native::{local_ntfs_path, parse_volume_guid};
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

pub(super) fn require_access(
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
	assert!(align_of::<RenameBuffer>() == align_of::<FILE_RENAME_INFO>());
	assert!(offset_of!(RenameBuffer, replace_if_exists) == offset_of!(FILE_RENAME_INFO, Anonymous));
	assert!(offset_of!(RenameBuffer, root) == offset_of!(FILE_RENAME_INFO, RootDirectory));
	assert!(offset_of!(RenameBuffer, name_length) == offset_of!(FILE_RENAME_INFO, FileNameLength));
	assert!(offset_of!(RenameBuffer, name) == offset_of!(FILE_RENAME_INFO, FileName));
};

impl RenameBuffer {
	fn new(
		root: HANDLE,
		name: WindowsComponent<'_>,
	) -> Result<(Self, u32), WindowsPublicationError> {
		let units = name.as_units();
		let name_length = u32::try_from(size_of_val(units))
			.map_err(|_| WindowsPublicationError::InvalidRenameLength)?;
		let bytes = size_of::<FILE_RENAME_INFO>()
			.checked_add(size_of_val(units))
			.and_then(|count| count.checked_add(size_of::<u16>()))
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
	let (mut buffer, bytes) = RenameBuffer::new(root.as_raw_handle(), name)
		.map_err(WindowsPublicationOutcome::Rejected)?;
	// SAFETY: Both borrowed handles are live through this synchronous call.
	// The initialized C-layout buffer has the native prefix and enough storage
	// for the counted UTF-16 component and its zero terminator. No replacement
	// or extended flags are set and the root is the held target directory.
	let success = unsafe {
		SetFileInformationByHandle(
			source.as_raw_handle(),
			FileRenameInfo,
			(&raw mut buffer).cast(),
			bytes,
		)
	};
	if success == 0 {
		return Err(classify(io::Error::last_os_error()));
	}
	Ok(())
}

fn classify(cause: io::Error) -> WindowsPublicationOutcome {
	match cause
		.raw_os_error()
		.and_then(|code| u32::try_from(code).ok())
	{
		Some(ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) => {
			WindowsPublicationOutcome::Conflict(cause)
		}
		Some(ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION | ERROR_CALL_NOT_IMPLEMENTED) => {
			WindowsPublicationOutcome::Unsupported(cause)
		}
		_ => WindowsPublicationOutcome::Uncertain(cause),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rename_buffer_has_counted_units_and_zero_replacement() {
		for length in [1, MAX_WINDOWS_COMPONENT_UNITS] {
			let units = vec![u16::from(b'x'); length];
			let (buffer, bytes) =
				RenameBuffer::new(std::ptr::null_mut(), WindowsComponent::new(&units).unwrap())
					.unwrap();
			assert_eq!(buffer.replace_if_exists, 0);
			assert_eq!(buffer.name_length as usize, length * size_of::<u16>());
			assert_eq!(&buffer.name[..length], &units);
			assert_eq!(buffer.name[length], 0);
			assert_eq!(
				bytes as usize,
				size_of::<FILE_RENAME_INFO>() + (length + 1) * size_of::<u16>(),
			);
			assert!(bytes as usize <= size_of::<RenameBuffer>());
		}
	}

	#[test]
	fn native_refusals_keep_unknown_effects_distinct() {
		assert!(matches!(
			classify(io::Error::from_raw_os_error(ERROR_NOT_SUPPORTED as i32)),
			WindowsPublicationOutcome::Unsupported(_)
		));
		assert!(matches!(
			classify(io::Error::from_raw_os_error(ERROR_ALREADY_EXISTS as i32)),
			WindowsPublicationOutcome::Conflict(_)
		));
		assert!(matches!(
			classify(io::Error::from_raw_os_error(5)),
			WindowsPublicationOutcome::Uncertain(_)
		));
	}
}
