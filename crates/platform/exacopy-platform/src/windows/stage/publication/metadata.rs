use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows_sys::Win32::Security::{
	DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, OWNER_SECURITY_INFORMATION,
	SE_DACL_PRESENT, SE_SELF_RELATIVE, SECURITY_DESCRIPTOR_RELATIVE,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_STREAM_INFO, FileStreamInfo, GetFileInformationByHandleEx,
};

use super::WindowsPublicationError;
use crate::windows::stage::handles::Stamp;

const SECURITY_BYTES: usize = 16 * 1024;
const STREAM_NAME_CAPACITY: usize = 256;
const DATA_STREAM: [u16; 7] = [58, 58, 36, 68, 65, 84, 65]; // ::$DATA

/// Exact held observations for the experimental unnamed-stream metadata profile.
///
/// This profile includes the owner and DACL, creation and last-write times,
/// admitted attributes and one unnamed stream of the selected extent. Access
/// time can change on a read. Arbitrary NTFS metadata fidelity requires a
/// separate policy and is outside this profile.
pub struct WindowsPublicationMetadata {
	stamp: Stamp,
	extent: u64,
	security: Vec<u8>,
}

impl WindowsPublicationMetadata {
	pub(super) fn observe(
		handle: BorrowedHandle<'_>,
		stamp: Stamp,
		extent: u64,
	) -> Result<Self, WindowsPublicationError> {
		// NTFS rename sets ARCHIVE. Refuse before publication when that
		// would alter the required file attributes.
		if !stamp.has_archive() {
			return Err(WindowsPublicationError::UnsupportedMetadata);
		}
		require_unnamed_stream(handle, extent)?;
		Ok(Self {
			stamp,
			extent,
			security: descriptor(handle)?,
		})
	}

	pub(super) fn matches_required(&self, original: &Self) -> bool {
		self.extent == original.extent
			&& self.security == original.security
			&& self.stamp.preserves_required(original.stamp)
	}
}

#[repr(C, align(8))]
struct StreamBuffer {
	next: u32,
	name_bytes: u32,
	size: i64,
	allocation: i64,
	name: [u16; STREAM_NAME_CAPACITY],
}

const _: () = {
	assert!(align_of::<StreamBuffer>() == 8);
	assert!(offset_of!(StreamBuffer, next) == offset_of!(FILE_STREAM_INFO, NextEntryOffset));
	assert!(offset_of!(StreamBuffer, name_bytes) == offset_of!(FILE_STREAM_INFO, StreamNameLength));
	assert!(offset_of!(StreamBuffer, size) == offset_of!(FILE_STREAM_INFO, StreamSize));
	assert!(
		offset_of!(StreamBuffer, allocation) == offset_of!(FILE_STREAM_INFO, StreamAllocationSize)
	);
	assert!(offset_of!(StreamBuffer, name) == offset_of!(FILE_STREAM_INFO, StreamName));
};

fn require_unnamed_stream(
	handle: BorrowedHandle<'_>,
	extent: u64,
) -> Result<(), WindowsPublicationError> {
	let mut stream = StreamBuffer {
		next: 0,
		name_bytes: 0,
		size: 0,
		allocation: 0,
		name: [0; STREAM_NAME_CAPACITY],
	};
	let size = u32::try_from(size_of::<StreamBuffer>())
		.map_err(|_| WindowsPublicationError::UnsupportedMetadata)?;
	// SAFETY: The live handle and writable buffer are valid through this
	// synchronous query. The buffer is initialized, bounded, and the prefix
	// and alignment match FILE_STREAM_INFO.
	let success = unsafe {
		GetFileInformationByHandleEx(
			handle.as_raw_handle(),
			FileStreamInfo,
			(&raw mut stream).cast(),
			size,
		)
	};
	if success == 0 {
		return Err(WindowsPublicationError::MetadataQuery(
			io::Error::last_os_error(),
		));
	}
	if stream.next != 0
		|| usize::try_from(stream.name_bytes).ok() != Some(size_of_val(&DATA_STREAM))
		|| !stream.name.starts_with(&DATA_STREAM)
		|| u64::try_from(stream.size).ok() != Some(extent)
		|| stream.allocation < 0
	{
		return Err(WindowsPublicationError::UnsupportedMetadata);
	}
	Ok(())
}

#[repr(align(4))]
struct SecurityBuffer([u8; SECURITY_BYTES]);

pub(super) fn descriptor(handle: BorrowedHandle<'_>) -> Result<Vec<u8>, WindowsPublicationError> {
	let mut storage = SecurityBuffer([0; SECURITY_BYTES]);
	let mut written = 0;
	let size =
		u32::try_from(SECURITY_BYTES).map_err(|_| WindowsPublicationError::UnsupportedMetadata)?;
	// SAFETY: The handle stays live. Both writable outputs are correctly
	// aligned and the initialized descriptor buffer has the declared size.
	let success = unsafe {
		GetKernelObjectSecurity(
			handle.as_raw_handle(),
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			storage.0.as_mut_ptr().cast(),
			size,
			&mut written,
		)
	};
	if success == 0 {
		return Err(WindowsPublicationError::MetadataQuery(
			io::Error::last_os_error(),
		));
	}
	let bytes = usize::try_from(written)
		.ok()
		.and_then(|count| storage.0.get(..count))
		.ok_or(WindowsPublicationError::UnsupportedMetadata)?;
	if !has_owner_and_dacl(bytes) {
		return Err(WindowsPublicationError::UnsupportedMetadata);
	}
	Ok(bytes.to_vec())
}

fn has_owner_and_dacl(bytes: &[u8]) -> bool {
	const CONTROL: usize = offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Control);
	const OWNER: usize = offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Owner);
	const DACL: usize = offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Dacl);
	const HEADER: usize = size_of::<SECURITY_DESCRIPTOR_RELATIVE>();
	if bytes.len() < HEADER || bytes[0] != 1 {
		return false;
	}
	let control = u16::from_le_bytes([bytes[CONTROL], bytes[CONTROL + 1]]);
	control & (SE_SELF_RELATIVE | SE_DACL_PRESENT) == SE_SELF_RELATIVE | SE_DACL_PRESENT
		&& [OWNER, DACL].into_iter().all(|field| {
			let offset = bytes[field..field + 4]
				.try_into()
				.ok()
				.map(u32::from_le_bytes)
				.and_then(|offset| usize::try_from(offset).ok());
			offset.is_some_and(|offset| offset % 4 == 0 && offset >= HEADER && offset < bytes.len())
		})
}
