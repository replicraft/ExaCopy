use std::fs::File;
use std::io;
use std::os::windows::io::{BorrowedHandle, IntoRawHandle};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO, FileBasicInfo, FileStandardInfo,
};

use super::WindowsStageError;
use crate::windows::native::{StandardInformation, query};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Stamp {
	created: i64,
	written: i64,
	changed: i64,
	attributes: u32,
}

impl Stamp {
	pub(super) fn has_archive(self) -> bool {
		self.attributes & FILE_ATTRIBUTE_ARCHIVE != 0
	}

	pub(super) fn preserves_required(self, original: Self) -> bool {
		self.created == original.created
			&& self.written == original.written
			&& self.attributes == original.attributes
	}
}

pub(super) fn stamp(handle: BorrowedHandle<'_>, length: u64) -> Result<Stamp, WindowsStageError> {
	let mut standard = StandardInformation::default();
	let mut basic = FILE_BASIC_INFO::default();
	// SAFETY: Both classes match their initialized, ABI-checked output types.
	unsafe {
		query(handle, FileStandardInfo, &mut standard).map_err(WindowsStageError::native)?;
		query(handle, FileBasicInfo, &mut basic).map_err(WindowsStageError::native)?;
	}
	if standard.delete_pending != 0
		|| standard.directory != 0
		|| standard.link_count != 1
		|| u64::try_from(standard.end_of_file) != Ok(length)
	{
		return Err(WindowsStageError::Changed);
	}
	// An admitted stage is an ordinary unnamed data stream on a regular file.
	// Refuse storage-changing attributes, including new flags this profile
	// has not qualified. ARCHIVE can be set by ordinary writes.
	let supported = FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL;
	if basic.FileAttributes == 0 || basic.FileAttributes & !supported != 0 {
		return Err(WindowsStageError::Changed);
	}
	Ok(Stamp {
		created: basic.CreationTime,
		written: basic.LastWriteTime,
		changed: basic.ChangeTime,
		attributes: basic.FileAttributes,
	})
}

pub(super) fn close_writer(file: File) -> io::Result<()> {
	let handle = file.into_raw_handle();
	// SAFETY: Consuming the File gives this call the sole ownership of the live
	// handle and prevents a destructor from attempting to close it again.
	if unsafe { CloseHandle(handle) } == 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}
