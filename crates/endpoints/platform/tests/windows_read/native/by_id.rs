use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::null;

use exacopy_platform::windows::WindowsComponent;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
	ExtendedFileIdType, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
	FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_ID_128,
	FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_EXTD_DIR_INFO, FILE_READ_ATTRIBUTES,
	FILE_READ_DATA, FILE_SHARE_READ, FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo,
	GetFileInformationByHandleEx, OpenFileById, SYNCHRONIZE,
};

use super::{
	DATA_RECALL_ATTRIBUTES, HeldDirectory, Kind, ObjectId, Refusal, RegularFile, observe_file,
};
use crate::directory_entries::{
	ATTRIBUTES_OFFSET, DirectoryEntry, ENTRY_ALIGNMENT, EntryRefusal, ID_OFFSET, NAME_BYTES_OFFSET,
	NAME_OFFSET, NEXT_OFFSET, REPARSE_TAG_OFFSET, find_in_batch, ntfs_reference,
};

const _: () = {
	assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, NextEntryOffset) == NEXT_OFFSET);
	assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileAttributes) == ATTRIBUTES_OFFSET);
	assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileNameLength) == NAME_BYTES_OFFSET);
	assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, ReparsePointTag) == REPARSE_TAG_OFFSET);
	assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileId) == ID_OFFSET);
	assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileName) == NAME_OFFSET);
	assert!(align_of::<FILE_ID_EXTD_DIR_INFO>() == ENTRY_ALIGNMENT);
};

const BATCH_BYTES: u32 = 16 * 1024;
const MAX_BATCHES: usize = 128;

#[repr(C, align(8))]
struct DirectoryBuffer([u8; BATCH_BYTES as usize]);

#[derive(Debug)]
pub(crate) enum ByIdRefusal {
	Native(Refusal),
	Records(EntryRefusal),
	DirectoryQuery(io::Error),
	Open(io::Error),
	UnexpectedHandle,
	Missing,
	EnumerationLimit,
	WrongEntryKind,
	EntryChanged,
}

impl std::fmt::Display for ByIdRefusal {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Native(error) => error.fmt(formatter),
			Self::Records(error) => write!(formatter, "invalid directory evidence: {error:?}"),
			Self::DirectoryQuery(error) => {
				write!(formatter, "directory enumeration failed: {error}")
			}
			Self::Open(error) => write!(formatter, "file ID open failed: {error}"),
			other => write!(formatter, "{other:?}"),
		}
	}
}

#[path = "qualification.rs"]
mod qualification;

impl HeldDirectory<'_> {
	/// The caller gives this fixture exclusive use of the parent enumeration cursor.
	pub(crate) fn open_by_id(
		&mut self,
		name: WindowsComponent<'_>,
	) -> Result<RegularFile, ByIdRefusal> {
		self.open_by_id_after_observation(name, || {})
	}

	pub(crate) fn open_by_id_after_observation(
		&mut self,
		name: WindowsComponent<'_>,
		interleave: impl FnOnce(),
	) -> Result<RegularFile, ByIdRefusal> {
		let (handle, identity) =
			self.open_by_id_with_observations(name, ReadMode::Synchronous, lookup, interleave)?;
		Ok(RegularFile {
			file: handle.into(),
			identity,
		})
	}

	pub(super) fn open_by_id_for_comparison(
		&mut self,
		name: WindowsComponent<'_>,
	) -> Result<(OwnedHandle, ObjectId), ByIdRefusal> {
		self.open_by_id_with_observations(name, ReadMode::Overlapped, lookup, || {})
	}

	fn open_by_id_with_observations(
		&mut self,
		name: WindowsComponent<'_>,
		mode: ReadMode,
		mut observe_entry: impl FnMut(
			BorrowedHandle<'_>,
			WindowsComponent<'_>,
		) -> Result<DirectoryEntry, ByIdRefusal>,
		interleave: impl FnOnce(),
	) -> Result<(OwnedHandle, ObjectId), ByIdRefusal> {
		self.check_parent().map_err(ByIdRefusal::Native)?;
		let before = observe_entry(self.handle, name)?;
		let id = ntfs_reference(before.id).map_err(ByIdRefusal::Records)?;
		interleave();
		// The live, validated NTFS directory already belongs to the anchored volume.
		let handle = open_id(self.handle, id, mode)?;
		let file_id =
			observe_file(handle.as_handle(), Kind::RegularFile).map_err(ByIdRefusal::Native)?;
		if file_id.VolumeSerialNumber != self.identity.volume_serial
			|| file_id.FileId.Identifier != id
		{
			return Err(ByIdRefusal::EntryChanged);
		}
		// Re-observe name membership while the identity returned by OpenFileById is pinned.
		if observe_entry(self.handle, name)? != before {
			return Err(ByIdRefusal::EntryChanged);
		}
		self.check_parent().map_err(ByIdRefusal::Native)?;
		Ok((
			handle,
			ObjectId {
				volume: self.identity.volume,
				volume_serial: file_id.VolumeSerialNumber,
				file_id: id,
			},
		))
	}
}

fn lookup(
	handle: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
) -> Result<DirectoryEntry, ByIdRefusal> {
	let mut found: Option<DirectoryEntry> = None;
	let mut buffer = DirectoryBuffer([0; BATCH_BYTES as usize]);
	let mut class = FileIdExtdDirectoryRestartInfo;
	for _ in 0..MAX_BATCHES {
		buffer.0.fill(0);
		// SAFETY: The live handle supplies the cursor. The synchronous call receives a writable
		// 8-byte aligned buffer of the declared size for the documented directory record class.
		let result = unsafe {
			GetFileInformationByHandleEx(
				handle.as_raw_handle(),
				class,
				buffer.0.as_mut_ptr().cast(),
				BATCH_BYTES,
			)
		};
		if result == 0 {
			let error = io::Error::last_os_error();
			if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
				return Err(ByIdRefusal::DirectoryQuery(error));
			}
			let entry = found.ok_or(ByIdRefusal::Missing)?;
			let disallowed = FILE_ATTRIBUTE_DEVICE
				| FILE_ATTRIBUTE_DIRECTORY
				| FILE_ATTRIBUTE_REPARSE_POINT
				| DATA_RECALL_ATTRIBUTES;
			if entry.attributes & disallowed != 0 || entry.reparse_tag != 0 {
				return Err(ByIdRefusal::WrongEntryKind);
			}
			return Ok(entry);
		}
		find_in_batch(&buffer.0, name, &mut found).map_err(ByIdRefusal::Records)?;
		class = FileIdExtdDirectoryInfo;
	}
	Err(ByIdRefusal::EnumerationLimit)
}

#[derive(Clone, Copy)]
enum ReadMode {
	Synchronous,
	Overlapped,
}

fn open_id(
	volume_hint: BorrowedHandle<'_>,
	id: [u8; 16],
	mode: ReadMode,
) -> Result<OwnedHandle, ByIdRefusal> {
	let input = FILE_ID_DESCRIPTOR {
		dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
		Type: ExtendedFileIdType,
		Anonymous: FILE_ID_DESCRIPTOR_0 {
			ExtendedFileId: FILE_ID_128 { Identifier: id },
		},
	};
	// SAFETY: The live volume-hint handle and initialized descriptor match their ABI. The
	// existing-object call requests read-only rights and takes no path or security attributes.
	let flags = FILE_FLAG_OPEN_REPARSE_POINT
		| match mode {
			ReadMode::Synchronous => 0,
			ReadMode::Overlapped => FILE_FLAG_OVERLAPPED,
		};
	let handle = unsafe {
		OpenFileById(
			volume_hint.as_raw_handle(),
			&input,
			FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
			FILE_SHARE_READ,
			null(),
			flags,
		)
	};
	if handle == INVALID_HANDLE_VALUE {
		return Err(ByIdRefusal::Open(io::Error::last_os_error()));
	}
	if handle.is_null() {
		return Err(ByIdRefusal::UnexpectedHandle);
	}
	// SAFETY: A successful OpenFileById transfers ownership of the open handle to its caller.
	Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
