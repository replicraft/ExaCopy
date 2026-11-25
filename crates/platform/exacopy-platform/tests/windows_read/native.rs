use std::fs::File;
use std::io;
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};

use exacopy_platform::windows::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent};
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Storage::FileSystem::{
	FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, SYNCHRONIZE,
};

#[path = "../../src/windows/native.rs"]
mod handles;
pub(super) use handles::Refusal;
use handles::{
	DATA_RECALL_ATTRIBUTES, Kind, ObjectId, RelativeFileOpen, StandardInformation, observe,
	observe_file, open_relative_file, query,
};

#[path = "native/by_id.rs"]
mod by_id;
#[path = "native/comparison.rs"]
mod comparison;
pub(super) use by_id::ByIdRefusal;

/// A borrowed, already authorized parent. Its acquisition and path provenance are separate gates.
pub(super) struct HeldDirectory<'a> {
	handle: BorrowedHandle<'a>,
	identity: ObjectId,
}

impl<'a> HeldDirectory<'a> {
	pub(super) fn inspect(handle: BorrowedHandle<'a>) -> Result<Self, Refusal> {
		let identity = observe(handle, Kind::Directory)?;
		Ok(Self { handle, identity })
	}

	pub(super) fn open(&self, name: WindowsComponent<'_>) -> Result<RegularFile, Refusal> {
		// Re-observation catches reported drift. The native race gate must establish
		// how a change to a held parent's reparse state interacts with the relative open.
		self.check_parent()?;
		let handle = open_one(self.handle, name)?;
		let child = observe(handle.as_handle(), Kind::RegularFile)?;
		self.check_parent()?;
		if child.volume != self.identity.volume
			|| child.volume_serial != self.identity.volume_serial
		{
			return Err(Refusal::VolumeChanged);
		}
		Ok(RegularFile {
			file: handle.into(),
			identity: child,
		})
	}

	fn check_parent(&self) -> Result<(), Refusal> {
		if observe(self.handle, Kind::Directory)? != self.identity {
			return Err(Refusal::ParentChanged);
		}
		Ok(())
	}
}

/// An existing disk file opened with only read-data, read-attributes and synchronization rights.
pub(super) struct RegularFile {
	file: File,
	identity: ObjectId,
}

std::thread_local! {
	static POSITIONED_READ_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

impl RegularFile {
	pub(super) fn identity(&self) -> ObjectId {
		self.identity
	}

	/// A short read or zero at EOF is returned to the caller. Rust's Windows read updates
	/// the private file cursor, so this method keeps exclusive access to the held handle.
	pub(super) fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, ReadRefusal> {
		let count = u32::try_from(buffer.len()).map_err(|_| ReadRefusal::InvalidRange)?;
		let start = i64::try_from(offset).map_err(|_| ReadRefusal::InvalidRange)?;
		start
			.checked_add(i64::from(count))
			.ok_or(ReadRefusal::InvalidRange)?;
		if count == 0 {
			return Ok(0);
		}
		POSITIONED_READ_CALLS.set(POSITIONED_READ_CALLS.get() + 1);
		self.file.seek_read(buffer, offset).map_err(ReadRefusal::Io)
	}
}

#[derive(Debug)]
pub(super) enum ReadRefusal {
	InvalidRange,
	Io(io::Error),
}

impl std::fmt::Display for ReadRefusal {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidRange => formatter.write_str("invalid positioned read range"),
			Self::Io(error) => write!(formatter, "positioned read failed: {error}"),
		}
	}
}

fn open_one(
	parent: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
) -> Result<OwnedHandle, Refusal> {
	open_relative_file(
		parent,
		name,
		RelativeFileOpen {
			access: FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
			share: FILE_SHARE_READ,
			disposition: FILE_OPEN,
			attributes: 0,
			expected_result: None,
		},
	)
}
