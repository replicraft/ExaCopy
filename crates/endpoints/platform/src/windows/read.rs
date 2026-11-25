//! Read-only live file observations on a local fixed NTFS volume.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};
use std::path::Path;
use std::sync::Mutex;

use exacopy_endpoint::{MAX_FILE_LENGTH, ReadView, read_exact_at};
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Foundation::OBJ_DONT_REPARSE;
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
	FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
	FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
};

use super::WindowsComponent;
use super::native::{
	DATA_RECALL_ATTRIBUTES, Kind, ObjectId, Refusal, RelativeFileOpen, observe,
	open_relative_entry, open_relative_file,
};

mod error;
#[allow(
	unsafe_code,
	reason = "bounded fixed-drive and initialized file information queries"
)]
mod native;

use super::read_path::{DrivePath, MAX_PATH_UNITS};
use error::ReadError;
pub use error::WindowsReadError;
use native::{comparison_information, ensure_fixed_drive, observe_fixed_root};

const DIRECTORY_RIGHTS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const DIRECTORY_SHARING: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
// NtCreateFile's FILE_OPENED value in IO_STATUS_BLOCK.Information.
const FILE_OPENED_INFORMATION: usize = 1;

/// A held read-only Windows file and its bounded chain of local NTFS directories.
///
/// Its observations support live comparison. External changes can escape the available
/// metadata checks, including mutations through a mapping or an unqualified filter.
#[derive(Debug)]
pub struct WindowsReadFile {
	ancestors: Vec<HeldDirectory>,
	// FileExt::seek_read can change the Windows file pointer, so keep one call in flight
	// per held file. The two inputs use separate file handles.
	file: Mutex<File>,
	observation: Observation,
}

impl WindowsReadFile {
	/// Binds a regular file reached by walking a literal absolute drive path.
	///
	/// Each child open is relative to its held directory. The drive letter is resolved
	/// once in the caller's trusted Windows device namespace. The captured root is
	/// required to be the physical root of a local fixed NTFS volume.
	///
	/// # Errors
	///
	/// Returns a refusal for unsupported spelling, filesystem, reparse state, changed
	/// ancestry, or an unsuccessful Windows observation or open.
	pub fn open_absolute(path: &Path) -> Result<Self, WindowsReadError> {
		let units: Vec<_> = path
			.as_os_str()
			.encode_wide()
			.take(MAX_PATH_UNITS + 1)
			.collect();
		let drive = DrivePath::parse(&units).map_err(ReadError::Path)?;
		let mut parent = HeldDirectory::open_root(drive.letter)?;
		let volume = parent.identity;
		let mut ancestors = Vec::with_capacity(drive.parents.len() + 1);
		let directory_request = RelativeFileOpen {
			access: DIRECTORY_RIGHTS,
			share: DIRECTORY_SHARING,
			disposition: FILE_OPEN,
			attributes: OBJ_DONT_REPARSE,
			expected_result: Some(FILE_OPENED_INFORMATION),
		};
		for component in drive.parents {
			let child = open_relative_entry(
				parent.handle.as_handle(),
				component,
				directory_request,
				Kind::Directory,
			)?;
			let identity = observe(child.as_handle(), Kind::Directory)?;
			same_volume(identity, volume)?;
			ancestors.push(parent);
			parent = HeldDirectory {
				handle: child,
				identity,
			};
		}
		let (file, observation) = open_checked_regular(&parent, drive.leaf)?;
		ancestors.push(parent);
		let file = Self {
			ancestors,
			file: Mutex::new(file.into()),
			observation,
		};
		file.check_ancestry()?;
		Ok(file)
	}

	fn check_ancestry(&self) -> Result<(), WindowsReadError> {
		for held in &self.ancestors {
			if observe(held.handle.as_handle(), Kind::Directory)? != held.identity {
				return Err(Refusal::ParentChanged.into());
			}
		}
		Ok(())
	}

	fn check_file(&self, file: &File) -> Result<(), WindowsReadError> {
		if Observation::capture(file.as_handle())? != self.observation {
			return Err(ReadError::Changed.into());
		}
		Ok(())
	}
}

impl ReadView for WindowsReadFile {
	type Error = WindowsReadError;

	fn length(&self) -> u64 {
		self.observation.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.check_ancestry()?;
		let file = self.file.lock().map_err(|_| ReadError::ReaderUnavailable)?;
		self.check_file(&file)?;
		let count = file
			.seek_read(&mut [0], self.length())
			.map_err(ReadError::Read)?;
		if count != 0 {
			return Err(ReadError::Changed.into());
		}
		self.check_file(&file)?;
		self.check_ancestry()
	}

	fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
		let length = u64::try_from(output.len()).map_err(|_| ReadError::Range)?;
		if !matches!(offset.checked_add(length), Some(end) if end <= self.length()) {
			return Err(ReadError::Range.into());
		}
		let file = self.file.lock().map_err(|_| ReadError::ReaderUnavailable)?;
		read_exact_at(offset, output, |position, remaining| {
			file.seek_read(remaining, position)
		})
		.map_err(|error| ReadError::ExactRead(error).into())
	}
}

#[derive(Debug)]
struct HeldDirectory {
	handle: OwnedHandle,
	identity: ObjectId,
}

impl HeldDirectory {
	fn open_root(letter: u8) -> Result<Self, WindowsReadError> {
		let root = [u16::from(letter), u16::from(b':'), u16::from(b'\\')];
		ensure_fixed_drive(&[root[0], root[1], root[2], 0])?;
		let mut spelling = OsString::from(r"\\?\");
		spelling.push(OsString::from_wide(&root));
		let handle = OpenOptions::new()
			.access_mode(DIRECTORY_RIGHTS)
			.share_mode(DIRECTORY_SHARING)
			.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
			.open(spelling)
			.map_err(ReadError::RootOpen)?;
		let identity = observe_fixed_root(handle.as_handle())?;
		Ok(Self {
			handle: handle.into(),
			identity,
		})
	}
}

fn open_checked_regular(
	parent: &HeldDirectory,
	name: WindowsComponent<'_>,
) -> Result<(OwnedHandle, Observation), WindowsReadError> {
	let metadata_request = RelativeFileOpen {
		access: FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		share: FILE_SHARE_READ,
		disposition: FILE_OPEN,
		attributes: OBJ_DONT_REPARSE,
		expected_result: Some(FILE_OPENED_INFORMATION),
	};
	let metadata = open_relative_file(parent.handle.as_handle(), name, metadata_request)?;
	// Check the leaf before requesting data access. Retain the first handle
	// through the second open so both observations refer to the held object.
	let before = Observation::capture(metadata.as_handle())?;
	same_volume(before.identity, parent.identity)?;
	let read_request = RelativeFileOpen {
		access: FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		..metadata_request
	};
	let file = open_relative_file(parent.handle.as_handle(), name, read_request)?;
	if Observation::capture(file.as_handle())? != before {
		return Err(ReadError::Changed.into());
	}
	Ok((file, before))
}

fn same_volume(actual: ObjectId, root: ObjectId) -> Result<(), Refusal> {
	if actual.volume != root.volume || actual.volume_serial != root.volume_serial {
		return Err(Refusal::VolumeChanged);
	}
	Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Observation {
	identity: ObjectId,
	length: u64,
	creation_time: i64,
	write_time: i64,
	change_time: i64,
	attributes: u32,
}

impl Observation {
	fn capture(handle: BorrowedHandle<'_>) -> Result<Self, WindowsReadError> {
		let identity = observe(handle, Kind::RegularFile)?;
		let (standard, basic) = comparison_information(handle)?;
		const DISALLOWED: u32 = FILE_ATTRIBUTE_DEVICE
			| FILE_ATTRIBUTE_DIRECTORY
			| FILE_ATTRIBUTE_REPARSE_POINT
			| DATA_RECALL_ATTRIBUTES;
		if standard.delete_pending != 0
			|| standard.directory != 0
			|| basic.FileAttributes & DISALLOWED != 0
		{
			return Err(ReadError::Changed.into());
		}
		let length = u64::try_from(standard.end_of_file).map_err(|_| ReadError::Extent)?;
		if length > MAX_FILE_LENGTH {
			return Err(ReadError::Extent.into());
		}
		Ok(Self {
			identity,
			length,
			creation_time: basic.CreationTime,
			write_time: basic.LastWriteTime,
			change_time: basic.ChangeTime,
			attributes: basic.FileAttributes,
		})
	}
}
