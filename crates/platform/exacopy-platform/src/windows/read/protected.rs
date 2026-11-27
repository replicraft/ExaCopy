//! Read-only protected snapshots on local fixed NTFS.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::FileExt as _;
use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};
use std::path::Path;

use exacopy_endpoint::read_exact_at;
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Foundation::{
	ERROR_SHARING_VIOLATION, OBJ_DONT_REPARSE, STATUS_REPARSE_POINT_ENCOUNTERED,
	STATUS_SHARING_VIOLATION,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, READ_CONTROL,
	SYNCHRONIZE,
};

use crate::protected_snapshot::{MAX_PROTECTED_SNAPSHOT_BYTES, ProtectedSnapshotError as Error};
use crate::windows::native::streams::{StreamError, require_unnamed_stream};
use crate::windows::native::{
	Kind, ObjectId, Refusal, RelativeFileOpen, local_ntfs_path, observe_file, open_relative_entry,
	parse_volume_guid,
};

use super::{
	DIRECTORY_RIGHTS, DrivePath, FILE_OPENED_INFORMATION, HeldDirectory, MAX_PATH_UNITS,
	WindowsComponent, comparison_information, observe_fixed_root,
};

mod acl;
#[allow(
	unsafe_code,
	reason = "bounded Windows token and self-relative descriptor queries"
)]
mod security;

#[cfg(test)]
mod tests;

const READBACK_CHUNK_BYTES: usize = 16 * 1024;
const DIRECTORY_ACCESS: u32 = DIRECTORY_RIGHTS | READ_CONTROL;
const FILE_METADATA_ACCESS: u32 = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

pub(crate) fn read(path: &Path) -> Result<Vec<u8>, Error> {
	with_snapshot(path, MAX_PROTECTED_SNAPSHOT_BYTES, |snapshot| {
		let mut output = vec![0; snapshot.length()];
		snapshot.read_twice(&mut output, &mut [0; READBACK_CHUNK_BYTES])?;
		Ok(output)
	})
}

pub(crate) fn read_into(
	path: &Path,
	bytes: &mut [u8],
	readback: &mut [u8],
) -> Result<usize, Error> {
	if readback.is_empty() {
		return Err(Error::Unavailable);
	}
	let limit = bytes.len().min(MAX_PROTECTED_SNAPSHOT_BYTES);
	with_snapshot(path, limit, |snapshot| {
		let length = snapshot.length();
		snapshot.read_twice(&mut bytes[..length], readback)?;
		Ok(length)
	})
}

fn with_snapshot<T>(
	path: &Path,
	limit: usize,
	read: impl FnOnce(Snapshot<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
	let units: Vec<_> = path
		.as_os_str()
		.encode_wide()
		.take(MAX_PATH_UNITS + 1)
		.collect();
	let drive = DrivePath::parse(&units).map_err(|_| Error::InvalidPath)?;
	if drive.parents.is_empty() {
		return Err(Error::InvalidPath);
	}
	read(Snapshot::open(drive, limit)?)
}

struct Snapshot<'path> {
	path: DrivePath<'path>,
	subject: security::Subject,
	directories: Vec<Directory>,
	file: File,
	leaf: Binding,
	stamp: LeafStamp,
}

impl<'path> Snapshot<'path> {
	fn open(path: DrivePath<'path>, limit: usize) -> Result<Self, Error> {
		let subject = security::Subject::current()?;
		let root = hold_root(path.letter)?;
		let volume = root.identity;
		let mut directories = vec![Directory {
			binding: Binding::capture(
				root.handle.as_handle(),
				root.identity,
				&subject,
				acl::Role::UpperDirectory,
			)?,
			handle: root.handle,
		}];

		for (index, &name) in path.parents.iter().enumerate() {
			let parent = directories.last().ok_or(Error::InvalidPath)?;
			let role = directory_role(index, path.parents.len());
			let handle = open_relative(
				parent.handle.as_handle(),
				name,
				Kind::Directory,
				DIRECTORY_ACCESS,
			)?;
			let identity = named_identity(handle.as_handle(), Kind::Directory, name)?;
			super::same_volume(identity, volume).map_err(refused)?;
			let binding = Binding::capture(handle.as_handle(), identity, &subject, role)?;
			directories.push(Directory { handle, binding });
		}

		let parent = directories.last().ok_or(Error::InvalidPath)?;
		let first = open_relative(
			parent.handle.as_handle(),
			path.leaf,
			Kind::RegularFile,
			FILE_METADATA_ACCESS,
		)?;
		let (leaf, stamp) = observe_leaf(first.as_handle(), path.leaf, &subject)?;
		super::same_volume(leaf.identity, volume).map_err(refused)?;
		if stamp.length > limit {
			return Err(Error::TooLarge);
		}
		stamp.check_stream(first.as_handle(), Error::Unprotected)?;
		let file = open_relative(
			parent.handle.as_handle(),
			path.leaf,
			Kind::RegularFile,
			FILE_METADATA_ACCESS | FILE_READ_DATA,
		)?;
		let (held_leaf, held_stamp) = observe_leaf(file.as_handle(), path.leaf, &subject)?;
		if held_leaf != leaf || held_stamp != stamp {
			return Err(Error::Changed);
		}
		stamp.check_stream(file.as_handle(), Error::Changed)?;
		Ok(Self {
			path,
			subject,
			directories,
			file: file.into(),
			leaf,
			stamp,
		})
	}

	fn length(&self) -> usize {
		self.stamp.length
	}

	fn check_current(&self) -> Result<(), Error> {
		if security::Subject::current()? != self.subject {
			return Err(Error::Changed);
		}
		let root = self.directories.first().ok_or(Error::Changed)?;
		let reopened_root = hold_root(self.path.letter)?;
		let held_id = observe_fixed_root(root.handle.as_handle()).map_err(root_error)?;
		root.binding.recheck(root.handle.as_handle(), held_id)?;
		root.binding
			.recheck(reopened_root.handle.as_handle(), reopened_root.identity)?;

		for (pair, &name) in self.directories.windows(2).zip(&self.path.parents) {
			let [parent, held] = pair else {
				return Err(Error::Changed);
			};
			let freshly_named = open_relative(
				parent.handle.as_handle(),
				name,
				Kind::Directory,
				DIRECTORY_ACCESS,
			)?;
			for current in [held.handle.as_handle(), freshly_named.as_handle()] {
				let identity = named_identity(current, Kind::Directory, name)?;
				held.binding.recheck(current, identity)?;
			}
		}

		let parent = self.directories.last().ok_or(Error::Changed)?;
		let named = open_relative(
			parent.handle.as_handle(),
			self.path.leaf,
			Kind::RegularFile,
			FILE_METADATA_ACCESS,
		)?;
		for handle in [self.file.as_handle(), named.as_handle()] {
			let identity = named_identity(handle, Kind::RegularFile, self.path.leaf)?;
			self.leaf.recheck(handle, identity)?;
			if LeafStamp::capture(handle)? != self.stamp {
				return Err(Error::Changed);
			}
			self.stamp.check_stream(handle, Error::Changed)?;
		}
		if security::Subject::current()? != self.subject {
			return Err(Error::Changed);
		}
		Ok(())
	}

	fn read_twice(&self, output: &mut [u8], readback: &mut [u8]) -> Result<(), Error> {
		self.check_current()?;
		read_at(&self.file, 0, output)?;
		self.eof()?;
		self.check_current()?;
		let mut offset = 0_u64;
		for chunk in output.chunks(readback.len()) {
			let observed = &mut readback[..chunk.len()];
			read_at(&self.file, offset, observed)?;
			if chunk != observed {
				return Err(Error::Changed);
			}
			offset += chunk.len() as u64;
		}
		self.eof()?;
		self.check_current()
	}

	fn eof(&self) -> Result<(), Error> {
		match self.file.seek_read(&mut [0], self.length() as u64) {
			Ok(0) => Ok(()),
			Ok(_) => Err(Error::Changed),
			Err(error) => Err(io_error(&error)),
		}
	}
}

struct Directory {
	handle: OwnedHandle,
	binding: Binding,
}

#[derive(PartialEq, Eq)]
struct Binding {
	identity: ObjectId,
	security: Vec<u8>,
}

impl Binding {
	fn capture(
		handle: BorrowedHandle<'_>,
		identity: ObjectId,
		subject: &security::Subject,
		role: acl::Role,
	) -> Result<Self, Error> {
		let security = security::descriptor(handle)?;
		acl::approve(&security, &subject.sid, role)?;
		Ok(Self { identity, security })
	}

	fn recheck(&self, handle: BorrowedHandle<'_>, identity: ObjectId) -> Result<(), Error> {
		if self.identity != identity || self.security != security::descriptor(handle)? {
			return Err(Error::Changed);
		}
		Ok(())
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LeafStamp {
	length: usize,
	creation_time: i64,
	write_time: i64,
	change_time: i64,
	attributes: u32,
}

impl LeafStamp {
	fn capture(handle: BorrowedHandle<'_>) -> Result<Self, Error> {
		let (standard, basic) = comparison_information(handle).map_err(refused)?;
		if standard.delete_pending != 0 || standard.directory != 0 || standard.link_count != 1 {
			return Err(Error::Unprotected);
		}
		let length = usize::try_from(standard.end_of_file).map_err(|_| Error::TooLarge)?;
		Ok(Self {
			length,
			creation_time: basic.CreationTime,
			write_time: basic.LastWriteTime,
			change_time: basic.ChangeTime,
			attributes: basic.FileAttributes,
		})
	}

	fn check_stream(self, handle: BorrowedHandle<'_>, unsupported: Error) -> Result<(), Error> {
		require_unnamed_stream(handle, self.length as u64).map_err(|error| match error {
			StreamError::Query(_cause) => Error::Unavailable,
			StreamError::Unsupported => unsupported,
		})
	}
}

fn observe_leaf(
	handle: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
	subject: &security::Subject,
) -> Result<(Binding, LeafStamp), Error> {
	let identity = named_identity(handle, Kind::RegularFile, name)?;
	let binding = Binding::capture(handle, identity, subject, acl::Role::Private)?;
	Ok((binding, LeafStamp::capture(handle)?))
}

fn hold_root(letter: u8) -> Result<HeldDirectory, Error> {
	HeldDirectory::open_root_with(letter, DIRECTORY_ACCESS, FILE_SHARE_READ)
		.map_err(|error| root_error(error.0))
}

fn root_error(error: super::error::ReadError) -> Error {
	use super::error::ReadError;
	match error {
		ReadError::NotFixedDrive | ReadError::NotVolumeRoot => Error::Unsupported,
		ReadError::Native(error) => refused(error),
		ReadError::RootOpen(error)
			if error.raw_os_error() == i32::try_from(ERROR_SHARING_VIOLATION).ok() =>
		{
			Error::Busy
		}
		_ => Error::Unavailable,
	}
}

fn named_identity(
	handle: BorrowedHandle<'_>,
	kind: Kind,
	name: WindowsComponent<'_>,
) -> Result<ObjectId, Error> {
	let info = observe_file(handle, kind).map_err(refused)?;
	let mut buffer = [0; MAX_PATH_UNITS + 1];
	let count = local_ntfs_path(handle, FILE_NAME_NORMALIZED, &mut buffer).map_err(refused)?;
	let (volume, relative) = parse_volume_guid(&buffer[..count]).map_err(refused)?;
	if relative.rsplit(|&unit| unit == u16::from(b'\\')).next() != Some(name.as_units()) {
		return Err(Error::Unprotected);
	}
	Ok(ObjectId {
		volume,
		volume_serial: info.VolumeSerialNumber,
		file_id: info.FileId.Identifier,
	})
}

fn open_relative(
	parent: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
	kind: Kind,
	access: u32,
) -> Result<OwnedHandle, Error> {
	open_relative_entry(
		parent,
		name,
		RelativeFileOpen {
			access,
			share: FILE_SHARE_READ,
			disposition: FILE_OPEN,
			attributes: OBJ_DONT_REPARSE,
			expected_result: Some(FILE_OPENED_INFORMATION),
		},
		kind,
	)
	.map_err(refused)
}

fn directory_role(index: usize, count: usize) -> acl::Role {
	if index + 1 == count {
		acl::Role::Private
	} else {
		acl::Role::UpperDirectory
	}
}

fn read_at(file: &File, offset: u64, output: &mut [u8]) -> Result<(), Error> {
	read_exact_at(offset, output, |position, buffer| {
		file.seek_read(buffer, position)
	})
	.map_err(|error| match error {
		exacopy_endpoint::IoError::UnexpectedEof { .. } => Error::Changed,
		exacopy_endpoint::IoError::System { source, .. } => io_error(&source),
		_ => Error::Unavailable,
	})
}

fn io_error(error: &io::Error) -> Error {
	match error.kind() {
		io::ErrorKind::UnexpectedEof | io::ErrorKind::NotFound => Error::Changed,
		_ => Error::Unavailable,
	}
}

fn refused(error: Refusal) -> Error {
	match error {
		Refusal::OpenFailed(STATUS_SHARING_VIOLATION) => Error::Busy,
		Refusal::NotDisk
		| Refusal::NotNtfs
		| Refusal::UnidentifiedVolume
		| Refusal::VolumeChanged => Error::Unsupported,
		Refusal::ReparsePoint
		| Refusal::WrongKind
		| Refusal::DeletePending
		| Refusal::OpenFailed(STATUS_REPARSE_POINT_ENCOUNTERED) => Error::Unprotected,
		Refusal::ParentChanged => Error::Changed,
		_ => Error::Unavailable,
	}
}
