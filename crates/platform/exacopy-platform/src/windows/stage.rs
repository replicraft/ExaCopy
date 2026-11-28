//! Experimental private staging under a caller-authorized Windows NTFS directory.

use std::fs::File;
use std::io;
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};

use exacopy_endpoint::{IoError, MAX_FILE_LENGTH, read_exact_at, write_all_at};
use exacopy_model::checked_range_end;
use windows_sys::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN};
use windows_sys::Win32::Foundation::{
	GENERIC_WRITE, OBJ_DONT_REPARSE, STATUS_OBJECT_NAME_COLLISION,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
};

use super::WindowsComponent;
use super::native::{
	Kind, ObjectId, Refusal, RelativeFileOpen, observe, observe_entry, open_relative_file,
};

mod capture;
mod error;
#[allow(
	unsafe_code,
	reason = "bounded handle observations and consuming Windows handle close"
)]
mod handles;
pub(super) mod publication;

use handles::{Stamp, close_writer, stamp};

pub use capture::{WindowsRetainedStage, WindowsStagePrefix, WindowsStageView};
pub use error::{NativeStageError, WindowsStageError};
pub use publication::{
	WindowsClosedPublicationStage, WindowsPublicationAttempt, WindowsPublicationBinding,
	WindowsPublicationDestination, WindowsPublicationError, WindowsPublicationMetadata,
	WindowsPublicationOutcome, WindowsPublicationRoot, WindowsPublicationTargetObservation,
	WindowsSealedPublicationStage, WindowsUnconfirmedPublicationDirectory,
	inspect_windows_publication_target,
};

/// Maximum bytes admitted for one synchronous stage read or write.
pub const MAX_WINDOWS_STAGE_IO_BYTES: usize = 4 * 1024 * 1024;

// NtCreateFile's FILE_CREATED and FILE_OPENED values in IO_STATUS_BLOCK.Information.
pub(in crate::windows) const FILE_CREATED_INFORMATION: usize = 2;
const FILE_OPENED_INFORMATION: usize = 1;
const READ_ACCESS: u32 = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

/// Borrowed NTFS directory for one-component private stage creation.
///
/// The caller provisions a private directory that excludes other writers and
/// namespace changes. It supplies the already authorized directory handle,
/// keeps it live without pending deletion, and establishes root path and ACL
/// provenance separately. This capability never resolves a path to the parent.
pub struct WindowsStageDirectory<'root> {
	handle: BorrowedHandle<'root>,
	identity: ObjectId,
}

impl<'root> WindowsStageDirectory<'root> {
	/// Binds an already authorized private directory on a local NTFS volume.
	///
	/// # Errors
	/// Rejects non-disk, non-directory, reparse, recall, delete-pending, or
	/// non-identifiable observations.
	pub fn from_authorized_handle(
		handle: BorrowedHandle<'root>,
	) -> Result<Self, WindowsStageError> {
		let identity = observe(handle, Kind::Directory).map_err(WindowsStageError::native)?;
		Ok(Self { handle, identity })
	}

	/// Exclusively creates a new empty one-link private stage.
	///
	/// # Errors
	/// Rejects an out-of-range length, occupied name, or uncertain native
	/// outcome. The stage is retained on any subsequent failure. The caller
	/// owns its selected name and must reconcile ambiguous outcomes.
	pub fn create<'stage>(
		&'stage self,
		name: WindowsComponent<'stage>,
		length: u64,
	) -> Result<WindowsStageWriter<'stage>, WindowsStageError> {
		self.create_with(name, length, |request| self.open(name, request))
	}

	#[cfg(feature = "experimental-windows-read")]
	pub(super) fn create_protected<'stage>(
		&'stage self,
		name: WindowsComponent<'stage>,
		length: u64,
		descriptor: &super::capture_creation::CreationDescriptor,
	) -> Result<WindowsStageWriter<'stage>, WindowsStageError> {
		self.create_with(name, length, |request| {
			descriptor.create(self.handle, name, request, Kind::RegularFile)
		})
	}

	fn create_with<'stage>(
		&'stage self,
		name: WindowsComponent<'stage>,
		length: u64,
		open: impl FnOnce(RelativeFileOpen) -> Result<OwnedHandle, Refusal>,
	) -> Result<WindowsStageWriter<'stage>, WindowsStageError> {
		if length > MAX_FILE_LENGTH {
			return Err(WindowsStageError::InvalidExtent);
		}
		self.check()?;
		let handle = match open(RelativeFileOpen {
			access: GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
			share: FILE_SHARE_READ,
			disposition: FILE_CREATE,
			attributes: OBJ_DONT_REPARSE,
			expected_result: Some(FILE_CREATED_INFORMATION),
		}) {
			Ok(handle) => handle,
			Err(Refusal::OpenFailed(STATUS_OBJECT_NAME_COLLISION)) => {
				return Err(WindowsStageError::Occupied);
			}
			Err(error) => return Err(WindowsStageError::creation_uncertain(error)),
		};
		let identity = observe(handle.as_handle(), Kind::RegularFile)
			.map_err(WindowsStageError::native)
			.map_err(created_unconfirmed)?;
		let location = Location {
			parent: self,
			name,
			identity,
		};
		location
			.check(handle.as_handle(), 0)
			.map_err(created_unconfirmed)?;
		Ok(WindowsStageWriter {
			location,
			file: Some(handle.into()),
			length,
			written: 0,
		})
	}

	fn check(&self) -> Result<(), WindowsStageError> {
		if observe(self.handle, Kind::Directory).map_err(WindowsStageError::native)?
			!= self.identity
		{
			return Err(WindowsStageError::native(Refusal::ParentChanged));
		}
		Ok(())
	}

	fn open(
		&self,
		name: WindowsComponent<'_>,
		request: RelativeFileOpen,
	) -> Result<OwnedHandle, Refusal> {
		open_relative_file(self.handle, name, request)
	}
}

struct Location<'stage> {
	parent: &'stage WindowsStageDirectory<'stage>,
	name: WindowsComponent<'stage>,
	identity: ObjectId,
}

impl Location<'_> {
	fn check(&self, file: BorrowedHandle<'_>, length: u64) -> Result<Stamp, WindowsStageError> {
		self.parent.check()?;
		let found = observe_entry(file, Kind::RegularFile, Some(self.name))
			.map_err(WindowsStageError::native)?;
		if found.volume != self.parent.identity.volume
			|| found.volume_serial != self.parent.identity.volume_serial
		{
			return Err(WindowsStageError::native(Refusal::VolumeChanged));
		}
		if found != self.identity {
			return Err(WindowsStageError::Changed);
		}
		stamp(file, length)
	}

	fn open_read(&self, share: u32) -> Result<File, WindowsStageError> {
		self.open_observation(READ_ACCESS, share)
	}

	fn open_observation(&self, access: u32, share: u32) -> Result<File, WindowsStageError> {
		self.parent.check()?;
		self.parent
			.open(
				self.name,
				RelativeFileOpen {
					access,
					share,
					disposition: FILE_OPEN,
					attributes: OBJ_DONT_REPARSE,
					expected_result: Some(FILE_OPENED_INFORMATION),
				},
			)
			.map(File::from)
			.map_err(WindowsStageError::native)
	}
}

/// The sole writable handle issued for a fresh stage. No writable descriptor escapes.
pub struct WindowsStageWriter<'stage> {
	location: Location<'stage>,
	file: Option<File>,
	length: u64,
	written: u64,
}

impl<'stage> WindowsStageWriter<'stage> {
	/// Returns the physical identity observed after exclusive creation.
	#[must_use]
	pub const fn identity(&self) -> ObjectId {
		self.location.identity
	}

	/// Writes one nonempty range at the next contiguous offset.
	///
	/// # Errors
	/// Rejects invalid ranges without issuing I/O. An observation or I/O failure
	/// retires the writable capability and leaves the stage for reconciliation.
	pub fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), WindowsStageError> {
		self.write_with(offset, bytes, |file, position, remaining| {
			file.seek_write(remaining, position)
		})
	}

	fn write_with(
		&mut self,
		offset: u64,
		bytes: &[u8],
		mut write: impl FnMut(&File, u64, &[u8]) -> io::Result<usize>,
	) -> Result<(), WindowsStageError> {
		if self.file.is_none() {
			return Err(WindowsStageError::WriterRetired);
		}
		if offset != self.written || bytes.is_empty() {
			return Err(WindowsStageError::InvalidRange);
		}
		let end = range_end(offset, bytes.len(), self.length)?;
		let file = self.file.take().ok_or(WindowsStageError::WriterRetired)?;
		self.location.check(file.as_handle(), self.written)?;
		write_all_at(offset, bytes, |position, remaining| {
			write(&file, position, remaining)
		})
		.map_err(WindowsStageError::Write)?;
		self.location.check(file.as_handle(), end)?;
		self.written = end;
		self.file = Some(file);
		Ok(())
	}

	/// Flushes the complete stage, explicitly closes its writer, and establishes independent read-back.
	///
	/// This file barrier does not establish namespace persistence or authorize publication.
	///
	/// # Errors
	/// Rejects an incomplete or retired writer and any unconfirmed barrier,
	/// writer close, name binding, or read-back observation.
	pub fn finish(self) -> Result<WindowsStageReadBack<'stage>, WindowsStageError> {
		self.finish_with(File::sync_all, close_writer)
	}

	fn finish_with(
		self,
		sync: impl FnOnce(&File) -> io::Result<()>,
		close: impl FnOnce(File) -> io::Result<()>,
	) -> Result<WindowsStageReadBack<'stage>, WindowsStageError> {
		self.finish_with_observation(sync, close, READ_ACCESS, FILE_SHARE_READ)
	}

	fn finish_with_observation(
		self,
		sync: impl FnOnce(&File) -> io::Result<()>,
		close: impl FnOnce(File) -> io::Result<()>,
		reader_access: u32,
		reader_share: u32,
	) -> Result<WindowsStageReadBack<'stage>, WindowsStageError> {
		let file = self.file.ok_or(WindowsStageError::WriterRetired)?;
		let Self {
			location,
			length,
			written,
			..
		} = self;
		if length != written {
			return Err(WindowsStageError::Incomplete);
		}
		location.check(file.as_handle(), length)?;
		sync(&file).map_err(WindowsStageError::Barrier)?;
		location.check(file.as_handle(), length)?;

		// Retain an identity pin across confirmed close. Its share mask permits
		// the existing writer only inside the caller-provisioned private root.
		// No read-back bytes are taken through this transitional handle.
		let pin = location.open_read(FILE_SHARE_READ | FILE_SHARE_WRITE)?;
		location.check(pin.as_handle(), length)?;
		close(file).map_err(WindowsStageError::CloseWriter)?;

		let reader = location.open_observation(reader_access, reader_share)?;
		let observed = location.check(reader.as_handle(), length)?;
		if location.check(pin.as_handle(), length)? != observed {
			return Err(WindowsStageError::Changed);
		}
		let observation = ObservedStage {
			location,
			file: reader,
			observed,
			length,
			reader_access,
			reader_share,
		};
		observation.check_eof()?;
		Ok(WindowsStageReadBack { observation })
	}
}

/// Independently reopened read-only stage after a confirmed file flush and writer close.
pub struct WindowsStageReadBack<'stage> {
	observation: ObservedStage<'stage>,
}

/// A live read-only observation that carries no writer closure or barrier provenance.
struct ObservedStage<'stage> {
	location: Location<'stage>,
	file: File,
	observed: Stamp,
	length: u64,
	reader_access: u32,
	reader_share: u32,
}

impl WindowsStageReadBack<'_> {
	/// Returns the physical identity checked on the independent read handle.
	#[must_use]
	pub const fn identity(&self) -> ObjectId {
		self.observation.location.identity
	}

	/// Reads a bounded exact range and revalidates the stage around it.
	///
	/// # Errors
	/// Rejects out-of-bounds ranges, identity or observation changes, and I/O
	/// failures. Discard the requested buffer on any failure.
	pub fn read_exact_at(
		&mut self,
		offset: u64,
		bytes: &mut [u8],
	) -> Result<(), WindowsStageError> {
		self.observation.read_checked(offset, bytes)
	}

	/// Checks the live held and named observations and logical EOF.
	///
	/// # Errors
	/// Rejects a changed or unavailable stage observation.
	pub fn recheck(&mut self) -> Result<(), WindowsStageError> {
		self.observation.check_eof()
	}
}

impl ObservedStage<'_> {
	fn read_checked(&self, offset: u64, bytes: &mut [u8]) -> Result<(), WindowsStageError> {
		range_end(offset, bytes.len(), self.length)?;
		let reader = self.open_checked_view()?;
		self.check_view_eof(&reader)?;
		read_exact_at(offset, bytes, |position, remaining| {
			reader.seek_read(remaining, position)
		})
		.map_err(WindowsStageError::Read)?;
		self.check_view_eof(&reader)?;
		self.open_checked_view()?;
		Ok(())
	}

	fn check_eof(&self) -> Result<(), WindowsStageError> {
		let reader = self.open_checked_view()?;
		self.check_view_eof(&reader)?;
		self.open_checked_view()?;
		Ok(())
	}

	fn open_checked_view(&self) -> Result<File, WindowsStageError> {
		let reader = self
			.location
			.open_observation(self.reader_access, self.reader_share)?;
		self.check_stamps(&reader)?;
		Ok(reader)
	}

	fn check_view_eof(&self, reader: &File) -> Result<(), WindowsStageError> {
		let mut extra = [0];
		if reader
			.seek_read(&mut extra, self.length)
			.map_err(|source| {
				WindowsStageError::Read(IoError::System {
					offset: self.length,
					source,
				})
			})?
			!= 0
		{
			return Err(WindowsStageError::Changed);
		}
		self.check_stamps(reader)
	}

	fn check_stamps(&self, named: &File) -> Result<(), WindowsStageError> {
		if self.location.check(self.file.as_handle(), self.length)? != self.observed
			|| self.location.check(named.as_handle(), self.length)? != self.observed
		{
			return Err(WindowsStageError::Changed);
		}
		Ok(())
	}
}

fn created_unconfirmed(error: WindowsStageError) -> WindowsStageError {
	WindowsStageError::CreatedUnconfirmed(Box::new(error))
}

fn range_end(offset: u64, count: usize, length: u64) -> Result<u64, WindowsStageError> {
	if count > MAX_WINDOWS_STAGE_IO_BYTES {
		return Err(WindowsStageError::InvalidRange);
	}
	let count = u64::try_from(count).map_err(|_| WindowsStageError::InvalidRange)?;
	let end = if count == 0 {
		(offset <= length).then_some(offset)
	} else {
		checked_range_end(length, offset, count)
	};
	end.ok_or(WindowsStageError::InvalidRange)
}

#[cfg(test)]
mod tests;
