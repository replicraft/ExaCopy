use std::fmt;
use std::fs::File;
use std::os::unix::fs::FileExt;

use exacopy_endpoint::{IoError, MAX_FILE_LENGTH, UnixComponent, read_exact_at, write_all_at};
use exacopy_model::CopyBinding;
use rustix::fs::{self, FileType, Mode, OFlags, Stat};
use rustix::process::geteuid;

use super::super::handle::{FileIdentity, mount_id};
use super::super::source::reopen_regular_read_only;
use super::directory::{CHILD_RESOLVE, StageName, component};
use super::{StageDirectory, StageError};

const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

/// Exclusive synchronous writer for one newly created private file.
///
/// The data handle cannot be extracted or cloned. Each write and resize holds a
/// mutable borrow for the entire operation. Dropping the writer retains the
/// private entry for later reconciliation.
pub struct WriteStage<'stage> {
	location: StageLocation<'stage>,
	file: File,
	flushed: Option<Stat>,
}

impl<'stage> WriteStage<'stage> {
	pub(super) fn create(
		directory: &'stage StageDirectory<'stage>,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
	) -> Result<Self, StageError> {
		let file = fs::openat2(
			&directory.directory,
			component(name),
			OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			FILE_MODE,
			CHILD_RESOLVE,
		)
		.map_err(StageError::on_create)?;
		let stat = fs::fstat(&file)?;
		check_private_file(&stat)?;
		if mount_id(&file)? != directory.root.mount {
			return Err(StageError::IdentityChanged);
		}
		let identity = FileIdentity::from_stat(&stat);
		let location = StageLocation {
			directory,
			name: StageName::from(name),
			target: StageName::from(target),
			binding,
			identity,
		};

		Ok(Self {
			location,
			file: file.into(),
			flushed: None,
		})
	}

	/// Writes a complete buffer at the specified absolute byte position.
	///
	/// # Errors
	///
	/// Returns a bounded-range, incomplete-transfer, or system error. An error
	/// can leave partially written data in the private stage.
	pub fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), IoError> {
		self.flushed = None;
		write_all_at(offset, bytes, |position, remaining| {
			self.file.write_at(remaining, position)
		})
	}

	/// Sets the private file's exact logical length.
	///
	/// # Errors
	///
	/// Returns an error if the length exceeds the signed offset limit or resizing
	/// fails. A subsequent close requires a successful full flush.
	pub fn set_len(&mut self, length: u64) -> Result<(), StageError> {
		if length > MAX_FILE_LENGTH {
			return Err(StageError::InvalidLength);
		}
		self.flushed = None;
		Ok(fs::ftruncate(&self.file, length)?)
	}

	/// Requests a full file barrier.
	///
	/// # Errors
	///
	/// Returns an error for a changed stage name or inode, unsafe stage, or
	/// failed file sync. Any failed flush prevents closure until another flush
	/// succeeds.
	pub fn flush(&mut self) -> Result<(), StageError> {
		self.flushed = None;
		let before = self.location.check_named_file()?;
		fs::fsync(&self.file)?;
		let after = fs::fstat(&self.file)?;
		check_private_file(&after)?;
		check_content_stamp(&before, &after)?;
		self.flushed = Some(after);
		Ok(())
	}

	/// Releases the only data-writing handle and returns a pinned read-only stage.
	///
	/// # Errors
	///
	/// Requires a successful full flush after the last write or resize, the
	/// unchanged stage entry, and a verified read-only reopen of the same inode.
	/// An error releases the writer and leaves its private file in place.
	pub fn close_writes(self) -> Result<ClosedStage<'stage>, StageError> {
		let flushed = self.flushed.ok_or(StageError::Unflushed)?;
		self.location.check_named_file()?;
		let (read_back, stat) =
			reopen_regular_read_only(&self.file).map_err(StageError::ReadBack)?;
		check_private_file(&stat)?;
		check_content_stamp(&flushed, &stat)?;
		let length = u64::try_from(stat.st_size).map_err(|_| StageError::InvalidLength)?;
		if length > MAX_FILE_LENGTH {
			return Err(StageError::InvalidLength);
		}
		drop(self.file);

		Ok(ClosedStage {
			location: self.location,
			file: read_back,
			stat,
			length,
		})
	}
}

/// Pinned read-only view of a private stage after its writer has been released.
///
/// Reading this view supplies bytes for the coordinator's independent
/// verification. Publication also needs that coordinator's model authorization.
pub struct ClosedStage<'stage> {
	pub(super) location: StageLocation<'stage>,
	file: File,
	stat: Stat,
	length: u64,
}

impl ClosedStage<'_> {
	/// The opened file identity of this stage.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.location.identity
	}

	/// Logical byte length observed on the opened read-back handle.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.length
	}

	/// Reads the complete buffer at the specified absolute byte position.
	///
	/// # Errors
	///
	/// Returns an error if the range extends beyond the captured length or if
	/// read-back encounters early EOF or a system failure.
	pub fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), IoError> {
		let length = u64::try_from(bytes.len()).map_err(|_| IoError::InvalidRange {
			offset,
			length: bytes.len(),
		})?;
		if !offset
			.checked_add(length)
			.is_some_and(|end| end <= self.length)
		{
			return Err(IoError::InvalidRange {
				offset,
				length: bytes.len(),
			});
		}
		read_exact_at(offset, bytes, |position, remaining| {
			self.file.read_at(remaining, position)
		})
	}

	pub(super) fn check_current(&self) -> Result<(), StageError> {
		let current = self.location.check_named_file()?;
		check_content_stamp(&self.stat, &current)
	}
}

pub(super) struct StageLocation<'stage> {
	pub(super) directory: &'stage StageDirectory<'stage>,
	pub(super) name: StageName,
	pub(super) target: StageName,
	pub(super) binding: CopyBinding,
	identity: FileIdentity,
}

impl StageLocation<'_> {
	fn check_named_file(&self) -> Result<Stat, StageError> {
		self.directory.check_current()?;
		let file = fs::openat2(
			&self.directory.directory,
			self.name.as_os_str(),
			OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			CHILD_RESOLVE,
		)?;
		let stat = fs::fstat(&file)?;
		if FileIdentity::from_stat(&stat) != self.identity
			|| mount_id(&file)? != self.directory.root.mount
		{
			return Err(StageError::IdentityChanged);
		}
		check_private_file(&stat)?;
		Ok(stat)
	}
}

fn check_private_file(stat: &Stat) -> Result<(), StageError> {
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| stat.st_uid != geteuid().as_raw()
		|| stat.st_nlink != 1
		|| Mode::from_raw_mode(stat.st_mode) != FILE_MODE
	{
		return Err(StageError::UnsafeFile);
	}
	Ok(())
}

fn check_content_stamp(previous: &Stat, current: &Stat) -> Result<(), StageError> {
	if previous.st_size != current.st_size
		|| previous.st_mtime != current.st_mtime
		|| previous.st_mtime_nsec != current.st_mtime_nsec
		|| previous.st_ctime != current.st_ctime
		|| previous.st_ctime_nsec != current.st_ctime_nsec
	{
		return Err(StageError::IdentityChanged);
	}
	Ok(())
}

impl fmt::Debug for WriteStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WriteStage")
			.field("identity", &self.location.identity)
			.field("flushed", &self.flushed.is_some())
			.finish_non_exhaustive()
	}
}

impl fmt::Debug for ClosedStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ClosedStage")
			.field("identity", &self.location.identity)
			.field("length", &self.length)
			.finish_non_exhaustive()
	}
}
