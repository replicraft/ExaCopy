use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::os::unix::fs::FileExt;

use exacopy_endpoint::{IoError, MAX_FILE_LENGTH, UnixComponent, read_exact_at, write_all_at};
use exacopy_model::CopyBinding;
use rustix::fs::{self, FileType, Mode, OFlags, Stat};
use rustix::io;
use rustix::process::geteuid;

use super::super::handle::{FileIdentity, mount_id};
use super::super::source::{SourceObservation, reopen_regular_read_only};
use super::directory::{CHILD_RESOLVE, StageName, component};
use super::{StageDirectory, StageError};

mod metadata;

pub(in crate::linux) use metadata::check_no_visible_attributes;

#[cfg(test)]
mod tests;

pub(in crate::linux) const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

/// Exclusive synchronous writer for one newly created private file.
///
/// The data handle cannot be extracted or cloned. Each write and resize holds a
/// mutable borrow for the entire operation. Dropping the writer retains the
/// private entry for later reconciliation.
pub struct WriteStage<'stage> {
	location: StageLocation<'stage>,
	file: File,
	barrier: WriteBarrier,
}

impl<'stage> WriteStage<'stage> {
	pub(super) fn create(
		directory: &'stage StageDirectory<'stage>,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
	) -> Result<Self, StageError> {
		let (file, stat) = create_private_file(
			&directory.directory,
			directory.root.mount,
			component(name),
			OFlags::WRONLY,
		)?;
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
			file,
			barrier: WriteBarrier::Pending,
		})
	}

	/// Returns the identity of the exclusively created stage.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.location.identity
	}

	/// Checks whether this stage's existing owner and group can represent the source.
	///
	/// # Errors
	///
	/// Returns an error for a changed stage, an unusable writer, or mismatched
	/// UID/GID. The adapter does not change ownership.
	pub fn check_ownership(&self, source: SourceObservation) -> Result<(), StageError> {
		self.barrier.require_usable()?;
		let stat = self.location.check_named_file(FILE_MODE)?;
		if stat.st_uid != source.owner() || stat.st_gid != source.group() {
			return Err(StageError::DifferentOwnership);
		}
		Ok(())
	}

	/// Writes a complete buffer at the specified absolute byte position.
	///
	/// # Errors
	///
	/// A prior file barrier failure prevents any further writes. Other failures
	/// include bounded-range, incomplete-transfer, and system errors. An error
	/// can leave partially written data in the private stage.
	pub fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StageError> {
		self.barrier.require_usable()?;
		self.barrier = WriteBarrier::Pending;
		write_all_at(offset, bytes, |position, remaining| {
			self.file.write_at(remaining, position)
		})
		.map_err(StageError::Write)
	}

	/// Sets the private file's exact logical length.
	///
	/// # Errors
	///
	/// A prior file barrier failure prevents resizing. Returns an error if the
	/// length exceeds the signed offset limit or resizing fails. A subsequent
	/// close requires a successful full flush.
	pub fn set_len(&mut self, length: u64) -> Result<(), StageError> {
		self.barrier.require_usable()?;
		if length > MAX_FILE_LENGTH {
			return Err(StageError::InvalidLength);
		}
		self.barrier = WriteBarrier::Pending;
		Ok(fs::ftruncate(&self.file, length)?)
	}

	/// Requests a full file barrier.
	///
	/// # Errors
	///
	/// Returns an error for a changed stage name or inode, unsafe stage, or
	/// failed file sync. A file sync failure permanently blocks this stage and
	/// leaves its private entry for reconciliation.
	pub fn flush(&mut self) -> Result<(), StageError> {
		self.flush_with(|file| fs::fsync(file))
	}

	fn flush_with(&mut self, sync: impl FnOnce(&File) -> io::Result<()>) -> Result<(), StageError> {
		self.barrier.require_usable()?;
		self.barrier = WriteBarrier::Pending;
		let before = self.location.check_named_file(FILE_MODE)?;
		if let Err(source) = sync(&self.file) {
			// Linux can report a writeback error only once for this open file.
			self.barrier = WriteBarrier::Failed;
			return Err(StageError::BarrierFailed(source.into()));
		}
		let after = fs::fstat(&self.file)?;
		check_stage_file(&after, FILE_MODE)?;
		check_content_stamp(&before, &after)?;
		self.barrier = WriteBarrier::Complete(after);
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
		let flushed = match self.barrier {
			WriteBarrier::Pending => return Err(StageError::Unflushed),
			WriteBarrier::Complete(stat) => stat,
			WriteBarrier::Failed => return Err(StageError::PriorBarrierFailure),
		};
		self.location.check_named_file(FILE_MODE)?;
		let (read_back, stat) =
			reopen_regular_read_only(&self.file).map_err(StageError::ReadBack)?;
		check_stage_file(&stat, FILE_MODE)?;
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
			metadata_applied: false,
		})
	}
}

enum WriteBarrier {
	Pending,
	Complete(Stat),
	Failed,
}

impl WriteBarrier {
	fn require_usable(&self) -> Result<(), StageError> {
		match self {
			Self::Pending | Self::Complete(_) => Ok(()),
			Self::Failed => Err(StageError::PriorBarrierFailure),
		}
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
	metadata_applied: bool,
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
		let current = self
			.location
			.check_named_file(Mode::from_raw_mode(self.stat.st_mode))?;
		check_content_stamp(&self.stat, &current)?;
		if self.stat.st_uid != current.st_uid || self.stat.st_gid != current.st_gid {
			return Err(StageError::IdentityChanged);
		}
		if self.metadata_applied {
			if self.stat.st_atime != current.st_atime
				|| self.stat.st_atime_nsec != current.st_atime_nsec
			{
				return Err(StageError::MetadataMismatch);
			}
			check_no_visible_attributes(&self.file)?;
		}
		Ok(())
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
	fn check_named_file(&self, expected_mode: Mode) -> Result<Stat, StageError> {
		self.directory.check_current()?;
		check_named_file(
			&self.directory.directory,
			self.name.as_os_str(),
			self.identity,
			self.directory.root.mount,
			expected_mode,
		)
	}
}

pub(in crate::linux) fn check_named_file(
	directory: &File,
	name: &OsStr,
	identity: FileIdentity,
	mount: u64,
	expected_mode: Mode,
) -> Result<Stat, StageError> {
	let file = fs::openat2(
		directory,
		name,
		OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
		Mode::empty(),
		CHILD_RESOLVE,
	)?;
	let stat = fs::fstat(&file)?;
	if FileIdentity::from_stat(&stat) != identity || mount_id(&file)? != mount {
		return Err(StageError::IdentityChanged);
	}
	check_stage_file(&stat, expected_mode)?;
	Ok(stat)
}

pub(in crate::linux) fn create_private_file(
	directory: &File,
	mount: u64,
	name: &OsStr,
	access: OFlags,
) -> Result<(File, Stat), StageError> {
	let file = fs::openat2(
		directory,
		name,
		access | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
		FILE_MODE,
		CHILD_RESOLVE,
	)
	.map_err(StageError::on_create)?;
	let stat = fs::fstat(&file)?;
	check_stage_file(&stat, FILE_MODE)?;
	if mount_id(&file)? != mount {
		return Err(StageError::IdentityChanged);
	}
	Ok((file.into(), stat))
}

fn check_stage_file(stat: &Stat, expected_mode: Mode) -> Result<(), StageError> {
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| stat.st_uid != geteuid().as_raw()
		|| stat.st_nlink != 1
		|| Mode::from_raw_mode(stat.st_mode) != expected_mode
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
			.field(
				"flushed",
				&matches!(self.barrier, WriteBarrier::Complete(_)),
			)
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
