use std::fmt;
use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::{UnixComponent, write_all_at};
use exacopy_model::CopyBinding;
use rustix::fs::{self, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::super::{
	EVENT_ONLY, FILE_MODE, PhysicalFsid, acl, file::same_observation, with_materialization_disabled,
};
use super::close::close_writer;
use super::{StageDirectory, StageError, StageIdentity};

const PRIVATE_OPEN: OFlags = OFlags::CLOEXEC
	.union(OFlags::NONBLOCK)
	.union(OFlags::NOFOLLOW);
pub(super) const MAX_STAGE_IO_BYTES: usize = 1024 * 1024;

/// Sole synchronous writer for a newly created private file and declared logical extent.
///
/// Its handle remains private. The only admitted ranges are contiguous and advance from
/// offset zero. Any uncertain attempted write retires the handle and retains its private entry.
pub struct WriteStage<'stage> {
	location: StageLocation<'stage>,
	file: Option<File>,
	position: u64,
	observed: Stat,
}

impl<'stage> WriteStage<'stage> {
	pub(super) fn create(
		directory: &'stage StageDirectory<'stage>,
		name: UnixComponent<'stage>,
		target: UnixComponent<'stage>,
		identity: StageIdentity,
		length: u64,
	) -> Result<Self, StageError> {
		let file = match fs::openat(
			directory.descriptor(),
			name.as_bytes(),
			PRIVATE_OPEN | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
			FILE_MODE,
		) {
			Ok(descriptor) => File::from(descriptor),
			Err(Errno::EXIST) => return Err(StageError::NameCollision),
			Err(error) => return Err(error.into()),
		};
		let observed = fs::fstat(&file)?;
		check_private(directory, &file, &observed)?;
		check_length(&observed, 0)?;
		directory.check_current()?;
		if !same_observation(&directory.named_stat(name)?, &observed) {
			return Err(StageError::StageChanged);
		}
		// Keep the inode pinned independently from the sole writer and the later
		// reader. This descriptor has neither content-read nor write authority.
		let anchor = File::from(fs::openat(
			directory.descriptor(),
			name.as_bytes(),
			PRIVATE_OPEN | EVENT_ONLY,
			Mode::empty(),
		)?);
		if !fs::fcntl_getfl(&anchor)?.contains(EVENT_ONLY) {
			return Err(StageError::StageChanged);
		}
		let location = StageLocation {
			directory,
			name,
			target,
			identity,
			length,
			anchor,
		};
		location.check_observation(&observed)?;
		Ok(Self {
			location,
			file: Some(file),
			position: 0,
			observed,
		})
	}

	/// Returns the identity allocated before this private file was created.
	#[must_use]
	pub fn identity(&self) -> StageIdentity {
		self.location.identity
	}

	/// Returns the transaction binding this writer will report to the model.
	#[must_use]
	pub fn binding(&self) -> CopyBinding {
		self.identity().binding()
	}

	/// Completes the next positioned chunk using at most 1 MiB from the supplied buffer.
	///
	/// # Errors
	/// Rejected ranges leave the writer unchanged. A failure after accepting a range
	/// retires this writer and retains its entry, which may contain a partial transfer.
	pub fn write_next(&mut self, bytes: &[u8]) -> Result<(), StageError> {
		self.write_next_with(bytes, |file, position, remaining| {
			file.write_at(remaining, position)
		})
	}

	fn write_next_with(
		&mut self,
		bytes: &[u8],
		mut write: impl FnMut(&File, u64, &[u8]) -> std::io::Result<usize>,
	) -> Result<(), StageError> {
		self.location.check_process()?;
		if self.file.is_none() {
			return Err(StageError::WriterRetired);
		}
		let end = bounded_end(self.position, bytes.len(), self.location.length)?;
		if bytes.is_empty() {
			return Err(StageError::InvalidRange);
		}
		let file = self.file.take().ok_or(StageError::WriterRetired)?;
		let observed = with_materialization_disabled(|| {
			self.location.check_observation(&self.observed)?;
			self.location.check_descriptor(&file, &self.observed)?;
			write_all_at(self.position, bytes, |position, remaining| {
				write(&file, position, remaining)
			})
			.map_err(StageError::Write)?;
			let observed = fs::fstat(&file)?;
			check_length(&observed, end)?;
			self.location.check_observation(&observed)?;
			Ok::<_, StageError>(observed)
		})?;
		self.file = Some(file);
		self.observed = observed;
		self.position = end;
		Ok(())
	}

	/// Consumes the sole writer after the full declared extent and a Darwin file barrier.
	///
	/// The successful result permits independent read-back. The barrier records a
	/// successful F_FULLFSYNC call on this descriptor.
	///
	/// # Errors
	/// Returns an error for incomplete data, a failed identity check, a retired writer,
	/// or a failed barrier or close. Every failure consumes the writer and retains the
	/// stage for reconciliation.
	pub fn flush_and_close(self) -> Result<ClosedStage<'stage>, StageError> {
		self.finish_with(|file| fs::fcntl_fullfsync(file), close_writer)
	}

	fn finish_with(
		self,
		sync: impl FnOnce(&File) -> rustix::io::Result<()>,
		close: impl FnOnce(File) -> Result<(), StageError>,
	) -> Result<ClosedStage<'stage>, StageError> {
		self.location.check_process()?;
		let file = self.file.ok_or(StageError::WriterRetired)?;
		if self.position != self.location.length {
			return Err(StageError::Incomplete);
		}
		with_materialization_disabled(|| {
			self.location.check_observation(&self.observed)?;
			self.location.check_descriptor(&file, &self.observed)?;
			sync(&file).map_err(|error| StageError::FileBarrier(error.into()))?;
			self.location.check_descriptor(&file, &self.observed)?;
			close(file)?;
			self.location.check_observation(&self.observed)?;
			Ok(ClosedStage {
				location: self.location,
				observed: self.observed,
			})
		})
	}
}

impl fmt::Debug for WriteStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.debug_struct("WriteStage").finish_non_exhaustive()
	}
}

/// A private inode with a fully written extent and a closed write descriptor.
///
/// The acquiring process confirmed closure of its sole writable descriptor under the
/// managed staging grant. An event-only descriptor retains the inode identity for a
/// separate readable open and independent comparison against the source stream.
pub struct ClosedStage<'stage> {
	pub(super) location: StageLocation<'stage>,
	pub(super) observed: Stat,
}

impl ClosedStage<'_> {
	/// Returns the logical extent fixed before staging began.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.location.length
	}

	/// Reports whether the declared extent was empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.length() == 0
	}

	/// Returns the identity allocated for this stage before exclusive creation.
	#[must_use]
	pub fn identity(&self) -> StageIdentity {
		self.location.identity
	}

	/// Returns the transaction binding fixed at exclusive creation.
	#[must_use]
	pub fn binding(&self) -> CopyBinding {
		self.identity().binding()
	}

	/// Returns the checked public target component fixed at exclusive creation.
	#[must_use]
	pub fn target(&self) -> UnixComponent<'_> {
		self.location.target
	}
}

impl fmt::Debug for ClosedStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ClosedStage")
			.finish_non_exhaustive()
	}
}

pub(super) struct StageLocation<'stage> {
	directory: &'stage StageDirectory<'stage>,
	name: UnixComponent<'stage>,
	target: UnixComponent<'stage>,
	identity: StageIdentity,
	length: u64,
	anchor: File,
}

impl StageLocation<'_> {
	pub(super) fn check_process(&self) -> Result<(), StageError> {
		self.directory.check_process()
	}

	pub(super) fn check_observation(&self, expected: &Stat) -> Result<(), StageError> {
		self.directory.check_current()?;
		self.check_descriptor(&self.anchor, expected)?;
		let named = self.directory.named_stat(self.name)?;
		if !same_observation(&named, expected) {
			return Err(StageError::StageChanged);
		}
		Ok(())
	}

	pub(super) fn check_descriptor(&self, file: &File, expected: &Stat) -> Result<(), StageError> {
		let observed = fs::fstat(file)?;
		if !same_observation(&observed, expected) {
			return Err(StageError::StageChanged);
		}
		check_private(self.directory, file, &observed)
	}

	pub(super) fn reopen_read_only(&self) -> Result<File, StageError> {
		let descriptor = fs::openat(
			self.directory.descriptor(),
			self.name.as_bytes(),
			PRIVATE_OPEN | OFlags::RDONLY,
			Mode::empty(),
		)?;
		Ok(descriptor.into())
	}
}

pub(super) fn bounded_end(offset: u64, length: usize, extent: u64) -> Result<u64, StageError> {
	if length > MAX_STAGE_IO_BYTES {
		return Err(StageError::InvalidRange);
	}
	let length = u64::try_from(length).map_err(|_| StageError::InvalidRange)?;
	match offset.checked_add(length) {
		Some(end) if end <= extent => Ok(end),
		_ => Err(StageError::InvalidRange),
	}
}

fn check_private(
	directory: &StageDirectory<'_>,
	file: &File,
	observed: &Stat,
) -> Result<(), StageError> {
	if FileType::from_raw_mode(observed.st_mode) != FileType::RegularFile
		|| observed.st_uid != directory.owner()
		|| observed.st_nlink != 1
		|| Mode::from_raw_mode(observed.st_mode) != FILE_MODE
		|| observed.st_flags != 0
		|| PhysicalFsid::held(file.as_fd())? != Some(directory.physical_fsid())
		|| !acl::has_no_stage_acl_entries(file.as_fd())?
	{
		return Err(StageError::StageChanged);
	}
	Ok(())
}

fn check_length(observed: &Stat, expected: u64) -> Result<(), StageError> {
	if u64::try_from(observed.st_size).ok() == Some(expected) {
		Ok(())
	} else {
		Err(StageError::StageChanged)
	}
}

#[cfg(test)]
mod tests;
