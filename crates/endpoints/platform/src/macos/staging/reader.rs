use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::{MAX_INTERRUPTED_RETRIES, ReadView, read_exact_at};

use super::super::with_materialization_disabled;
use super::file::bounded_end;
use super::{ClosedStage, StageError};

impl ClosedStage<'_> {
	/// Independently opens the same private inode read-only after writer closure.
	///
	/// # Errors
	/// Refuses an unsafe or changed name, stage or root and reports failed opens or policy checks.
	pub fn open_read_back(&self) -> Result<StageReader<'_>, StageError> {
		self.location.check_process()?;
		with_materialization_disabled(|| {
			self.location.check_observation(&self.observed)?;
			let reader = StageReader {
				stage: self,
				file: self.location.reopen_read_only()?,
			};
			reader.check_current()?;
			Ok(reader)
		})
	}
}

/// Independent, read-only handle for positioned read-back of the closed stage.
pub struct StageReader<'stage> {
	stage: &'stage ClosedStage<'stage>,
	file: File,
}

impl StageReader<'_> {
	/// Reads the exact requested stage range using at most 1 MiB per call.
	///
	/// # Errors
	/// A failed check or read may leave a partially updated buffer, which the caller must discard.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), StageError> {
		self.stage.location.check_process()?;
		bounded_end(offset, buffer.len(), self.stage.length())?;
		with_materialization_disabled(|| {
			self.check_current()?;
			read_exact_at(offset, buffer, |position, remaining| {
				self.file.read_at(remaining, position)
			})
			.map_err(StageError::Read)?;
			self.check_current()
		})
	}

	/// Confirms the held and named staged inode and observes logical EOF at the declared length.
	///
	/// # Errors
	/// Rejects changed identity or metadata, unexpected extra data, and I/O or policy failures.
	pub fn revalidate(&self) -> Result<(), StageError> {
		self.stage.location.check_process()?;
		with_materialization_disabled(|| {
			self.check_current()?;
			let mut retries = MAX_INTERRUPTED_RETRIES;
			loop {
				match self.file.read_at(&mut [0], self.stage.length()) {
					Ok(0) => break,
					Ok(_) => return Err(StageError::UnexpectedDataAfterEnd),
					Err(error) if error.kind() == io::ErrorKind::Interrupted && retries > 0 => {
						retries -= 1;
					}
					Err(error) => return Err(error.into()),
				}
			}
			self.check_current()
		})
	}

	fn check_current(&self) -> Result<(), StageError> {
		self.stage
			.location
			.check_observation(&self.stage.observed)?;
		self.stage
			.location
			.check_descriptor(&self.file, &self.stage.observed)
	}
}

impl fmt::Debug for StageReader<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("StageReader")
			.finish_non_exhaustive()
	}
}

impl ReadView for StageReader<'_> {
	type Error = StageError;

	fn length(&self) -> u64 {
		self.stage.length()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.revalidate()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		StageReader::read_exact_at(self, offset, buffer)
	}
}
