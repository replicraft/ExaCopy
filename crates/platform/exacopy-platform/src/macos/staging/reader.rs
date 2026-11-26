use std::fmt;

use apfs_mounted::metadata::Metadata;
use apfs_mounted::writer::ReadBack;
use exacopy_endpoint::ReadView;

use super::super::{metadata, with_materialization_disabled};
use super::file::{bounded_end, check_stage_view_acl};
use super::{ClosedStage, StageError};

impl ClosedStage<'_> {
	/// Independently opens the same private inode read-only after writer closure.
	///
	/// # Errors
	/// Refuses an unsafe or changed name, stage or root and reports failed opens or policy checks.
	pub fn open_read_back(&self) -> Result<StageReader<'_>, StageError> {
		with_materialization_disabled(|| {
			self.location.check_current()?;
			let read_back = self.closed.open_read_back()?;
			read_back.with_metadata(check_stage_view_acl)??;
			self.location.check_current()?;
			Ok(StageReader {
				stage: self,
				read_back,
			})
		})
	}
}

/// Independent, read-only handle for positioned read-back of the closed stage.
pub struct StageReader<'stage> {
	stage: &'stage ClosedStage<'stage>,
	read_back: ReadBack<'stage>,
}

impl StageReader<'_> {
	pub(super) fn observe_selected_metadata_with_policy(&self) -> Result<Metadata, StageError> {
		self.stage.location.check_current()?;
		let (stat, inventory) = self
			.read_back
			.with_metadata(|view| Ok((view.stat()?, metadata::check_view_inventory(&view))))?;
		inventory?;
		self.stage.location.check_current()?;
		Ok(stat)
	}

	/// Reads the exact requested stage range using at most 1 MiB per call.
	///
	/// # Errors
	/// A failed check or read may leave a partially updated buffer, which the caller must discard.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), StageError> {
		bounded_end(offset, buffer.len(), self.stage.length())?;
		with_materialization_disabled(|| {
			self.stage.location.check_current()?;
			self.read_back.with_metadata(check_stage_view_acl)??;
			self.read_back.read_exact_at(offset, buffer)?;
			self.read_back.with_metadata(check_stage_view_acl)??;
			self.stage.location.check_current()
		})
	}

	/// Confirms the held and named staged inode and observes logical EOF at the declared length.
	///
	/// # Errors
	/// Rejects changed identity or metadata, unexpected extra data, and I/O or policy failures.
	pub fn revalidate(&self) -> Result<(), StageError> {
		with_materialization_disabled(|| {
			self.stage.location.check_current()?;
			self.read_back.with_metadata(check_stage_view_acl)??;
			self.read_back.revalidate()?;
			self.read_back.with_metadata(check_stage_view_acl)??;
			self.stage.location.check_current()
		})
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
