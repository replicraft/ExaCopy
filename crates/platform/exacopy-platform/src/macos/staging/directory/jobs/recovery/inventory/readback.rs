use std::fmt;
use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::read_exact_at;
use rustix::fs::{self, Mode, OFlags, Stat};

use super::super::super::super::super::super::{BasicMetadata, metadata};
use super::super::super::super::super::{StageError, file::bounded_end, reader::check_logical_eof};
use super::{
	DirectoryLease, EVENT_ONLY, HeldEntry, PhysicalFsid, RecoveryError, RecoveryFileObservation,
	RecoveryInventory, RecoveryName, same_observation, with_materialization_disabled,
};

const READ_STAGE: OFlags = OFlags::RDONLY
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK)
	.union(OFlags::CLOEXEC);

impl RecoveryInventory<'_> {
	/// Independently opens the selected private stage for fresh read-back.
	///
	/// Pass the exact stage observation after checking it against the accepted
	/// job records. Reads, including the EOF probe, can advance the private
	/// stage's access time. Compare the final observed metadata with the
	/// recorded policy before relying on this read-back for reconciliation.
	///
	/// # Errors
	/// Rejects absent, changed or mismatched stages and strict metadata failures.
	pub fn open_stage_read_back(
		&self,
		expected: RecoveryFileObservation,
	) -> Result<RecoveryStageReader<'_>, RecoveryError> {
		let invalid = || RecoveryError::InvalidEntry(RecoveryName::Stage);
		let parent = &self.directory.as_ref().ok_or_else(invalid)?.lease;
		let stage = self.stage.as_ref().ok_or_else(invalid)?;
		if stage.observation != expected {
			return Err(invalid());
		}
		with_materialization_disabled(|| {
			self.check_current()?;
			let file = File::from(fs::openat(
				&parent.file,
				self.stage_name.as_bytes(),
				READ_STAGE,
				Mode::empty(),
			)?);
			let flags = fs::fcntl_getfl(&file)?;
			if flags.intersection(OFlags::ACCMODE) != OFlags::RDONLY || flags.contains(EVENT_ONLY) {
				return Err(invalid());
			}
			let initial = fs::fstat(&file)?;
			let initial_metadata =
				BasicMetadata::from_stat(&initial).map_err(StageError::BasicMetadata)?;
			let reader = RecoveryStageReader {
				inventory: self,
				stage,
				parent,
				file,
				initial_metadata,
			};
			if reader.observe_strict_metadata()? != initial_metadata {
				return Err(invalid());
			}
			Ok(reader)
		})
	}
}

/// Leased positioned read-back of one independently reopened private stage.
pub struct RecoveryStageReader<'inventory> {
	inventory: &'inventory RecoveryInventory<'inventory>,
	stage: &'inventory HeldEntry,
	parent: &'inventory DirectoryLease,
	file: File,
	initial_metadata: BasicMetadata,
}

impl RecoveryStageReader<'_> {
	/// Returns the stage identity and extent bound to this reader.
	#[must_use]
	pub const fn observation(&self) -> RecoveryFileObservation {
		self.stage.observation
	}

	/// Returns strict basic metadata observed before the first content read.
	#[must_use]
	pub const fn initial_metadata(&self) -> BasicMetadata {
		self.initial_metadata
	}

	/// Reads exactly the requested range, with the same chunk ceiling as fresh staging.
	///
	/// # Errors
	/// Rejects out-of-range reads, changed observations and I/O failures. Discard the
	/// buffer on error, since a failed check can follow a partial or completed read.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), RecoveryError> {
		bounded_end(offset, buffer.len(), self.stage.observation.length())?;
		with_materialization_disabled(|| {
			self.check_current()?;
			read_exact_at(offset, buffer, |position, remaining| {
				self.file.read_at(remaining, position)
			})
			.map_err(StageError::Read)?;
			self.check_current()?;
			Ok(())
		})
	}

	/// Checks both names, EOF, and strict metadata after the caller's read-back.
	///
	/// Access time is the current live observation. The caller verifies it against
	/// any recorded fidelity requirement.
	///
	/// # Errors
	/// Rejects changed bindings, failed strict metadata checks, and unexpected logical EOF.
	pub fn revalidate(&self) -> Result<BasicMetadata, RecoveryError> {
		with_materialization_disabled(|| {
			self.check_current()?;
			check_logical_eof(&self.file, self.stage.observation.length())?;
			self.observe_strict_metadata()
		})
	}

	fn check_current(&self) -> Result<Stat, RecoveryError> {
		self.inventory.check_current()?;
		let held = fs::fstat(&self.file)?;
		if !same_observation(&held, &self.stage.initial)
			|| PhysicalFsid::held(self.file.as_fd())? != Some(self.parent.identity.physical_fsid)
		{
			return Err(RecoveryError::InvalidEntry(RecoveryName::Stage));
		}
		Ok(held)
	}

	fn observe_strict_metadata(&self) -> Result<BasicMetadata, RecoveryError> {
		self.check_current()?;
		metadata::check_inventory(self.file.as_fd()).map_err(StageError::BasicMetadata)?;
		Ok(BasicMetadata::from_stat(&self.check_current()?).map_err(StageError::BasicMetadata)?)
	}
}

impl fmt::Debug for RecoveryStageReader<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecoveryStageReader")
			.finish_non_exhaustive()
	}
}
