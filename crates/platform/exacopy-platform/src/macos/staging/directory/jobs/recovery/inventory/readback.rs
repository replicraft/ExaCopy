use std::fmt;

use apfs_mounted::EntryName;
use apfs_mounted::metadata::MAX_EXTENDED_SECURITY_BYTES;
use apfs_mounted::recovery::{ReopenedStage, StageAdmission};
use apfs_mounted::source::SourceError;

use super::super::super::super::super::super::{BasicMetadata, FILE_MODE, metadata};
use super::super::super::super::super::{StageError, file::bounded_end};
use super::{
	HeldEntry, ManagedObjectIdentity, RecoveryError, RecoveryFileObservation, RecoveryInventory,
	RecoveryName, acl,
};

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
		let parent = &self.directory.as_ref().ok_or_else(invalid_stage)?.lease;
		let stage = self.stage.as_ref().ok_or_else(invalid_stage)?;
		if stage.observation != expected {
			return Err(invalid_stage());
		}
		let name = EntryName::new(self.stage_name.as_bytes()).map_err(|_| invalid_stage())?;
		let mounted = self.observe_stage_operation(|| {
			ReopenedStage::open_named(
				&parent.directory,
				name,
				&parent.lease,
				expected.length(),
				|admission| admit_stage(admission, stage, parent.owner),
			)
			.map_err(|cause| RecoveryError::mounted_stage(None, cause))
		})?;
		// Capture live access time after opening the data descriptor, before
		// reading. The event anchor's earlier access time is not equivalent.
		let initial_metadata = observe_strict_metadata(self, &mounted)?;
		Ok(RecoveryStageReader {
			inventory: self,
			observation: expected,
			mounted,
			initial_metadata,
		})
	}

	fn observe_stage_operation<T>(
		&self,
		operation: impl FnOnce() -> Result<T, RecoveryError>,
	) -> Result<T, RecoveryError> {
		self.revalidate()?;
		let result = operation();
		let checked_after = self.revalidate();
		result.and_then(|value| checked_after.map(|()| value))
	}
}

/// Leased positioned read-back of one independently reopened private stage.
pub struct RecoveryStageReader<'inventory> {
	inventory: &'inventory RecoveryInventory<'inventory>,
	observation: RecoveryFileObservation,
	mounted: ReopenedStage<'inventory>,
	initial_metadata: BasicMetadata,
}

impl RecoveryStageReader<'_> {
	/// Returns the stage identity and extent bound to this reader.
	#[must_use]
	pub const fn observation(&self) -> RecoveryFileObservation {
		self.observation
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
		let count = buffer.len();
		bounded_end(offset, count, self.observation.length())?;
		self.inventory.observe_stage_operation(|| {
			self.mounted
				.read_exact_at(offset, buffer)
				.map_err(|cause| RecoveryError::mounted_stage(Some((offset, count)), cause))
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
		self.inventory.observe_stage_operation(|| {
			self.mounted
				.confirm_eof()
				.map_err(|cause| RecoveryError::mounted_stage(None, cause))
		})?;
		observe_strict_metadata(self.inventory, &self.mounted)
	}
}

fn admit_stage(
	admission: StageAdmission<'_>,
	stage: &HeldEntry,
	owner: u32,
) -> Result<(), SourceError> {
	let observed = admission.metadata();
	let initial = &stage.initial;
	if ManagedObjectIdentity::from_mounted(admission.identity()) != stage.observation.identity()
		|| observed.length != stage.observation.length()
		|| observed.owner != owner
		|| observed.group != initial.st_gid
		|| observed.mode != FILE_MODE.bits()
		|| observed.link_count != 1
		|| observed.flags != 0
		|| observed.modified.seconds != initial.st_mtime
		|| i64::from(observed.modified.nanoseconds) != initial.st_mtime_nsec
		|| observed.changed.seconds != initial.st_ctime
		|| i64::from(observed.changed.nanoseconds) != initial.st_ctime_nsec
	{
		return Err(SourceError::AdmissionRefused);
	}
	let security = admission
		.extended_security(MAX_EXTENDED_SECURITY_BYTES)
		.map_err(SourceError::Metadata)?;
	if !acl::basic_security(Ok(security)).map_err(SourceError::Io)? {
		return Err(SourceError::AdmissionRefused);
	}
	Ok(())
}

fn observe_strict_metadata(
	inventory: &RecoveryInventory<'_>,
	mounted: &ReopenedStage<'_>,
) -> Result<BasicMetadata, RecoveryError> {
	inventory.observe_stage_operation(|| {
		let (snapshot, strict) = mounted
			.with_observation(|_, view| Ok(metadata::check_view_inventory(&view)))
			.map_err(|cause| RecoveryError::mounted_stage(None, cause))?;
		strict.map_err(StageError::BasicMetadata)?;
		Ok(BasicMetadata::from_mounted_observation(snapshot.metadata)
			.map_err(StageError::BasicMetadata)?)
	})
}

fn invalid_stage() -> RecoveryError {
	RecoveryError::InvalidEntry(RecoveryName::Stage)
}

impl fmt::Debug for RecoveryStageReader<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecoveryStageReader")
			.finish_non_exhaustive()
	}
}
