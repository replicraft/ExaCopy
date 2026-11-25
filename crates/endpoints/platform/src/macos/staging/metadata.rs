use std::fmt;
use std::fs::File;
use std::os::fd::AsFd as _;

use exacopy_endpoint::UnixComponent;
use exacopy_model::CopyBinding;
use rustix::fs::{self, OFlags, Stat};

use super::super::{
	BasicMetadata, EVENT_ONLY, ManagedObjectIdentity, ManagedRegularFile, file::same_observation,
	metadata, with_materialization_disabled,
};
use super::file::StageLocation;
use super::{ClosedStage, StageError, StageIdentity};

impl<'stage> ClosedStage<'stage> {
	/// Applies required basic metadata to the private inode after verified data and EOF read-back.
	///
	/// Call after complete independent read-back and digest comparison, with the same source
	/// capability used for the transfer. The result confirms metadata and a full file barrier.
	/// It consumes the previous stage state so the adapter cannot reopen stage data after the
	/// final access time is installed.
	///
	/// # Errors
	/// Refuses changed identity, unsupported metadata or unequal UID/GID, and reports any
	/// failed timestamp update, read-back or barrier. The private entry remains for reconciliation.
	pub fn apply_basic_metadata(
		self,
		source: &ManagedRegularFile<'_>,
	) -> Result<MetadataReadyStage<'stage>, StageError> {
		with_materialization_disabled(|| {
			let metadata = source.check_basic_metadata_with_policy()?;
			self.location.check_observation(&self.observed)?;
			if self.length() != source.length()
				|| metadata.uid() != self.observed.st_uid
				|| metadata.gid() != self.observed.st_gid
			{
				return Err(StageError::MetadataMismatch);
			}

			let reader = self.location.reopen_read_only()?;
			let flags = fs::fcntl_getfl(&reader)?;
			if flags.intersection(OFlags::ACCMODE) != OFlags::RDONLY || flags.contains(EVENT_ONLY) {
				return Err(StageError::StageChanged);
			}
			self.location.check_descriptor(&reader, &self.observed)?;
			metadata::check_inventory(reader.as_fd())?;
			self.location.check_observation(&self.observed)?;

			fs::futimens(&reader, &metadata.times())
				.map_err(|error| StageError::SetMetadata(error.into()))?;

			let observed = fs::fstat(&reader)?;
			let mut expected = self.observed;
			expected.st_ctime = observed.st_ctime;
			expected.st_ctime_nsec = observed.st_ctime_nsec;
			expected.st_mtime = observed.st_mtime;
			expected.st_mtime_nsec = observed.st_mtime_nsec;
			if !same_observation(&observed, &expected) || !metadata.matches(&observed) {
				return Err(StageError::StageChanged);
			}
			let ready = MetadataReadyStage {
				location: self.location,
				observed,
				metadata,
				reader,
			};
			ready.check_current_with_policy()?;
			fs::fcntl_fullfsync(&ready.reader)
				.map_err(|error| StageError::FileBarrier(error.into()))?;
			ready.check_current_with_policy()?;
			source.check_basic_metadata_with_policy()?;
			Ok(ready)
		})
	}
}

/// Private stage with the sole writer closed and the required metadata synchronized.
///
/// No operation on this capability reads the unnamed stream. The held reader remains
/// available to the adapter for metadata observations of the same physical inode.
pub struct MetadataReadyStage<'stage> {
	pub(in super::super) location: StageLocation<'stage>,
	pub(in super::super) observed: Stat,
	metadata: BasicMetadata,
	reader: File,
}

impl MetadataReadyStage<'_> {
	/// Returns the transaction binding fixed at exclusive creation.
	#[must_use]
	pub fn binding(&self) -> CopyBinding {
		self.identity().binding()
	}

	/// Returns the private stage identity.
	#[must_use]
	pub fn identity(&self) -> StageIdentity {
		self.location.identity()
	}

	/// Returns the declared unnamed-stream extent in bytes.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.location.length()
	}

	/// Reports whether the declared unnamed stream was empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.length() == 0
	}

	/// Returns the checked public target component fixed at creation.
	#[must_use]
	pub fn target(&self) -> UnixComponent<'_> {
		self.location.target()
	}

	/// Returns the required metadata confirmed through held and named observations.
	#[must_use]
	pub fn metadata(&self) -> BasicMetadata {
		self.metadata
	}

	/// Rechecks the sealed stage's identity and required metadata for the journal.
	/// # Errors
	/// Refuses changed or unavailable observations.
	pub fn observe_identity(&self) -> Result<ManagedObjectIdentity, StageError> {
		with_materialization_disabled(|| self.check_current_with_policy())?;
		self.location.observe_identity(&self.observed)
	}

	pub(in super::super) fn check_current_with_policy(&self) -> Result<(), StageError> {
		self.location.check_observation(&self.observed)?;
		self.location
			.check_descriptor(&self.reader, &self.observed)?;
		metadata::check_inventory(self.reader.as_fd())?;
		for stat in [
			fs::fstat(&self.reader)?,
			self.location.held_stat()?,
			self.location.named_stat()?,
		] {
			if !same_observation(&stat, &self.observed) || !self.metadata.matches(&stat) {
				return Err(StageError::StageChanged);
			}
		}
		Ok(())
	}

	// The namespace effect may change ctime while the required timestamps and inode stay fixed.
	pub(in super::super) fn matches_published_stat(&self, stat: &Stat) -> bool {
		let mut expected = self.observed;
		expected.st_ctime = stat.st_ctime;
		expected.st_ctime_nsec = stat.st_ctime_nsec;
		same_observation(stat, &expected) && self.metadata.matches(stat)
	}

	pub(in super::super) fn check_published_descriptor(&self) -> Result<Stat, StageError> {
		let stat = fs::fstat(&self.reader)?;
		if !self.matches_published_stat(&stat) {
			return Err(StageError::StageChanged);
		}
		self.location.check_descriptor(&self.reader, &stat)?;
		metadata::check_inventory(self.reader.as_fd())?;
		for held in [fs::fstat(&self.reader)?, self.location.held_stat()?] {
			if !same_observation(&held, &stat) || !self.metadata.matches(&held) {
				return Err(StageError::StageChanged);
			}
		}
		Ok(stat)
	}
}

impl fmt::Debug for MetadataReadyStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("MetadataReadyStage")
			.finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests;
