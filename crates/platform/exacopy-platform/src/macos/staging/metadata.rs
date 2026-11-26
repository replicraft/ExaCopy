use std::fmt;

use apfs_mounted::metadata::{AccessModificationTimes, Metadata as MountedMetadata, Timestamp};
use apfs_mounted::writer::{
	BirthTimePolicy, LifecycleEffect, MetadataCheckPhase, MetadataReadyFile, WriterError,
};
use apfs_mounted::{EventHandle, ObjectIdentity};
use exacopy_endpoint::UnixComponent;
use exacopy_model::CopyBinding;

use super::super::{
	BasicMetadata, ManagedObjectIdentity, ManagedRegularFile, metadata,
	with_materialization_disabled,
};
use super::error::with_mounted_effect;
use super::file::{StageLocation, check_stage_view_acl};
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
		with_mounted_effect(LifecycleEffect::TimesApplied, || {
			let metadata = source.check_basic_metadata_with_policy()?;
			if self.length() != source.length() {
				return Err(StageError::MetadataMismatch);
			}
			let times = AccessModificationTimes {
				access: mounted_timestamp(metadata.atime())?,
				modification: mounted_timestamp(metadata.mtime())?,
			};
			self.closed.with_metadata(check_stage_view_acl)??;
			let location = self.location;
			let mounted = self.closed.apply_times_checked(
				times,
				BirthTimePolicy::Preserve,
				|phase, view| {
					location.check_current().map_err(refuse_metadata)?;
					let stat = view.stat()?;
					if stat.uid != metadata.uid() || stat.gid != metadata.gid() {
						return Err(refuse_metadata(StageError::MetadataMismatch));
					}
					if phase != MetadataCheckPhase::BeforeUpdate && stat.times != times {
						return Err(WriterError::TimesMismatch);
					}
					metadata::check_view_inventory(&view)
						.map_err(|error| refuse_metadata(error.into()))
				},
			)?;
			let verified = || {
				let ready = MetadataReadyStage {
					location,
					metadata,
					mounted,
				};
				ready.check_current_with_policy()?;
				source.check_basic_metadata_with_policy()?;
				Ok(ready)
			};
			verified().map_err(|error| StageError::MetadataUnverified(Box::new(error)))
		})
	}
}

/// Private stage with the sole writer closed and the required metadata synchronized.
///
/// No operation on this capability reads the unnamed stream. The mounted capability
/// retains its read-only descriptor for metadata observations of the sealed inode.
pub struct MetadataReadyStage<'stage> {
	pub(in super::super) location: StageLocation<'stage>,
	mounted: MetadataReadyFile<'stage>,
	metadata: BasicMetadata,
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
		self.location.identity
	}

	/// Returns the declared unnamed-stream extent in bytes.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.location.length
	}

	/// Reports whether the declared unnamed stream was empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.length() == 0
	}

	/// Returns the checked public target component fixed at creation.
	#[must_use]
	pub fn target(&self) -> UnixComponent<'_> {
		self.location.target
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
		with_materialization_disabled(|| {
			self.check_current_with_policy()?;
			self.location.observe_identity(self.mounted.identity())
		})
	}

	pub(in super::super) fn mounted_identity(&self) -> &ObjectIdentity {
		self.mounted.identity()
	}

	pub(in super::super) fn event_handle(&self) -> &EventHandle {
		self.mounted.event_handle()
	}

	pub(in super::super) fn check_current_with_policy(&self) -> Result<(), StageError> {
		self.location.observe_identity(self.mounted.identity())?;
		self.mounted
			.with_metadata(|view| Ok(metadata::check_view_inventory(&view)))??;
		Ok(())
	}

	pub(in super::super) fn check_published_metadata(&self) -> Result<MountedMetadata, StageError> {
		let (held, inventory) = self.mounted.with_held_metadata(|view| {
			let held = view.stat()?;
			Ok((held, metadata::check_view_inventory(&view)))
		})?;
		inventory?;
		Ok(held)
	}
}

fn refuse_metadata(error: StageError) -> WriterError {
	WriterError::MetadataRefused(Box::new(error))
}

fn mounted_timestamp(value: super::super::ManagedTimestamp) -> Result<Timestamp, StageError> {
	Timestamp::new(value.seconds(), value.nanoseconds().into()).ok_or(StageError::BasicMetadata(
		super::super::BasicMetadataError::Timestamp,
	))
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
