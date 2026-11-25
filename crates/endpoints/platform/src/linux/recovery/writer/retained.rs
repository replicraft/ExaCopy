use std::ffi::OsStr;
use std::fs::File;
use std::sync::MutexGuard;

use exacopy_model::{CopyBinding, PublishNoClobber};
use rustix::fs;

use super::{
	FileIdentity, FilePolicy, RecoveryFile, RecoveryInventory, RecoveryWriteLease,
	SourceObservation, StageError, reopen_directory, sync_file,
};
use crate::linux::job::STAGE;
use crate::linux::stage::{
	PublicationNames, PublishError, check_no_visible_attributes, check_private_child,
};

#[cfg(test)]
mod tests;

impl RecoveryWriteLease<'_> {
	/// Flushes the held private stage and prepares one publication attempt under this lease.
	///
	/// The inventory must originate from this lease and hold a private stage with
	/// an absent target. The coordinator verifies the physical identities against
	/// the journal and establishes fresh read-back, required metadata and durable
	/// intent before using the returned capability.
	///
	/// # Errors
	/// Rejects a mismatched or changed inventory and reports stage barrier failures.
	pub fn prepare_retained_stage<'lease>(
		&'lease self,
		inventory: &'lease RecoveryInventory<'lease>,
		binding: CopyBinding,
	) -> Result<RetainedStage<'lease>, StageError> {
		if !std::ptr::eq(inventory.job, self.job()) || inventory.target.is_some() {
			return Err(StageError::IdentityChanged);
		}
		let stage = inventory.stage().ok_or(StageError::IdentityChanged)?;
		let private = inventory
			.directory
			.as_ref()
			.ok_or(StageError::IdentityChanged)?;
		let retained = RetainedStage {
			_access: self.try_stage_access()?,
			inventory,
			stage,
			directory_identity: private.identity,
			directory: reopen_directory(&private.file, private.identity, self.job.root.mount)?,
			binding,
		};
		retained.recheck_private()?;
		sync_file(&stage.file)?;
		retained.recheck_private()?;
		Ok(retained)
	}
}

/// A flushed retained stage with its original observations and exclusive recovery lease.
#[derive(Debug)]
#[must_use]
pub struct RetainedStage<'lease> {
	_access: MutexGuard<'lease, ()>,
	inventory: &'lease RecoveryInventory<'lease>,
	stage: &'lease RecoveryFile,
	directory_identity: FileIdentity,
	directory: File,
	binding: CopyBinding,
}

impl RetainedStage<'_> {
	/// Consumes this stage and matching model authorization for one exclusive rename.
	///
	/// On success, both directory barriers completed and the observed public name
	/// identifies the held inode. The original private stage name is absent.
	///
	/// # Errors
	/// Stale bindings or a conflict preserve both names. An uncertain rename,
	/// barrier failure, or post-rename observation failure requires reconciliation.
	pub fn publish_no_clobber(self, authorization: PublishNoClobber) -> Result<(), PublishError> {
		self.publish_with_barriers(authorization, |directory| fs::fsync(directory))
	}

	fn publish_with_barriers(
		self,
		authorization: PublishNoClobber,
		sync: impl FnMut(&File) -> rustix::io::Result<()>,
	) -> Result<(), PublishError> {
		if authorization.binding() != self.binding {
			return Err(PublishError::BindingMismatch);
		}
		self.recheck_private().map_err(PublishError::StageChanged)?;
		let names = PublicationNames {
			stage: &self.directory,
			stage_name: &self.inventory.stage_name,
			destination: self.inventory.job.root,
			target_name: &self.inventory.target_name,
		};
		names.rename()?;
		// Compare the post-rename ctime across both barriers. The rename itself
		// may have changed it. Request both barriers even if observation fails.
		let renamed = self.observe_publication(&names);
		names.sync_directories(sync)?;
		let renamed = renamed.map_err(PublishError::ObservationFailed)?;
		let stable = self
			.observe_publication(&names)
			.map_err(PublishError::ObservationFailed)?;
		if renamed != stable {
			return Err(PublishError::ObservationFailed(StageError::IdentityChanged));
		}
		Ok(())
	}

	fn recheck_private(&self) -> Result<(), StageError> {
		self.inventory.recheck()?;
		let observation = self.held_stage_observation()?;
		self.stage
			.observation()
			.recheck(observation)
			.map_err(StageError::ReadBack)?;
		if self.stage.observation().accessed_at() != observation.accessed_at() {
			return Err(StageError::IdentityChanged);
		}
		Ok(())
	}

	fn held_stage_observation(&self) -> Result<SourceObservation, StageError> {
		check_no_visible_attributes(&self.stage.file)?;
		let stat = fs::fstat(&self.stage.file)?;
		FilePolicy::Stage.check(&stat)?;
		SourceObservation::capture(&stat).map_err(StageError::ReadBack)
	}

	fn observe_publication(
		&self,
		names: &PublicationNames<'_>,
	) -> Result<SourceObservation, StageError> {
		let job = self.inventory.job;
		job.recheck()?;
		self.recheck_directory()?;
		let stat = names.observe_target(self.stage.identity())?;
		FilePolicy::Stage.check(&stat)?;
		let named = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
		let held = self.held_stage_observation()?;
		let original = self.stage.observation();
		if named != held
			|| named.len() != original.len()
			|| named.mode() != original.mode()
			|| named.owner() != original.owner()
			|| named.group() != original.group()
			|| named.accessed_at() != original.accessed_at()
			|| named.modified_at() != original.modified_at()
		{
			return Err(StageError::IdentityChanged);
		}
		self.recheck_directory()?;
		job.recheck()?;
		Ok(named)
	}

	fn recheck_directory(&self) -> Result<(), StageError> {
		let job = self.inventory.job;
		check_private_child(
			&job.directory.file,
			&self.directory,
			OsStr::new(STAGE),
			self.directory_identity,
			job.root.mount,
		)
	}
}
