use std::fs::File;
use std::sync::MutexGuard;

use exacopy_model::CopyBinding;

use super::{RecoveryInventory, RecoveryJob, RecoveryWriteLease, StageError, reopen_directory};
use crate::linux::FileIdentity;
use crate::linux::stage::{StageDirectory, WriteStage};

#[cfg(test)]
mod tests;

impl RecoveryWriteLease<'_> {
	/// Pins the exact stage directory observed under this exclusive job lease.
	///
	/// The inventory fixes both names and the staged inode for a subsequent
	/// write reopen. This method grants no access to other private files.
	///
	/// # Errors
	/// Rejects a mismatched or changed inventory, a missing stage, or a busy lease.
	pub fn reopen_stage_directory<'lease>(
		&'lease self,
		inventory: &'lease RecoveryInventory<'lease>,
	) -> Result<RecoveryStageDirectory<'lease>, StageError> {
		if !std::ptr::eq(inventory.job, self.job()) || inventory.target.is_some() {
			return Err(StageError::IdentityChanged);
		}
		let private = inventory
			.directory
			.as_ref()
			.filter(|_| inventory.stage.is_some())
			.ok_or(StageError::IdentityChanged)?;
		let access = self.try_stage_access()?;
		inventory.recheck()?;
		let job = inventory.job;
		let directory = reopen_directory(&private.file, private.identity, job.root.mount)?;
		let directory = StageDirectory::for_recovery(job.root, job, directory, private.identity);
		inventory.recheck()?;
		Ok(RecoveryStageDirectory {
			directory,
			inventory,
			_access: access,
		})
	}
}

/// A held stage directory restricted to one private file and one public target.
#[derive(Debug)]
#[must_use]
pub struct RecoveryStageDirectory<'lease> {
	directory: StageDirectory<'lease>,
	inventory: &'lease RecoveryInventory<'lease>,
	_access: MutexGuard<'lease, ()>,
}

impl RecoveryStageDirectory<'_> {
	/// Returns the identity of the held private stage directory.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.directory.identity()
	}

	/// Requests a full barrier on the checked private stage directory.
	///
	/// # Errors
	/// Fails if the directory became unsafe or detached, or if its barrier fails.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.directory.sync_directory()
	}

	/// Reopens the captured private stage for positional writes under a fresh binding.
	///
	/// The coordinator must authenticate the retained pre-intent job and durably
	/// establish its new epoch before calling this method. The writer opens the
	/// existing inode without creating or truncating a file.
	///
	/// # Errors
	/// Rejects a changed inventory or a stage outside the private 0600 file policy.
	pub fn open_writer(&mut self, binding: CopyBinding) -> Result<WriteStage<'_>, StageError> {
		let inventory = self.inventory;
		let stage = inventory.stage().ok_or(StageError::IdentityChanged)?;
		inventory.recheck()?;
		let writer = WriteStage::reopen(
			&self.directory,
			&inventory.stage_name,
			&inventory.target_name,
			binding,
			&stage.file,
			stage.observation,
		)?;
		inventory.recheck()?;
		Ok(writer)
	}
}

impl RecoveryJob<'_> {
	pub(in crate::linux) fn directory_for_stage(&self) -> Result<&File, StageError> {
		self.recheck()?;
		Ok(&self.directory.file)
	}
}
