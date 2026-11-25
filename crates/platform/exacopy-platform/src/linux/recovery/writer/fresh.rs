use std::os::unix::ffi::OsStrExt as _;
use std::sync::MutexGuard;

use exacopy_endpoint::UnixComponent;
use exacopy_model::CopyBinding;

use super::{FileIdentity, RecoveryInventory, RecoveryWriteLease, StageError, reopen_directory};
use crate::linux::stage::{FILE_MODE, StageDirectory, WriteStage};

#[cfg(test)]
mod tests;

impl RecoveryWriteLease<'_> {
	/// Pins the recorded directory for a new stage name observed absent under this lease.
	///
	/// The inventory fixes both names. Supply the stage directory identity from
	/// authenticated replay. Before creating the file, the coordinator must
	/// synchronize its authorization for the fresh stage name and attempt.
	///
	/// # Errors
	/// Refuses a foreign or changed inventory, another active stage capability,
	/// a mismatched directory identity, or an occupied stage or target name.
	pub fn prepare_fresh_stage<'lease>(
		&'lease self,
		inventory: &'lease RecoveryInventory<'lease>,
		expected_directory: FileIdentity,
	) -> Result<FreshRecoveryStage<'lease>, StageError> {
		if !std::ptr::eq(inventory.job, self.job())
			|| inventory.stage.is_some()
			|| inventory.target.is_some()
		{
			return Err(StageError::IdentityChanged);
		}
		let private = inventory
			.directory
			.as_ref()
			.filter(|directory| directory.identity == expected_directory)
			.ok_or(StageError::IdentityChanged)?;
		let access = self.try_stage_access()?;
		inventory.recheck()?;
		let job = inventory.job;
		let directory = reopen_directory(&private.file, expected_directory, job.root.mount)?;
		let directory = StageDirectory::for_recovery(job.root, job, directory, expected_directory);
		inventory.recheck()?;
		Ok(FreshRecoveryStage {
			directory,
			inventory: Some(inventory),
			_access: access,
		})
	}
}

/// One fresh private filename and target bound to an exclusive recovery lease.
#[derive(Debug)]
#[must_use]
pub struct FreshRecoveryStage<'lease> {
	directory: StageDirectory<'lease>,
	inventory: Option<&'lease RecoveryInventory<'lease>>,
	_access: MutexGuard<'lease, ()>,
}

impl FreshRecoveryStage<'_> {
	/// Returns the native stage-directory identity matched against the recorded value.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.directory.identity()
	}

	/// Exclusively creates the bound empty stage and synchronizes its name.
	///
	/// Supply the binding from the synchronized fresh-attempt authorization.
	/// The old stage entries remain untouched. The returned writer borrows this
	/// capability and carries the selected target and model binding.
	///
	/// # Errors
	/// Refuses a used allocation, an observed rebind or collision, and failed
	/// creation or directory synchronization. Each call spends the allocation.
	/// A file created before a later failure remains private for reconciliation.
	pub fn create_writer(&mut self, binding: CopyBinding) -> Result<WriteStage<'_>, StageError> {
		self.create_with(binding, |directory| directory.sync_directory())
	}

	fn create_with(
		&mut self,
		binding: CopyBinding,
		sync: impl FnOnce(&StageDirectory<'_>) -> Result<(), StageError>,
	) -> Result<WriteStage<'_>, StageError> {
		let inventory = self.inventory.take().ok_or(StageError::IdentityChanged)?;
		inventory.recheck()?;
		let stage = UnixComponent::new(inventory.stage_name.as_bytes())
			.map_err(|_| StageError::IdentityChanged)?;
		let target = UnixComponent::new(inventory.target_name.as_bytes())
			.map_err(|_| StageError::IdentityChanged)?;
		let writer = self.directory.create_file(stage, target, binding)?;
		sync(&self.directory)?;
		let observed = inventory.job.inventory(stage, target)?;
		if observed.stage_directory_identity() != Some(self.directory.identity())
			|| observed.target().is_some()
			|| !observed.stage().is_some_and(|file| {
				file.identity() == writer.identity()
					&& file.is_empty()
					&& file.observation().mode() == FILE_MODE.as_raw_mode()
			}) {
			return Err(StageError::IdentityChanged);
		}
		Ok(writer)
	}
}
