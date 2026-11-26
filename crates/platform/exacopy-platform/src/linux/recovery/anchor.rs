use std::ffi::OsStr;
use std::fmt;
use std::fs::File;

use super::{RecoveryFile, RecoveryInventory, StageError, file_identity, lease::reopen_directory};

/// Read-only pins for one private recovery stage and its checked namespace.
///
/// The pins keep local inode incarnations alive in this process. They hold
/// no lock, writer, barrier evidence or authority to modify the stage.
#[must_use]
pub struct RecoveryStageAnchor {
	root: File,
	job: File,
	directory: File,
	stage: RecoveryFile,
	stage_name: Box<OsStr>,
	target_name: Box<OsStr>,
	mount: u64,
}

impl RecoveryInventory<'_> {
	pub(super) fn into_stage_anchor(self) -> Result<RecoveryStageAnchor, StageError> {
		self.recheck()?;
		let directory = self.directory.as_ref().ok_or(StageError::IdentityChanged)?;
		if self.stage.is_none() || self.target.is_some() {
			return Err(StageError::IdentityChanged);
		}
		let mount = self.job.root.mount;
		// Open separate descriptions. In particular, retain no descriptor
		// that shares the job lease's flock-owning file description.
		let root = reopen_directory(
			&self.job.root.directory,
			self.job.destination_identity(),
			mount,
		)?;
		let job = reopen_directory(&self.job.directory.file, self.job.identity(), mount)?;
		let directory = reopen_directory(&directory.file, directory.identity, mount)?;
		self.recheck()?;
		Ok(RecoveryStageAnchor {
			root,
			job,
			directory,
			stage: self.stage.ok_or(StageError::IdentityChanged)?,
			stage_name: self.stage_name,
			target_name: self.target_name,
			mount,
		})
	}
}

impl RecoveryStageAnchor {
	/// Compares a fresh held inventory with the original pinned inodes and names.
	///
	/// # Errors
	/// Refuses changed scope, missing or changed stage and unexpected target
	/// occupancy. A successful comparison is a live observation.
	pub fn recheck(&self, current: &RecoveryInventory<'_>) -> Result<(), StageError> {
		current.recheck()?;
		if self.mount != current.job.root.mount
			|| self.stage_name != current.stage_name
			|| self.target_name != current.target_name
			|| file_identity(&self.root)? != current.job.destination_identity()
			|| file_identity(&self.job)? != current.job.identity()
			|| current.stage_directory_identity() != Some(file_identity(&self.directory)?)
			|| current.stage().map(RecoveryFile::observation) != Some(self.stage.observation())
			|| current.target().is_some()
		{
			return Err(StageError::IdentityChanged);
		}
		self.stage
			.recheck_observation()
			.map_err(StageError::ReadBack)?;
		current.recheck()
	}
}

impl fmt::Debug for RecoveryStageAnchor {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RecoveryStageAnchor")
			.finish_non_exhaustive()
	}
}
