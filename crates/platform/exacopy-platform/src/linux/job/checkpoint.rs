use std::ffi::OsStr;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::write_all_at;
use rustix::fs::OFlags;

use super::super::handle::FileIdentity;
use super::super::source::SourceObservation;
use super::super::stage::{FILE_MODE, check_named_file};
use super::{JobDirectory, RecordDirectory, StageError, create_private_file};

#[cfg(test)]
mod tests;

pub(in crate::linux) const CHECKPOINTS: &str = "checkpoints";
const MAX_PAGE_ORDINAL: u32 = 4_096;
const MAX_PAGE_BYTES: u64 = 95;

impl JobDirectory<'_> {
	/// Exclusively creates the private checkpoint directory for this job.
	/// Synchronize the job directory to persist this new child before recording
	/// any dependent journal entries.
	///
	/// # Errors
	/// Rejects a changed job binding, a collision, or a failed syscall.
	pub fn create_checkpoint_directory(&self) -> Result<CheckpointDirectory<'_>, StageError> {
		Ok(CheckpointDirectory(
			self.create_record_directory(CHECKPOINTS)?,
		))
	}
}

/// Write-once checkpoint storage bound to a held private job directory.
#[derive(Debug)]
pub struct CheckpointDirectory<'job>(RecordDirectory<'job>);

impl CheckpointDirectory<'_> {
	/// Exclusively creates one bounded page and synchronizes it and its directory.
	///
	/// # Errors
	/// Rejects invalid bounds, collisions, unsafe or changed bindings, and I/O
	/// failures. A page created before a later failure remains for reconciliation.
	pub fn write_page(&self, ordinal: u32, bytes: &[u8]) -> Result<(), StageError> {
		let name = checkpoint_page_name(ordinal)?;
		let len =
			u64::try_from(bytes.len()).map_err(|_| StageError::InvalidCheckpointPageLength)?;
		check_page_length(len)?;
		self.0.check_current()?;
		let name = OsStr::new(&name);
		let directory = &self.0.directory;
		let mount = self.0.job.root.mount;
		let (file, initial) = create_private_file(directory, mount, name, OFlags::WRONLY)?;
		let identity = FileIdentity::from_stat(&initial);
		let check_page = || {
			self.0.check_current()?;
			let stat = check_named_file(directory, name, identity, mount, FILE_MODE)?;
			SourceObservation::capture(&stat).map_err(StageError::ReadBack)
		};
		check_page()?;
		write_all_at(0, bytes, |position, remaining| {
			file.write_at(remaining, position)
		})
		.map_err(StageError::Write)?;
		let written = check_page()?;
		if written.len() != len {
			return Err(StageError::IdentityChanged);
		}
		file.sync_all().map_err(StageError::BarrierFailed)?;
		drop(file);
		self.0.sync_directory()?;
		written.recheck(check_page()?).map_err(StageError::ReadBack)
	}
}

pub(in crate::linux) fn checkpoint_page_name(ordinal: u32) -> Result<String, StageError> {
	if !(1..=MAX_PAGE_ORDINAL).contains(&ordinal) {
		return Err(StageError::InvalidCheckpointOrdinal);
	}
	Ok(format!("range-{ordinal:010}.cbor"))
}

pub(in crate::linux) fn check_page_length(len: u64) -> Result<(), StageError> {
	if !(1..=MAX_PAGE_BYTES).contains(&len) {
		return Err(StageError::InvalidCheckpointPageLength);
	}
	Ok(())
}
