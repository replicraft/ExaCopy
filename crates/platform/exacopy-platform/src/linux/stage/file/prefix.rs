use std::fs::File;

use exacopy_endpoint::MAX_FILE_LENGTH;
use rustix::fs::{self, Stat};
use rustix::io;

use super::{
	FILE_MODE, FileIdentity, StageError, WriteBarrier, WriteStage, check_content_stamp,
	check_stage_file, mount_id,
};

impl WriteStage<'_> {
	/// Checks the exact current length of the held, named private writer.
	/// # Errors
	/// Refuses a changed identity, extent, private file or failed writer barrier.
	pub fn observe_prefix(&self, end: u64) -> Result<FileIdentity, StageError> {
		self.check_prefix(end)
			.map(|stat| FileIdentity::from_stat(&stat))
	}

	/// Synchronizes the exact prefix with a full file barrier.
	/// The returned identity is confirmed on the held writer and private name
	/// before and after synchronization. No write or resize is performed.
	/// # Errors
	/// Refuses a changed observation, invalid extent or failed barrier.
	pub fn sync_prefix(&mut self, end: u64) -> Result<FileIdentity, StageError> {
		self.sync_prefix_admitted(end, || Ok(()))
	}

	/// Checks the complete prefix and admits its file barrier immediately before sync.
	///
	/// # Errors
	/// Refuses a changed observation, failed admission or a failed barrier.
	pub fn sync_prefix_admitted<G>(
		&mut self,
		end: u64,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<FileIdentity, StageError> {
		self.sync_prefix_admitted_with(end, enter, |file| fs::fsync(file))
	}

	#[cfg(test)]
	pub(super) fn sync_prefix_with(
		&mut self,
		end: u64,
		sync: impl FnOnce(&File) -> io::Result<()>,
	) -> Result<FileIdentity, StageError> {
		self.sync_prefix_admitted_with(end, || Ok(()), sync)
	}

	fn sync_prefix_admitted_with<G>(
		&mut self,
		end: u64,
		enter: impl FnOnce() -> std::io::Result<G>,
		sync: impl FnOnce(&File) -> io::Result<()>,
	) -> Result<FileIdentity, StageError> {
		let before = self.check_prefix(end)?;
		self.flush_admitted_with(enter, sync)?;
		let result = self
			.check_prefix(end)
			.and_then(|after| check_content_stamp(&before, &after).map(|()| after));
		if result.is_err() {
			// A changed observation negates the completed barrier as close evidence.
			self.barrier = WriteBarrier::Pending;
		}
		result.map(|stat| FileIdentity::from_stat(&stat))
	}

	fn check_prefix(&self, end: u64) -> Result<Stat, StageError> {
		self.barrier.require_usable()?;
		if end > MAX_FILE_LENGTH {
			return Err(StageError::InvalidLength);
		}
		let named = self.location.check_named_file(FILE_MODE)?;
		let held = fs::fstat(&self.file)?;
		check_stage_file(&held, FILE_MODE)?;
		if FileIdentity::from_stat(&held) != self.location.identity
			|| mount_id(&self.file)? != self.location.directory.root.mount
			|| u64::try_from(held.st_size) != Ok(end)
		{
			return Err(StageError::IdentityChanged);
		}
		check_content_stamp(&named, &held)?;
		Ok(held)
	}
}
