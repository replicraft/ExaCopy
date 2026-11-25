use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};

use super::StageError;

const STAGE_ID_BYTES: usize = 16;
pub(super) const RANDOM_STAGE_ID_BYTES: usize = STAGE_ID_BYTES - size_of::<u32>();

// A successful allocation never reuses its process-local serial, even if the
// entropy source repeats bytes. Random bits separate acquisitions across processes.
static NEXT_STAGE_SERIAL: AtomicU32 = AtomicU32::new(0);

/// Model context shared by staging attempts for the same entry and run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageBindingContext {
	job: JobId,
	entry: EntryId,
	epoch: RunEpoch,
}

impl StageBindingContext {
	/// Fixes the model fields supplied by the coordinator before a native attempt.
	#[must_use]
	pub const fn new(job: JobId, entry: EntryId, epoch: RunEpoch) -> Self {
		Self { job, entry, epoch }
	}

	pub(super) fn allocate(
		self,
		entropy: impl FnOnce(&mut [u8; RANDOM_STAGE_ID_BYTES]) -> io::Result<()>,
	) -> Result<StageIdentity, StageError> {
		self.allocate_with_serial(&NEXT_STAGE_SERIAL, entropy)
	}

	fn allocate_with_serial(
		self,
		serial: &AtomicU32,
		entropy: impl FnOnce(&mut [u8; RANDOM_STAGE_ID_BYTES]) -> io::Result<()>,
	) -> Result<StageIdentity, StageError> {
		let mut prefix = [0; RANDOM_STAGE_ID_BYTES];
		entropy(&mut prefix).map_err(StageError::EntropyUnavailable)?;
		let serial = serial
			.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
				value.checked_add(1)
			})
			.map_err(|_| StageError::StageIdsExhausted)?;
		let mut stage_id = [0; STAGE_ID_BYTES];
		let (random_bytes, serial_bytes) = stage_id.split_at_mut(RANDOM_STAGE_ID_BYTES);
		random_bytes.copy_from_slice(&prefix);
		serial_bytes.copy_from_slice(&serial.to_be_bytes());
		Ok(StageIdentity {
			context: self,
			stage_id,
		})
	}
}

/// The logical identity allocated by the native stage adapter for one attempt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StageIdentity {
	context: StageBindingContext,
	stage_id: [u8; STAGE_ID_BYTES],
}

impl StageIdentity {
	/// Returns the immutable binding used to report this attempt to the model.
	#[must_use]
	pub const fn binding(self) -> CopyBinding {
		CopyBinding::new(
			self.context.job,
			self.context.entry,
			self.context.epoch,
			StageId::from_bytes(self.stage_id),
		)
	}

	/// Returns the exact StageId bytes for recording the binding.
	#[must_use]
	pub const fn stage_id_bytes(&self) -> &[u8; STAGE_ID_BYTES] {
		&self.stage_id
	}
}

impl fmt::Debug for StageIdentity {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("StageIdentity")
			.finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests;
