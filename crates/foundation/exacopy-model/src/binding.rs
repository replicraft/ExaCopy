use exacopy_core::{EntryId, JobId, RunEpoch, StageId};

/// The complete identity to which a copy event or effect applies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CopyBinding {
	job: JobId,
	entry: EntryId,
	epoch: RunEpoch,
	stage: StageId,
}

impl CopyBinding {
	/// Binds the job, entry, run generation and privately owned stage.
	#[must_use]
	pub const fn new(job: JobId, entry: EntryId, epoch: RunEpoch, stage: StageId) -> Self {
		Self {
			job,
			entry,
			epoch,
			stage,
		}
	}
}
