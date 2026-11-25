use std::num::NonZeroU32;

use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DarwinJobPrepared, DarwinOwnerManifest, DarwinOwnerRecord, DarwinPreparedError,
	DarwinRootBinding, DurableJournal, DurableJournalError, JournalFileBarrier, OwnerError,
	SyncedFrame,
};

use super::super::{DarwinJobProfile, JobPreparationStep};
use super::capabilities::{PrivateJob, PrivateJournalDirectory};
use crate::macos::plan::DarwinCopyPlan;

pub(in crate::macos::job) struct JobPreparation<D> {
	// Drop the sole segment writer before releasing the journal directory lease.
	pub(in crate::macos::job) journal: DurableJournal,
	pub(in crate::macos::job) journal_directory: D,
	pub(in crate::macos::job) owner: DarwinOwnerRecord,
	pub(in crate::macos::job) preparation: DarwinJobPrepared,
	pub(in crate::macos::job) initial_frame: SyncedFrame,
}

pub(super) enum BootstrapError<E> {
	Owner(OwnerError),
	Binding(DarwinPreparedError),
	Artifact { step: JobPreparationStep, source: E },
	Journal(DurableJournalError),
}

impl<E> BootstrapError<E> {
	fn artifact(step: JobPreparationStep) -> impl FnOnce(E) -> Self {
		move |source| Self::Artifact { step, source }
	}
}

impl<E> From<OwnerError> for BootstrapError<E> {
	fn from(error: OwnerError) -> Self {
		Self::Owner(error)
	}
}

pub(super) fn prepare<'job, J: PrivateJob>(
	plan: &DarwinCopyPlan<'_>,
	profile: DarwinJobProfile<'_>,
	job: &'job J,
	destination: DarwinRootBinding,
) -> Result<JobPreparation<J::JournalDirectory<'job>>, BootstrapError<J::Error>> {
	let context = plan.context();
	let state_root_uid = NonZeroU32::new(job.owner_uid()).ok_or(OwnerError::InvalidOwnerUid)?;
	let owner = DarwinOwnerRecord::sign(
		DarwinOwnerManifest {
			token: profile.owner_token,
			job: context.job,
			profile: profile.id,
			created: profile.created,
			destination_volume: destination.identity.volume(),
			state_root: job.identity()?,
			state_root_uid,
			plan_digest: context.plan_digest,
		},
		profile.signer,
	)?;
	let preparation =
		DarwinJobPrepared::new(context, &owner, destination).map_err(BootstrapError::Binding)?;
	job.write_owner_record(owner.as_bytes())
		.map_err(BootstrapError::artifact(JobPreparationStep::OwnerRecord))?;
	job.write_plan_record(&plan.encode())
		.map_err(BootstrapError::artifact(JobPreparationStep::PlanRecord))?;
	let journal_directory = job
		.create_journal_directory()
		.map_err(BootstrapError::artifact(
			JobPreparationStep::JournalDirectory,
		))?;
	let segment = journal_directory
		.create_first_segment()
		.map_err(BootstrapError::artifact(JobPreparationStep::FirstSegment))?;
	let mut journal =
		DurableJournal::from_new_file_with_barrier(segment, JournalFileBarrier::DarwinFullFsync)
			.map_err(BootstrapError::Journal)?;
	let initial_frame = journal
		.append(FrameKind::JobPrepared, &preparation.encode())
		.map_err(BootstrapError::Journal)?;
	Ok(JobPreparation {
		journal,
		journal_directory,
		owner,
		preparation,
		initial_frame,
	})
}
