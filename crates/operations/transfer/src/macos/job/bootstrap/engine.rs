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

/// Signed owner, synchronized first frame, and held journal namespace.
#[derive(Debug)]
pub struct JobPreparation<D> {
	// Drop the sole segment writer before releasing the journal directory lease.
	/// The sole first-segment writer, closed before the journal directory lease is released.
	pub journal: DurableJournal,
	/// The private lease held for the entire journal writer lifetime.
	pub journal_directory: D,
	/// The signed owner envelope persisted for this job.
	pub owner: DarwinOwnerRecord,
	/// The exact preparation matching the synchronized first frame.
	pub preparation: DarwinJobPrepared,
	/// The completed file barrier for the first frame.
	pub initial_frame: SyncedFrame,
}

/// The boundary at which preparation of a created private job stopped.
#[derive(Debug)]
pub enum BootstrapError<E> {
	/// The owner record could not be constructed or signed.
	Owner(OwnerError),
	/// The observations could not be associated with the prepared job.
	Binding(DarwinPreparedError),
	/// A private record or namespace operation failed.
	Artifact {
		/// The private artifact or namespace that was being prepared.
		step: JobPreparationStep,
		/// The original failure, including any uncertain creation.
		source: E,
	},
	/// The journal could not accept or synchronize the frame.
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

/// Signs and persists the private preparation before returning the first synchronized frame.
///
/// The job must have been exclusively created under the admitted destination.
/// The caller must use the independently validated signing profile and retain the job lease.
///
/// # Errors
/// Refuses an invalid binding, failed artifact creation, or incomplete journal synchronization.
pub fn prepare<'job, J: PrivateJob>(
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
