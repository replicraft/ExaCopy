use std::mem;

use exacopy_endpoint::{NameError, UnixComponent};
use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinEntryPreparation, DarwinEntryPrepared, DarwinFileIdentity, DarwinJobPrepared,
	DarwinPreparedError, DarwinRootBinding, DarwinSourceMetadata, DarwinSourceTimes,
	DarwinSourceView, DarwinStageId, DarwinStageObservation, DurableJournal, DurableJournalError,
	JournalEntryId, ObservedTimestamp, OwnerError, OwnerTimestamp, PreparedError, SyncedFrame,
	TargetObservation,
};
use exacopy_model::{EntryId, JobId, RunEpoch};

use super::super::STAGE_PAYLOAD;
use crate::macos::plan::{DarwinCopyPlan, SourcePlanBinding};

// The model's single entry and the independently assigned entry UUID in the record
// are separate identities.
const MODEL_ENTRY: EntryId = EntryId::new(1);

/// A failed prerequisite before any private stage creation.
#[derive(Debug)]
pub enum RequestError {
	/// This prepared job already consumed its sole stage attempt.
	AlreadyAttempted,
	/// The fixed private payload component failed validation.
	StageComponent(NameError),
	/// An observation is outside the journal's representation.
	Observation(OwnerError),
	/// The source metadata is outside the journal's representation.
	Metadata(PreparedError),
	/// The observations could not be associated with the prepared job.
	Binding(DarwinPreparedError),
}

/// The reason preparation of the private stage or its exact frame stopped.
#[derive(Debug)]
pub enum PreparationFailure<E> {
	/// The private stage adapter failed creation or revalidation.
	Stage(E),
	/// An observation is outside the journal's representation.
	Observation(OwnerError),
	/// The observations could not be associated with the prepared job.
	Binding(DarwinPreparedError),
	/// The journal could not accept or synchronize the frame.
	Journal(DurableJournalError),
}

/// A stage creation or observation that did not yield a bound writer.
#[derive(Debug)]
pub enum StageAdmissionFailure<E> {
	/// The adapter failed the requested operation.
	Adapter(E),
	/// An observation is outside the journal's representation.
	Observation(OwnerError),
}

/// Inputs for a single exclusive private creation beneath the held stage directory.
#[derive(Debug)]
pub struct StageRequest<'name> {
	/// The fixed component of the private stage payload.
	pub component: UnixComponent<'name>,
	/// The public component whose absence the adapter checks before creation.
	pub target: UnixComponent<'name>,
	/// The logical length of the unnamed stream in bytes.
	pub length: u64,
	/// The model job identity of the held private directory.
	pub job: JobId,
	/// The model entry identity in the single-file profile.
	pub entry: EntryId,
	/// The model epoch of this copy attempt.
	pub epoch: RunEpoch,
}

/// The single stage attempt owned by a prepared job.
#[derive(Debug, Default)]
pub struct EntryAttempt {
	attempted: bool,
}

/// A checked plan and consumed attempt ready for exclusive stage creation.
#[derive(Debug)]
pub struct EntryRequest<'name> {
	stage: StageRequest<'name>,
	source: DarwinSourceView<'name>,
	entry: JournalEntryId,
}

/// An unwritten stage and fresh identity evidence supplied by the adapter.
#[derive(Debug)]
pub struct ObservedStage<W> {
	/// The sole authorized writer of the unwritten stage.
	pub writer: W,
	/// The allocated logical stage identifier.
	pub id: DarwinStageId,
	/// The fresh identity of the held staging directory.
	pub directory: DarwinFileIdentity,
	/// The observed file identity in the journal profile.
	pub identity: DarwinFileIdentity,
}

/// The unwritten stage and the exact synchronized entry frame.
#[derive(Debug)]
pub struct PreparedStage<'name, W> {
	/// The sole authorized writer of the unwritten stage.
	pub writer: W,
	/// The entry preparation bound to the job and stage.
	pub preparation: DarwinEntryPrepared<'name>,
	/// The complete appended entry frame.
	pub frame: Frame,
	/// The successful barrier associated with the exact entry frame.
	pub synced: SyncedFrame,
}

/// Creates an unwritten stage and rechecks its held file and parent identities.
pub trait PrivateStage {
	/// The adapter failure retained for diagnostics.
	type Error;
	/// The unwritten stage writer borrowing the private directory lease.
	type Writer<'stage>
	where
		Self: 'stage;

	/// Checks target absence, creates the unwritten stage exclusively, and revalidates it.
	fn create<'stage>(
		&'stage self,
		request: &StageRequest<'stage>,
	) -> Result<ObservedStage<Self::Writer<'stage>>, StageAdmissionFailure<Self::Error>>;
}

/// Claims the attempt and validates all record inputs before private directory creation.
pub fn begin<'name>(
	attempt: &mut EntryAttempt,
	plan: DarwinCopyPlan<'name>,
	job: JobId,
) -> Result<EntryRequest<'name>, RequestError> {
	if mem::replace(&mut attempt.attempted, true) {
		return Err(RequestError::AlreadyAttempted);
	}
	let source = source_view(plan.source())?;
	let component = UnixComponent::new(STAGE_PAYLOAD).map_err(RequestError::StageComponent)?;
	Ok(EntryRequest {
		stage: StageRequest {
			component,
			target: plan.destination().component,
			length: source.length(),
			job,
			entry: MODEL_ENTRY,
			epoch: RunEpoch::new(plan.attempt().epoch.get()),
		},
		source,
		entry: plan.attempt().entry,
	})
}

/// Creates the private stage and appends its entry preparation before returning its writer.
/// # Errors
/// Reports failed stage admission, mismatched observations, or a failed append or barrier.
pub fn prepare<'stage, S: PrivateStage>(
	request: EntryRequest<'stage>,
	job: &DarwinJobPrepared,
	stage: &'stage S,
	journal: &mut DurableJournal,
) -> Result<PreparedStage<'stage, S::Writer<'stage>>, PreparationFailure<S::Error>> {
	let observed = stage.create(&request.stage).map_err(|error| match error {
		StageAdmissionFailure::Adapter(error) => PreparationFailure::Stage(error),
		StageAdmissionFailure::Observation(error) => PreparationFailure::Observation(error),
	})?;
	let preparation = DarwinEntryPrepared::new(
		job,
		request.entry,
		DarwinEntryPreparation {
			source: request.source,
			stage: DarwinStageObservation {
				id: observed.id,
				directory: observed.directory,
				identity: observed.identity,
				component: request.stage.component,
			},
			target_component: request.stage.target,
			target_observation: TargetObservation::AbsentObserved,
		},
	)
	.map_err(PreparationFailure::Binding)?;
	let (frame, synced) = journal
		.append_frame(FrameKind::EntryPrepared, preparation.encode())
		.map_err(PreparationFailure::Journal)?;
	Ok(PreparedStage {
		writer: observed.writer,
		preparation,
		frame,
		synced,
	})
}

fn source_view(source: SourcePlanBinding<'_>) -> Result<DarwinSourceView<'_>, RequestError> {
	let metadata = source.metadata;
	DarwinSourceView::new(
		DarwinRootBinding {
			id: source.root_id,
			identity: source.root_identity,
		},
		source.component,
		source.file_identity,
		source.length,
		DarwinSourceTimes {
			accessed_at: owner_time(metadata.accessed_at())?,
			modified_at: owner_time(metadata.modified_at())?,
			changed_at: owner_time(metadata.changed_at())?,
		},
		DarwinSourceMetadata::new(u32::from(metadata.mode()), metadata.uid(), metadata.gid())
			.map_err(RequestError::Metadata)?,
	)
	.map_err(RequestError::Binding)
}

fn owner_time(timestamp: ObservedTimestamp) -> Result<OwnerTimestamp, RequestError> {
	OwnerTimestamp::new(timestamp.seconds(), timestamp.nanoseconds())
		.map_err(RequestError::Observation)
}
