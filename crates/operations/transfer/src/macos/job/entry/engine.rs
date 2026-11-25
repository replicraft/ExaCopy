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

pub(super) enum RequestError {
	AlreadyAttempted,
	StageComponent(NameError),
	Observation(OwnerError),
	Metadata(PreparedError),
	Binding(DarwinPreparedError),
}

pub(super) enum PreparationFailure<E> {
	Stage(E),
	Observation(OwnerError),
	Binding(DarwinPreparedError),
	Journal(DurableJournalError),
}

pub(super) enum StageAdmissionFailure<E> {
	Adapter(E),
	Observation(OwnerError),
}

/// Inputs for a single exclusive private creation beneath the held stage directory.
pub(super) struct StageRequest<'name> {
	pub(super) component: UnixComponent<'name>,
	pub(super) target: UnixComponent<'name>,
	pub(super) length: u64,
	pub(super) job: JobId,
	pub(super) entry: EntryId,
	pub(super) epoch: RunEpoch,
}

pub(super) struct EntryRequest<'name> {
	stage: StageRequest<'name>,
	source: DarwinSourceView<'name>,
	entry: JournalEntryId,
}

pub(super) struct ObservedStage<W> {
	pub(super) writer: W,
	pub(super) id: DarwinStageId,
	pub(super) directory: DarwinFileIdentity,
	pub(super) identity: DarwinFileIdentity,
}

pub(super) struct PreparedStage<'name, W> {
	pub(super) writer: W,
	pub(super) preparation: DarwinEntryPrepared<'name>,
	pub(super) frame: Frame,
	pub(super) synced: SyncedFrame,
}

/// Creates an unwritten stage and rechecks its held file and parent identities.
pub(super) trait PrivateStage {
	type Error;
	type Writer<'stage>
	where
		Self: 'stage;

	fn create<'stage>(
		&'stage self,
		request: &StageRequest<'stage>,
	) -> Result<ObservedStage<Self::Writer<'stage>>, StageAdmissionFailure<Self::Error>>;
}

/// Claims the attempt and validates all record inputs before private directory creation.
pub(super) fn begin<'name>(
	attempted: &mut bool,
	plan: DarwinCopyPlan<'name>,
	job: JobId,
) -> Result<EntryRequest<'name>, RequestError> {
	if mem::replace(attempted, true) {
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

pub(super) fn prepare<'stage, S: PrivateStage>(
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
