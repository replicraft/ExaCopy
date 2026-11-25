use std::mem;

use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinEntryPreparation, DarwinEntryPrepared, DarwinRootBinding, DarwinSourceMetadata,
	DarwinSourceTimes, DarwinSourceView, DarwinStageId, DarwinStageObservation, DurableJournal,
	ObservedTimestamp, OwnerTimestamp, SyncedFrame, TargetObservation,
};
use exacopy_model::{EntryId, RunEpoch};
use exacopy_platform::macos::ManagedRegularFile;
use exacopy_platform::macos::staging::jobs::{JobDirectory, JobName};
use exacopy_platform::macos::staging::{StageBindingContext, WriteStage};

use super::super::plan::SourcePlanBinding;
use super::PreparedDarwinJob;
use super::admission::{check_source, native_identity};

mod error;

pub use error::{EntryPreparationError, EntryPreparationFailure};

const STAGE_PAYLOAD: &[u8] = b"payload";
// This preserve profile has exactly one model entry. Its persisted entry UUID
// comes from the independent plan and is copied exactly into kind 2.
const MODEL_ENTRY: EntryId = EntryId::new(1);

/// The private unwritten stage and synchronized kind-2 evidence for one entry.
#[derive(Debug)]
pub struct PreparedDarwinEntry<'entry> {
	_writer: Option<WriteStage<'entry>>,
	_source: &'entry ManagedRegularFile<'entry>,
	_journal: &'entry mut DurableJournal,
	job: &'entry JobDirectory<'entry>,
	preparation: DarwinEntryPrepared<'entry>,
	frame: Frame,
	synced: SyncedFrame,
}

impl<'entry> PreparedDarwinEntry<'entry> {
	/// Returns the private job name whose stage and segment remain held.
	#[must_use]
	pub const fn job_name(&self) -> JobName {
		self.job.name()
	}

	/// Returns the exact observation record bound to the first live stage.
	#[must_use]
	pub const fn preparation(&self) -> &DarwinEntryPrepared<'entry> {
		&self.preparation
	}

	/// Returns the envelope written for entry preparation.
	#[must_use]
	pub const fn frame(&self) -> &Frame {
		&self.frame
	}

	/// Returns the barrier evidence for the exact envelope.
	#[must_use]
	pub const fn synced(&self) -> &SyncedFrame {
		&self.synced
	}
}

impl PreparedDarwinJob<'_> {
	/// Exclusively creates the private stage and synchronizes its kind-2 frame.
	///
	/// The operation is called only after the exact frame barrier succeeds, with
	/// the stage, job, and journal directory leases still held. Stage creation
	/// rechecks the public target's absence under the destination lease.
	///
	/// # Errors
	/// Refuses a stale source, a second stage preparation attempt, failed
	/// creation or revalidation, and any unsuccessful journal append or barrier.
	/// Existing private job artifacts remain in place for reconciliation.
	pub fn with_prepared_entry<T>(
		&mut self,
		operation: impl FnOnce(&mut PreparedDarwinEntry<'_>) -> T,
	) -> Result<T, EntryPreparationError> {
		let source = self.plan.source();
		check_source(source, self.source, self.source_root_id)
			.map_err(EntryPreparationFailure::Source)
			.map_err(|source| EntryPreparationError::new(self.job.name(), source))?;
		self.with_admitted_entry(operation)
	}

	pub(super) fn with_admitted_entry<T>(
		&mut self,
		operation: impl FnOnce(&mut PreparedDarwinEntry<'_>) -> T,
	) -> Result<T, EntryPreparationError> {
		let name = self.job.name();
		self.prepare_entry(operation)
			.map_err(|source| EntryPreparationError::new(name, source))
	}

	fn prepare_entry<T>(
		&mut self,
		operation: impl FnOnce(&mut PreparedDarwinEntry<'_>) -> T,
	) -> Result<T, EntryPreparationFailure> {
		if mem::replace(&mut self.entry_attempted, true) {
			return Err(EntryPreparationFailure::AlreadyAttempted);
		}
		let plan = self.plan;
		let source = source_view(plan.source())?;
		let target = plan.destination().component;
		let component =
			UnixComponent::new(STAGE_PAYLOAD).map_err(EntryPreparationFailure::StageComponent)?;
		let context = StageBindingContext::new(
			self.job.name().job_id(),
			MODEL_ENTRY,
			RunEpoch::new(plan.attempt().epoch.get()),
		);
		let stage = self
			.job
			.create_stage_directory()
			.map_err(EntryPreparationFailure::Directory)?;
		let writer = stage
			.create_file(component, target, context, source.length())
			.map_err(EntryPreparationFailure::Stage)?;
		let stage_identity = writer
			.observe_identity()
			.map_err(EntryPreparationFailure::Stage)?;
		let directory_identity = stage
			.observe_identity()
			.map_err(EntryPreparationFailure::Stage)?;
		let preparation = DarwinEntryPrepared::new(
			&self.preparation,
			plan.attempt().entry,
			DarwinEntryPreparation {
				source,
				stage: DarwinStageObservation {
					id: DarwinStageId::from_bytes(*writer.identity().stage_id_bytes()),
					directory: native_identity(directory_identity)?,
					identity: native_identity(stage_identity)?,
					component,
				},
				target_component: target,
				target_observation: TargetObservation::AbsentObserved,
			},
		)?;
		let (frame, synced) = self
			.journal
			.append_frame(FrameKind::EntryPrepared, preparation.encode())
			.map_err(EntryPreparationFailure::Journal)?;
		let mut entry = PreparedDarwinEntry {
			_writer: Some(writer),
			_source: self.source,
			_journal: &mut self.journal,
			job: self.job,
			preparation,
			frame,
			synced,
		};
		Ok(operation(&mut entry))
	}
}

fn source_view(
	source: SourcePlanBinding<'_>,
) -> Result<DarwinSourceView<'_>, EntryPreparationFailure> {
	let metadata = source.metadata;
	Ok(DarwinSourceView::new(
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
			.map_err(EntryPreparationFailure::Metadata)?,
	)?)
}

fn owner_time(timestamp: ObservedTimestamp) -> Result<OwnerTimestamp, exacopy_journal::OwnerError> {
	OwnerTimestamp::new(timestamp.seconds(), timestamp.nanoseconds())
}
