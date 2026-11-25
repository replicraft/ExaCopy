use exacopy_journal::frame::Frame;
use exacopy_journal::{DarwinEntryPrepared, DarwinStageId, DurableJournal, SyncedFrame};
use exacopy_platform::macos::ManagedRegularFile;
use exacopy_platform::macos::staging::jobs::{JobDirectory, JobName};
use exacopy_platform::macos::staging::{
	StageBindingContext, StageDirectory, StageError, WriteStage,
};

use super::super::plan::DarwinCopyPlan;
use super::PreparedDarwinJob;
use super::admission::{check_source, native_identity};

mod engine;
mod error;
mod publish;

use engine::{ObservedStage, PrivateStage, StageAdmissionFailure, StageRequest};

pub use error::{EntryPreparationError, EntryPreparationFailure};
pub use publish::{DarwinCopyError, DarwinCopyFailure, PublicationProgress};

/// The private unwritten stage and synchronized kind-2 evidence for one entry.
#[derive(Debug)]
pub struct PreparedDarwinEntry<'entry> {
	writer: Option<WriteStage<'entry>>,
	source: &'entry ManagedRegularFile<'entry>,
	journal: &'entry mut DurableJournal,
	plan: DarwinCopyPlan<'entry>,
	progress: PublicationProgress,
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
		let plan = self.plan;
		let request = engine::begin(&mut self.entry_attempted, plan, self.job.name().job_id())?;
		let stage = self
			.job
			.create_stage_directory()
			.map_err(EntryPreparationFailure::Directory)?;
		let prepared = engine::prepare(request, &self.preparation, &stage, &mut self.journal)?;
		let mut entry = PreparedDarwinEntry {
			writer: Some(prepared.writer),
			source: self.source,
			journal: &mut self.journal,
			plan,
			progress: PublicationProgress::Private,
			job: self.job,
			preparation: prepared.preparation,
			frame: prepared.frame,
			synced: prepared.synced,
		};
		Ok(operation(&mut entry))
	}
}

impl PrivateStage for StageDirectory<'_> {
	type Error = StageError;
	type Writer<'stage>
		= WriteStage<'stage>
	where
		Self: 'stage;

	fn create<'stage>(
		&'stage self,
		request: &StageRequest<'stage>,
	) -> Result<ObservedStage<Self::Writer<'stage>>, StageAdmissionFailure<Self::Error>> {
		let context = StageBindingContext::new(request.job, request.entry, request.epoch);
		let writer = self
			.create_file(request.component, request.target, context, request.length)
			.map_err(StageAdmissionFailure::Adapter)?;
		let observed_file = writer
			.observe_identity()
			.map_err(StageAdmissionFailure::Adapter)?;
		let observed_directory = self
			.observe_identity()
			.map_err(StageAdmissionFailure::Adapter)?;
		Ok(ObservedStage {
			id: DarwinStageId::from_bytes(*writer.identity().stage_id_bytes()),
			directory: native_identity(observed_directory)
				.map_err(StageAdmissionFailure::Observation)?,
			identity: native_identity(observed_file).map_err(StageAdmissionFailure::Observation)?,
			writer,
		})
	}
}
