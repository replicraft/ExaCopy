use std::fmt;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinEntryPrepared, DarwinStageId, DurableJournalError, RootCapabilityId, SyncedFrame,
};
use exacopy_platform::macos::ManagedRegularFile;
use exacopy_platform::macos::staging::jobs::{JobDirectory, JobName};
use exacopy_platform::macos::staging::{
	StageBindingContext, StageDirectory, StageError, WriteStage,
};
use exacopy_transfer::macos::job::entry::publish::{PublicationAttempt, PublicationJournal};
use exacopy_transfer::macos::job::entry::{
	self, ObservedStage, PrivateStage, StageAdmissionFailure, StageRequest,
};

use super::super::plan::{DarwinCopyPlan, SourcePlanBinding};
use super::admission::{check_source, native_identity};
use super::{JobAdmissionError, PreparedDarwinJob};

mod error;
mod publish;

pub use error::{EntryPreparationError, EntryPreparationFailure};
pub use publish::{DarwinCopyError, DarwinCopyFailure, PublicationProgress};

/// The private unwritten stage and synchronized kind-2 evidence for one entry.
#[derive(Debug)]
pub struct PreparedDarwinEntry<'entry> {
	attempt: PublicationAttempt<publish::NativePreparedCopy<'entry>>,
	journal: HeldJournal<'entry>,
	plan: DarwinCopyPlan<'entry>,
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
		self.with_source_check(check_source, operation)
	}

	#[cfg(test)]
	pub(super) fn with_admitted_entry<T>(
		&mut self,
		operation: impl FnOnce(&mut PreparedDarwinEntry<'_>) -> T,
	) -> Result<T, EntryPreparationError> {
		self.with_source_check(|_, _, _| Ok(()), operation)
	}

	fn with_source_check<T>(
		&mut self,
		check: impl FnOnce(
			SourcePlanBinding<'_>,
			&ManagedRegularFile<'_>,
			RootCapabilityId,
		) -> Result<(), JobAdmissionError>,
		operation: impl FnOnce(&mut PreparedDarwinEntry<'_>) -> T,
	) -> Result<T, EntryPreparationError> {
		let name = self.job.name();
		let (planned, source, root_id) = (self.plan.source(), self.source, self.source_root_id);
		self.prepare_entry(|| check(planned, source, root_id), operation)
			.map_err(|source| EntryPreparationError::new(name, source))
	}

	fn prepare_entry<T>(
		&mut self,
		check: impl FnOnce() -> Result<(), JobAdmissionError>,
		operation: impl FnOnce(&mut PreparedDarwinEntry<'_>) -> T,
	) -> Result<T, EntryPreparationFailure> {
		let plan = self.plan;
		let (request, stage) = entry::open(
			&mut self.entry_attempt,
			plan,
			self.job.name().job_id(),
			check,
			|| self.job.create_stage_directory(),
		)?;
		let held = HeldStageDirectory(&stage);
		let prepared = entry::prepare(request, &self.preparation, &held, &mut self.journal)?;
		let mut entry = PreparedDarwinEntry {
			attempt: PublicationAttempt::new(publish::NativePreparedCopy::new(
				self.source,
				prepared.writer,
			)),
			journal: HeldJournal(&mut self.journal),
			plan,
			job: self.job,
			preparation: prepared.preparation,
			frame: prepared.frame,
			synced: prepared.synced,
		};
		Ok(operation(&mut entry))
	}
}

struct HeldStageDirectory<'stage>(&'stage StageDirectory<'stage>);

impl PrivateStage for HeldStageDirectory<'_> {
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
			.0
			.create_file(request.component, request.target, context, request.length)
			.map_err(StageAdmissionFailure::Adapter)?;
		let observed_file = writer
			.observe_identity()
			.map_err(StageAdmissionFailure::Adapter)?;
		let observed_directory = self
			.0
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

struct HeldJournal<'entry>(&'entry mut dyn PublicationJournal);

impl fmt::Debug for HeldJournal<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("HeldJournal")
			.finish_non_exhaustive()
	}
}

impl PublicationJournal for HeldJournal<'_> {
	fn append(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError> {
		self.0.append(kind, payload)
	}
}
