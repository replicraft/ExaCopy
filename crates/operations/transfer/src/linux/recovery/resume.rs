use exacopy_content::validate_stream_input;
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_journal::{DurableJournal, LinuxFileIdentity};
use exacopy_model::CopyBinding;
use exacopy_platform::linux::{
	ClosedStage, DestinationRoot, FileIdentity, PublishError, ReadError, RecoveryFile,
	RecoveryStageDirectory, RecoveryWriteLease, SourceObservation, SourceTimestamp, StageError,
	WriteStage,
};

use super::super::local_copy::ProtocolError;
use super::super::{CopyReceipt, JournalBoundary};
use super::finish::{acquire_lease, completion, finish_leased, sync_receipt};
use super::source::open_source;
use super::{
	RecoveryDisposition, RecoveryFinishError, RecoveryHistory, RecoveryInspectError,
	RecoveryInspection, RecoveryProfile, RecoveryRetryError, RecoverySource, RecoveryStep,
	native_identity,
};

mod engine;
mod error;

use engine::{Evidence, Records, Resume, RetainedStage, StageDirectory};
use error::ResumeError;

/// Resumes an interrupted, journaled copy from its bound private stage.
///
/// The current source grant must match the original plan and preparation. The job must
/// have an intact pre-intent journal and a bound private stage. A synchronized new
/// generation precedes writes under the exclusive job lease. For a writable stage,
/// reuse requires the historical digest to agree in both held streams. A stage that
/// already has the planned permissions can proceed through a read-only data handle
/// after fresh full-stream agreement. Both paths finish metadata and require a new
/// exclusive publication intent. Source consistency is live observed.
///
/// Existing publication intents remain subject to their ordinary recovery paths.
/// If publication already happened, this function can complete its receipt under the same lease.
///
/// # Errors
/// A mismatched source grant or current metadata, unsafe stage, unsupported history or
/// failed verification cannot authorize publication. Partial writes remain in the original
/// private stage. Uncertain publication and receipt effects require reconciliation.
pub fn resume_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	source: RecoverySource<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryRetryError> {
	validate_stream_input(0, scratch.len()).map_err(RecoveryInspectError::Input)?;
	let lease = acquire_lease(destination, name)?;
	let job = lease.job();
	let history = RecoveryHistory::load(job, name, profile)?;
	let plan = history.plan()?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	let current = history.inspect(job, &names, scratch)?;
	match current.disposition {
		RecoveryDisposition::RetainedPreparation if history.journal.stage.is_some() => {
			let stage = names
				.stage()
				.ok_or(RecoveryFinishError::IncompleteEvidence)?;
			let retained = RetainedFile(stage);
			let reopened = open_source(&plan, &history.journal, source)?;
			let resume = Resume::admit::<StageError, PublishError, RecoveryFinishError>(
				Evidence {
					plan: &plan,
					replay: &history.journal,
					ranges: &history.ranges,
					owner: history.owner.digest(),
				},
				&reopened,
				RetainedStage {
					reader: &retained,
					identity: stage.identity(),
					mode: stage.observation().mode(),
				},
				scratch.len(),
				|time| SourceTimestamp::new(time.seconds(), time.nanoseconds()),
			)
			.map_err(native_error)?;
			let directory = lease
				.reopen_stage_directory(&names)
				.map_err(completion(RecoveryStep::Namespace))?;
			resume
				.execute(
					&mut HeldDirectory(directory),
					&NativeRecords {
						lease: &lease,
						journal: &history.journal_file,
					},
					scratch,
				)
				.map_err(native_error)?;
		}
		RecoveryDisposition::PublishedNeedsBarriers
		| RecoveryDisposition::PublishedNeedsReceipt { .. } => {}
		_ => return Ok(current),
	}
	finish_leased(&lease, name, profile, scratch)
		.map_err(|error| match error {
			RecoveryFinishError::Inspection(error) => RecoveryFinishError::Completion(error),
			error => error,
		})
		.map_err(RecoveryRetryError::Recovery)
}

struct RetainedFile<'file>(&'file RecoveryFile);

impl ReadView for RetainedFile<'_> {
	type Error = ReadError;

	fn length(&self) -> u64 {
		self.0.len()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.0.recheck_observation()
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.0.read_exact_at(offset, bytes)
	}
}

struct HeldDirectory<'lease>(RecoveryStageDirectory<'lease>);

impl StageDirectory<SourceObservation, FileIdentity> for HeldDirectory<'_> {
	type Error = StageError;
	type PublicationError = PublishError;
	type Reader<'stage>
		= ClosedStage<'stage>
	where
		Self: 'stage;
	type Writer<'stage>
		= WriteStage<'stage>
	where
		Self: 'stage;

	fn identity(&self) -> LinuxFileIdentity {
		native_identity(self.0.identity())
	}

	fn record_identity(identity: FileIdentity) -> LinuxFileIdentity {
		native_identity(identity)
	}

	fn open_writer(&mut self, binding: CopyBinding) -> Result<Self::Writer<'_>, Self::Error> {
		self.0.open_writer(binding)
	}

	fn open_flushed_readback(
		&mut self,
		binding: CopyBinding,
		source: SourceObservation,
	) -> Result<Self::Reader<'_>, Self::Error> {
		self.0.open_flushed_readback(binding, source)
	}
}

struct NativeRecords<'lease, 'root> {
	lease: &'lease RecoveryWriteLease<'root>,
	journal: &'lease RecoveryFile,
}

impl Records for NativeRecords<'_, '_> {
	type Error = RecoveryFinishError;

	fn resume_journal(&self, boundary: JournalBoundary) -> Result<DurableJournal, Self::Error> {
		let segment = self
			.lease
			.open_first_segment_for_append(self.journal)
			.map_err(completion(RecoveryStep::Journal))?;
		DurableJournal::resume_first_segment(segment, boundary.head, boundary.offset)
			.map_err(RecoveryFinishError::Resume)
	}

	fn sync_receipt(&self, receipt: &CopyReceipt<'_>) -> Result<(), Self::Error> {
		sync_receipt(self.lease, receipt, None)
	}
}

fn native_error(
	error: ResumeError<ReadError, StageError, PublishError, RecoveryFinishError>,
) -> RecoveryRetryError {
	match error {
		ResumeError::Input(error) => RecoveryInspectError::Input(error).into(),
		ResumeError::IncompleteEvidence => RecoveryFinishError::IncompleteEvidence.into(),
		ResumeError::EpochExhausted => RecoveryFinishError::EpochExhausted.into(),
		ResumeError::Resume(error) => RecoveryFinishError::Resume(error).into(),
		ResumeError::Decision(error) => RecoveryFinishError::Decision(error).into(),
		ResumeError::PublicationRecord(error) => RecoveryFinishError::Publication(error).into(),
		ResumeError::Journal { kind, source } => {
			RecoveryFinishError::Journal { kind, source }.into()
		}
		ResumeError::Records(error) => error.into(),
		ResumeError::Receipt(error) => RecoveryFinishError::Receipt(error).into(),
		ResumeError::Namespace(error) => completion(RecoveryStep::Namespace)(error).into(),
		ResumeError::SourceMismatch => RecoveryRetryError::SourceMismatch,
		ResumeError::SourcePolicy(error) => RecoveryRetryError::SourcePolicy(error),
		ResumeError::MeasureSource(error) => RecoveryRetryError::MeasureSource(error),
		ResumeError::Stage(issue) => RecoveryRetryError::Stage(issue),
		ResumeError::Model(error) => RecoveryRetryError::Model(error),
		ResumeError::ResumeStage(error) => RecoveryRetryError::ResumeStage(error),
		ResumeError::Seal(error) => RecoveryRetryError::ResumeCopy(Box::new(error.into())),
		ResumeError::Publish(ProtocolError::Publication {
			source: PublishError::Conflict,
			recording: None,
		}) => RecoveryRetryError::Publish(PublishError::Conflict),
		ResumeError::Publish(error) => RecoveryRetryError::ResumeCopy(Box::new(error.into())),
	}
}
