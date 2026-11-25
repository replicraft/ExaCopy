use exacopy_content::{
	CheckpointCandidate, ContentDigest, ResumeMeasureError, measure_at, resume_and_measure_at,
	validate_stream_input,
};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, JournalContext, JournalEpoch, LinuxFileIdentity, RangeResumeEvidence,
	RangeResumeStarted, ReceiptCommitted, ReceiptDigest,
};
use exacopy_model::{CopyBinding, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::{
	ClosedStage, DestinationRoot, PublishError, RecoveryFile, RecoveryInventory,
	RecoveryStageDirectory, RecoveryWriteLease, SourceFile, SourceTimestamp, WriteStage,
};

use super::super::local_copy::Publication;
#[cfg(test)]
use super::super::local_copy::crash_tests::{Checkpoint, pause_at};
use super::super::local_copy::records::EntryEvidence;
use super::super::{
	CopyReceipt, LocalCopyError, LocalCopyPlan, MAX_LOCAL_JOURNAL_BYTES, ReceiptEvidence,
	StageFailure, VerifiedStage, begin_stage_reads, check_source, complete_stage_metadata,
	flush_written_stage, observe, verify_stage_readback,
};
use super::finish::{acquire_lease, append, completion, finish_leased, required, sync_receipt};
use super::source::open_source;
use super::{
	RecoveryDisposition, RecoveryFinishError, RecoveryHistory, RecoveryInspectError,
	RecoveryInspection, RecoveryIssue, RecoveryProfile, RecoveryRetryError, RecoverySource,
	RecoveryStep, native_identity,
};

const PRIVATE_STAGE_MODE: u32 = 0o600;
// The local start, seal, verification, metadata, effect and receipt suffixes are
// independently bounded. Keep room for a complete attempt and receipt recovery.
const RESUME_JOURNAL_RESERVE: u64 = 16 * 1024;

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
			Resume {
				history: &history,
				plan: &plan,
				names: &names,
			}
			.copy_and_publish(&lease, source, scratch)?;
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

struct Resume<'history, 'root> {
	history: &'history RecoveryHistory,
	plan: &'history LocalCopyPlan<'history>,
	names: &'history RecoveryInventory<'root>,
}

impl Resume<'_, '_> {
	fn copy_and_publish(
		&self,
		lease: &RecoveryWriteLease<'_>,
		grant: RecoverySource<'_>,
		scratch: &mut [u8],
	) -> Result<(), RecoveryRetryError> {
		let replay = &self.history.journal;
		let stage = self
			.names
			.stage()
			.ok_or(RecoveryFinishError::IncompleteEvidence)?;
		let source = open_source(self.plan, replay, grant)?;
		validate_stream_input(source.len(), scratch.len()).map_err(RecoveryInspectError::Input)?;
		let prepared_source = required(replay.source)?;
		let source_metadata = required(replay.source_metadata)?;
		let recorded_atime = prepared_source.times().accessed_at;
		let accessed_at =
			SourceTimestamp::new(recorded_atime.seconds(), recorded_atime.nanoseconds())
				.map_err(|error| RecoveryRetryError::SourcePolicy(StageFailure::Source(error)))?;
		let stage_mode = stage.observation().mode();
		if stage_mode != PRIVATE_STAGE_MODE && stage_mode != source_metadata.mode() {
			return Err(RecoveryRetryError::Stage(RecoveryIssue::MetadataMismatch));
		}
		if stage.len() > source.len()
			|| (stage_mode != PRIVATE_STAGE_MODE && stage.len() != source.len())
			|| stage.identity() == source.identity()
		{
			return Err(RecoveryRetryError::Stage(RecoveryIssue::StreamMismatch));
		}
		let mut directory = lease
			.reopen_stage_directory(self.names)
			.map_err(completion(RecoveryStep::Namespace))?;
		let stage_directory = native_identity(directory.identity());
		let (context, binding) = self.next_attempt()?;
		let mut session = CopySession::new(binding);
		let (stage, digest, mut journal) = if stage_mode == PRIVATE_STAGE_MODE {
			let journal = self.start(
				lease,
				context,
				native_identity(stage.identity()),
				stage_directory,
			)?;
			let writer = directory
				.open_writer(binding)
				.map_err(completion(RecoveryStep::Namespace))?;
			let (stage, digest) = rewrite_ranges(
				writer,
				stage,
				&source,
				&self.history.ranges,
				scratch,
				&mut session,
				binding,
			)?;
			(stage, digest, journal)
		} else {
			let (stage, digest) =
				verify_retained_stage(&mut directory, &source, scratch, &mut session, binding)?;
			// Refuse a changed source before appending anything or applying metadata.
			check_source(&source).map_err(RecoveryRetryError::SourcePolicy)?;
			let journal = self.start(
				lease,
				context,
				native_identity(stage.identity()),
				stage_directory,
			)?;
			(stage, digest, journal)
		};
		let stage = complete_stage_metadata(stage, &source, accessed_at, &mut session, binding)
			.map_err(RecoveryRetryError::ResumeStage)?;
		#[cfg(test)]
		super::super::local_copy::crash_tests::pause_metadata_at(
			Checkpoint::RangeResumeMetadataApplied,
		);

		let mut verified = VerifiedStage {
			stage,
			session,
			digest,
		};
		let sealed = EntryEvidence::from_preparation(
			context,
			self.plan.attempt().entry,
			prepared_source,
			source_metadata,
			self.plan.destination(),
		)
		.seal(&verified)
		.map_err(copy_error)?;
		let metadata = sealed.record(&mut journal).map_err(copy_error)?;
		check_source(&source).map_err(RecoveryRetryError::SourcePolicy)?;
		let publication = Publication {
			context,
			plan: self.plan,
			binding,
			stage_directory,
		};
		let durability = publication
			.complete(
				&mut journal,
				&mut verified.session,
				verified.stage,
				&sealed,
				&metadata,
			)
			.map_err(copy_error)?;
		let receipt = CopyReceipt::from_synced_durability(
			ReceiptEvidence {
				context,
				entry: self.plan.attempt().entry,
				source: prepared_source.identity(),
				destination: self.plan.destination().root,
				target: self.plan.destination().component,
				stream: sealed.verification.stage(),
			},
			&durability,
		)
		.map_err(RecoveryFinishError::Receipt)?;
		let committed = ReceiptCommitted::new(
			publication.intent_context(),
			ReceiptDigest::from_bytes(receipt.digest()),
			durability.head(),
		)
		.map_err(RecoveryFinishError::Publication)?;
		sync_receipt(lease, &receipt, None)?;
		let _ = append(
			&mut journal,
			FrameKind::ReceiptCommitted,
			&committed.encode(),
		)?;
		observe(&mut verified.session, binding, CopyEvent::ReceiptRecorded)
			.map_err(RecoveryRetryError::Model)?;
		Ok(())
	}

	fn next_attempt(&self) -> Result<(JournalContext, CopyBinding), RecoveryRetryError> {
		let replay = &self.history.journal;
		let context = JournalContext {
			epoch: JournalEpoch::new(
				replay
					.latest_epoch
					.get()
					.checked_add(1)
					.ok_or(RecoveryFinishError::EpochExhausted)?,
			),
			..self.plan.context()
		};
		let entry = self.plan.attempt().entry;
		let binding = CopyBinding::new(
			JobId::try_from_bytes(*context.job.as_bytes())
				.map_err(|_| RecoveryFinishError::IncompleteEvidence)?,
			EntryId::new(1),
			RunEpoch::new(context.epoch.get()),
			StageId::from_bytes(*entry.as_bytes()),
		);
		Ok((context, binding))
	}

	fn start(
		&self,
		lease: &RecoveryWriteLease<'_>,
		context: JournalContext,
		stage: LinuxFileIdentity,
		stage_directory: LinuxFileIdentity,
	) -> Result<DurableJournal, RecoveryRetryError> {
		let replay = &self.history.journal;
		let boundary = replay.boundary;
		if boundary.offset > MAX_LOCAL_JOURNAL_BYTES - RESUME_JOURNAL_RESERVE {
			return Err(RecoveryFinishError::Resume(
				exacopy_journal::DurableJournalError::SegmentTooLarge {
					length: boundary.offset + RESUME_JOURNAL_RESERVE,
					limit: MAX_LOCAL_JOURNAL_BYTES,
				},
			)
			.into());
		}
		let entry = self.plan.attempt().entry;
		let start = RangeResumeStarted::new(
			context,
			entry,
			replay.latest_epoch,
			RangeResumeEvidence {
				preparation: required(replay.preparation_head)?,
				preceding: boundary.head,
				stage,
				stage_directory,
				authorization: self.history.owner.digest(),
			},
		)
		.map_err(RecoveryFinishError::Decision)?;
		let segment = lease
			.open_first_segment_for_append(&self.history.journal_file)
			.map_err(completion(RecoveryStep::Journal))?;
		let mut journal =
			DurableJournal::resume_first_segment(segment, boundary.head, boundary.offset)
				.map_err(RecoveryFinishError::Resume)?;
		let _ = append(&mut journal, FrameKind::RecoveryStarted, &start.encode())?;
		#[cfg(test)]
		pause_at(Checkpoint::RangeResumeStartedSynced);
		Ok(journal)
	}
}

fn rewrite_ranges<'stage>(
	mut writer: WriteStage<'stage>,
	retained: &RecoveryFile,
	source: &SourceFile,
	candidates: &[CheckpointCandidate],
	scratch: &mut [u8],
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(ClosedStage<'stage>, ContentDigest), RecoveryRetryError> {
	writer
		.check_ownership(source.observation())
		.map_err(completion(RecoveryStep::Namespace))?;
	begin_stage_reads(session, binding).map_err(RecoveryRetryError::Model)?;
	let digest = resume_and_measure_at(
		source.len(),
		retained.len(),
		scratch,
		candidates,
		|offset, bytes| source.read_exact_at(offset, bytes),
		|offset, bytes| retained.read_exact_at(offset, bytes),
		|offset, bytes| writer.write_all_at(offset, bytes),
	)
	.map_err(|error| match error {
		ResumeMeasureError::SourceChanged { .. } => RecoveryRetryError::SourceMismatch,
		error => RecoveryRetryError::ResumeStage(StageFailure::Resume(error)),
	})?
	.digest;
	flush_written_stage(&mut writer, source.len(), session, binding)
		.map_err(RecoveryRetryError::ResumeStage)?;
	#[cfg(test)]
	pause_at(Checkpoint::RangeResumeDataFlushed);
	let stage = writer
		.close_writes()
		.map_err(|error| RecoveryRetryError::ResumeStage(StageFailure::Stage(error)))?;
	verify_stage_readback(&stage, source.len(), digest, scratch, session, binding)
		.map_err(RecoveryRetryError::ResumeStage)?;
	Ok((stage, digest))
}

fn verify_retained_stage<'stage>(
	directory: &'stage mut RecoveryStageDirectory<'_>,
	source: &SourceFile,
	scratch: &mut [u8],
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(ClosedStage<'stage>, ContentDigest), RecoveryRetryError> {
	observe(session, binding, CopyEvent::RetainedStageReopened)
		.map_err(RecoveryRetryError::Model)?;
	observe(session, binding, CopyEvent::WritersJoined).map_err(RecoveryRetryError::Model)?;
	let stage = directory
		.open_flushed_readback(binding, source.observation())
		.map_err(completion(RecoveryStep::Namespace))?;
	observe(session, binding, CopyEvent::DataFlushed).map_err(RecoveryRetryError::Model)?;
	let digest = measure_at(source.len(), scratch, |offset, bytes| {
		source.read_exact_at(offset, bytes)
	})
	.map_err(RecoveryRetryError::MeasureSource)?;
	verify_stage_readback(&stage, source.len(), digest, scratch, session, binding)
		.map_err(RecoveryRetryError::ResumeStage)?;
	Ok((stage, digest))
}

fn copy_error(error: LocalCopyError) -> RecoveryRetryError {
	match error {
		LocalCopyError::Publication {
			source: PublishError::Conflict,
			recording: None,
		} => RecoveryRetryError::Publish(PublishError::Conflict),
		error => RecoveryRetryError::ResumeCopy(Box::new(error)),
	}
}
