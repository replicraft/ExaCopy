use exacopy_content::{ResumeMeasureError, resume_and_measure_at, validate_stream_input};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, JournalContext, JournalEpoch, RangeResumeEvidence, RangeResumeStarted,
	ReceiptCommitted, ReceiptDigest,
};
use exacopy_model::{CopyBinding, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::{
	DestinationRoot, PublishError, RecoveryInventory, RecoveryWriteLease, SourceTimestamp,
};

use super::super::local_copy::Publication;
#[cfg(test)]
use super::super::local_copy::crash_tests::{Checkpoint, pause_at};
use super::super::local_copy::records::EntryEvidence;
use super::super::{
	CopyReceipt, LocalCopyError, LocalCopyPlan, MAX_LOCAL_JOURNAL_BYTES, ReceiptEvidence,
	StageFailure, VerifiedStage, begin_stage_reads, check_source, flush_written_stage, observe,
	verify_written_stage,
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

/// Completes an interrupted, journaled copy using freshly checked private ranges.
///
/// The current source grant must match the original plan and preparation. The job must
/// have at least one complete range checkpoint and an intact pre-intent journal and
/// private writable stage. Under an exclusive job lease, a synchronized new generation
/// precedes all writes. Every reused range must agree with the historical digest in
/// both current streams. The complete source is measured and the sealed stage is read
/// independently before a new exclusive publication intent. Source consistency is live observed.
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
		RecoveryDisposition::RetainedPreparation if !history.ranges.is_empty() => {
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
		if stage.observation().mode() != PRIVATE_STAGE_MODE {
			return Err(RecoveryRetryError::Stage(RecoveryIssue::MetadataMismatch));
		}
		let source = open_source(self.plan, replay, grant)?;
		validate_stream_input(source.len(), scratch.len()).map_err(RecoveryInspectError::Input)?;
		let prepared_source = required(replay.source)?;
		let source_metadata = required(replay.source_metadata)?;
		let recorded_atime = prepared_source.times().accessed_at;
		let accessed_at =
			SourceTimestamp::new(recorded_atime.seconds(), recorded_atime.nanoseconds())
				.map_err(|error| RecoveryRetryError::SourcePolicy(StageFailure::Source(error)))?;
		if stage.len() > source.len() || stage.identity() == source.identity() {
			return Err(RecoveryRetryError::Stage(RecoveryIssue::StreamMismatch));
		}
		let mut directory = lease
			.reopen_stage_directory(self.names)
			.map_err(completion(RecoveryStep::Namespace))?;
		let stage_directory = native_identity(directory.identity());
		let (context, binding, mut journal) =
			self.start(lease, native_identity(stage.identity()), stage_directory)?;

		let mut writer = directory
			.open_writer(binding)
			.map_err(completion(RecoveryStep::Namespace))?;
		writer
			.check_ownership(source.observation())
			.map_err(completion(RecoveryStep::Namespace))?;
		let mut session = CopySession::new(binding);
		begin_stage_reads(&mut session, binding).map_err(RecoveryRetryError::Model)?;
		let measurement = resume_and_measure_at(
			source.len(),
			stage.len(),
			scratch,
			&self.history.ranges,
			|offset, bytes| source.read_exact_at(offset, bytes),
			|offset, bytes| stage.read_exact_at(offset, bytes),
			|offset, bytes| writer.write_all_at(offset, bytes),
		)
		.map_err(|error| match error {
			ResumeMeasureError::SourceChanged { .. } => RecoveryRetryError::SourceMismatch,
			error => RecoveryRetryError::ResumeStage(StageFailure::Resume(error)),
		})?;
		flush_written_stage(&mut writer, source.len(), &mut session, binding)
			.map_err(RecoveryRetryError::ResumeStage)?;
		#[cfg(test)]
		pause_at(Checkpoint::RangeResumeDataFlushed);

		let (stage, digest) = verify_written_stage(
			writer,
			&source,
			accessed_at,
			measurement.digest,
			scratch,
			&mut session,
			binding,
		)
		.map_err(RecoveryRetryError::ResumeStage)?;
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

	fn start(
		&self,
		lease: &RecoveryWriteLease<'_>,
		stage: exacopy_journal::LinuxFileIdentity,
		stage_directory: exacopy_journal::LinuxFileIdentity,
	) -> Result<(JournalContext, CopyBinding, DurableJournal), RecoveryRetryError> {
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
		Ok((context, binding, journal))
	}
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
