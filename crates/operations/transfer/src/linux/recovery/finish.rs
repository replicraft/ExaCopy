use std::io::Write as _;

use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurabilityRecorded, DurableJournal, JournalContext, JournalEpoch, LinuxPublicationBarriers,
	PublicationOutcome, PublishObserved, PublishedRecoveryEvidence, ReceiptCommitted,
	ReceiptDigest, RecoveryDecision, RecoveryStartEvidence, RecoveryStarted, SyncedFrame,
};
use exacopy_platform::linux::{
	DestinationRoot, RecoveryFile, RecoveryInventory, RecoveryWriteLease,
};

use super::super::{CopyReceipt, JournalTail, LocalCopyPlan, ReceiptEvidence};
use super::{
	RecoveryDisposition, RecoveryHistory, RecoveryInspectError, RecoveryInspection,
	RecoveryProfile, RecoveryStep, native_identity,
};

mod error;

pub use error::RecoveryFinishError;

/// Completes the journal and receipt after an already-published Linux copy.
///
/// The caller authorizes this specific job under the held destination and supplies its
/// independently trusted profile. Recovery obtains an exclusive job lease, verifies the
/// historical evidence and freshly checks the current published inode, then synchronizes
/// the relevant directories and completes the job's private history. Running this again
/// after receipt commitment returns the existing complete observation.
///
/// An intact private stage, a conflict, and a torn journal yield their current
/// inspection dispositions. This operation issues no new publication or deletion.
///
/// # Errors
/// Reports authentication, observation, effect recording, or barrier failures. Existing
/// source and destination names and all previously reached records remain in place.
pub fn finish_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryFinishError> {
	validate_stream_input(0, scratch.len()).map_err(super::RecoveryInspectError::Input)?;
	let lease = acquire_lease(destination, name)?;
	finish_leased(&lease, name, profile, scratch)
}

pub(super) fn acquire_lease<'root>(
	destination: &'root DestinationRoot,
	name: UnixComponent<'_>,
) -> Result<RecoveryWriteLease<'root>, RecoveryInspectError> {
	let previous = destination
		.open_recovery_job(name)
		.map_err(RecoveryStep::Job.platform())?;
	destination
		.try_recovery_write_lease(name, previous.identity())
		.map_err(RecoveryStep::Lease.platform())
}

pub(super) fn finish_leased(
	lease: &RecoveryWriteLease<'_>,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryFinishError> {
	let job = lease.job();
	let history = RecoveryHistory::load(job, name, profile)?;
	let plan = history.plan()?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	let current = history.inspect(job, &names, scratch)?;
	if current.tail != JournalTail::Clean
		|| !matches!(
			current.disposition,
			RecoveryDisposition::PublishedNeedsBarriers
				| RecoveryDisposition::PublishedNeedsReceipt { .. }
		) {
		return Ok(current);
	}

	CompleteCopy {
		history: &history,
		plan,
		names: &names,
	}
	.complete(lease)?;
	let history =
		RecoveryHistory::load(job, name, profile).map_err(RecoveryFinishError::Completion)?;
	history
		.inspect(job, &names, scratch)
		.map_err(RecoveryFinishError::Completion)
}

struct CompleteCopy<'history, 'root> {
	history: &'history RecoveryHistory,
	plan: LocalCopyPlan<'history>,
	names: &'history RecoveryInventory<'root>,
}

impl CompleteCopy<'_, '_> {
	fn complete(&self, lease: &RecoveryWriteLease<'_>) -> Result<(), RecoveryFinishError> {
		let replay = &self.history.journal;
		let intent = required(replay.intent)?;
		let intent_head = required(replay.intent_head)?;
		let metadata_head = required(replay.metadata_head)?;
		let verification_head = required(replay.verification_head)?;
		let evidence = required(replay.verification)?.stage();
		let stage = self
			.names
			.stage_directory_identity()
			.map(native_identity)
			.ok_or(RecoveryFinishError::IncompleteEvidence)?;
		let parent = self.plan.destination().root.identity;
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

		let segment = lease
			.open_first_segment_for_append(&self.history.journal_file)
			.map_err(completion(RecoveryStep::Journal))?;
		let mut journal = DurableJournal::resume_first_segment(
			segment,
			replay.boundary.head,
			replay.boundary.offset,
		)
		.map_err(RecoveryFinishError::Resume)?;
		let entry = self.plan.attempt().entry;
		let started = RecoveryStarted::new(
			context,
			entry,
			replay.latest_epoch,
			RecoveryStartEvidence {
				intent: intent_head,
				preceding: replay.boundary.head,
				authorization: self.history.owner.digest(),
			},
		)
		.map_err(RecoveryFinishError::Decision)?;
		let started = append(&mut journal, FrameKind::RecoveryStarted, &started.encode())?;
		let decision = RecoveryDecision::new(
			context,
			entry,
			started.head(),
			PublishedRecoveryEvidence {
				target: evidence.identity,
				destination_directory: parent,
				stage_directory: stage,
				verification: verification_head,
				stream: evidence,
				metadata: metadata_head,
			},
		)
		.map_err(RecoveryFinishError::Decision)?;
		let _ = append(
			&mut journal,
			FrameKind::RecoveryDecision,
			&decision.encode(),
		)?;
		lease
			.sync_publication(self.names)
			.map_err(completion(RecoveryStep::Namespace))?;

		let observed_head = match replay.observation.map(|observation| observation.outcome()) {
			Some(PublicationOutcome::Published { .. }) => required(replay.observation_head)?,
			None | Some(PublicationOutcome::Uncertain { .. }) => {
				let observed = PublishObserved::new(
					intent,
					intent_head,
					PublicationOutcome::Published {
						target: evidence.identity,
					},
				)
				.map_err(RecoveryFinishError::Publication)?;
				append(&mut journal, FrameKind::PublishObserved, &observed.encode())?.head()
			}
			Some(_) => return Err(RecoveryFinishError::IncompleteEvidence),
		};
		let durability = if let Some(head) = replay.durability_head {
			head
		} else {
			let record = DurabilityRecorded::new(
				intent,
				observed_head,
				LinuxPublicationBarriers {
					metadata: metadata_head,
					stage_directory: stage,
					destination_directory: parent,
				},
			)
			.map_err(RecoveryFinishError::Publication)?;
			append(
				&mut journal,
				FrameKind::DurabilityRecorded,
				&record.encode(),
			)?
			.head()
		};
		let receipt = CopyReceipt::from_evidence(
			ReceiptEvidence {
				context: JournalContext {
					epoch: intent.epoch,
					..self.plan.context()
				},
				entry,
				source: self.plan.source().file_identity,
				destination: self.plan.destination().root,
				target: self.plan.destination().component,
				stream: evidence,
			},
			durability,
		)
		.map_err(RecoveryFinishError::Receipt)?;

		let committed = ReceiptCommitted::new(
			intent,
			ReceiptDigest::from_bytes(receipt.digest()),
			durability,
		)
		.map_err(RecoveryFinishError::Publication)?;
		sync_receipt(lease, &receipt, self.history.receipt.as_ref())?;
		self.names
			.recheck()
			.map_err(completion(RecoveryStep::Namespace))?;
		let _ = append(
			&mut journal,
			FrameKind::ReceiptCommitted,
			&committed.encode(),
		)?;
		Ok(())
	}
}

pub(super) fn sync_receipt(
	lease: &RecoveryWriteLease<'_>,
	receipt: &CopyReceipt<'_>,
	existing: Option<&RecoveryFile>,
) -> Result<(), RecoveryFinishError> {
	let receipts = lease
		.open_receipt_directory()
		.map_err(completion(RecoveryStep::Receipt))?;
	if let Some(current) = existing {
		receipts
			.sync_receipt(current)
			.map_err(completion(RecoveryStep::Receipt))?;
	} else {
		let mut file = receipts
			.create_receipt()
			.map_err(completion(RecoveryStep::Receipt))?;
		file.write_all(&receipt.encode())
			.map_err(RecoveryFinishError::WriteReceipt)?;
		file.sync_all().map_err(RecoveryFinishError::WriteReceipt)?;
	}
	receipts
		.sync_directory()
		.map_err(completion(RecoveryStep::Receipt))?;
	lease
		.sync_job_directory()
		.map_err(completion(RecoveryStep::Job))?;
	Ok(())
}

pub(super) fn required<T>(value: Option<T>) -> Result<T, RecoveryFinishError> {
	value.ok_or(RecoveryFinishError::IncompleteEvidence)
}

pub(super) fn append(
	journal: &mut DurableJournal,
	kind: FrameKind,
	payload: &[u8],
) -> Result<SyncedFrame, RecoveryFinishError> {
	journal
		.append(kind, payload)
		.map_err(|source| RecoveryFinishError::Journal { kind, source })
}

pub(super) fn completion(
	step: RecoveryStep,
) -> impl FnOnce(exacopy_platform::linux::StageError) -> RecoveryFinishError {
	move |source| RecoveryFinishError::Completion(step.platform()(source))
}
