use std::io::Write as _;

use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurabilityRecorded, DurableJournal, JournalContext, JournalEpoch, LinuxPublicationBarriers,
	PublicationOutcome, PublishObserved, PublishedRecoveryEvidence, ReceiptCommitted,
	ReceiptDigest, RecoveryDecision, RecoveryStartEvidence, RecoveryStarted, SyncedFrame,
};
use exacopy_platform::linux::{DestinationRoot, RecoveryInventory, RecoveryWriteLease};

use super::super::{CopyReceipt, JournalTail, LocalCopyPlan, ReceiptEvidence};
use super::{
	RecoveryDisposition, RecoveryHistory, RecoveryInspection, RecoveryProfile, RecoveryStep,
	native_identity,
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
	let previous = destination
		.open_recovery_job(name)
		.map_err(RecoveryStep::Job.platform())?;
	let lease = destination
		.try_recovery_write_lease(name, previous.identity())
		.map_err(RecoveryStep::Lease.platform())?;
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
	.complete(&lease)?;
	let history = RecoveryHistory::load(job, name, profile)?;
	history
		.inspect(job, &names, scratch)
		.map_err(RecoveryFinishError::Inspection)
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
			.map_err(RecoveryStep::Journal.platform())?;
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
			.map_err(RecoveryStep::Namespace.platform())?;

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
				context: self.plan.context(),
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
		self.sync_receipt(lease, &receipt)?;
		self.names
			.recheck()
			.map_err(RecoveryStep::Namespace.platform())?;
		let _ = append(
			&mut journal,
			FrameKind::ReceiptCommitted,
			&committed.encode(),
		)?;
		Ok(())
	}

	fn sync_receipt(
		&self,
		lease: &RecoveryWriteLease<'_>,
		receipt: &CopyReceipt<'_>,
	) -> Result<(), RecoveryFinishError> {
		let receipts = lease
			.open_receipt_directory()
			.map_err(RecoveryStep::Receipt.platform())?;
		if let Some(current) = &self.history.receipt {
			receipts
				.sync_receipt(current)
				.map_err(RecoveryStep::Receipt.platform())?;
		} else {
			let mut file = receipts
				.create_receipt()
				.map_err(RecoveryStep::Receipt.platform())?;
			file.write_all(&receipt.encode())
				.map_err(RecoveryFinishError::WriteReceipt)?;
			file.sync_all().map_err(RecoveryFinishError::WriteReceipt)?;
		}
		receipts
			.sync_directory()
			.map_err(RecoveryStep::Receipt.platform())?;
		lease
			.sync_job_directory()
			.map_err(RecoveryStep::Job.platform())?;
		Ok(())
	}
}

fn required<T>(value: Option<T>) -> Result<T, RecoveryFinishError> {
	value.ok_or(RecoveryFinishError::IncompleteEvidence)
}

fn append(
	journal: &mut DurableJournal,
	kind: FrameKind,
	payload: &[u8],
) -> Result<SyncedFrame, RecoveryFinishError> {
	journal
		.append(kind, payload)
		.map_err(|source| RecoveryFinishError::Journal { kind, source })
}
