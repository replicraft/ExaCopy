use std::io::{self, Write as _};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_publication::ReceiptRecord as _;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	DurabilityRecorded, DurableJournalError, JournalContext, JournalEpoch,
	LinuxPublicationBarriers, PublicationOutcome, PublicationRecordError, PublishObserved,
	PublishedRecoveryEvidence, ReceiptCommitted, ReceiptDigest, RecoveryDecision,
	RecoveryRecordError, RecoveryStartEvidence, RecoveryStarted,
};

use super::super::super::{CopyReceipt, JournalTail, ReceiptError, ReceiptEvidence};
use super::super::{RecoveryDisposition, RecoveryInspection, RecoveryProfile, RecoveryStep};
use super::capabilities::{
	FinishEvidence, FinishJournal, FinishLease, FinishReceiptDirectory, ReceiptLease,
};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(super) enum FinishError<I, E> {
	Inspection(I),
	Completion(I),
	Effect {
		step: RecoveryStep,
		source: E,
	},
	IncompleteEvidence,
	EpochExhausted,
	Resume(DurableJournalError),
	Decision(RecoveryRecordError),
	Publication(PublicationRecordError),
	Journal {
		kind: FrameKind,
		source: DurableJournalError,
	},
	Receipt(ReceiptError),
	WriteReceipt(io::Error),
}

type FinishResult<L, T> =
	Result<T, FinishError<<L as FinishLease>::InspectError, <L as ReceiptLease>::EffectError>>;

pub(super) fn finish<L: FinishLease>(
	lease: &L,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> FinishResult<L, RecoveryInspection> {
	let history = lease.load(name, profile).map_err(FinishError::Inspection)?;
	let evidence = lease.evidence(&history).map_err(FinishError::Inspection)?;
	let names = lease
		.inventory(evidence.plan)
		.map_err(FinishError::Inspection)?;
	let current = lease
		.inspect(&history, &names, scratch)
		.map_err(FinishError::Inspection)?;
	if current.tail != JournalTail::Clean
		|| !matches!(
			current.disposition,
			RecoveryDisposition::PublishedNeedsBarriers
				| RecoveryDisposition::PublishedNeedsReceipt { .. }
		) {
		return Ok(current);
	}

	complete(lease, &history, &names, evidence)?;
	let history = lease.load(name, profile).map_err(FinishError::Completion)?;
	lease
		.inspect(&history, &names, scratch)
		.map_err(FinishError::Completion)
}

fn complete<'lease, L: FinishLease>(
	lease: &'lease L,
	history: &L::History,
	names: &L::Inventory<'lease>,
	evidence: FinishEvidence<'_, L::ExistingReceipt>,
) -> FinishResult<L, ()> {
	let replay = evidence.replay;
	let intent = required(replay.intent)?;
	let intent_head = required(replay.intent_head)?;
	let metadata_head = required(replay.metadata_head)?;
	let verification_head = required(replay.verification_head)?;
	let stream = required(replay.verification)?.stage();
	let stage = required(lease.stage_directory_identity(names))?;
	let parent = evidence.plan.destination().root.identity;
	let context = JournalContext {
		epoch: JournalEpoch::new(
			replay
				.latest_epoch
				.get()
				.checked_add(1)
				.ok_or(FinishError::EpochExhausted)?,
		),
		..evidence.plan.context()
	};

	let segment = lease
		.open_journal(history)
		.map_err(effect(RecoveryStep::Journal))?;
	let mut journal = lease
		.resume_journal(segment, replay.boundary)
		.map_err(FinishError::Resume)?;
	let entry = evidence.plan.attempt().entry;
	let started = RecoveryStarted::new(
		context,
		entry,
		replay.latest_epoch,
		RecoveryStartEvidence {
			intent: intent_head,
			preceding: replay.boundary.head,
			authorization: evidence.authorization,
		},
	)
	.map_err(FinishError::Decision)?;
	let started = append(&mut journal, FrameKind::RecoveryStarted, &started.encode())?;
	let decision = RecoveryDecision::new(
		context,
		entry,
		started,
		PublishedRecoveryEvidence {
			target: stream.identity,
			destination_directory: parent,
			stage_directory: stage,
			verification: verification_head,
			stream,
			metadata: metadata_head,
		},
	)
	.map_err(FinishError::Decision)?;
	let _ = append(
		&mut journal,
		FrameKind::RecoveryDecision,
		&decision.encode(),
	)?;
	lease
		.sync_publication(names)
		.map_err(effect(RecoveryStep::Namespace))?;

	let observed_head = match replay.observation.map(|observation| observation.outcome()) {
		Some(PublicationOutcome::Published { .. }) => required(replay.observation_head)?,
		None | Some(PublicationOutcome::Uncertain { .. }) => {
			let observed = PublishObserved::new(
				intent,
				intent_head,
				PublicationOutcome::Published {
					target: stream.identity,
				},
			)
			.map_err(FinishError::Publication)?;
			append(&mut journal, FrameKind::PublishObserved, &observed.encode())?
		}
		Some(_) => return Err(FinishError::IncompleteEvidence),
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
		.map_err(FinishError::Publication)?;
		append(
			&mut journal,
			FrameKind::DurabilityRecorded,
			&record.encode(),
		)?
	};
	let receipt = CopyReceipt::from_evidence(
		ReceiptEvidence {
			context: JournalContext {
				epoch: intent.epoch,
				..evidence.plan.context()
			},
			entry,
			source: evidence.plan.source().file_identity,
			destination: evidence.plan.destination().root,
			target: evidence.plan.destination().component,
			stream,
		},
		durability,
	)
	.map_err(FinishError::Receipt)?;
	let committed = ReceiptCommitted::new(
		intent,
		ReceiptDigest::from_bytes(receipt.digest()),
		durability,
	)
	.map_err(FinishError::Publication)?;
	sync_receipt(lease, &receipt, evidence.receipt)?;
	lease
		.recheck_names(names)
		.map_err(effect(RecoveryStep::Namespace))?;
	let _ = append(
		&mut journal,
		FrameKind::ReceiptCommitted,
		&committed.encode(),
	)?;
	Ok(())
}

pub(super) fn sync_receipt<I, L: ReceiptLease>(
	lease: &L,
	receipt: &CopyReceipt<'_>,
	existing: Option<&L::ExistingReceipt>,
) -> Result<(), FinishError<I, L::EffectError>> {
	let directory = lease
		.open_receipt_directory()
		.map_err(effect(RecoveryStep::Receipt))?;
	if let Some(existing) = existing {
		directory
			.sync_receipt(existing)
			.map_err(effect(RecoveryStep::Receipt))?;
	} else {
		let mut file = directory
			.create_receipt()
			.map_err(effect(RecoveryStep::Receipt))?;
		file.write_all(&receipt.encode())
			.map_err(FinishError::WriteReceipt)?;
		file.sync_all().map_err(FinishError::WriteReceipt)?;
	}
	directory
		.sync_directory()
		.map_err(effect(RecoveryStep::Receipt))?;
	lease
		.sync_job_directory()
		.map_err(effect(RecoveryStep::Job))?;
	Ok(())
}

fn required<T, I, E>(value: Option<T>) -> Result<T, FinishError<I, E>> {
	value.ok_or(FinishError::IncompleteEvidence)
}

fn append<I, E>(
	journal: &mut impl FinishJournal,
	kind: FrameKind,
	payload: &[u8],
) -> Result<ChainHead, FinishError<I, E>> {
	journal
		.append(kind, payload)
		.map_err(|source| FinishError::Journal { kind, source })
}

fn effect<I, E>(step: RecoveryStep) -> impl FnOnce(E) -> FinishError<I, E> {
	move |source| FinishError::Effect { step, source }
}
