use std::io;

use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_publication::{
	ExclusivePublication, FreshReceiptError, FreshReceiptWorkspace, HeldFreshReceipt as _,
	PublicationFailure,
};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurabilityRecorded, DurableJournal, DurableJournalError, JournalContext,
	LinuxPublicationBarriers, NamespaceObservation, PublicationOutcome, PublicationPrimitive,
	PublicationRecordError, PublishIntent, PublishIntentContext, PublishIntentTarget,
	PublishObserved, ReceiptCommitted, ReceiptDigest, SyncedFrame,
};
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent, CopySession, PublishNoClobber};

use crate::linux_staging::{StageFailure, observe};

use super::super::{
	CopyCheckpoint, CopyReceipt, LocalCopyPlan, MAX_COPY_RECEIPT_BYTES, ReceiptError,
};
use super::records::SealEvidence;

#[derive(Debug)]
pub(in crate::linux) enum ProtocolError<R, S, P> {
	Journal {
		kind: FrameKind,
		source: DurableJournalError,
	},
	Model(StageFailure<R, S>),
	Record(PublicationRecordError),
	Publication {
		source: P,
		recording: Option<DurableJournalError>,
	},
	Receipt(ReceiptError),
	ReceiptNamespace(S),
	ReceiptIo(io::Error),
}

pub(in crate::linux) struct Publication<'plan, 'name> {
	pub(in crate::linux) context: JournalContext,
	pub(in crate::linux) plan: &'plan LocalCopyPlan<'name>,
	pub(in crate::linux) binding: CopyBinding,
	pub(in crate::linux) stage_directory: exacopy_journal::LinuxFileIdentity,
}

impl Publication<'_, '_> {
	pub(in crate::linux) fn intent_context(&self) -> PublishIntentContext {
		PublishIntentContext {
			job: self.context.job,
			epoch: self.context.epoch,
			entry: self.plan.attempt().entry,
			effect_sequence: 1,
			plan_digest: self.context.plan_digest,
		}
	}

	pub(in crate::linux) fn complete_with<R, S, P: ExclusivePublication>(
		&self,
		journal: &mut DurableJournal<impl JournalSegment>,
		session: &mut CopySession,
		stage: P,
		sealed: &SealEvidence,
		metadata: &SyncedFrame,
		checkpoint: fn(CopyCheckpoint),
	) -> Result<SyncedFrame, ProtocolError<R, S, P::Error>> {
		self.complete_using(journal, session, sealed, metadata, checkpoint, |permit| {
			stage.publish_no_clobber(permit)
		})
	}

	pub(super) fn complete_using<R, S, P>(
		&self,
		journal: &mut DurableJournal<impl JournalSegment>,
		session: &mut CopySession,
		sealed: &SealEvidence,
		metadata: &SyncedFrame,
		checkpoint: fn(CopyCheckpoint),
		publish: impl FnOnce(PublishNoClobber) -> Result<(), PublicationFailure<P>>,
	) -> Result<SyncedFrame, ProtocolError<R, S, P>> {
		let context = self.intent_context();
		let destination = self.plan.destination();
		let intent = PublishIntent {
			context,
			target: PublishIntentTarget {
				stage: sealed.verification.stage().identity,
				parent: destination.root.identity,
				component: destination.component,
				verification_digest: sealed.verification.record_digest(),
				primitive: PublicationPrimitive::LinuxRenameNoReplace,
			},
		};
		let synced = append(journal, FrameKind::PublishIntent, &intent.encode())?;
		checkpoint(if self.context.epoch == self.plan.context().epoch {
			CopyCheckpoint::IntentSynced
		} else {
			CopyCheckpoint::RangeResumeIntentSynced
		});
		let authorization = match session
			.apply(self.binding, CopyEvent::PublishIntentRecorded)
			.map_err(StageFailure::Model)
			.map_err(ProtocolError::Model)?
		{
			Some(CopyEffect::PublishNoClobber(authorization)) => authorization,
			_ => {
				return Err(ProtocolError::Model(StageFailure::UnexpectedEffect));
			}
		};
		if let Err(failure) = publish(authorization) {
			let (event, source) = match failure {
				PublicationFailure::Conflict(source) => (CopyEvent::Conflict, source),
				PublicationFailure::Uncertain(source) => (CopyEvent::OutcomeUncertain, source),
			};
			observe(session, self.binding, event).map_err(ProtocolError::Model)?;
			let observation = PublishObserved::new(
				context,
				synced.head(),
				PublicationOutcome::Uncertain {
					target: NamespaceObservation::Unobserved,
					stage_name: NamespaceObservation::Unobserved,
				},
			)
			.map_err(ProtocolError::Record)?;
			let recording = journal
				.append(FrameKind::PublishObserved, &observation.encode())
				.err();
			return Err(ProtocolError::Publication { source, recording });
		}
		checkpoint(CopyCheckpoint::RenamedAndSynced);

		let observation = PublishObserved::new(
			context,
			synced.head(),
			PublicationOutcome::Published {
				target: intent.target.stage,
			},
		)
		.map_err(ProtocolError::Record)?;
		let observed = append(journal, FrameKind::PublishObserved, &observation.encode())?;
		observe(session, self.binding, CopyEvent::Published).map_err(ProtocolError::Model)?;
		let durability = DurabilityRecorded::new(
			context,
			observed.head(),
			LinuxPublicationBarriers {
				metadata: metadata.head(),
				stage_directory: self.stage_directory,
				destination_directory: destination.root.identity,
			},
		)
		.map_err(ProtocolError::Record)?;
		let durable = append(journal, FrameKind::DurabilityRecorded, &durability.encode())?;
		observe(session, self.binding, CopyEvent::DirectoryFlushed)
			.map_err(ProtocolError::Model)?;
		Ok(durable)
	}
}

pub(super) fn persist_receipt<R, P, J: FreshReceiptWorkspace>(
	job: &J,
	journal: &mut DurableJournal<impl JournalSegment>,
	context: PublishIntentContext,
	receipt: &CopyReceipt<'_>,
	durability: &SyncedFrame,
	checkpoint: fn(CopyCheckpoint),
) -> Result<(), ProtocolError<R, J::Error, P>> {
	let exact = receipt.encode();
	let held = job
		.seal_fresh_receipt(&exact)
		.map_err(|error| match error {
			FreshReceiptError::Namespace(error) => ProtocolError::ReceiptNamespace(error),
			FreshReceiptError::Io(error) => ProtocolError::ReceiptIo(error),
			_ => ProtocolError::ReceiptIo(io::Error::other("unrecognized fresh receipt failure")),
		})?;
	checkpoint(CopyCheckpoint::ReceiptSynced);

	let mut bytes = [0; MAX_COPY_RECEIPT_BYTES];
	let observed = &mut bytes[..exact.len()];
	held.read_exact_receipt(observed)
		.map_err(ProtocolError::ReceiptNamespace)?;
	if observed[..] != exact[..] {
		return Err(ProtocolError::ReceiptIo(io::Error::new(
			io::ErrorKind::InvalidData,
			"receipt read-back differs from the canonical copy receipt",
		)));
	}
	let decoded = CopyReceipt::decode(observed).map_err(ProtocolError::Receipt)?;
	let committed = ReceiptCommitted::new(
		context,
		ReceiptDigest::from_bytes(decoded.digest()),
		durability.head(),
	)
	.map_err(ProtocolError::Record)?;
	let _ = append(journal, FrameKind::ReceiptCommitted, &committed.encode())?;
	checkpoint(CopyCheckpoint::ReceiptCommitted);
	held.read_exact_receipt(observed)
		.map_err(ProtocolError::ReceiptNamespace)?;
	if observed[..] != exact[..] {
		return Err(ProtocolError::ReceiptIo(io::Error::new(
			io::ErrorKind::InvalidData,
			"committed receipt read-back differs from the canonical copy receipt",
		)));
	}
	Ok(())
}

fn append<R, S, P>(
	journal: &mut DurableJournal<impl JournalSegment>,
	kind: FrameKind,
	payload: &[u8],
) -> Result<SyncedFrame, ProtocolError<R, S, P>> {
	journal
		.append(kind, payload)
		.map_err(|source| ProtocolError::Journal { kind, source })
}
