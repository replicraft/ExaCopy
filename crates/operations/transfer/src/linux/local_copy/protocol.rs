use std::io::{self, Write as _};

use exacopy_endpoint::linux_publication::{
	ExclusivePublication, PublicationFailure, ReceiptDirectory as _, ReceiptRecord as _,
	ReceiptWorkspace,
};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurabilityRecorded, DurableJournal, DurableJournalError, JournalContext,
	LinuxPublicationBarriers, NamespaceObservation, PublicationOutcome, PublicationPrimitive,
	PublicationRecordError, PublishIntent, PublishIntentContext, PublishIntentTarget,
	PublishObserved, ReceiptCommitted, ReceiptDigest, SyncedFrame,
};
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent, CopySession};

use crate::linux_staging::{StageFailure, observe};

use super::super::{CopyReceipt, LocalCopyPlan};
use super::records::SealEvidence;

#[derive(Debug)]
pub(super) enum ProtocolError<R, S, P> {
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

	pub(super) fn complete_with<R, S, P: ExclusivePublication>(
		&self,
		journal: &mut DurableJournal,
		session: &mut CopySession,
		stage: P,
		sealed: &SealEvidence,
		metadata: &SyncedFrame,
	) -> Result<SyncedFrame, ProtocolError<R, S, P::Error>> {
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
		#[cfg(test)]
		super::crash_tests::pause_at(if self.context.epoch == self.plan.context().epoch {
			super::crash_tests::Checkpoint::IntentSynced
		} else {
			super::crash_tests::Checkpoint::RangeResumeIntentSynced
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
		if let Err(failure) = stage.publish_no_clobber(authorization) {
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
		#[cfg(test)]
		super::crash_tests::pause_at(super::crash_tests::Checkpoint::RenamedAndSynced);

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

pub(super) fn persist_receipt<'job, R, P, J: ReceiptWorkspace<'job>>(
	job: &'job J,
	journal: &mut DurableJournal,
	context: PublishIntentContext,
	receipt: &CopyReceipt<'_>,
	durability: &SyncedFrame,
) -> Result<(), ProtocolError<R, J::Error, P>> {
	let committed = ReceiptCommitted::new(
		context,
		ReceiptDigest::from_bytes(receipt.digest()),
		durability.head(),
	)
	.map_err(ProtocolError::Record)?;
	let receipts = job
		.create_receipt_directory()
		.map_err(ProtocolError::ReceiptNamespace)?;
	let mut artifact = receipts
		.create_receipt_record()
		.map_err(ProtocolError::ReceiptNamespace)?;
	artifact
		.write_all(&receipt.encode())
		.map_err(ProtocolError::ReceiptIo)?;
	artifact.sync_all().map_err(ProtocolError::ReceiptIo)?;
	drop(artifact);
	receipts
		.sync_directory()
		.map_err(ProtocolError::ReceiptNamespace)?;
	job.sync_directory()
		.map_err(ProtocolError::ReceiptNamespace)?;
	#[cfg(test)]
	super::crash_tests::pause_at(super::crash_tests::Checkpoint::ReceiptSynced);
	let _ = append(journal, FrameKind::ReceiptCommitted, &committed.encode())?;
	#[cfg(test)]
	super::crash_tests::pause_at(super::crash_tests::Checkpoint::ReceiptCommitted);
	Ok(())
}

fn append<R, S, P>(
	journal: &mut DurableJournal,
	kind: FrameKind,
	payload: &[u8],
) -> Result<SyncedFrame, ProtocolError<R, S, P>> {
	journal
		.append(kind, payload)
		.map_err(|source| ProtocolError::Journal { kind, source })
}
