use std::num::NonZeroU64;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinFileIdentity, DarwinMetadataRecorded,
	DarwinNamespaceObservation, DarwinPhaseError, DarwinPublicationNames, DarwinPublicationOutcome,
	DarwinPublishIntent, DarwinPublishObserved, DarwinReceiptCommitted, DarwinStageSealed,
	DarwinStreamEvidence, DarwinVerificationRecorded, JournalFileBarrier, StreamLength,
	SyncedFrame,
};
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent, CopySession, PublishNoClobber};

use crate::macos::plan::DarwinCopyPlan;
use crate::macos::receipt::{DarwinCopyReceipt, DarwinReceiptFrames};

use super::capabilities::{
	FailedEffect, PreparedCopy, PublicationJournal, PublishedEvidence, ReceiptStore, VerifiedCopy,
	VerifiedStreams,
};
use super::{DarwinCopyFailure, PublicationProgress};

pub(super) struct PreparedEvidence<'frame, 'name> {
	pub(super) frame: &'frame Frame,
	pub(super) source: DarwinFileIdentity,
	pub(super) plan: &'frame DarwinCopyPlan<'name>,
}

pub(super) fn execute<'entry>(
	prepared: PreparedEvidence<'_, 'entry>,
	copy: impl PreparedCopy,
	journal: &mut impl PublicationJournal,
	receipts: &impl ReceiptStore,
	scratch: &mut [u8],
	progress: &mut PublicationProgress,
) -> Result<DarwinCopyReceipt<'entry>, DarwinCopyFailure> {
	let binding = copy.binding();
	let mut session = CopySession::new(binding);
	match session
		.apply(binding, CopyEvent::StagePrepared)
		.map_err(DarwinCopyFailure::Model)?
	{
		Some(CopyEffect::ReadSource(read)) if read.binding() == binding => {}
		_ => return Err(DarwinCopyFailure::UnexpectedEffect),
	}
	copy.check_source_before_read()?;
	let verified = copy.verify(scratch)?;
	for event in [
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		observe(&mut session, binding, event)?;
	}

	let phases = VerifiedPhases::new(prepared.frame, prepared.source, &verified)?;
	let metadata_frame = phases.record(journal)?;
	verified.check_source_after_metadata()?;
	let intent = DarwinPublishIntent::new(
		NonZeroU64::MIN,
		prepared.frame,
		&phases.seal,
		&phases.verification,
		&phases.metadata,
	)?;
	let (intent_frame, authorization) =
		authorize(journal, &mut session, binding, intent, progress)?;

	let published = match verified.publish_exclusively(authorization) {
		Ok(published) => published,
		Err(error) => {
			let (outcome, event) = error.effect.classify(progress);
			let recording = observe(&mut session, binding, event)
				.and_then(|()| {
					record_observation(journal, &intent_frame, outcome, error.effect.names()?)
						.map(|_| ())
				})
				.err()
				.map(Box::new);
			return Err(DarwinCopyFailure::Publish {
				error: error.cause,
				recording,
			});
		}
	};
	*progress = PublicationProgress::Renamed;
	let (observed, durability, synced) = record_success(
		journal,
		&metadata_frame,
		&intent_frame,
		published,
		&mut session,
		binding,
	)?;
	let receipt = DarwinCopyReceipt::from_synced_durability(
		prepared.plan,
		DarwinReceiptFrames {
			verification: &metadata_frame.verification,
			metadata: &metadata_frame.metadata,
			intent: &intent_frame,
			observed: &observed,
			durability: &durability,
		},
		&synced,
	)
	.map_err(DarwinCopyFailure::Receipt)?;
	receipts.persist(&receipt.encode())?;
	let committed = DarwinReceiptCommitted::new(&durability, receipt.digest())?;
	let _ = append_frame(journal, FrameKind::ReceiptCommitted, committed.encode())?;
	*progress = PublicationProgress::ReceiptCommitted;
	observe(&mut session, binding, CopyEvent::ReceiptRecorded)?;
	Ok(receipt)
}

struct VerifiedPhases {
	seal: DarwinStageSealed,
	verification: DarwinVerificationRecorded,
	metadata: DarwinMetadataRecorded,
}

struct VerifiedFrames {
	verification: Frame,
	metadata: Frame,
}

impl VerifiedPhases {
	fn new(
		prepared: &Frame,
		source: DarwinFileIdentity,
		verified: &impl VerifiedCopy,
	) -> Result<Self, DarwinCopyFailure> {
		let VerifiedStreams {
			stage,
			length,
			source_digest,
			stage_digest,
		} = verified.observe_streams()?;
		let length = StreamLength::new(length).map_err(|_| DarwinPhaseError::StreamMismatch)?;
		let seal = DarwinStageSealed::new(prepared, stage, length)?;
		let verification = DarwinVerificationRecorded::new(
			prepared,
			&seal,
			DarwinStreamEvidence {
				identity: source,
				length,
				digest: source_digest,
			},
			DarwinStreamEvidence {
				identity: stage,
				length,
				digest: stage_digest,
			},
		)?;
		let observed = verified.required_metadata()?;
		let metadata =
			DarwinMetadataRecorded::new(prepared, &seal, &verification, stage, observed)?;
		Ok(Self {
			seal,
			verification,
			metadata,
		})
	}

	fn record(
		&self,
		journal: &mut impl PublicationJournal,
	) -> Result<VerifiedFrames, DarwinCopyFailure> {
		let _ = append_frame(journal, FrameKind::StageSealed, self.seal.encode())?;
		let (verification, _) = append_frame(
			journal,
			FrameKind::VerificationRecorded,
			self.verification.encode(),
		)?;
		let (metadata, _) =
			append_frame(journal, FrameKind::MetadataRecorded, self.metadata.encode())?;
		Ok(VerifiedFrames {
			verification,
			metadata,
		})
	}
}

fn observe(
	session: &mut CopySession,
	binding: CopyBinding,
	event: CopyEvent,
) -> Result<(), DarwinCopyFailure> {
	if session
		.apply(binding, event)
		.map_err(DarwinCopyFailure::Model)?
		.is_some()
	{
		return Err(DarwinCopyFailure::UnexpectedEffect);
	}
	Ok(())
}

fn authorize(
	journal: &mut impl PublicationJournal,
	session: &mut CopySession,
	binding: CopyBinding,
	intent: DarwinPublishIntent<'_>,
	progress: &mut PublicationProgress,
) -> Result<(Frame, PublishNoClobber), DarwinCopyFailure> {
	let (frame, synced) = append_frame(journal, FrameKind::PublishIntent, intent.encode())?;
	if synced.kind() != FrameKind::PublishIntent
		|| synced.head() != frame.head()
		|| synced.barrier() != JournalFileBarrier::DarwinFullFsync
	{
		return Err(DarwinCopyFailure::UnexpectedBarrier);
	}
	if DarwinPublishIntent::from_frame(&frame)? != intent {
		return Err(DarwinPhaseError::BindingMismatch.into());
	}
	*progress = PublicationProgress::IntentSynchronized;
	let effect = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.map_err(DarwinCopyFailure::Model)?;
	let Some(CopyEffect::PublishNoClobber(authorization)) = effect else {
		return Err(DarwinCopyFailure::UnexpectedEffect);
	};
	Ok((frame, authorization))
}

impl FailedEffect {
	fn classify(
		&self,
		progress: &mut PublicationProgress,
	) -> (DarwinPublicationOutcome, CopyEvent) {
		let outcome = match self {
			Self::Rejected => DarwinPublicationOutcome::RejectedBeforeRename,
			Self::Conflict => return (DarwinPublicationOutcome::Conflict, CopyEvent::Conflict),
			Self::Uncertain => DarwinPublicationOutcome::UncertainRename,
			Self::Renamed { .. } => {
				*progress = PublicationProgress::Renamed;
				DarwinPublicationOutcome::RenameConfirmedIncomplete
			}
		};
		(outcome, CopyEvent::OutcomeUncertain)
	}

	fn names(self) -> Result<DarwinPublicationNames, DarwinCopyFailure> {
		if let Self::Renamed {
			target: Some(target),
		} = self
		{
			return Ok(DarwinPublicationNames {
				target: DarwinNamespaceObservation::Present(
					target.map_err(DarwinCopyFailure::Observation)?,
				),
				stage: DarwinNamespaceObservation::Absent,
			});
		}
		Ok(DarwinPublicationNames {
			target: DarwinNamespaceObservation::Unobserved,
			stage: DarwinNamespaceObservation::Unobserved,
		})
	}
}

fn record_observation(
	journal: &mut impl PublicationJournal,
	intent: &Frame,
	outcome: DarwinPublicationOutcome,
	names: DarwinPublicationNames,
) -> Result<Frame, DarwinCopyFailure> {
	let observed = DarwinPublishObserved::new(intent, outcome, names)?;
	let (frame, _) = append_frame(journal, FrameKind::PublishObserved, observed.encode())?;
	Ok(frame)
}

fn record_success(
	journal: &mut impl PublicationJournal,
	frames: &VerifiedFrames,
	intent: &Frame,
	published: PublishedEvidence,
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(Frame, Frame, SyncedFrame), DarwinCopyFailure> {
	let target = published.target.map_err(DarwinCopyFailure::Observation)?;
	let observed = record_observation(
		journal,
		intent,
		DarwinPublicationOutcome::Published,
		DarwinPublicationNames {
			target: DarwinNamespaceObservation::Present(target),
			stage: DarwinNamespaceObservation::Absent,
		},
	)?;
	observe(session, binding, CopyEvent::Published)?;
	let durability = DarwinDurabilityRecorded::new(
		&frames.metadata,
		intent,
		&observed,
		published.barriers.map_err(DarwinCopyFailure::Observation)?,
	)?;
	let (durability, synced) =
		append_frame(journal, FrameKind::DurabilityRecorded, durability.encode())?;
	observe(session, binding, CopyEvent::DirectoryFlushed)?;
	Ok((observed, durability, synced))
}

fn append_frame(
	journal: &mut impl PublicationJournal,
	kind: FrameKind,
	payload: Vec<u8>,
) -> Result<(Frame, SyncedFrame), DarwinCopyFailure> {
	journal
		.append(kind, payload)
		.map_err(|error| DarwinCopyFailure::Journal { kind, error })
}
