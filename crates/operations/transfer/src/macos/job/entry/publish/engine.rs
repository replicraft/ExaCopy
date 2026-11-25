use std::num::NonZeroU64;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinFileIdentity, DarwinMetadataRecorded,
	DarwinNamespaceObservation, DarwinPhaseError, DarwinPublicationNames, DarwinPublicationOutcome,
	DarwinPublishIntent, DarwinPublishObserved, DarwinReceiptCommitted, DarwinStageSealed,
	DarwinStreamEvidence, DarwinVerificationRecorded, DurableJournalError, JournalFileBarrier,
	OwnerError, StreamLength, SyncedFrame,
};
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, PublishNoClobber, TransitionError,
};

use crate::macos::plan::DarwinCopyPlan;
use crate::macos::receipt::{DarwinCopyReceipt, DarwinCopyReceiptError, DarwinReceiptFrames};

use super::capabilities::{
	FailedEffect, PreparedCopy, PublicationJournal, PublishedEvidence, ReceiptStore, VerifiedCopy,
	VerifiedStreams,
};

/// The last established namespace boundary of the managed APFS copy.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicationProgress {
	/// The coordinator has only operated on the private job.
	Private,
	/// Intent passed its barrier. Recovery must resolve any unobserved namespace effect.
	IntentSynchronized,
	/// Exclusive rename is known to have succeeded.
	Renamed,
	/// The receipt file and exact journal commitment passed their barriers.
	ReceiptCommitted,
}

/// The exact entry preparation and plan bound to a single stage publication.
#[derive(Debug)]
pub struct PreparedEvidence<'frame, 'name> {
	/// The synchronized envelope for the entry preparation.
	pub frame: &'frame Frame,
	/// The source identity recorded by that envelope.
	pub source: DarwinFileIdentity,
	/// The admitted plan supplying the receipt binding.
	pub plan: &'frame DarwinCopyPlan<'name>,
}

#[derive(Debug)]
/// An adapter or coordinator failure with any established publication evidence.
pub enum CopyFailure<A, P, R> {
	/// An adapter check or operation failed.
	Adapter(A),
	/// The coordinator could not establish a required observation or decision.
	Coordinator(CoordinatorError),
	/// Native publication failed or left incomplete evidence.
	Publish {
		/// The original publication failure.
		error: P,
		/// An additional failure while recording the observed namespace outcome.
		recording: Option<Box<CoordinatorError>>,
	},
	/// A publication receipt could not be persisted.
	PersistReceipt(R),
}

#[derive(Debug)]
/// A failed decision, record binding, or journal barrier during publication.
pub enum CoordinatorError {
	/// An observation is outside the journal's representation.
	Observation(OwnerError),
	/// A journal record could not bind to its prerequisites.
	Record(DarwinPhaseError),
	/// The model refused a coordinator event.
	Model(TransitionError),
	/// The model returned an effect inconsistent with the current phase.
	UnexpectedEffect,
	/// The append evidence did not establish the exact Darwin full-sync intent.
	UnexpectedBarrier,
	/// Writing or synchronizing the requested frame failed.
	Journal {
		/// The kind of frame the coordinator attempted to append.
		kind: FrameKind,
		/// The exact journal failure.
		error: DurableJournalError,
	},
	/// The receipt could not bind to the plan and synchronized history.
	Receipt(DarwinCopyReceiptError),
}

impl From<DarwinPhaseError> for CoordinatorError {
	fn from(error: DarwinPhaseError) -> Self {
		Self::Record(error)
	}
}

impl<A, P, R> From<CoordinatorError> for CopyFailure<A, P, R> {
	fn from(error: CoordinatorError) -> Self {
		Self::Coordinator(error)
	}
}

type ExecutionError<C, R> = CopyFailure<
	<C as PreparedCopy>::Error,
	<C as PreparedCopy>::PublishError,
	<R as ReceiptStore>::Error,
>;

/// Verifies the stage, records exclusive publication intent, and commits the receipt.
///
/// Use the bound writer, entry frame, and journal from the same admitted private job.
/// The adapter retains the directory leases and reports the observed namespace effect.
///
/// # Errors
/// Reports adapter, binding, and barrier failures, retaining any known namespace effect.
pub fn execute<'entry, C: PreparedCopy, R: ReceiptStore>(
	prepared: PreparedEvidence<'_, 'entry>,
	copy: C,
	journal: &mut impl PublicationJournal,
	receipts: &R,
	scratch: &mut [u8],
	progress: &mut PublicationProgress,
) -> Result<DarwinCopyReceipt<'entry>, ExecutionError<C, R>> {
	let binding = copy.binding();
	let mut session = CopySession::new(binding);
	match session
		.apply(binding, CopyEvent::StagePrepared)
		.map_err(CoordinatorError::Model)?
	{
		Some(CopyEffect::ReadSource(read)) if read.binding() == binding => {}
		_ => return Err(CoordinatorError::UnexpectedEffect.into()),
	}
	copy.check_source_before_read()
		.map_err(CopyFailure::Adapter)?;
	let verified = copy.verify(scratch).map_err(CopyFailure::Adapter)?;
	for event in [
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		observe(&mut session, binding, event)?;
	}

	let phases = verified_phases::<_, R::Error>(prepared.frame, prepared.source, &verified)?;
	let metadata_frame = phases.record(journal)?;
	verified
		.check_source_after_metadata()
		.map_err(CopyFailure::Adapter)?;
	let intent = DarwinPublishIntent::new(
		NonZeroU64::MIN,
		prepared.frame,
		&phases.seal,
		&phases.verification,
		&phases.metadata,
	)
	.map_err(CoordinatorError::Record)?;
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
			return Err(CopyFailure::Publish {
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
	.map_err(CoordinatorError::Receipt)?;
	receipts
		.persist(&receipt.encode())
		.map_err(CopyFailure::PersistReceipt)?;
	let committed = DarwinReceiptCommitted::new(&durability, receipt.digest())
		.map_err(CoordinatorError::Record)?;
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

type VerificationError<V, R> =
	CopyFailure<<V as VerifiedCopy>::Error, <V as VerifiedCopy>::PublishError, R>;

fn verified_phases<V: VerifiedCopy, R>(
	prepared: &Frame,
	source: DarwinFileIdentity,
	verified: &V,
) -> Result<VerifiedPhases, VerificationError<V, R>> {
	let VerifiedStreams {
		stage,
		length,
		source_digest,
		stage_digest,
	} = verified.observe_streams().map_err(CopyFailure::Adapter)?;
	let length = StreamLength::new(length)
		.map_err(|_| CoordinatorError::Record(DarwinPhaseError::StreamMismatch))?;
	let seal = DarwinStageSealed::new(prepared, stage, length).map_err(CoordinatorError::Record)?;
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
	)
	.map_err(CoordinatorError::Record)?;
	let observed = verified.required_metadata().map_err(CopyFailure::Adapter)?;
	let metadata = DarwinMetadataRecorded::new(prepared, &seal, &verification, stage, observed)
		.map_err(CoordinatorError::Record)?;
	Ok(VerifiedPhases {
		seal,
		verification,
		metadata,
	})
}

impl VerifiedPhases {
	fn record(
		&self,
		journal: &mut impl PublicationJournal,
	) -> Result<VerifiedFrames, CoordinatorError> {
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
) -> Result<(), CoordinatorError> {
	if session
		.apply(binding, event)
		.map_err(CoordinatorError::Model)?
		.is_some()
	{
		return Err(CoordinatorError::UnexpectedEffect);
	}
	Ok(())
}

fn authorize(
	journal: &mut impl PublicationJournal,
	session: &mut CopySession,
	binding: CopyBinding,
	intent: DarwinPublishIntent<'_>,
	progress: &mut PublicationProgress,
) -> Result<(Frame, PublishNoClobber), CoordinatorError> {
	let (frame, synced) = append_frame(journal, FrameKind::PublishIntent, intent.encode())?;
	if synced.kind() != FrameKind::PublishIntent
		|| synced.head() != frame.head()
		|| synced.barrier() != JournalFileBarrier::DarwinFullFsync
	{
		return Err(CoordinatorError::UnexpectedBarrier);
	}
	if DarwinPublishIntent::from_frame(&frame)? != intent {
		return Err(DarwinPhaseError::BindingMismatch.into());
	}
	*progress = PublicationProgress::IntentSynchronized;
	let effect = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.map_err(CoordinatorError::Model)?;
	let Some(CopyEffect::PublishNoClobber(authorization)) = effect else {
		return Err(CoordinatorError::UnexpectedEffect);
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

	fn names(self) -> Result<DarwinPublicationNames, CoordinatorError> {
		if let Self::Renamed {
			target: Some(target),
		} = self
		{
			return Ok(DarwinPublicationNames {
				target: DarwinNamespaceObservation::Present(
					target.map_err(CoordinatorError::Observation)?,
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
) -> Result<Frame, CoordinatorError> {
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
) -> Result<(Frame, Frame, SyncedFrame), CoordinatorError> {
	let target = published.target.map_err(CoordinatorError::Observation)?;
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
		published.barriers.map_err(CoordinatorError::Observation)?,
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
) -> Result<(Frame, SyncedFrame), CoordinatorError> {
	journal
		.append(kind, payload)
		.map_err(|error| CoordinatorError::Journal { kind, error })
}
