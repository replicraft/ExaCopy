use exacopy_content::{MeasureError, measure_at};
use exacopy_endpoint::ReadView;
use exacopy_endpoint::linux_publication::{ExclusivePublication, PublicationFailure};
use exacopy_endpoint::linux_staging::StagingSource;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	DurableJournalError, JournalContext, JournalEpoch, LinuxFileIdentity, MetadataRecorded,
	OwnerDigest, PublicationOutcome, PublicationPrimitive, PublicationRecordError, PublishIntent,
	PublishIntentContext, PublishIntentTarget, PublishObserved, RecoveryDirectories,
	RecoveryRecordError, RecoveryStartEvidence, RecoveryStarted, RetainedPublicationDecision,
	RetainedPublicationEvidence, StreamEvidence, VerificationRecordError, VerificationRecorded,
};
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId,
};

use crate::linux::{JournalBoundary, JournalReplay, LocalCopyPlan, RecoveryIssue};
use crate::linux_staging::{StageFailure, check_source, observe};

#[cfg(test)]
mod tests;

pub(super) struct RetryHistory<'plan, 'name> {
	pub(super) plan: &'plan LocalCopyPlan<'name>,
	pub(super) journal: &'plan JournalReplay,
	pub(super) owner: OwnerDigest,
}

#[derive(Clone, Copy)]
pub(super) struct RetainedIdentity {
	pub(super) file: LinuxFileIdentity,
	pub(super) directory: LinuxFileIdentity,
}

/// Retry authority tied to an inventoried stage under an exclusive recovery lease.
pub(super) trait RetainedStage {
	type NamespaceError;
	type ReadBackError;
	type PublishError;
	type Publisher<'lease>: ExclusivePublication<Error = Self::PublishError>
	where
		Self: 'lease;

	fn identity(&self) -> RetainedIdentity;

	/// Establishes writer exclusion, a file barrier, and one publication capability.
	fn flush(&self, binding: CopyBinding) -> Result<Self::Publisher<'_>, Self::NamespaceError>;

	/// Independently rereads the held stage and checks required metadata apart from atime.
	fn verify_readback(
		&self,
		stream: StreamEvidence,
		metadata: MetadataRecorded,
		scratch: &mut [u8],
	) -> Result<Option<RecoveryIssue>, Self::ReadBackError>;

	fn accessed_at(&self) -> (i64, u32);

	/// Confirms the inventoried stage and namespace still match the leased observations.
	fn recheck_namespace(&self) -> Result<(), Self::NamespaceError>;
}

/// Exclusive appender reopened at the accepted prefix, returning a head after each barrier.
pub(super) trait RetryJournal {
	fn append_synced(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<ChainHead, DurableJournalError>;
}

#[derive(Debug)]
pub(super) enum JournalOpenError<S> {
	Namespace(S),
	Resume(DurableJournalError),
}

#[derive(Debug)]
pub(super) enum RetryError<R, S, I, P> {
	IncompleteEvidence,
	EpochExhausted,
	EffectSequenceExhausted,
	SourceMismatch,
	SourcePolicy(StageFailure<R, S>),
	MeasureSource(MeasureError<R>),
	Stage(RecoveryIssue),
	ReadBack(I),
	Model(StageFailure<R, S>),
	Namespace(S),
	Verification(VerificationRecordError),
	Decision(RecoveryRecordError),
	Publication(PublicationRecordError),
	OpenJournal(JournalOpenError<S>),
	Append {
		kind: FrameKind,
		source: DurableJournalError,
	},
	Publish(P),
}

type Failure<R, S> = RetryError<
	<R as ReadView>::Error,
	<S as RetainedStage>::NamespaceError,
	<S as RetainedStage>::ReadBackError,
	<S as RetainedStage>::PublishError,
>;

pub(super) fn publish<R: StagingSource, S: RetainedStage, J: RetryJournal>(
	history: RetryHistory<'_, '_>,
	source: &R,
	stage: &S,
	open_journal: impl FnOnce(JournalBoundary) -> Result<J, JournalOpenError<S::NamespaceError>>,
	scratch: &mut [u8],
) -> Result<(), Failure<R, S>> {
	let journal = history.journal;
	let identity = stage.identity();
	let prior_intent = journal.intent_head.ok_or(RetryError::IncompleteEvidence)?;
	let measurements = journal.verification.ok_or(RetryError::IncompleteEvidence)?;
	let mut metadata = journal.metadata.ok_or(RetryError::IncompleteEvidence)?;
	if journal.stage != Some(identity.file)
		|| measurements.stage().identity != identity.file
		|| metadata.stage != identity.file
	{
		return Err(RetryError::Stage(RecoveryIssue::UnrecognizedStage));
	}
	if journal
		.recovery_stage_directory
		.is_some_and(|known| known != identity.directory)
	{
		return Err(RetryError::Stage(RecoveryIssue::StageDirectoryBinding));
	}
	let epoch = journal
		.latest_epoch
		.get()
		.checked_add(1)
		.map(JournalEpoch::new)
		.ok_or(RetryError::EpochExhausted)?;
	let effect_sequence = journal
		.last_effect_sequence
		.checked_add(1)
		.ok_or(RetryError::EffectSequenceExhausted)?;
	let context = JournalContext {
		epoch,
		..history.plan.context()
	};
	let entry = history.plan.attempt().entry;
	let binding = CopyBinding::new(
		JobId::try_from_bytes(*context.job.as_bytes())
			.map_err(|_| RetryError::IncompleteEvidence)?,
		EntryId::new(1),
		RunEpoch::new(epoch.get()),
		StageId::from_bytes(*entry.as_bytes()),
	);
	let mut session = CopySession::new(binding);
	observe(&mut session, binding, CopyEvent::RetainedStageReopened).map_err(RetryError::Model)?;
	observe(&mut session, binding, CopyEvent::WritersJoined).map_err(RetryError::Model)?;
	let publisher = stage.flush(binding).map_err(RetryError::Namespace)?;
	observe(&mut session, binding, CopyEvent::DataFlushed).map_err(RetryError::Model)?;

	let digest = measure_at(source.length(), scratch, |offset, buffer| {
		source.read_exact_at(offset, buffer)
	})
	.map_err(RetryError::MeasureSource)?;
	if digest.as_bytes() != measurements.source().digest.as_bytes() {
		return Err(RetryError::SourceMismatch);
	}
	if let Some(issue) = stage
		.verify_readback(measurements.stage(), metadata, scratch)
		.map_err(RetryError::ReadBack)?
	{
		return Err(RetryError::Stage(issue));
	}
	let atime = metadata.metadata.accessed_at;
	if stage.accessed_at() != (atime.seconds(), atime.nanoseconds()) {
		return Err(RetryError::Stage(RecoveryIssue::MetadataMismatch));
	}
	for event in [
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		observe(&mut session, binding, event).map_err(RetryError::Model)?;
	}
	check_source(source).map_err(RetryError::SourcePolicy)?;
	stage.recheck_namespace().map_err(RetryError::Namespace)?;

	let fresh =
		VerificationRecorded::new(context, entry, measurements.source(), measurements.stage())
			.map_err(RetryError::Verification)?;
	metadata.context = context;
	let mut writer = open_journal(journal.boundary).map_err(RetryError::OpenJournal)?;
	let started = RecoveryStarted::new(
		context,
		entry,
		journal.latest_epoch,
		RecoveryStartEvidence {
			intent: prior_intent,
			preceding: journal.boundary.head,
			authorization: history.owner,
		},
	)
	.map_err(RetryError::Decision)?;
	let start = append(&mut writer, FrameKind::RecoveryStarted, &started.encode())?;
	let verification = append(
		&mut writer,
		FrameKind::VerificationRecorded,
		&fresh.encode(),
	)?;
	let metadata = append(&mut writer, FrameKind::MetadataRecorded, &metadata.encode())?;
	let destination = history.plan.destination();
	let decision = RetainedPublicationDecision::new(
		context,
		entry,
		start,
		RetainedPublicationEvidence {
			stage: identity.file,
			directories: RecoveryDirectories {
				stage: identity.directory,
				destination: destination.root.identity,
			},
			verification,
			metadata,
		},
		effect_sequence,
	)
	.map_err(RetryError::Decision)?;
	let _ = append(&mut writer, FrameKind::RecoveryDecision, &decision.encode())?;
	let effect = PublishIntentContext {
		job: context.job,
		epoch,
		entry,
		effect_sequence,
		plan_digest: context.plan_digest,
	};
	let intent = PublishIntent {
		context: effect,
		target: PublishIntentTarget {
			stage: identity.file,
			parent: destination.root.identity,
			component: destination.component,
			verification_digest: fresh.record_digest(),
			primitive: PublicationPrimitive::LinuxRenameNoReplace,
		},
	};
	let intent = append(&mut writer, FrameKind::PublishIntent, &intent.encode())?;
	check_source(source).map_err(RetryError::SourcePolicy)?;
	let Some(CopyEffect::PublishNoClobber(authorization)) = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.map_err(StageFailure::from)
		.map_err(RetryError::Model)?
	else {
		return Err(RetryError::Model(StageFailure::UnexpectedEffect));
	};
	publisher
		.publish_no_clobber(authorization)
		.map_err(|failure| match failure {
			PublicationFailure::Conflict(cause) | PublicationFailure::Uncertain(cause) => {
				RetryError::Publish(cause)
			}
		})?;
	let observed = PublishObserved::new(
		effect,
		intent,
		PublicationOutcome::Published {
			target: identity.file,
		},
	)
	.map_err(RetryError::Publication)?;
	let _ = append(&mut writer, FrameKind::PublishObserved, &observed.encode())?;
	Ok(())
}

fn append<R, S, I, P>(
	journal: &mut impl RetryJournal,
	kind: FrameKind,
	payload: &[u8],
) -> Result<ChainHead, RetryError<R, S, I, P>> {
	journal
		.append_synced(kind, payload)
		.map_err(|source| RetryError::Append { kind, source })
}
