use exacopy_endpoint::linux_publication::{ExclusivePublication, PublicationFailure};
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{DurableJournal, DurableJournalError, MetadataRecorded, StreamEvidence};
use exacopy_model::{CopyBinding, PublishNoClobber};
use exacopy_platform::linux::{
	PublishError, ReadError, RecoveryFile, RecoveryInventory, RecoveryWriteLease,
	RetainedStage as PlatformStage, StageError,
};

#[cfg(test)]
use crate::linux::local_copy::crash_tests::{Checkpoint, pause_at};
use crate::linux::{JournalBoundary, RecoveryFinishError, RecoveryInspectError, RecoveryIssue};

use super::super::finish::completion;
use super::super::{RecoveryStep, native_identity, verify};
use super::RecoveryRetryError;
use super::engine::{JournalOpenError, RetainedIdentity, RetainedStage, RetryError, RetryJournal};

pub(super) struct NativeRetainedStage<'lease> {
	lease: &'lease RecoveryWriteLease<'lease>,
	names: &'lease RecoveryInventory<'lease>,
	file: &'lease RecoveryFile,
	identity: RetainedIdentity,
}

impl<'lease> NativeRetainedStage<'lease> {
	pub(super) fn new(
		lease: &'lease RecoveryWriteLease<'lease>,
		names: &'lease RecoveryInventory<'lease>,
	) -> Result<Self, RecoveryFinishError> {
		let file = names
			.stage()
			.ok_or(RecoveryFinishError::IncompleteEvidence)?;
		let directory = names
			.stage_directory_identity()
			.map(native_identity)
			.ok_or(RecoveryFinishError::IncompleteEvidence)?;
		Ok(Self {
			lease,
			names,
			file,
			identity: RetainedIdentity {
				file: native_identity(file.identity()),
				directory,
			},
		})
	}
}

impl RetainedStage for NativeRetainedStage<'_> {
	type NamespaceError = StageError;
	type ReadBackError = RecoveryInspectError;
	type PublishError = PublishError;
	type Publisher<'lease>
		= NativePublisher<'lease>
	where
		Self: 'lease;

	fn identity(&self) -> RetainedIdentity {
		self.identity
	}

	fn flush(&self, binding: CopyBinding) -> Result<Self::Publisher<'_>, StageError> {
		self.lease
			.prepare_retained_stage(self.names, binding)
			.map(NativePublisher)
	}

	fn verify_readback(
		&self,
		stream: StreamEvidence,
		metadata: MetadataRecorded,
		scratch: &mut [u8],
	) -> Result<Option<RecoveryIssue>, RecoveryInspectError> {
		verify(self.file, stream, Some(metadata), scratch)
	}

	fn accessed_at(&self) -> (i64, u32) {
		let time = self.file.observation().accessed_at();
		(time.seconds(), time.nanoseconds())
	}

	fn recheck_namespace(&self) -> Result<(), StageError> {
		self.names.recheck()
	}
}

pub(super) struct NativePublisher<'lease>(PlatformStage<'lease>);

impl ExclusivePublication for NativePublisher<'_> {
	type Error = PublishError;

	fn publish_no_clobber(
		self,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<PublishError>> {
		self.0
			.publish_no_clobber(authorization)
			.map_err(|cause| match cause {
				PublishError::Conflict => PublicationFailure::Conflict(cause),
				_ => PublicationFailure::Uncertain(cause),
			})?;
		#[cfg(test)]
		pause_at(Checkpoint::RetryRenamedAndSynced);
		Ok(())
	}
}

pub(super) struct NativeRetryJournal(DurableJournal);

impl NativeRetryJournal {
	pub(super) fn open(
		lease: &RecoveryWriteLease<'_>,
		journal_file: &RecoveryFile,
		boundary: JournalBoundary,
	) -> Result<Self, JournalOpenError<StageError>> {
		let segment = lease
			.open_first_segment_for_append(journal_file)
			.map_err(JournalOpenError::Namespace)?;
		DurableJournal::resume_first_segment(segment, boundary.head, boundary.offset)
			.map(Self)
			.map_err(JournalOpenError::Resume)
	}
}

impl RetryJournal for NativeRetryJournal {
	fn append_synced(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<ChainHead, DurableJournalError> {
		let head = self.0.append(kind, payload)?.head();
		#[cfg(test)]
		match kind {
			FrameKind::RecoveryDecision => pause_at(Checkpoint::RetryDecisionSynced),
			FrameKind::PublishIntent => pause_at(Checkpoint::RetryIntentSynced),
			_ => {}
		}
		Ok(head)
	}
}

pub(super) fn retry_error(
	error: RetryError<ReadError, StageError, RecoveryInspectError, PublishError>,
) -> RecoveryRetryError {
	match error {
		RetryError::IncompleteEvidence => RecoveryFinishError::IncompleteEvidence.into(),
		RetryError::EpochExhausted => RecoveryFinishError::EpochExhausted.into(),
		RetryError::EffectSequenceExhausted => RecoveryRetryError::EffectSequenceExhausted,
		RetryError::SourceMismatch => RecoveryRetryError::SourceMismatch,
		RetryError::SourcePolicy(error) => RecoveryRetryError::SourcePolicy(error),
		RetryError::MeasureSource(error) => RecoveryRetryError::MeasureSource(error),
		RetryError::Stage(issue) => RecoveryRetryError::Stage(issue),
		RetryError::ReadBack(error) => error.into(),
		RetryError::Model(error) => RecoveryRetryError::Model(error),
		RetryError::Namespace(error) => completion(RecoveryStep::Namespace)(error).into(),
		RetryError::Verification(error) => RecoveryRetryError::Verification(error),
		RetryError::Decision(error) => RecoveryFinishError::Decision(error).into(),
		RetryError::Publication(error) => RecoveryFinishError::Publication(error).into(),
		RetryError::OpenJournal(JournalOpenError::Namespace(error)) => {
			completion(RecoveryStep::Journal)(error).into()
		}
		RetryError::OpenJournal(JournalOpenError::Resume(error)) => {
			RecoveryFinishError::Resume(error).into()
		}
		RetryError::Append { kind, source } => RecoveryFinishError::Journal { kind, source }.into(),
		RetryError::Publish(error) => RecoveryRetryError::Publish(error),
	}
}
