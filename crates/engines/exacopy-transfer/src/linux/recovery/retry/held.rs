use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_recovery::{RecoveryInventoryView, RecoveryRecord};
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{DurableJournal, DurableJournalError, MetadataRecorded, StreamEvidence};
use exacopy_model::CopyBinding;

use super::super::finish::completion;
use super::super::{
	FinishFailure, InspectionError, LeaseInventory, LeaseReadError, RecoveryStageLease,
	RecoveryStep, record_identity, verify,
};
use super::SourceRecoveryFailure;
use super::engine::{JournalOpenError, RetainedIdentity, RetainedStage, RetryError, RetryJournal};
use crate::linux::{CopyCheckpoint, JournalBoundary, RecoveryIssue};

pub(super) struct HeldStage<'lease, 'inventory: 'lease, L: RecoveryStageLease + 'inventory> {
	lease: &'lease L,
	names: &'lease LeaseInventory<'inventory, L>,
	file: &'lease L::File,
	identity: RetainedIdentity,
}

impl<'lease, 'inventory: 'lease, L: RecoveryStageLease> HeldStage<'lease, 'inventory, L> {
	pub(super) fn new(
		lease: &'lease L,
		names: &'lease LeaseInventory<'inventory, L>,
	) -> Result<Self, FinishFailure<LeaseReadError<L>, L::EffectError>> {
		let file = names.stage().ok_or(FinishFailure::IncompleteEvidence)?;
		let directory = names
			.stage_directory_identity()
			.map(record_identity)
			.ok_or(FinishFailure::IncompleteEvidence)?;
		Ok(Self {
			lease,
			names,
			file,
			identity: RetainedIdentity {
				file: record_identity(file.identity().into()),
				directory,
			},
		})
	}
}

impl<L: RecoveryStageLease> RetainedStage for HeldStage<'_, '_, L> {
	type NamespaceError = L::EffectError;
	type ReadBackError = InspectionError<LeaseReadError<L>, L::EffectError>;
	type PublishError = L::PublishError;
	type Publisher<'lease>
		= L::Publisher<'lease>
	where
		Self: 'lease;

	fn identity(&self) -> RetainedIdentity {
		self.identity
	}

	fn flush(&self, binding: CopyBinding) -> Result<Self::Publisher<'_>, Self::NamespaceError> {
		self.lease.prepare_retry(self.names, binding)
	}

	fn verify_readback(
		&self,
		stream: StreamEvidence,
		metadata: MetadataRecorded,
		scratch: &mut [u8],
	) -> Result<Option<RecoveryIssue>, Self::ReadBackError> {
		verify(self.file, stream, Some(metadata), scratch)
	}

	fn accessed_at(&self) -> (i64, u32) {
		let time = self.file.observation().accessed_at;
		(time.seconds, time.nanoseconds)
	}

	fn recheck_namespace(&self) -> Result<(), Self::NamespaceError> {
		self.names.recheck()
	}
}

pub(super) fn open_journal<'lease, L: RecoveryStageLease>(
	lease: &'lease L,
	file: &L::File,
	boundary: JournalBoundary,
	checkpoint: fn(CopyCheckpoint),
) -> Result<ObservedJournal<L::Segment<'lease>>, JournalOpenError<L::EffectError>> {
	let segment = lease
		.open_segment(file)
		.map_err(JournalOpenError::Namespace)?;
	DurableJournal::resume_first_segment(segment, boundary.head, boundary.offset)
		.map(|journal| ObservedJournal {
			journal,
			checkpoint,
		})
		.map_err(JournalOpenError::Resume)
}

pub(super) struct ObservedJournal<S> {
	journal: DurableJournal<S>,
	checkpoint: fn(CopyCheckpoint),
}

impl<S: JournalSegment> RetryJournal for ObservedJournal<S> {
	fn append_synced(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<ChainHead, DurableJournalError> {
		let head = self.journal.append(kind, payload)?.head();
		match kind {
			FrameKind::RecoveryDecision => (self.checkpoint)(CopyCheckpoint::RetryDecisionSynced),
			FrameKind::PublishIntent => (self.checkpoint)(CopyCheckpoint::RetryIntentSynced),
			_ => {}
		}
		Ok(head)
	}
}

pub(super) fn retry_error<R, S, P>(
	error: RetryError<R, S, InspectionError<R, S>, P>,
) -> SourceRecoveryFailure<R, S, P> {
	match error {
		RetryError::IncompleteEvidence => FinishFailure::IncompleteEvidence.into(),
		RetryError::EpochExhausted => FinishFailure::EpochExhausted.into(),
		RetryError::EffectSequenceExhausted => SourceRecoveryFailure::EffectSequenceExhausted,
		RetryError::SourceMismatch => SourceRecoveryFailure::SourceMismatch,
		RetryError::SourcePolicy(error) => SourceRecoveryFailure::SourcePolicy(error),
		RetryError::MeasureSource(error) => SourceRecoveryFailure::MeasureSource(error),
		RetryError::Stage(issue) => SourceRecoveryFailure::Stage(issue),
		RetryError::ReadBack(error) => error.into(),
		RetryError::Model(error) => SourceRecoveryFailure::Model(error),
		RetryError::Namespace(error) => completion(RecoveryStep::Namespace)(error).into(),
		RetryError::Verification(error) => SourceRecoveryFailure::Verification(error),
		RetryError::Decision(error) => FinishFailure::Decision(error).into(),
		RetryError::Publication(error) => FinishFailure::Publication(error).into(),
		RetryError::OpenJournal(JournalOpenError::Namespace(error)) => {
			completion(RecoveryStep::Journal)(error).into()
		}
		RetryError::OpenJournal(JournalOpenError::Resume(error)) => {
			FinishFailure::Resume(error).into()
		}
		RetryError::Append { kind, source } => FinishFailure::Journal { kind, source }.into(),
		RetryError::Publish(error) => SourceRecoveryFailure::Publish(error),
	}
}
