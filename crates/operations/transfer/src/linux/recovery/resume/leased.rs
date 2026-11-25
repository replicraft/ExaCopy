use super::super::finish::{completion, sync_leased_receipt};
use super::super::{
	FinishFailure, InspectionError, LeaseReadError, RecoveryLease, RecoveryStageLease,
	RecoveryStep, SourceRecoveryFailure,
};
use super::engine::Records;
use super::error::ResumeError;
use crate::linux::local_copy::ProtocolError;
use crate::linux::{CopyCheckpoint, CopyReceipt, JournalBoundary};
use exacopy_journal::DurableJournal;

pub(super) struct HeldRecords<'lease, L: RecoveryLease> {
	pub(super) lease: &'lease L,
	pub(super) journal: &'lease L::File,
	pub(super) checkpoint: fn(CopyCheckpoint),
}

impl<L: RecoveryLease> Records for HeldRecords<'_, L> {
	type Error = FinishFailure<LeaseReadError<L>, L::EffectError>;

	fn checkpoint(&self) -> fn(CopyCheckpoint) {
		self.checkpoint
	}

	fn resume_journal(&self, boundary: JournalBoundary) -> Result<DurableJournal, Self::Error> {
		let segment = self
			.lease
			.open_segment(self.journal)
			.map_err(completion(RecoveryStep::Journal))?;
		DurableJournal::resume_first_segment(segment, boundary.head, boundary.offset)
			.map_err(FinishFailure::Resume)
	}

	fn sync_receipt(&self, receipt: &CopyReceipt<'_>) -> Result<(), Self::Error> {
		sync_leased_receipt(self.lease, receipt)
	}
}

type LeasedResumeError<L> = ResumeError<
	LeaseReadError<L>,
	<L as super::super::ReceiptLease>::EffectError,
	<L as RecoveryStageLease>::PublishError,
	FinishFailure<LeaseReadError<L>, <L as super::super::ReceiptLease>::EffectError>,
>;

pub(super) fn resume_error<L: RecoveryStageLease>(
	error: LeasedResumeError<L>,
) -> SourceRecoveryFailure<LeaseReadError<L>, L::EffectError, L::PublishError> {
	match error {
		ResumeError::Input(error) => InspectionError::Input(error).into(),
		ResumeError::IncompleteEvidence => FinishFailure::IncompleteEvidence.into(),
		ResumeError::EpochExhausted => FinishFailure::EpochExhausted.into(),
		ResumeError::Resume(error) => FinishFailure::Resume(error).into(),
		ResumeError::Decision(error) => FinishFailure::Decision(error).into(),
		ResumeError::PublicationRecord(error) => FinishFailure::Publication(error).into(),
		ResumeError::Journal { kind, source } => FinishFailure::Journal { kind, source }.into(),
		ResumeError::Records(error) => error.into(),
		ResumeError::Receipt(error) => FinishFailure::Receipt(error).into(),
		ResumeError::Namespace(error) => completion(RecoveryStep::Namespace)(error).into(),
		ResumeError::SourceMismatch => SourceRecoveryFailure::SourceMismatch,
		ResumeError::SourcePolicy(error) => SourceRecoveryFailure::SourcePolicy(error),
		ResumeError::MeasureSource(error) => SourceRecoveryFailure::MeasureSource(error),
		ResumeError::Stage(issue) => SourceRecoveryFailure::Stage(issue),
		ResumeError::Model(error) => SourceRecoveryFailure::Model(error),
		ResumeError::ResumeStage(error) => SourceRecoveryFailure::ResumeStage(error),
		ResumeError::Seal(error) => SourceRecoveryFailure::ResumeCopy(Box::new(error.into())),
		ResumeError::Publish(ProtocolError::Publication {
			source,
			recording: None,
		}) if L::is_conflict(&source) => SourceRecoveryFailure::Publish(source),
		ResumeError::Publish(error) => SourceRecoveryFailure::ResumeCopy(Box::new(error.into())),
	}
}
