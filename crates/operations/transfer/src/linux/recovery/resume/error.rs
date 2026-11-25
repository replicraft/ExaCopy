use exacopy_content::{MeasureError, StreamInputError};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{DurableJournalError, PublicationRecordError, RecoveryRecordError};

use super::super::super::ReceiptError;
use super::super::super::local_copy::ProtocolError;
use super::super::super::local_copy::records::SealError;
use super::super::RecoveryIssue;
use crate::linux_staging::StageFailure;

#[derive(Debug)]
pub(super) enum ResumeError<R, S, P, F> {
	Input(StreamInputError),
	IncompleteEvidence,
	EpochExhausted,
	Resume(DurableJournalError),
	Decision(RecoveryRecordError),
	PublicationRecord(PublicationRecordError),
	Journal {
		kind: FrameKind,
		source: DurableJournalError,
	},
	Records(F),
	Receipt(ReceiptError),
	Namespace(S),
	SourceMismatch,
	SourcePolicy(StageFailure<R, S>),
	MeasureSource(MeasureError<R>),
	Stage(RecoveryIssue),
	Model(StageFailure<R, S>),
	ResumeStage(StageFailure<R, S>),
	Seal(SealError),
	Publish(ProtocolError<R, S, P>),
}
