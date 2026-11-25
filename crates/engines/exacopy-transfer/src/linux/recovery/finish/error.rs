use std::{error::Error, fmt, io};

use exacopy_journal::frame::FrameKind;
use exacopy_journal::{DurableJournalError, PublicationRecordError, RecoveryRecordError};

use super::super::super::ReceiptError;
use super::super::InspectionError;

/// A failure while checking or completing an already-published copy.
#[derive(Debug)]
#[non_exhaustive]
pub enum FinishFailure<R, S> {
	/// A held object or recorded artifact did not support inspection.
	Inspection(InspectionError<R, S>),
	/// A held operation failed after the job was admitted for completion.
	Completion(InspectionError<R, S>),
	/// The verified prefix lacked a reference required for completion.
	IncompleteEvidence,
	/// No later recovery generation can be assigned.
	EpochExhausted,
	/// Reopening and synchronizing the verified prefix failed.
	Resume(DurableJournalError),
	/// The authenticated recovery start or decision could not be recorded.
	Decision(RecoveryRecordError),
	/// Publication or receipt evidence did not fit the supported profile.
	Publication(PublicationRecordError),
	/// A frame was not synchronized. Reinspect the actual prefix before retry.
	Journal {
		/// The frame whose append or barrier failed.
		kind: FrameKind,
		/// The exact failure from its writer.
		source: DurableJournalError,
	},
	/// Recovered stream and durability observations could not describe a receipt.
	Receipt(ReceiptError),
	/// Writing and synchronizing a new owner-private receipt failed.
	WriteReceipt(io::Error),
}

impl<R, S> From<InspectionError<R, S>> for FinishFailure<R, S> {
	fn from(error: InspectionError<R, S>) -> Self {
		Self::Inspection(error)
	}
}

impl<R: fmt::Display, S: fmt::Display> fmt::Display for FinishFailure<R, S> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Inspection(error) | Self::Completion(error) => error.fmt(formatter),
			Self::IncompleteEvidence => {
				formatter.write_str("recovery lacks required publication evidence")
			}
			Self::EpochExhausted => formatter.write_str("recovery generation is exhausted"),
			Self::Resume(error) => write!(
				formatter,
				"could not synchronize the verified journal prefix ({error})"
			),
			Self::Decision(error) => write!(
				formatter,
				"could not record the recovery decision ({error})"
			),
			Self::Publication(error) => {
				write!(formatter, "could not record publication evidence ({error})")
			}
			Self::Journal { kind, source } => {
				write!(formatter, "could not synchronize {kind:?} ({source})")
			}
			Self::Receipt(error) => write!(
				formatter,
				"could not construct the recovered receipt ({error})"
			),
			Self::WriteReceipt(error) => write!(
				formatter,
				"could not synchronize the recovered receipt ({error})"
			),
		}
	}
}

impl<R: Error + 'static, S: Error + 'static> Error for FinishFailure<R, S> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Inspection(error) | Self::Completion(error) => Some(error),
			Self::Resume(error) | Self::Journal { source: error, .. } => Some(error),
			Self::Decision(error) => Some(error),
			Self::Publication(error) => Some(error),
			Self::Receipt(error) => Some(error),
			Self::WriteReceipt(error) => Some(error),
			Self::IncompleteEvidence | Self::EpochExhausted => None,
		}
	}
}
