use std::fmt;

use exacopy_journal::frame::{FrameKind, FrameReadError};
use exacopy_journal::{DarwinPhaseError, DarwinPreparedError, OwnerError};

use crate::macos::receipt::DarwinCopyReceiptError;

/// Failure to accept a managed APFS journal prefix or its associated receipt.
#[derive(Debug)]
#[non_exhaustive]
pub enum DarwinReplayError {
	/// The signed owner failed authentication against the independent profile.
	Owner(OwnerError),
	/// The owner and plan disagree with the authorized private directory or profile.
	OwnerBinding,
	/// The frame envelope is invalid or could not be read.
	Frame(FrameReadError),
	/// The journal contains a complete frame after a sequence gap.
	NonconsecutiveSequence {
		/// The found sequence rather than its consecutive predecessor plus one.
		sequence: u64,
	},
	/// A record does not belong at this point in the supported history.
	UnexpectedRecord {
		/// The expected continuation, or no kind after the last supported record.
		expected: Option<FrameKind>,
		/// The kind of the complete unexpected frame.
		found: FrameKind,
	},
	/// The typed preparation is invalid or bound to different records.
	Prepared(DarwinPreparedError),
	/// A record differs from the independent plan or owner binding.
	RecordBinding {
		/// The mismatched record.
		kind: FrameKind,
	},
	/// The phase record is invalid or does not refer to the accepted evidence.
	Phase(DarwinPhaseError),
	/// The initial history cannot contain a publication confirmed by later reconciliation.
	UnsupportedRecoveryObservation,
	/// No commitment in the accepted history can authenticate a receipt artifact.
	MissingReceiptCommitment,
	/// The receipt is invalid or differs from the accepted observations.
	Receipt(DarwinCopyReceiptError),
}

impl From<OwnerError> for DarwinReplayError {
	fn from(error: OwnerError) -> Self {
		Self::Owner(error)
	}
}

impl From<DarwinPreparedError> for DarwinReplayError {
	fn from(error: DarwinPreparedError) -> Self {
		Self::Prepared(error)
	}
}

impl From<DarwinPhaseError> for DarwinReplayError {
	fn from(error: DarwinPhaseError) -> Self {
		Self::Phase(error)
	}
}

impl From<DarwinCopyReceiptError> for DarwinReplayError {
	fn from(error: DarwinCopyReceiptError) -> Self {
		Self::Receipt(error)
	}
}

impl fmt::Display for DarwinReplayError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Owner(error) => write!(formatter, "invalid APFS journal owner ({error})"),
			Self::OwnerBinding => formatter.write_str("APFS journal owner binding mismatch"),
			Self::Frame(error) => write!(formatter, "invalid APFS journal frame ({error})"),
			Self::NonconsecutiveSequence { sequence } => {
				write!(formatter, "nonconsecutive APFS journal sequence {sequence}")
			}
			Self::UnexpectedRecord { expected, found } => {
				write!(
					formatter,
					"unexpected APFS journal record {found:?}, expected {expected:?}"
				)
			}
			Self::Prepared(error) => {
				write!(formatter, "invalid APFS journal preparation ({error})")
			}
			Self::RecordBinding { kind } => {
				write!(formatter, "APFS journal binding mismatch for {kind:?}")
			}
			Self::Phase(error) => write!(formatter, "invalid APFS journal phase ({error})"),
			Self::UnsupportedRecoveryObservation => {
				formatter.write_str("APFS recovery observation in an initial journal")
			}
			Self::MissingReceiptCommitment => {
				formatter.write_str("APFS journal lacks a receipt commitment")
			}
			Self::Receipt(error) => write!(formatter, "invalid APFS journal receipt ({error})"),
		}
	}
}

impl std::error::Error for DarwinReplayError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Owner(error) => Some(error),
			Self::Frame(error) => Some(error),
			Self::Prepared(error) => Some(error),
			Self::Phase(error) => Some(error),
			Self::Receipt(error) => Some(error),
			_ => None,
		}
	}
}
