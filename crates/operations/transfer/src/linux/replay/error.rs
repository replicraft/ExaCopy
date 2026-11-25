use std::{error::Error, fmt};

use exacopy_journal::frame::{FrameKind, FrameReadError};
use exacopy_journal::{
	IntentError, PreparedError, PublicationRecordError, VerificationRecordError,
};

/// A local journal prefix that cannot be used as compatible recovery evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum JournalReplayError {
	/// The signed owner and canonical local plan disagree.
	OwnerBinding,
	/// An envelope was incompatible, corrupted, or unreadable.
	Frame(FrameReadError),
	/// A complete frame was not the next record allowed for this journal.
	UnexpectedRecord {
		/// The next supported record, or none at the end of the fixed sequence.
		expected: Option<FrameKind>,
		/// The kind given by the verified frame envelope.
		found: FrameKind,
	},
	/// A complete frame skipped a sequence number.
	NonconsecutiveSequence {
		/// The unexpected sequence from the verified frame envelope.
		sequence: u64,
	},
	/// A decoded record disagreed with the owner, plan, or another journal record.
	RecordBinding {
		/// The record containing the incompatible binding.
		kind: FrameKind,
	},
	/// A job or entry preparation payload was refused.
	Prepared(PreparedError),
	/// A stage, verification, or metadata payload was refused.
	Verification(VerificationRecordError),
	/// The publication intent payload was refused.
	Intent(IntentError),
	/// A publication observation, barrier, or receipt payload or binding was refused.
	Publication(PublicationRecordError),
}

impl fmt::Display for JournalReplayError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::OwnerBinding => formatter.write_str("owner and local plan bindings disagree"),
			Self::Frame(error) => write!(formatter, "journal frame refused ({error})"),
			Self::UnexpectedRecord { expected, found } => {
				write!(
					formatter,
					"unexpected journal record {found:?}, expected {expected:?}"
				)
			}
			Self::NonconsecutiveSequence { sequence } => {
				write!(
					formatter,
					"nonconsecutive journal frame sequence {sequence}"
				)
			}
			Self::RecordBinding { kind } => {
				write!(
					formatter,
					"journal record {kind:?} has incompatible evidence"
				)
			}
			Self::Prepared(error) => write!(formatter, "preparation payload refused ({error})"),
			Self::Verification(error) => {
				write!(formatter, "stage evidence payload refused ({error})")
			}
			Self::Intent(error) => {
				write!(formatter, "publication intent payload refused ({error})")
			}
			Self::Publication(error) => write!(formatter, "publication evidence refused ({error})"),
		}
	}
}

impl Error for JournalReplayError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Frame(error) => Some(error),
			Self::Prepared(error) => Some(error),
			Self::Verification(error) => Some(error),
			Self::Intent(error) => Some(error),
			Self::Publication(error) => Some(error),
			_ => None,
		}
	}
}

impl From<PreparedError> for JournalReplayError {
	fn from(error: PreparedError) -> Self {
		Self::Prepared(error)
	}
}

impl From<VerificationRecordError> for JournalReplayError {
	fn from(error: VerificationRecordError) -> Self {
		Self::Verification(error)
	}
}

impl From<IntentError> for JournalReplayError {
	fn from(error: IntentError) -> Self {
		Self::Intent(error)
	}
}

impl From<PublicationRecordError> for JournalReplayError {
	fn from(error: PublicationRecordError) -> Self {
		Self::Publication(error)
	}
}
