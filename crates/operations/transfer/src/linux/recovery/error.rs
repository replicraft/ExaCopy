use std::error::Error;
use std::fmt;

use exacopy_content::{MeasureError, StreamInputError};
use exacopy_journal::OwnerError;
use exacopy_platform::linux::{ReadError, StageError};

use super::super::{JournalReplayError, LocalCopyPlanError, ReceiptError};

/// The evidence or namespace scope of a failed inspection operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecoveryStep {
	/// The held private job directory.
	Job,
	/// The job lease that excludes the active copy writer.
	Lease,
	/// The signed owner envelope.
	Owner,
	/// The immutable local plan.
	Plan,
	/// The first and only journal segment.
	Journal,
	/// The local receipt artifact.
	Receipt,
	/// The current private stage and public target names.
	Namespace,
	/// The current known stage or target's logical stream and metadata.
	Stream,
}

impl RecoveryStep {
	pub(super) fn platform(self) -> impl FnOnce(StageError) -> RecoveryInspectError {
		move |source| RecoveryInspectError::Platform { step: self, source }
	}

	pub(super) fn read(self) -> impl FnOnce(ReadError) -> RecoveryInspectError {
		move |source| RecoveryInspectError::Read { step: self, source }
	}
}

/// The evidence or current namespace could not be safely inspected.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecoveryInspectError {
	/// A retained Linux handle could not be admitted or rechecked.
	Platform {
		/// Evidence needed when the operation failed.
		step: RecoveryStep,
		/// The typed Linux platform error.
		source: StageError,
	},
	/// A held file could not be read or its observation could not be rechecked.
	Read {
		/// Evidence needed when the operation failed.
		step: RecoveryStep,
		/// The typed Linux read error.
		source: ReadError,
	},
	/// An immutable record's length exceeds its private format limit.
	Oversize(RecoveryStep),
	/// An immutable record was bound differently at the final check.
	RecordChanged(RecoveryStep),
	/// The signed owner envelope failed validation using the selected trust.
	Owner(OwnerError),
	/// The owner claims do not identify the expected private destination layout.
	OwnerBinding,
	/// The current immutable plan has an invalid representation.
	Plan(LocalCopyPlanError),
	/// The plan fails binding to the owner, current destination root, or admitted job name.
	PlanBinding,
	/// The journal cannot be replayed under the bound owner and plan.
	Journal(JournalReplayError),
	/// The receipt does not have a supported representation.
	Receipt(ReceiptError),
	/// The receipt disagrees with the bound plan, observed stream, or durability record.
	ReceiptBinding,
	/// The supplied scratch buffer is outside the stream limits.
	Input(StreamInputError),
	/// A fresh measurement of the known stage inode failed.
	ReadBack(MeasureError<ReadError>),
}

impl fmt::Display for RecoveryInspectError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Platform { step, source } => {
				write!(formatter, "could not inspect {step:?} ({source})")
			}
			Self::Read { step, source } => {
				write!(formatter, "could not read or verify {step:?} ({source})")
			}
			Self::Oversize(step) => write!(
				formatter,
				"recovery artifact {step:?} exceeds its byte limit"
			),
			Self::RecordChanged(step) => write!(
				formatter,
				"recovery artifact {step:?} changed during inspection"
			),
			Self::Owner(error) => {
				write!(formatter, "could not authenticate recovery owner ({error})")
			}
			Self::OwnerBinding => {
				formatter.write_str("recovery owner claims disagree with the held directories")
			}
			Self::Plan(error) => write!(formatter, "could not decode recovery plan ({error})"),
			Self::PlanBinding => formatter
				.write_str("recovery plan disagrees with the owner, destination or job name"),
			Self::Journal(error) => {
				write!(formatter, "could not replay recovery journal ({error})")
			}
			Self::Receipt(error) => {
				write!(formatter, "could not decode recovery receipt ({error})")
			}
			Self::ReceiptBinding => {
				formatter.write_str("recovery receipt disagrees with the plan or journal")
			}
			Self::Input(error) => write!(formatter, "invalid recovery scratch buffer ({error})"),
			Self::ReadBack(error) => write!(
				formatter,
				"could not freshly measure recovery stream ({error})"
			),
		}
	}
}

impl Error for RecoveryInspectError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Platform { source, .. } => Some(source),
			Self::Read { source, .. } => Some(source),
			Self::Owner(error) => Some(error),
			Self::Plan(error) => Some(error),
			Self::Journal(error) => Some(error),
			Self::Receipt(error) => Some(error),
			Self::Input(error) => Some(error),
			Self::ReadBack(error) => Some(error),
			Self::Oversize(_)
			| Self::RecordChanged(_)
			| Self::OwnerBinding
			| Self::PlanBinding
			| Self::ReceiptBinding => None,
		}
	}
}
