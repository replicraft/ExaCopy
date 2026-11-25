use std::{error::Error, fmt};

use exacopy_content::{MeasureError, StreamInputError};

use super::SourceEpoch;

/// A private stage boundary during live capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StageStep {
	/// The writer must be fresh and held.
	Admit,
	/// The next complete window must be written.
	Write {
		/// Starting byte offset of the unconfirmed window.
		offset: u64,
	},
	/// The written prefix must reach its data barrier.
	SyncPrefix {
		/// Exclusive end of the unconfirmed prefix.
		end: u64,
	},
	/// The full stage must be synchronized and its writer closed.
	Close,
	/// An independent read-only view must bind the held stage.
	OpenReadBack,
	/// The read-back observation must retain its binding and exact EOF.
	RecheckReadBack,
}

/// First failed boundary of a live source capture.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureError<R, W, C> {
	/// The captured extent or supplied scratch is outside the stream bounds.
	Input(StreamInputError),
	/// The stage reports a different extent than the captured source.
	Extent {
		/// Captured source extent in bytes.
		expected: u64,
		/// Observed stage extent in bytes.
		found: u64,
	},
	/// A different pass was reported while the original was active.
	Epoch {
		/// Active source epoch.
		expected: SourceEpoch,
		/// Epoch most recently reported by the capability.
		found: SourceEpoch,
	},
	/// The held source could not confirm its required initial live observation.
	SourceObservation(R),
	/// EOF, final live observations or source closure were unconfirmed.
	SourceFinish(R),
	/// The source failed to supply the whole window.
	Read {
		/// Starting byte offset of the failed window.
		offset: u64,
		/// Driver error for the unconfirmed range.
		cause: R,
	},
	/// A local stage boundary was not confirmed.
	Stage {
		/// Operation that failed.
		step: StageStep,
		/// Adapter's failure for that operation.
		cause: W,
	},
	/// The synced data range could not be recorded.
	Checkpoint {
		/// Starting byte offset of the unconfirmed checkpoint.
		offset: u64,
		/// Adapter's failure for that record.
		cause: C,
	},
	/// Independent read-back could not measure the complete stage.
	ReadBack(MeasureError<W>),
	/// Measured source and read-back digests disagree.
	DigestMismatch,
}

impl<R: fmt::Display, W: fmt::Display, C: fmt::Display> fmt::Display for CaptureError<R, W, C> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Input(cause) => cause.fmt(f),
			Self::Extent { expected, found } => {
				write!(
					f,
					"stage extent {found} differs from captured extent {expected}"
				)
			}
			Self::Epoch { .. } => f.write_str("live capture source epoch changed"),
			Self::SourceObservation(cause) => write!(f, "source recheck failed ({cause})"),
			Self::SourceFinish(cause) => write!(f, "finishing held source failed ({cause})"),
			Self::Read { offset, cause } => write!(f, "source read failed at {offset} ({cause})"),
			Self::Stage { step, cause } => write!(f, "private stage {step:?} failed ({cause})"),
			Self::Checkpoint { offset, cause } => {
				write!(f, "checkpoint failed at {offset} ({cause})")
			}
			Self::ReadBack(cause) => write!(f, "stage read-back failed ({cause})"),
			Self::DigestMismatch => f.write_str("stage read-back digest mismatch"),
		}
	}
}

impl<R: Error + 'static, W: Error + 'static, C: Error + 'static> Error for CaptureError<R, W, C> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Input(cause) => Some(cause),
			Self::SourceObservation(cause)
			| Self::SourceFinish(cause)
			| Self::Read { cause, .. } => Some(cause),
			Self::Stage { cause, .. } => Some(cause),
			Self::Checkpoint { cause, .. } => Some(cause),
			Self::ReadBack(cause) => Some(cause),
			Self::Extent { .. } | Self::Epoch { .. } | Self::DigestMismatch => None,
		}
	}
}
