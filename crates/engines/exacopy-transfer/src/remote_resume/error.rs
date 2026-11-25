use std::{error::Error, fmt};

use exacopy_content::StreamInputError;

use super::ReplayState;
use crate::remote_capture::CaptureError;

/// Pre-effect refusal from replay or admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RestartRefusal {
	/// A durable intent, publication, or uncertain history requires reconciliation.
	Reconcile(ReplayState),
	/// Current job, entry, owner, endpoint, or policy differs from the persisted scope.
	ScopeChanged,
	/// A pre-existing destination occupies the public name.
	TargetOccupied,
	/// The destination observation could not establish an absent name.
	TargetUnknown,
	/// The held live pass differs from the allocation or reuses a consumed source epoch.
	StaleSource,
	/// The allocation heads do not match the selected chain or allow no successor.
	JournalBoundary,
	/// The run generation is invalid or has no representable successor.
	RunEpoch,
	/// The previous physical stage conflicts with the latest consumed allocation.
	AllocationBinding,
	/// The new stage is the physical stage already recorded for the old attempt.
	RetainedStage,
	/// The held stage and the captured stream have different declared extents.
	StageExtent {
		/// Field from the newly held source.
		source_length: u64,
		/// Confirmed extent of the new private stage.
		stage_length: u64,
	},
	/// The freshly observed stream exceeds the existing grant.
	SourceLimit {
		/// Freshly observed byte length.
		length: u64,
		/// Maximum approved byte length.
		limit: u64,
	},
}

impl fmt::Display for RestartRefusal {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Reconcile(_) => "remote job requires reconciliation before restart",
			Self::ScopeChanged => "remote restart scope does not match the authenticated job",
			Self::TargetOccupied => "remote restart destination is occupied",
			Self::TargetUnknown => "remote restart destination cannot be confirmed absent",
			Self::StaleSource => "remote restart requires a fresh held source pass",
			Self::JournalBoundary => "remote restart journal boundary cannot advance",
			Self::RunEpoch => "remote restart requires the next allocated run epoch",
			Self::AllocationBinding => "retained stage conflicts with the consumed allocation",
			Self::RetainedStage => "remote restart requires a distinct private stage",
			Self::StageExtent { .. } => "remote restart source and private stage extents differ",
			Self::SourceLimit { .. } => "remote restart stream exceeds the authorized length",
		})
	}
}

impl Error for RestartRefusal {}

/// A failed or mismatched checkpoint under the synchronized restart.
#[derive(Debug)]
pub enum RestartCheckpointError<J> {
	/// The barrier returned the wrong private stage or the checkpoint used another source pass.
	Binding,
	/// The private job journal did not confirm the checkpoint.
	Journal(J),
}

impl<J: fmt::Display> fmt::Display for RestartCheckpointError<J> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Binding => formatter.write_str("checkpoint belongs to a different restart"),
			Self::Journal(cause) => write!(formatter, "remote restart checkpoint failed ({cause})"),
		}
	}
}

impl<J: Error + 'static> Error for RestartCheckpointError<J> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Binding => None,
			Self::Journal(cause) => Some(cause),
		}
	}
}

/// The first failed boundary of a private restart attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum RestartError<R, W, J> {
	/// An admitted restart supplied stale or conflicting evidence.
	Refused(RestartRefusal),
	/// A capture buffer or signed extent is unsupported.
	Input(StreamInputError),
	/// The new private stage observation failed.
	Stage(W),
	/// The journal could not confirm the restart append and its applicable barriers.
	RestartRecord(J),
	/// The returned append evidence did not bind the exact restart and successor.
	RestartBinding,
	/// The resumed live capture failed in a data, checkpoint or read-back boundary.
	Capture(CaptureError<R, W, RestartCheckpointError<J>>),
	/// The closed, read-back stage does not match the recorded physical stage.
	ClosedStageBinding,
}

impl<R: fmt::Display, W: fmt::Display, J: fmt::Display> fmt::Display for RestartError<R, W, J> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Refused(cause) => cause.fmt(formatter),
			Self::Input(cause) => cause.fmt(formatter),
			Self::Stage(cause) => write!(formatter, "could not confirm restart stage ({cause})"),
			Self::RestartRecord(cause) => {
				write!(formatter, "could not synchronize remote restart ({cause})")
			}
			Self::RestartBinding => {
				formatter.write_str("remote restart journal did not confirm its binding")
			}
			Self::Capture(cause) => cause.fmt(formatter),
			Self::ClosedStageBinding => {
				formatter.write_str("verified restart stage identity changed")
			}
		}
	}
}

impl<R: Error + 'static, W: Error + 'static, J: Error + 'static> Error for RestartError<R, W, J> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Refused(cause) => Some(cause),
			Self::Input(cause) => Some(cause),
			Self::Stage(cause) => Some(cause),
			Self::RestartRecord(cause) => Some(cause),
			Self::Capture(cause) => Some(cause),
			Self::RestartBinding | Self::ClosedStageBinding => None,
		}
	}
}
