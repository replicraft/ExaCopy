use std::{error::Error, fmt, io};

use exacopy_journal::{DarwinPreparedError, OwnerError};
use exacopy_platform::macos::staging::jobs::{JobArtifact, RecoveryError};

use crate::macos::plan::DarwinCopyPlanError;
use crate::macos::replay::DarwinReplayError;

/// A failed native observation or authentication of the initial managed APFS history.
#[derive(Debug)]
#[non_exhaustive]
pub enum DarwinInspectionError {
	/// A required held artifact or namespace observation could not be established.
	Platform(RecoveryError),
	/// A native observation could not fit the owner record profile.
	Identity(OwnerError),
	/// The bounded artifact exceeds its codec limit.
	ArtifactTooLarge {
		/// The affected private artifact.
		artifact: JobArtifact,
		/// Its codec's supported size in bytes.
		limit: usize,
	},
	/// The bounded artifact could not be read.
	Read {
		/// The affected private artifact.
		artifact: JobArtifact,
		/// The underlying error.
		error: io::Error,
	},
	/// The plan is incompatible or malformed.
	Plan(DarwinCopyPlanError),
	/// The private name or destination does not match the plan and trusted capability.
	PlanBinding,
	/// The accepted entry could not provide a valid stage component.
	Preparation(DarwinPreparedError),
	/// The owner, journal or receipt failed authentication or semantic replay.
	Replay(DarwinReplayError),
}

impl fmt::Display for DarwinInspectionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Platform(error) => error.fmt(formatter),
			Self::Identity(error) => error.fmt(formatter),
			Self::ArtifactTooLarge { artifact, limit } => {
				write!(formatter, "private {artifact:?} exceeds {limit} bytes")
			}
			Self::Read { artifact, error } => {
				write!(formatter, "cannot read private {artifact:?} ({error})")
			}
			Self::Plan(error) => error.fmt(formatter),
			Self::PlanBinding => {
				formatter.write_str("private plan differs from the observed job or destination")
			}
			Self::Preparation(error) => error.fmt(formatter),
			Self::Replay(error) => error.fmt(formatter),
		}
	}
}

impl Error for DarwinInspectionError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(match self {
			Self::Platform(error) => error,
			Self::Identity(error) => error,
			Self::Read { error, .. } => error,
			Self::Plan(error) => error,
			Self::Preparation(error) => error,
			Self::Replay(error) => error,
			Self::ArtifactTooLarge { .. } | Self::PlanBinding => return None,
		})
	}
}

impl From<RecoveryError> for DarwinInspectionError {
	fn from(error: RecoveryError) -> Self {
		Self::Platform(error)
	}
}

impl From<OwnerError> for DarwinInspectionError {
	fn from(error: OwnerError) -> Self {
		Self::Identity(error)
	}
}
