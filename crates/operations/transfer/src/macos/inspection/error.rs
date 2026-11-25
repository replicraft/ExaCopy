use std::{error::Error, fmt, io};

use exacopy_content::{MeasureError, StreamInputError};
use exacopy_journal::{DarwinPhaseError, DarwinPreparedError, OwnerError};
use exacopy_platform::macos::staging::MAX_STAGE_IO_BYTES;
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
	/// Opt-in verification of the retained private stage failed.
	StageReadBack(DarwinStageReadBackError),
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
			Self::StageReadBack(error) => error.fmt(formatter),
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
			Self::StageReadBack(error) => error,
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

/// Failure to match a fresh private stage observation with accepted APFS journal evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum DarwinStageReadBackError {
	/// There is no accepted prior stage verification for this job.
	MissingVerification,
	/// The retained stage directory, inode or extent differs from the accepted evidence.
	StageBinding,
	/// An accepted stage phase could not be decoded.
	Phase(DarwinPhaseError),
	/// Scratch exceeds the native positioned read limit.
	ScratchTooLarge {
		/// Supplied scratch length in bytes.
		length: usize,
	},
	/// The stream length or scratch size is invalid.
	Input(StreamInputError),
	/// The private reader could not be opened or revalidated.
	Platform(RecoveryError),
	/// The positioned content measurement failed.
	Read(MeasureError<RecoveryError>),
	/// The independently measured digest differs from the recorded stage digest.
	DigestMismatch,
	/// The initial live metadata differs from the recorded required metadata.
	InitialMetadataMismatch,
	/// The metadata observed after content and EOF reads differs from the recorded metadata.
	FinalMetadataMismatch,
}

impl fmt::Display for DarwinStageReadBackError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::MissingVerification => {
				formatter.write_str("APFS journal lacks stage verification")
			}
			Self::StageBinding => {
				formatter.write_str("private stage differs from the APFS journal")
			}
			Self::Phase(error) => write!(formatter, "invalid APFS stage phase ({error})"),
			Self::ScratchTooLarge { length } => write!(
				formatter,
				"scratch length {length} exceeds the {MAX_STAGE_IO_BYTES}-byte APFS limit"
			),
			Self::Input(error) => error.fmt(formatter),
			Self::Platform(error) => error.fmt(formatter),
			Self::Read(error) => error.fmt(formatter),
			Self::DigestMismatch => {
				formatter.write_str("private stage digest differs from verification")
			}
			Self::InitialMetadataMismatch => {
				formatter.write_str("private stage metadata differs before read-back")
			}
			Self::FinalMetadataMismatch => {
				formatter.write_str("private stage metadata differs after read-back")
			}
		}
	}
}

impl Error for DarwinStageReadBackError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Phase(error) => Some(error),
			Self::Input(error) => Some(error),
			Self::Platform(error) => Some(error),
			Self::Read(error) => Some(error),
			_ => None,
		}
	}
}
