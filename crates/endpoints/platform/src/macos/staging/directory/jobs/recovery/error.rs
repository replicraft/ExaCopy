use std::{fmt, io};

use rustix::io::Errno;

use super::super::super::super::super::ManagedReadError;
use super::super::super::super::super::thread_policy::PolicyError;
use super::{JobArtifact, RecoveryName, StageError};

/// Failure observing one read-only managed APFS recovery job.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecoveryError {
	/// The already supplied managed namespace lease failed revalidation.
	Managed(StageError),
	/// The supplied staging directory belongs to a job and cannot contain one.
	NestedJob,
	/// A fixed name was absent.
	Missing(JobArtifact),
	/// A fixed object could not be admitted or no longer matches its binding.
	InvalidObject(JobArtifact),
	/// A selected stage or target cannot be admitted or its observation changed.
	InvalidEntry(RecoveryName),
	/// An independently acquired directory lease would conflict with another actor.
	DirectoryBusy(JobArtifact),
	/// A record's extent falls outside the selected fixed artifact's bounds.
	InvalidLength {
		/// The bounded private artifact.
		artifact: JobArtifact,
		/// The observed logical length.
		length: u64,
		/// The supported upper bound.
		limit: u64,
	},
	/// A read interrupted the attempted observation.
	System(io::Error),
}

impl fmt::Display for RecoveryError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Managed(error) => write!(formatter, "managed recovery lease failed ({error})"),
			Self::NestedJob => formatter.write_str("job recovery requires the private container"),
			Self::Missing(artifact) => write!(formatter, "private recovery {artifact:?} is absent"),
			Self::InvalidObject(artifact) => {
				write!(
					formatter,
					"private recovery {artifact:?} identity or metadata is invalid"
				)
			}
			Self::InvalidEntry(name) => {
				write!(
					formatter,
					"recovery {name:?} identity or metadata is invalid"
				)
			}
			Self::DirectoryBusy(artifact) => {
				write!(formatter, "private recovery {artifact:?} lease is busy")
			}
			Self::InvalidLength {
				artifact,
				length,
				limit,
			} => write!(
				formatter,
				"private recovery {artifact:?} length {length} is outside its bounds (limit {limit})"
			),
			Self::System(error) => {
				write!(formatter, "private recovery descriptor failed ({error})")
			}
		}
	}
}

impl std::error::Error for RecoveryError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Managed(error) => Some(error),
			Self::System(error) => Some(error),
			_ => None,
		}
	}
}

impl From<StageError> for RecoveryError {
	fn from(error: StageError) -> Self {
		Self::Managed(error)
	}
}

impl From<ManagedReadError> for RecoveryError {
	fn from(error: ManagedReadError) -> Self {
		Self::Managed(error.into())
	}
}

impl From<PolicyError> for RecoveryError {
	fn from(error: PolicyError) -> Self {
		Self::Managed(error.into())
	}
}

impl From<io::Error> for RecoveryError {
	fn from(error: io::Error) -> Self {
		Self::System(error)
	}
}

impl From<Errno> for RecoveryError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}
