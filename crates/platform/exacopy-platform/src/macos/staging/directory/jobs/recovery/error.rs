use std::{fmt, io};

use apfs_mounted::source::SourceError;
use rustix::io::Errno;

use super::super::super::super::super::ManagedReadError;
use super::super::super::super::super::thread_policy::PolicyError;
use super::{JobArtifact, RecoveryName, StageError};

/// Failure observing one read-only managed APFS recovery job.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecoveryError {
	/// A managed APFS lease, native metadata or bounded read check failed.
	Managed(StageError),
	/// The supplied staging directory belongs to a job and cannot contain one.
	NestedJob,
	/// A fixed name was absent.
	Missing(JobArtifact),
	/// The fixed receipt staging name is occupied and requires reconciliation.
	PendingReceipt,
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
	/// An independently reopened stage operation failed.
	MountedStage {
		/// The requested offset and byte count for a positioned read.
		requested: Option<(u64, usize)>,
		/// The underlying read-only APFS observation failure.
		cause: Box<SourceError>,
	},
	/// A read interrupted the attempted observation.
	System(io::Error),
}

impl fmt::Display for RecoveryError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Managed(error) => {
				write!(formatter, "managed APFS recovery check failed ({error})")
			}
			Self::NestedJob => formatter.write_str("job recovery requires the private container"),
			Self::Missing(artifact) => write!(formatter, "private recovery {artifact:?} is absent"),
			Self::PendingReceipt => {
				formatter.write_str("private receipt is pending reconciliation")
			}
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
			Self::MountedStage {
				requested: Some((offset, count)),
				cause,
			} => write!(
				formatter,
				"private stage read requested {count} bytes at offset {offset} ({cause})"
			),
			Self::MountedStage {
				requested: None,
				cause,
			} => {
				write!(formatter, "private stage observation failed ({cause})")
			}
			Self::System(error) => {
				write!(formatter, "private recovery descriptor failed ({error})")
			}
		}
	}
}

impl RecoveryError {
	pub(super) fn mounted_stage(requested: Option<(u64, usize)>, cause: SourceError) -> Self {
		Self::MountedStage {
			requested,
			cause: Box::new(cause),
		}
	}
}

impl std::error::Error for RecoveryError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Managed(error) => Some(error),
			Self::System(error) => Some(error),
			Self::MountedStage { cause, .. } => Some(cause.as_ref()),
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

#[test]
fn mounted_read_failure_keeps_request_range_and_original_errno() {
	use std::error::Error as _;

	let error = RecoveryError::mounted_stage(
		Some((4096, 32)),
		SourceError::Io(io::Error::from_raw_os_error(libc::EIO)),
	);
	assert!(
		error
			.to_string()
			.contains("requested 32 bytes at offset 4096")
	);
	let cause = error.source().unwrap().downcast_ref::<SourceError>();
	assert!(matches!(
		cause,
		Some(SourceError::Io(error)) if error.raw_os_error() == Some(libc::EIO)
	));
}
