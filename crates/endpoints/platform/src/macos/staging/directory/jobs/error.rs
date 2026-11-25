use std::{fmt, io};

use rustix::io::Errno;

use super::super::super::super::{ManagedReadError, thread_policy::PolicyError};
use super::super::super::StageError;
use super::JobName;

/// A fixed object in the private Darwin job layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobArtifact {
	/// The job directory itself.
	Directory,
	/// The signed owner envelope.
	Owner,
	/// The canonical plan.
	Plan,
	/// The journal subdirectory.
	Journal,
	/// The first framed journal segment.
	FirstSegment,
	/// The receipts subdirectory.
	Receipts,
	/// The exclusively created pending receipt.
	ReceiptPending,
	/// The immutable initial receipt.
	Receipt,
	/// The stage subdirectory.
	Stage,
}

/// The failed boundary of an attempted private artifact creation or publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobStep {
	/// The exclusive creation syscall was attempted.
	Create,
	/// The new object's identity or authority could not be established.
	Bind,
	/// The new record may contain a partially written payload.
	Write,
	/// A Darwin full file barrier was attempted.
	FileBarrier,
	/// The writer closure could not be confirmed.
	Close,
	/// The closed record's bytes and binding were checked before publication.
	Verify,
	/// The exclusive private receipt rename was attempted.
	Publish,
	/// A namespace barrier on the containing directory was attempted.
	NamespaceBarrier,
	/// A post-operation check or thread policy restoration failed.
	Revalidate,
}

/// Failure preparing an owner-private managed APFS job artifact.
#[derive(Debug)]
#[non_exhaustive]
pub enum JobError {
	/// The checked APFS lease or materialization scope failed.
	Managed(StageError),
	/// A required name was occupied. The incumbent was never opened or changed.
	Occupied {
		/// The job whose name was used.
		job: JobName,
		/// The colliding name's fixed role.
		artifact: JobArtifact,
	},
	/// A child reserved for stage files cannot contain new job state.
	NestedJob,
	/// The payload is empty or exceeds the bounded size.
	InvalidLength,
	/// A held or named object no longer matches the required binding or metadata.
	IdentityChanged,
	/// The receipt read-back disagrees with the requested bytes.
	ReceiptMismatch,
	/// A filesystem operation failed.
	System(io::Error),
	/// A private entry may have been created or published. Preserve it for reconciliation.
	Uncertain {
		/// The job whose name was used.
		job: JobName,
		/// The possibly affected object.
		artifact: JobArtifact,
		/// The attempted operation or failed check.
		step: JobStep,
		/// The underlying failure.
		source: Box<JobError>,
	},
}

impl fmt::Display for JobError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Managed(error) => {
				write!(formatter, "managed APFS job authority failed ({error})")
			}
			Self::Occupied { artifact, .. } => {
				write!(formatter, "private job {artifact:?} name is occupied")
			}
			Self::NestedJob => {
				formatter.write_str("job creation requires a provisioned private container")
			}
			Self::InvalidLength => {
				formatter.write_str("private job record length exceeds its bounds")
			}
			Self::IdentityChanged => {
				formatter.write_str("private job object identity or metadata changed")
			}
			Self::ReceiptMismatch => formatter.write_str("private receipt read-back disagrees"),
			Self::System(error) => write!(
				formatter,
				"private job descriptor operation failed ({error})"
			),
			Self::Uncertain {
				artifact,
				step,
				source,
				..
			} => {
				write!(
					formatter,
					"private job {artifact:?} requires reconciliation after {step:?} ({source})"
				)
			}
		}
	}
}

impl std::error::Error for JobError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Managed(error) => Some(error),
			Self::System(error) => Some(error),
			Self::Uncertain { source, .. } => Some(source),
			_ => None,
		}
	}
}

impl From<StageError> for JobError {
	fn from(error: StageError) -> Self {
		Self::Managed(error)
	}
}

impl From<ManagedReadError> for JobError {
	fn from(error: ManagedReadError) -> Self {
		Self::Managed(error.into())
	}
}

impl From<PolicyError> for JobError {
	fn from(error: PolicyError) -> Self {
		Self::Managed(error.into())
	}
}

impl From<io::Error> for JobError {
	fn from(error: io::Error) -> Self {
		Self::System(error)
	}
}

impl From<Errno> for JobError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}
