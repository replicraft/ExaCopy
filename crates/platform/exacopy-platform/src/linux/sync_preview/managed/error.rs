use std::fmt;
use std::io;

use rustix::io::Errno;

use super::SyncPreviewError;

/// Failure to establish or retain the managed one-subject read scope.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagedSyncError {
	/// Selected scope differs from the held native roots.
	ScopeMismatch,
	/// Required process credentials or full UID/GID mappings were refused.
	CredentialProfile,
	/// A held directory is outside the selected owner-private policy.
	PrivateDirectoryRequired,
	/// A selected file reports an ambiguous ownership mapping.
	AmbiguousSubjectOwnership,
	/// A participating writer holds an incompatible common-parent lease.
	Busy,
	/// An existing held scope or subject observation failed.
	Preview(SyncPreviewError),
	/// A native managed check failed.
	System(io::Error),
}

impl fmt::Display for ManagedSyncError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ScopeMismatch => formatter.write_str("managed sync scope differs from selection"),
			Self::CredentialProfile => formatter
				.write_str("managed sync requires the selected credentials and identity maps"),
			Self::PrivateDirectoryRequired => {
				formatter.write_str("managed sync requires exact owner-private directories")
			}
			Self::AmbiguousSubjectOwnership => {
				formatter.write_str("managed sync subject reports ambiguous ownership")
			}
			Self::Busy => formatter.write_str("managed sync common parent is locked by a writer"),
			Self::Preview(error) => error.fmt(formatter),
			Self::System(error) => error.fmt(formatter),
		}
	}
}

impl std::error::Error for ManagedSyncError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Preview(error) => Some(error),
			Self::System(error) => Some(error),
			_ => None,
		}
	}
}

impl From<SyncPreviewError> for ManagedSyncError {
	fn from(error: SyncPreviewError) -> Self {
		Self::Preview(error)
	}
}

impl From<io::Error> for ManagedSyncError {
	fn from(error: io::Error) -> Self {
		Self::System(error)
	}
}

impl From<Errno> for ManagedSyncError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}
