use std::fmt;
use std::io;

use exacopy_endpoint::IoError;
use rustix::io::Errno;

use super::thread_policy::PolicyError;

/// Failure to admit a managed APFS root, select a regular file, or read it.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagedReadError {
	/// The directory or filesystem did not meet the managed-root contract.
	UnsupportedNamespace,
	/// A cooperating writer already holds the root's exclusive advisory lock.
	DirectoryBusy,
	/// The selected name did not exist at the initial lookup.
	Missing,
	/// The selected entry did not meet the regular-file admission rules.
	UnsupportedChild,
	/// The selected name, held identity, or observed metadata changed.
	SourceChanged,
	/// The requested range exceeds the length recorded at open.
	RangeOutsideFile,
	/// A positioned read produced data at the recorded logical end.
	UnexpectedDataAfterEnd,
	/// The thread could not confirm disabled dataless materialization.
	MaterializationPolicy(io::Error),
	/// The thread could not confirm restoration of its prior materialization policy.
	RestoreMaterializationPolicy(io::Error),
	/// Exact positioned I/O could not complete.
	Read(IoError),
	/// A filesystem syscall failed.
	System(io::Error),
}

impl fmt::Display for ManagedReadError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnsupportedNamespace => formatter.write_str("managed APFS evidence unavailable"),
			Self::DirectoryBusy => formatter.write_str("managed directory has an exclusive lease"),
			Self::Missing => formatter.write_str("selected child is absent"),
			Self::UnsupportedChild => {
				formatter.write_str("selected child cannot be opened by this capability")
			}
			Self::SourceChanged => {
				formatter.write_str("selected child's identity or metadata changed")
			}
			Self::RangeOutsideFile => formatter.write_str("read range exceeds the captured extent"),
			Self::UnexpectedDataAfterEnd => {
				formatter.write_str("source returned data beyond the captured extent")
			}
			Self::MaterializationPolicy(error) => {
				write!(
					formatter,
					"could not disable dataless materialization ({error})"
				)
			}
			Self::RestoreMaterializationPolicy(error) => {
				write!(
					formatter,
					"could not restore thread materialization policy ({error})"
				)
			}
			Self::Read(error) => write!(formatter, "positioned read failed ({error})"),
			Self::System(error) => write!(formatter, "descriptor operation failed ({error})"),
		}
	}
}

impl std::error::Error for ManagedReadError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Read(error) => Some(error),
			Self::System(error)
			| Self::MaterializationPolicy(error)
			| Self::RestoreMaterializationPolicy(error) => Some(error),
			_ => None,
		}
	}
}

impl From<PolicyError> for ManagedReadError {
	fn from(error: PolicyError) -> Self {
		match error {
			PolicyError::Configure(error) => Self::MaterializationPolicy(error),
			PolicyError::Restore(error) => Self::RestoreMaterializationPolicy(error),
		}
	}
}

impl From<io::Error> for ManagedReadError {
	fn from(error: io::Error) -> Self {
		Self::System(error)
	}
}

impl From<Errno> for ManagedReadError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}
