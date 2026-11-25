use std::{fmt, io};

use exacopy_endpoint::IoError;
use rustix::io::Errno;

use super::super::{ManagedReadError, thread_policy::PolicyError};
use super::StageIdentity;

/// Failure to create, write, synchronize or reopen a managed APFS stage.
#[derive(Debug)]
#[non_exhaustive]
pub enum StageError {
	/// A capability is being used by a process that did not acquire its leases.
	WrongProcess,
	/// The nonblocking exclusive lease could not be acquired.
	DirectoryBusy,
	/// The authorized directory or its name no longer has the required identity.
	DirectoryChanged,
	/// A root or requested operation failed the existing managed APFS or thread policy checks.
	Managed(ManagedReadError),
	/// The stage name or public target already has an occupant.
	NameCollision,
	/// A creation may have occurred. Reconcile the retained private name before retrying.
	CreateUncertain {
		/// The attempt identity allocated before the create syscall.
		identity: StageIdentity,
		/// The operation or check that failed.
		source: Box<StageError>,
	},
	/// Darwin did not provide entropy. No private file creation was attempted.
	EntropyUnavailable(io::Error),
	/// The process exhausted its pool of distinct attempt serials.
	StageIdsExhausted,
	/// The requested extent exceeds the common signed offset ceiling.
	InvalidLength,
	/// A positioned operation exceeded the declared extent or the allowed chunk size.
	InvalidRange,
	/// The file did not have the expected private ownership, type, links, attributes or identity.
	StageChanged,
	/// The synchronous writer was previously retired after an uncertain outcome.
	WriterRetired,
	/// Sequential writes have not covered the complete declared extent.
	Incomplete,
	/// A positioned write failed, possibly after a prefix was transferred.
	Write(IoError),
	/// A positioned read failed.
	Read(IoError),
	/// An EOF probe returned data outside the declared extent.
	UnexpectedDataAfterEnd,
	/// The Darwin full file barrier failed. The private stage requires reconciliation.
	FileBarrier(io::Error),
	/// Closing the write descriptor failed. The private stage requires reconciliation.
	CloseWriter(io::Error),
	/// A descriptor-relative filesystem operation failed.
	System(io::Error),
}

impl fmt::Display for StageError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::WrongProcess => formatter.write_str("staging lease belongs to another process"),
			Self::DirectoryBusy => formatter.write_str("managed directory lease is busy"),
			Self::DirectoryChanged => formatter.write_str("managed directory identity changed"),
			Self::Managed(error) => {
				write!(formatter, "managed APFS evidence unavailable ({error})")
			}
			Self::NameCollision => formatter.write_str("stage or target name is occupied"),
			Self::CreateUncertain { source, .. } => {
				write!(
					formatter,
					"private stage creation requires reconciliation ({source})"
				)
			}
			Self::EntropyUnavailable(error) => {
				write!(formatter, "stage identity entropy unavailable ({error})")
			}
			Self::StageIdsExhausted => {
				formatter.write_str("process exhausted stage attempt identities")
			}
			Self::InvalidLength => formatter.write_str("stage extent exceeds the offset limit"),
			Self::InvalidRange => formatter.write_str("positioned range exceeds the stage bounds"),
			Self::StageChanged => formatter.write_str("private stage identity or metadata changed"),
			Self::WriterRetired => formatter.write_str("stage writer was retired"),
			Self::Incomplete => formatter.write_str("stage extent has incomplete writes"),
			Self::Write(error) => write!(formatter, "stage write failed ({error})"),
			Self::Read(error) => write!(formatter, "stage read-back failed ({error})"),
			Self::UnexpectedDataAfterEnd => {
				formatter.write_str("stage returned data beyond its extent")
			}
			Self::FileBarrier(error) => write!(formatter, "stage file barrier failed ({error})"),
			Self::CloseWriter(error) => write!(
				formatter,
				"could not confirm stage writer closure ({error})"
			),
			Self::System(error) => write!(formatter, "stage descriptor operation failed ({error})"),
		}
	}
}

impl std::error::Error for StageError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Managed(error) => Some(error),
			Self::CreateUncertain { source, .. } => Some(source.as_ref()),
			Self::Write(error) | Self::Read(error) => Some(error),
			Self::EntropyUnavailable(error)
			| Self::FileBarrier(error)
			| Self::CloseWriter(error)
			| Self::System(error) => Some(error),
			_ => None,
		}
	}
}

impl From<ManagedReadError> for StageError {
	fn from(error: ManagedReadError) -> Self {
		Self::Managed(error)
	}
}

impl From<PolicyError> for StageError {
	fn from(error: PolicyError) -> Self {
		ManagedReadError::from(error).into()
	}
}

impl From<io::Error> for StageError {
	fn from(error: io::Error) -> Self {
		Self::System(error)
	}
}

impl From<Errno> for StageError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}
