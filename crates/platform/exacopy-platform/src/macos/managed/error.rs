use std::fmt;
use std::io;

use apfs_mounted::IdentityError;
use apfs_mounted::dataless::PolicyError as MountedPolicyError;
use apfs_mounted::lease::LeaseError;
use apfs_mounted::source::SourceError;
use exacopy_endpoint::IoError;
use rustix::io::Errno;

use super::{BasicMetadataError, thread_policy::PolicyError};

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
	/// Strict basic metadata admission or observation failed.
	BasicMetadata(BasicMetadataError),
	/// The requested range exceeds the length recorded at open.
	RangeOutsideFile,
	/// A positioned read produced data at the recorded logical end.
	UnexpectedDataAfterEnd,
	/// The thread could not confirm disabled dataless materialization.
	MaterializationPolicy(io::Error),
	/// The thread could not confirm restoration of its prior materialization policy.
	RestoreMaterializationPolicy(io::Error),
	/// Exact positioned I/O could not complete at the recorded offset.
	Read(IoError),
	/// A mounted read request failed. The companion supplies no failure offset.
	MountedRead {
		/// Starting offset of the request made to the companion.
		request_offset: u64,
		/// Requested byte count.
		request_length: usize,
		/// Original companion error. The buffer may contain a partial read.
		cause: Box<SourceError>,
	},
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
			Self::BasicMetadata(error) => write!(formatter, "source metadata refused ({error})"),
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
			Self::MountedRead {
				request_offset,
				request_length,
				cause,
			} => write!(
				formatter,
				"positioned read request for {request_length} bytes beginning at offset {request_offset} failed ({cause})"
			),
			Self::System(error) => write!(formatter, "descriptor operation failed ({error})"),
		}
	}
}

impl std::error::Error for ManagedReadError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Read(error) => Some(error),
			Self::MountedRead { cause, .. } => Some(cause.as_ref()),
			Self::BasicMetadata(error) => Some(error),
			Self::System(error)
			| Self::MaterializationPolicy(error)
			| Self::RestoreMaterializationPolicy(error) => Some(error),
			_ => None,
		}
	}
}

impl From<BasicMetadataError> for ManagedReadError {
	fn from(error: BasicMetadataError) -> Self {
		Self::BasicMetadata(error)
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

pub(super) fn root_identity_error(error: IdentityError) -> ManagedReadError {
	match error {
		IdentityError::Changed | IdentityError::Unavailable => {
			ManagedReadError::UnsupportedNamespace
		}
		IdentityError::Io(error) => error.into(),
		error => io::Error::other(error).into(),
	}
}

pub(super) fn lease_error(error: LeaseError) -> ManagedReadError {
	match error {
		LeaseError::WrongProcess => ManagedReadError::UnsupportedNamespace,
		LeaseError::Identity(error) => root_identity_error(error),
		LeaseError::Io(error) => error.into(),
		error => io::Error::other(error).into(),
	}
}

pub(super) fn source_open_error(error: SourceError) -> ManagedReadError {
	match error {
		SourceError::Identity(IdentityError::Unavailable) => ManagedReadError::UnsupportedChild,
		error => source_error(error),
	}
}

pub(super) fn source_error(error: SourceError) -> ManagedReadError {
	match error {
		SourceError::Missing => ManagedReadError::Missing,
		SourceError::Unsupported | SourceError::AdmissionRefused => {
			ManagedReadError::UnsupportedChild
		}
		SourceError::Changed
		| SourceError::Identity(IdentityError::Changed | IdentityError::Unavailable) => {
			ManagedReadError::SourceChanged
		}
		SourceError::LeaseMismatch => ManagedReadError::UnsupportedNamespace,
		SourceError::Lease(error) => lease_error(error),
		SourceError::Range { .. } | SourceError::RequestTooLarge { .. } => {
			ManagedReadError::RangeOutsideFile
		}
		SourceError::Identity(IdentityError::Io(error))
		| SourceError::Io(error)
		| SourceError::ContentUnavailable(error) => error.into(),
		SourceError::PolicyConfigure {
			error,
			restoration: None,
		} => ManagedReadError::MaterializationPolicy(policy_io(error)),
		error @ (SourceError::PolicyConfigure {
			restoration: Some(_),
			..
		}
		| SourceError::PolicyRestore { .. }) => ManagedReadError::RestoreMaterializationPolicy(
			io::Error::new(io::ErrorKind::Unsupported, error),
		),
		error => io::Error::other(error).into(),
	}
}

pub(super) fn source_read_error(
	error: SourceError,
	request_offset: u64,
	request_length: usize,
) -> ManagedReadError {
	match error {
		cause @ (SourceError::Io(_)
		| SourceError::ContentUnavailable(_)
		| SourceError::UnexpectedEof) => ManagedReadError::MountedRead {
			request_offset,
			request_length,
			cause: Box::new(cause),
		},
		error => source_error(error),
	}
}

fn policy_io(error: MountedPolicyError) -> io::Error {
	match error {
		MountedPolicyError::Io(error) => error,
		error => io::Error::new(io::ErrorKind::Unsupported, error),
	}
}

#[test]
fn companion_change_cannot_be_reported_as_a_success_or_a_more_specific_eof() {
	assert!(matches!(
		source_error(SourceError::Changed),
		ManagedReadError::SourceChanged
	));
}

#[test]
fn mounted_io_reports_the_request_and_retains_the_original_errno() {
	use std::error::Error as _;

	let error = source_read_error(SourceError::Io(Errno::IO.into()), 4096, 32);
	assert!(matches!(
		&error,
		ManagedReadError::MountedRead {
			request_offset: 4096,
			request_length: 32,
			..
		}
	));
	assert_eq!(
		error.to_string(),
		"positioned read request for 32 bytes beginning at offset 4096 failed (source I/O failed)"
	);
	let mounted = error
		.source()
		.unwrap()
		.downcast_ref::<SourceError>()
		.unwrap();
	let cause = mounted
		.source()
		.unwrap()
		.downcast_ref::<io::Error>()
		.unwrap();
	assert_eq!(cause.raw_os_error(), Some(Errno::IO.raw_os_error()));

	let unavailable =
		source_read_error(SourceError::ContentUnavailable(Errno::IO.into()), 4096, 32);
	assert!(matches!(
		unavailable,
		ManagedReadError::MountedRead {
			request_offset: 4096,
			request_length: 32,
			cause,
		} if matches!(*cause, SourceError::ContentUnavailable(_))
	));
}

#[test]
fn mounted_eof_after_an_unknown_prefix_retains_the_rejected_request_range() {
	let error = source_read_error(SourceError::UnexpectedEof, 900, 8);
	assert!(matches!(
		error,
		ManagedReadError::MountedRead {
			request_offset: 900,
			request_length: 8,
			ref cause,
		} if matches!(**cause, SourceError::UnexpectedEof)
	));
	assert_eq!(
		error.to_string(),
		"positioned read request for 8 bytes beginning at offset 900 failed (source ended before the requested range)"
	);
	assert!(matches!(
		source_read_error(SourceError::Changed, 900, 8),
		ManagedReadError::SourceChanged
	));
}
